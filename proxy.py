from sys import argv
from socket import *
from urllib.parse import urlparse
from multiprocessing import Process
import hashlib
import http.client
import json

#######################################################
# A simple HTTP/1.0 proxy for get requests
# The proxy will send requests to virus total to
# determine if the body of the response contains malware
# See www.virustotal.com
#
# Jared Nielson u0495206
# CS 4480 Spring 2018
######################################################


# Sends the data to the socket and then closes it#
def send_response(send_socket, response):
    print(response)
    send_socket.send(response.encode())
    send_socket.close()


# Processes a single request from a connected socket
def process_connection(client_socket, addr):
    first_line = True
    eo_header = False
    headers = dict()
    response = 0
    request_line = ""
    # keep reading and processing lines until we've read the end of header
    while not eo_header:
        # Read bytes from the socket
        request = client_socket.recv(4096)
        req_string = request.decode("utf-8")
        lines = req_string.splitlines(True)
        response = ""
        # Loop over all lines until we reach end of header
        for i in range(first_line, len(lines)):
            s = lines[i]
            if s == "\r\n":
                eo_header = True
                break

            # <Header Name>: <Header Value>
            slc = s.find(':') + 1
            if slc == 0:
                response = "HTTP/1.0 400 Bad Request\r\n"
                break
            header_name = s[:slc]
            header_val = s[slc:]
            assert isinstance(header_name, str)
            headers[header_name] = header_val

        # If this is the first time reading bytes get the request line
        if first_line:
            first_line = False
            request_line = lines[0]

    request_line_split = request_line.split(" ")
    if len(request_line_split) != 3:
        send_response(client_socket, "HTTP/1.0 400 Bad Request\r\n")
        return
    request_type = request_line_split[0]
    request_uri = request_line_split[1]
    # request_protocol = request_line_split[2]

    http_methods = ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "CONNECT"]
    # Is it a valid request type?
    if http_methods.count(request_type) < 1:
        response = "HTTP/1.0 400 Bad Request\r\n"
    # Is it implemented?
    elif request_type != "GET":
        response = "HTTP/1.0 501 Not Implemented\r\n"

    if response:
        send_response(client_socket, response)
        return

    # parse the URL
    o = urlparse(request_uri)
    # possible relative
    if not o.netloc:
        if "Host:" not in headers:
            if not request_uri.lower().startswith("http://"):
                o = urlparse("http://" + request_uri)
                if not o.netloc:
                    response = "HTTP/1.0 400 Bad Request\r\n"
                    send_response(client_socket, response)
                    return
        # Add http to the netloc if needed
        else:
            host = headers["Host:"]
            full_url = host.rstrip().lstrip() + request_uri
            if not full_url.lower().startswith("http://"):
                full_url = "http://" + full_url

            o = urlparse(full_url)

    # Port extraction and netloc clean up
    if o.port:
        port = int(o.port)
        netloc = o.netloc[:len(o.netloc) - len(str(o.port))]
        if netloc[len(netloc) - 1] == ':':
            netloc = netloc[:len(netloc) - 1]
        print(netloc)
    else:
        port = 80
        netloc = o.netloc
    # Valid port checking
    if port < 0 or port > 65535:
        send_response(client_socket, "HTTP/1.0 400 Bad Request\r\n")
        return

    # Connect to the end server
    print("Connecting to host: " + netloc + " On port: " + str(port))
    host_socket = socket(AF_INET, SOCK_STREAM)
    try:
        host_socket.connect((netloc, port))
    except OSError:
        send_response(client_socket, "HTTP/1.0 404 Not Found\r\n")
        host_socket.close()
        return

    # Construct the request
    headers["Connection:"] = " close\r\n"
    headers["Host:"] = " " + o.netloc + "\r\n"
    if o.path:
        path = o.path
    else:
        path = "/"
            
    request = request_type + " " + path
    request += " HTTP/1.0"
    request += "\r\n"
    for key, value in headers.items():
        request += key + value
    request += "\r\n"

    bytes_to_send = request.encode()
    num_bytes_to_send = len(bytes_to_send)
    num_bytes_sent = 0

    # Keep sending the request until its been sent
    while num_bytes_sent < num_bytes_to_send:
        num_bytes_sent += host_socket.send(bytes_to_send)
        bytes_to_send = bytes_to_send[num_bytes_sent:]
        if not num_bytes_sent:
            send_response(client_socket, "HTTP/1.0 502 Bad Gateway\r\n")
            return

    # Keep receiving the response until its all here
    response = host_socket.recv(4096)
    num_bytes_received = len(response)
    old_len = num_bytes_received
    while num_bytes_received:
        try:
            response += host_socket.recv(4096)
        except IOError:
            print("Error receiving data from host.")
        curr_len = len(response)
        num_bytes_received = curr_len - old_len
        old_len = curr_len

    host_socket.close()
    # Parse the response
    (resp_headers, separator, body) = response.partition(b'\r\n\r\n')
    safe = True
    # If we have a body check it for malware
    if body:
        m = hashlib.md5()
        m.update(body)
        body_hash = m.hexdigest()

        headers = {"Accept-Encoding": "gizip, deflate",
                   "User-Agent": "gzip, jnielson88"}
        conn = http.client.HTTPConnection("www.virustotal.com")
        conn.request("GET", "/vtapi/v2/file/report" +
                     "?apikey=0d4048aae87b6baec2483a7083d1bbf7f19db2a5001d857534070e17d3ed6fbd&resource=" +
                     body_hash, "", headers)
        vt_resp = conn.getresponse()
        # Read the entire response from virus total
        vt_response_body = vt_resp.read()
        num_bytes_received = len(vt_response_body)
        old_len = num_bytes_received
        while num_bytes_received:
            vt_response_body += vt_resp.read()
            curr_len = len(vt_response_body)
            num_bytes_received = curr_len - old_len
            old_len = curr_len

        conn.close()
        data = json.JSONDecoder().decode(vt_response_body.decode())
        # We really only care about response code
        if 'response_code' in data:
            if data['response_code'] == 1:
                safe = False

    # We have malware construct this response informing the client
    if not safe:
        html = "<!DOCTYPE html><html><body><h1>Warning</h1>" + \
               "<p>The file you requested contains malware</p></body></html>"
        status_line = "HTTP/1.0 200 OK\r\n"
        headers = "Content-type: text/html\r\n"
        headers += "Content-Length: " + str(len(html)) + "\r\n"
        headers += "\r\n"
        response = (status_line + headers + html).encode('utf-8')
        print(response)

    # Send resopnse from server if safe, or warning response until its all sent
    num_bytes_to_send = len(response)
    num_bytes_sent = 0
    while num_bytes_sent < num_bytes_to_send:
        num_bytes_sent += client_socket.send(response)
        response = response[num_bytes_sent:]
        if not num_bytes_sent:
            client_socket.close()
            return
    client_socket.close()


#################################################################
# Main program Starts Here
#################################################################
if len(argv) < 2:
    print("You must specify a port number")
    exit()

try:
    server_port = int(argv[1])
    # set up server to listen
    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.bind(('', server_port))
    serverSocket.listen(100)
    print("Server is listening")

    # begin listening
    while True:
        requesterSocket, requesterAddr = serverSocket.accept()
        p = Process(target=process_connection, args=(requesterSocket, requesterAddr,))
        p.daemon = False
        p.start()

except ValueError:
    print("The first argument must be of type int")
    exit()
except OSError:
    print("Port: " + str(server_port) + " already in use.")
