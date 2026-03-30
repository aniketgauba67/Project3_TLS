import socket
import ssl
import json

HOST = "127.0.0.1"
PORT = 8443

with socket.create_connection((HOST, PORT)) as sock:
    request = {"command": "GET_TIME"}
    sock.sendall(json.dumps(request).encode())

    response = sock.recv(4096)
    print("Server Response:", response.decode())
