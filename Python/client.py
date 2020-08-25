#!/usr/bin/env python3

# Creates a socket object, connects to the server and sends the message. Then, prints the server reply.
# Code extracted from https://realpython.com/python-sockets/#echo-client-and-server

import socket

HOST = '127.0.0.1'
PORT = 6000

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(b'Hello World')
    data = s.recv(1024)

print('Received ', repr(data))