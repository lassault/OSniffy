#!/usr/bin/env python3

# Creates a socket object and waits for a connection. When connected, prints the client's IP and sends it back to the client.
# Code extracted from https://realpython.com/python-sockets/#echo-client-and-server

import socket

HOST = '0.0.0.0'
PORT = 80

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by ', addr)
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(data)