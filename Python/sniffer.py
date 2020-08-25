#!/usr/bin/env python3

# Creates a packet sniffer and prints the info
# Code extracted from https://www.bitforestinfo.com/2017/01/how-to-write-simple-packet-sniffer.html

import socket
 
#create an INET, raw socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
 
# receive a packet
while True:

   # print output on terminal
   print(s.recvfrom(65565))