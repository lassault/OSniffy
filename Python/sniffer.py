#!/usr/bin/env python3

import socket, struct, binascii, os, frames, parser

# Check if works with Windows machines

# if operating system is windows
if os.name == "nt":
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
    s.bind(("YOUR_INTERFACE_IP",0))
    s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

# if operating system is linux
else:
    s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

parser = parser.Parser()

# Difference between 'recv()' and 'recvfrom()'?
# Buffer size, look at that

while True:
  data = s.recvfrom(1024)
  # data = s.recv(655565)

  print("Layer 2:")
  print("========")

  ethernet = frames.Ethernet()
  parser.ethernet_header(data[0][0:14], ethernet)
  ethernet.print()

  if int(ethernet.ethertype, 16) == int('0x800', 16):
    print("IPv4") 
  
    print()
    print("Layer 3:")
    print("========")

    ipv4 = frames.IPv4()
    parser.ipv4_header(data[0][14:34], ipv4)
    ipv4.print()

    print()

    if ipv4.protocol == 1:
      print("ICMP")
      icmp = frames.ICMP()
      parser.icmp_header(data[0][34:42], icmp)
      icmp.print()
    elif ipv4.protocol == 6:
      print("Layer 4:")
      print("========")
      print("TCP")
      tcp = frames.TCP()
      parser.tcp_header(data[0][34:54], tcp)
      tcp.print()
    elif ipv4.protocol == 17:
      print("Layer 4:")
      print("========")
      print("UDP")
      udp = frames.UDP()
      parser.udp_header(data[0][34:42], udp)
      udp.print()
    else:
      print("Other:", ipv4.protocol)
      
  elif int(ethernet.ethertype, 16) == int('0x86dd', 16):
    print("IPv6")
  elif int(ethernet.ethertype, 16) == int('0x806', 16):
    print("ARP")
  else:
    print("Other:", ethernet.ethertype)

  print()