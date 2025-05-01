import binascii
import frames
import launcher
import mysql_db
import os
import parser
import settings
import socket
import struct


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
mysql = mysql_db.MySQL()
mysql.main()

def main():
  launcher.main("now-5m", "now")

  while True:
    data = s.recvfrom(1024)

    packet = frames.Packet()

    ethernet = frames.Ethernet()
    parser.ethernet_header(data[0][0:14], ethernet)
    packet.layer2 = ethernet

    if int(ethernet.ethertype, 16) == int('0x800', 16):
      ipv4 = frames.IPv4()
      parser.ipv4_header(data[0][14:34], ipv4)
      packet.layer3 = ipv4

      if ipv4.protocol == 1:
        icmp = frames.ICMP()
        parser.icmp_header(data[0][34:42], icmp)
        packet.layer4 = icmp
        packet.label = "ICMP"

      elif ipv4.protocol == 6:
        tcp = frames.TCP()
        parser.tcp_header(data[0][34:54], tcp)
        packet.layer4 = tcp
        packet.label = "TCP"

      elif ipv4.protocol == 17:
        udp = frames.UDP()
        parser.udp_header(data[0][34:42], udp)
        packet.layer4 = udp
        packet.label = "UDP"

      else:
        print("Other protocol:", ipv4.protocol)
        print()
        
    elif int(ethernet.ethertype, 16) == int('0x86dd', 16):
      print("Name: IPv6")
      print()
    elif int(ethernet.ethertype, 16) == int('0x806', 16):
      arp = frames.ARP()
      parser.arp_header(data[0][14:42], arp)
      packet.layer3 = arp
      packet.label = "ARP"

    else:
      print("Other ethertype:", ethernet.ethertype)
      print()

    mysql.insert_sniffer(packet)