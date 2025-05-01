import binascii
import socket
import struct

class Parser:
    def __init__(self):
        pass

    def ethernet_header(self, frame, ethernet):
        data = struct.unpack("!6s6sH", frame)
        ethernet.destination = binascii.hexlify(data[0]).decode('utf-8')
        ethernet.destination = (':'.join(format(c, '02x') for c in bytes.fromhex(ethernet.destination))).upper()
        ethernet.source = binascii.hexlify(data[1]).decode('utf-8')
        ethernet.source = (':'.join(format(c, '02x') for c in bytes.fromhex(ethernet.source))).upper()
        ethernet.ethertype = hex(data[2])

    def arp_header(self, frame, arp):
        data = struct.unpack("!HHBBH6s4s6s4s", frame)
        arp.hard_type = data[0]
        arp.protocol = hex(data[1])
        arp.opcode = data[4]
        arp.hard_source = binascii.hexlify(data[5]).decode('utf-8')
        arp.hard_source = (':'.join(format(c, '02x') for c in bytes.fromhex(arp.hard_source))).upper()
        arp.proto_source = socket.inet_ntoa(data[6])
        arp.hard_destination = binascii.hexlify(data[7]).decode('utf-8')
        arp.hard_destination = (':'.join(format(c, '02x') for c in bytes.fromhex(arp.hard_destination))).upper()
        arp.proto_destination = socket.inet_ntoa(data[8])

    def icmp_header(self, frame, icmp):
        data = struct.unpack("!BBH4s", frame)
        icmp.type = data[0]
        icmp.code = data[1]
        icmp.rest = binascii.hexlify(data[3]).decode('utf-8')

    def ipv4_header(self, frame, ipv4):
        data = struct.unpack("!BBHHHBBH4s4s", frame)
        ipv4.version = (data[0] & 240) >> 4
        ipv4.total_length = data[2]
        ipv4.TTL = data[5]
        ipv4.protocol = data[6]
        ipv4.source = socket.inet_ntoa(data[8])
        ipv4.destination = socket.inet_ntoa(data[9])

    def tcp_header(self, frame, tcp):
        data = struct.unpack("!HH4s4sHHHH", frame)
        tcp.source = data[0]
        tcp.destination = data[1]
        tcp.sequence_number = str(int(binascii.hexlify(data[2]), 16))
        tcp.ACK = str(int(binascii.hexlify(data[3]), 16))
        tcp.flags = data[4] & 511
        tcp.window_size = data[5]

    def udp_header(self, frame, udp):
        data = struct.unpack("!HHHH", frame)
        udp.source = data[0]
        udp.destination = data[1]
        udp.length = data[2]