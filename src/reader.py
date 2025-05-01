from pylibpcap.pcap import rpcap
from datetime import datetime
import parser, frames, mysql_db, launcher
import time

parser = parser.Parser()
mysql = mysql_db.MySQL()
mysql.main()

def main(file):

    packets = []
    total_counter = 0
    counter = 0

    start = time.time()

    for lenght, timestamp, pkt in rpcap(file):

        if counter == 10000:
            mysql.insert_reader(packets)
            counter = 0
            packets.clear()

        packet = frames.Packet()
        ethernet = frames.Ethernet()
        parser.ethernet_header(pkt[0:14], ethernet)
        packet.layer2 = ethernet
        
        if int(ethernet.ethertype, 16) == int('0x800', 16):
            ipv4 = frames.IPv4()
            parser.ipv4_header(pkt[14:34], ipv4)
            packet.layer3 = ipv4

            if ipv4.protocol == 1:
                icmp = frames.ICMP()
                parser.icmp_header(pkt[34:42], icmp)
                packet.layer4 = icmp
                packet.label = "ICMP"
            
            elif ipv4.protocol == 6:
                tcp = frames.TCP()
                parser.tcp_header(pkt[34:54], tcp)
                packet.layer4 = tcp
                packet.label = "TCP"

            elif ipv4.protocol == 17:
                udp = frames.UDP()
                parser.udp_header(pkt[34:42], udp)
                packet.layer4 = udp
                packet.label = "UDP"

            else:
                pass
                #print("Other protocol:", ipv4.protocol)
                #print()
        
        elif int(ethernet.ethertype, 16) == int('0x86dd', 16):
            pass
            #print("Name: IPv6")
            #print()

        elif int(ethernet.ethertype, 16) == int('0x806', 16):
            arp = frames.ARP()
            parser.arp_header(pkt[14:42], arp)
            packet.layer3 = arp
            packet.label = "ARP"

        else:
            pass
            #print("Other ethertype:", ethernet.ethertype)
            #print()

        packet.time = datetime.fromtimestamp(timestamp)
        packets.append(packet)
        counter += 1
        total_counter += 1

    mysql.insert_reader(packets)

    end = time.time()
    
    print()
    print("Inserted {PACKETS} in {TIME:.2f} seconds".format(PACKETS=total_counter, TIME=(end - start)))
    print()

    start, end = mysql.get_time_range()
    launcher.main(start, end)