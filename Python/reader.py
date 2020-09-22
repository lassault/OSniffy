from pylibpcap.pcap import rpcap
from datetime import datetime
import parser, frames, mysql_db

parser = parser.Parser()
mysql = mysql_db.MySQL()
mysql.main()

def main():
    '''parser = parser.Parser()
    mysql = mysql_db.MySQL()
    mysql.main()'''

    packets = []
    counter = 0

    # Now, it inserts the packets in amounts of 1000
    # Read the file name from the args
    # Maintain the timestamp of the packat when reading from a *.pcap file (Done)

    #for lenght, timestamp, pkt in rpcap("lotsofweb.pcapng"):
    for lenght, timestamp, pkt in rpcap("test.pcap"):

        if counter == 1000:
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
                print("Other protocol:", ipv4.protocol)
                print()
        
        elif int(ethernet.ethertype, 16) == int('0x86dd', 16):
            print("Name: IPv6")
            print()

        elif int(ethernet.ethertype, 16) == int('0x806', 16):
            arp = frames.ARP()
            parser.arp_header(pkt[14:42], arp)
            packet.layer3 = arp
            packet.label = "ARP"

        else:
            print("Other ethertype:", ethernet.ethertype)
            print()

        #packet.print()
        packet.time = datetime.fromtimestamp(timestamp)
        packets.append(packet)
        counter += 1
        #mysql.insert(packet)
    mysql.insert_reader(packets)

main()