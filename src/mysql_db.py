import mysql.connector
import settings
import time

class MySQL:
    def __init__(self):
        self.HOST = settings.MYSQL_HOST
        self.USER = settings.MYSQL_USER
        self.PASSWORD = settings.MYSQL_PASS
        self.DB_NAME = settings.DB_NAME
        self.TABLE_NAME = settings.TABLE_NAME
        self.db_exists = False
        self.table_exists = False
        self.connection = mysql.connector.connect(
            host = self.HOST,
            user = self.USER,
            password = self.PASSWORD
        )
        self.pointer = self.connection.cursor()

    def main(self):
        self.db_exists = self.check_database()
        if not self.db_exists:
            self.create_db()
        
        self.pointer.close()
        self.connection.close()

        self.connection = mysql.connector.connect(
            host = self.HOST,
            user = self.USER,
            password = self.PASSWORD,
            database = self.DB_NAME
        )
        self.pointer = self.connection.cursor(buffered=True)

        self.table_exists = self.check_table()
        if not self.table_exists:
            self.create_table()

    def check_database(self):
        exist_db = False
        self.pointer.execute("SHOW DATABASES")
        for db in self.pointer:
            if self.DB_NAME in db:
                exist_db = True
                break
        return exist_db

    def create_db(self):
        query = "CREATE DATABASE {NAME}".format(NAME=self.DB_NAME)
        self.pointer.execute(query)

    def check_table(self):
        exist_table = False
        self.pointer.execute("SHOW TABLES")
        for table in self.pointer:
            if self.TABLE_NAME in table:
                exist_table = True
                break
        return exist_table

    def create_table(self):
        query = """CREATE TABLE {NAME} (
            packetID INT NOT NULL AUTO_INCREMENT,
            srcMAC VARCHAR(17) NOT NULL,
            dstMAC VARCHAR(17) NOT NULL,
            etherType VARCHAR(6) NOT NULL,
            srcIP VARCHAR(15) NOT NULL,
            dstIP VARCHAR(15) NOT NULL,
            protocol TINYINT(1) UNSIGNED,
            srcPort SMALLINT(2) UNSIGNED,
            dstPort SMALLINT(2) UNSIGNED,
            timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(packetID)
            )
            ENGINE=INNODB
            AUTO_INCREMENT=1
            DEFAULT CHARSET=UTF8
            """.format(NAME=self.TABLE_NAME)
        self.pointer.execute(query)

    def insert_sniffer(self, packet):
        if packet.label is "ARP":
            query_arp = """INSERT INTO {NAME}
                (srcMAC, dstMAC, etherType, srcIP, dstIP)
                VALUES (%s, %s, %s, %s, %s)
                """.format(NAME=self.TABLE_NAME)

            params_arp = (
                packet.layer2.source,
                packet.layer2.destination,
                packet.layer2.ethertype,
                packet.layer3.proto_source,
                packet.layer3.proto_destination
                )

            self.pointer.execute(query_arp, params_arp)
        
        elif packet.label is "ICMP":
            query_icmp = """INSERT INTO {NAME}
                (srcMAC, dstMAC, etherType, srcIP, dstIP, protocol)
                VALUES (%s, %s, %s, %s, %s, %s)
                """.format(NAME=self.TABLE_NAME)

            params_icmp = (
                packet.layer2.source,
                packet.layer2.destination,
                packet.layer2.ethertype,
                packet.layer3.source,
                packet.layer3.destination,
                packet.layer3.protocol
                )

            self.pointer.execute(query_icmp, params_icmp)

        elif packet.label is "TCP":
            # Filter all the packets of inserting in MySQL
            if (packet.layer3.source == "127.0.0.1") and (packet.layer3.destination == "127.0.0.1"):
                if (packet.layer4.source == 3306) or (packet.layer4.destination == 3306):
                    return

            # Filter all the packets of consulting to Grafana
            if (packet.layer3.source == "127.0.0.1") and (packet.layer3.destination == "127.0.0.1"):
                if (packet.layer4.source == 3000) or (packet.layer4.destination == 3000):
                    return

            query_tcp = """INSERT INTO {NAME}
                (srcMAC, dstMAC, etherType, srcIP, dstIP, protocol, srcPort, dstPort)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """.format(NAME=self.TABLE_NAME)

            params_tcp = (
                packet.layer2.source,
                packet.layer2.destination,
                packet.layer2.ethertype,
                packet.layer3.source,
                packet.layer3.destination,
                packet.layer3.protocol,
                packet.layer4.source,
                packet.layer4.destination
                )

            self.pointer.execute(query_tcp, params_tcp)

        elif packet.label is "UDP":
            query_udp = """INSERT INTO {NAME}
                (srcMAC, dstMAC, etherType, srcIP, dstIP, protocol, srcPort, dstPort)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """.format(NAME=self.TABLE_NAME)

            params_udp = (
                packet.layer2.source,
                packet.layer2.destination,
                packet.layer2.ethertype,   
                packet.layer3.source,
                packet.layer3.destination,
                packet.layer3.protocol,
                packet.layer4.source,
                packet.layer4.destination
                )

            self.pointer.execute(query_udp, params_udp)

        self.connection.commit()   
        packet.print()         

    def insert_reader(self, packets):
        for packet in packets:
            if packet.label is "ARP":
                query_arp = """INSERT INTO {NAME}
                    (srcMAC, dstMAC, etherType, srcIP, dstIP, timestamp)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """.format(NAME=self.TABLE_NAME)

                params_arp = (
                    packet.layer2.source,
                    packet.layer2.destination,
                    packet.layer2.ethertype,
                    packet.layer3.proto_source,
                    packet.layer3.proto_destination,
                    packet.time
                )

                self.pointer.execute(query_arp, params_arp)
            
            elif packet.label is "ICMP":
                query_icmp = """INSERT INTO {NAME}
                (srcMAC, dstMAC, etherType, srcIP, dstIP, protocol, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """.format(NAME=self.TABLE_NAME)

                params_icmp = (
                    packet.layer2.source,
                    packet.layer2.destination,
                    packet.layer2.ethertype,
                    packet.layer3.source,
                    packet.layer3.destination,
                    packet.layer3.protocol,
                    packet.time
                )

                self.pointer.execute(query_icmp, params_icmp)

            elif packet.label is "TCP":
                query_tcp = """INSERT INTO {NAME}
                    (srcMAC, dstMAC, etherType, srcIP, dstIP, protocol, srcPort, dstPort, timestamp)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """.format(NAME=self.TABLE_NAME)

                params_tcp = (
                    packet.layer2.source,
                    packet.layer2.destination,
                    packet.layer2.ethertype,
                    packet.layer3.source,
                    packet.layer3.destination,
                    packet.layer3.protocol,
                    packet.layer4.source,
                    packet.layer4.destination,
                    packet.time
                    )

                self.pointer.execute(query_tcp, params_tcp)

            elif packet.label is "UDP":
                query_udp = """INSERT INTO {NAME}
                (srcMAC, dstMAC, etherType, srcIP, dstIP, protocol, srcPort, dstPort, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """.format(NAME=self.TABLE_NAME)

                params_udp = (
                    packet.layer2.source,
                    packet.layer2.destination,
                    packet.layer2.ethertype,
                    packet.layer3.source,
                    packet.layer3.destination,
                    packet.layer3.protocol,
                    packet.layer4.source,
                    packet.layer4.destination,
                    packet.time
                    )

                self.pointer.execute(query_udp, params_udp)

        self.connection.commit()
        print("Inserted {PACKETS} packets".format(PACKETS=len(packets)))

    def get_time_range(self):
        query_start = """SELECT timestamp FROM {NAME}
                    WHERE packetID = {ID}
                    """.format(NAME=self.TABLE_NAME, ID=1)

        self.pointer.execute(query_start)

        start = self.pointer.fetchone()
        start = int(start[0].timestamp()) * 1000

        query_end = """SELECT timestamp FROM {NAME}
                    WHERE packetID = (SELECT COUNT(*) FROM {NAME})
                    """.format(NAME=self.TABLE_NAME)

        self.pointer.execute(query_end)

        end = self.pointer.fetchone()
        end = int(end[0].timestamp()) * 1000

        return start, end