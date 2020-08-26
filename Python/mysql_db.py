import mysql.connector
import settings

class MySQL:
    def __init__(self):
        self.HOST = settings.HOST
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
        self.pointer = self.connection.cursor()

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
            protocol TINYINT UNSIGNED,
            srcPort SMALLINT UNSIGNED,
            dstPort SMALLINT UNSIGNED,
            timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(packetID)
            )
            ENGINE=INNODB
            AUTO_INCREMENT=1
            DEFAULT CHARSET=UTF8
            """.format(NAME=self.TABLE_NAME)
        self.pointer.execute(query)

    def insert(self, packet):
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

            # Filter all the oackets that insert in the DB
            if (packet.layer3.source == "127.0.0.1") and (packet.layer3.destination == "127.0.0.1"):
                if (packet.layer4.source == 3306) or (packet.layer4.destination == 3306):
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
        #packet.print()



