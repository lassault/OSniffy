class Packet:
    def __init__(self):
        self.layer2 = None
        self.layer3 = None
        self.layer4 = None
        self.label = None
        self.time = None

    def print(self):
        print("Packet:", self.label)
        print("======")
        if self.layer2 is not None:
            self.layer2.print()
        if self.layer3 is not None:
            self.layer3.print()
        if self.layer4 is not None:
            self.layer4.print()
        print("======")
        print()


class Ethernet:
    def __init__(self):
        self.destination = None
        self.source = None
        self.ethertype = None

    def print(self):
        print("Name: Ethernet")
        print("Destination MAC:", self.destination)
        print("Source MAC:", self.source)
        print("Ethertype:", self.ethertype)
        print("----------------")

class ARP:
    def __init__(self):
        self.hard_type = None
        self.protocol = None
        self.opcode = None
        self.hard_source = None
        self.proto_source = None
        self.hard_destination = None
        self.proto_destination = None

    def print(self):
        print("Name: ARP")
        print("Hardware type:", self.hard_type)
        print("Protocol type:", self.protocol)
        print("Opcode:", self.opcode)
        print("Source MAC:", self.hard_source)
        print("Source IP:", self.proto_source)
        print("Destination MAC:", self.hard_destination)
        print("Destination IP:", self.proto_destination)

class ICMP:
    def __init__(self):
        self.type = None
        self.code = None
        self.rest = None

    def print(self):
        print("Name: ICMP")
        print("Type:", self.type)
        print("Code:", self.code)
        print("Rest:", self.rest)
        print("----------------")

class IPv4:
    def __init__(self):
        self.version = None
        self.total_length = None
        self.TTL = None
        self.protocol = None
        self.source = None
        self.destination = None

    def print(self):
        print("Name: IPv4")
        print("Version:", self.version)
        print("Length:", self.total_length)
        print("TTL:", self.TTL)
        print("Protocol:", self.protocol)
        print("Source IP:", self.source)
        print("Destination IP:", self.destination)
        print("----------------")

class TCP:
    def __init__(self):
        self.source = None
        self.destination = None
        self.sequence_number = None
        self.ACK = None
        self.flags = None
        self.window_size = None

    def print(self):
        print("Name: TCP")
        print("Source port:", self.source)
        print("Destination port:", self.destination)
        print("Sequence number:", self.sequence_number)
        print("ACK:", self.ACK)
        print("Flags:", self.flags)
        print("Window size:", self.window_size)
        print("----------------")

class UDP:
    def __init__(self):
        self.source = None
        self.destination = None
        self.length = None

    def print(self):
        print("Name: UDP")
        print("Source port:", self.source)
        print("Destination port:", self.destination)
        print("Length:", self.length)
        print("----------------")