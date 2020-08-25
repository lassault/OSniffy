class Ethernet:
    def __init__(self):
        self.destination = None
        self.source = None
        self.ethertype = None

    def print(self):
        print("Destination MAC:", self.destination)
        print("Source MAC:", self.source)
        print("Ethertype:", self.ethertype)

class ICMP:
    def __init__(self):
        self.type = None
        self.code = None
        self.rest = None

    def print(self):
        print("Type:", self.type)
        print("Code:", self.code)
        print("Rest:", self.rest)

class IPv4:
    def __init__(self):
        self.version = None
        self.total_length = None
        self.TTL = None
        self.protocol = None
        self.source = None
        self.destination = None

    def print(self):
        print("Version:", self.version)
        print("Length:", self.total_length)
        print("TTL:", self.TTL)
        print("Protocol:", self.protocol)
        print("Source IP:", self.source)
        print("Destination IP:", self.destination)

class TCP:
    def __init__(self):
        self.source = None
        self.destination = None
        self.sequence_number = None
        self.ACK = None
        self.flags = None
        self.window_size = None

    def print(self):
        print("Source port:", self.source)
        print("Destination port:", self.destination)
        print("Sequence number:", self.sequence_number)
        print("ACK:", self.ACK)
        print("Flags:", self.flags)
        print("Window size:", self.window_size)

class UDP:
    def __init__(self):
        self.source = None
        self.destination = None
        self.length = None

    def print(self):
        print("Source port:", self.source)
        print("Destination port:", self.destination)
        print("Length:", self.length)