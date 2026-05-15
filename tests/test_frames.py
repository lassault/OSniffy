"""Unit tests for osniffy.protocol.frames – dataclass field defaults and typing."""

from __future__ import annotations

from datetime import datetime

from osniffy.protocol.frames import ARP, ICMP, TCP, UDP, Ethernet, IPv4, Packet


class TestEthernet:
    def test_defaults(self) -> None:
        eth = Ethernet()
        assert eth.source == ""
        assert eth.destination == ""
        assert eth.ethertype == ""

    def test_custom_values(self) -> None:
        eth = Ethernet(
            destination="FF:FF:FF:FF:FF:FF", source="AA:BB:CC:DD:EE:FF", ethertype="0x806"
        )
        assert eth.destination == "FF:FF:FF:FF:FF:FF"
        assert eth.source == "AA:BB:CC:DD:EE:FF"
        assert eth.ethertype == "0x806"


class TestIPv4:
    def test_defaults(self) -> None:
        ip = IPv4()
        assert ip.version == 0
        assert ip.source == ""
        assert ip.destination == ""

    def test_custom_values(self) -> None:
        ip = IPv4(
            version=4, total_length=40, ttl=64, protocol=6, source="1.2.3.4", destination="5.6.7.8"
        )
        assert ip.version == 4
        assert ip.protocol == 6
        assert ip.source == "1.2.3.4"


class TestARP:
    def test_defaults(self) -> None:
        arp = ARP()
        assert arp.hard_type == 0
        assert arp.opcode == 0

    def test_custom_values(self) -> None:
        arp = ARP(
            hard_type=1,
            protocol="0x800",
            opcode=1,
            hard_source="AA:BB:CC:DD:EE:FF",
            proto_source="192.168.1.1",
            hard_destination="00:00:00:00:00:00",
            proto_destination="10.0.0.1",
        )
        assert arp.opcode == 1
        assert arp.proto_source == "192.168.1.1"
        assert arp.proto_destination == "10.0.0.1"


class TestICMP:
    def test_defaults(self) -> None:
        icmp = ICMP()
        assert icmp.type == 0
        assert icmp.code == 0

    def test_custom_values(self) -> None:
        icmp = ICMP(type=8, code=0, rest="00000000")
        assert icmp.type == 8
        assert icmp.rest == "00000000"


class TestTCP:
    def test_defaults(self) -> None:
        tcp = TCP()
        assert tcp.source == 0
        assert tcp.destination == 0
        assert tcp.flags == 0

    def test_custom_values(self) -> None:
        tcp = TCP(source=54321, destination=80, flags=0x002, window_size=65535)
        assert tcp.source == 54321
        assert tcp.destination == 80
        assert tcp.flags == 0x002


class TestUDP:
    def test_defaults(self) -> None:
        udp = UDP()
        assert udp.source == 0
        assert udp.length == 0

    def test_custom_values(self) -> None:
        udp = UDP(source=1234, destination=53, length=20)
        assert udp.source == 1234
        assert udp.length == 20


class TestPacket:
    def test_defaults(self) -> None:
        p = Packet()
        assert p.layer2 is None
        assert p.layer3 is None
        assert p.layer4 is None
        assert p.label == ""
        assert p.time is None

    def test_with_all_layers(self) -> None:
        ts = datetime(2024, 1, 1, 12, 0, 0)
        eth = Ethernet(
            source="11:22:33:44:55:66", destination="AA:BB:CC:DD:EE:FF", ethertype="0x800"
        )
        ip = IPv4(source="192.168.1.1", destination="10.0.0.1", protocol=6)
        tcp = TCP(source=12345, destination=80)
        p = Packet(layer2=eth, layer3=ip, layer4=tcp, label="TCP", time=ts)
        assert p.label == "TCP"
        assert p.layer2 is eth
        assert p.layer3 is ip
        assert p.layer4 is tcp
        assert p.time == ts

    def test_label_is_string(self) -> None:
        p = Packet(label="UDP")
        assert isinstance(p.label, str)
        assert p.label == "UDP"
