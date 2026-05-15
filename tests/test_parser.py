"""Unit tests for osniffy.protocol.parser – raw bytes → typed frame objects."""

from __future__ import annotations

import pytest

from osniffy.protocol.frames import ARP, ICMP, TCP, UDP, Ethernet, IPv4
from osniffy.protocol.parser import PacketParser
from tests.conftest import (
    DST_IP,
    SRC_IP,
    build_arp_header,
    build_eth_header,
    build_icmp_header,
    build_ipv4_header,
    build_tcp_header,
    build_udp_header,
)


@pytest.fixture
def parser() -> PacketParser:
    return PacketParser()


# ---------------------------------------------------------------------------
# Ethernet
# ---------------------------------------------------------------------------


class TestEthernetHeader:
    def test_mac_formatting(self, parser: PacketParser) -> None:
        frame = build_eth_header(0x0800)
        eth = parser.ethernet_header(frame)
        assert eth.source == "11:22:33:44:55:66"
        assert eth.destination == "AA:BB:CC:DD:EE:FF"

    def test_ethertype_ipv4(self, parser: PacketParser) -> None:
        frame = build_eth_header(0x0800)
        eth = parser.ethernet_header(frame)
        assert eth.ethertype == "0x800"

    def test_ethertype_arp(self, parser: PacketParser) -> None:
        frame = build_eth_header(0x0806)
        eth = parser.ethernet_header(frame)
        assert eth.ethertype == "0x806"

    def test_too_short_raises(self, parser: PacketParser) -> None:
        with pytest.raises(ValueError, match="too short"):
            parser.ethernet_header(b"\x00" * 10)

    def test_macs_are_uppercase(self, parser: PacketParser) -> None:
        frame = build_eth_header(0x0800)
        eth = parser.ethernet_header(frame)
        assert eth.source == eth.source.upper()
        assert eth.destination == eth.destination.upper()


# ---------------------------------------------------------------------------
# IPv4
# ---------------------------------------------------------------------------


class TestIPv4Header:
    def test_fields(self, parser: PacketParser) -> None:
        frame = build_ipv4_header(6)
        ipv4 = parser.ipv4_header(frame)
        assert ipv4.version == 4
        assert ipv4.ttl == 64
        assert ipv4.protocol == 6
        assert ipv4.source == SRC_IP
        assert ipv4.destination == DST_IP

    def test_protocol_udp(self, parser: PacketParser) -> None:
        frame = build_ipv4_header(17)
        assert parser.ipv4_header(frame).protocol == 17

    def test_protocol_icmp(self, parser: PacketParser) -> None:
        frame = build_ipv4_header(1)
        assert parser.ipv4_header(frame).protocol == 1

    def test_too_short_raises(self, parser: PacketParser) -> None:
        with pytest.raises(ValueError, match="too short"):
            parser.ipv4_header(b"\x00" * 10)


# ---------------------------------------------------------------------------
# TCP
# ---------------------------------------------------------------------------


class TestTCPHeader:
    def test_ports(self, parser: PacketParser) -> None:
        frame = build_tcp_header(src_port=12345, dst_port=80)
        tcp = parser.tcp_header(frame)
        assert tcp.source == 12345
        assert tcp.destination == 80

    def test_sequence_number(self, parser: PacketParser) -> None:
        frame = build_tcp_header(seq=1000)
        tcp = parser.tcp_header(frame)
        assert tcp.sequence_number == "1000"

    def test_syn_flag(self, parser: PacketParser) -> None:
        frame = build_tcp_header(flags=0x002)  # SYN
        tcp = parser.tcp_header(frame)
        assert tcp.flags & 0x002

    def test_window_size(self, parser: PacketParser) -> None:
        frame = build_tcp_header(window=8192)
        tcp = parser.tcp_header(frame)
        assert tcp.window_size == 8192

    def test_too_short_raises(self, parser: PacketParser) -> None:
        with pytest.raises(ValueError, match="too short"):
            parser.tcp_header(b"\x00" * 10)


# ---------------------------------------------------------------------------
# UDP
# ---------------------------------------------------------------------------


class TestUDPHeader:
    def test_fields(self, parser: PacketParser) -> None:
        frame = build_udp_header(src_port=53, dst_port=1024, length=20)
        udp = parser.udp_header(frame)
        assert udp.source == 53
        assert udp.destination == 1024
        assert udp.length == 20

    def test_too_short_raises(self, parser: PacketParser) -> None:
        with pytest.raises(ValueError, match="too short"):
            parser.udp_header(b"\x00" * 4)


# ---------------------------------------------------------------------------
# ICMP
# ---------------------------------------------------------------------------


class TestICMPHeader:
    def test_echo_request(self, parser: PacketParser) -> None:
        frame = build_icmp_header(type_=8, code=0)
        icmp = parser.icmp_header(frame)
        assert icmp.type == 8
        assert icmp.code == 0

    def test_echo_reply(self, parser: PacketParser) -> None:
        frame = build_icmp_header(type_=0, code=0)
        assert parser.icmp_header(frame).type == 0

    def test_too_short_raises(self, parser: PacketParser) -> None:
        with pytest.raises(ValueError, match="too short"):
            parser.icmp_header(b"\x00" * 4)


# ---------------------------------------------------------------------------
# ARP
# ---------------------------------------------------------------------------


class TestARPHeader:
    def test_fields(self, parser: PacketParser) -> None:
        frame = build_arp_header(src_ip=SRC_IP, dst_ip=DST_IP)
        arp = parser.arp_header(frame)
        assert arp.hard_type == 1
        assert arp.opcode == 1
        assert arp.proto_source == SRC_IP
        assert arp.proto_destination == DST_IP
        assert arp.hard_source == "11:22:33:44:55:66"
        assert arp.hard_destination == "AA:BB:CC:DD:EE:FF"

    def test_too_short_raises(self, parser: PacketParser) -> None:
        with pytest.raises(ValueError, match="too short"):
            parser.arp_header(b"\x00" * 20)


# ---------------------------------------------------------------------------
# Full packet parsing (parse_packet)
# ---------------------------------------------------------------------------


class TestParsePacket:
    def test_tcp_packet(self, parser: PacketParser) -> None:
        raw = build_eth_header(0x0800) + build_ipv4_header(6) + build_tcp_header()
        pkt = parser.parse_packet(raw)
        assert pkt.label == "TCP"
        assert isinstance(pkt.layer2, Ethernet)
        assert isinstance(pkt.layer3, IPv4)
        assert isinstance(pkt.layer4, TCP)

    def test_udp_packet(self, parser: PacketParser) -> None:
        raw = build_eth_header(0x0800) + build_ipv4_header(17) + build_udp_header()
        pkt = parser.parse_packet(raw)
        assert pkt.label == "UDP"
        assert isinstance(pkt.layer4, UDP)

    def test_icmp_packet(self, parser: PacketParser) -> None:
        raw = build_eth_header(0x0800) + build_ipv4_header(1) + build_icmp_header()
        pkt = parser.parse_packet(raw)
        assert pkt.label == "ICMP"
        assert isinstance(pkt.layer4, ICMP)

    def test_arp_packet(self, parser: PacketParser) -> None:
        raw = build_eth_header(0x0806) + build_arp_header()
        pkt = parser.parse_packet(raw)
        assert pkt.label == "ARP"
        assert isinstance(pkt.layer3, ARP)
        assert pkt.layer4 is None

    def test_ipv6_ignored(self, parser: PacketParser) -> None:
        raw = build_eth_header(0x86DD) + b"\x00" * 40
        pkt = parser.parse_packet(raw)
        assert pkt.label == ""

    def test_unknown_ethertype_ignored(self, parser: PacketParser) -> None:
        raw = build_eth_header(0x9999) + b"\x00" * 20
        pkt = parser.parse_packet(raw)
        assert pkt.label == ""

    def test_too_short_returns_empty_packet(self, parser: PacketParser) -> None:
        pkt = parser.parse_packet(b"\x00" * 5)
        assert pkt.label == ""
        assert pkt.layer2 is None

    def test_unknown_ip_protocol_layer3_set_label_empty(self, parser: PacketParser) -> None:
        # Protocol 253 is reserved/experimental – should parse IPv4 but leave label empty
        raw = build_eth_header(0x0800) + build_ipv4_header(253) + b"\x00" * 20
        pkt = parser.parse_packet(raw)
        assert isinstance(pkt.layer3, IPv4)
        assert pkt.label == ""

    def test_tcp_source_ip_preserved(self, parser: PacketParser) -> None:
        raw = (
            build_eth_header(0x0800)
            + build_ipv4_header(6, src="172.16.0.1", dst="8.8.8.8")
            + build_tcp_header()
        )
        pkt = parser.parse_packet(raw)
        assert isinstance(pkt.layer3, IPv4)
        assert pkt.layer3.source == "172.16.0.1"
        assert pkt.layer3.destination == "8.8.8.8"
