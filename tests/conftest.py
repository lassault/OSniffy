"""Shared test fixtures and helpers."""

from __future__ import annotations

import socket as _socket
import struct

import pytest

from osniffy.config import Config

# ---------------------------------------------------------------------------
# Reusable Config fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_config() -> Config:
    """A fully-populated :class:`~osniffy.config.Config` for use in tests."""
    return Config(
        mysql_host="localhost",
        db_name="testdb",
        table_name="packets",
        mysql_user="user",
        mysql_pass="pass",
        mysql_user_grafana="grafana_user",
        mysql_pass_grafana="grafana_pass",
        grafana_host="localhost",
        grafana_port=3000,
        grafana_api_key="test_key",
        client_user="testuser",
    )


# ---------------------------------------------------------------------------
# Raw frame builders (used across parser and reader tests)
# ---------------------------------------------------------------------------

SRC_MAC = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
DST_MAC = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
SRC_IP = "192.168.1.100"
DST_IP = "10.0.0.1"


def build_eth_header(ethertype: int) -> bytes:
    """14-byte Ethernet II header."""
    return DST_MAC + SRC_MAC + struct.pack("!H", ethertype)


def build_ipv4_header(protocol: int, src: str = SRC_IP, dst: str = DST_IP) -> bytes:
    """20-byte IPv4 header (no options)."""
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # version=4, IHL=5
        0,
        40,  # total length
        0,
        0,  # id, frag offset
        64,  # TTL
        protocol,
        0,  # checksum (not validated)
        _socket.inet_aton(src),
        _socket.inet_aton(dst),
    )


def build_tcp_header(
    src_port: int = 54321,
    dst_port: int = 80,
    seq: int = 0,
    ack: int = 0,
    flags: int = 0,
    window: int = 65535,
) -> bytes:
    """20-byte TCP header."""
    return struct.pack(
        "!HH4s4sHHHH",
        src_port,
        dst_port,
        seq.to_bytes(4, "big"),
        ack.to_bytes(4, "big"),
        (5 << 12) | flags,  # data offset + flags
        window,
        0,  # checksum
        0,  # urgent pointer
    )


def build_udp_header(src_port: int = 1234, dst_port: int = 53, length: int = 8) -> bytes:
    """8-byte UDP header."""
    return struct.pack("!HHHH", src_port, dst_port, length, 0)


def build_icmp_header(type_: int = 8, code: int = 0) -> bytes:
    """8-byte ICMP header (echo request by default)."""
    return struct.pack("!BBH4s", type_, code, 0, b"\x00" * 4)


def build_arp_header(src_ip: str = SRC_IP, dst_ip: str = DST_IP) -> bytes:
    """28-byte ARP header (Ethernet/IPv4)."""
    return struct.pack(
        "!HHBBH6s4s6s4s",
        1,  # hardware type: Ethernet
        0x0800,  # protocol type: IPv4
        6,  # hardware address length
        4,  # protocol address length
        1,  # opcode: request
        SRC_MAC,
        _socket.inet_aton(src_ip),
        DST_MAC,
        _socket.inet_aton(dst_ip),
    )
