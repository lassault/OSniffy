"""Network protocol frame data-classes.

Each class represents a parsed protocol header.  Using :mod:`dataclasses`
gives us free ``__repr__``, equality, and (optionally) frozen instances
without boilerplate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Ethernet:
    """IEEE 802.3 Ethernet II frame header."""

    destination: str = ""
    source: str = ""
    ethertype: str = ""


@dataclass
class ARP:
    """Address Resolution Protocol header (RFC 826)."""

    hard_type: int = 0
    protocol: str = ""
    opcode: int = 0
    hard_source: str = ""
    proto_source: str = ""
    hard_destination: str = ""
    proto_destination: str = ""


@dataclass
class IPv4:
    """Internet Protocol version 4 header (RFC 791)."""

    version: int = 0
    total_length: int = 0
    ttl: int = 0
    protocol: int = 0
    source: str = ""
    destination: str = ""


@dataclass
class ICMP:
    """Internet Control Message Protocol header (RFC 792)."""

    type: int = 0
    code: int = 0
    rest: str = ""


@dataclass
class TCP:
    """Transmission Control Protocol header (RFC 793)."""

    source: int = 0
    destination: int = 0
    sequence_number: str = ""
    ack: str = ""
    flags: int = 0
    window_size: int = 0


@dataclass
class UDP:
    """User Datagram Protocol header (RFC 768)."""

    source: int = 0
    destination: int = 0
    length: int = 0


@dataclass
class Packet:
    """A fully parsed network packet, up to layer 4.

    Fields are typed as ``| None`` so callers can check which layers were
    successfully parsed before accessing them.
    """

    layer2: Ethernet | None = None
    layer3: IPv4 | ARP | None = None
    layer4: ICMP | TCP | UDP | None = None
    label: str = ""          # "ARP" | "ICMP" | "TCP" | "UDP" | ""
    time: datetime | None = None
