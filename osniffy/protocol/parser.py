"""Raw-byte → typed-frame protocol parser.

All parsing is done via :mod:`struct` for zero-copy efficiency.  Each method
returns a new frame dataclass; no mutable state is held between calls, making
:class:`PacketParser` safe to use from multiple threads.
"""

from __future__ import annotations

import binascii
import socket as _socket
import struct

from .frames import ARP, ICMP, TCP, UDP, Ethernet, IPv4, Packet

# Ethertype constants
_ETH_IPV4 = 0x0800
_ETH_ARP = 0x0806
_ETH_IPV6 = 0x86DD

# IP protocol number constants
_PROTO_ICMP = 1
_PROTO_TCP = 6
_PROTO_UDP = 17


def _mac_bytes_to_str(raw: bytes) -> str:
    """Convert 6 raw MAC bytes to canonical upper-case colon notation."""
    return ":".join(f"{b:02x}" for b in raw).upper()


class PacketParser:
    """Stateless parser that converts raw frame bytes into typed dataclasses."""

    # ------------------------------------------------------------------
    # Individual header parsers
    # ------------------------------------------------------------------

    def ethernet_header(self, frame: bytes) -> Ethernet:
        """Parse a 14-byte Ethernet II header.

        Raises
        ------
        ValueError
            If *frame* is shorter than 14 bytes.
        """
        if len(frame) < 14:
            raise ValueError(f"Ethernet frame too short: {len(frame)} bytes (need 14)")
        dst_raw, src_raw, ethertype_int = struct.unpack("!6s6sH", frame[:14])
        return Ethernet(
            destination=_mac_bytes_to_str(dst_raw),
            source=_mac_bytes_to_str(src_raw),
            ethertype=hex(ethertype_int),
        )

    def arp_header(self, frame: bytes) -> ARP:
        """Parse a 28-byte ARP header (Ethernet + IPv4 variant).

        Raises
        ------
        ValueError
            If *frame* is shorter than 28 bytes.
        """
        if len(frame) < 28:
            raise ValueError(f"ARP frame too short: {len(frame)} bytes (need 28)")
        data = struct.unpack("!HHBBH6s4s6s4s", frame[:28])
        return ARP(
            hard_type=data[0],
            protocol=hex(data[1]),
            opcode=data[4],
            hard_source=_mac_bytes_to_str(data[5]),
            proto_source=_socket.inet_ntoa(data[6]),
            hard_destination=_mac_bytes_to_str(data[7]),
            proto_destination=_socket.inet_ntoa(data[8]),
        )

    def ipv4_header(self, frame: bytes) -> IPv4:
        """Parse a 20-byte IPv4 header (options not decoded).

        Raises
        ------
        ValueError
            If *frame* is shorter than 20 bytes.
        """
        if len(frame) < 20:
            raise ValueError(f"IPv4 header too short: {len(frame)} bytes (need 20)")
        data = struct.unpack("!BBHHHBBH4s4s", frame[:20])
        return IPv4(
            version=(data[0] & 0xF0) >> 4,
            total_length=data[2],
            ttl=data[5],
            protocol=data[6],
            source=_socket.inet_ntoa(data[8]),
            destination=_socket.inet_ntoa(data[9]),
        )

    def icmp_header(self, frame: bytes) -> ICMP:
        """Parse an 8-byte ICMP header.

        Raises
        ------
        ValueError
            If *frame* is shorter than 8 bytes.
        """
        if len(frame) < 8:
            raise ValueError(f"ICMP header too short: {len(frame)} bytes (need 8)")
        data = struct.unpack("!BBH4s", frame[:8])
        return ICMP(
            type=data[0],
            code=data[1],
            rest=binascii.hexlify(data[3]).decode("ascii"),
        )

    def tcp_header(self, frame: bytes) -> TCP:
        """Parse a 20-byte TCP header (options not decoded).

        Raises
        ------
        ValueError
            If *frame* is shorter than 20 bytes.
        """
        if len(frame) < 20:
            raise ValueError(f"TCP header too short: {len(frame)} bytes (need 20)")
        data = struct.unpack("!HH4s4sHHHH", frame[:20])
        return TCP(
            source=data[0],
            destination=data[1],
            sequence_number=str(int(binascii.hexlify(data[2]), 16)),
            ack=str(int(binascii.hexlify(data[3]), 16)),
            flags=data[4] & 0x1FF,
            window_size=data[5],
        )

    def udp_header(self, frame: bytes) -> UDP:
        """Parse an 8-byte UDP header.

        Raises
        ------
        ValueError
            If *frame* is shorter than 8 bytes.
        """
        if len(frame) < 8:
            raise ValueError(f"UDP header too short: {len(frame)} bytes (need 8)")
        data = struct.unpack("!HHHH", frame[:8])
        return UDP(source=data[0], destination=data[1], length=data[2])

    # ------------------------------------------------------------------
    # Full-packet parser
    # ------------------------------------------------------------------

    def parse_packet(self, raw: bytes) -> Packet:
        """Parse a complete raw Ethernet frame into a :class:`~.frames.Packet`.

        Unknown or unsupported ethertypes/protocols result in a :class:`~.frames.Packet`
        with an empty *label* rather than raising an exception, so the caller
        can safely filter on ``packet.label``.
        """
        packet = Packet()

        if len(raw) < 14:
            return packet

        try:
            eth = self.ethernet_header(raw[:14])
        except (ValueError, struct.error):
            return packet

        packet.layer2 = eth
        ethertype = int(eth.ethertype, 16)

        if ethertype == _ETH_IPV4:
            if len(raw) < 34:
                return packet
            try:
                ipv4 = self.ipv4_header(raw[14:34])
            except (ValueError, struct.error):
                return packet
            packet.layer3 = ipv4

            if ipv4.protocol == _PROTO_ICMP and len(raw) >= 42:
                try:
                    packet.layer4 = self.icmp_header(raw[34:42])
                    packet.label = "ICMP"
                except (ValueError, struct.error):
                    pass

            elif ipv4.protocol == _PROTO_TCP and len(raw) >= 54:
                try:
                    packet.layer4 = self.tcp_header(raw[34:54])
                    packet.label = "TCP"
                except (ValueError, struct.error):
                    pass

            elif ipv4.protocol == _PROTO_UDP and len(raw) >= 42:
                try:
                    packet.layer4 = self.udp_header(raw[34:42])
                    packet.label = "UDP"
                except (ValueError, struct.error):
                    pass
            # Other IP protocols are silently skipped.

        elif ethertype == _ETH_ARP:
            if len(raw) >= 42:
                try:
                    packet.layer3 = self.arp_header(raw[14:42])
                    packet.label = "ARP"
                except (ValueError, struct.error):
                    pass

        # IPv6 (0x86DD) and other ethertypes are silently skipped.

        return packet
