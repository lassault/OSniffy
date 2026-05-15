"""Live packet sniffer using raw sockets.

The sniffer must be run as *root* on Linux (or with appropriate capabilities).
On Windows, ``AF_INET`` raw sockets are used instead of ``AF_PACKET``.

No module-level socket is created; the socket is instantiated inside
:func:`run` so that importing this module is always safe.
"""

from __future__ import annotations

import logging
import os
import socket

from .db.repository import MySQLRepository
from .protocol.parser import PacketParser

logger = logging.getLogger(__name__)


def _create_raw_socket() -> socket.socket:
    """Return a raw socket appropriate for the current operating system."""
    if os.name == "nt":  # Windows
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind(("0.0.0.0", 0))  # noqa: S104 – intentional wildcard for raw capture
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # type: ignore[attr-defined]
    else:  # Linux / BSD
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    return s


def run(repository: MySQLRepository) -> None:
    """Capture packets forever, inserting each into *repository*.

    Blocks until interrupted by ``KeyboardInterrupt`` (Ctrl-C).

    Parameters
    ----------
    repository:
        An already-connected :class:`~osniffy.db.repository.MySQLRepository`.
    """
    parser = PacketParser()
    sock = _create_raw_socket()
    logger.info("Sniffer started – press Ctrl-C to stop")

    try:
        while True:
            raw_data, _ = sock.recvfrom(65535)
            try:
                packet = parser.parse_packet(raw_data)
                if packet.label:
                    repository.insert_packet(packet)
            except Exception:  # noqa: BLE001
                logger.exception("Unexpected error processing a packet – continuing")
    except KeyboardInterrupt:
        logger.info("Sniffer stopped by user")
    finally:
        sock.close()
        repository.close()
