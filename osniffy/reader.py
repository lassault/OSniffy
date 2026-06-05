"""Pcap file reader.

Reads a packet capture file and inserts packets into the database in
configurable batches (default: :data:`~osniffy.db.repository.BATCH_SIZE`).

The optional *source* parameter makes the reader fully testable without an
actual pcap file or libpcap installation – pass any iterable that yields
``(incl_len, timestamp_float, raw_bytes)`` tuples.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable
from datetime import datetime

from .db.repository import BATCH_SIZE, MySQLRepository
from .protocol.frames import Packet
from .protocol.parser import PacketParser

logger = logging.getLogger(__name__)

# Type alias for the raw packet stream
RawPacketSource = Iterable[tuple[int, float, bytes]]


def _default_source(file: str) -> RawPacketSource:
    """Open a pcap file via pylibpcap (imported lazily to keep tests light)."""
    from pylibpcap.pcap import rpcap  # type: ignore[import]

    return rpcap(file)  # type: ignore[no-any-return]


def run(
    file: str,
    repository: MySQLRepository,
    *,
    source: RawPacketSource | None = None,
    batch_size: int = BATCH_SIZE,
) -> tuple[int, float]:
    """Read packets from *file* and persist them via *repository*.

    Parameters
    ----------
    file:
        Path to the pcap/pcapng capture file (only used when *source* is
        ``None``).
    repository:
        An already-connected :class:`~osniffy.db.repository.MySQLRepository`.
    source:
        Optional iterable of ``(incl_len, timestamp, raw_bytes)`` tuples.
        When provided, *file* is ignored.  Useful for unit testing.
    batch_size:
        Number of packets to accumulate before each ``INSERT`` call.

    Returns
    -------
    tuple[int, float]
        ``(total_packets, elapsed_seconds)``.
    """
    parser = PacketParser()
    packets: list[Packet] = []
    total = 0
    t_start = time.monotonic()

    it: RawPacketSource = source if source is not None else _default_source(file)

    try:
        for _incl_len, timestamp, raw in it:
            if len(packets) >= batch_size:
                repository.insert_batch(packets)
                packets.clear()

            packet = parser.parse_packet(raw)
            packet.time = datetime.fromtimestamp(timestamp)
            packets.append(packet)
            total += 1
    finally:
        # Always flush the remaining partial batch.
        if packets:
            repository.insert_batch(packets)

    elapsed = time.monotonic() - t_start
    logger.info("Processed %d packets in %.2f s", total, elapsed)
    return total, elapsed
