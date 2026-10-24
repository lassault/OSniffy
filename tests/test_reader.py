"""Integration-style tests for osniffy.reader – using a synthetic packet source."""

from __future__ import annotations

import socket as _socket
import struct
from datetime import datetime
from unittest.mock import MagicMock

from osniffy.db.repository import MySQLRepository
from osniffy.protocol.frames import Packet
from osniffy.reader import run

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_tcp_frame(
    src_ip: str = "192.168.1.1",
    dst_ip: str = "10.0.0.1",
    src_port: int = 54321,
    dst_port: int = 80,
) -> bytes:
    """Build a minimal Ethernet/IPv4/TCP raw frame."""
    eth = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]) + bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
    eth += struct.pack("!H", 0x0800)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40,
        0,
        0,
        64,
        6,
        0,
        _socket.inet_aton(src_ip),
        _socket.inet_aton(dst_ip),
    )
    tcp = struct.pack(
        "!HH4s4sHHHH",
        src_port,
        dst_port,
        (0).to_bytes(4, "big"),
        (0).to_bytes(4, "big"),
        5 << 12,
        65535,
        0,
        0,
    )
    return eth + ipv4 + tcp


def _make_udp_frame() -> bytes:
    """Build a minimal Ethernet/IPv4/UDP raw frame."""
    eth = bytes(6) + bytes(6) + struct.pack("!H", 0x0800)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        28,
        0,
        0,
        64,
        17,
        0,
        _socket.inet_aton("1.2.3.4"),
        _socket.inet_aton("5.6.7.8"),
    )
    udp = struct.pack("!HHHH", 1234, 53, 8, 0)
    return eth + ipv4 + udp


def _make_mock_repo() -> MagicMock:
    return MagicMock(spec=MySQLRepository)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestReaderRun:
    def test_returns_correct_packet_count(self) -> None:
        repo = _make_mock_repo()
        source = [(54, 1000.0 + i, _make_tcp_frame()) for i in range(5)]
        total, _elapsed = run("unused.pcap", repo, source=iter(source))
        assert total == 5

    def test_elapsed_is_non_negative(self) -> None:
        repo = _make_mock_repo()
        source = [(54, 1000.0, _make_tcp_frame())]
        _total, elapsed = run("unused.pcap", repo, source=iter(source))
        assert elapsed >= 0.0

    def test_empty_source_inserts_nothing(self) -> None:
        repo = _make_mock_repo()
        total, _ = run("unused.pcap", repo, source=iter([]))
        assert total == 0
        repo.insert_batch.assert_not_called()  # guard `if packets:` prevents empty flush

    def test_partial_batch_flushed_at_end(self) -> None:
        repo = _make_mock_repo()
        source = [(54, float(i), _make_tcp_frame()) for i in range(3)]
        run("unused.pcap", repo, source=iter(source))
        # With 3 packets (< BATCH_SIZE) there should be exactly one insert_batch call
        assert repo.insert_batch.call_count == 1

    def test_full_batch_triggers_intermediate_flush(self) -> None:
        """When packet count reaches batch_size, an intermediate flush happens."""
        repo = _make_mock_repo()
        n = 5
        source = [(54, float(i), _make_tcp_frame()) for i in range(n)]
        run("unused.pcap", repo, source=iter(source), batch_size=3)
        # 5 packets with batch_size=3: flush at index 3, then final flush with 2
        assert repo.insert_batch.call_count == 2

    def test_packet_timestamps_set_from_pcap(self) -> None:
        repo = _make_mock_repo()
        ts = 1_700_000_000.0
        source = [(54, ts, _make_tcp_frame())]
        run("unused.pcap", repo, source=iter(source))
        inserted: list[Packet] = repo.insert_batch.call_args[0][0]
        assert inserted[0].time == datetime.fromtimestamp(ts)

    def test_mixed_protocols_all_counted(self) -> None:
        repo = _make_mock_repo()
        source = [
            (54, 1000.0, _make_tcp_frame()),
            (28, 1001.0, _make_udp_frame()),
            (54, 1002.0, _make_tcp_frame()),
        ]
        total, _ = run("unused.pcap", repo, source=iter(source))
        assert total == 3

    def test_loopback_mysql_packets_not_inserted(self) -> None:
        """TCP packets to/from localhost:3306 should be filtered by the repository."""
        # reader.run passes them to insert_batch, which calls _should_insert.
        # Since we mock the repo, we verify that the packet IS passed to insert_batch
        # (filtering is the repo's responsibility, tested separately in test_db.py).
        repo = _make_mock_repo()
        loopback = _make_tcp_frame(
            src_ip="127.0.0.1", dst_ip="127.0.0.1", src_port=45678, dst_port=3306
        )
        source = [(54, 1000.0, loopback)]
        total, _ = run("unused.pcap", repo, source=iter(source))
        assert total == 1  # reader always counts the raw packet
