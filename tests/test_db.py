"""Unit tests for osniffy.db.repository – filtering, row-building, and insert logic."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from osniffy.config import Config
from osniffy.db.repository import MySQLRepository
from osniffy.protocol.frames import ARP, ICMP, TCP, UDP, Ethernet, IPv4, Packet


@pytest.fixture
def cfg() -> Config:
    return Config(
        mysql_host="localhost",
        db_name="testdb",
        table_name="packets",
        mysql_user="user",
        mysql_pass="pass",
        mysql_user_grafana="grafana",
        mysql_pass_grafana="gpass",
        grafana_host="localhost",
        grafana_port=3000,
        grafana_api_key="key",
        client_user="tester",
    )


@pytest.fixture
def mock_conn() -> tuple[MagicMock, MagicMock]:
    """Return (connection_mock, cursor_mock)."""
    cursor = MagicMock()
    conn = MagicMock()
    conn.is_connected.return_value = True
    conn.cursor.return_value = cursor
    return conn, cursor


def _make_repo(cfg: Config, conn: MagicMock) -> MySQLRepository:
    repo = MySQLRepository(cfg)
    repo._conn = conn
    return repo


# ---------------------------------------------------------------------------
# _should_insert
# ---------------------------------------------------------------------------


class TestShouldInsert:
    def test_unlabeled_packet_excluded(self) -> None:
        assert MySQLRepository._should_insert(Packet(label="")) is False

    def test_arp_included(self) -> None:
        assert MySQLRepository._should_insert(Packet(label="ARP")) is True

    def test_icmp_included(self) -> None:
        assert MySQLRepository._should_insert(Packet(label="ICMP")) is True

    def test_udp_included(self) -> None:
        assert MySQLRepository._should_insert(Packet(label="UDP")) is True

    def test_tcp_external_included(self) -> None:
        pkt = Packet(
            label="TCP",
            layer3=IPv4(source="192.168.1.1", destination="10.0.0.1"),
            layer4=TCP(source=54321, destination=80),
        )
        assert MySQLRepository._should_insert(pkt) is True

    def test_tcp_loopback_mysql_port_excluded(self) -> None:
        pkt = Packet(
            label="TCP",
            layer3=IPv4(source="127.0.0.1", destination="127.0.0.1"),
            layer4=TCP(source=45678, destination=3306),
        )
        assert MySQLRepository._should_insert(pkt) is False

    def test_tcp_loopback_grafana_port_excluded(self) -> None:
        pkt = Packet(
            label="TCP",
            layer3=IPv4(source="127.0.0.1", destination="127.0.0.1"),
            layer4=TCP(source=3000, destination=54321),
        )
        assert MySQLRepository._should_insert(pkt) is False

    def test_tcp_loopback_non_internal_port_included(self) -> None:
        pkt = Packet(
            label="TCP",
            layer3=IPv4(source="127.0.0.1", destination="127.0.0.1"),
            layer4=TCP(source=8080, destination=9090),
        )
        assert MySQLRepository._should_insert(pkt) is True


# ---------------------------------------------------------------------------
# _packet_to_row
# ---------------------------------------------------------------------------

_TS = datetime(2024, 6, 1, 12, 0, 0)


class TestPacketToRow:
    def test_tcp_packet_row(self) -> None:
        pkt = Packet(
            label="TCP",
            layer2=Ethernet(
                source="AA:BB:CC:DD:EE:FF", destination="11:22:33:44:55:66", ethertype="0x800"
            ),
            layer3=IPv4(source="192.168.1.1", destination="10.0.0.1", protocol=6),
            layer4=TCP(source=54321, destination=80),
            time=_TS,
        )
        row = MySQLRepository._packet_to_row(pkt)
        assert row[0] == "AA:BB:CC:DD:EE:FF"  # srcMAC
        assert row[1] == "11:22:33:44:55:66"  # dstMAC
        assert row[2] == "0x800"  # etherType
        assert row[3] == "192.168.1.1"  # srcIP
        assert row[4] == "10.0.0.1"  # dstIP
        assert row[5] == 6  # protocol
        assert row[6] == 54321  # srcPort
        assert row[7] == 80  # dstPort
        assert row[8] == _TS  # timestamp

    def test_udp_packet_row(self) -> None:
        pkt = Packet(
            label="UDP",
            layer2=Ethernet(
                source="11:22:33:44:55:66", destination="FF:FF:FF:FF:FF:FF", ethertype="0x800"
            ),
            layer3=IPv4(source="1.2.3.4", destination="5.6.7.8", protocol=17),
            layer4=UDP(source=1234, destination=53),
            time=_TS,
        )
        row = MySQLRepository._packet_to_row(pkt)
        assert row[5] == 17  # protocol
        assert row[6] == 1234  # srcPort
        assert row[7] == 53  # dstPort

    def test_icmp_packet_row_no_ports(self) -> None:
        pkt = Packet(
            label="ICMP",
            layer2=Ethernet(
                source="AA:BB:CC:DD:EE:FF", destination="11:22:33:44:55:66", ethertype="0x800"
            ),
            layer3=IPv4(source="1.1.1.1", destination="2.2.2.2", protocol=1),
            layer4=ICMP(type=8, code=0),
            time=_TS,
        )
        row = MySQLRepository._packet_to_row(pkt)
        assert row[5] == 1  # protocol
        assert row[6] is None  # srcPort (ICMP has no ports)
        assert row[7] is None  # dstPort

    def test_arp_packet_row(self) -> None:
        pkt = Packet(
            label="ARP",
            layer2=Ethernet(
                source="AA:BB:CC:DD:EE:FF", destination="FF:FF:FF:FF:FF:FF", ethertype="0x806"
            ),
            layer3=ARP(proto_source="192.168.1.1", proto_destination="10.0.0.1"),
            time=_TS,
        )
        row = MySQLRepository._packet_to_row(pkt)
        assert row[3] == "192.168.1.1"  # srcIP from ARP
        assert row[4] == "10.0.0.1"  # dstIP from ARP
        assert row[5] is None  # protocol (ARP has no IP protocol number)

    def test_fallback_timestamp_when_none(self) -> None:
        pkt = Packet(
            label="UDP",
            layer2=Ethernet(
                source="AA:BB:CC:DD:EE:FF", destination="11:22:33:44:55:66", ethertype="0x800"
            ),
            layer3=IPv4(source="1.2.3.4", destination="5.6.7.8", protocol=17),
            layer4=UDP(source=1234, destination=53),
            time=None,  # no timestamp set
        )
        row = MySQLRepository._packet_to_row(pkt)
        assert isinstance(row[8], datetime)

    def test_none_layer2_yields_empty_macs(self) -> None:
        pkt = Packet(label="ARP", layer2=None, time=_TS)
        row = MySQLRepository._packet_to_row(pkt)
        assert row[0] == ""  # srcMAC
        assert row[1] == ""  # dstMAC


# ---------------------------------------------------------------------------
# insert_batch
# ---------------------------------------------------------------------------


class TestInsertBatch:
    def test_empty_batch_is_noop(self, cfg: Config, mock_conn: tuple[MagicMock, MagicMock]) -> None:
        conn, cursor = mock_conn
        repo = _make_repo(cfg, conn)
        repo.insert_batch([])
        cursor.executemany.assert_not_called()
        conn.commit.assert_not_called()

    def test_all_filtered_packets_is_noop(
        self, cfg: Config, mock_conn: tuple[MagicMock, MagicMock]
    ) -> None:
        conn, cursor = mock_conn
        repo = _make_repo(cfg, conn)
        # Unlabeled packet – _should_insert returns False
        repo.insert_batch([Packet(label="")])
        cursor.executemany.assert_not_called()

    def test_single_packet_inserted(
        self, cfg: Config, mock_conn: tuple[MagicMock, MagicMock]
    ) -> None:
        conn, cursor = mock_conn
        repo = _make_repo(cfg, conn)
        pkt = Packet(
            label="UDP",
            layer2=Ethernet(
                source="AA:BB:CC:DD:EE:FF", destination="11:22:33:44:55:66", ethertype="0x800"
            ),
            layer3=IPv4(source="1.2.3.4", destination="5.6.7.8", protocol=17),
            layer4=UDP(source=1234, destination=53),
            time=_TS,
        )
        repo.insert_batch([pkt])
        cursor.executemany.assert_called_once()
        conn.commit.assert_called_once()
        cursor.close.assert_called_once()

    def test_multiple_packets_inserted_in_one_call(
        self, cfg: Config, mock_conn: tuple[MagicMock, MagicMock]
    ) -> None:
        conn, cursor = mock_conn
        repo = _make_repo(cfg, conn)
        pkts = [
            Packet(
                label="UDP",
                layer2=Ethernet(
                    source="AA:BB:CC:DD:EE:FF", destination="11:22:33:44:55:66", ethertype="0x800"
                ),
                layer3=IPv4(source="1.2.3.4", destination="5.6.7.8", protocol=17),
                layer4=UDP(source=1234, destination=53),
                time=_TS,
            )
            for _ in range(5)
        ]
        repo.insert_batch(pkts)
        # executemany should be called once with 5 rows
        args = cursor.executemany.call_args
        rows = args[0][1]
        assert len(rows) == 5

    def test_rollback_on_error(self, cfg: Config, mock_conn: tuple[MagicMock, MagicMock]) -> None:
        import mysql.connector

        conn, cursor = mock_conn
        cursor.executemany.side_effect = mysql.connector.Error("disk full")
        repo = _make_repo(cfg, conn)
        pkt = Packet(
            label="UDP",
            layer2=Ethernet(
                source="AA:BB:CC:DD:EE:FF", destination="11:22:33:44:55:66", ethertype="0x800"
            ),
            layer3=IPv4(source="1.2.3.4", destination="5.6.7.8", protocol=17),
            layer4=UDP(source=1234, destination=53),
            time=_TS,
        )
        with pytest.raises(mysql.connector.Error):
            repo.insert_batch([pkt])
        conn.rollback.assert_called_once()


# ---------------------------------------------------------------------------
# insert_packet (delegates to insert_batch)
# ---------------------------------------------------------------------------


class TestInsertPacket:
    def test_delegates_to_insert_batch(
        self, cfg: Config, mock_conn: tuple[MagicMock, MagicMock]
    ) -> None:
        conn, cursor = mock_conn
        repo = _make_repo(cfg, conn)
        pkt = Packet(
            label="TCP",
            layer2=Ethernet(
                source="AA:BB:CC:DD:EE:FF", destination="11:22:33:44:55:66", ethertype="0x800"
            ),
            layer3=IPv4(source="1.2.3.4", destination="5.6.7.8", protocol=6),
            layer4=TCP(source=54321, destination=80),
            time=_TS,
        )
        repo.insert_packet(pkt)
        cursor.executemany.assert_called_once()


# ---------------------------------------------------------------------------
# close
# ---------------------------------------------------------------------------


class TestClose:
    def test_closes_open_connection(
        self, cfg: Config, mock_conn: tuple[MagicMock, MagicMock]
    ) -> None:
        conn, _ = mock_conn
        repo = _make_repo(cfg, conn)
        repo.close()
        conn.close.assert_called_once()

    def test_safe_when_no_connection(self, cfg: Config) -> None:
        repo = MySQLRepository(cfg)
        assert repo._conn is None
        repo.close()  # should not raise


# ---------------------------------------------------------------------------
# connect (mocked mysql.connector)
# ---------------------------------------------------------------------------


class TestConnect:
    def test_connect_calls_ensure_schema(self, cfg: Config) -> None:
        conn = MagicMock()
        conn.is_connected.return_value = True
        cursor = MagicMock()
        conn.cursor.return_value = cursor

        with patch("mysql.connector.connect", return_value=conn):
            repo = MySQLRepository(cfg)
            repo.connect()

        # _ensure_schema runs CREATE DATABASE + USE + CREATE TABLE
        assert cursor.execute.called

    def test_connect_retries_then_raises(self, cfg: Config) -> None:
        import mysql.connector as mc

        with patch("mysql.connector.connect", side_effect=mc.Error("refused")):
            with patch("time.sleep"):  # speed up retries
                repo = MySQLRepository(cfg)
                with pytest.raises(mc.Error):
                    repo.connect()


# ---------------------------------------------------------------------------
# get_time_range
# ---------------------------------------------------------------------------


class TestGetTimeRange:
    def test_returns_millisecond_timestamps(
        self, cfg: Config, mock_conn: tuple[MagicMock, MagicMock]
    ) -> None:
        conn, cursor = mock_conn
        ts_start = datetime(2024, 1, 1, 0, 0, 0)
        ts_end = datetime(2024, 1, 1, 1, 0, 0)
        cursor.fetchone.return_value = (ts_start, ts_end)

        repo = _make_repo(cfg, conn)
        start_ms, end_ms = repo.get_time_range()

        assert start_ms == int(ts_start.timestamp()) * 1000
        assert end_ms == int(ts_end.timestamp()) * 1000

    def test_raises_when_table_empty(
        self, cfg: Config, mock_conn: tuple[MagicMock, MagicMock]
    ) -> None:
        conn, cursor = mock_conn
        cursor.fetchone.return_value = (None, None)

        repo = _make_repo(cfg, conn)
        with pytest.raises(ValueError, match="No packets found"):
            repo.get_time_range()
