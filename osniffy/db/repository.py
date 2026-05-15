"""MySQL-backed packet repository.

Design goals
------------
* No module-level side-effects – the socket/connection is created only when
  :meth:`MySQLRepository.connect` is called explicitly.
* Automatic schema creation (``IF NOT EXISTS``) on first connect.
* Batch inserts via ``executemany`` to minimise round-trips.
* Connection retry with exponential back-off.
* Loopback MySQL/Grafana traffic is filtered before any DB write.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

import mysql.connector
from mysql.connector import MySQLConnection

from ..config import Config
from ..protocol.frames import ARP, ICMP, IPv4, TCP, UDP, Packet

logger = logging.getLogger(__name__)

# How many packets to send per ``executemany`` call (reader mode).
BATCH_SIZE = 10_000

_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 2.0  # seconds; multiplied by attempt number

# Internal ports to exclude from live-capture ingestion (MySQL, Grafana).
_INTERNAL_PORTS = frozenset({3306, 3000})

# ---------------------------------------------------------------------------
# DDL
# ---------------------------------------------------------------------------
_CREATE_TABLE_SQL = """\
CREATE TABLE IF NOT EXISTS `{table}` (
    packetID   INT UNSIGNED     NOT NULL AUTO_INCREMENT,
    srcMAC     CHAR(17)         NOT NULL,
    dstMAC     CHAR(17)         NOT NULL,
    etherType  VARCHAR(6)       NOT NULL,
    srcIP      VARCHAR(45)      NOT NULL DEFAULT '',
    dstIP      VARCHAR(45)      NOT NULL DEFAULT '',
    protocol   TINYINT UNSIGNED,
    srcPort    SMALLINT UNSIGNED,
    dstPort    SMALLINT UNSIGNED,
    `timestamp` DATETIME(3)     NOT NULL,
    PRIMARY KEY (packetID),
    INDEX idx_ts        (`timestamp`),
    INDEX idx_protocol  (protocol),
    INDEX idx_srcIP     (srcIP(15)),
    INDEX idx_dstIP     (dstIP(15))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
"""

_INSERT_SQL = """\
INSERT INTO `{table}`
    (srcMAC, dstMAC, etherType, srcIP, dstIP, protocol, srcPort, dstPort, `timestamp`)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
"""


class MySQLRepository:
    """Manages the MySQL connection and packet persistence."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._conn: MySQLConnection | None = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Open the database connection and ensure the schema exists.

        Retries up to :data:`_MAX_RETRIES` times with exponential back-off
        before re-raising the last :class:`mysql.connector.Error`.
        """
        last_exc: Exception | None = None
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                conn = mysql.connector.connect(
                    host=self._config.mysql_host,
                    user=self._config.mysql_user,
                    password=self._config.mysql_pass,
                )
                # MySQLConnection is the concrete type returned here.
                self._conn = conn  # type: ignore[assignment]
                logger.debug("Connected to MySQL at %s", self._config.mysql_host)
                self._ensure_schema()
                return
            except mysql.connector.Error as exc:
                last_exc = exc
                logger.warning(
                    "MySQL connection attempt %d/%d failed: %s",
                    attempt,
                    _MAX_RETRIES,
                    exc,
                )
                if attempt < _MAX_RETRIES:
                    time.sleep(_RETRY_BASE_DELAY * attempt)

        raise last_exc  # type: ignore[misc]

    def close(self) -> None:
        """Close the underlying connection if it is open."""
        if self._conn is not None and self._conn.is_connected():
            self._conn.close()
            logger.debug("MySQL connection closed")

    # ------------------------------------------------------------------
    # Schema management
    # ------------------------------------------------------------------

    def _ensure_schema(self) -> None:
        """Create the database and table if they do not already exist."""
        assert self._conn is not None

        cursor = self._conn.cursor()
        try:
            cursor.execute(
                "CREATE DATABASE IF NOT EXISTS `{db}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci".format(
                    db=self._config.db_name
                )
            )
            self._conn.commit()
            cursor.execute(f"USE `{self._config.db_name}`")
            cursor.execute(
                _CREATE_TABLE_SQL.format(table=self._config.table_name)
            )
            self._conn.commit()
        finally:
            cursor.close()

        logger.debug(
            "Schema verified for database '%s', table '%s'",
            self._config.db_name,
            self._config.table_name,
        )

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def insert_packet(self, packet: Packet) -> None:
        """Insert a single packet (sniffer mode)."""
        self.insert_batch([packet])

    def insert_batch(self, packets: list[Packet]) -> None:
        """Insert a list of packets in a single transaction.

        Packets that fail :meth:`_should_insert` (e.g. loopback MySQL/Grafana
        traffic) are silently excluded.  An empty resulting row-set is a
        no-op.
        """
        if not packets:
            return

        rows = [self._packet_to_row(p) for p in packets if self._should_insert(p)]
        if not rows:
            return

        assert self._conn is not None
        cursor = self._conn.cursor()
        try:
            cursor.executemany(
                _INSERT_SQL.format(table=self._config.table_name),
                rows,
            )
            self._conn.commit()
            logger.info("Inserted %d packet(s)", len(rows))
        except mysql.connector.Error:
            self._conn.rollback()
            raise
        finally:
            cursor.close()

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def get_time_range(self) -> tuple[int, int]:
        """Return ``(start_ms, end_ms)`` Unix-millisecond timestamps.

        Used to build the Grafana URL time range after a pcap read.

        Raises
        ------
        ValueError
            If the table is empty.
        """
        assert self._conn is not None
        cursor = self._conn.cursor()
        try:
            cursor.execute(
                "SELECT MIN(`timestamp`), MAX(`timestamp`) "
                "FROM `{table}`".format(table=self._config.table_name)
            )
            row = cursor.fetchone()
        finally:
            cursor.close()

        if row is None or row[0] is None:
            raise ValueError("No packets found – cannot determine time range")

        start_ms = int(row[0].timestamp()) * 1000
        end_ms = int(row[1].timestamp()) * 1000
        return start_ms, end_ms

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _should_insert(packet: Packet) -> bool:
        """Return *False* for unlabeled packets and internal loopback traffic.

        Filters out MySQL (3306) and Grafana (3000) loopback TCP connections
        that the sniffer would otherwise pick up when running on the same host.
        """
        if not packet.label:
            return False

        if packet.label == "TCP":
            l3 = packet.layer3
            l4 = packet.layer4
            if (
                isinstance(l3, IPv4)
                and isinstance(l4, TCP)
                and l3.source == "127.0.0.1"
                and l3.destination == "127.0.0.1"
                and (l4.source in _INTERNAL_PORTS or l4.destination in _INTERNAL_PORTS)
            ):
                return False

        return True

    @staticmethod
    def _packet_to_row(packet: Packet) -> tuple[Any, ...]:
        """Flatten a :class:`~.protocol.frames.Packet` into a DB row tuple."""
        l2 = packet.layer2
        l3 = packet.layer3
        l4 = packet.layer4
        ts = packet.time if packet.time is not None else datetime.now(tz=timezone.utc)

        src_ip = dst_ip = ""
        protocol: int | None = None
        src_port: int | None = None
        dst_port: int | None = None

        if isinstance(l3, IPv4):
            src_ip = l3.source
            dst_ip = l3.destination
            protocol = l3.protocol
        elif isinstance(l3, ARP):
            src_ip = l3.proto_source
            dst_ip = l3.proto_destination

        if isinstance(l4, (TCP, UDP)):
            src_port = l4.source
            dst_port = l4.destination

        return (
            l2.source if l2 else "",
            l2.destination if l2 else "",
            l2.ethertype if l2 else "",
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            ts,
        )
