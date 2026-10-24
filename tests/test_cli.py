"""Unit tests for osniffy.cli – argument parser and main() exit codes."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from osniffy.cli import _build_parser, main

_MINIMAL_ENV = {
    "MYSQL_HOST": "localhost",
    "DB_NAME": "testdb",
    "TABLE_NAME": "packets",
    "MYSQL_USER": "user",
    "MYSQL_PASS": "pass",
}


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


class TestArgumentParser:
    def test_sniffer_mode(self) -> None:
        args = _build_parser().parse_args(["-s"])
        assert args.sniffer is True
        assert args.reader is None

    def test_sniffer_long_flag(self) -> None:
        args = _build_parser().parse_args(["--sniffer"])
        assert args.sniffer is True

    def test_reader_mode(self) -> None:
        args = _build_parser().parse_args(["-r", "/tmp/cap.pcap"])
        assert args.reader == "/tmp/cap.pcap"
        assert args.sniffer is False

    def test_reader_long_flag(self) -> None:
        args = _build_parser().parse_args(["--reader", "/tmp/cap.pcap"])
        assert args.reader == "/tmp/cap.pcap"

    def test_mutually_exclusive_flags_rejected(self) -> None:
        with pytest.raises(SystemExit):
            _build_parser().parse_args(["-s", "-r", "/tmp/cap.pcap"])

    def test_no_mode_rejected(self) -> None:
        with pytest.raises(SystemExit):
            _build_parser().parse_args([])

    def test_log_level_default(self) -> None:
        args = _build_parser().parse_args(["-s"])
        assert args.log_level == "INFO"

    def test_log_level_custom(self) -> None:
        args = _build_parser().parse_args(["-s", "--log-level", "DEBUG"])
        assert args.log_level == "DEBUG"

    def test_skip_dashboard_flag(self) -> None:
        args = _build_parser().parse_args(["-r", "/tmp/f.pcap", "--skip-dashboard"])
        assert args.skip_dashboard is True

    def test_skip_dashboard_default_false(self) -> None:
        args = _build_parser().parse_args(["-r", "/tmp/f.pcap"])
        assert args.skip_dashboard is False

    def test_env_file_option(self) -> None:
        args = _build_parser().parse_args(["-s", "--env-file", "/etc/osniffy.env"])
        assert args.env_file == "/etc/osniffy.env"

    def test_version_exits(self) -> None:
        with pytest.raises(SystemExit) as exc:
            _build_parser().parse_args(["--version"])
        assert exc.value.code == 0


# ---------------------------------------------------------------------------
# main() exit codes
# ---------------------------------------------------------------------------


class TestMainExitCodes:
    def test_missing_config_returns_2(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            result = main(["-s"])
        assert result == 2

    def test_nonexistent_file_returns_1(self, tmp_path: pytest.TempPathFactory) -> None:
        nonexistent = str(tmp_path / "nonexistent.pcap")
        with patch.dict(os.environ, _MINIMAL_ENV, clear=True):
            with patch("osniffy.db.repository.MySQLRepository.connect"):
                result = main(["-r", nonexistent, "--skip-dashboard"])
        assert result == 1

    def test_reader_db_connect_failure_returns_1(self, tmp_path: pytest.TempPathFactory) -> None:
        pcap = tmp_path / "dummy.pcap"
        pcap.write_bytes(b"\x00" * 24)
        import mysql.connector

        with patch.dict(os.environ, _MINIMAL_ENV, clear=True):
            with patch(
                "osniffy.db.repository.MySQLRepository.connect",
                side_effect=mysql.connector.Error("connection refused"),
            ):
                result = main(["-r", str(pcap), "--skip-dashboard"])
        assert result == 1

    def test_sniffer_non_root_returns_1(self) -> None:
        with patch.dict(os.environ, {**_MINIMAL_ENV, "USER": "alice"}, clear=True):
            with patch("osniffy.db.repository.MySQLRepository.connect"):
                # os.name is "posix" on Linux CI; patch USER to non-root
                with patch("os.name", "posix"):
                    result = main(["-s", "--skip-dashboard"])
        assert result == 1
