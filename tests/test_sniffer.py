"""Unit tests for osniffy.sniffer – socket creation and run() control flow."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from osniffy.db.repository import MySQLRepository
from osniffy.sniffer import _create_raw_socket, run


class TestCreateRawSocket:
    def test_linux_uses_af_packet(self) -> None:
        mock_sock = MagicMock()
        with (
            patch("os.name", "posix"),
            patch("osniffy.sniffer.socket.socket", return_value=mock_sock) as mock_cls,
        ):
            sock = _create_raw_socket()

        import socket as _socket

        mock_cls.assert_called_once_with(
            _socket.AF_PACKET,
            _socket.SOCK_RAW,
            _socket.ntohs(0x0003),
        )
        assert sock is mock_sock

    def test_windows_uses_af_inet(self) -> None:
        mock_sock = MagicMock()
        import socket as _socket

        # SIO_RCVALL and RCVALL_ON are Windows-only; mock them so the test
        # runs on Linux CI without AttributeError.
        with (
            patch("os.name", "nt"),
            patch("osniffy.sniffer.socket.socket", return_value=mock_sock) as mock_cls,
            patch.object(_socket, "SIO_RCVALL", 0x98000001, create=True),
            patch.object(_socket, "RCVALL_ON", 1, create=True),
        ):
            sock = _create_raw_socket()

        mock_cls.assert_called_once_with(
            _socket.AF_INET,
            _socket.SOCK_RAW,
            _socket.IPPROTO_IP,
        )
        assert sock is mock_sock


class TestSnifferRun:
    def _make_repo(self) -> MagicMock:
        return MagicMock(spec=MySQLRepository)

    def test_stops_on_keyboard_interrupt(self) -> None:
        """run() should return cleanly on KeyboardInterrupt."""
        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = KeyboardInterrupt
        repo = self._make_repo()

        with patch("osniffy.sniffer._create_raw_socket", return_value=mock_sock):
            run(repo)  # should not raise

        mock_sock.close.assert_called_once()

    def test_packet_parse_error_continues(self) -> None:
        """A single bad packet should not kill the sniffer loop."""
        raw_good = bytes(60)  # silently skipped (too short for label), not an error
        mock_sock = MagicMock()
        # First call returns data, second raises KeyboardInterrupt to stop loop.
        mock_sock.recvfrom.side_effect = [
            (raw_good, ("192.168.1.1", 0)),
            KeyboardInterrupt,
        ]
        repo = self._make_repo()

        with patch("osniffy.sniffer._create_raw_socket", return_value=mock_sock):
            run(repo)

        # Socket is closed even after abrupt stop
        mock_sock.close.assert_called_once()


class TestMain:
    def test_main_module_importable(self) -> None:
        import osniffy.__main__  # noqa: F401 – just verify it imports cleanly
