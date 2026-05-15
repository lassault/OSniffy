"""Command-line interface for OSniffy.

Usage examples
--------------
.. code-block:: shell

    # Live capture (requires root / CAP_NET_RAW)
    sudo osniffy --sniffer

    # Read a capture file
    osniffy --reader traffic.pcap

    # Skip auto-opening the browser
    osniffy --reader traffic.pcap --skip-dashboard

    # Use a custom .env file
    osniffy --reader traffic.pcap --env-file /etc/osniffy.env
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

_BANNER = r"""
 ██████╗ ███████╗███╗   ██╗██╗███████╗███████╗██╗   ██╗
██╔═══██╗██╔════╝████╗  ██║██║██╔════╝██╔════╝╚██╗ ██╔╝
██║   ██║███████╗██╔██╗ ██║██║█████╗  █████╗   ╚████╔╝
██║   ██║╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝    ╚██╔╝
╚██████╔╝███████║██║ ╚████║██║██║     ██║        ██║
 ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝        ╚═╝
"""

# Exit codes
_EXIT_OK = 0
_EXIT_RUNTIME_ERROR = 1
_EXIT_CONFIG_ERROR = 2


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osniffy",
        description="A modern network packet capture and analysis tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "-s",
        "--sniffer",
        action="store_true",
        help="Run in live capture mode (requires root on Linux)",
    )
    mode.add_argument(
        "-r",
        "--reader",
        metavar="FILE",
        help="Read and analyse a .pcap capture file",
    )

    p.add_argument(
        "--env-file",
        metavar="FILE",
        default=None,
        help="Path to a custom .env configuration file",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )
    p.add_argument(
        "--skip-dashboard",
        action="store_true",
        help="Do not open the Grafana dashboard after reading",
    )
    p.add_argument(
        "--version",
        action="version",
        version="%(prog)s 2.0.0",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``osniffy`` command.

    Returns an integer exit code (0 = success, 1 = runtime error,
    2 = configuration error).
    """
    p = _build_parser()
    args = p.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    logger = logging.getLogger(__name__)

    print(_BANNER)

    # Lazy imports keep startup fast and allow unit-testing the CLI without
    # needing a live MySQL server.
    from .config import ConfigError, load_config
    from .db.repository import MySQLRepository

    try:
        cfg = load_config(args.env_file)
    except ConfigError as exc:
        logger.error("Configuration error: %s", exc)
        return _EXIT_CONFIG_ERROR

    repo = MySQLRepository(cfg)
    try:
        repo.connect()
    except Exception as exc:  # noqa: BLE001
        logger.error("Cannot connect to MySQL at '%s': %s", cfg.mysql_host, exc)
        return _EXIT_RUNTIME_ERROR

    if args.sniffer:
        if os.name != "nt" and os.getenv("USER") != "root":
            logger.error(
                "Sniffer mode requires root privileges on Linux. Try: sudo osniffy --sniffer"
            )
            return _EXIT_RUNTIME_ERROR

        from .dashboard.grafana import open_dashboard
        from .sniffer import run as sniffer_run

        if not args.skip_dashboard:
            open_dashboard(cfg, "now-5m", "now")

        sniffer_run(repo)

    else:  # reader mode
        file_path = args.reader
        if not os.path.isfile(file_path):
            logger.error("File not found: %s", file_path)
            return _EXIT_RUNTIME_ERROR

        from .dashboard.grafana import open_dashboard
        from .reader import run as reader_run

        total, elapsed = reader_run(file_path, repo)
        print(f"\nInserted {total:,} packets in {elapsed:.2f} s\n")

        if not args.skip_dashboard:
            try:
                start_ms, end_ms = repo.get_time_range()
                open_dashboard(cfg, str(start_ms), str(end_ms))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not open dashboard: %s", exc)

        repo.close()

    return _EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
