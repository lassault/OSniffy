"""Grafana dashboard provisioning helper.

Provides two modes of operation:

1. **Declarative (recommended):** Mount ``grafana/provisioning/`` into the
   Grafana container.  No runtime API calls needed.

2. **API-based (fallback):** Call :func:`open_dashboard` from the CLI after
   a pcap read – it provisions the datasource and uploads the dashboard JSON
   via the Grafana HTTP API, then opens a browser tab.

The API key (service-account token) is read from ``Config.grafana_api_key``.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path

import requests

from ..config import Config

logger = logging.getLogger(__name__)

# Path to the bundled dashboard JSON files shipped with the package.
_DASHBOARD_DIR = Path(__file__).parent.parent.parent / "grafana" / "dashboards"

# Dashboard UID used when opening the URL.  Matches the uid field in the JSON.
_DASHBOARD_UID = "zyHdgQcMk"


def provision_datasource(cfg: Config) -> None:
    """Register (or update) the OSniffy MySQL datasource via the Grafana API."""
    if not cfg.grafana_api_key:
        logger.debug("No GRAFANA_API_KEY set – skipping datasource provisioning")
        return

    url = f"http://{cfg.grafana_host}:{cfg.grafana_port}/api/datasources"
    headers = {
        "Authorization": f"Bearer {cfg.grafana_api_key}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    body = {
        "name": "OSniffy",
        "type": "mysql",
        "access": "proxy",
        "url": f"{cfg.mysql_host}:3306",
        "user": cfg.mysql_user_grafana,
        "secureJsonData": {"password": cfg.mysql_pass_grafana},
        "database": cfg.db_name,
        "jsonData": {
            "maxOpenConns": 10,
            "maxIdleConns": 2,
            "connMaxLifetime": 14400,
        },
    }
    try:
        resp = requests.post(url, headers=headers, json=body, timeout=10)
        if resp.status_code == 409:
            logger.info("Grafana datasource 'OSniffy' already exists")
        elif resp.ok:
            logger.info("Grafana datasource 'OSniffy' provisioned")
        else:
            logger.warning(
                "Datasource provisioning returned HTTP %d: %s",
                resp.status_code,
                resp.text[:200],
            )
    except requests.RequestException as exc:
        logger.warning("Could not provision Grafana datasource: %s", exc)


def provision_dashboard(cfg: Config, dashboard_file: str = "reader.json") -> None:
    """Upload a dashboard JSON to Grafana via the HTTP API."""
    if not cfg.grafana_api_key:
        logger.debug("No GRAFANA_API_KEY set – skipping dashboard provisioning")
        return

    dashboard_path = _DASHBOARD_DIR / dashboard_file
    if not dashboard_path.exists():
        logger.warning("Dashboard file not found: %s", dashboard_path)
        return

    url = f"http://{cfg.grafana_host}:{cfg.grafana_port}/api/dashboards/db"
    headers = {
        "Authorization": f"Bearer {cfg.grafana_api_key}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))
    body = {"dashboard": dashboard, "overwrite": True, "folderId": 0}

    try:
        resp = requests.post(url, headers=headers, json=body, timeout=10)
        if resp.ok:
            logger.info("Dashboard '%s' uploaded to Grafana", dashboard_file)
        else:
            logger.warning(
                "Dashboard upload returned HTTP %d: %s",
                resp.status_code,
                resp.text[:200],
            )
    except requests.RequestException as exc:
        logger.warning("Could not upload dashboard to Grafana: %s", exc)


def open_dashboard(cfg: Config, start: str, end: str) -> None:
    """Provision the datasource/dashboard if an API key is configured, then
    open the Grafana dashboard in the system browser.

    Parameters
    ----------
    start:
        Grafana-compatible start time (epoch-ms string or ``now-5m``).
    end:
        Grafana-compatible end time (epoch-ms string or ``now``).
    """
    provision_datasource(cfg)
    provision_dashboard(cfg)

    refresh = "&refresh=5s" if end == "now" else ""
    url = (
        f"http://{cfg.grafana_host}:{cfg.grafana_port}"
        f"/d/{_DASHBOARD_UID}/osniffy?from={start}&to={end}{refresh}"
    )
    logger.info("Opening Grafana dashboard: %s", url)

    current_user = cfg.client_user or os.getenv("USER", "")
    running_as_root = os.getenv("USER") == "root"

    try:
        if running_as_root and current_user and current_user != "root":
            subprocess.Popen(["runuser", "-u", current_user, "sensible-browser", url])
        else:
            subprocess.Popen(["sensible-browser", url])
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not open browser automatically: %s", exc)
