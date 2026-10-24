"""Unit tests for osniffy.dashboard.grafana – API calls and browser launch."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from osniffy.config import Config
from osniffy.dashboard.grafana import (
    open_dashboard,
    provision_dashboard,
    provision_datasource,
)


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    return Config(
        mysql_host="db.local",
        db_name="osniffy",
        table_name="packets",
        mysql_user="user",
        mysql_pass="pass",
        mysql_user_grafana="grafana_ro",
        mysql_pass_grafana="grafana_pass",
        grafana_host="grafana.local",
        grafana_port=3000,
        grafana_api_key="service-account-token",
        client_user="alice",
    )


@pytest.fixture
def cfg_no_key(cfg: Config) -> Config:
    """Config with an empty API key."""
    import dataclasses

    return dataclasses.replace(cfg, grafana_api_key="")


# ---------------------------------------------------------------------------
# provision_datasource
# ---------------------------------------------------------------------------


class TestProvisionDatasource:
    def test_skips_when_no_api_key(self, cfg_no_key: Config) -> None:
        with patch("requests.post") as mock_post:
            provision_datasource(cfg_no_key)
        mock_post.assert_not_called()

    def test_posts_to_datasource_endpoint(self, cfg: Config) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.ok = True
        with patch("requests.post", return_value=mock_resp) as mock_post:
            provision_datasource(cfg)
        url = mock_post.call_args[0][0]
        assert "/api/datasources" in url
        assert cfg.grafana_host in url

    def test_bearer_token_in_header(self, cfg: Config) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.ok = True
        with patch("requests.post", return_value=mock_resp) as mock_post:
            provision_datasource(cfg)
        headers = mock_post.call_args[1]["headers"]
        assert headers["Authorization"] == f"Bearer {cfg.grafana_api_key}"

    def test_409_conflict_does_not_raise(self, cfg: Config) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 409
        mock_resp.ok = False
        with patch("requests.post", return_value=mock_resp):
            provision_datasource(cfg)  # should not raise

    def test_network_error_does_not_raise(self, cfg: Config) -> None:
        with patch("requests.post", side_effect=requests.ConnectionError("refused")):
            provision_datasource(cfg)  # should not raise


# ---------------------------------------------------------------------------
# provision_dashboard
# ---------------------------------------------------------------------------


class TestProvisionDashboard:
    def test_skips_when_no_api_key(self, cfg_no_key: Config) -> None:
        with patch("requests.post") as mock_post:
            provision_dashboard(cfg_no_key)
        mock_post.assert_not_called()

    def test_skips_missing_file(self, cfg: Config) -> None:
        with patch("requests.post") as mock_post:
            provision_dashboard(cfg, dashboard_file="nonexistent.json")
        mock_post.assert_not_called()

    def test_posts_dashboard_json(self, cfg: Config, tmp_path: Path) -> None:
        dashboard = {"uid": "test", "title": "Test Dashboard", "panels": []}
        # Temporarily patch _DASHBOARD_DIR to point at tmp_path
        dashboard_file = tmp_path / "reader.json"
        dashboard_file.write_text(json.dumps(dashboard))

        mock_resp = MagicMock()
        mock_resp.ok = True
        with (
            patch("requests.post", return_value=mock_resp) as mock_post,
            patch("osniffy.dashboard.grafana._DASHBOARD_DIR", tmp_path),
        ):
            provision_dashboard(cfg)

        url = mock_post.call_args[0][0]
        assert "/api/dashboards/db" in url

    def test_network_error_does_not_raise(self, cfg: Config, tmp_path: Path) -> None:
        dashboard_file = tmp_path / "reader.json"
        dashboard_file.write_text('{"uid":"test","panels":[]}')
        with (
            patch("requests.post", side_effect=requests.ConnectionError("refused")),
            patch("osniffy.dashboard.grafana._DASHBOARD_DIR", tmp_path),
        ):
            provision_dashboard(cfg)  # should not raise


# ---------------------------------------------------------------------------
# open_dashboard
# ---------------------------------------------------------------------------


class TestOpenDashboard:
    def _patch_all(self) -> tuple:
        return (
            patch("osniffy.dashboard.grafana.provision_datasource"),
            patch("osniffy.dashboard.grafana.provision_dashboard"),
            patch("subprocess.Popen"),
        )

    def test_calls_provision_and_opens_browser(self, cfg: Config) -> None:
        with (
            patch("osniffy.dashboard.grafana.provision_datasource") as mock_ds,
            patch("osniffy.dashboard.grafana.provision_dashboard") as mock_db,
            patch("subprocess.Popen") as mock_popen,
            patch.dict(os.environ, {"USER": "alice"}),
        ):
            open_dashboard(cfg, "1000000", "2000000")

        mock_ds.assert_called_once_with(cfg)
        mock_db.assert_called_once()
        mock_popen.assert_called_once()

    def test_url_contains_time_range(self, cfg: Config) -> None:
        captured: list[str] = []

        def fake_popen(args: list, **_kwargs: object) -> None:
            captured.extend(args)

        with (
            patch("osniffy.dashboard.grafana.provision_datasource"),
            patch("osniffy.dashboard.grafana.provision_dashboard"),
            patch("subprocess.Popen", side_effect=fake_popen),
            patch.dict(os.environ, {"USER": "alice"}),
        ):
            open_dashboard(cfg, "1000000", "2000000")

        assert any("1000000" in a for a in captured)
        assert any("2000000" in a for a in captured)

    def test_live_mode_adds_refresh(self, cfg: Config) -> None:
        captured: list[str] = []

        def fake_popen(args: list, **_kwargs: object) -> None:
            captured.extend(args)

        with (
            patch("osniffy.dashboard.grafana.provision_datasource"),
            patch("osniffy.dashboard.grafana.provision_dashboard"),
            patch("subprocess.Popen", side_effect=fake_popen),
            patch.dict(os.environ, {"USER": "alice"}),
        ):
            open_dashboard(cfg, "now-5m", "now")

        assert any("refresh" in a for a in captured)

    def test_browser_error_does_not_raise(self, cfg: Config) -> None:
        with (
            patch("osniffy.dashboard.grafana.provision_datasource"),
            patch("osniffy.dashboard.grafana.provision_dashboard"),
            patch("subprocess.Popen", side_effect=FileNotFoundError("no browser")),
            patch.dict(os.environ, {"USER": "alice"}),
        ):
            open_dashboard(cfg, "1000000", "2000000")  # should not raise
