"""Unit tests for osniffy.config – environment variable loading & validation."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from osniffy.config import Config, ConfigError, load_config

_MINIMAL_ENV = {
    "MYSQL_HOST": "db.example.com",
    "DB_NAME": "osniffy",
    "TABLE_NAME": "packets",
    "MYSQL_USER": "admin",
    "MYSQL_PASS": "s3cr3t",
}

_FULL_ENV = {
    **_MINIMAL_ENV,
    "MYSQL_USER_GRAFANA": "grafana_ro",
    "MYSQL_PASS_GRAFANA": "g_pass",
    "GRAFANA_HOST": "grafana.example.com",
    "GRAFANA_PORT": "3001",
    "GRAFANA_API_KEY": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    "CLIENT": "alice",
}


class TestLoadConfigSuccess:
    def test_minimal_env_loads(self) -> None:
        with patch.dict(os.environ, _MINIMAL_ENV, clear=True):
            cfg = load_config()
        assert cfg.mysql_host == "db.example.com"
        assert cfg.db_name == "osniffy"
        assert cfg.table_name == "packets"

    def test_full_env_loads(self) -> None:
        with patch.dict(os.environ, _FULL_ENV, clear=True):
            cfg = load_config()
        assert cfg.grafana_host == "grafana.example.com"
        assert cfg.grafana_port == 3001
        assert cfg.grafana_api_key.startswith("eyJ")
        assert cfg.client_user == "alice"

    def test_optional_defaults(self) -> None:
        with patch.dict(os.environ, _MINIMAL_ENV, clear=True):
            cfg = load_config()
        assert cfg.grafana_host == "localhost"
        assert cfg.grafana_port == 3000
        assert cfg.grafana_api_key == ""
        assert cfg.mysql_user_grafana == ""
        assert cfg.client_user == ""

    def test_config_is_frozen(self) -> None:
        with patch.dict(os.environ, _MINIMAL_ENV, clear=True):
            cfg = load_config()
        with pytest.raises((AttributeError, TypeError)):
            cfg.mysql_host = "other"  # type: ignore[misc]

    def test_returns_config_instance(self) -> None:
        with patch.dict(os.environ, _MINIMAL_ENV, clear=True):
            cfg = load_config()
        assert isinstance(cfg, Config)


class TestLoadConfigFailures:
    @pytest.mark.parametrize(
        "missing_key",
        ["MYSQL_HOST", "DB_NAME", "TABLE_NAME", "MYSQL_USER", "MYSQL_PASS"],
    )
    def test_missing_required_raises(self, missing_key: str) -> None:
        env = {k: v for k, v in _MINIMAL_ENV.items() if k != missing_key}
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ConfigError, match=missing_key):
                load_config()

    def test_empty_required_raises(self) -> None:
        env = {**_MINIMAL_ENV, "MYSQL_HOST": "   "}  # whitespace-only
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ConfigError, match="MYSQL_HOST"):
                load_config()

    def test_invalid_grafana_port_raises(self) -> None:
        env = {**_MINIMAL_ENV, "GRAFANA_PORT": "not_a_number"}
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ConfigError, match="GRAFANA_PORT"):
                load_config()

    def test_empty_env_raises(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ConfigError):
                load_config()
