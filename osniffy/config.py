"""Configuration loading and validation.

All runtime settings are sourced from environment variables (or a ``.env``
file).  Missing *required* variables raise :class:`ConfigError` early so that
the process never starts in a broken state.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv


class ConfigError(ValueError):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class Config:
    """Immutable snapshot of all runtime settings."""

    mysql_host: str
    db_name: str
    table_name: str
    mysql_user: str
    mysql_pass: str
    mysql_user_grafana: str
    mysql_pass_grafana: str
    grafana_host: str
    grafana_port: int
    grafana_api_key: str
    client_user: str


def load_config(env_file: str | None = None) -> Config:
    """Load and validate configuration from the environment / ``.env`` file.

    Parameters
    ----------
    env_file:
        Optional explicit path to a ``.env`` file.  When *None* the standard
        ``python-dotenv`` search (CWD and parent directories) is used.

    Raises
    ------
    ConfigError
        If any *required* variable is absent or empty, or if ``GRAFANA_PORT``
        cannot be parsed as an integer.
    """
    if env_file is not None:
        load_dotenv(env_file, override=True)
    else:
        load_dotenv()

    def _require(key: str) -> str:
        val = os.getenv(key, "").strip()
        if not val:
            raise ConfigError(
                f"Required environment variable '{key}' is missing or empty. "
                "Copy .env.example to .env and fill in the values."
            )
        return val

    def _optional(key: str, default: str = "") -> str:
        return os.getenv(key, default).strip()

    mysql_host = _require("MYSQL_HOST")
    db_name = _require("DB_NAME")
    table_name = _require("TABLE_NAME")
    mysql_user = _require("MYSQL_USER")
    mysql_pass = _require("MYSQL_PASS")

    grafana_port_raw = _optional("GRAFANA_PORT", "3000")
    try:
        grafana_port = int(grafana_port_raw)
    except ValueError:
        raise ConfigError(f"GRAFANA_PORT must be an integer, got '{grafana_port_raw}'") from None

    return Config(
        mysql_host=mysql_host,
        db_name=db_name,
        table_name=table_name,
        mysql_user=mysql_user,
        mysql_pass=mysql_pass,
        mysql_user_grafana=_optional("MYSQL_USER_GRAFANA"),
        mysql_pass_grafana=_optional("MYSQL_PASS_GRAFANA"),
        grafana_host=_optional("GRAFANA_HOST", "localhost"),
        grafana_port=grafana_port,
        grafana_api_key=_optional("GRAFANA_API_KEY"),
        client_user=_optional("CLIENT"),
    )
