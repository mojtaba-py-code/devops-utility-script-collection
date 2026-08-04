"""Layered configuration: built-in defaults merged with YAML overrides.

Three files are recognised (all optional):

* ``settings.yaml`` — general behaviour (paths, thresholds, logging, security).
* ``servers.yaml``  — the inventory of remote hosts for SSH/deploy commands.
* ``logging.yaml``  — an optional override for the logging block.

Missing files fall back to safe defaults; an *explicitly requested* file that is
absent raises :class:`ConfigError`, so a typo in ``--config`` is caught instead
of silently ignored. Credentials never live here — only the *name* of the
environment variable that holds them.
"""

from __future__ import annotations

import copy
import os
import re
from pathlib import Path
from typing import Any

from utils.exceptions import ConfigError

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a hard dependency
    yaml = None  # type: ignore[assignment]

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"

# ``${VAR}`` / ``${VAR:-fallback}`` substitution inside YAML string values.
_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

DEFAULT_SETTINGS: dict[str, Any] = {
    "general": {
        "workers": 8,             # ThreadPoolExecutor size for parallel tools
        "dry_run": False,         # global default; --dry-run overrides per call
        "chunk_size": 1_048_576,  # bytes per read when streaming large files
    },
    "security": {
        # Confine every write/delete to these roots when non-empty. Absolute
        # paths recommended in production.
        "allowed_roots": [],
        "redact_secrets": True,
    },
    "logging": {
        "level": "INFO",
        "directory": "logs",
        "max_bytes": 5_242_880,
        "backup_count": 5,
        "console": True,
    },
    "database": {
        "path": "database/history.db",
        "retention_days": 90,
    },
    "reporting": {
        "directory": "reports",
        "default_format": "json",
    },
    "backup": {
        "destination": "backups",
        "compression": "zip",     # zip | tar | gztar
        "keep_versions": 5,
        "verify": True,
    },
    "network": {
        "timeout": 3.0,
        "ping_count": 3,
        "port_scan_timeout": 0.5,
    },
    "monitoring": {
        "cpu_percent": {"warning": 80, "critical": 95},
        "memory_percent": {"warning": 80, "critical": 92},
        "disk_percent": {"warning": 80, "critical": 92},
    },
    "notifications": {
        # Channel toggles; credentials come from the environment (see .env).
        "slack": {"enabled": False, "webhook_env": "SLACK_WEBHOOK_URL"},
        # "TELEGRAM_BOT_TOKEN" is the *name* of the env var to read, not a secret.
        "telegram": {"enabled": False, "token_env": "TELEGRAM_BOT_TOKEN", "chat_id_env": "TELEGRAM_CHAT_ID"},  # nosec B105
    },
}

DEFAULT_SERVERS: dict[str, Any] = {"servers": []}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge *override* onto a deep copy of *base*."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _expand_env(node: Any) -> Any:
    """Recursively expand ``${VAR}`` references in string leaves."""
    if isinstance(node, str):
        return _ENV_REF.sub(
            lambda m: os.environ.get(m.group(1), m.group(2) if m.group(2) is not None else ""),
            node,
        )
    if isinstance(node, dict):
        return {k: _expand_env(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_expand_env(v) for v in node]
    return node


def _load_yaml(path: Path, *, explicit: bool, default: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        if explicit:
            raise ConfigError(f"Config file not found: {path}")
        return copy.deepcopy(default)
    if yaml is None:  # pragma: no cover
        raise ConfigError("PyYAML is required to read configuration files")
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:  # type: ignore[union-attr]
        raise ConfigError(f"Failed to read {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ConfigError(f"Config root must be a mapping: {path}")
    return _deep_merge(default, _expand_env(loaded))


class Config:
    """Access point for settings and the server inventory with dotted lookups."""

    def __init__(self, settings: dict[str, Any], servers: dict[str, Any]) -> None:
        self._settings = settings
        self._servers = servers

    @classmethod
    def load(
        cls,
        settings_path: str | Path | None = None,
        servers_path: str | Path | None = None,
    ) -> "Config":
        s_path = Path(settings_path) if settings_path else CONFIG_DIR / "settings.yaml"
        v_path = Path(servers_path) if servers_path else CONFIG_DIR / "servers.yaml"
        settings = _load_yaml(s_path, explicit=settings_path is not None, default=DEFAULT_SETTINGS)
        servers = _load_yaml(v_path, explicit=servers_path is not None, default=DEFAULT_SERVERS)
        return cls(settings, servers)

    def get(self, dotted_key: str, default: Any = None) -> Any:
        """Look up ``"a.b.c"`` in the settings tree, returning *default* if absent."""
        node: Any = self._settings
        for part in dotted_key.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def server(self, name: str) -> dict[str, Any] | None:
        """Return the inventory entry named *name*, if present."""
        for entry in self._servers.get("servers", []) or []:
            if isinstance(entry, dict) and entry.get("name") == name:
                return entry
        return None

    @property
    def servers(self) -> list[dict[str, Any]]:
        return list(self._servers.get("servers", []) or [])

    @property
    def settings(self) -> dict[str, Any]:
        return self._settings

    def allowed_roots(self) -> list[str] | None:
        roots = self.get("security.allowed_roots", []) or []
        return list(roots) if roots else None
