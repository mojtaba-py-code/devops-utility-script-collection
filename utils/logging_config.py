"""Logging setup with rotation and per-domain log files.

* ``devops.log``     — everything from the application logger.
* ``errors.log``     — only WARNING and above (fast triage).
* ``<domain>.log``   — a dedicated rotating file per subsystem on demand
  (``backup``, ``docker``, ``ssh``, ``deploy``, ``monitoring`` ...).

Every record is passed through a redacting filter so credentials that slip
into a log message are masked before they touch disk. The console handler is
colourised when ``colorama`` is available.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from utils.security import redact

try:
    from colorama import Fore, Style
    from colorama import init as colorama_init

    colorama_init()
    _COLOURS = {
        "DEBUG": Fore.CYAN,
        "INFO": Fore.GREEN,
        "WARNING": Fore.YELLOW,
        "ERROR": Fore.RED,
        "CRITICAL": Fore.MAGENTA + Style.BRIGHT,
    }
    _RESET = Style.RESET_ALL
except ImportError:  # pragma: no cover
    _COLOURS = {}
    _RESET = ""

APP_LOGGER = "devops"
_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"

# Remembered so ``domain_logger`` can attach files after ``setup_logging``.
_LOG_DIR: Path | None = None
_LOG_CFG: dict[str, Any] = {}


class _RedactingFilter(logging.Filter):
    """Mask anything that looks like a secret in the rendered message."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        return True


class _ColourFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        colour = _COLOURS.get(record.levelname)
        if colour:
            return message.replace(record.levelname, f"{colour}{record.levelname}{_RESET}", 1)
        return message


def _rotating(path: Path, level: int, cfg: dict[str, Any]) -> RotatingFileHandler:
    handler = RotatingFileHandler(
        path,
        maxBytes=int(cfg.get("max_bytes", 5_242_880)),
        backupCount=int(cfg.get("backup_count", 5)),
        encoding="utf-8",
    )
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter(_FORMAT, datefmt=_DATEFMT))
    handler.addFilter(_RedactingFilter())
    return handler


def setup_logging(config: dict[str, Any] | None = None, *, root: Path | None = None) -> logging.Logger:
    """Configure the application logger; return it. Idempotent per process."""
    global _LOG_DIR, _LOG_CFG
    config = config or {}
    _LOG_CFG = dict(config)
    root = root or Path(__file__).resolve().parent.parent
    level = getattr(logging, str(config.get("level", "INFO")).upper(), logging.INFO)

    log_dir = root / str(config.get("directory", "logs"))
    log_dir.mkdir(parents=True, exist_ok=True)
    _LOG_DIR = log_dir

    app = logging.getLogger(APP_LOGGER)
    app.setLevel(level)
    app.propagate = False
    app.handlers.clear()

    app.addHandler(_rotating(log_dir / "devops.log", level, config))
    app.addHandler(_rotating(log_dir / "errors.log", logging.WARNING, config))

    if config.get("console", True):
        console = logging.StreamHandler()
        console.setLevel(level)
        console.setFormatter(_ColourFormatter(_FORMAT, datefmt=_DATEFMT))
        console.addFilter(_RedactingFilter())
        app.addHandler(console)

    return app


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a child of the application logger (``devops.<name>``)."""
    return logging.getLogger(f"{APP_LOGGER}.{name}") if name else logging.getLogger(APP_LOGGER)


def domain_logger(domain: str) -> logging.Logger:
    """Return a logger that also writes to its own ``<domain>.log`` file.

    Falls back to the plain child logger if ``setup_logging`` has not run yet.
    """
    logger = get_logger(domain)
    if _LOG_DIR is None:
        return logger
    target = str((_LOG_DIR / f"{domain}.log").resolve())
    already = any(
        isinstance(h, RotatingFileHandler) and getattr(h, "baseFilename", None) == target
        for h in logger.handlers
    )
    if not already:
        logger.addHandler(_rotating(_LOG_DIR / f"{domain}.log", logging.INFO, _LOG_CFG))
    return logger
