"""Shared fixtures for the test-suite."""

from __future__ import annotations

from pathlib import Path

import pytest

from utils.config import Config


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """A small source directory tree used by backup/sync/archive tests."""
    root = tmp_path / "src"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_text("alpha", encoding="utf-8")
    (root / "b.txt").write_text("bravo", encoding="utf-8")
    (root / "sub" / "c.txt").write_text("charlie", encoding="utf-8")
    return root


@pytest.fixture
def sample_log(tmp_path: Path) -> Path:
    """A log file with mixed levels, IPs and a couple of attack signatures."""
    lines = [
        "2026-08-03 10:00:00 INFO  10.0.0.5 request served",
        "2026-08-03 10:00:01 WARNING 10.0.0.5 slow response",
        "2026-08-03 10:00:02 ERROR 10.0.0.9 unhandled exception",
        "2026-08-03 10:00:03 ERROR 10.0.0.9 Failed password for root",
        "2026-08-03 10:00:04 INFO 10.0.0.5 GET /../../etc/passwd",
        "2026-08-03 10:00:05 INFO 203.0.113.7 GET /?id=1 UNION SELECT password",
        "2026-08-03 10:00:06 CRITICAL 203.0.113.7 sqlmap/1.5 scanning",
    ]
    path = tmp_path / "app.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def config() -> Config:
    return Config.load(None, None)
