"""Tests for disk tools, the log analyzer and system-info."""

from __future__ import annotations

import time
from pathlib import Path

from tools import disk_tools, log_analyzer, system_info


# --- disk tools -------------------------------------------------------------
def test_disk_usage(tmp_path: Path):
    result = disk_tools.disk_usage(tmp_path)
    assert result.ok
    assert result.data["total"] > 0
    assert 0 <= result.data["used_percent"] <= 100


def test_largest_files(tree: Path):
    (tree / "big.bin").write_bytes(b"x" * 5000)
    result = disk_tools.largest_files(tree, top=2)
    assert result.ok
    assert result.data["files"][0]["path"].endswith("big.bin")
    assert len(result.data["files"]) == 2


def test_empty_dirs(tmp_path: Path):
    (tmp_path / "empty").mkdir()
    (tmp_path / "full").mkdir()
    (tmp_path / "full" / "f.txt").write_text("x", encoding="utf-8")
    result = disk_tools.empty_dirs(tmp_path)
    assert any(p.endswith("empty") for p in result.data["empty_dirs"])
    assert not any(p.endswith("full") for p in result.data["empty_dirs"])


def test_cleanup_temp_dry_run_then_live(tmp_path: Path):
    tmp_file = tmp_path / "junk.tmp"
    tmp_file.write_text("temp", encoding="utf-8")
    keep = tmp_path / "keep.txt"
    keep.write_text("keep", encoding="utf-8")

    planned = disk_tools.cleanup_temp(tmp_path, dry_run=True)
    assert planned.status.value == "dry_run"
    assert tmp_file.exists()  # nothing deleted in dry-run

    live = disk_tools.cleanup_temp(tmp_path, dry_run=False)
    assert live.ok
    assert not tmp_file.exists()
    assert keep.exists()      # non-temp file untouched


def test_cleanup_respects_age(tmp_path: Path):
    old = tmp_path / "old.tmp"
    old.write_text("x", encoding="utf-8")
    # Backdate mtime two days.
    past = time.time() - 2 * 86_400
    import os

    os.utime(old, (past, past))
    new = tmp_path / "new.tmp"
    new.write_text("x", encoding="utf-8")
    disk_tools.cleanup_temp(tmp_path, older_than_days=1, dry_run=False)
    assert not old.exists()
    assert new.exists()  # newer than the cutoff


def test_disk_tools_bad_path():
    result = disk_tools.largest_files("/definitely/not/here/xyz")
    assert not result.ok  # SecurityError/ValidationError captured onto result


# --- log analyzer -----------------------------------------------------------
def test_analyze_log_counts_and_threats(sample_log: Path):
    result = log_analyzer.analyze_log(sample_log, keywords=["request"])
    assert result.ok
    assert result.data["errors"] == 3   # 2 ERROR + 1 CRITICAL
    assert result.data["warnings"] == 1
    assert result.data["keywords"]["request"] == 1
    assert result.data["unique_ips"] == 3
    suspicious = result.data["suspicious"]
    assert suspicious.get("auth_failure")
    assert suspicious.get("path_traversal")
    assert suspicious.get("sql_injection")
    assert suspicious.get("suspicious_agent")
    assert result.warnings  # threats raise a warning


def test_analyze_missing_file():
    # A missing file is reported as a failed result, not a raised exception,
    # so a single bad path never aborts a batch of analyses.
    result = log_analyzer.analyze_log("/no/such/file.log")
    assert not result.ok


# --- system info ------------------------------------------------------------
def test_collect_system_info():
    result = system_info.collect_system_info()
    assert result.ok
    data = result.data
    assert data["python_version"]
    assert data["os"]["system"]
    assert "hostname" in data["network"]
    assert data["network"]["mac_address"].count(":") == 5
