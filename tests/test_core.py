"""Tests for the core layer: result model, history DB, reporting, config."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.base import OperationResult, Status, timed
from core.database import HistoryDB
from core.reporting import SUPPORTED_FORMATS, generate_report
from utils.config import Config
from utils.exceptions import ConfigError, ToolError
from utils.formatting import human_bytes, human_duration, truncate


# --- result model -----------------------------------------------------------
def test_operation_result_lifecycle():
    r = OperationResult(tool="t", action="a")
    assert r.status is Status.SUCCESS and r.ok
    r.add_warning("w")
    r.add_error("e")
    assert r.status is Status.PARTIAL
    assert not Status.PARTIAL.ok
    d = r.as_dict()
    assert d["errors"] == ["e"] and d["warnings"] == ["w"]


def test_timed_captures_exception():
    with timed("t", "boom") as r:
        raise RuntimeError("kaboom")
    assert r.status is Status.FAILURE
    assert "kaboom" in r.errors[0]
    assert r.duration_ms >= 0


def test_status_ok_semantics():
    assert Status.SUCCESS.ok and Status.DRY_RUN.ok and Status.SKIPPED.ok
    assert not Status.FAILURE.ok and not Status.PARTIAL.ok


# --- history database -------------------------------------------------------
def test_history_record_and_query(tmp_path: Path):
    db = HistoryDB(tmp_path / "h.db")
    r = OperationResult(tool="backup", action="full", message="done")
    row_id = db.record(r)
    assert row_id > 0
    recent = db.recent(limit=5)
    assert recent[0]["tool"] == "backup"
    assert db.recent(tool="backup")[0]["action"] == "full"
    assert db.summary()["total"] == 1
    assert db.last_success("backup", "full")["message"] == "done"
    db.close()


def test_history_record_redacts_secrets(tmp_path: Path):
    db = HistoryDB(tmp_path / "h.db")
    r = OperationResult(tool="ssh", action="exec", message="ran command")
    r.data = {"command": "deploy --token=FAKEtokenValue123"}
    db.record(r)
    stored = db.recent(limit=1)[0]
    assert "FAKEtokenValue123" not in json.dumps(stored)
    db.close()


def test_report_redacts_secrets(tmp_path: Path):
    r = OperationResult(tool="ssh", action="exec")
    r.data = {"url": "redis://:mypassword@10.0.0.1:6379"}
    path = generate_report([r], fmt="json", output_dir=tmp_path)
    assert "mypassword" not in path.read_text(encoding="utf-8")


def test_history_prune(tmp_path: Path):
    db = HistoryDB(tmp_path / "h.db")
    db.record(OperationResult(tool="t", action="a"))
    assert db.prune(0) == 0          # disabled
    assert db.prune(3650) == 0       # nothing that old
    db.close()


# --- reporting --------------------------------------------------------------
@pytest.mark.parametrize("fmt", ["json", "csv", "txt", "html"])
def test_generate_report_formats(tmp_path: Path, fmt: str):
    results = [OperationResult(tool="t", action="a", message="hi")]
    path = generate_report(results, fmt=fmt, output_dir=tmp_path)
    assert path.exists() and path.suffix == f".{fmt}"
    assert path.read_text(encoding="utf-8")


def test_report_json_roundtrip(tmp_path: Path):
    results = [OperationResult(tool="t", action="a")]
    path = generate_report(results, fmt="json", output_dir=tmp_path)
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["summary"]["success"] == 1


def test_report_bad_format(tmp_path: Path):
    with pytest.raises(ToolError):
        generate_report([], fmt="xml", output_dir=tmp_path)
    assert "pdf" in SUPPORTED_FORMATS


# --- config -----------------------------------------------------------------
def test_config_defaults_and_dotted_lookup():
    cfg = Config.load(None, None)
    assert cfg.get("general.workers") == 8
    assert cfg.get("does.not.exist", "fallback") == "fallback"
    assert cfg.allowed_roots() is None


def test_config_yaml_override_and_env_expansion(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("MY_DIR", "/data/out")
    settings = tmp_path / "settings.yaml"
    settings.write_text(
        "general:\n  workers: 3\nreporting:\n  directory: ${MY_DIR}\n", encoding="utf-8"
    )
    cfg = Config.load(settings, None)
    assert cfg.get("general.workers") == 3
    assert cfg.get("reporting.directory") == "/data/out"


def test_config_missing_explicit_file_raises(tmp_path: Path):
    with pytest.raises(ConfigError):
        Config.load(tmp_path / "nope.yaml", None)


def test_config_server_lookup(tmp_path: Path):
    servers = tmp_path / "servers.yaml"
    servers.write_text(
        "servers:\n  - name: web\n    host: 10.0.0.1\n    username: deploy\n", encoding="utf-8"
    )
    cfg = Config.load(None, servers)
    assert cfg.server("web")["host"] == "10.0.0.1"
    assert cfg.server("missing") is None
    assert len(cfg.servers) == 1


# --- formatting -------------------------------------------------------------
def test_human_bytes_and_duration():
    assert human_bytes(0) == "0 B"
    assert human_bytes(1536).endswith("KB")
    assert human_bytes(None) == "—"
    assert human_bytes(-2048).startswith("-")
    assert human_duration(0) == "0s"
    assert human_duration(3661) == "1h 1m 1s"
    assert human_duration(None) == "—"
    assert human_duration(-5) == "—"
    assert truncate("abcdef", 4).endswith("…")
    assert truncate("ab", 4) == "ab"
