"""Additional tests to exercise report formats, process control, notify,
archive edge cases and the history-DB context manager."""

from __future__ import annotations

import subprocess
import sys
import tarfile
import time
from pathlib import Path

import pytest

from core.base import OperationResult
from core.database import HistoryDB
from core.reporting import generate_report
from tools import archive, notify, process_tools
from types import SimpleNamespace


# --- reporting: PDF + error/warning rendering -------------------------------
def test_pdf_report(tmp_path: Path):
    pytest.importorskip("reportlab")
    results = [OperationResult(tool="t", action="a", message="ok")]
    path = generate_report(results, fmt="pdf", output_dir=tmp_path)
    assert path.exists() and path.read_bytes()[:4] == b"%PDF"


def test_txt_and_html_render_errors(tmp_path: Path):
    r = OperationResult(tool="t", action="a", message="boom")
    r.add_error("something failed")
    r.status = r.status.FAILURE
    txt = generate_report([r], fmt="txt", output_dir=tmp_path).read_text(encoding="utf-8")
    assert "something failed" in txt
    html = generate_report([r], fmt="html", output_dir=tmp_path).read_text(encoding="utf-8")
    assert "failure" in html


# --- process control on a real, disposable child ----------------------------
def test_process_suspend_resume_kill():
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        suspended = process_tools.control_process(proc.pid, "suspend")
        assert suspended.ok
        resumed = process_tools.control_process(proc.pid, "resume")
        assert resumed.ok
        killed = process_tools.control_process(proc.pid, "kill")
        assert killed.ok
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover
            proc.kill()


def test_process_details_nonexistent():
    result = process_tools.process_details(999_999)
    assert not result.ok  # NoSuchProcess captured onto the result


# --- notify: telegram + slack error paths -----------------------------------
def test_notify_telegram_sends(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "tok")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "123")
    monkeypatch.setattr(notify.requests, "post", lambda *a, **k: SimpleNamespace(status_code=200))
    result = notify.send_telegram("hello")
    assert result.ok


def test_notify_telegram_api_error(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "tok")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "123")
    monkeypatch.setattr(notify.requests, "post", lambda *a, **k: SimpleNamespace(status_code=500))
    result = notify.send_telegram("hello")
    assert not result.ok


def test_notify_slack_error(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example/x")
    monkeypatch.setattr(notify.requests, "post", lambda *a, **k: SimpleNamespace(status_code=500))
    result = notify.send_slack("hi")
    assert not result.ok


# --- archive: tar verify + link rejection + bztar ---------------------------
def test_verify_valid_tar(tree: Path, tmp_path: Path):
    dest = tmp_path / "a.tar"
    archive.create_archive([tree], dest, fmt="tar")
    result = archive.verify_archive(dest)
    assert result.ok


def test_create_bztar(tree: Path, tmp_path: Path):
    dest = tmp_path / "a.tar.bz2"
    result = archive.create_archive([tree], dest, fmt="bztar")
    assert result.ok and dest.exists()


def test_extract_rejects_tar_symlink(tmp_path: Path):
    evil = tmp_path / "evil.tar"
    with tarfile.open(evil, "w") as tf:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tf.addfile(info)
    result = archive.extract_archive(evil, tmp_path / "out")
    assert not result.ok


def test_verify_unrecognised_file(tmp_path: Path):
    junk = tmp_path / "notanarchive.bin"
    junk.write_bytes(b"just some bytes")
    result = archive.verify_archive(junk)
    assert not result.ok


# --- history DB: context manager + empty queries ----------------------------
def test_history_context_manager(tmp_path: Path):
    with HistoryDB(tmp_path / "h.db") as db:
        assert db.recent() == []
        assert db.last_success("x", "y") is None
        assert db.summary()["total"] == 0
        time.sleep(0)  # keep 'time' import meaningful / no-op


def test_history_recent_filter(tmp_path: Path):
    with HistoryDB(tmp_path / "h.db") as db:
        db.record(OperationResult(tool="backup", action="full"))
        db.record(OperationResult(tool="docker", action="list"))
        assert len(db.recent(tool="backup")) == 1
        assert len(db.recent()) == 2
