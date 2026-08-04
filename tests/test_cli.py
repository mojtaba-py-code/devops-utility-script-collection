"""End-to-end tests driving the CLI through ``main.main``.

Every invocation passes ``--no-history`` so the tests never write to the
project's real history database, and uses ``tmp_path`` for any file output.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import main as cli


def run(*argv: str) -> int:
    return cli.main(list(argv))


def test_no_command_prints_help(capsys):
    assert run() == 0
    out = capsys.readouterr().out
    assert "command" in out.lower()


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        run("--version")
    assert exc.value.code == 0
    assert "1.0.0" in capsys.readouterr().out


def test_system_info_json(capsys):
    assert run("system-info", "--json", "--no-history") == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["tool"] == "system_info"


def test_config_command(capsys):
    assert run("config", "--no-history") == 0
    doc = json.loads(capsys.readouterr().out)
    assert "settings" in doc


def test_checksum_cli(tmp_path: Path, capsys):
    f = tmp_path / "a.txt"
    f.write_text("hello", encoding="utf-8")
    assert run("checksum", str(f), "--json", "--no-history") == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["data"]["count"] == 1


def test_checksum_verify_cli(tmp_path: Path, capsys):
    from tools import checksum

    f = tmp_path / "a.txt"
    f.write_text("hello", encoding="utf-8")
    digest = checksum.hash_file(f)
    rc = run("checksum", str(f), "--verify", digest, "--json", "--no-history")
    assert rc == 0


def test_backup_and_list_cli(tree: Path, tmp_path: Path, capsys):
    dest = tmp_path / "bk"
    rc = run("backup", str(tree), "--dest", str(dest), "--json", "--no-history")
    assert rc == 0
    capsys.readouterr()
    rc = run("backup", "--dest", str(dest), "--list", "--json", "--no-history")
    assert rc == 0


def test_sync_dry_run_cli(tree: Path, tmp_path: Path, capsys):
    dst = tmp_path / "dst"
    rc = run("sync", str(tree), str(dst), "--mode", "one-way", "--dry-run",
             "--json", "--no-history")
    assert rc == 0
    assert not (dst / "a.txt").exists()


def test_disk_usage_cli(tmp_path: Path, capsys):
    assert run("disk", str(tmp_path), "--json", "--no-history") == 0


def test_logs_cli(sample_log: Path, capsys):
    assert run("logs", str(sample_log), "--json", "--no-history") == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["data"]["errors"] == 3


def test_monitor_cli(capsys):
    rc = run("monitor", "--json", "--no-history")
    assert rc in (0, 1)  # 1 if the host happens to breach a threshold


def test_report_generation_cli(tree: Path, tmp_path: Path, capsys):
    out = tmp_path / "reports"
    rc = run("checksum", str(tree / "a.txt"), "--report", "json",
             "--output", str(out), "--no-history")
    assert rc == 0
    assert list(out.glob("report_*.json"))


def test_error_exit_code(capsys):
    # archive with no mode selected -> DevOpsError -> exit code 2.
    rc = run("archive", "--no-history")
    assert rc == 2


def test_history_roundtrip(tmp_path: Path, capsys):
    # Use a temp settings file pointing the DB into tmp_path so we can record.
    settings = tmp_path / "s.yaml"
    settings.write_text(f"database:\n  path: {(tmp_path / 'h.db').as_posix()}\n", encoding="utf-8")
    f = tmp_path / "a.txt"
    f.write_text("x", encoding="utf-8")
    assert run("checksum", str(f), "--config", str(settings)) == 0
    capsys.readouterr()
    assert run("history", "--summary", "--config", str(settings)) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["total"] >= 1
