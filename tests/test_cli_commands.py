"""CLI coverage for the network, process, docker, service and deploy commands.

Outbound/system effects are mocked at the tool boundary so these exercise the
``main`` dispatch, argument wiring and result emission without real I/O.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import main as cli
from core.base import OperationResult


def run(*argv: str) -> int:
    return cli.main(list(argv))


def _ok(tool="t", action="a", **data) -> OperationResult:
    r = OperationResult(tool=tool, action=action, message="done")
    r.data = data
    return r


def test_ping_cli(monkeypatch, capsys):
    monkeypatch.setattr(
        "tools.network_tools.subprocess.run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout="1 received"),
    )
    assert run("ping", "example.com", "--count", "1", "--json", "--no-history") == 0
    assert json.loads(capsys.readouterr().out)[0]["data"]["reachable"]


def test_dns_cli(capsys):
    assert run("dns", "localhost", "--json", "--no-history") == 0


def test_scan_cli(monkeypatch, capsys):
    monkeypatch.setattr("tools.network_tools._probe_port", lambda h, p, t: p == 80)
    assert run("scan", "127.0.0.1", "--ports", "79-81", "--json", "--no-history") == 0
    payload = json.loads(capsys.readouterr().out)
    assert 80 in payload[0]["data"]["open_ports"]


def test_http_cli(monkeypatch, capsys):
    monkeypatch.setattr("tools.network_tools.http_health",
                        lambda url, **k: _ok("network_tools", "http_health", status_code=200))
    assert run("http", "https://example.com", "--no-history") == 0


def test_ssl_cli(monkeypatch, capsys):
    monkeypatch.setattr("tools.network_tools.ssl_expiry",
                        lambda host, **k: _ok("network_tools", "ssl_expiry", days_left=90))
    assert run("ssl", "example.com", "--no-history") == 0


def test_processes_cli(capsys):
    assert run("processes", "--top", "3", "--no-history") == 0


def test_processes_details_cli(capsys):
    import os

    assert run("processes", "--details", str(os.getpid()), "--json", "--no-history") == 0


def test_docker_cli(monkeypatch, capsys):
    monkeypatch.setattr("tools.docker_tools.list_containers",
                        lambda **k: _ok("docker", "list", count=0, containers=[]))
    assert run("docker", "list", "--no-history") == 0


def test_docker_missing_target(capsys):
    # `docker logs` with no target -> DevOpsError -> exit 2.
    assert run("docker", "logs", "--no-history") == 2


def test_services_cli(monkeypatch, capsys):
    monkeypatch.setattr("tools.service_manager.safe_run",
                        lambda argv, timeout=20: SimpleNamespace(returncode=0, stdout="active", stderr=""))
    assert run("services", "nginx", "status", "--no-history") == 0


def test_deploy_cli(monkeypatch, capsys):
    monkeypatch.setattr("tools.deploy.deploy",
                        lambda repo, **k: _ok("deploy", "pipeline", rolled_back=False))
    assert run("deploy", ".", "--no-history") == 0


def test_disk_variants_cli(tmp_path, capsys):
    (tmp_path / "f.tmp").write_text("junk", encoding="utf-8")
    assert run("disk", str(tmp_path), "--largest", "3", "--no-history") == 0
    assert run("disk", str(tmp_path), "--empty", "--no-history") == 0
    # cleanup without --force is a dry-run and must not delete.
    assert run("disk", str(tmp_path), "--cleanup", "--no-history") == 0
    assert (tmp_path / "f.tmp").exists()


def test_archive_cli(tree, tmp_path, capsys):
    out = tmp_path / "a.zip"
    assert run("archive", "--create", str(tree), "--dest", str(out), "--no-history") == 0
    assert out.exists()
    assert run("archive", "--verify", str(out), "--no-history") == 0
    ex = tmp_path / "ex"
    assert run("archive", "--extract", str(out), "--dest", str(ex), "--no-history") == 0


def test_backup_verify_restore_cli(tree, tmp_path, capsys):
    dest = tmp_path / "bk"
    assert run("backup", str(tree), "--dest", str(dest), "--no-history") == 0
    capsys.readouterr()
    import glob

    archives = glob.glob(str(dest / "backup_*.zip"))
    assert archives
    assert run("backup", "--verify", archives[0], "--no-history") == 0
    target = tmp_path / "restored"
    assert run("backup", "--restore", archives[0], "--target", str(target), "--no-history") == 0
    assert (target / "a.txt").exists()


def test_sync_mirror_cli(tree, tmp_path, capsys):
    dst = tmp_path / "dst"
    assert run("sync", str(tree), str(dst), "--mode", "mirror", "--no-history") == 0
    assert (dst / "a.txt").exists()
