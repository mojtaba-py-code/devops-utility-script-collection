"""Tests for the external-system tools using injected fakes / mocks.

None of these touch a real Docker daemon, SSH host or system service; the tools
are designed to accept an injected client or to route every command through
``safe_run``, which we monkeypatch. This keeps the suite fast, hermetic and
runnable in CI on any OS.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tools import deploy, docker_tools, monitoring, notify, service_manager, ssh_tools
from utils.exceptions import SecurityError


# --- Docker (injected fake client) ------------------------------------------
class _FakeImage:
    tags = ["nginx:latest"]
    short_id = "img123"


class _FakeContainer:
    def __init__(self, name="web"):
        self.name = name
        self.short_id = "abc123"
        self.status = "running"
        self.image = _FakeImage()
        self.actions: list[str] = []

    def start(self): self.actions.append("start")
    def stop(self): self.actions.append("stop")
    def restart(self): self.actions.append("restart")
    def remove(self): self.actions.append("remove")
    def logs(self, tail=100): return b"line1\nline2"
    def stats(self, stream=False):
        return {"memory_stats": {"usage": 1000, "limit": 5000},
                "cpu_stats": {"cpu_usage": {"total_usage": 42}}}


class _FakeContainers:
    def __init__(self, container): self._c = container
    def list(self, all=True): return [self._c]
    def get(self, name):
        if name != self._c.name:
            from docker.errors import NotFound
            raise NotFound(name)
        return self._c


class _FakeImages:
    def pull(self, reference): return _FakeImage()


class _FakeDocker:
    def __init__(self):
        self.containers = _FakeContainers(_FakeContainer())
        self.images = _FakeImages()


def test_docker_list_and_actions():
    cli = _FakeDocker()
    listed = docker_tools.list_containers(client=cli)
    assert listed.ok and listed.data["count"] == 1
    assert listed.data["containers"][0]["image"] == "nginx:latest"

    acted = docker_tools.container_action("web", "restart", client=cli)
    assert acted.ok

    logs = docker_tools.container_logs("web", client=cli)
    assert "line1" in logs.data["logs"]

    stats = docker_tools.container_stats("web", client=cli)
    assert stats.data["memory_usage"] == 1000

    pulled = docker_tools.pull_image("nginx:latest", client=cli)
    assert pulled.ok


def test_docker_missing_container():
    cli = _FakeDocker()
    result = docker_tools.container_action("nope", "stop", client=cli)
    assert not result.ok


def test_docker_bad_action():
    # An unknown action is captured onto a failed result, not raised.
    result = docker_tools.container_action("web", "levitate", client=_FakeDocker())
    assert not result.ok


# --- SSH (injected fake client) ---------------------------------------------
class _FakeChannel:
    def recv_exit_status(self): return 0


class _FakeStream:
    def __init__(self, data=b""):
        self._data = data
        self.channel = _FakeChannel()
    def read(self): return self._data


class _FakeSFTP:
    def __init__(self): self.put_calls = []; self.get_calls = []
    def put(self, local, remote): self.put_calls.append((local, remote))
    def get(self, remote, local):
        from pathlib import Path
        Path(local).write_text("downloaded", encoding="utf-8")
    def close(self): pass


class _FakeSSH:
    def __init__(self, exit_code=0):
        self._exit = exit_code
        self.sftp = _FakeSFTP()
    def exec_command(self, command, timeout=30):
        out = _FakeStream(b"ok")
        out.channel = SimpleNamespace(recv_exit_status=lambda: self._exit)
        return (_FakeStream(), out, _FakeStream(b""))
    def open_sftp(self): return self.sftp


def test_ssh_run_command_success():
    result = ssh_tools.run_command(_FakeSSH(0), "uptime")
    assert result.ok and result.data["exit_code"] == 0


def test_ssh_run_command_nonzero():
    result = ssh_tools.run_command(_FakeSSH(1), "false")
    assert not result.ok


def test_ssh_upload_download(tmp_path):
    local = tmp_path / "f.txt"
    local.write_text("data", encoding="utf-8")
    client = _FakeSSH()
    up = ssh_tools.upload(client, local, "/remote/f.txt")
    assert up.ok and client.sftp.put_calls

    dst = tmp_path / "back.txt"
    down = ssh_tools.download(client, "/remote/f.txt", dst)
    assert down.ok and dst.read_text(encoding="utf-8") == "downloaded"


def test_ssh_upload_missing_local(tmp_path):
    result = ssh_tools.upload(_FakeSSH(), tmp_path / "nope", "/r")
    assert not result.ok


def test_connect_requires_credential():
    # No password_env and no key -> SecurityError raised to the caller.
    with pytest.raises(SecurityError):
        ssh_tools.connect("h", username="u")


# --- Service manager (monkeypatched safe_run) -------------------------------
def test_service_status(monkeypatch):
    monkeypatch.setattr(
        service_manager, "safe_run",
        lambda argv, timeout=20: SimpleNamespace(returncode=0, stdout="active", stderr=""),
    )
    result = service_manager.manage_service("nginx", "status")
    assert result.ok
    assert result.data["service"] == "nginx"


def test_service_invalid_name():
    result = service_manager.manage_service("bad name!", "status")
    assert not result.ok


def test_service_failed_action(monkeypatch):
    monkeypatch.setattr(
        service_manager, "safe_run",
        lambda argv, timeout=20: SimpleNamespace(returncode=3, stdout="", stderr="nope"),
    )
    result = service_manager.manage_service("nginx", "start")
    assert not result.ok


# --- Deploy (monkeypatched safe_run + health) -------------------------------
def _fake_run_factory(rev_before="aaaaaaa", rev_after="bbbbbbb"):
    calls = {"n": 0}

    def fake_run(argv, timeout=30, cwd=None, env=None, check=False):
        joined = " ".join(argv)
        if "rev-parse" in joined:
            calls["n"] += 1
            rev = rev_before if calls["n"] <= 1 else rev_after
            return SimpleNamespace(returncode=0, stdout=rev + "\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    return fake_run


def test_deploy_pull(monkeypatch, tmp_path):
    monkeypatch.setattr(deploy, "safe_run", _fake_run_factory())
    monkeypatch.setattr(deploy, "resolve_path", lambda p, strict=False: tmp_path)
    result = deploy.git_pull(tmp_path)
    assert result.ok
    assert result.data["updated"]


def test_deploy_rollback_validates_revision(monkeypatch, tmp_path):
    monkeypatch.setattr(deploy, "resolve_path", lambda p, strict=False: tmp_path)
    result = deploy.rollback(tmp_path, "not-a-hash!")
    assert not result.ok


def test_deploy_health_check(monkeypatch):
    from core.base import OperationResult

    good = OperationResult(tool="network_tools", action="http_health")
    good.data = {"status_code": 200}
    monkeypatch.setattr("tools.network_tools.http_health", lambda *a, **k: good)
    result = deploy.health_check("http://localhost/health")
    assert result.ok


# --- Monitoring -------------------------------------------------------------
def test_monitoring_snapshot():
    result = monitoring.snapshot()
    assert "metrics" in result.data
    assert result.data["worst_severity"] in ("ok", "warning", "critical")


def test_monitoring_critical_threshold():
    # Force everything critical with a threshold of 0.
    thresholds = {k: {"warning": 0, "critical": 0} for k in
                  ("cpu_percent", "memory_percent", "disk_percent")}
    result = monitoring.snapshot(thresholds)
    assert result.data["worst_severity"] == "critical"
    assert not result.ok


def test_monitoring_warning_threshold():
    # warning breached (>=0) but critical far out of reach.
    thresholds = {k: {"warning": 0, "critical": 999} for k in
                  ("cpu_percent", "memory_percent", "disk_percent")}
    result = monitoring.snapshot(thresholds)
    assert result.data["worst_severity"] == "warning"
    assert result.warnings


# --- Service manager: platform-specific argv builders -----------------------
def test_service_linux_path(monkeypatch):
    monkeypatch.setattr(service_manager.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        service_manager, "safe_run",
        lambda argv, timeout=20: SimpleNamespace(returncode=0, stdout="active", stderr=""),
    )
    result = service_manager.manage_service("nginx", "enable")
    assert result.ok and result.data["platform"] == "Linux"


def test_service_linux_bad_action(monkeypatch):
    monkeypatch.setattr(service_manager.platform, "system", lambda: "Linux")
    result = service_manager.manage_service("nginx", "levitate")
    assert not result.ok


def test_service_windows_unsupported_action(monkeypatch):
    monkeypatch.setattr(service_manager.platform, "system", lambda: "Windows")
    result = service_manager.manage_service("Spooler", "enable")
    assert not result.ok  # enable is unsupported on Windows


# --- Notify (monkeypatched requests) ----------------------------------------
def test_notify_slack_skipped_without_env(monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    result = notify.send_slack("hi")
    assert result.status.value == "skipped"


def test_notify_slack_sends(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example/abc")
    monkeypatch.setattr(notify.requests, "post",
                        lambda *a, **k: SimpleNamespace(status_code=200))
    result = notify.send_slack("hi")
    assert result.ok


def test_notify_telegram_skipped(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    result = notify.send_telegram("hi")
    assert result.status.value == "skipped"
