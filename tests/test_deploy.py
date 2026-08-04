"""Focused tests for the deployment pipeline (safe_run fully mocked)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tools import deploy
from utils.exceptions import ToolError


class FakeGit:
    """Scriptable stand-in for ``safe_run`` that models a git working copy."""

    def __init__(self, *, rev="a1b2c3d", pull_rc=0, install_rc=0, moved=True):
        self.rev = rev
        self.pull_rc = pull_rc
        self.install_rc = install_rc
        self.moved = moved
        self._pulled = False

    def __call__(self, argv, timeout=30, cwd=None, env=None, check=False):
        joined = " ".join(argv)
        if "rev-parse" in joined:
            rev = "e5f6a7b" if (self._pulled and self.moved) else self.rev
            return SimpleNamespace(returncode=0, stdout=rev + "\n", stderr="")
        if "pull" in joined:
            self._pulled = True
            return SimpleNamespace(returncode=self.pull_rc, stdout="Updating", stderr="err")
        if "reset" in joined:
            return SimpleNamespace(returncode=0, stdout="HEAD is now at", stderr="")
        # pip / npm install
        return SimpleNamespace(returncode=self.install_rc, stdout="installed", stderr="")


@pytest.fixture
def repo(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("rich\n", encoding="utf-8")
    monkeypatch.setattr(deploy, "resolve_path", lambda p, strict=False: tmp_path)
    return tmp_path


def test_current_revision(repo, monkeypatch):
    monkeypatch.setattr(deploy, "safe_run", FakeGit(rev="deadbee"))
    assert deploy.current_revision(repo) == "deadbee"


def test_current_revision_not_a_repo(repo, monkeypatch):
    monkeypatch.setattr(
        deploy, "safe_run",
        lambda *a, **k: SimpleNamespace(returncode=128, stdout="", stderr="not a repo"),
    )
    with pytest.raises(ToolError):
        deploy.current_revision(repo)


def test_git_pull_updates(repo, monkeypatch):
    monkeypatch.setattr(deploy, "safe_run", FakeGit(moved=True))
    result = deploy.git_pull(repo)
    assert result.ok and result.data["updated"]


def test_git_pull_no_change(repo, monkeypatch):
    monkeypatch.setattr(deploy, "safe_run", FakeGit(moved=False))
    result = deploy.git_pull(repo)
    assert result.ok and not result.data["updated"]


def test_git_pull_failure(repo, monkeypatch):
    monkeypatch.setattr(deploy, "safe_run", FakeGit(pull_rc=1))
    result = deploy.git_pull(repo)
    assert not result.ok


def test_git_pull_rejects_injected_branch(repo, monkeypatch):
    monkeypatch.setattr(deploy, "safe_run", FakeGit())
    # A branch that looks like a git option must be rejected, not passed through.
    for evil in ["--upload-pack=touch /tmp/x", "-x", "main;rm -rf /", "a..b"]:
        result = deploy.git_pull(repo, branch=evil)
        assert not result.ok, f"should reject branch {evil!r}"


def test_git_pull_accepts_valid_branch(repo, monkeypatch):
    captured = {}

    def fake(argv, timeout=30, cwd=None, env=None, check=False):
        if "pull" in argv:
            captured["argv"] = argv
        return FakeGit(moved=True)(argv, timeout, cwd, env, check)

    monkeypatch.setattr(deploy, "safe_run", fake)
    result = deploy.git_pull(repo, branch="release/1.2")
    assert result.ok
    assert "--" in captured["argv"]  # ref passed after '--' so it can't be an option


def test_install_pip(repo, monkeypatch):
    monkeypatch.setattr(deploy, "safe_run", FakeGit())
    result = deploy.install_dependencies(repo, manager="pip")
    assert result.ok


def test_install_pip_skips_without_requirements(tmp_path, monkeypatch):
    monkeypatch.setattr(deploy, "resolve_path", lambda p, strict=False: tmp_path)
    monkeypatch.setattr(deploy, "safe_run", FakeGit())
    result = deploy.install_dependencies(tmp_path, manager="pip")
    assert result.status.value == "skipped"


def test_install_npm(repo, monkeypatch):
    monkeypatch.setattr(deploy, "safe_run", FakeGit())
    result = deploy.install_dependencies(repo, manager="npm")
    assert result.ok


def test_install_bad_manager(repo, monkeypatch):
    monkeypatch.setattr(deploy, "safe_run", FakeGit())
    result = deploy.install_dependencies(repo, manager="cargo")
    assert not result.ok


def test_install_failure(repo, monkeypatch):
    monkeypatch.setattr(deploy, "safe_run", FakeGit(install_rc=1))
    result = deploy.install_dependencies(repo, manager="pip")
    assert not result.ok


def test_rollback_success(repo, monkeypatch):
    monkeypatch.setattr(deploy, "safe_run", FakeGit())
    result = deploy.rollback(repo, "a1b2c3d")
    assert result.ok


def test_rollback_invalid_revision(repo, monkeypatch):
    monkeypatch.setattr(deploy, "resolve_path", lambda p, strict=False: repo)
    result = deploy.rollback(repo, "zzz")
    assert not result.ok


def test_health_check_fails_after_retries(monkeypatch):
    from core.base import OperationResult

    bad = OperationResult(tool="network_tools", action="http_health")
    bad.fail("503")
    monkeypatch.setattr("tools.network_tools.http_health", lambda *a, **k: bad)
    result = deploy.health_check("http://localhost/health", retries=2)
    assert not result.ok
    assert result.data["attempts"] == 2


def test_full_pipeline_success(repo, monkeypatch):
    monkeypatch.setattr(deploy, "safe_run", FakeGit(moved=True))
    result = deploy.deploy(repo, manager="pip")
    assert result.ok
    assert not result.data["rolled_back"]
    steps = [s["step"] for s in result.data["steps"]]
    assert steps == ["capture", "pull", "install"]


def test_pipeline_aborts_on_pull(repo, monkeypatch):
    monkeypatch.setattr(deploy, "safe_run", FakeGit(pull_rc=1))
    result = deploy.deploy(repo)
    assert not result.ok


def test_pipeline_rolls_back_on_install(repo, monkeypatch):
    monkeypatch.setattr(deploy, "safe_run", FakeGit(install_rc=1))
    result = deploy.deploy(repo, manager="pip")
    assert not result.ok
    assert result.data["rolled_back"]


def test_pipeline_rolls_back_on_health(repo, monkeypatch):
    from core.base import OperationResult

    monkeypatch.setattr(deploy, "safe_run", FakeGit(moved=True))
    bad = OperationResult(tool="deploy", action="health")
    bad.fail("unhealthy")
    monkeypatch.setattr(deploy, "health_check", lambda *a, **k: bad)
    result = deploy.deploy(repo, manager="pip", health_url="http://localhost/health")
    assert not result.ok
    assert result.data["rolled_back"]
