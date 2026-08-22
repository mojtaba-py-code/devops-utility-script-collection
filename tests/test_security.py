"""Tests for the security primitives — the core of the toolkit's safety."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from utils import security
from utils.exceptions import SecurityError, ValidationError


def test_resolve_and_is_within(tmp_path: Path):
    child = tmp_path / "a" / "b"
    child.mkdir(parents=True)
    assert security.is_within(child, tmp_path)
    assert not security.is_within(tmp_path, child)


def test_validate_output_path_confines_to_roots(tmp_path: Path):
    inside = tmp_path / "reports" / "r.json"
    assert security.validate_output_path(inside, allowed_roots=[tmp_path])
    with pytest.raises(SecurityError):
        security.validate_output_path("/etc/passwd", allowed_roots=[tmp_path])


def test_validate_output_path_rejects_symlink(tmp_path: Path):
    target = tmp_path / "real"
    target.write_text("x", encoding="utf-8")
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this platform")
    with pytest.raises(SecurityError):
        security.validate_output_path(link)


def test_validate_delete_path_blocks_root_and_protected():
    with pytest.raises(SecurityError):
        security.validate_delete_path("/")
    with pytest.raises(SecurityError):
        security.validate_delete_path(os.environ.get("SystemRoot", "/etc"))


def test_validate_pid_and_port_and_host():
    assert security.validate_pid(1234) == 1234
    with pytest.raises(SecurityError):
        security.validate_pid(1)
    with pytest.raises(ValidationError):
        security.validate_pid("abc")
    assert security.validate_port(443) == 443
    with pytest.raises(ValidationError):
        security.validate_port(70000)
    assert security.validate_host("example.com") == "example.com"
    assert security.validate_host("10.0.0.1") == "10.0.0.1"
    with pytest.raises(ValidationError):
        security.validate_host("bad host!")


def test_validate_port_range():
    assert security.validate_port_range("22,80,443") == [22, 80, 443]
    assert security.validate_port_range("20-22") == [20, 21, 22]
    with pytest.raises(ValidationError):
        security.validate_port_range("30-20")
    with pytest.raises(ValidationError):
        security.validate_port_range("")


def test_safe_run_rejects_non_allowlisted():
    with pytest.raises(SecurityError):
        security.safe_run(["rm", "-rf", "/"])
    with pytest.raises(SecurityError):
        security.safe_run([])


def test_safe_run_rejects_an_allow_listed_name_behind_a_path(tmp_path: Path):
    """A path whose basename is allow-listed must not smuggle a binary past it."""
    planted = tmp_path / "git"
    planted.write_text("#!/bin/sh\necho pwned\n", encoding="utf-8")
    planted.chmod(0o755)
    for argv0 in (str(planted), "/tmp/attacker/git", r"C:\attacker\git.exe", "./git"):
        with pytest.raises(SecurityError):
            security.safe_run([argv0, "--version"])


def test_safe_run_rejects_a_binary_planted_in_the_working_directory(tmp_path, monkeypatch):
    """``shutil.which`` searches the working directory first on Windows.

    ``tmp_path`` normally lives *under* the system temp root, so the temp-tree
    rule would reject the planted binary before the working-directory
    comparison was ever reached — and the test would pass even with that
    comparison deleted. Pointing the temp root at a sibling directory takes
    that rule out of play, leaving the cwd rule as the only thing that can
    make this call fail.
    """
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    elsewhere = tmp_path / "not-the-temp-root"
    elsewhere.mkdir()
    monkeypatch.setattr(security.tempfile, "gettempdir", lambda: str(elsewhere))

    planted = workdir / "git"
    planted.write_text("#!/bin/sh\necho pwned\n", encoding="utf-8")
    planted.chmod(0o755)
    monkeypatch.chdir(workdir)
    monkeypatch.setattr(security.shutil, "which", lambda name: str(planted))

    # Precondition: the temp-tree rule cannot fire for this file, so anything
    # that rejects it below is the working-directory rule doing the work.
    assert not security.is_within(planted, Path(security.tempfile.gettempdir()))
    assert security._is_untrusted_location(planted)

    with pytest.raises(SecurityError, match="writable location"):
        security.safe_run(["git", "--version"])


def test_safe_run_allows_git_version():
    proc = security.safe_run(["git", "--version"], timeout=15)
    assert proc.returncode == 0
    assert "git version" in proc.stdout.lower()


def test_redact_masks_secrets():
    assert "***" in security.redact("password=hunter2")
    assert "***" in security.redact("api_key: ABC123")
    assert security.redact_iter(["token=abc"])[0].endswith("***")
    assert security.redact("") == ""


def test_redact_masks_uri_credentials():
    masked = security.redact("db=postgres://user:MyP@ssw0rd@dbhost:5432/app")
    assert "MyP@ssw0rd" not in masked
    assert "user:***@" in masked
    # A URL with no credentials is left intact.
    assert security.redact("https://example.com/path") == "https://example.com/path"


def test_dotenv_and_secret(tmp_path: Path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text('FOO="bar"\n# comment\nBAZ=qux\n', encoding="utf-8")
    monkeypatch.delenv("FOO", raising=False)
    applied = security.load_dotenv(env_file)
    assert applied["FOO"] == "bar"
    assert os.environ["BAZ"] == "qux"
    assert security.get_secret("FOO") == "bar"
    with pytest.raises(SecurityError):
        security.get_secret("DOES_NOT_EXIST_XYZ", required=True)


def test_free_tcp_port_is_usable():
    port = security.free_tcp_port()
    assert 1 <= port <= 65535


def test_redact_data_masks_strings_not_counts():
    data = {
        "command": "mysql --password=S3cret -h db",
        "url": "postgres://user:topsecret@host/db",
        "suspicious": {"auth_failure": 5},   # key contains 'auth' but value is a count
        "items": ["token=abc123", "harmless"],
    }
    out = security.redact_data(data)
    assert "S3cret" not in out["command"]
    assert "topsecret" not in out["url"]
    assert out["suspicious"]["auth_failure"] == 5     # structural count preserved
    assert out["items"][0].endswith("***")
    assert out["items"][1] == "harmless"
