"""Deployment helper: pull, install, health-check, rollback and track versions.

A deployment is expressed as a small, ordered pipeline of steps. Each step runs
an allow-listed command (``git``, ``pip``/``npm``) through
:func:`utils.security.safe_run`; if any step fails the pipeline stops and the
result reports exactly where. ``current_revision`` and ``rollback`` use git to
capture and restore a known-good commit, giving a safe undo path.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from core.base import OperationResult, timed
from utils.exceptions import ToolError, ValidationError
from utils.logging_config import domain_logger
from utils.security import resolve_path, safe_run

_log = domain_logger("deploy")
_REV_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
# Conservative git ref grammar: no leading '-' (which git would parse as an
# option), no whitespace, no '..'/control characters. Prevents an operator- or
# config-supplied branch like '--upload-pack=...' from injecting a git flag.
_BRANCH_RE = re.compile(r"^(?!-)(?!.*\.\.)[A-Za-z0-9._/-]{1,255}$")


def _validate_branch(branch: str) -> str:
    if not _BRANCH_RE.match(branch or ""):
        raise ValidationError(f"Invalid git branch/ref: {branch!r}")
    return branch


def current_revision(repo: str | Path) -> str:
    """Return the current git commit hash of *repo*."""
    path = resolve_path(repo, strict=True)
    proc = safe_run(["git", "-C", str(path), "rev-parse", "HEAD"], timeout=15)
    if proc.returncode != 0:
        raise ToolError(f"Not a git repository or git failed: {path}")
    return proc.stdout.strip()


def git_pull(repo: str | Path, *, branch: str | None = None) -> OperationResult:
    """Fast-forward *repo* to the latest commit on its (or *branch*) tracking ref."""
    with timed("deploy", "pull") as result:
        path = resolve_path(repo, strict=True)
        before = current_revision(path)
        argv = ["git", "-C", str(path), "pull", "--ff-only"]
        if branch:
            # Validate then use '--' so the ref can never be read as an option.
            argv += ["origin", "--", _validate_branch(branch)]
        proc = safe_run(argv, timeout=120)
        after = current_revision(path) if proc.returncode == 0 else before
        result.data = {"repo": str(path), "before": before, "after": after,
                       "updated": before != after, "output": proc.stdout.strip()[-1000:]}
        if proc.returncode != 0:
            result.fail(f"git pull failed: {proc.stderr.strip()[:300]}")
        else:
            result.finalize(
                "Already up to date"
                if before == after
                else f"Updated {before[:7]} -> {after[:7]}"
            )
        _log.info("deploy: pull %s rc=%s", path, proc.returncode)
    return result


def install_dependencies(repo: str | Path, *, manager: str = "pip") -> OperationResult:
    """Install project dependencies (pip requirements.txt, or npm install)."""
    with timed("deploy", "install") as result:
        path = resolve_path(repo, strict=True)
        if manager == "pip":
            req = path / "requirements.txt"
            if not req.exists():
                result.status = result.status.SKIPPED
                result.finalize("No requirements.txt — skipped")
                return result
            argv = ["pip", "install", "-r", str(req)]
        elif manager == "npm":
            argv = ["npm", "install"]
        else:
            raise ValidationError(f"Unknown package manager {manager!r} (pip|npm)")
        proc = safe_run(argv, timeout=600, cwd=path)
        result.data = {"repo": str(path), "manager": manager, "returncode": proc.returncode,
                       "output": proc.stdout.strip()[-1500:]}
        if proc.returncode != 0:
            result.fail(f"Dependency install failed (rc={proc.returncode})")
        else:
            result.finalize(f"Dependencies installed via {manager}")
    return result


def health_check(url: str, *, timeout: float = 5.0, expect: int = 200, retries: int = 3) -> OperationResult:
    """Poll an application health endpoint until it is healthy or retries run out."""
    with timed("deploy", "health") as result:
        from tools.network_tools import http_health

        last: dict[str, Any] = {}
        for attempt in range(1, max(1, retries) + 1):
            check = http_health(url, timeout=timeout, expect=expect)
            last = check.data
            if check.ok:
                result.data = {"url": url, "attempts": attempt, **check.data}
                result.finalize(f"Healthy after {attempt} attempt(s)")
                return result
        result.data = {"url": url, "attempts": retries, **last}
        result.fail(f"Unhealthy after {retries} attempt(s)")
    return result


def rollback(repo: str | Path, revision: str) -> OperationResult:
    """Hard-reset *repo* to a previously recorded *revision* (a git commit)."""
    with timed("deploy", "rollback") as result:
        path = resolve_path(repo, strict=True)
        if not _REV_RE.match(revision or ""):
            raise ValidationError(f"Invalid revision: {revision!r}")
        proc = safe_run(["git", "-C", str(path), "reset", "--hard", revision], timeout=60)
        result.data = {"repo": str(path), "revision": revision, "returncode": proc.returncode,
                       "output": proc.stdout.strip()[-500:]}
        if proc.returncode != 0:
            result.fail(f"Rollback to {revision[:7]} failed")
        else:
            result.finalize(f"Rolled back to {revision[:7]}")
        _log.warning("deploy: rollback %s -> %s rc=%s", path, revision[:7], proc.returncode)
    return result


def deploy(
    repo: str | Path,
    *,
    branch: str | None = None,
    manager: str = "pip",
    health_url: str | None = None,
) -> OperationResult:
    """Run the full deploy pipeline: capture → pull → install → health check.

    On a failed health check the pipeline automatically rolls back to the commit
    captured before the pull, so a bad deploy self-heals to the last-good state.
    """
    with timed("deploy", "pipeline") as result:
        path = resolve_path(repo, strict=True)
        before = current_revision(path)
        steps: list[dict[str, Any]] = [{"step": "capture", "revision": before}]

        pull = git_pull(path, branch=branch)
        steps.append({"step": "pull", "status": pull.status.value, "data": pull.data})
        if not pull.ok:
            result.data = {"repo": str(path), "steps": steps, "rolled_back": False}
            return result.fail("Deploy aborted at git pull")

        install = install_dependencies(path, manager=manager)
        steps.append({"step": "install", "status": install.status.value})
        if not install.ok:
            rb = rollback(path, before)
            result.data = {"repo": str(path), "steps": steps, "rolled_back": rb.ok}
            return result.fail("Deploy aborted at install; rolled back")

        if health_url:
            health = health_check(health_url)
            steps.append({"step": "health", "status": health.status.value, "data": health.data})
            if not health.ok:
                rb = rollback(path, before)
                result.data = {"repo": str(path), "steps": steps, "rolled_back": rb.ok}
                return result.fail("Health check failed; rolled back")

        result.data = {"repo": str(path), "steps": steps, "before": before,
                       "after": current_revision(path), "rolled_back": False}
        result.finalize("Deployment completed successfully")
        _log.info("deploy: pipeline complete for %s", path)
    return result
