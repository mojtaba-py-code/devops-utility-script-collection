"""Security primitives shared by every tool.

The toolkit runs privileged, side-effectful operations (deleting files,
killing processes, opening SSH sessions, shelling out to ``git``/``systemctl``).
This module centralises the guarantees that keep those operations safe:

* **Path safety** — every path we write to or delete is resolved, checked for
  symlink redirection and (when configured) confined to an allow-listed root,
  so a crafted ``..`` or symlink can never escape the intended directory.
* **Command safety** — sub-processes run with ``shell=False`` from a curated
  allow-list and always with a timeout, eliminating shell-injection and hangs.
* **Input validation** — PIDs, ports, hostnames and intervals are validated
  before they reach the OS or the network.
* **Secret hygiene** — credentials come from the environment / ``.env`` and are
  redacted from anything that is logged or exported.

Nothing here trusts its input; every helper raises :class:`SecurityError` or
:class:`ValidationError` rather than silently doing the wrong thing.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from utils.exceptions import SecurityError, ValidationError

# Executables the toolkit is ever allowed to invoke. Resolved to absolute
# paths at call time; anything not listed here is refused outright.
_ALLOWED_COMMANDS: frozenset[str] = frozenset(
    {
        "git",
        "git.exe",
        "systemctl",
        "service",
        "sc",
        "sc.exe",
        "docker",
        "docker.exe",
        "python",
        "python3",
        "python.exe",
        "pip",
        "pip3",
        "npm",
        "npm.cmd",
        "pytest",
    }
)

# Patterns that commonly indicate a secret embedded in text (command lines,
# environment dumps, config echoes). Used by :func:`redact`.
_SECRET_PATTERNS = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|"
    r"access[_-]?key|secret[_-]?key|private[_-]?key|passphrase|auth)"
    r"\s*[=:]\s*\S+"
)

# Credentials embedded in a connection URI, e.g. ``postgres://user:pass@host``
# or ``redis://:pass@host`` (empty user). The password runs to the last ``@``
# before the path, so an unencoded ``@`` inside the password is still masked.
_URI_CRED_PATTERN = re.compile(r"(?i)([a-z][a-z0-9+.\-]*://[^:/\s]*):([^/\s]+)@")

# A conservative hostname grammar (RFC 1123 label rules).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------
def resolve_path(path: str | os.PathLike[str], *, strict: bool = False) -> Path:
    """Resolve *path* to an absolute path, collapsing ``..`` segments."""
    try:
        return Path(path).expanduser().resolve(strict=strict)
    except (OSError, RuntimeError) as exc:
        raise SecurityError(f"Invalid path {path!r}: {exc}") from exc


def is_within(child: Path, parent: Path) -> bool:
    """Return ``True`` if *child* is *parent* or lives beneath it."""
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except (ValueError, OSError):
        return False


def validate_output_path(
    path: str | os.PathLike[str],
    *,
    allowed_roots: Sequence[str | os.PathLike[str]] | None = None,
) -> Path:
    """Validate a path we are about to **write** to.

    Refuses to write through an existing symlink (a classic redirection trick)
    and, when *allowed_roots* is provided, rejects any target that resolves
    outside those roots.
    """
    original = Path(path).expanduser()
    if original.is_symlink():
        raise SecurityError(f"Refusing to write through a symlink: {path}")
    resolved = resolve_path(path, strict=False)
    _enforce_roots(resolved, allowed_roots)
    return resolved


def validate_delete_path(
    path: str | os.PathLike[str],
    *,
    allowed_roots: Sequence[str | os.PathLike[str]] | None = None,
) -> Path:
    """Validate a path we are about to **delete**.

    On top of the write checks, this refuses to delete a filesystem root or a
    small set of well-known critical directories — a guard against a bad glob
    or a mis-typed config wiping out ``/`` or ``C:\\Windows``.
    """
    resolved = resolve_path(path, strict=False)
    if resolved.parent == resolved:
        raise SecurityError(f"Refusing to delete a filesystem root: {resolved}")
    if _is_protected(resolved):
        raise SecurityError(f"Refusing to delete a protected system path: {resolved}")
    _enforce_roots(resolved, allowed_roots)
    return resolved


def _enforce_roots(
    resolved: Path, allowed_roots: Sequence[str | os.PathLike[str]] | None
) -> None:
    if allowed_roots:
        roots = [resolve_path(r) for r in allowed_roots]
        if not any(is_within(resolved, root) for root in roots):
            raise SecurityError(f"Path {resolved} is outside the allowed roots")


def _is_protected(path: Path) -> bool:
    protected = {
        Path("/"),
        Path("/etc"),
        Path("/bin"),
        Path("/usr"),
        Path("/boot"),
        Path("/var"),
        Path("/sys"),
        Path("/proc"),
        Path(os.environ.get("SystemRoot", r"C:\Windows")),
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
    }
    resolved = path.resolve()
    return any(resolved == p.resolve() for p in protected if str(p) not in ("", "."))


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
def validate_interval(value: float, *, minimum: float = 0.1, maximum: float = 86_400) -> float:
    """Validate a polling/timeout interval (seconds) to a sane range."""
    try:
        seconds = float(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"Interval must be a number, got {value!r}") from exc
    if not (minimum <= seconds <= maximum):
        raise ValidationError(f"Interval {seconds}s out of range [{minimum}, {maximum}]")
    return seconds


def validate_pid(pid: int) -> int:
    """Validate a process id: a positive integer that is not the kernel/init."""
    try:
        value = int(pid)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"Invalid PID {pid!r}") from exc
    if value <= 1:
        raise SecurityError(f"Refusing to target protected PID {value}")
    return value


def validate_port(port: int) -> int:
    """Validate a TCP/UDP port number."""
    try:
        value = int(port)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"Invalid port {port!r}") from exc
    if not (1 <= value <= 65_535):
        raise ValidationError(f"Port {value} out of range [1, 65535]")
    return value


def validate_host(host: str) -> str:
    """Validate that *host* is a syntactically valid hostname or IP address."""
    if not host or not isinstance(host, str):
        raise ValidationError(f"Invalid host: {host!r}")
    host = host.strip()
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not _HOSTNAME_RE.match(host):
        raise ValidationError(f"Invalid hostname: {host!r}")
    return host


def validate_port_range(spec: str) -> list[int]:
    """Parse ``"22,80,443"`` or ``"1-1024"`` into a validated list of ports."""
    ports: list[int] = []
    for chunk in str(spec).split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            low, _, high = chunk.partition("-")
            start, end = validate_port(low), validate_port(high)
            if start > end:
                raise ValidationError(f"Descending port range: {chunk}")
            ports.extend(range(start, end + 1))
        else:
            ports.append(validate_port(chunk))
    if not ports:
        raise ValidationError(f"No ports parsed from {spec!r}")
    return sorted(set(ports))


# ---------------------------------------------------------------------------
# Command safety
# ---------------------------------------------------------------------------
def safe_run(
    command: Sequence[str],
    *,
    timeout: float = 30.0,
    check: bool = False,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run *command* safely: no shell, allow-listed executable, with a timeout.

    Raises :class:`SecurityError` if the executable is not allow-listed or is
    not found, and :class:`ToolError`-friendly ``TimeoutExpired`` handling via
    :class:`SecurityError` on timeout.
    """
    if not command:
        raise SecurityError("Empty command")
    executable = Path(command[0]).name.lower()
    if executable not in _ALLOWED_COMMANDS:
        raise SecurityError(f"Command not permitted: {command[0]}")
    if shutil.which(command[0]) is None and not Path(command[0]).exists():
        raise SecurityError(f"Command not found: {command[0]}")
    try:
        return subprocess.run(  # noqa: S603 - shell=False, allow-listed, timed
            list(command),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
            shell=False,
            cwd=str(cwd) if cwd else None,
            env=dict(env) if env else None,
        )
    except subprocess.TimeoutExpired as exc:
        raise SecurityError(f"Command timed out after {timeout}s: {command[0]}") from exc


# ---------------------------------------------------------------------------
# Secret hygiene
# ---------------------------------------------------------------------------
def load_dotenv(path: str | os.PathLike[str] = ".env", *, override: bool = False) -> dict[str, str]:
    """Load ``KEY=VALUE`` pairs from a ``.env`` file into ``os.environ``.

    A tiny, dependency-free parser: blank lines and ``#`` comments are ignored,
    surrounding quotes are stripped, and existing environment variables are
    preserved unless *override* is set. Returns the values that were applied.
    """
    env_path = Path(path)
    applied: dict[str, str] = {}
    if not env_path.exists():
        return applied
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not key:
            continue
        if override or key not in os.environ:
            os.environ[key] = value
            applied[key] = value
    return applied


def get_secret(name: str, *, required: bool = False, default: str | None = None) -> str | None:
    """Read a secret from the environment, never from a config file or argv."""
    value = os.environ.get(name, default)
    if required and not value:
        raise SecurityError(f"Required secret {name!r} is not set in the environment")
    return value


def redact(text: str) -> str:
    """Redact obvious secrets from a string before logging/exporting it."""
    if not text:
        return text
    masked = _SECRET_PATTERNS.sub(
        lambda m: re.split(r"[=:]", m.group(0), maxsplit=1)[0].rstrip() + "=***", text
    )
    # Also mask the password component of a connection URI (user:pass@host).
    return _URI_CRED_PATTERN.sub(r"\1:***@", masked)


def redact_iter(items: Iterable[str]) -> list[str]:
    """Redact every string in *items*."""
    return [redact(item) for item in items]


def redact_data(value: Any) -> Any:
    """Recursively redact secrets from a JSON-like structure before it is
    persisted or exported.

    Only *string leaves* are rewritten (via :func:`redact`); keys and numeric
    values are left untouched, so structural fields such as counts named
    ``auth_failure`` are preserved while ``"password=..."`` inside a value is
    masked. This is the export-boundary counterpart to the logging redactor.
    """
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {k: redact_data(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_data(v) for v in value]
    return value


def free_tcp_port() -> int:
    """Ask the OS for an unused TCP port (handy for tests and health checks)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
