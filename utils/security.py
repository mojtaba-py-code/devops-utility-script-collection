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
import tempfile
import zipfile
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from utils.exceptions import SecurityError, ValidationError

# Executables the toolkit is ever allowed to invoke. A caller names one of
# these and nothing else — never a path — and the name is resolved on PATH to
# the absolute file that actually runs; anything else is refused outright.
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
        "ping",
        "ping.exe",
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


def validate_port(port: int | str) -> int:
    """Validate a TCP/UDP port number.

    Accepts the string form too, because port ranges arrive as text
    (``"22,80,443"`` / ``"1-1024"``) and are split before validation.
    """
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


# Unix mode bits sit in the top 16 of a ZIP entry's external_attr when the
# archive was written on a Unix system; S_IFLNK marks the entry as a symlink.
_S_IFLNK = 0xA000
_S_IFMT = 0xF000


def zip_member_is_symlink(info: zipfile.ZipInfo) -> bool:
    """True if *info* describes a symbolic link.

    A ZIP can carry symlinks and ``extractall`` recreates them. A member written
    as ``etc -> /etc`` passes a path-traversal check on its own name and only
    escapes once a *later* member is written through it, so link members are
    refused outright — the rule the tar path already applies via
    ``filter="data"``.
    """
    if info.create_system != 3:  # 3 == Unix; other systems carry no mode bits
        return False
    return (info.external_attr >> 16) & _S_IFMT == _S_IFLNK


def validate_http_url(url: str) -> str:
    """Validate *url* for an outbound HTTP(S) request.

    Only the scheme and the presence of a host are enforced. Deliberately
    **not** an SSRF guard: this toolkit is an operator CLI, and checking the
    health of ``http://10.0.0.4:8080/healthz`` on your own private network is
    the normal case rather than an attack. What is refused is a scheme that
    would make ``requests`` read a local file or speak a protocol nobody asked
    for (``file://``, ``gopher://``, and friends) — those are never what an
    operator meant to type.

    A service that takes a URL from an untrusted caller needs the stricter
    check: resolve the host and require every address to be publicly routable.
    """
    if not url or not isinstance(url, str):
        raise ValidationError(f"Invalid URL: {url!r}")
    parts = urlsplit(url.strip())
    if parts.scheme.lower() not in ("http", "https"):
        raise ValidationError(f"Only http(s) URLs are allowed, got {parts.scheme!r}")
    if not parts.hostname:
        raise ValidationError(f"URL has no host: {url!r}")
    return url.strip()


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
def _is_allow_listed(name: str) -> bool:
    """Match a file name against the allow-list, ignoring a Windows suffix.

    ``shutil.which("pip")`` answers ``pip.exe`` on Windows, so the resolved
    file is compared both verbatim and with its executable extension removed.
    """
    lowered = name.lower()
    return lowered in _ALLOWED_COMMANDS or Path(lowered).stem in _ALLOWED_COMMANDS


def _is_untrusted_location(executable: Path) -> bool:
    """Report whether *executable* sits somewhere any process could plant it.

    Two locations matter and both are portable: the working directory — which
    ``shutil.which`` searches *first* on Windows, so a dropped ``git.exe``
    would otherwise beat the real one — and the system temp tree, where no
    legitimate system binary lives.
    """
    try:
        if executable.parent.resolve() == Path.cwd().resolve():
            return True
    except OSError:  # pragma: no cover - unreadable working directory
        return True
    return is_within(executable, Path(tempfile.gettempdir()))


def resolve_executable(name: str) -> str:
    """Resolve an allow-listed program *name* to the absolute path to run.

    The allow-list is only meaningful if the caller cannot choose *which* file
    the name refers to, so a name carrying a directory component is refused
    outright: matching on the basename alone would let ``/tmp/attacker/git``
    pass as ``git``. What ``PATH`` resolves the name to is then checked against
    the allow-list in its own right, and rejected if it was found somewhere
    unprivileged code can write.
    """
    if not name or os.path.dirname(name) or "/" in name or "\\" in name:
        raise SecurityError(f"Command must be a bare program name, not a path: {name!r}")
    if not _is_allow_listed(name):
        raise SecurityError(f"Command not permitted: {name}")
    found = shutil.which(name)
    if found is None:
        raise SecurityError(f"Command not found: {name}")
    executable = Path(found).absolute()
    if not _is_allow_listed(executable.name):
        raise SecurityError(f"Command not permitted: {executable}")
    # Both the entry found on PATH and whatever it finally points at have to
    # live somewhere trustworthy; a symlink from a system directory into a
    # writable one is the same attack wearing a hat.
    for candidate in (executable, Path(found).resolve()):
        if _is_untrusted_location(candidate):
            raise SecurityError(f"Refusing to run {name} from a writable location: {candidate}")
    return str(executable)


def safe_run(
    command: Sequence[str],
    *,
    timeout: float = 30.0,
    check: bool = False,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run *command* safely: no shell, allow-listed executable, with a timeout.

    The program name is vetted and resolved by :func:`resolve_executable`, and
    the absolute path it returns — not the name — is what gets executed, so the
    file that was checked is the file that runs.

    Raises :class:`SecurityError` if the executable is not allow-listed or is
    not found, and :class:`ToolError`-friendly ``TimeoutExpired`` handling via
    :class:`SecurityError` on timeout.
    """
    if not command:
        raise SecurityError("Empty command")
    executable = resolve_executable(command[0])
    try:
        return subprocess.run(  # noqa: S603 - shell=False, allow-listed, timed
            [executable, *list(command)[1:]],
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
