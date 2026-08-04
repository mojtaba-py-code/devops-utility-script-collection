"""Service manager: query and control system services cross-platform.

On Linux the tool shells out to ``systemctl``; on Windows it uses ``sc``. Every
invocation goes through :func:`utils.security.safe_run`, so only the allow-listed
binaries can run, always without a shell and always with a timeout. Service
names are validated to a conservative character set before use.
"""

from __future__ import annotations

import platform
import re

from core.base import OperationResult, timed
from utils.exceptions import UnsupportedPlatformError, ValidationError
from utils.logging_config import domain_logger
from utils.security import safe_run

_log = domain_logger("service")

_SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")
_LINUX_ACTIONS = {"status": "status", "start": "start", "stop": "stop",
                  "restart": "restart", "enable": "enable", "disable": "disable"}
_WINDOWS_ACTIONS = {"status": "query", "start": "start", "stop": "stop"}


def _validate_name(name: str) -> str:
    if not _SERVICE_RE.match(name or ""):
        raise ValidationError(f"Invalid service name: {name!r}")
    return name


def manage_service(name: str, action: str, *, timeout: float = 20.0) -> OperationResult:
    """Run *action* against service *name* using the platform's service manager."""
    with timed("service", action) as result:
        name = _validate_name(name)
        system = platform.system()
        if system == "Windows":
            argv, mapped = _windows_argv(name, action)
        else:
            argv, mapped = _linux_argv(name, action)

        proc = safe_run(argv, timeout=timeout)
        succeeded = proc.returncode == 0
        result.data = {
            "service": name,
            "action": action,
            "platform": system,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip()[-2000:],
            "stderr": proc.stderr.strip()[-1000:],
        }
        # ``status``/``query`` returning non-zero is informational, not a failure
        # of the tool itself (e.g. an inactive service).
        if action in ("status",) or succeeded:
            result.finalize(f"{action} {name}: rc={proc.returncode}")
        else:
            result.fail(f"{action} {name} failed (rc={proc.returncode})")
        _log.info("service: %s %s rc=%s", action, name, proc.returncode)
    return result


def _linux_argv(name: str, action: str) -> tuple[list[str], str]:
    if action not in _LINUX_ACTIONS:
        raise ValidationError(f"Unsupported action {action!r} on Linux")
    return (["systemctl", _LINUX_ACTIONS[action], name], _LINUX_ACTIONS[action])


def _windows_argv(name: str, action: str) -> tuple[list[str], str]:
    if action not in _WINDOWS_ACTIONS:
        raise UnsupportedPlatformError(f"Action {action!r} is not supported on Windows")
    return (["sc", _WINDOWS_ACTIONS[action], name], _WINDOWS_ACTIONS[action])
