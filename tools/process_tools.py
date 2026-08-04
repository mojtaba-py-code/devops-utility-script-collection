"""Process manager: inspect, rank and safely control running processes.

Listing is read-only. The control actions (kill/suspend/resume) validate the
target PID through :func:`utils.security.validate_pid` — which refuses PID 0/1
— so a mistyped argument can never signal the kernel or init.
"""

from __future__ import annotations

from typing import Any

from core.base import OperationResult, timed
from utils.exceptions import ToolError, ValidationError
from utils.logging_config import get_logger
from utils.security import validate_pid

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore[assignment]

_log = get_logger("process_tools")


def _require_psutil() -> "psutil":  # type: ignore[valid-type]
    if psutil is None:  # pragma: no cover
        raise ToolError("process tools require 'psutil' (pip install psutil)")
    return psutil


def list_processes(*, top: int = 15, sort_by: str = "cpu") -> OperationResult:
    """List the top processes ranked by CPU or memory usage."""
    with timed("process_tools", "list") as result:
        ps = _require_psutil()
        if sort_by not in ("cpu", "memory"):
            raise ValidationError(f"sort_by must be 'cpu' or 'memory', got {sort_by!r}")
        procs: list[dict[str, Any]] = []
        for proc in ps.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent", "status"]):
            try:
                info = proc.info
                procs.append({
                    "pid": info["pid"],
                    "name": info.get("name") or "?",
                    "user": info.get("username") or "?",
                    "cpu_percent": round(info.get("cpu_percent") or 0.0, 1),
                    "memory_percent": round(info.get("memory_percent") or 0.0, 1),
                    "status": info.get("status") or "?",
                })
            except (ps.NoSuchProcess, ps.AccessDenied):  # pragma: no cover
                continue
        key = "cpu_percent" if sort_by == "cpu" else "memory_percent"
        procs.sort(key=lambda p: p[key], reverse=True)
        result.data = {"total": len(procs), "sort_by": sort_by, "processes": procs[: max(1, top)]}
        result.finalize(f"{len(procs)} process(es); showing top {min(top, len(procs))} by {sort_by}")
    return result


def process_details(pid: int) -> OperationResult:
    """Return detailed information about a single process."""
    with timed("process_tools", "details") as result:
        ps = _require_psutil()
        pid = validate_pid(pid)
        try:
            proc = ps.Process(pid)
            with proc.oneshot():
                result.data = {
                    "pid": pid,
                    "name": proc.name(),
                    "exe": _safe(proc.exe),
                    "cmdline": _safe(lambda: " ".join(proc.cmdline())),
                    "status": proc.status(),
                    "cpu_percent": proc.cpu_percent(interval=0.1),
                    "memory_percent": round(proc.memory_percent(), 2),
                    "num_threads": proc.num_threads(),
                    "create_time": int(proc.create_time()),
                }
        except ps.NoSuchProcess as exc:
            raise ToolError(f"No such process: {pid}") from exc
        except ps.AccessDenied as exc:
            raise ToolError(f"Access denied to process {pid}") from exc
        result.finalize(f"Details for PID {pid} ({result.data['name']})")
    return result


def control_process(pid: int, action: str) -> OperationResult:
    """Kill, suspend or resume a process by PID."""
    with timed("process_tools", action) as result:
        ps = _require_psutil()
        if action not in ("kill", "suspend", "resume"):
            raise ValidationError(f"Unknown action {action!r} (kill|suspend|resume)")
        pid = validate_pid(pid)
        try:
            proc = ps.Process(pid)
            name = proc.name()
            getattr(proc, "terminate" if action == "kill" else action)()
        except ps.NoSuchProcess as exc:
            raise ToolError(f"No such process: {pid}") from exc
        except ps.AccessDenied as exc:
            raise ToolError(f"Access denied to process {pid}") from exc
        result.data = {"pid": pid, "name": name, "action": action}
        result.finalize(f"Sent {action} to PID {pid} ({name})")
        _log.warning("process_tools: %s PID %d (%s)", action, pid, name)
    return result


def _safe(func) -> Any:
    try:
        return func()
    except Exception:  # noqa: BLE001 - best-effort field, may be denied  # pragma: no cover
        return None
