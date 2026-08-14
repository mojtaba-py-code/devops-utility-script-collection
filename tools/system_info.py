"""System information tool: CPU, memory, disk, OS, network identity, uptime.

Uses ``psutil`` when available for rich metrics and degrades gracefully to the
standard library (``platform``, ``socket``, ``os``) when it is not, so the tool
still returns useful data on a minimal host.
"""

from __future__ import annotations

import os
import platform
import socket
import time
import uuid
from typing import TYPE_CHECKING, Any

from core.base import OperationResult, timed
from utils.formatting import human_bytes, human_duration

# Optional at runtime, always present for the type checker: the module is
# imported normally under TYPE_CHECKING so its real signatures are used,
# and falls back to None at runtime when it is not installed.
if TYPE_CHECKING:
    import psutil
else:
    try:
        import psutil
    except ImportError:  # pragma: no cover
        psutil = None


def _cpu_info() -> dict[str, Any]:
    info: dict[str, Any] = {
        "processor": platform.processor() or platform.machine(),
        "architecture": platform.machine(),
    }
    if psutil is not None:
        info["physical_cores"] = psutil.cpu_count(logical=False)
        info["logical_cores"] = psutil.cpu_count(logical=True)
        info["usage_percent"] = psutil.cpu_percent(interval=0.1)
        # cpu_freq() can raise on hosts where performance counters are
        # disabled (some Windows/VM setups) — treat it as best-effort.
        try:
            freq = psutil.cpu_freq()
            if freq is not None:
                info["frequency_mhz"] = round(freq.current, 1)
        except (RuntimeError, OSError, NotImplementedError):  # pragma: no cover
            info["frequency_mhz"] = None
    else:  # pragma: no cover - exercised only without psutil
        info["logical_cores"] = os.cpu_count()
    return info


def _memory_info() -> dict[str, Any]:
    if psutil is None:  # pragma: no cover
        return {}
    vm = psutil.virtual_memory()
    info = {
        "total": vm.total,
        "total_human": human_bytes(vm.total),
        "available": vm.available,
        "available_human": human_bytes(vm.available),
        "used_percent": vm.percent,
    }
    # swap_memory() can raise where performance counters are unavailable
    # (some Windows/VM hosts) — report it best-effort.
    try:
        swap = psutil.swap_memory()
        info["swap_total"] = swap.total
        info["swap_used_percent"] = swap.percent
    except (RuntimeError, OSError, NotImplementedError):  # pragma: no cover
        info["swap_total"] = None
        info["swap_used_percent"] = None
    return info


def _disk_info() -> list[dict[str, Any]]:
    if psutil is None:  # pragma: no cover
        return []
    disks = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (PermissionError, OSError):  # pragma: no cover - CD-ROM, etc.
            continue
        disks.append({
            "device": part.device,
            "mountpoint": part.mountpoint,
            "fstype": part.fstype,
            "total_human": human_bytes(usage.total),
            "used_percent": usage.percent,
        })
    return disks


def _network_identity() -> dict[str, Any]:
    hostname = socket.gethostname()
    try:
        ip_address = socket.gethostbyname(hostname)
    except socket.gaierror:  # pragma: no cover - offline host
        ip_address = "127.0.0.1"
    mac = ":".join(f"{(uuid.getnode() >> ele) & 0xFF:02x}" for ele in range(40, -1, -8))
    return {"hostname": hostname, "ip_address": ip_address, "mac_address": mac}


def _uptime() -> dict[str, Any]:
    if psutil is None:  # pragma: no cover
        return {}
    boot = psutil.boot_time()
    seconds = max(0, int(time.time() - boot))
    return {"boot_time": int(boot), "uptime_seconds": seconds, "uptime_human": human_duration(seconds)}


def collect_system_info() -> OperationResult:
    """Gather a full snapshot of the host's identity and resource usage."""
    with timed("system_info", "collect") as result:
        result.data = {
            "os": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "platform": platform.platform(),
            },
            "python_version": platform.python_version(),
            "cpu": _cpu_info(),
            "memory": _memory_info(),
            "disks": _disk_info(),
            "network": _network_identity(),
            "uptime": _uptime(),
        }
        host = result.data["network"]["hostname"]
        result.finalize(f"System snapshot for {host} ({platform.system()})")
    return result
