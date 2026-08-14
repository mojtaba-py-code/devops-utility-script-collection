"""Resource monitoring with threshold-based severity and alerting.

Samples CPU, memory and disk via ``psutil``, compares each against configurable
``warning``/``critical`` thresholds, and returns a structured result whose
status reflects the worst breach. Optional notification channels (webhook based)
are delivered through :mod:`tools.notify`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from core.base import OperationResult, timed
from utils.logging_config import domain_logger

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

_log = domain_logger("monitoring")

_DEFAULT_THRESHOLDS: dict[str, dict[str, float]] = {
    "cpu_percent": {"warning": 80, "critical": 95},
    "memory_percent": {"warning": 80, "critical": 92},
    "disk_percent": {"warning": 80, "critical": 92},
}


def _severity(value: float, thresholds: dict[str, float]) -> str:
    if value >= thresholds.get("critical", 101):
        return "critical"
    if value >= thresholds.get("warning", 101):
        return "warning"
    return "ok"


def snapshot(
    thresholds: dict[str, dict[str, float]] | None = None, *, disk_path: str = "/"
) -> OperationResult:
    """Take one monitoring sample and evaluate it against *thresholds*."""
    with timed("monitoring", "snapshot") as result:
        if psutil is None:  # pragma: no cover
            from utils.exceptions import ToolError

            raise ToolError("monitoring requires 'psutil' (pip install psutil)")
        cfg = {**_DEFAULT_THRESHOLDS, **(thresholds or {})}

        import os

        path = disk_path if os.path.exists(disk_path) else os.path.abspath(os.sep)
        readings = {
            "cpu_percent": psutil.cpu_percent(interval=0.2),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage(path).percent,
        }
        metrics: dict[str, Any] = {}
        worst = "ok"
        for key, value in readings.items():
            sev = _severity(value, cfg.get(key, {}))
            metrics[key] = {"value": round(value, 1), "severity": sev,
                            "thresholds": cfg.get(key, {})}
            if sev == "critical" or (sev == "warning" and worst == "ok"):
                worst = sev
        result.data = {"metrics": metrics, "worst_severity": worst}
        breaches = [k for k, m in metrics.items() if m["severity"] != "ok"]
        if worst == "critical":
            result.fail(f"CRITICAL: {', '.join(breaches)}")
        elif worst == "warning":
            result.add_warning(f"WARNING: {', '.join(breaches)}")
            result.finalize(f"Warning on {', '.join(breaches)}")
        else:
            result.finalize("All metrics within thresholds")
        _log.info("monitoring: worst=%s breaches=%s", worst, breaches)
    return result
