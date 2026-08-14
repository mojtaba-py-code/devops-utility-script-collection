"""Human-friendly formatting helpers used by the CLI and reports."""

from __future__ import annotations

from datetime import UTC, datetime

_UNITS = ("B", "KB", "MB", "GB", "TB", "PB")


def human_bytes(num: float | int | None) -> str:
    """Render a byte count as e.g. ``1.4 GB``. ``None`` becomes ``"—"``."""
    if num is None:
        return "—"
    value = float(num)
    negative = value < 0
    value = abs(value)
    for unit in _UNITS:
        if value < 1024 or unit == _UNITS[-1]:
            rendered = f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
            return f"-{rendered}" if negative else rendered
        value /= 1024
    return f"{value:.1f} PB"  # pragma: no cover - unreachable, loop returns


def human_duration(seconds: float | int | None) -> str:
    """Render a duration in seconds as ``1h 2m 3s`` (compact, no zero units)."""
    if seconds is None:
        return "—"
    seconds = int(seconds)
    if seconds < 0:
        return "—"
    if seconds == 0:
        return "0s"
    parts: list[str] = []
    for label, size in (("d", 86_400), ("h", 3_600), ("m", 60), ("s", 1)):
        if seconds >= size:
            qty, seconds = divmod(seconds, size)
            parts.append(f"{qty}{label}")
    return " ".join(parts)


def utc_now_iso() -> str:
    """Current UTC time as a second-precision ISO-8601 string."""
    return datetime.now(UTC).isoformat(timespec="seconds")


def utc_stamp() -> str:
    """Filesystem-safe UTC timestamp with microseconds, e.g.
    ``20260803T061500_123456Z`` — precise enough to keep rapid, successive
    filenames (backups, reports) unique."""
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S_%fZ")


def truncate(text: str, width: int = 60) -> str:
    """Truncate *text* to *width* characters with an ellipsis."""
    text = str(text)
    return text if len(text) <= width else text[: width - 1] + "…"
