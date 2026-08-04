"""Disk utility: usage, free space, largest files, empty dirs, temp cleanup.

The cleanup action is the only destructive one; it is ``dry_run`` by default at
the CLI layer, validates every deletion through the security helpers, and only
ever targets files matching the configured age/pattern criteria.
"""

from __future__ import annotations

import time
from pathlib import Path

from core.base import OperationResult, timed
from utils.exceptions import ValidationError
from utils.formatting import human_bytes
from utils.logging_config import get_logger
from utils.security import resolve_path, validate_delete_path

_log = get_logger("disk_tools")

# Extensions considered "temporary" by the cleanup helper.
_TEMP_PATTERNS = ("*.tmp", "*.temp", "*.log.old", "*.bak", "*~", "*.pyc")


def disk_usage(path: str | Path = ".") -> OperationResult:
    """Report total/used/free space for the filesystem containing *path*."""
    with timed("disk_tools", "usage") as result:
        import shutil

        target = resolve_path(path, strict=True)
        total, used, free = shutil.disk_usage(target)
        result.data = {
            "path": str(target),
            "total": total,
            "used": used,
            "free": free,
            "total_human": human_bytes(total),
            "used_human": human_bytes(used),
            "free_human": human_bytes(free),
            "used_percent": round(used / total * 100, 1) if total else 0.0,
        }
        result.finalize(f"{human_bytes(free)} free of {human_bytes(total)} on {target}")
    return result


def largest_files(path: str | Path, *, top: int = 10) -> OperationResult:
    """Find the *top* largest files beneath *path*."""
    with timed("disk_tools", "largest") as result:
        root = resolve_path(path, strict=True)
        if not root.is_dir():
            raise ValidationError(f"Not a directory: {root}")
        sizes: list[tuple[int, str]] = []
        for child in root.rglob("*"):
            if child.is_file() and not child.is_symlink():
                try:
                    sizes.append((child.stat().st_size, str(child)))
                except OSError:  # pragma: no cover
                    continue
        sizes.sort(reverse=True)
        top_files = [
            {"path": p, "size": s, "size_human": human_bytes(s)} for s, p in sizes[: max(1, top)]
        ]
        result.data = {"path": str(root), "top": top, "files": top_files, "scanned": len(sizes)}
        result.finalize(f"Found {len(top_files)} largest file(s) under {root.name}")
    return result


def empty_dirs(path: str | Path) -> OperationResult:
    """List directories under *path* that contain no files (recursively)."""
    with timed("disk_tools", "empty_dirs") as result:
        root = resolve_path(path, strict=True)
        empties = []
        for child in root.rglob("*"):
            if child.is_dir() and not any(child.iterdir()):
                empties.append(str(child))
        result.data = {"path": str(root), "empty_dirs": empties, "count": len(empties)}
        result.finalize(f"Found {len(empties)} empty director(y/ies)")
    return result


def cleanup_temp(
    path: str | Path,
    *,
    older_than_days: float = 0,
    dry_run: bool = True,
    allowed_roots: list[str] | None = None,
) -> OperationResult:
    """Remove temporary files under *path* (dry-run by default).

    A file is a candidate when its name matches a temp pattern *and* it is older
    than *older_than_days*. Nothing outside *allowed_roots* (when set) is ever
    touched, and each deletion is re-validated defensively.
    """
    with timed("disk_tools", "cleanup") as result:
        root = resolve_path(path, strict=True)
        if not root.is_dir():
            raise ValidationError(f"Not a directory: {root}")
        cutoff = time.time() - older_than_days * 86_400
        removed: list[str] = []
        reclaimed = 0
        for pattern in _TEMP_PATTERNS:
            for child in root.rglob(pattern):
                if not child.is_file() or child.is_symlink():
                    continue
                if older_than_days and child.stat().st_mtime > cutoff:
                    continue
                size = child.stat().st_size
                validate_delete_path(child, allowed_roots=allowed_roots)
                if not dry_run:
                    try:
                        child.unlink()
                    except OSError as exc:  # pragma: no cover
                        result.add_error(f"{child}: {exc}")
                        continue
                removed.append(str(child))
                reclaimed += size
        result.status = result.status.DRY_RUN if dry_run else result.status.SUCCESS
        result.data = {
            "path": str(root),
            "dry_run": dry_run,
            "removed": removed,
            "count": len(removed),
            "reclaimed_bytes": reclaimed,
            "reclaimed_human": human_bytes(reclaimed),
        }
        verb = "Would remove" if dry_run else "Removed"
        result.finalize(f"{verb} {len(removed)} temp file(s), {human_bytes(reclaimed)}")
        _log.info("disk_tools cleanup[%s]: %d files, %s",
                  "dry" if dry_run else "live", len(removed), human_bytes(reclaimed))
    return result
