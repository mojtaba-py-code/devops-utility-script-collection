"""File synchronisation: one-way, mirror and two-way sync with SHA-256 checks.

A file is considered "changed" when its size differs or, when sizes match, when
its SHA-256 digest differs — so an in-place edit that preserves the size is
still detected. Every mode honours ``dry_run`` (plan without touching disk) and
confines all writes/deletes to the destination through the security helpers.

* **one-way**  — make *destination* look like *source* for changed/new files
  (existing extra files in *destination* are left alone).
* **mirror**   — like one-way, but also delete files in *destination* that no
  longer exist in *source* (exact replica).
* **two-way**  — reconcile both trees; the newer mtime wins on conflict.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from core.base import OperationResult, timed
from tools.checksum import hash_file
from utils.exceptions import ValidationError
from utils.logging_config import get_logger
from utils.security import resolve_path, validate_delete_path, validate_output_path

_log = get_logger("file_sync")


def _relative_files(root: Path) -> dict[str, Path]:
    return {
        child.relative_to(root).as_posix(): child
        for child in root.rglob("*")
        if child.is_file() and not child.is_symlink()
    }


def _differs(a: Path, b: Path) -> bool:
    """True if files *a* and *b* differ (by size, then by digest)."""
    if a.stat().st_size != b.stat().st_size:
        return True
    return hash_file(a) != hash_file(b)


def _copy(src: Path, dst: Path, *, dry_run: bool) -> None:
    if dry_run:
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def sync(
    source: str | Path,
    destination: str | Path,
    *,
    mode: str = "one-way",
    dry_run: bool = False,
    allowed_roots: list[str] | None = None,
) -> OperationResult:
    """Synchronise *source* into *destination* using the given *mode*."""
    with timed("file_sync", mode) as result:
        if mode not in ("one-way", "mirror", "two-way"):
            raise ValidationError(f"Unknown sync mode {mode!r} (one-way|mirror|two-way)")
        src = resolve_path(source, strict=True)
        if not src.is_dir():
            raise ValidationError(f"Sync source must be a directory: {src}")
        dst = validate_output_path(destination, allowed_roots=allowed_roots)
        dst.mkdir(parents=True, exist_ok=True)

        if mode == "two-way":
            plan = _plan_two_way(src, dst)
        else:
            plan = _plan_one_way(src, dst, mirror=mode == "mirror")

        _apply(plan, allowed_roots=allowed_roots, dry_run=dry_run)

        result.status = result.status.DRY_RUN if dry_run else result.status.SUCCESS
        result.data = {
            "source": str(src),
            "destination": str(dst),
            "mode": mode,
            "dry_run": dry_run,
            "copied": [str(p) for _, p in plan["copy"]],
            "deleted": [str(p) for p in plan["delete"]],
        }
        verb = "Would sync" if dry_run else "Synced"
        result.finalize(
            f"{verb} {len(plan['copy'])} file(s), "
            f"{len(plan['delete'])} deletion(s) [{mode}]"
        )
        _log.info("file_sync[%s%s]: %d copy, %d delete", mode,
                  ":dry" if dry_run else "", len(plan["copy"]), len(plan["delete"]))
    return result


def _plan_one_way(src: Path, dst: Path, *, mirror: bool) -> dict[str, list[Any]]:
    src_files = _relative_files(src)
    dst_files = _relative_files(dst)
    copy: list[tuple[Path, Path]] = []
    for rel, src_path in src_files.items():
        dst_path = dst / rel
        if rel not in dst_files or _differs(src_path, dst_files[rel]):
            copy.append((src_path, dst_path))
    delete: list[Path] = []
    if mirror:
        for rel, dst_path in dst_files.items():
            if rel not in src_files:
                delete.append(dst_path)
    return {"copy": copy, "delete": delete}


def _plan_two_way(a: Path, b: Path) -> dict[str, list[Any]]:
    a_files, b_files = _relative_files(a), _relative_files(b)
    copy: list[tuple[Path, Path]] = []
    for rel in set(a_files) | set(b_files):
        in_a, in_b = a_files.get(rel), b_files.get(rel)
        if in_a and not in_b:
            copy.append((in_a, b / rel))
        elif in_b and not in_a:
            copy.append((in_b, a / rel))
        elif in_a and in_b and _differs(in_a, in_b):
            # Conflict: newest mtime wins.
            if in_a.stat().st_mtime >= in_b.stat().st_mtime:
                copy.append((in_a, b / rel))
            else:
                copy.append((in_b, a / rel))
    return {"copy": copy, "delete": []}


def _apply(plan: dict[str, list[Any]], *, allowed_roots: list[str] | None, dry_run: bool) -> None:
    for src_path, dst_path in plan["copy"]:
        validate_output_path(dst_path, allowed_roots=allowed_roots)
        _copy(src_path, dst_path, dry_run=dry_run)
    for path in plan["delete"]:
        validate_delete_path(path, allowed_roots=allowed_roots)
        if not dry_run:
            path.unlink()
