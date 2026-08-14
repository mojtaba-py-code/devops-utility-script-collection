"""Backup utility: full & incremental backups with verification and versioning.

Each backup is a compressed ZIP archive plus a JSON *manifest* recording every
file's relative path, size, mtime and SHA-256 digest. The manifest is what makes
the richer features possible:

* **Incremental** backups compare the source tree against the most recent
  manifest and archive only files that are new or whose digest changed.
* **Verification** re-hashes the archived bytes against the manifest, proving
  the backup is restorable rather than merely present.
* **Versioning** keeps the N most recent backups and prunes the rest.
* **Restore** extracts a chosen (or the latest) backup to a target directory,
  with the same Zip-Slip protection as the archive tool.
"""

from __future__ import annotations

import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.base import OperationResult, timed
from tools.checksum import hash_file
from utils.exceptions import ToolError, ValidationError
from utils.formatting import utc_stamp
from utils.logging_config import domain_logger
from utils.security import is_within, resolve_path, validate_output_path, zip_member_is_symlink

_log = domain_logger("backup")
_MANIFEST_SUFFIX = ".manifest.json"


@dataclass(frozen=True)
class FileEntry:
    """One file's fingerprint inside a backup manifest."""

    path: str          # POSIX-style path relative to the source root
    size: int
    mtime: float
    sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {"path": self.path, "size": self.size, "mtime": self.mtime, "sha256": self.sha256}


def _scan(source: Path) -> dict[str, FileEntry]:
    """Fingerprint every file under *source* keyed by its relative path."""
    entries: dict[str, FileEntry] = {}
    for child in sorted(source.rglob("*")):
        if child.is_file() and not child.is_symlink():
            rel = child.relative_to(source).as_posix()
            stat = child.stat()
            entries[rel] = FileEntry(rel, stat.st_size, stat.st_mtime, hash_file(child))
    return entries


# The creation stamp embedded in ``backup_{mode}_{stamp}.zip`` /
# ``...manifest.json``. Sorting on this (not the raw filename) is essential:
# a lexical sort puts every ``full`` before every ``incremental`` because
# 'f' < 'i', which would otherwise make pruning delete the newest full backup.
_STAMP_RE = re.compile(r"backup_(?:full|incremental)_(\d{8}T\d{6}_\d{6}Z)")


def _stamp_of(path: Path) -> str:
    match = _STAMP_RE.search(path.name)
    return match.group(1) if match else path.name


def _sorted_backups(dest: Path, pattern: str) -> list[Path]:
    """Return matching backup files ordered oldest → newest by creation stamp."""
    return sorted(dest.glob(pattern), key=_stamp_of)


def _latest_manifest(dest: Path) -> dict[str, Any] | None:
    manifests = _sorted_backups(dest, f"*{_MANIFEST_SUFFIX}")
    if not manifests:
        return None
    try:
        return json.loads(manifests[-1].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):  # pragma: no cover
        return None


def create_backup(
    source: str | Path,
    destination: str | Path,
    *,
    mode: str = "full",
    allowed_roots: list[str] | None = None,
    verify: bool = True,
    keep_versions: int = 5,
) -> OperationResult:
    """Create a *full* or *incremental* backup of *source* under *destination*."""
    with timed("backup", mode) as result:
        if mode not in ("full", "incremental"):
            raise ValidationError(f"Unknown backup mode {mode!r} (full|incremental)")
        src = resolve_path(source, strict=True)
        if not src.is_dir():
            raise ValidationError(f"Backup source must be a directory: {src}")
        dest = validate_output_path(destination, allowed_roots=allowed_roots)
        dest.mkdir(parents=True, exist_ok=True)

        current = _scan(src)
        previous = _latest_manifest(dest) if mode == "incremental" else None
        to_archive = _select_changed(current, previous) if previous else current

        if not to_archive:
            result.status = result.status.SKIPPED
            result.data = {"source": str(src), "changed": 0, "mode": mode}
            result.finalize("No changes since last backup — nothing to do")
            _log.info("backup: no changes for %s", src)
            return result

        stamp = utc_stamp()
        archive_path = dest / f"backup_{mode}_{stamp}.zip"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for rel in to_archive:
                zf.write(src / rel, arcname=rel)

        manifest = {
            "created_at": stamp,
            "mode": mode,
            "source": str(src),
            "archive": archive_path.name,
            "files": [current[rel].as_dict() for rel in current],
            "archived": sorted(to_archive),
        }
        manifest_path = dest / f"backup_{mode}_{stamp}{_MANIFEST_SUFFIX}"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        result.data = {
            "source": str(src),
            "archive": str(archive_path),
            "manifest": str(manifest_path),
            "mode": mode,
            "total_files": len(current),
            "archived": len(to_archive),
            "size_bytes": archive_path.stat().st_size,
        }

        if verify:
            report = verify_backup(archive_path)
            result.data["verified"] = report.ok
            if not report.ok:
                result.fail("Backup verification failed")
                return result

        pruned = _prune_versions(dest, keep_versions)
        result.data["pruned"] = pruned
        result.finalize(
            f"{mode.capitalize()} backup: {len(to_archive)}/{len(current)} file(s) archived"
        )
        _log.info("backup: %s backup of %s -> %s (%d files)", mode, src, archive_path.name, len(to_archive))
    return result


def _select_changed(current: dict[str, FileEntry], previous: dict[str, Any]) -> set[str]:
    prior = {f["path"]: f["sha256"] for f in previous.get("files", [])}
    return {rel for rel, entry in current.items() if prior.get(rel) != entry.sha256}


def _prune_versions(dest: Path, keep: int) -> int:
    if keep <= 0:
        return 0
    archives = _sorted_backups(dest, "backup_*.zip")  # oldest → newest by stamp
    stale = archives[:-keep] if len(archives) > keep else []
    removed = 0
    for archive in stale:
        manifest = archive.with_name(archive.stem + _MANIFEST_SUFFIX)
        for target in (archive, manifest):
            if target.exists():
                target.unlink()
        removed += 1
    return removed


def verify_backup(archive: str | Path) -> OperationResult:
    """Re-hash every entry in a backup archive against its manifest."""
    with timed("backup", "verify") as result:
        arc = resolve_path(archive, strict=True)
        manifest_path = arc.with_name(arc.stem + _MANIFEST_SUFFIX)
        if not manifest_path.exists():
            raise ToolError(f"No manifest for {arc.name}; cannot verify")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = {f["path"]: f["sha256"] for f in manifest.get("files", [])}

        import hashlib

        mismatched: list[str] = []
        checked = 0
        with zipfile.ZipFile(arc) as zf:
            for name in zf.namelist():
                if name.endswith("/"):
                    continue
                checked += 1
                digest = hashlib.sha256(zf.read(name)).hexdigest()
                if name in expected and expected[name] != digest:
                    mismatched.append(name)
        result.data = {"archive": str(arc), "checked": checked, "mismatched": mismatched}
        if mismatched:
            result.fail(f"{len(mismatched)} corrupt entr(y/ies) in {arc.name}")
        else:
            result.finalize(f"{arc.name} verified against manifest")
    return result


def _extract_into(arc: Path, dest: Path) -> int:
    """Safely extract *arc* into *dest* (Zip-Slip protected); return file count."""
    # Both sides of the containment test have to be resolved, or a symlink
    # anywhere in *dest*'s own path makes a contained target look uncontained
    # (or the reverse) purely because one side went through the link and the
    # other did not.
    root = dest.resolve()
    with zipfile.ZipFile(arc) as zf:
        for info in zf.infolist():
            if zip_member_is_symlink(info):
                raise ToolError(f"Refusing link member while restoring: {info.filename!r}")
            if not is_within((root / info.filename).resolve(), root):
                raise ToolError(f"Blocked path traversal restoring {info.filename!r}")
        zf.extractall(dest)  # nosec B202 - members validated above
        return sum(1 for n in zf.namelist() if not n.endswith("/"))


def _restore_chain(arc: Path) -> list[Path]:
    """Resolve the archive list needed to fully restore *arc*.

    A full backup restores from itself. An incremental only contains the files
    that changed since its baseline, so restoring it alone yields a *partial*
    tree — instead we walk back to the most recent full at or before it and
    replay every backup in between, oldest first (later files overwrite earlier).
    """
    if _STAMP_RE.search(arc.name) and "_full_" in arc.name:
        return [arc]
    dest = arc.parent
    target_stamp = _stamp_of(arc)
    history = [p for p in _sorted_backups(dest, "backup_*.zip") if _stamp_of(p) <= target_stamp]
    base_idx = next((i for i in range(len(history) - 1, -1, -1)
                     if "_full_" in history[i].name), None)
    if base_idx is None:
        raise ToolError(
            f"Cannot restore {arc.name}: no full backup found to base the chain on"
        )
    return history[base_idx:]


def restore_backup(
    archive: str | Path,
    target: str | Path,
    *,
    allowed_roots: list[str] | None = None,
    chain: bool = True,
) -> OperationResult:
    """Restore a backup into *target* (Zip-Slip protected).

    For an incremental backup this replays the full chain (most recent full →
    the requested incremental) so the restored tree is complete. Pass
    ``chain=False`` to extract only the single archive.
    """
    with timed("backup", "restore") as result:
        arc = resolve_path(archive, strict=True)
        dest = validate_output_path(target, allowed_roots=allowed_roots)
        dest.mkdir(parents=True, exist_ok=True)

        archives = _restore_chain(arc) if chain else [arc]
        total = 0
        for member in archives:
            total += _extract_into(member, dest)
        result.data = {
            "archive": str(arc),
            "target": str(dest),
            "restored": total,
            "chain": [p.name for p in archives],
        }
        if not chain and "_incremental_" in arc.name:
            result.add_warning("Restored a single incremental archive — the tree may be partial")
        result.finalize(f"Restored {total} file(s) to {dest.name} from {len(archives)} archive(s)")
        _log.info("backup: restored %d file(s) into %s from %d archive(s)",
                  total, dest, len(archives))
    return result


def list_backups(destination: str | Path) -> list[dict[str, Any]]:
    """List available backups under *destination*, newest first."""
    dest = Path(destination)
    if not dest.is_dir():
        return []
    backups = []
    for archive in reversed(_sorted_backups(dest, "backup_*.zip")):
        manifest = archive.with_name(archive.stem + _MANIFEST_SUFFIX)
        info: dict[str, Any] = {"archive": archive.name, "size_bytes": archive.stat().st_size}
        if manifest.exists():
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
                info.update(mode=data.get("mode"), created_at=data.get("created_at"),
                            files=len(data.get("files", [])), archived=len(data.get("archived", [])))
            except (OSError, json.JSONDecodeError):  # pragma: no cover
                pass
        backups.append(info)
    return backups
