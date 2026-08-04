"""Archive utility: create, extract and verify ZIP / TAR / GZIP archives.

Extraction is the dangerous direction — a malicious archive can carry entries
whose names escape the destination (``../../etc/passwd``) or absolute paths.
Every member is validated against the destination root before it is written,
defeating the classic *Zip-Slip* / *Tar-Slip* path-traversal attack.
"""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path
from typing import Iterable

from core.base import OperationResult, timed
from utils.exceptions import SecurityError, ValidationError
from utils.logging_config import get_logger
from utils.security import is_within, resolve_path, validate_output_path

_log = get_logger("archive")

# format -> (suffix, tar mode or None for zip)
_FORMATS: dict[str, tuple[str, str | None]] = {
    "zip": (".zip", None),
    "tar": (".tar", "w"),
    "gztar": (".tar.gz", "w:gz"),
    "bztar": (".tar.bz2", "w:bz2"),
}


def create_archive(
    sources: Iterable[str | Path],
    destination: str | Path,
    *,
    fmt: str = "zip",
    allowed_roots: Iterable[str] | None = None,
) -> OperationResult:
    """Compress *sources* into a single archive at *destination*."""
    with timed("archive", "create") as result:
        fmt = fmt.lower()
        if fmt not in _FORMATS:
            raise ValidationError(f"Unsupported format {fmt!r} (choose {tuple(_FORMATS)})")
        roots = list(allowed_roots) if allowed_roots else None
        dest = validate_output_path(destination, allowed_roots=roots)
        dest.parent.mkdir(parents=True, exist_ok=True)
        source_paths = [resolve_path(s, strict=True) for s in sources]

        added = 0
        if fmt == "zip":
            with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for src in source_paths:
                    added += _add_to_zip(zf, src)
        else:
            _, mode = _FORMATS[fmt]
            with tarfile.open(dest, mode) as tf:  # type: ignore[arg-type]
                for src in source_paths:
                    tf.add(src, arcname=src.name)
                    added += 1 if src.is_file() else sum(1 for _ in src.rglob("*"))

        result.data = {"archive": str(dest), "format": fmt, "entries": added,
                       "size_bytes": dest.stat().st_size}
        result.finalize(f"Created {dest.name} ({added} entr{'y' if added == 1 else 'ies'})")
        _log.info("archive: created %s with %d entries", dest, added)
    return result


def _add_to_zip(zf: zipfile.ZipFile, src: Path) -> int:
    if src.is_file():
        zf.write(src, arcname=src.name)
        return 1
    count = 0
    base = src.parent
    for child in src.rglob("*"):
        if child.is_file():
            zf.write(child, arcname=str(child.relative_to(base)))
            count += 1
    return count


def extract_archive(
    archive: str | Path,
    destination: str | Path,
    *,
    allowed_roots: Iterable[str] | None = None,
) -> OperationResult:
    """Safely extract *archive* into *destination* (Zip-Slip protected)."""
    with timed("archive", "extract") as result:
        arc = resolve_path(archive, strict=True)
        roots = list(allowed_roots) if allowed_roots else None
        dest = validate_output_path(destination, allowed_roots=roots)
        dest.mkdir(parents=True, exist_ok=True)

        if zipfile.is_zipfile(arc):
            extracted = _extract_zip(arc, dest)
        elif tarfile.is_tarfile(arc):
            extracted = _extract_tar(arc, dest)
        else:
            raise ValidationError(f"Not a recognised archive: {arc}")

        result.data = {"archive": str(arc), "destination": str(dest), "extracted": extracted}
        result.finalize(f"Extracted {extracted} member(s) to {dest.name}")
        _log.info("archive: extracted %d members from %s", extracted, arc)
    return result


def _safe_target(dest: Path, member_name: str) -> Path:
    """Resolve *member_name* under *dest*, rejecting traversal/absolute paths."""
    target = (dest / member_name).resolve()
    if not is_within(target, dest):
        raise SecurityError(f"Blocked path traversal in archive member: {member_name!r}")
    return target


def _extract_zip(arc: Path, dest: Path) -> int:
    count = 0
    with zipfile.ZipFile(arc) as zf:
        for member in zf.namelist():
            _safe_target(dest, member)  # validate before extracting
        zf.extractall(dest)
        count = sum(1 for m in zf.namelist() if not m.endswith("/"))
    return count


def _extract_tar(arc: Path, dest: Path) -> int:
    count = 0
    with tarfile.open(arc) as tf:
        members = tf.getmembers()
        for member in members:
            if member.islnk() or member.issym():
                raise SecurityError(f"Refusing link member in archive: {member.name!r}")
            _safe_target(dest, member.name)
        tf.extractall(dest)  # noqa: S202 - members validated above
        count = sum(1 for m in members if m.isfile())
    return count


def verify_archive(archive: str | Path) -> OperationResult:
    """Test the integrity of an archive without extracting it."""
    with timed("archive", "verify") as result:
        arc = resolve_path(archive, strict=True)
        bad: str | None
        if zipfile.is_zipfile(arc):
            with zipfile.ZipFile(arc) as zf:
                bad = zf.testzip()
            ok = bad is None
        elif tarfile.is_tarfile(arc):
            try:
                with tarfile.open(arc) as tf:
                    for member in tf.getmembers():
                        tf.extractfile(member) if member.isfile() else None
                ok, bad = True, None
            except tarfile.TarError as exc:
                ok, bad = False, str(exc)
        else:
            raise ValidationError(f"Not a recognised archive: {arc}")

        result.data = {"archive": str(arc), "valid": ok, "first_bad_member": bad}
        if ok:
            result.finalize(f"{arc.name} is intact")
        else:
            result.fail(f"Corrupt member in {arc.name}: {bad}")
    return result
