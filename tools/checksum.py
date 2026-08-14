"""Checksum utility: generate and verify cryptographic file hashes.

Large files are streamed in configurable chunks so hashing a multi-gigabyte
archive never loads it into memory. Verification is constant-time-friendly
(``hmac.compare_digest``) to avoid leaking timing information about the digest.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable
from pathlib import Path

from core.base import OperationResult, timed
from utils.exceptions import ValidationError
from utils.logging_config import get_logger

SUPPORTED_ALGORITHMS: tuple[str, ...] = ("md5", "sha1", "sha256", "sha512")
_DEFAULT_CHUNK = 1_048_576  # 1 MiB

_log = get_logger("checksum")


def _new_hash(algorithm: str):
    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValidationError(
            f"Unsupported algorithm {algorithm!r} (choose {SUPPORTED_ALGORITHMS})"
        )
    return hashlib.new(algorithm)


def hash_file(path: str | Path, *, algorithm: str = "sha256", chunk_size: int = _DEFAULT_CHUNK) -> str:
    """Return the hex digest of *path* using *algorithm*, streamed in chunks."""
    file_path = Path(path)
    if not file_path.is_file():
        raise ValidationError(f"Not a file: {file_path}")
    digest = _new_hash(algorithm)
    with file_path.open("rb") as handle:
        for block in iter(lambda: handle.read(chunk_size), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_file(path: str | Path, expected: str, *, algorithm: str = "sha256") -> bool:
    """Return ``True`` if *path* hashes to *expected* (case-insensitive)."""
    actual = hash_file(path, algorithm=algorithm)
    return hmac.compare_digest(actual.lower(), str(expected).strip().lower())


def hash_paths(
    paths: Iterable[str | Path], *, algorithm: str = "sha256", chunk_size: int = _DEFAULT_CHUNK
) -> OperationResult:
    """Hash every path in *paths*; collect digests and per-file errors."""
    with timed("checksum", "hash") as result:
        digests: dict[str, str] = {}
        for raw in paths:
            path = Path(raw)
            try:
                digests[str(path)] = hash_file(path, algorithm=algorithm, chunk_size=chunk_size)
            except (ValidationError, OSError) as exc:
                result.add_error(f"{path}: {exc}")
        result.data = {"algorithm": algorithm, "digests": digests, "count": len(digests)}
        result.finalize(f"Hashed {len(digests)} file(s) with {algorithm}")
        _log.info("checksum: hashed %d file(s) with %s", len(digests), algorithm)
    return result


def verify_paths(
    expected: dict[str, str], *, algorithm: str = "sha256"
) -> OperationResult:
    """Verify a mapping of ``{path: expected_digest}``; report mismatches."""
    with timed("checksum", "verify") as result:
        matched, mismatched, missing = [], [], []
        for path, digest in expected.items():
            file_path = Path(path)
            if not file_path.is_file():
                missing.append(path)
                result.add_error(f"{path}: file not found")
                continue
            if verify_file(file_path, digest, algorithm=algorithm):
                matched.append(path)
            else:
                mismatched.append(path)
                result.add_error(f"{path}: digest mismatch")
        result.data = {
            "algorithm": algorithm,
            "matched": matched,
            "mismatched": mismatched,
            "missing": missing,
        }
        if mismatched or missing:
            result.fail(f"{len(mismatched)} mismatch(es), {len(missing)} missing")
        else:
            result.finalize(f"All {len(matched)} file(s) verified")
    return result


def write_checksum_file(
    paths: Iterable[str | Path], out_path: str | Path, *, algorithm: str = "sha256"
) -> Path:
    """Write a ``sha256sum``-style ``<digest>  <name>`` manifest and return it."""
    out = Path(out_path)
    lines = []
    for raw in paths:
        path = Path(raw)
        lines.append(f"{hash_file(path, algorithm=algorithm)}  {path.name}")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out
