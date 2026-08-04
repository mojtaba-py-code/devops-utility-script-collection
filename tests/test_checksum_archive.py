"""Tests for checksum and archive tools (including Zip-Slip protection)."""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

import pytest

from tools import archive, checksum
from utils.exceptions import ValidationError


# --- checksum ---------------------------------------------------------------
def test_hash_and_verify_file(tmp_path: Path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"hello world")
    digest = checksum.hash_file(f, algorithm="sha256")
    assert len(digest) == 64
    assert checksum.verify_file(f, digest)
    assert not checksum.verify_file(f, "0" * 64)


def test_hash_paths_result_and_errors(tmp_path: Path):
    f = tmp_path / "a.txt"
    f.write_text("x", encoding="utf-8")
    result = checksum.hash_paths([f, tmp_path / "missing.txt"])
    assert result.data["count"] == 1
    assert result.errors  # the missing file was reported
    assert result.status.value == "partial"


def test_unsupported_algorithm(tmp_path: Path):
    f = tmp_path / "a.txt"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(ValidationError):
        checksum.hash_file(f, algorithm="crc32")


def test_verify_paths_detects_mismatch_and_missing(tmp_path: Path):
    f = tmp_path / "a.txt"
    f.write_text("hello", encoding="utf-8")
    good = checksum.hash_file(f)
    result = checksum.verify_paths({str(f): good})
    assert result.ok
    bad = checksum.verify_paths({str(f): "0" * 64, str(tmp_path / "nope"): "x"})
    assert not bad.ok
    assert bad.data["mismatched"] and bad.data["missing"]


def test_write_checksum_file(tmp_path: Path):
    f = tmp_path / "a.txt"
    f.write_text("x", encoding="utf-8")
    manifest = checksum.write_checksum_file([f], tmp_path / "SHA256SUMS")
    assert manifest.exists()
    assert "a.txt" in manifest.read_text(encoding="utf-8")


# --- archive ----------------------------------------------------------------
def test_create_extract_verify_zip(tree: Path, tmp_path: Path):
    dest = tmp_path / "out.zip"
    created = archive.create_archive([tree], dest, fmt="zip")
    assert created.ok and dest.exists()

    verified = archive.verify_archive(dest)
    assert verified.ok and verified.data["valid"]

    out = tmp_path / "extracted"
    extracted = archive.extract_archive(dest, out)
    assert extracted.ok
    assert (out / "src" / "a.txt").exists()


def test_create_tar_gztar(tree: Path, tmp_path: Path):
    for fmt, suffix in (("tar", ".tar"), ("gztar", ".tar.gz")):
        dest = tmp_path / f"out{suffix}"
        result = archive.create_archive([tree], dest, fmt=fmt)
        assert result.ok and dest.exists()


def test_archive_rejects_bad_format(tree: Path, tmp_path: Path):
    result = archive.create_archive([tree], tmp_path / "x.7z", fmt="7z")
    assert not result.ok  # ValidationError captured onto the result


def test_extract_blocks_zip_slip(tmp_path: Path):
    evil = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil, "w") as zf:
        zf.writestr("../escape.txt", "pwned")
    result = archive.extract_archive(evil, tmp_path / "dest")
    assert not result.ok
    assert not (tmp_path / "escape.txt").exists()


def test_extract_blocks_tar_slip(tmp_path: Path):
    payload = tmp_path / "payload.txt"
    payload.write_text("data", encoding="utf-8")
    evil = tmp_path / "evil.tar"
    with tarfile.open(evil, "w") as tf:
        tf.add(payload, arcname="../escape.txt")
    result = archive.extract_archive(evil, tmp_path / "dest")
    assert not result.ok
    assert not (tmp_path / "escape.txt").exists()


def test_verify_detects_corruption(tree: Path, tmp_path: Path):
    dest = tmp_path / "out.zip"
    archive.create_archive([tree], dest, fmt="zip")
    data = bytearray(dest.read_bytes())
    data[-20] ^= 0xFF  # flip a byte inside the compressed payload
    dest.write_bytes(bytes(data))
    result = archive.verify_archive(dest)
    assert not result.ok
