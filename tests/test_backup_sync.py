"""Tests for the backup and file-sync tools."""

from __future__ import annotations

from pathlib import Path

from tools import backup, file_sync


# --- backup -----------------------------------------------------------------
def test_full_backup_creates_archive_and_manifest(tree: Path, tmp_path: Path):
    dest = tmp_path / "backups"
    result = backup.create_backup(tree, dest, mode="full")
    assert result.ok
    assert result.data["archived"] == 3
    assert Path(result.data["archive"]).exists()
    assert Path(result.data["manifest"]).exists()
    assert result.data["verified"] is True


def test_incremental_only_archives_changes(tree: Path, tmp_path: Path):
    dest = tmp_path / "backups"
    backup.create_backup(tree, dest, mode="full")
    # No changes -> skipped.
    second = backup.create_backup(tree, dest, mode="incremental")
    assert second.status.value == "skipped"
    # Change one file -> only that file is archived.
    (tree / "a.txt").write_text("changed", encoding="utf-8")
    third = backup.create_backup(tree, dest, mode="incremental")
    assert third.ok
    assert third.data["archived"] == 1


def test_backup_verify_and_restore(tree: Path, tmp_path: Path):
    dest = tmp_path / "backups"
    result = backup.create_backup(tree, dest, mode="full")
    archive_path = result.data["archive"]

    verified = backup.verify_backup(archive_path)
    assert verified.ok

    target = tmp_path / "restored"
    restored = backup.restore_backup(archive_path, target)
    assert restored.ok
    assert (target / "a.txt").read_text(encoding="utf-8") == "alpha"


def test_backup_versioning_prunes(tree: Path, tmp_path: Path):
    dest = tmp_path / "backups"
    for i in range(4):
        (tree / "a.txt").write_text(f"v{i}", encoding="utf-8")
        backup.create_backup(tree, dest, mode="full", keep_versions=2)
    archives = list(dest.glob("backup_*.zip"))
    assert len(archives) == 2  # older versions pruned


def test_pruning_keeps_newest_full_across_mixed_modes(tree: Path, tmp_path: Path):
    # Regression: filenames must be ordered by timestamp, not lexically — else
    # 'full' < 'incremental' makes pruning delete the newest full backup.
    dest = tmp_path / "backups"
    backup.create_backup(tree, dest, mode="full", keep_versions=10)
    for i in range(3):
        (tree / "a.txt").write_text(f"change{i}", encoding="utf-8")
        backup.create_backup(tree, dest, mode="incremental", keep_versions=10)
    # A newer full backup, then more incrementals.
    (tree / "b.txt").write_text("newfull", encoding="utf-8")
    newest_full = backup.create_backup(tree, dest, mode="full", keep_versions=3)
    newest_full_name = Path(newest_full.data["archive"]).name
    (tree / "a.txt").write_text("later", encoding="utf-8")
    backup.create_backup(tree, dest, mode="incremental", keep_versions=3)

    remaining = {p.name for p in dest.glob("backup_*.zip")}
    assert newest_full_name in remaining  # the newest full survived pruning
    assert len(remaining) == 3            # keep_versions honoured


def test_incremental_restore_reconstructs_full_chain(tree: Path, tmp_path: Path):
    dest = tmp_path / "backups"
    backup.create_backup(tree, dest, mode="full")
    (tree / "a.txt").write_text("edited", encoding="utf-8")
    backup.create_backup(tree, dest, mode="incremental")
    (tree / "d.txt").write_text("delta", encoding="utf-8")
    latest = backup.create_backup(tree, dest, mode="incremental")

    target = tmp_path / "restored"
    result = backup.restore_backup(latest.data["archive"], target)
    assert result.ok
    assert len(result.data["chain"]) == 3               # full + 2 incrementals
    assert (target / "a.txt").read_text(encoding="utf-8") == "edited"   # latest content
    assert (target / "b.txt").read_text(encoding="utf-8") == "bravo"    # from the full
    assert (target / "d.txt").read_text(encoding="utf-8") == "delta"    # new file
    assert (target / "sub" / "c.txt").exists()


def test_single_incremental_restore_warns_partial(tree: Path, tmp_path: Path):
    dest = tmp_path / "backups"
    backup.create_backup(tree, dest, mode="full")
    (tree / "a.txt").write_text("edited", encoding="utf-8")
    inc = backup.create_backup(tree, dest, mode="incremental")
    target = tmp_path / "partial"
    result = backup.restore_backup(inc.data["archive"], target, chain=False)
    assert result.ok
    assert result.warnings                              # flagged as possibly partial
    assert not (target / "b.txt").exists()              # unchanged file absent


def test_restore_incremental_without_full_fails(tree: Path, tmp_path: Path):
    # An incremental archive with no full backup in the directory cannot be
    # reconstructed and must fail loudly rather than restore a partial tree.
    dest = tmp_path / "backups"
    backup.create_backup(tree, dest, mode="full")
    (tree / "a.txt").write_text("edited", encoding="utf-8")
    inc = backup.create_backup(tree, dest, mode="incremental")
    # Remove the full backup + its manifest, leaving only the incremental.
    for full in list(dest.glob("backup_full_*")):
        full.unlink()
    result = backup.restore_backup(inc.data["archive"], tmp_path / "out")
    assert not result.ok


def test_list_backups(tree: Path, tmp_path: Path):
    dest = tmp_path / "backups"
    backup.create_backup(tree, dest, mode="full")
    listed = backup.list_backups(dest)
    assert listed and listed[0]["mode"] == "full"
    assert backup.list_backups(tmp_path / "nope") == []


# --- file sync --------------------------------------------------------------
def test_one_way_sync_copies_new_and_changed(tree: Path, tmp_path: Path):
    dst = tmp_path / "dst"
    result = file_sync.sync(tree, dst, mode="one-way")
    assert result.ok
    assert (dst / "a.txt").read_text(encoding="utf-8") == "alpha"
    assert (dst / "sub" / "c.txt").exists()

    # Re-sync with no changes -> nothing copied.
    again = file_sync.sync(tree, dst, mode="one-way")
    assert again.data["copied"] == []


def test_mirror_deletes_extraneous(tree: Path, tmp_path: Path):
    dst = tmp_path / "dst"
    file_sync.sync(tree, dst, mode="one-way")
    extra = dst / "extra.txt"
    extra.write_text("remove me", encoding="utf-8")
    result = file_sync.sync(tree, dst, mode="mirror")
    assert not extra.exists()
    assert result.data["deleted"]


def test_dry_run_changes_nothing(tree: Path, tmp_path: Path):
    dst = tmp_path / "dst"
    result = file_sync.sync(tree, dst, mode="one-way", dry_run=True)
    assert result.status.value == "dry_run"
    assert not (dst / "a.txt").exists()  # planned but not written


def test_two_way_sync_reconciles(tree: Path, tmp_path: Path):
    other = tmp_path / "other"
    other.mkdir()
    (other / "new.txt").write_text("fresh", encoding="utf-8")
    result = file_sync.sync(tree, other, mode="two-way")
    assert result.ok
    assert (other / "a.txt").exists()      # a.txt propagated tree -> other
    assert (tree / "new.txt").exists()     # new.txt propagated other -> tree


def test_detects_same_size_different_content(tmp_path: Path):
    src, dst = tmp_path / "s", tmp_path / "d"
    src.mkdir()
    dst.mkdir()
    (src / "f.txt").write_text("AAAAA", encoding="utf-8")
    (dst / "f.txt").write_text("BBBBB", encoding="utf-8")  # same size, different bytes
    result = file_sync.sync(src, dst, mode="one-way")
    assert result.data["copied"]
    assert (dst / "f.txt").read_text(encoding="utf-8") == "AAAAA"
