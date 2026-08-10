"""Tests for warrantor_backup: target validation, backup, restore, prune, edge cases."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from warrantor_backup import (
    BackupManager,
    BackupResult,
    BackupTarget,
    RestoreResult,
)


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------
def test_backup_target_validation() -> None:
    with pytest.raises(ValueError):
        BackupTarget(name="", path="/x", backup_path="/y")
    with pytest.raises(ValueError):
        BackupTarget(name="x", path="/x", backup_path="/y", retention_days=-1)
    with pytest.raises(ValueError):
        BackupTarget(name="x", path="/x", backup_path="/y", frequency_hours=0)


def test_add_target_rejects_non_target() -> None:
    mgr = BackupManager()
    with pytest.raises(TypeError):
        mgr.add_target("nope")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Backup: file and directory
# ---------------------------------------------------------------------------
def test_run_backup_unknown_target_fails() -> None:
    mgr = BackupManager()
    result = mgr.run_backup("ghost")
    assert isinstance(result, BackupResult)
    assert result.success is False
    assert "unknown target" in result.reason


def test_run_backup_missing_source_fails(tmp_path: Path) -> None:
    mgr = BackupManager()
    mgr.add_target(
        BackupTarget(
            name="t",
            path=str(tmp_path / "missing"),
            backup_path=str(tmp_path / "bk"),
        )
    )
    result = mgr.run_backup("t")
    assert result.success is False
    assert "does not exist" in result.reason


def test_run_backup_single_file_succeeds(tmp_path: Path) -> None:
    src = tmp_path / "data.txt"
    src.write_text("hello aumos")
    bk = tmp_path / "backups"
    mgr = BackupManager()
    mgr.add_target(BackupTarget(name="data", path=str(src), backup_path=str(bk)))
    result = mgr.run_backup("data")
    assert result.success
    assert result.bytes_copied > 0
    assert result.digest and result.digest.startswith(result.backup_path.split("__")[-1])
    assert os.path.exists(result.backup_path)
    # Filename encodes the digest
    assert "__" in Path(result.backup_path).name


def test_run_backup_directory_succeeds(tmp_path: Path) -> None:
    src = tmp_path / "evidence"
    (src / "sub").mkdir(parents=True)
    (src / "a.txt").write_text("aaa")
    (src / "sub" / "b.txt").write_text("bbb")
    bk = tmp_path / "backups"
    mgr = BackupManager()
    mgr.add_target(BackupTarget(name="ev", path=str(src), backup_path=str(bk)))
    result = mgr.run_backup("ev")
    assert result.success
    # The backup is a directory with the same structure
    assert Path(result.backup_path).is_dir()
    assert (Path(result.backup_path) / "a.txt").read_text() == "aaa"
    assert (Path(result.backup_path) / "sub" / "b.txt").read_text() == "bbb"


def test_run_backup_is_idempotent(tmp_path: Path) -> None:
    src = tmp_path / "f.txt"
    src.write_text("same")
    bk = tmp_path / "bk"
    mgr = BackupManager()
    mgr.add_target(BackupTarget(name="f", path=str(src), backup_path=str(bk)))
    r1 = mgr.run_backup("f", now=1000.0)
    r2 = mgr.run_backup("f", now=1000.0)
    assert r1.success and r2.success
    # Same timestamp+digest -> same path
    assert r1.backup_path == r2.backup_path


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------
def test_restore_roundtrip_file(tmp_path: Path) -> None:
    src = tmp_path / "cfg"
    src.write_text("config v1")
    bk = tmp_path / "bk"
    mgr = BackupManager()
    mgr.add_target(BackupTarget(name="cfg", path=str(src), backup_path=str(bk)))
    backup = mgr.run_backup("cfg")
    assert backup.success
    # Mutate the source so we can prove restore brings it back.
    src.write_text("config v2 - corrupted")
    restore = mgr.restore("cfg", backup.backup_path)
    assert isinstance(restore, RestoreResult)
    assert restore.success
    assert restore.digest_verified
    assert src.read_text() == "config v1"


def test_restore_unknown_target_fails(tmp_path: Path) -> None:
    mgr = BackupManager()
    r = mgr.restore("ghost", str(tmp_path / "x"))
    assert r.success is False
    assert "unknown target" in r.reason


def test_restore_missing_backup_path_fails(tmp_path: Path) -> None:
    src = tmp_path / "f"
    src.write_text("x")
    mgr = BackupManager()
    mgr.add_target(BackupTarget(name="f", path=str(src), backup_path=str(tmp_path / "bk")))
    r = mgr.restore("f", str(tmp_path / "does_not_exist"))
    assert r.success is False
    assert "does not exist" in r.reason


def test_restore_detects_tampered_backup(tmp_path: Path) -> None:
    src = tmp_path / "f"
    src.write_text("original")
    bk = tmp_path / "bk"
    mgr = BackupManager()
    mgr.add_target(BackupTarget(name="f", path=str(src), backup_path=str(bk)))
    result = mgr.run_backup("f")
    assert result.success
    # Tamper with the on-disk backup so the digest no longer matches.
    Path(result.backup_path).write_text("tampered")
    restore = mgr.restore("f", result.backup_path)
    assert restore.success is False
    assert "digest" in restore.reason
    assert restore.digest_verified is False


def test_restore_without_digest_verification(tmp_path: Path) -> None:
    src = tmp_path / "f"
    src.write_text("x")
    bk = tmp_path / "bk"
    mgr = BackupManager()
    mgr.add_target(BackupTarget(name="f", path=str(src), backup_path=str(bk)))
    result = mgr.run_backup("f")
    # Tamper, but skip verification -> restore succeeds
    Path(result.backup_path).write_text("tampered")
    restore = mgr.restore("f", result.backup_path, verify_digest=False)
    assert restore.success
    assert restore.digest_verified is True  # skipped -> treated as verified
    assert src.read_text() == "tampered"


# ---------------------------------------------------------------------------
# Listing + pruning
# ---------------------------------------------------------------------------
def test_list_backups_sorted_newest_first(tmp_path: Path) -> None:
    src = tmp_path / "f"
    src.write_text("x")
    bk = tmp_path / "bk"
    mgr = BackupManager()
    mgr.add_target(BackupTarget(name="f", path=str(src), backup_path=str(bk)))
    r1 = mgr.run_backup("f", now=1000.0)
    r2 = mgr.run_backup("f", now=2000.0)
    r3 = mgr.run_backup("f", now=3000.0)
    listed = mgr.list_backups("f")
    assert listed == [r3.backup_path, r2.backup_path, r1.backup_path]


def test_list_backups_unknown_target_empty() -> None:
    mgr = BackupManager()
    assert mgr.list_backups("ghost") == []


def test_prune_expired_removes_old_backups(tmp_path: Path) -> None:
    src = tmp_path / "f"
    src.write_text("x")
    bk = tmp_path / "bk"
    mgr = BackupManager()
    mgr.add_target(BackupTarget(name="f", path=str(src), backup_path=str(bk), retention_days=1))
    old = mgr.run_backup("f", now=time.time() - 2 * 86400)  # 2 days ago
    fresh = mgr.run_backup("f", now=time.time())
    assert old.success and fresh.success
    removed = mgr.prune_expired()
    assert removed == 1
    remaining = mgr.list_backups("f")
    assert fresh.backup_path in remaining
    assert old.backup_path not in remaining


def test_prune_expired_zero_when_nothing_old(tmp_path: Path) -> None:
    src = tmp_path / "f"
    src.write_text("x")
    bk = tmp_path / "bk"
    mgr = BackupManager()
    mgr.add_target(BackupTarget(name="f", path=str(src), backup_path=str(bk), retention_days=30))
    mgr.run_backup("f")
    assert mgr.prune_expired() == 0


def test_remove_target_does_not_delete_backups(tmp_path: Path) -> None:
    src = tmp_path / "f"
    src.write_text("x")
    bk = tmp_path / "bk"
    mgr = BackupManager()
    mgr.add_target(BackupTarget(name="f", path=str(src), backup_path=str(bk)))
    result = mgr.run_backup("f")
    assert mgr.remove_target("f") is True
    assert mgr.remove_target("f") is False
    # Backup file still on disk
    assert os.path.exists(result.backup_path)
