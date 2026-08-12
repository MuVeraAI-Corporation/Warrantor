"""Warrantor Backup/DR Coordinator — file-based backup, restore, retention pruning.

Coordinates file-level backups of Warrantor state: signed evidence stores (E1),
attestation ledgers, AAE policy snapshots, RBAC role bindings, SLA target
configs. Each ``BackupTarget`` names a source path, a destination directory, a
retention horizon (in days) and an ideal backup frequency (in hours).

The manager copies the source into ``backup_path`` with a timestamped suffix,
verifies the copy with a SHA-256 digest, records the result, and (during
``prune_expired``) removes backups older than the target's retention window.

Usage:
    mgr = BackupManager()
    mgr.add_target(BackupTarget(name="evidence", path="/var/aumos/evidence",
                                backup_path="/backups/evidence",
                                retention_days=30, frequency_hours=6))
    result = mgr.run_backup("evidence")
    assert result.success
"""

from __future__ import annotations

import contextlib
import hashlib
import re
import shutil
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class BackupTarget:
    """Definition of something that should be backed up.

    Attributes:
        name:            human-readable identifier used in API calls.
        path:            absolute source path (file or directory) to back up.
        backup_path:     directory where timestamped backup copies land.
        retention_days:  backups older than this many days are pruned.
        frequency_hours: advisory cadence — used by external schedulers.
    """

    name: str
    path: str
    backup_path: str
    retention_days: int = 30
    frequency_hours: int = 24

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("name must be a non-empty string")
        if self.retention_days < 0:
            raise ValueError("retention_days must be >= 0")
        if self.frequency_hours <= 0:
            raise ValueError("frequency_hours must be positive")


@dataclass
class BackupResult:
    """Outcome of a single ``run_backup`` invocation."""

    target_name: str
    success: bool
    backup_path: str = ""
    bytes_copied: int = 0
    digest: str = ""
    timestamp: float = 0.0
    reason: str = ""

    @property
    def timestamp_iso(self) -> str:
        if not self.timestamp:
            return ""
        return datetime.fromtimestamp(self.timestamp, tz=UTC).isoformat()


@dataclass
class RestoreResult:
    """Outcome of a single ``restore`` invocation."""

    target_name: str
    success: bool
    restored_to: str = ""
    bytes_restored: int = 0
    digest_verified: bool = False
    reason: str = ""


@dataclass
class _BackupManifestEntry:
    """In-memory record of one backup. (Persisted implicitly via filesystem.)"""

    target_name: str
    backup_path: str
    timestamp: float
    digest: str
    bytes_copied: int


# Backup filename pattern: <name>__<YYYYmmddTHHMMSSZ>__[digest8>
_BACKUP_RE = re.compile(r"^(?P<name>[^/]+)__(?P<ts>\d{8}T\d{6}Z)__\w+$")


def _sha256_of_path(path: Path) -> tuple[str, int]:
    """Compute SHA-256 and total byte count over a file or directory tree."""
    h = hashlib.sha256()
    total = 0
    if path.is_file():
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                h.update(chunk)
                total += len(chunk)
    else:
        for child in sorted(path.rglob("*")):
            if child.is_file():
                with child.open("rb") as f:
                    for chunk in iter(lambda: f.read(1 << 16), b""):
                        h.update(chunk)
                        total += len(chunk)
            # Stable ordering for empty dirs / metadata: include the rel path.
            h.update(str(child.relative_to(path)).encode("utf-8"))
    return h.hexdigest(), total


def _format_timestamp(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y%m%dT%H%M%SZ")


def _parse_timestamp(name_ts: str) -> float:
    return datetime.strptime(name_ts, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC).timestamp()


@dataclass
class BackupManager:
    """Coordinates backup, restore, listing and retention pruning.

    The manager keeps an in-memory manifest of backups it has performed in
    this process. ``list_backups`` falls back to scanning the destination
    directory so backups created in a prior process are still discoverable.
    """

    targets: dict[str, BackupTarget] = field(default_factory=dict)
    _manifest: list[_BackupManifestEntry] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Target management
    # ------------------------------------------------------------------
    def add_target(self, target: BackupTarget) -> None:
        """Register ``target``. Re-registering replaces the prior definition."""
        if not isinstance(target, BackupTarget):
            raise TypeError("target must be a BackupTarget instance")
        self.targets[target.name] = target

    def remove_target(self, name: str) -> bool:
        """Forget the target ``name``. Returns ``True`` if it existed.

        Note: this does **not** delete backups already on disk.
        """
        return self.targets.pop(name, None) is not None

    # ------------------------------------------------------------------
    # Backup
    # ------------------------------------------------------------------
    def run_backup(self, target_name: str, *, now: float | None = None) -> BackupResult:
        """Perform a backup of ``target_name``.

        Copies the source to ``backup_path`` under a timestamped name, computes
        a SHA-256 over the copy, and returns a ``BackupResult``. Missing
        sources or targets are reported as ``success=False`` rather than
        raising, so a scheduler can continue with the next target.
        """
        target = self.targets.get(target_name)
        if target is None:
            return BackupResult(
                target_name=target_name,
                success=False,
                reason=f"unknown target {target_name!r}",
            )
        src = Path(target.path)
        if not src.exists():
            return BackupResult(
                target_name=target_name,
                success=False,
                reason=f"source path does not exist: {target.path}",
            )
        if now is None:
            now = time.time()
        ts_str = _format_timestamp(now)
        # Temp dir is moved into place after the copy + digest succeeds so a
        # partial copy is never exposed under its final name.
        dest_root = Path(target.backup_path)
        dest_root.mkdir(parents=True, exist_ok=True)
        final_name = f"{target.name}__{ts_str}"
        final_path = dest_root / final_name
        tmp_path = dest_root / f"{final_name}.partial"

        try:
            if tmp_path.exists():
                shutil.rmtree(tmp_path) if tmp_path.is_dir() else tmp_path.unlink()
            if src.is_dir():
                shutil.copytree(src, tmp_path)
            else:
                tmp_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, tmp_path)
            digest, nbytes = _sha256_of_path(tmp_path)
            short_digest = digest[:8]
            final_with_digest = final_path.parent / f"{final_name}__{short_digest}"
            if final_with_digest.exists():
                # Idempotent: same name + digest already exists.
                shutil.rmtree(tmp_path) if tmp_path.is_dir() else tmp_path.unlink()
                result = BackupResult(
                    target_name=target_name,
                    success=True,
                    backup_path=str(final_with_digest),
                    bytes_copied=nbytes,
                    digest=digest,
                    timestamp=now,
                    reason="backup already exists (idempotent)",
                )
            else:
                tmp_path.rename(final_with_digest)
                result = BackupResult(
                    target_name=target_name,
                    success=True,
                    backup_path=str(final_with_digest),
                    bytes_copied=nbytes,
                    digest=digest,
                    timestamp=now,
                )
            self._manifest.append(
                _BackupManifestEntry(
                    target_name=target_name,
                    backup_path=result.backup_path,
                    timestamp=result.timestamp,
                    digest=result.digest,
                    bytes_copied=result.bytes_copied,
                )
            )
            return result
        except Exception as exc:
            # Best-effort cleanup of the partial copy.
            if tmp_path.exists():
                with contextlib.suppress(OSError):
                    if tmp_path.is_dir():
                        shutil.rmtree(tmp_path)
                    else:
                        tmp_path.unlink()
            return BackupResult(
                target_name=target_name,
                success=False,
                reason=f"backup failed: {exc}",
                timestamp=now,
            )

    # ------------------------------------------------------------------
    # Restore
    # ------------------------------------------------------------------
    def restore(
        self,
        target_name: str,
        backup_path: str,
        *,
        verify_digest: bool = True,
    ) -> RestoreResult:
        """Restore ``backup_path`` over the target's configured source path.

        When ``verify_digest`` is ``True`` (default) the manager recomputes the
        SHA-256 of the backup and matches it against the digest embedded in the
        backup's filename. A mismatch fails the restore.
        """
        target = self.targets.get(target_name)
        if target is None:
            return RestoreResult(
                target_name=target_name,
                success=False,
                reason=f"unknown target {target_name!r}",
            )
        bpath = Path(backup_path)
        if not bpath.exists():
            return RestoreResult(
                target_name=target_name,
                success=False,
                reason=f"backup path does not exist: {backup_path}",
            )
        digest_verified = False
        if verify_digest:
            digest, _ = _sha256_of_path(bpath)
            expected = bpath.name.rsplit("__", 1)[-1]
            digest_verified = digest.startswith(expected)
            if not digest_verified:
                return RestoreResult(
                    target_name=target_name,
                    success=False,
                    reason="digest verification failed",
                    digest_verified=False,
                )

        dest = Path(target.path)
        try:
            # Replace destination atomically-ish: blow away then copy in.
            if dest.exists():
                if dest.is_dir():
                    shutil.rmtree(dest)
                else:
                    dest.unlink()
            dest.parent.mkdir(parents=True, exist_ok=True)
            if bpath.is_dir():
                shutil.copytree(bpath, dest)
            else:
                shutil.copy2(bpath, dest)
            _, nbytes = _sha256_of_path(dest)
            return RestoreResult(
                target_name=target_name,
                success=True,
                restored_to=str(dest),
                bytes_restored=nbytes,
                digest_verified=digest_verified or not verify_digest,
            )
        except Exception as exc:
            return RestoreResult(
                target_name=target_name,
                success=False,
                reason=f"restore failed: {exc}",
            )

    # ------------------------------------------------------------------
    # Listing + pruning
    # ------------------------------------------------------------------
    def list_backups(self, target_name: str) -> list[str]:
        """Return sorted (newest-first) backup paths for ``target_name``."""
        target = self.targets.get(target_name)
        if target is None:
            return []
        root = Path(target.backup_path)
        if not root.exists():
            return []
        prefix = f"{target.name}__"
        candidates = [p for p in root.iterdir() if p.name.startswith(prefix)]

        # Sort by parsed timestamp descending.
        def _key(p: Path) -> float:
            m = _BACKUP_RE.match(p.name)
            return _parse_timestamp(m.group("ts")) if m else 0.0

        candidates.sort(key=_key, reverse=True)
        return [str(p) for p in candidates]

    def prune_expired(self, *, now: float | None = None) -> int:
        """Delete backups older than each target's retention window.

        Returns the number of backups removed.
        """
        if now is None:
            now = time.time()
        removed = 0
        for target in self.targets.values():
            root = Path(target.backup_path)
            if not root.exists():
                continue
            cutoff = now - target.retention_days * 86400
            for p in root.iterdir():
                m = _BACKUP_RE.match(p.name)
                if not m:
                    continue
                ts = _parse_timestamp(m.group("ts"))
                if ts < cutoff:
                    try:
                        if p.is_dir():
                            shutil.rmtree(p)
                        else:
                            p.unlink()
                        removed += 1
                    except OSError:
                        pass
        return removed


__all__ = [
    "BackupManager",
    "BackupResult",
    "BackupTarget",
    "RestoreResult",
]
