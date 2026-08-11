# warrantor-backup

File-level **backup and disaster-recovery coordinator** for AumOS. Coordinates
backups of AumOS state: signed evidence stores (E1), attestation ledgers, AAE
policy snapshots, RBAC role bindings, SLA target configs.

Each `BackupTarget` names:

- `name` — human-readable identifier.
- `path` — absolute source path (file or directory) to back up.
- `backup_path` — directory where timestamped backup copies land.
- `retention_days` — backups older than this are pruned.
- `frequency_hours` — advisory cadence for external schedulers.

## Properties

- **Content-addressed**: each backup's filename embeds the first 8 hex chars of
  the SHA-256 of the backup content. `run_backup` is idempotent — the same
  source at the same timestamp produces the same backup path.
- **Verified restores**: by default, `restore` recomputes the SHA-256 of the
  backup and matches it against the digest encoded in the filename, failing
  fast on tampering.
- **Atomic-ish writes**: a copy lands in a `.partial` directory first and is
  renamed into place only after the digest is computed, so partial copies are
  never exposed under their final name.
- **Pluggable retention**: `prune_expired` deletes backups older than each
  target's `retention_days`.

## Usage

```python
from warrantor_backup import BackupManager, BackupTarget

mgr = BackupManager()
mgr.add_target(
    BackupTarget(
        name="evidence",
        path="/var/aumos/evidence",
        backup_path="/backups/evidence",
        retention_days=30,
        frequency_hours=6,
    )
)
result = mgr.run_backup("evidence")
assert result.success

# Later, restore a specific backup:
mgr.restore("evidence", result.backup_path)

# Discover and prune:
mgr.list_backups("evidence")
mgr.prune_expired()
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```
