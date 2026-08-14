-- One key, one device id — enforced by the database, not only by the code above it.
--
-- Revocation here is by device id (`warrantor-archive revoke --device <id>`). That is only a
-- withdrawal if a private key can name exactly one id. If one public key could be enrolled twice,
-- revoking the id an operator can name would withdraw nothing: the same key would keep filing and
-- reading under the other id, and a revoked key could be re-enrolled into a fresh row and launder
-- its own revocation.
--
-- `store.rs` and `postgres.rs` both refuse a second enrolment of a known key before it gets this
-- far, with a message an operator can act on. This index is what holds when two enrolments race
-- past that read — the check is the message, the constraint is the guarantee.
--
-- Written as a separate migration rather than an edit to 0001 because 0001 may already have been
-- applied: `schema_migrations` records file names, and a changed 0001 would simply never run.
-- On a database that already holds a duplicate this CREATE fails, the transaction rolls back, and
-- `warrantor-archive migrate` reports it — which is the correct outcome. Two devices sharing a key
-- is exactly the state that has to be resolved by a human, by revoking one of them, before an
-- archive can claim its revocations mean anything.

CREATE UNIQUE INDEX IF NOT EXISTS device_public_key_unique ON device (public_key);
