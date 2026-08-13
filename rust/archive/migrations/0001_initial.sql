-- The evidence archive's schema: append-only custody for signed Warrantor evidence.
--
-- Two roles, and the split is the point:
--   * archive_admin -- owns the schema, runs migrations, can do anything.
--   * archive_runtime -- what the server connects as. INSERT and SELECT on `artifact`, and NO
--     UPDATE or DELETE grant at all.
--
-- Append-only is enforced TWICE, and both are wanted. A grant can be misconfigured by an operator
-- restoring a backup or copying a role; a BEFORE UPDATE OR DELETE trigger cannot be, because it is
-- part of the object being restored. Belt is not a substitute for braces here: the grant stops the
-- server from asking, and the trigger stops the database from complying.
--
-- What neither prevents, and the RFC says so out loud: whoever owns the database can drop the
-- trigger and delete rows. Append-only is a property of the application role, not of the storage.
-- What actually carries the custody guarantee is that every artifact here is independently
-- verifiable OFF this archive, against an anchor the reader pinned.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── devices ──────────────────────────────────────────────────────────────────────────
--
-- Only PUBLIC key material is ever stored. A stolen dump of this table lets nobody sign anything.

CREATE TABLE IF NOT EXISTS device (
    id           TEXT PRIMARY KEY,
    label        TEXT NOT NULL,
    public_key   TEXT NOT NULL,
    enrolled_at  BIGINT NOT NULL,
    enrolled_by  TEXT,
    -- Revocation is a timestamp, not a delete. A revoked device's past submissions still need a
    -- name attached to them, and deleting the row would silently anonymise its whole history.
    revoked_at   BIGINT
);

-- ── one-time enrolment codes ─────────────────────────────────────────────────────────
--
-- The code itself is NEVER stored, only its SHA-256 -- the same shape as a password digest and for
-- the same reason. `consumed_at` is what makes a code single-use, and it is only ever set by a
-- conditional UPDATE inside a transaction, so two racing devices cannot both claim one code.

CREATE TABLE IF NOT EXISTS enrolment_code (
    code_sha256        TEXT PRIMARY KEY,
    label              TEXT NOT NULL,
    created_at         BIGINT NOT NULL,
    expires_at         BIGINT NOT NULL,
    consumed_at        BIGINT,
    consumed_by_device TEXT REFERENCES device(id)
);

-- ── the replay store ─────────────────────────────────────────────────────────────────
--
-- This is what lets the archive claim replay detection where `report.rs` honestly says it cannot:
-- the notary's freshness gate is handed an empty seen-nonce set, and says so. Here the set is real,
-- and the UNIQUE constraint is the mechanism -- a second insert of the same pair raises a
-- unique-violation, which the server reads as a replay refusal.

CREATE TABLE IF NOT EXISTS seen_nonce (
    device_id  TEXT NOT NULL REFERENCES device(id),
    nonce      TEXT NOT NULL,
    seen_at    BIGINT NOT NULL,
    UNIQUE (device_id, nonce)
);

CREATE INDEX IF NOT EXISTS seen_nonce_seen_at ON seen_nonce (seen_at);

-- ── the artifacts ────────────────────────────────────────────────────────────────────
--
-- `bytes` is BYTEA and holds the submission verbatim. Not JSONB: JSONB normalises key order and
-- number formatting, which would change the bytes and therefore the digest, and an archive that
-- returns different bytes than it was given cannot be verified off.
--
-- `digest` is NOT computed here. There is deliberately no generated column and no
-- `CHECK (digest = encode(sha256(bytes), 'hex'))`: that would be a second implementation of the
-- digest rule, in a language nobody on this project audits, that can disagree with the Rust one.
-- The digest is computed once, in Rust, at ingest.
--
-- `ingest_check` is the door's three-valued note ('ok' | 'failed' | 'unknown'). It is NOT a verdict
-- and is never served as one. A row with ingest_check = 'failed' is kept and returned byte for
-- byte: a tampered file is the most important thing to be able to put in front of a human.

CREATE TABLE IF NOT EXISTS artifact (
    digest              TEXT PRIMARY KEY,
    kind                TEXT NOT NULL CHECK (kind IN ('report', 'stop', 'ledger')),
    warrant_id          TEXT NOT NULL,
    subject             TEXT,
    submitted_at        BIGINT NOT NULL,
    submitted_by_device TEXT NOT NULL REFERENCES device(id),
    ingest_check        TEXT NOT NULL CHECK (ingest_check IN ('ok', 'failed', 'unknown')),
    ingest_check_reason TEXT NOT NULL DEFAULT '',
    bytes               BYTEA NOT NULL
);

CREATE INDEX IF NOT EXISTS artifact_warrant ON artifact (warrant_id, submitted_at DESC);
CREATE INDEX IF NOT EXISTS artifact_submitted_at ON artifact (submitted_at DESC);

-- Enforcement 1 of 2: the database refuses, whatever the connecting role was granted.
CREATE OR REPLACE FUNCTION artifact_is_append_only() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'the artifact table is append-only: % is refused. Evidence custody means the archive '
        'cannot revise what it was given -- that is the whole claim. If a submission was wrong, '
        'file the correction as a new artifact; the record of the first one stays.',
        TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS artifact_append_only ON artifact;
CREATE TRIGGER artifact_append_only
    BEFORE UPDATE OR DELETE ON artifact
    FOR EACH ROW EXECUTE FUNCTION artifact_is_append_only();

-- ── retention ────────────────────────────────────────────────────────────────────────
--
-- THE ABSENT-LIMIT RULE, ENCODED. `enabled` is a separate NOT NULL boolean defaulting to FALSE, and
-- deletion authority is NOT derived from `window_seconds`.
--
-- The failure this shape prevents is specific. If the policy were "delete anything older than
-- window_seconds" and window_seconds were NULL or 0, a straightforward reading -- `submitted_at <
-- now() - COALESCE(window, 0)` -- deletes EVERYTHING, immediately, because an absent window was
-- silently read as a window of zero. An absent limit means NO deletion authority was granted. It
-- never means unlimited, and it never means immediate.
--
-- With `enabled = FALSE`, which is the shipped default for every kind, nothing is deletable no
-- matter what the window says. A `window_seconds` that is NULL or 0 also authorises nothing even
-- when enabled is TRUE -- both halves are required. Stage 1 ships no deletion job at all; this
-- table records the policy so that when one is written it has something explicit to read, rather
-- than inferring authority from an absence.

CREATE TABLE IF NOT EXISTS retention_policy (
    kind           TEXT PRIMARY KEY CHECK (kind IN ('report', 'stop', 'ledger')),
    enabled        BOOLEAN NOT NULL DEFAULT FALSE,
    window_seconds BIGINT,
    updated_at     BIGINT NOT NULL DEFAULT 0
);

INSERT INTO retention_policy (kind, enabled, window_seconds) VALUES
    ('report', FALSE, NULL),
    ('stop',   FALSE, NULL),
    ('ledger', FALSE, NULL)
ON CONFLICT (kind) DO NOTHING;

-- ── enforcement 2 of 2: the runtime role's grants ────────────────────────────────────
--
-- Created here rather than left to a runbook, because a role that exists only in documentation is a
-- role somebody skips on the day they are restoring a backup at 2am. The password is set by the
-- operator out of band (see deploy/evidence-archive/README.md) -- never in a migration, which lands
-- in git.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'archive_runtime') THEN
        CREATE ROLE archive_runtime LOGIN;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO archive_runtime;

-- The whole append-only claim, in three lines. Note the absence of UPDATE and DELETE on `artifact`.
GRANT INSERT, SELECT ON artifact TO archive_runtime;
GRANT INSERT, SELECT, UPDATE ON device TO archive_runtime;
GRANT INSERT, SELECT, UPDATE ON enrolment_code TO archive_runtime;
GRANT INSERT, SELECT ON seen_nonce TO archive_runtime;
GRANT SELECT ON retention_policy TO archive_runtime;
GRANT SELECT ON schema_migrations TO archive_runtime;

-- `device` and `enrolment_code` carry UPDATE because revocation and single-use code consumption are
-- updates by nature: a revoked device must stay readable and a claimed code must stay claimed.
-- Neither table holds evidence. `artifact` is the table custody is about, and it is the one with no
-- UPDATE grant.
