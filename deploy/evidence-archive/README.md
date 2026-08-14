# Running the evidence archive

Self-hosted, append-only custody for signed Warrantor evidence. Design and rationale:
[RFC W2](../../docs/rfcs/W2-evidence-archive.md); the surfaces argument it is stage 1 of:
[RFC W1](../../docs/rfcs/W1-surfaces-and-the-backend.md).

Read this first, in one sentence: **the archive relays evidence it cannot forge, and every reader
verifies locally against an issuer key they obtained out of band.** Nothing below changes that, and
nothing below should be taken as a reason to skip it.

## Before you start

Two secrets, neither of which goes in a file that is committed. **Both must be exported before the
first compose command**: `docker-compose.yml` interpolates `${POSTGRES_PASSWORD:?…}` and
`${ARCHIVE_RUNTIME_PASSWORD:?…}`, and compose refuses to bring anything up at all if either is
unset — deliberately, because the alternative is a guessable default.

```sh
export POSTGRES_PASSWORD=$(openssl rand -hex 32)
export ARCHIVE_RUNTIME_PASSWORD=$(openssl rand -hex 32)
```

`POSTGRES_PASSWORD` is the schema owner (`archive_admin`). `ARCHIVE_RUNTIME_PASSWORD` is the role
the server connects as (`archive_runtime`), which holds `INSERT, SELECT` on the artifact table and
**no `UPDATE` or `DELETE` grant at all**. Connecting the server as the owner would throw away half
the append-only enforcement and leave the trigger standing alone, so the two roles are not
interchangeable.

## Start it

Three steps, in this order, and the order is not cosmetic. `archive_runtime` **does not exist** until
the migration has run, so its password cannot be set before that; and the server cannot authenticate
until the password is set, so it is started last. `make archive-up` runs exactly this sequence.

```sh
# 1. the database, and the schema — which creates archive_runtime, the trigger and the grants
docker compose -f deploy/evidence-archive/docker-compose.yml up -d db
docker compose -f deploy/evidence-archive/docker-compose.yml run --rm migrate

# 2. the runtime role's password, out of band. A migration lands in git, and a password in git is
#    a password everybody has — so the migration creates the role without one.
docker compose -f deploy/evidence-archive/docker-compose.yml exec -T \
  -e PGPASSWORD="$POSTGRES_PASSWORD" db \
  psql -U archive_admin -d warrantor_archive -v ON_ERROR_STOP=1 \
  -c "ALTER ROLE archive_runtime PASSWORD '$ARCHIVE_RUNTIME_PASSWORD'"

# 3. the server
docker compose -f deploy/evidence-archive/docker-compose.yml up -d archive
curl -s http://127.0.0.1:8788/v1/health
```

`PGPASSWORD` is passed into the exec because the database is initialised with
`--auth-local=scram-sha-256`: even the local socket wants a password, and `psql` would otherwise sit
waiting for one that never comes.

The `migrate` service runs once and exits; the `archive` service declares
`service_completed_successfully` on it, so step 3 re-runs it and the server never starts against a
database whose trigger and grants have not been installed. Migrations are recorded in
`schema_migrations`, so the second run applies nothing.

## Running the database-backed tests

Three tests need a real database and are `#[ignore]`d so `cargo test --workspace` stays green in CI,
which has no Postgres. They cover the trigger, the runtime role's grants and the single-use
enrolment code, and they need **both** URLs, because a single connection cannot tell "the trigger
refused" from "this role was never granted UPDATE":

```sh
WARRANTOR_ARCHIVE_DATABASE_URL=postgres://archive_admin:$POSTGRES_PASSWORD@127.0.0.1:5433/warrantor_archive \
WARRANTOR_ARCHIVE_RUNTIME_DATABASE_URL=postgres://archive_runtime:$ARCHIVE_RUNTIME_PASSWORD@127.0.0.1:5433/warrantor_archive \
  make archive-test
```

They insert and never delete: the tests run under the same append-only rules the product claims, so
they are safe against a real archive but will leave their fixtures in it. Point them at a database
you are willing to keep rows in.

## Enrol the first device

Authentication is device pairing, not a shared token. An operator mints a one-time code; the device
generates an Ed25519 keypair, keeps the private half, and signs every request. That is what makes
`submitted_by_device` a person's name rather than "someone holding the token".

```sh
docker compose -f deploy/evidence-archive/docker-compose.yml exec archive \
  warrantor-archive enrol --label "Ana's laptop"
```

The code is printed **once** and only its SHA-256 is stored. It is single-use and expires in fifteen
minutes. The device claims it:

```sh
curl -s http://127.0.0.1:8788/v1/devices/enrol \
  -H 'content-type: application/json' \
  -d '{"code":"<the code>","public_key":"<64 hex chars>"}'
```

The archive never sees a private key, at enrolment or afterwards.

## Signing a request

```text
Authorization: Warrantor-Device <device_id>.<timestamp>.<nonce>.<hex-signature>
```

The signature is Ed25519 over DSSE PAE of:

```text
warrantor.archive-request/1
{METHOD}
{path}
{device_id}
{nonce}
{unix-seconds}
{sha256-hex of the body}
```

Everything that could otherwise be swapped is inside it: a signature cannot be lifted onto another
route, another body, or another device, and a nonce is refused the second time it is seen.
Timestamps must sit within five minutes of the archive's clock, in either direction.

## Before it leaves this machine

**There is no TLS.** Device signatures authenticate a request; they do not encrypt it. Every byte —
the evidence itself, and the label naming whoever filed it — crosses the network in the clear.
A signature cannot be replayed, so an eavesdropper cannot resubmit a captured request; that is the
only thing the absence of TLS does not cost you.

So stage 1 is **loopback-or-VPN only** until the commented-out reverse proxy in the compose file is
filled in with a real certificate. The compose file publishes both ports to `127.0.0.1` deliberately.

## What this deployment does and does not guarantee

- **Append-only, twice over.** A `BEFORE UPDATE OR DELETE` trigger on `artifact`, and a runtime role
  with no `UPDATE`/`DELETE` grant. Both, because a grant can be misconfigured while restoring a
  backup and a trigger cannot.
- **Retention is off.** Every kind ships `enabled = FALSE` with no window, and an absent window
  grants no deletion authority — it is never read as "delete everything older than nothing". There
  is no deletion job in stage 1 at all.
- **The residual, stated plainly.** Whoever owns this database can drop the trigger and delete rows.
  Append-only is a property of the application role, not of the storage. What actually carries the
  custody guarantee is that every artifact here is independently verifiable *off* the archive:

  ```sh
  curl -s http://127.0.0.1:8788/v1/evidence/<sha256> \
    -H "Authorization: Warrantor-Device …" > report.json
  warrantor verify report.json --issuer <the issuer's hex key>
  ```

  Without `--issuer` that checks self-consistency only, and a file fabricated end to end by anyone
  at all passes. The anchor is what makes the check mean something, and it must come from somewhere
  other than the archive.

## Backup

`docker compose … exec db pg_dump -U archive_admin warrantor_archive`. A dump contains public keys,
labels and evidence, and no private key — but the evidence is the thing being kept, so treat a dump
with the same care as the archive itself.
