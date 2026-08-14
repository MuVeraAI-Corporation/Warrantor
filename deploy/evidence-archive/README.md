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
minutes. On the machine that will file evidence, claim it:

```sh
warrantor archive enrol --url http://127.0.0.1:8788 --code <the code>
```

That generates `~/.warrantor/keys/device.key`, sends only the public half, and writes
`~/.warrantor/archive.json` recording which archive this device is paired with and under what id.
The archive never sees a private key, at enrolment or afterwards.

## Filing and reading evidence

```sh
warrantor report <warrant-id> --export report.json --archive   # write it, then file it
warrantor archive push report.json                             # or file a file you already have
warrantor archive fetch <sha256> --out fetched.json            # read it back out
warrantor verify fetched.json --issuer <the issuer's hex key>  # and check it, off the archive
```

`push` sends the file's bytes **verbatim** and refuses if the digest the archive returns is not the
SHA-256 of the bytes it sent — a content-addressed archive whose address does not name the bytes is
not holding your file, and both copies would still verify against their own signatures. `--archive`
on `report`, `stop` and `spend` files the file `--export` just wrote, through the same code path,
and exits non-zero if the push fails; it never unwrites the local file.

A filing is **custody, not a verdict**. The archive stores artifacts whose signatures do not check
out and marks them, because refusing to hold a tampered file would destroy the evidence that it
arrived. Nothing the client prints says "verified": that answer comes from `warrantor verify`, in
Rust, on your machine, against an issuer key you obtained out of band.

## Revoking a device

```sh
docker compose -f deploy/evidence-archive/docker-compose.yml exec archive \
  warrantor-archive revoke --device dev_…
```

Revocation is not a delete: the row stays, so everything that device filed keeps its attribution.
The device still holds its private key — delete `~/.warrantor/keys/device.key` and
`~/.warrantor/archive.json` on that machine too, or it will keep trying.

## Signing a request

You do not need this to use the archive; `warrantor archive` does it. It is written down because it
is the wire contract, and because it is what makes `curl` insufficient — every route except
`/v1/health` and `/v1/devices/enrol` needs a signature, **reads included**. There is exactly one
implementation, in `rust/warrant/src/archive_client.rs`, which the server re-exports from
`warrantor_archive::device` rather than keeping a second copy of.

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
  warrantor archive fetch <sha256> --out report.json
  warrantor verify report.json --issuer <the issuer's hex key>
  ```

  The fetch is signed like every other read, and it checks that the bytes it got back hash to the
  digest it asked for before it writes them. The verify that follows is the one that matters, and it
  has no archive in its call graph at all.

  Without `--issuer` that checks self-consistency only, and a file fabricated end to end by anyone
  at all passes. The anchor is what makes the check mean something, and it must come from somewhere
  other than the archive.

## Backup

`docker compose … exec db pg_dump -U archive_admin warrantor_archive`. A dump contains public keys,
labels and evidence, and no private key — but the evidence is the thing being kept, so treat a dump
with the same care as the archive itself.
