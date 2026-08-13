# Running the evidence archive

Self-hosted, append-only custody for signed Warrantor evidence. Design and rationale:
[RFC W2](../../docs/rfcs/W2-evidence-archive.md); the surfaces argument it is stage 1 of:
[RFC W1](../../docs/rfcs/W1-surfaces-and-the-backend.md).

Read this first, in one sentence: **the archive relays evidence it cannot forge, and every reader
verifies locally against an issuer key they obtained out of band.** Nothing below changes that, and
nothing below should be taken as a reason to skip it.

## Before you start

Two secrets, neither of which goes in a file that is committed.

```sh
export POSTGRES_PASSWORD=$(openssl rand -hex 32)
export ARCHIVE_RUNTIME_PASSWORD=$(openssl rand -hex 32)
```

`POSTGRES_PASSWORD` is the schema owner (`archive_admin`). `ARCHIVE_RUNTIME_PASSWORD` is the role
the server connects as (`archive_runtime`), which holds `INSERT, SELECT` on the artifact table and
**no `UPDATE` or `DELETE` grant at all**. Connecting the server as the owner would throw away half
the append-only enforcement and leave the trigger standing alone, so the two roles are not
interchangeable.

The migration creates `archive_runtime` without a password — a migration lands in git, and a
password in git is a password everybody has. Set it once, out of band:

```sh
docker compose -f deploy/evidence-archive/docker-compose.yml exec db \
  psql -U archive_admin -d warrantor_archive \
  -c "ALTER ROLE archive_runtime PASSWORD '$ARCHIVE_RUNTIME_PASSWORD'"
```

## Start it

```sh
docker compose -f deploy/evidence-archive/docker-compose.yml up -d
curl -s http://127.0.0.1:8788/v1/health
```

The `migrate` service runs once and exits; the server waits for it to exit successfully, so the
server never starts against a database whose trigger and grants have not been installed.

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
