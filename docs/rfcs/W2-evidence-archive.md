# RFC W2 — The evidence archive

**Status:** accepted
**Date:** 2026-08-13

Stage 1 of the backend [RFC W1](W1-surfaces-and-the-backend.md) bounds: durable custody for signed
evidence, held by a party that cannot forge it. It answers the third of W1's five needs — *evidence
in `~/.warrantor` dies with the laptop, and is held by the very person being audited* — and
[delivery gap 2.1](../W1-delivery-gaps.md), which names the absence of a backend as the largest
single gap in the product.

> **A naming collision, stated first so nobody trips over it later.** `rust/evidence`'s module doc
> calls itself "W2 Evidence envelope", after the *spec-wave* numbering that produced the twelve-plane
> portfolio. This document is RFC W2 in the **W series**, the warrant-primitive series that W1
> opened. Same token, two vocabularies. This is exactly the hazard `report.rs` documents about the
> two `WarReceipt` types, and it gets the same treatment: documented rather than renamed, because a
> rename does not remove a hazard that exists, and both names are correct in their own vocabulary.
> When it matters, write "RFC W2" or "spec-wave W2" and never the bare token.

## Background

W1 established that a backend is required for five things, each physically impossible on one
machine, and bounded it precisely:

> **Design target: compromise of the backend must degrade availability, never integrity.**

It also established what must never move server-side: `grant`, verification, the settle key, and
enforcement. And it set the gate every stage must pass: *each backend stage ships only if a client
can still verify without it.*

Three facts from the code shaped this design more than any plan did.

1. **`warrantor serve` binds loopback.** Its own docstring promises "a second person, a desktop
   application, a browser client", and a second person on another machine cannot reach a loopback
   socket. That promise is false today.
2. **The bearer token is one unscoped value.** `serve.rs` says so itself, and says scoping it is the
   right next fix. Until it is scoped, the trail cannot say which human did anything.
3. **`report::verify_export` is anchor-free.** This is the one that changed the shape of the work,
   and it is set out in full under [Threat Model](#threat-model).

## Goals

1. Hold the three signed evidence files `warrantor verify` already reads, durably, off the audited
   party's laptop, with nothing forgeable added.
2. Make the audit trail name a **person**, not a token holder, for the acts this surface can see.
3. Keep the relay-not-authority target falsifiable: a test that fails if the archive ever becomes
   something a client must trust.
4. Ship append-only, with retention and export implemented and defaulted off.

**Non-goals.** The trust directory (stage 2 — where an anchor legitimately comes from), approval
routing, time anchoring, fleet summaries. A browser client for the archive. TLS termination, which
is a deployment concern and is left explicitly unfinished rather than half-done. Any change to what
verification means.

## Detailed Design

### A new workspace crate, and why it lives in this repository

`rust/archive`, package `warrantor-archive`. In this workspace rather than in a repository of its
own, for one reason that outweighs the coupling: it depends on `warrantor-warrant`, so it calls
`report::verify_export`, `stop::verify_stop` and `spend::verify_spend` — **the same functions
`warrantor verify` calls**. There is exactly one implementation of what "verifies" means, and it
cannot come to disagree with itself across two processes.

The dependency edge runs `archive → warrant`, never the reverse. That matters because the archive
carries `postgres`, which pulls tokio transitively, and `rust/warrant`'s tokio-free posture is a
property worth keeping: it is the program that runs on a developer's laptop with nothing installed.
Inverting that edge would give the local agent an async runtime and a database client for nothing.

### What is stored, and in what form

The three files, dispatched on their declared `format` — the same three-way match `cmd_verify`
makes. An unknown format is a refusal at the door, never a stored blob.

Bytes are stored **verbatim**, content-addressed by SHA-256 of exactly what arrived, in a `BYTEA`
column. Not `JSONB`, which normalises key order and number formatting; not a parsed value
re-serialised on the way out, because a faithful round trip through `serde_json` is still the
archive choosing the bytes. *The archive returns what it was given* is the only claim that makes
verifying off the archive worth anything, and it is only true if nothing rewrites a byte.

The digest is computed once, in Rust, at ingest. There is deliberately no generated column and no
`CHECK (digest = encode(sha256(bytes),'hex'))`: that would be a second implementation of the rule
saying which bytes are which artifact, in a language nobody on this project audits.

### Ingest verification: why it exists, and why it is never a verdict

Every submission is run through the existing verifier at the door. That is **hygiene**, and it is
worth being exact about what it refuses: a submission that is not one of the three evidence files at
all, or that names no warrant to be filed under, so the archive is not a convenient place to park
arbitrary bytes. A file whose *signatures* do not hold is not refused — it is stored and marked, for
the reason given below.

Its result is recorded three-valued (`ok` / `failed` / `unknown`, mirroring `serve::Integrity`, with
`unknown` never rendered as `failed`) and served under a field literally named `not_a_verdict`. The
name is the guardrail. The failure mode this design exists to prevent is not somebody deciding to
make the archive an authority; it is somebody reusing `serve::Response`, whose `json` constructor
puts `"verified": true` on every body. On the local agent that field is correct — computed in Rust,
on the operator's own machine, from their own store. On a remote archive the identical field is a
verdict from a machine the audited party may control, and a console renders what it is handed.

So `rust/archive/src/http.rs` defines its own `ArchiveResponse` with two constructors, neither of
which can produce a key called `verified` or `verification`, and
`tests/the_archive_never_serves_a_verdict.rs` walks every route's body at every depth to keep it
that way.

An artifact whose ingest check **failed** is still stored, still listed and still returned byte for
byte. Refusing to hold a tampered file would destroy the evidence that it existed, and a tampered
file is the single most important thing to be able to put in front of a human.

The same is true of `unknown`, and making it true took a fix. A body that declares one of the three
formats and will not deserialise into it is filed under the warrant it names, with the check recorded
as `unknown` — no verifier ran, so nothing established that its signatures are wrong. Until now that
was documentation rather than behaviour: every arm producing `unknown` also produced no warrant id,
and ingest refused the submission on the next line, so the third value could not be written and the
version-skew case (a newer build's export this one cannot parse) was dropped at the door instead of
kept. The warrant id is read out of the raw JSON purely as a **filing key**, validated with the same
`is_warrant_id` the router applies, and a body naming no usable warrant is still refused.

### The route table

| Route | Method | What it does |
|---|---|---|
| `/v1/health` | GET | version and liveness; reads no store data; answered before authentication |
| `/v1/evidence` | POST | file an artifact |
| `/v1/evidence/{sha256}` | GET | the stored bytes, verbatim |
| `/v1/warrants/{id}/evidence` | GET | what is held about one warrant |
| `/v1/devices/enrol` | POST | claim a one-time code with a public key |

There is no settle, void, stop or grant, and **no route that accepts warrant claims and returns
something signed**. The archive holds no key that could perform one. The table is kept short
precisely so that a route which did would be visible on sight in review: a convenience endpoint that
notarised a submission would move warrant-minting authority into a network-reachable process.

`/v1/health` is the only route answered before authentication. It reads no store data and is
byte-identical across archives, so it can tell a load balancer the process is up without becoming a
way to probe what is held. Everything else authenticates first, so an unauthenticated caller gets
the same refusal for a digest that exists and one that does not.

### Device pairing

An operator runs `warrantor-archive enrol --label "Ana's laptop"`, which mints 32 CSPRNG bytes
(`getrandom::fill`, refusing to proceed if the OS declines — the same refusal
`SessionToken::mint` makes), prints the code once, and stores only its SHA-256. The device POSTs the
code with its Ed25519 public key. Consumption is one conditional `UPDATE ... WHERE consumed_at IS
NULL AND expires_at > $2 RETURNING label` inside a transaction, so of two racing devices exactly one
wins — there is no window between a check and a write.

Unknown, expired and already-claimed give **one** refusal. Three would tell someone holding a
guessed code whether they guessed a real one.

Every subsequent request carries:

```text
Authorization: Warrantor-Device <device_id>.<timestamp>.<nonce>.<hex-signature>
```

signed over `dsse_pae` of a canonical descriptor pinning the format, method, path, device id, nonce,
timestamp and a digest of the body. Everything swappable is inside the signature, so it cannot be
lifted onto another route, another body or another device. Verification order is: freshness, then
the device is known, then the signature, **then** revocation, and **only then** is the nonce
recorded — a stale or unsigned request must not consume a nonce, or an attacker replaying old
traffic could burn the nonces an honest client is about to use.

Revocation sits after the signature rather than before it, and that ordering is load-bearing.
`device_revoked` and `unauthorized` are distinct wire codes, so checking revocation first answered
"does this device id exist?" to anyone willing to sign with a key they invented — an enumeration
oracle over a route whose documented property is that it is not one. After `verify_strict`, only the
holder of that device's private key can tell a revoked device from an unknown one, and that is the
person entitled to know.

**Freshness, and the contrast worth naming.** `report.rs` says plainly that the notary's freshness
gate sees an empty seen-nonce set and cannot detect a replay. That is honest about a report built in
one process from one clock read. This surface has a real replay store — a unique index on
`(device_id, nonce)` — so the claim is made here and made no wider than that.

**What this attributes.** Submission and read. It does **not** attribute the settle, which happens on
a laptop under the local agent's settle key and may never touch this server. W1 delivery gap 2.2 is
therefore **half closed**: "who filed this evidence" is now answerable and "who settled this" is
not. It becomes answerable when the local agent binds a device key into the settle record, which is
not this stage. Marking 2.2 done would put a claim in front of an examiner that the evidence cannot
support.

### Append-only, and the honest limit

Enforced twice in `migrations/0001_initial.sql`: a `BEFORE UPDATE OR DELETE` trigger on `artifact`,
and a runtime role (`archive_runtime`) granted `INSERT, SELECT` and nothing else. Both, because a
grant can be misconfigured by an operator restoring a backup and a trigger cannot. The `ArchiveStore`
trait itself declares no update and no delete, so the guarantee is a property of the seam's shape
before it is a property of any implementation — asserted at source level by
`tests/append_only.rs::the_store_trait_offers_no_way_to_update_or_delete_an_artifact`.

Filing identical bytes twice is idempotent and never an error: two people filing the same evidence
is ordinary, and an archive that errored on the second would teach them to stop filing. It never
overwrites, because the first submitter's name is the attribution.

**The residual, stated rather than buried.** Whoever owns the database can drop the trigger and
delete rows. Append-only is a property of the application role, not of the storage. Durable custody
against the audited party's own engineers does not come from the trigger — it comes from the
artifacts being independently verifiable *off* this archive, which is why the anchor pinning below
is what actually carries the guarantee.

### Retention and export: implemented, defaulted off

`retention_policy` carries an explicit `enabled BOOLEAN NOT NULL DEFAULT FALSE` per kind, and
deletion authority is **not** derived from `window_seconds`. Both halves are required:
`RetentionPolicy::deletes_anything()` is false unless deletion is enabled *and* a non-zero window is
set.

This is the absent-limit rule at its most dangerous point. The obvious implementation — "delete
anything older than the window", with a window that is NULL or zero — deletes everything,
immediately, because an absent limit was silently read as a limit of zero. **An absent window grants
no deletion authority.** It never means unlimited and it never means immediate. Stage 1 ships no
deletion job at all; the table records the policy so that when one is written it has something
explicit to read rather than inferring authority from an absence.

### Transport

The archive reuses `serve::parse_request_with`, added additively in this change so `parse_request`
keeps its exact signature and behaviour. The framing discipline — refuse every `Transfer-Encoding`,
validate path segments and never percent-decode them, cap every line read, one request per
connection, `Connection: close` — is the part most worth not rewriting, and this surface faces a
network rather than a loopback socket. Only the body cap differs: 4 MiB rather than 64 KiB, because
an exported bundle with a long changed-files list exceeds the smaller number, and a cap that refuses
real evidence teaches people to stop filing it.

**No CORS header.** W1's no-CORS rule is written about the local agent, and the archive is genuinely
remote, so the rule does not transfer automatically. It is still not added: no browser client talks
to the archive in stage 1, and a header added before the client exists is a header nobody reviewed
against a real threat. Adding one should be a documented decision naming an origin.

## Dependencies

- `warrantor-warrant` — the one verifier, and the HTTP framing. This is the load-bearing dependency
  and the reason the crate is a workspace member.
- `warrantor-evidence` — `dsse_pae`, reused for the device request signature rather than inventing a
  second signing convention.
- `postgres` 0.19, the pure-Rust synchronous rust-postgres client. No libpq, no C client library, no
  `async fn` and no `.await` in this crate. It pulls tokio transitively, which is a genuine cost and
  is confined by the `archive → warrant` edge direction.
- `ed25519-dalek`, `sha2`, `hex`, `getrandom`, `serde`, `serde_json`, `thiserror` — all already in
  the workspace at these versions. **No new cryptographic primitive is introduced**, which is what
  W1 promised of the backend.
- No connection-pool crate: a `Mutex<Client>`, mirroring `serve.rs`'s answer and inheriting its
  honest caveat — it serialises requests in this process and cannot serialise against another.

## Threat Model

| Threat | Mitigation | Residual |
|---|---|---|
| **A fully compromised archive fabricates evidence** | Clients re-verify locally with `warrantor verify --issuer <hex>`, which pins the key that must have signed the file. `tests/verification_does_not_depend_on_the_archive.rs` asserts a fabricated, archive-signed bundle is refused | **A reader who omits `--issuer` gets self-consistency only.** The command now says so on every unanchored run; where the anchor comes from is stage 2 |
| A compromised archive withholds, delays, or serves a stale list | None attempted — this is availability, and W1 accepts it by design | Availability degradation is the accepted failure mode |
| A forged or malformed file is submitted | Ingest runs the existing verifier and records `ok`/`failed`/`unknown`; unknown formats are refused at the door and never stored | An artifact that verifies but was signed by an untrusted key is stored, correctly: the archive is not the judge of whose key matters |
| A captured request is replayed | The signature pins method, path, device, nonce, timestamp and body digest; nonces are single-use per device (unique index); timestamps must be within 5 minutes either way | A replay inside the window from a device whose key is held by the attacker — see the next row |
| A device key is on a lost laptop | `warrantor-archive` revocation sets `revoked_at`; a revoked device is refused on the next request. Keys are per-device, so the blast radius is one person's device rather than everyone's token | Anything that device submitted before revocation was legitimately signed and stays. There is no automatic key expiry in stage 1 |
| A stolen enrolment code | Single-use (one conditional `UPDATE`, tested against a real database), 15-minute expiry, only its SHA-256 stored, and one refusal for unknown/expired/claimed so the route is not an oracle | Whoever holds the code within its window can enrol a device under the operator's chosen label. The digest lookup runs in data-dependent time — a `BTreeMap::get` and a primary-key index probe — so a timing side channel exists against a SHA-256 of 32 CSPRNG bytes, which is not a practical path to guessing a code. This row previously claimed a mitigation the code did not apply; see `tests/append_only.rs::the_threat_model_names_no_mitigation_this_crate_does_not_implement` |
| An operator deletes rows out of band | A `BEFORE UPDATE OR DELETE` trigger and a runtime role with no `UPDATE`/`DELETE` grant | **Not prevented.** The DBA owns the database. Custody against the audited party rests on off-archive verifiability, not on the trigger |
| Someone renders the archive's ingest check as a verdict | The field is named `not_a_verdict`; `ArchiveResponse` cannot produce a `verified` key; every route's body is walked by test | A client that reads `not_a_verdict.ingest_check` and renders it as a tick anyway. The name makes that a deliberate act |
| SQL injection through a digest, id or filter | Parameterised queries only (`$1`, `$2` …); no string concatenation near SQL; digests and ids validated before they reach the store | None known |
| The archive is reached over a hostile network | Loopback bind by default; a non-loopback bind prints a warning naming exactly what is and is not protected | **No TLS in stage 1.** Signatures authenticate, they do not encrypt. Loopback-or-VPN only until the reverse proxy is configured |
| A panicking handler takes the server down | `panic = "abort"` is the release profile, so every path validates before calling, recovers a poisoned mutex, and turns every Postgres error into a refusal | A panic in a dependency |

### The anchor-free property, and what this change does about it

`report::verify_export` verifies each receipt against **the public key embedded in that receipt**,
and cross-checks only that the two receipts share one key. It is anchor-free by construction, and
`warrantor verify` merely *printed* `signed by <key>` — comparing it to nothing.

That is correct for what `verify_export` claims ("nothing has changed since signing") and it is not
enough for what a reader hears. Anyone holding an Ed25519 keypair can fabricate a bundle, sign both
receipts with it, and produce a file that verifies. An archive is exactly a party that holds
artifacts it did not produce, so **without an anchor the mandated test "a malicious archive cannot
make a tampered bundle verify" is not merely unpassable — it is false.**

So this change adds `report::verify_export_signed_by`, and the equivalents on stop records and spend
ledgers, plus `warrantor verify --issuer <hex>`. It is a thin wrapper — `verify_export` first, then
a key comparison — not a second verifier. The anchor is never defaulted from the local store:
verifying somebody else's evidence against your own issuer key produces a verdict from a key with
nothing to do with the case, which is worse than no check because it looks like an answer. Without
`--issuer`, the command now prints an explicit limitation saying it checked self-consistency only.

**This is a limitation of the shipped system, not a solved problem.** Where an anchor legitimately
comes from is the trust directory, which is stage 2. Stage 1 accepts one from the operator.

## API

Every success body:

```json
{ "format": "warrantor.archive-response/1",
  "data": { … },
  "not_a_verdict": {
    "ingest_check": "ok | failed | unknown",
    "reason": "…",
    "verify_locally": "warrantor verify <file> --issuer <hex>" } }
```

Every refusal carries `error: { code, message }` and the same `not_a_verdict` block, so a client
never branches on whether the field exists. `GET /v1/evidence/{sha256}` is the exception and carries
no envelope at all: it returns the stored bytes verbatim as `application/json`, because wrapping
them would force the client to unwrap and re-serialise, and the re-serialisation would change the
digest.

Responses carry `connection: close`, `cache-control: no-store` and `x-content-type-options: nosniff`,
as `serve.rs` writes them. No `Access-Control-Allow-Origin`, ever.

New CLI: `warrantor-archive migrate | enrol --label <text> | serve [--bind …]`. The database URL
comes from `$WARRANTOR_ARCHIVE_DATABASE_URL` or `--database-url`; the environment is preferred
because a flag lands in every process listing on the machine.

Changed CLI: `warrantor verify <file> [--issuer <hex>]`. Additive — the flag is optional and the
unanchored path behaves as before, except that it now states what it did not check.

## Testing

`rust/archive/tests/`, four files. Everything runs against `MemoryStore`, because CI has no Postgres;
**three** tests need a database, are `#[ignore]`d, and name the command that runs them
(`make archive-test`). That number is asserted by
`append_only.rs::the_ignored_database_tests_are_the_number_the_docs_claim` rather than left to this
paragraph: this section previously said "two" while one existed, and a reviewer who runs the
documented command and sees `1 passed` has no way to know which claim is the wrong one. A test that
is counted and does not exist is worse than a missing test.

**`verification_does_not_depend_on_the_archive.rs`** is the load-bearing file.

- `a_client_verifies_an_exported_bundle_with_no_archive_in_the_process` — the positive case, notable
  for what it does not import: no store, no HTTP, no socket, no archive type in the call graph.
- `a_malicious_archive_cannot_make_a_tampered_bundle_verify` — four attacks. Flip a byte (digest
  mismatch); delete a limitation (digest mismatch — the most tempting edit for an audited party gets
  the same detection as forging the verdict); graft valid receipts onto a different bundle (binding
  failure); and **re-sign a fabricated bundle end to end with an archive-held key**.

  The fourth is asserted in **both directions**: `verify_export` must pass, and
  `verify_export_signed_by` against the pinned issuer must fail. A refactor that drops the anchor
  comparison fails on the first assertion rather than leaving a hole nobody notices.
- `the_archive_returns_the_bytes_it_was_given_and_the_digest_proves_it` — the property every other
  assertion rests on.

**`the_archive_never_serves_a_verdict.rs`** walks every route's body at every depth for a field a
client could render as a verdict, and asserts an artifact whose ingest check failed is still
retrievable byte for byte, and that an unparseable file is `unknown` rather than `failed` — at the
unit boundary and end to end through the wire and the listing.

The walker bans more than the two words. `/v1/health` served `append_only: true`,
`holds_no_signing_key: true` and `routes_that_mutate_a_warrant: 0` as unauthenticated,
machine-readable literals — values a compromised archive that had acquired a signing key or lost its
trigger would return identically, next to a name a viewer renders as a badge. They are removed:
whether this archive is append-only is answered by reading the migration and by verifying artifacts
off the archive, never by asking the archive.

**`append_only.rs`** covers idempotence-without-overwrite, second artifacts under one warrant, the
trait's shape, the migration's two enforcement mechanisms *as text*, and that retention grants
nothing by default — including the enabled-with-no-window and enabled-with-zero-window cases, which
are the ones an absent-limit bug produces. The two enforcement mechanisms are exercised *for real*
by one `#[ignore]`d test each, deliberately not one test: connected as a single role, "the trigger
refused" and "this role was never granted UPDATE" are indistinguishable, and the earlier single test
proved neither — it updated a table it had never inserted into, and a `FOR EACH ROW` trigger does
not fire on a statement that matches no rows.

**`device_pairing.rs`** covers single-use codes under a race, expiry, replayed nonces, a signature
over a different body, a signature lifted onto another route, staleness in both directions without
burning a nonce, revocation that keeps its history, and the oracle-avoidance properties. The last
test is `two_devices_submitting_produce_two_distinguishable_submitters` — the attribution claim,
executable.

`rust/warrant/tests/serve.rs` passes untouched, which is the check that `parse_request_with` changed
no behaviour.

## Deployment

`rust/Dockerfile.archive`, built from the `rust/` workspace root, following `Dockerfile.trust-core`:
`rust:1.85-slim` builder, `debian:bookworm-slim` runtime, non-root, `EXPOSE 8788`, read-only root
filesystem (the archive writes nothing to disk — all its state is in Postgres).

`deploy/evidence-archive/docker-compose.yml`, a sibling of `deploy/local-sigstore/` rather than an
edit to the repository-root compose file, which is the whole-portfolio development environment.
A pinned `postgres:16.4-bookworm` with a named volume and a `pg_isready` healthcheck; a one-shot
`migrate` service the server waits on with `service_completed_successfully`, so the server never
starts against a database whose trigger and grants are not installed; both ports published to
`127.0.0.1`. No password in the file — `POSTGRES_PASSWORD` and `ARCHIVE_RUNTIME_PASSWORD` come from
the environment and compose fails loudly if they are unset.

**Bringing it up is three steps, not one, and the order is forced by the schema.** `archive_runtime`
is created *by* the migration, so its password cannot be set before the migration has run; and the
server cannot authenticate until that password is set, so it starts last: `up -d db` →
`run --rm migrate` → `ALTER ROLE archive_runtime PASSWORD …` → `up -d archive`. `make archive-up` is
that sequence, and it refuses to start at all if either password is unset rather than failing halfway
through. The earlier runbook told the operator to `exec db psql` before anything was running, to
alter a role that did not exist yet, and its `psql` invocation supplied no password to a database
initialised with `--auth-local=scram-sha-256`. It could not be followed as written by anybody.

The TLS-terminating reverse proxy is present and **commented out**, with the note that stage 1
without it is loopback-or-VPN only. That is not a recommendation; it is the boundary of what the
deployment supports.

The server connects as `archive_runtime`, not as the schema owner. Connecting as the owner would
discard half the append-only enforcement and leave the trigger standing alone.

## Milestones

1. **The crate, ingest, device pairing, append-only storage, Docker and compose** — done, this
   change.
2. **Issuer-anchor pinning in the client verify path** — done, this change, because stage 1 could
   not honestly ship without it. `verify_export_signed_by` and `warrantor verify --issuer`.
3. **A push path from the local agent** — **done.** `warrantor archive enrol --url … --code …`
   pairs a machine, writing `~/.warrantor/keys/device.key` beside the issuer and settle keys and a
   pairing record at `~/.warrantor/archive.json`; `warrantor archive push <file>` files a file's
   bytes verbatim; `warrantor archive fetch <sha256> --out <path>` reads one back, because reads are
   signed too and a `curl` could never perform one; and `--archive` on `report`, `stop` and `spend`
   files what `--export` just wrote, through the same code path, exiting non-zero if it fails and
   never unwriting the local file.

   The signing half of the wire contract **moved** to `rust/warrant/src/archive_client.rs`, and
   `warrantor_archive::device` re-exports it. That is the only shape in which one definition of the
   descriptor exists: this crate cannot become a dependency of the local agent — it pulls `postgres`
   and therefore tokio — so a client reaching for `sign_request` would have inverted the edge this
   RFC and `Cargo.toml` both forbid. `warrantor_archive::sha256_hex` now delegates to
   `warrantor_warrant::report::sha256_hex` for the same reason: the body digest a device signature
   covers is computed on both sides of the wire, and "one implementation" would otherwise have
   quietly become two.

   What the client refuses at **runtime**, not in a test: a digest the archive names that is not the
   SHA-256 of the bytes sent, and fetched bytes that are not the bytes their address names. Both
   checks are free — the client already computed that digest to sign the request — and an archive
   whose address does not name the bytes is not holding the operator's file, while both copies would
   still verify against their own signatures.

   What did **not** ship: no TLS, and no revocation *from the agent* — revocation is
   `warrantor-archive revoke --device <id>` on the archive host, added in the same
   change because issuing long-lived device keys with no way to withdraw one is not a credential
   system. (The list client, `warrantor archive list <warrant-id>`, shipped later — it was the one
   route this client still could not reach. So did automatic push at settle: `warrantor archive
   auto settle` records the policy in the pairing record, the CLI settle files the final report
   under it, and failures queue for the next settle rather than failing the settle. The HTTP
   settle surface does not auto-file.)
4. **TLS** — not done, and deliberately not half-done. Needs a certificate and a proxy config, both
   deployment rather than engineering.
5. **The trust directory (stage 2)** — the local half shipped: `warrantor issuer add` pins
   name → key into `trusted/issuers.json` (TOFU-with-pinning, no network, re-pinning refuses
   without an explicit replace), and `verify --issuer <name>` prints which anchor a verdict used.
   Stage 2 proper — a signed or shared directory, rotation, and organisational vouching — is
   still open, and a directory that hands out keys over the network remains a trust root this
   design has not decided to add. That is what would fully close the residual in row 1 of the
   threat model.
6. **Binding a device key into the settle record** — what would close the other half of W1 delivery
   gap 2.2 and make "who settled this" answerable.
7. **A retention job** — only after somebody needs one. The policy table exists so that job reads an
   explicit grant rather than inferring authority from an absent window.
