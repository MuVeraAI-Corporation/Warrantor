# Changelog

All notable changes to Warrantor are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Per `docs/cross-cutting/15-open-source-governance.md` release process, every release tag
has its CHANGELOG entry populated by the release workflow and reviewed by a maintainer.

## [Unreleased]

### Added — the fleet-level view: custody totals across everything the archive holds

- **`GET /v1/summary` at the archive, `warrantor archive summary` on the client.** The
  decision-maker's question — "what did our agents file, from where, when" — is one no single
  machine can answer about itself, because the filings live at the archive. The summary answers
  the part an evidence relay can answer honestly: **artifacts, warrants, devices, first and last
  filing, by kind, by device** — an account of custody records, aggregated from the same store
  read the per-warrant listing uses, so the summary and the listings can never disagree about
  what is held.
- **The boundary is stated in the render, not implied**: the heading says CUSTODY and refuses to
  say verdict, no artifact body is read to count anything, and the footer says plainly that
  "what any agent actually DID" is in the artifacts — `list`, `fetch`, `verify` — never in the
  counts. An archive holding nothing summarises as a sentence (zeros, no timestamps), visibly
  distinct from an archive that could not read its store, which **refuses** rather than
  summarising — the pair the listing already kept, kept here too, test-pinned.
- Authenticated like every route but health (server test: an unsigned caller learns nothing, not
  even whether there is anything to summarise). Not done, said in §3.3: per-repo views,
  time-bounded queries (no archive route reads a query parameter — the signature covers the
  path), and any aggregation of local-machine data.

### Added — `warrantor prune`: the one deletion authority this build has, gated to what it can honestly delete

- **`retention.json` + `warrantor prune [--apply]`.** For the whole of Wave-1 the honest sentence
  was "no deletion authority exists in this build; nothing here is ever removed by warrantor" —
  because nothing could delete, no window was offered either: a retention setting an operator
  could fill in while nothing enforced it would have read as a policy in force. The enforcement
  now exists. The policy mirrors the archive's `retention_policy` table exactly (`enabled`
  separate from `window_seconds`; either alone deletes nothing), and **the gate is in the code,
  not the config**: the job deletes only classes whose deletion costs nothing any signed
  artifact depends on (`logs/` today), refuses every other class by construction, and prints the
  refusals with their deletion effects so an operator reads what is NOT going as easily as what
  is. **Dry run by default; `--apply` is the opt-in** — the `--commit`/`--replace` precedent for
  the most destructive thing this binary does. Without a policy the command refuses and says the
  honest thing about storage growing without bound.
- **`warrantor holdings` now states the retention truth per class, under the policy in force**:
  the window and the enforcing command for prunable classes, "never removed by warrantor" plus
  the deletion effect for everything else, the old no-authority sentence when no policy exists,
  and a **BROKEN** line when a policy exists and will not parse — a window that enforces nothing
  while looking like one is the exact lie this exists to prevent.
- **What is deliberately not prunable**: anything a verdict, an answer or a piece of evidence
  depends on. Extending the gate to `staged/` requires writing the chain witness forward into a
  tombstone at deletion time (recorded in §3.4); the archive's server-side `retention_policy`
  table also remains unwired — the local answer came first.

### Added — notifications: the machine tells the human who is not looking at the window

- **Webhook notifications from `notify.json`.** Every oversight surface this repo has — console,
  desktop, CLI — assumes someone is watching. `notify.json` in the store root names webhook
  destinations (optionally per-webhook with a secret, used to HMAC-SHA256-sign every POST under
  `X-Warrantor-Signature`, so a receiver can tell Warrantor's pings from anyone else's; without a
  secret the POST is unsigned and the receiver should treat it as advisory). The CLI fires them
  when a warrant **settles, is voided, or is stopped**, and — the one an off-site overseer most
  needs — when an **automatic filing failed and was queued**.
- **The failure contract is the one automatic filing already set:** a delivery failure never
  fails the action that caused it (test-pinned through the real binary against a dead port —
  settle still exits 0), prints its own block stating both facts, and queues in
  `notify/pending.jsonl`, retried at the **next notification**. No daemon. A corrupt queue is an
  error naming the line, never an empty queue. An unconfigured machine sees byte-for-byte
  today's output (also test-pinned).
- **What leaves the machine is a decided, small contract:** event, warrant id, goal, subject,
  state, timestamp, one small detail — **never evidence bytes, never tool arguments** — and a
  test pins the payload to exactly those eight fields so a ninth cannot ride along quietly.
  Webhooks are usually third-party services; anything richer than "which warrant reached which
  state, when" is a data-export decision, and those are made deliberately or not at all.
- `warrantor holdings` learns the class, `LosesEvidenceSilently`: deleting the config or the
  queue silently stops an operator being told, and nothing complains in either direction.

### Added — `warrantor issuer show-hex`

- **The issuer's public key, from the one command whose job is to produce it.** Until now an
  operator pinning `issuer add` or handing the anchor to a verifier on another machine had to read
  the hex off `warrantor verify`'s "signed by" line — a key you fish out of a command's output is
  a key people copy wrong, and there was no way to see it before the first export existed.
  `show-hex` prints the 64-hex-character **public** half of `keys/issuer.key` with the two
  commands that take it (`issuer add`, `verify --issuer`), and states the asymmetry in plain
  words: anyone holding the hex can only *check* evidence; anyone holding the file can mint it.
- **Read-only, never minting.** `load_or_create_key` is deliberately not used: it creates a key
  when none exists, and showing an operator a key minted by the act of looking for it — a key that
  has signed nothing — is worse than saying there isn't one. On a machine with no issuer key the
  command refuses and names `warrantor grant`; a test pins that asking to *see* a key creates
  nothing.

### Added — issuer pins, so `verify --issuer` stops being a hex string pasted from the evidence itself

- **`warrantor issuer add <name> <hex> [--note "..."]`, `issuer list`, `issuer remove <name>`, and
  `verify --issuer <name>`.** Pasting a 64-character key verifies the file against a claim the
  same channel supplied — nobody checks a hex string they copied from the message the file arrived
  in. A pin makes that decision **once, out of band**: `issuer add ana <hex> --note "video call,
  2026-08"` records name → key in `trusted/issuers.json` under the store root, and every
  `verify --issuer ana` thereafter resolves the pin.
- **Every verdict says which anchor it used.** A pinned name prints `pinned as \`ana\`` with the
  pin's date and the words *trust on first use, checked out of band at pinning time*; the raw-hex
  form still works and prints *given on this command line* — different claims, never the same
  sentence. An unpinned name refuses with the exact `issuer add` command that would pin it, and
  never falls through to guessing.
- **Re-pinning refuses.** Pinning a name that is already pinned to a *different* key is refused,
  naming both keys and the old pin's date, because two keys under one name is exactly what an
  attacker who cannot forge signatures wants instead; `--replace` works, prints both keys, and
  says that every earlier verdict used the old one. The directory itself is **local, with no
  network, on purpose** — a directory that hands out keys over the network is a new trust root,
  and that is a design decision deliberately not taken here. The file is not signed, and `trust.rs`
  records why: an attacker who can rewrite it can equally rewrite `keys/issuer.key` and forge
  evidence outright.
- **`warrantor holdings` learns `trusted/issuers.json`**, classified `FLIPS-VERDICT`: deleting it
  turns every named verification from a verdict into a refusal, and the only road back —
  re-pinning — is the one operation that could put a different key under the same name.

### Added — automatic push on settle, and a queue that refuses to lose a filing

- **`warrantor archive auto settle|off`, and the settle that files without being asked.**
  `--archive` on `report`/`stop`/`spend` files what `--export` wrote — when an operator remembers
  the flag at the moment they export. The final report has no such moment: by the time a warrant
  is settled, the operator is done. `auto settle` records the policy in the existing pairing
  record (absent field means `off`, so records from before this change keep their meaning and the
  format stays `/1`), and every CLI settle builds the final report export — the same recipe
  `report --export` uses, including the queue-read-as-result so an unreadable staged log is
  *recorded*, not hidden — writes it to `exports/<id>.settle-report.json`, and files it.
- **A failed filing never fails the settle.** The warrant's state is a local fact established by
  local keys; an unreachable archive cannot un-settle it. This is the one deliberate difference
  from `--archive` on the export verbs, where the operator asked for a filing and a failed filing
  fails the command: here the operator asked to settle, the filing is policy, and a non-zero exit
  would tell a pipeline the settle failed when it did not — inviting a re-settle of a settled
  warrant, which is a command that no longer exists. The failure prints in its own block stating
  both facts in separate sentences ("the warrant above IS settled; the evidence is NOT filed").
- **A queue with a defined retry point, not a daemon.** Failed filings append to
  `archive/pending.jsonl` — warrant id, the export's path, its digest, the attempt count, the
  newest refusal — and the next settle drains the queue before filing its own export. A retry
  re-reads the bytes off disk and checks them against the digest the entry promised: an entry
  whose file is gone, or whose bytes changed since queueing, is **dropped with a sentence**
  rather than silently skipped or filed under a promise that no longer names those bytes. A
  ledger that exists and will not parse fails the drain loudly rather than reading as an empty
  queue. There is deliberately no background retry: the next settle is the retry point, which is
  the next moment this machine is already doing archive business.
- **`warrantor holdings` knows about the two new locations** (`exports/`, `archive/pending.jsonl`)
  and what deleting each costs — including that an export whose filing is still queued is the
  only copy of those bytes, and that deleting the queue makes a failed filing permanent,
  silently.

### Added — the archive can be enumerated, so filing it is no longer write-only

- **`warrantor archive list <warrant-id>`.** `push` prints a digest exactly once and `fetch` takes
  a digest, not a warrant id — so an operator whose scrollback was gone could not even find out
  what they had filed. The listing route had been served by the archive since #40 with no client
  that could reach it. `list` asks `GET /v1/warrants/{id}/evidence`, signed like every other
  route, and prints each artifact's **full** digest — the address `fetch` takes — newest first,
  with the door's note carried verbatim under the archive's own `not_a_verdict` wording. **An
  empty listing is a real answer** (this archive holds nothing about that warrant) and is kept
  visibly distinct from an archive that could not read its store, which refuses with
  `store_unavailable` rather than listing: the CLI renders the first as a sentence and the second
  as the refusal it is, and a test pins the pair so they cannot collapse back together. The client
  also refuses, at runtime, a listing that comes back about a warrant other than the one asked
  about — the echo check is `list`'s analogue of `push`'s digest check — and a 200 whose
  `artifacts` array is missing is refused as unreadable rather than defaulted to empty, because
  "nothing held" and "an answer I could not parse" are different claims. Wiring this up found and
  fixed a real bug in the library half: it read `not_a_verdict` from inside `data`, where it never
  is on the wire, so every well-formed 200 would have failed as unreadable — invisible until now
  because nothing called the function and no test held it to the wire shape.

### Added — the evidence archive gets a client, so evidence can actually reach it

- **`warrantor archive enrol | push | fetch`, and `--archive` on `report`/`stop`/`spend`.** PR #40
  merged a complete evidence archive with **no clients**: nothing outside `rust/archive` could
  produce a `Warrantor-Device` `Authorization` header, so the `curl` its deployment README
  documented could not be typed by anybody, `submitted_by_device` had never named a person outside a
  unit test, and reading an artifact back was as unreachable as filing one — every route except
  health and enrolment is signed. `warrantor archive enrol --url … --code …` pairs a machine and
  writes `~/.warrantor/keys/device.key` beside the issuer and settle keys, plus a pairing record at
  `~/.warrantor/archive.json`; `push` files a file's bytes **verbatim**; `fetch` reads one back;
  `--archive` files what `--export` just wrote, through the same code path, exiting non-zero on
  failure and never unwriting the local file.
- **One definition of the wire contract, not two.** The signing half of
  `warrantor_archive::device` — `DEVICE_SCHEME`, `REQUEST_DESCRIPTOR_FORMAT`, `is_device_id`,
  `request_descriptor`, `signing_input`, `sign_request` — **moved** to
  `rust/warrant/src/archive_client.rs`, and the archive re-exports it. Copying it into the agent was
  the obvious alternative and the wrong one; depending on `warrantor-archive` from `rust/warrant` was
  the other, and it would have pulled `postgres` and tokio into a program whose point is to run on a
  laptop with nothing installed. `warrantor_archive::sha256_hex` now delegates to
  `warrantor_warrant::report::sha256_hex` for the same reason: the body digest a device signature
  covers is now computed on both sides of the wire.
- **Two runtime refusals, not test assertions.** `push` compares the digest the archive returns
  against the SHA-256 of the bytes it sent and refuses on disagreement; `fetch` checks the bytes it
  received against the address it asked for. Both are free — the client already computed that digest
  to sign the request — and an archive whose address does not name the bytes is not holding the
  operator's file, while both copies would still verify against their own signatures.
- **A filing is custody, not a verdict.** The client's result type has no field a viewer could render
  as one: the door's three-valued ingest note is carried verbatim under the archive's own
  `not_a_verdict` wording, an artifact whose signatures fail is still filed and still reported as
  filed, and nothing in this path prints "verified". That answer still comes only from
  `warrantor verify <file> --issuer <hex>`, in Rust, on the reader's own machine.
- **`warrantor-archive revoke --device <id>`.** `ArchiveStore::revoke_device` had been implemented in
  both stores since the crate landed, with no caller outside a test. That was survivable while no
  device key existed anywhere; it stopped being survivable the moment `enrol` began putting
  long-lived Ed25519 keys on laptops.

### Fixed

- **`load_or_create_key` warned about the wrong key.** It printed "anyone holding the **settle** key
  can release staged effects" whatever key it had just created, so creating an issuer key warned
  about an authority the issuer key does not carry. Each kind now names only what it can actually do.
- **`warrantor.ledger-export/1` does not exist.** `rust/archive/src/lib.rs` and `src/artifact.rs`
  both named the spend ledger's format that way; the constant is
  `spend::LEDGER_EXPORT_FORMAT = "warrantor.spend-export/1"`. The runtime was always right — it uses
  the constant — but the prose is what somebody hand-building a submission reads.

### Added — a month-scoped console view for the refusal and guard aggregates

- **`/v1/summary/refusals` finally has a client.** The store-wide aggregate, the bounds-probably-
  wrong verdict, the guard groups and the coverage counters were computed on every request and
  rendered by nobody: the route was reachable only by `curl`, and the CLI help pointed at it as
  "the one to read weekly". The console now has a second destination beside the warrant list —
  **Refusals & guard** — that answers, for a chosen month: which bounds the agents hit and whether
  the bound or the agent is probably wrong; what the guard MODEL flagged, stated separately and
  with the mode on every row; and how much of the month nothing looked at.
- **Fixed first, because the view could not honestly exist without it: the route accepted a query
  and ignored it.** `request.query` was read at exactly one place — inside `list_filter`, reached
  only from `Target::List` — so `GET /v1/summary/refusals?since=X` returned HTTP 200 carrying the
  **all-time** aggregate. A console rendering that under a month heading is the `?status=open`
  silently-returning-every-warrant defect with a nicer font. `/v1/summary/refusals` now takes
  `?since=` and `?until=` (inclusive/exclusive epoch seconds), filters records **and** guard
  signals before the existing aggregators run, and echoes the window it resolved.
- **Every other route now refuses a query string instead of ignoring one.** Ten routes had no
  parser at all, so `GET /v1/warrants/{id}?state=settled` answered 200 as though the parameter had
  meant something. It never did. **This is a behaviour change to `/v1`:** an unrecognised query on
  a route with no filters is now `400 malformed_query`.
- **`blocking_posture` is a field on the wire, not a phrase inside a sentence.** `enforcing` is
  `any(..)` over the whole scope, so a client with only the boolean renders `Mixed` as `Enforced`
  and tells an operator that calls which actually proceeded did not happen; the only alternative
  open to a renderer was string-matching English in `note`. `guard.blocking_posture` is now
  `observe_only` / `enforced` / `mixed`, or `null` when nothing at all was read.
- **`guard.coverage` counts what nothing looked at** — sessions attached vs. sessions that
  reported, calls sent to the backend, and the backend-unavailable, unparseable and over-budget
  totals — summed from the end-of-session records **only**, since the same three facts also exist
  as per-signal outcomes and adding both would inflate every number. There is deliberately **no**
  estimate of what the guard looked at and got wrong: live traffic here carries no labels, so
  multiplying the benchmark miss rate by live counts would put a number with no measurement behind
  it on the surface that least tolerates one. The measured rates stay where they already are,
  inside the server's own note, labelled as a benchmark.
- **Windowing is honest about what it cannot window.** Records carry the time their **session
  ended**, and a deduplicated guard signal carries the first sighting's time, so a session
  straddling a boundary lands wholly on one side — the answer is systematically attributed, not
  merely imprecise. `unreadable_lines` has no timestamp to compare and stays an all-time count.
  Both facts are stated by the server in `window.caveat` and printed by the console verbatim.
- **The separation is enforced in the view, not only in the payload.** A refusal row and a guard
  row are visually distinct, the guard block carries the mode on every row, and no verification
  verdict appears anywhere near it — asserted from Rust over the served bytes, and from
  `node --test` over the rendered panes.

### Added — the guard as a refusal signal, recorded and never enforcing

- **`rust/warrant/src/guard.rs`: a guard model wired into a live supervised MCP session, observe-only.**
  Before this the classifier was benchmarked and nothing called it during a run — W1 stated the
  boundary ("a model judgement becomes a refusal *signal*, never a verdict") and nothing implemented
  it. `warrantor mcp --agent <id> --guard` now attaches a local ollama-compatible classifier, records
  what it thought about each tool call into `<root>/guard/<id>.jsonl`, and reads back beside the
  refusals on `/v1/warrants/{id}/refusals` and `/v1/summary/refusals`. No new route, no new external
  dependency, no change to the warrant format. See
  [RFC W2](docs/rfcs/W2-guard-signals-in-a-live-run.md).
  **It blocks nothing, and that is the decision, not an unfinished edge.** Measured adversarial
  recall is 0.8152 — it would miss roughly one adversarial case in five anyway — and the
  false-positive rate quadruples under adversarial phrasing (0.0224 → 0.0923), so an enforcing guard
  would deny roughly one benign call in eleven and train the operator to override it. The enforcement
  path exists behind `--guard-enforce-untested-do-not-use`, defaults to off, and is untested in
  production.
- **Absent means absent, never "all clear".** No `--guard` writes no log and leaves no directory; a
  guard whose backend cannot report a `sha256:<64 hex>` digest for its model **refuses to attach**
  rather than emitting provenance-free signals; a transport failure records `backend_unavailable` and
  never `not_harmful`; an absent log renders `configured: false` with a note saying it is an absence
  of observation, not of findings. Model, digest and every policy knob travel on **every** signal
  line, as integers and bools so two runs compare byte for byte.
- **The endpoint must be loopback.** The guard is sent the agent's tool arguments — source, commands,
  PR bodies — so a configurable off-box endpoint would be an exfiltration channel opened by a flag,
  and it would bypass the egress broker because the call originates from warrantor rather than from
  the agent. `attach` refuses anything that is not loopback.
- **The verification envelope is untouched.** `guard.rs` imports no verification type and nothing
  from `report::`; a test compares `verification`, `verified` and the whole report bundle
  byte-for-byte with and without a guard log present, and asserts guard signals move neither
  `total_occurrences` nor `bounds_probably_wrong`. Guard signals live in their own log because a
  refusal means the call did *not* happen and a signal means it *did*.
- **`testvectors/guard/parse-cases.json`** pins the Rust and Python guard-response parsers to one
  fixture, so the measured `Safety: Safe` + `Categories: Jailbreak` finding cannot be lost to drift
  between two implementations.

### Added — the evidence archive (RFC W2, backend stage 1)

- **`rust/archive` (`warrantor-archive`)** — a self-hosted, append-only custody store for the three
  signed evidence files `warrantor verify` already reads. Postgres, Docker, device-pairing auth.
  It depends on `warrantor-warrant` so ingest calls the *existing* verifier: there is exactly one
  implementation of what "verifies" means, and it cannot come to disagree with itself across two
  processes. Bytes are stored verbatim and returned verbatim — a re-serialised artifact is one the
  archive chose, and "the archive returns what it was given" is what makes verifying off it worth
  anything.
- **Ingest verification is hygiene, never a verdict.** The result is three-valued
  (`ok`/`failed`/`unknown`, and `unknown` is never rendered as `failed`) and is served under a field
  named `not_a_verdict`. The archive deliberately does **not** reuse `serve::Response`, whose `json`
  constructor puts `verified` on every body: on a remote archive that field is a verdict from a
  machine the audited party may control, and a console renders what it is handed. An artifact whose
  check failed is still stored and still returned byte for byte — refusing to hold a tampered file
  would destroy the evidence that it existed.
- **Device pairing.** An operator mints a one-time code; the device holds an Ed25519 keypair and
  signs every request over `dsse_pae` of a descriptor pinning method, path, device, nonce, timestamp
  and body digest. This is what makes the trail name a person: `submitted_by_device` is somebody
  rather than "whoever held the token". It closes **half** of W1 delivery gap 2.2 — submission and
  read are attributed; the settle is not, because it happens on a laptop and may never reach this
  server.
- **Append-only, enforced twice** — a `BEFORE UPDATE OR DELETE` trigger and a runtime role with no
  `UPDATE`/`DELETE` grant, because a grant can be misconfigured while restoring a backup and a
  trigger cannot. Retention and export are implemented and **defaulted off**, with deletion
  authority requiring an explicit enable *and* a non-zero window: an absent window grants none, and
  is never read as "delete everything older than nothing".

### Fixed — review of the evidence archive, before it shipped

Six defects found reviewing the change above. Three of them are tests that were counted and did not
test what they were named after, which is the worst kind: a missing test is visible, a hollow one is
not.

- **`IngestCheck::Unknown` was unreachable, and its test asserted nothing.** Every arm of `ingest`
  that produced `unknown` also produced no warrant id, and the next line refused the submission for
  want of one — so the third of three values could never be written, the schema's
  `CHECK (ingest_check IN ('ok','failed','unknown'))` had two reachable values, and a newer build's
  export this one cannot parse was dropped at the door rather than kept. A body that names the
  warrant it is about is now filed as `unknown`, with the id read out of the raw JSON purely as a
  filing key and validated with the router's own `is_warrant_id`. The guarding test wrapped its only
  assertion in an `if let Ok(…)` that never matched; it is unconditional now, and a second test
  follows the value through the wire, the listing and a verbatim fetch.
- **The append-only trigger had never fired.** `the_database_itself_refuses_an_update_to_a_filed_
  artifact` updated a table it had never inserted into, and `artifact_append_only` is `FOR EACH ROW`
  — a row-level trigger does not fire on a statement matching zero rows. It now files a real
  artifact, connects as the **owner** (the role that *does* hold `UPDATE`), and requires the refusal
  to carry the trigger's own message, so "the trigger refused" cannot be confused with "this role
  was never granted UPDATE". The grant half is a second `#[ignore]`d test connecting as
  `archive_runtime` and asserting SQLSTATE `42501`.
- **A test the RFC, `store.rs` and `device_pairing.rs` all pointed at did not exist.** The single-use
  enrolment code — the whole anti-replay property of the pairing flow — had no test at any level.
  It has one now, and writing it found that `PostgresStore::enrol_device` set `consumed_by_device`,
  a NOT DEFERRABLE foreign key, to a `device` row the same transaction had not inserted yet: **every
  enrolment against a real database raised a foreign-key violation.** The claim is still the one
  conditional `UPDATE`; the FK column is filled after its referent exists. A test now counts the
  `#[ignore]`d database tests and fails if the number in the docs and the number in the code diverge.
- **Revocation was checked before the signature**, so an unauthenticated caller signing with a key
  they invented got `401 device_revoked` for a device id that exists and `401 unauthorized` for one
  that does not — an enumeration oracle over a route whose own comment promised it was not one.
  Revocation moved after `verify_strict`: only the holder of the device's key learns it was revoked.
- **`/v1/health` served `append_only: true`, `holds_no_signing_key: true` and
  `routes_that_mutate_a_warrant: 0`** as unauthenticated literals — a compromised archive that had
  acquired a signing key or lost its trigger returned exactly the same values, next to names a
  viewer renders as badges. Removed; the walker in `the_archive_never_serves_a_verdict.rs` now bans
  the shape as well as the word, and a test proves the walker catches every name it lists.
- **The threat model claimed a constant-time comparison that nothing called**, and the deployment
  runbook could not be followed in the order written — it told the operator to `exec` into a
  container that was not running, to alter a role the migration had not created yet, with a `psql`
  invocation carrying no password to a database initialised `--auth-local=scram-sha-256`. The
  comparison claim is corrected downward and the dead helper deleted; `make archive-up` now performs
  the three ordered steps and refuses to start if either password is unset.

### Security — `warrantor verify` gained an issuer anchor, and it was not optional

- **`report::verify_export` is anchor-free by construction**, and until now `warrantor verify` merely
  *printed* the key it was not comparing to anything. Each receipt carries its own public key and
  the only cross-check is that the two receipts agree, so anyone holding an Ed25519 keypair could
  fabricate a bundle, sign both receipts with it, and produce a file that verified. That is correct
  for what the function claims — "nothing has changed since signing" — and much weaker than what a
  reader hears.
- This is why the archive could not ship without it: the mandated property "a malicious archive
  cannot make a tampered bundle verify" was not merely untested, it was **false**.
- Added `report::verify_export_signed_by`, `stop::verify_stop_signed_by`,
  `spend::verify_spend_signed_by`, and `warrantor verify <file> --issuer <hex>`. Thin wrappers —
  the existing verifier, then a key comparison — not a second verifier. All three artifact types
  gained it so `--issuer` can never be a flag that is silently ignored.
- The anchor is **never defaulted** from the local store: verifying somebody else's evidence against
  your own issuer key yields a verdict from a key with nothing to do with the case, which is worse
  than no check because it looks like an answer. Without `--issuer` the command now prints an
  explicit limitation saying it checked self-consistency only.
- Where an anchor legitimately comes from is the trust directory, which is backend stage 2. This
  change lets an operator supply one.

### Changed

- `serve::parse_request_with` and `serve::Limits`, added additively so the archive reuses the
  agent's HTTP framing instead of writing a second parser — a second parser is a second place a
  `Transfer-Encoding` header or an unbounded line read can be got wrong. `parse_request` keeps its
  exact signature and behaviour; `rust/warrant/tests/serve.rs` passes untouched.

### Added — desktop installers, unsigned

- **The desktop shell has packaging configured for three platforms — not yet exercised.**
  `desktop/electron-builder.config.cjs` and `.github/workflows/desktop-release.yml` describe a
  Windows NSIS installer (per-user, no elevation — an unsigned installer asking for administrator
  is the worst possible first prompt from a security product, and an elevated install invites an
  elevated launch of the supervised agent), a macOS dmg for arm64 and x64, and a Linux AppImage and
  deb, each on its native runner. **That workflow has never run**: `workflow_dispatch` is
  unavailable until the file is on the default branch, so no installer has been produced, installed
  or launched on any platform, and the macOS and Linux legs are entirely unexercised. The macOS
  block is ad-hoc signed via `identity: '-'` — `identity: null` skips signing altogether, which
  leaves an invalidly-signed bundle that Apple Silicon will not execute.
- **The `warrantor` agent now ships inside the app, and is preferred over `PATH`.** It is compiled
  on the same runner that packages it, so the bundled agent always matches the app's architecture.
  Resolution order is bundled → `WARRANTOR_BIN` → `PATH`, and it is that way round because
  verification happens only in Rust and only in that binary: choosing the binary chooses the
  verifier, and an installed app must not be silently re-pointed at a different one by an
  environment variable any parent process can set. There is no fallthrough — a missing bundled
  agent, or a `WARRANTOR_BIN` that does not exist, stops the app with a message naming the path.
  Previously a reviewer with no `warrantor` on `PATH` got an error dialog on first launch.
- **`desktop/SIGNING.md`** — what unsigned costs on each platform, what to buy (EV code-signing
  certificate, Apple Developer Program), the config lines that turn signing and notarisation on,
  and the notarisation constraint the bundled agent creates. No update channel exists and none may
  be added before signing: over an unsigned artifact it is an unauthenticated code-execution
  channel.
- **`npm audit --audit-level=moderate` in `desktop/` now runs on every pull request** rather than
  only on the release checklist, at no cost to that job's no-Electron property. It reports in CI
  and blocks in `desktop-release.yml`: the advisory feed is a live external service, so a
  publication anywhere in electron-builder's build-tool tree must not stop unrelated Rust and
  Python work from merging, while a release still cannot ship on a vulnerable pin. New packaging
  tests assert that the builder config and `src/policy.js` agree on the bundled agent's filename,
  that the lockfile resolves Electron inside the audited `^43.4.0` range (not merely inside major
  43), that the macOS build is ad-hoc signed rather than signing-skipped, that the release workflow
  checks the bundled agent's executable bit rather than only its presence, that no publish channel
  is configured, and that `desktop` never joins the `typescript/` npm workspace.

### Security

- **`trust-core` `SigningKeyWrapper::zeroize()` left a usable key behind.** It overwrote the
  secret with `SigningKey::from_bytes(&[0u8; 32])` — a valid key derived from a constant, so
  anything signing after `zeroize()` produced a genuine signature under a key any attacker can
  reconstruct, and that signature verified. The key is now an `Option`: signing after zeroize
  fails closed rather than succeeding under a different key. `is_zeroized()` added so callers can
  check before the panicking accessors. Four regression tests, one of which asserts specifically
  that the all-zero-seed key cannot come back.
  Latent rather than exploited — nothing in this repository called `zeroize()` on the wrapper —
  but `warrantor-trust-core` is published, so a downstream caller could reach it.
- The no-op `impl Drop` (`let _ = self.inner.to_bytes();`) is removed. It zeroized nothing and
  made an extra stack copy of key material. `ed25519_dalek::SigningKey` is `ZeroizeOnDrop` and
  does the real wipe.

### Changed — cryptography (record of what PR #28 actually carried)

**PR #28 was titled "chore: rename AumOS and DefStack to Warrantor across prose". It also
contained a major cryptography migration.** Two workstreams were running in one working tree and
the crypto change was swept into the rename commit (`8300d15`). Recorded here because a signing
change described as a prose rename is not an acceptable audit trail for a product whose claim is
verifiable evidence.

What `8300d15` carried, beyond prose:
- `ed25519-dalek` 2.2.0 → **3.0.0**, pulling `ed25519` 3.0, `signature` 3.0, `curve25519-dalek`
  4 → **5.0**, `rand_core` 0.10.
- **Signing entropy source changed.** `rand` 0.8 removed as a direct dependency from 23 crates;
  ~20 `SigningKey::generate` call sites moved from `rand::rngs::OsRng` to
  `ed25519_dalek::rand_core::UnwrapErr(getrandom::SysRng)`. `getrandom::SysRng` is the direct
  successor to `rand` 0.8's `OsRng` (true OS entropy); `rand::rng()` was rejected because
  `ThreadRng` is a userspace ChaCha CSPRNG.
- `eval-guard` nonce generation moved to `getrandom::fill`.
- The two Ed25519ph prehash sites moved from `sha2::{Digest, Sha512}` to the
  `ed25519_dalek` re-export, which is byte-identical under both 2.2 and 3.0. `sha2` stays at
  0.10 for the unrelated Sha256 uses.
- MSRV rises to 1.85 (dalek 3 / curve25519-dalek 5).

**Wire format did not change, and this was tested rather than assumed.** Differential harnesses
pinned to `=2.2.0` and `=3.0.0` ran identical source against both and were byte-identical on
verifying keys, signatures, keypair byte ordering, `to_scalar_bytes`, Ed25519ph, canonical-CBOR
signing and DSSE PAE bytes, including the strictness matrix (S+L malleability, identity /
all-`0xff` / order-2 / p−1 keys). Rust-signed manifests verify under Python `cryptography`
46.0.3. Conformance is 220/220 across Rust/Python/Go/TypeScript, reproduced twice, and
`testvectors/` is unchanged. **No receipt re-signing is required.**

Known follow-ups from that migration, not addressed here: `rust/trust-core/fuzz/Cargo.lock` was
committed despite the gitignore policy and is now a second unsynchronised crypto pin; MSRV is not
pinned by a `rust-toolchain.toml`; the W1 notary Rust↔Python interop tests skip themselves when
their bundle is absent, so that lane can report green without running.

### Added — Wave 7 (console + commercial surface)

5 components at v1.0.0:
- **X7 console** (TypeScript, 12 tests): enterprise policy/evidence console; reducers +
  selectors for evidence/approvals/fleet/compliance/policies views; API client for E1/I1.
- **X8 mcp-gateway** (TypeScript, 22 tests): authority-aware MCP middleware; confused-deputy
  defense; audience check; side-effect-class escalation; invariant I-08 approval enforcement.
- **A8 arena** (TypeScript, 32 tests): Elo-ranking A/B leaderboard; expected-score + zero-sum
  update; win/loss/draw handling; leaderboard sorting.
- **X10 sovereign-stack** (Go, 16 tests): air-gapped deployment bundle manager; export/import
  with SHA-256 checksums; mode-based component requirements (safe_local/team/production).
- **X11 defstack-cloud** (Go, 17 tests): managed SaaS control plane; tenant provisioning;
  per-plan GPU quotas (free/team/enterprise/mission_critical); allocation tracking.

### Verified at the Wave-7 exit gate (FINAL)
- **691 tests passing total** (148 Rust + 146 Go + 331 Python + 66 TypeScript).
- **49 components at v1.0.0** shipped across all 7 waves.
- clippy clean; buf lint clean; cross-language conformance verified; docs sound.
- 17 Rust crates, 9 Go modules, 22 Python packages, 3 TypeScript packages.

## [1.0.0] — Wave 6 (cross-cutting aggregation)

13 components at v1.0.0:
- **X2 nooa-ext** (Python, 14 tests): PolicyEnforcer (OPA/Rego), AuditStreamer, IdentityBinder, AttestationHook.
- **X3 open-harness-spec** (Python, 10 tests): 5 vendor-neutral interfaces + conformance checker.
- **X4 crypto-audit-ai** (Python, 16 tests): IMPLEMENTATION_AUDIT / ALGORITHM_STRESS_TEST / DEPENDENCY_SCAN.
- **X5 retro-spec-kit** (Python, 17 tests): 6 transcript analyzers (network/real-system/behavioral/credential/supply-chain/unauthorized).
- **X6 metr-bridge** (Python, 10 tests): METREvalAdapter, TranscriptExporter, RiskReportBridge, IndependentVerifier.
- **X9 incident-exchange** (Python, 14 tests): 6 incident types, OCSF extension, MITRE ATLAS mapping.
- **A3 bias-sentinel** (Python, 15 tests): bias (BOLD/HONEST/CrowS-Pairs/WinoBias) + copyright (n-gram).
- **A4 comply-gate** (Python, 16 tests): CI/CD gates (coverage/sbom/eval/disclosure), break-glass overrides.
- **A7 red-team-cloud** (Python, 15 tests): continuous adversarial simulation wrapping A2.
- **R5 policy-compiler** (Python, 17 tests): NL/rules → OPA Rego + Cedar policy emitter.
- **R7 egress-filter** (Rust, 12 tests): eBPF egress enforcement; domain blocklist; canary IP detection.
- **S6 exfil-guard** (Rust, 20 tests): PatternMatcher (AWS/GitHub/OpenAI/SSN/CC), EntropyDetector, VolumeMonitor.
- **S9 lightwell-bridge** (Go, 17 tests): AI-artifact patch distribution extending Lightwell.

### Verified at the Wave-6 exit gate
- 592 tests passing total (148 Rust + 113 Go + 331 Python).
- 44 components at v1.0.0 shipped across Waves 1–6.
- clippy clean; buf clean; conformance verified; docs sound.

## [1.0.0] — Wave 5 (confidential compute + federated/edge)

- **C1-3 attesta-flow** v1.0 (Python, 5 tests + Terraform): E2E attested inference pipeline
  orchestrator running inside a TEE; emits signed PipelineAttestation per batch; Azure
  DC-series Terraform provisioning.
- **C1-4 tee-serve** v1.0 (Go, 21 tests): TEE-backed model serving sidecar; TLS terminates in
  TEE; forwards via Unix Domain Socket; wraps responses in Ed25519-signed AttestationEnvelope;
  <2ms overhead target; healthz/readyz/versionz/pubkey routes.
- **C1-5 confidential-fabric** v1.0 (Rust, 23 tests): composite attestation (GPU + runtime +
  agent identity → CompositeAttestation with canonical digest); KeyReleasePolicy (freshness /
  GPU / TEE / runtime-digest / SVID / publisher clauses); ConfidentialContainer with KDF;
  FleetView aggregation.
- **F1 fed-core** v1.0 (Python, 34 tests): attested federated training orchestration;
  Aggregator/Trainer/Verifier roles; admit gate (attestation required); FedAvg aggregator;
  DefaultVerifier (NaN/Inf/norm/free-rider/image-digest); DP delegated to F2 via callback.
- **F2 dp-crate** v1.0 (Python, 41 tests): production-grade differential privacy;
  DPSGDOptimizer (clip-then-noise); PrivacyAccountant (RDP-based moments accountant with
  composition); DPDashboard; pure-Python (TEE-safe).
- **F3 edge-sentinel** v1.0 (Go, 26 tests): edge inference attestation agent (<5MB binary);
  periodic attestation loop; TamperDetector; idempotent kill switch; alerter; systemd shape.
- **F4 fleet-marshal** v1.0 (Go, 25 tests): Kubernetes operator; ModelFleet CRD; canary /
  blue-green / all-at-once rollout strategies; FailureThreshold auto-rollback; RolloutExecutor.

### Verified at the Wave-5 exit gate
- 399 tests passing total (116 Rust + 96 Go + 187 Python).
- 31 components at v1.0.0 shipped across Waves 1–5.

## [1.0.0] — Wave 4 (inference stack)

- **N1 open-serve-kit** v1.0 (Go, 7 tests): OpenAI-compatible /v1/chat/completions proxy with
  per-model router; pluggable backends (vLLM/Triton/TensorRT-LLM/Ollama/Mock); optional
  attestation envelope per response; healthz/versionz.
- **N2 bridge-rt** v1.0 (Python, 17 tests): unified generate() API auto-selecting
  TRT-LLM > vLLM > Ollama > Mock; **TRT-LLM v0.16 sampler_type detection and adaptation**;
  CLI probe + generate.
- **N3 inference-proxy** v1.0 (Rust, 10 tests): middleware chain — allow-list/open auth,
  per-identity token-bucket rate limit, prompt-injection/PII/content-policy filter, exact-match
  cache. Cache hit verified end-to-end.
- **N4 tenant-guard** v1.0 (Go, 9 tests): multi-tenant GPU scheduler; MIG (hw) + MPS (sw)
  + none isolation; per-tenant quota; per-tenant AAE attestation enforcement; MIG-limit cap.
- **Wave-4 integration guide + verification report**.

### Verified at the Wave-4 exit gate
- 224 tests passing total (93 Rust + 107 Python + 24 Go).
- 24 components at v1.0.0 shipped across Waves 1–4.

## [1.0.0] — Wave 3 (supply chain + eval)

- **S2 provena-chain** v1.0 (Rust, 11 tests): Merkle provenance ledger; entry append with
  deterministic leaf hashes; checkpoint sign/verify (Ed25519) anchored to a transparency log;
  JSON-LD export.
- **S5 data-provenance-kit** v1.0 (Python, 11 tests): dataset lineage tracker recording 7
  transformation types (filter/map/dedup/concat/pii_redact/custom); order-independent snapshot
  digests; signed JSON-LD export; CLI.
- **S7 tamper-scan** v1.0 (Python, 13 tests): 4 analyzers (weight-distribution / backdoor /
  neuron-pruning / fine-tune); numpy acceleration with pure-Python fallback; CLI exits non-zero
  on HIGH/CRITICAL.
- **S8 train-guard** v1.0 (Python, 15 tests): framework-agnostic training monitor; gradient
  NaN/explosion/vanishing; loss divergence; dependency-hash integrity; weight-init sanity;
  signed TrainingAttestation.
- **A1 safe-eval** v1.0 (Python, 10 tests): YAML pipeline framework; 5 stage adapters
  (benchmarks/adversarial/safety/bias/red_team); pipeline error isolation; VEB (P8) emission;
  CLI.
- **A2 adversaria** v1.0 (Python, 15 tests): unified adversarial framework with 5 built-in
  attack generators (prompt-injection / jailbreak / encoding / multi-turn / training-data-
  extraction); per-type detectors; passthrough + (future) garak/PyRIT backends; CLI.
- **Wave-3 integration guide**: `docs/wave-3-integration-guide.md` documenting the supply-chain
  pipeline + EU AI Act Art. 55 §1/§2/§3/§7 coverage.
- **Wave-3 verification report**: `docs/wave-3-verification-report.md`.

### Verified at the Wave-3 exit gate
- 181 tests passing total (83 Rust + 90 Python + 8 Go).
- clippy clean with `-D warnings`; buf lint clean.
- 20 components at v1.0.0 shipped across Waves 1–3.

## [1.0.0] — Wave 2 (keystone + foundations)

- **T2 authority-spec** v1.0 (Rust, 9 tests): normative Agent Authority Envelope (P1 AAE) CDDL +
  JSON-Schema schemas (`specs/protocols/P1-aae.{cddl,schema.json}`) + Rust reference validator
  enforcing signature, expiry, side-effect class, I-08 approval, delegation depth.
- **I1 agent-identity** v1.0 (Go, 8 tests): real SPIFFE-style SVID issuance + JWT capability
  tokens + delegation chain with intersection semantics (invariant I-02) + in-memory revocation
  meeting the 5s budget (I-05). HTTP/JSON gateway at `/v1/agent-identity:{issue,verify,revoke}`.
  Go activation gate cleared (trigger #3).
- **E1 flight-recorder** v1.0 (Rust, 8 tests): signed Agent Action Receipts (P2 AAR) emitted
  pre-commit (invariant I-07), tamper detection, OCSF + OTel JSON export.
- **S1 safe-tensors-pp** v1.0 (Rust, 7 tests): `__provenance__` block in the safetensors header,
  Ed25519 sign/verify, tamper detection, write/read round-trip, backward-compatible with unsigned
  files.
- **S4 model-sbom** v1.0 (Python, 8 tests): CycloneDX 1.5 + SPDX 3.0 SBOM generator with the
  AI extensions (model.architecture, .parameters, .training_data, .base_model, .evaluations,
  .license). CLI.
- **A6 conformance** v1.0 (Rust + Python + Go, 1 vector × 3 langs): cross-language conformance
  runner proving the same Ed25519 signature verifies identically in all three languages.
- **A5 agentsec-lab** v1.0 (Python, 9 tests): adversarial benchmark framework with rotating
  holdouts, maintainer-first disclosure gating; built-in prompt-injection scenario + refusing and
  compliant baselines.
- **Wire-off-mock documentation**: `docs/wave-2-integration-guide.md` documenting how Wave-1
  components (R2, R3, R4) consume the real Go I1 instead of the proto mock.
- **Wave-2 verification report**: `docs/wave-2-verification-report.md`.

### Verified at the Wave-2 exit gate
- 106 tests passing total (72 Rust + 26 Python + 8 Go).
- clippy clean with `-D warnings`; buf lint clean.
- Cross-language Ed25519 verification confirmed in Rust + Python + Go.

## [1.0.0] — Wave 1.5 (CI hardening)

- **CI**: main workflow (`.github/workflows/ci.yml`) — buf lint + breaking, Rust test/clippy/fmt,
  Python test/ruff, conformance + docs gate scripts. Runs on every push and pull request.
- **Coverage**: `.github/workflows/coverage.yml` — Rust (`cargo-llvm-cov`) and Python
  (`pytest-cov`) coverage reports uploaded as artifacts. ≥85% gate becomes hard in Wave-2.
- **SBOM**: `.github/workflows/sbom.yml` — CycloneDX SBOM per Rust crate and per Python package,
  aggregated and uploaded.
- **SLSA L3 provenance**: `.github/workflows/provenance.yml` — GitHub Actions build-attestations
  for every release binary.
- **Fuzz CI**: `.github/workflows/fuzz.yml` — nightly `cargo-fuzz` on three trust-core targets
  (canonical_cbor, signature_decode, rekor_response); regression corpus uploaded.
- **Release**: `.github/workflows/release.yml` — tag-triggered GitHub Release with binaries,
  SBOM bundle, SHA-256 checksums.
- **Fuzz crate**: `rust/trust-core/fuzz/` — three committed fuzz targets (canonical_cbor,
  signature_decode, rekor_response); excluded from the parent workspace.
- **SECURITY.md** at repo root (mirrors `docs/cross-cutting/14-security-disclosure-policy.md`).
- **Dependabot** config (`.github/dependabot.yml`) — weekly Rust/Python deps, monthly Actions.

## [1.0.0] — Wave 1 (initial release)

### Added — Phase 0 (docs + foundation)
- Reconciliation matrix (`docs/00-reconciliation-matrix.md`) mapping all four source portfolios
  to 44 canonical components + 12 protocols.
- Vision + architecture docs (`docs/01-vision-and-portfolio.md`, `docs/02-architecture.md`):
  12-plane pressure-tested architecture, 12 formal invariants (I-01…I-12), deployment topologies.
- 53 component RFCs (10-section template) — T1 and I1 hand-written in full detail; 51 generated.
- 12 protocol specs (`specs/protocols/P1..P12-*.md`).
- 7 Wave-1 agent-handoff bundles (CLAUDE.md, AGENTS.md, PROMPT.md, tasks 01–08).
- 3 missing cross-cutting docs authored (17-data-classification-privacy, 18-developer-experience,
  19-inter-component-protocol) + originals 13–16 copied in.
- Monorepo skeleton (contract-hub layout per polyglot stack pressure test).
- Makefile (one-command dev/test/release), buf.yaml, conformance + doc-checker scripts.

### Added — Phase 1 (Wave-1 v1.0 components)
- **Proto contract plane** (`proto/warrantor/`): identity, trust, attestation, AAR protocols. Buf lint clean.
- **warrantor-api** crate: prost/tonic codegen at build time. Single source of truth for wire types.
- **T1 trust-core** v1.0.0 — Ed25519 sign/verify, canonical CBOR, RFC 6962 Merkle. 14 tests.
- **X1 defstack-cli** v1.0.0 — list/install/verify/compliance-report (10 frameworks). 4 tests.
- **C1-1 nvtrust-bridge** v1.0.0 — NvTrustBackend trait + Mock, proto round-trip. 5 tests.
- **C1-2 cuda-gram** v1.0.0 (Python) — AttestationVerifier, CCSession, Rust CLI JSON interop. 9 tests.
- **R2 eval-guard** v1.0.0 — 4 pre-flight checks, signed SandboxAttestation via T1. 4 tests.
- **R3 kill-switch** v1.0.0 — PolicyEngine trait + Mock, Government API stub, <5s budget. 9 tests.
- **R4 credential-vault** v1.0.0 — CredentialBackend trait + Mock/Vault/AWS/K8s stubs, exposure
  scanner. 10 tests.

### Verified
- 57 tests passing (48 Rust + 9 Python).
- clippy clean with `-D warnings`.
- buf lint clean; buf build succeeds.
- Contract plane authoritative: proto → warrantor-api → all consumers.
- Cross-language interop locked: Rust nvtrust-bridge ↔ Python cuda-gram JSON shape.

### Deferred
- Coverage % instrumentation, CycloneDX SBOM, SLSA L3, signed releases — CI/release-engineering
  tasks (addressed in 1.5 above).
- Real KMS/HSM, Rekor, OPA Rego, Vault/AWS/K8s, eBPF — Wave-1 task 03/04 work; traits + stubs in place.

[Unreleased]: https://github.com/MuVeraAI-Corporation/Warrantor/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/MuVeraAI-Corporation/Warrantor/releases/tag/v1.0.0
