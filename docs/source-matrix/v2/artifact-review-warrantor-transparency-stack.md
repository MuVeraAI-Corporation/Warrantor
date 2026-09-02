# Warrantor transparency-stack artifact review

Status: current deployment rejected; specification/implementation mismatch and known-vulnerable pin  
Reviewed: 2026-08-30  
Local surface: `deploy/local-sigstore/`  
Claim adjudication: `CLM-0017` — contradicted, high confidence

## Executive decision

**Do not deploy the bundled stack as a Warrantor trust anchor.** The specifications name Rekor v2,
but the compose file runs Rekor v1.3.6. That release is in maintenance lineage and falls inside the
affected ranges of two 2026 GitHub-reviewed advisories. One advisory concerns the record-retrieval
API, and the compose file explicitly enables that API. The bootstrap also downloads a live,
unpinned Trillian schema and directly inserts tree state.

Adopt Sigstore's threat model and signed-artifact ecosystem. Replace this deployment with either a
pinned Rekor v2 profile that passes operational gates or a managed service with explicit privacy,
availability, trust-root and monitoring acceptance. Keep SCITT/COSE Receipts as a separate optional
registration profile, not a synonym for Rekor.

## What the repository says versus what it runs

| Concern | Warrantor specifications | Bundled implementation | Decision |
|---|---|---|---|
| Log generation | Rekor v2 | `rekor-server:v1.3.6` plus v1 Trillian services | Contradiction |
| Storage model | v2 tile-backed design implied | v1 Trillian/MySQL topology | Different system |
| Retrieval API | Not bounded in assurance claim | `--enable_retrieve_api=true` | Exposes affected v1 feature |
| Bootstrap inputs | Reproducible trust infrastructure implied | Downloads schema from live `master` | Reject mutable bootstrap |
| Tree creation | Managed log initialization implied | Direct SQL insertion with random ID and empty key columns | No production provenance/recovery story |
| Proof verification | Merkle/Rekor language | No demonstrated Warrantor v2 checkpoint verifier | Critical evidence gap |
| Trusted time | Timestamps and log anchoring blur together | v1 behavior implied | v2 requires RFC 3161 path |
| Operations | “working local transparency log” | Compose not executable in this review environment | Claim still contradicted statically |

## Security advisory exposure

The reviewed deployment pins v1.3.6. The official advisories state that releases through v1.4.3
are affected and v1.5.0 contains the fixes.

| Advisory | Affected behavior | Warrantor exposure | Required disposition |
|---|---|---|---|
| [GHSA-273p-m2cw-6833 / CVE-2026-23831](https://github.com/sigstore/rekor/security/advisories/GHSA-273p-m2cw-6833) | Malformed COSE input can cause denial of service | v1.3.6 is affected by version | Remove pin; add malformed-input tests and rate/resource controls |
| [GHSA-4c4x-jm2x-pf9j / CVE-2026-24117](https://github.com/sigstore/rekor/security/advisories/GHSA-4c4x-jm2x-pf9j) | Blind SSRF through `/api/v1/index/retrieve` | v1.3.6 is affected and retrieval is explicitly enabled | Disable affected service immediately; replacement preferred |

The latest observed Rekor v1 release was
[v1.5.4](https://github.com/sigstore/rekor/releases/tag/v1.5.4), published 2026-08-20.
Upgrading v1 would address known version exposure, but it would not make the architecture Rekor v2
or resolve the specification mismatch.

## Rekor v2 client contract

The [official Rekor v2 repository](https://github.com/sigstore/rekor-tiles) and
[client migration contract](https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md) establish:

- a tile-backed log with different deployment and storage architecture;
- a `hashedRekordRequestV002` request wrapper, not the v1 kind/apiVersion body;
- a direct `TransparencyLogEntry` response, not a UUID-keyed v1 map;
- client verification of the signed checkpoint and inclusion proof;
- explicit trusted-log/root configuration;
- `integrated_time == 0`, which clients must ignore;
- RFC 3161 timestamp evidence for trusted time; and
- removal of the DSSE entry type in
  [v2.3.0](https://github.com/sigstore/rekor-tiles/releases/tag/v2.3.0), requiring DSSE
  statements to be registered by digest while their semantic bytes remain elsewhere.

Therefore a valid Warrantor proof result must carry at least the exact statement digest, log ID,
API generation, checkpoint bytes/signature, tree size/root, inclusion proof, trusted-root version,
verification time/result and separate TSA evidence where time matters.

## Sigstore configuration nuance

The official root-signing repository was inspected rather than assuming that “current Sigstore”
means “Rekor v2 everywhere.” At the review snapshot:

- the default `signing_config.v0.2.json` target selected the v1 public URL; and
- a separate `signing_config_rekor_v2.v0.2.json` target selected a v2 log first with v1 fallback.

This is a dated configuration fact, not a permanent product promise. Warrantor must record which
TUF target, log and API it actually selected. Generic Sigstore branding is insufficient evidence.

## Guarantee boundary

| Verified fact | What it establishes | What it does not establish |
|---|---|---|
| DSSE signature valid | Exact typed bytes were accepted under a configured key rule | Signer authority, truthful statement or execution |
| Rekor inclusion valid | Digest was registered in the authenticated log state | Complete submission, action mediation or good content |
| Checkpoint consistent | Checked views are append-only/non-equivocating under assumptions | No private/off-path event exists |
| RFC 3161 timestamp valid | Token binds digest to TSA time under configured trust | Event occurred or was authorized at that time |
| Monitor saw expected sequence | Declared log views passed monitor policy | Every required producer submitted an event |
| Expected set reconciled | Declared required events were matched | The manifest enumerated every real-world path |

## Recommended profiles

### Preferred: private or managed Rekor v2, optional by assurance level

- pin release and image digest;
- pin TUF target, log ID and trusted root;
- register DSSE/in-toto statement digests;
- verify signed checkpoints and inclusion proofs locally;
- obtain and verify RFC 3161 time separately;
- use at least one independently operated checkpoint monitor for high consequence;
- define retention, backup, restore, shard transition and compromise recovery;
- classify submitted metadata and forbid confidential payload publication; and
- reconcile an authenticated expected set independently of the log.

### Acceptable interim: signed statements plus trusted timestamps

Defer transparency until the operational profile is ready. This provides less fork/registration
evidence but is more honest than deploying an unverified log. Preserve a migration-ready registration
record containing the statement digest and timestamp evidence.

### Alternate: SCITT service

SCITT and COSE Receipts provide a standards-based registered-history model but retain the same
selective-submission, privacy, monitoring, trust-root, key-status and operations questions. Do not
treat migration to SCITT as automatic resolution.

## Release-blocking acceptance gates

1. A pinned v2 deployment produces a correctly shaped entry and rejects v1-shaped requests.
2. Two independent clients verify the checkpoint and inclusion proof from official fixtures.
3. Wrong log ID, wrong root, malformed proof, rollback, split view and unavailable-log tests fail closed.
4. RFC 3161 evidence is verified; `integrated_time` is ignored.
5. Backup/restore and year-shard transition preserve verifiability.
6. TUF root rotation and compromise recovery are rehearsed.
7. Privacy review classifies digest, identity, time and tenant metadata.
8. Expected-set deletion and selective-submission tests demonstrate the separate reconciliation path.
9. Known advisory scanning and update latency are enforced in release policy.
10. Marketing and specifications name the exact profile and never equate inclusion with truth or completeness.

## Evidence limitations

Docker was unavailable in the review environment, so the compose topology was not started. The
version identity, configuration flags, mutable bootstrap and advisory ranges are static facts that
do not depend on a successful start. Live throughput, recovery and proof behavior remain unverified
and are acceptance gates rather than presumed failures.

