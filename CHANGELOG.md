# Changelog

All notable changes to Warrantor are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Per `docs/cross-cutting/15-open-source-governance.md` release process, every release tag
has its CHANGELOG entry populated by the release workflow and reviewed by a maintainer.

## [Unreleased]

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
