# Warrantor / AumOS codebase survey

Repository root: `M:/Project AumOS - Open Secure AI Alliance/aumos` (nested git repo inside the
parent working directory). Surveyed 2026-09-02 at HEAD `834db38`, branch `docs/content-program-p9-fold`.
Read-only; nothing was modified.

Reading note that governs everything below: the Rust workspace has **80 member crates**, and the
shipping product is **one** of them (`rust/warrant`, 34,101 LOC). The intra-workspace dependency
graph has **13 edges total**. That asymmetry is the single most important structural fact in this
repository and section 2 quantifies it exactly.

---

## 1. Workspace layout

### 1.1 Rust workspace — `M:/Project AumOS - Open Secure AI Alliance/aumos/rust/Cargo.toml`

`[workspace] resolver = "2"`, 80 members, `exclude = ["trust-core/fuzz", "gguf-ext/fuzz"]`.
Workspace package block: `version = "1.0.0"`, `edition = "2021"`, `rust-version = "1.94"`,
`license = "Apache-2.0"`, `publish = false`.

The `rust-version = "1.94"` line carries a long comment: the floor was 1.85 until the
`wasmtime =45.0.1 -> =47.0.3` bump in PR #11 raised the real floor nine minors without touching the
declaration. CI never caught it because `rust-toolchain.toml` says `channel = "stable"`.

Release profile: `lto = true`, `codegen-units = 1`, `panic = "abort"`, `strip = true`.

**`rust/reputation/` exists on disk with a valid `Cargo.toml` (`name = "warrantor-reputation"`,
318 LOC) but is NOT listed in `[workspace] members`.** It is therefore never built, never linted
and never tested by `cargo test --workspace`. This is a concrete, unrecorded defect.

#### Crates with a binary target (10)

| Binary | Crate | Path |
|---|---|---|
| `warrantor` | `warrantor-warrant` | `rust/warrant/src/bin/warrantor.rs` |
| `warrantor-archive` | `warrantor-archive` | `rust/archive/src/bin/warrantor-archive.rs` |
| `defstack` | `defstack-cli` | `rust/defstack-cli/src/main.rs` |
| `credential-vault` | `warrantor-credential-vault` | `rust/credential-vault/src/cli.rs` |
| `eval-guard` | `warrantor-eval-guard` | `rust/eval-guard/src/cli.rs` |
| `kill-switch` | `warrantor-kill-switch` | `rust/kill-switch/src/cli.rs` |
| `trust-core` | `warrantor-trust-core` | `rust/trust-core/src/cli.rs` |
| `nvtrust-verify` | `warrantor-nvtrust-bridge` | `rust/nvtrust-bridge/src/cli.rs` |
| `gguf-ext` | `warrantor-gguf-ext` | `rust/gguf-ext/src/bin/gguf-ext.rs` |
| `protocol-tck-rust` | `warrantor-protocol-contracts` | `rust/protocol-contracts/src/bin/protocol_tck.rs` |

#### Crate size and test presence

Only **9 crates have an integration `tests/` directory**: `agent-manifest` (1 file), `archive` (6),
`credential-vault` (1), `defstack-cli` (1), `notary` (1), `protocol-contracts` (1), `trust-core` (1),
`warrant` (35), `warrantor-api` (1). Every other crate's tests are in-file `#[cfg(test)] mod tests`
blocks — typically exactly one per crate.

Largest crates by `src/` LOC: `warrant` 34,101 · `archive` 3,102 · `gguf-ext` 2,894 ·
`kill-switch` 2,547 · `credential-vault` 2,332 · `flight-recorder` 1,997 · `trust-core` 1,750 ·
`sandbox-runtime` 1,314 · `secure-workspace` 1,304 · `protocol-contracts` 1,112 ·
`egress-filter` 1,102.

The 40+ "catalogue domain" crates (`authority-algebra`, `capability-tokens`, `receipt-federation`,
`transparency-log`, `time-anchoring`, `delegation-chain`, `metering`, `quorum-warrants`,
`escrow-warrants`, `proof-of-erasure`, `guard-graduation`, `promotion-pipeline`, and the rest) are
uniformly 170–600 LOC with one unit-test module and no dependents.

#### `rust/warrant` module map (`src/lib.rs` declares 33 `pub mod`)

`src/bin/warrantor.rs` 6,728 · `serve.rs` 4,726 · `guard.rs` 1,843 · `report.rs` 1,418 ·
`harness.rs` 1,404 · `archive_client.rs` 1,231 · `mcp_endpoints.rs` 1,212 · `operators.rs` 1,170 ·
`retention.rs` 1,113 · `stop.rs` 1,067 · `review.rs` 932 · `spend.rs` 921 · `upstream.rs` 821 ·
`sandbox.rs` 689 · `bundle.rs` 675 · `lib.rs` 653 · `bench.rs` 600 · `notify.rs` 558 ·
`anchor.rs` 553 · `corpus.rs` 513 · `staging.rs` 500 · `egress.rs` 499 · `store.rs` 488 ·
`supervise.rs` 444 · `daemon.rs` 444 · `runs.rs` 384 · `worktree.rs` 340 · `autofile.rs` 320 ·
`proxy.rs` 311 · `mcp.rs` 296 · `trust.rs` 295 · `settle.rs` 257 · `tls.rs` 235 · `lock.rs` 218 ·
`adapters/github.rs` 236.

External dependency posture is deliberately tiny and commented as such: `thiserror`, `serde`,
`serde_json`, `ed25519-dalek` 3, `hex`, `digest`, `hmac`, `sha2` 0.11, `getrandom` 0.4,
`ureq` 2. `rustls` + `rustls-pemfile` are behind the **off-by-default `tls` feature**. The manifest
explicitly refuses a path dependency on `warrantor-kill-switch` because that crate declares `tokio`,
`clap`, `tracing` and `tracing-subscriber` unconditionally and would break the tokio-free posture —
"grep finds no tokio, no `async fn` and no `.await` anywhere in that crate's src".

### 1.2 Python — `aumos/python/` (54 `pyproject.toml` files, CI job says "35 projects")

All setuptools + `src/` layout, `requires-python = ">=3.11"`, ruff `line-length = 100`,
`select = ["E","F","I","B","UP","SIM","RUF"]`, `ignore = ["E501"]`.

Key packages: `warrantor` (the one-import SDK wrapping notary + evidence envelope + agent manifest;
only dependency `cryptography>=42`), `warrantor_ml`, `policy_compiler`, `warrantor_agent`,
`warrantor_evidence`, `warrantor_notary`, `warrantor_egress`, `warrantor_harness`,
`warrantor_adapters`, `warrantor_langchain`, `warrantor_vllm`, `warrantor_hf_plugin`,
`warrantor_ocsf`, `warrantor_rbac`, plus 30+ research/plane packages (`adversaria`, `safe_eval`,
`bias_sentinel`, `comply_gate`, `fed_core`, `dp_crate`, `model_sbom`, `tamper_scan`, `train_guard`,
`red_team_cloud`, `metr_bridge`, `incident_exchange`, …), each exposing one `[project.scripts]`
console entry of the form `<name> = "<module>.cli:main"`.

`aumos/ml/` is a separate launcher directory with **no `pyproject.toml`** — deliberately, and it is
policed: `tools/ci/run_python_checks.py` enforces `ML_LAUNCHER_MAX_LINES = 60` against the
filesystem because "186 lines of ungoverned benchmark code once lived there."

### 1.3 Desktop — `aumos/desktop/`

`package.json`: `@warrantor/desktop` 1.0.0, `"type": "module"`, `"main": "src/main.js"`,
engines `^20.19.0 || >=22.12.0`. Scripts: `start` (`electron .`), `test`/`test:ci`
(`node --test test/*.test.js`), `pack` and `dist` (`electron-builder --config
electron-builder.config.cjs`). devDeps: `electron ^43.4.0`, `electron-builder ^26.15.3`.

Source is only three JS files — `src/main.js`, `src/ipc.js`, `src/policy.js` — plus four pinned JSON
schemas under `src/schemas/`: `agent-serve-announce-v1.0.0.json`, `warrant-list-v1.0.0.json`,
`warrant-list-v1.0.1.json`, `warrantor-openapi-v1.0.0.json`.

**How it talks to Rust:** it does not reimplement anything. It spawns the bundled `warrantor.exe`
(`resources/warrantor.exe`) running `warrantor console`/`serve`, and renders the HTTP console the
Rust agent itself serves. Tests: `build-manifest`, `corpus`, `cross-surface-drift`, `golden`,
`ipc-integration`, `packaging`, `policy`, `security-posture-drift`, `shell`, `source-files-parse`,
`wire-contract`.

### 1.4 TypeScript — `aumos/typescript/`

npm workspaces: `console`, `mcp-gateway`, `arena`, `mcp-server`, `protocol-contracts`.
Toolchain: `typescript ^5.5`, `vitest ^4.1.10`, `eslint ^10.8.1`. Scripts: `build` (`tsc -b`),
`typecheck:conformance` (`tsc -p tsconfig.conformance.json`), `test` (`vitest run`), `lint`.

### 1.5 Go — `aumos/go/` (12 modules)

`agent-identity`, `defstack-cloud`, `edge-sentinel`, `fleet-marshal`, `identity-bindings`,
`lightwell-bridge`, `metrics`, `open-serve-kit`, `protocol-contracts`, `sovereign-stack`,
`tee-serve`, `tenant-guard`.

### 1.6 Backend / relay and deploy

- **Evidence archive** — `rust/archive` (3,102 LOC, 6 test files), modules `artifact`, `device`,
  `http`, `postgres`, `store`. Routes: `/v1/health`, `/v1/devices/enrol`, `/v1/evidence`,
  `/v1/evidence/<sha256>`, `/v1/warrants/<id>`, `/v1/summary`. Postgres-backed; tests are
  `#[ignore]`d so `cargo test --workspace` stays green with no database.
- `deploy/evidence-archive` (Postgres + archive + Caddy TLS proxy), `deploy/local-sigstore`
  (MySQL + Trillian + Rekor `v1.3.6`), `deploy/helm/aumos`, `deploy/k8s`, `deploy/spire`,
  `deploy/systemd`, `deploy/airgap`, `deploy/modal`, `deploy/muveraai-worker` (Cloudflare Wrangler).
- Six Dockerfiles in `rust/`: `Dockerfile.archive`, `.credential-vault`, `.flight-recorder`,
  `.inference-proxy`, `.kill-switch`, `.trust-core`. Root `docker-compose.yml` (11,927 bytes).

---

## 2. The W1–W6 spine as implemented, and what the CLI actually calls

### 2.1 Which crate implements which wave

| Wave | Crate | Path | Core public items |
|---|---|---|---|
| **W1 Notary** | `warrantor-notary` | `rust/notary` | `enum Gate` (9 variants), `enum Verdict`, `fn verdict(&VerdictRequest, &VerdictContext) -> Verdict`, `fn issue_receipt(...)`, `fn verify_receipt(&WarReceipt)`, `struct WarReceipt` |
| **W1 warrant** | `warrantor-warrant` | `rust/warrant` | `struct Warrant`, `WarrantClaims`, `WarrantBounds`, `CapabilityToken`, `enum WarrantState`, `enum BoundStrength` |
| **W2 Evidence** | `warrantor-evidence` | `rust/evidence` | `WAR_VERSION = "war/2.0"`, `issue_pre_commit`, `issue_post_commit`, `issue_atomic`, `verify_chain`, `compute_intersection_proof` |
| **W3 Containment** | `warrantor-containment-conformance` + `rust/warrant/src/stop.rs` | | `conformance_report`, `StopRecord`, `SignedStop`, `STOP_BUDGET = 5s` |
| **W3 kill switch** | `warrantor-kill-switch` | `rust/kill-switch` | 2,547 LOC, own `kill-switch` binary — **not linked by `warrantor`** |
| **W4 Policy compiler** | `python/policy_compiler` + `warrantor-policy-bridge` | | no Rust policy compiler in the CLI path |
| **W5 Egress broker** | `warrantor-egress` | `rust/egress` | `fn decide(&EgressRequest, Option<&DestinationCatalog>) -> EgressVerdict`, `EgressReceipt`, `DenyReason` |
| **W6 Delegation** | `warrantor-delegation-chain` | `rust/delegation-chain` | `fn intersection(&WarrantScope, &WarrantScope) -> Result<WarrantScope, Escalation>`, `WarrantStore::delegate`, `is_revoked_lineage` |

**W6 is the sharp one.** `warrantor-delegation-chain` implements the intersection algebra and
lineage revocation, and **nothing depends on it**. The delegation semantics the CLI actually uses
are the separate `recompute_intersection` / `compute_intersection_proof` pair inside
`warrantor-evidence`, plus `WarrantBounds::delegation_depth`. Two implementations of the same
primitive, one of them dead.

### 2.2 The notary's nine gates, verbatim from `rust/notary/src/lib.rs:37`

```
Containment = 1  // I-12: a kill-switch is active for this scope.
Identity    = 2  // I-01: SVID absent, expired, revoked, or unverifiable.
Freshness   = 3  // I-10: nonce reused, timestamp outside window, clock skew.
Chain       = 4  // I-02: a delegation link fails signature or validity-window checks.
Authority   = 5  // I-02: requested operation not in the recomputed intersection.
Artifacts   = 6  // I-06: a digest unverified, unsigned, or mismatched.
Budget      = 7  // Autonomy budget exhausted or blast-radius cap exceeded.
Policy      = 8  // I-04: policy engine returns deny, evaluated now.
Approval    = 9  // I-08: critical action without valid, non-delegable human approval.
```

`Verdict::Deny { gate }` carries **only** the failing gate, never the missing capability — spec 11
§4: "an agent that learns *why* it was denied learns the shape of the boundary."

### 2.3 Bound strength — the three enforcement tiers, verbatim from `rust/warrant/src/lib.rs:635`

```rust
("tools",                 BoundStrength::Mediated),
("write_paths",           BoundStrength::Observed),
("egress_hosts",          BoundStrength::Mediated),
("staged_classes",        BoundStrength::Mediated),
("expires_at",            BoundStrength::Enforced),
("delegation_depth",      BoundStrength::Enforced),
("budget_cents_observed", BoundStrength::Observed),
```

`Enforced` = "cryptography or the operating system: a signature it cannot forge, a process link it
cannot outlive." `Mediated` = "the MCP proxy … the agent could decline to use [it]" —
the comment on `egress_hosts` says plainly "**no netns, no seccomp, no firewall**". `Observed` =
measures and reports, cannot prevent.

### 2.4 The `warrantor` CLI surface

Dispatch is a flat `match` at `rust/warrant/src/bin/warrantor.rs:6464`. 31 top-level commands:

`grant · list · holdings · prune · report · verify · issuer · archive · egress · spend · stop ·
settle · void · stage · run · supervise · status · mcp · operator · approve · queue · sandbox ·
agents · guard · anchor · selftest-upstream · serve · console · help`

Global flags: `--root <path>` (default `~/.warrantor`), `--allow-notify-command`.
Notable subcommand shapes:
- `grant --goal G --tools T,T --write P,P [--deadline 8h] [--repo .] [--egress H,H] [--budget CENTS] [--subject <id>]`
- `mcp [--agent <id>] [--observe] [--guard [--guard-model M]] [--upstream 'name=cmd args'] [--upstream-timeout 30s] [--upstream-class '<tool>=read|write|destructive|financial'] [--upstream-refuse-unclassified]`
- `agents list | detect | show <harness> | wire <harness> <warrant-id> [--apply] [--replace]`
- `guard doctor | bench --cases <file.jsonl> | export-corpus --out <file.jsonl> [--min-labelled N]`
- `operator list | add <name> --scope read,stop,settle,approve --note "..." | remove | session-scope`
- `serve/console [--bind] [--port] [--token-file] [--allow-settle] [--i-accept-cleartext-on-this-network] [--tls-cert --tls-key]`

### 2.5 The call graph, and the orphan count

`rust/warrant/Cargo.toml` declares exactly **seven** intra-workspace path dependencies:
`trust-core`, `authority-spec`, `evidence`, `notary`, `egress`, `containment-conformance`, `spend`.

Usage frequency inside `rust/warrant/src` (`grep 'warrantor_*::'`): `warrantor_evidence` 4,
`warrantor_spend` 3, `warrantor_archive` 3, `warrantor_notary` 2, `warrantor_egress` 2,
`warrantor_containment_conformance` 1, `warrantor_authority_spec` 1.

**The entire workspace has 13 path-dependency edges:**

```
warrant           -> trust-core authority-spec evidence notary egress containment-conformance spend
archive           -> warrant evidence
agent-channel     -> trust-core
gguf-ext          -> trust-core
jurisdiction      -> trust-core
sandbox-runtime   -> trust-core
secure-workspace  -> trust-core
task-validity     -> trust-core
authority-spec    -> warrantor-api
eval-guard        -> warrantor-api
flight-recorder   -> warrantor-api
nvtrust-bridge    -> warrantor-api
trust-core        -> warrantor-api
```

**Orphaned from the `warrant` CLI: 71 of 80 crates.** Only these 9 are reachable from the
`warrantor` binary: `warrant`, `trust-core`, `authority-spec`, `evidence`, `notary`, `egress`,
`containment-conformance`, `spend`, `warrantor-api`. Every named-plane crate — `transparency-log`,
`time-anchoring`, `delegation-chain`, `capability-tokens`, `receipt-federation`, `revocation-verbs`,
`incident-replay`, `swarm-detection`, `retrieval`, `computer-use`, `content-moderation`,
`csam-defense`, `misinformation-defense`, `responsible-ai`, `post-quantum`, `self-governance`,
`data-plane`, `plugin-api`, `kill-switch`, `credential-vault`, `flight-recorder`,
`secure-workspace`, `sandbox-runtime`, `egress-filter`, `exfil-guard`, `policy-bridge`,
`provena-chain`, `safe-tensors-pp`, `confidential-fabric`, `inference-proxy` and all 40+ catalogue
crates — is compiled, tested in isolation, and called by nothing a user can run.

This is the pattern `docs/W1-delivery-gaps.md` names three separate times as **wire before widen**.

---

## 3. The formal invariants I-01 … I-12

Source: `docs/02-architecture.md` §3 (lines 68–86). Verbatim, with the doc's own "primary
components" column and my assessment of what actually enforces each today.

| ID | Statement (verbatim) | Doc says | Actually enforced by |
|---|---|---|---|
| **I-01** | "No active identity, no action. Every action carries a verifiable AAE (P1) with a valid, unrevoked SPIFFE SVID." | I1, all components check AAE | `notary::Gate::Identity`; `authority-spec::validate`. No live SPIRE in the CLI path — subject is the constant `DEFAULT_CLI_SUBJECT = "spiffe://muveraai.com/agent/local"` |
| **I-02** | "No authority expansion. The intersection of authorities in the delegation chain is the maximum authority; never the union." | I1, R3, MADE (P10) | `evidence::recompute_intersection` + `verify_authority` (error text: "authority expansion; I-02"); `notary::Gate::Chain`/`Authority`. Also `delegation-chain::intersection` — **unreached** |
| **I-03** | "Purpose-bound data use. Data tagged with a purpose in CPE (P3) is only used for that purpose; violation fails-closed." | "(future context comps), all egress paths" | **Nothing.** No CPE implementation in Rust |
| **I-04** | "No consequential action without current policy. Policy is re-evaluated at commit time, not just at start." | R5, R6, R3 | `notary::Gate::Policy` (gate exists; policy engine is a caller-supplied context field) |
| **I-05** | "Revocation latency is bounded. Identity revocation (I1) propagates to all replicas in <5s; credential revocation (R4) in <1s." | I1, R4 | `credential-vault`: `REVOKE_BUDGET`, `persist.rs`, test `"a revoked credential MUST stay revoked across a restart (I-05)"`. **Orphaned from the CLI** |
| **I-06** | "Artifact identity is exact. A model/skill/dataset is identified by its content digest, not its name or URI." | T1, S1, S4, AATM (P6) | `notary::Gate::Artifacts`; `trust-core::merkle`; `gguf-ext`; `safe-tensors-pp` |
| **I-07** | "Evidence precedes commitment. The AAR (P2) is signed *before* the action's effect is visible; the action only commits once evidence is durable." | E1, R3, R4 | `evidence`: `issue_pre_commit` / `issue_post_commit` / `verify_chain`; error `"commit-gate violation (I-07)"`, `"post_commit has no parent_receipt (orphan; I-07)"` |
| **I-08** | "Critical actions require non-delegable human authority. A defined class of actions (financial transfer, destructive op, physical actuation) require a human approval in the chain." | R3, R5, I1 | `authority-spec::SideEffectClass` + `validate` §4; `notary::Gate::Approval`; `warrant/src/operators.rs` `ApprovalPolicy`/`ApprovalVerdict` |
| **I-09** | "Failure is safe. If any plane fails open, the action fails closed. Network loss to I1 = deny." | All | `eval-guard/src/cli.rs:50` ("REFUSING to start the agent (invariant I-09: failure is safe…"). Orphaned |
| **I-10** | "Replay is detectable. Every action carries a nonce + timestamp; replays outside the window are rejected." | I1, all RPCs | `notary::Gate::Freshness` (gate exists; no nonce store in `warrant`) |
| **I-11** | "Self-change is governed. An agent cannot modify its own enforcement boundary, policy, or identity." | R1, R2, R8, R5 | `egress/src/lib.rs:51` — catalog-amendment denial. Also `CapabilityToken` has no settle scope by construction |
| **I-12** | "Physical systems can reach a safe state. For any cyber-physical action, there exists a kill path to a known-safe state." | R3, (future physical authority), R4 | `notary::Gate::Containment`; `warrant/src/stop.rs`. `STOP_ENFORCEMENT_MODE = "advisory"` |

116 `I-0x`/`I-1x` references exist across `rust/**/*.rs`, concentrated in `credential-vault` (I-05),
`evidence` (I-02, I-07) and `authority-spec` (I-08). **I-03 has zero Rust references.**

The 12 planes are in `docs/02-architecture.md` §2 (lines 50–67), keyed 0–12 with a "failure
invariant" per plane.

---

## 4. Tests and gates

### 4.1 Running tests

- **Rust:** `cd rust && cargo test --workspace --all-targets`. Postgres-backed archive tests are
  `#[ignore]`d; run them with `make archive-test` after `make archive-up` (needs
  `POSTGRES_PASSWORD` and `ARCHIVE_RUNTIME_PASSWORD` exported; uses two DB roles deliberately so a
  refusing trigger is distinguishable from a missing GRANT).
- **Python:** `python3 tools/ci/run_python_checks.py {install,test,lint,format,ml_launchers}`.
- **Desktop:** `cd desktop && npm test` → `node --test test/*.test.js`.
- **TypeScript:** `cd typescript && npm test` → `vitest run`.
- **Everything:** `make verify` = `require-tools check-proto check-protocols fmt-check lint test
  build conformance docs tracker`. Makefile uses `SHELL := /bin/bash`,
  `.SHELLFLAGS := -eu -o pipefail -c`; every target is fail-closed.

Other Makefile targets: `demo`, `setup`, `sigstore-up`, `archive-up`, `archive-test`, `tracker`,
`check-proto` (buf lint + breaking-change vs main), `check-protocols` (registry.json drift),
`conformance`, `docs`, `clean`.

Counts recorded in `HANDOFF-2026-08-17.md`: 678 Rust (default), 681 with `--features tls`,
68 desktop, 44 console, 607 `warrantor_ml`. `rust/warrant/tests/` alone holds **552 `#[test]`
functions across 35 files**.

### 4.2 CI — `.github/workflows/ci.yml` (376 lines)

`on: push: branches:[main]` and `pull_request: branches:[main]`. **Every job is
`runs-on: ubuntu-latest` — there is no OS matrix anywhere.** Jobs: `dco`, `contract-plane`, `rust`,
`python` ("Python (35 projects)"), `go`, `typescript`, `conformance`, `docs`, `desktop`, `console`,
`required`.

The `rust` job, in order: install `protobuf-compiler` (needed by `warrantor-api`'s `build.rs`
tonic-build) → `cargo metadata --format-version 1 --locked` → `cargo fmt --all -- --check` →
`cargo clippy --workspace --all-targets -- -D warnings` → `cargo test --workspace --all-targets` →
`cargo build --workspace --all-targets`.

The `--locked` step has a comment explaining why it exists: PRs #11 and #47 each edited `Cargo.lock`
on different lines, git merged both textually, and main ended up resolving wasm-tools 0.132 under a
wasmtime requiring 0.134. `sbom.yml` reads that lock, so a stale lock publishes a dependency set
nobody builds.

**DCO gate:** for every non-merge commit in `BASE_SHA..HEAD_SHA`, requires a trailer matching
`^Signed-off-by: .+ <[^>]+@[^>]+>[[:space:]]*$`. Use `git commit -s`.

### 4.3 Other workflows

| File | Trigger | Purpose |
|---|---|---|
| `coverage.yml` (75 L) | **push to main only** + dispatch | `cargo-llvm-cov`; informational in Wave-1.5, ≥85% becomes hard in Wave-2 |
| `sbom.yml` (85 L) | **push to main only** + dispatch | CycloneDX per Rust crate + Python package |
| `fuzz.yml` (66 L) | nightly cron `0 4 * * *` + dispatch | `cargo-fuzz` on `rust/trust-core` |
| `provenance.yml` (52 L) | — | SLSA provenance |
| `desktop-release.yml` (242 L) | dispatch | Windows NSIS, macOS dmg x64+arm64, Linux AppImage + deb |
| `publish.yml` (271 L), `release.yml` (74 L), `release-artifacts.yml` (182 L), `aumos-security.yml` (159 L) | | |

Because coverage and SBOM run only on push-to-main, they can sit unexercised for dozens of commits —
the handoff records 56.

### 4.4 Lint configuration

- Rust: `rust-toolchain.toml` pins `channel = "stable"` + `components = ["rustfmt","clippy"]`
  (deliberately floating, so new clippy lints are discovered on our schedule). Its comment still
  says `rust-version = "1.85"` — **stale**, the manifest now says 1.94. No `clippy.toml` or
  `rustfmt.toml` exists; defaults plus `-D warnings`.
- Python: ruff per-project, identical config (see 1.2).
- TypeScript: `eslint.config.mjs` + `typescript-eslint ^8.66`.

---

## 5. Agent integrations and enforcement tiers

### 5.1 The harness registry — `rust/warrant/src/harness.rs`

`pub fn registry() -> Vec<Harness>` returns **25 harnesses**: `claude-code`, `codex`, `cursor`,
`gemini-cli`, `opencode`, `aider`, `copilot-cli`, `cline`, `continue`, `zed`, `claude-desktop`,
`goose`, `claude-agent-sdk`, `openai-agents-sdk`, `langchain`, `pydantic-ai`, `windsurf`,
`roo-code`, `amp`, `qwen-code`, `crush`, `factory-droid`, `warp`, `grok-cli`, `glm-coding`.

Each carries `Kind`, `Coverage`, `Scope` (Project|Home), `Wiring` and `Format`. The coverage
taxonomy is the honest core:

```rust
pub enum Coverage {
    McpOnly,                      // every tool is MCP; every call is mediated
    McpAndBuiltins(&'static str), // MCP mediated; the harness's own file/edit/shell tools are NOT
    ProcessOnly,                  // no MCP at all; only deadline/worktree/evidence/OS-link apply
}
```

`Coverage::escapes()` returns the named built-in tools that bypass the proxy. `aider`
(`ProcessOnly`) is **refused a config file** rather than given a decorative one. Wiring is a dry run
unless `--apply`. Public API: `find`, `server_command`, `server_entry`, `splice_json`, `splice_toml`,
`render_manual`, `by_kind`, `ENTRY_NAME = "warrantor"`.

### 5.2 MCP forwarding

`src/proxy.rs` — `enum ProxyMode`, `enum Decision` (includes `Forward`), `struct Proxy`,
`struct ToolCall`, `struct AuthorityRequest`, `fn host_of`.
`src/upstream.rs` (821 LOC) — synchronous MCP client over a child process's stdio.
`DEFAULT_TIMEOUT = 30s`, `enum LifecyclePolicy`, `struct UpstreamSpec`, `struct Upstream`,
`struct UpstreamSet`. `--upstream 'name=command args'` is repeatable; tools are published as
`<name>.<tool>`. Under enforce, a tool the warrant does not allow is **not published at all**.
An upstream publishing warrant lifecycle verbs (`grant`, `settle`, `void`, `stage`) is **refused at
attach**.
`src/mcp_endpoints.rs` — `struct ControlEndpoint`, `struct AgentEndpoint`, `fn agent_endpoint_for`.

Unknown-tool side-effect class: previously guessed as `Read` and forwarded. Now declarable via
`--upstream-class` and fail-closable via `--upstream-refuse-unclassified`; tools decided by the
fallback are **named** at end of session. The effect registry (`src/adapters/github.rs`) covers
exactly four staged effects: `github.create_pr`, `github.comment`, `github.request_review`,
`github.add_label`.

### 5.3 Operator approval routing

`src/operators.rs` — `OPERATORS_FORMAT = "warrantor.operators/1"`, `ACTOR_FORMAT =
"warrantor.actor/1"`, `APPROVALS_FORMAT = "warrantor.approvals/1"`, `MAX_NAME = 32`.
Four scopes (`read`, `stop`, `settle`, `approve`). Tokens are printed once and stored only as
SHA-256. Every settle/void/stop/approve appends to `actors/<warrant-id>.jsonl`, hash-chained
(`fn verify_chain`). **That chain is explicitly NOT inside the signed evidence envelope** — the
USAGE text says so and calls it "the weaker guarantee it is rather than dressed as a signature."
Revocation takes effect on the operator's next request (registry read per request, not at startup).

`src/review.rs` — `REVIEW_FORMAT = "warrantor.review-request/1"`, `enum Blocker`, `fn standing`,
`fn available_acts`, `should_announce`. `src/notify.rs` — webhooks with HMAC
`signature_header`, `EVENTS: [&str; 5]`, pending queue + `drain_pending`. Commands in `notify.json`
run **only** with the global `--allow-notify-command` flag.

### 5.4 Enforcement tiers actually available

Three, and only two of them are real boundaries:

1. **OS/crypto (`Enforced`)** — `expires_at` via Windows job object / Linux `setsid` +
   `PR_SET_PDEATHSIG` (`src/supervise.rs`); `delegation_depth` via Ed25519 over warrant claims.
2. **Proxy chokepoint (`Mediated`)** — `tools`, `egress_hosts`, `staged_classes`. Real against MCP
   traffic, defeated by any harness built-in or shell.
3. **Observed** — `write_paths` (contained after the fact: out-of-bounds edits are never staged by
   settle), `budget_cents_observed` (parsed from the agent's own usage reports).

**Optional composition:** `src/sandbox.rs` — `enum Confinement { Bubblewrap, Firejail }`,
`fn profile(&WarrantBounds, worktree, Confinement) -> Profile`, `enum Divergence`,
`fn bounds_to_cover`. Emits `--unshare-net` / `--net=none` when no egress is granted. This is a
*derived profile the operator runs*, not something the CLI enforces. There is no netns, seccomp,
eBPF or firewall in the `warrantor` path — `egress-filter` and `exfil-guard` (the eBPF crates) are
orphans.

---

## 6. Documents that state current state

### 6.1 `docs/W1-delivery-gaps.md` (1,035 lines) — the authoritative ledger

Structure: Tier 0 (§0.1 MCP forward — **fixed**, §0.2 harness wiring — **fixed**),
Tier 1 (§1.1 signing, §1.2 desktop bundle, §1.5 cold-start, §1.3 first run — **done**,
§1.4 refresh — **done**), Tier 2 (§2.1 approvals — **closed**, §2.1b archive — **stage 1 wired**,
§2.2 identity — **built**, §2.2b/c, §2.3 TLS — **built behind a feature**, §2.4 agent→API —
**narrowed; residue unfixable under same-UID**), Tier 3 (§3.1 bounds, §3.2 notifications —
**closed**, §3.3 multi-machine — **custody half only**, §3.4 retention — **ships**, §3.5
concurrency), Tier 4 (§4.1 guard observe-only — **partly done**, §4.1b–d, §4.2 fine-tune
**rejected by the gate**, §4.3 model-intelligence surface — **partly done**).

The closing "honest summary" verbatim on what is left:

> The **substrate is real** and the **single-machine loop is complete**. Most of what is missing is
> still what makes it a product rather than a tool: it installs but announces itself with an
> operating system warning, it cannot be reached by a second person, and it cannot say who did what.

> The recurring shape is worth naming because it has now happened three times: **a component is
> built, is correct, and is not wired to anything that would exercise it.** The ~20 substrate crates
> orphaned from the warrant, the guard benchmarked but never called during a run, and now an
> evidence archive with no client. … The next unit of work in this document that changes what a
> person can *do* is not another component — it is a caller for one that already exists.

> Every other item is closed or is a purchase: §2.1, §2.4, §3.2, §3.4 and §4.3's unguarded-run gap
> all landed on 2026-08-17, and §1.1 is a certificate.

(My section 2.5 measures that "~20 orphaned crates" figure at **71**.)

### 6.2 `HANDOFF-2026-08-17.md` (28,922 bytes)

`origin/main` at `0edd869`. All gates green including Coverage and SBOM. Self-correction worth
quoting:

> **A correction to this document's first version.** It said the session "closed every gap in
> `docs/W1-delivery-gaps.md` that engineering can close". That was wrong, and checkably so: six
> roadmap items were still open, including the one the roadmap itself called *"the one that decides
> whether this is a product"*.

What is left, per §1: "**two actions only you can take** (§1.2, §1.3) and **three engineering items
that remain genuinely open** (§1.5)". §1.2 = accept corpus terms and set a token (10 min).
§1.3 = decide about the guard-model programme. §1.5 = §3.1 bounds, §3.2's email/mobile-push
remainder (needs a decision), §2.4's residue, §1.1 signing certificate.
**"no installer has been run on macOS"** — the `identity: '-'` ad-hoc signature Apple Silicon
requires has never been observed executing; all four platforms are built by CI, exactly one is
installed.

### 6.3 `docs/final-verification-report.md` — **superseded, do not cite**

> **Superseded on 2026-08-09.** … Its 49-component and 691-test claims were not generated from
> reproducible gate artifacts. The canonical catalogue is `implementation/catalog.json`.

### 6.4 `docs/phase-a-status-2026-09-01.md` (88 lines) — newest infra state

> **Status 2026-09-01: cannot proceed as scoped. Nothing has been deployed and nothing is billing.**

Azure AI Foundry quota is real (A100_80GB 8 · H100_80GB 8 · MI300_192GB 8 · H200_141GB 8, all
zero-used) but **Qwen3Guard is absent from the Foundry catalog** — `guard` matches 0 of 212 models.
Three options: request it into the catalog, custom container on managed compute, or re-scope
Phase A around the five existing deployments (0% utilisation, 200M enqueued batch tokens unused).

### 6.5 `docs/W1-W3-findings-2026-09-01.md` (448 lines) — newest ML state

> **Every fine-tune in this programme damaged its severity field, and the damage is invisible to a
> recall-only review.** Four of four … The 4B adapters lost **56%** and **65%** of their
> `controversial` verdicts while scoring *within noise* on recall.

R1 baselines reproduce: WildGuardTest 0.8568 vs pinned 0.8554; ExpGuardTest 0.7588 vs 0.7596.
W1 adapter recall 0.7150 → 0.7818, FPR 0.0854 → 0.0550, exact two-sided *p* < 0.0001, 115
candidate-only catches vs 31 baseline-only. The section documents its own two prior wrong
conclusions rather than rewriting them.

### 6.6 Other

`CHANGELOG.md` (62,616 bytes) `## [Unreleased]` covers the August 2026 working set: HTTP settle
files evidence (`StoreApi::with_filer`), cross-process warrant locks (`src/lock.rs`, HTTP 409
`warrant_locked`), `notary.proto` → `warrantor_api::notary::v1`, default session scoping on
multi-user registries, archive fleet queries + retention (migration 0003), change cursor
(`GET /v1/warrants?changed_since=`), archive TLS via Caddy, Go metrics + Trillian pinned to
`v1.3.6`. Under "honesty repairs": README bounds prose corrected to match `bound_strengths()`
line for line.

Also: `docs/wave-{1,2,3,4}-verification-report.md`, `docs/wave-{2,3,4}-integration-guide.md`,
`docs/00-reconciliation-matrix.md`, `docs/03-portfolio-recut-v4.md`, `docs/04-sprint-runbook.md`.

---

## 7. Evidence and receipt formats

### 7.1 The WAR receipt — `rust/evidence/src/lib.rs`

```rust
pub const WAR_VERSION: &str = "war/2.0";
pub const PREDICATE_TYPE: &str = "https://warrantor.dev/ActionReceipt/v2";
```

Types: `Phase` (pre/post), `EnforcementMode`, `ConsequenceTier`, `Verdict`, `DelegationLink`,
`IntersectionProof`, `Authority`, `Binding`, `Actor`, `Decision`, `Operation`, `Outcome`,
`WarPredicate`, `SignatureEnvelope`, `WarReceipt`.

**Canonicalization:** `fn canonical_predicate(&WarPredicate) -> String` — serde_json Value,
recursively canonicalized (sorted keys), re-serialized.
**Signed bytes:** DSSE Pre-Auth Encoding, `fn dsse_pae(payload: &str) -> Vec<u8>` producing
`"DSSEv1 {len} {payload}"`.
**Hashing:** SHA-256 hex throughout (`sha2` 0.11). **Signatures:** Ed25519 (`ed25519-dalek` 3).

Verification entry points: `verify_receipt`, `verify_receipt_at`, `verify_chain`, `verify_chain_at`,
`verify_authority`, `check_mode_honesty`, `is_expired`. Errors: `"commit-gate violation (I-07)"`,
`"authority violation (I-02)"`, and the full expansion text
`"effective_capabilities {:?} != recomputed intersection {:?} (authority expansion; I-02)"`.

### 7.2 Notary receipts — `rust/notary/src/lib.rs`

`NOTARY_VERSION = "warrantor-notary/1.0"`; `ReceiptBody`, `WarReceipt`, `SignatureEnvelope`,
`receipt_digest -> [u8; 32]`, `receipt_digest_hex`, `issue_receipt`, `verify_receipt`,
`generate_keypair`. Private `mod hex` with `encode`/`decode` (each spine crate ships its own, to
avoid a shared dependency).

### 7.3 Warrant and token signing — `rust/warrant/src/lib.rs`

`WARRANT_FORMAT = "warrantor.warrant/1"`. Signature bytes are **domain-separated and
length-prefixed** — the comment explains why: without length prefixing `id="ab"`+`subject="c"` and
`id="a"`+`subject="bc"` produce identical bytes and interchangeable signatures.
`CAPABILITY_TTL_SECONDS = 60`. `CapabilityToken` has no settle scope and no field that could grant
one. `settle_authority` is deliberately not the agent's key.

### 7.4 Anchoring

Three separate mechanisms, only one reachable:

- **Local hash chain (reachable):** `rust/warrant/src/anchor.rs` —
  `ANCHOR_FORMAT = "warrantor.anchor/1"`, `enum Anchored`, `AnchorEntry`, `append`, `verify ->
  Vec<AnchorFault>`, `head`, `position_of`, and a published `ANCHOR_CAVEAT` string. CLI:
  `warrantor anchor show | verify`.
- **Rekor / Sigstore (orphaned):** `rust/trust-core/src/rekor.rs` —
  `DEFAULT_REKOR_BASE_URL = "https://rekor.sigstore.dev"`,
  `HASHED_REKORD_TYPE = "hashedrekord:v0.0.1"`, `RekorClient`, `RekorEntry`, `StdTransport`.
  Plus `trust-core::merkle` (`leaf_hash`, `node_hash`, `merkle_root`) and
  `trust-core::canonical::canonical_cbor`. Local stack in `deploy/local-sigstore` (Trillian v1.3.6).
- **RFC 3161 / epoch custody (orphaned):** `rust/time-anchoring` (B-2), 271 LOC.
- **Transparency log (orphaned):** `rust/transparency-log` (B-1), 584 LOC, Merkle inclusion +
  consistency proofs.

### 7.5 Offline verification

`warrantor verify <exported-report.json | exported-stop.json | exported-spend.json>` — dispatches on
the declared format, runs on any machine with no access to the issuing one, and (per USAGE) "says
plainly what it does not prove". `warrantor issuer add <name> <hex> --note "..."` pins keys locally;
`--issuer <name>` names the pin and every verdict reports which pin was used and when it was made.
Nothing fetches keys over a network — "a directory that hands them out is a new trust root, and this
design does not add one."

Export formats also include `warrantor.stop-record/1`, `warrantor.stop-export/1`,
`warrantor.spend-ledger/1`, `warrantor.spend-export/1`, `warrantor.guard-signal/1`,
`warrantor.guard-session/1`, `warrantor.guard-summary/1`, `warrantor.notify/1`,
`warrantor.review-request/1`.

### 7.6 Schemas and vectors

`specs/protocols/` — P1–P12, each as `.md` + `.cddl` + `.schema.json`, plus `registry.json` and
`errors.json`. P1 AAE, P2 AAR, P3 CPE, P4 AMIL, P5 SSP, P6 AATM, P7 ABS, P8 VEB, P9 AIX, P10 MADE,
P11 PRB, P12 CAP.
`specs/warrantor-v4/` — `01-war-receipt.md` + `.schema.json`, `02-notary-api.md`,
`03-enforcement-mode.md`, `04-safe-finding.md` + `.schema.json`, `05-killswitch-conformance.md`,
`06-capability-algebra.md`, `07-root-compromise.md`, `08-egress-broker.md`, …
`testvectors/` — `S3`, `T1`, `agent-manifest`, `guard`, `notary`, `protocols`.
`evidence/` — `claim-vs-mechanism.json`, `conformance.json`.
`proto/warrantor/` + `buf.yaml`; `make check-proto` runs buf lint + breaking-change vs main.

---

## 8. The ML lane

### 8.1 `python/warrantor_ml` (12,655 LOC across `src/warrantor_ml/`)

Dependency tiering is deliberate and documented: base is only `cryptography>=42`; `dev` adds pytest
and ruff; the heavy stacks are separate extras that CI never installs —
`train` (torch, transformers, datasets, peft, trl, accelerate, bitsandbytes), `hub`
(huggingface-hub), `parquet` (pyarrow), `modal` (modal). **Every test must degrade gracefully
without these installed.** `warrantor_ml` never imports `modal` — `lane_export` *renders* a Modal
entrypoint as text and the orchestrator runs it.

Console scripts (13): `warrantor-ml-evaluate`, `-benchmark-wildguard`, `-benchmark-expguard`,
`-datasets`, `-model-card`, `-fine-tune`, `-deploy`, `-build-corpus`, `-recipes`, `-lanes`,
`-export`, `-parity`, `-publish`.

Modules by size: `model_card.py` 967 · `fine_tune.py` 959 · `evaluate.py` 830 ·
`build_corpus.py` 793 · `benchmark_expguard.py` 681 · `parity.py` 640 · `lane_export.py` 626 ·
`recipes.py` 580 · `datasets.py` 567 · `benchmark_wildguard.py` 544 · `tasks/guard.py` 531 ·
`baselines.py` 505 · `deploy_model.py` 456 · `publish.py` 365 · `manifest.py` 358 ·
`tasks/bounds.py` 352 · `programme.py` 344 · `teachers.py` 330 · `lanes.py` 328 ·
`tasks/summary.py` 327 · `tasks/triage.py` 307 · `run_corpus_benchmarks.py` 250 · `metrics.py` 238 ·
`tasks/effects.py` 178 · `paired_analysis.py` 174 · `leakage.py` 168 · `stats.py` 129 ·
`_canonical.py` 77.

### 8.2 Launchers — `aumos/ml/` (no package)

`benchmark_expguard.py`, `benchmark_wildguard.py`, `build_corpus.py`, `datasets.py`,
`deploy_model.py`, `evaluate.py`, `export_lane_script.py`, `fine_tune.py`, `lanes.py`, `parity.py`,
`publish_adapter.py`, `recipes.py`, `run_corpus_benchmarks.py`, `model_card.py`, `_bootstrap.py`,
plus `kaggle/` and `modal/` subdirectories. Capped at 60 lines each by
`tools/ci/run_python_checks.py`.

### 8.3 The guard in the product — `rust/warrant/src/guard.rs` (1,843 LOC), advisory only

```rust
pub const DEFAULT_GUARD_ENDPOINT: &str = "http://127.0.0.1:11434";   // Ollama
pub const DEFAULT_GUARD_MODEL: &str =
    "hf.co/mradermacher/Qwen3Guard-Gen-4B-GGUF:Q4_K_M";
pub const MEASURED_NUM_CTX: u32 = 8192;
pub const MAX_CLASSIFIED_BYTES: usize = 4096;
pub const MAX_EXCERPT_BYTES: usize = 240;
pub const DEFAULT_MAX_CALLS: u32 = 200;
```

Types: `GuardKnobs`, `GuardProvenance`, `GuardVerdict`, `GuardOutcome`, `GuardSignal`,
`parse_guard_response`, `default_gating_categories`. The guard writes **signals**, never verdicts —
per `docs/W1-delivery-gaps.md` §4.1 it is wired in observe-only, and per the content-moderation
crate's own description, "advisory signals may deny, never allow".

`src/runs.rs` writes `runs/<warrant-id>.jsonl` at the start of every supervised session with
`guard: null` when nothing was watching — a positive record of an unwatched run, surfaced as a third
block on `/v1/summary/refusals` (`total`, `guarded`, `unguarded`, `warrants`, `unreadable_lines`).
`unguarded` is never rendered as "missed".

Artifacts on disk: `adapters/T1-A-control-2026-09-01.gguf` + its `Modelfile`, `hf/`, `eval_results/`,
`t1-staging/` (`run_record_T1-A-control-2026-09-01.json`, `corpus-expguard-weak.jsonl`).

---

## 9. Branch and worktree state

- **Branch:** `docs/content-program-p9-fold` (not `main`).
- **HEAD:** `834db38`.
- **`git status --short | wc -l` = 214** — 66 modified, 148 untracked. Git also warns
  `untracked cache is disabled on this system or location`.
- Untracked/modified concentrations: `docs/rfcs` 44 · `rust/warrant` 24 · `desktop/test` 12 ·
  `rust/archive` 10 · `go/lightwell-bridge` 6 · `typescript/mcp-gateway` 4 · `rust/warrantor-api` 4 ·
  `go/open-serve-kit` 4 · `deploy/evidence-archive` 4.
- **`docs/html` uncommitted:** ` M docs/html/warrantor-exponential-value-blueprint-2026-09-01.html`,
  `?? docs/html/master-2026-09-01-src/`,
  `?? docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html`.

**Last 15 commits:**

```
834db38 docs(blueprint): correct the NCCoE claim and the CBUAE date
a432cfd Merge branch 'docs/content-program-p9-fold' into docs/blueprint-control-catalog
1958af9 docs(blueprint): write the control catalog the document promised
f6780af chore(hf): keep the adapter chat templates and tokenizer configs in git
f0279ed docs(html): track the six strategy artifacts that were outside git
60d1c01 feat(zenodo): submit to the MuVeraAI community, and verify it exists first
c30a7d0 feat(zenodo): deposition metadata and a deposit script that will not auto-publish
716b187 Merge branch 'docs/content-program-p9-fold' into docs/incident-fold-content-program
aea4d44 chore(hf): move the published artifacts to the MuVeraAI org
20e9870 feat(hf): publish the verdicts dataset, three adapters and a static Space
a4e6687 docs(content-program): fold in the July 2026 agent-collective incident
2789c9e docs(T-12): add the bibliography, and say what it does not cover
dcd723e feat(papers): named publication set with author block, ORCID and CC BY
3c20987 fix(guard): singular verdict in the severity-policy note
43bde7a feat(guard): the Controversial policy now reports when it binds nothing
```

**24 open worktrees** (`git worktree list`) — this is a major coordination hazard:

`M:/Project AumOS - Open Secure AI Alliance/aumos` (main checkout) ·
`M:/warrantor-wt-ci` [fix/ci-coverage-sbom] · `M:/warrantor-wt-console` [feat/console-ui] ·
`M:/warrantor-wt-desktop` [feat/desktop-app] · `M:/warrantor-wt-isolation` [feat/copy-isolation] ·
`M:/warrantor-wt-ml` [feat/model-intelligence] · `M:/warrantor-wt-mlbench`
[feat/ml-vertical-benchmarks] · `M:/warrantor-wt-serve` [feat/warrantor-serve-v2] ·
`M:/warrantor-wt-stage1` [feat/wire-substrate-into-warrant] · `M:/wt-2point1`
[feat/fine-tune-sweep-close] · `M:/wt-archive` [feat/evidence-archive] · `M:/wt-archive-push`
[feat/archive-push-client] · `M:/wt-authslice` [feat/identity-actor-slice] · `M:/wt-bounds`
[feat/bounds-enforcement] · `M:/wt-depth` [feat/agent-integrations] · `M:/wt-firstrun`
[feat/console-first-run] · `M:/wt-guardwiring` [feat/guard-refusal-signals] · `M:/wt-mlexp`
[feat/ml-expguard-recipe] · `M:/wt-mlpipeline` [fix/ml-severity-masking-finding] · `M:/wt-notify`
[feat/approval-notifications] · `M:/wt-packaging` [feat/desktop-packaging] · `M:/wt-refusal-view`
[feat/refusal-quality-view] · `M:/wt-retention` [feat/retention-policy] · `M:/wt-sha2check`
[pr8-sha2].

Note `M:/warrantor-wt-stage1` is on branch `feat/wire-substrate-into-warrant` — an existing,
possibly stale attempt at exactly the orphan-wiring work section 2.5 identifies.

---

## 10. Build hazards recorded in the repository

From `HANDOFF-2026-08-17.md` §6 "Environment notes that cost real time", verbatim:

- **"Never pipe cargo through `head`."** SIGPIPE orphans rustc and corrupts `target/`. Write to a
  log and grep it after.
- **"Use `-j 2`."** clippy and the NSIS icon step both died with Windows resource-exhaustion errors
  at higher parallelism.
- **"Windows fork exhaustion corrupts the build cache."** It presents as nonsense: *"only metadata
  stub found for `rlib` dependency `std`"*, `STATUS_STACK_BUFFER_OVERRUN`, crates that cannot be
  found. **Targeted `cargo clean -p` does not clear it once it has cascaded; a full `cargo clean`
  does.** The handoff records wiping 39.7 GB / 118,269 files to re-verify a clean gate.
- **"`gh pr merge` is blocked on this repository."** Use
  `gh api --method PUT repos/MuVeraAI-Corporation/Warrantor/pulls/<N>/merge -f merge_method=squash`.
- **Merge doctrine:** "rebase, verify, merge **one at a time**. Batch-merging five green PRs broke
  `main` five ways once, because PR CI tests the branch against *old* main."

Additional hazards found in code and CI comments:

- **`Cargo.lock` drift is a real, historical failure.** The `--locked` guard in `ci.yml` exists
  because two independently-green PRs merged textually into an unbuildable lock. `sbom.yml` reads
  that lock, so drift also falsifies a published supply-chain claim.
- **Windows Rust paths are ungated.** Every CI job is `ubuntu-latest`, so every `#[cfg(windows)]`
  code path in `supervise.rs`, `kill-switch` and `lock.rs` is untested by CI. The
  `local_process_engine_actually_kills_a_real_process_ax05` timing failure lived on `main` for
  exactly this reason (resolved 2026-08-22 via the pid-keyed `critical_image_memo` in
  `rust/kill-switch/src/execution.rs`).
- **`protoc` is required** for any workspace build — `warrantor-api`'s `build.rs` runs tonic-build,
  and without it *the whole workspace* fails, not just that crate.
- **Postgres-dependent tests are `#[ignore]`d**, so `cargo test --workspace` passing says nothing
  about `rust/archive`'s database layer. `make archive-test` with two role URLs is the real gate.
- **A stale in-repo virtualenv exists at `aumos/.auditvenv/`** plus
  `python/model_sbom/.venv/` — these pollute repo-wide greps and are a known source of the
  "editable install points at another worktree" class of confusion given the 24 live worktrees.
- **`rust/reputation` is not a workspace member** — it compiles for nobody and is checked by nothing.
- **`rust-toolchain.toml`'s comment still cites `rust-version = "1.85"`** while `rust/Cargo.toml`
  says `1.94`. Cosmetic, but it is the exact class of stale declaration that caused the #11 incident.
