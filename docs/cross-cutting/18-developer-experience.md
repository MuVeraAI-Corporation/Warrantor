# 18 — Developer Experience

> A contributor should be able to clone this repo, run **one command**, and have a working dev
> environment. If they can't, we've failed. This standard closes gap-analysis-v3 gap #36.

## Why this exists

DefStack v1/v2 had inconsistent setup instructions per component. The polyglot stack pressure test
made this a **kill criterion** (#7): "Monorepo cannot be built/tested with one top-level command."
This standard defines the canonical setup, contribution workflow, debugging story, and documentation
rules — the same across all 44 components.

---

## 1. The One-Command Promise

```bash
git clone <repo> aumos
cd aumos
make setup    # detects toolchains, reports what's missing (does not fail)
make test     # tests every present language; skips missing ones
```

If `make setup` reports a missing toolchain, install it (links printed) and re-run. The Makefile
**detects and skips** missing languages rather than failing — so a contributor who only touches the
Rust core can run `make test` without installing Python or Node.

**Forbidden:** any per-component setup script that diverges from this. Component-specific
instructions belong in the RFC, not in a separate README that drifts.

---

## 2. Toolchains

| Language | Required for | Version | Install |
|---|---|---|---|
| **Rust** | trusted core (T1, R2, R3, R4, C1-1, E1, N3, R7, S6, X4) | latest stable | https://rustup.rs |
| **Python** | agents, evals, adapters (C1-2, S1, S4, S5, S7, S8, A1–A5, R3-policy, X2, X5, X6) | 3.11+ | https://python.org or `uv` |
| **TypeScript** | console, SDK, MCP (X7, X8, A8) | Node 20 LTS + TS 5.x | https://nodejs.org |
| **Go** | K8s operators, control plane (I1, N1, N4, F3, F4, C1-4) — **phase-gated** | 1.22+ | https://go.dev |
| **Terraform** | C1-3 attesta-flow | 1.7+ | https://terraform.io |
| **Buf** | proto breaking-change gate | latest | https://buf.build/docs/installation |
| **Docker** | deployable components | latest | https://docker.com |
| **Helm** | K8s deployable components | 3.x | https://helm.sh |

**`make setup`** checks each of these and prints status. It never installs anything without
confirmation (respecting the user's environment).

---

## 3. Repository Layout (recap)

See [`../README.md`](../README.md) and [`../00-reconciliation-matrix.md`](../00-reconciliation-matrix.md).
The contract plane (`specs/`, `proto/`, `testvectors/`) is the spine; per-language implementations
hang off it.

---

## 4. Makefile Targets

Standard targets every contributor uses:

| Target | What it does |
|---|---|
| `make help` | List all targets |
| `make setup` | Detect toolchains; report status |
| `make lint` | Lint every present language |
| `make test` | Test every present language |
| `make fmt` | Format every present language |
| `make conformance` | Run cross-language conformance suite |
| `make check-proto` | Buf lint + breaking-change gate |
| `make docs` | Check docs (RFC template, link integrity) |
| `make clean` | Remove build artifacts |

Per-language: `make lint-rust`, `make test-python`, etc.

---

## 5. Contribution Workflow

```
1. Fork the repo (or branch if internal)
2. git checkout -b feat/<canonical-id>-<short-description>
3. Make changes; commit with `git commit -s` (DCO sign-off — REQUIRED)
4. make lint test conformance   ← all must pass
5. Open PR; fill the PR template (which RFC, which tasks ticket, coverage delta)
6. Two reviewer approvals required:
     - 1 from the component owner (see docs/rfcs/<id>/CLAUDE.md OWNERS)
     - 1 from any other maintainer
7. CI runs: lint + test + conformance + SBOM generation + SLSA provenance
8. Squash-merge to main; release tag cut by maintainer (signed)
```

**DCO:** every commit must be signed off (`git commit -s`). This is the Developer Certificate of
Origin — it asserts you have the right to contribute the code. Enforced by a CI bot.

**CLA:** required for corporate contributors only (automated via CLA bot). Individual contributors:
DCO only.

**Commit message format:** `feat(<scope>): <subject>` / `fix(<scope>): <subject>` /
`docs(<scope>): <subject>` / `refactor`, `test`, `chore`, `ci`, `build`. Scope = canonical ID
(e.g. `feat(T1): add Ed25519 signing`).

---

## 6. RFC and Tasks Workflow

Every component has:
- `docs/rfcs/<id>-<name>.md` — the 10-section RFC (the spec)
- `docs/rfcs/<id>-<name>/CLAUDE.md` — build instructions for coding agents
- `docs/rfcs/<id>-<name>/AGENTS.md` — agent anti-patterns
- `docs/rfcs/<id>-<name>/PROMPT.md` — master prompt to paste into an agent
- `docs/rfcs/<id>-<name>/tasks/01-setup.md` … `08-release.md` — 8 sequenced tickets

A typical component takes one coding-agent session (~8 focused hours) to build, working the tickets
in order.

---

## 7. Debugging

| Symptom | First check |
|---|---|
| `make test` fails on one language | Is the toolchain installed? `make setup` will say |
| Proto changes don't propagate | Did you run `buf generate`? Is `buf breaking` failing? |
| Conformance fails | Did you update `testvectors/`? See RFC T-CORE-1 |
| Component can't find a dependency | Are mocks in place? Wave-1 components use mock I1 (AgentVault) |
| eBPF fails to load (R2/R7/S6) | Are you on Linux 5.13+? See component RFC |
| CI green locally, red in CI | Reproduce with `act` (GitHub Actions locally) |

**Logging convention:** every component emits OpenTelemetry traces with standardized attribute names
(see cross-cutting standard 01-observability). Trace IDs propagate across components so a single
agent action can be traced end-to-end.

---

## 8. Documentation Standards

- **RFCs:** the 10-section template (see `tools/ci/check-docs.sh`).
- **ADRs:** `docs/decisions/NN-<kebab-title>.md`, using the ADR template (cross-cutting standard 03).
- **README:** every component crate/package has a README with: what it does, install, quickstart,
  links to its RFC.
- **CHANGELOG:** `CHANGELOG.md` per component, Keep a Changelog format.
- **Spelling/grammar:** CI runs a prose linter on all `.md` files.

---

## 9. The 5-Minute Quickstart

A new contributor's first task should be runnable in 5 minutes:

```bash
git clone <repo> aumos && cd aumos
make setup
# (install any reported missing toolchain)
make test          # green
make conformance   # green
cd rust/trust-core # pick a component
cargo test         # green — you're ready to contribute
```

If this takes longer than 5 minutes on a fresh machine, that's a bug against this standard.

---

## 10. The Go Activation Gate

Go is **phase-gated**. A component may be written in Go only when **at least 3** of these are true
(per the polyglot stack pressure test §7):

1. A production Kubernetes operator is required.
2. At least three independent reconciliation loops must run continuously.
3. SPIRE registration or trust-domain federation needs programmatic lifecycle management.
4. Policy and revocation state must converge across multiple clusters/sites.
5. Control plane needs independent horizontal scaling from the Rust enforcement plane.
6. Two people can own Go services through incidents, upgrades, security reviews.
7. Profiling shows keeping these workflows in Rust harms delivery/operations.

**Currently Go-justified (Wave 2+):** I1 agent-identity, N1 open-serve-kit, N4 tenant-guard,
F4 fleet-marshal, C1-4 tee-serve. All others must default to Rust/Python/TypeScript.

---

## Review Cadence

- This standard is reviewed **monthly** during Wave-1.
- A contributor friction report is filed by DevRel after every onboarding session.
