# AumOS — Open Defense Stack for AI (Unified)

> One trusted semantic core. Four carefully bounded ecosystems. Complexity activated only when earned.
> AumOS should look polyglot from the outside and remain semantically singular on the inside.

AumOS is the **unified implementation** of the Open Secure AI Alliance (OSAF / OSAA) defense stack. It
reconciles **four source portfolios** that previously lived as separate strategy documents in this
project folder:

| Source portfolio | Originating documents |
|------------------|-----------------------|
| **DefStack (36-component, 8-phase)** | `DefStack_Implementation_Plan.pdf`, `OSAF_War_Mode_Strategy*.pdf`, `*-compliance-frameworks.md`, `*-security-disclosure-policy.md`, `*-open-source-governance.md`, `*-disaster-recovery.md`, `gap-analysis-v3.md` |
| **AumSecure Open Agent Defense Stack (20-comp + 12 protocols)** | `aumsecure_open_secure_ai_alliance_war_mode_strategy.html`, `aumsecure_open_secure_ai_alliance_oss_authority_v2.html` |
| **AumSecure Authority V3 (6 canonical repos)** | `aumsecure_open_secure_ai_alliance_authority_pressure_test_v3.html` |
| **PROJECT SENTINEL (10 frameworks)** | `sentinel-blueprint.html` |
| **Polyglot stack red-team decision** | `aumsecure_rust_go_python_typescript_stack_pressure_test.html` |

The four portfolios describe the **same mission** (build the open authority/evidence/enforcement layer
that AI agents cannot bypass) at four different granularities. AumOS merges them into **one canonical
catalog of ~38 components** with no duplicate effort. See
[`docs/00-reconciliation-matrix.md`](docs/00-reconciliation-matrix.md) for the full provenance map.

---

## Mission

> Build the open authority and evidence layer for autonomous systems — the specifications, reference
> enforcement, and conformance tests that make agent actions verifiable across models, harnesses,
> tools, and infrastructure.

We are not building "another AI-security dashboard." We are building the **security substrate that
agents cannot bypass**: open foundations, external enforcement, verifiable authority, reproducible
evidence, ecosystem-scale remediation.

---

## Architecture in one picture (contract-hub monorepo)

```
                        ┌────────────────────────────────────────┐
                        │  specs/  proto/  testvectors/  policies/│   ← normative, language-neutral
                        │       (Buf breaking-change gate)       │
                        └───────────────────┬────────────────────┘
                                            │ generate / consume
        ┌───────────────┬───────────────────┼───────────────────┬────────────────┐
        ▼               ▼                   ▼                   ▼                ▼
   ┌─────────┐    ┌──────────┐       ┌────────────┐      ┌────────────┐    ┌──────────┐
   │  rust/  │    │ python/  │       │typescript/ │      │    go/     │    │ deploy/  │
   │ trusted │    │ agents,  │       │ console,   │      │ K8s ops,   │    │ Docker,  │
   │   core  │    │  evals,  │       │ MCP, SDK,  │      │ reconcilia-│    │ Helm,    │
   │ (sign / │    │ adapters │       │  IDE tool  │      │  tion only │    │ k8s,     │
   │ verify /│    │          │       │            │      │ (gated)    │    │ systemd  │
   │ enforce)│    │          │       │            │      │            │    │ air-gap  │
   └─────────┘    └──────────┘       └────────────┘      └────────────┘    └──────────┘
```

- **Rust** owns the trusted core: authority validation, evidence canonicalization/signing,
  attestation verification, revocation enforcement, capability mediation, local daemon.
  *No security invariant may have two authoritative implementations.*
- **Python** owns everything outside the trust boundary: agents, adapters, evals, attack generation,
  research, notebooks.
- **TypeScript** owns developer surfaces: console, MCP middleware, SDK ergonomics, IDE tooling,
  evidence viewer.
- **Go** is **phase-gated** — only for Kubernetes operators, reconciliation controllers, policy
  distribution, fleet state, SPIRE registration, revocation fan-out. The Go activation gate (see
  `docs/cross-cutting/18-developer-experience.md`) must clear before Go services ship.

---

## Repository layout

```
aumos/
├── docs/                       # Vision, architecture, RFCs, cross-cutting standards
│   ├── 00-reconciliation-matrix.md
│   ├── 01-vision-and-portfolio.md
│   ├── 02-architecture.md
│   ├── cross-cutting/          # 19 numbered cross-cutting standards (13–19 + more)
│   ├── rfcs/                   # RFCs + agent handoff files per canonical component
│   ├── decisions/              # ADRs (architecture decision records)
│   └── source-matrix/          # read-only pointers to original 20 source docs
├── specs/                      # Normative language-neutral specs (AAE/AAR/CPE/ABS/...)
├── proto/                      # Canonical protobuf + JSON-Schema contracts (Buf-managed)
├── testvectors/                # Golden cross-language behavior vectors
├── rust/                       # Trusted-core workspace
├── python/                     # Agents, evals, adapters, SDK
├── typescript/                 # Console, SDK, MCP middleware
├── go/                         # Phase-gated: CLI, K8s operators, control plane
├── policies/                   # Rego + Cedar + OpenShell profiles
├── deploy/                     # Dockerfile, Helm, K8s, systemd, air-gap bundles
├── tools/                      # CI, fuzz harnesses, conformance runner
├── Makefile                    # One-command dev/test/release
├── buf.yaml                    # Breaking-change gate for proto
└── .gitignore
```

---

## Quick start

```bash
# Prereqs: make, git, and the toolchains for the languages you'll touch
make help            # list all targets
make conformance     # run the cross-language conformance suite
make lint            # lint every language that's present
make test            # test every language that's present
make docs            # render/check docs
```

AumOS is designed to build/test with **one top-level command** regardless of how many languages are
present. Missing toolchains are detected and skipped, not failed.

---

## Roadmap (waves)

| Wave | Theme | Components |
|------|-------|-----------|
| **0** | Docs + scaffolding | Reconciliation matrix, vision, architecture, 38 RFCs, agent handoff, language scaffolding |
| **1** | Foundations + Containment (90-day sprint) | `NVTrustBridge, CudaGram, ModelNotary (trust-core), DefStack CLI, EvalGuard, KillSwitchKit, SentinelTrace, CredentialVault` |
| **2** | Keystone + foundations | `AgentVault` (Go activated), `SafeTensors++`, `ModelSBOM`, `trust-core` spec |
| **3** | Supply chain + eval | `ProvenaChain, DataProvenanceKit, TamperScan, TrainGuard, SafeEval, Adversaria` |
| **4** | Inference | `OpenServeKit, BridgeRT, InferenceProxy, TenantGuard` |
| **5** | Confidential + federated | `AttestaFlow, TeeServe, FedCore, DPCrate, EdgeSentinel, FleetMarshal` |
| **6** | Cross-cutting aggregation | `NOOA-Ext, OpenHarnessSpec, BiasSentinel, ComplyGate, ExfilGuard, CryptoAuditAI, RetroSpecKit, METRBridge` |
| **7** | Console + commercial | TypeScript console, MCP middleware, sovereign/enterprise packaging |

See [`docs/00-reconciliation-matrix.md`](docs/00-reconciliation-matrix.md) for the canonical mapping
and [`docs/01-vision-and-portfolio.md`](docs/01-vision-and-portfolio.md) for the full roadmap with
milestones, success metrics, and the 3-war-horizon framing.

---

## Governance & standards

- **BDFL → Steering Committee → Foundation** phased governance (see
  `docs/cross-cutting/15-open-source-governance.md`).
- **Licensing:** Apache-2.0 for core libraries/CLI/specs; BSL 1.1 (4-year change date) for enterprise
  features; CC-BY-4.0 for specs/governance docs; CDLA-Permissive-2.0 / CC-BY-4.0 for datasets.
- **DCO required** for all contributions (`git commit -s`); CLA bot for corporate contributors.
- **19 cross-cutting standards** apply to every component (OTel mandatory, CycloneDX SBOMs in CI,
  gRPC+protobuf internal / REST+JSON external / CloudEvents+Kafka async, STRIDE threat models for
  pillars 1/4/7, SLSA Level 3+ target, ≥85% test coverage gate).

---

## Status

**Phase 0 (docs + scaffolding) in progress.** No Wave-1 component has shipped v1.0 yet. See
[`docs/decisions/`](docs/decisions/) for ADRs and the active todo list for current progress.
