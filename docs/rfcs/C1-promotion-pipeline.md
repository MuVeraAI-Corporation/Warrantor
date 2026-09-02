# C1 — `promotion-pipeline` RFC

> The continuous promotion pipeline (build-catalogue **C-1**, Domain C, Wave 1, loop L1): corpus build →
> train → publish → parity gate → promotion decision → deploy, unified into one governed assembly line
> where every stage emits a receipt and a promotion that lacks its parity-gate receipt is *unregisterable*
> — machine-enforced, not policy-enforced.

| Field | Value |
|---|---|
| **Canonical ID** | C1 (catalogue C-1) |
| **Name** | promotion-pipeline |
| **Wave** | 1 (model intelligence) |
| **Languages** | Rust |
| **Catalogue item** | C-1 |
| **Dependencies** | none (the `ml/` pipeline and `deploy_model.py` do the work and consult this record) |

## Background

The flywheel today is "a person with a terminal": promotion is a human-run ceremony, and the parity gate —
the thing that makes a promotion mean something — is run by hand. C-1 mechanizes the assembly line and,
more importantly, makes the ML programme itself governed: the platform trains its own models with the same
receipt discipline it forces on its users' agents (SG1: the platform's models govern themselves). The
catalogue's gate is explicit — *"an adapter attempting registration without a parity-gate receipt is
refused by `deploy_model.py`"* — so the enforcement must be structural, not a policy someone can skip.

## Goals and Non-Goals

**Goals:**
- Model a [`PipelineRun`](rust/promotion-pipeline/src/lib.rs) as an ordered set of [`StageReceipt`](rust/promotion-pipeline/src/lib.rs)s, one per [`Stage`](rust/promotion-pipeline/src/lib.rs), each with a content digest.
- Record the parity gate's [`GateVerdict`](rust/promotion-pipeline/src/lib.rs) on its receipt.
- [`deploy_model`](rust/promotion-pipeline/src/lib.rs) returns a [`DeployReceipt`](rust/promotion-pipeline/src/lib.rs) only when the run carries a ParityGate receipt whose
  verdict is `Promote`; otherwise refuse with [`DeployError::MissingGateReceipt`](rust/promotion-pipeline/src/lib.rs) or [`DeployError::GateRefused`](rust/promotion-pipeline/src/lib.rs) — the
  machine-enforced registration gate.
- Bind the deploy receipt to the gate receipt's digest, so a deployment is traceable to the exact gate run
  that authorized it.

**Non-Goals:**
- Training, evaluating, or deploying — this is the governed record and the registration gate.
- Computing the parity verdict — the gate supplies it.

## Detailed Design

`record(stage, output_digest, at_ms)` appends a non-gate receipt; `record_gate(verdict, output_digest,
at_ms)` appends the ParityGate receipt carrying the verdict. Each receipt's digest is `sha256:` over the
canonical JSON of `(stage, run_id, output_digest, at_ms, verdict)`, so the gate verdict is folded into the
receipt's identity — a Promote and a Refuse gate on the same artifact produce different digests.

`deploy_model` looks up the gate receipt (`gate_receipt()`); absent → `MissingGateReceipt`; present but not
`Promote` → `GateRefused`. On success it resolves the artifact digest from the Publish stage (falling back
to the gate's own output if no Publish stage was recorded) and emits a `DeployReceipt` whose digest covers
`(run_id, gate_digest, artifact_digest)`. Because the only path to a deploy receipt runs through the gate
check, an ungated promotion cannot be registered — the property is enforced by the function's structure,
not by a convention.

## Threat Boundary

The adversary is a skipped gate: a promotion that reaches production without passing parity, which would
make the gate's whole purpose (the honest promotion rate the scoreboard tracks) meaningless. Making
`deploy_model` refuse without a Promote gate receipt turns that from a process violation into an
impossibility at the API boundary. The crate trusts the supplied verdict (the gate computes it; a
compromised gate that lies about the verdict is outside this boundary — the same trust the parity gate
already holds) and the supplied `at_ms`. It does not itself run training or touch the registry; it is the
record the registry consults.

## API

Library: `warrantor_promotion_pipeline::{Stage, GateVerdict, StageReceipt, PipelineRun, DeployReceipt,
DeployError, deploy_model}`. `PipelineRun::{new, run_id, receipts, record, record_gate, gate_receipt}`.

## Testing

12 unit tests: a Promote gate allows deploy and the deploy binds to the gate digest; a Refuse gate blocks
deploy; a missing gate receipt blocks deploy; every stage emits a receipt with a digest; the gate receipt
carries its verdict; stage and deploy digests are deterministic; the gate verdict changes the receipt
digest; deploy falls back to the gate digest when no Publish stage exists; receipts are ordered by
recording; the run id is recorded on each receipt.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §6 Domain C, C-1; §17.2 flywheel chain (C-2 → C-1 → C-3 → C-7).
- Intake: `rust/training-extractor` (C-2) feeds the corpus; C-3 supplies per-plane corpora.
- Gate: the parity gate (the promotion-rate scoreboard metric); C-7 guard-to-enforcement graduation.
- Governed self-deployment: SG1 (the platform's models govern themselves); `rust/responsible-ai`.
