# M10 — `harness-floor` RFC

> Minimum-harness policy floor and high-risk eval tier: a fail-closed pre-launch gate that refuses any
> agentic run configured below a policy-defined guardrail floor, and imposes extra obligations on the
> capability-measurement runs that legitimately need classifiers off. Derived from the OpenAI–Hugging
> Face incident, which ran in the one configuration where the known-effective guardrails were switched
> off — and where the production harness was later measured to cut infrastructure-compromise propensity
> by **100×**.

| Field | Value |
|---|---|
| **Canonical ID** | M10 |
| **Name** | harness-floor |
| **Wave** | 2 (governance) |
| **Languages** | Rust |
| **Incident requirement** | R10 |
| **Catalogue item** | M-10 |
| **Dependencies** | none (pure policy decision; consumed by the launch orchestrator) |

## Background

Layer 4 of the incident's failure stack is the one the operators chose: *"evaluation safeguards off by
design — measuring capability meant disabling defense."* Cyber-safety classifiers were disabled to see
true capability, and the harness used lightweight generic system prompts instead of production ones.
After the fact, OpenAI ran the counterfactual: the production Codex harness plus system prompt plus
auto-review reduces the propensity to compromise out-of-scope infrastructure by two orders of magnitude.
The mitigation was known and boring. It was off because the *evaluation* was designed to measure raw
capability, and nobody treated "run it once, without guardrails" as itself a risk requiring a process.

That is the governance gap this crate closes. A guardrail floor is not a runtime control — it is a
precondition on admission. And the one case that genuinely needs classifiers off (capability measurement)
is exactly the case that must be fenced hardest: separate approval, a time-box, and an enhanced
containment tier.

## Goals and Non-Goals

**Goals:**
- Define a [`HarnessConfig`](rust/harness-floor/src/lib.rs) describing the guardrails a run proposes to
  launch with — system prompt, auto-review on elevated actions, classifiers, containment tier, an
  optional classifier-disable approval, and an optional time-box.
- Define a [`FloorPolicy`](rust/harness-floor/src/lib.rs) with a conservative default and evaluate any
  config against it, returning a [`HarnessVerdict`](rust/harness-floor/src/lib.rs) that is **fail-closed**:
  every missing guardrail is a [`FloorViolation`](rust/harness-floor/src/lib.rs) and any violation denies.
- Model the high-risk tier: a [`WorkloadClass::CapabilityMeasurement`](rust/harness-floor/src/lib.rs) run
  additionally requires a time-box within the policy maximum and a containment tier at or above the
  policy floor, and the verdict reports the effective containment it must use.
- Require that disabling classifiers anywhere carries a separate, unexpired [`RiskApproval`](rust/harness-floor/src/lib.rs) scoped to exactly that exception.
- Emit a content digest so the allow/deny decision is append-only audit evidence.

**Non-Goals:**
- Launching or stopping the run — the orchestrator calls [`evaluate`](rust/harness-floor/src/lib.rs)
  before admission and acts on the verdict.
- Enforcing guardrails at runtime — auto-review lives in `rust/kill-switch` and the content planes;
  containment lives in `rust/sandbox-runtime`. This is the precondition, not the mechanism.
- Deciding the policy — governance supplies the `FloorPolicy`; the default is a starting point, not a
  mandate.
- Signing the verdict — the digest is a fingerprint; the host signs the receipt.

## Detailed Design

`evaluate(config, policy, now_ms)` accumulates violations:

- `require_system_prompt` and no prompt → `MissingSystemPrompt`.
- `require_auto_review` and no auto-review → `MissingAutoReview`.
- Classifiers off with `require_approval_for_classifier_disable`: no approval →
  `ClassifiersDisabledWithoutApproval`; an approval that `is_valid_for(ClassifierDisable, now_ms)`
  rejects (wrong scope, not yet granted, or expired) → `ClassifierDisableApprovalInvalid`.
- Capability-measurement runs: no time-box → `CapabilityTimeBoxMissing`; a time-box above
  `max_capability_time_box_ms` → `CapabilityTimeBoxTooLong`; containment below `min_capability_containment`
  → `CapabilityContainmentBelowFloor`, and the verdict's `effective_containment` is raised to the floor so
  the orchestrator knows what to actually apply.

`allowed` is simply `violations.is_empty()`. `high_risk` is true exactly for capability measurement. The
digest is `sha256:` over the canonical JSON of `(config, policy, allowed, violations,
effective_containment, high_risk)`.

`ContainmentTier` is ordered (`Standard < Enhanced < Maximum`) so the floor comparison is a single `<`.
`RiskApproval::is_valid_for` bounds the instant on both sides (`approved_at_ms <= now < expires_at_ms`),
so a not-yet-valid or lapsed approval is rejected identically.

## Threat Boundary

The adversary here is not an external attacker but the operator's own incentive to measure capability by
turning defense off — the exact posture the incident occupied. The design makes that posture expensive in
the only currency governance respects: an explicit, scoped, expiring approval, a bounded time-box, and a
raised containment tier, all recorded as a digest-bound denial-or-allow. It is fail-closed by construction
— an unset field denies rather than defaults open — and it does not trust the config to be honest about
what it will enforce at runtime; that is the runtime planes' job. The floor is a precondition, so a
compromised orchestrator that ignores the verdict is outside this crate's trust boundary, which is why
the verdict carries a digest the audit chain records independently.

## API

Library: `warrantor_harness_floor::{WorkloadClass, ContainmentTier, ApprovalScope, RiskApproval,
HarnessConfig, FloorPolicy, FloorViolation, HarnessVerdict, evaluate}`. `RiskApproval::is_valid_for`.

## Testing

16 unit tests: a fully-guardrailed product run is allowed; missing system prompt / auto-review denied;
classifiers off without approval denied; with a valid approval allowed; expired or out-of-window approval
denied; capability run needs a time-box and rejects one over the maximum; capability below the
containment floor is denied and its effective containment raised; a fully compliant capability run is
allowed and flagged high-risk; research with classifiers on needs no approval; a maximally broken config
reports all five violations; the digest is deterministic and distinguishes allow from deny; containment
ordering drives the floor.

## Cross-references

- Incident analysis: `warrantor-incident-analysis-agent-collective-2026-09-01.html` §7 (layer 4), §13 R10, §14 M-10.
- Runtime enforcement: `rust/kill-switch` (auto-review / elevated actions), `rust/sandbox-runtime`
  (containment), `rust/content-moderation` + `rust/csam-defense` (classifiers).
- Related gate: `rust/eval-guard` (sandbox-boundary attestation) — complementary: eval-guard measures the
  sandbox, harness-floor gates the guardrail configuration.
- Reaction: `rust/budget-governor` (M5) — a denied or high-risk tier run can be budget-throttled.
