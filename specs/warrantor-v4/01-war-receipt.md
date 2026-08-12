# WAR — Warrantor Action Receipt, v2.0

> The single evidence object. A WAR carries the **pre-action authorization proof** and the
> **post-action outcome** in one signed envelope, bound to the delegation chain that authorized it
> and to the artifacts that served it. It supersedes P2-AAR v1.0.
>
> **Status:** FROZEN CANDIDATE — Blueprint v4, Sprint Days 1–14. Breaking changes after freeze
> require a new protocol version per `specs/protocols/README.md`.

| Field | Value |
|---|---|
| **Protocol ID** | P2 |
| **Version** | 2.0 (supersedes 1.0) |
| **Name** | `war` (Warrantor Action Receipt) |
| **Serialization** | JSON, JCS-canonical ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)) |
| **Envelope** | DSSE, wrapping an in-toto Statement |
| **Transparency** | Sigstore Rekor v2, tiered anchoring (§7) |
| **Schema** | `01-war-receipt.schema.json` |
| **Enforces** | I-01, I-02, I-05, I-06, I-07, I-09 |

Key words **MUST**, **MUST NOT**, **SHOULD**, **MAY** are to be interpreted per RFC 2119.

---

## 1. What changed from v1.0, and why

v1.0 signed canonical CBOR over a flat payload. v2.0 makes five normative changes, each traceable
to a finding in the Research Dossier:

| # | Change | Rationale |
|---|---|---|
| 1 | **DSSE + in-toto Statement, JCS-canonical JSON** replaces bare canonical-CBOR signing | Reuses exactly what OpenSSF Model Signing, Sigstore, and SLSA already use. Auditors and verification tooling in the alliance stack already trust this envelope; a bespoke encoding would have forfeited that for no gain. |
| 2 | **`authority.intersection_proof`** becomes a mandatory field | v1.0 carried `authority_digest` only — a pointer, not a proof. Invariant I-02 (no authority expansion) was therefore unfalsifiable from the receipt alone. |
| 3 | **`artifacts.runtime_aibom`** binds the model digest that *actually served* the action | AIBOMs everywhere are build-time and static. Nobody binds them to the runtime-attested weight digest. This closes the supply-chain-to-runtime gap. |
| 4 | **`platform_verdict`** (optional) carries the six-term composite attestation verdict | Lets a receipt state, verifiably, that the sealed recorder agrees with the logbook — or that it does not. |
| 5 | **`enforcement_mode`** becomes mandatory | A receipt MUST declare what it is entitled to claim. Without it, an advisory deployment's receipt is indistinguishable from a mediated one, and the non-bypassability claim becomes unfalsifiable marketing. |

---

## 2. Structure

A WAR is a DSSE envelope whose payload is an in-toto Statement:

```
DSSE envelope
├── payloadType: "application/vnd.in-toto+json"
├── payload:     base64( JCS-canonical in-toto Statement )
└── signatures[]: { keyid, sig }

in-toto Statement
├── _type:         "https://in-toto.io/Statement/v1"
├── subject[]:     ResourceDescriptor[]   ← the artifacts this action touched
├── predicateType: "https://warrantor.dev/ActionReceipt/v2"
└── predicate:     WAR predicate (§3)
```

Using in-toto's `subject` for artifacts is deliberate: any existing in-toto verifier can already
answer "was this artifact involved in this action" without understanding Warrantor at all.

---

## 3. The WAR predicate

### 3.1 `binding` — what this receipt is about (MANDATORY)

| Field | Type | Notes |
|---|---|---|
| `receipt_id` | string (UUIDv7) | Time-ordered; unique per action attempt |
| `phase` | enum | `pre_commit` \| `post_commit` \| `atomic` — see §5 |
| `parent_receipt` | string \| null | Receipt of the delegating action, forming the causal chain |
| `nonce` | string (base64, ≥128 bit) | Replay resistance (I-10) |
| `issued_at` / `expires_at` | RFC 3339 UTC | Expired receipts are rejected without further checks |
| `enforcement_mode` | enum | `mediated` \| `advisory` — see §6. **MUST** be present |

### 3.2 `actor` — who acted (MANDATORY, enforces I-01)

| Field | Type | Notes |
|---|---|---|
| `principal` | string | The accountable human or governed autonomous principal (Plane 1) |
| `workload_id` | string (SPIFFE ID) | The SVID under which the action ran. **MUST** be live and unrevoked at issuance |
| `svid_digest` | string (`sha256:…`) | Digest of the presented SVID, so the receipt is verifiable after rotation |

### 3.3 `authority` — under what warrant (MANDATORY, enforces I-02)

This is the field v1.0 lacked, and it is the reason the receipt is evidence rather than a log line.

| Field | Type | Notes |
|---|---|---|
| `chain[]` | DelegationLink[] | Ordered, root-first. Each link: `{issuer, subject, capabilities[], not_before, not_after, token_digest, token_format}` |
| `token_format` | enum | `id_jag` \| `oauth_rfc8693` \| `aae` — Warrantor **verifies** these formats, it does not define new ones |
| `effective_capabilities[]` | string[] | The computed **intersection** across all links |
| `intersection_proof` | object | `{algorithm, links_digest, result_digest}` — recomputable by any verifier from `chain[]` |
| `budget` | object \| null | Remaining autonomy budget at issuance (P7/ABS) |

**Normative rule (I-02).** A verifier **MUST** independently recompute the intersection from
`chain[]` and **MUST** reject the receipt if the recomputed set differs from
`effective_capabilities`, or if `effective_capabilities` contains any capability absent from **any**
link. Authority is the intersection, never the union. A chain of length *n* whose links disagree
yields the narrowest set, not the widest.

**Known limit.** Intersection is sound only while the identity root is honest. Root compromise is
an explicit failure mode (§9), not an assumption.

### 3.4 `decision` — what the policy said (MANDATORY)

| Field | Type | Notes |
|---|---|---|
| `verdict` | enum | `allow` \| `deny` |
| `engine` | string | e.g. `cedar@4`, `opa@1` — Warrantor **embeds**, does not replace |
| `policy_digest` | string | Content digest of the exact policy evaluated |
| `inputs_digest` | string | Digest of the canonicalized decision inputs |
| `evaluated_at` | RFC 3339 | **MUST** be at commit time, not session start (I-04) |
| `advisory_signals[]` | object[] | Guardrail/classifier outputs (NeMo, Shieldstral, garak). **Advisory only** — they inform, they never decide |

`deny` receipts are first-class and **MUST** be emitted and retained. A substrate that only records
its permissions has no deny-path audit trail.

**Normative — the advisory asymmetry.** An advisory signal **MAY** cause a `deny`. An advisory
signal **MUST NEVER** cause or contribute to an `allow`.

Probabilistic guards — content classifiers, guardrail models, anomaly scores — may add caution but
must never grant authority. The asymmetry is deliberate: a false positive costs a blocked action,
while a false negative that *granted* authority would place a statistical model inside the trust
boundary, which is precisely the architecture the 2026 incidents discredited. Where an advisory
signal is decisive, the receipt **MUST** record which signal, its source, its score, and the model
digest that produced it, so the denial is reviewable and the classifier is accountable.

### 3.5 `operation` — what was attempted (MANDATORY)

`{ class, target, method, parameters_digest, reversible (bool), consequence_tier }`

`consequence_tier` (`routine` \| `elevated` \| `critical`) selects the anchoring policy in §7 and
determines whether non-delegable human approval is required (I-08).

### 3.6 `artifacts` — what served the action (MANDATORY)

| Field | Notes |
|---|---|
| `model` | `{digest, format, oms_signature_ref}` — the weights that served this action |
| `runtime_aibom` | `{bom_ref, bom_digest, bound_at}` — CycloneDX ML-BOM bound to the **runtime** digest above |
| `skills[]` | `{digest, skill_card_ref, signature_ref}` — signed skills, per the SKILL.md / OMS pipeline |
| `tools[]` | `{identifier, canonical_resource_id, digest}` |

**Normative rule (I-06).** Every artifact **MUST** be identified by content digest. A name, URI, tag,
or version string alone **MUST NOT** be accepted as artifact identity.

**Normative rule (canonical resources).** `canonical_resource_id` **MUST** be the
provider-resolved identifier, never a caller-supplied string. This closes the confused-deputy class.

### 3.7 `platform_verdict` — the sealed recorder (OPTIONAL, high-assurance tier)

```
{ authorization: "Authorised" | "Unauthorised" | "Indeterminate",
  platform:      "Attested"   | "Contested"    | "Expired",
  ar4si_tier:    "None" | "Affirming" | "Warning" | "Contraindicated",
  evidence_ref, verifier, appraised_at }
```

**`(Authorised, Contested)` is a first-class alarm state**: the logbook reads clean while the sealed
recorder disagrees — the signature of a swapped model artifact. A verifier **MUST** surface this
combination distinctly and **MUST NOT** treat it as a pass.

Absent `platform_verdict`, a receipt makes **no** hardware claim. Verifiers **MUST NOT** infer one.

### 3.8 `outcome` — what happened (MANDATORY in `post_commit` and `atomic`)

`{ status, outcome_digest, effects[], error, rollback_pointer }`

`outcome_digest` establishes **provenance of this output**. It does **not** establish
re-derivability — see §8.

---

## 4. Signing

- Signature covers the DSSE PAE encoding of the JCS-canonical payload.
- Default algorithm `ed25519`; production deployments **SHOULD** use KMS/HSM-backed keys.
- **Crypto-agility is mandatory.** Every receipt carries `alg` explicitly. Implementations **MUST NOT**
  hardcode a digest or signature algorithm, and **MUST** support running two algorithms
  concurrently during migration. This is a direct response to demonstrated AI-assisted cryptanalysis:
  an evidence chain pinned to one primitive is one break from worthless.
- Only the Rust trusted core signs. No other language re-implements sign or verify.

---

## 5. Phases and the commit gate (I-07)

```
   authorize ──▶ [pre_commit WAR signed + DURABLE] ──▶ EFFECT ──▶ [post_commit WAR]
                              │
                    if this fails, the effect
                    MUST NOT become visible
```

- `pre_commit` **MUST** be signed and durable **before** the effect is visible.
- `atomic` MAY be used only where `reversible = true` **and** `consequence_tier = routine`.
- **Durable** means committed to local append-only storage with an fsync barrier. It does **not**
  require the transparency-log round-trip (§7).

Implementations **MUST NOT** treat "receipt emitted" as satisfying I-07. Emission is not durability.

---

## 6. Enforcement mode (the honesty field)

| Mode | Meaning | Entitled to claim |
|---|---|---|
| `mediated` | The decision sits **in** the enforcement path — kernel (seccomp/Landlock/BPF-LSM via OpenShell) or a mandatory gateway. Bypassing Warrantor means bypassing execution itself. | Non-bypassability |
| `advisory` | The host calls Warrantor and **may ignore** the verdict. | Evidence and attribution only |

A verifier **MUST** reject any non-bypassability claim asserted by a receipt whose
`enforcement_mode` is `advisory`. Conformance reports **MUST** state the mode of every run.

This field exists because an advisory core is exactly as bypassable as OPA. Rather than assert a
guarantee the topology may not support, the receipt records which guarantee it actually earned.

---

## 7. Tiered transparency anchoring

Inline signing, batched anchoring. Evidence-before-commit is preserved without putting a network
round-trip on every action.

| Stage | Timing | Requirement |
|---|---|---|
| **Sign** | Inline, before effect | **MUST** — sub-millisecond, local |
| **Durable** | Inline, before effect | **MUST** — append-only + fsync |
| **Anchor** | Asynchronous, batched | **SHOULD** — Merkle root to Rekor v2; inclusion proof backfilled into `anchor` |

Anchoring policy by consequence tier:

| Tier | Policy |
|---|---|
| `routine` | Batched. Anchor interval **SHOULD NOT** exceed 60 s. |
| `elevated` | Batched, interval **SHOULD NOT** exceed 5 s. |
| `critical` | Inline anchoring **MAY** be required by policy; if the log is unreachable the action **MUST** fail closed. |

**Availability rule.** Transparency-log unavailability **MUST NOT** block `routine` or `elevated`
actions — the receipt remains signed, durable, and valid with `anchor.status = "pending"`.
Fail-closed must not become self-inflicted denial of service; only `critical` actions may be gated
on the log. Unanchored receipts **MUST** be reconciled when the log returns, and an unanchored
receipt older than the policy window **MUST** raise an alarm.

### 7.1 Receipt granularity — consequence-tiered batching

A receipt per consequential action is defensible; a receipt per tool call is not, and pretending
otherwise produces a system teams disable under load.

| Tier | Granularity |
|---|---|
| `critical`, `elevated` | **One receipt per action.** No batching, ever. |
| `routine` | **Windowed batch receipt** carrying a Merkle root over the individual action records |

In a batch receipt, each constituent action remains **individually provable**: the batch carries the
Merkle root, and any single action's inclusion is demonstrable with a path. `subject[]` lists the
union of artifacts; per-action detail lives in the leaves.

**Normative — how I-07 survives batching.** Evidence-before-commit is preserved *at the batch
boundary*: the batch receipt for window *n* **MUST** be signed and durable before any action in
window *n+1* may commit. A window **MUST** be bounded by both count and duration
(`max_actions`, `max_duration`), and either bound reaching its limit closes the window immediately.

**Normative — no tier laundering.** An action's tier is a property of the operation, not a
performance dial. Implementations **MUST NOT** downgrade an action's `consequence_tier` to obtain
batching, and a batch containing any non-`routine` action is invalid.

---

## 8. What a WAR does and does not prove

Stated plainly, because overclaiming here is the fastest way to lose technical credibility:

**A WAR proves** that a named principal, under a verifiable delegation chain whose intersection was
independently recomputable, received a specific policy verdict evaluated at commit time against a
digest-identified policy, over digest-identified artifacts, and that evidence was durable before the
effect became visible — non-repudiably, with an independent timestamp once anchored.

**A WAR does not prove** that the output is *re-derivable*. Recovering re-derivation requires
measuring decode parameters, sampler PRNG state, and a pinned numerical pipeline into attested
state — the optional re-derivable-inference profile, not this document. Nor does a WAR prove
platform integrity unless `platform_verdict` is present. Nor does it prove non-bypassability unless
`enforcement_mode` is `mediated`.

---

## 9. Adversarial vectors (normative — `testvectors/protocols/P2/v2/`)

Every implementation **MUST** pass all of these before claiming conformance:

| Vector | Expected |
|---|---|
| Replay — receipt re-presented after `expires_at` | Reject |
| Replay across context — valid receipt replayed in another task | Reject on `nonce` + `receipt_id` uniqueness |
| Tampering — any field mutated post-signing | Verification fails |
| **Authority expansion** — `effective_capabilities` contains a capability absent from one link | Reject (I-02) |
| **Forged intersection** — `intersection_proof` inconsistent with `chain[]` | Reject on recomputation |
| Confused deputy — `canonical_resource_id` replaced with a caller-supplied string | Reject |
| Downgrade — receipt claims v1.0 semantics on a v2.0 endpoint | Reject |
| Unknown critical extension | Reject (fail-closed) |
| Commit-order violation — `post_commit` present with no durable `pre_commit` | Reject (I-07) |
| Mode escalation — `advisory` receipt asserting non-bypassability | Reject |
| `(Authorised, Contested)` | **MUST NOT** pass silently; surfaced as alarm |
| Artifact substitution — same name, different digest | Reject (I-06) |
| Algorithm confusion — `alg` mismatched to key type | Reject |
| Root compromise — chain valid but root key on the revocation list | Reject; containment path invoked |

---

## 10. Cross-references

- Notary API that emits WARs: [`02-notary-api.md`](02-notary-api.md)
- Enforcement-mode contract: [`03-enforcement-mode.md`](03-enforcement-mode.md)
- SAFE Finding projection: [`04-safe-finding.md`](04-safe-finding.md)
- Superseded: [`../protocols/P2-aar.md`](../protocols/P2-aar.md) (v1.0)
- Architecture, invariants I-01…I-12: [`../../docs/02-architecture.md`](../../docs/02-architecture.md)
