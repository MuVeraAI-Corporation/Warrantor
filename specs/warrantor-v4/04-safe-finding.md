# The SAFE Finding, v0.1 — a proposed data model for the Shared AI Findings Exchange

> The SAFE RFC defines *what* to report and *when*. It does not define a field. This is a proposed
> fielded schema, offered to the Open Secure AI Alliance RFC process as a starting point, designed
> so that a signed Warrantor Action Receipt projects into a valid SAFE Finding without translation
> loss.
>
> **Status:** DRAFT FOR CONTRIBUTION — intended for `github.com/OpenSecureAIAlliance/RFCs`.
> **Schema:** `04-safe-finding.schema.json`

---

## 1. What the RFC leaves open

The SAFE proposal specifies four reportable conditions in prose, an eight-layer review framework,
and notification windows (as-soon-as-possible, 72 hours to customers on credible data exposure,
four business days to the exchange, then 14 / 30 / 90-day stages). It commits the working group to
publish *"reusable tests, machine-readable policies, detection rules, reference configurations and
incident-response guidance."*

It specifies the format of none of them, and it references no existing schema — not OCSF, not
STIX, not CVE, not CVSS, not MITRE ATLAS. That omission is deliberate and well-reasoned: the RFC
observes that this failure class *"has no CVE number, no CVSS score, and no existing
cross-organizational disclosure mechanism."* The conclusion this document draws is not that
existing standards are wrong, but that SAFE needs **its own severity vocabulary** and a
**crosswalk** rather than a forced fit.

## 2. Design principles

1. **Reuse OCSF as the carrier, but as a first-class class.** The current practice of attaching
   agent events to API Activity via an `unmapped` object makes agent findings second-class and
   unqueryable. A SAFE Finding should be a proper class.
2. **Severity must not assume CVSS.** A sandbox escape with third-party impact has no meaningful
   CVSS vector. SAFE needs a vocabulary keyed to *blast radius and reversibility*.
3. **Structure the eight review layers, don't prose them.** They are the RFC's most reusable
   contribution and should be enums that aggregate across incidents.
4. **Findings must be mechanically verifiable** — this is what issues #4 and #7 ask for. A finding
   carries an integrity block or it is an anecdote.
5. **Bridge to OpenTelemetry GenAI semantic conventions**, which the issue discussions treat as the
   de facto interoperability anchor — while adding the signature layer telemetry lacks.

## 3. Structure

```
SAFE Finding
├── finding_id, schema_version, disclosure_state, timestamps{}
├── reporter{}          — org, contact class, confidentiality tier
├── condition           — the four reportable conditions, as an enum
├── review_layers[]     — the eight-layer taxonomy, structured per layer
├── impact{}            — severity vocabulary that does not assume CVSS
├── causal_graph{}      — reconstructable chain (issue #7)
├── authority_evidence{} — temporal authority + self-extension denial (issue #1)
├── verification{}      — method, failure modes, noise floor (issue #4)
├── artifacts[]         — content-digest identity for everything involved
├── crosswalk{}         — ATLAS / OWASP / OCSF / STIX / OTel mappings
├── controls[]          — from lessons to controls: tests, policies, detections
└── integrity{}         — signature, transparency anchor, receipt lineage
```

### 3.1 `condition` — the four reportable conditions

`third_party_compromise` · `boundary_escape_with_third_party_impact` ·
`unauthorized_confidential_access` · `continued_probing_after_discovery`

Structured as an enum so the exchange can aggregate "how often does class X recur," which is the
entire point of a findings exchange.

### 3.2 `review_layers[]` — the eight-layer taxonomy

One entry per implicated layer: `model` · `instructions` · `safeguards` · `tools` · `environment` ·
`monitoring` · `human_operations` · `supply_chain`. Each carries whether the layer **failed**,
**contained**, or was **not_implicated**, plus the specific control that failed and whether it
existed at all.

The distinction between *a control that failed* and *a control that was never implemented* is the
single most useful thing an exchange can aggregate, and prose reporting loses it every time.

### 3.3 `impact` — severity without CVSS

| Dimension | Values |
|---|---|
| `blast_radius` | `self` · `tenant` · `organization` · `third_party` · `ecosystem` |
| `reversibility` | `reversible` · `partially_reversible` · `irreversible` |
| `data_exposure` | `none` · `suspected` · `confirmed` |
| `autonomy_level` | `human_directed` · `human_supervised` · `autonomous` |
| `dwell` | duration from first unauthorized action to containment |
| `action_count` | count of unauthorized actions |

`autonomy_level` matters because "an agent did this without being told to" is the distinguishing
property of this incident class, and no existing severity scheme captures it. `dwell` and
`action_count` are the numbers that made the July 2026 incidents legible — roughly 17,600 actions
over about four and a half days is a description no severity score conveys.

### 3.4 `authority_evidence` — answering issue #1

Issue #1 asks for a temporal authority framework with self-extension denial. The fields:

- `authority_at_incident` — capabilities actually held when the unauthorized action occurred
- `authority_expected` — capabilities the design intended
- `expansion_detected` — whether effective authority exceeded any single delegation link
- `self_extension_attempted` / `self_extension_denied` — did the agent try to widen its own
  authority, and did the substrate stop it
- `revocation_latency_observed` — measured time from decision-to-revoke to last authorized action

`revocation_latency_observed` is deliberately a *measured* field. An exchange that collects it
across members produces the first real distribution of how long containment actually takes.

### 3.5 `verification` — answering issue #4

`method` (`reproduced` · `log_derived` · `inferred` · `reported_only`), `failure_modes[]`
(what this method can miss), `noise_floor` (the detection threshold below which the finding would
not have been observed), and `reproducible` with `reproduction_ref`.

A finding that does not declare what it could have missed cannot be aggregated honestly — two
organizations reporting different rates may simply have different noise floors.

### 3.6 `causal_graph` — answering issue #7

Nodes are typed (`action`, `decision`, `artifact`, `identity`, `boundary`) and edges are causal
(`enabled`, `authorized`, `escalated`, `contained`). Each node **MAY** carry a `receipt_ref`. Where
receipts exist for every node, the graph is mechanically verifiable end to end rather than narrated.

### 3.7 `integrity` — what makes a finding evidence

`{ signature (DSSE), signer, transparency_anchor, receipt_lineage[], aibom_ref }`

A finding **SHOULD** carry an integrity block. Where `receipt_lineage` is populated, a consumer can
verify the claimed sequence independently of the reporter's narrative — which is what
"mechanically verifiable" has to mean in practice.

### 3.8 `crosswalk` — the mappings the RFC omits

MITRE ATLAS technique IDs; OWASP Agentic Top-10 and LLM Top-10 classes; OCSF class and activity;
optional STIX 2.1 bundle reference; and OpenTelemetry GenAI trace and span IDs. Every field is
optional and additive — the crosswalk exists to make SAFE findings consumable by tooling that
already exists, not to subordinate SAFE to any one taxonomy.

## 4. Disclosure state machine

`draft` → `confidential` → `notified` → `advisory` → `public` → `superseded`

Each transition carries a timestamp and the RFC's windows as *derived deadlines* rather than
hardcoded values, so a schema change is not required when the compact's timing is tuned. Redaction
is expressed as field-level policy: a `confidential` finding and its later `public` form are the
same object with fields elided, so aggregate analysis survives redaction.

## 5. Relationship to the Warrantor receipt

A Warrantor Action Receipt projects into a SAFE Finding by construction: `authority.chain` and
`intersection_proof` populate `authority_evidence`; the receipt lineage populates `causal_graph`
and `integrity.receipt_lineage`; `artifacts` carries over unchanged; the enforcement mode records
whether the control could have contained the incident at all.

This is offered as *evidence of feasibility*, not as a requirement. **A SAFE Finding must be
producible by any member, with or without Warrantor** — a schema that only one implementation can
emit is not a standard. The integrity block is optional precisely so that members without a signing
substrate can still report.
