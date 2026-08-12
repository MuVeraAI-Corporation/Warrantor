# R10 — The Attack-to-Policy Loop

> Scanners find vulnerabilities. Control protocols mitigate at runtime. **Nothing connects them.**
> No system today takes "attack X succeeded against action-class Y in evaluation" and turns it into
> "therefore action-class Y is denied in production."
>
> **Status:** DRAFT SPEC — Tier B. The loop that makes evidence actionable.

---

## 1. The loop

```
eval receipt (finding)  →  triage  →  candidate rule  →  human approval  →  enforced
        ▲                                                                       │
        └────────────── regression case added to the corpus ◀───────────────────┘
```

Five stages, one of which is deliberately not automatic.

---

## 2. Why a human approves

You chose propose-then-approve, and it is the right call for a reason worth writing down: **an
automatic loop is an attack surface.**

If a succeeding red-team finding automatically denies an action class, then an attacker who can
influence what the red-teamer finds can deny *legitimate* capability at will. A tool that
manufactures findings becomes a remote switch for disabling production functionality — the loop
inverts from a safety mechanism into a denial-of-service primitive, and the more trusted the loop,
the more damaging the inversion.

Requiring approval on the consequential step costs latency measured in minutes and removes that
inversion entirely.

**Normative.**

- A candidate rule **MUST NOT** take effect without an approval recorded as a receipt.
- Approval is per-rule, never blanket. "Approve all findings from source X" is prohibited — it
  reconstructs the automatic loop through a policy back door.
- The approver **MUST** see the evidence: the eval receipt digest, the reproduction reference, the
  elicitation method, and the noise floor. Approving a finding whose validity block is missing is
  approving an anecdote.
- A rule **MAY** be auto-applied in **monitor** mode without approval, since monitoring denies
  nothing. Promotion from monitor to deny always requires approval.

---

## 3. Triage — what earns a candidate rule

Not every finding should become a rule, and a loop that proposes indiscriminately will be ignored
within a week.

A finding is promoted only if it is **reproducible** (or a bounded distribution across repetitions),
carries elicitation method and noise floor, maps to a **specific action class** rather than a
diffuse behavior, and is not already covered by an existing rule.

Findings that fail triage are not discarded — they are recorded with the reason, because a pattern
of near-miss findings is itself signal, and a loop that silently drops what it cannot handle hides
its own blind spots.

---

## 4. Candidate rule generation

The generated rule targets the **narrowest** scope that covers the finding:

| Finding scope | Rule scope |
|---|---|
| Specific tool + specific parameter shape | That tool, that shape |
| Action class against any target | That action class |
| Model-specific behavior | That model digest, not the model family |
| Capability-level failure | That capability in the delegation vocabulary |

**Normative.** A generated rule **MUST NOT** be broader than the evidence supports. Over-broad rules
are how a safety loop becomes an availability incident, and the temptation to generalize "this
failed once" into "this class is forbidden" is exactly what the approval step exists to catch.

Every rule carries its provenance: the eval receipt digest that motivated it, the finding
identifier, the generation timestamp, and an expiry. **Rules generated from evidence expire**, and
renewal requires the finding to still reproduce — otherwise a system slowly accretes denials nobody
can justify or remove.

---

## 5. Rollout

Approved rules deploy progressively, because a policy change is a production change:

1. **Monitor** — log matches, deny nothing, for a declared observation window.
2. **Canary** — enforce for a subset of principals or tenants.
3. **Enforce** — full deployment.
4. **Rollback** — any stage can revert; rollback is a receipted action like any other.

If a monitor-stage rule matches far more traffic than the finding predicted, that is a signal the
rule is over-broad, and it **MUST** be re-scoped rather than promoted. This is the single most
useful safeguard in the loop and costs nothing but patience.

---

## 6. Closing the loop

A confirmed finding also becomes a **regression case** in the invariant attack corpus, so the same
attack is tested forever after. This is what makes the loop compounding rather than merely
reactive: the corpus grows from real failures instead of imagined ones, and a rule that is later
removed still leaves its test behind.

Where the finding defeats a claim in a safety case, the corresponding **defeater** fires, the claim
is invalidated, and any authority resting on that claim is revoked within the bounded window. That
path is what makes assurance arguments dynamic rather than decorative.

---

## 7. Conformance

| Test | Expected |
|---|---|
| Finding auto-applies as `deny` without approval | Non-conformant |
| Blanket approval configured for a source | Non-conformant |
| Rule broader than the evidence supports | Rejected at triage or in review |
| Rule generated from a finding lacking noise floor | Rejected |
| Generated rule with no expiry | Non-conformant |
| Monitor-stage match rate far exceeds prediction, rule promoted anyway | Non-conformant |
| Approval recorded without a receipt | Non-conformant |
| Confirmed finding not added to the corpus | Non-conformant |
| Manufactured finding from a compromised scanner reaches enforcement without human review | Non-conformant — this is the inversion the design exists to prevent |
