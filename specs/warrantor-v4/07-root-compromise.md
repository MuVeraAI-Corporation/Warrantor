# Root Compromise — Containment Design

> The capability algebra proves that authority cannot expand along a chain **provided every link is
> authentic**. This document addresses what happens when that proviso fails: an attacker who holds
> the root signing key can mint any warrant they like, and every downstream proof will verify
> correctly.
>
> **Status:** FROZEN CANDIDATE — closes the most serious open question in the v4 contract pack.

---

## 1. The threat is not hypothetical

In the July 2026 Hugging Face intrusion the agent did not break cryptography. It read projected
Kubernetes service-account tokens, pulled node-role credentials from the cloud instance-metadata
endpoint, and extracted **136 keys** from cluster secret objects — including mesh-VPN authentication
and access-broker credentials. Nothing was forged; long-lived secrets were simply *found* and reused
across four accounts and four services.

A signing root sitting in an environment variable, a mounted secret, or a metadata-service response
would have been harvested with everything else. Any design that assumes an honest root is assuming
away the exact failure that happened.

**Stated plainly: a fully compromised root defeats delegation-chain intersection.** No amount of
elegance in the algebra changes that. The design goal is therefore not prevention alone — it is to
make compromise *hard*, *detectable*, and *survivable*, so that the outcome degrades rather than
collapses. Four layers, each independently useful.

---

## 2. Layer 1 — Hardware-bound root (prevention)

The root private key **MUST NOT** exist in process memory, an environment variable, a mounted file,
a container image, or any secret-manager response. It lives in an HSM, a TPM, or a cloud KMS with a
non-exportable key policy, and signing is an operation performed *by* that device.

| Requirement | Rule |
|---|---|
| Key material | Non-exportable by policy; generated on-device |
| Attestation | The root **SHOULD** publish a key-attestation certificate proving on-device generation |
| Access | Signing requires an authenticated channel; the credential for that channel is itself short-lived |
| Agent reachability | No agent workload may hold a credential that can reach the signing device. **Agents sign nothing; they request.** |
| Metadata services | The signing path **MUST NOT** be reachable using instance-metadata-derived credentials |

This layer answers the Hugging Face failure mode directly: a harvested environment yields no signing
capability, because there was never a key in the environment to harvest.

---

## 3. Layer 2 — Threshold issuance (prevention)

Root authority requires **M-of-N** independent signers, held in distinct trust domains — ideally
different key custodians, different hardware, different operators.

- Root-level delegation (issuing or widening a top-level warrant) **MUST** require a threshold
  signature. A single harvested key cannot mint authority.
- Routine downstream delegation **MUST NOT** require threshold — that would make the system
  unusable, and downstream links can only ever narrow authority (§ the algebra's theorem).
- Threshold membership changes are themselves threshold operations, and are logged (§4).
- `N ≥ 3`, `M ≥ 2` for production. Deployments below this **MUST** report themselves as
  single-root, since their actual guarantee differs.

The cost is real and should be stated: threshold issuance adds operational friction to exactly the
ceremony that is already the most annoying. It is scoped to root issuance only for that reason.

---

## 4. Layer 3 — Transparency-log detection (detection)

Prevention can fail silently. Detection assumes it did.

**Every root-issued delegation MUST be logged to the transparency log before use.** A verifier
**MUST** reject a root-issued warrant with no inclusion proof once the deployment's log-availability
window has elapsed. This converts a *silent* forgery into a *loud* one: an attacker holding the root
key faces a choice, and both branches are visible.

| Attacker branch | Consequence |
|---|---|
| Issues **off-log** to stay hidden | Warrants are rejected by verifiers (no inclusion proof) |
| Issues **on-log** so warrants verify | The issuance is permanently, publicly recorded and monitorable |

Monitors **MUST** alarm on: issuance outside declared ceremony windows; a rate exceeding the
declared baseline; capability sets broader than any previously issued; issuance to unrecognized
subjects; and **any gap** between logged issuance and the operator's own issuance record.

That last check is the one that catches a fully compromised root, and it works precisely because it
compares two independent records — the log and the operator's expectation — rather than trusting
either alone.

**Honest limit.** Detection is not prevention. It bounds *dwell time*, not blast radius within that
window. The relevant benchmark is the 4.5 days and roughly 17,600 actions that elapsed in the July
2026 incident; the design target is minutes.

---

## 5. Layer 4 — Blast-radius caps (survivability)

The final layer assumes the previous three have all failed and the attacker holds a valid,
correctly-logged, threshold-signed root warrant. **Caps are enforced independently of the delegation
chain**, so a valid warrant is necessary but not sufficient.

| Cap | Enforcement |
|---|---|
| Per-tenant action-rate ceiling | Exceeded → throttle, then contain. Applies regardless of granted authority |
| Consequence-tier ceiling | A tenant may be barred from `critical` actions outright, independent of any warrant |
| Novel-capability ceiling | First-time-seen capability for a principal is rate-limited and flagged, even if authorized |
| Egress destination ceiling | New destinations require separate approval (the egress broker), not merely authority |
| Aggregate budget | Autonomy budgets deplete and cannot be replenished by the same principal that spends them |

**Normative.** Caps **MUST NOT** be expressible as capabilities in the delegation chain. If a
warrant could raise its own ceiling, the layer provides nothing — this is the same self-extension
denial that invariant I-11 enforces for enforcement boundaries, applied to limits.

The design intent: a compromised root that would otherwise have executed ~17,600 actions in 4.5 days
is instead throttled within seconds and contained within minutes, having done bounded damage.

---

## 6. Recovery

Once compromise is confirmed, recovery **MUST NOT** be a silent re-grant of previously held
authority — that would launder the attacker's position into the new trust root.

1. **Contain first.** Invoke `Contain` at the widest affected scope; reaching a safe state precedes
   diagnosis.
2. **Revoke the root**, publish revocation to the log, and treat *every* warrant in its lineage as
   suspect — receipts remain valid evidence of what happened, they simply no longer authorize.
3. **Re-key under ceremony**, with a fresh threshold set, and record the new root's first issuance.
4. **Re-grant explicitly.** Downstream authority is re-issued by deliberate human action, never
   restored automatically. The containment conformance suite measures exactly this as *restoration
   integrity*.
5. **Report.** The incident projects into a SAFE Finding with
   `authority_evidence.expansion_detected` and the measured `revocation_latency_observed_ms`.

---

## 7. What this design does not claim

- It does **not** claim a compromised root is harmless. It is not.
- It does **not** claim detection is instantaneous — it bounds dwell time, and the bound depends on
  log availability and monitor quality, both of which are deployment properties.
- It does **not** claim threshold issuance prevents insider collusion at or above the threshold.
- A deployment that has implemented only some layers **MUST** report which ones, in the conformance
  report and in the receipt's deployment profile. Claiming root-compromise containment while
  running a single software-held key is precisely the kind of unfalsifiable assertion the
  enforcement-mode contract exists to prevent.

---

## 8. Conformance

The containment suite (`05-killswitch-conformance.md`) gains a root-compromise battery: simulate a
harvested software root and verify caps engage; issue off-log and verify rejection; issue on-log
outside the ceremony window and verify the alarm; attempt a single-key root issuance under threshold
policy and verify refusal; attempt to raise a cap via a warrant and verify refusal; and run recovery
end-to-end, verifying that authority is **not** silently restored.
