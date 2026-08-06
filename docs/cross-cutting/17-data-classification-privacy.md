# 17 — Data Classification & Privacy

> Every AumOS component that touches data must classify it, enforce residency, redact PII on egress,
> and honor data-subject rights. This standard closes the gap that blocked EU / healthcare / financial
> customers (gap-analysis-v3 gap #35).

## Why this exists

DefStack v1/v2 had no data-classification spec. Without it:
- Components cannot decide what may be logged, cached, replicated, or sent to a third-party model.
- EU customers cannot demonstrate GDPR compliance.
- Healthcare customers cannot demonstrate HIPAA compliance.
- Financial customers cannot demonstrate DORA / residency compliance.

This standard defines **5 classification levels**, **10 PII types with redaction rules**, **GDPR
data-subject rights**, **CCPA / HIPAA operating modes**, and **data-residency enforcement**.

---

## 1. Classification Levels

| Level | Label | Examples | Default handling |
|---|---|---|---|
| **L0** | Public | OSS docs, published RFCs, public model cards | No restrictions |
| **L1** | Internal | Internal metrics, non-sensitive logs, config (no secrets) | Encrypt at rest; internal network only |
| **L2** | Confidential | Customer telemetry, eval transcripts (non-PII), model weights under license | Encrypt at rest + in transit; access-controlled; **never** sent to third-party model without explicit per-record approval |
| **L3** | Sensitive PII | Names, emails, phones, IPs, credentials, financial, health | Encrypt at rest + in transit; **redact before logging**; **never** sent to third-party model; residency-locked |
| **L4** | Regulated | PHI (HIPAA), PCI, government CUI, EU special-category data | Encrypt with customer-managed keys (HSM); air-gapped or confidential-compute only; full audit trail; data-processing agreement required |

**Default rule:** when in doubt, classify **up**, not down.

---

## 2. PII Types and Redaction Rules

| Type | Detector | Redaction | Notes |
|---|---|---|---|
| **Email** | RFC 5322 regex + validator | `sha256(local-part)@redacted.tld` | Keep domain if needed for routing; redact local part |
| **Phone (E.164)** | libphonenumber | `(REDACTED-PHONE)` | All formats; preserve country code only if needed |
| **SSN (US)** | `^\d{3}-\d{2}-\d{4}$` + checksum | `(REDACTED-SSN)` | High-confidence only; never partial-redact |
| **Credit card** | Luhn + IIN ranges | `(REDACTED-CC:<last4>)` | Keep last 4 for support; tokenize via CredentialVault |
| **IP address (v4/v6)** | IETF parser | `(REDACTED-IP:</24-prefix>)` | Preserve /24 for geo; redact host |
| **API key** | Per-service patterns (`sk-…`, `AKIA…`, `ghp_…`) | `(REDACTED-KEY:<service>)` | Same patterns as ExfilGuard (S6) |
| **Physical address** | NER model + postal parser | `(REDACTED-ADDRESS)` | NER-based; flag for human review |
| **Date of birth** | Date NER + age check | `(REDACTED-DOB:<decade>)` | Preserve decade only |
| **Biometric** | Never processed in text streams | N/A — block at ingestion | L4; reject if detected |
| **Credentials / secrets** | TruffleHog / gitleaks patterns | `(REDACTED-SECRET)` | Revoke via CredentialVault (R4) on detection |

**Implementation:** redaction runs in the **evidence plane** (E1 flight-recorder) before any AAR is
emitted, and in **R7 egress-filter** before any outbound network call. Both use the same detector
library so behavior is identical.

---

## 3. GDPR Data-Subject Rights

AumOS supports all six GDPR rights data subjects can exercise:

| Right (Article) | AumOS mechanism | Component |
|---|---|---|
| **Access (Art. 15)** | `defstack privacy export --subject <id>` → JSON of every record referencing the subject | E1 + A6 (search the evidence store) |
| **Rectification (Art. 16)** | `defstack privacy rectify --subject <id> --field <x> --value <y>` | E1 (append-only ledger entry) |
| **Erasure (Art. 17)** | `defstack privacy erase --subject <id>` → cryptographically-shred keys, tombstone records, propagate to replicas | E1 + I1 (revoke identity) + R4 (revoke credentials) |
| **Restriction (Art. 18)** | `defstack privacy restrict --subject <id>` → mark records read-only, halt processing | E1 + policy flag |
| **Portability (Art. 20)** | `defstack privacy export --subject <id> --format json-ld` → machine-readable bundle | E1 |
| **Objection (Art. 21)** | `defstack privacy object --subject <id> --purpose <p>` → halt the named processing purpose | Policy compiler (R5) + E1 |

**SLA:** all rights actions complete within **30 days** (GDPR Art. 12). Erasure propagates to all
replicas within **72 hours**.

---

## 4. CCPA / CPRA Operating Mode

`defstack privacy --mode ccpa` enables:

- **Right to know** — same as GDPR access.
- **Right to delete** — same as GDPR erasure.
- **Right to opt-out of sale** — `defstack privacy opt-out --subject <id>` sets a flag consumed by
  the Privacy & Sovereignty Router (future component) so the subject's data is never routed to any
  "sale" downstream.
- **Right to non-discrimination** — explicitly: opting out does not degrade service.

CCPA applies to California residents; AumOS applies the rule globally when the mode is enabled (it
is stricter than the default).

---

## 5. HIPAA Operating Mode

`defstack privacy --mode hipaa` enables **L4 (Regulated)** handling for all health data:

- **PHI detection:** NER model trained on HIPAA's 18 identifiers, runs at ingestion.
- **Encryption:** customer-managed keys in a FIPS 140-2 Level 3 HSM; no AumOS-side key access.
- **BAA (Business Associate Agreement):** required before any PHI touches AumOS. Template stored in
  `docs/legal/baa-template.pdf` (provided per customer).
- **Audit:** every PHI access logged with accessor identity, purpose, timestamp. Logs retained 6
  years (HIPAA requirement).
- **Breach notification:** if PHI is exposed, the HIPAA breach-notification clock starts — AumOS
  provides the audit trail within 1 hour to support the customer's 60-day notification obligation.
- **No third-party model routing:** PHI never sent to any non-HIPAA-compliant inference provider.
  The Privacy & Sovereignty Router (future) enforces this.

---

## 6. Data Residency

`defstack config set residency <region>` constrains where each classification level may be stored
and processed:

| Region | L0 | L1 | L2 | L3 | L4 |
|---|---|---|---|---|---|
| **US** | Anywhere | US | US | US + EU (with SCC) | US only (FedRAMP) |
| **EU** | Anywhere | EU | EU | EU only | EU only (member-state lock optional) |
| **UK** | Anywhere | UK/EU | UK/EU | UK only | UK only |
| **India** | Anywhere | India | India | India only | India only |
| **Air-gapped** | On-prem | On-prem | On-prem | On-prem | On-prem (confidential compute) |

**Enforcement:** the residency flag is consumed by the Privacy & Sovereignty Router (future
component) at every storage and network-egress decision. Violations fail-closed.

---

## 7. Encryption Requirements

| Data state | Algorithm | Key management |
|---|---|---|
| At rest (L2+) | AES-256-GCM | Envelope encryption; DEK per object, KEK in KMS/HSM |
| In transit (all L1+) | TLS 1.3 | mTLS for internal (SPIFFE); TLS 1.3 for external |
| In use (L3+ with confidential compute) | Confidential VM / TEE | NVIDIA CC mode (C1-1/C1-2 attest) |
| Backups (L2+) | AES-256-GCM | Separate keys from primary; cross-region |
| Secrets / credentials | Never "encrypted at rest" — rotated | CredentialVault (R4) |

**Key rotation:** automatic every **90 days** for L2, **30 days** for L3, **7 days** for L4.
**Crypto agility:** all encryption is abstracted behind the trust-core (T1) so post-quantum
algorithms can be swapped in without component changes.

---

## 8. Component Obligations

Every component MUST:

1. **Classify** all data it touches, tag it in the Context Provenance Envelope (P3).
2. **Redact** PII before logging (use the shared detector library).
3. **Enforce residency** at every storage and egress decision.
4. **Honor** the privacy CLI commands within the SLA.
5. **Emit** an AAR (P2) for every data-access action with the classification and purpose recorded.
6. **Never** log secrets — even redacted; reject at ingestion.
7. **Document** its data flows in its RFC's "Data Handling" subsection.

---

## 9. Privacy Impact Assessment (DPIA)

Before any new processing that is "likely to result in a high risk" (GDPR Art. 35), a DPIA must be
completed using the template at `docs/legal/dpia-template.md`. The DPIA is reviewed by the privacy
lead (to be hired by M6) and signed off before the feature ships.

---

## 10. Review Cadence

- This standard is reviewed **quarterly**.
- Regulatory changes (new GDPR guidance, new state privacy laws) trigger updates within **14 days**.
- A component that cannot meet these obligations is **not shipped**.
