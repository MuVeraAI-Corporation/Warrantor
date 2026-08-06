# P9 — Agent Incident Exchange

> Normalized incidents for goal hijack, memory poisoning, tool abuse, identity compromise, exfiltration, rogue delegation. Base: OCSF extension + MITRE ATLAS mapping.

| Field | Value |
|---|---|
| **Protocol ID** | P9 |
| **Name** | aix (Agent Incident Exchange) |
| **Spec-only canonical** | Yes — see [`../../docs/00-reconciliation-matrix.md`](../../docs/00-reconciliation-matrix.md) §9 |
| **Consumed by** | X9, R3 |
| **Schema location** | `OCSF extension + JSON` |
| **Base standards** | SPIFFE, OAuth RAR/DPoP, OCSF, OTel, CycloneDX/SPDX, OMS, MITRE ATLAS (as applicable) |

## Purpose

Normalized incidents for goal hijack, memory poisoning, tool abuse, identity compromise, exfiltration, rogue delegation. Base: OCSF extension + MITRE ATLAS mapping.

The protocol is **language-neutral**. It is defined once here and consumed identically by every
language implementation via the contract plane (see
[`../../docs/cross-cutting/19-inter-component-protocol.md`](../../docs/cross-cutting/19-inter-component-protocol.md)).

## Schema sketch (CDDL / protobuf)

The normative schema lives at `OCSF extension + JSON`. Mandatory fields:

```
incident_id, type, severity, agent, authority, evidence_refs, mitre_atlas_id, ocsf_class, detected_at, contained_at
```

(Field names are stable; renaming is a breaking change requiring a new protocol version per the
governance rules in `specs/protocols/README.md`.)

## Signing

Every instance is signed by the issuer using T1 trust-core (Ed25519 by default; KMS/HSM in
production). The signature covers the canonical-CBOR encoding of the protocol message. The
Sigstore Rekor transparency log entry is returned for non-repudiation.

## Revocation

- **Expiry:** every instance carries an explicit expiry timestamp; expired instances are rejected
  without further checks.
- **Revocation handle:** issuers may revoke by publishing the revocation handle to
  `aumos.<domain>.revoked.v1` CloudEvent on Kafka.
- **Propagation:** revocation propagates fleet-wide within the I-05 budget (identity <5s,
  credentials <1s).
- **Partial disclosure:** protocols support selective disclosure where the use case requires it
  (e.g. zero-knowledge proofs for sensitive authority claims — future work).

## Adversarial test vectors

Each protocol ships adversarial test vectors in `testvectors/P9/`:

- **Replay** — expired and re-used instances are rejected.
- **Tampering** — any field modified post-signing fails verification.
- **Confused deputy** — an instance presented to the wrong audience is rejected.
- **Privilege amplification** — a delegation chain whose intersection would expand authority is
  rejected (invariant I-02).
- **Downgrade** — an instance claiming an unsupported protocol version is rejected.
- **Replay across contexts** — a receipt from one task replayed in another is detected by
  `subject` + `jti` uniqueness.

Conformance is enforced by A6 (the cross-language conformance suite) against every language
implementation that consumes the protocol.

## Cross-references

- Reconciliation: [`../../docs/00-reconciliation-matrix.md`](../../docs/00-reconciliation-matrix.md) §9
- Architecture: [`../../docs/02-architecture.md`](../../docs/02-architecture.md) (planes consuming this protocol)
- Trust core: [`../../docs/rfcs/T1-trust-core.md`](../../docs/rfcs/T1-trust-core.md) (signs/verifies)
- Conformance: [`../../docs/rfcs/A6-conformance.md`](../../docs/rfcs/A6-conformance.md)
