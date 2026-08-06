# Open Protocols — Spec-Only Canonical Components

This directory holds the **12 normative, language-neutral protocols** reconciled from the AumSecure
V2 portfolio. They are *spec-only* canonical components (P1–P12 in the reconciliation matrix):
no single language implementation owns them; every relevant component consumes them via the
contract plane.

Each protocol lives as `<id>-<kebab-name>.md` (human-readable normative spec) plus a future
machine-checkable schema in `proto/aumos/protocols/v1/` or `specs/<id>/schema.cddl` (CDDL) /
`schema.json` (JSON-Schema). Schemas land in Wave-1 for P1/P2 (consumed by T1, I1, E1) and
incrementally after.

## Protocol governance rules (from source docs)

1. Start as implementation notes + JSON/CBOR schemas; standardize only after real multi-vendor use.
2. Never encode hidden reasoning.
3. Separate identity, authority, reputation.
4. Design for revocation, expiry, rotation, federation, partial disclosure from v1.
5. Every protocol requires adversarial test vectors + a conformance suite.

## The 12 protocols

| ID | Name | Spelled out | Consumed by | Schema |
|----|------|-------------|-------------|--------|
| P1 | `aae` | Agent Authority Envelope | I1, R3, R4, all trusted-core | `proto/aumos/protocols/v1/aae.proto` + CDDL |
| P2 | `aar` | Agent Action Receipt | E1, X2, all auditing components | `proto/aumos/protocols/v1/aar.proto` + CDDL |
| P3 | `cpe` | Context Provenance Envelope | (future context components) | CDDL |
| P4 | `amil` | Agent Memory Integrity Ledger | (future context/memory components) | CDDL |
| P5 | `ssp` | Secure Skill Package | S4, X8 | CDDL + JSON-LD |
| P6 | `aatm` | AI Artifact Trust Manifest | T1, S1, S4, S5 | JSON-LD |
| P7 | `abs` | Autonomy Budget Specification | I1, R3 | CDDL |
| P8 | `veb` | Verifiable Evaluation Bundle | A1, A5, A6 | CDDL |
| P9 | `aix` | Agent Incident Exchange | X9, R3 | OCSF ext + JSON |
| P10 | `made` | Multi-Agent Delegation Exchange | I1 (multi-agent future) | CDDL |
| P11 | `prb` | Proof-Carrying Remediation Bundle | S9, X9 | CDDL + JSON-LD |
| P12 | `cap` | Capability Attestation Profile | R1, R2, I1 | CDDL |

Each protocol file below contains: purpose, schema sketch, mandatory fields, signing requirements,
revocation semantics, and the adversarial test vectors required for conformance.
