# Aevum v0.9 operational artifact review

Status: pinned artifact reproduced; high-quality comparator with a failed external-protocol claim  
Reviewed: 2026-08-30  
Repository: <https://github.com/aevum-labs/aevum>  
Pinned commit: `72a31ba909be20f41cf4ac9d587de30b5dda13f8`  
Pinned commit date: 2026-07-20  
Release baseline: [v0.9.0](https://github.com/aevum-labs/aevum/releases/tag/v0.9.0), 2026-06-22  
License: Apache-2.0

## Decision

**Modify and selectively consume.** Aevum is credible prior art and a useful implementation source
for hash-chained agent records, portable COSE receipts, crypto agility, timestamps, Merkle material,
standalone verification, policy adapters and enforcement-barrier integration. It should influence
W1/W2 design and Warrantor's conformance corpus.

It is not a drop-in Warrantor substrate. It explicitly occupies a recorder-oriented boundary, has
no independent security audit or production evidence in this review, and its claimed Rekor v2
integration is not compatible with the official v2 protocol. Warrantor should preserve Aevum input
bytes and semantics through an adapter, fix or contribute external-protocol tests, and retain its own
authority/effect binding, enforcement conformance and authenticated expected-set reconciliation.

## Reproduction receipt

The repository was cloned and pinned without modifying its source. The first default pytest run
failed because the mounted execution environment could not open its output-capture file. Disabling
pytest capture allowed the intended suite to run; this was a host workaround, not a product patch.

| Surface | Result | Interpretation |
|---|---:|---|
| Python/project tests | 1,930 passed | Large positive and negative implementation surface reproduced |
| Skipped tests | 174 | Optional/environment-dependent behavior remains unexecuted |
| Deselected tests | 10 | Not part of the controlled run |
| Conformance checks | 9 passed, 0 failed | Required available profiles passed |
| Optional conformance | 2 skipped | Cedar-dependent checks were unavailable |
| External Rekor v2 compatibility | Failed | Official-shaped response raised an `AttributeError` |

The high pass count is evidence for the repository's internally asserted behavior. It is not by
itself evidence that a mocked third-party protocol is represented correctly.

## Implemented surface

| Layer | Pinned implementation | Warrantor relevance |
|---|---|---|
| History integrity | SHA3-linked event history | Useful W1 tamper-evidence primitive; not population completeness |
| Signatures | Ed25519 and ML-DSA paths | Crypto-agility comparator; requires key/authority profile |
| Portable receipt | COSE-based receipt | Useful constrained-format interoperability option |
| Time | RFC 3161 material | Appropriate separation from Rekor v2 `integrated_time` |
| Set proof | Merkle inclusion material | Proves membership only under a trusted root/checkpoint |
| Verification | Standalone verifier | Strong pattern for relying-party independence |
| Policy integration | Adapters including optional Cedar | Useful W4 integration model; two Cedar checks skipped |
| Enforcement | Kernel barriers and framework hooks | Better than recorder-only claims, but complete mediation is unproved |
| Transparency | Nominal Rekor v2 backend | Protocol-incompatible at the reviewed commit |

## Rekor v2 incompatibility

The defect is a contract mismatch, not a minor field omission.

| Contract element | Official Rekor v2 | Aevum reviewed path |
|---|---|---|
| Endpoint | `/api/v2/log/entries` | Uses the v2 endpoint |
| Request top level | `hashedRekordRequestV002` wrapper | Sends v1 `kind`/`apiVersion` object |
| Digest | Binary value encoded for v2 schema | v1 hashedrekord representation |
| Signature/verifier | Required inside v0.0.2 request | Not represented as the v2 object expects |
| Response | Direct `TransparencyLogEntry` | Expects UUID-keyed v1 map |
| Verification | Signed checkpoint plus inclusion proof | Parses v1-style body fields |
| Time | Ignore zero `integrated_time`; use RFC 3161 | Documentation implies older integrated-time behavior |

The project's tests mock a v1-shaped response at the v2 URL, so they validate the same mistaken
assumption. A controlled response shaped like the official `TransparencyLogEntry` reached a code
path that treated a string as a mapping and raised `AttributeError: 'str' object has no attribute
'get'`.

This finding is bounded to the reviewed revision. It does not imply that the receipt, chain,
timestamp or non-Rekor verification paths failed.

## Guarantee boundary

| Property | Standing |
|---|---|
| Record-byte signature validity | Implemented and extensively tested |
| Local chain continuity | Implemented; depends on retained history and verifier input |
| Portable receipt verification | Implemented for available profiles |
| Trusted external time | Profile exists; live TSA interoperability not reproduced |
| Rekor v2 registration/proof | **Not interoperable as reviewed** |
| Signer authorization for the action | External policy and identity responsibility |
| Truth of recorded context/effect | Not established by signature or chain |
| Complete mediation | Not established across every process/network/tool path |
| Complete event population | Not established by a chain or inclusion proof |
| Independent operational assurance | No audit or production evidence located |

## Warrantor actions

### Adopt

- standalone verifier and offline-verification posture;
- explicit crypto-agility and receipt portability tests;
- hash-chain, timestamp and proof failure vectors;
- clear recorder-versus-enforcer boundary language; and
- adapter and barrier patterns as comparator inputs.

### Modify

- define a field-by-field Aevum-to-in-toto/Warrantor mapping with loss reporting;
- replace mocked Rekor shapes with fixtures derived from official v2 types;
- verify signed checkpoints, inclusion proofs, trusted log identity and RFC 3161 time separately;
- exercise optional policy adapters and failure paths; and
- add independent receiver/gateway corroboration where the recorder can be bypassed or lie.

### Reject

- calling the reviewed Rekor path v2-conformant;
- using the green internal suite as external interoperability proof;
- treating a signed history as proof that every required event was captured; and
- positioning Aevum or Warrantor as non-bypassable without enumerated enforcement-point tests.

## Remaining gates

1. Run corrected requests against a pinned real Rekor v2 service and official test vectors.
2. Verify checkpoint signature, inclusion proof, TSA evidence and wrong-log rejection.
3. Execute Cedar-dependent conformance and adapter loss tests.
4. Add deletion, truncation, fork, replay, forged-context and bypass tests.
5. Obtain an independent security review and document maintainer-continuity risk.

## Promotion rationale

Aevum is promoted as **high-quality (82/100)**. Its open implementation, scale of reproduced tests,
technical breadth, candid boundaries and direct Warrantor relevance justify promotion. Solo
maintenance, absent independent assurance and the externally demonstrated Rekor mismatch prevent an
essential rating.

