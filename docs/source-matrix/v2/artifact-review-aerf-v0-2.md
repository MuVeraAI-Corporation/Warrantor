# AERF v0.2.0-draft.1 artifact review

Status: pinned artifact reproduced; supporting evidence, not a core-standard recommendation  
Reviewed: 2026-08-30  
Repository: <https://github.com/aerf-spec/aerf>  
Pinned commit: `59fce60fe30bde35318812f502a55ab4bace4650`  
Commit date: 2026-05-14  
Declared version in the specification/schema/verifier: `v0.2.0-draft.1`

## Decision

**Modify and interoperate.** Consume AERF's threat model, executable adversary cases and receipt
concepts, and provide a loss-reporting adapter. Do not adopt its JCS/Ed25519 wire format as the
Warrantor core. Warrantor should use DSSE plus an in-toto predicate as its default portable
attestation profile, optionally register it through SCITT/COSE Receipts, and keep AERF as a bounded
compatibility surface.

This is not a dismissal of AERF. It is meaningful prior art against broad W1/W2 absence claims and
one of the more honest early receipt projects reviewed. Its own tests demonstrate why receipt
authentication, policy correctness, enforcement, collection completeness and upstream-context truth
must remain separate properties.

## What exists at the pinned revision

The v0.2 draft adds materially stronger bindings than the earlier v0.1 description:

- a signature over the receipt;
- a parent-receipt signature;
- a PDP signature over the decision inputs and result;
- hashes of policy and context;
- allow/deny or in-policy result material;
- optional transparency-log inclusion material;
- impact tags;
- JSON Schema and verifier code;
- twelve conformance vectors;
- an explicit threat model; and
- an adversary simulator with eleven expected attack outcomes.

These are useful schema and conformance ideas. They are not proof that an external action was
mediated, executed as described, or recorded completely.

## Reproduction receipt

The checkout was tested without modifying the repository. The first environment attempt could not
create a standard Python virtual environment because the host lacks `ensurepip`; a uv-managed
environment was used instead. The first project test attempt also could not locate Go on the default
path; the installed Go binary was provided explicitly. These were environment-preparation issues,
not AERF failures.

The successful controlled run used the repository Make target with its declared Python dependency
installed and the available Go toolchain selected explicitly.

| Test surface | Collected | Result | Interpretation |
|---|---:|---:|---|
| Conformance vectors | 12 | 12 matched expected outcomes | Positive and negative verifier behavior reproduced |
| Receipt-schema cases | 16 | 16 matched expected outcomes | Includes one intentionally invalid case expected to fail |
| Adversary scenarios | 11 | 11 matched expected outcomes | Includes two intentionally accepted `KNOWN_LIMIT` outcomes |

The two accepted attacks are important evidence, not hidden failures:

1. **Tag stripping.** A compromised child can omit `impact_tags`, and the current verifier accepts
   the receipt. The documented mitigation is deployment policy at the PEP; format-level enforcement
   is deferred.
2. **Common-mode poisoned context.** If upstream components consistently provide the same false
   context, each signer can honestly authenticate incorrect input. Composition and independent
   observation are still required.

## Guarantee boundary

| Property | Standing at the pinned revision |
|---|---|
| Receipt-byte integrity | Direct, subject to correct JCS and key handling |
| Parent-receipt binding | Direct v0.2 field/signature path |
| PDP-decision binding | Direct v0.2 signature and hash path |
| Context/policy content identity | Hash-bound; source truth is not established |
| Log inclusion | Optional proof carriage; log trust and completeness remain external |
| Replay resistance | Not general; replay is accepted for the EVIDENCE profile |
| Identity and key acquisition | Out of scope |
| Enforcement-before-execution | Not supplied by the receipt format |
| Complete mediation | Not supplied |
| Complete event population | Not supplied |
| Endpoint or signer honesty | Not supplied |
| Timestamp verification | RFC 3161 verification not implemented in the reviewed Go path |
| Multi-receipt chain verification | Not implemented in the reviewed Go path |

## Repository-version inconsistency

The project is not internally version-clean. At the pinned commit, the specification, schema,
changelog, threat model, verifier and vectors target `v0.2.0-draft.1`, while the top-level README and
several compliance documents still advertise `v0.1.0-draft.1`. This creates four risks:

- implementers can build against the wrong field set;
- evaluators can report conformance to an obsolete version;
- links and examples can silently mix incompatible semantics; and
- Warrantor cannot safely claim adapter conformance without pinning the exact schema digest.

Any AERF adapter should require an explicit version, preserve the original bytes, record the schema
digest and reject ambiguous version claims.

## Warrantor implications

### Consume

- threat-model categories and known-limit discipline;
- parent and PDP decision linkage concepts;
- context/policy hash commitments;
- adversarial vectors for stripping, replay, tampering and common-mode error; and
- optional AERF import/export for ecosystem compatibility.

### Build

- a standards-aligned DSSE/in-toto predicate that covers prior authority, decision, execution and
  outcome as distinct typed claims;
- exact verified-byte and signer handling;
- authenticated expected-set/reconciliation evidence;
- receiver, gateway or TEE corroboration profiles;
- a key, time, revocation and trust-root profile; and
- explicit enforcement-point conformance separate from receipt validity.

### Reject

- describing AERF as a stable adopted standard;
- treating a signed receipt as proof of non-bypassable enforcement;
- treating context hashes as proof that the context is true; and
- counting AERF's log proof as evidence that omitted events do not exist.

## Promotion rationale

AERF is promoted as **supporting (78/100)** because metadata, free access, code, schemas, threat
boundaries and executable tests are verified. It is not high-quality or essential yet because the
draft is unstable, documentation is inconsistent, important verification functions are unfinished,
and no independent security review, deployment or interoperability evidence was found.

