# in-toto Attestation Framework v1.2 artifact review

Status: stable specification reviewed; current multi-language implementation reproduced  
Reviewed: 2026-08-30  
Stable release: `v1.2.0`, released 2026-03-18  
Release commit: `df02077`  
Inspected implementation commit: `2dcd055e9f72e746687c306e35f4e59720ff45be`  
Inspected commit date: 2026-08-24

## Decision

**Adopt with a completeness layer.** Use DSSE plus the in-toto v1 Statement/predicate model as the
canonical Warrantor portable attestation base. Define Warrantor-specific typed predicates only for
semantics not already covered, preserve upstream predicate compatibility, and add an authenticated
expected-set manifest and reconciliation result. Do not claim that an in-toto Bundle proves the
complete population of receipts.

## Layer model

| Layer | What it contributes | What Warrantor must add or constrain |
|---|---|---|
| Envelope | Authentication and serialization; DSSE recommended; multiple signatures required by the framework profile | Trusted-key/identity policy, time, revocation, threshold semantics, exact verified-byte handoff |
| Statement | `_type`, subjects, `predicateType` and predicate binding | Subject role/content-type policy; authority and action identifiers |
| Predicate | URI-versioned domain semantics | Warrantor authority, evaluation, outcome, completeness and reconciliation schemas |
| Bundle | JSONL grouping of multiple envelopes | Set-level authentication, expected membership, monotonic update/replay rules and deletion detection |

The framework's layered design is precisely why Warrantor should consume it. A domain predicate can
evolve without defining a new signing envelope, and several independently signed claims can refer to
the same artifact. The same separation also prevents overclaiming: envelope validity does not imply
predicate truth, and per-item validity does not imply set completeness.

## v1.2 findings

- The current stable release is `v1.2.0`, not the `1.0` version previously named in the candidate
  ledger.
- DSSE remains the recommended envelope. Alternative envelopes must meet framework requirements,
  including multiple-signature support and authenticated payload typing.
- The Sigstore Bundle is not currently ITE-5-compliant because its relevant envelope path requires
  one signature; `COSE_Sign` can comply while `COSE_Sign1` alone cannot satisfy a multi-signature
  envelope requirement.
- A Statement binds subjects by digest and identifies predicate semantics by URI.
- Subject matching is explicitly digest-based regardless of content type. Warrantor must bind role
  and content expectations in policy or its predicate.
- Unknown fields are ignored under the extension model unless a predicate says otherwise. Critical
  Warrantor semantics therefore need versioned required fields or a profile that rejects unknown
  critical extensions.
- The Test Result predicate is a general pass/warn/fail and configuration/result model, not Every
  Eval Ever's cross-harness semantic schema and not proof that every expected test was routed.
- The Runtime Trace predicate can represent process, network and file observations, but the spec
  cautions that asynchronous observation such as eBPF cannot provide every guarantee of synchronous
  interposition such as ptrace.

## Bundle completeness failure model

The Bundle is a sequence of separately authenticated envelopes. It is not authenticated as a whole.
That permits several attacks even when every included attestation verifies:

- deletion of a valid but unfavorable attestation;
- replay of an obsolete otherwise valid attestation set;
- injection of an irrelevant or misleading attestation;
- presentation of only one producer's evidence when several were expected; and
- disagreement between a provider, receiver, gateway and auditor about how many events occurred.

Monotonic relying-party policy can reduce replay risk, but it does not establish the expected
population. Warrantor needs a signed manifest or epoch root listing expected statement identifiers,
producer roles and sequence bounds, plus a reconciliation result that identifies missing, duplicate,
late and conflicting records.

## Reproduction receipt

The current implementation commit was tested without modifying the repository.

| Language path | Result | Important boundary |
|---|---|---|
| Go | All discovered tests passed with the locally installed toolchain | Tested packages cover core v1 and provenance v1; several generated predicate packages have no tests |
| Rust | 12 unit tests and 4 documentation tests passed | Newer binding surface with smaller test depth than the mature Go path |
| Python | 12 tests passed in a uv-managed environment | The default mounted-environment capture path failed before collection; capture-disabled execution was used |

The initial direct Python invocation lacked the declared protobuf dependency. Installing the project
with its test extras resolved dependency setup. The default pytest capture mechanism then encountered
the same mounted-environment cleanup failure seen in another artifact review before collecting tests;
the controlled capture-disabled run passed all twelve collected Python tests. These environment
issues are preserved rather than converted into false project failures.

## Warrantor profile requirements

1. Require DSSE v1.0.2 or a separately versioned equivalent envelope profile.
2. Verify the envelope before parsing semantics and pass the exact verified payload bytes forward.
3. Bind signer identity to a credential and an explicit authority/appraisal role.
4. Bind subject digest, content type, role, tenant, action/evaluation identifier and predicate version.
5. Preserve native evidence and record any EEE conversion with field-coverage and loss results.
6. Link prior authority, policy decision, execution evidence, outcome and reviewer/appraisal result as
   distinct predicates rather than one overloaded record.
7. Add a signed expected-set manifest and reconciliation predicate.
8. Define replay, supersession, expiry, revocation and key-history semantics.
9. Make optional receiver, witness, gateway and TEE corroboration identities explicit.
10. Test deletion, obsolete-bundle replay, irrelevant injection, duplicate signatures, content-type
    confusion and unknown critical fields across all supported languages.

## Promotion rationale

The framework is promoted as **essential (94/100)** because stable current versioning, CNCF/in-toto
governance, normative depth, widespread ecosystem relevance, a broad predicate model, multi-language
bindings and successful reproduction make it the strongest reviewed consume target. The score does
not imply complete assurance: bundle membership, producer truth, enforcement and complete routing
remain outside its guarantees.

