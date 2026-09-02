# Warrantor attestation and transparency substrate decision matrix

Status: normative substrate wave complete; implementation interoperability remains open  
Snapshot: 2026-08-30  
Primary scope: W1 Notary core, W2 evidence-before-commit and receipts, evaluation receipts,
confidential-computing attestation, runtime AIBOM and cross-language conformance

## Strong recommendation

Use a layered standards composition rather than choosing one format and claiming it supplies every
assurance property:

1. **DSSE v1.0.2** for the default portable authentication envelope.
2. **in-toto Attestation Framework v1.2** for subject binding and typed predicates.
3. **Every Eval Ever** for evaluation-result semantics and cross-harness normalization.
4. **RATS RFC 9334 roles plus EAT RFC 9711** for measured-execution evidence, appraisal and results.
5. **RATS CMW RFC 9999** for typed carriage of heterogeneous attestation artifacts.
6. **SCITT RFC 9943 plus COSE Receipts RFC 9942** as an optional registration/transparency profile.
7. **A Warrantor-owned authority, reconciliation and conformance layer** for the properties those
   standards deliberately do not supply.
8. **AERF compatibility**, not AERF as the canonical core.

No reviewed component establishes all of signer authenticity, prior authority, truthful execution,
complete mediation, accurate semantics, population completeness, freshness, non-equivocation and
enforcement. The architecture must represent each property and its evidence separately.

## Property map

| Property | DSSE | in-toto v1.2 | RATS/EAT | RATS CMW | SCITT/RFC 9942 | AERF v0.2 | Warrantor responsibility |
|---|---|---|---|---|---|---|---|
| Exact typed-payload authentication | **Direct** | Uses envelope | Profile-dependent | Optional protection | COSE statement/receipt | **Direct** | Select algorithms, keys and trust policy |
| Multi-signature envelope | **Direct** | Required by framework profile | COSE/JOSE profile-dependent | COSE/JWS option-dependent | COSE_Sign1 is single-signer | Not the central assurance model | Define threshold and role semantics |
| Subject/artifact binding | Payload-defined | **Direct digest subject** | Entity/claim profile | Opaque wrapper | Statement subject/profile | Receipt fields/hashes | Bind role and content type, not digest alone |
| Domain predicate semantics | No | **Direct extensibility** | Attestation claims | No semantic validation | Payload/profile-defined | Fixed receipt schema | Own authority/action/evaluation predicates where needed |
| Evaluation normalization | No | Generic predicate base | No | No | Content-agnostic | No | Consume EEE; measure conversion loss |
| Evidence versus appraisal result | No | Can model separately | **Direct role distinction** | **Direct type distinction** | Content-agnostic | Primarily receipt assertion | Preserve links and verifier inputs |
| Freshness | No | Predicate/profile-defined | Nonce/time/epoch model | Hosting profile | Receipt/statement profile; status external | Replay allowed in EVIDENCE; timestamp incomplete | Define nonce, time, max age and clock trust |
| Transparency/log inclusion | No | External | External | External | **Direct registered-history proof** | Optional proof carriage | Select trusted services and monitor them |
| Non-equivocation within a declared log | No | External | External | External | **Direct VDS property** | External log-dependent | Multi-service/auditor policy and fork handling |
| Statement truth | No | No | Depends on attester/verifier | No | Explicitly **not guaranteed** | No | Corroboration, appraisal and assurance case |
| Complete mediation | No | No | No | No | No | No | W3/W5 enforcement-point conformance |
| Enforcement-before-execution | No | No | Relying-party decision can gate access | No | Registration is not action gating | No | PEP transaction/state-machine design |
| Bundle/set completeness | No | Explicit gap | Composite appraisal helps but does not count all events | Collections require binding | Selective issuer submission allowed | No | Signed expected-set manifest and reconciliation |
| Key discovery and authority | Out of scope | External | Endorsement/profile-dependent | External | Discovery/authz/revocation partly external | Identity/key acquisition out of scope | W6 authority graph, credential and key lifecycle |
| Confidentiality/privacy | No | Storage/profile-dependent | Encryption/profile plus minimization | Protection/hosting-dependent | TS and metadata leakage risks | Not the complete privacy model | Selective disclosure, encryption and access policy |
| Cross-language conformance | Implementations exist | Go/Python/Rust/Java bindings | Multiple ecosystems | New standard, evidence pending | New standard, evidence pending | Python/Go surface | One normative corpus and differential testing |

## Guarantee vocabulary

Warrantor documentation and APIs should return typed facts rather than one overloaded `verified`
boolean:

| Fact | Minimum meaning | Forbidden inference |
|---|---|---|
| `envelope_signature_valid` | A configured verifier accepted a signature over exact typed bytes | The signer was authorized or honest |
| `credential_accepted` | The signer credential chained to a configured trust rule at a stated time | The signed claim is true |
| `predicate_schema_valid` | The verified payload conforms to the named schema/version | Required evidence is present or semantically correct |
| `authority_appraised` | A stated policy accepted the signer/principal/action/tenant/constraints | The action was mediated or executed |
| `attestation_evidence_valid` | Vendor/profile cryptography and freshness checks passed | The entity is trustworthy or uncompromised |
| `attestation_result_accepted` | A named verifier appraised evidence under a named policy/reference set | Every relying party should authorize the entity |
| `transparency_inclusion_valid` | A trusted service receipt proves registration in a named VDS state | Every required event was submitted or the statement is accurate |
| `sequence_consistent` | A declared VDS history is append-only/non-equivocating for the checked views | No undisclosed log or off-path action exists |
| `expected_set_reconciled` | All events expected by a named manifest/epoch were matched under stated rules | The manifest itself captured every real-world event |
| `enforcement_conformant` | Tested PEPs mediated the enumerated paths under the tested host/threat model | Arbitrary host compromise or unknown paths cannot bypass control |

## Envelope choice

### Default: DSSE

DSSE is the preferred default because it authenticates payload type and exact bytes, avoids
canonicalization and is directly aligned with in-toto and existing supply-chain ecosystems. Require:

- explicit payload type;
- verification before semantic parsing;
- exact verified-byte handoff;
- a trusted key/credential resolver that ignores `keyid` as an authority claim;
- algorithm and key-strength policy;
- signer-role and threshold policy;
- replay, expiry, revocation and supersession rules outside DSSE; and
- negative cross-language vectors.

### Alternate: COSE

COSE is appropriate for constrained environments, EAT, SCITT and compact binary operation. Do not
pretend that `COSE_Sign1` alone satisfies in-toto's multiple-signature envelope requirement. Define
whether the COSE object is an alternative Warrantor envelope, a SCITT re-envelope or a linked
registration artifact, and bind formats with a stable digest to prevent semantic drift.

### Reject: a third proprietary envelope

A new Warrantor signing envelope would duplicate solved cryptographic framing and increase:

- canonicalization and parser risk;
- key-management ambiguity;
- language-specific divergence;
- procurement objections;
- integration cost; and
- novelty claims that reviewers can easily disprove.

## Predicate composition

Use several linked, single-purpose predicates rather than one mutable super-record:

| Predicate | Producer | Core content | Required link |
|---|---|---|---|
| Authority mandate | Principal/authority service | principal, delegate, tenant, purpose, scope, constraints, expiry, delegation depth | request/action ID and policy version |
| Policy decision | PDP | verified request projection, decision, reason, policy/input digests | authority mandate and intended effect |
| Execution observation | PEP/gateway/receiver/TEE | exact request, environment, target, observed operation and timing | decision and effect identifier |
| Outcome/effect | Receiver or independently positioned observer | external result, resource mutation, status and error | execution observation |
| Evaluation record | Evaluator/harness adapter | EEE-compatible run/model/data/grader/result semantics and native-artifact digest | authority, target and native artifacts |
| Attestation evidence | Attester | EAT/vendor evidence and freshness | execution environment and challenge |
| Attestation result | Verifier | appraisal result, policy/reference/endorsement digests, limitations | exact evidence set |
| Registration receipt | Transparency Service | SCITT/RFC 9942 proof | exact statement digest and service epoch |
| Expected-set manifest | Independent or dual-controlled coordinator | expected producers, event IDs, ranges, epoch and closure rule | tenant/workflow/transaction epoch |
| Reconciliation result | Reconciler/auditor | matched, missing, duplicate, late, conflicting and unverifiable items | manifest and observed statement set |

This design allows a relying party to demand different assurance profiles without redefining core
semantics. A low-risk workflow may accept a producer DSSE statement. A high-consequence workflow can
require authority plus dual observation, EAT evidence/result, SCITT registration and successful
reconciliation.

## Completeness design

Neither in-toto Bundle nor SCITT solves population completeness:

- Bundle does not authenticate the collection as a whole.
- SCITT explicitly allows selective issuer submission.
- a valid inclusion proof says nothing about unsubmitted events;
- a producer can omit its own unfavorable evidence; and
- a gateway log cannot observe an unmediated network/process path.

The recommended minimum protocol is:

1. Open an epoch or transaction with a signed manifest that names required producer roles, expected
   identifiers/ranges and closure rules.
2. Each producer signs its own statements and preserves native bytes.
3. Independent observation is required where one producer can both act and self-report.
4. Statements may be registered with one or more transparency services.
5. At closure, a reconciler compares the manifest, producer sequences, receiver observations and log
   views.
6. The reconciler emits a signed result with explicit missing, duplicate, stale, conflicting and
   unverifiable categories.
7. Policy fails closed or degrades to a named assurance level when reconciliation is incomplete.

This still does not prove that the manifest captured every possible real-world path. W3/W5
containment and egress conformance must separately show that the enumerated enforcement points cover
the system under the stated host-compromise assumptions.

## Confidential-computing profile

Adopt RATS vocabulary and EAT claims, not a vendor-specific `trusted: true` field.

The verifier record should bind:

- evidence format/profile and exact bytes;
- nonce, timestamp or epoch mechanism and freshness result;
- target and attesting-environment identities;
- measured software/model/runtime digests;
- debug and security state where available;
- endorsements and their status;
- reference-value set and version;
- verifier identity and software digest;
- appraisal-policy digest and decision path;
- unsupported or unappraised claims;
- residual assurance limitations; and
- the relying party's separately recorded authorization decision.

An EAT signature alone must not be displayed as proof that a TEE ran the intended evaluator. The
profile must show what was measured, how it was appraised and which external inputs were bound.

## Interoperability plan

| Direction | Required behavior | Failure policy |
|---|---|---|
| Native harness → EEE | Preserve all representable run, target, dataset, grader, sample, metric and provenance fields | Emit field-coverage report; fail closed on unclassified loss |
| EEE → Warrantor predicate | Preserve EEE object and digest; add authority, signer, native artifact, validity and assurance links | Never rewrite source semantics silently |
| AERF → Warrantor | Preserve original bytes/version; map parent/PDP/context/policy/log fields | Reject ambiguous version or lost security-relevant fields |
| Warrantor DSSE → SCITT | Register exact statement or a digest-bound COSE representation | Record both formats and cross-format digest; prevent semantic reserialization drift |
| Vendor EAT → CMW | Preserve opaque evidence and precise media type/profile | Reject unknown critical types and unprotected collections |
| CMW → Verifier graph | Separate evidence, endorsements, reference values, policy and results by role | Do not infer semantic validity from wrapper type |

## Prescriptive roadmap

### Adopt now

- DSSE v1.0.2 envelope rules and negative tests.
- in-toto v1.2 Statement and predicate model.
- RATS evidence/verifier/relying-party separation.
- EAT as the profile base for attestation claims.
- CMW for external heterogeneous attestation carriage.
- EEE for evaluation semantics.

### Build now

- Warrantor authority, action/effect and evaluation-assurance predicates.
- expected-set manifest and reconciliation predicates.
- credential, key-history, time, revocation and supersession policy.
- cross-language conformance corpus and differential verifier.
- AERF and SCITT bridges with loss/identity reports.
- enforcement-point conformance that proves where receipts are obligatorily emitted.

### Pilot

- private and public SCITT registration profiles;
- a pinned Rekor v2 profile with signed-checkpoint, inclusion-proof and RFC 3161 verification;
- a supported SPIRE deployment with real native or Envoy mTLS, credential rotation and receipt-bound validation evidence;
- independent receiver/gateway corroboration;
- one hardware-neutral EAT appraisal profile with at least two vendor adapters; and
- Inspect → EEE → Warrantor → SCITT end-to-end evaluation evidence.

### Defer

- a new VDS registration until an existing registered structure is shown insufficient;
- mandatory TEE use for every action or evaluation;
- a Warrantor-operated public transparency service before privacy, cost and governance are measured;
- AERF as the canonical format while its draft and documentation remain inconsistent; and
- novelty claims about signed evaluation or receipt formats.

### Reject

- a proprietary signing envelope;
- a single `verified` boolean crossing envelope, semantics, appraisal and completeness;
- claims that a signature proves execution;
- claims that log inclusion proves no omitted event;
- claims that EAT or TEE branding proves trustworthiness; and
- silent cross-format conversion.
- the bundled Rekor v1.3.6 stack as a Rekor v2 or production trust anchor; and
- treating a SPIFFE ID string, one-shot SVID fetch or current Helm init container as evidence of live credential validation or mutual TLS.

## Remaining evidence gates

- Reproduce at least two independent DSSE/in-toto verifier implementations against one Warrantor
  negative corpus.
- Run a real Inspect → EEE → Warrantor conversion and publish field-level loss.
- Implement deletion, replay, injection and split-view tests for authenticated-set and SCITT layers.
- Verify SCITT reference implementations and their key/status/privacy operations at pinned versions.
- Test at least two EAT ecosystems and one CMW implementation; no cross-vendor assurance-equivalence
  claim is currently justified.
- Model producer/receiver/log collusion and define the minimum independent quorum by consequence.
- Benchmark signing, verification, registration, reconciliation, storage and recovery costs.
- Replace and clean-room test the Rekor and SPIRE deployment profiles before depending on their assurance facts.
