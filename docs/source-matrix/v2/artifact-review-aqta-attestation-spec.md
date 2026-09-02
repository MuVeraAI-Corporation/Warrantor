# Artifact review — Aqta ATTESTATION-v1 / ACTION-v1

Status: pinned first-party artifact reproduced; managed gateway not independently verified  
Review date: 2026-08-30  
Repository: `https://github.com/Aqta-ai/attestation-spec`  
Pinned commit: `9daac5dc7fb88ef626cfabb82d933972b5c5487a`  
Commit date: 2026-08-27  
Licenses: CC-BY-4.0 specification; Apache-2.0 code

## Decision

Use this repository as a mandatory conformance and trust-boundary comparator, not as Warrantor's
core receipt format. Its base engineering is reproducible and its limitations are unusually honest.
Its semantics remain materially weaker than Warrantor's objective: it signs a gateway assertion but
does not prove provider compute, evaluator/grader identity, execution outcome, verified agent or
reviewer authority, complete mediation or receipt-set completeness.

Library score: **77/100 — supporting**. The score rewards executable multi-language artifacts,
negative vectors and explicit threat boundaries. Vendor authorship, closed managed-gateway code,
low independent adoption evidence and limited assertion independence prevent promotion to
high-quality.

## Artifact inventory

The pinned checkout contained 164 non-Git files, including:

- stable ATTESTATION-v1 model-call decision and ACTION-v1 agent-action authorization specifications;
- a draft ACCEPT-v1 human acceptance/override/escalation specification;
- Python and TypeScript reference verifiers plus stand-alone reference issuers;
- 92 JSON vectors across attestation, action, acceptance and transparency directories;
- CI for Python 3.9–3.12, TypeScript, cross-language interop, conformance, differential fuzzing and
  action-profile sweeps;
- issuer-adversary, receipt-boundary, SCITT-relationship, security and conformance documents;
- an RFC 6962-style Merkle transparency implementation and vectors.

The repository explicitly excludes the managed Seal gateway. Statements about production request
placement, key custody, traffic coverage and operational behavior are therefore first-party claims,
not reproduced results.

## Reproduction record

| Check | Result | Interpretation |
|---|---:|---|
| Python verifier tests | **92 passed** | All locally exposed Python unit/vector tests passed under an isolated Python 3.13 environment |
| TypeScript build and tests | **29 passed** | Package built and action/envelope/receipt tests passed |
| Python issuer → TypeScript verifier | **Passed** | Basic pinned-key, tamper, wrong-key and integrity-only interop worked |
| Differential fuzz | **329 checks, 0 divergences** | Both implementations agreed across mutated encoding/structure cases exercised by the script |
| ACTION-v1 cross-implementation sweep | **Clean** | Valid/invalid action vectors, misuse cases, type probes and ATTESTATION regression vectors agreed |
| Generated base conformance report | **27/27 agree; 27/27 correct** | Stable ATTESTATION-v1 vector results matched both implementations |

The first attempt to create a system-Python virtual environment was unavailable because the host
lacked the distribution's `venv` support. Tests were rerun in an isolated environment provisioned
by the workspace toolchain; this is an environment condition, not an artifact failure.

## What the stable formats prove

### ATTESTATION-v1

The signature covers organization, request hash, named model, gateway outcome, policies, estimated
prevented cost, signer timestamp and key. With a pinned external issuer key it can establish:

- the trusted key holder signed exactly those canonical fields;
- no signed field changed after signing;
- the verifier applied the stable v1 schema and encoding rules.

It cannot establish:

- that the provider executed the named model;
- the evaluator, grader, rubric, dataset or complete prompt that produced an evaluation;
- that the issuer truthfully reported the gateway decision;
- that all calls traversed the gateway or all receipts were disclosed;
- external time, unless an independent timestamp or anchor is added.

### ACTION-v1

The record binds the issuer's allow/block decision to a declared tool and canonical argument hash,
plus an optional session/intent hash. It explicitly labels the agent identity as caller-asserted and
does not claim that an allowed action subsequently executed. This is a good assertion-provenance
practice and a critical limit: authorization evidence and outcome evidence are different artifacts.

### ACCEPT-v1 draft

The draft binds an issuer-recorded accept/override/escalate decision to the hash of an exact machine
record. It explicitly does not verify the named reviewer or their authority. The Python artifact
contains acceptance vectors, but the profile is draft and not yet a stable symmetric Python/
TypeScript conformance target. Warrantor should borrow the separation between machine output and
human decision while adding an optional independent reviewer credential or countersignature.

## Security-boundary findings

| Boundary | Aqta treatment | Warrantor consequence |
|---|---|---|
| Key substitution | External key pin required by default; embedded-key mode labeled untrusted | Preserve issuer key history and reject self-authenticating receipts |
| Canonicalization | Normative Unicode/number rules plus regression vectors | Use RFC 8785/DSSE but retain equivalent differential vectors |
| Profile confusion | Explicit profile selection and cross-profile rejection | Version every predicate/profile and test wrong-profile inputs |
| Issuer lies | Explicitly not solved by a signature | Add receiver, provider, TEE or auditor corroboration where consequence warrants it |
| Named provider compute | Explicitly not bound | Add measured runtime/attestation profile and distinguish asserted from measured model identity |
| Complete mediation | Gateway sees routed traffic only | Bind `enforcement_mode` and test bypass paths |
| Omission | Explicitly open | Reconcile against an independently produced inventory; do not call a Merkle log complete evidence |
| Equivocation/reordering | Transparency and history mechanisms partially address | Require monitored tree heads and define the observer population and timing bound |
| External outcome | ACTION record stops before execution | Link receiver or post-commit outcome evidence to the authorization record |
| Reviewer authority | ACCEPT records caller assertion only | Require credential-backed identity/authority before claiming accountable human acceptance |

## Important engineering defect history

The specification records cross-language defects that are directly relevant to Warrantor:

- Python and JavaScript disagree by default on non-ASCII escaping.
- Numeric forms such as integer-valued floats and small decimals can serialize differently.
- An earlier reference issuer produced receipts rejected by another published verifier until an
  adversarial cross-implementation sweep exposed the difference.
- A single happy-path interop fixture was insufficient; whole-vector sweeps and mutation tests were
  added.

Warrantor's use of JCS and DSSE avoids Aqta's custom numeric rules, but does not remove the need for
multi-language negative vectors around parsed number domains, duplicate keys, Unicode normalization,
unknown fields, profile confusion and algorithm/key identifiers.

## Build, consume and interoperability decision

### Adopt

- pinned-key-by-default verifier behavior;
- explicit integrity-only labeling;
- assertion-provenance tables;
- strict unknown-field and profile-confusion vectors;
- cross-language differential mutation and whole-corpus sweeps;
- separate authorization, outcome and human-acceptance artifacts.

### Interoperate or port selectively

- provide an import/verifier adapter if enterprise buyers already receive Aqta records;
- map ATTESTATION-v1 model-call decisions and ACTION-v1 authorization decisions into Warrantor
  evidence nodes without upgrading their guarantee;
- preserve original bytes, signer key/version and verification result so transformations are
  auditable.

### Do not adopt as core

- bare canonical JSON with an embedded issuer key rather than Warrantor's DSSE/in-toto base;
- signer-asserted model strings as runtime model evidence;
- gateway decisions as evaluation receipts;
- first-party production claims as independent proof;
- an issuer-local timestamp as trusted time;
- per-record validity as receipt-set completeness.

## Required Warrantor tests derived from this artifact

1. Receipt with an embedded attacker key but no externally trusted signer.
2. Unicode strings represented with different escapes or normalization forms.
3. Semantically equal numbers with different textual encodings at every supported language boundary.
4. Valid receipt presented to the wrong predicate/profile verifier.
5. Unknown field carrying security-relevant data that one implementation ignores.
6. Valid pre-action authorization with a mismatched post-action effect.
7. Correctly signed model name with a different runtime measurement.
8. Backdated receipt across signer-key rotation or revocation.
9. Selective receipt disclosure against a pinned tree head.
10. Complete-looking receipt set missing an event present in provider, receiver or billing evidence.
11. Acceptance record naming a reviewer without a verifiable identity/authority credential.
12. Lossy import adapter that drops policy, model, tool or provenance fields and must fail closed.

## Remaining gates

- Verify package-registry provenance and the published key-history mechanism across a real rotation.
- Obtain independent evidence of managed Seal gateway operation before treating production claims as
  more than vendor documentation.
- Measure verifier throughput and evidence size at representative Warrantor volumes.
- Test transparency split-view, stale tree head, anchoring outage and recovery.
- Re-run against future stable ACCEPT-v1 only after both independent language implementations and
  adversarial vectors are published.

