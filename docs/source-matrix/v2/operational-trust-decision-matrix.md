# Operational trust decision matrix

Status: architecture decision input after Sigstore/Rekor, Aevum and SPIFFE/SPIRE review  
Snapshot: 2026-08-30

## Outcome

Warrantor should own the composition and assurance profile, not reimplement mature identity,
envelope, statement, timestamp or transparency substrates. The operational trust stack must expose
typed verification facts and fail independently at each layer.

| Layer | Preferred substrate | Warrantor-owned work | Current local standing | Decision |
|---|---|---|---|---|
| Release/source integrity | SLSA + GitHub/Sigstore attestations + TUF | Release policy, builder constraints, verification gate, root recovery | Partial; SLSA level overclaimed elsewhere | Adopt and correct claims |
| Signed evidence envelope | DSSE v1.0.2 | Key/credential authority, thresholds, time, revocation, typed result | Normative decision already frozen | Adopt |
| Statement/predicate model | in-toto v1.2 + EEE semantics | Authority, decision, execution, effect, assurance and reconciliation predicates | Multi-language in-toto reproduced | Adopt and extend |
| Recorder implementation | Aevum adapter or selected primitives | Loss reporting, authority/effect links, enforcement conformance | Aevum reproduced; Rekor adapter broken | Modify/pilot |
| Transparency | Rekor v2 for selected profiles | Log selection, checkpoint/proof verification, monitoring, privacy, expected-set reconciliation | Local stack is vulnerable v1.3.6, not v2 | Reject current; replace |
| Standards registration alternative | SCITT RFC 9943 + COSE Receipts RFC 9942 | Profile, privacy, key/status, completeness and operations | Normative review complete; implementation pending | Pilot |
| Trusted time | RFC 3161 TSA | TSA trust policy, nonce/digest binding, validation and availability behavior | Fragmented | Adopt as separate fact |
| Workload identity | SPIFFE | Agent/principal/authority model and receipt credential evidence | Standard reviewed | Adopt |
| Workload identity implementation | SPIRE upstream profile | Deployment conformance, authorization, HA/recovery, receipt binding | Current manifests fail validation/topology | Reject current; replace |
| Mutual TLS data plane | Native go-spiffe or defined Envoy/SDS | Peer authorization and initiating-principal preservation | Helm init fetch is not mTLS | Build explicit data plane |
| Agent authority | W6 delegation intersection | Mandates, attenuation, multi-principal intersection, limits and revocation bounds | Defensible Warrantor ownership if formalized | Build |
| Action policy | W4 compiler + consumed PDPs | Cross-stack semantic preservation and verified inputs | Researching | Build narrow layer |
| Complete mediation | W3/W5 conformance | Path inventory, bypass tests, failure state and residual exposure | Not supplied by identity/signature/log | Build and measure |
| Complete event set | Signed manifest + independent reconciliation | Expected producer/event set and missing/late/conflict semantics | No external substrate supplies it | Build |

## Typed assurance result

One `verified=true` flag is prohibited. A relying party should receive a structured result similar to:

| Fact | Producer/verifier | Required evidence | Independent failure |
|---|---|---|---|
| `envelope_signature_valid` | DSSE verifier | exact payload/type, signature, algorithm/key result | Yes |
| `credential_accepted` | PKI/SPIFFE verifier | exact SVID/cert, bundle, time, status and constraints | Yes |
| `authority_appraised` | W6/W4 | principal/delegate/action/context and policy digest | Yes |
| `timestamp_valid` | RFC 3161 verifier | token, TSA chain, nonce/digest and time result | Yes |
| `transparency_inclusion_valid` | Rekor/SCITT verifier | log ID, checkpoint, proof, root and entry digest | Yes |
| `sequence_consistent` | monitor | checkpoint history/witness evidence | Yes |
| `execution_observed` | PEP/receiver/TEE | request/effect binding and observer identity | Yes |
| `expected_set_reconciled` | independent reconciler | manifest and observed set with missing/conflict classes | Yes |
| `enforcement_conformant` | conformance runner | enumerated path, environment and bypass results | Yes |

No success in one row implies success in another.

## Product-profile options

### Profile A — portable baseline

- DSSE/in-toto statement;
- accepted enterprise key or SPIFFE credential;
- RFC 3161 time where time is material;
- no external transparency requirement;
- explicit `transparency_inclusion_valid = not_required`; and
- local expected-set reconciliation for multi-event workflows.

Use for private deployments where public metadata disclosure or log dependency is unacceptable.

### Profile B — enterprise high assurance

- Profile A;
- upstream SPIRE or approved managed identity;
- real native/Envoy mTLS with peer authorization;
- private or managed Rekor v2/SCITT registration;
- independent checkpoint monitoring;
- dual producer/receiver observation; and
- fail-closed expected-set reconciliation.

This is the preferred target for consequential production actions.

### Profile C — public-verifiability release

- SLSA/in-toto release provenance;
- Sigstore identity and public transparency;
- public checkpoint monitoring;
- published schemas, conformance corpus and verifier; and
- no confidential action content in the public log.

Use for Warrantor releases, policy/compiler artifacts and public benchmarks, not private agent prompts.

## Immediate priorities

### P0 — stop unsafe or misleading behavior

1. Quarantine the Rekor v1.3.6 compose stack and SPIRE manifests from supported deployment paths.
2. Remove “working Rekor v2,” “mTLS enabled,” and “SVID live/unrevoked” claims until the named gates pass.
3. Keep the Helm mTLS switch disabled and fail chart validation if users attempt the unsupported path.
4. Represent a SPIFFE ID and an SVID validation result as separate fields.

### P1 — establish interoperable trust plumbing

1. Implement official Rekor v2 fixtures and checkpoint/proof/TSA verification.
2. Adopt upstream SPIRE Helm/controller-manager topology with pinned digests.
3. Build the actual native or Envoy mTLS data plane and peer authorization.
4. Emit typed assurance results and preserve exact verified bytes.
5. Add Aevum/in-toto adapter loss reports and an authenticated expected-set manifest.

### P2 — prove operations and differentiators

1. Run split-view, deletion, replay, wrong-root, stale-credential and bypass corpora.
2. Rehearse trust-root/bundle rotation, compromise recovery, backup/restore and upgrades.
3. Benchmark sign, verify, timestamp, register, monitor, reconcile and mTLS rotation costs.
4. Publish the precise Warrantor-owned invariants and proof-to-code correspondence.

## Positioning correction

The defensible thesis is not “Warrantor invented signing, workload identity, receipts or
transparency.” It is:

> Warrantor composes existing identity, signed-statement, attestation, timestamp and transparency
> standards into a typed, testable agent-action assurance profile, while adding authority/effect
> binding, cross-stack enforcement conformance and authenticated expected-set reconciliation.

That claim is narrower, more credible and more valuable to enterprise architecture and audit teams.

