# Machine-checked invariants decision matrix

Status: architecture gate; SentinelAgent and SAGA artifact evidence incorporated  
Snapshot: 2026-08-30

## Decision

**Build a Warrantor-owned composition specification and proof-to-code conformance layer; consume
existing provers, model checkers, policy engines and verified libraries.** Do not build a new theorem
prover, cryptographic primitive or general policy language. Do not label a property “machine
checked” unless the published evidence states the model, bound, assumptions, tool/version, checked
formula, result, code correspondence and deployment boundary.

SentinelAgent demonstrates why this distinction is necessary. Its direct TLC run is real and
reproducible, but its P3–P7 labels are much broader than the finite state represented. SAGA
demonstrates the complementary risk: symbolic secrecy/authentication analysis can coexist with an
implementation that overshoots a quota under concurrency and selects policy by list order. A proof
of model M is not evidence that implementation I refines M unless the correspondence is separately
defined and checked.

## Evidence ladder

| Level | Required evidence | Permitted wording | Insufficient substitutes |
|---|---|---|---|
| L0 prose requirement | Named property, threat, protected asset and failure consequence | “Requirement defined” | Architecture diagram or security adjective |
| L1 executable examples | Positive and negative examples with deterministic expected results | “Example suite passes” | Same-author demonstrations without negative cases |
| L2 property-based testing | Generators, shrinking, mutation score, seed and coverage model | “Tested over generated inputs under stated generators” | Raw case count or green unit tests |
| L3 bounded model checking | Formal state, transitions, invariant/temporal formula, configuration, tool/version, distinct/generated states and full result | “No counterexample within bound B for model M” | “Formally verified,” state count alone or a wrapper that hides failure |
| L4 symbolic protocol analysis | Roles, terms, equational theory, attacker model, secrecy/authentication queries and tool output | “Query Q holds in symbolic model M under attacker A” | Inference about state consistency, code safety or side channels |
| L5 deductive proof | Machine-checked theorem, assumptions, trusted computing base and proof object/source | “Theorem T is proven for formal object M” | Finite enumeration labeled a theorem |
| L6 refinement/conformance | Mapping from model actions/types to implementation operations plus generated vectors or verified extraction | “Implementation path I conforms to checked model M within stated mapping” | Similar names, hand-maintained comments or one happy-path trace |
| L7 deployment assurance | Attested binary/config, non-bypassable mediation, operational fault tests, monitoring and independent review | “Deployed profile D maintains measured guarantee G under stated faults” | Code proof, signature, log inclusion or benchmark accuracy alone |

Warrantor's external guarantee should name the highest completed level per property. Lower levels
remain useful and should not be inflated to a higher one.

## Property-to-model obligations

| Warrantor property family | Minimum formal state | Safety or liveness obligation | Mandatory counterexamples/faults | Runtime evidence |
|---|---|---|---|---|
| Prior authority | principal, delegate, resource owner, tenant, task, requested operation, context and credential status | Effective authority equals the documented intersection; no omitted principal can add permission | Missing principal, stale context, conflicting denies, confused deputy, holder substitution | Signed authority input set and decision receipt |
| Evidence before commit | immutable operation, decision, commit state, evidence state and idempotency key | No externally visible commit without required evidence; retry cannot duplicate commit | verifier outage, receipt-store outage, crash between decision/evidence/effect, duplicate/replay | Correlated predecision, commit and outcome evidence |
| Cascade containment | delegation graph, revocation state, in-flight operations, enforcement-point state and clock | No new effect after the defined bound; all descendants become unusable | partition, delayed event, stale worker, reconnect, restart, queued work | Measured stop latency and residual accepted/effected operations |
| Cross-stack policy | source policy, normalized IR, target policy, request universe and target decision | Source and target decisions are equivalent or every loss is explicit and fail closed | unsupported construct, version skew, unknown field, target outage, conflict-order permutation | Signed compilation/loss report and differential conformance result |
| Default-deny egress | process/tool/network path, destination identity, DNS/connection state and policy decision | Every external effect traverses an authoritative deny-by-default point | direct socket, child process, alternate resolver, stale connection, redirect, remote tool server | Tool and network enforcement receipts plus bypass-test result |
| Delegation intersection | chain, holder keys, authority sets, operation, output contract, expiry/revocation and policy versions | Child authority never exceeds the intersection at the decision instant | bearer reuse, unsigned field mutation, cross-scope laundering, expired token, missing ancestor | Proof-of-possession decision and complete verified chain |
| Receipt completeness | expected event set, observed set, sequence/epoch and producer/receiver/witness views | Missing, duplicate, reordered and selectively submitted events are detectable | log omission, split view, offline producer, clock skew, witness collusion | Reconciliation report with explicit incomplete/unavailable state |

## Source-specific guarantee boundaries

| Source | What is genuinely established | What remains unestablished | Warrantor use |
|---|---|---|---|
| SentinelAgent | TLC v1.7.4 completed 2,744,789 generated and 1,145,473 distinct states without violating six finite subset/link invariants | Runtime API/output semantics, cryptography, expiry/revocation timing, policy evaluation, complete reconstruction, code refinement and deployment | Keep as supporting prior art and negative-vector source; do not adopt the prototype |
| SAGA | Peer-reviewed agent authorization design; public protocol/implementation; selected symbolic secrecy/authentication properties | Atomic quota consumption, rule precedence, durable release consistency, complete mediation and proof-to-code correspondence | Essential W6 design baseline; replace enforcement path |
| Cedar | Formally specified deterministic policy language and validated implementation ecosystem | Warrantor's cross-engine equivalence, request completeness, PEP non-bypassability and distributed revocation | Consume as one policy target and verified library; prove only Warrantor seams |
| DSSE/in-toto | Typed signed statement/envelope behavior and subject/predicate conventions | Statement truth, prior authority, execution, routing and expected-set completeness | Consume as evidence substrate; model Warrantor authority/effect composition |
| TLA+ TLC | Exhaustive exploration of a finite configured state graph | Universal unbounded theorem, cryptographic security, implementation equivalence or deployment operation | Primary state-machine counterexample tool |
| ProVerif/Verifpal class | Symbolic protocol secrecy/authentication under declared equational/attacker assumptions | Memory/concurrency bugs, numeric quotas, side channels, policy semantics or real transport code | Use for key/token protocol slice only |
| Lean/Coq class | Deductive proofs and reusable formal libraries | Deployment correctness unless verified extraction/refinement and operational controls exist | Use for algebraic/core theorems only when proof maintenance is justified |

## Recommended Warrantor proof portfolio

### Build

1. One normative machine-readable catalogue of the twelve invariants with identifiers, formulas,
   threat assumptions, state ownership, enforcement points and failure meaning.
2. A TLA+ composition model for authority, operation, decision, evidence, effect, revocation,
   reconciliation and failover.
3. A W6 algebra specification for multi-principal intersection, attenuation, deny conflict,
   holder binding and chain completeness.
4. A trace/conformance format mapping model actions to canonical implementation events.
5. A generated invariant corpus that turns every counterexample into cross-language release tests.
6. Proof and model-check receipts containing source digest, tool image/digest, configuration,
   assumptions, formula identifiers, bounds, state counts, exit status and full output digest.

### Consume

- TLA+ and TLC for state exploration;
- an existing theorem prover and verified set/map/crypto libraries where deductive proof has clear
  value;
- ProVerif or an equivalent protocol analyzer for key exchange, token secrecy and authentication;
- Cedar and OPA/Rego as target engines rather than proving a new general policy language;
- DSSE/in-toto for proof-receipt packaging; and
- reproducible build/provenance tooling for the checker and verified artifacts.

### Defer

- full verified extraction of all Warrantor services;
- proofs of third-party cloud/provider internals;
- one monolithic theorem covering every operational control; and
- liveness guarantees that cannot yet be given a precise availability and partition policy.

### Reject

- “formally verified” without the exact formula and proof/model artifact;
- generated-state counts without distinct states, depth, configuration and checker result;
- a proof script that emits success after a failed checker pipeline;
- invariant names broader than their modeled variables/transitions;
- symbolic protocol results used as evidence of atomic storage or concurrency;
- executable finite enumeration called a proof without a formal theorem and trusted base;
- same-author tests labeled independent; and
- proof completion treated as evidence of complete mediation.

## Proof-to-code release gate

Every release claiming a checked invariant should fail unless all of the following are present:

1. invariant catalogue version and exact formula identifier;
2. source model digest and model-check configuration;
3. tool name, version, executable/container digest and trusted base;
4. full checker exit status and output, not grep-selected success lines;
5. generated and distinct state counts, depth, bound and symmetry/reduction settings where relevant;
6. assumption and out-of-model register;
7. model-action to implementation-event mapping;
8. positive, negative, mutation and concurrency vectors generated from the model or its
   counterexamples;
9. implementation build digest and configuration evaluated by the conformance suite;
10. explicit unavailable/incomplete result if any evidence is missing;
11. independent review for externally marketed high-assurance claims; and
12. signed, subject-bound proof receipt linked to the release artifact.

## Publication and product wording

| Evidence state | Approved phrasing | Prohibited phrasing |
|---|---|---|
| Bounded TLC pass only | “No counterexample was found for invariant X in model/configuration Y through bound Z.” | “Warrantor is formally verified.” |
| Symbolic protocol query | “Query Q holds under the stated symbolic attacker and cryptographic abstractions.” | “The deployed protocol cannot be compromised.” |
| Machine theorem only | “Theorem T is machine checked under assumptions A.” | “The service implementation is proven secure.” |
| Conformance plus artifact | “Build B passed vectors derived from model M at release R.” | “All implementations are equivalent.” |
| Deployment/fault evidence | “Profile D met measured bound G in environment E under fault set F.” | “Guaranteed everywhere” or “zero residual risk.” |

## Immediate repository actions

1. Freeze the exact twelve invariant statements before making a full-composition novelty claim.
2. Add the six SentinelAgent defects as mandatory W6 negative vectors: unsigned output authority,
   expiry bypass, cross-scope output laundering, empty evidence, truncated reconstruction and
   bearer delegation.
3. Add SAGA's quota-one/two-accept race and rule-order permutation as concurrency/policy vectors.
4. Require direct checker exit codes and full outputs; prohibit unconditional success wrappers.
5. Create the first vertical proof slice around W6 authorize-and-consume because it joins
   authority, revocation, durability, idempotency and receipt binding.
6. Commission an independent proof/model review only after the normative model and implementation
   mapping stop changing rapidly.
