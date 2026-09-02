# SentinelAgent artifact and formal-assurance review

Status: pinned artifact reproduced; useful W6 prior art retained; broad runtime and proof claims bounded  
Reviewed: 2026-08-30  
Paper: <https://arxiv.org/abs/2604.02767>  
Repository: <https://github.com/ksrpatil/sentinelagent>  
Pinned commit: b7b1add07b7485e99aa3b91882a3f8f879f2e357  
Pinned commit date: 2026-04-02T21:56:01-07:00  
License: MIT  
TLA+ tools: official tla2tools.jar v1.7.4, SHA-256
936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88

## Decision

**Retain SentinelAgent as supporting W6, invariant-corpus and formal-method prior art; do not
adopt the reviewed Delegation Authority Service as an enforcement boundary or describe its TLA+
model as an end-to-end proof.** The artifact is unusually valuable because its code, benchmark,
fine-tuning data, TLA+ specification and evaluation scripts are public and mostly executable. A
direct TLC run reproduced the headline generated-state count and found no violation of the six
encoded invariants. The deterministic benchmark and several robustness scripts also reproduced.

The stronger security interpretation does not survive artifact inspection. The TLA+ model proves
finite, transition-local subset and parent-link properties that are largely established by the only
issuance transition. It does not represent a real API call, output value, policy decision,
cryptographic hash, expiry clock, network, partition, persistence layer, independent enforcement
point or implementation correspondence. The Python prototype then violates several properties that
a reader could reasonably infer from the paper's labels: output authority is not signed; API and
output checks continue after token expiry; output tags are pooled across scopes; empty output tags
pass; a missing parent silently yields an incomplete chain; and anyone holding a token identifier
can request another delegation because the HTTP endpoint has no caller authentication or proof of
possession.

The empirical headline also depends on the chosen evaluation path. The static 516-scenario
benchmark reproduced 100% attack detection and 0% false positives, but the repository's actual
sentence-transformer workflow evaluation reproduced only 77.8% accuracy, detected none of four
malicious delegation intents and falsely blocked two of 23 benign steps. The five-fold NLI
fine-tuning run was substantially better and close to the paper's malicious-recall claim, but still
produced a 12.3% benign false-positive rate. These results establish an interesting research
prototype, not a production authorization guarantee.

Warrantor should consume the formalization discipline and negative vectors, then require signed
immutable authority, authenticated delegation, scope-specific output enforcement, expiry at every
decision, complete chain validation, durable revocation and proof-to-code conformance.

## Provenance and independence

The repository had 12 commits at the pinned revision. All recorded author and committer identities
were the same account, and the implementation, benchmark, formal specification, red-team scripts
and documentation entered through the same project history. The file named
sentinelagent_redteam_independent.py is therefore a separate attack suite, not an independently
authored or independently published evaluation.

The README contains a paper badge linked to a TBD DOI and a BibTeX record naming IEEE
Transactions on Dependable and Secure Computing. The verified scholarly publication is the arXiv
preprint. Neither the paper source archive nor the bounded metadata search established an IEEE TDSC
acceptance. The source record therefore treats the venue as arXiv and assigns no peer-review credit.

Dependencies are expressed only as live lower bounds, including sentence-transformers>=5.0.0,
torch>=2.0.0, datasets>=4.0.0 and langchain>=1.0.0. There is no lock file, environment image,
software bill of materials or CI workflow at the pinned commit. Reproduction is consequently
commit-pinned but not dependency-bit-reproducible.

## Reproduction receipt

The public repository was cloned and pinned without modifying its source. Runs that needed third-
party packages used an isolated environment. Live paid-model integration was not executed because
it requires an external API key and would add provider drift rather than validate deterministic
enforcement. The TLA+ result was run directly through TLC rather than trusting the repository's
wrapper.

| Surface | Reproduced result | Assurance interpretation |
|---|---:|---|
| Python syntax compilation | Passed | All checked Python sources compiled |
| DelegationBench v4 | 516 scenarios; 150/150 attacks blocked; 0/366 benign false positives | Reproduces the authored deterministic benchmark, not independent external validity |
| Repository red team | P6 20/20; P7 10/10; 0/10 benign false positives | Exact manifest/tag test cases largely restate the enforcement tables |
| File labeled independent red team | 45 attack steps blocked; 0/14 benign false positives | Same-author suite; summary arithmetic is internally inconsistent |
| Robustness suite | 29/29 passed | Useful edge checks, but it expects some questionable semantics such as empty scope handling |
| Fault-tolerance simulation | All nine scenarios passed | Three in-process HMAC signers with shared state; not threshold cryptography, consensus or distributed failover |
| Executable meta-theorems | Five reported verified | Finite Python enumerations and set calculations, not mechanized proofs over the runtime |
| Static DAS/LLM scenarios | 5/5 attack steps blocked; 0/23 benign false positives | Authored static scenarios routed through DAS; no live model generation |
| Sentence-transformer simulation | 99/100; attack TPR 32/32; benign FPR 1/50 | One benign payment-routing case contradicted the zero-FPR headline |
| Sentence-transformer workflow evaluation | 21/27 correct; malicious TPR 0/4; benign FPR 2/23 | The four intended malicious delegation intents all passed the verifier |
| NLI baseline | 34.7% three-class accuracy; malicious TPR 1/60; benign FPR 2/130 | Untuned base model is not an adequate intent gate |
| Five-fold NLI fine-tuning | Accuracy 82.6% ± 2.1; malicious TPR 86.7% ± 4.1; benign FPR 12.3% ± 5.7; malicious F1 81.5% ± 4.7 | Close to the paper's recall/F1 range; operational false positives remain material |
| Full-data NLI training fit | 100% training accuracy/TPR; 0% training FPR | Training-set fit is not generalization evidence |
| Direct TLC v1.7.4 medium model | 2,744,789 generated; 1,145,473 distinct; depth 7; zero queued; no invariant violation | Reproduces bounded internal consistency of the specification, not the Python implementation |
| Live LangChain/provider run | Not executed | Requires external credentials and a mutable model/provider path |

The red-team script prints both “Blocked: 42/45 (93.3%)” and that all 45 attacks were blocked. Its
counter subtracts three benign chain steps from a total to which those steps were not added as
blocked. Inspection of the attack-step results supports 45 blocked attacks, but the published
summary calculation is defective. This matters because an assurance artifact should fail closed on
metric-accounting disagreement rather than select the more favorable number silently.

## TLA+ reproduction and actual proof boundary

The direct run used the repository's medium configuration: two agents, two scopes, one policy, two
API endpoints, one output tag and at most three tokens. TLC v1.7.4 on Java 21 completed in
approximately 15 seconds:

    2,744,789 states generated
    1,145,473 distinct states found
    0 states left on queue
    search depth 7
    no invariant violation reported

The README's “2.7M states” is the generated count, not the distinct-state count. Both should be
reported. The run is a genuine, reproducible bounded model check. The following table prevents its
labels from being mistaken for stronger properties.

| Label | What the TLA+ model actually checks | What it does not check |
|---|---|---|
| P1 authority narrowing | Every child tokenScope is a subset of its parent | Multiple principals, resource-owner/tenant policy, conflicts, runtime request context or identity authentication |
| P3 policy conjunction | Delegation copies the parent's policy set unchanged; the invariant checks parent subset of child | Policy evaluation, conjunction semantics, deny precedence, cross-language compilation or policy updates |
| P4 forensic reconstructibility | Parent is active and an integer equals parentHash + id + 1 | Cryptographic hashes/signatures, log append-only behavior, completeness, missing ancestors, key lifecycle or independent verification |
| P5 cascade containment | One atomic transition inserts the token and its finite descendants into a revoked set | Time to revoke, propagation, concurrent use, partitions, restart, stale sessions, in-flight effects or maximum residual actions |
| P6 scope-action binding | Child endpoint set is a subset of parent endpoint set | An API invocation variable, exact forwarded request, complete mediation, endpoint identity, arguments, responses or bypass paths |
| P7 output conformance | Child output-tag set is a subset of parent tag set | Output content, output operation, scope-specific tags, semantic validation, empty evidence, exfiltration or signed schema integrity |

Agents is quantified for root issuance but no issued token stores its agent, so agent identity does
not affect any invariant. P3 is true because the Delegate transition assigns the parent policy
unchanged. P6 and P7 are true because that same transition requires subset relationships before
assigning the child sets. P4 uses arithmetic rather than a cryptographic or append-only structure.
P5 performs finite closure in one transition. These are legitimate abstract design constraints, but
they do not establish a refinement mapping to the Python code or deployment.

The repository wrapper is not an adequate verification gate. It pipes TLC output through grep
without pipefail and prints “Properties verified” unconditionally. A TLC or Java failure can
therefore be obscured. Warrantor should invoke the checker directly, preserve its exit code and full
machine-readable output, and make the proof artifact a release input.

## Controlled implementation counterexamples

### 1. Unsigned output authority

DelegationToken._canonical() signs the identifier, principals, scope, API manifest, policy,
parent hash, expiry and intent. It omits output_schema, even though check_output() treats that
field as authoritative. Mutating the schema after issuance leaves the original HMAC valid and lets
the attacker add a previously forbidden output tag:

    OUTPUT_SCHEMA_SIGNATURE signature_valid=True signature_unchanged=True attacker_tag_allowed=True

This directly breaks the binding readers could infer from P7. The TLA+ model represents
tokenOutput as state updated only through trusted transitions, so it cannot reveal the Python
omission.

### 2. Expired-token enforcement bypass

delegate() checks the parent's expiry; check_api_call() and check_output() do not. A validly
signed token whose expiry has passed can continue to authorize API and output decisions while
further delegation is refused. A controlled token with a past, correctly signed expiry produced:

    EXPIRED_ENFORCEMENT api_allowed=True output_allowed=True delegation_allowed=False signature_valid=True

Expiry must be a common precondition at every authoritative decision, not only at child issuance.

### 3. Cross-scope output laundering

P6 returns when an operation appears in any scope element's manifest. P7 independently unions all
permitted output tags across every scope element. It does not bind the output check to the scope
element or exact API decision that produced the output. A call authorized by one scope can therefore
be followed by a tag authorized only under another scope:

    CROSS_SCOPE_OUTPUT api_allowed=True other_scope_tag_allowed=True

One authority decision must bind token, principal, scope, method, endpoint, canonical arguments,
response channel and output profile under one operation identifier.

### 4. Empty output evidence is accepted

Because the validator checks output_tags minus all_permitted, an empty caller-supplied set always
passes:

    EMPTY_OUTPUT allowed=True

The server trusts tags supplied by the caller rather than deriving them from output content or a
validated schema. Omission is therefore indistinguishable from compliant output.

### 5. Incomplete chain reconstruction is reported as success

reconstruct_chain() follows an in-memory hash index until a root or missing lookup. When an
ancestor mapping is absent, it returns the partial list without an error, completeness flag,
signature verification or parent-link validation:

    TRUNCATED_RECONSTRUCTION depth=1 reported_without_error=True

Forensic evidence needs an expected root/chain commitment and explicit incomplete/invalid states.
A list that stops early is not proof of reconstructibility.

### 6. Bearer token identifier authorizes delegation

The /delegate handler accepts a parent token identifier, destination, scope and intent. It has no
transport authentication, token proof of possession, request signature or check that the caller is
the parent token's destination principal. Knowledge of the short identifier is sufficient in the
reviewed service:

    BEARER_DELEGATION allowed=True status=OK

Token identifiers use only the first eight hexadecimal UUID characters, a 32-bit namespace. Even a
full random identifier would remain bearer-only without an authenticated holder binding.

## Additional trust and runtime boundaries

| Boundary | Finding | Required Warrantor control |
|---|---|---|
| Key custody | One hard-coded repository HMAC secret signs every token | External key provider, scoped asymmetric issuer identity, rotation and verifier trust policy |
| Token immutability | Python objects are mutable and several authoritative sets/dicts are stored by reference | Immutable canonical token bytes; sign every authority-bearing field; reject duplicate/unknown fields |
| Policy use | Policy identifiers are copied and signed but not consulted by API or output enforcement | Deterministic policy evaluation with version/hash, decision evidence and fail-closed error semantics |
| Mediation | /check_api returns a decision but does not forward or intercept the actual call | Non-bypassable tool and network enforcement that binds evaluated request to forwarded request |
| Output enforcement | Caller supplies abstract tags; no output payload/schema is validated | Validate actual bytes/structure/flow at the egress boundary; make omission fail closed |
| Audit | Mutable in-process list; no hash chain, signature, durable storage, witness or expected-set reconciliation | Authenticated append-only records, durable export, gap detection and independent reconciliation |
| Reconstruction | Does not verify signatures/hashes/completeness while walking | Verify every link and issuer, require expected root/length, return explicit invalid/incomplete outcomes |
| Revocation | Direct in-memory breadth-first mutation; no HTTP revocation endpoint or concurrency protocol | Authenticated revocation, durable consistent state, stale-work fencing and measured residual-action bound |
| Availability | One process and one memory image | Replication, crash recovery, partition semantics and explicit fail-closed availability policy |
| Fault tolerance | Three HMAC objects in one process with hard-coded keys and shared state | Real threshold protocol or independently administered quorum with adversarial network/fault tests |
| HTTP security | No application authentication or TLS configuration in the prototype | Mutual workload identity, authorization of every endpoint and replay-bound signed requests |
| Complete mediation | Agents may call tools or networks without consulting the decision endpoint | Tool, child-process and network interception with bypass tests |

## Empirical-evidence interpretation

The 516-scenario result is reproducible and still useful as a regression corpus. Its P6 and P7
decisions are primarily exact membership checks over manifests and tag sets authored with the test
cases. High accuracy therefore shows consistent table enforcement, not general semantic robustness.

The more realistic repository path uses a sentence-transformer for intent preservation. Two
different executions expose the central assurance distinction:

- the 100-scenario simulation achieved 32/32 malicious recall with one benign false positive;
- the ten-workflow evaluation detected 0/4 intended malicious delegation intents and produced two
  benign false positives among 23 benign steps.

Fine-tuning on the repository's 190 government examples improved five-fold malicious recall to
86.7% ± 4.1 and malicious F1 to 81.5% ± 4.7, close to the paper's reported range. The corresponding
12.3% ± 5.7 benign false-positive rate is material for production. The full-data 100% score is a
training-fit result and must not be reported as a held-out guarantee.

Warrantor should distinguish:

1. deterministic structural authorization, which can be fail closed and mechanically checked;
2. probabilistic intent classification, which needs calibrated abstention, appeal and human
   escalation; and
3. enforcement-path completeness, which neither classification accuracy nor a token model proves.

## Warrantor actions

### Adopt

- the seven-property decomposition as a useful requirements-review checklist, with property names
  rewritten to their exact enforceable semantics;
- the public benchmark scenarios as one seed for the invariant attack corpus;
- bounded TLA+ model checking for W6 state-machine design;
- separate empirical treatment of probabilistic intent preservation; and
- preservation of model-checker version, input, output and state counts as release evidence.

### Modify

- define W6 as the intersection of initiator, delegator, agent, task, resource owner, tenant,
  environment and current risk authority, with explicit deny/conflict semantics;
- make every token and decision immutable, canonical and signed over scope, policy, manifest,
  output contract, expiry, chain/root commitment and holder key;
- authenticate delegation through proof of possession and bind the caller to the parent token's
  authorized delegate;
- check expiry, revocation, signature, holder, policy version and request binding in one
  authoritative decision;
- bind P6 and P7 to one immutable operation rather than independently unioning authority;
- require nonempty, derived output evidence or a typed “no output” assertion;
- return complete, incomplete, invalid and unavailable chain states explicitly;
- model time, in-flight work, durable state, restart, partition and residual actions;
- introduce a refinement/conformance layer connecting TLA+ actions to production functions and
  canonical test vectors; and
- make live-model intent checks advisory or escalation-triggering unless their measured error cost
  supports fail-closed use.

### Reject

- the reviewed hard-coded shared-secret and eight-character bearer-token pattern;
- unsigned or mutable output authority;
- separate API and caller-tag checks as proof of output confinement;
- partial chain return as successful forensic reconstruction;
- same-author “independent” labeling;
- unconditional verification-success wrappers;
- generated-state counts presented without distinct-state and configuration details; and
- marketing the bounded model as proof of runtime, deployment or full Warrantor composition.

## Claim decisions

### CLM-0003 — W6 delegation-chain intersection

The claim remains **challenged**. SentinelAgent implements direct monotonic delegation-chain
narrowing and therefore defeats the unqualified statement that nobody builds the area. It does not
implement Warrantor's proposed exact multi-principal/resource-owner intersection, and its bearer
delegation and unsigned output authority sharply limit equivalence. The defensible novelty target is
the exact intersection algebra plus authenticated, non-bypassable, receipt-bound implementation.

### CLM-0005 — invariant attack corpus

The claim remains **researching**. DelegationBench and the attack scripts provide direct
authorization-substrate test cases, so “nothing tests an authority substrate” is too broad. Because
the benchmark and defense are co-designed and many expected results reduce to exact membership,
there is still room for an independent, capability-elicited, cross-implementation conformance
corpus with coverage and mutation criteria.

### CLM-0008 — machine-checked composition

The claim changes to **partially supported**. SentinelAgent is not contradictory evidence after
artifact inspection; it is a concrete example of the repository's “narrow slices” boundary. Its
six TLA+ invariants do not model the full runtime semantics, all twelve Warrantor invariants or their
cross-component composition. Universal absence still cannot be proven, and Warrantor's twelve
properties require exact formal statements before any novelty claim is publishable.

## Quality score

SentinelAgent is promoted as **supporting (72/100)**:

| Dimension | Score | Reason |
|---|---:|---|
| Rigor | 13/20 | Explicit properties, threat assumptions and several evaluations, offset by co-designed tests and overbroad labels |
| Technical depth | 13/15 | Working DAS, formal model, empirical intent path, fine-tuning and multiple test suites |
| Authority | 7/15 | Single-author arXiv preprint; IEEE venue claim not verified |
| Warrantor relevance | 15/15 | Direct W6, containment, attack-corpus and proof-boundary relevance |
| Reproducibility | 8/10 | Most deterministic, ML and TLC paths ran; dependencies are unlocked and live-provider path was excluded |
| Independence | 3/10 | Same author controls paper, artifact, benchmark and red teams |
| Originality | 4/5 | Useful delegation-calculus and combined assurance framing |
| Durability | 4/5 | MIT source and self-contained model; archival/maintenance depth is limited |
| Recency fitness | 5/5 | Published inside the main 2024–2026 window |

## Remaining gates

1. Obtain documentary evidence of any peer-reviewed venue or correct the repository badge and
   citation to arXiv.
2. Re-run ML evaluations from a generated lock file and publish seeds, fold assignments, model
   digest and exact environment.
3. Have an unrelated team create a blind attack corpus before seeing the decision tables.
4. Replace caller-supplied tags with output-payload/schema validation and repeat semantic
   exfiltration tests.
5. Add authenticated proof-of-possession delegation, signed output authority and expiry checks at
   every decision; preserve the six reproduced failures as regression tests.
6. Add TLC failure-injection tests for the wrapper and preserve full checker output as a signed
   artifact.
7. Define a refinement mapping or executable conformance bridge between each TLA+ transition and
   the production authorization functions.
8. Extend the model with multiple principals, policy conflicts, authenticated holders, time,
   in-flight actions, crash/restart, partition and receipt completeness before using it as Warrantor
   composition evidence.
