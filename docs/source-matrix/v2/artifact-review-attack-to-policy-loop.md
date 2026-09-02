# Attack-to-policy feedback loop: prior art, implementation audit, and defensible product boundary

Status: primary-source review, external artifact reproduction, repository implementation audit, and product decision  
Snapshot: 2026-08-31  
Repository claim: CLM-0009  
Authoritative Warrantor requirement: `specs/warrantor-v4/13-attack-to-policy.md`  
Decision: **contradict the broad nonexistence claim; retain and implement a narrower evidence-bound lifecycle**

## Executive decision

The repository says that nothing ties a successful evaluation attack to a denial of the implicated
production action class. That universal statement is not defensible.

Several existing systems already close substantial parts of the loop:

- OWASP documents automated conversion of scanner findings into virtual patches and a governed
  virtual-patching lifecycle.
- Falco Talon maps runtime security findings to destructive or containing production actions.
- KubeArmor's Discovery Engine mines observed behavior into least-permissive system and network
  policy that can later be activated.
- Amazon Bedrock AgentCore generates candidate Cedar policy, validates it against gateway schemas,
  applies automated reasoning, consumes prompt-attack signals, supports log-only staging, and can
  require prior approval through temporal policy.
- CACAO and OpenC2 standardize machine-readable response workflows and actuator commands.
- Contemporary research translates high-level mitigation policy into executable API calls with
  LLM and retrieval assistance.

The correct conclusion is therefore two-part:

1. **Broad novelty is contradicted.** Automated finding-to-protection, event-to-response,
   behavior-to-policy, policy-to-action, candidate-policy generation, approval-aware control, and
   staged enforcement all have prior art.
2. **A narrower Warrantor composition remains differentiated in this review.** No reviewed system
   jointly requires a reproduced adversarial-evaluation receipt, narrow action-class candidate,
   per-rule approval receipt, immutable candidate-to-enforcement binding, monitor/canary/enforce
   progression, receipted rollback, expiry and renewal by reproduction, and automatic insertion of
   the finding into a regression corpus and safety-case defeater.

That second statement is a feature-bounded comparison, not proof that no equivalent exists. It must
remain conditional until the implementation passes independent conformance and a broader product
search stops changing the result.

## Recommended product decision

**Modify and build the Warrantor-specific composition; consume the response and policy substrates.**

- Consume OWASP's governed virtual-patching process and false-positive controls.
- Consume CACAO for portable response-playbook structure.
- Consume OpenC2 where an actuator supports it; do not extend OpenC2 into a decision engine.
- Add Falco Talon as a runtime-response adapter and comparator, not as the policy compiler.
- Use AuthZEN as the external PDP/PEP interface and Cedar, Rego, Cerbos, and OpenFGA as differential
  targets under explicit capability profiles.
- Treat AgentCore Policy as a strong managed-service comparator and possible deployment adapter.
- Build only Warrantor's evidence-bound state machine, typed intermediate rule representation,
  approval/rollout receipts, expiry, regression linkage, and cross-target conformance layer.

Do not market the capability as the first system to turn attacks into policy. A defensible claim is:

> Warrantor is designed to make an adversarial-evaluation finding a governed, expiring, narrowly
> scoped production-policy candidate whose approval, rollout, effect, rollback, and regression
> lineage are independently verifiable across policy engines.

Even this language should say "designed to" until the release gate near the end of this report is
green.

## Question tested

The broad repository wording and the normative R10 design are not the same claim.

| Layer | Question |
|---|---|
| Broad absence | Does any existing system convert a security finding, alert, or evaluated policy into a production protection or denial? |
| Agent-specific adjacency | Does a current agent platform convert natural-language or safety signals into enforceable tool policy? |
| R10 workflow | Does a system implement finding → triage → candidate → approval → staged enforcement → rollback/expiry? |
| Evidence binding | Are the finding, candidate, approval, exact deployed rule, decision, forwarded operation, effect, and rollback cryptographically or otherwise tamper-evidently linked? |
| Learning closure | Does the finding automatically become a regression case and safety-case defeater? |
| Cross-stack assurance | Is semantic equivalence tested across multiple policy engines and enforcement points? |

Prior art answers the first three questions substantially. The reviewed material does not answer the
last three as a complete composition.

## Method and evidence standard

This wave used four evidence classes:

1. normative specifications and government guidance;
2. official current product documentation;
3. open-source implementations pinned to a reviewed revision;
4. academic research with freely accessible full text.

The review deliberately searched for disconfirming evidence in virtual patching, SOAR, security
orchestration, runtime response, behavior-based policy generation, natural-language policy
generation, policy-to-API translation, and agent gateway enforcement. Search failure was not treated
as evidence of nonexistence.

For code artifacts, documentation claims were separated from reproduced observations. A passing
native suite is not proof of safe response semantics; a failing environmental integration test is
not automatically a product defect. Every reproduced result below states the boundary.

## What R10 actually requires

The authoritative Warrantor specification defines a materially stronger lifecycle than the sentence
in the portfolio document.

### Intake and triage

A candidate may originate from an evaluation receipt, but the triage decision must establish:

- reproduction or a bounded stochastic reproduction distribution;
- elicitation method and measured noise floor;
- a specific implicated action class;
- novelty relative to existing controls;
- sufficient evidence for an approver to understand the failure.

An isolated model refusal or judge score is not enough. The finding must be tied to an authority,
decision, operation, and observed or credibly simulated effect.

### Narrow candidate generation

The generated rule must use the narrowest justified scope, such as:

- tool or endpoint;
- parameter predicate;
- action class;
- model, adapter, or runtime digest;
- authority and delegation context;
- tenant, environment, region, or data classification where relevant.

The generator may propose a tightening. It must not silently deploy it, broaden the scope, or invent
an allow rule.

### Approval

- A monitor-only rule may be automatically staged under bounded policy.
- A production deny requires an approval receipt.
- Approval is per rule, not a blanket trust decision for a generator or source.
- The approver must see the evaluation digest, reproduction evidence, elicitation method, noise
  floor, scope, predicted utility loss, conflict analysis, expiry, and rollout plan.
- Approval identity, authority, time, decision, candidate digest, and policy revision must be bound
  in durable evidence.

### Rollout and rollback

The intended progression is:

`candidate → monitor → canary → enforce → retain, rescope, rollback, expire, or supersede`

The system must measure overmatching, undermatching, bypass, and utility loss at each stage. An
overbroad match requires rescoping. Rollback is a first-class receipted transition rather than a
manual configuration edit that erases history.

### Expiry and renewal

Every generated rule has an expiry. Renewal requires current reproduction rather than organizational
inertia. Model, tool, policy-schema, gateway, and threat changes can invalidate both the finding and
the rule.

### Regression and safety-case linkage

The accepted finding becomes an immutable regression-corpus case. A recurrence, bypass, or inability
to reproduce can invalidate the corresponding safety assertion. This is the most important seam that
is absent from the reviewed operational response products.

## Prior-art map

| Source | Input | Transformation | Production effect | Human/staging control | Durable evidence | R10 boundary |
|---|---|---|---|---|---|---|
| OWASP Virtual Patching | Scanner/vulnerability data | XML finding to virtual patch plus governed lifecycle | WAF/security-layer block | Preparation, analysis, testing, implementation, follow-up; pre-authorization patterns | Rule and ticket identifiers; implementation-dependent | Directly contradicts broad absence; not agent-eval receipt or cross-stack lineage |
| Falco Talon | Falco event | Rule/event match to ordered response actions | Delete/terminate/drain/network-policy/cloud function and more | Per-rule dry run; configured rules | Logs, metrics, traces, outputs; no signed approval chain | Direct event-to-production response; no candidate synthesis or regression closure |
| KubeArmor Discovery Engine | Runtime behavior/logs | Least-permissive system/network policy mining | KubeArmor/CNI enforcement after activation | Inactive-to-active policy state in associated tooling | Product/database state; no reviewed receipt chain | Behavior-to-policy prior art, not adversarial finding-to-deny |
| AWS AgentCore Policy | Natural-language rule and live guardrail/history signals | Candidate Cedar/Dogwood generation, validation, reasoning | Gateway permit/forbid/output suppression | log-only mode; temporal prior-approval rules | CloudWatch decision logs; vendor-managed | Strong agent-specific adjacency; no reviewed finding/reproduction/expiry/regression chain |
| CACAO 2.0 | Event, observation, incident, or operator trigger | Structured security playbook and workflow | Executor-dependent commands | Manual or automatic triggers; workflow controls | Versioned/revocable/signed playbook objects | Portable orchestration substrate, not safe rule inference |
| OpenC2 2.0 | Decision already made | Structured command and response | deny/contain/stop/remediate and other actuator actions | Authorization assumed external | Request/command identifiers and responses | Actuator wire format; analytics and decision explicitly outside scope |
| CACAO Roaster 1.3.0 | Analyst-authored playbook | Generate, validate, edit, sign, visualize, export | SOARCA integration executes playbook | Interactive authoring and validation | CACAO object/signature support | Maintained implementation evidence, not finding compiler |
| Fernández Saura et al. | High-level attack-mitigation policy | LLM decomposition and RAG-assisted API-call generation | Executable API calls | Research pipeline; no production governance shown | Experimental metrics | Policy-to-action synthesis; input is already policy, not a finding |
| NIST SP 800-61r3 | Incident/risk information | Governed incident-response process | Organization-specific containment/recovery | Governance and lifecycle guidance | Organization-specific records | High-authority process baseline, not a compiler |

## Library promotion and quality scores

Scores use the library's 100-point rubric: rigor 20, technical depth 15, authority 15, Warrantor
relevance 15, reproducibility 10, independence 10, originality 5, durability 5, and recency fitness
5. A high score means the source deserves decision weight within its category; it does not turn a
specification into an implementation or vendor documentation into independent proof.

| Source | Score | Band | Decisive strength | Score-limiting boundary |
|---|---:|---|---|---|
| CACAO Security Playbooks 2.0 | 91 | Essential | Deep stable OASIS orchestration specification with signatures, versioning and revocation | Older foundation; no finding inference or execution evidence |
| OpenC2 Language 2.0 | 88 | High-quality | Precise vendor-neutral response command/target/argument model | Draft/older stage; decision, authorization and effect proof excluded |
| NIST SP 800-61r3 | 87 | High-quality | Current final government incident-response and improvement baseline | Technology-neutral and United States-origin; indirect technical mechanics |
| Falco Talon | 86 | High-quality | Current open operational response engine; complete Go suite passed | No R10 candidate/approval/expiry/regression chain; real destructive actions not rerun |
| OWASP Virtual Patching | 85 | High-quality | Direct disconfirmation plus mature deployment/follow-up process | Guidance rather than controlled study; web/WAF focus |
| AWS AgentCore Policy | 82 | High-quality | Shipping agent-specific candidate generation, safety-signal policy, temporal approval and staging | First-party managed-service documentation; no independent service reproduction |
| CACAO Roaster 1.3.0 | 81 | High-quality | Maintained licensed implementation, archive and SOARCA integration | No full local UI/executor reproduction; indirect R10 scope |
| On Automating Security Policies with Contemporary LLMs | 71 | Supporting | Direct current policy-to-action synthesis experiment | Short preprint, no reproduced artifact or production governance |
| KubeArmor Discovery Engine | 70 | Supporting | Concrete behavior-to-policy source with meaningful negative test evidence | Stale revision, ambiguous license and non-green full suite |

The scoring deliberately avoids category distortion. NIST and OASIS score for authoritative durable
guidance; Falco and KubeArmor score for executable mechanics; AgentCore scores for authoritative
product contracts but loses independence/reproducibility points; the preprint remains useful without
being inflated to the same evidentiary level as a standard or reproduced system.

## Deep source reviews

### 1. OWASP Virtual Patching Cheat Sheet

Canonical source: [OWASP Virtual Patching Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Virtual_Patching_Cheat_Sheet.html)

Why it changes the claim:

- It defines virtual patching as a security enforcement layer that prevents and reports exploitation
  without changing application source.
- It explicitly describes automated conversion of vulnerability-scanner XML into protection rules.
- It identifies ZAP/ModSecurity CRS conversion, ThreadFix conversion, and commercial WAF imports as
  examples.
- It treats patch creation as a lifecycle including preparation, identification, analysis, creation,
  implementation/testing, and follow-up.

What Warrantor should adopt:

- emergency change pre-authorization with explicit limits;
- rule/ticket identifiers and traceability;
- positive-security and negative-security trade-off analysis;
- false-positive and false-negative testing;
- protection-level rather than exploit-string-only rules;
- follow-up and retirement after the underlying cause is fixed.

What it does not establish:

- agent-evaluation receipts;
- action-class semantics across tool gateways;
- per-rule cryptographic approval evidence;
- exact permit-to-forward/effect binding;
- automatic regression-corpus insertion.

Decision: **essential disconfirmation of broad novelty; adopt the lifecycle, not the WAF-specific data model.**

### 2. Falco Talon

Canonical source: [Falco Talon](https://github.com/falcosecurity/falco-talon)  
Reviewed revision: `19d3add6cec50ed8a050745d3e327a8d473104cb`  
Current reviewed release: v0.3.0, 2025-02-05

Falco Talon receives Falco or Falcosidekick events, matches event fields, rule names, and tags, and
runs ordered actions. The action catalog includes Kubernetes termination, deletion, drain, label,
execution, script, collection, and network-policy operations, Calico/Cilium policy actions, and
cloud functions. Per-rule dry-run support provides a basic staging control.

Reproduction receipt:

- the reviewed revision contained 112 tracked files and 14 Go test files;
- `go test ./...` passed under Go 1.25.0;
- several destructive-action packages had no package-local tests;
- source inspection found an `ignore_errors`/continuation telemetry assignment defect in the action
  construction path: the parsed value is assigned to a different local variable while the emitted
  metadata retains the default. The later execution loop reads the action fields directly, so this
  is bounded as a telemetry/representation defect rather than a demonstrated enforcement bypass.

R10 boundary:

- Rules are configured, not synthesized from an adversarial evaluation.
- There is no per-finding approval receipt or expiry/renewal requirement.
- Dry run is not the complete monitor/canary/enforce/rollback state machine.
- A handled alert is not automatically converted into a regression test.
- Logs and traces are not an independently verifiable chain from finding to external effect.

Decision: **adopt as an event/response adapter and conformance comparator; do not use it as R10's evidence or policy layer.**

### 3. KubeArmor / AccuKnox Discovery Engine

Canonical source: [Discovery Engine](https://github.com/accuknox/discovery-engine)  
Reviewed revision: `0b5b73425c5aec89b803e737b188b2a331d0e218`, 2023-09-12

Discovery Engine uses KubeArmor and Cilium visibility to infer least-permissive system and network
policy from observed workload behavior. Associated CLI and Terraform paths distinguish discovered
inactive policy from activation.

Reproduction receipt:

- the repository contained 412 tracked files and 25 Go test files;
- most packages passed under the controlled Go 1.25.0 run;
- cluster-oriented tests failed while trying to reach an absent Kubernetes API endpoint;
- `systempolicy.TestMergeSysPolicies` reproducibly panicked with an index-out-of-range after two
  policies were merged into one;
- no clear root open-source license was located during this review, while a functional `src/license`
  subsystem exists.

R10 boundary:

- the source signal is normal/observed behavior, not a successful adversarial evaluation;
- least-permissive allow-policy mining can encode poisoned or incomplete observation;
- activation and rollback evidence are not bound to an evaluation receipt;
- stale public source, ambiguous licensing, and the non-green suite preclude unchanged adoption.

Decision: **reference-only behavior-to-policy prior art; import poisoning and observation-coverage cases into the Warrantor corpus.**

### 4. Amazon Bedrock AgentCore Policy

Canonical source: [Policy in Amazon Bedrock AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html)

This is the strongest current agent-specific comparator. The service documents:

- interception of AgentCore Gateway tool requests outside agent code;
- deterministic deny-by-default Cedar policy and forbid-overrides-permit semantics;
- natural-language-to-Cedar candidate generation;
- schema validation and automated reasoning for overly permissive, overly restrictive, and
  unreachable policies;
- prompt-attack, content, and sensitive-information provider signals in policy;
- output suppression;
- session-aware Dogwood rules, prior-approval conditions, count/sum bounds, and time windows;
- `LOG_ONLY` staging before `ENFORCE` for temporal policy;
- session invalidation when temporal policy changes.

R10 boundary:

- policy authoring starts from a stated policy requirement, not a verified attack finding;
- guardrail scores can be policy inputs but are not reviewed as signed evaluation receipts;
- the documentation does not establish per-candidate approval receipts, expiry tied to reproduction,
  canary/rollback receipts, or regression-corpus closure;
- guarantees apply only to traffic routed through the attached AgentCore Gateway;
- logs are vendor-service evidence rather than a portable independently verifiable chain.

Decision: **high-priority comparator and optional deployment target; do not claim Warrantor invents candidate policy, safety-signal policy, approval-aware policy, or staged enforcement.**

### 5. OASIS CACAO Security Playbooks 2.0

Canonical source: [CACAO Security Playbooks Version 2.0](https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html)  
Status: Committee Specification 01, 2023-11-27  
Editors: Bret Jordan and Allan Thomson

CACAO defines portable playbooks, workflow steps, commands, authentication, agents, targets,
extensions, markings, versioning, revocation, and digital signatures. Workflows can be sequential,
parallel, conditional, temporal, manual, or automatically triggered.

Decision: **adopt as the external playbook representation where interoperability matters; keep R10 candidate safety, approval authority, deployment semantics, and evidence binding in a strict Warrantor profile.**

### 6. OASIS OpenC2 Language 2.0

Canonical source: [OpenC2 Language Specification Version 2.0](https://docs.oasis-open.org/openc2/oc2ls/v2.0/oc2ls-v2.0.html)  
Reviewed stage: Committee Specification Draft 02, 2024-05-15  
Editors: Duncan Sparrell, Toby Considine, and David Lemire

OpenC2 supplies a command/response language with actions including deny, contain, stop, cancel, and
remediate; targets; arguments for timing and duration; command identifiers; and response status.
Its conceptual model assumes that an event was detected, a decision was made, and action is
warranted. Sensing, analytics, decision-making, authentication, and authorization are outside the
language's core scope.

Decision: **consume as an actuator adapter, never cite it as evidence that safe finding-to-policy inference or approval exists.**

### 7. CACAO Roaster 1.3.0

Canonical source: [CACAO Roaster](https://github.com/opencybersecurityalliance/cacao-roaster)  
Release: 1.3.0, 2025-04-01  
Archive: [Zenodo DOI 10.5281/zenodo.20570338](https://doi.org/10.5281/zenodo.20570338)

Roaster is a maintained Apache-2.0 web application for generating, parsing, validating, editing,
signing, visualizing, and exporting CACAO 2.0 playbooks, with basic SOARCA execution integration.
It demonstrates that CACAO is more than a paper format.

Decision: **use its fixtures and validation behavior for CACAO interoperability; do not fork its user interface into the Warrantor core.**

### 8. On Automating Security Policies with Contemporary LLMs

Canonical source: [arXiv:2506.04838](https://arxiv.org/abs/2506.04838)  
Published: 2025-06-05

The paper decomposes high-level mitigation policy into tasks and uses retrieved tool/API
documentation to produce executable calls. The evaluation uses public STIX 2 CTI policy and Windows
API documentation and reports materially better F1 with retrieval than without it.

R10 boundary:

- the input is an already selected mitigation policy, not a raw adversarial finding;
- the paper is a short preprint with no production governance or independently reproduced artifact
  in this wave;
- generative translation adds prompt, retrieval, hallucination, and overbreadth risks;
- no permit/effect receipt or regression linkage is demonstrated.

Decision: **supporting prior art for policy-to-action synthesis; use as a baseline experiment, not a production dependency.**

### 9. NIST SP 800-61 Revision 3

Canonical source: [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)  
Published: April 2025  
DOI: `10.6028/NIST.SP.800-61r3`

NIST's incident-response guidance aligns preparation, detection, response, recovery, governance, and
continuous improvement with the Cybersecurity Framework 2.0. It is not a policy compiler, but it is
the authority baseline for treating automated denial as one governed response control rather than a
standalone AI feature.

Decision: **adopt for lifecycle governance and enterprise evidence mapping; do not infer technical guarantees from process conformity.**

## Current repository implementation audit

The untracked `build/exp-2026-08-31` tree now contains fragments labeled as the R10 loop. It is useful
implementation evidence, but it does not implement the normative lifecycle and must not be described
as complete.

### Candidate generation defects

TypeScript W3 candidate generation:

- `src/typescript/w3-operator/src/candidate-rule.ts` maps `findingClass` directly to
  `deny.<findingClass>`.
- It does not carry a resource, parameter predicate, model/runtime digest, authority context,
  evidence digest, reproduction, noise floor, conflict analysis, utility estimate, expiry, or
  rollout plan.
- It labels an unkeyed SHA-256 digest as `signature`.
- Severity, observation time, and evidence are ignored.
- The test checks only that the action starts with `deny.`; an empty evidence string still satisfies
  the tested contract.

Rust W3 and W5 candidate generation:

- both construct `resource: "*"` with no constraints;
- both ignore severity and evidence;
- both label a hash as a signature;
- both omit expiry, target profile, approval requirement, and regression identity;
- their tests assert only the `deny.` prefix.

This is the opposite of the R10 narrowest-scope requirement. An asymmetric generator that can only
produce denial still causes a denial-of-service failure when its scope is wildcard.

### Approval defects

The Rust W4 queue:

- stores mutable in-memory items;
- changes `Pending` to `Approved`;
- deliberately discards the approver while claiming the approver is recorded elsewhere;
- emits no receipt in this module;
- does not authenticate or authorize the approver;
- has no expiry enforcement, quorum, candidate digest, policy revision, evidence reference, or
  atomic connection to deployment;
- tests only state transition and double approval.

The TypeScript W4 queue adds quorum and TTL but still:

- uses in-memory maps and arrays;
- accepts arbitrary caller-supplied signer strings and timestamps;
- has no identity proof, authorization, signature, receipt, candidate digest, or deployment binding;
- overwrites duplicate request IDs on enqueue;
- allows repeated decisions to accumulate;
- evaluates expiry with local `Date.now()` while storing caller-supplied decision time.

The Python port uses the caller-supplied decision timestamp for expiry, creating cross-language
semantic inconsistency. Cross-language ports that agree on field names but disagree on time authority
do not provide conformance.

### Missing lifecycle

No integrated implementation was found for:

- triage and bounded reproduction;
- monitor → canary → enforce state transitions;
- immutable rule/policy revision binding;
- approver receipt and deployment receipt;
- effect measurement tied to the finding;
- receipted rollback;
- expiry plus renewal by reproduction;
- automatic regression-corpus insertion;
- safety-case defeater propagation.

The manifest maps G10 to F63-F67, but feature labels do not form a coherent end-to-end R10 path
across languages. For example, feature numbers and semantics differ between TypeScript and Rust, and
the candidate and approval modules are not wired into one durable transaction.

### Build and test standing

- The targeted W3 Rust crate did not compile because referenced shim modules were unresolved.
- Isolated W4 and W5 Rust copies failed on similar unresolved imports.
- The W3 TypeScript install encountered a registry integrity failure for `execa`; this is bounded as
  an environment/cache failure rather than a source defect.
- Isolated W4 TypeScript could not resolve its `workspace:*` contracts dependency outside a workspace.
- W5 TypeScript's test script targets `tests/*.test.ts`, but no matching test files were present.

These results do not prove every experimental package is broken. They do prove that the claimed R10
loop has not supplied a clean, integrated, reproducible release receipt.

## Threat model for finding-to-policy automation

### Finding poisoning

An attacker manipulates the evaluation environment, judge, evidence, sample selection, or telemetry
so a benign action class appears unsafe. A blind auto-deny path converts test poisoning into
production denial of service.

Required controls:

- signed evaluator and environment identity;
- runtime bill of materials;
- independent reproduction;
- held-out and defense-adaptive cases;
- provenance and contamination checks;
- two-person approval for high-blast-radius denial.

### Overgeneralization

One exploit succeeds for a specific tool, model, prompt, role, parameter, or data source. A generator
denies the entire action class, resource wildcard, or tenant population.

Required controls:

- minimal predicate synthesis;
- counterexample generation;
- negative and positive semantic fixtures;
- explicit blast-radius estimate;
- monitor/canary utility measurement;
- maximum-scope policy enforced independently of the generator.

### Under-generalization and bypass

An exploit-specific string or endpoint rule blocks the observed vector while mutations, aliases,
raw transport, redirects, retries, nested calls, or alternate effect channels succeed.

Required controls:

- invariant- and action-class-level representation;
- adaptive mutation and transfer tests;
- final-wire and external-effect observation;
- complete mediation inventory;
- route and transport conformance.

### Rule conflict and semantic drift

The same intermediate rule compiles differently under Cedar, Rego, Cerbos, OpenFGA, gateway
versions, or application wrappers.

Required controls:

- versioned target capability profiles;
- explicit lossy-compilation reports;
- differential allow/deny/unknown fixtures;
- policy and data revision evidence;
- fail-closed unsupported semantics.

### Approval compromise, replay, and confusion

An attacker forges a signer, replays an old approval, swaps the candidate after approval, or applies
approval to another environment.

Required controls:

- authenticated authorized signer identity;
- immutable candidate digest and exact target/environment binding;
- nonce, time, expiry, and one-shot consumption;
- quorum and separation of duties;
- append-only approval and deployment receipts.

### Stale or orphaned denial

A rule remains active after the vulnerable model, tool, or workflow is replaced, or its finding can
no longer be reproduced.

Required controls:

- mandatory expiry;
- owner and renewal policy;
- automatic reproduction schedule;
- stale-reference detection;
- safe expiration and explicit renewal receipt.

### Rollout, rollback, and split brain

Some enforcement points receive the rule while others do not; rollback removes only part of the
deployment; policy and data revisions disagree.

Required controls:

- intended enforcement-point set;
- prepare/commit or reconciled staged deployment;
- per-target acknowledgement and active digest;
- read-your-writes verification;
- rollback completeness and residual-effect checks.

### Availability and response abuse

The response service, approval queue, or policy distributor becomes unavailable, or a response
action recursively triggers more alerts and actions.

Required controls:

- bounded retry and deduplication;
- circuit breakers and recursion guards;
- emergency fail-mode policy per action class;
- queue/service SLOs;
- manual recovery and immutable incident history.

## Recommended reference state machine

```text
finding_received
  ├── rejected_invalid
  └── triage_pending
        ├── rejected_not_reproduced
        ├── rejected_duplicate
        ├── rejected_no_action_class
        └── candidate_generated
              ├── rejected_overbroad
              ├── candidate_monitor_only
              └── approval_pending
                    ├── rejected_by_approver
                    ├── expired_unapproved
                    └── approved
                          └── monitor
                                ├── rescope
                                ├── rollback
                                └── canary
                                      ├── rescope
                                      ├── rollback
                                      └── enforced
                                            ├── renewed_after_reproduction
                                            ├── superseded
                                            ├── rolled_back
                                            └── expired
```

Every arrow emits an append-only transition receipt. No component may infer a later state merely
because a mutable database row contains it.

## Minimum candidate-rule record

| Field | Requirement |
|---|---|
| `candidate_id` | Stable identifier |
| `finding_id` and `eval_receipt_digest` | Exact source evidence |
| `reproduction_receipt_refs` | Independent or bounded stochastic reproduction |
| `elicitation_method` and `noise_floor` | Evaluation validity context |
| `implicated_action_class` | Typed action, not a free-form label alone |
| `scope_predicate` | Tool/resource/parameters/principal/tenant/model/runtime constraints |
| `counterexamples` | Known safe calls that must remain allowed |
| `generation_method` | Deterministic template or generator/model/retrieval digest |
| `policy_ir` and `policy_ir_digest` | Canonical candidate semantics |
| `target_profiles` | Engine/version/capability expectations |
| `conflict_analysis` | Existing rule and precedence interactions |
| `predicted_security_gain` | Expected attack reduction and uncertainty |
| `predicted_utility_loss` | Expected legitimate-operation loss and uncertainty |
| `maximum_blast_radius` | Independently enforced bound |
| `approval_policy` | Required roles/quorum/separation |
| `rollout_plan` | Monitor/canary population and gates |
| `rollback_plan` | Trigger, mechanism, owner, and time bound |
| `expires_at` | Mandatory; no indefinite generated rule |
| `regression_case_id` | Immutable corpus linkage |

## Receipt chain

The minimum independently verifiable chain is:

1. evaluation-run receipt;
2. finding/triage receipt;
3. candidate-generation receipt;
4. approval or rejection receipt;
5. compilation receipt per target;
6. monitor deployment receipt;
7. canary deployment and observation receipt;
8. enforcement deployment receipt;
9. decision/permit/forward/result/effect receipts for sampled or policy-required operations;
10. rollback, expiry, renewal, or supersession receipt;
11. regression-corpus inclusion and subsequent run receipts.

Each receipt must bind its input digests, output digest, actor/workload identity, authority, time,
toolchain/runtime bill of materials, target/environment, and predecessor transition.

## Acceptance metrics

Security metrics:

- finding precision and independently reproduced rate;
- residual attack success after monitor/canary/enforcement;
- adaptive and repeated-attempt attack success;
- scope undermatch and bypass rate;
- cross-transport and cross-engine transfer;
- recurrence rate for accepted findings;
- time from valid finding to monitor, canary, and enforce.

Utility and safety metrics:

- safe-call false denial rate;
- semantic task utility before and after the rule;
- overmatch rate by action, tenant, model, and target;
- canary incident count and severity;
- approval disagreement and rescope rate;
- rollback trigger precision;
- time to safe rollback and residual active-target count.

Evidence and operations metrics:

- percentage of transitions with valid receipts;
- intended-versus-observed deployment-set reconciliation;
- policy/data revision consistency;
- expired-rule cleanup latency;
- renewal reproduction success;
- cross-PDP semantic agreement;
- missing decision/forward/result/effect events;
- approval queue latency and emergency-path usage.

Do not optimize only attack reduction. A system that blocks every action has perfect attack
prevention and zero enterprise utility.

## Build, consume, modify, reject

| Element | Decision | Why |
|---|---|---|
| Virtual-patching governance | Adopt | Mature lifecycle and failure analysis already exist |
| CACAO playbook schema | Adopt/profile | Portable workflow representation; add strict Warrantor evidence fields |
| OpenC2 command language | Adopt where supported | Avoid inventing actuator verbs and response shapes |
| Falco Talon action adapters | Modify/integrate | Useful production-response path; needs exact operation/effect receipts and Warrantor policy gate |
| KubeArmor behavior mining | Reference-only | Valuable comparator; poisoning, coverage, suite, freshness, and license concerns |
| AgentCore Policy | Monitor/adapt | Strong managed target and comparator; vendor and gateway boundary remain |
| LLM policy generation | Constrained experiment | Candidate only; independently cap scope and require deterministic validation |
| Warrantor evidence-bound state machine | Build | Reviewed sources do not supply the complete composition |
| Warrantor typed policy IR and target profiles | Build | Needed for semantic loss reporting and cross-stack conformance |
| Home-grown generic SOAR or envelope | Reject | CACAO/OpenC2 and DSSE/in-toto already cover those layers |
| Automatic production deny without approval | Reject | Converts evaluator/generator compromise into production denial of service |

## Implementation roadmap

### P0: correct claims and stop unsafe convergence

1. Mark CLM-0009 contradicted at its current universal scope.
2. Replace every first/only/nonexistence statement with the feature-bounded residual claim.
3. Reject `resource: "*"` generated rules and unkeyed hashes labeled as signatures.
4. Prevent any experimental candidate or approval module from reaching production policy.
5. Freeze canonical finding, candidate, approval, deployment, rollback, and regression records.

### P1: one safe vertical slice

1. Use one deterministic evaluation finding with a directly observed effect.
2. Generate one parameter-bounded monitor rule without an LLM.
3. Compile it to two policy targets with explicit profiles.
4. issue a signed approval receipt for the exact candidate digest.
5. deploy monitor, canary, and enforce under a reconciled state machine.
6. demonstrate rollback and expiry.
7. prove the case is automatically rerun in the regression corpus.

### P2: adversarial and failure conformance

Add release-blocking vectors for:

- finding/evidence substitution;
- empty evidence and non-reproduction;
- wildcard or overbroad scope;
- safe-counterexample denial;
- candidate mutation after approval;
- signer spoofing, replay, duplicate approval, and expired approval;
- target semantic mismatch;
- partial deployment and split-brain rollback;
- alternate transport and direct-call bypass;
- stale model/tool/policy revision;
- recursive response action;
- omitted regression insertion;
- missing or forged effect evidence.

### P3: interoperability and research

1. Publish the Warrantor CACAO/OpenC2 profile and AuthZEN target profile.
2. Add Falco Talon and one managed-agent-policy adapter.
3. Run Cedar/Rego/Cerbos/OpenFGA differential tests.
4. Publish an anonymized corpus and evaluation protocol.
5. invite independent red-team and policy-engine implementations.

## Reading paths

### Executives and product leaders

1. Executive decision and prior-art map in this document.
2. OWASP virtual-patching lifecycle.
3. AWS AgentCore Policy product boundary.
4. Build/consume table and P0/P1 roadmap.

Decision question: fund the evidence-bound composition, not a generic automated-remediation claim.

### Security and platform architects

1. R10 exact requirements.
2. CACAO and OpenC2 specifications.
3. Falco Talon and AgentCore comparisons.
4. Threat model, state machine, record schema, and receipt chain.

Decision question: identify authoritative enforcement/effect points and failure consistency before
choosing policy engines.

### Engineers and implementers

1. Current repository implementation audit.
2. Falco Talon reproduction notes.
3. State machine and minimum record.
4. P1 vertical slice and P2 negative vectors.

Decision question: prove one safe end-to-end path before adding generative rule synthesis.

### Academic researchers

1. Fernández Saura et al. policy-to-action method.
2. Feature-level prior-art table.
3. Threat model and acceptance metrics.
4. Cross-engine and evidence-chain research questions below.

### Risk, audit, policy, and compliance teams

1. NIST SP 800-61r3.
2. OWASP lifecycle.
3. Approval, expiry, rollback, and evidence requirements.
4. Metrics and evidence limits.

### Marketing, partnerships, and content teams

1. Retired and approved claim language.
2. Comparator boundaries.
3. Content programme below.
4. Never reuse a finding count, vendor guarantee, or novelty statement without its scope.

## Academic programme

High-value research questions:

- How can a successful adversarial trace be generalized to the narrowest safe policy predicate?
- Can policy overbreadth be bounded using automatically generated safe counterexamples?
- How much semantic loss occurs when one attack-derived policy IR compiles to Cedar, Rego, Cerbos,
  OpenFGA, and gateway-native controls?
- Which receipt fields are necessary to detect candidate/approval/deployment substitution?
- How do monitor/canary observations change posterior confidence that a denial is safe?
- What is the optimal expiry/renewal policy under model, tool, and threat drift?
- How often do attack-derived rules create second-order workflow failures or route attackers to an
  alternate effect channel?
- Can a state-machine model refine to production transition receipts and reconciliation evidence?

Recommended experiment design:

- public training findings plus private held-out findings;
- blind candidate authorship for a subset;
- deterministic templates, constrained LLM, and analyst baselines;
- multiple policy engines and gateways;
- semantic safe/unsafe operation oracle;
- repeated and adaptive attacks;
- measured security, utility, latency, cost, and evidence completeness;
- independent reproduction of a preregistered subset.

## Content and whitepaper programme

Recommended evidence-led outputs:

1. **From Red-Team Finding to Production Rule Without Creating a Denial-of-Service Machine**
2. **Why Automated Remediation Is Prior Art—and What Verifiable Attack-to-Policy Still Adds**
3. **CACAO, OpenC2, AuthZEN, and Receipts: A Composable Response Stack for AI Agents**
4. **Monitor, Canary, Enforce, Expire: The Missing Lifecycle for Generated Security Policy**
5. **A Hash Is Not a Signature: Auditing Candidate-Rule Evidence**
6. **The Wildcard Denial Trap: Why Asymmetric Policy Generators Can Still Be Unsafe**
7. **AgentCore Policy Versus Warrantor: Managed Enforcement and Portable Evidence**
8. **Measuring Both Attack Reduction and Enterprise Utility in Policy Feedback Loops**

Every output should cite the prior art first and present Warrantor as a narrower interoperable
assurance composition.

## Claim disposition

### Retire

> No existing system converts a successful adversarial evaluation finding into a production denial
> policy for the implicated action class.

Reason: OWASP virtual patch generation alone contradicts the universal wording; Falco Talon,
behavior-to-policy mining, AgentCore candidate/guardrail policy, and policy-to-action synthesis add
independent pressure.

### Use internally as a hypothesis

> No reviewed system jointly binds a reproduced adversarial-evaluation finding to a narrowly scoped,
> per-rule-approved, staged, expiring, cross-stack denial and then binds that denial to rollback,
> observed effect, and regression-corpus evidence.

This is the current literature-review result, not a universal fact.

### Publish only after conformance

> Warrantor provides a verifiable attack-to-policy lifecycle that links evaluation evidence,
> approval, staged enforcement, effect, rollback, expiry, and regression across supported policy
> engines.

Required publication evidence:

- one released reference implementation;
- two independent policy targets;
- one independent producer or verifier;
- a public positive/negative conformance corpus;
- a clean integrated build and test receipt;
- demonstrated monitor/canary/enforce/rollback/expiry flow;
- field-level traceability from finding to regression rerun;
- published limitations and bypass boundary.

## Evidence limits and unresolved questions

- The search is broad but cannot prove universal absence of the complete residual composition.
- Falco Talon's suite passed, but the real Kubernetes/cloud response actions were not executed in a
  sacrificial cluster/account in this wave.
- Discovery Engine was mechanically inspected and tested, but its last public revision is old, its
  full cluster environment was unavailable, and licensing requires resolution.
- AgentCore evidence is vendor documentation; no independent managed-service experiment was run.
- CACAO Roaster was reviewed as maintained implementation evidence but not subjected to a full local
  browser/executor security test in this wave.
- The LLM policy paper's reported experiment was not independently rerun and no production safety
  conclusion follows from its metrics.
- The repository experimental tree is untracked and may change; this audit records the 2026-08-31
  snapshot only.

Next bounded searches should test patents, commercial SOAR/RASP products with evaluation imports,
attack-informed policy mining, cloud WAF/EDR automated mitigation, and academic systems that couple
red-team outputs to guardrail synthesis. They should compare exact features rather than search only
for the phrase "attack-to-policy."

## Primary sources

- [OWASP Virtual Patching Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Virtual_Patching_Cheat_Sheet.html)
- [Falco Talon source](https://github.com/falcosecurity/falco-talon)
- [Falco Talon documentation](https://falco-talon.github.io/docs/)
- [KubeArmor / AccuKnox Discovery Engine](https://github.com/accuknox/discovery-engine)
- [Amazon Bedrock AgentCore Policy](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html)
- [AgentCore temporal policy](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-temporal.html)
- [AgentCore policy generation validation](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-generation-validation.html)
- [CACAO Security Playbooks Version 2.0](https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html)
- [OpenC2 Language Specification Version 2.0](https://docs.oasis-open.org/openc2/oc2ls/v2.0/oc2ls-v2.0.html)
- [CACAO Roaster](https://github.com/opencybersecurityalliance/cacao-roaster)
- [On Automating Security Policies with Contemporary LLMs](https://arxiv.org/abs/2506.04838)
- [NIST SP 800-61 Revision 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
