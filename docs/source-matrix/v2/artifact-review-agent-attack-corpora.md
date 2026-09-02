# Agent attack corpus and benchmark-integrity review

Status: full-text review and bounded artifact reproduction complete  
Review date: 2026-08-31  
Primary decision: consume the attacks and evaluation lessons, but build a Warrantor-specific, independent conformance profile rather than adopting any reviewed benchmark unchanged

## Executive decision

The repository's original statement that “nothing tests an authority substrate's invariants” is no longer defensible. SentinelAgent already provides an authored authorization-substrate benchmark, and this wave adds a dense body of adjacent, high-quality work across taint vulnerabilities, agent workflow attacks, tool-selection poisoning, cross-tool control-flow attacks, adaptive hijacking evaluation and MCP operational security.

None of the reviewed sources, however, supplies the exact asset Warrantor needs: an independently authored, capability-elicited, cross-implementation corpus that asserts authority-substrate invariants at the policy decision point, policy enforcement point, final wire operation and observed effect. That narrower opportunity remains open.

The recommended posture is therefore:

1. **Retire the universal absence claim.** Replace it with a precise, testable differentiation claim.
2. **Adopt attack families and evaluation principles.** Import or re-express the useful cases from AgentFuzz, Agent Security Bench, AgentDojo/CAISI, Chord and ToolHijacker.
3. **Do not inherit benchmark ground truth uncritically.** A later study shows that one ASB design choice inflated a reported attack-success rate from 9.25% to 73.58% by forcing attacker tools into execution candidates.
4. **Make the corpus substrate-aware.** Every case must identify the invariant, authority input, decision, permit, exact operation, enforcement point and effect—not merely whether an LLM emitted an attacker-preferred string or called a named tool.
5. **Separate authorship and evaluation.** The corpus, expected decisions, Warrantor implementation and red-team mutations must have independent maintainers and blind holdout partitions.
6. **Require adaptive and repeated-attempt testing.** Static public vectors can be memorized or saturated; NIST's experiments moved measured attack success from 11% to 81% under an adaptive attack and from 57% to 80% when attacks were tried 25 times.
7. **Treat containment as layered.** NSA's MCP guidance supports explicit egress controls, operating-system sandboxing, parameter validation, signed/time-bound messages, output inspection and exact invocation logging. Model or prompt defenses alone are not the authority boundary.

## Review set

| Source | Evidence class | Canonical version | Artifact standing | Warrantor decision |
|---|---|---|---|---|
| [AgentFuzz, USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/liu-fengyu) | Peer-reviewed conference paper | USENIX proceedings, August 2025 | Public repository pinned and statically exercised; full experiment requires model/API setup; no repository-level license located | Adopt attack generation and taint triage ideas; modify for authority/effect invariants |
| [Agent Security Bench, ICLR 2025](https://proceedings.iclr.cc/paper_files/paper/2025/hash/5750f91d8fb9d5c02bd8ad2c3b44456b-Abstract-Conference.html) | Peer-reviewed conference paper | ICLR proceedings, 2025 | MIT repository pinned; current tree contains an unresolved merge conflict and no credible release test gate | Reference as broad taxonomy; do not use headline ASR or ground truth unchanged |
| [Les Dissonances, NDSS 2026](https://www.ndss-symposium.org/ndss-paper/les-dissonances-cross-tool-harvesting-and-polluting-in-pool-of-tools-empowered-llm-agents/) | Peer-reviewed security paper | NDSS proceedings, February 2026 | Chord MIT repository pinned; locked environment installed and modules imported; full scans need third-party credentials | Adopt cross-tool flow and data-taint classes; modify into policy/effect assertions |
| [ToolHijacker, NDSS 2026](https://www.ndss-symposium.org/ndss-paper/prompt-injection-attack-to-tool-selection-in-llm-agents/) | Peer-reviewed security paper | NDSS proceedings, February 2026 | No official public implementation artifact located in the bounded search | Adopt malicious metadata and retrieval cases as black-box vectors; independently reimplement |
| [Strengthening AI Agent Hijacking Evaluations, NIST CAISI](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations) | Government technical blog plus public code | Updated December 19, 2025 | NIST repository pinned; locked environment installed; 16 tests passed and 4 async tests skipped | Adopt adaptive, task-severity and repeated-attempt methodology |
| [MCP: Security Design Considerations, NSA](https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF) | Government technical whitepaper | Version 1.0, May 2026 | Guidance, not an experimental artifact | Adopt as operational threat/control checklist; do not cite as efficacy proof |
| [Indirect Prompt Injections: Are Firewalls All You Need, or Stronger Benchmarks?](https://arxiv.org/abs/2510.05244) | Preprint and workshop paper | arXiv v2, March 23, 2026 | Full methods inspected; corrected code claimed but no public repository located in the bounded search | Adopt benchmark-integrity requirements and disconfirming evidence; reproduce before product claims |

## What each source actually tests

The sources are complementary, not interchangeable.

| Layer | Primary reviewed evidence | Unit under test | Typical success condition | What it does not establish |
|---|---|---|---|---|
| Application code and dataflow | AgentFuzz | An open-source LLM-agent application with source access | A generated prompt reaches a sensitive sink through a feasible taint-style path | Correct authority algebra, cross-language enforcement or final effect binding |
| Agent behavior and workflow | ASB; AgentDojo/CAISI | An agent, model, tools, memory and simulated task environment | The attacker objective occurs, often expressed as tool invocation or task state | That a policy enforcement point denied every unauthorized operation |
| Tool discovery and selection | ToolHijacker | Retrieval-plus-selection from a tool library | A malicious tool document causes selection of the attacker's tool | Exploitation after selection, default-deny enforcement or network containment |
| Cross-tool control and data flow | Les Dissonances/Chord | Multi-tool sequences in LangChain and LlamaIndex | One tool harvests or pollutes information across another tool's workflow position | Multi-principal authority, formal policy equivalence or production complete mediation |
| Evaluation methodology | NIST CAISI; firewall/benchmark critique | Benchmark construction and attack process | Adaptive or repeated attacks expose failures missed by a static aggregate score | An implementation of a Warrantor authority substrate |
| Protocol and operational controls | NSA MCP guidance | MCP design, deployment and operations | Security practices reduce identified classes of exposure | Controlled efficacy, conformance, formal proof or novelty |
| Authority substrate | SentinelAgent, reviewed previously | Delegation service and seven authored properties | Expected authorization decisions under authored cases | Independent ground truth, complete mediation, final-wire/effect binding or cross-implementation transfer |

This separation is central. A benchmark that shows model compromise is not automatically a test of W3 containment or W5 egress. Conversely, a policy decision returning `deny` is not a successful containment test unless the exact prohibited operation and effect are blocked at every authoritative path.

## Evidence receipt: what was reproduced

### AgentFuzz

- Repository: `https://github.com/LFYSec/AgentFuzz`
- Pinned commit: `0fc9960fd126b20cb0d19b4aec4b1266855d44f0`
- Commit date: 2026-04-13
- Tracked files: 276
- License standing: the repository API and root tree exposed no project-level license; a bundled dependency has its own license, which does not license AgentFuzz itself
- Mechanical result: Python compilation completed, but the bundled `py-conbyte` emitted extensive syntax warnings, including literal identity comparisons and invalid escapes
- Test standing: no native test suite was located
- Reproduction boundary: the full fuzzer requires source-target setup, CodeQL/dataflow preparation and an external model endpoint/key; the reported vulnerability campaign was not rerun
- Archive standing: the paper points to Zenodo DOI `10.5281/zenodo.15590097`, but the record's files were restricted during this review; the linked GitHub repository was available

The official USENIX page reports 34 high-risk zero-days across 20 applications and 23 assigned CVEs. The paper/repository material later references 27 CVEs, creating a version/date discrepancy that must be labeled rather than silently reconciled. The paper reports 100% precision and 97.14% recall, but its recall denominator is not a complete independent universe of vulnerabilities: candidate positives aggregate findings from AgentFuzz and LLMSmith, while a sample of negatives is manually inspected. These are useful results, not a proof of near-complete vulnerability discovery.

### Agent Security Bench

- Repository: `https://github.com/agiresearch/ASB`
- Pinned commit: `1f561dccf92d55302368fa67679b4ba9d9c8fdc4`
- Commit date: 2026-04-16
- License: MIT
- Tracked files: 218
- Benchmark scope reported by ICLR: ten scenarios, ten agents, more than 400 tools, 27 attack/defense types, 13 model backbones and seven metrics
- Mechanical result: current Python compilation fails because `pyopenagi/tools/imdb/top_series.py` contains literal unresolved merge-conflict markers
- Test standing: no credible repository-wide automated suite was located; the current release tree therefore cannot serve as a clean conformance baseline
- Environment standing: requirements files exist, but there is no reviewed deterministic lock for the complete experiment stack

ASB's breadth is valuable for taxonomy and scenario generation. Its headline maximum average attack-success rate of 84.30% must not be carried into Warrantor materials as a context-free measure. The later benchmark-integrity paper demonstrates that the evaluation force-injected attacker tools into selected tool subsets and then counted invocation of those tools as attack success. On GPT-4o, removing the forced injection changed the relevant ASR from 73.58 ± 2.70 to 9.25 ± 0.25. The same critique shows that coarse utility can be gamed by calling every available tool and can ignore required action order.

### Les Dissonances and Chord

- Repository: `https://github.com/systemsecurity-uiuc/Chord`
- Pinned commit: `8ac19e8bd5fdca0a7c21bfe46b3e16e943f07831`
- Commit date: 2025-12-17
- License: MIT
- Tracked files: 45
- Packaging: `pyproject.toml` plus `uv.lock`
- Mechanical result: Python compilation passed; the frozen environment installed; package imports passed with one dependency warning
- Data inspected: 148 LangChain tool-map entries, 160 query entries in one set, 32 in a second, plus malicious-tool and malicious-argument definitions
- Test standing: no native unit or integration test suite was located
- Reproduction boundary: substantive scans require multiple framework/provider dependencies and third-party API credentials; the published vulnerability rates were not independently rerun
- Cost friction: the frozen environment resolves 238 packages and downloads a large GPU-enabled Torch/CUDA stack, which is disproportionate to a basic scanner smoke test

The canonical NDSS paper evaluates 66 executable tools from LangChain and LlamaIndex and reports 75% vulnerable to cross-tool harvesting or polluting. Earlier arXiv/repository text refers to 73 tools and different harvested/polluted percentages. The conference version is authoritative for citation; older figures should be labeled as prior-version results, not merged into one sample.

The most important Warrantor insight is the *seam*: a tool can be individually acceptable while the predecessor/successor relationship leaks or corrupts data. W4 cannot compile per-tool decisions alone, and W5 cannot treat a single tool call as the full egress unit. The policy model needs typed control-flow and information-flow edges.

### ToolHijacker

- Canonical paper: NDSS 2026 proceedings
- Public artifact: no author-controlled code or dataset repository was located through the paper, project searches or bounded repository searches
- Threat: a no-box attacker injects a crafted malicious tool document into a tool library so retrieval and selection prefer the attacker's tool for a target task
- Defenses evaluated: StruQ, SecAlign, known-answer detection, DataSentinel, perplexity detection and windowed perplexity detection
- Artifact decision: reimplement only the minimal tool-document transformation and test it against Warrantor's registry/provenance gates; do not claim reproduction of the authors' effect sizes

ToolHijacker establishes that registry text and tool metadata are active security inputs. A signed tool binary or allowlisted server is insufficient if an attacker can alter the description, identifier resolution, version association or retrieval index. W1/W2 should include tool-document digest and provenance in the notary/evidence envelope; W4 should type and validate selection metadata; W3/W5 must remain secure even if selection is wrong.

### NIST CAISI AgentDojo/Inspect extension

- Repository: `https://github.com/usnistgov/agentdojo-inspect`
- Pinned commit: `a491020fd14e87bcc19b2eb77fe307d8b329b05d`
- Commit date: 2025-10-23
- Repository standing: archived by NIST; more than 22,000 tracked files because run artifacts are committed
- Environment: `uv.lock` installed successfully with the development group
- Test result: `uv run pytest -q -s tests` produced 16 passes, 4 skips and 12 warnings in 4.07 seconds
- Important limitation: four async tests were skipped because the environment did not install/configure an async pytest plugin, so the green result is not complete execution of the visible tests
- Initial capture failure: a PTY output-capture error occurred under default pytest capture; rerunning with `-s` isolated it as an environment/capture issue rather than a product assertion

NIST's technical blog and code are unusually actionable government evidence. The work fixes upstream scenarios, adds Inspect integration, and adds remote-code-execution, mass-exfiltration and automated-phishing tasks. It also supplies four rules Warrantor should make normative:

1. Shared suites must be continuously repaired and expanded.
2. Attacks must adapt to the evaluated defense; a held-out adaptive attack raised ASR from 11% to 81% in the reported experiment.
3. Risk must be reported per task and consequence, not only as an average.
4. Repeated attempts matter; 25 attempts raised the reported average ASR from 57% to 80%.

### NSA MCP security guidance

The 17-page, version 1.0 Cybersecurity Information Sheet is authoritative current guidance, not original controlled research. It identifies optional/uneven authentication, bearer-token and session lifecycle gaps, weak serialization validation, dynamic discovery, implicit trust, cross-context leakage, poor approval flows, insufficient logs and inconsistent implementations.

Its strongest direct implications for Warrantor are:

- Define trust zones across clients, servers, tools, models and users.
- Verify origin and authorization before dynamic discovery or tool enrollment.
- Use a filtering outbound proxy or enterprise DLP with destination- and method-specific rules.
- Validate the schema, range, intended context and provenance of every invocation parameter.
- Restrict ambiguous forwarding between components.
- Run tools in least-privilege operating-system isolation such as seccomp, AppArmor or SELinux.
- Bind messages cryptographically to time and context, including expiry and replay metadata.
- Treat every tool output as untrusted input to the next component.
- Log exact parameters, identities and—where feasible—hashes of results.
- Maintain a versioned inventory and vulnerability-response process for deployed MCP agents and tools.

These controls align with W1-W5, but the document does not prove that a proposed Warrantor mechanism is effective, complete or novel. It should be used as a requirement source and enterprise adoption reference.

### Firewall and benchmark-integrity critique

The March 2026 arXiv v2 paper is the most important disconfirming source in this wave. It demonstrates a simple input minimizer and output sanitizer across AgentDojo, ASB, InjecAgent and tau-Bench, then argues that current static benchmarks are too weak and contain design or metric defects. Its contribution is not that “firewalls solve prompt injection.” Its own adaptive cascade reaches failures after the static attacks are saturated.

The paper's durable lessons are:

- Report benign utility, utility under attack and attack success together.
- Do not alter the agent's candidate/action path to force exposure to the attack primitive.
- Require semantically correct task completion, not brittle state deltas or unordered tool-set membership.
- Preserve task-critical content when injecting attacks.
- Use held-out, defense-adaptive attacks and disclose attacker knowledge.
- Treat a static public benchmark score as regression evidence, not deployment assurance.
- Track added model calls, latency, token cost and privacy exposure introduced by defenses.

The work is a preprint/workshop contribution, and no public implementation repository was located in this bounded review despite the paper's statement that corrected versions were released. Its results should therefore be treated as strong challenge evidence that still requires independent reproduction.

## Reported evidence versus verified evidence

| Claim | Source-reported standing | This review's standing |
|---|---|---|
| AgentFuzz found 34 high-risk zero-days in 20 applications | Peer-reviewed report; official USENIX page | Metadata and methods inspected; campaign not rerun; CVE count differs by source version |
| AgentFuzz achieved 100% precision and 97.14% recall | Paper experiment | Ground-truth construction is partly tool-union plus sampled negatives, not a complete independent oracle |
| ASB reaches 84.30% highest average ASR | ICLR abstract | Valid as a reported result only; later methodology work shows severe inflation in a related ASB setting |
| Removing forced ASB tool injection changes 73.58% ASR to 9.25% | arXiv v2 benchmark critique | Full method/table inspected; no public corrected artifact located; independent rerun pending |
| Chord finds 75% of 66 tools vulnerable | NDSS conference version | Paper and pinned artifact inspected; environment/import gate passed; scans not rerun |
| NIST adaptive attacks raise ASR 11% to 81% | Government technical experiment | Blog, experiment design and repository inspected; hosted-model run not rerun |
| NIST 25-attempt testing raises average ASR 57% to 80% | Government technical experiment | Blog and framing inspected; stochastic campaign not rerun |
| NSA controls reduce MCP compromise | The document recommends controls; it does not provide an efficacy experiment | Treat as requirements/guidance, never as measured efficacy |

## Benchmark failure modes Warrantor must prevent

### 1. Forced exposure

The harness must not insert a malicious tool into the chosen plan, authorize a denied action, bypass retrieval, or otherwise force the system into a state that the production path would not reach. The attack may poison legitimate inputs; the harness may not replace the decision under test.

### 2. Co-designed ground truth

When implementation authors also write expected decisions and attack cases, 100% success may measure agreement with their own encoding. Independent case authorship, concealed holdouts and an adjudication record are mandatory.

### 3. Output-only success metrics

An LLM refusal or correct final string does not prove containment. Record the model trajectory, policy request, decision, permit, exact forwarded bytes, egress, downstream state transition and recovery behavior.

### 4. Aggregate-score concealment

A 1% attack-success rate can hide a 100% success rate for the only catastrophic action. Report by action class, authority class, consequence, attacker access and repeated-attempt budget. Use risk-weighted results only in addition to raw strata, never as their replacement.

### 5. Static attack saturation

Public prompts and fixed labels are regression vectors. A release claim requires held-out semantic mutations, protocol mutations, sequence mutations, tool-registry mutations and defense-aware adaptive attacks.

### 6. Utility gaming

Utility must require semantically correct, ordered, side-effect-bounded task completion. Calling every tool, returning a plausible answer, or causing the desired state by an unauthorized path must not count as utility.

### 7. One-shot stochasticity

Report both per-attempt and at-least-one-success-over-budget probability. Pin temperature, sampling policy, model/version, provider date and seed where supported. For unseedable hosted models, report repeated distributions and cost.

### 8. Model and version drift

Model aliases, mutable hosted APIs and changing tool libraries invalidate historical comparisons. Each run needs a runtime AI bill of materials: model identifier and digest/version, provider, endpoint, prompts, tokenizer, tool schemas, policy bundle, code commit, container/image digest and dependency lock.

### 9. Corpus contamination

Public benchmarks may be present in model training or system prompts. Maintain private holdouts, synthetically mutate semantics rather than only surface form, and report contamination checks and uncertainty.

### 10. Decision/effect confusion

A PDP response is not enforcement. A PEP rejection is not effect absence if another socket, SDK, shell, browser, filesystem or queue path can perform the operation. Every case must identify and observe the authoritative effect boundary.

## Proposed Warrantor invariant attack corpus profile

### Corpus layers

| Layer | Required attack families | Primary assertion |
|---|---|---|
| Identity and mandate | subject substitution, tenant confusion, stale identity, unsigned mandate mutation, replay | W1 recognizes the intended authenticated principal and immutable mandate |
| Delegation algebra | bearer delegation, missing ancestor, scope widening, output laundering, principal omission, cycle/fork, revocation race | W6 computes the exact intersection of every applicable authority and rejects incomplete chains |
| Decision semantics | target-field mismatch, wildcard ambiguity, rule-order permutation, type coercion, default drift, cross-engine differential | W4 produces equivalent intended decisions across supported targets |
| Permit and operation binding | argument mutation, tool-version swap, method/path alias, payload canonicalization ambiguity, delayed use, duplicate use | W1/W2 bind the permit and receipt to the exact operation admitted |
| Enforcement coverage | direct SDK, raw socket, subprocess, alternate MCP route, notification path, cached connection, retry/failover | W3/W5 completely mediate all effects in the declared boundary |
| Egress and information flow | encoded exfiltration, DNS/HTTP alternate channel, cross-tool harvesting, context carryover, output injection | W5 denies unauthorized destinations/methods/data classes and W3 contains indirect flow |
| Evidence integrity | omitted event, field stripping, result substitution, hash/signature failure, forked log, clock skew, replay | W2 makes accepted action/effect evidence verifiable and omission detectable within its stated population model |
| Revocation and failure | in-flight operation, queue backlog, partition, process crash, stale cache, failover, clock rollback | W3 meets measured residual-action and propagation bounds under specified failures |
| Registry and supply chain | malicious description, name collision, dependency substitution, server rug pull, schema drift | Tool identity, metadata, version, provenance and policy are bound and revalidated |
| Evaluation pipeline | poisoned grader, model swap, dropped trials, duplicate weighting, adapter loss, selective publication | Evaluation receipts authenticate inputs, execution, scoring, omissions and conversions |

### Required case schema

Every attack case should contain at least:

- Stable case identifier and semantic family.
- Threat actor, access, knowledge and attempt budget.
- Preconditions and trust-boundary diagram reference.
- Target W1-W6 product and named invariant.
- Capability requested and authority inputs expected to constrain it.
- Typed benign task, adversarial payload and task-critical content that must be preserved.
- Expected PDP decision and reason.
- Expected permit fields, digest and lifetime when applicable.
- Exact expected wire operation or explicit absence.
- Expected external effect, recovery action and maximum residual-action bound.
- Severity, reversibility, data classification and affected tenant/principal.
- Model, agent framework, protocol, policy engine and implementation matrix.
- Mutation operators and holdout status.
- Ground-truth author, adjudicator and independence metadata.
- Required evidence events, ordering, correlation identifiers and omission checks.
- Repetition count, seeds/sampling configuration and statistical estimator.
- Runtime bill of materials and source/artifact licenses.

### Minimum metrics

| Metric | Why it is required |
|---|---|
| Unauthorized effect rate | Measures the security outcome, not merely model behavior |
| Unauthorized final-wire operation rate | Separates enforcement failure from downstream effect observation |
| False-denial rate | Prevents a system from “winning” by blocking all work |
| Benign task utility | Measures normal usefulness with no attack |
| Utility under attack | Detects defenses that preserve security by destroying the intended task |
| At-least-one success over N attempts | Captures stochastic repeated attack risk |
| Risk-stratified success | Prevents catastrophic classes from disappearing in averages |
| Mutation score | Shows whether the suite detects seeded policy/PEP/substrate defects |
| Cross-implementation transfer | Tests whether vectors expose the invariant rather than one codebase's syntax |
| Cross-engine semantic divergence | Measures W4 portability and default/typing drift |
| Residual actions after revocation | Makes W3 bounded-revocation language operational |
| Detection latency and evidence completeness | Measures incident and receipt usefulness |
| Cost, latency and privacy overhead | Makes enterprise adoption trade-offs explicit |

### Independence and governance

The corpus should be governed as a security test standard, not a product demo:

- Separate maintainers for implementation, corpus, oracle and red-team mutation sets.
- Public core vectors plus encrypted/private release-gate holdouts.
- Signed corpus releases with provenance, licenses and change logs.
- An appeals/adjudication process for ambiguous expected decisions.
- Quarantined challenge submissions before promotion into public regression vectors.
- Versioned profiles for MCP, A2A, direct SDK, shell/browser and network enforcement.
- Compatibility windows rather than silent updates when policy engines or model providers change.
- Public reporting of failed reproduction, flaky cases and excluded trials.
- No aggregate “secure” badge; conformance claims must name profile, version, environment and exclusions.

## W1-W6 implications

### W1 — Notary core

- Include the tool registry document, schema, version, origin and retrieval-index identity in the notarized input set.
- Authenticate the actual delegate and proof of possession; a token identifier is not authority.
- Bind the permit to method, resource, arguments, destination, tool version, policy bundle, model/agent context where material, expiry and one-time/replay semantics.
- Expose canonicalization test vectors because argument and tool-document representations are adversarial surfaces.

### W2 — Evidence-before-commit envelope and receipts

- Record the attack case, decision, permit, forwarded operation, result/effect observation and evaluator identity in one correlated evidence graph.
- Distinguish evidence that an enforcement point *said deny* from evidence that no effect occurred.
- Preserve native harness outputs and produce a signed, loss-audited adapter record when normalizing them.
- Model population completeness explicitly; a signature on one event does not prove missing events do not exist.

### W3 — Containment and kill-switch conformance

- Add cross-tool, retry, queue, crash, cached-connection and alternate-channel cases.
- Measure residual actions after revocation rather than reporting only notification latency.
- Require operating-system and network enforcement for high-risk tools; prompt rejection is defense in depth.
- Re-run adaptive attacks after every material defense change.

### W4 — Cross-stack policy compiler

- Type tools, arguments, destinations, data classifications, sequence state and effect classes.
- Differentially test rule order, wildcards, absent fields, coercions, unknown values and default behavior across every target.
- Include semantic counterexamples discovered from AgentFuzz/Chord/ToolHijacker as compiler fixtures.
- Fail a target profile if its enforcement API cannot represent a required invariant; do not silently weaken the source policy.

### W5 — Default-deny egress broker

- Make destination, protocol, method, identity, tool version and data class explicit policy dimensions.
- Treat cross-tool flow and downstream tool output as tainted until declassified by policy.
- Cover raw sockets, DNS, redirects, proxies, browser automation, subprocesses, queues and cloud SDKs.
- Use NSA's proxy/DLP recommendation as a minimum operational baseline, then prove which paths are actually mediated.

### W6 — Delegation-chain authority intersection

- Attack missing, reordered, forked, revoked and unauthenticated ancestors.
- Test scope and output authorities together to prevent cross-scope laundering.
- Bind every ancestor and effective intersection into the permit/receipt.
- Add multi-principal cases where user, tenant, resource owner, deployer, tool owner and regulator constraints conflict.

## Product choices

| Option | Benefits | Costs and risks | Recommendation |
|---|---|---|---|
| Adopt ASB or AgentDojo unchanged | Fastest path; established tasks and comparisons | Model/workflow-centric, mutable model dependencies, known benchmark defects, no exact Warrantor substrate oracle | Reject unchanged adoption |
| Extend one benchmark with Warrantor cases | Reuses runners and community recognition | Warrantor semantics may be forced into an unsuitable task/metric model | Use for external comparison, not the sole conformance gate |
| Build a standalone Warrantor corpus | Exact invariants, effects, receipts and cross-engine semantics | Higher governance, maintenance and independent-review cost | Preferred core strategy |
| Publish only attack vectors | Easy adoption by other frameworks | No normative oracle, runner, evidence profile or cross-implementation comparability | Useful secondary export, insufficient alone |

**Strong recommendation:** build the standalone corpus as a versioned conformance profile, while maintaining adapters that run selected cases through AgentDojo/Inspect and export results into the evaluation-receipt schema. This preserves ecosystem leverage without allowing an external benchmark's semantics to define Warrantor's guarantee.

## Phased implementation plan

### Phase 0 — Claim repair and taxonomy

1. Replace the absolute benchmark absence claim.
2. Freeze the layer taxonomy in this review.
3. Define named invariants and effect boundaries for W1-W6.
4. Publish what the corpus explicitly does not prove.

### Phase 1 — Minimal independent conformance core

1. Implement deterministic non-LLM cases for policy, permit, PEP, egress and revocation.
2. Seed real defects already found in reviewed Warrantor comparators: unsigned fields, expiry bypass, cross-scope output laundering, non-atomic quota, rule-order dependence, post-decision mutation and direct-hook bypass.
3. Require mutation score and cross-implementation transfer before release.
4. Issue signed run receipts with exact environment pins.

### Phase 2 — Agent and protocol attacks

1. Port selected AgentFuzz taint paths, Chord cross-tool cases and ToolHijacker metadata poisoning.
2. Add AgentDojo/CAISI RCE, mass-exfiltration and phishing scenarios.
3. Exercise MCP, A2A, direct SDK and browser/shell routes.
4. Add repeated attempts and defense-adaptive mutations.

### Phase 3 — Independent evaluation and standardization

1. Commission an external red team to author blind cases.
2. Run at least two independently implemented policy/enforcement stacks.
3. Publish oracle disagreements and adjudication.
4. Submit a narrow negative-vector/evidence profile to a suitable standards or security venue only after independent transfer is demonstrated.

## Academic, business and content opportunities

### Academic research

- **Paper:** “From Attack Success to Unauthorized Effect: A Cross-Implementation Conformance Benchmark for Agent Authority Substrates.”
- **Research question:** Do model/workflow benchmark scores predict final-wire or effect-level containment?
- **Hypothesis:** Cross-layer invariant assertions and adaptive sequence mutations expose failures missed by static prompt-injection suites.
- **Evaluation:** Multiple agents, models, policy engines and enforcement topologies; independent holdout authoring; mutation score; repeated attempts; utility and cost.
- **Potential venues:** USENIX Security, NDSS, IEEE Symposium on Security and Privacy, ACM CCS, RAID and security/evaluation workshops. Venue fit must be rechecked at submission time.

### Product and business

- Treat the conformance corpus as a procurement trust artifact, not a marketing score.
- Offer customer-specific policy/egress profiles without exposing private holdouts.
- Map cases to threat models and control evidence for North America, India, Saudi Arabia, UAE and Qatar; do not claim legal compliance from technical passes alone.
- Differentiate on inspectable guarantees: exact operation binding, effect evidence, residual-action bounds and cross-engine equivalence.

### Content program

1. Why 84% versus 9% attack success can both be “correct” for the same benchmark family.
2. Model benchmarks do not prove enforcement: the decision-to-effect gap.
3. Tool descriptions are executable security inputs.
4. Why repeated attacks change enterprise risk.
5. Cross-tool attacks and the limits of per-tool allowlists.
6. What NSA's MCP guidance implies for real agent architecture.
7. How to design a benchmark that cannot win by blocking everything.

## Quality scores

The weighted scores follow the repository protocol: rigor 20, technical depth 15, authority 15, Warrantor relevance 15, reproducibility 10, independence 10, originality 5, durability 5 and recency fitness 5.

| Source | Rigor | Depth | Authority | Relevance | Reproducibility | Independence | Originality | Durability | Recency | Total | Band |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| AgentFuzz | 18 | 15 | 15 | 14 | 7 | 9 | 5 | 4 | 5 | 92 | Essential |
| Les Dissonances | 18 | 15 | 15 | 15 | 7 | 8 | 5 | 3 | 5 | 91 | Essential |
| NSA MCP guidance | 16 | 13 | 15 | 15 | 5 | 9 | 4 | 5 | 5 | 87 | High-quality |
| NIST hijacking evaluations | 16 | 13 | 15 | 15 | 8 | 8 | 3 | 4 | 5 | 87 | High-quality |
| ToolHijacker | 18 | 14 | 15 | 14 | 3 | 8 | 5 | 4 | 5 | 86 | High-quality |
| Agent Security Bench | 17 | 13 | 15 | 14 | 4 | 8 | 4 | 3 | 5 | 83 | High-quality |
| Firewall/benchmark critique | 17 | 14 | 11 | 15 | 5 | 8 | 5 | 3 | 5 | 83 | High-quality |

The scores rank evidence quality and Warrantor utility—not whether a source's conclusions are favorable. The skeptical benchmark critique scores highly because it materially changes how all other benchmark evidence should be interpreted.

## Final recommendation

The invariant attack corpus should remain a Warrantor build item, but its claim and design must change.

The defensible claim is not that no benchmark exists. It is:

> Warrantor is developing an independent, capability-elicited, cross-implementation conformance corpus that tests named authority invariants from principal and policy inputs through decision, permit, final-wire operation and observed effect, with adaptive attacks, repeated attempts, mutation scoring and signed evidence.

That statement is narrower, measurable and materially differentiated from the reviewed prior art. It also creates a hard acceptance condition: until independent authorship, cross-implementation transfer and effect-level evidence exist, the repository must describe the corpus as a planned research/conformance capability rather than a proven assurance result.
