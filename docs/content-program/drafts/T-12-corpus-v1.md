# T-12 Corpus v1: Screening Record, Pilot Adjudication, and Early Findings

**Companion artifact to [T-12](T-12-sok-authority-and-containment.md) · 2026-08-30 · scored against [`ACTION-SURFACE-v1.0`](ACTION-SURFACE-v1.md)**

> **Read this first.** The pilot as delivered covers **two works**, not ten. One of them
> (CaMeL) was coded by both coders; the other (Progent) was coded by the conservative coder
> only, and that record arrived truncated. Every number below is stated with that sample size
> attached. No Cohen's kappa is reported, because the data does not support one and inventing
> one would be worse than reporting nothing.

---

## 0. Lead: what the pilot actually shows

Six results, in order of how much they change the paper. Three of them contradict the draft's
own predictions.

**0.1 · The weakest-link rule produced zero demotions on the delivered pilot.** Both coded
works advertise T3 and score T3. Delta is 0 on 2 of 2. §3.1 predicts that "systems marketed
as enforcing bind, in the majority of cases, only at a chokepoint," and the pilot as delivered
neither confirms nor moves that prediction. **This is a selection artifact, not a
disconfirmation.** The screening record nominates at least six works specifically as demotion
candidates — SEAgent's "mandatory access control" with no kernel, MiniScope's borrowed
mobile-permission vocabulary, CaMeLs-Can-Use-Computers' "system-level," AgentArmor's
"enforcing," the Design Patterns paper's "provable resistance," and AARM's
specification-versus-implementation split. **None of them was coded.** The two works that were
coded are the two the screening rationales flag as tier-honest anchors. So the demotion rate is
**untested**, and the correct statement in the paper is that it is untested, not that it is low.

**0.2 · The coverage axis has an agreement problem, and it is a rubric defect rather than a
reading disagreement.** On the one doubly-coded work the two coders agreed on **1 of 7**
coverage cells (14.3%), against 5 of 5 agreement on every other coded field. Diagnosing the six
disagreements: **two** are pure value-set collisions in which the coders read the text
identically and disagreed only about which label to write, because `ACTION-SURFACE-v1.0` never
defines the permitted values; **three** are depth-of-mediation disagreements about whether an
effector whose top-level tool call is mediated but whose descendants and covert channels are not
counts as covered or partial; **one** is a generous grant the charitable coder flagged against
itself. All six are fixable by rubric text. None required a judgment call about what the paper
says. §3.2 says this axis "is either the paper's best contribution or its fatal weakness, and
the difference is entirely procedural" — the pilot's answer is that the procedure has two
specific, nameable holes and they are cheap to close.

**0.3 · Not one cell in the adjudicated pilot scored `covered`.** After adjudication, CaMeL's
vector is four `partial` and three `not-covered`; Progent's single-coder vector is identical in
shape. Zero fully mediated effectors across both works. If this survives the full pass it is a
**stronger result than the demotion delta** and it lands directly on §6.4: no work in the pilot
satisfies Anderson's "always invoked" property on any effector, by the paper's own definition.

**0.4 · E2 is least covered as predicted, but it is not uniquely least covered.** E2 subprocess
spawn scored `not-covered` on both works. So did **E4** and **E5**. §3.2 calls E2 "the exclusion
that inflates coverage most" and §5 predicts it will be "the least covered"; on this pilot it is
**tied** with two other effectors, and the draft's framing of E2 as singular needs softening
until the full pass either restores or removes the distinction.

**0.5 · The Schneider column returned a value the paper's §7 does not have.** Every coder on
both works returned **"partial"**, and all three records give the same structure: the object the
monitor mechanically enforces is a prefix-closed safety property over a per-call predicate, and
the objective the paper advertises is an information-flow hyperproperty that no execution monitor
can decide. §7 asks which claimed policies fall "outside the enforceable class" and implies a
binary. The pilot answer on 2 of 2 works is **neither** — it is a split between a monitorable
surrogate that is enforced and a non-monitorable goal that is claimed. The gap between them is
where the residual attack surface lives, and both coders located it independently in the same
place. **The split value may be the modal one, and it is a better finding than the binary.**

**0.6 · The composition result is entirely untested.** Both works are A2. Two A2 controls are
trivially compatible under §6.1, so the pilot exhibits no non-composing pair — zero out of one
available pair. Worse for the method: both coders on CaMeL recorded that the work's secondary
scenarios move the adversary to A1 and to an A5-flavored supply-chain placement, and one coder
argued A3 is arguably the work's real strength but is untested by the authors. **Adversary
placement is therefore not single-valued per work**, and coding it as a partition, which §3.3
requires, discards exactly the information §6 needs.

---

## 1. Screening record

### 1.1 What was delivered, and what was not

| Item | Status |
|---|---|
| Included set | **At least 28 records delivered.** The payload truncated mid-rationale on the 28th entry, so 28 is a floor and not the screened total |
| Excluded set | **Not delivered.** No excluded array, no gate-failure attributions |
| Excluded count | **Cannot be reported** |
| Attrition rate against §4's expected 10–20% | **Cannot be computed** without the excluded set |

**This is a reporting gap, not a finding.** §4 commits to publishing the excluded set with the
gate that excluded each work, and that commitment is unmet until the excluded array is produced.
Until then no attrition claim belongs in the paper.

### 1.2 Corpus statistics on the 28 delivered inclusions

**By screening category:**

| Category | n | Share |
|---|---|---|
| Policy enforcement | 14 | 50.0% |
| Sandbox | 4 | 14.3% |
| Capability | 3 | 10.7% |
| Protocol | 3 | 10.7% |
| TOCTOU | 2 | 7.1% |
| Delegation | 1 | 3.6% |
| Egress | 1 | 3.6% |
| **Total** | **28** | |

Half the delivered corpus is a single category. If that survives to the full population, the
tier distribution will be dominated by one mechanism family, and the paper should say so in §5
rather than let a reader infer breadth from seven category names.

**By screening priority:**

| Scoring value | n |
|---|---|
| High | 17 |
| Medium | 10 |
| Low | 1 |
| **Total** | **28** |

**By year of the arXiv identifier:**

| Year | n |
|---|---|
| 2024 | 1 |
| 2025 | 16 |
| 2026 | 11 |
| **Total** | **28** |

Twenty-seven of twenty-eight are from 2025 or later, which is consistent with §10's statement
that the corpus is "a preprint-heavy population in a field publishing monthly."

### 1.3 Works flagged at screening as demotion candidates, and not yet coded

Recorded here because §0.1 turns on it. These are the works whose screening rationale explicitly
predicts an advertised-versus-scored delta:

| id | Work | Predicted delta driver |
|---|---|---|
| arXiv:2601.11893 | SEAgent | "mandatory access control" with no kernel, no label store, no reference monitor below the process |
| arXiv:2512.11147 | MiniScope | mobile-permission analogy imports an OS-grade expectation the tool-caller authorization layer does not deliver |
| arXiv:2601.09923 | CaMeLs Can Use Computers Too | "system-level" while a perception model resolves runtime values inside the loop |
| arXiv:2508.01249 | AgentArmor | "enforcing" with a trace-derived, post-hoc decision point |
| arXiv:2506.08837 | Design Patterns for Securing LLM Agents | "provable resistance" where the proof ranges over the pattern, not an enforcement substrate |
| arXiv:2602.09433 | AARM | names kernel eBPF as one possible implementation among others; the same document scores T2 or T3 by deployment choice |

Two further works are flagged as the **T2 counterweights** that would keep the tier axis from
collapsing to a single value: arXiv:2602.09345 (AgentCgroup, kernel-enforced via eBPF, sched_ext
and memcg, hierarchical so the control survives descendants) and arXiv:2601.01241
(MCP-SandboxScan, WASI as a genuine capability boundary). Neither has been coded either, so the
pilot currently contains **no T2 observation at all**.

---

## 2. Inter-coder agreement

### 2.1 What the data supports

| Axis | Doubly coded works | Raw agreement | Cohen's kappa |
|---|---|---|---|
| Advertised tier | 1 | 1/1 | **not computed** |
| Scored tier | 1 | 1/1 | **not computed** |
| Adversary placement | 1 | 1/1 | **not computed** |
| Evidence grade | 1 | 1/1 | **not computed** |
| Schneider verdict | 1 | 1/1 | **not computed** |
| Coverage, per cell | 1 work × 7 cells | **1/7 (14.3%)** | **not computed** |
| All fields pooled | 1 work × 12 cells | 6/12 (50.0%) | **not computed** |

### 2.2 Why no Cohen's kappa is reported

Three independent reasons, any one of which is sufficient.

1. **n = 1 doubly coded work.** For every per-work axis there is a single paired observation.
   Kappa requires marginal distributions to compute expected agreement, and a single observation
   has none. A kappa computed here would be undefined or degenerate, not small.
2. **The seven coverage cells are not seven independent observations.** They are seven cells of
   one paper, produced from one reading of one text by each coder. Treating them as an n = 7
   sample would inflate apparent precision by exactly the amount the dependence is ignored.
3. **The two coders did not use the same nominal scale.** The conservative coder used
   {covered, partial, not-covered}; the charitable coder used those three plus **not-applicable**.
   Kappa across unequal category sets is undefined without collapsing, and the only available
   collapse — folding not-applicable into not-covered — presupposes the adjudication that §3
   below performs. Computing kappa after that collapse would be measuring agreement with the
   adjudicator, not between the coders.

**And even were it computable, it would not be inter-coder reliability.** Per §3.5.2 of the paper,
both coders are LLM agents differing only in stance prompt. Their agreement rate is an **upper
bound** on reliability, not an estimate of it, and reporting it as kappa would be the kind of
misrepresentation that gets a paper retracted rather than rejected. The number above is reported
as a **methodological measurement of stance-prompt divergence**, which is what §3.5.2 says it is.

### 2.3 The measurement §3.5.2 asked for

§3.5.2 says the rate at which two opposed-stance LLM coders disagree "belongs in the paper, in
the LLM usage section, as a measured result rather than a caveat." On this pilot:

- **Divergence is concentrated, not diffuse.** Zero disagreement on tier, placement, evidence
  grade and enforceability; 85.7% disagreement on coverage cells.
- **Divergence tracks rubric under-specification, not textual ambiguity.** Two of six coverage
  disagreements involved no disagreement about the text at all.
- **The opposed-stance design worked as designed.** §3.5.2 calls the LLM pass a "disagreement
  detector" that surfaces "the cells where the text is genuinely ambiguous, which is where human
  attention is worth spending." It surfaced six cells, all in one axis, and the axis it surfaced
  is the one §3.2 identifies as the paper's own greatest risk.

---

## 3. The disagreement record

Six disagreements, all on CaMeL (arXiv:2503.18813), all on the coverage axis. Each is
adjudicated against the text of `ACTION-SURFACE-v1.0`, which is the frozen instrument and
therefore the only legitimate tiebreaker.

**Standing note on the adjudicator.** The rulings below were made by the same program that wrote
the enumeration. That is a real weakness, and it is why every ruling cites the specific clause of
`ACTION-SURFACE-v1.0` it turns on: a reader who rejects the clause can reject the ruling without
having to re-read the paper. It also means the six-of-six direction of the rulings (§3.7) must
not be read as evidence of charitable-coder bias.

---

### D-1 · E1 file write — `partial` vs `covered` → **ruled `partial`**

**Conservative span.** "document create/append/delete in the workspace suite passes the
chokepoint … and direct filesystem access is excluded only by language restriction, not by
policy: 'We build a custom Python interpreter that operates over a restricted version of Python.'
Completeness of that restriction is not established; the authors note 'some violations of the
dialect are easily detectable and fixable automatically,' implying not all are."

**Charitable span.** "the file-mutating tools are exposed only through the interpreter and every
call is policy-checked … 'Before executing a tool with a given set of variables as input, relevant
security policies are applied to that variable and its dependencies… the tool's execution is
blocked.'"

**Ruling and reasoning.** `partial`. `ACTION-SURFACE-v1.0` §2 scopes E1 as "writes anywhere the
process can reach, including outside any declared workspace," and counting rule 2 states that
"descendants inherit nothing — a descendant's effects are not mediated because its parent was
invoked through a mediated channel." The charitable coder scored the **tool surface**; the
enumeration scores the **effector**. A write performed inside a tool implementation, or by
anything that implementation starts, is never evaluated against a policy. The charitable coder's
own quoted mechanism stops at "before executing a tool," which is the boundary, not past it.
`partial` rather than `not-covered` because the mediated calls do carry real, blocking decisions,
which both coders confirm.

---

### D-2 · E2 subprocess spawn — `not-covered` vs `not-applicable` → **ruled `not-covered`**

**Conservative span.** "no subprocess effector exists in the evaluated tool set and no mechanism
reaches below a tool invocation. Capability propagation explicitly stops at the tool boundary: 'as
soon as the agent needs to interact with external, third-party tools, the challenge of ensuring
capability support arises.' Descendants are entirely outside the dependency graph."

**Charitable span.** "Coded not-applicable rather than covered because the effector is absent from
the evaluated action surface, not because mediation fails. Note for adjudication: **were a shell
tool added, the interpreter would mediate the top-level call only; it has no visibility below the
tool API boundary, so descendants would be uncovered.**"

**Ruling and reasoning.** `not-covered`, on three grounds.

1. **`ACTION-SURFACE-v1.0` defines no `not-applicable` value.** §5 names three states — mediated,
   not-mediated, and `observed-not-mediated` — and §6 defines coverage as "the subset of {E1…E7}
   its guarantee reaches." There is no fourth value and no license to invent one.
2. **The work claims generality.** CaMeL is presented as a defense for tool-calling agents, and
   the restricted interpreter is a design choice inside that claim, not a scope limit on it. An
   effector absent from one evaluation harness is not absent from the claim.
3. **The coders do not actually disagree about the text.** The charitable coder's own adjudication
   note states the descendant conclusion the conservative coder reached. This is a label collision,
   not a reading collision.

**This is the most consequential ruling in the pilot.** E2 is the effector §3.2 identifies as "the
single largest source of inflated coverage claims," and `not-applicable` is precisely the escape
hatch that would let a control mediating "the first spawn and nothing beneath it" avoid being
scored on it. Admitting the value would defeat the axis.

---

### D-3 · E3 network egress — `partial` vs `covered` → **ruled `partial`**

**Conservative span.** "the ACTION-SURFACE definition includes egress by any descendant, which is
unmediated once a tool runs; and the authors demonstrate working egress-based leakage: 'an
adversary can leak a private variable to an external service through indirect dependency' … Also
§8's spy tool: 'the tool passively monitors and exfiltrates data processed by the agent.'"

**Charitable span.** "egress-capable tools are named as first-class policy targets … Concession
noted: covert-channel egress survives. 'We find that CaMeL is vulnerable to side-channel attacks'
… STRICT mode closes the two demonstrated instances: 'When using the interpreter in STRICT mode,
this attack is prevented by CaMeL.'"

**Ruling and reasoning.** `partial`. E3 is defined as egress "by the agent process or any
descendant," with the enumeration's stated rationale that "exfiltration after a successful
injection is the consequence being bounded, and it rarely originates in the agent process." The
charitable coder's argument is genuinely good, and it is why this is `partial` and not
`not-covered`: the named egress tools are interposed, the decisions are real, and STRICT mode
closes both demonstrated leaks. But `covered` would require the guarantee to reach descendant
egress, and the work does not claim that. The charitable coder anticipated this exact split in
its own notes.

---

### D-4 · E4 VCS push — `not-covered` vs `not-applicable` → **ruled `not-covered`**

**Conservative span.** "no VCS tool, no git, no push appears anywhere in the policy language, the
benchmarks, or the real-world integrations… would be mediated only as an opaque tool call with no
reach past invocation."

**Charitable span.** "no VCS tool appears anywhere in the AgentDojo tool set given to the P-LLM
(Workspace, Banking, Travel, Slack suites only)."

**Ruling and reasoning.** `not-covered`, on the same value-set grounds as D-2. The two coders
agree on every fact: the effector is absent from the evaluated harness, and mediation would
terminate at invocation. Only the label differs.

---

### D-5 · E5 package install — `not-covered` vs `partial` → **ruled `not-covered`**

**Conservative span.** "package installation is never mentioned. Even under the most generous
reading, an admitted install tool call executes third-party lifecycle hooks entirely below the
argument predicate — the check terminates at the tool boundary, which is exactly where this
effector begins."

**Charitable span.** "no install effector is mediated — installation happens outside CaMeL
entirely — but the paper claims coverage of the installed component's data access… Partial rather
than covered because the third-party code still runs and is trusted to honor capabilities."
Self-flagged in the same record: "whether E5 deserves partial at all, given CaMeL mediates
nothing about installation — I granted it on the strength of the Scenario 2 claim."

**Ruling and reasoning.** `not-covered`. `ACTION-SURFACE-v1.0` §2 defines E5 as "adding a
dependency," separated from the others "because it is the supply-chain effector — it executes
third-party install hooks with the agent's privileges." Counting rule 5 requires that "mediated
requires a decision," and there is no decision point at install because CaMeL never sees one.
What the charitable coder scored is a constraint on an already-installed component's **data
access**, which is E3 and E6 behavior, not E5. Collapsing it into E5 is, in the enumeration's own
phrase, "the most flattering available error." The coder flagged the grant against itself, which
made this adjudication cheap.

---

### D-6 · E7 sub-agent spawn — `partial` vs `covered` → **ruled `partial`**

**Conservative span.** "the one sub-model CaMeL defines is deliberately authority-free — 'The
Quarantined LLM (Q-LLM) is a large language model that has no tool access' — and STRICT mode
propagates dependencies through it. But the Q-LLM is itself the documented injection vector for
the exception channel… and there is no general mechanism for spawning arbitrary sub-agents with
delegated authority."

**Charitable span.** "the only sub-model invocation is interposed and stripped of authority by
construction … A genuine recursive planner is explicitly future work and explicitly policy-gated:
'providing the P-LLM with an extra tool which consists of another instance of a P-LLM… security
policies for executing this tool should be very strict.'"

**Ruling and reasoning.** `partial`. E7 is defined as "delegating to another agent or model
instance **with its own tool access**," separated "because authority propagates here and does not
naturally diminish." The Q-LLM has no tool access, so **it is not an instance of the E7 effector**;
what the charitable coder scored as `covered` is the effector's absence plus a design that keeps
it absent. Meanwhile the mechanism that would apply to real delegation — policy-gated invocation
of a P-LLM-as-tool — is described by the authors as unimplemented future work. So the guarantee
reaches E7 in proposal only. `partial` rather than `not-covered` because the mechanism is named
and would plausibly apply; `partial` rather than `covered` because nothing implemented or
evaluated exercises it.

---

### 3.7 What the disagreements diagnose

| Disagreement | Root cause | Class |
|---|---|---|
| D-2 (E2), D-4 (E4) | `not-applicable` is not a value the frozen enumeration defines | **Rubric defect** |
| D-1 (E1), D-3 (E3), D-6 (E7) | `covered` vs `partial` when the top-level call is mediated but descendants and covert channels are not | **Depth-of-mediation rule missing** |
| D-5 (E5) | Over-generous grant on an adjacent claim; self-flagged by the coder | **Coder error, caught by the coder** |

**All six rulings went to the conservative coder.** That is one work, and it is not evidence of a
systematic charitable bias — it is the expected consequence of adjudicating against an enumeration
whose counting rules were written to resist exactly the inflations the charitable stance produces.
The finding to take from it is not "the charitable coder was wrong six times" but **"the frozen
enumeration resolved six of six disagreements without a judgment call,"** which is the strongest
available defense of the coverage axis and should be said in those words in §3.2.

### 3.8 The three rubric amendments the pilot triggers

`ACTION-SURFACE-v1.0` §8 requires that changes carry a version bump, a dated changelog entry, and
re-scoring of anything already scored. These are therefore recorded as **v1.1 triggers, not
applied here**:

1. **Fix the value set.** Coverage cells take exactly {`covered`, `partial`, `not-covered`}. There
   is no `not-applicable`. An effector absent from a work's evaluated surface is `not-covered`
   when the work claims generality; the generality test is recorded per row with a span.
2. **Define the depth rule for `covered`.** A cell is `covered` only if the guarantee reaches the
   effector **including descendants**, per counting rule 2. Mediation of the top-level call alone
   is `partial`. This makes D-1, D-3 and D-6 mechanical rather than argued.
3. **Define what "advertised tier" is coded from.** See §5.2 — this one is not cosmetic.

---

## 4. The populated corpus table

**Pilot rows only. n = 2 of an intended 10.**

Coverage legend: **●** covered · **◐** partial · **○** not-covered.
Delta is advertised tier minus scored tier, in tiers of demotion.

| id | Title | Advert. | **Scored** | Δ | Placement | E1 | E2 | E3 | E4 | E5 | E6 | E7 | Evid. | Schneider |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| arXiv:2503.18813 | Defeating Prompt Injections by Design (CaMeL) | T3 | **T3** | **0** | A2 | ◐ | ○ | ◐ | ○ | ○ | ◐ | ◐ | L3 | **Split** |
| arXiv:2504.11703 | Progent: Securing AI Agents with Privilege Control | T3 | **T3** | **0** | A2 | ◐ | ○ | ◐ | ○ | ○ | ◐ | ◐ | L2 | **Split** |

**Row provenance.**

- **CaMeL** — both coders, full text retrieved by both, adjudicated on all six coverage
  disagreements per §3. Tier, placement, evidence grade and Schneider verdict were unanimous and
  required no adjudication.
- **Progent** — **conservative coder only.** The charitable-coder record was not delivered, and
  the conservative record arrived truncated mid-sentence in its tier rationale. This row is
  **single coded and therefore does not satisfy §4's two-coder commitment.** It is printed because
  its coded fields are complete and legible; it must be re-coded before it enters any finding.

**Schneider column.** "Split" is not one of §7's anticipated values. Both works enforce a
prefix-closed safety property — a per-call allow/deny predicate over a tool name, its arguments,
and their transitive dependencies, decided from the trace prefix and enforced by halting, which is
a textbook Schneider execution monitor — while advertising an information-flow objective
(non-interference for CaMeL, "only send data to authorized recipients" for Progent) that is a
hyperproperty over sets of executions and is **not** enforceable by any execution monitor. Both
coders on CaMeL reached this independently and located the residual in the same three channels:
whether a call happened, how many times, and when.

**Coverage vectors are identical across the two works** — ◐○◐○○◐◐ in both cases. On n = 2 that is
not a pattern, but it is worth watching: both are application-chokepoint controls over a
tool-dispatch boundary, and if the vector is a **property of the interposition point rather than
of the individual system**, the coverage axis will produce far less per-row variance than §3.2
assumes, and the finding shifts from "these systems differ in coverage" to "this class of
interposition point has a fixed coverage ceiling." That would be a better result. It is also
testable cheaply: the two uncoded T2 counterweights (AgentCgroup, MCP-SandboxScan) should produce
a visibly different vector, and if they do not, the axis is measuring the enumeration rather than
the corpus.

---

## 5. Early findings, stated carefully

Every claim in this section carries **n = 2 works (1 doubly coded)**. None is a corpus result.

### 5.1 Demotions under the weakest-link rule: 0 of 2

Neither coded work demotes. Both advertise and score T3.

**This does not disconfirm §3.1's prediction, and the paper must not report it as if it might.**
The pilot has no power to test the prediction, because none of the six screening-flagged demotion
candidates was coded and no T2 work was coded either. The honest statement for §5 is that the
demotion rate is **not yet measured**, and the honest next action is §7.1 below.

What the pilot does show is a **second-order result worth keeping**: on both works, advertised and
scored tier coincided, and both coders independently recorded this as an **honesty finding rather
than an inflation finding**. The charitable coder considered and explicitly declined the reading
that CaMeL's libcap, Capsicum and CHERI lineage citations advertise T2 or T1 semantics, on the
ground that the paper "never claims otherwise and locates its own mechanism precisely and
repeatedly at the interpreter." That decline is load bearing, which brings us to:

### 5.2 A rubric hole that threatens the headline finding

**What is "advertised tier" coded from — the rhetoric, or the mechanism section?**

Both coders coded it from the mechanism section. If that rule holds corpus-wide, then **the delta
is near zero by construction for every paper that describes its own mechanism accurately**, and
the headline number stops measuring "systems marketed as enforcing bind only at a chokepoint" and
starts measuring the much narrower "systems that misdescribe their own mechanism." Those are
different findings, and only one of them is the paper's claim.

The screening rationales assume the other rule. SEAgent is flagged because it "advertises mandatory
access control — a term with a precise kernel meaning"; MiniScope because "the borrowed vocabulary
does the overclaiming"; CaMeLs-Can-Use-Computers because "the tier label and the interposition
point disagree **in the title**." Every one of those is a rhetoric-level advertisement that a
mechanism-section reading would score away.

**This must be decided before the full pass, and it should be decided as a two-column coding:**
advertised-by-rhetoric (title, abstract, framing) and advertised-by-mechanism (the interposition
paragraph), scored separately, with the delta reported against each. The gap between the two
columns is itself a finding — it is the measure of how far a paper's framing outruns its own
described mechanism — and it costs one extra field per row.

### 5.3 Coverage distribution

Adjudicated, both works, n = 2:

| Effector | `covered` | `partial` | `not-covered` |
|---|---|---|---|
| E1 file write | 0 | 2 | 0 |
| **E2 subprocess spawn** | 0 | 0 | **2** |
| E3 network egress | 0 | 2 | 0 |
| **E4 VCS push** | 0 | 0 | **2** |
| **E5 package install** | 0 | 0 | **2** |
| E6 credential use | 0 | 2 | 0 |
| E7 sub-agent spawn | 0 | 2 | 0 |

**E2 is least covered, as predicted — and tied.** §3.2 singles E2 out as "the exclusion that
inflates coverage most," and §5 predicts it will be the least covered effector. On the pilot, E2,
E4 and E5 are all uniformly `not-covered`. The E2 prediction is **consistent with the data and not
distinguished by it**, and the paper should say "E2, E4 and E5" until the full pass separates them.

**No cell scored `covered`, on either work, on any effector.** Fourteen cells, zero covered. Stated
as a claim about the pilot only, this is the finding with the sharpest consequence: it means both
works fail Anderson's "always invoked" property on every effector by §6.4's own criterion, and
§6.4's argument that "a control that mediates three of seven effectors is not always invoked" is
too generous — neither pilot work mediates **one** of seven completely.

### 5.4 Schneider: 2 of 2 split, 0 of 2 clean

No work in the pilot has a claimed policy cleanly inside the enforceable class, and none has one
cleanly outside it. Both are splits. §7 should be restructured around three values — enforceable,
non-enforceable, and split — with the split cases reported as the substantive result, because the
split is where the guarantee gap is. §7's current framing ("identify claimed policies outside the
enforceable class") would record both pilot works as **unremarkable**, and both coders found the
opposite: on both works the enforceability gap **is** the residual attack surface, and on CaMeL it
is exactly where the authors' own demonstrated side channels live.

Note also that CaMeL's formal security definition (the PI-SEC game's per-prompt allowed-action set)
is, in the authors' own footnote, "only used as part of the security definition and not as part of
any design." A definition that is not enforced is a third object again, distinct from both the
surrogate and the goal. If that pattern recurs, §7 needs a fourth category.

### 5.5 Composition: no non-composing pair observed, and the axis needs a second value

Both works are A2. Under §6.1 two A2 controls are compatible, so the pilot's one available pair
composes and the composition result is untested.

**The more serious result is that placement is not single-valued.** Both coders recorded CaMeL's
primary threat model as A2, and both recorded, in their adjudication notes, that the work's §8
scenarios assert coverage against an A1 adversary (a rogue user, which inverts the paper's own
trusted-prompt assumption) and an A5-flavored one (a malicious tool whose documentation
prompt-injects tool selection), neither of which is evaluated. One coder argued that A3 — an
adversary in the model's weights — is arguably the work's real strength, since the design holds
with an untrusted planner LLM, but declined to code it because no maliciously trained model is
tested.

§3.3 requires placement to be a **partition**, and a partition forces one value per work. On this
work, forcing one value discards three claims, two of them the work's own. **The composition matrix
in §6.2 would then be built on a lossy projection of the very field it depends on.**

The fix is a **primary/secondary encoding**: one coded primary placement, extracted from the
stated threat model per G3, plus a set of asserted-but-unevaluated secondary placements, each with
a span and an evidence grade of its own. The compatibility matrix is computed on primaries — so
§3.3's partition argument survives — and the secondaries become the **conditional** cells the
matrix already anticipates ("compose / does-not-compose / conditional, with the condition stated").
That is not a weakening of §6; it is where §6's third value comes from.

---

## 6. Honest limits

**Sample size, restated.** The pilot as delivered is **2 works**, of which **1** was coded by both
coders. The intended pilot was 10. Every finding in §5 carries n = 2 and none is a corpus result.
Six of the eight works needed to make the pilot decisive were identified at screening and were not
coded (§1.3).

**The Progent row is single coded** and therefore does not meet §4's two-coder commitment. It is
printed with that flag and must be re-coded before it supports any claim.

**The Progent conservative record arrived truncated**, cut off mid-sentence inside its tier
rationale at "…no kernel, namespace, capability, or sandbox mechanism appears,". Its coded fields
(tier, placement, coverage vector, evidence grade, enforceability verdict, cheapest defeat, stated
guarantee, coverage spans) are complete and were used; the truncated tail was not reconstructed,
and nothing in this document depends on it.

**The screening payload was truncated** after 28 included records, and **no excluded set was
delivered**. The included count is a floor. The excluded count, the gate-failure distribution, and
the attrition rate against §4's expected 10–20% are all **unreportable** until that array exists.

**Full text was retrieved for every coded work.** All three coder records report
`fullTextRetrieved: true`. §4's "no work is scored from an abstract" commitment holds on the pilot
without exception, which is worth stating because it is the commitment most easily broken silently.

**No kappa is reported anywhere in this document**, for the three reasons in §2.2. Any future
version that reports one must first satisfy all three, and must still label it stance-prompt
divergence rather than inter-coder reliability until human coding exists.

**Both coders are LLM agents of the same model family** differing only in stance prompt, per
§3.5.2. Their agreement is an upper bound on reliability. **No row in this document has been
human coded**, which means, by §3.5.2's own standard, **no row here is yet eligible to enter a
headline finding.**

**The adjudicator is not independent.** §3's rulings were made by the same program that authored
`ACTION-SURFACE-v1.0`. Each ruling cites the clause it turns on so that the dependency is
inspectable, but it remains a dependency.

---

## 7. What this changes, and what to do next

### 7.1 The venue decision, under the paper's own rule

The draft's decision rule is explicit: *"If agreement is high and the weakest-link rule produces
clear demotions — target SaTML. If agreement is poor, or the rule produces few demotions — the
method needs work before any submission, and USENIX Cycle 2 is the correct target."*

**Both clauses of the second arm are satisfied by the delivered pilot.** Agreement on the coverage
axis is 14.3%, and the demotion count is zero. Read literally, the rule says USENIX.

**Read carefully, the rule cannot be applied yet**, because it was designed to be decided on a
pilot of ten and it has been handed two — and the two are the two the screening record itself
flags as tier-honest anchors, which is the selection under which zero demotions is the *expected*
outcome rather than an informative one.

**The decidable version of the rule.** Code the six demotion candidates and the two T2
counterweights named in §1.3, both coders, spans mandatory. That is eight works, and it is exactly
the set with power to move the demotion number in either direction.

- **If those eight produce clear demotions and the two coverage amendments in §3.8 lift coverage
  agreement**, the SaTML branch is live and the 22 September abstract registration is reachable.
- **If they do not**, the rule's second arm fires on data that can actually support it, and USENIX
  Cycle 2 is correct — which is also the branch that buys the time to do the human coding §3.5.2
  requires and the empirical artifact in §8.

**Default if the eight are not coded before 22 September: USENIX.** A venue decision made on n = 2
is not a decision made on the pilot; it is a decision made on the calendar, which the draft
explicitly forbids.

### 7.2 Method changes the pilot has already earned

1. **Amend `ACTION-SURFACE` to v1.1** with the value set and the depth rule (§3.8, items 1–2),
   version bumped, changelogged, and with the two pilot rows re-scored — which, as it happens, the
   §3 adjudication has already done.
2. **Split the advertised-tier field into rhetoric and mechanism columns** (§5.2). This is the
   change that protects the headline finding, and it is one field.
3. **Add primary/secondary adversary placement** (§5.5), so §6.2's conditional cells have a source.
4. **Restructure §7's Schneider column to three values** — enforceable, non-enforceable, split —
   with split as the reportable result (§5.4).
5. **Produce the excluded set** with per-work gate attributions, discharging §4's commitment.
6. **Begin human coding on any row intended for a headline finding**, per §3.5.2. Currently that
   is zero rows, and no finding in this document is eligible until it is not.
