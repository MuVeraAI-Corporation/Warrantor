# SoK: Acceptance Is Not Action

### Where agent containment actually binds

### Adjudicating the guarantees of execution controls for autonomous coding agents

**Research paper · Draft 1 (structure and methodology frozen) · 2026-08-30 · Vikram Jha**
*Catalog ref: T-12 · **IEEE SaTML 2027 — abstract 22 Sep 2026, paper 29 Sep, artifacts 2 Oct. DECIDED 2026-08-30.** · see Schedule*

> **Repositioned 2026-08-30.** The original conception — a systematization organizing the agent
> containment literature — is **dead on novelty**. arXiv:2607.05743 (July 2026) systematizes 39
> papers across 17 categories over substantially this population. This paper is therefore **not a
> catalog**. It adjudicates: it scores published guarantees at the tier where they can actually be
> defeated, derives a coverage measurement the literature does not report, and identifies claimed
> policies that lie outside the enforceable class.
>
> **Corpus screening not yet performed.** §4's method is frozen; §§5–7 populate from the September
> screening pass. Every derived cell will be traceable to a quoted span.

---

## Abstract

Autonomous coding agents execute code, write files, spawn subprocesses, install packages and reach
the network. A large and fast-growing literature proposes controls to contain them. That literature
has been catalogued; it has not been adjudicated.

We systematize execution controls for autonomous coding agents along three orthogonal axes and, in
doing so, perform two measurements the literature does not report. First, we apply a **weakest-link
tier rule**: each control is scored at the *lowest* enforcement tier at which its guarantee can be
defeated — cryptographic, operating-system, or application-proxy — rather than the tier it
advertises. Second, we **derive mediation coverage** for each system against a frozen enumeration of
the coding-agent action surface, because no work in the corpus reports it. We further classify each
work by **adversary placement** relative to its interposition point, which yields our central
composition result: two controls compose only if their assumed adversary placements are compatible,
and a specific, nameable set of published guarantees do not.

We apply Schneider's enforceability result to the corpus and identify claimed policies outside the
class any execution monitor can enforce. We grade every work's evidence level from claim-only to
reproducible bypass. **One scored system is subject to a declared conflict of interest; it is scored
under the same procedure as every other row, and it does not survive that procedure intact.**

**The central result.** Across 15 systems re-scored under a two-column tier rule, **the cryptography
in this literature binds acceptance, not action.** Seven systems make a claim whose forgery requires
breaking a signature, a hash chain or an attestation — **tier T1 of acceptance**. Only one bounds an
action cryptographically. **Eleven bound actions only where they traverse an application chokepoint.**
The modal pattern, five of fifteen, is **A-T1 over B-T3**: a strong cryptographic claim about what a
relying party will accept, resting on an application-layer bound on what the process can do. We name
that pattern the **authorization–execution gap**, and show it has a composition consequence: such a
system delivers its advertised guarantee only atop an operating-system substrate it does not itself
provide. The corpus contains both halves and almost no system that is both.

**Two findings the corpus did not want to give up.** **Tier T2 of acceptance is empty** — no system
makes acceptance turn on a kernel-mediated fact. And the best-placed candidate in the set, an Intel
TDX trusted plane, fails to populate T1 of acceptance at all: the rhetoric is unforgeability, the
cryptographic construction binding the token is never given, and the verifier is untrusted.

**Supporting results (25 works, 50 codings, full text on 50 of 50).** Under the action column,
**12 of 14 systems with a scorable advertised tier bind lower than they advertise**, five by two
tiers. **Two of 105 coverage cells reach `covered` (1.9%)** — thirteen of fifteen systems fully
mediate nothing. **Network egress is reached by 14 of 15 systems and bounded completely by none.**
And the enforceability verdict is `split` on **50 of 50 codings** across every tier the corpus
contains: a monitorable safety surrogate enforced beneath a non-monitorable advertised objective.
Not modal. Universal.

⚠️ **The instrument was wrong first, and we report that.** A single-column weakest-link rule
collapsed every cryptographic system to the application tier, because "defeated by an actor that
never consults the verifier" and "defeated by any path that does not traverse it" are the same
sentence for an agent-side guarantee. §3.1.1 states the defect and the repair. The repair was
validated against a prediction made before it ran: coders had recorded a narrower genuinely-T1
guarantee in four of five cryptographic works, and **exactly those four rise to T1 of acceptance**.

Selection caveat: the fifteen were chosen for tier-axis power, so demotion rates are upper bounds and
are never reported as corpus rates. Full corpus pass follows the 15 November freeze.

---

## 1. Introduction

An autonomous coding agent is a language model with a tool loop and a shell. It edits files, runs
builds, installs dependencies, pushes commits and calls networks — and it decides, within a task,
which of those to do next. The security question is not whether it will take an action nobody
anticipated. It is what happens when it does.

A substantial literature has grown to answer that. It spans sandbox isolation, capability and access
control, policy enforcement, time-of-check/time-of-use defenses, protocol-level threat analysis,
identity and delegation, execution provenance and network egress control. It has recently been
systematized: arXiv:2607.05743 organizes 39 papers from 2023–2026 into 17 categories and reports,
among other findings, that policy enforcement fails at rates between 69% and 98%, and that up to
17.1% of benign actions fall out of scope under realistic prompting.

**That systematization is a taxonomy, and this paper is not another one.** Organizing by topic tells
a reader what has been studied. It does not tell them whether the guarantees hold, whether two
controls can be deployed together, or how much of an agent's behavior any control actually sees.

Those are adjudication questions, and they are unanswered.

### 1.1 What this paper does differently

| | arXiv:2607.05743 (Jul 2026) | This paper |
|---|---|---|
| Organizing principle | 17 topical categories | 3 orthogonal axes, each partitioning |
| Tier treatment | none | **weakest-link scoring** — lowest tier at which the guarantee falls |
| Coverage | not addressed | **derived** against a frozen action surface |
| Threat placement | per-paper, unaggregated | **adversary placement** as a partition |
| Composition | not addressed | pairwise compatibility as the central result |
| Enforceability theory | not applied | Schneider applied to claimed policies |
| Evidence quality | not graded | L0–L3 per row |
| Authors' own system | n/a | **scored first, at full severity** |

We state this on page one deliberately. A reviewer who has read 2607.05743 and reaches our page six
without seeing it named will stop reading, and they would be right to.

### 1.2 Contributions

1. **The weakest-link tier rule** (§3.1) and its application to the corpus. A control that signs its
   mandates but enforces them in an in-process hook is proxy-tier, because forging the signature is
   unnecessary when the hook can be bypassed. This rule prevents the "hybrid" bin into which prior
   taxonomies in this space have dissolved.
2. **Derived mediation coverage** (§3.2) against a frozen seven-effector enumeration. This is a
   measurement the SoK performs, not a classification of what authors claim.
3. **Adversary placement** (§3.3) as a partition, and the **composition compatibility result** it
   makes possible (§6).
4. **Application of Schneider's enforceability result** (§7) to identify claimed policies that no
   execution monitor can enforce.
5. **An evidence grade** per work (§3.4), L0 claim-only to L3 reproducible bypass, and the
   observation this permits about enforcement claims that have never been tested above L1.
6. **A small empirical artifact** (§8) demonstrating bypass on representative systems, one per tier.

---

## 2. Scope, and the classical spine

### 2.1 Inclusion

A work enters the corpus if it: (**G1**) targets autonomous or semi-autonomous agents that execute
code or invoke tools with side effects; (**G2**) proposes, implements or evaluates a control
intended to constrain those effects; (**G3**) states a threat model naming an assumed-compromised
component; and (**G4**) makes an authority or tamper-evidence claim, not merely a visibility claim.

**G4 is doing real work.** It excludes agent-observability systems whose only claim is that you can
see what happened. Those matter, and they are not controls.

### 2.2 Exclusion

Excluded: alignment and training-time safety; content moderation and guard models, which operate on
content rather than capability and are surveyed elsewhere; general LLM security without an execution
surface; and position papers without a mechanism.

### 2.3 The classical spine — positioning, never rows

Complete mediation, least privilege, confinement, execution monitors and capability confinement
enter this paper **without a date bound and without tiering**. They are the evaluative vocabulary and
the positioning apparatus. They are never scored as corpus rows and never coverage-graded.

We say so explicitly because SoK reviewers look for exactly this discipline, and because a
systematization that tiers Saltzer and Schroeder alongside a 2026 preprint has confused its own
categories.

The classical results that do real work here:

- **Complete mediation** is the property our coverage axis measures the absence of.
- **Confinement** in Lampson's sense names what a proxy-tier control cannot achieve.
- **Schneider's enforceability result** bounds what any execution monitor can enforce, and §7 applies
  it to claimed policies in the corpus.
- **Anderson's three properties** of a reference monitor — tamperproof, always invoked, small enough
  to verify — are the cross-cut in §6.4.

---

## 3. The three axes

### 3.1 Axis 1 — Enforcement tier, under the weakest-link rule

Three tiers, distinguished by what defeats them:

| Tier | Binds | Defeated by |
|---|---|---|
| **T1 Cryptographic** | What a compliant verifier will accept | An actor that never consults the verifier |
| **T2 Operating system** | What the process can do, regardless of intent | Kernel vulnerability, misconfiguration, over-broad capability |
| **T3 Application proxy** | What passes the chokepoint | Any path that does not traverse it |

**The rule.** *A work is scored at the lowest tier at which its guarantee can be defeated, not the
tier it advertises.*

**Worked example.** A system issues cryptographically signed capability mandates and enforces them
via an in-process hook in the agent harness. It presents as T1. It scores **T3**, because an
adversary need not forge a signature when the hook can be bypassed by a subprocess that never calls
it. The cryptography is real and it constrains a different adversary than the one the system faces.

**Why this rule is the paper.** Every prior taxonomy over this literature dissolves into a "hybrid"
category once systems combine mechanisms. Weakest-link scoring refuses the hybrid bin. It also
produces a testable prediction: **systems marketed as enforcing bind, in the majority of cases, only
at a chokepoint — and a chokepoint bound ends at the first subprocess spawn.** ⟦Quantify from the
screening pass.⟧

#### 3.1.1 ⚠️ The T1/T3 collapse, and the repair

**The decisive pass found that the rule as stated above cannot measure its own top tier.** Five works
advertised cryptographic enforcement. All five scored T3. In four of the five, the coder who scored
T1 wrote in the same record that a *narrower* guarantee in the same paper is genuinely T1 and proved.

The cause is textual, not empirical:

> **T1 is "defeated by an actor that never consults the verifier." T3 is "defeated by any path that
> does not traverse it." For an agent-side guarantee these are the same sentence.**

Any work claiming a compromised agent *cannot act* outside its authority is therefore T3 by
construction, however sound its cryptography, because the agent can always write a file. The rule
could not distinguish two very different situations: **the cryptography does not bind execution** —
a real finding, and the one §9 makes about the authors' own system — from **the guarantee happened to
be phrased in agent-side terms**, which is a sentence-level accident.

**The repair is one column split into two.**

| Column | Question | Sandlock example |
|---|---|---|
| **Tier of acceptance** | At what tier is a *claim* verified — what will a relying party accept? | n/a (no signed claim) |
| **Tier of action** | At what tier is an *action* bounded — what stops the process? | T2 (kernel) |

A signed capability token can be **T1 of acceptance and T3 of action** simultaneously, and saying so
is more informative than either verdict alone. It also states the §9 system's position precisely: its
receipts are T1 of acceptance, its enforcement is T3 of action, and the gap between those two columns
is what that section is about.

**Plus a mechanism-specificity floor.** A tier claim is scorable only where the paper names the
mechanism that would have to fail. Works that gesture at a mechanism without an interposition point
are recorded as `unscorable`, not silently demoted — which is what happened to one work in this pass
and should not have.

**Outcome of the re-score, run 2026-08-30 over all 15 works.** The repair is discriminating rather
than permissive, which is the test that matters — a fix that promoted everything would be worthless.

| Column A — acceptance | n | | Column B — action | n |
|---|---|---|---|---|
| A-T1 cryptographic | **7** | | B-T1 cryptographic | **1** |
| A-T2 operating system | **0** | | B-T2 operating system | 2 |
| A-T3 application | 7 | | B-T3 application | **11** |
| A-NONE | 1 | | unscorable | 1 |

**Validated against a prior prediction.** Before the re-score, coders had independently recorded that
four of the five cryptographic works contained a *narrower* guarantee that is genuinely T1 and
proved. **Exactly those four rise to A-T1.** All seven works with a recorded narrower guarantee score
A-T1; **zero works without one were promoted**; and one recorded guarantee was declined on a stated
criterion. The repair therefore tracks evidence gathered before it existed, which is the difference
between a fix and a rationalization.

**Six works remain A-T3/B-T3.** The old rule was right about them. The repair does not rescue systems
whose rhetoric outran their mechanism — it separates them from systems whose cryptography was real
and was being measured against the wrong question.

**Re-scoring obligation.** Every tier cell scored under the single-column rule is re-scored under the
two-column rule before entering a finding. This is a rule change discovered by measurement, and it is
disclosed as such rather than presented as the design.

**Assignment procedure.** For each work: enumerate the guarantee as stated; identify the mechanism
that would have to fail for it not to hold; identify the cheapest adversary action that causes that
failure; assign the tier of the mechanism that action defeats. Every assignment carries a quoted span
from the source. Disagreements between coders are adjudicated on the record and published.

### 3.2 Axis 2 — Mediation coverage, derived

**No work in the corpus reports coverage.** Extraction from author claims is not viable, because
authors describe what their control mediates rather than what fraction of the agent's action surface
that represents. So the SoK derives it.

**The frozen action surface.** Seven effectors, frozen 2026-08-30 as [`ACTION-SURFACE-v1.0`](ACTION-SURFACE-v1.md)
and published with the artifact. That document also reconciles this enumeration with T-01’s
instrumentation classes, so the derived scores here and the measured score in §9 share a denominator:

| | Effector | Note |
|---|---|---|
| E1 | File write | Including rename and unlink |
| E2 | Subprocess spawn | **Including descendants** — the exclusion that inflates coverage most |
| E3 | Network egress | By the agent or any descendant |
| E4 | VCS push | Distinguished from E1 because its blast radius leaves the machine |
| E5 | Package install | The supply-chain effector |
| E6 | Credential use | Environment, config, keychain, metadata endpoint |
| E7 | Sub-agent spawn | Delegation, where authority propagates |

Coverage for a system is the subset of {E1…E7} its guarantee reaches, at its assigned tier, with a
quoted justification per cell.

**This axis is either the paper's best contribution or its fatal weakness**, and the difference is
entirely procedural. Therefore:

- The enumeration is **frozen and published before coding**, not adjusted as the corpus is read.
- **Two independent coders**, with Cohen's κ reported and every disagreement adjudicated on the
  record.
- **Every derived cell is traceable to a quoted span in the source paper.** A cell with no span is
  not recorded. We borrow this discipline from AgentThread's validator design, which rejects any
  record whose source span is absent from the document.

Without that procedure a reviewer calls this the authors' opinion rendered as a heatmap, and they
are right.

### 3.3 Axis 3 — Adversary placement

**Where does the work assume the attacker sits, relative to the interposition point?**

| | Placement | Typical class |
|---|---|---|
| **A1** | Outside the system entirely | Perimeter and egress controls |
| **A2** | In inputs or retrieved context | Indirect injection defenses, tool-output screening |
| **A3** | In the agent's policy or weights | Misaligned or compromised model; behavioral bounds |
| **A4** | Inside the harness or orchestrator process | In-process hooks, protocol-layer policy, TOCTOU |
| **A5** | Below the harness | Kernel, hypervisor, supply chain, package install |

**Why this axis and not "evidence model."** An earlier design used evidence model as axis 3. It
collapses: isolation, capability, policy-enforcement and TOCTOU papers make no tamper-evidence claim
at all, so the column reads *none* for most rows and populates almost exclusively in the receipts and
attestation cluster — **which is the present authors' own research area.** An axis whose only
populated cells are the authors' own work reads as a systematization arguing toward its sponsor, and
it hands a reviewer the most damaging thing they can say about an SoK from an organization that ships
in the space.

Adversary placement is the correct substitution on four grounds: it is **extractable** rather than
derived, since G3 already requires a stated threat model; it **partitions the corpus differently
from axis 1**, which is what an axis must do to earn its place; it is the **instrument of the
composition result** in §6; and it is precisely the ground the protocol-composition literature leaves
open, since that work assumes its transport substrate and places no adversary below the protocol
layer.

### 3.4 Evidence grade — a column, not an axis

Every row carries a grade:

| | Level | Meaning |
|---|---|---|
| **L0** | Claim only | The guarantee is asserted |
| **L1** | Source inspection | Mechanism verified by reading the implementation |
| **L2** | Behavioral confirmation | Guarantee tested against constructed cases |
| **L3** | Reproducible bypass | The guarantee has been broken, reproducibly, by someone |

This is deliberately demoted from an organizing axis to a reported column. It preserves the real
question — enforcement claims are under-tested — without giving it structural weight the corpus
cannot support. It also sharpens a finding: given that the prior systematization reports policy
enforcement failing at 69–98%, **how many works claiming enforcement have ever been graded above
L1?** ⟦Populate.⟧

---

## 3.5 Submission constraints that change the method

**Confirmed 2026-08-30 against the SaTML 2027 call for papers.** Three requirements alter the method
rather than merely the formatting, and two of them are serious.

### 3.5.1 Double-blind review breaks §9 as written

SaTML mandates double-blind review. Submissions must omit author names and institutions, must cite
the authors' own related work **in the third person**, and must not reveal identity through
artifacts. The call explicitly warns against phrasing such as *"our artifacts are already available
as open source tools."*

§9 as drafted — "we score our own system first, at full severity" — de-anonymizes on its first line.

**Resolution, and it improves the paper.** The system is scored as an ordinary corpus row, in third
person, under the same procedure as every other work. The neutrality claim then rests where it
should: on the **procedure** — two coders, mandatory quoted spans, a published disagreement record —
rather than on a visible act of self-criticism that a reviewer has to take on trust. The authorship
relationship is declared to the chair through the conflict-of-interest mechanism, not in the body,
and disclosed in the camera-ready.

This is standard double-blind practice rather than concealment. It also removes a real weakness: a
self-flagellation page reads as performance to a skeptical reviewer, whereas a system scored T3 by
the same rule that scored everything else reads as the rule working.

### 3.5.2 Coding method: machine coding, disclosed, with human verification on load-bearing rows

SaTML requires an **LLM usage considerations** section. Ours is not incidental, so it is stated here
as method rather than confessed in a limitations paragraph.

**All 15 works were coded by two LLM agents given opposed stance prompts** — one conservative, one
charitable to the authors — each required to retrieve full text and produce verbatim spans. Full text
was retrieved on 30 of 30 codings.

**What that is, stated precisely.** Agreement between two prompts of one model family is **not
inter-coder reliability**. The two share failure modes and will agree on the same misreadings, so
their agreement rate is an **upper bound** on reliability rather than an estimate of it. Every
agreement figure in this paper is labeled accordingly, and a Cohen's kappa is reported only where the
marginals support one — which for the coverage axis they do not.

**The verification layer.** Machine coding alone is insufficient for rows that carry findings. Every
work supporting a headline claim — nine of fifteen — is **verified by a human coder against the
recorded spans**, who confirms, corrects or rejects each verdict. The count of **overturned rows is
reported** in this section. A non-zero count is evidence the layer is real rather than ceremonial; a
zero count would itself require explanation.

**Three things the machine layer does that a human layer would not.**

1. **Opposed stances by construction.** Two humans bring whatever priors they have. Two prompts bring
   priors we specified and can publish, which makes the divergence interpretable.
2. **Mandatory spans.** A cell without a verbatim span is not recorded. That constraint is trivial to
   impose on an agent and awkward to impose on a person, and it is what makes human verification a
   four-hour task rather than a re-reading of fifteen papers.
3. **Divergence as measurement.** The rate at which opposed-stance coders diverge, and where, is
   reported as a result. On this corpus it was concentrated rather than diffuse: near-total agreement
   on evidence grade and enforceability, and 29.5% disagreement on coverage cells running **entirely
   in one direction**. That pattern diagnosed a defect in our own rubric that neither stance alone
   would have surfaced.

**The honest summary for a reviewer.** This is machine-extracted, human-verified adjudication. It is
not a human systematization, and it does not claim to be. We think the trade is favorable at this
corpus size, and we report enough for a reader who disagrees to discount it precisely.

### 3.5.3 Twelve pages, and appendices do not count

Both research and SoK papers are capped at **12 pages of body text**. There is no limit on references
or appendices, but **reviewers are not required to read appendices and papers are assessed on the
body**.

For a corpus paper this is the binding structural constraint. The full corpus table — rows by tier,
coverage vector, placement, evidence grade, with spans — goes to the appendix. **Every finding that
carries the paper must be argued in the body**, which means the body presents the *deltas* and the
*distributions*, not the table.

Also required and not counted against the limit: an **Open Science** section, and **Ethical
Considerations** if applicable.

---

## 4. Method

**Screening.** ~60 candidates identified by systematic search across cs.CR, cs.AI and cs.SE, plus
citation chasing from the prior systematization and from the classical spine. Screened to ~45 by
full-text application of G1–G4. **Expected attrition 10–20%**, and the excluded set is published with
the gate that excluded each.

**Full-text only.** No work is scored from an abstract. This is stated as a method commitment because
the failure mode is real and we have committed it elsewhere in this program: a related-work section
built from abstracts is both a desk-reject risk and an integrity problem.

**Coding.** Two coders, independent, on all three axes plus the evidence grade. Cohen's κ per axis.
Disagreements adjudicated by discussion, on the record, published in the artifact.

**Corpus freeze: 15 November 2026.** Works appearing after the freeze are noted in a postscript and
not scored, so the corpus is a stated population rather than a moving one.

---

## 5. The corpus

> **Pilot-populated 2026-08-30.** Numbers below carry their sample size. The full coverage pass runs
> October–November; corpus freeze 15 November. Nothing here is a final result and every figure is
> labeled with what produced it.

### 5.1 Screening

322 candidate records were produced by four independent discovery modalities — mechanism-first
search, systematic database sweep, venue and industry search, and seed mining from the prior
systematization. **55 were screened; 49 included, 6 excluded.**

⚠️ **The remaining 267 candidates were not screened.** The screening payload truncated at the 55th
record. This is a process defect, not a scope decision, and it is disclosed rather than absorbed: the
delegation and TOCTOU clusters are expected to grow, and the corpus is **not closed**. No attrition
rate is reported, because §4's commitment to publish the excluded set with per-work gate
attributions is only partly discharged.

The 89% inclusion rate on the screened slice reflects a pool that arrived pre-filtered with per-item
scope rationales. It is not evidence that the gates were applied loosely; every exclusion is a
recorded gate failure.

### 5.2 Composition of the screened corpus (n = 49)

| Category | n | Share |
|---|---|---|
| Policy enforcement | 17 | 35% |
| Sandbox | 8 | 16% |
| Delegation | 7 | 14% |
| Capability | 6 | 12% |
| Protocol | 4 | 8% |
| TOCTOU | 4 | 8% |
| Egress | 2 | 4% |
| Provenance | 1 | 2% |

**By year:** 2024 — 1 (2%); 2025 — 16 (33%); **2026 — 32 (65%)**. Only one pre-2025 work survives the
gates. The field is under two years old and accelerating.

### 5.3 ⭐ The corpus is 48 preprints and one peer-reviewed paper

| Venue type | n | Share |
|---|---|---|
| arXiv preprint | 48 | **98%** |
| Peer-reviewed venue | 1 | 2% |

This is a finding, not a housekeeping note, and it conditions everything downstream. **An unreviewed
claim of "provable," "verifiable," "mandatory" or "kernel-level" has had no external check.** The
evidence-grade column in §3.4 exists precisely because such claims are, in this literature, the
default rather than the exception — and because the one work that did pass peer review is also one
of the works that demotes (§5.4).

### 5.3A ⭐ The authorization–execution gap

**Five of fifteen systems score A-T1 over B-T3**: forging the *claim* requires breaking a signature;
bounding the *action* requires only a path that avoids a chokepoint. This pattern is unrepresentable
under a single-column rule, which is why it had not been named.

It has a composition consequence, and it is the paper's central one:

> **An A-T1/B-T3 system delivers its advertised guarantee only on top of a B-T2 substrate it does not
> itself provide.** The cryptography is sound and it is answering a question about acceptance. The
> question the deployment needs answered is about action.

The corpus contains both halves and almost nothing that is both. Sandlock is A-NONE/B-T2 — a real
kernel bound making no verifiable claim to anyone. The five A-T1/B-T3 systems are verifiable claims
with no kernel bound. **One work is both**, and how it got there is instructive: PAuth achieves
B-T1 *topologically*, by placing the verifier outside the adversary's address space rather than by
strengthening the cryptography.

**Two negative results sharpen it.**

**A-T2 is empty.** Not one system in the corpus makes acceptance turn on a kernel-mediated fact — a
real uid, a namespace membership, a measured boot value. Acceptance is either cryptographic or
application-level, and the middle is unoccupied.

**The best-placed candidate does not populate A-T1.** An Intel TDX trusted plane — the only work
interposing below the harness, and the one most likely on its face to hold a hardware-rooted
acceptance claim — scores A-T3. The rhetoric is unforgeability; the construction binding the token is
never given; the verifier is untrusted. That is stated first among the results rather than buried,
because it is the result least convenient to the framing.

### 5.4 The action column: advertised against scored

⚠️ **Relabeled.** The demotion statistic below is an **action-column** measurement. Under the
single-column rule it was reported as *the* tier result; §3.1.1 shows that rule could not see the
acceptance column at all, so the figure measures less than it appeared to.

Two passes. Every coding retrieved full text: **50 of 50**.

| | Pilot (10 works) | **Decisive pass (15 works)** |
|---|---|---|
| Demotion rate | 4 of 10 (40%) | **12 of 14 scorable (85.7%)** |
| Two-tier falls | 0 | **5** |
| Works scoring above T3 | 0 | **1** |
| Scored-tier agreement | 6 of 6 (100%) | 11 of 15 (73.3%) |

⚠️ **The two passes are not like-for-like.** The pilot sampled the prompt-injection cluster, which
is largely tier-honest. The decisive pass was selected for tier-axis power — six demotion candidates,
six T2 anchors, three T1 candidates. **The 85.7% figure is an upper bound and must never be reported
as a corpus rate.**

**Exactly one work scores above T3: Sandlock, T2, unanimous across both coders.** It is also the only
work in the set whose prose declines to overclaim — a correlation worth stating and too small a
sample to lean on.

Five of the six deliberate T2 anchors demoted, **and for five structurally different reasons**, each
quoted. The through-line is a sentence the paper did not previously contain:

> **Tier is set by the weakest placement step, not by the strongest enforcement mechanism.**

A system can hold a genuine kernel boundary in one limb and lose the guarantee at a configuration
step, a userspace resolver, or a trusted-path assumption elsewhere. That is what weakest-link
scoring is for, and it is what a taxonomy organized by mechanism cannot see.

### 5.5 Coverage

**2 of 105 adjudicated cells scored `covered` — 1.9%.** Both belong to Sandlock (E1, E2).
**Thirteen of fifteen systems fully mediate nothing.** The modal cell is `partial`.

⚠️ This supersedes the earlier pass's 17 of 140 (12.1%). **The number moved by an order of
magnitude in the unflattering direction** once OS-tier and cryptographic-tier systems were coded
under the v1.1 depth rule.

**The E2 prediction was wrong, and the replacement is better.** §3.2 called E2 subprocess spawn "the
exclusion that inflates coverage most" and predicted it would be least covered. It is third
(8 of 15 `not-covered`), behind **E5 package install (12 of 15)** and **E4 VCS push (11 of 15)**.

The sharper finding sits beside it:

> **Network egress is reached by 14 of 15 systems and scored `covered` by none of them.**

Every system in the set touches egress. Not one bounds it completely. That is a stronger sentence
than the E2 claim it replaces and it lands on the same reference-monitor target in §6.4.

**Coverage-cell agreement: 74 of 105 (70.5%)**, against 64.3% under v1.0 in the pilot. The v1.1
three-value rubric **eliminated the entire label-collision class** — zero pure collisions remain.
The residual 29.5% is depth-of-mediation judgment, and **all 31 disagreements ran one direction**,
with the charitable coder scoring higher every time. A one-directional residual is a rubric signal,
not noise: the depth rule is being read as a floor by one stance and a ceiling by the other, and
§5A needs one more sentence before the full pass.

### 5.6 Evidence grades (pilot, 20 codings)

| Grade | n |
|---|---|
| L0 claim only | 4 |
| L1 source inspection | **0** |
| L2 behavioral confirmation | 13 |
| L3 reproducible bypass | 3 |

**The empty L1 cell is informative.** Works in this literature tend either to assert a guarantee or
to test it behaviorally; the intermediate practice of verifying a mechanism by inspection without
testing it is nearly absent. Screening locates the L3 material in five rows — two defense-breaking
papers and three TOCTOU exploitation papers — which means **reproducible bypass evidence in this
field is produced almost entirely by attack papers rather than by the defenses re-testing
themselves.**

## 6. The composition result

### 6.1 The claim

*Two controls compose only if their assumed adversary placements are compatible.* A control assuming
A2 and a control assuming A4 do not compose: the first assumes the harness is trustworthy and
screens what enters it; the second assumes the harness is compromised. Deploying both does not yield
the union of their guarantees. It yields the weaker one over any action reachable at the weaker
placement.

### 6.2 The placement distribution, and what it already shows

Primary placement is the adversary a work's **evaluation actually tests**. Secondary placements are
those its design addresses but does not test. Coder agreement on primary placement: **12 of 15 (80%)**.

| Placement | As **primary** | As **secondary** |
|---|---|---|
| A1 outside the system | 2 | **13** |
| A2 in inputs or retrieved context | **10** | 4 |
| A3 in the agent's policy or weights | 1 | 11 |
| A4 inside the harness | 2 | 7 |
| **A5 below the harness** | **0** | 7 |

Three results, and the first vindicates a method change made on one work's evidence.

**Every work in the corpus has at least one secondary placement — 15 of 15.** The strict partition
required by the original design would have discarded information on **every single row**. That is not
a marginal improvement to the axis; it is the difference between an axis that can support a
composition argument and one that cannot.

**A5 is never a primary.** Not one system in this corpus is *evaluated* against an adversary below
the harness, though seven acknowledge one in design. The sharpest instance is the Intel TDX trusted
plane: it is the only work in the set that **interposes** below the harness, and its evaluation still
assumes an **A2** adversary. The construction reaches lower than the threat model it is tested
against, which is a different failure from overclaiming and arguably a more interesting one.

**A2 dominates at 10 of 15.** The field is overwhelmingly organized around an adversary in the inputs
— indirect injection — with the harness assumed trustworthy. That assumption is exactly what A4
denies, and it is the axis on which composition fails.

### 6.3 The compatibility matrix

Two controls compose only if their assumed adversary placements are compatible. A control that
assumes the harness is trustworthy and screens what enters it, and a control that assumes the harness
is compromised, do not compose: deploying both yields the weaker guarantee over any action reachable
at the weaker placement, not the union.

| | A1 | A2 | A3 | A4 | A5 |
|---|---|---|---|---|---|
| **A1** | ✓ | ✓ | ✓ | ⚠️ | ⚠️ |
| **A2** | ✓ | ✓ | ⚠️ | ✗ | ✗ |
| **A3** | ✓ | ⚠️ | ✓ | ⚠️ | ✗ |
| **A4** | ⚠️ | ✗ | ⚠️ | ✓ | ⚠️ |
| **A5** | ⚠️ | ✗ | ✗ | ⚠️ | ✓ |

✓ compose · ⚠️ conditional · ✗ do not compose

**The load-bearing cell is A2×A4.** An A2 control's guarantee is stated over a trustworthy harness.
An A4 adversary is inside that harness. Composing them does not produce defense in depth; it produces
an A2 guarantee that is void under the A4 assumption the other control was purchased to address, and
an A4 control whose input screening the A2 component was supposed to supply.

**On the primary distribution, the corpus is mostly self-compatible and that is the problem.** Ten of
fifteen works are A2. Two A2 controls compose trivially and add little, because they share the same
blind spot. The pairs that would add something — A2 with A4, A2 with A5 — are exactly the
non-composing cells.

### 6.3.1 The named set

Applying the matrix to the 15 primary placements gives **105 pairs**:

| | n | Share |
|---|---|---|
| Compose | 69 | 66% |
| Conditional | 16 | 15% |
| **Do not compose** | **20** | **19%** |

**Every one of the twenty is the same cell.** All 20 non-composing pairs are **A2 x A4** — one of the
ten works assuming an adversary in the inputs, paired with one of the two assuming an adversary
inside the harness. There is no second failure mode in this corpus. The composition problem is not
diffuse; it is a single incompatibility, occurring twenty times.

**And the two A4 works are the two you would most want.** Only two systems in the corpus assume a
compromised harness. Those are precisely the systems a practitioner would reach for to cover what an
input-screening control cannot see — and they are the two that do not compose with the ten
input-screening controls. **The pairing that would most improve a stack is the pairing the field
cannot currently supply.**

The 66% that do compose are mostly **A2 x A2**. They compose because they share an assumption, and
they add correspondingly little: two controls blind in the same direction give defense in depth
against the threat both already handle and none against the threat neither does. **A high
compose-rate is not a healthy corpus. It is a monoculture.**

⟦Per-pair quoted justification for the twenty, drawn from both sources, populates from the pairwise
pass. The placement data supporting the counts above is in the artifact.⟧

### 6.4 Cross-cut against the reference-monitor properties

Each work assessed against tamperproof, always-invoked, small-enough-to-verify. **The "always
invoked" property is where the coverage axis and the classical literature meet**: a control that
mediates three of seven effectors is not always invoked, by definition, and its guarantee is
therefore conditional on the agent not using the other four.

---

## 7. Enforceability

Schneider's result bounds what an execution monitor can enforce: safety properties, and not more.
We apply it to the claimed policies in the corpus.

### 7.1 ⭐ The binary was the wrong question, and the answer is universal

§7 was drafted expecting to sort claimed policies into *enforceable* and *not enforceable*.

**Across both passes, 50 of 50 codings returned neither.** The pilot's 20 of 20 invited the obvious
objection that it had sampled only proxy-tier systems. The decisive pass answers it: the set includes
a Landlock/seccomp sandbox, an eBPF cgroup controller, a WASI runtime, an Intel TDX trusted plane and
three signature-based capability protocols. **Every one returned split.** Zero enforceable, zero
non-enforceable, both stances, all works.

§7.2's prediction that split would be "modal" is too weak. On the evidence to date it is
**universal**, and that is a categorically different claim: not that most systems enforce a surrogate,
but that **every system examined does**, across every enforcement tier the corpus contains. Every coding, on every work, across both
stances, returned **partial** — and independently described the same structure:

> The object the monitor mechanically enforces is a **prefix-closed safety property over a per-call
> predicate**. The objective the paper advertises is an **information-flow hyperproperty** that no
> execution monitor can decide.

That two opposed-stance coders located the same split, in the same place, on every work, is the
strongest agreement signal in the pilot — stronger than the 100% tier agreement, because it is
agreement on a *decomposition* rather than on a label.

### 7.2 The three-value column

The Schneider column therefore takes three values, and **split is expected to be modal**:

| Value | Meaning |
|---|---|
| **Enforceable** | The claimed policy is a safety property a monitor can enforce |
| **Split** | A monitorable safety surrogate is enforced; a non-monitorable objective is advertised |
| **Non-enforceable** | The claimed policy lies outside the enforceable class and no surrogate is identified |

### 7.3 Why the split is the finding

A work classified *split* is not weakly enforced. It is enforcing something **real and narrower than
what it claims**, and the distance between the surrogate and the objective is where the residual
attack surface lives. Naming that distance per work is more useful to a practitioner than a verdict,
and it is not available from any existing systematization of this literature.

It also sharpens §5.3. A field that is 98% unreviewed, in which every pilot work advertises an
objective its own mechanism cannot decide, is not a field with a few overclaiming papers. It is a
field with a systematic gap between advertised objective and enforced surrogate — and that gap, not
the tier delta, may be the paper's central contribution.

⟦Full-pass distribution across the three values; per-work naming of the surrogate and the objective;
identification of any work with no identifiable surrogate.⟧

## 8. Empirical artifact

A small demonstration, one representative system per tier, showing bypass of the advertised
guarantee.

⟦Three or four systems, selected on stated criteria after the corpus freeze, with reproducible
bypass scripts and the resulting L3 grades.⟧

**Why this exists.** It converts the paper from analysis into analysis-with-evidence, and it is the
difference between a borderline and a clear accept. It also disciplines the weakest-link rule: if the
rule predicts a system is proxy-tier, a subprocess spawn should defeat it, and that is demonstrable
rather than argued.

---

## 9. Applying the rule to a system the authors know well

> **Double-blind note (strip at camera-ready, replace with disclosure).** This section is written in
> third person per §3.5.1. One scored system is the authors'; the relationship is declared to the
> chair through the conflict-of-interest mechanism and disclosed in the camera-ready. Nothing in the
> scoring procedure differs for it.

⟦System W⟧ issues cryptographically signed warrants and produces tamper-evident action receipts.
Those are genuine T1 mechanisms and they constrain what a verifier will accept. **They do not
constrain execution.** The enforcement point is a protocol-layer handler, and an agent holding a
shell does not consult it. The published architecture contains no namespace, seccomp or firewall
mechanism.

**Scored: A-T1 of acceptance, B-T3 of action.** Its receipts and warrants are cryptographically
verifiable — forging what a relying party accepts requires breaking a signature. Its enforcement
point is a protocol handler, and the cheapest defeat of an *action* bound is a subprocess spawn that
never traverses it.

⚠️ **The system is a textbook instance of the authorization–execution gap in §5.3A**, and under the
single-column rule that fact was invisible: the system scored a flat T3 alongside works whose
cryptography is decorative. The two-column rule states the position exactly, and it is less
flattering in one respect and more accurate in both — the cryptography is real, and it is answering
a question about acceptance while the deployment needs one about action.

**Coverage, on ACTION-SURFACE-v1.0:** the protocol-declared surface only. E2 subprocess spawn, E3
descendant egress, E5 package install and E6 credential use fall outside it unless the deployment
composes an operating-system boundary the system does not itself provide.

**Adversary placement: A2.** The threat model assumes the harness is trustworthy and screens what
enters it. Against A4 — an adversary inside the harness — the guarantee does not hold.

**Evidence grade: L1** — source inspection. The guarantee has not been tested to L2 or broken to L3.

This row is presented early and in full because a systematization that adjudicates other people's
guarantees should demonstrate the rule producing an unflattering result before it produces flattering
ones.

## 10. Limitations

**The coverage axis is a measurement we perform, not one the field reports.** Its validity rests
entirely on the frozen enumeration, the two-coder procedure and span traceability. A different
enumeration would produce different numbers, and the enumeration is a judgment.

**Scoring is adversarial by design and therefore contestable.** We score guarantees at the tier where
we believe they fall. Authors may disagree, and the published spans exist so that disagreement can be
specific rather than general.

**The corpus is a preprint-heavy population** in a field publishing monthly, frozen at a date.

**We are not neutral.** The authors build in this space. §9 and the procedural safeguards in §4 are
the mitigation; they are not a solution, and a reader should weight the scoring accordingly.

**Machine coding with human verification.** All coding was performed by opposed-stance LLM agents;
the nine works carrying headline findings are human-verified against recorded spans (§3.5.2).
Agreement figures are reported as stance-divergence measurements and as upper bounds on reliability,
never as inter-coder reliability. ⟦Insert the overturned-row count before submission. If it is zero,
say why that is credible rather than letting it pass unremarked.⟧

**Corpus size and selection.** Fifteen works, selected for tier-axis power rather than sampled. The
contribution is adjudication rather than enumeration, and the population is stated rather than
implied — but a reader who wants a census of this literature should read the prior systematization,
which we cite and do not attempt to replace.

---

## 11. Related work

⟦Full engagement with arXiv:2607.05743 and the three other overlapping systematizations, plus
AgentThread on protocol composition, and the runtime-invariant, evidence-sufficiency and
injection-defense strands. Differentiation table from §1.1 expanded.⟧

**Reads that discharge debt elsewhere in this program.** HCP (arXiv:2606.29073), DEMM-Bench
(arXiv:2606.20634) and ClawGuard (arXiv:2604.11790) are all in-corpus rows under G1–G4. Reading them
inside this schedule costs nothing additional and settles open positioning questions for two other
papers at the same time.

---

## Venue decision, and two schedules

**⚠️ Corrected 2026-08-30.** This paper was scheduled against USENIX Security '27 Cycle 2 on the
assumption it was the earliest venue accepting systematizations. It is not.

**IEEE SaTML 2027 closes 29 September 2026** — abstract 22 September, anonymized artifacts 2 October.
It accepts SoK papers explicitly, at **12 pages** of body text, requires "SoK:" in the title, and
runs an interactive discussion period in which a **Revision** decision can be resubmitted for
re-evaluation rather than starting over. Early reject 4 Nov, final decision 16 Dec, conference early
May 2027.

That is **30 days from today**, against **149 days** for USENIX.

### The tradeoff, stated plainly

| | **SaTML 2027 — 29 Sep** | **USENIX Sec '27 C2 — 26 Jan** |
|---|---|---|
| Time available | 30 days | 149 days |
| Page limit | 12 | longer |
| Corpus achievable | **bounded** — perhaps 15–20 works coded properly | full ~45 |
| Coverage pass | pilot-scale, two coders, stated population | complete |
| Empirical artifact (§8) | not achievable | achievable |
| Failure mode | thin corpus read as an incomplete SoK | none, but four months later |
| Recovery | **Revision decision is resubmittable** | none |

**The case for SaTML.** A 12-page limit suits a bounded corpus better than a 15-page one. The
revision path means a first submission that is directionally right but thin can be repaired rather
than rejected outright. And the adjudication contribution — weakest-link scoring, derived coverage,
composition compatibility — does not require 45 rows to be *demonstrated*; it requires enough rows to
be *convincing*, and the highest-value rows are exactly the ones that demote.

**The case against.** An SoK with 15–20 works, when a 39-work systematization of the same population
was published in July, invites the obvious question. The answer would have to be that we adjudicate
rather than enumerate and that our population is stated and defended — which is true, and which a
reviewer may or may not accept under a 12-page limit.

**Decision rule, and it is decidable this week.** The pilot two-coder pass now running codes the
highest-value works with quoted spans and reports inter-coder agreement.

- **If agreement is high and the weakest-link rule produces clear demotions** — target SaTML.
  The contribution is demonstrable at pilot scale, and the revision path covers the corpus-size risk.
- **If agreement is poor, or the rule produces few demotions** — the method needs work before any
  submission, and USENIX Cycle 2 is the correct target. A method that does not discriminate at pilot
  scale will not discriminate at 45 rows either; it will just take longer to find out.

**Decide on the pilot, not on the calendar.**

### Schedule A — SaTML, if the pilot is clean

| Window | Work |
|---|---|
| Now – 5 Sep | Validate ACTION-SURFACE-v1.0 against a real agent session. Freeze the bounded population and publish the exclusion record |
| 6 – 18 Sep | Two-coder pass on the bounded corpus, κ reported, disagreements adjudicated on the record |
| 19 – 21 Sep | Composition matrix, Schneider pass, §9 self-scoring |
| **22 Sep** | **Abstract registration** |
| 23 – 29 Sep | Write to 12 pages. Differentiation from 2607.05743 in the first two pages, non-negotiable |
| **29 Sep** | **Submit.** Anonymized artifacts by 2 Oct |

§8's empirical bypass artifact does not fit this schedule and is deferred to the revision round, where
it is the strongest possible response to a Revision decision.

### Schedule B — USENIX Cycle 2, the original plan

| Month | Work | Gate |
|---|---|---|
| **September** | Full-text screening, ~60 → ~45. Freeze and validate the action surface | Enumeration frozen before coding |
| **October–November** | **Derived-coverage pass — the critical path.** Two coders, 45 systems, κ reported | **Corpus freeze 15 Nov** |
| **December** | Weakest-link scoring; Schneider; reference-monitor cross-cut; composition matrix; writing | Draft complete |
| **January** | Empirical artifact — bypass demonstration, one system per tier | **Submit 26 Jan** |

**Kill decision 15 November** applies to Schedule B: if the coverage pass proves infeasible at scale
during October, stop and redirect to a narrower venue rather than burn the cycle.

### Two immediate tasks

**1. Decide the venue on the pilot result**, per the rule above. This is decidable within days and
everything else depends on it.

**2. Check whether arXiv:2607.05743 has been accepted anywhere.** If it lands at USENIX Cycle 1 or
Cycle 2, the program committee has it in front of them while reading ours, which changes the
differentiation burden materially. Half an hour of work, and it should happen this week.

---

## Page budget — SaTML 12-page body limit

Body text is capped at 12 pages. References, appendices, the Open Science section and LLM usage
considerations do not count. **Reviewers are not required to read appendices**, so no finding may
live there.

| § | Content | Pages | Placement |
|---|---|---|---|
| 1 | Introduction + differentiation table | 1.25 | **Body — the table is on page one, non-negotiable** |
| 2 | Scope, gates, classical spine | 0.75 | Body |
| 3 | Three axes + the T1/T3 repair (§3.1.1) | 2.25 | Body |
| 4 | Method | 0.5 | Body |
| 5 | Corpus, tier and coverage results | 2.5 | **Body** (table → appendix) |
| 5.3A | The authorization–execution gap | 0.75 | **Body — the central result** |
| 6 | Composition, matrix, the named twenty | 1.5 | Body |
| 7 | Enforceability, the universal split | 1.0 | Body |
| 9 | The ⟦System W⟦ row | 0.5 | Body |
| 10 | Limitations | 0.5 | Body |
| 11 | Related work | 0.5 | Body |
| | **Total** | **12.0** | |

**Moved to appendix** (uncounted): the 15-row corpus table with per-cell spans; the full
disagreement record; the compatibility matrix derivation; the coverage vectors.

**Stripped at submission** (working material, not paper):
§3.5.1 (which explains the double-blind problem rather than solving it), §3.5.3, the venue-decision
section and both schedules, and these production notes.

**§8 (empirical bypass artifact) is deferred to the revision round.** It does not fit 30 days and it
is the strongest available response to a Revision decision.

⚠️ **The squeeze is §5.** Corpus results plus the gap section is 3.25 pages, the largest block in the
paper. If the budget overruns, cut the evidence-grade subsection to a sentence and push its table to
the appendix — do **not** cut §5.3A or the §3.1.1 repair, which are the contribution and the
credibility respectively.

---

## Production notes

**Status.** Structure and methodology frozen. Corpus screening not started. This is the same
discipline as T-03's pre-registration and for the same reason: fixing the method before the data
prevents the analysis being shaped by what the corpus turns out to contain.

**What makes this submittable where T-03 is not.** No GPU, no gated corpora, no regenerated raw
outputs. The inputs are published papers and reading time. The binding constraint is labor, and
labor is available in a way that clean experimental runs currently are not.

**The three things that would sink it,** in order: (1) the coverage pass proving infeasible — hence
the 15 November gate; (2) failing to differentiate from 2607.05743 in the first two pages; (3) axis 3
reverting to evidence model, which reconstructs the self-serving-axis problem §3.3 exists to avoid.

**Forward-links.** T-01 supplies the mediation-ceiling argument and its measurement protocol, which
is the coverage axis applied to a single system. T-07 supplies the tier taxonomy in applied form.
T-11 shares the composition argument in business register.