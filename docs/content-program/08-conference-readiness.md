# Conference Submission Readiness

**Decision document. Written 2026-08-30 for the author, not for the file.**
Covers T-03 (empirical guard paper), T-04 (negative results short paper), T-12 (SoK).
Inputs: the AgentThread full-text read, the repo evidence audit, the SoK corpus scoping,
and the hostile PC review of T-03.

---

## 0. The verdict, first

**T-03 will not make IEEE S&P 2027 Cycle 2 on 17 November 2026.** Not in its three-finding form,
and I do not think the narrowed two-finding form is worth taking either. The reason is not compute.
The entire experimental program is 15 to 25 GPU-hours, which the 5080 and free Kaggle cover with
room to spare. The reason is that four of the five items on the critical path have latency you do
not control: two Hugging Face corpus gate approvals, a license contradiction that has to be resolved
with a third party, two independent human annotators who do not yet exist by name, and a
sample-size redesign that the current negatives pool cannot support. Wrapped around those is a
harder fact: **zero of the four fine-tuned checkpoints in the model matrix exist**, so Experiment 1
has never been piloted, let alone run, and the paper's most expensive experiment is also its least
de-risked. Seventy-nine days is enough time to run the experiments. It is not enough time to run
them *after* clearing four external dependencies in series.

**The recommendation is T-12 to USENIX Security '27 Cycle 2 on 26 January 2027**, with T-03
following into the same cycle only if E1 and E2 land clean by early January. T-12's long pole is
reading and coding papers. That is calendar-schedulable, parallelizable, and depends on no gate
approval, no annotator, no license clearance and no GPU. It is the only paper in the estate whose
critical path is entirely inside the building.

**T-04 is the cheapest real paper you own** and it is being held hostage by a coupling that does not
need to exist. One measurement run of three to five GPU-hours unblocks it. Decouple it from T-03 and
send it to a workshop or arXiv on its own schedule.

One correction to the catalog before anything else. `01-track-technical.md` scores T-03 at
**E4** on evidence readiness. That is wrong by three points. Zero of four checkpoints exist, the raw
outputs of the runs that did happen were destroyed, the corpora are not on the box, and one of the
three headline findings has never been measured in any form by anyone. **T-03's honest evidence
score is E1.** Re-scoring at D5 E1 N4 C3 gives 25.0 against T-12's 23.5, and the ranking that made
T-03 the flagship collapses to a rounding error while T-12's deadline sits seventy days later with
bounded risk.

---

## 1. Per-paper verdict

### T-03 · Measuring Guard Models

| | |
|---|---|
| **Submittable today** | No |
| **IEEE S&P 2027 Cycle 2 (17 Nov 2026)** | **No.** Do not attempt, including the narrowed form |
| **Realistic target** | USENIX Security '27 Cycle 2, 26 Jan 2027, three findings, conditional on E1 and E2 completing by 5 Jan |
| **Fallback** | USENIX '28 Cycle 1, or an arXiv preprint of E2+E3 once measured |
| **Desk-reject probability if submitted as-is** | Certain |

**What blocks it, in dependency order.**

1. **Corpora are not on this machine and both are gated.** No Hugging Face cache. Gate approval
   latency is uncontrolled and historically runs days to weeks. Nothing downstream starts until
   this clears.
2. **ExpGuardMix is not license-cleared.** `baselines.py` records
   `commercial_clearance = "NOT CLEARED"`, notes that its CC-BY-4.0 declaration and its
   research-only gate form disagree, and records that the corpus was GPT-4o-generated upstream.
   Three separate problems: you may not be permitted to use it, you may not be permitted to
   republish per-item outputs from it in the artifact, and a guard trained on GPT-4o-generated data
   and then evaluated for "specialization" invites a distillation confound the paper does not
   address anywhere.
3. **Zero of four fine-tuned checkpoints exist.** `G-gen-0.6B`, `G-gen-4B`, `G-vert-0.6B` and
   `G-vert-4B` are all unbuilt. E1 is not late, it is unstarted. The vertical corpus that
   `G-vert-*` requires is not a frozen, manifested, cleared artifact either.
4. **The rephrasing transformation set does not exist.** P5 is unticked. No `transformations.json`,
   no `pairs.jsonl`, no annotation.
5. **No annotators.** E2's headline number is only defensible with the 200-pair independent
   equivalence check, two annotators, Cohen's kappa and a reported exclusion rate. Two people who
   are not you, scheduled, is a two-to-four-week calendar item from a standing start.
6. **The raw outputs of the runs that did happen no longer exist.**
   `/python/warrantor_ml/eval_sets/results/` is gitignored at `.gitignore:122`, was never committed
   (`git log --all --diff-filter=A` returns nothing), and is absent from disk. The only surviving
   record of every number in this program is prose in `ml/README.md` and hand-transcribed literals
   in `baselines.py`, whose own comment concedes the per-slice counts were solved backward from
   rounded recall, FPR, precision and n, and are accurate to roughly plus or minus one row. Section
   7.1 of the paper promises raw per-item outputs as an artifact deliverable. They are gone.
7. **No power analysis, no minimum detectable effect, no stated sample size anywhere in §4.** Three
   of the headline claims are nulls. See §4 below for the arithmetic; the short version is that the
   design as specified cannot distinguish fourfold from twofold.
8. **Results are asserted in the indicative against empty result sections.** This is the item that
   makes it a desk reject rather than a reject. See §4, finding D1.

**Why the narrowed E2+E3 form is not worth taking either.** The 18 October decision gate in the
protocol offers "submit E2 + E3 to IEEE S&P as a narrower paper." That option assumes E2 is the
cheap half. It is not. E2 carries the annotator dependency, the transformation freeze, the corpus
gate and the power redesign. E3 is the genuinely cheap one, and E3 alone is a note, not an S&P
paper. So the narrowed form still runs through three of the five external dependencies and buys you
a two-finding paper with a rushed equivalence check, at a venue where the reviewers read equivalence
checks for a living.

### T-04 · Negative Results in Guard Fine-Tuning

| | |
|---|---|
| **Submittable today** | No, but closer than anything else you own |
| **Realistic target** | A workshop with a late-2026 or rolling deadline, or arXiv, within about four weeks of one measurement run |
| **Do not** | Couple it to T-03 or to USENIX Cycle 2 |

**What blocks it.** Exactly two things, both small.

1. **The effect size of the leakage is unmeasured.** "Masking the field's loss did not isolate the
   field" is an observation. The paper needs a number: how much did the masked field move, against
   what baseline, on what metric. That is one measurement over checkpoints that already exist.
2. **Only one adapter configuration exists, and the spec's own falsification test demands two.**
   T-04's "what would make it wrong" says: *a rank/target-module configuration under which masking
   does isolate*. Claim generality from one configuration and a reviewer kills it in a sentence,
   correctly. Two additional short LoRA runs at a different rank and a different target-module set
   close this.

**Why decouple it.** T-04 was made a dependent of T-03 because they share infrastructure. They do
not share blockers. T-04 needs no benchmark corpus, no rephrasing set, no annotators and no license
clearance — its subject is training dynamics, not benchmark content. It is the only piece in the
technical track that is one small run away from being real, and holding it behind a paper that is
five external dependencies away from being real is a scheduling error, not a strategy.

**One honest caution.** The T-04 spec anticipates the objection *"this is obvious from the method"*
and answers that it cost two runs and a week. That answer works in a blog post. In a paper it works
only if the effect size is surprising in magnitude or the boundary conditions are non-obvious. Get
the number first, then decide whether it is a paper or a very good engineering note. If the leakage
turns out to be small, the honest publication is the note.

### T-12 · SoK: Authority and Containment for Autonomous Coding Agents

| | |
|---|---|
| **Submittable today** | No |
| **Realistic target** | **USENIX Security '27 Cycle 2, 26 January 2027. Recommended primary.** |
| **Confidence it can be built to deadline** | Good, conditional on the four items in §5 |
| **Existential risk** | arXiv:2607.05743, an unvenued SoK over the same population |

**What blocks it.** The corpus is not built; axis 3 collapses as currently specified (see §5); the
differentiation from 2607.05743 is not argued anywhere; and 2607.05743's venue status is unchecked,
which is a thirty-minute task with disproportionate consequences.

**Why it is nonetheless the right primary.** Its long pole is reading, coding and adjudicating
papers. That work is fully under your control, splits cleanly across the fleet with a review gate,
and has zero external latency. The scoping already done is unusually strong: four cumulative
inclusion gates rather than a vibe, an explicit exclusion list, a hard freeze at 2026-11-15 leaving
ten weeks, and the weakest-link tier assignment rule, which is a real methodological contribution
rather than bookkeeping. That last rule is what stops the enforcement-tier axis dissolving into a
"hybrid" bin, which is how every prior taxonomy in this space has failed.

---

## 2. What the reads changed

### First, a disclosure that is itself a finding

Of the five papers scheduled for full reads, **one arrived as full text in this pass: AgentThread
(arXiv:2606.28690).** One more, the Balkanization SoK (arXiv:2607.05743), is characterized at
read-level depth in the corpus scoping — page counts, category counts, the 69–98% policy-enforcement
failure figure, the 17.1% out-of-scope benign action rate — which is more than an abstract yields.

**Three remain at abstract level: HCP (2606.29073), DEMM-Bench (2606.20634) and ClawGuard
(2604.11790).** No full read of any of them exists anywhere in this repository; a search across all
markdown and JSON returns only the corpus entries that were themselves written from abstracts.

This matters because T-03's own production notes already say it: *"A related-work section built on
abstracts is a desk-reject risk and an integrity problem."* That assessment was correct when it was
written and it is still true. Three of the four blocking reads have not happened. I am flagging it
here rather than writing around it, because writing around it is precisely the failure mode the note
was warning about. It also lands hardest on the two pieces whose positioning depends most on papers
nobody has seen — T-10 depends on DEMM-Bench, and T-03's §2 depends on ClawGuard, which the
production notes single out as "closest to our subject."

### AgentThread (arXiv:2606.28690) — full text, 11pp, 62 refs

**What it forecloses, permanently.**

- Any claim that agent-protocol composition has not been formally analyzed. It has: eight composed
  models, 43 security obligations across two classes, 30 admitting counterexamples, replayed against
  pinned production SDKs.
- Any claim that *"responsibility for cross-protocol security is unassigned"* is our observation.
  That is their §6.5 result, with 35 responsibility records across four protocols, and their closing
  sentence is that composition safety is a responsibility-allocation problem and not only a
  verification problem. The framing we would have reached for is already published.
- Any framing of "things fall between the protocols" as novel. It is now a counterexample-backed
  result, not an insight.

The decision to merge T-02 into T-12 and keep only the enforcement-tier axis was correct, and the
full text confirms it more strongly than the abstract did.

**What it leaves wide open — verified by keyword sweep of the full text, not inferred.**

Zero occurrences of: proxy, chokepoint, seccomp, kernel, netns, tamper, receipt, cryptographic
signature, hash, Merkle, non-repudiation, telemetry, observability, classifier, regulator,
regulation, SoK, "enforcement tier", "mediation coverage". "Sandbox" appears once, as the name of a
single ACP-Client check. "Guard" appears only as TLA+ guarded actions. Transport security is an
explicitly assumed substrate, out of scope. **No OS-level or network-level containment mechanism is
analyzed anywhere in the paper.**

That is a clean, verified statement of the ground still unclaimed, and it covers our entire
mechanism-layer argument.

**What it hands us for free.**

1. **An evidence-grading ladder.** Their Table 3 grades findings L0 spec-only, L1 source inspection,
   L2 behavioral confirmation, L3 reproducible exploit chain, and they are disciplined about it —
   only three of five protocols reach L3. That ladder is directly borrowable as a per-row column in
   T-12, and it is citable rather than invented.
2. **A denominator norm.** They ran 40 model-validation invariants, all passed, and excluded them
   from the reported denominator. That is the honest move, and T-12 should match it visibly.
3. **A citable formal result for T-10.** Two gaps appear in **all five** protocols: audit
   completeness and credential/registry integrity. And L5 audit/provenance continuity is one of the
   five layer templates that fails across composed pairs. That converts T-10's central assertion —
   that records present is not records sufficient — from our claim into someone else's formal
   result, which is a much better place to argue from.
4. **An OSCAL hook for T-08.** They frame the Responsibility IR as extending NIST OSCAL from fixed
   control catalogs to protocol-derived normative clauses. T-08's SP 800-53 agent control overlay is
   adjacent to that and should cite it rather than arrive at it independently.

**What it costs us in narrowing.**

| Piece | Change required |
|---|---|
| **T-12** | Cannot open on composition under-specification. Must open on the mechanism/protocol distinction: AgentThread proves orphaned responsibility at the protocol layer; T-12 shows the same orphaning at the mechanism layer with a different instrument. Cite in the first two pages, not in related work. |
| **T-12** | Their honest limitation is our positioning lever: the models are small. ACP-Cap is an 8-clause abstraction of an entire protocol; the operation-count bound is 12 throughout. Formal coverage of a tiny abstraction is not coverage of the protocol. State this once, factually, without editorializing. |
| **T-10** | Upgrade, not a narrowing. Cite the all-five-protocols audit-completeness gap as independent formal support, then claim only the tamper-evidence delta, which their keyword sweep proves nobody in that paper touched. |
| **T-07** | Their flagship finding is that the MCP spec requires servers to sanitize tool outputs while the reference SDK performs zero sanitization, with five injection payloads passing unmodified. Usable, with a constraint — see below. |
| **T-03** | **Unaffected.** No classifier, no guard model, no FPR, nothing in their scope touches ours. AgentThread is not a threat to T-03 and should not be cited defensively there. |
| **T-01** | Their descriptive use of "mediate" ("protocols mediate tool access") is never a supervisory property, and they never measure coverage. The mediation-ceiling argument is untouched. |

**A record-doctrine constraint on the MCP sanitization finding.** The spec text is self-published by
the protocol's own authors, so quoting the requirement is clean. The reference SDK's zero
sanitization is a *researcher* finding that the vendor has not acknowledged. Under the standing rule
— name the record, never judge the company, and only where the vendor published it themselves — cite
AgentThread as the record and attribute the finding to them explicitly. Do not present it as a
vendor-acknowledged defect, and do not characterize the maintainers.

### The Balkanization SoK (arXiv:2607.05743) — the one that decides T-12

An SoK over 39 papers from 2023 to 2026, in 17 categories, across exactly T-12's population: sandbox
isolation, capability and access control, policy enforcement, TOCTOU, MCP threats, identity
delegation, execution provenance, network egress. Unvenued preprint, July 2026.

**What it forecloses.** Any presentation of T-12 as the first systematization of this literature.
Any claim that the field is fragmented, unless you say who already said so.

**What it leaves open, and this is the whole opportunity.** Its five stated gaps read as a
commissioning brief: no shared benchmark across isolation versus capability models; policy
enforcement failing at 69–98% with isolation papers never re-testing under those conditions; TOCTOU
and MCP threats studied as two problems when they are one; nothing on policy-authoring error; and
out-of-scope benign actions at up to 17.1% under realistic prompting. It organizes by *category* —
17 of them — which is a taxonomy, not a partition. It has no enforcement-tier axis and no
weakest-link rule.

**What T-12 must therefore do.** Argue the differentiation in the first two pages with a table, not
in §9. The differentiation is real and it is structural: they classify by topic, we partition by
where a guarantee can be defeated. But it has to be shown, because a reviewer who has read
2607.05743 and reaches page 6 of ours without seeing it named will stop.

**And check its venue status this week.** If it lands at USENIX Cycle 1 or Cycle 2, the PC has it in
front of them while reading ours. That changes the calculus, and it is a half-hour of work.

### HCP, DEMM-Bench, ClawGuard — not read, and the consequences of that

I will not characterize what these do to our claims from abstracts, because doing so is the exact
defect flagged above. What can be stated is the exposure:

- **DEMM-Bench is the live risk to T-10.** The corpus entry says it measures whether records across
  eight evidence regimes are *sufficient to reconstruct decision-level properties* rather than merely
  present — which is T-10's core move, benchmarked. The proposed reframe ("sufficient for whom" —
  mapping OCC 2026-13, RBI June 2026 and SDAIA evidentiary demands onto DEMM's property questions)
  is a good bet, but it is currently **a bet on an unread paper.** If DEMM-Bench already maps to
  supervisory demands, T-10's reframe is dead and we would not know. Read it before writing another
  word of T-10.
- **ClawGuard is the live risk to T-03 §2.** The production notes already identify it as closest to
  our subject. Until it is read, T-03's related-work positioning is unknown, not merely incomplete.
- **HCP threatens T-11 and T-12's tier axis** at the level of "what a runtime can enforce." The
  corpus entry claims the distinction holds because our subject is mechanism *class* and not
  protocol invariants inside one class. That distinction is probably right. It is not yet verified.

**These three reads are now T-12 corpus work.** All three are in-corpus rows under the stated
inclusion gates. Doing them inside the T-12 schedule costs nothing extra and discharges T-03's and
T-10's debt at the same time. That efficiency is a significant part of why the sequencing in §6
routes through T-12.

---

## 3. The evidence gap, quantified

### What can be salvaged from existing data

The protocol document is wrong to say nothing exists. `T-03-experimental-protocol.md` P6 concluded
"zero salvageable experimental evidence" after looking only at the two hand-built files, and never
opened `ml/README.md` or `python/warrantor_ml/src/warrantor_ml/baselines.py`, where every real
number in this program lives. That is a mis-scoped literature search inside our own repository, and
it is worth naming because it is the same failure mode as the abstract-level related work:
concluding from a partial sweep.

**What is actually there.** Four base-model benchmark runs and two rejected training runs, all
2026-08-13, full splits, no sampling, seed 0, temperature 0, fail-closed, `num_ctx=8192`,
Controversial treated as harmful. On the WildGuardTest held-out split against Qwen3Guard-Gen-4B-GGUF
Q4_K_M via Ollama: overall recall 0.8554, precision 0.9241, F1 0.8884, FPR 0.0561, n=1699; the
`adversarial=false` slice FPR 0.0224, n=903; the `adversarial=true` slice FPR 0.0923.

**Exactly one empirical claim is supportable today, and it is not one of the three in the abstract.**
You can defend: *the apparent finance / healthcare / law spread in a general guard is a prevalence
artifact of one weak category.* It was measured twice, at both scales, with z-values and Wilson
intervals, and the repo already records that no domain pair separates at 95% with a largest |z| of
1.75. That is the *mechanism behind* §6.1. It is not §6.1's claim, which is about a fine-tuned
vertical guard against a fine-tuned general guard — a contrast for which no checkpoint exists.

**But even the salvageable claim must be re-run**, because the raw per-item outputs it rests on were
never committed and are gone from disk, and the per-slice counts in `baselines.py` were solved
backward from rounded rates to plus or minus one row. You cannot ship an artifact whose numbers were
reconstructed from their own rounding.

### The runs, in required order

Three columns, deliberately separated: GPU-hours is the cheap part, person-days is the real part,
and calendar latency is what actually decides the deadline.

| # | Run | GPU-hrs | Person-days | Calendar latency | Blocked on |
|---|---|---|---|---|---|
| **R0** | Regenerate base-model baselines with committed per-item artifacts | 2–3 | 1–2 | corpus gates | B-C1, B-C2, B-A |
| **R1** | **E3** `num_ctx` sweep on the two existing base checkpoints, 5 configs × 3 seeds | 2–4 | 2–3 | none beyond R0 | R0 |
| **R2** | **E2** rephrasing: freeze T1–T5, generate pairs locally, annotate 200, run E2.1/2.2/2.3 | 4–8 | 5–8 | **2–4 weeks (annotators)** | B-B, P5, power redesign |
| **R3** | **E1** four LoRA trainings + 8 evaluations across splits A and B | 8–14 | 8–12 | **unknown (vertical corpus + license)** | B-C2, vertical corpus, P4 |
| **R4** | **T-04** leakage effect size, two adapter configurations | 3–5 | 2–3 | none | nothing; checkpoints exist |

**Total compute across the entire program: 19 to 34 GPU-hours.** That is a weekend on the 5080 plus
one Kaggle session. Compute has never been the constraint, and treating it as the long pole in the
protocol timeline was a misdiagnosis. The 32768 sweep point will OOM the 16 GB card; either clip at
16384 and record the clipping, as the protocol already instructs, or push that one point to Modal.

**Notes that change the estimates.**

- **R1 is the best-value run in the program.** Inference only, two existing checkpoints, no gate on
  anything but the corpus, and it produces the *only* number in the whole `num_ctx` argument. Every
  existing `num_ctx` statement in this repository is either a VRAM constraint (32768 OOMs the 5080)
  or a config-divergence incident (4096 shipped for eight releases while published figures said
  8192). The prose assertion "it also changes results" has no measurement behind it anywhere in the
  tree. Run R1 in September regardless of which paper you target.
- **R2's pole is human, not silicon.** Two independent annotators, 200 pairs, kappa and exclusion
  rate reported. Four to six hours of work each; two to four weeks of scheduling from a standing
  start. Nothing about the GPU budget touches this.
- **R2 also needs a sample redesign before it runs.** At 491 benign originals and FPR 0.0224 you
  have about 11 false-positive events, Wilson 95% [0.0126, 0.0397]. The amplification ratio inherits
  a multiplier of roughly 0.56× to 1.78× from the denominator alone, so a point estimate of 4.0
  carries a confidence interval of at least [2.26, 7.14]. That cannot distinguish fourfold from
  twofold. Expanding the negatives pool from the WildGuardMix train split (~88k rows) fixes it, and
  forces a re-freeze of the P3 splits and a re-run of R0 on the expanded pool. Budget that.
- **R3's pole is the corpus, not the training.** Four LoRA runs is a day. A frozen, manifested,
  license-cleared vertical corpus that differs from the general corpus *only* in domain content —
  because E1's critical control permits corpus as the single difference — is unestimated work that
  has not started.
- **R4 is unblocked.** The two rejected runs exist. Two more short runs at a different rank and
  target-module set, plus a defined leakage metric, and T-04 has its number.

### The five blockers that are not runs

| ID | Blocker | Action | Latency |
|---|---|---|---|
| **B-C1** | WildGuardMix not on this machine, gated | Submit the gate request | Days to weeks, uncontrolled |
| **B-C2** | ExpGuardMix gated **and** not license-cleared; CC-BY-4.0 declaration conflicts with the research-only gate form; GPT-4o-generated upstream | Get the conflict resolved in writing by the maintainers, or drop the corpus from the program | Weeks, uncontrolled |
| **B-A** | Raw outputs gitignored (`.gitignore:122`), never committed, absent from disk | Decide what part of `results/` is committed — **and whether per-item JSONL of a gated corpus may lawfully be republished at all.** This gates every run, including R0 | Days, internal, but must precede R0 |
| **B-B** | No annotators identified for the 200-pair equivalence sample | Two names, committed, this week | 2–4 weeks |
| **B-R** | Four of five blocking reads outstanding | Fold into T-12 corpus work | 6–10 person-days |

B-A deserves emphasis. It looks like housekeeping and it is a licensing landmine. Committing
per-item outputs of a gated corpus means republishing gated content. That decision has to be made
before R0 produces the files, not after.

---

## 4. The PC review, consolidated

**Coverage note.** The methodology-and-statistics lens arrived in full and is reproduced faithfully
below. The other two lenses did not reach this pass intact; findings E1–E4 and P1–P3 are derived
from the repo evidence audit and the AgentThread read rather than from those lenses directly. Treat
this section as complete on statistics and provisional on the other two until they are
re-consolidated.

Ranked by whether the finding kills the paper **at the chair** (desk-reject tier) or **at review**.

### Desk-reject tier — these stop it before a reviewer is assigned

**D1. Results stated in the indicative past tense against empty result sections.**
The Abstract, §1 ("Each result is negative for the practice") and §9 ("We test three common
practices and find each unsupported") assert all three outcomes as completed, and the Abstract
quantifies one of them ("approximately fourfold"), while §5 and §6 contain nothing but `⟦R#⟧`
markers. A chair reading the abstract against §5 sees results asserted that the paper does not
contain. That is an integrity flag, not a formatting flag. It is also self-refuting: §6 is written
conditionally ("*If* the naive aggregate favors... *then* the gain is a distribution artifact")
three sections after §1 has already declared the answer. The header's pre-commitment sentence — that
all three findings are reported whatever they show, including nulls and reversals — is inoperative
once the abstract has declared what they show.
**Fix:** rewrite the Abstract, §1 and §9 in the interrogative until §5 exists — "We test whether",
"We report the measured amplification factor". Delete every predicted direction and every predicted
magnitude from the abstract. Move the three predicted directions into a clearly labeled §4.8
"Pre-registered predictions" where a reader can score them against the outcome. That form makes the
pre-registration worth something, because it becomes falsifiable. **Two hours of editing, and it is
the single highest-value change in this entire document.** Do it this week, before the draft
circulates further.

**D2. "Approximately fourfold" is a transcription, not a prediction, and it is from the wrong
design.** The figure comes from `baselines.py` `_WILDGUARD`: WildGuardTest FPR 0.0224 on the
`adversarial=false` slice against 0.0923 on `adversarial=true`, ratio 4.12. Those are two disjoint
sets of roughly 491 and 455 **different** items carrying a corpus-supplied `adversarial` flag,
written adversarially by the corpus authors. §4.4 pre-registers something categorically different:
the *same* benign item under five mechanical transformations, paired. A between-items contrast and a
within-item paired contrast measure different constructs and have no reason to agree. The paper has
published a number it cannot have measured, from a design it is not running.
**Fix, and take option (b):** (a) delete the magnitude and report only the design; or (b) cite the
WildGuard slice contrast explicitly in §1 as prior *between-items* evidence from the corpus's own
adversarial flag, state the n of each arm, and state plainly that Experiment 2 tests whether a
paired within-item design reproduces it. Option (b) is the better paper — *"does a corpus's
adversarial flag predict robustness under controlled rephrasing?"* is a sharper question than the
one currently asked, and it converts an embarrassment into the motivation.

**D3. Related work built from abstracts.** Four of seven references are characterized from
abstracts; the paper's own production notes call this "a desk-reject risk and an integrity problem."
As of today only AgentThread has been read in full, and it is the one of the four that turns out
*not* to threaten T-03. The three that might — HCP, DEMM-Bench, ClawGuard — are unread.
**Fix:** read them. Six to ten person-days, and they are T-12 corpus rows anyway.

**D4. §7.1 promises an artifact deliverable that does not exist and was never committed.** "Raw
per-item outputs" are gitignored and absent from disk. An artifact section promising files the
repository cannot produce is worse than having no artifact section, because artifact-evaluation
committees check.
**Fix:** resolve B-A, then regenerate via R0, and do not restate the promise until the files are
committed.

### Review tier — these do not stop the chair, but they end the review

**S1. No power analysis, no minimum detectable effect, no stated sample size anywhere in §4.** How
many items in the in-domain test set, how many benign originals feed E2, how many rephrasings per
item, how many categories survive normalization — none of it is stated. Three headline claims are
nulls, and a null without a power calculation is uninterpretable. The arithmetic is in §3 above: the
E2 design as specified carries a ratio confidence interval of at least [2.26, 7.14] around a point
estimate of 4.0.
**Fix:** add §4.0 "Sample sizes and power" giving, per experiment, N items, N per cell, the smallest
effect size of interest, and the power to detect it at the corrected alpha. Where power is
inadequate, expand the negatives pool from the ~88k-row WildGuardMix train split, or pre-register the
claim at the precision the design supports — "amplification is at least 2×" rather than
"approximately fourfold." Ship the power calculation as a runnable script in the artifact, since the
paper's entire rhetorical position is reproducibility.

**S2. H1₀ accepts the null from a failure to reject.** "After controlling category distribution, the
difference is not significant" is the most common statistical error in null-result papers and an
automatic reject in front of statistically literate reviewers. Failing to reject is compatible with a
large true effect and an underpowered design — which, per S1 and S3, is nearly certain here.
**Fix:** replace with a formal equivalence test. Pre-register a smallest effect size of interest in
operational units ("a gain below 2.0 points of recall at fixed FPR, or below 1.0 point of FPR at
fixed recall, is operationally trivial"), justify the threshold operationally rather than
statistically, and test with TOST or a Bayes factor against a pre-specified ROPE. The claim then
becomes *"vertical specialization is statistically equivalent to general within ±2 points"* — a
positive, defensible, publishable finding — instead of *"we did not find a difference,"* which is not
a finding at all.

**S3. E1 is known to be underpowered before it runs.** 753 positives and 946 negatives spread over
roughly 13 WildGuard categories, then Bonferroni-corrected across categories, gives per-category
power near zero for anything but a very large effect. The repository already records the analogous
result: no domain pair separates at 95%, largest |z| = 1.75.
**Fix:** either expand the pool, or restate E1 at the granularity the data supports — aggregate,
reweighted, with equivalence bounds — and report per-category as exploratory, labeled as such.

**S4. "Operationally trivial" is never defined numerically.** §4.7 converts significant-but-trivial
results to nulls under a rule with no threshold. That is unbounded post-hoc analyst discretion
sitting inside a document whose whole claim to credibility is that discretion was removed in advance.
**Fix:** a number, in §4, before any run. Same threshold as S2's smallest effect size of interest.

**S5. The freeze claim in §8.1 rests on an author-controlled file timestamp.** That is not a
registration, and IEEE S&P has no pre-registration track, so the framing buys zero procedural
leniency there. USENIX is no different on this point.
**Fix:** register the protocol on OSF or AsPredicted, or — better, and thematically exact — anchor
the protocol hash to a public transparency log using the mechanism this project builds. A paper about
tamper-evident evidence that timestamps its own pre-registration with a mutable local file is making
its reviewers' argument for them.

**E1. Corpus licensing is unresolved and it reaches the results.** ExpGuardMix is marked NOT CLEARED
for commercial use, its CC-BY-4.0 declaration disagrees with its research-only gate form, and it is
GPT-4o-generated upstream. A guard trained on GPT-4o-generated data and then evaluated for
"specialization" raises a distillation confound the paper never addresses.
**Fix:** resolve the license in writing or drop the corpus; and if it stays, add a
threats-to-validity paragraph on synthetic-corpus provenance. Do not let this surface first in a
review.

**E2. The E1 critical control is stated but unverifiable.** `G-gen-*` and `G-vert-*` must share
identical hyperparameters, token budget and adapter configuration, with corpus as the only
difference. No checkpoint exists, so nothing has been verified. Reviewers will ask for the Model
BOMs.
**Fix:** emit the Model BOM before the runs, not after, and diff the two configurations in the
artifact so the control is checkable rather than asserted.

**E3. The catalog records an unmeasured claim as evidence in hand.** `01-track-technical.md` lists
"the recorded findings on category artifact / 4× FPR / `num_ctx` pinning" under `HAVE`. The `num_ctx`
item is not a finding, it is a deployment decision. Listing a deployment decision as evidence is the
exact mechanism by which an unmeasured claim reached the abstract.
**Fix:** correct the row, and re-score T-03's E axis from 4 to 1.

**E4. The category-artifact claim in §6.1 is not the claim the data supports.** What was measured is
domain spread *within one untuned guard* — a different hypothesis from vertical-fine-tuned versus
general-fine-tuned. The measured result is a good result. It is a different result.
**Fix:** say what was measured. It is defensible; the substitution is not.

**P1. Position T-12 against AgentThread in the first two pages, not in related work.** Applies to
T-12 rather than T-03, but it is the same class of error: a reviewer who knows the prior art and does
not see it named early stops reading.

**P2. Position T-12 against arXiv:2607.05743 with a table, in the introduction.** See §5.

**P3. Do not cite AgentThread defensively in T-03.** Nothing in its scope touches guard models,
classifiers, false-positive rates or context configuration. Citing it in T-03's related work invites
a comparison that does not exist and signals that the authors have not read it.

---

## 5. T-12 SoK assessment

### Is a credible SoK achievable by 26 January 2027?

**Yes, conditionally.** 149 days, with a corpus freeze at 2026-11-15 leaving ten weeks for analysis
and writing — which is the right shape, and matches how good SoKs are actually built. The four
conditions:

1. **Check 2607.05743's venue status this week.** If it is under submission at USENIX, reconsider the
   cycle or sharpen the differentiation further. Thirty minutes.
2. **Publish the inclusion criteria and the action-surface enumeration to the repo before coding
   begins**, the same discipline P4 applies to the category normalization map in T-03. Publishing the
   rules first makes it impossible to shape them around the findings, accidentally or otherwise.
3. **Two independent coders and a reported kappa on the derived cells.** See axis 2 below. This is
   non-optional, and it is the same class of human dependency that is sinking T-03's E2 — but here it
   sits inside a 149-day window rather than a 79-day one, and the coders can be the same people.
4. **Argue the differentiation from 2607.05743 in the first two pages with a table.** Not §9.

### Do the three axes partition the corpus?

**Axis 1 — enforcement tier (cryptographic / OS-kernel / application-proxy). Yes, and it is the
paper's strongest asset.** The weakest-link assignment rule — score each work at the *lowest* tier at
which its guarantee can be defeated, not the tier it advertises — is a genuine contribution rather
than bookkeeping, and it is the thing that stops the axis dissolving into a "hybrid" bin, which is
where every prior taxonomy in this space has ended up. The worked example in the scoping is exactly
right: a system that signs mandates but enforces them in an in-process hook is proxy-tier, because
forging the signature is unnecessary when the hook can be bypassed. Keep this. It is the paper.

**Axis 2 — mediation coverage. Partitions, but only because the SoK *derives* it, and that makes it
the most contestable thing in the paper.** The scoping is honest that extraction from author claims
is not viable and that coverage must be derived against a fixed enumeration of the coding-agent
action surface. That is the correct call, and it means axis 2 is a *new measurement the SoK
performs*, not a classification of what the literature says. It is either the paper's best
contribution or its fatal weakness, and which one depends entirely on procedure:

- Freeze and publish the action-surface enumeration first. The scoping already names seven effectors:
  file write, subprocess spawn, network egress, VCS push, package install, credential use, sub-agent
  spawn. Freeze that list before coding.
- Two independent coders, reported kappa, disagreements adjudicated on the record.
- **Every derived cell traceable to a quoted span in the source paper.** Borrow AgentThread's
  discipline here: their IR validators reject any record whose source span is absent from the
  document. Same rule, applied to coverage cells.

Do that and axis 2 is defensible. Skip it and a reviewer calls it the authors' opinion rendered as a
heatmap, and they will be right.

**Axis 3 — evidence model. It collapses. Replace it.**

The corpus will not populate it. Isolation papers, capability and access-control papers,
policy-enforcement papers and TOCTOU papers make no evidence or tamper-evidence claim at all, and
inclusion gate 4 of the exclusions already removes agent-observability work "whose only claim is
visibility with no authority or tamper-evidence claim." So the column reads *none* for the large
majority of rows and populates almost exclusively in the receipts, provenance and attestation
cluster — which is our own lane.

That is worse than a weak axis. **An axis whose only populated cells are the authors' own work reads
as the paper arguing toward its sponsor's product**, and it hands a reviewer the single most damaging
thing they can say about an SoK from an organization that ships in the space. The T-12 spec already
anticipates the neutrality objection and answers that the classification must be applied to our own
work first and most harshly. Axis 3 as specified does the opposite: it constructs a dimension on
which only we score.

**Proposed replacement: adversary placement.** Where does the work assume the attacker sits, relative
to the interposition point? Five positions:

| | Placement | Example class |
|---|---|---|
| A1 | Outside the system entirely | Network and perimeter controls, egress filtering |
| A2 | In the agent's inputs or retrieved context | Indirect prompt injection defenses, tool-output screening |
| A3 | In the agent's own policy or weights | Misaligned or compromised model; behavioral controls |
| A4 | Inside the harness or orchestrator process | In-process hooks, MCP-layer policy, TOCTOU |
| A5 | Below the harness | Kernel, hypervisor, supply chain, package install |

Four reasons this is the right substitution:

1. **It is extractable, not derived.** Inclusion gate 3 already requires a stated threat model with an
   assumed-compromised component. The data is in the papers.
2. **It partitions cleanly**, and it partitions the corpus differently from axis 1 — which is what an
   axis has to do to earn its place.
3. **It is the mechanism of the headline result.** T-12's falsifiable claim is that a specific,
   nameable set of published guarantees do not compose. Two controls compose only if their adversary
   placements are compatible — a control that assumes A2 and a control that assumes A4 do not
   compose, and you can *show* that per pair. Axis 3 as evidence model supports that claim not at
   all. Axis 3 as adversary placement *is* that claim's instrument.
4. **It is exactly the ground AgentThread leaves open.** Their threat model is a protocol-level
   Dolev-Yao adversary augmented with agent-specific capabilities, and their transport substrate is
   assumed. Nothing in their paper places an adversary below the protocol layer. Ours does, on every
   row.

**Keep the evidence model, demoted.** Carry it as a per-row grade borrowed from AgentThread's Table 3
— L0 claim-only, L1 source inspection, L2 behavioral confirmation, L3 reproducible bypass or exploit
— reported as a column in the corpus table rather than as an organizing axis. That preserves what you
wanted from axis 3 (the evidence question is a real one, and receipts genuinely are underexamined)
without giving it structural weight it cannot carry, and it gives you something sharp to say against
2607.05743's finding that policy enforcement fails at 69–98%: how many of the works claiming
enforcement have ever been graded above L1?

### Two more things the SoK should keep

- **The classical-works handling is right.** Complete mediation, confinement, least privilege,
  execution monitors and capability confinement enter without a date bound, but as positioning
  apparatus and evaluative vocabulary — never as tiered corpus rows, never coverage-scored. Say so
  explicitly in §2; reviewers of SoKs look for exactly this discipline.
- **Apply the tier rule to our own work first, in the paper, at full severity.** The spec commits to
  it and the estate already has the material: the three-enforcement-tiers finding records that
  "Enforced" conflates cryptographic and OS bounds with proxy-chokepoint bounds, and that no netns,
  seccomp or firewall mechanism exists. Under the weakest-link rule our own system scores proxy-tier.
  Publishing that is the single most credible page in the paper.

---

## 6. Recommended sequencing

**Objective: one paper actually submitted. The target is T-12 at USENIX Security '27 Cycle 2 on
26 January 2027.**

### The tradeoff, stated plainly

**Taking 17 November** buys you a submission at IEEE S&P and costs you: a known-underpowered design,
an unresolved corpus license, a related-work section built on three unread papers, an equivalence
check rushed through two annotators recruited under deadline, and an abstract that currently states
results the paper does not contain. At a venue with roughly 14% acceptance and statistically literate
reviewers, every one of those is found. The most likely outcome is a reject with reviews that say,
correctly, that the paper was submitted before it was finished — and that review record follows the
work.

**Taking 26 January** costs you ten weeks of visible silence on the academic track, and carries the
risk that 2607.05743 gets venued in the interim. The second risk is real and checkable in an
afternoon. The first is a communications problem with a communications solution: the business track
and the technical blog estate keep shipping on their own cadence, and R1's `num_ctx` result is
publishable as an arXiv note in September if you want a flag planted.

**The asymmetry that decides it:** T-03's critical path runs through four external dependencies you
cannot accelerate. T-12's critical path runs through reading, coding and writing, which you can
parallelize across the fleet with a review gate and which has no external latency at all. In burst
mode the enemy is starting something you cannot finish — the catalog's own words — and T-03 for
17 November is that thing.

### The sequence

**Week 1 (30 Aug – 6 Sep). Start everything with external latency, in parallel, today.**

1. Submit both Hugging Face corpus gate requests. Escalate the ExpGuardMix license contradiction to
   its maintainers in writing. Get the CC-BY-4.0 versus research-only-gate conflict resolved on the
   record, or drop ExpGuardMix from the program and say so in the protocol.
2. Name two independent annotators. Names committed, not intentions.
3. Decide the artifact-commit policy (B-A), including whether per-item JSONL derived from a gated
   corpus may lawfully be republished. This gates every run, including R0.
4. Check 2607.05743's venue status.
5. **Rewrite T-03's Abstract, §1 and §9 into the interrogative and move the predictions to a labeled
   §4.8.** Two hours. Highest value per minute in this document, and it should not wait for a venue
   decision, because the draft is already circulating internally.
6. Fix the `HAVE` row in `01-track-technical.md` and re-score T-03's E axis to 1.

**Weeks 1–2. Run R1 (E3) on the two existing base checkpoints.** Commit the artifacts. First real
result and first committed artifact this program has ever produced, and it validates the harness end
to end on a cheap job before anything expensive runs. Do this regardless of paper target.

**Weeks 2–11 (Sep – 15 Nov). T-12 corpus construction against the stated freeze.** Publish the
inclusion criteria and the frozen action-surface enumeration to the repo before coding begins. Two
coders, kappa reported, every derived coverage cell traced to a quoted span. **Read HCP, DEMM-Bench,
ClawGuard and 2607.05743 in full inside this stream** — all four are in-corpus rows under the stated
gates, so doing them here discharges T-03's and T-10's related-work debt at zero marginal cost. That
efficiency is a large part of why this sequencing works.

**Weeks 4–10, in parallel and on its own clock. R2 (E2) and R3 (E1)**, targeting the full
three-finding T-03 at the same 26 January cycle. Two USENIX submissions from one lab in one cycle is
normal. If the annotation or the vertical corpus slips, T-03 moves to the next cycle and T-12 is
unaffected, which is the whole point of putting T-12 on the critical path instead.

**Weeks 4–6, whenever a gap opens. R4, and ship T-04.** Two adapter configurations, a defined leakage
metric, three to five GPU-hours. Then a workshop or arXiv on its own schedule. Do not couple it to
anything.

**15 November. T-12 corpus freeze**, as scoped.
**15 Nov – 26 Jan. T-12 analysis and writing**, ten weeks, as scoped.
**26 January. Submit T-12.** Submit T-03 alongside it only if E1 and E2 both completed clean by
5 January. If they did not, T-03 goes to the following cycle and nothing is lost, because T-12
carried the deadline.

### What the 17 November date is still good for

Nothing for T-03. But there is a real use for the pressure: **treat 17 November as the hard internal
deadline for R1, R2 and B-A.** If E2 and E3 are both complete and artifact-backed by 17 November,
T-03 for 26 January becomes a comfortable paper instead of a scramble, and the vertical-corpus
question for E1 gets decided with time to drop it cleanly if the license does not resolve. Use the
date as a forcing function on the dependencies rather than as a submission target on the paper.

---

## 7. The three sentences to carry out of this

1. **Compute was never the constraint.** The whole experimental program is 19 to 34 GPU-hours; the
   constraints are two corpus gates, one license conflict, two annotators and a committed
   artifact-storage decision, and none of them are made faster by working harder.
2. **The abstract states results the paper does not contain**, and fixing that is two hours of editing
   that removes the single largest risk to a document already in circulation.
3. **T-12 is the paper that can actually be finished**, because its long pole is reading — and the
   reads it requires are the same four reads that T-03 and T-10 have been deferring since the program
   was built.
