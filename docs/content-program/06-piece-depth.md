# Depth Addendum — All 28 Pieces

> Four dimensions per piece: **figures** spec'd to buildable detail · the **three hardest
> objections** with the actual counter · **distribution, headline variants, the ask and its success
> measure** · **reviewer and reader targeting**.
>
> Companion to [`01-track-technical.md`](01-track-technical.md) and
> [`02-track-business.md`](02-track-business.md), which hold thesis, outline, evidence and drafted
> openings. This file does not repeat those.

**A note on the objections.** Each piece lists the objection it is *most likely to be killed by*
first. If the first counter is weak, the piece is weak — that ordering is the point, and two entries
below fail it and say so.

---

# Track 1 — Technical

## T-01 · The Mediation Ceiling

**Figures**
1. *Action surface, drawn to scale by frequency.* Five classes as areas proportional to measured
   counts; the mediated slice shaded. Data: `coverage.json` from the measurement protocol. Earns its
   place because the argument is fundamentally about proportion, and a reader who sees the areas does
   not need the paragraph.
2. *One real session, annotated.* A vertical timeline of a genuine run; each action marked mediated /
   observed-not-mediated / unseen. Data: the three correlated logs. Earns it by making an abstract
   claim concrete in a way no diagram of boxes can.
3. *Coverage under composition, same workload.* Paired bars, bare vs. sandboxed, per action class.
   This is the pre-committed "what the fix buys" figure and it must appear beside figure 1, not in a
   later section.

**Hardest objections**
1. *"You're describing your own product's limitation as an industry law."* — The falsifier is named
   in the piece and the metric is published so anyone can measure a competitor. If a protocol-level
   supervisor exceeds the ceiling, the protocol shows it. Nothing here rests on our implementation.
2. *"Then the product is worth little."* — It is worth exactly the declared surface, which is where
   authorization decisions and receipts live. The composition figure quantifies the rest. A bounded
   claim with a number beats an unbounded one without.
3. *"One session is an anecdote."* — Correct, which is why the standardized ten-task set carries the
   headline figure and the real session is reported separately and never averaged in.

**Distribution & CTA** — Repo canonical → Substack lead → LinkedIn ~900w. Headlines: *"The Mediation
Ceiling"* (canonical) · *"I stopped calling it a mediation layer"* (Substack) · *"Your agent
supervisor sees less than you think. Here's how to measure it."* (LinkedIn). **Ask:** run the
protocol on your own deployment and tell me the number. **Success:** third-party coverage figures
reported back — one is a result, three is a metric.

**Targeting** — Staff/principal security engineers evaluating agent controls; they already believe
supervision is an implementation-quality problem. The belief being changed: that it is a deployment
property they must measure rather than a feature they can buy.

---

## T-02 · Three Kinds of "Enforced"

**Figures**
1. *Tier stack with adversary classes.* Three bands — cryptographic / OS / proxy — each annotated
   with the adversary that defeats it and the ones it survives. The core contribution in one image.
2. *Composition table.* Control × tier × survives-what. Includes our own kill switch and sandbox
   attestation, scoring them honestly.
3. *Our two papers, re-scored.* Papers 13 and 14 mapped onto the tiers, with the overclaimed cells
   marked. Earns its place by being the piece's credibility: a taxonomy that only indicts others is
   marketing.

**Hardest objections**
1. *"AgentThread already did composition, formally, with counterexamples."* — ⚠️ **This is the one
   that decides the paper.** The counter is that AgentThread analyzes whether composed *protocols*
   preserve stated requirements; this analyzes whether composed *mechanisms* have compatible
   adversary models. Orthogonal axes. **If that distinction cannot be made crisply in two pages, the
   paper should merge into T-12 instead of standing alone** — decide after reading, not before.
2. *"A taxonomy isn't a contribution."* — The composition rule is, and it is falsifiable: it predicts
   which composed guarantees fail and names the reachability condition.
3. *"WASM isolation is neither OS nor proxy — your taxonomy is incomplete."* — Correct as stated, and
   `arXiv 2601.01241` makes it concrete. Address it as a named open question in the paper rather than
   stretching the taxonomy to cover it.

**Distribution & CTA** — arXiv + repo canonical; Substack practitioner summary. Headlines: *"Three
Kinds of Enforced"* · *"I wrote 'enforces containment' in three documents and meant three different
things."* **Ask:** apply the tiers to your own controls. **Success:** the tier vocabulary used by
someone who did not get it from us.

**Targeting** — Program committee: security systems reviewers who will attack novelty against
AgentThread and completeness against WASM. Both pre-empted in the text. Practitioners: architects who
have written "enforced" without qualifying it.

---

## T-03 · Measuring Guard Models

**Figures**
1. *Vertical vs. general, per category, artifact isolated.* Paired bars per category plus the
   controlled aggregate. The whole first claim.
2. *FPR under neutral vs. adversarial phrasing,* with three real rephrasing pairs shown verbatim so
   a reader can judge semantic equivalence themselves.
3. *Decision sensitivity vs. `num_ctx`.* Line plot across the swept range, pin marked at 8192.
4. *Provenance chain.* Dataset manifest → training config → Model BOM → result. Earns its place in an
   artifact-evaluated venue, where it is read before the results are.

**Hardest objections**
1. *"Single-lab results on models you trained yourself."* — The artifact is the answer: harness,
   manifests, BOMs, pinned environments, clean-room reproduction. Plus the negative results published
   alongside, which is not what a lab optimizing for a favorable result does.
2. *"The category artifact is a split artifact."* — Pre-register the split; report both splits;
   state explicitly that finding (a) collapses if it does not survive the second.
3. *"Adversarial rephrasing is subjective."* — Publish every pair. Semantic equivalence is a judgment
   and the reader must be able to make it independently.

**Distribution & CTA** — IEEE S&P 2027 Cycle 2 (abstract ~10 Nov, full 17 Nov) → arXiv on submission
→ repo → Substack plain-language version after acceptance or preprint. **Ask:** re-run against your
guard. **Success:** acceptance; failing that, citations of the `num_ctx` pinning finding, which is
the most immediately useful result for practitioners.

**Targeting** — Reviewers: applied ML security. They will attack sample size, statistical treatment,
and generalization beyond our models. Pre-empt with confidence intervals, seed control, and an
explicitly narrow generalization claim. **Do not claim the findings hold for all guards.**

---

## T-04 · Negative Results in Guard Fine-Tuning

**Figures**
1. *Masking configuration vs. observed field drift* — the leak, quantified. Without an effect size
   this is an anecdote.
2. *4B vs. 0.6B,* vertical content beside general content, so the null result sits next to the real
   one.

**Hardest objections**
1. *"Obvious from the method."* — Obvious in retrospect; we did it deliberately, twice, with a
   reasonable hypothesis. The page count is justified by the compute it costs others.
2. *"You configured LoRA wrong."* — Test at least two rank/target-module configurations before
   claiming generality, and say which were tested.
3. *"Negative results papers are filler."* — Only when vague. This has a mechanism, an effect size,
   and a prescription.

**Distribution & CTA** — Workshop or USENIX Cycle 2 companion → arXiv → Substack. Headline: *"We
rejected two training runs on the same hypothesis. The second one is the interesting one."**Ask:*
none — this piece is pure credibility. **Success:** cited by someone about to make the same mistake.

**Targeting** — Practitioners fine-tuning structured-output models. They believe loss masking
isolates. It does not.

---

## T-05 · No New Trust Root

**Figures**
1. *Three subsystems, before and after the rule.* Blocked-on-what → shipped-with-what.
2. *The non-guarantee register,* worked: claim / mechanism / explicitly-not-established. This table
   is the transferable artifact and should be designed to be lifted into other people's specs.

**Hardest objections**
1. *"Weaker guarantees are worth less."* — They are worth more when the stronger one is unadoptable.
   A guarantee nobody will root their PKI in has a real-world strength of zero.
2. *"This is just federation / delegation, renamed."* — ⚠️ **Fair, and partly true.** The
   contribution is the *discipline* — the register as a required specification artifact — not the
   architecture. **Say so.** Overclaiming novelty here would be ironic given the paper's subject.
3. *"Eventually you need a root anyway."* — Yes, and the register names exactly which phase needs it.
   That is the point, not a rebuttal.

**Distribution & CTA** — arXiv + repo → Substack essay. Headlines: *"No New Trust Root"* · *"Three
subsystems were stuck. They were one problem."* **Ask:** adopt the non-guarantee register in your own
spec. **Success:** a register appearing in someone else's specification.

**Targeting** — Architects who have watched trust-root projects fail; standards participants. They
believe strength is the goal. The reframe: adoptability is.

---

## T-06 · What MCP 2026-07-28 Changes

**Figures**
1. *Delegation under stateful vs. stateless core* — where authority lived, where it must live now.
2. *Correction table.* Article 07 claim → current spec reality → corrected claim. The piece is a
   self-correction and the table is that, made checkable.

**Hardest objections**
1. *"Every spec release gets a blog post."* — This one is published as a correction to our own prior
   article, which is a different genre.
2. *"Stateless doesn't actually break delegation."* — Possible. If the bridge migrates cleanly, the
   piece shrinks to a note and publishes honestly as one.
3. *"You should have anticipated this."* — Yes. That is worth one sentence and no more.

**Distribution & CTA** — Repo blog series (replacing 07's position) → Substack → LinkedIn.
**Ask:** check your own delegation layer for implicit session assumptions. **Success:** shipped
inside the window where it is still news. **Value decays to zero by roughly late October — drop it
rather than publish it late.**

**Targeting** — Engineers building on MCP who read the changelog and not the implications.

---

## T-07 · Reading the NSA Advisory as an Engineering Specification

**Figures**
1. *Risk → control → enforcement tier matrix,* gaps shaded. **The shaded cells are the piece.** A
   matrix with no gaps is marketing and will be read as such.
2. *30-day hardening sequence as a dependency graph.*

**Hardest objections**
1. *"A vendor reading a government document to sell me something."* — Four rows are our own gaps,
   shaded, in the same table at the same size. That is checkable.
2. *"You're implying agency endorsement."* — Explicit disclaimer; quote precisely; never paraphrase a
   normative statement upward.
3. *"The CSI is generic."* — It is. That is why the mapping has value, and why the mapping is the
   contribution rather than the summary.

**Distribution & CTA** — Repo canonical + vikramjha.work → Substack → LinkedIn. Headlines: *"Reading
the NSA's MCP Advisory as an Engineering Specification"* · *"A signals-intelligence agency wrote
about a tool protocol. Read it as a spec."* **Ask:** the 30-day sequence. **Success:** highest-value
outreach asset in Track 1 — measure by meetings it opens.

**Targeting** — US enterprise security architects and CISOs who need a citation to open a budget
line. They believe agent risk is speculative. A CSI is not speculative.

---

## T-08 · An SP 800-53 Control Overlay for Agent Systems

**Figures**
1. *Control family × agent capability coverage grid* (AC, AU, CM, SI, SC).
2. *Controls that do not exist in any family,* with rationale per entry. The genuinely new claim.

**Hardest objections**
1. *"Who are you to write an overlay?"* — Nobody is, yet; that is the argument for a public draft.
   Carry an explicit invitation to be shredded.
2. *"NIST will publish something different."* — Framed as a contribution, dated, and positioned to
   inform rather than compete.
3. *"This implies NIST endorsement."* — Title, header and first line all state independence.

**Distribution & CTA** — Standards channel first (COSAiS contribution route, CSA working group),
repo published in parallel. **Ask:** comment on it. **Success:** cited or absorbed into a working
group. **Highest standards leverage available in the window.**

**Targeting** — NIST reviewers, federal integrators, CSA members, enterprises mapping agents onto
800-53. They believe the overlay is coming soon. It has no date.

---

## T-09 · The Kill Switch That Passed CI

**Figures**
1. *CI matrix before and after,* untested surface shaded.
2. *The breach:* contract → Windows path → the assertion that never executed.

**Hardest objections**
1. *"That's a CI misconfiguration, not a finding."* — Correct, and it is the class of
   misconfiguration that makes a security claim false while every dashboard stays green.
2. *"Why publish your own defect?"* — It is self-disclosed, describes the defect not any person, and
   the fix shipped first. That is the permitted case under the naming doctrine, and it buys more
   credibility than it costs.
3. *"Over-generalized."* — Scope the claim to platform-gated paths under single-OS CI. Do not extend.

**Distribution & CTA** — Repo → Substack → LinkedIn. Headline: *"The kill switch had 33 passing tests
and a contract breach."* **Ask:** check your own platform-gated paths. **Success:** engineers
reporting the same gap in their CI. ⚠️ **Now also feeds B-14** — the RBI mandates kill switches; this
is what building one honestly looks like.

**Targeting** — Rust and platform engineers; auditors of our claims. They believe green CI means
tested.

---

## T-10 · Action Receipts as Supervisory Evidence

**Figures**
1. *Evidentiary demand per regime → receipt field that answers it.* Now spans OCC 2026-13, **RBI
   Chapter V-B.3 and its third-party accountability provision**, and SDAIA.
2. *Log vs. receipt trust model* — who can alter what, undetected.
3. *Minimum receipt schema.*
4. **New:** *DEMM property questions → supervisory demand.* The reframed contribution.

**Hardest objections**
1. *"DEMM-Bench already benchmarks evidence sufficiency."* — ⚠️ **The decisive one.** It validates
   sufficiency against a property set, never against a supervisory demand. The mapping is the
   contribution. **Reframe to 'sufficient for whom' or do not write it.**
2. *"Our audit logs already do this."* — The delta is not completeness, it is that the examined party
   cannot alter them undetectably. Cryptographic, not operational.
3. *"No regulator requires receipts."* — True today. Argue from direction of travel, the US RFI, and
   the RBI's mandatory independent validation even of vendor-certified models.

**Distribution & CTA** — Repo + vikramjha.work → regulator channels → Substack. **Ask:** what would
your evidence prove if someone had altered it? **Success:** cited in a comment filing.

**Targeting** — Technical staff in regulated institutions and their examiners. They believe logging
is solved.

---

## T-11 · What Each Layer Actually Enforces

**Figures**
1. *Action timeline with each layer's enforcement point marked.*
2. *Worked example, three-column verdict table* — one action, three verdicts, plus the fourth case
   all three miss including ours.

**Hardest objections**
1. *"A map with yourself at the center."* — The map includes our ceiling and tier limits at the same
   size, and ends on a case we also miss.
2. *"Products span layers now."* — Possible; re-verify within 30 days of publishing. This entry ages
   fastest in Track 1.
3. *"OWASP's Solutions Landscape already does this."* — ⚠️ **Read it first.** If it does, cite and
   build; do not restate.

**Distribution & CTA** — Repo + vikramjha.work → LinkedIn. **Ask:** which layer is missing from your
stack. **Success:** used inside an evaluation we are not part of.

**Targeting** — Technical evaluators on buying committees. They believe the three categories are
substitutes. ⚠️ **Highest doctrine risk in Track 1** — every product claim carries the vendor's own
document inline; never characterize a firm.

---

## T-12 · SoK: Authority and Containment

**Figures**
1. *Three-axis classification with the corpus plotted.*
2. *Composition matrix* — what does not compose with what.

**Hardest objections**
1. *"Insufficient breadth."* — The corpus and inclusion criteria are pre-stated and published. A thin
   SoK is worse than none.
2. *"Not neutral — you're a vendor."* — Apply the classification to our own work first and most
   harshly.
3. *"The axes are arbitrary."* — Each must be shown to partition the corpus non-trivially, or it is
   not an axis.

**Distribution & CTA** — USENIX Security '27 Cycle 2 (26 Jan 2027) → arXiv. **Ask:** none.
**Success:** becomes the citation for how this field is organized. **Ranked last deliberately; most
likely to eat a quarter.**

**Targeting** — The security research community. Reviewers will attack corpus construction above all
else — spend the effort there.

---

## T-13 · The Verification Claim Audit

**Figures**
1. *Claims by backing type* — executing assertion vs. prose.
2. *The understating correction:* stated → corrected → actual.

**Hardest objections**
1. *"Why publish your own audit failures?"* — Because someone else would, and because the
   claim-to-assertion ratio is a metric the field should report.
2. *"The ratio is arbitrary."* — Publish the extraction method; let it be argued with.
3. *"This is self-flagellation."* — Keep it factual. No tallying, no apology, no rumination.

**Distribution & CTA** — Repo + `claim-vs-mechanism.json` artifact → Substack. **Ask:** compute your
own ratio. **Success:** the ratio reported by someone else. ⚠️ **Run the audit before writing** — if
the ratio is fine, the piece says so.

**Targeting** — Engineers; anyone auditing us. They believe test count implies claim coverage.

---

## T-14 · Reproducibility Package

**Figures**
1. *Provenance chain:* dataset manifest → training config → Model BOM → result.

**Hardest objections**
1. *"Reproducible on your infrastructure."* — Clean-room test on an untouched machine is the
   acceptance criterion, and it is stated before the run.
2. *"Pinned environments drift anyway."* — They did. A floating torch/CUDA pairing already changed
   what "same environment" meant between two runs; it is pinned at source now and the incident is
   disclosed in the package.
3. *"Artifacts are an appendix."* — This one ships as a first-class deliverable with its own
   acceptance test.

**Distribution & CTA** — Repo + Hugging Face + arXiv artifact appendix. **Ask:** re-run it.
**Success:** artifact badge, or a third-party reproduction. ⚠️ **Compute discipline:** Kaggle first
(30h/wk, free), Modal only above 16 GB VRAM, $100 cap, open/synthetic data only on US-cloud tiers.

**Targeting** — Artifact evaluation committees; practitioners re-running against their own guards.

---

# Track 2 — Business

## B-01 · The Guidance That Excluded Your Biggest Risk

**Figures**
1. *Before/after:* what SR 11-7 specified vs. what 2026-13 leaves to the institution. Two columns,
   same control categories. Earns its place because "the map changed, the territory didn't" is the
   whole argument and a table says it faster than three paragraphs.
2. *Obligations map:* what fell out of scope vs. what did not move — safety and soundness, consumer
   protection and fair lending, sectoral duties, third-party risk, all marked untouched.

**Hardest objections**
1. *"Out of scope means less work for validation, not more."* — Scope exclusion moves the work from a
   checklist to a documented judgment, and judgments are evidenced or they are not defensible. The
   exam still happens.
2. *"You're predicting regulatory intent."* — No prediction required. The agencies stated they will
   issue an RFI covering generative and agentic AI. A regulator intending permanent exclusion does
   not announce a consultation.
3. *"This is a vendor manufacturing urgency."* — No product is mentioned, no framework proposed, and
   the closing is a diagnostic question the reader answers alone.

**Distribution & CTA** — Repo canonical + vikramjha.work → Substack full → LinkedIn ~1,100w.
Headlines: *"The Guidance That Excluded Your Biggest Risk"* (canonical) · *"Two sentences in April's
model risk guidance have been read as relief for four months"* (Substack) · *"Your regulator just
stopped telling you what adequate looks like"* (LinkedIn). **Ask:** the board question — name an
agent in production and say what it is allowed to do. **Success:** forwarded internally by a CRO;
measure by inbound referencing the board question specifically.

**Targeting** — CRO, head of model risk, board risk committee, institutions above $30bn. They
currently believe the exclusion reduces their obligations. **Draft complete:**
[`drafts/B-01-...`](drafts/B-01-the-guidance-that-excluded-your-biggest-risk.md).

---

## B-14 · ⭐ Two Regulators, Opposite Choices, Identical Gap

**Figures**
1. *The two documents side by side:* scope decision · agentic treatment · control specificity ·
   enforceability. Four rows, two columns. The entire thesis, readable in ten seconds.
2. *"Kill switch" decomposed across the three enforcement tiers,* with neither regulator's language
   mapping cleanly to any of them. This is the figure that turns a comparison into a contribution.
3. *Build-once map:* one control set, two regimes, showing which artifacts satisfy both.

**Hardest objections**
1. *"Different regimes differ — that's not a finding."* — They differ in **direction** and converge
   on the **hole**. The convergence is the finding, and it means the work is portable.
2. *"The RBI draft may change before it's final."* — Stated explicitly. The piece is true now and
   dated; the gap it identifies is what the final guidance will have to close.
3. *"You're quoting a central bank from secondary summaries."* — ⚠️ **Currently valid.** Obtain the
   RBI PDF before publication. Non-negotiable.

**Distribution & CTA** — Repo canonical → Substack → LinkedIn (two cuts, one per market). Headlines:
*"Two Regulators, Opposite Choices, Identical Gap"* · *"One regulator deferred. The other mandated.
Neither said what to build."* **Ask:** if you operate in both markets, you have one problem, not two
— what have you built for it? **Success:** the strongest available door-opener for cross-market
institutions; measure by GCC/India/US meetings it generates.

**Targeting** — CROs and boards at institutions operating across both jurisdictions. They believe
their obligations differ by market. ⚠️ **Highest factual density in the program** — every instrument
dated, linked, quoted exactly.

---

## B-02 · The RFI Is Coming

**Figures**
1. *Timeline:* SR 11-7 → 2026-13 → RFI → separate AI guidance, with the build window marked.
2. *Cost curve:* build now vs. retrofit later vs. comment.

**Hardest objections**
1. *"We'll respond when it publishes."* — By then your posture is fixed and your comment describes
   whatever you happen to have. Leverage comes from arriving with a built thing.
2. *"Post-hoc specification doesn't really codify existing practice."* — Argue from mechanism and
   mark it as an argument, not a finding. **Do not overstate this.**
3. *"The RFI might not come."* — State it as a scenario with an alternative branch.

**Distribution & CTA** — Repo → LinkedIn → Substack. Headline: *"The guidance that will govern your
agents hasn't been written yet. That's the opportunity."* **Ask:** be ready to file. **Success:**
meetings before the RFI publishes. ⚠️ **Shelf life in weeks** — check the RFI status weekly; on
publication this becomes a response piece and must be rewritten, not reposted.

**Targeting** — Head of model risk, government-affairs leads, CRO. They believe consultation is a
future event rather than a current deadline.

---

## B-07 · From Advisory to Binding — India's June 2026 Draft

**Figures**
1. *FREE-AI recommendation → June 2026 draft obligation,* mapped. Shows advisory becoming
   examinable.
2. *Two clocks on one calendar:* draft finalization and DPDP consent rules, November 2026.
3. **New:** *Chapter V-B.3 requirements vs. what a bank can actually evidence today.*

**Hardest objections**
1. *"It's still a draft."* — ⚠️ **And the comment window closed 24 July 2026.** The piece must pivot
   from "file a comment" to "prepare for final guidance" — that pivot is now the honest framing and
   it is more urgent, not less.
2. *"We already have a model risk framework."* — The draft requires a **Board-approved** MRMF across
   all models, risk tiering by level of autonomy, and kill-switch arrangements. Check each against
   what exists.
3. *"Vendor certification covers our third-party models."* — It does not. Independent RE validation
   is mandatory even where vendors have certified. Quote the provision.

**Distribution & CTA** — Repo → Substack → LinkedIn (India audience). Headline: *"The RBI published
FREE-AI in August 2025. The binding one arrived in June."* **Ask:** does your MRMF cover eleven
categories of obligation across every AI model? **Success:** India consulting conversations.

**Targeting** — CROs, CCOs, heads of compliance at banks, NBFCs, payment firms. They know their own
regime better than you do — **get the date right (August 2025) or lose them in the first paragraph.**

---

## B-05 · SDAIA Accreditation as a Procurement Gate

**Figures**
1. *Five pillars → evidence artifact → who produces it.*
2. *Four maturity levels with observable indicators* — what each looks like from outside.

**Hardest objections**
1. *"It's non-binding, so it's a checkbox."* — Non-binding and contract-determining are compatible,
   and the second has revenue attached.
2. *"The framework doesn't address agents."* — ⚠️ Verify before asserting the gap. If it now does,
   the piece becomes a mapping instead of a gap analysis.
3. *"You're overstating enforceability."* — The exact claim is *non-binding, increasingly
   contract-relevant.* Anything stronger is wrong; anything weaker misses the point.

**Distribution & CTA** — Repo + vikramjha.work → LinkedIn (GCC) → Substack. Headline: *"A procurement
gate wearing the clothes of a voluntary standard."* **Ask:** is your evidence pack
accreditation-ready? **Success:** GCC pipeline — this opens the region the estate currently lacks
entirely.

**Targeting** — Regional CIOs, systems integrators, Vision 2030 bidders. They believe non-binding
means optional.

---

## B-04 · Can You Stop It? A Containment Self-Audit

**Figures**
1. *Four containment levels with preconditions per level* — state checkpointing, transaction
   reversibility, perimeter contraction.
2. *The in-flight-action timeline* — the failure mode nobody drills.
3. *Scoring sheet,* designed to be printed and filled in by hand.

**Hardest objections**
1. *"We can revoke the credentials."* — Revocation stops the next action, not the one executing, not
   the three that completed during the decision, and not the half-finished work in a system with no
   concept of a partial agent transaction.
2. *"Your statistics are vendor-sourced."* — ⚠️ **Now answerable.** Kiteworks 2026 Data Security
   Forecast, n=225 security/IT/risk leaders, 10 industries, 8 regions: 60% cannot terminate a
   misbehaving agent quickly, 63% cannot enforce purpose limitations. Cite in full every time.
3. *"Drills are theater."* — Then the score will be high and the piece costs ninety minutes.

**Distribution & CTA** — Repo (instrument as downloadable) → Substack → LinkedIn. Headline: *"If one
of your agents started doing something wrong right now, how long until it stops?"* **Ask:** run the
drill. **Success:** completed self-audits reported back. ⚠️ **Lead with the 35%/60% discrepancy, not
either figure** — the gap between "can't stop it at all" and "can't stop it quickly" is roughly the
population that believes it has containment and has never timed it. That is the thesis, handed over
by the data.

**Targeting** — CISOs, heads of platform engineering. They believe they have containment. Also now
directly relevant to **RBI-regulated entities** facing a kill-switch mandate.

---

## B-03 · The Autonomy Perimeter

**Figures**
1. *Model inventory row vs. autonomy perimeter row,* same agent, side by side.
2. *Five-level maturity rubric,* published in full.

**Hardest objections**
1. *"We have an AI inventory."* — Name any agent on it and state its action envelope. If the answer
   is prose rather than configuration, the inventory describes a prediction and the risk is an
   action.
2. *"You're coining a term that already exists."* — ⚠️ **Check `arXiv 2606.30970` (AgentBound)
   first.** If it names this object, adopt or extend rather than compete. A duplicate term is a
   category-authority loss.
3. *"Rubrics invite score inflation."* — Named as a section: why teams claim Level 3 and drills prove
   Level 1.

**Distribution & CTA** — Repo + board one-pager → Substack → LinkedIn. **Ask:** score yourself.
**Success:** the rubric used in a board pack.

**Targeting** — Board risk committees, CROs, CIOs. They believe an inventory is coverage.

---

## B-13 · The 90-Day Readiness Sequence

**Figures**
1. *The sequence as a dependency graph, not a Gantt chart* — the ordering claim is falsifiable and
   the figure must show why.
2. *End-state evidence pack:* what you can show an examiner at day 90.

**Hardest objections**
1. *"Ninety-day plans are consultant theater."* — This one states which step each later step depends
   on. Check the dependency; it is falsifiable on purpose.
2. *"We can't do this without you."* — Then it has failed its own test. It must be executable alone.
3. *"Ninety days is arbitrary."* — It is the window to the likely RFI, stated as such.

**Distribution & CTA** — Repo + vikramjha.work → Substack → LinkedIn. **Ask:** start day 1.
**Success:** the obvious commercial piece; measure by engagements, but only publish it if it is
genuinely executable without us.

**Targeting** — CISOs and program leads who need to start something Monday.

---

## B-09 · Funding Agent Oversight — The Budget Memo

**Figures**
1. *Four leaking budgets vs. one funded capability.*
2. *Year-one allocation* — instrumentation and drills, not licenses.

**Hardest objections**
1. *"A platform purchase in a trend costume."* — Year one buys instrumentation and drills. If that is
   not the proposal, the objection is correct.
2. *"Analyst projections aren't evidence."* — Cite what Gartner published, never imply endorsement,
   never present a projection as a measurement.
3. *"Consolidation isn't obviously better."* — Argue from mechanism and label it an argument.

**Distribution & CTA** — One-page memo (forwardable) + explainer → LinkedIn. **Ask:** forward the
memo. **Success:** budget conversations. ⚠️ **Only traced statistics in a CFO-facing document** —
Kiteworks with full attribution; nothing from the untraced §H3 list.

**Targeting** — CISO preparing the request; CFO receiving it.

---

## B-08 · A Buyer's Map of What Each Layer Enforces

**Figures**
1. *Action timeline with enforcement points.*
2. *Evaluation scorecard,* usable in a live bake-off.

**Hardest objections**
1. *"A map with yourself at the center."* — Our layer's ceiling appears on it at the same size.
2. *"Products span layers."* — Re-verify within 30 days of publishing.
3. *"OWASP already published a solutions landscape."* — ⚠️ Read it first; cite and build if so.

**Distribution & CTA** — Repo + vikramjha.work → LinkedIn. **Ask:** score your shortlist.
**Success:** used in an evaluation we are not in. ⚠️ **Highest doctrine risk in Track 2** — every
product claim carries the vendor's own document inline.

**Targeting** — Procurement leads, technical evaluators, CISOs running a bake-off.

---

## B-12 · Sovereign AI Without a Sovereign Trust Root

**Figures**
1. *Phase-one guarantees vs. deferred guarantees.*
2. *The non-guarantee register as a policy artifact.*

**Hardest objections**
1. *"Sovereignty means our own root."* — Eventually. The question is what ships before it exists, and
   the answer is more than assumed.
2. *"This is a vendor arguing for its own architecture."* — The rule is published; the architecture
   is open source; sovereignty is framed as verifiability rather than custody.
3. *"Some programs genuinely need a national root in phase one."* — Name that case rather than
   assuming it away.

**Distribution & CTA** — Repo → Substack → LinkedIn (GCC + India). **Ask:** what is actually phase
one? **Success:** sovereign program conversations. ⚠️ Argue mechanism, never geopolitics. Frame open
source multi-regionally — India, GCC, US, Canada — **never India alone.**

**Targeting** — Sovereign program leads, national AI authority staff, policy advisors.

---

## B-06 · The Gulf Sovereign-AI Assurance Brief

**Figures**
1. *Binding-layer map:* instrument × jurisdiction × enforceability × applies-to-agents.
2. *Artifact list by demand source* — buyer, supervisor, sovereign program.

**Hardest objections**
1. *"There's no regulation yet, so this is premature."* — DIFC Regulation 10 fully enforced since
   January; a Federal Authority created in June; procurement already gating. Absence of a horizontal
   statute is not absence of requirements.
2. *"You're describing instruments you haven't read."* — ⚠️ Verify each before citing clause
   structure. Regional regulatory writing ages fast and is easy to get subtly wrong.
3. *"Three demand sources is an artificial framing."* — Show that the three ask for different
   artifacts, or drop the framing.

**Distribution & CTA** — Repo + vikramjha.work → Substack → LinkedIn (GCC). **Ask:** which of the
three demand sources are you actually ready for? **Success:** regional authority.

**Targeting** — Regional CIOs/CISOs, sovereign program leads, integrators.

---

## B-10 · AEC — The BEP as the Governance Artifact

**Figures**
1. *Perimeter element → BEP clause mapping.*
2. *Where agents enter a project information workflow.*

**Hardest objections**
1. *"The BEP is about model data, not AI."* — It is about who is responsible for information others
   rely on. An agent producing that information is the case it was built for.
2. *"Real BEPs are too thin to carry this."* — ⚠️ Check actual ones before claiming otherwise.
3. *"You're citing ISO 19650 from memory."* — Do not. Verify clause structure.

**Distribution & CTA** — Repo + vikramjha.work → LinkedIn (AEC). Headline: *"AEC already has the
governance document. It's called a BEP."* **Ask:** add the perimeter to your next BEP. **Success:**
AEC pipeline — cheapest adoption path found in any sector and almost entirely unoccupied.

**Targeting** — Digital leads at AEC firms, BIM managers, project directors.

---

## B-11 · When the Agent Touches the Record

**Figures**
1. *Read / write / act authority matrix.*
2. *Evidence required per action type.*

**Hardest objections**
1. *"Access control already covers this."* — RBAC grants a human a scope and assumes a human's
   judgment about using it. An agent inherits the scope and runs the loop.
2. *"Clinical validation covers our AI."* — It addresses output quality. It is silent on action
   authority over records.
3. *"A sectoral rule already handles agent action authority."* — ⚠️ **Possible, and unverified.**
   Check first; if true, the piece becomes a mapping.

**Distribution & CTA** — Repo → LinkedIn (health) → Substack. **Ask:** what can each clinical agent
write? **Success:** healthcare conversations. ⚠️ **Least evidence-ready piece in the program** — do
not write before the verification lands. No clinical claims, no patient-safety assertions.

**Targeting** — Health-system CIOs/CISOs, clinical informatics leads, digital-health compliance.

---

## Cross-cutting distribution notes

**Routing.** Per your instruction, every piece is written platform-neutral: a canonical version plus
a LinkedIn cut. Which Substack publication each lands in is your call, made at publish time — no
routing is assumed anywhere in this catalog.

**Headline discipline.** Every headline variant above is US English, contains no em-dash-appended
explainer, and names the specific thing rather than the category.

**The three pieces that age fastest:** T-06 (weeks) · B-02 (until the RFI publishes) · T-11 and B-08
(30-day vendor re-verification). Everything else keeps.
