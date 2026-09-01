# Track 2 — Business Catalog

> **16 pieces** (B-14 added 2026-08-30 after the RBI verification; B-15 and B-16 added to close the
> sectoral-supervision gap). For CISOs, CIOs, CROs, heads of model risk, boards, and procurement. Voice: Vikram,
> first person. US English. Every external citation traces to
> [`04-verified-anchors.md`](04-verified-anchors.md).

Track 2 is not Track 1 simplified. It answers a different question. Track 1 asks *does this
mechanism hold*; Track 2 asks *what do I now have to do, by when, and what does it cost me if I
don't*. A business piece that is a technical piece with the equations removed fails both readers.

## Scoring and job tags

Same four axes as Track 1 — **D**eadline, **E**vidence, **N**arrative, **C**ommercial;
**Priority = D×2 + E×1.5 + N×1.5 + C**.

**Job** tags, per your weighting of all three objectives:
**§C** consulting pipeline · **§A** category authority · **§O** Alliance/OSS adoption.

**Geographic balance is a hard constraint here.** The existing 120-topic Editorial Arsenal is deep
on India and silent on the US supervisory record and the GCC. This track deliberately over-weights
US/NA and GCC to correct that. It is not a rebalance of the *market* — it is a rebalance of the
*estate*.

---

## The ranked slate

| # | Piece | Region | Job | D | E | N | C | **Pri** |
|---|---|---|---|---|---|---|---|---|
| B-01 | The guidance that excluded your biggest risk | US/NA | §C §A | 4 | 5 | 5 | 5 | **35.0** |
| B-02 | The RFI is coming | US/NA | §C §A | 5 | 4 | 3 | 4 | **34.5** |
| B-07 | From advisory to binding: India's June 2026 draft | India | §C | 4 | 5 | 3 | 4 | **32.0** |
| B-05 | SDAIA accreditation as a procurement gate | GCC | §C | 3 | 4 | 3 | 5 | **27.5** |
| B-04 | Can you stop it? A containment self-audit | Global | §C §O | 2 | 4 | 4 | 5 | **27.0** |
| **B-14** | ⭐ **Two regulators, opposite choices, identical gap** | US + India | §C §A | 3 | 5 | 5 | 5 | **26.0** |
| B-03 | The autonomy perimeter | Global | §A | 1 | 4 | 5 | 4 | **21.5** |
| B-13 | The 90-day readiness sequence | Global | §C | 1 | 4 | 3 | 5 | **20.5** |
| B-09 | Funding agent oversight: the budget memo | US/NA + GCC | §C | 1 | 3 | 3 | 5 | **18.0** |
| B-08 | A buyer's map of what each layer enforces | Global | §C §A | 1 | 3 | 3 | 5 | **18.0** |
| B-12 | Sovereign AI without a sovereign trust root | GCC + India | §A §O | 1 | 4 | 3 | 3 | **17.5** |
| B-06 | The Gulf sovereign-AI assurance brief | GCC | §A §C | 1 | 3 | 3 | 4 | **17.0** |
| B-10 | AEC: the BEP as the governance artifact | Global | §C | 1 | 3 | 2 | 5 | **15.5** |
| B-15 | CBUAE — the binding layer the Gulf actually has | GCC | §C | 1 | 2 | 3 | 4 | **14.5** |
| B-16 | NAIC — the vertical the banking guidance never touched | US/NA | §C | 1 | 2 | 2 | 4 | **13.0** |
| B-11 | When the agent touches the record | US + India | §C | 1 | 2 | 2 | 4 | **12.0** |

⚠️ **B-15, B-16 and B-11 are all blocked on verification** and cannot be drafted yet — CBUAE's
current position, NAIC's instrument set and adoption state, and US/India healthcare agent-authority
rules respectively. They are ranked, not ready.

**If you only get one burst:** B-01 and B-02. They are the same argument split across two moments —
what the supervisors removed, and what they are about to ask for — and together they are the entire
US/NA wedge that the estate currently lacks.

---

## B-14 · ⭐ Two Regulators, Opposite Choices, Identical Gap

**Format** flagship comparative brief + LinkedIn article + Substack · **Region** US + India
· **Job** §C §A · **Length** 2,600–3,200 words · **D3 E5 N5 C5 → 26.0**

> **The formula underrates this piece.** It scores 26.0 because the weighting rewards hard deadlines
> and this one has none. On argument strength it is the best thing in the program, and it did not
> exist until the RBI draft was verified on 2026-08-30.

**Thesis.** In one quarter of 2026, the two regulators that matter most to your markets made
opposite decisions about agentic AI — the US agencies put it **out of scope**, the RBI put it **in
scope and mandated kill switches** — and both landed in exactly the same place: a control that is
required or expected, and specified by nobody.

**The falsifiable claim.** OCC 2026-13 / SR 26-2 (17 April 2026) excludes generative and agentic AI
and states it sets no enforceable standards. The RBI Draft Guidance on Regulatory Principles for
Model Risk Management, 2026 (24 June 2026) includes AI/ML, and at Chapter V-B.3 requires *"override,
suspension, and deactivation mechanisms — including kill-switch arrangements for AI models"* — while
providing **no technical specification of what a kill switch is**. Therefore the specification gap is
regime-independent: it is not a consequence of either regulator's choice, and it will not be closed
by waiting for either.

**Reader and their objection.** CROs and boards at institutions operating across both jurisdictions;
also anyone who has concluded their obligations differ by market. Objection: *"These are different
regimes with different requirements — of course they differ."* Answer: that is the point of the
comparison. They differ in **direction** and converge on the **hole**. An institution that builds to
satisfy either one has to answer the same unanswered question, which means the work is portable and
the waiting is not.

**Outline.**
1. Two documents, two months apart, opposite decisions
2. What the US agencies removed — and the RFI that follows
3. What the RBI required — Chapter V-B.3, and the sentence that stops short
4. The convergence: "kill switch" is mandated, deferred, and defined nowhere
5. Why that is a specification problem and not a compliance problem — the word spans three
   enforcement tiers and neither regulator says which one is meant
6. Third-party accountability: the RBI's provision that survives any vendor certification
7. What a bank operating in both markets should build once
8. What the final RBI guidance and the US RFI will most likely codify

**Evidence.** `HAVE` — both regimes fully verified, §A1 and §E1; the enforcement-tier taxonomy that
shows why "kill switch" is under-specified; our own kill-switch implementation and the Windows CI
finding as a demonstration that the control is hard even when you are trying. ⚠️ `VERIFY` — **obtain
the RBI draft PDF itself.** Every current source is a secondary legal summary and the Chapter V-B.3
quotation, while consistent across them, must be confirmed against the original before publication.

**Figures.** (1) The two documents side by side: scope decision, agentic treatment, control
specificity, enforceability. (2) "Kill switch" decomposed across the three enforcement tiers, with
neither regulator's language mapping cleanly to any of them. (3) The build-once map: one control
set, two regimes.

**Prerequisites.** B-01 (the US half), B-07 (the India half), and the tier decomposition that makes
point 5 work — now carried by the tier practitioner blog and T-12 rather than by a standalone T-02.
The blog is short and evidence-ready, so this is a light dependency.

**What would make it wrong.** Final RBI guidance arriving with a technical specification, which
would close the India half of the gap. That would not weaken the piece so much as date it — and it
is worth writing precisely because it is true now and may not be in six months.

**Risk flags.** Two jurisdictions, high factual density, and an audience in each that knows its own
regime better than you do. Every instrument dated, linked, and quoted exactly. **Do not publish the
Chapter V-B.3 quotation until it is confirmed against the RBI's own PDF** — a misquotation of a
central bank in front of Indian banking readers is not recoverable.

**Drafted opening.**
> Two months apart this year, the two regulators with the most direct claim on my clients' AI
> programs made opposite decisions about the same technology.
>
> On 17 April, the Federal Reserve, FDIC and OCC replaced their model risk management guidance and
> wrote generative and agentic AI **out** of scope — novel, rapidly evolving, a separate document to
> follow. On 24 June, the Reserve Bank of India published draft guidance that writes AI and machine
> learning **in**, across eleven categories of regulated entity, and requires — at Chapter V-B.3,
> under human oversight — override, suspension and deactivation mechanisms, *including kill-switch
> arrangements for AI models*.
>
> One regulator deferred. The other mandated. If you operate in both markets, the natural reading is
> that you now have two different problems.
>
> You have one. The RBI requires a kill switch and does not say what a kill switch is. The US
> agencies removed the framework that would have said. Both documents leave the same sentence
> unwritten, and it is the only sentence that would tell an engineer what to build.

---

## B-01 · The Guidance That Excluded Your Biggest Risk

**Format** executive brief + LinkedIn article + Substack · **Region** US/NA · **Job** §C §A
· **Length** 2,000 words (brief) / 1,200 (LinkedIn cut) · **D4 E5 N5 C5 → 35.0**

**Thesis.** In April 2026 the federal banking agencies rewrote model risk management guidance and
explicitly put generative and agentic AI outside its scope — and most institutions have read that as
relief when it is the opposite: the framework that would have told you which controls satisfy the
examiner has been removed, while every underlying obligation stayed exactly where it was.

**The falsifiable claim.** OCC 2026-13 / SR 26-2 removes prescriptive specification, not liability.
Safety and soundness, consumer protection and fair lending, sectoral duties and third-party risk
management all continue to apply to agentic deployments; therefore the institution, not the
regulator, now bears the burden of defining and evidencing adequate control.

**Reader and their objection.** CRO, head of model risk, board risk committee at an institution
above $30bn. Objection: *"If it's out of scope, our validation team has less to do, not more."*
Answer: scope exclusion moves the work from a checklist to a judgment call, and judgment calls are
evidenced or they are not defensible. The exam still happens.

**Outline.**
1. What actually changed on 17 April 2026, in the agencies' own words
2. The two sentences everyone should read — the exclusion, and "does not set forth enforceable
   standards"
3. Why the exclusion is a deferral: the obligations that did not move
4. What "your own judgment" means when an examiner asks to see it
5. The evidence an institution should be generating now, before the specification exists
6. The uncomfortable timing — see B-02

**Evidence.** `HAVE` — the verified guidance and both quotations, §A1. Nothing else required. This
piece is writable today, in full, with no new work.

**Figures.** (1) Before/after: what SR 11-7 specified vs. what 2026-13 leaves to the institution.
(2) The obligations map — what fell out of scope vs. what did not move.

**Prerequisites.** None. This is the head of the US/NA lane.

**What would make it wrong.** If the agencies issue agentic-specific guidance sooner than expected
and it is prescriptive, the "you must define it yourself" window narrows. Frame as a window, with a
date, not as a permanent condition.

**Risk flags.** Do not give legal advice or characterize any institution's compliance posture.
Quote the guidance exactly; link the primary PDF; never paraphrase a normative statement upward.

**Drafted opening.**
> On 17 April 2026 the Federal Reserve, FDIC and OCC replaced the model risk management guidance the
> industry had been building against since 2011. Two sentences in the replacement matter more than
> the rest of the document, and I have watched them be read as good news for four months.
>
> The first says that generative AI and agentic AI models are *not within the scope of this
> guidance*, because they are novel and rapidly evolving. The second says the guidance *does not set
> forth enforceable standards or prescriptive requirements*.
>
> If you run a bank above thirty billion in assets and you have agents touching regulated workflows,
> the temptation is to file that under relief. It is not relief. Everything that made those
> deployments risky is still your obligation — safety and soundness, fair lending, third-party risk,
> the sectoral duties attached to whatever the agent is actually doing. What was withdrawn is the
> part that would have told you which controls are enough.
>
> You now have to answer that question yourself, in writing, in front of an examiner who will ask it
> whether or not anyone told you the format.

---

## B-02 · The RFI Is Coming

**Format** timing brief + LinkedIn · **Region** US/NA · **Job** §C §A · **Length** 1,400 words
· **D5 E4 N3 C4 → 34.5**

**Thesis.** The same agencies have said they intend to issue a Request for Information covering
banks' use of AI including generative and agentic systems — which means the separate guidance will
be written against whatever the industry has already built, and the institutions with something to
show will shape it.

**The falsifiable claim.** Regulatory specifications written after an industry practice exists tend
to codify a recognizable version of that practice; therefore the cost of building agent controls now
is lower than the cost of retrofitting to a specification written without your input, and filing a
comment is materially cheaper than either.

**Reader and their objection.** Head of model risk, government-affairs lead, CRO. Objection:
*"We'll respond when it's published."* Answer: by then your posture is fixed and your comment is a
description of what you happen to have. The leverage is in arriving with a built thing.

**Outline.** What the agencies said they will do · why post-hoc specification codifies existing
practice · the three things worth having built before it lands · what a defensible comment filing
looks like · the cost comparison, plainly · the readiness sequence (link B-13).

**Evidence.** `HAVE` — the stated RFI intent, §A1. `VERIFY` — whether the RFI has been published
since 2026-08-30; **re-check before every use of this piece**, because publication changes it from a
forecast into a deadline.

**Figures.** (1) Timeline: SR 11-7 → 2026-13 → RFI → separate AI guidance, with the build window
marked. (2) Cost curve: build now vs. retrofit later vs. comment.

**Prerequisites.** B-01.

**What would make it wrong.** The RFI arriving with a prescriptive draft attached, or not arriving
at all within a reasonable horizon. Both are stateable as scenarios rather than as a single bet.

**Risk flags.** This piece has a shelf life measured in weeks once the RFI publishes. Write it
early in the window or convert it into a response piece.

**Drafted opening.**
> Buried in the coverage of April's model risk guidance is a sentence about what happens next: the
> agencies plan to issue a request for information on model risk management that specifically
> addresses banks' use of AI, including generative and agentic AI.
>
> That is the whole strategic picture in one line. The guidance that will eventually govern agentic
> deployments has not been written. It will be written after a consultation. And consultations get
> answered, in practice, by the institutions that have something concrete to describe.
>
> There is a version of the next eighteen months where your controls are shaped by a specification
> written mostly from other people's implementations. There is another version where you spend the
> window building something defensible and then describe it. The second one is cheaper, and it is
> only available before the docket opens.

---

## B-03 · The Autonomy Perimeter

**Format** concept essay + board one-pager · **Region** global · **Job** §A · **Length** 2,400 words
· **D1 E4 N5 C4 → 21.5**

**Thesis.** Boards inventory models; agents are not models, they are actors — and the missing
governance object is not a longer model inventory but a documented, enforced boundary on what each
agent is permitted to *do*, which I call the autonomy perimeter.

**The falsifiable claim.** A model inventory captures what a system predicts; it captures nothing
about what a system may act upon. For any deployed agent, the questions *which systems can it reach,
which actions can it take without a human, and what stops it* are unanswerable from a model
inventory alone.

**Reader and their objection.** Board risk committee, CRO, CIO. Objection: *"We have an AI
inventory."* Answer: name any agent in it and ask what its action envelope is. If the answer is
prose rather than a configuration, the inventory is describing a prediction and the risk is in an
action.

**Outline.** Inventory vs. perimeter — the distinction stated once, precisely · the five questions a
perimeter must answer · why the answer must be enforced rather than documented (link to the tier
argument, in business language) · what a board can reasonably ask for · a maturity rubric, published
in full · common score inflation.

**Evidence.** `HAVE` — the RFC set and the enforcement-tier work translated to business language;
the Editorial Arsenal's existing capability-inventory-vs-model-inventory rubric, which is strong and
gets lifted and re-anchored from India-only to US/GCC/India.

**Figures.** (1) Model inventory row vs. autonomy perimeter row, same agent, side by side.
(2) The five-level maturity rubric.

**Prerequisites.** None; feeds B-04 and B-13.

**What would make it wrong.** If institutions are already capturing action envelopes under another
name, the concept is a relabel. Check the actual artifacts before claiming the gap.

**Risk flags.** Coining a term is a category-authority play and it only works if the term is more
precise than the alternatives, not merely newer. Define it once, tightly, and never stretch it.

**Drafted opening.**
> Every board I talk to has an AI inventory. Almost none of them can answer a question I now ask
> first: pick any system on that list and tell me what it is allowed to *do*.
>
> The inventory will tell you what the model predicts, who owns it, when it was validated, how it
> performs. Those are the right questions about a model. An agent is not a model — it is a model with
> a set of tools and a loop, and the risk has moved from the accuracy of a prediction to the reach of
> an action. Nothing on a standard inventory row describes reach.
>
> The missing object is a perimeter: which systems this agent can touch, which actions it may take
> without a human, what evidence each action leaves, and what stops it. Written down, and then
> actually enforced, because a perimeter that exists only in a document is a description of an
> intention.

---

## B-04 · Can You Stop It? A Containment Self-Audit

**Format** self-audit instrument + short guide · **Region** global · **Job** §C §O · **Length**
1,600 words + the instrument · **D2 E4 N4 C5 → 27.0**

**Thesis.** Most organizations running agents have never tested whether they can stop one, and the
gap between believing you can and having drilled it is where the incident lives — so here is a
ninety-minute self-audit that produces one honest number.

**The falsifiable claim.** Containment readiness is drillable and therefore measurable. An
organization's self-reported readiness and its drilled readiness diverge predictably, and the
divergence is concentrated in the in-flight-action problem: what happens to work already in progress
when the switch is thrown.

**Reader and their objection.** CISO, head of platform engineering. Objection: *"We can revoke the
credentials."* Answer: credential revocation stops the next action, not the one already executing,
and the difference is the entire failure mode nobody drills.

**Outline.** The question, asked plainly · the four containment levels and what each actually
requires · the in-flight-action problem · the drill: eight questions, ninety minutes · scoring, with
common inflation patterns named · what to do with a bad score.

**Evidence.** `HAVE` — the kill-switch implementation and its semantics, the enforcement-tier
taxonomy, the recorded requirement set (state checkpointing, transaction reversibility, perimeter
contraction). `VERIFY` — **the 35% "could not shut down a rogue agent" figure**, §H. **If it traces
to a primary source it becomes this piece's opening line; if it does not, the piece opens on the
drill instead and loses nothing structural.**

**Figures.** (1) Four containment levels with preconditions per level. (2) The in-flight-action
timeline. (3) The scoring sheet, designed to be printed.

**Prerequisites.** B-03 (the perimeter is what gets contracted).

**What would make it wrong.** If drills routinely pass, the premise is wrong and that is worth
publishing too.

**Risk flags.** This is a lead magnet, and lead magnets rot when they are thin. The instrument has
to be genuinely usable by someone who never contacts us — that is the condition of it working at
all.

**Drafted opening.**
> Here is a question worth asking in your next operations meeting, and worth timing: if one of your
> agents started doing something wrong right now, how long until it stops, and who is certain of
> that answer?
>
> The usual response is credential revocation. Revocation stops the next action. It does not stop
> the one already executing, it does not roll back the three that completed while the decision was
> being made, and it does nothing about the work sitting half-finished in a system that has no
> concept of a partial agent transaction. That gap — in-flight actions — is the failure mode I have
> never seen drilled and have repeatedly seen assumed away.
>
> What follows is a self-audit. Eight questions, about ninety minutes, no vendor required. It
> produces one number, and the number is only useful if you are willing to let it be low.

---

## B-05 · SDAIA Accreditation as a Procurement Gate

**Format** market brief · **Region** GCC (Saudi) · **Job** §C · **Length** 1,800 words
· **D3 E4 N3 C5 → 27.5**

**Thesis.** Saudi Arabia has declared 2026 the Year of AI, SDAIA's AI Adoption Framework sets a
mandatory governance baseline for every public-sector entity, and although none of it is legally
binding, accreditation is increasingly required to win government contracts — which turns a
voluntary framework into a commercial gate.

**The falsifiable claim.** For vendors and integrators selling into Saudi public-sector AI programs,
the binding constraint is procurement eligibility rather than legal liability, and the five SDAIA
pillars map to specific evidence artifacts a bidder can prepare in advance.

**Reader and their objection.** Regional CIOs, systems integrators, and any firm bidding into
Vision 2030 AI programs. Objection: *"It's non-binding, so it's a checkbox."* Answer: non-binding
and contract-determining are entirely compatible, and the second one is the one with revenue
attached.

**Outline.** What SDAIA published and what it requires · the five pillars — data governance, model
accountability, transparency, human oversight, risk management — as evidence demands · the four
maturity levels and where bidders actually sit · PDPL underneath it all · what an accreditation-ready
evidence pack contains · the agentic gap the framework does not yet address.

**Evidence.** `HAVE` — verified framework structure, §F. `VERIFY` — current accreditation procedure
and whether agentic systems are addressed explicitly; **do not claim the agentic gap without
checking the latest framework text.**

**Figures.** (1) Five pillars → evidence artifact → who produces it. (2) Maturity levels with
observable indicators.

**Prerequisites.** None. This is the head of the GCC lane, which the estate currently lacks
entirely.

**What would make it wrong.** SDAIA publishing agentic-specific requirements, which would change the
gap analysis. Date the piece explicitly.

**Risk flags.** Do not overstate the enforceability. "Non-binding, increasingly contract-relevant"
is the exact claim; anything stronger is wrong and anything weaker misses the point.

**Drafted opening.**
> Saudi Arabia has declared 2026 the Year of Artificial Intelligence, and SDAIA's AI Adoption
> Framework now sets a governance baseline for every public-sector entity in the Kingdom: data
> governance, model accountability, transparency, human oversight, risk management, across four
> maturity levels.
>
> None of it is legally binding. A dedicated AI law is expected, but it does not exist yet, and the
> binding layer today is the Personal Data Protection Law.
>
> That reading misses where the pressure actually is. Accreditation against the framework is
> increasingly a condition of winning government work. Non-binding and contract-determining are not
> in tension — and for a vendor, the second one is the one with a number attached. If you are bidding
> into a Vision 2030 program, this is a procurement gate wearing the clothes of a voluntary standard.

---

## B-06 · The Gulf Sovereign-AI Assurance Brief

**Format** regional whitepaper · **Region** GCC · **Job** §A §C · **Length** 3,500 words
· **D1 E3 N3 C4 → 17.0**

**Thesis.** No GCC state has a horizontal AI statute; the binding layer is data protection law plus
sectoral supervision, and a Federal Authority for AI and Data now exists in the UAE — so the
region's assurance question is not *what does the law require* but *what will the buyer, the
supervisor and the sovereign program each ask for*, which are three different lists.

**The falsifiable claim.** Across UAE and Saudi, the effective assurance requirements for an agentic
deployment derive from three non-statutory sources — procurement conditions, sectoral supervisory
expectation, and free-zone regimes such as DIFC Regulation 10 — and these produce a coherent, listable
set of artifacts.

**Reader and their objection.** Regional CIOs/CISOs, sovereign program leads, integrators.
Objection: *"There's no regulation, so this is premature."* Answer: DIFC Regulation 10 is fully
enforced, a federal authority was created in June 2026, and procurement is already gating. The
absence of a horizontal statute is not the absence of requirements.

**Outline.** The map: what binds where, as of today · UAE — AI Charter, National Strategy 2031,
DIFC Regulation 10, the new federal authority · Saudi — SDAIA framework, PDPL, accreditation ·
what the three demand sources actually ask for · the artifact list · sovereignty and data residency
as an architecture constraint, not a slogan · the agentic gap across all of it.

**Evidence.** `HAVE` — verified regional map, §F. `VERIFY` — the Federal Authority's mandate and
whether it has issued anything; DIFC Regulation 10's applicability to agentic systems specifically.

**Figures.** (1) The binding-layer map: instrument × emirate/kingdom × enforceability × applies-to-
agents. (2) Artifact list by demand source.

**Prerequisites.** B-05.

**What would make it wrong.** A horizontal statute landing in either jurisdiction. Watch item.

**Risk flags.** Regional-regulatory writing ages fast and is easy to get subtly wrong. Every
instrument gets a date and a link; nothing is described from memory.

**Drafted opening.**
> The most common thing I hear about AI governance in the Gulf is that there is not any yet. As a
> statement about statute, that is nearly true: no GCC state has a horizontal AI law as of the
> middle of 2026.
>
> As a statement about requirements, it is wrong in three separate ways. DIFC Regulation 10 has been
> fully enforced since January. The UAE created a Federal Authority for AI and Data in June. And in
> Saudi Arabia, SDAIA accreditation is quietly becoming a condition of public-sector work, which is a
> requirement in every sense that matters to a bidder even though it is not a requirement in law.
>
> So the useful question in this region is not what the law demands. It is what the buyer, the
> supervisor and the sovereign program each ask you to show — three lists that overlap and are not
> the same.

---

## B-07 · From Advisory to Binding — India's June 2026 Draft

**Format** regulatory brief · **Region** India · **Job** §C · **Length** 2,200 words
· **D4 E5 N3 C4 → 32.0**

**Thesis.** FREE-AI was advisory when the RBI published it in August 2025; the June 2026 draft
guidelines requiring regulated entities to establish governance frameworks for AI, ML and analytical
models are the binding successor — and DPDP consent rules landing in November 2026 mean two clocks
run out in the same quarter.

**The falsifiable claim.** The June 2026 draft converts specific FREE-AI recommendations into
governance obligations, and the intersection of those obligations with DPDP consent rules produces
concrete, datable work for any RBI-regulated entity running agents on customer data.

**Reader and their objection.** CROs, CCOs, heads of compliance at banks, NBFCs and payment firms.
Objection: *"It's still a draft."* Answer: drafts have comment periods, and the entities that respond
with a built posture are the ones that shape the final text — the same argument as B-02, in a
different jurisdiction, on a shorter clock.

**Outline.** What FREE-AI was and was not · what the June 2026 draft changes · the DPDP November 2026
consent clock and where it intersects · the IT Amendment Rules 2026 on synthetic content, in force
since February · what an RBI-regulated entity should have before the quarter ends · the comment
opportunity.

**Evidence.** `HAVE` — verified India stack, §E; the existing Editorial Arsenal's India material,
which is deep and largely reusable once dated correctly. `VERIFY` — the June 2026 draft's exact
scope and comment deadline. **This is the single most important outstanding verification in Track 2.**

**Figures.** (1) FREE-AI recommendation → June 2026 draft obligation, mapped. (2) The two clocks:
draft finalization and DPDP consent, on one calendar.

**Prerequisites.** None.

**What would make it wrong.** Misdating FREE-AI — it is **August 2025**, and project memory had it
as 2026. Getting this wrong in front of an Indian banking audience is disqualifying.

**Risk flags.** High factual density in a market where readers know the material better than you do
about their own institution. Every instrument dated and linked.

**Drafted opening.**
> There is a date worth fixing before anything else: the RBI published FREE-AI in **August 2025**,
> not this year. I have seen it cited as a 2026 framework often enough to want that on the record,
> because the distinction matters — FREE-AI was the advisory step, and the binding one arrived
> afterward.
>
> In June 2026 the RBI proposed draft guidelines requiring banks and regulated entities to establish
> governance frameworks for AI, machine learning and other analytical models. That is a different
> kind of document. Seven sutras and twenty-six recommendations become a governance obligation, and
> obligations get examined.
>
> Meanwhile the DPDP consent rules arrive in November. If you are running agents over customer data
> inside a regulated entity, two clocks run out in the same quarter, and they intersect precisely
> where the agent reads something it needed consent for.

---

## B-08 · A Buyer's Map of What Each Layer Enforces

**Format** procurement guide · **Region** global · **Job** §C §A · **Length** 2,000 words
· **D1 E3 N3 C5 → 18.0**

**Thesis.** Buying committees evaluate governance platforms, policy engines and runtime supervisors
as substitutes; they enforce different objects at different moments, and a stack that buys two of the
three has a gap nobody on the committee is positioned to notice.

**The falsifiable claim.** For a defined agent action, each layer's enforcement point falls at a
different moment, and I can name an action each layer independently permits.

**Reader and their objection.** Procurement leads, technical evaluators, CISOs running a bake-off.
Objection: *"You're drawing a map with yourself at the center."* Answer: the map includes what the
runtime layer cannot do, in the same table, at the same size.

**Outline.** Three objects, three moments · what to ask each vendor, in their own vocabulary · the
worked action, walked past all three · the gap that remains after all three · an evaluation
scorecard.

**Evidence.** `VERIFY` — **every** comparative claim from the vendors' own published documentation.
Name the record, never the firm's character; describe by class anything not self-disclosed.

**Figures.** (1) Action timeline with enforcement points. (2) Evaluation scorecard.

**Prerequisites.** T-11 (this is its business cut; write the technical one first so the claims are
already sourced).

**What would make it wrong.** A product shipping across two layers, collapsing the distinction.
Re-verify within 30 days of publishing.

**Risk flags.** **Highest doctrine risk in Track 2**, same as T-11. Zero characterization of any
firm. Every product claim carries its source link inline.

**Drafted opening.**
> I have now sat in enough evaluations to recognize the moment they go wrong, and it is early. Three
> categories go on the comparison grid as though they answer the same question — a governance
> platform, a policy engine, a runtime supervisor — and the committee starts scoring features.
>
> They are not substitutes. One enforces that your organization followed a process. One enforces an
> authorization decision at the moment a request is evaluated. One enforces bounds on an action while
> it executes. A stack with two of the three does not have a partial answer; it has a specific hole,
> at a specific moment, that nothing on the grid is measuring.
>
> This is the map I would want if I were buying, including the part where I mark what the layer I
> build does not cover.

---

## B-09 · Funding Agent Oversight — The Budget Memo

**Format** CFO-forwardable one-pager + explainer · **Region** US/NA + GCC · **Job** §C
· **Length** 1,200 words + one-page memo · **D1 E3 N3 C5 → 18.0**

**Thesis.** Gartner named agentic AI oversight the number-one cybersecurity trend for 2026 and
created a dedicated agentic market segment for the first time — which means the budget argument no
longer has to be invented, only assembled, and it should be assembled as one funded capability rather
than four leaking ones.

**The falsifiable claim.** Oversight spend distributed across four unfunded owners costs more and
evidences less than a single funded capability, and the first-year budget should buy instrumentation
before headcount and drills before dashboards.

**Reader and their objection.** CISO preparing a request; CFO receiving one. Objection: *"This is a
platform purchase in a trend costume."* Answer: the memo's first year is instrumentation and drills,
not licenses — and if that is not what is being proposed, the objection is correct.

**Outline.** The external validation, cited properly · the consolidation argument · what year one
actually buys · the trap: funding the title without the tooling · the one-page memo, formatted for
forwarding.

**Evidence.** `HAVE` — verified Gartner framing, §D. `VERIFY` — the adoption/incident statistics in
§H before any of them appear in a CFO-facing document. **A CFO memo with an untraceable statistic in
it is worse than one with none.**

**Figures.** (1) Four leaking budgets vs. one funded capability. (2) Year-one allocation.

**Prerequisites.** B-03, B-04.

**What would make it wrong.** If consolidated oversight functions underperform distributed ones in
practice. Argue from mechanism, and mark it as an argument.

**Risk flags.** Analyst-citation discipline — cite what Gartner published, do not imply endorsement,
and never present a projection as a measurement.

**Drafted opening.**
> The budget argument for agent oversight used to require inventing the category. It does not
> anymore. Gartner created a dedicated agentic AI segment in its spending forecast for the first
> time, named agentic AI oversight the number-one cybersecurity trend for 2026, and projects that
> agents whose job is watching other agents will take a tenth to a sixth of the agentic market by
> 2030.
>
> That does not win you the money. It means you no longer have to spend the first half of the meeting
> establishing that the problem exists, which changes what the second half can be about.
>
> What the second half should be about is consolidation. Right now this work is usually happening in
> four places — platform engineering, security, model risk, and whoever owns the vendor relationship
> — none of them funded for it, all of them partially doing it. The memo below makes the case for one
> funded capability, and it is deliberate that the first year buys instrumentation and drills rather
> than licenses.

---

## B-10 · AEC — The BEP as the Governance Artifact

**Format** sector brief · **Region** global · **Job** §C · **Length** 2,000 words
· **D1 E3 N2 C5 → 15.5**

**Thesis.** Architecture, engineering and construction already has a contractual document that
assigns responsibility for information production across parties — the BIM Execution Plan — and it is
the natural and almost unoccupied entry point for agent governance in the sector.

**The falsifiable claim.** The BEP's existing structure — responsibility assignment, information
requirements, validation gates — maps onto the autonomy perimeter without inventing a new
contractual instrument, which is why it is the cheapest possible adoption path in this sector.

**Reader and their objection.** Digital leads at AEC firms, BIM managers, project directors.
Objection: *"The BEP is about model data, not AI."* Answer: it is about who is responsible for
information that other parties rely on. An agent producing that information is exactly the case it
was built for.

**Outline.** Why AEC is early and under-served · what a BEP already assigns · the mapping: perimeter
→ BEP clause · what a project can adopt on the next job without renegotiating anything · the
evidence trail a client will eventually ask for.

**Evidence.** `HAVE` — the standing AEC sector doctrine and the recorded observation that an industry
publication described this product's function without knowing it exists. `VERIFY` — current BEP
standard references (ISO 19650 family) before citing clause structure.

**Figures.** (1) Perimeter element → BEP clause mapping. (2) Where agents enter a project
information workflow.

**Prerequisites.** B-03.

**What would make it wrong.** If BEPs in practice are too thin to carry it. Check real ones.

**Risk flags.** Do not cite a standard's clause structure from memory.

**Drafted opening.**
> Every sector adopting agents has to answer the same question — who is responsible for what this
> thing produces — and most of them are trying to answer it with a new document.
>
> Architecture, engineering and construction already has the document. A BIM Execution Plan assigns,
> contractually, who produces which information, to what standard, validated by whom, at which
> project stage. It exists because the industry learned that information other parties rely on needs
> an owner, and it learned that the expensive way.
>
> An agent generating design information is precisely the case the BEP was built for, and nobody has
> to invent a governance instrument to cover it. This is the cheapest adoption path I have found in
> any sector, and it is almost entirely unoccupied.

---

## B-11 · When the Agent Touches the Record

**Format** sector brief · **Region** US + India · **Job** §C · **Length** 2,000 words
· **D1 E2 N2 C4 → 12.0**

**Thesis.** In healthcare the interesting boundary is not whether an AI system is clinically
validated but whether an agent may read, write or act upon a patient record — and existing clinical
AI governance is built almost entirely around the first question.

**The falsifiable claim.** Clinical validation frameworks address model output quality and are silent
on action authority over records; therefore an agent that passes clinical validation may still hold
unbounded write access, and no current artifact records that fact.

**Reader and their objection.** Health-system CIOs/CISOs, clinical informatics leads, digital-health
compliance. Objection: *"Access control already covers this."* Answer: role-based access grants a
human a scope and assumes a human's judgment about when to use it. An agent inherits the scope
without the judgment, and the loop makes it act at machine rate.

**Outline.** Two different questions, one governance regime · read/write/act as distinct authorities
· what DPDP and US sectoral duties each demand of the record trail · the consent problem when the
actor is not a person · minimum evidence per agent action on a record.

**Evidence.** `HAVE` — perimeter and receipt frames. `VERIFY` — **substantial.** US healthcare AI
governance state as of 2026, DPDP health-data specifics, and whether any regulator has addressed
agent action authority over records. **This piece is the least evidence-ready in Track 2 and should
not be written before that verification lands.**

**Figures.** (1) Read / write / act authority matrix. (2) Evidence per action type.

**Prerequisites.** B-03, T-10.

**What would make it wrong.** A sectoral rule already covering agent action authority. Check first.

**Risk flags.** No clinical claims. No patient-safety assertions. Stay strictly on the governance
and access boundary — this is the sector where over-reach is least forgivable.

**Drafted opening.**
> Clinical AI governance has spent a decade getting good at one question: is this model's output
> reliable enough to inform care? The frameworks, the validation protocols, the committees — all of
> it addresses output quality.
>
> Agents ask a different question, and the frameworks do not see it. Not *is the output good* but
> *what is this thing allowed to do to the record*. Read it. Write to it. Act on it — order,
> schedule, escalate, close.
>
> Those are three separate authorities and existing governance treats them as one, inherited from
> whichever human account the integration runs under. Role-based access was designed around a person
> who has scope and exercises judgment about when to use it. An agent gets the scope and runs the
> loop.

---

## B-12 · Sovereign AI Without a Sovereign Trust Root

**Format** policy-adjacent essay · **Region** GCC + India · **Job** §A §O · **Length** 2,600 words
· **D1 E4 N3 C3 → 17.5**

**Thesis.** Sovereign AI programs keep reaching for national trust infrastructure they do not have
and cannot build quickly; the design rule that unblocked our own identity and anchoring work — build
the strictly weaker mechanism and name what it does not establish — is the same rule that lets a
sovereign program ship this year instead of after a PKI program.

**The falsifiable claim.** Every guarantee a sovereign AI assurance regime actually needs in its
first phase is obtainable without establishing a new national root of trust, and the guarantees that
are not obtainable can be named precisely and deferred deliberately rather than blocking the program.

**Reader and their objection.** Sovereign program leads, national AI authority staff, policy
advisors in GCC and India. Objection: *"Sovereignty means our own root."* Answer: eventually, yes.
The question is what ships before that exists, and the answer is more than people assume.

**Outline.** What sovereign AI programs are trying to guarantee · why the trust-root question stalls
them · the weaker-mechanism rule · what ships in phase one without it · the non-guarantee register as
a policy instrument · the open-source argument — sovereignty is verifiability, not custody.

**Evidence.** `HAVE` — the no-new-trust-root design work and its three subsystem outcomes; the
sovereign-stack RFC (X10); verified GCC/India regional context.

**Figures.** (1) Phase-one guarantees vs. deferred guarantees. (2) The non-guarantee register as a
policy artifact.

**Prerequisites.** T-05 — this is its policy translation and should not precede it.

**What would make it wrong.** A program whose first-phase requirement genuinely needs a national
root. Name that case rather than assuming it away.

**Risk flags.** Sovereignty is politically loaded. Argue mechanism, never geopolitics. Per doctrine,
frame open source multi-regionally — India, GCC, US, Canada — and never let India be the only pillar.

**Drafted opening.**
> Sovereign AI programs stall in a predictable place. The architecture holds up until someone asks
> who signs, and then the answer requires national trust infrastructure that either does not exist
> yet or is three years and a procurement away.
>
> We hit the same wall on a much smaller scale, three times in one month, in three subsystems that
> turned out to be one problem. Each design had quietly assumed we would become a root of trust, and
> each stalled the moment it had to justify that.
>
> The rule that unblocked all three transfers directly. Refuse the root. Build the strictly weaker
> mechanism — the one that needs no new authority — and then write down, in the specification itself,
> exactly what it does not establish. That last part is not a disclaimer. For a sovereign program it
> is the most useful policy artifact in the document, because it says precisely what phase two is for.

---

## B-13 · The 90-Day Readiness Sequence

**Format** implementation guide · **Region** global · **Job** §C · **Length** 2,800 words
· **D1 E4 N3 C5 → 20.5**

**Thesis.** Given the window between now and whatever the supervisors eventually specify, there is a
defensible ninety-day sequence that produces evidence rather than documentation — and the order
matters more than the content, because each step makes the next one cheap.

**The falsifiable claim.** The sequence is dependency-ordered: perimeter definition before
instrumentation, instrumentation before drills, drills before dashboards, and inverting any pair
produces work that has to be redone.

**Reader and their objection.** CISOs and program leads who have to start something on Monday.
Objection: *"Ninety-day plans are consultant theater."* Answer: this one is falsifiable — it states
which step each later step depends on, and you can check whether the dependency is real.

**Outline.** What the window is and why it closes · days 1–30: perimeter · days 31–60:
instrumentation and evidence · days 61–90: drills and the honest number · what deliberately is not in
the first ninety days · what to show an examiner at the end of it.

**Evidence.** `HAVE` — the perimeter, containment and receipt frames from B-03, B-04, T-10; the
supervisory window from B-01/B-02.

**Figures.** (1) The sequence as a dependency graph, not a Gantt chart. (2) End-state evidence pack.

**Prerequisites.** B-01, B-03, B-04.

**What would make it wrong.** If organizations that invert the order succeed anyway, the dependency
claim is false. It is falsifiable on purpose.

**Risk flags.** The obvious commercial piece in the track. It earns its place only if it is genuinely
executable without us — that is the test.

**Drafted opening.**
> Every institution I talk to about agent governance is waiting for the same thing: someone to say
> what adequate looks like. Nobody is going to, for a while. The April guidance took generative and
> agentic systems out of scope, the request for information that would start specifying them has not
> been published, and the guidance that follows it will be written against whatever the industry has
> built by then.
>
> So the useful question is not what will be required. It is what is worth building in the window,
> and in what order.
>
> The order is the part people get wrong. Instrumentation before you have defined a perimeter
> produces telemetry about nothing in particular. Dashboards before drills produce a green screen
> nobody has tested. This sequence is dependency-ordered, and I have written down which step each
> later step depends on so you can check whether I am right.

---

## B-15 · CBUAE — The Binding Layer the Gulf Actually Has

**Format** regional sector brief · **Region** GCC (UAE) · **Job** §C · **Length** 2,000 words
· **D1 E2 N3 C4 → 14.5**

**Thesis.** The Gulf's AI-specific instruments are voluntary; its **central-bank supervision is
not** — so for a UAE financial institution the operative constraint on agent deployment comes from
CBUAE and DIFC Regulation 10, not from the AI Charter or any national strategy.

**The falsifiable claim.** For a UAE-regulated financial institution, the enforceable obligations
touching an agentic deployment derive from banking supervision, data protection law and DIFC
Regulation 10 — and I can list which artifacts each demands, none of which is produced by
compliance with the voluntary AI frameworks.

**Reader and their objection.** UAE bank CROs/CISOs, DIFC-based institutions, regional integrators.
Objection: *"AI regulation hasn't arrived here."* Answer: AI-*specific* regulation hasn't. Banking
supervision has been here the whole time, and it does not care what produced the decision.

**Outline.** The voluntary layer and why it misleads · what CBUAE supervision actually reaches ·
DIFC Regulation 10, fully enforced since January 2026 · the new Federal Authority for AI and Data
and what it may become · the artifact list · what changes when a horizontal statute lands.

**Evidence.** ⚠️ `VERIFY` — **this piece is entirely blocked on verification.** CBUAE's current
position on AI/model governance is named in the `vj-substack` skill but is not in the verified
anchors and I have not confirmed it. Do not draft before it is.

**Figures.** (1) Voluntary vs. binding, by instrument, for a UAE financial institution.
(2) Artifact demanded × supervisory source.

**Prerequisites.** B-06 (the regional map this sharpens).

**What would make it wrong.** CBUAE issuing AI-specific guidance, which would move it from the
binding-by-implication column to the explicit one — strengthening the piece but changing it.

**Risk flags.** Regional regulatory writing ages fast. Every instrument dated and linked; nothing
from memory.

**Drafted opening.**
> Ask what regulates AI in the UAE and you get the Charter, the National Strategy, maybe the new
> Federal Authority. All real, none of them binding on a bank in the way the question implies.
>
> Ask instead what a UAE bank's supervisor can already require of a system that makes decisions
> about customers, and the answer is considerably older than any of it.

---

## B-16 · NAIC — The Vertical the Banking Guidance Never Touched

**Format** sector brief · **Region** US/NA · **Job** §C · **Length** 2,000 words
· **D1 E2 N2 C4 → 13.0**

**Thesis.** The April 2026 banking guidance and its agentic exclusion govern banks. **Insurance is a
separate regime with its own AI model bulletin lineage and its own state-level supervisors** — and
an insurer reading the banking headlines is reading about someone else's regulator.

**The falsifiable claim.** US insurance AI supervision derives from a different instrument set than
OCC 2026-13, applies through state adoption rather than federal issuance, and did not exclude
agentic systems — so an insurer's obligations diverge from a bank's in ways that are specific and
listable.

**Reader and their objection.** Insurance CROs, chief actuaries, compliance leads. Objection: *"The
model bulletin already covers our AI."* Answer: check whether it reaches action authority as opposed
to model output, which is the distinction B-03 draws and the one agents break.

**Outline.** Why the banking guidance is not your guidance · the NAIC instrument set and how state
adoption works · what it says about AI systems · where agents fall outside it · the divergence
table · what to build.

**Evidence.** ⚠️ `VERIFY` — **entirely blocked.** NAIC's current AI instruments and their adoption
state are named in `vj-substack` but unverified here. State-by-state adoption must be checked, not
assumed.

**Figures.** (1) Banking vs. insurance: instrument, issuer, adoption mechanism, agentic treatment.
(2) State adoption map, if the data supports one.

**Prerequisites.** B-01 (the banking contrast this depends on).

**What would make it wrong.** NAIC having already addressed agentic systems explicitly, which would
make this a mapping rather than a gap analysis.

**Risk flags.** State-level variation is the trap. Do not generalize across states without checking,
and do not present a national picture that does not exist.

**Drafted opening.**
> Every insurer I have spoken to since April has read about the model risk guidance, and about half
> of them think it applies to them.
>
> It does not. That guidance was issued by the banking agencies to the institutions they supervise.
> Insurance is regulated by the states, through a different instrument set, on a different adoption
> mechanism — and notably, one that did not carve agentic systems out.

