# Track 1 — Technical Catalog

> **13 pieces** (T-02 merged into T-12 on 2026-08-30). For engineers, architects, security
> researchers and program committees.
> Voice: Vikram, first person, throughout. US English. Every external citation traces to
> [`04-verified-anchors.md`](04-verified-anchors.md). Every entry is dispositioned against
> [`00-inventory-and-gaps.md`](00-inventory-and-gaps.md).

## How to read an entry

Each piece carries a **priority score** on four axes, because you asked for hybrid sequencing and
burst-mode capacity — you need to know what to write when a window opens, not what week it is.

| Axis | Question | 5 means |
|---|---|---|
| **D — Deadline** | Is there an external date I cannot move? | Hard date inside 90 days |
| **E — Evidence** | Does the evidence exist right now? | Fully in hand, no new runs |
| **N — Narrative** | Does the rest of the argument depend on this? | Nothing downstream works without it |
| **C — Commercial** | Does this open enterprise conversations? | Directly usable in outreach this week |

**Priority = D×2 + E×1.5 + N×1.5 + C×1** — deadlines and readiness weighted hardest, because in
burst mode the enemy is starting something you cannot finish.

**Evidence status tags:** `HAVE` (in the repo now) · `NEEDS RUN` (a measurement you must take)
· `VERIFY` (external fact not yet cleared).

---

## The ranked slate

| # | Piece | Format | Disp. | D | E | N | C | **Pri** |
|---|---|---|---|---|---|---|---|---|
| T-03 | Measuring guard models | Empirical paper | NEW | 5 | 4 | 4 | 3 | **31.0** |
| T-01 | The mediation ceiling | Position + blog | NEW | 2 | 5 | 5 | 4 | **29.0** |
| T-07 | NSA advisory as an engineering spec | Whitepaper | NEW | 3 | 5 | 3 | 5 | **28.5** |
| T-08 | SP 800-53 agent control overlay | Standards draft | NEW | 4 | 3 | 3 | 4 | **28.0** |
| T-06 | What MCP 2026-07-28 changes | Blog | REFRAME | 4 | 4 | 2 | 3 | **26.0** |
| T-05 | The non-guarantee register (was: no new trust root) | Method note + essay | RE-SCOPED | 1 | 5 | 4 | 3 | **24.5** |
| **T-12** | ⭐ **SoK: authority and containment** (absorbs T-02) | SoK paper | NEW | 2 | 3 | 5 | 3 | **23.5** |
| T-09 | The kill switch that passed CI | Engineering blog | NEW | 1 | 5 | 2 | 4 | **21.5** |
| T-11 | What each layer actually enforces | Differentiation | NEW | 1 | 3 | 3 | 5 | **20.5** |
| T-10 | Receipts as supervisory evidence | Whitepaper | REFRAME | 2 | 4 | 2 | 4 | **20.0** |
| T-14 | Reproducibility package | Artifact + note | NEW | 3 | 3 | 2 | 1 | **19.5** |
| T-13 | The verification claim audit | Blog + artifact | NEW | 1 | 4 | 3 | 2 | **17.5** |
| T-04 | Negative results in guard tuning | Short paper | NEW | 2 | 4 | 2 | 2 | **17.0** |

**If you only get one burst:** T-03 and T-01. T-03 because 17 November is the only hard academic
date in the window and it needs the most lead time; T-01 because everything else in the catalog
either depends on that honesty or is undermined by its absence.

---

## T-01 · The Mediation Ceiling

**Format** long-form essay + companion position note · **Disposition** NEW · **Venue** Substack
lead, LinkedIn abridged, repo canonical · **Length** 2,800–3,500 words · **D2 E5 N5 C4 → 29.0**

**Thesis.** Full mediation of a terminal coding agent is not achievable through MCP, and any product
claiming it is either redefining mediation or has not looked hard enough — so the honest claim is
narrower, and the narrow claim is the one worth building on.

**The falsifiable claim.** An MCP-based supervisor cannot observe or gate agent actions that do not
traverse the MCP transport — direct shell execution, filesystem writes outside declared paths, and
any tool the agent invokes natively. Therefore mediation coverage is a property of the *deployment*,
not of the supervisor, and must be stated as a measured percentage of an enumerated action surface.

**Reader and their objection.** A staff security engineer evaluating agent controls. Their objection:
*"Then your product doesn't do what the category says it does."* The answer is that no product in
the category does, the ceiling is structural, and the value is in bounding and evidencing what is
mediated rather than in pretending the gap is closed.

**Outline.**
1. The claim I stopped making, and the week I stopped making it
2. Why the ceiling is structural — transport, not implementation
3. The enumerated action surface: what a coding agent can actually do
4. Measuring coverage instead of asserting it
5. What composition buys you — and what it still doesn't (forward-reference the tier blog / T-12)
6. The claim I make now, stated precisely enough to be attacked

**Evidence.** `HAVE` — Warrantor MCP bridge and proxy handler implementation; the enumerated action
surface from the RFC set; dogfood run findings. `NEEDS RUN` — a coverage measurement on one real
`claude -p --permission-mode acceptEdits` session, expressed as mediated/total actions. That single
number is what makes this piece land.

**Figures.** (1) Action-surface diagram: what crosses MCP vs. what does not, drawn to scale by
frequency. (2) A real session trace with mediated and unmediated actions marked.

**Prerequisites.** None. This is the root of the technical narrative.

**What would make it wrong.** A transport-level interception point that catches native tool use
without kernel or OS mediation. If someone demonstrates one, the piece is obsolete and I should say
so publicly.

**Risk flags.** Reads as an admission of product weakness if the framing slips. It is not — it is
the precondition for every enforceable claim that follows. Do not soften it; softening it is the
failure mode.

**Drafted opening.**
> For about six weeks I described what we were building as a mediation layer for coding agents. It
> was the natural word. It was also wrong, and the way I found out was not an argument — it was a
> session log.
>
> We had wired the supervisor through MCP. Every tool call the agent made through the protocol
> arrived at our handler, got checked against a warrant, and produced a receipt. The loop worked
> end to end. Then I read the log next to the agent's own transcript and counted the actions that
> never appeared on our side at all.
>
> The gap is not a bug in our implementation. It is a property of where MCP sits. An agent with a
> shell does not need the protocol's permission to use the shell, and a supervisor that only sees
> the protocol only sees the actions that chose to be seen. That is the ceiling. Everything I now
> claim about containment is stated underneath it.

---

## T-02 · Three Kinds of "Enforced" — ⛔ MERGED INTO T-12

**Status: retired as a standalone paper, 2026-08-30.**

`arXiv 2606.28690` (AgentThread) formalizes agent-protocol composition in TLA+, with 35
specification-level findings across five protocols and 80 implementation tests against production
SDKs. The observation that composition is under-specified is now established prior art, and a
standalone paper restating it would be desk-rejected on novelty.

**What survives, and where it goes.** The **enforcement-tier axis** — that cryptographic, OS and
proxy bounds carry different adversary classes, and that a composed system inherits the weakest
*reachable* tier — is orthogonal to protocol conformance and remains a genuine contribution. It
becomes **axis 1 of T-12**, which is promoted to flagship as a result.

**What still ships early, and soon.** A standalone practitioner blog on the three tiers, without the
formal apparatus. The taxonomy is immediately useful to engineers and does not need peer review to
be worth publishing, and it carries the self-correction of papers 13 and 14 — which is the
credibility move and does not belong buried in a SoK. Ships under **Agentic Attack Surface**;
~1,600 words; evidence fully in hand.

**The open question it hands to T-12.** WASM isolation (`arXiv 2601.01241`) is neither an OS nor a
proxy bound. Whether it constitutes a genuine Tier 2 guarantee is unresolved, and the taxonomy is
incomplete until the SoK answers it.

## T-03 · Measuring Guard Models — Adversarial Phrasing, Vertical Specialization, and Context Length

**Format** empirical research paper · **Disposition** NEW (the flagship) · **Venue** **IEEE S&P 2027
Cycle 2 — abstract ~10 Nov 2026, full 17 Nov 2026**; arXiv preprint on submission; repo artifact
· **Length** 12 pages + appendix · **D5 E4 N4 C3 → 31.0**

**Thesis.** Three findings from our guard-model program contradict prevailing practice: vertical
specialization does not improve guard performance (the apparent gain is a category artifact),
adversarial phrasing quadruples false-positive rate, and context length is a silent confound that
makes published guard comparisons non-reproducible unless pinned.

**The falsifiable claim.** (a) A guard fine-tuned on vertical-specific data shows no significant
improvement over a general guard once category distribution is controlled; (b) semantically
equivalent adversarial rephrasing raises FPR by approximately 4×; (c) guard decisions are sensitive
to `num_ctx` such that unpinned evaluations are not comparable across runs.

**Reader and their objection.** Program committee and applied-safety researchers. Objection:
*"Single-lab results on models you trained yourself."* Answer: release the harness, the dataset
manifest, and the Model BOM; report the negative results alongside; pin every environment. The
artifact is the argument.

**Outline.**
1. Introduction — three claims, three experiments
2. Setup: models, the WildGuardMix/ExpGuardMix corpora, pinned environments
3. Experiment 1 — vertical vs. general guards; the category-artifact analysis
4. Experiment 2 — adversarial rephrasing protocol and FPR measurement
5. Experiment 3 — context-length sensitivity; the `num_ctx=8192` pin
6. Threats to validity, stated at length
7. Artifact and reproduction instructions
8. What this means for anyone shipping a guard in production

**Evidence.** `HAVE` — `ml/benchmark_wildguard.py`, `ml/benchmark_expguard.py`,
`ml/run_corpus_benchmarks.py`, `ml/kaggle/train_guard_lora.py`, `ml/modal/train_guard_0_6b_weak.py`,
the recorded findings on category artifact and the 4.12× adversarial-slice FPR gap. ⚠️ **`num_ctx` pinning is NOT a finding** — it is a deployment decision and a config-divergence incident, with no sensitivity sweep behind it. Listing it as evidence is how an unmeasured claim reaches an abstract, and the 4B-vs-0.6B result.
`NEEDS RUN` — a clean, pinned, seed-controlled re-run of all three experiments with confidence
intervals, on the pinned environment, so nothing in the paper rests on an exploratory run.

**Figures.** (1) Vertical vs. general guard, per-category, with the artifact isolated. (2) FPR under
neutral vs. adversarial phrasing, with example pairs. (3) Decision sensitivity as a function of
`num_ctx`. (4) The pinned-environment and provenance chain (dataset manifest → Model BOM → result).

**Prerequisites.** T-14 (the artifact) must ship with it. T-04 (negative results) is the companion.

**What would make it wrong.** If the category artifact disappears under a different corpus split,
finding (a) collapses. Pre-register the split and report both.

**Risk flags.** **Deadline risk is the dominant risk.** 79 days, and the clean re-runs are the long
pole. Budget compute early — Kaggle first, Modal for anything over 16 GB VRAM, and stay inside the
$100 cap.

**Drafted opening (abstract).**
> Guard models — small classifiers that screen agent inputs and outputs for unsafe content — are
> increasingly deployed as the primary runtime control in agentic systems. We report three findings
> from a controlled evaluation program that contradict common practice. First, fine-tuning a guard
> on vertical-specific data yields no significant improvement over a general-purpose guard once
> category distribution is controlled; the apparent vertical gain is an artifact of category
> imbalance rather than domain knowledge. Second, semantically equivalent adversarial rephrasing of
> benign inputs raises false-positive rate by approximately fourfold, a fragility that standard
> benchmarks do not surface. Third, guard decisions are materially sensitive to context-window
> configuration, making published comparisons non-reproducible unless the parameter is pinned. We
> release the evaluation harness, dataset manifests and model bills of materials, and we report our
> rejected training runs alongside the accepted ones.

---

## T-04 · Negative Results in Guard Fine-Tuning

**Format** short paper / workshop submission · **Disposition** NEW · **Venue** NeurIPS-adjacent or
USENIX Security '27 Cycle 2 companion; arXiv · **Length** 4–6 pages · **D2 E4 N2 C2 → 17.0**

**Thesis.** Masking a field's loss during LoRA fine-tuning does not isolate that field, because the
adapter shares weights across all fields — a result we obtained by rejecting two consecutive
training runs, and one that is not, as far as I can find, written down anywhere.

**The falsifiable claim.** Under LoRA, zeroing the loss contribution of field *F* does not prevent
the adapter from altering *F*'s behavior, because the low-rank update is shared. Measured effect
sizes on the rejected runs demonstrate the leakage.

**Reader and their objection.** Practitioners fine-tuning structured-output models. Objection:
*"This is obvious from the method."* Answer: it is obvious in retrospect and it is nonetheless a
mistake we made deliberately, twice, with a reasonable-looking hypothesis — and negative results
that cost real compute are worth the page count.

**Outline.** Setup and hypothesis · run 1 and why it was rejected · run 2, the masking attempt, and
why it was also rejected · the weight-sharing explanation · what actually works (separate adapters,
or accept the coupling) · the 4B-vs-0.6B vertical-content result as a secondary finding.

**Evidence.** `HAVE` — both rejected runs, the masking configuration, the 4B/0.6B comparison.
`NEEDS RUN` — effect-size measurement on the leaked field, to turn "it didn't work" into a number.

**Figures.** (1) Loss-masking configuration vs. observed field drift. (2) 4B vs. 0.6B on vertical
content, with the null result on general content beside it.

**Prerequisites.** T-03 (shares the experimental infrastructure).

**What would make it wrong.** A rank/target-module configuration under which masking *does* isolate.
Test at least two configurations before claiming generality.

**Risk flags.** Low. Negative-results papers are cheap credibility if they are precise and expensive
embarrassment if they are vague.

**Drafted opening.**
> We rejected two training runs in a row on the same hypothesis, and the second rejection is the
> interesting one. The plan was ordinary: a structured-output guard where one field was
> underperforming, so mask that field's loss contribution and study the rest in isolation. The
> masking was implemented correctly. The field moved anyway.
>
> The reason is not subtle once you say it out loud — a LoRA adapter is a shared low-rank update, so
> there is no "the rest" to isolate. Every field rides the same weights. Masking a loss term removes
> a gradient signal; it does not build a wall.
>
> I am writing this up because it cost us two runs and a week, the explanation is one sentence, and
> I could not find that sentence written down anywhere I looked.

---

## T-05 · The Non-Guarantee Register

**Format** method note + essay · **Disposition** NEW, **re-scoped 2026-08-30** · **Venue** repo +
arXiv + Substack (Sovereign Stack) · **Length** 3,000–4,000 words · **D1 E5 N4 C3 → 24.5**

> **Why re-scoped.** The original framing claimed a design principle — "refuse to become a root of
> trust" — as novel. It is not: that is federation and delegation discipline, and claiming otherwise
> in a paper about honest claim-making would be self-refuting. **The contribution is the artifact,
> not the architecture.**

**Thesis.** A specification should carry a **non-guarantee register** — a required, structured
statement of what each mechanism explicitly does *not* establish — and adopting that discipline
unblocked three subsystems that had each stalled on the same unstated assumption.

**The falsifiable claim.** For identity, anchoring and directory, a register can be written that
(a) names a useful guarantee obtainable without a new trust root, and (b) names the non-guarantees
precisely enough that a deploying organization can tell which of its existing trust infrastructure
must supply them. If a register cannot be written for a mechanism, the mechanism is under-specified.

**Reader and their objection.** Architects and standards participants. Objection: *"This is
delegation, renamed."* Answer, stated in the piece itself: **yes, largely.** The architecture is
familiar; what is missing from practice is the *register as a required specification artifact*.
Naming a non-guarantee is cheap, almost nobody does it, and the three subsystems that stalled here
stalled precisely because nobody had.

**Outline.** Three subsystems, one unstated assumption · what a register is, formally · worked
register for identity · for anchoring · for directory · why the discipline is the contribution and
the architecture is not · adoption as the real argument.

**Evidence.** `HAVE` — the identity implementation and E2E audit trail,
`docs/cross-cutting/22-did-web-identity.md`, the anchoring and directory designs, and the decision
record itself.

**Figures.** (1) Three subsystems, blocked-on-what → shipped-with-what. (2) The register, worked:
claim / mechanism / explicitly-not-established. Designed to be lifted into other people's specs.

**Prerequisites.** None. Feeds T-10 and B-12, both of which use the register directly.

**What would make it wrong.** A deployment where the named non-guarantees are exactly what the
customer needed and could not supply — that would mean the discipline is right and the product
under-scoped, a distinction worth making rather than hiding.

**Risk flags.** Reads as modest, and more so after re-scoping. That is correct. **Do not re-inflate
the novelty claim in the LinkedIn cut** — doing so in this particular piece would be a visible
contradiction of its own argument.

**Drafted opening.**
> For most of a month, three subsystems were stuck, and I kept treating them as three problems.
> Agent identity would not converge. Evidence anchoring had no defensible story. The trust directory
> raised an objection I could not answer — who are we to say which agents are trustworthy?
>
> They were one problem. Each design had quietly assumed we would become a root of trust, and each
> stalled at the moment it had to justify that.
>
> I want to be careful about what I am claiming, because the fix is not novel. Building the weaker
> mechanism and leaning on someone else's trust is federation, and people have been doing it for
> decades. What was missing was smaller and stranger: nowhere in any of our specifications was there
> a place to write down what a mechanism *does not* establish.
>
> So we added one. A non-guarantee register, per mechanism, required. It cost almost nothing, and
> all three subsystems shipped within a fortnight of it existing.

## T-06 · What MCP 2026-07-28 Changes for Agent Delegation

**Format** technical blog · **Disposition** **REFRAME of `blog-series/07`** · **Venue** repo blog
series + Substack + LinkedIn · **Length** 2,000–2,500 words · **D4 E4 N2 C3 → 26.0**

**Thesis.** The 2026-07-28 revision — stateless core, authorization hardening, Enterprise-Managed
Authorization moved to production-grade — changes what a delegation layer must implement, and the
previous version of this article rests on assumptions the specification no longer makes.

**The falsifiable claim.** A stateless protocol core removes the server-held session state that
several delegation designs (including our earlier one) implicitly relied on for continuity of
authority; therefore authority continuity must be carried in the request, which is what EMA reaching
production-grade now enables.

**Reader and their objection.** Engineers building on MCP. Objection: *"Every spec update gets a
blog post."* Answer: this one changes an architectural assumption, and I am publishing it as a
correction to my own earlier article rather than as news.

**Outline.** What changed, precisely · why stateless breaks the implicit-session delegation pattern
· EMA production-grade and what it now carries · token audience binding and confused-deputy in an
agent context · the correction to article 07 · migration notes.

**Evidence.** `HAVE` — verified spec details in [`04-verified-anchors.md`](04-verified-anchors.md)
§B1; the existing bridge implementation. `NEEDS RUN` — confirm our bridge against the 2026-07-28
SDKs and report what broke.

**Figures.** (1) Delegation under stateful vs. stateless core. (2) A diff table: article 07 claim →
current spec reality → corrected claim.

**Prerequisites.** T-01 (the mediation ceiling bounds what any of this buys).

**What would make it wrong.** If our bridge migrates with no behavioral change, the piece shrinks to
a note — still publish, but honestly, as "less changed than I expected."

**Risk flags.** Time-sensitive; value decays as the ecosystem absorbs the release. Write it inside
the first burst or drop it.

**Drafted opening.**
> I wrote an article about MCP delegation earlier this year that no longer describes the protocol.
> The 2026-07-28 revision is the largest since launch, and the part that matters for delegation is
> not on the headline list: the core went stateless.
>
> That sounds like a scaling change. It is an authority change. A stateful server can hold what an
> agent was permitted to do across a sequence of calls; a stateless one cannot, so continuity of
> authority has to travel in the request itself. Every delegation design that leaned on an implicit
> session — mine included — now has to carry its authority explicitly or lose it between calls.
>
> Enterprise-Managed Authorization moving from experimental to production-grade in the same release
> is not a coincidence. Here is what actually changed, and what I got wrong.

---

## T-07 · Reading the NSA MCP Advisory as an Engineering Specification

**Format** technical whitepaper · **Disposition** NEW · **Venue** repo canonical + vikramjha.work +
Substack + LinkedIn; the highest-value outreach asset in the track · **Length** 4,000–5,000 words
· **D3 E5 N3 C5 → 28.5**

**Thesis.** The NSA's May 2026 MCP Cybersecurity Information Sheet reads as a threat description,
but every risk it names maps to a specific, buildable control — and I can show the mapping, control
by control, including where we have not built the control ourselves.

**The falsifiable claim.** Each named risk in the CSI — uncontrolled automated actions, absent input
screening, serialization risk, trust-boundary erosion, agent misuse — has an implementable control
with a stated enforcement tier (per T-02), and the honest coverage table includes gaps.

**Reader and their objection.** US enterprise security architects and their CISOs — the people who
need a citation to open a budget line. Objection: *"This is a vendor reading a government document
to sell me something."* Answer: publish the gaps in the same table as the coverage. A mapping that
scores itself 100% is marketing; one that names its own holes is engineering.

**Outline.**
1. Why a signals-intelligence agency wrote about a tool protocol
2. The five risk classes, in the CSI's own terms
3. Risk → control → enforcement tier, one section each
4. The coverage table, gaps included
5. What a 30-day hardening sequence looks like for a team already on MCP
6. What the CSI does not say — and why the omissions are informative

**Evidence.** `HAVE` — the CSI itself (verified, §A2); the full RFC set for control mapping; T-02's
tier taxonomy. Nothing new required.

**Figures.** (1) Risk-to-control matrix with enforcement tier per cell and gaps shaded. (2) The
30-day sequence as a dependency graph.

**Prerequisites.** T-02 (tiers), T-01 (ceiling — several controls are bounded by it).

**What would make it wrong.** Mischaracterizing the CSI. Quote it precisely, link the primary
document, and never paraphrase a normative statement into a stronger one.

**Risk flags.** Do not imply endorsement by any agency. Cite the record, describe the defect class,
never characterize an organization — the same discipline that governs vendor naming.

**Drafted opening.**
> In May, the NSA published a Cybersecurity Information Sheet about a tool-calling protocol. That is
> a strange sentence, and it is the most useful thing that happened to this field all year.
>
> The document says that gaps in MCP's design, implementation and operational posture have created
> significant and evolving security concerns. It names uncontrolled automated actions — an AI system
> independently deciding to use a new tool — and the absence of input screening as data crosses
> system boundaries. It calls dynamic tool invocation, implicit trust relationships and context
> sharing systemic, not incidental.
>
> Read as a warning, it changes nothing you did not already suspect. Read as a specification, it is
> a list of controls somebody has to build. This is my attempt at that mapping, risk by risk,
> including the four rows where our own coverage is honestly incomplete.

---

## T-08 · An SP 800-53 Control Overlay for Single- and Multi-Agent Systems

**Format** standards draft / whitepaper · **Disposition** NEW · **Venue** **standards channel** —
NIST COSAiS contribution, CSA working group, published in repo · **Length** overlay document + 3,000
word rationale · **D4 E3 N3 C4 → 28.0**

**Thesis.** NIST's agent control overlays are in active development with no publication date, NIST
CAISI has already concluded existing SP 800-53 controls are insufficient for the orchestration loop,
tool-use chains and memory persistence — so a credible mapped overlay published now enters an open
docket with no incumbent.

**The falsifiable claim.** The three threat categories organizing the emerging framework —
adversarial data interaction, model compromise, misaligned objectives — can be covered by a defined
set of SP 800-53 control enhancements plus a small number of genuinely new controls, and I can name
which are which.

**Reader and their objection.** NIST reviewers, federal integrators, CSA working-group members,
and any US enterprise mapping agents onto an existing control framework. Objection: *"Who are you to
write an overlay?"* Answer: nobody is, yet — the point of a public draft is to be improved, and it
carries an explicit invitation to be shredded.

**Outline.** The gap NIST itself names · overlay scope and the single/multi-agent split · control
family walkthrough (AC, AU, CM, SI, SC) with agent-specific enhancements · the controls that do not
exist yet · mapping to the tier taxonomy · how to comment.

**Evidence.** `HAVE` — RFC set, threat model (`cross-cutting/21`), tier taxonomy from T-02.
`VERIFY` — COSAiS concept paper current text; CSA working-group contribution route; whether a public
comment period is open.

**Figures.** (1) Control family × agent capability coverage grid. (2) The new-controls-needed list
with rationale per entry.

**Prerequisites.** T-02, T-07.

**What would make it wrong.** NIST publishing first with a materially different structure. Mitigate
by framing as a contribution rather than a competitor, and by dating it explicitly.

**Risk flags.** Never imply this is a NIST product. Title, header and first line must all say it is
an independent draft contribution.

**Drafted opening.**
> NIST has said the quiet part in its own analysis: existing SP 800-53 controls do not cover the
> orchestration loop, tool-use chains and memory persistence that make agentic systems different.
> Two overlays are in development for exactly this — single-agent and multi-agent — and as of the
> last public update they have no publication date.
>
> That leaves every organization deploying agents against a federal control baseline doing the
> mapping privately, badly, and in isolation. This document is a public draft of that mapping. It
> covers the control families that need agent-specific enhancements, it identifies the small number
> of controls that do not exist in any family today, and it is deliberately specific enough to be
> wrong in ways you can point at.

---

## T-09 · The Kill Switch That Passed CI

**Format** engineering blog / incident write-up · **Disposition** NEW · **Venue** repo + Substack +
LinkedIn · **Length** 1,800–2,200 words · **D1 E5 N2 C4 → 21.5**

**Thesis.** Our workspace CI ran every test on every crate — on Ubuntu only — so every
`#[cfg(windows)]` path in the codebase was untested, and that gap concealed a real contract breach in
the kill switch, which is the one component whose correctness is the whole argument.

**The falsifiable claim.** Platform-gated code paths in a cross-platform Rust workspace are
systematically untested when CI runs a single OS, and the standard coverage signal does not reveal
it because coverage is computed on the platform that ran.

**Reader and their objection.** Rust and platform engineers; also anyone auditing our claims.
Objection: *"That's a CI misconfiguration, not a finding."* Answer: correct, and it is the class of
misconfiguration that makes a security claim false while every dashboard stays green — which is the
point.

**Outline.** What the kill switch promises · the Windows-only path and why it existed · how the
breach survived a full green workspace run · what coverage did and did not show · the fix, and the
matrix change · the general rule for platform-gated security code.

**Evidence.** `HAVE` — the defect, the fix, the 33 passing kill-switch tests, the CI configuration
before and after, and the duration→elapsed field correction.

**Figures.** (1) The CI matrix before and after, with untested surface shaded. (2) The breach:
contract, Windows path, and the assertion that was never executed.

**Prerequisites.** None. Pairs with T-13.

**What would make it wrong.** Nothing — it happened. The risk is overstating generality; scope the
claim to platform-gated paths under single-OS CI.

**Risk flags.** Publishing a security defect in your own product. Per the naming doctrine this is
the *permitted* kind: it is self-disclosed, it describes the defect and not any person, and the fix
shipped first.

**Drafted opening.**
> The kill switch had 33 passing tests and a green workspace run across every crate. It also had a
> contract breach that none of those tests could have caught, because the code containing it never
> executed in CI.
>
> Our workflow runs the whole Rust workspace, which sounds like thorough coverage and is — on Ubuntu.
> Every `#[cfg(windows)]` block in the repository was compiled by developers on Windows and verified
> by nobody. Coverage did not flag it, because coverage measures the lines that ran on the platform
> that ran them, and those lines were not in the build.
>
> The component this hid a defect in is the one whose correctness is the entire argument. If the
> kill switch does not do what it says on the platform a customer runs, nothing else in the stack
> matters.

---

## T-10 · Action Receipts as Supervisory Evidence

**Format** technical whitepaper · **Disposition** **REFRAME of papers 03 and 22** — re-anchored from
EU to US/India/GCC · **Venue** repo + vikramjha.work + regulator channels · **Length** 5,000 words
· **D2 E4 N2 C4 → 20.0**

**Thesis.** A tamper-evident action receipt is the artifact that answers the question every one of
the live supervisory regimes actually asks — *who authorized this, on what basis, and can you show
me* — and the regimes to anchor on are OCC 2026-13 / SR 26-2, the RBI June 2026 draft, and SDAIA's
accountability pillar, not the EU AI Act.

**The falsifiable claim.** For each of the three regimes, there is a specific evidentiary demand
that a receipt satisfies and that conventional application logging does not — because logs are
mutable by the party being examined and receipts are not.

**Reader and their objection.** Technical staff in regulated institutions and their examiners.
Objection: *"Our audit logs already do this."* Answer: the distinguishing property is not
completeness, it is that the examined party cannot alter them undetectably — that is the whole
delta, and it is a cryptographic property, not an operational one.

**Outline.** The evidentiary question, in each regime's own words · what a receipt binds (and per
T-05, what it does not) · logs vs. receipts: the mutability delta · retention, jurisdiction and
localization (India localization, GCC data residency) · what an examiner should ask to see · a
minimum receipt schema.

**Evidence.** `HAVE` — the AAR implementation and OSAF standard draft (papers 03, 22), the archive
crate and retention policy, the anchoring design, the E2E identity audit trail. `VERIFY` — CERT-In
retention directions for agent telemetry.

**Figures.** (1) Evidentiary demand per regime → receipt field that answers it. (2) Log vs. receipt
trust model. (3) Minimum schema.

**Prerequisites.** T-05 (non-guarantees must be stated), T-02 (tiering the anchoring guarantee).

**What would make it wrong.** If examiners in practice accept mutable logs without challenge, the
commercial argument weakens even though the technical one holds. Say so; do not assume the
regulatory posture you want.

**Risk flags.** Regulatory over-claim is the failure mode. Nothing in the live regimes *requires*
receipts today. State that plainly and argue from the direction of travel and the RFI.

**Drafted opening.**
> Every supervisory regime now looking at autonomous systems converges on one question, phrased
> three ways: who authorized this action, on what basis, and can you show me?
>
> The instinctive answer is the audit log. The problem with the audit log is structural rather than
> technical — it is maintained by the party being examined, and it can be edited by that party
> without leaving a trace that survives the party's own tooling. Nobody in a bank believes their
> colleagues are falsifying logs. That is not the standard. The standard is whether the evidence
> would still mean something if someone had.
>
> A tamper-evident action receipt answers that, and it answers less than people assume, which is why
> this paper spends as much space on what a receipt does not prove as on what it does.

---

## T-11 · What Each Layer Actually Enforces

**Format** technical differentiation analysis · **Disposition** NEW · **Venue** repo +
vikramjha.work + LinkedIn · **Length** 3,000–3,500 words · **D1 E3 N3 C5 → 20.5**

**Thesis.** Governance platforms, policy engines and runtime supervisors are routinely compared as
if they were competitors for the same job; they enforce three different objects — organizational
process, request-time authorization decisions, and action-time execution bounds — and a buyer who
treats one as a substitute for another ends up with a gap they cannot see.

**The falsifiable claim.** For a defined agent action, each layer's enforcement point occurs at a
different moment with a different failure mode, and I can construct a concrete action that each
layer independently permits and another layer independently blocks.

**Reader and their objection.** Technical evaluators on a buying committee. Objection: *"This is a
vendor drawing a map with itself at the center."* Answer: the map puts the runtime layer's ceiling
(T-01) and tier limits (T-02) on it too — a comparison that only bounds the competition is
propaganda.

**Outline.** Three objects, three enforcement moments · policy engines: what a request-time
authorization decision covers and what it structurally cannot · governance platforms: process
attestation and its evidentiary weight · runtime supervision: bounded by the ceiling · the worked
example — one action, three verdicts · what a complete stack looks like, including layers we do not
build.

**Evidence.** `VERIFY` — **all** comparative claims must come from the vendors' own published
documentation. Per standing doctrine: name the record, never judge the company; cite the document
alongside every name; describe by class anything not self-disclosed.

**Figures.** (1) The action timeline with each layer's enforcement point marked. (2) The worked
example as a three-column verdict table.

**Prerequisites.** T-01, T-02. This piece is not writable without both.

**What would make it wrong.** If a policy engine in the comparison has shipped runtime action
mediation since I last checked, the boundary moves. Re-verify every product claim within 30 days of
publishing — this is the entry most likely to age badly.

**Risk flags.** **Highest doctrine risk in the track.** Zero characterization of any firm. Cite
published documentation for every factual claim about another product. If a claim cannot be sourced
to the vendor's own material, describe it by class and name nobody.

**Drafted opening.**
> I keep getting asked which of three things we compete with, and the honest answer is that the
> question has a false premise. A governance platform, a policy engine and a runtime supervisor
> enforce three different objects, at three different moments, with three different things going
> wrong when they fail.
>
> A governance platform enforces that your organization followed a process. A policy engine enforces
> an authorization decision at the moment a request is evaluated. A runtime supervisor enforces
> bounds on what an action does while it is executing. Those are not competing answers. They are
> answers to questions asked at different times, and the gap between them is where the incidents
> live.
>
> To make that concrete, I take one agent action and walk it past all three, using each product's own
> published documentation for what it does. Two of the three permit it. The third blocks it for a
> reason the other two are not built to see — and there is a fourth case, at the end, that all three
> miss, including ours.

---

## T-12 · ⭐ SoK: Authority and Containment for Autonomous Coding Agents

**Format** systematization-of-knowledge paper · **Disposition** NEW, **promoted to flagship
2026-08-30 — absorbs T-02** · **Venue** **USENIX Security '27 Cycle 2 — 26 Jan 2027** (outside the
window; the corpus work lands inside) · **Length** 13–15 pages · **D2 E3 N5 C3 → 23.5**

> **Promoted because it now carries the enforcement argument.** With T-02 merged in, the tier
> taxonomy becomes axis 1 of the systematization rather than a separate paper. This is the technical
> track's second sustained campaign alongside T-03, and corpus construction starts in this window.

**Thesis.** The literature on agent authority and containment is fragmented across security,
programming languages and AI safety, uses incompatible threat models, and a systematization
organized by enforcement tier and mediation coverage reveals which published guarantees actually
compose.

**The falsifiable claim.** Classifying the corpus by tier (T-02) and mediation coverage (T-01)
produces a partition in which a specific, nameable set of published guarantees are shown not to
compose with each other.

**Reader and their objection.** The security research community. Objection: *"SoKs need breadth and
neutrality."* Answer: the classification must be applied to our own work first and most harshly, and
every exclusion criterion must be pre-stated.

**Outline.** Scope and method · the corpus and selection criteria · axis 1: enforcement tier · axis
2: mediation coverage · axis 3: evidence model · the composition analysis · what does not compose ·
open problems.

**Evidence.** `HAVE` — the reading list (Track 3) as the corpus seed; the tier and ceiling frames.
`NEEDS RUN` — systematic corpus construction with stated inclusion criteria; this is the long pole
and it is a genuine research effort, not a literature summary.

**Figures.** (1) The three-axis classification with the corpus plotted. (2) The composition matrix.

**Prerequisites.** T-01, T-02, T-05, and Track 3's corpus at canon depth.

**What would make it wrong.** Insufficient corpus breadth. A thin SoK is worse than none.

**Risk flags.** Scope. This is the piece most likely to eat a quarter. Deliberately ranked last;
begin corpus construction inside the window, submit outside it.

**Drafted opening (abstract).**
> Work on constraining autonomous coding agents is spread across three research communities that
> rarely cite each other and do not share a threat model. Systems security contributes sandboxing
> and mediation; programming languages contributes capability discipline and effect systems; AI
> safety contributes behavioral evaluation and guard models. Each produces guarantees that are sound
> internally and frequently incomparable across communities. We systematize this work along three
> axes — the enforcement tier at which a control binds, the fraction of an agent's action surface a
> control mediates, and the evidence model by which a guarantee can be checked after the fact — and
> show that the resulting partition identifies published guarantees that do not compose. We apply
> the classification to our own prior work first, where it invalidates two previously stated claims.

---

## T-13 · The Verification Claim Audit

**Format** engineering blog + published audit artifact · **Disposition** NEW · **Venue** repo +
Substack · **Length** 2,200 words + machine-readable artifact · **D1 E4 N3 C2 → 17.5**

**Thesis.** I audited every verification claim in our own documentation against the test that
supposedly backs it, and the failures cluster in the prose rather than in the code — including one
case where a *correction* introduced a new error by understating.

**The falsifiable claim.** For a documented claim set, the ratio of claims backed by an executing
assertion to claims backed by prose is measurable, and in our case it was worse than the test count
suggested.

**Reader and their objection.** Engineers and anyone auditing us. Objection: *"Why publish your own
audit failures?"* Answer: because the alternative is that someone else publishes them, and because
the claim-to-assertion ratio is a metric the whole field should be reporting.

**Outline.** The method · claim extraction from docs · mapping claims to assertions · the results,
unflattering · the understating correction, as its own case · the `claim-vs-mechanism.json` artifact
· proposing the ratio as a reportable metric.

**Evidence.** `HAVE` — `evidence/claim-vs-mechanism.json`, `evidence/conformance.json`, the recorded
finding that failures cluster in prose, and the understating-correction case.

**Figures.** (1) Claims by backing type. (2) The understating correction, before/after/actual.

**Prerequisites.** T-09 (a concrete instance of the same phenomenon).

**What would make it wrong.** If the ratio is fine and the memory is pessimistic — run the audit
before writing, and report whatever it says.

**Risk flags.** Self-critical in public. Keep it factual; no self-flagellation, no tallying.

**Drafted opening.**
> We keep a file called `claim-vs-mechanism.json`. It exists because I wanted to know, for every
> assertion our documentation makes about what the system guarantees, whether there is an assertion
> in the test suite that would fail if the guarantee broke.
>
> The result was not what the test count implied. The code was mostly fine. The prose was not —
> claims had drifted a little past their mechanism, each drift individually defensible, and the
> aggregate substantially overstated.
>
> The case I find most instructive is a correction that made things worse. I had overstated a
> guarantee, noticed, and corrected it — and the correction understated it in a different direction,
> which is its own kind of false claim and a harder one to catch, because a correction reads as
> already-audited.

---

## T-14 · Reproducibility Package — Guard Benchmark Harness and Provenance Chain

**Format** artifact release + short companion note · **Disposition** NEW · **Venue** repo, Hugging
Face, arXiv artifact appendix · **Length** artifact + 1,500 word note · **D3 E3 N2 C1 → 19.5**

**Thesis.** T-03's claims are only as strong as their reproducibility, so the harness, dataset
manifest, Model BOM and pinned environment ship as a first-class artifact, not an appendix.

**The falsifiable claim.** A third party with the published artifact and access to comparable compute
can reproduce each of T-03's three findings within stated tolerance.

**Reader and their objection.** Artifact-evaluation committees; practitioners who want to re-run
against their own guards. Objection: *"Reproducible on your infrastructure."* Answer: pin the
environment at source, publish the manifest, and test the package on a second machine before release.

**Outline.** What is in the package · pinned environments · dataset manifest and provenance ·
Model BOM · running the three experiments · expected results and tolerances · known
non-determinism.

**Evidence.** `HAVE` — the benchmark scripts, the pinned golden-env script (the floating
torch/CUDA mismatch is already fixed at source), the provenance/Model-BOM discipline. `NEEDS RUN` —
a clean-room reproduction on a machine that is not the development box. That test is the deliverable.

**Figures.** (1) Provenance chain: dataset manifest → training config → Model BOM → result.

**Prerequisites.** T-03 (ships with it; no independent value before it).

**What would make it wrong.** Failing the clean-room reproduction. If it fails, that failure is the
publication, and T-03's claims narrow accordingly.

**Risk flags.** Compute cost — Kaggle first (30h/wk GPU, free), Modal only for anything over 16 GB
VRAM, stay inside the $100 cap. Sovereign-data rule applies: US-cloud tiers get open or synthetic
data only.

**Drafted opening.**
> The three findings in the guard-model paper are worth exactly as much as somebody else's ability
> to check them, so this package exists before the paper does.
>
> It contains the evaluation harness, the dataset manifests with provenance for every corpus, the
> Model BOM for each checkpoint, and pinned environment definitions — pinned at source, because a
> floating torch/CUDA pairing in our golden environment script had already silently changed what
> "the same environment" meant between two runs, and I would rather tell you that than have you find
> it.
>
> The acceptance test for this package is not that it runs here. It is that it runs on a machine
> nobody on this project has touched.
