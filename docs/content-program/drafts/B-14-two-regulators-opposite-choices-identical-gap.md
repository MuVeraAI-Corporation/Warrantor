# Two Regulators, Opposite Choices, Identical Gap

### What the April banking guidance removed, what the June RBI draft required, and the sentence neither of them wrote

**Business whitepaper · Draft 1 · 2026-08-30 · Vikram Jha**
*Catalog ref: B-14 · ~3,900 words · repo canonical + vikramjha.work; Substack flagship cut; two LinkedIn cuts, one per market*

> ⚠️ **Publication blocker.** The Chapter V-B.3 quotation in §4 is drawn from secondary legal
> summaries that agree with one another. It **must** be confirmed against the RBI's own draft PDF
> before this document is published. Misquoting a central bank in front of Indian banking readers is
> not a recoverable error.

> Nothing here is legal advice. Nothing here characterizes any institution's compliance posture.

---

## Contents

1. [Two months, two decisions](#1)
2. [What the US agencies removed](#2)
3. [What the exclusion did not touch](#3)
4. [What the RBI required](#4)
5. [The convergence](#5)
6. [Somebody specified it. Your framework fails it.](#6)
7. [Third-party accountability: the provision that survives certification](#7)
8. [What a bank in both markets should build once](#8)
9. [What the final texts will most likely codify](#9)
10. [The uncomfortable part](#10)
11. [Sources](#11)

---

<a id="1"></a>
## 1. Two months, two decisions

Two months apart this year, the two regulators with the most direct claim on my clients' AI programs
made opposite decisions about the same technology.

On **17 April 2026**, the Federal Reserve, the FDIC and the Office of the Comptroller of the
Currency replaced the model risk management guidance the US industry had been building against since
2011, and wrote generative and agentic AI **out** of scope. The stated reason: these models are
novel and rapidly evolving. Separate guidance is promised.

On **24 June 2026**, the Reserve Bank of India published its *Draft Guidance on Regulatory Principles
for Model Risk Management, 2026*, which writes artificial intelligence and machine learning **in** —
across eleven categories of regulated entity — and requires, under human oversight, override,
suspension and deactivation mechanisms **including kill-switch arrangements for AI models**.

One regulator deferred. The other mandated.

If you operate in both markets, the natural reading is that you now have two different problems, and
that the sensible response is two different programs on two different timelines.

You have one problem. The RBI requires a kill switch and does not say what one is. The US agencies
withdrew the framework that would have said. Both documents leave the same sentence unwritten.

**And then, three weeks after the RBI draft, somebody else wrote it.** Not a regulator — an
independent researcher, in a paper that specifies stop semantics as four safety clauses, proves them
mechanically, and then measures whether the agent frameworks people actually build on satisfy them.

Most of them do not. That is §6, and it is the part of this document a bank should read first.

---

<a id="2"></a>
## 2. What the US agencies removed

OCC Bulletin 2026-13, issued with the Federal Reserve's SR 26-2 and a parallel FDIC issuance,
supersedes SR 11-7 and SR 21-8. It rescinds OCC 2011-12, OCC 2021-19, OCC 1997-24, and the model
risk management booklet of the Comptroller's Handbook. It is expected to be most relevant to banking
organizations above **$30 billion** in total assets.

That is not an amendment. It is a replacement, and it takes a specification layer with it.

Two sentences carry the consequence:

- Generative AI and agentic AI models are *"not within the scope of this guidance."*
- The guidance *"does not set forth enforceable standards or prescriptive requirements."*

For fifteen years, SR 11-7 answered a question that is otherwise very hard to answer: what does
adequate model risk management look like? It gave validation teams a structure and examiners a
shared vocabulary. You could disagree about whether a control was sufficient; you disagreed inside a
common frame.

The revised guidance keeps a frame for traditional models. For generative and agentic systems, it
declines to provide one — and hands the determination back to the institution: a banking
organization's own risk management and governance practices should guide the determination of
appropriate governance and controls for tools, processes and systems not covered in the document.

**The obligation did not move. The map did.**

---

<a id="3"></a>
## 3. What the exclusion did not touch

This is the part that gets lost in the summaries, so it is worth being concrete about what remains
in force.

**Safety and soundness.** An agent taking actions in a regulated workflow creates operational risk
regardless of which supervisory document describes the technology.

**Consumer protection and fair lending.** If a system participates in a credit decision, a
collections workflow or a customer communication, the statutes governing those outcomes apply to the
outcome. They do not ask what produced it.

**Sectoral duties.** Whatever the agent is doing — surveillance, reconciliation, KYC refresh,
disclosure drafting — carries its own obligations, attached to the activity.

**Third-party risk management.** An agent built on a vendor's model, running on a vendor's
infrastructure, invoking a vendor's tools, sits inside existing third-party risk expectations.

Every one of those was in force before 17 April and is in force now.

**And the agencies have said what comes next.** They plan to issue a **request for information**
addressing model risk management generally and specifically considering banks' use of AI, including
generative AI, agentic AI and AI-based models.

That single fact settles the interpretation. A regulator intending permanent exclusion does not
announce a consultation. **The exclusion is a deferral, not an exemption** — a statement about the
maturity of the technology, not about whether the risk is supervised.

So the current US position is precisely this: the risk is supervised, the controls are unspecified,
and the specification is coming.

---

<a id="4"></a>
## 4. What the RBI required

The RBI's draft takes the opposite path, and the contrast is sharper than a summary suggests.

**Scope.** Traditional statistical models **and** AI/ML systems, including foundational and frontier
models. The draft does not use the word "agentic" — autonomy enters through **"extent of reliance and
level of autonomy"** as an input to risk tiering, which is arguably a more durable formulation than
naming a technology that will be renamed.

**Applicability.** Eleven categories of regulated entity: commercial banks, small finance banks,
payments banks, local area banks, regional rural banks, urban co-operative banks, rural co-operative
banks, NBFCs across all layers, All-India Financial Institutions (EXIM, NABARD, NaBFID, NHB, SIDBI),
asset reconstruction companies, and credit information companies.

**Consultation closed 24 July 2026.** The comment window is shut. Unlike the US, where the docket has
not opened, India's has already closed — which means the influence phase is over and the preparation
phase is all that remains.

Three provisions matter more than the rest.

**First — kill switches, mandated and undefined.** Chapter V-B.3, under Human Oversight, prescribes:
*"Override, suspension, and deactivation mechanisms — including kill-switch arrangements for AI
models."*

No technical specification of what constitutes a kill switch is provided. The requirement is
conceptual, not prescriptive.

**Second — board-approved model risk management framework.** Every regulated entity must put in place
a Board-approved MRMF applicable to all models. The Board approves risk appetite and tiering policy;
the Risk Management Committee of the Board approves high-risk deployments. This is not a
documentation exercise delegated to a second line — it is named accountability at the top.

**Third — third-party accountability, absolute.** *"An RE acquiring, using, or relying upon
third-party models remains fully accountable for its outcomes."* Independent validation by the
regulated entity is mandatory **even where vendors have certified the model.**

The draft also addresses customer-facing systems directly: the customer must be able to switch to
human assistance on request, and AI interfaces cannot be a dead end.

---

<a id="5"></a>
## 5. The convergence

Set the two documents side by side.

| | **US — OCC 2026-13 / SR 26-2** | **India — RBI Draft, 2026** |
|---|---|---|
| Date | 17 April 2026 | 24 June 2026 |
| Generative / agentic AI | **Out of scope** | **In scope** (via autonomy in risk tiering) |
| Enforceability | *"Does not set forth enforceable standards"* | Draft; consultation closed 24 July 2026 |
| Applies to | Banking organizations, most relevant above $30bn | 11 categories of regulated entity |
| Containment requirement | None stated | **Kill-switch arrangements required** |
| Containment **specification** | **None** | **None** |
| Board accountability | Institution's own governance determines controls | **Board-approved MRMF mandatory** |
| Third-party models | Existing third-party risk expectations | **Full accountability; independent validation mandatory** |
| What comes next | RFI covering generative and agentic AI | Final guidance |

Read down the two columns and the divergence is obvious. Read across the **containment
specification** row and the divergence disappears.

One regulator withdrew the framework that would have specified the control. The other required the
control and did not specify it. **The specification gap is regime-independent.** It is not a
consequence of either regulator's choice, and — this is the operative point — **it will not be closed
by waiting for either of them.**

---

<a id="6"></a>
## 6. Somebody specified it. Your framework fails it.

### 6.1 The specification exists

On 15 July 2026 — three weeks after the RBI draft — Sajjad Khan published *"Stop Means Stop:
Measuring and Repairing the Enforcement Gap in Agent-Framework Control Primitives"*
(arXiv:2607.14166). It does what neither regulator did.

It defines the thing precisely. A **barrier contract**, in the operator's sense, as four safety
clauses:

| | Clause | Plain statement |
|---|---|---|
| **B1** | Approval | No gated effect of the run executes between the pause and the decision |
| **B2** | Rejection | A rejected effect never executes |
| **B3** | Resume | Each logical effect executes at most once |
| **B4** | Cancel / timeout | After the caller observes the stop, no further effect of the run lands |

Khan is careful about what that is: *"a fence at the effect boundary, not a synchronization barrier
in the parallel-computing sense."* These are safety clauses only — liveness, the guarantee that a
held effect is eventually decided, is deliberately not part of the contract.

That is what a kill-switch requirement looks like when written by someone who has to implement it.
It is four sentences. Both regulators had room for them.

### 6.2 The measurement, and why it should alarm a regulated entity

Khan then tests whether shipped frameworks honor the contract their own documentation implies.

**They do not.** The central failure is the **sibling leak**: when an approval gate and a
side-effecting action are siblings in the same execution step, the gate suspends its own branch
while the sibling's effect executes anyway — *during the pause, while the run awaits approval*. The
operator's subsequent rejection is powerless. The e-mail was delivered. The payment was captured.

The recurrence is not one vendor's bug. It appears in **every evaluated framework shipping a
pre-execution gate — five of six** — across four distinct execution models and two language
runtimes, in independently designed codebases. Named with pinned versions, per the paper: a
Pregel/BSP graph runtime, an event-driven workflow runtime, a message-passing runtime with fan-out,
an agent SDK with parallel tool calls, a role/task crew orchestrator, and a JavaScript port of the
first. Three further gaps are confirmed on current releases: **replay double-execution** (an effect
before a resume point executes twice), **cancellation orphaning** (a canceled run's tool effect
lands after the caller observes cancellation), and **timeout zombies** (an effect completes after a
timeout is reported).

Two numbers carry the risk from theoretical to operational. Frontier models emit the leak-triggering
plan shape at rates **up to 14%**, and across live models driving unmodified frameworks, **215 of
1,200 runs leaked** — with the conditional probability of a leak, once the plan shape is emitted,
measured at **1.00**. A 13-incident public corpus corroborates the replay and cancellation failures
in the wild.

**Read that against Chapter V-B.3.** An RBI-regulated entity is required to have override,
suspension and deactivation mechanisms including kill-switch arrangements. If that entity has built
on mainstream agent infrastructure, there is now published, reproducible evidence that **its stop
button does not stop everything** — and the failure is a property of the framework, not of the model,
so no amount of prompt engineering or model choice repairs it.

### 6.3 The repair, and what it tells you about tiers

Khan's repair, SOUNDGATE, is an **environment-external** gate — outside every framework, since the
framework's own control flow is the thing that fails — through which every side effect must be
admitted. It enforces hold-until-decided, reject-cancels, dedup-on-replay and fence-on-cancel under
a **stated complete-mediation contract**, discharged for network egress by **two kernel-enforced
routes**. The admission core is mechanically verified (Verus; TLA+/TLC to 7.5×10⁷ states; TLAPS;
Loom) and bridged to the deployed implementation by differential conformance over 1.2×10⁷
operations with zero divergences. It blocks every measured violation across all six frameworks at
roughly a millisecond per write.

**Notice where the guarantee comes from.** Not from the signature, and not from the framework's own
hook. From being *outside* the thing being controlled, and from *kernel-enforced* routes for the one
channel where complete mediation is discharged.

That is the tier argument, made by someone else, with proofs. And Khan is explicit about its edge:
the contract covers network egress; **non-network channels — shared filesystem, local IPC, shared
memory — are outside it** absent "an analogous seccomp/LSM policy." The paper also states plainly
that it does not defend against prompt injection or a compromised tool, which are orthogonal.

So the honest decomposition of "kill switch" stands, and now has a worked example on each side:

- **A signed revocation a compliant client honors.** Real, auditable, and it constrains nothing that
  declines to consult it.
- **A framework's own pause primitive.** Measured. Leaks in five of six.
- **An external gate with kernel-enforced routes.** Verified, and bounded to the channels the
  placement contract actually covers.

A supervisory requirement satisfied by the first is satisfied by a document. One satisfied by the
third is an infrastructure program. **Both are currently "kill-switch arrangements."**

### 6.4 The gap is not specifiability. It is disconnection.

The framing this document opened with needs correcting, and the correction is the more damning
version.

The problem is not that a kill switch is too hard to specify for a regulator to attempt. Somebody
specified it in four clauses, proved it, and published a `pip`-installable artifact.

The problem is that the RBI mandated the control three weeks before the specification appeared, the
US agencies withdrew the framework that would have specified it, and **nothing connects the
regulatory track to the research track.** A supervisor writing final guidance has, right now, a
verified contract and a cross-framework measurement available to cite. Whether the final text cites
them is the whole question.

**What to do with this before that text exists.** Test your own stack against B1–B4. The probes are
in the paper's artifact, they are model-free by construction, and they answer a question your board
will eventually be asked: when you press stop, does everything stop?

> ⚠️ **Naming discipline.** The frameworks above are named because a published, reproducible research
> record names them with pinned versions. Cite Khan alongside every mention. Describe the defect,
> never characterize the vendor — and note the paper's own framing: the recurrence across
> independently designed codebases is evidence of a **shared design pattern left unresolved**, not of
> any one team's carelessness.

<a id="7"></a>
## 7. Third-party accountability: the provision that survives certification

The RBI provision most likely to be under-read is the third-party one, because it looks like
boilerplate and is not.

*An RE acquiring, using, or relying upon third-party models remains fully accountable for its
outcomes*, and **independent RE validation is mandatory even where vendors have certified the
model.**

Consider what that does to a common procurement posture. The reasonable-sounding position — *we
bought a governed platform from a serious vendor, and their certifications transfer to us* — is
foreclosed. Vendor certification is not a substitute for your validation; it is an input to it.

Which raises a question a vendor should be able to answer and frequently cannot: **what evidence does
this system produce that would let us validate it independently?**

Not a compliance attestation. Not a control narrative. Evidence, generated at runtime, about what
the system actually did — that a validator inside your institution can examine without relying on the
vendor's assurance that the record is complete and unaltered.

That is a hard requirement to meet with application logs, for a structural rather than a
technological reason: logs are maintained by the party being examined and can be altered by that
party without leaving a trace that survives that party's own tooling. Nobody in a bank believes
their vendor is falsifying logs. That is not the standard. The standard is whether the evidence
would still mean something if someone had.

**This provision is where the Indian draft is most directly ahead of the US position,** and it is the
one most likely to survive into final guidance, because it does not depend on any technical
specification. It is an allocation of accountability, and allocations of accountability are what
regulators are most confident writing.

---

<a id="8"></a>
## 8. What a bank in both markets should build once

The portability argument is the practical payoff, so here it is concretely.

**One — an enumerated action envelope per agent.**
Not a model inventory row. For each deployed agent: which systems it can reach, which actions it can
take without a human, where those bounds are *enforced* rather than described, and at which of the
three tiers. This satisfies the RBI's risk-tiering-by-autonomy requirement and is the artifact a US
examiner will ask for when your own governance is the standard.

**Two — containment at a stated tier, drilled and timed.**
Pick the tier deliberately. Document which mechanism you have implemented, what it binds, and what it
does not. Then drill it: time the stop, account for in-flight actions, record the result even when
the result is bad. A timed drill is evidence. An architecture diagram is not.

**Three — evidence whose integrity does not depend on you.**
Tamper-evident records of consequential actions and of refusals, in a form an independent validator
can check. This is what the RBI's third-party provision effectively requires and what the eventual US
guidance is most likely to converge on, because it is the only artifact that answers *who authorized
this, on what basis, and can you show me* without the examiner having to trust the examined.

**Four — board-level ownership with something real attached.**
The RBI mandates a Board-approved MRMF. The US guidance hands the determination to your governance.
Both land in the same place: a named accountable body, and — this is the part that gets skipped —
telemetry that makes the accountability survivable. Named accountability without observability is a
signature on something nobody can see.

None of the four is jurisdiction-specific. Each is required or strongly implied by both regimes, and
none of them requires knowing what the final texts will say.

---

<a id="9"></a>
## 9. What the final texts will most likely codify

An informed guess, labeled as one.

Specifications written after an industry practice exists tend to codify a recognizable version of
that practice. This is not cynicism about regulatory capture; it is how technical specification works
generally. The people who have built the thing supply the vocabulary, because they are the only
people with a vocabulary to supply.

Two consequences follow, one for each market.

**In India, the influence window has closed.** The consultation ended on 24 July. Whatever shapes the
final guidance has already been said. The remaining question is preparation, and the entities that
will find final guidance cheap are the ones whose posture already resembles what it describes.

**In the US, the window is open and nobody has walked through it.** The RFI has not been published.
Comment periods are answered, in practice, by institutions with something concrete to describe — and
an institution that arrives with a measured containment drill, an enumerated action envelope and a
working evidence trail is describing a practice rather than an aspiration.

The asymmetry is worth stating plainly: **the same work is preparation in one market and influence in
the other.** That is unusual, and it will not persist.

---

<a id="10"></a>
## 10. The uncomfortable part

I want to end on the thing this analysis does not resolve, because a whitepaper that resolves
everything is selling something.

Neither regulator specified the control **because specifying it is genuinely hard.** That is not a
failure of regulatory nerve. A kill switch that binds a non-cooperating process requires
infrastructure most organizations have not built; a kill switch that binds a cooperating one is
mostly a document. Writing a requirement that distinguishes them, without freezing a technology that
is changing every quarter, is a real drafting problem.

Which means the specification, when it arrives, will be written against whatever the industry has by
then demonstrated is achievable. If what the industry has demonstrated is signed revocations and
architecture diagrams, that is what "kill-switch arrangements" will come to mean, and it will not be
worth much.

I have built a kill switch. It had thirty-three passing tests and a green workspace run, and it still
contained a contract breach on Windows — because the platform-gated code path had never executed in
continuous integration, which ran on Linux only. Test coverage did not flag it, because coverage
measures the lines that ran on the platform that ran them.

The component that hid a defect in is the one whose correctness is the whole argument. I disclose it
here for one reason: **the gap between "we have a kill switch" and "we have demonstrated a kill
switch on every platform we ship" is exactly the gap the eventual specification will either close or
enshrine.**

Which of those it does depends on what is built in the next twelve months, by institutions that have
no instructions and cannot wait for them.

---

<a id="11"></a>
## 11. Sources

**United States**
- OCC Bulletin 2026-13, *Model Risk Management: Revised Guidance*, 17 April 2026.
  https://www.occ.gov/news-issuances/bulletins/2026/bulletin-2026-13.html ·
  https://www.occ.treas.gov/news-issuances/bulletins/2026/bulletin-2026-13a.pdf
- Federal Reserve SR 26-2. https://www.federalreserve.gov/supervisionreg/srletters/SR2602.htm
- OCC news release NR-2026-29.
  https://www.occ.gov/news-issuances/news-releases/2026/nr-occ-2026-29.html
- Sullivan & Cromwell, *Federal Banking Agencies Issue Revised Guidance on Model Risk Management*,
  April 2026. https://www.sullcrom.com/insights/memo/2026/April/OCC-Fed-FDIC-Issue-Revised-Guidance-Model-Risk-Management

**India**
- RBI, *Draft Guidance on Regulatory Principles for Model Risk Management, 2026*, 24 June 2026.
  Consultation closed 24 July 2026. ⚠️ **Obtain and cite the RBI's own PDF; the summaries below are
  secondary.**
  https://www.business-standard.com/finance/news/rbi-propose-norms-to-manage-ai-ml-related-risks-for-regulated-entities-126062401168_1.html ·
  https://community.nasscom.in/communities/public-policy/analysis-rbis-draft-guidance-regulatory-principles-model-risk-management ·
  https://www.corplawupdates.in/updates/rbi-draft-guidance-model-risk-management-2026-ai-ml-banks-nbfcs
- RBI FREE-AI framework, 13 August 2025 (advisory; the predecessor to the above).

**The specification, and the measurement**
- Sajjad Khan, *"Stop Means Stop: Measuring and Repairing the Enforcement Gap in Agent-Framework
  Control Primitives."* arXiv:2607.14166v3, submitted 15 July 2026, revised 8 August 2026. CC-BY-4.0.
  Read in full 2026-08-30. Artifact: probes, harness, formal models and the SOUNDGATE reference
  implementation; installable as `pip install soundgate` (v0.1.0).
  https://arxiv.org/abs/2607.14166

**Survey data**
- Kiteworks 2026 Data Security Forecast (n=225 security, IT and risk leaders; 10 industries;
  8 regions).
  https://www.kiteworks.com/cybersecurity-risk-management/2026-data-security-forecast-ai-governance-predictions/

---

## Production notes (strip before publishing)

**Blocking items, in order.**

1. **Obtain the RBI draft PDF.** Confirm the Chapter V-B.3 quotation, the eleven RE categories, the
   Board-approved MRMF requirement, and the third-party accountability sentence. Three secondary
   sources agree, which is encouraging and is not verification.
2. **Confirm both US quotations** against `bulletin-2026-13a.pdf`, not the press release.
3. **Confirm the RFI has not published since 2026-08-30.** If it has, §9 is wrong in its most
   load-bearing paragraph and this becomes a different piece.
4. **Trace or cut the 35% figure.** The 60% figure is fully attributed and carries §6 alone.

**Structural notes.** §5's table is the piece — build it as the cover figure. §6 is the technical
contribution in business language and is where a differentiated reader stops skimming. §10 is the
credibility close; do not soften the self-disclosure, because it is the only paragraph in the
document that could not have been written by someone selling a platform.

**What was left out on purpose.** No product named. No framework proposed. No claim about what the
final guidance will require beyond a labeled guess. The EU appears nowhere, correctly — this is a
US-plus-India argument and adding a third regime would dilute both halves.

**Cuts.** Substack flagship ~2,800 words: §§1, 2, 4, 5, 6, 8, 10. LinkedIn (US) ~1,100: open on the
two decisions, the convergence table, the three kinds of kill switch, close on §10. LinkedIn (India)
~1,100: lead on Chapter V-B.3 and the third-party provision, then the convergence.

**Forward-links.** B-01 (the US half at depth), B-07 (the India half at depth), B-04 (the containment
drill), T-07 (the control mapping), the tier practitioner blog (the three kinds of enforced), T-09
(the kill-switch CI finding in §10).
