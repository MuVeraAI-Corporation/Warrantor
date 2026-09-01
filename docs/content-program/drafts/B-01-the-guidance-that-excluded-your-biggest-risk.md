# The Guidance That Excluded Your Biggest Risk

**Draft 1 · 2026-08-30 · Vikram Jha**
*Catalog ref: B-01 · US/NA · ~2,050 words · board-circulatable*

> **Pre-publish checklist:** US English verified · every claim traces to `04-verified-anchors.md` §A1
> · no legal advice given · no institution's compliance posture characterized · quotations checked
> against the primary PDF, not the press release.

---

On 17 April 2026, the Federal Reserve, the FDIC and the Office of the Comptroller of the Currency
replaced the model risk management guidance the industry had been building against since 2011. Two
sentences in the replacement matter more than the rest of the document, and I have watched them read
as good news for four months.

The first says that generative AI and agentic AI models are *"not within the scope of this
guidance"* — the stated reason being that they are novel and rapidly evolving. The second says the
guidance *"does not set forth enforceable standards or prescriptive requirements."*

If you run an institution above thirty billion dollars in assets and you have agents touching
regulated workflows, the temptation is to file that under relief.

It is not relief. It is a deferral, and the difference is expensive.

---

## What actually changed

OCC Bulletin 2026-13, issued alongside the Federal Reserve's SR 26-2 and a parallel FDIC issuance,
supersedes SR 11-7 and SR 21-8. It rescinds OCC 2011-12, OCC 2021-19, OCC 1997-24, and the model
risk management booklet of the Comptroller's Handbook. That is not an amendment. It is a
replacement, and it takes the specification layer with it.

For fifteen years, SR 11-7 answered a question that is otherwise very hard to answer: what does
adequate model risk management look like? It gave validation teams a structure — conceptual
soundness, ongoing monitoring, outcomes analysis — and it gave examiners a common vocabulary to
examine against. You could disagree about whether a particular control was sufficient, but you were
disagreeing inside a shared frame.

The revised guidance keeps a frame for traditional models. For generative and agentic systems, it
declines to provide one.

It does not, however, say those systems are unsupervised. It says the opposite, in the plainest
available terms: a banking organization's own risk management and governance practices should guide
the determination of appropriate governance and controls for tools, processes and systems not
covered in the document.

Read that as what it is. The obligation did not move. The map did.

---

## The obligations that did not move

This is the part that gets lost, so it is worth being concrete about what remains untouched.

**Safety and soundness.** An agent that takes actions in a regulated workflow creates operational
risk regardless of which supervisory document describes the technology. Nothing about the scope
exclusion changes an examiner's mandate to assess whether an institution is operating safely.

**Consumer protection and fair lending.** If a system participates in a credit decision, a
collections workflow, or a customer communication, the statutes that govern those outcomes apply to
the outcome. They do not ask what produced it.

**Sectoral duties.** Whatever the agent is actually doing — surveillance, reconciliation, KYC
refresh, disclosure drafting — carries its own regulatory obligations, and those obligations attach
to the activity.

**Third-party risk management.** An agent built on a vendor's model, running on a vendor's
infrastructure, invoking a vendor's tools, sits squarely inside existing third-party risk
expectations.

Every one of those was in force before 17 April and is in force now. What changed is that the
document which would have told you *which controls satisfy them for this class of system* has been
withdrawn, and the replacement has not been written.

---

## Why "not in scope" is a deferral

The agencies have said what happens next. They plan to issue a request for information addressing
model risk management generally, and specifically considering banks' use of AI — including
generative AI, agentic AI, and AI-based models.

That single fact settles the interpretation. A regulator that intended permanent exclusion does not
announce a consultation. The exclusion is a statement about timing and about the maturity of the
technology, not a statement about whether the risk is supervised.

Which means the current position is precisely this: the risk is supervised, the controls are
unspecified, and the specification is coming.

An institution reading that as relief is making a bet that the eventual guidance will be
undemanding, and building nothing in the meantime. An institution reading it as a deferral is asking
a different question — what will the specification most likely require, and what does it cost to
have it already?

I think the second reading is correct, and I think it is correct on the guidance's own terms rather
than on any prediction about the agencies' intent.

---

## What "your own judgment" means in an examination

The revised guidance hands the determination of appropriate governance and controls back to the
institution. That is a real grant of discretion and it is worth taking seriously as one.

Discretion, in a supervisory context, is not the absence of a standard. It is the substitution of a
documented, defensible judgment for a prescribed one. An examiner who cannot check your controls
against a bulletin will check them against your own stated risk appetite, your own policy, and your
own evidence that the policy is operating.

That shifts the burden in a specific direction. Under a prescriptive regime, the question is *did
you do the required thing*. Under a discretionary one, the question becomes *what did you decide,
why, and can you show that it worked*.

The second question is harder to answer badly and easier to answer well — but only if you started
generating the answer before you were asked. Judgment that is documented after an examination begins
is not judgment. It is reconstruction, and it reads as reconstruction.

---

## The evidence worth generating now

I am deliberately not going to propose a control framework here, because proposing one would be the
same error the guidance just declined to make: specifying a technology that is still moving.

What I will say is that three questions appear in every version of this problem I have worked on,
across jurisdictions, and an institution that can answer them with evidence rather than prose is in
a defensible position under any specification I can imagine being written.

**First: for each deployed agent, what is it permitted to do?** Not what it predicts — what it can
reach, what actions it can take without a human, and where those bounds are enforced rather than
described. Most institutions have an AI inventory. Very few can answer this question from it,
because a model inventory describes a prediction and the risk has moved to an action.

**Second: can you stop it, and have you timed that?** Not in principle. Measured, in a drill, with
the in-flight actions accounted for — the ones already executing when the decision to stop is made.
Recent survey work is unflattering here, and I will come back to it in a separate piece, but the
short version is that belief and demonstrated capability diverge sharply on this question.

**Third: when the agent acted, what evidence exists that would survive scrutiny?** Application logs
are maintained by the party being examined. That is not an accusation; it is a structural property,
and it is exactly the property an examiner is trained to think about. Evidence whose integrity does
not depend on the good faith of the examined party is a different category of artifact.

None of those three requires a vendor, a framework, or a prediction about the final guidance. All
three will appear in it in some form, because they are the questions the underlying obligations
already ask.

---

## The window, and what closes it

There is a period — starting on 17 April and ending whenever the separate AI guidance lands — during
which institutions are defining adequate control for themselves, in public, in their own
implementations.

The specification that eventually arrives will be written after a consultation, and consultations
are answered in practice by the institutions with something concrete to describe. That is not a
cynical observation about regulatory capture. It is how technical specification works everywhere:
the people who have built the thing supply the vocabulary, because they are the only ones with a
vocabulary to supply.

So the window has an asymmetry in it. Build now, and your controls are a candidate for what
"adequate" comes to mean. Wait, and you retrofit to a definition assembled from other institutions'
implementations — which may be better than yours, and will certainly be shaped differently.

The cost difference between those two paths is not a rounding error, and it compounds with every
agent deployed in the interim.

---

## The question I would put to a board

If I had one question to ask a board risk committee about this, it would not be about the guidance
at all.

It would be: *name any agent currently in production, and tell me what it is allowed to do, who
decided that, and what stops it.*

If that produces a clear answer, backed by configuration rather than by policy language, then the
scope exclusion genuinely is relief and the institution is ahead of the specification.

If it produces a pause — and in my experience it usually does — then April did not reduce the work.
It removed the instructions and left the work exactly where it was.

---

*OCC Bulletin 2026-13, "Model Risk Management: Revised Guidance," 17 April 2026, issued with Federal
Reserve SR 26-2 and a parallel FDIC issuance. Quotations are from the guidance. The stated intent to
issue a request for information addressing banks' use of generative and agentic AI is from the
agencies' accompanying materials.*

*Nothing here is legal advice, and nothing here characterizes any institution's compliance posture.*

---

## Production notes (strip before publishing)

**Layering, per the brief.** Board-safe body: no vendor voice, no product mention, argument carried
by the guidance's own text. Citable core: the deferral-not-relief reading in §"Why 'not in scope' is
a deferral" is the paragraph designed to be quoted. Conversation opener: the closing question, which
is diagnostic rather than promotional and is answerable only by someone who has the configuration in
front of them.

**Deliberate omissions.** No control framework proposed — proposing one here would undercut the
argument and would date the piece. No statistics used; the containment figures are held for B-04
where they can carry full attribution. No mention of India — the comparison is B-14's job and
splitting it weakens both.

**Open verification before publish.**
- Confirm both quotations against `bulletin-2026-13a.pdf` directly, not the press release or any
  secondary summary.
- Confirm the RFI language in the agencies' own materials; if it has since been published, this
  piece needs a new final section and B-02 becomes a response rather than a forecast.

**Cuts.** LinkedIn: open at "It is not relief," keep §§ *obligations that did not move* and *why it
is a deferral*, close on the board question. ~1,100 words. Substack: full text.

**Forward-links.** B-02 (the RFI), B-03 (the perimeter question in §"evidence worth generating"),
B-04 (containment and the survey figures), B-14 (the RBI comparison).
