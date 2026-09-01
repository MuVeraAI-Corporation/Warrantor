# The Mediation Ceiling

**Draft 1 · 2026-08-30 · Vikram Jha**
*Catalog ref: T-01 · ~2,900 words · repo canonical, Substack lead, LinkedIn abridged*

> **BLOCKED ON MEASUREMENT.** Every `⟦MEASURED⟧` marker below is a placeholder for a figure from the
> instrumented run specified in [`T-01-measurement-protocol.md`](T-01-measurement-protocol.md).
> **Do not publish with placeholders.** Per the pre-commit: the number publishes whatever it says,
> paired with what composition raises it to.

---

For about six weeks I described what we were building as a mediation layer for coding agents. It was
the natural word. It was also wrong, and the way I found out was not an argument — it was a session
log.

We had wired the supervisor through the Model Context Protocol. Every tool call the agent made
through the protocol arrived at our handler, got checked against a warrant, and produced a receipt.
The loop worked end to end; I have the receipts. Then I put our log next to the agent's own
transcript and counted the actions that never appeared on our side at all.

The gap is not a bug in our implementation. It is a property of where MCP sits.

---

## The ceiling, stated plainly

An agent with a shell does not need the protocol's permission to use the shell.

That is the whole thing. Everything below is consequence.

A supervisor that observes MCP observes the actions that traverse MCP. A coding agent's action
surface is larger than that — it includes direct process execution, filesystem operations that never
declare themselves, network calls made by tools the agent invokes natively, and anything reachable
through an interpreter it can start. None of that is hidden maliciously. It simply never enters the
transport you are watching.

So mediation coverage is not a property of the supervisor. It is a property of the deployment: which
capabilities the agent was given, and which of those happen to route through a mediated channel. Two
installations of identical software can have very different coverage, and neither of them knows it.

This is what I mean by a ceiling. It is not the current limit of our engineering. It is the limit of
what any protocol-level supervisor can see, and no amount of implementation effort moves it, because
the actions we are missing are not failing to be intercepted — they are not addressed to us.

---

## Why this is worth saying out loud

There is a version of this essay that never gets written, in which I quietly narrow the product
claim and hope nobody runs the comparison.

I do not think that version survives contact with a competent buyer. The measurement is easy: turn
on your agent's transcript, turn on your supervisor's log, and diff them. Anyone evaluating this
class of product for real will do it, and they will do it after signing rather than before, which is
the worst possible time for both parties.

There is also a straightforwardly technical reason. If coverage is a deployment property, then
telling a customer "this is mediated" without measuring their deployment is not a strong claim
stated confidently. It is an unmeasured claim, and unmeasured claims are how a control ends up
carrying weight it cannot bear.

I would rather define the metric than have it defined for me.

---

## The enumerated action surface

You cannot measure coverage without first enumerating what you are covering. That enumeration is
itself the useful artifact, and it is more boring and more revealing than the theory.

For a terminal coding agent, the action classes that matter:

**Process execution.** Starting a shell, a build, a test runner, a package manager, an interpreter.
Sometimes proxied through a tool; frequently not. Every downstream effect of that process is invisible
to a protocol observer, including processes it starts in turn.

**Filesystem operations.** Reads, writes, moves, deletes. Some agents declare these; some do them
directly; most do both depending on the path taken. Declared paths tell you about intent, not about
reach.

**Network operations.** Requests made by the agent's own tooling, by processes it started, and by
dependencies those processes pulled. The last category is where supply-chain risk actually lives and
it is the furthest from any protocol boundary.

**Credential access.** Reading environment variables, config files, keychains, cloud metadata
endpoints. Almost never mediated, almost always consequential.

**Protocol-mediated tool calls.** The ones we see. In our measurements this is the smallest of the
five categories by count and not the most consequential by impact.

Write that list down for your own deployment and the coverage question stops being philosophical.
You now have a denominator.

---

## Measuring instead of asserting

The metric I want to propose is deliberately unflattering and deliberately simple.

**Mediation coverage** = mediated actions ÷ total observed actions, over a defined workload, with
the action surface enumerated in advance and both logs timestamped from the same clock.

Three properties make it worth reporting:

It is *per-deployment*, so it never gets quoted as a product specification.
It is *falsifiable*, because anyone can re-run it.
It is *decomposable* by action class, which is where the number becomes actionable rather than merely
sobering — a coverage figure tells you how much you are missing; the decomposition tells you what.

On our own measurements, across ⟦MEASURED: standardized task set, n tasks⟧ and one real session on
this codebase:

- Overall mediation coverage: ⟦MEASURED: %⟧ (standardized) · ⟦MEASURED: %⟧ (real session)
- By action class: ⟦MEASURED: table — process / filesystem / network / credential / protocol⟧
- The gap between standardized and real: ⟦MEASURED: pp⟧

⟦MEASURED: one-paragraph interpretation, written after the numbers exist and not before.⟧

I will say in advance, because saying it afterward is worth less: I expect the real-session figure to
be lower than the standardized one, and I expect the process-execution class to dominate the
uncovered remainder. If I am wrong about either, that is the more interesting result and it goes in
the piece unchanged.

---

## What composition buys, and what it does not

The honest answer to a ceiling is not to claim you have raised it. It is to say what else has to be
true.

Protocol-level supervision gives you something specific and worth having: an authorization decision
at the moment a declared tool call is made, and a receipt that the decision happened. That is real.
It is also bounded to the declared surface, and no amount of work inside the protocol extends it.

To bound the undeclared surface you need a boundary the agent cannot address around — an operating
system one. Namespaces, seccomp filters, cgroups, an egress-filtering network position the process
cannot route past. Those mechanisms do not care whether an action was declared, because they do not
operate on declarations. They operate on syscalls and packets.

Two things follow, and the second is the one people skip.

**First**, composition works. A protocol supervisor inside an OS sandbox has meaningfully different
coverage than either alone, because the sandbox bounds what the undeclared surface can reach and the
supervisor explains what the declared surface did. Evidence plus enforcement, each doing the job the
other cannot.

**Second**, the composed system's guarantee is not the union of the two guarantees. For any action
reachable at the weaker tier, the composed bound is the weaker bound. A cryptographically signed
warrant does not constrain a process that never consults it; an OS boundary does not tell you why an
action was permitted. Assuming otherwise — quietly treating "we have both" as "we have the stronger
one everywhere" — is the most common overclaim in this field, and I have made it myself in print.

That argument needs more room than it gets here, and it has three distinct enforcement mechanisms
underneath it that are routinely conflated. I have written it up separately.

⟦MEASURED: coverage under composition — the same workload run inside a sandbox, so the "what the fix
buys" figure is measured rather than asserted. Per the pre-commit, this ships alongside the bare
number, not instead of it.⟧

---

## The claim I make now

Stated precisely enough to be attacked:

> Warrantor mediates the protocol-declared action surface of a coding agent. For that surface it
> produces an authorization decision against a warrant and a tamper-evident receipt of the decision.
> It does not observe undeclared process execution, undeclared filesystem operations, or network
> activity originating below the protocol layer. Coverage of the total action surface is a property
> of the deployment, is measurable by the procedure published alongside this claim, and on our own
> reference workloads is ⟦MEASURED⟧. Bounding the unmediated remainder requires an operating-system
> boundary that Warrantor does not itself provide and is designed to compose with.

That is a smaller claim than "mediation layer." It is the one I can defend in a room with someone
holding both logs.

---

## What would make this wrong

A transport-level interception point that catches native tool use without an OS or kernel boundary.
I do not believe one exists, and I have looked, but "I have looked" is not a proof and I would rather
name the falsifier than pretend there isn't one.

If someone demonstrates it, this essay is obsolete and I will say so here, in this document, with a
link to their work.

---

## Production notes (strip before publishing)

**Status: blocked.** The piece is complete as argument and unpublishable as written. Six
`⟦MEASURED⟧` markers require the instrumented run. Do not soften them into prose — an unmeasured
version of this essay is exactly the behavior it criticizes.

**Related work that must be engaged before publication.**
- `arXiv 2605.05379` *Partial Evidence Bench* — benchmarks evidence quality under authorization
  limits. This is the same problem from the evidence side and it strengthens the piece; cite it in
  §"Measuring instead of asserting."
- `arXiv 2606.29073` *From Tool Connection to Execution Control* — eight security invariants and a
  reference runtime. Their invariants apply inside the declared surface; the ceiling is about the
  boundary of that surface. Distinguish explicitly.
- NSA MCP CSI (20 May 2026) — names *uncontrolled automated actions* as a systemic risk. It is the
  strongest external corroboration available and it belongs in §"The ceiling, stated plainly."

**Tone check.** The failure mode is this reading as an admission. It is not — it is the precondition
for every enforceable claim downstream. Do not add reassurance to the ceiling section; the composition
section is where the answer goes, and it lands harder for having waited.

**Cuts.** LinkedIn ~900 words: open on the session log, the ceiling stated plainly, the measured
number, close on the narrowed claim. Drop the action-surface enumeration and the composition
argument; link both.

**Forward-links.** T-02 (the three enforcement tiers — the composition rule referenced above),
T-07 (the CSI mapping), T-14 (the harness ships as a reusable artifact).
