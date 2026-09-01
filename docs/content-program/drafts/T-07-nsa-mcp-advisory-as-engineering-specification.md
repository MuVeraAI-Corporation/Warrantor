# Reading the NSA's MCP Advisory as an Engineering Specification

### A risk-to-control mapping for agent deployments, with the gaps left in

**Technical whitepaper · Draft 1 · 2026-08-30 · Vikram Jha**
*Catalog ref: T-07 · ~4,600 words · repo canonical + vikramjha.work; Substack cut at flagship length*

> **Independent analysis.** This document is not affiliated with, endorsed by, or reviewed by the
> National Security Agency or any government body. It maps published guidance to implementable
> controls and states where that mapping fails.

---

## Contents

1. [Why a signals-intelligence agency wrote about a tool protocol](#1)
2. [What the advisory actually says](#2)
3. [The missing vocabulary: three kinds of "enforced"](#3)
4. [Risk 1 — Uncontrolled automated actions](#4)
5. [Risk 2 — Absent input screening](#5)
6. [Risk 3 — Serialization](#6)
7. [Risk 4 — Trust boundary erosion](#7)
8. [Risk 5 — Agent misuse](#8)
9. [The coverage table, gaps included](#9)
10. [A 30-day hardening sequence](#10)
11. [What the advisory does not say](#11)
12. [Sources](#12)

---

<a id="1"></a>
## 1. Why a signals-intelligence agency wrote about a tool protocol

In May 2026 the National Security Agency published a Cybersecurity Information Sheet titled *Model
Context Protocol (MCP): Security Design Considerations for AI-Driven Automation.*

That is a strange sentence. MCP is roughly eighteen months old. It is a way for a language model to
call tools. It is not infrastructure in the sense that DNS or TLS is infrastructure, and it is not,
on its face, the kind of thing that attracts a national-security advisory.

It attracted one because of what it has quietly become. MCP is now the connective tissue between
language models and the systems those models act upon — ticketing systems, source repositories,
cloud consoles, databases, internal APIs. The protocol did not set out to be an authorization
boundary. It has become one by default, in thousands of deployments, without most of those
deployments deciding that it should be.

The advisory says this in its own terms: adoption has outpaced the development of appropriate
security safeguards, leaving organizations exposed to risks the protocol's designers and
implementers did not fully anticipate.

**Read as a warning, the document changes nothing you did not already suspect.** Read as a
specification, it is a list of controls somebody has to build.

This paper is that reading. For each risk the advisory names, I give the control that addresses it,
the enforcement tier at which that control binds, and — where it applies — the reason our own
coverage is incomplete. There are four such rows. They are in the same table, at the same size, as
everything else.

---

<a id="2"></a>
## 2. What the advisory actually says

Quoting and characterizing precisely matters here, because the temptation in a document like this
one is to paraphrase a government advisory into something stronger than it said.

The advisory identifies gaps in MCP **design, implementation, and operational posture** that have
created significant and evolving security concerns. It names three categories explicitly:
**serialization risks**, **trust boundaries**, and **agent misuse**.

It names two specific risks in more concrete terms:

- **Uncontrolled automated actions.** AI systems using MCP can independently decide to use new tools
  or take new actions.
- **Lack of input screening.** MCP allows data to pass between systems without sufficient checks on
  what that data contains, opening the door for malicious content — such as hidden commands — to
  pass through undetected.

And it makes a structural claim that is the most important sentence in the document. Traditional
cybersecurity principles — authentication, authorization, input validation — remain necessary. But
agentic systems, and MCP-based ones especially, introduce risks the advisory describes as **novel
and systemic**: dynamic tool invocation, implicit trust relationships, and context sharing.

**Systemic, not incidental.** That distinction is what makes this a specification problem rather
than a hygiene problem. Incidental risks are fixed by doing the existing thing more carefully.
Systemic risks are properties of the architecture, and they are fixed by changing what the
architecture guarantees.

---

<a id="3"></a>
## 3. The missing vocabulary: three kinds of "enforced"

Before the mapping, one piece of vocabulary, because without it the mapping is misleading.

The word *enforced* in agent security silently spans three mechanisms with different threat models.
A control that "enforces" something at one tier does not enforce it at another, and a system that
composes tiers does not get the strongest guarantee. It gets the weakest one the attacker can
reach.

| Tier | Mechanism | What it binds | What defeats it |
|---|---|---|---|
| **Tier 1 — Cryptographic** | Signatures, attestations, hash chains | What can be *proven* after the fact, and what a compliant verifier will accept | An actor that never consults the signature. Cryptography constrains verification, not execution |
| **Tier 2 — OS / kernel** | Namespaces, seccomp, cgroups, network position | What the process *can do*, regardless of intent or declaration | Kernel vulnerabilities, misconfiguration, capabilities granted too broadly |
| **Tier 3 — Proxy chokepoint** | A mediating service every request must traverse | What passes *through the chokepoint* | Any path that does not traverse it. Strong where traffic must pass, void where it need not |

MCP-layer controls are **Tier 3**. Every one of them. That is not a criticism of MCP — a protocol
cannot be anything else — but it has a hard consequence for this mapping:

> **An MCP-layer control binds the actions that traverse MCP. An agent with a shell does not need
> the protocol's permission to use the shell.**

I call this the mediation ceiling, and it means that several of the advisory's risks cannot be fully
addressed at the layer the advisory is about. Where that is true below, I say so rather than
presenting a Tier 3 control as though it closed a Tier 2 problem.

*A note on completeness: WASM-based isolation of MCP tools is neither an OS bound nor a proxy bound,
and whether it constitutes a genuine Tier 2 guarantee is an open question in the current literature.
Where it appears below, it is marked as unresolved.*

---

<a id="4"></a>
## 4. Risk 1 — Uncontrolled automated actions

**The advisory's framing.** An AI system using MCP can independently decide to use new tools or take
new actions.

**Why this is not solved by authorization.** The instinctive response is that this is what
authorization is for, and that an MCP server implementing OAuth 2.1 as a resource server addresses
it. That is a category error worth naming precisely.

Authorization answers *may this principal invoke this tool*. It does not answer *should this agent,
in this task, having already taken these four actions, invoke this tool now*. A servicing agent
legitimately authorized to issue refunds is authorized to issue the thousandth refund exactly as
much as the first. The permission model is static; the risk is cumulative.

This is the gap between a **permission** and a **warrant**. A permission is a standing grant. A
warrant is a bounded authority: this agent, for this task, within these limits, expiring at this
point, with these actions requiring escalation.

**Controls.**

| # | Control | Tier | Notes |
|---|---|---|---|
| 1.1 | **Warrant-scoped invocation.** Every tool call evaluated against a task-scoped authority with explicit bounds, not a standing role | 3 | Binds declared calls only |
| 1.2 | **Autonomy budget.** A declared, enforced ceiling on actions per task — count, value, blast radius — that halts and escalates on exhaustion | 3 | The control that addresses cumulative risk directly |
| 1.3 | **Escalation gates on irreversible classes.** Deletion, disbursement, publication, credential issuance require a human decision regardless of budget | 3 | Only as good as the class enumeration |
| 1.4 | **Deny-by-default tool registration.** New tools are unavailable until explicitly admitted, so "decide to use a new tool" fails closed | 3 | Directly addresses the advisory's phrasing |
| 1.5 | **Sandbox confinement.** The agent process runs inside an OS boundary bounding what it can reach when it acts outside MCP | **2** | **We do not provide this. Compose with a sandbox.** |

**Our gap, stated plainly.** Controls 1.1 through 1.4 are Tier 3. They bind the declared surface. An
agent that starts a shell and issues the same effect directly is not stopped by any of them.
Control 1.5 is the answer and it requires an operating-system boundary that our stack does not
implement. We have no namespace, seccomp, or firewall enforcement. The honest architecture is
composition with a sandbox, and the honest claim is bounded to the declared surface.

**The measurable question.** Not *is this mediated* but *what fraction of this deployment's action
surface is mediated*. Coverage is a property of the deployment — which capabilities the agent was
given, and which route through a mediated channel — and two installations of identical software can
differ substantially. It should be measured per deployment, decomposed by action class, and stated
as a number.

---

<a id="5"></a>
## 5. Risk 2 — Absent input screening

**The advisory's framing.** MCP allows data to pass between systems without sufficient checks on
what that data contains, opening the door for malicious content — such as hidden commands — to pass
through undetected.

**The mechanism.** This is indirect prompt injection, and its danger is architectural rather than
linguistic. A model reading tool output cannot reliably distinguish *data it was asked to process*
from *instructions embedded in that data*. A support ticket, a code comment, a web page, a file name
— any of these can carry text addressed to the model rather than to the user. The model has no
channel separation to fall back on.

**Controls.**

| # | Control | Tier | Notes |
|---|---|---|---|
| 2.1 | **Guard screening on tool output** before it re-enters model context | 3 | See the measurement caveats below |
| 2.2 | **Provenance labeling.** Untrusted content structurally marked at ingestion and carried through the context | 3 | Mitigates; does not eliminate |
| 2.3 | **Capability reduction after untrusted ingestion.** An agent that has read untrusted content operates under a reduced warrant for the remainder of the task | 3 | Underused, and cheap |
| 2.4 | **Egress filtering** so a successful injection cannot exfiltrate | **2** | **Not provided. Requires network position.** |
| 2.5 | **Content-addressed resources.** Tools return canonical identifiers rather than free text where the interface permits | 3 | Narrows the channel, does not close it |

**Three findings on guard models that change how 2.1 should be deployed.** These come from our own
controlled evaluation program, and they are unflattering in ways that matter operationally.

**First, apparent domain differences in a general guard are a prevalence artifact.** Measured twice,
at both parameter scales, with Wilson intervals: the finance/healthcare/law spread in an untuned
general guard is driven by one weak category rather than by domain difficulty. **We have not yet
compared a vertically fine-tuned guard against a general one** — those checkpoints do not exist — so
this is evidence about why the specialization intuition looks compelling, not yet evidence that
specialization fails.

**Second, guards degrade sharply on adversarial content, and the false-positive side is the
expensive one.** On WildGuardTest (n=1699), a general 4B guard scores recall 0.8886 and FPR 0.0224 on
the corpus's non-adversarial slice, against recall 0.8152 and FPR **0.0923** on its adversarial
slice. Recall falls 7.3 points; **false-positive rate rises 4.12x**.

Two caveats, both load-bearing. This is a **between-population comparison** using the corpus's own
`adversarial` label across different items — it is **not** a paired experiment on semantically
equivalent rephrasings of the same benign item, and we have not yet run that experiment. And the
per-slice counts underlying these rates were back-computed from published aggregates rather than
recorded per-item, so treat them as accurate to about a row.

What survives the caveats is the operational point: whatever produces adversarial-slice content also
produces four times the false alarms, and a guard that fires four times as often on benign content
gets tuned down or switched off by the team operating it. Fragility becomes disablement.

**Third, context-window configuration is a reproducibility hazard — as a configuration-management
finding, not yet a measured effect.** We shipped `num_ctx` 4096 for eight releases while our
published figures came from 8192, and a 32768 KV cache exhausts a 16 GB card. Pin the parameter and
report it. **We have not run a sensitivity sweep, so we make no claim about how much decisions
change across configurations** — only that comparisons are not reproducible when the parameter is
unstated.

**What follows.** Control 2.1 is real and worth deploying, and it is a probabilistic filter, not a
boundary. Treating it as a boundary is the error. Note also that the first finding above is not
measured at all — no vertical-versus-general contrast has been run, because none of the fine-tuned
checkpoints exist yet. What *is* measured is that a general guard's apparent domain spread is a
prevalence artifact of one weak category. That is the mechanism behind the specialization claim, not
the claim itself, and this paper states only the mechanism. It belongs in depth with 2.3 and 2.4, and 2.4 —
the one that bounds the consequence rather than the input — is the one we do not provide.

---

<a id="6"></a>
## 6. Risk 3 — Serialization

**The advisory's framing.** Serialization is named among the categories creating significant
security concerns.

**The mechanism.** Serialization risk in an MCP context is the classical problem in a new place.
Structured data crosses a trust boundary and is deserialized by a party that did not produce it.
Where deserialization instantiates types, resolves references, or evaluates content, the parsing
step becomes an execution step. In agent systems this surface is larger than usual because so many
boundaries are crossed per task — model to client, client to server, server to tool, tool to
downstream system — and each is an opportunity.

**Controls.**

| # | Control | Tier | Notes |
|---|---|---|---|
| 3.1 | **Schema-validated deserialization at every boundary,** with unknown fields rejected rather than ignored | 3 | Rejection, not tolerance, is the control |
| 3.2 | **No polymorphic or type-resolving deserialization** of externally supplied data | 3 | Language-level discipline |
| 3.3 | **Size and depth limits** enforced before parsing | 3 | Cheap; frequently absent |
| 3.4 | **Canonical serialization for anything signed,** so verification is not parser-dependent | **1** | Cryptographic tier |
| 3.5 | **Parser isolation** — deserialization in a constrained process | **2 / unresolved** | WASM isolation may qualify; open question |

**A note on 3.4.** Cross-language canonical serialization is not a formality. If a receipt is signed
in one runtime and verified in another, and the two disagree about field ordering or number
representation, the signature is either invalid or — worse — valid over a different logical object
than the verifier believes. Any Tier 1 claim in an agent system that spans runtimes depends on a
canonicalization the implementers agreed on explicitly.

---

<a id="7"></a>
## 7. Risk 4 — Trust boundary erosion

**The advisory's framing.** Trust boundaries are named as a category of concern, and **implicit
trust relationships** are named among the systemic risks.

**The mechanism, and why it is the hardest one.** In a multi-agent or multi-server deployment, an
agent invokes a tool that invokes a service that calls another agent. Each hop is individually
authorized. Nowhere in the chain does anything record that the fourth action is happening *on behalf
of* the first requester, under the first requester's authority, subject to the first requester's
limits.

Authority does not naturally diminish across delegation. Unless something forces it to, it
propagates at full strength, and a chain of individually reasonable authorizations composes into an
unreasonable one.

**Controls.**

| # | Control | Tier | Notes |
|---|---|---|---|
| 4.1 | **Delegation intersection.** Delegated authority is the intersection of delegator and delegate, never the union — enforced, not documented | 3 | The core control |
| 4.2 | **Principal binding through the chain,** so the originating principal is carried and checkable at every hop | 3 | Prevents laundering through intermediaries |
| 4.3 | **Explicit protocol state.** Authority carried in the request rather than held in an implicit session | 3 | ⚠️ Newly load-bearing — see below |
| 4.4 | **Token audience binding,** so a token for one server cannot be replayed at another | **1** | Addresses confused-deputy directly |
| 4.5 | **Depth limits on delegation chains,** with the limit expressed in the warrant | 3 | Crude, effective |

**⚠️ Control 4.3 changed meaning in July 2026.** The MCP specification revision of 2026-07-28 — the
largest since launch — moved the protocol core to a **stateless** model. Delegation designs that
relied on server-held session state for continuity of authority no longer have it. Authority must
now travel in the request or be lost between calls.

That is not a scaling change dressed as a security change; it is the reverse. In the same release,
**Enterprise-Managed Authorization moved from experimental to production-grade**, which is what
makes carrying authority explicitly viable. If your delegation layer was written before that
revision, it rests on an assumption the specification no longer makes, and the migration is a
security migration.

The revision also added normative security requirements covering token audience binding, token
theft, communication security, authorization-code protection, mix-up and confused-deputy attacks,
open redirection, and Client ID Metadata Document security. Controls 4.4 and 4.2 are now specified
rather than merely advisable.

---

<a id="8"></a>
## 8. Risk 5 — Agent misuse

**The advisory's framing.** Agent misuse is named among the categories of concern, alongside
**dynamic tool invocation** and **context sharing** as systemic risks.

**The mechanism.** This is the aggregate case: an agent used, deliberately or accidentally, to
accomplish something outside the intent of its deployment. It is not a single vulnerability, which
is why it is the hardest to control and the easiest to hand-wave. What makes it tractable is that
misuse is usually detectable *after the fact* and containable *during*, even when it is not
preventable *before*.

**Controls.**

| # | Control | Tier | Notes |
|---|---|---|---|
| 5.1 | **Tamper-evident action receipts.** Every consequential action produces a record whose integrity does not depend on the good faith of the party being examined | **1** | Detection and accountability |
| 5.2 | **Containment.** Override, suspension and deactivation, with in-flight actions accounted for | **2 + 3** | See below |
| 5.3 | **Deny-path audit.** Refusals logged as first-class events, not silently dropped | 3 | Refusals are the earliest misuse signal |
| 5.4 | **Behavioral bounds on the task,** not just on the tools — an autonomy perimeter | 3 | Requires the perimeter to be defined first |
| 5.5 | **Context isolation between tasks,** so shared context does not become a lateral channel | 3 | Addresses "context sharing" directly |

**On 5.1 — what a receipt proves, and what it does not.** A tamper-evident receipt proves that a
record existed, in a given form, at a given time, and that it has not been altered since. It does
**not** prove that the action was authorized, that the authorization was correct, or that the record
is complete. Its distinguishing property against ordinary application logging is narrow and
important: logs are maintained by the party being examined and can be altered by that party without
leaving a trace that survives the party's own tooling. That is not an accusation of bad faith; it
is a structural property, and it is exactly the property an examiner is trained to think about.

**On 5.2 — the failure mode nobody drills.** Containment is where stated capability and demonstrated
capability diverge most sharply. Survey work bears this out: the Kiteworks 2026 Data Security
Forecast, drawn from 225 security, IT and risk leaders across ten industries and eight regions,
reports that **60% cannot terminate a misbehaving AI agent quickly** and **63% cannot enforce
purpose limitations**. A separate enterprise survey reports 35% cannot shut down a rogue agent at
all.

The gap between those two figures is more instructive than either. *Cannot stop it* and *cannot stop
it quickly* are different questions, and the roughly one-quarter of organizations between them are
those that believe they have containment and have never timed it.

The specific thing that goes untested is **in-flight actions**. Credential revocation stops the next
action. It does not stop the one already executing, does not roll back the ones that completed while
the decision was being made, and does nothing about work left half-finished in a system with no
concept of a partial agent transaction.

**Containment is genuinely composite.** A revocation that a compliant client honors is Tier 1. A
proxy that refuses to forward is Tier 3. A kernel that will not let the process act regardless of
what the process wants is Tier 2 — and that one requires an OS boundary. A containment story that
does not say which tier it is operating at is not a containment story.

*One further caution from our own engineering, offered because it generalizes: our kill switch had
33 passing tests and a green workspace run, and still contained a contract breach on Windows — the
platform-gated code path had never executed in CI, which ran Ubuntu only. Coverage did not flag it,
because coverage measures the lines that ran on the platform that ran them. If containment is
platform-gated anywhere in your stack, test every platform you ship on.*

---

<a id="9"></a>
## 9. The coverage table, gaps included

Every control above, consolidated. **The four shaded rows are ours, not the industry's.**

| Advisory risk | Control | Tier | Warrantor status |
|---|---|---|---|
| Uncontrolled automated actions | Warrant-scoped invocation | 3 | Implemented |
| | Autonomy budget | 3 | Implemented |
| | Escalation gates | 3 | Implemented |
| | Deny-by-default tool registration | 3 | Implemented |
| | **Sandbox confinement** | **2** | ⛔ **Not provided — compose with a sandbox** |
| Absent input screening | Guard screening on tool output | 3 | Implemented, observe-only; see §5 caveats |
| | Provenance labeling | 3 | Partial |
| | Capability reduction after untrusted ingestion | 3 | ⚠️ **Designed, not implemented** |
| | **Egress filtering** | **2** | ⛔ **Not provided — requires network position** |
| | Content-addressed resources | 3 | Partial |
| Serialization | Schema-validated deserialization | 3 | Implemented |
| | No polymorphic deserialization | 3 | Implemented |
| | Size and depth limits | 3 | Implemented |
| | Canonical cross-language serialization | 1 | Implemented |
| | **Parser isolation** | **2 / unresolved** | ⛔ **Not provided** |
| Trust boundary erosion | Delegation intersection | 3 | Implemented |
| | Principal binding through the chain | 3 | Implemented |
| | Explicit protocol state | 3 | ⚠️ **Migration to the 2026-07-28 stateless core pending** |
| | Token audience binding | 1 | Implemented |
| | Delegation depth limits | 3 | Implemented |
| Agent misuse | Tamper-evident action receipts | 1 | Implemented |
| | Containment / kill switch | 1 + 3 | Implemented at Tiers 1 and 3; **Tier 2 requires composition** |
| | Deny-path audit | 3 | Implemented |
| | Autonomy perimeter | 3 | Implemented |
| | Context isolation between tasks | 3 | Partial |

**Four gaps, one cause.** Sandbox confinement, egress filtering, parser isolation and the Tier 2 half
of containment are all the same gap wearing four hats: **we do not implement an operating-system
boundary.** Every Tier 3 control in this table is bounded by the mediation ceiling, and the answer
is composition rather than a claim that the ceiling has been raised.

A composed system's guarantee is not the union of its parts' guarantees. For any action reachable at
the weaker tier, the composed bound is the weaker bound. Deploying a Tier 3 supervisor inside a Tier
2 sandbox produces meaningfully better coverage than either alone — the sandbox bounds what the
undeclared surface can reach, the supervisor explains what the declared surface did — but it does
not produce a Tier 2 guarantee everywhere.

---

<a id="10"></a>
## 10. A 30-day hardening sequence

Dependency-ordered, not calendar-ordered. Each step makes the next cheaper; inverting a pair
produces work that must be redone.

**Days 1–5 — Enumerate the action surface.**
Not the tool list. The action surface: process execution including descendants, filesystem
operations, network operations, credential access, and protocol-declared tool calls. Publish the
credential list explicitly. *Dependency: everything. You cannot bound what you have not enumerated,
and this is the step teams skip because it produces no artifact anyone wants to look at.*

**Days 6–10 — Measure mediation coverage.**
Run a defined workload with three independent observers: the agent transcript, the supervisor log,
and an OS-level tracer that catches descendants. Correlate on a single clock. Produce one number and
its decomposition by action class. *Dependency: the enumeration. Expect the process-execution class
to dominate the uncovered remainder.*

**Days 11–18 — Close the Tier 2 gap.**
This is the substantive work and it is infrastructure, not configuration: namespace and seccomp
confinement, egress filtering at a network position the agent cannot route around, parser isolation
where deserialization touches untrusted input. *Dependency: the measurement, which tells you which
of these to do first rather than all at once.*

**Days 19–24 — Warrant and budget the declared surface.**
Task-scoped warrants, autonomy budgets, escalation gates on irreversible classes, deny-by-default
tool registration, delegation intersection with principal binding. *Dependency: the sandbox. Warrants
without confinement bind only the well-behaved path, and you will not know that from your dashboard.*

**Days 25–30 — Drill containment and generate evidence.**
Time the stop. Account for in-flight actions explicitly. Verify receipts are produced for
consequential actions and refusals, and that their integrity does not depend on the system being
examined. *Dependency: all of the above. A drill before the controls exist measures nothing.*

**Deliberately not in the first thirty days:** dashboards, a governance framework document, vendor
selection. Each is legitimate work and each is cheaper after the measurement exists.

---

<a id="11"></a>
## 11. What the advisory does not say

Three omissions, each informative.

**It does not specify controls.** It describes risks and design considerations. That is appropriate
for the document's genre and it means the mapping in this paper is one reading among several
possible ones. Where I have inferred a control from a described risk, that inference is mine.

**It does not address the mediation ceiling.** The advisory is about MCP, and reasonably confines
itself to MCP. But "uncontrolled automated actions" cannot be fully addressed at the protocol layer,
because the most uncontrolled actions are the ones that never reach the protocol. A reader who
implements only MCP-layer controls in response to this advisory will have addressed the named risk
at exactly the layer where it is least tractable.

**It does not name an enforcement model.** It does not distinguish a control that a compliant client
honors from one a kernel imposes. That distinction determines what each control is worth against a
motivated adversary, and its absence is why §3 of this paper exists.

None of these is a criticism. An advisory that named specific controls would be a standard, and
standards for this technology are not yet written — NIST's own control overlays for single-agent and
multi-agent systems remain in development with no announced publication date, and NIST's analysis
concludes that existing SP 800-53 controls are insufficient for the orchestration loop, tool-use
chains and memory persistence that characterize these systems.

Which is the real situation. The risks are described by a national-security agency. The controls are
undescribed by anybody. Organizations are deploying anyway.

**That is not a reason to wait. It is the reason the mapping has to be done in public, by people who
will publish their own gaps, so it can be argued with rather than sold.**

---

<a id="12"></a>
## 12. Sources

**Primary**
- *Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation*, NSA
  Cybersecurity Information Sheet, 20 May 2026.
  https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF
- MCP Specification 2026-07-28 and its authorization section.
  https://blog.modelcontextprotocol.io/posts/2026-07-28/ ·
  https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- NIST, *Control Overlays for Securing AI Systems* (COSAiS) concept paper.
  https://csrc.nist.gov/csrc/media/Projects/cosais/documents/NIST-Overlays-SecuringAI-concept-paper.pdf
- OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10), released 9 December 2025.
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

**Survey data**
- Kiteworks 2026 Data Security Forecast (n=225 security, IT and risk leaders; 10 industries;
  8 regions). https://www.kiteworks.com/cybersecurity-risk-management/2026-data-security-forecast-ai-governance-predictions/

**Our own measurements**
Guard-model findings (§5) are from a controlled evaluation program whose harness, dataset manifests
and model bills of materials are released as a reproducibility package. The kill-switch CI finding
(§8) is self-disclosed; the fix shipped before publication.

---

## Production notes (strip before publishing)

**Status: publishable after four checks.**

1. **Read the CSI in full.** This draft is built on verified summaries of its findings, not on a
   full read. Every characterization in §2 must be checked against the document, and any normative
   statement must be quoted rather than paraphrased. **This is the blocking item.**
2. **Verify the coverage table against the codebase.** Twenty-five rows assert implementation status.
   Each needs checking; "Designed, not implemented" for control 2.3 and the pending 2026-07-28
   migration for 4.3 are the two most likely to be wrong in either direction.
3. **Add ASI identifiers.** Map each risk section to its OWASP ASI01–ASI10 identifiers. Free
   legibility with practitioners, and it costs one pass.
4. **Confirm the 35% figure's provenance** or cut the sentence. The 60% figure is fully attributed
   and carries the argument alone; the discrepancy is a bonus, not a dependency.

**What was deliberately left out.** No product pitch. No framework diagram. No claim that the four
gaps are closing. The credibility of this document is entirely in §9, and §9 works only because it
scores us honestly — an all-green coverage table would read as marketing and would be read that way.

**Related work to engage before publication.** `arXiv 2606.29073` (HCP — eight security invariants
with a reference runtime, benchmarked) is adjacent to §§4 and 7 and should be cited rather than
independently re-derived. `arXiv 2604.11790` (ClawGuard) is adjacent to §5. `arXiv 2603.22489`
(tool poisoning) is adjacent to §5 and §6.

**Cuts.** Substack flagship ~2,600 words: §§1, 2, 3, 4, 9, 11 — the argument plus the table. LinkedIn
~1,100: open on the strange sentence, the two named risks, the four gaps, close on §11's last line.

**Figures to build.** (1) Risk-to-control matrix, gaps shaded — §9 rendered as a graphic; this is the
piece's cover asset. (2) The 30-day sequence as a dependency graph, not a Gantt chart. (3) The
three-tier table from §3, which is reusable across the estate.

**Forward-links.** T-01 (the mediation ceiling, measured), the tier practitioner blog, T-08 (the
SP 800-53 overlay this argues is missing), B-04 (containment drilled), T-03 (the guard findings in
§5).
