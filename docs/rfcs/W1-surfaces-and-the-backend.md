# W1 — The surfaces, and whether Warrantor needs a backend

**Status:** accepted
**Date:** 2026-08-13
**Supersedes for the warrant architecture:** X7 (console), X11 (defstack-cloud) — see "What the
backend must not be".

This is the first RFC in the **W series**, which covers the warrant primitive. The existing
A/C/E/F/N/R/S/T/X series describe the twelve-plane component portfolio; none of them describe
`rust/warrant`, which is the spine the product now rests on. That gap is why this document exists.

---

## 1. What is actually built

Stated first, because the answer below is derived from it rather than from a plan.

| Surface | State | Evidence |
|---|---|---|
| **Local agent** | Real, ~10.9k lines | `rust/warrant` — grant, supervise, stage, settle, stop, spend, egress, MCP, and `warrantor serve` |
| **Browser console** | New (this RFC's companion change) | `rust/warrant/src/console/`, served same-origin from the agent |
| **Desktop app** | Did not exist | one mention of "electron" in the whole repo, in a `serve.rs` comment |
| **Web app** | Did not exist | `typescript/console` is a 263-line library modelling AARs, Rego policies and tenant-guard — a *different* architecture, consumed by nothing |
| **Model intelligence** | Real, in progress | `python/warrantor_ml`, `ml/` |

`warrantor serve` exposes twelve `/v1` routes over loopback HTTP. Exactly three mutate — `settle`,
`void`, `stop` — the three acts that require a human. There is deliberately no `grant` over HTTP.

## 2. The local agent is the authority, and stays the authority

Three properties in `serve.rs` are load-bearing, and everything below is shaped to preserve them.

**Grant never crosses the wire.** Grant mints authority and holds the issuer key. The moment it is
reachable over a network, warrant-minting authority lives in a network-reachable process.

**Verification happens only in Rust.** Every response carries a server-computed verdict; a client
renders `verified` and never derives it. A renderer that checked signatures itself would be a
second implementation of the verifier — and a second implementation can disagree with the first.
When two verifiers disagree, a human must decide which to believe, which is the exact situation
this product exists to prevent.

**There is no CORS header, ever.** One would let any page in the user's browser reach a loopback API
that can hold settle authority.

That last one decides the shape of the UI, and it is worth stating plainly because it forecloses
the obvious design: **a hosted web app can never talk to the local agent from a browser.** Not
"should not" — cannot, because the browser will block the cross-origin read and the correct fix
(adding CORS) is the thing that must not be done. So the browser client is served *by the agent
itself*, from `/`, same-origin. That is why the console assets are compiled into the binary.

## 3. Do we need a backend?

**Yes — for five things, each of which is physically impossible on one machine.** Not for
convenience, and not for any of the reasons a control plane is usually built.

1. **Multi-machine oversight.** `serve.rs` binds loopback. Its own docstring says multi-user
   oversight needs "a second person, a desktop application, a browser client" — but a second person
   *on another machine* cannot reach a loopback socket. Today that promise is false, and it is the
   core product claim.
2. **Trust anchoring.** `serve.rs` is explicit that a signature verifying "does not establish that
   the issuer should be trusted, **which has to come from somewhere else**." Which issuer key
   belongs to which human, and which keys an organisation accepts, is a directory. It cannot be
   local, because a local answer is one the audited party controls.
3. **Durable evidence custody.** Evidence in `~/.warrantor` dies with the laptop, and is held by
   the very person being audited. Regulated buyers need retention independent of them.
4. **Async approval routing.** Settle, void and stop require a human. Reaching a human who is not
   at that terminal requires something that outlives the terminal.
5. **Independent time anchoring.** `checked_at` is read from a clock the agent's own machine
   controls. "When did this happen" needs a countersignature from a party that is not the subject.

### What must never move server-side

Moving any of these collapses the trust model, and no amount of hardening compensates:

- **`grant`** — holds the issuer key. Already correctly refused over HTTP.
- **verification** — must stay in Rust, client-side.
- **the settle key** — release authority.
- **enforcement and containment** — process, filesystem and egress bounds are properties of the
  machine the agent runs on.

### Therefore: a relay, a directory, and an archive — not a control plane

The backend holds only **signed artifacts it cannot forge**. Every client re-verifies locally,
using the same Rust verifier, against a trust anchor obtained from the directory and pinned by the
operator. The design target is precise:

> **Compromise of the backend must degrade availability, never integrity.**

An attacker with full control of the server can withhold evidence, delay an approval, or serve a
stale list. They cannot forge a warrant, cannot make a tampered report verify, cannot mint
authority, and cannot release staged effects. If any of those becomes possible, the design is
wrong.

This has a pleasant consequence: the backend can be operated by a customer, by us, or by a third
party, in any jurisdiction, without changing the security argument. That is what makes it
compatible with sovereign deployments rather than a barrier to them.

### What the backend must not be

`go/defstack-cloud` (X11) is a multi-tenant SaaS control plane with per-plan GPU quotas and tenant
lifecycle management. It belongs to the twelve-plane architecture and is **not** the backend
described here. Adopting it would make the server an authority over tenants — precisely the
property this design forbids. The two should not be conflated because they are both "the cloud
bit".

## 4. The three surfaces, and why there are three and not one

All three are **viewers over the same local agent**, differing only in how they are launched and
what they can reach.

- **CLI** — the developer surface, and the only one that can `grant`. It is the trust root: a human
  at a terminal.
- **Browser console** — served same-origin by `warrantor serve`, token delivered in the URL
  fragment. This is the multi-user oversight surface, and it is what a reviewer opens.
- **Desktop app** — a shell around the same console, whose job is to remove the two steps a
  non-developer cannot be asked to perform: starting a daemon, and pasting a token.

The desktop app is deliberately thin. It does not reimplement the console, and it must not: a
second implementation of the viewer is a second thing that can misrender a verdict.

## 5. The three audiences

The surfaces map onto audiences, and the mapping is what decides what each one shows.

**Developers** get the CLI and MCP. They grant warrants, run agents under supervision, and read
reports. Everything is already available to them.

**Non-developers** (reviewers, operators, risk functions) get the desktop app and the console.
The design constraint is that they must never be asked to evaluate a signature. They are shown a
verdict computed in Rust, a sentence explaining what it means, and the three acts. Where the system
cannot answer, they see `unknown` — never a guess dressed as a fact.

**Decision-makers** get the archive and the summaries. Their question is not "is this warrant
valid" but "what did our agents do this quarter, and what did we refuse". That is
`/v1/summary/refusals` and `/v1/summary/daily` locally, and the aggregated archive centrally. This
is also the audience for whom the backend's independence matters most: evidence they can show an
examiner must not be evidence their own engineers could have edited.

## 6. Relationship to model intelligence

`python/warrantor_ml` is a separate concern and must stay separate. It produces classifiers and
evaluations — judgements about *content*. The warrant substrate produces evidence about *authority*
and *effects*. They meet at exactly one place: a model's judgement can become a **refusal signal**
recorded against a warrant, which is already the shape `record_refusals` expects.

The important boundary: **a model's output is never a verdict.** A refusal is evidence that
something was declined and why. Integrity remains an Ed25519 question with a three-valued answer,
and no classifier score is ever folded into it. Fine-tuning improves the quality of refusals; it
does not and must not touch the verification path.

## 7. Sequencing

1. **Browser console, same-origin** — done, this RFC's companion change.
2. **Desktop shell** — spawn or attach to the agent, pass the token, load the console.
3. **Backend, in the order the five needs bite:** evidence archive (custody) → directory (trust
   anchoring) → approval routing → time anchoring → fleet summaries.

Each backend stage ships only if a client can still verify without it. That test is what keeps the
relay from quietly becoming an authority.
