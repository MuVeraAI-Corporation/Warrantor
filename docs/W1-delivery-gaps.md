# What is still missing for a live end-to-end experience

Companion to [RFC W1](rfcs/W1-surfaces-and-the-backend.md). W1 says what the surfaces are and why
the backend is bounded the way it is. This says what is **not built**, ordered by what blocks a real
user first.

Written 2026-08-13, against the state of `main` plus the console and desktop work.

## What works today, end to end

Worth stating so the gaps are read against something real. A developer can grant a warrant, run an
agent under supervision in an isolated worktree, watch it from a CLI, a browser console or a desktop
window, read a signed report, and settle, void or stop it. Evidence exports verify offline on
another machine. That path is complete and tested.

Everything below is what stops that being true for someone who is *not* the developer who ran it.

---

## Tier 1 — blocks a non-developer using this at all

### 1.1 The desktop app is not packaged

`npm start` runs it from source. There is no installer, no `.exe`/`.dmg`/`.AppImage`, no code
signature, no notarisation, no icon and no update channel. A reviewer cannot install this.

Signing is the long pole: an unsigned binary is SmartScreen-blocked on Windows and Gatekeeper-blocked
on macOS, and a security product that asks a user to click through a "developer cannot be verified"
warning has taught them the wrong lesson on first contact. Needs an EV code-signing certificate and
an Apple Developer ID, both procurement rather than engineering.

### 1.2 The desktop app bundles no agent

It shells out to `warrantor` on `PATH`, or `WARRANTOR_BIN`. A reviewer has no `warrantor` binary,
so the app starts and immediately reports that it cannot find one. Packaging must ship the Rust
binary inside the app and prefer the bundled copy.

### 1.3 There is no first-run experience

The console assumes a store that already exists. On a machine that has never run `warrantor grant`,
the list is empty and nothing explains why, what a warrant is, or what to do next. An empty state
that says "no warrants" to someone who has never had one is indistinguishable from a broken app.

### 1.4 Nothing refreshes — **done**

The console now polls every five seconds, and re-renders the detail pane only when the selected
warrant's state actually changed: a five-second re-render would throw away the reader's scroll
position in the middle of a report bundle, which is the one document they are reading when they
decide whether to release an agent's work. Polling stops while the tab is hidden.

It is polling, not a change feed, because the read API has none — and `serve.rs` designed for
exactly that: "the consumer is one console polling at human speed". A real change feed remains
unbuilt, and would matter for a fleet view rather than for one machine.

---

## Tier 2 — blocks the multi-user claim, which is the product claim

### 2.1 No backend exists

None of the five needs in W1 §"Does this need a backend" is built: no evidence archive, no trust
directory, no approval routing, no time anchoring, no fleet summary. **`serve.rs` binds loopback,
so a second person on another machine cannot see anything at all.** The console makes oversight
usable for someone at the same keyboard, which is not the claim.

This is the largest single gap in the product, and everything in Tier 3 assumes it.

### 2.2 No identity, no per-person authorisation

There is one bearer token per server run, unscoped. Everyone who has it is the same principal, and
the audit trail cannot say which human settled a warrant — only that someone holding the token did.
`serve.rs` names this: the token "is a single unscoped value, and scoping it the same way is the
right next fix."

### 2.3 No TLS anywhere

Stated plainly in `serve.rs`: the token protects access, not bytes on the wire. Loopback makes that
acceptable today and unacceptable the moment anything binds beyond it. `--bind` already warns.

### 2.4 The agent can reach the API

Documented and not fully fixable under a same-UID model: the supervised agent can read the token
file and call the API. The mitigation is that `--allow-settle` is opt-in, so a stolen token yields a
viewer. Closing it properly needs the act-scoped capability tokens `daemon.rs` already uses, applied
to this surface.

---

## Tier 3 — needed before anyone trusts this with real oversight

### 3.1 Bounds are weaker than they read

Per [[three enforcement tiers]]: `write_paths` and `budget_cents_observed` are **Observed**, not
enforced. There is no netns, no seccomp and no firewall. The console shows `bound_strengths`
honestly, but "the agent is bounded" is a stronger sentence than the system currently earns without
composing with a real sandbox.

### 3.2 No notifications

Approval routing (2.1) is inert without a way to reach a human who is not looking at the window. No
email, no webhook, no push.

### 3.3 No multi-machine or multi-repo view

`/v1/summary/daily` covers one store on one machine. A decision-maker's question — "what did our
agents do this quarter" — has no surface at all.

### 3.4 No retention or export policy

Warrants accumulate in `~/.warrantor` forever. Nothing prunes, archives, or answers a data-retention
question, which is the first thing a regulated buyer asks.

---

## Tier 4 — model intelligence

### 4.1 The guard is measured but not wired in

The benchmarks land real numbers, and W1 fixes the boundary: a model judgement can become a
**refusal signal** recorded against a warrant, never a verification verdict. But nothing calls the
guard during a run. `record_refusals` exists; the classifier is not connected to it.

### 4.2 No fine-tune has been run

The benchmarks establish a baseline and identify the target — `Unqualified Professional Advice` at
0.4298 recall, and the adversarial FPR quadrupling. Neither has been acted on. No adapter has been
trained, and the parity gate in the model foundry has not been exercised on this task.

### 4.3 No non-developer surface for model intelligence

Decision-makers cannot see refusal quality at all. The console shows refusals per warrant; there is
no view of "what our guard caught and missed this month", which is the form the question actually
takes.

---

## The honest summary

The **substrate is real** and the **single-machine loop is complete**. What is missing is nearly
everything that makes it a product rather than a tool: it cannot be installed, cannot be reached by
a second person, and cannot say who did what.

The ordering matters. Packaging (1.1–1.2) is the cheapest visible win and unblocks any user
research. But **2.1 is the one that decides whether this is a product**, because multi-user
oversight is the claim, and today it is a claim the transport cannot support.
