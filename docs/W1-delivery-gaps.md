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

### 1.3 There is no first-run experience — **done**

The console now explains the empty store instead of showing an empty list. On a machine that has
never run `warrantor grant` it says what a warrant is, prints the grant line with a copy button, and
states plainly that granting is terminal-only *because* granting mints authority and holds the
issuer key — a boundary, not an unfinished screen. Leaving that unsaid made the product look broken
at exactly the moment a new reader was deciding whether it worked.

The change under the panel is smaller and matters more. One boolean —
`listEmpty.hidden = rows.length > 0` — used to render four different facts as one sentence. It is
now a total function over what the server actually answered, evaluated in this order:

1. **`error`** — the list route did not answer with `200`. First, because the response parse turns
   any errored or malformed body into zero rows, so without this rung a server-side failure would
   tell someone with a full store that they had never granted a warrant. Absence of an answer is
   not the answer "none".
2. **`rows`** — there is something to show, so nothing to explain.
3. **`unreadable`** — `unreadable_records > 0`. Counted over the store *before* the filter is
   applied, so it is a filter-independent proof that this store holds files. A store the server
   could not parse is not a store that has never granted, and saying otherwise would erase a
   history and bury a corruption warning in the same sentence.
4. **`filtered`** — a state chip is on. This is the bug named in this item's original text: a
   filter that matched nothing is not a machine with no history, and collapsing the two makes a
   chip look like data loss. The sidebar says so and offers one-click **Show all**.
5. **`first-run`** — unfiltered, zero rows, zero unreadable. The only case where "this machine has
   never granted a warrant" is a fact the response supports.

No `/v1` route was added or changed, and no `total` field was introduced. Distinguishing the states
by re-asking the server would make the console assert something the response it is rendering did not
contain, and would race the five-second poll. The state is re-derived on every poll instead, so the
panel clears itself within one tick of the first grant, with no reload.

The panel's copy about `--write` says what is true and not what would sound better: an out-of-bounds
write is contained at settle, never refused at the moment it happens (see 3.1). And it stays fixed
prose compiled into the binary — nothing store-derived may be templated into a document that is
served before the token check.

**One half of this is still open, and it is not a console problem.** On a machine that has never run
a warrant-touching command there is no issuer key, and `warrantor serve` refuses to start rather
than minting one — correctly, because a server that minted an identity on first use would sign
evidence with a key nobody chose. A brand-new user's first contact is therefore that CLI refusal,
which the browser never gets a chance to explain. The panel covers the keyed-but-empty store, which
is what a reviewer, a pruned store or an `mcp`-first setup presents. Covering the other half means
the packaged app (1.1–1.2) taking the user through key creation before it opens a window.

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
