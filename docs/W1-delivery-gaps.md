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

### 1.1 No installer has been built yet, and none of them will be signed

Two separable things, and the first was written here as finished when it was not.

**Packaging is configured, not exercised.** `.github/workflows/desktop-release.yml` and
`desktop/electron-builder.config.cjs` describe a Windows NSIS installer, a macOS dmg for both
architectures, and a Linux AppImage and deb, with an icon. **That workflow has never run** —
`workflow_dispatch` 404s until the file is on the default branch — and **no installer has been
produced, installed or launched on any platform.** The only build performed by hand was a Windows
`electron-builder --dir` run with a 17-byte dummy file standing in for the agent: an unpacked
directory, not an installer, and not a launch. The macOS and Linux legs have never been executed at
all, and the macOS leg was misconfigured for as long as this document called packaging done —
`identity: null` skips code signing rather than signing ad-hoc, and an invalidly-signed bundle does
not execute on Apple Silicon. That is the concrete cost of writing "done" here ahead of the
evidence, in the one document whose job is to prevent it. RELEASING.md step 1 is the dispatch that
resolves this, and it can only happen after merge.

**The signature is the second half**, and it is what remains once that dispatch is green: the code
signature, the notarisation, and the update channel — the last deliberately blocked behind the
signature, because an update channel over an unsigned artifact is an unauthenticated
code-execution channel.

Signing is the long pole: an unsigned binary is SmartScreen-blocked on Windows and Gatekeeper-blocked
on macOS, and a security product that asks a user to click through a "developer cannot be verified"
warning has taught them the wrong lesson on first contact. Needs an EV code-signing certificate and
an Apple Developer ID, both procurement rather than engineering. Exactly what to buy and the config
lines that change are written down in [../desktop/SIGNING.md](../desktop/SIGNING.md).

Until then, a tagged release publishes per-platform SHA256SUMS and a build-provenance attestation.
Those say where a file came from, not who stands behind it, and the difference is not papered over.

### 1.2 The desktop app bundles no agent — **resolver done, bundling unobserved**

Not "done", because half of this is configuration that has never been executed. See 1.1.

**Done:** the shell resolves the bundled copy first — ahead of `WARRANTOR_BIN` and ahead of `PATH`.
That is code in `desktop/src/policy.js`, and `node --test` gates it on every pull request. The
ordering is the security decision, not the bundling: verification happens only in Rust and only in
that binary, so substituting the binary substitutes the verifier, and an installed app must not be
silently re-pointed at a different one by an environment variable any parent process can set. There
is no fallthrough either — a missing bundled agent or a `WARRANTOR_BIN` that does not exist stops
the app with a message naming the path, rather than quietly running whatever is on `PATH`.

**Not observed:** that the `warrantor` binary actually arrives inside a produced app. The workflow
compiles it on the runner that packages it and asserts it is present and executable inside
`dist/`, and a packaging test asserts the builder config and the resolver agree on the name — but
the workflow has never run, so no installer has ever been shown to contain an agent, and no app has
ever been shown to start one. That last step is the one no gate can perform: RELEASING.md step 3
asks for an install on a machine with no `warrantor` on `PATH`.

### 1.3 There is no first-run experience — **done**

The console now explains the empty store instead of showing an empty list. On a machine that has
never run `warrantor grant` it says what a warrant is, prints the grant line with a copy button, and
states plainly that granting is terminal-only *because* granting mints authority and holds the
issuer key — a boundary, not an unfinished screen. Leaving that unsaid made the product look broken
at exactly the moment a new reader was deciding whether it worked.

The change under the panel is smaller and matters more. One boolean —
`listEmpty.hidden = rows.length > 0` — used to render four different facts as one sentence. It is
now two total functions over what the server actually answered. `listFacts` decides whether the
response established anything at all, and `emptyKind` picks a rung in this order:

1. **`error`** — the list was not read. Decided by `listFacts`, never by the status alone: a
   connection that was refused, a status that was not `200`, a body that did not parse, and a
   `warrants` field that is not an array all land here. First, because the optimistic read
   (`payload?.data?.warrants ?? []`) turns every one of those into the same zero rows as a genuinely
   empty store — which is how a 200 carrying a truncated body once told someone with a full store
   that they had never granted a warrant. Absence of an answer is not the answer "none".
2. **`rows`** — there is something to show, so nothing to explain.
3. **`filtered`** — a state chip is on. This is the bug named in this item's original text: a
   filter that matched nothing is not a machine with no history, and collapsing the two makes a
   chip look like data loss. The sidebar says so and offers one-click **Show all**.
4. **`unreadable`** — `unreadable_records > 0`, and no filter narrowing the view. This rung ranked
   *above* `filtered` in the first cut, and that was wrong: a store with five open warrants and one
   corrupt file, viewed under the Settled chip, was told "Nothing could be listed, but this store is
   not empty" — false, since plenty could be listed, and it carries no **Show all**, so it removed
   the way out as well. The count being filter-independent justifies knowing the store is non-empty;
   it does not justify a filter-independent *sentence*. Nothing is lost by the demotion: the warning
   row naming the count is written into the list whenever the count is non-zero, whatever the filter
   and whichever paragraph is showing below it.
5. **`first-run`** — a readable, unfiltered response with zero rows and zero unreadable. The only
   case where "this machine has never granted a warrant" is a fact the response supports.

A transport failure now reaches that first rung, which it could not before. `call()` used to throw
when `fetch` rejected — the likeliest way a loopback agent fails — `refresh()` swallowed the throw
in a bare `catch {}`, and a throw during `connect()` skipped `startRefreshing()` altogether, so a
dead agent produced a visible app with an empty list, every explanation still hidden, and no poll
that could ever recover it. `call()` now reports "no answer" as an outcome, the poll starts before
the first read rather than after it, and the console recovers on its own when the agent comes back.

No `/v1` route was added or changed, and no `total` field was introduced. Distinguishing the states
by re-asking the server would make the console assert something the response it is rendering did not
contain, and would race the five-second poll. The state is re-derived on every poll instead, so the
panel clears itself within one tick of the first grant, with no reload — and clears the detail pane
with it, so release controls for a warrant a pruned store no longer holds do not survive hidden and
reappear on the next poll.

The panel's copy about the bounds says what is true and not what would sound better. The lede
claimed "nothing it does is visible outside that copy" and "external effects are staged rather than
performed"; both were false and the second was checkable — `proxy.rs::decide()` forwards anything
whose class is not in `staged_classes` or whose tool is not in the effect registry, and a grant
seeds `Write` alone against four GitHub tools. The lede now names the three strengths from
`bound_strengths()` — enforced deadline and delegation, mediated tools and egress and staged
classes, observed paths and spend — says the broker is not a cage, and says Warrantor composes with
a sandbox rather than being one. The grant line gained `--repo .`, without which no worktree is
created at all and the paragraph above it described something that had not happened. And the panel
stays fixed prose compiled into the binary — nothing store-derived may be templated into a document
that is served before the token check.

These are behaviours, so they are now tested as behaviours. `rust/warrant/src/console/console.test.js`
runs under `node --test` — the runtime's own runner, no install, no bundler, no package manager, so
RFC W1 §Dependencies still holds — and boots `console.js` against a stubbed DOM and a scripted
server. Every fix above has a test that fails without it.

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

### 4.1 The guard is wired in as observe-only signals — **partly done**

The benchmarks land real numbers, and W1 fixes the boundary: a model judgement can become a
**refusal signal** recorded against a warrant, never a verification verdict.

That boundary is now wired. `rust/warrant/src/guard.rs` attaches a local guard model to a supervised
MCP session behind `warrantor mcp --agent <id> --guard`, records what it thought about each tool
call — with the model, its digest and every policy knob on every line — into
`<root>/guard/<id>.jsonl`, and reads back beside the refusals on the two existing `/v1` routes. See
[RFC W2](rfcs/W2-guard-signals-in-a-live-run.md).

What is still true: **it enforces nothing, deliberately.** At 0.8152 adversarial recall it would
miss roughly one adversarial case in five anyway, and its adversarial false-positive rate is 0.0923
— roughly one benign call in eleven — so an enforcing guard would train the operator to override it.
The enforcement path exists behind `--guard-enforce-untested-do-not-use`, is off, and is untested in
production. The backend is absent by default too: no `--guard` means no signals, and a guard that
cannot resolve its own model digest refuses to attach rather than emitting provenance-free
"evidence".

§4.2 and §4.3 below are unchanged by this.

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

The **substrate is real** and the **single-machine loop is complete**. Most of what is missing is
still what makes it a product rather than a tool: it installs but announces itself with an operating
system warning, it cannot be reached by a second person, and it cannot say who did what.

The ordering matters. Packaging (1.1–1.2) was the cheapest visible win and is now done to the point
where a reviewer can install and launch it; what remains of 1.1 is a purchase, not a build. But
**2.1 is the one that decides whether this is a product**, because multi-user oversight is the
claim, and today it is a claim the transport cannot support.
