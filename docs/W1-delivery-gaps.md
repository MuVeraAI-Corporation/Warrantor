# What is still missing for a live end-to-end experience

Companion to [RFC W1](rfcs/W1-surfaces-and-the-backend.md). W1 says what the surfaces are and why
the backend is bounded the way it is. This says what is **not built**, ordered by what blocks a real
user first.

Written 2026-08-13 against the state of `main` plus the console and desktop work. **Revised
2026-08-14, after PRs #37–#41 merged**, which changed enough of this document to make the
unrevised version misleading. What those five landed, and what each did *not* close, is marked
inline. The revision itself is the discipline §1.1 names: this document's job is to be the one
place that does not say "done" ahead of the evidence, which it can only do if it is re-read
against `main` every time `main` moves.

## What works today, end to end

Worth stating so the gaps are read against something real. A developer can grant a warrant, run an
agent under supervision in an isolated worktree, watch it from a CLI, a browser console or a desktop
window, read a signed report, and settle, void or stop it. Evidence exports verify offline on
another machine. That path is complete and tested.

Everything below is what stops that being true for someone who is *not* the developer who ran it.

---

## Tier 0 — the boundary could not be reached by anything that was not already ours

### 0.1 The MCP proxy could not forward — **fixed**

This gap was in no earlier revision of this document, and its absence is the finding.

`proxy::decide()` has returned `Decision::Forward` since the proxy was written. `AgentEndpoint`
answered that decision with an error telling the operator to *"start the agent endpoint with
`--upstream <command>`"*, and **`--upstream` did not exist anywhere in the binary.** Grep for it and
the only hit was the sentence recommending it.

What that cost, stated plainly: of everything an agent could ask a warranted session to do, exactly
four calls worked — `github.create_pr`, `github.comment`, `github.request_review`,
`github.add_label`, the effects `EffectRegistry::github()` knows how to stage. Every other tool the
warrant permitted came back as a failure whose remedy could not be performed. `tools/list` published
the warrant's tool *names* with `{"type":"object","additionalProperties":true}` — no properties, no
required fields — so a model could not have composed a correct call even to a tool that worked.

It has every marking of the [[wire before widen]] pattern this document already names three times,
with one addition: this one was **covered by a passing test**. The test asserted that the arm
returned an error, and the error it returned instructed the reader to do something impossible.

It is fixed. `rust/warrant/src/upstream.rs` is a synchronous MCP client over a child process's
stdio; `--upstream 'name=command args'` is repeatable; the upstream's real schemas are published;
an ungranted tool is not published at all under enforce; and an upstream that publishes warrant
lifecycle verbs is refused at attach, because pointing an agent at "the warrantor MCP server" has
two answers and one of them hands the supervised agent the authority to settle its own warrant.

Two things this does **not** fix, and they are why §3.1 still reads as it does:

- **Forwarding mediates MCP, and MCP only.** Every terminal coding agent ships file, edit and shell
  tools of its own that never traverse an MCP server. Wiring one is worth real things — the
  deadline, the worktree, the staged effects, the evidence, the OS lifetime link, and mediation of
  every MCP tool it uses — and it is not mediation of `bash`.
- **An unknown tool's side-effect class was guessed — now declarable, and refusable.** Anything the
  effect registry does not know was classed `Read` and forwarded, so an upstream `write_file` was
  performed rather than staged: a guess with exactly one reachable answer until forwarding existed,
  and load-bearing the moment it did. `--upstream-class '<tool>=read|write|destructive|financial'`
  replaces the guess with a statement and `--upstream-refuse-unclassified` fails closed. The
  registry still wins over a declaration, because those four tools are the ones the settle path can
  actually perform. Tools decided by the fallback are **named** at the end of a session — a count is
  not something an operator can act on; the names are the work list. Still true: the staging
  boundary covers four GitHub effects and nothing else.

### 0.2 Nothing pointed a real harness at the endpoint — **fixed, and what it replaced was worse**

There was an integration surface before this: `warrantor-harness config --agent
claude_code|codex|cursor` wrote `CLAUDE.md`, `AGENTS.md` or `.cursorrules` containing sentences like
*"Every action is recorded as an Agent Action Receipt"*, *"Secret exposure triggers kill-switch
(invariant I-09)"* and *"File access is tracked and logged"*.

Nothing in the system made any of those true. They were **instructions to a model** — a security
boundary written into the context window while the substrate permitted whatever it permitted, which
is the failure mode the README's five frontier-lab intrusions all share and the reason this product
exists. That is a worse class of defect than a missing feature: it is a false claim, generated by
us, into the file the agent reads first.

`warrantor agents` replaces it. Sixteen harnesses, each carrying the MCP client configuration that
actually routes calls through `warrantor mcp --agent <id>` **and** a coverage class stating what
does not go through it. `agents show <harness>` names the escaping tools. Aider, which has no MCP
client, gets a refusal and an explanation rather than a config file.

Still open here: the Python `warrantor-harness config` subcommand has not been removed, so the old
generator remains reachable by anyone who finds it first.

---

## Tier 1 — blocks a non-developer using this at all

### 1.1 No installer has been built yet, and none of them will be signed

Two separable things, and the first was written here as finished when it was not.

**Packaging is exercised, not observed.** `.github/workflows/desktop-release.yml` and
`desktop/electron-builder.config.cjs` describe a Windows NSIS installer, a macOS dmg for both
architectures, and a Linux AppImage and deb, with an icon. **The workflow has now run** — first
dispatch 2026-08-15, dry-run, run 31875701622: all four packaging jobs (mac x64, mac arm64,
linux x64, win x64) green in 4–6 minutes each, the run carrying one installer artifact per
platform (win 101 MB, mac ~243 MB per arch, linux ~230 MB). Still not done: no installer has been
**installed or launched** on any machine, and every artifact is unsigned. The only build performed by hand was a Windows
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

### 1.2 The desktop app bundles an agent, and has been seen to start one — **observed**

Not "done", because half of this is configuration that has never been executed. See 1.1.

**Done:** the shell resolves the bundled copy first — ahead of `WARRANTOR_BIN` and ahead of `PATH`.
That is code in `desktop/src/policy.js`, and `node --test` gates it on every pull request. The
ordering is the security decision, not the bundling: verification happens only in Rust and only in
that binary, so substituting the binary substitutes the verifier, and an installed app must not be
silently re-pointed at a different one by an environment variable any parent process can set. There
is no fallthrough either — a missing bundled agent or a `WARRANTOR_BIN` that does not exist stops
the app with a message naming the path, rather than quietly running whatever is on `PATH`.

**Now observed on Windows — the app has been packaged, launched, and shown to start its own
bundled agent.** A release `warrantor.exe` was staged into `vendor/x64`, `electron-builder --dir`
produced `dist/win-unpacked`, and the app was launched with `PATH` scrubbed to `C:\Windows\system32`
and `C:\Windows` — nothing on it that could supply a `warrantor` other than the copy inside the app.
The trace records the whole chain:

```
agent binary: ...\dist\win-unpacked\resources\warrantor.exe (bundled with the app)
agent ready on http://127.0.0.1:61803
window constructed
console loaded
tray skipped: no icon          <-- the defect
```

So the packaged app **does** contain an agent, **does** resolve the bundled copy ahead of `PATH`,
starts it, and loads the console. The token was redacted in the forwarded output, as `redactToken`
intends.

**That last line is the find, and no unit test could have produced it.** `build/` is
electron-builder's own *resources* directory — read at build time to make the window and installer
icons, and **not copied into the app** — so the path `installTray` opens exists in development and
does not exist in a packaged build. `installTray` skips silently when the image is empty, which is
right for a missing icon and wrong here: the tray shipped earlier the same day and had never
appeared in a packaged build. Every packaging test asserts against the *config*, and the config was
correct for the build and wrong for the runtime.

`build/icon.png` is in `files` now, with a test asserting the overlap — the file the runtime opens
must be in the list the packager copies — and a second packaged launch confirms it: the
`tray skipped` line is gone. Found and fixed by the same method, which is the argument for the
method.

**The installer itself has now been built locally too**: `Warrantor-1.0.0-x64-setup.exe`,
101,239,598 bytes, sha256 `f7f6cd68517de7d01929579c6bdee5bcb938e3bd0c1cd99bd8a170d0d3b151d2`, a
valid NSIS PE. One local finding came with it, and it is about the *pipeline* rather than the
product: electron-builder derives the `.ico` at build time with a **WebAssembly** icon tool, and on a
memory-pressured Windows box that step dies with `WebAssembly.Memory(): could not allocate memory` —
after the app has packaged, so the failure lands on the last step of a long build. Passing a
pre-generated `.ico` on the CLI got past it. The committed config was deliberately **not** changed:
the OOM is a machine being short of memory, not a defect, and committing a binary `.ico` would
contradict `build/make-icon.mjs`'s own reason for existing ("a binary in the source tree that nobody
can diff is a small version of the problem the whole product is about"). Worth knowing before a
release is cut on a small runner.

**Still not observed:** the installer being *run*. Two separate reasons, and neither is engineering.
Executing an installer is a system-changing action that this repository's own tooling gates, and
correctly so. And the step RELEASING.md actually asks for is an install on somebody *else's* machine
— which no automation can stand in for, because the point of it is whether the packaging assumption
holds somewhere this repository has never been.

What *is* now established, and was not before: the app packages, the bundled agent arrives inside it,
the resolver prefers that copy over an empty `PATH`, the agent starts, the window opens, the console
loads, and the installer builds into a valid NSIS artifact with a recorded digest. The residue is one
double-click by a person.

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

### 2.1 The approval loop is closed — **a second person can now be told, and can decide**

**2026-08-17.** This was the section that read "the one that decides whether this is a product",
because multi-user oversight is the claim and the transport could not support it. It can now.

The gap was never the *deciding*. §2.2 built scopes, a hash-chained actor log, a two-person rule
and a settle gate that reads all three. Every one of those assumed the reviewer already knew the
warrant existed and needed them. **Nothing told them.** `notify.json` fired on `settled`, `voided`,
`stopped` and `filing-queued` — four events that are all *after* a decision, and none that says one
is wanted. By the time `settled` arrives the moment to look has passed.

Three commits closed it:

- **`warrantor queue` and `GET /v1/queue`** (`rust/warrant/src/review.rs`). Derived from warrant
  state, the approval policy, each actor log and the registry — there is no `queue.json`, because
  every second copy of the truth in this codebase has eventually disagreed with the first. Rendered
  **per caller**: `you_can` names only acts this principal could actually take, and
  `tests/review.rs` asserts the queue and the settle gate agree at every step *against the gate
  itself* rather than against a second copy of its rules.
- **`--notify`**, raising a fifth event, `review-requested` — the only one that fires *before* a
  decision. It announces **transitions, not states**: a warrant moving from `awaiting-approval` to
  `awaiting-decision` is news and is announced again, which a plain "already notified" flag would
  have suppressed.
- **The console's "Waiting on you" destination**, so the second person in the sentence does not
  have to be at a terminal. Verified in a real browser across three operators with the two scopes
  separated.

**Deadlock is a first-class answer.** A store can be configured into a policy no set of people can
satisfy, and `approval_verdict` refuses each attempt with a sentence about what is *missing* —
which reads as "not yet" rather than "not ever". Three cases are now named with their own remedies,
including the one that surprises people: two operators holding both scopes with `required: 2` is
deadlocked, because satisfying the count consumes both and leaves nobody to settle.

**A defect this found.** `approval_verdict` refuses any settle whose log holds an anonymous
approval when `required > 1`, and it reads the *log*, not the registry — so one `warrantor approve`
typed at a terminal trips it on a fully registered store, and because the log is append-only it can
never be untripped. The warrant becomes settleable never, voidable only. The queue reports it as
deadlocked and the CLI now **refuses** the act rather than performing it and printing a caution
afterwards. What shipped told the operator they had achieved nothing; they had achieved worse.

---

### 2.1b The archive: one of five backend needs is built, and the agent can reach it — **stage 1 wired**

PR #40 landed `rust/archive` (`warrantor-archive`): a self-hosted, append-only, content-addressed
custody store for the three signed evidence files `warrantor verify` already reads, on Postgres,
behind device-pairing auth. It reuses `warrantor-warrant`'s verifier rather than reimplementing
one, stores and returns bytes verbatim, and never serves a verdict. Its design target —
*compromise degrades availability, never integrity* — is a falsifiable claim with a test that
asserts it (`tests/verification_does_not_depend_on_the_archive.rs`).

**For one release nothing sent it anything.** There was no client: no `warrantor` subcommand, no
agent hook, no console action, and nothing outside `rust/archive` could produce a `Warrantor-Device`
header at all — so the `curl` the deployment README documented could not be typed by anybody, and
`submitted_by_device` had never named a person outside a unit test. That was the [[wire before
widen]] failure this repository had by then made three times: the ~20 substrate crates orphaned from
the warrant, the guard benchmarked but not wired, and then this.

**It is wired now.** `warrantor archive enrol` pairs a machine against a one-time code and writes a
device key beside the issuer and settle keys; `warrantor archive push <file>` files bytes verbatim;
`warrantor archive fetch <sha256> --out <path>` reads one back — reads are signed too, which is the
other reason `curl` was never enough; `warrantor archive list <warrant-id>` enumerates what is held
about one warrant, newest first, with each artifact's full digest — the address `fetch` takes —
because `push` prints a digest exactly once and an operator whose scrollback is gone could not
otherwise even find out what they filed; and `--archive` on `report`, `stop` and `spend` files the
file `--export` just wrote. **Automatic push on settle exists**: `warrantor archive auto settle`
records the policy in the pairing record, and every CLI settle builds the final report export and
files it — a filing that fails does not fail the settle (the warrant's state is a local fact), it
is printed in its own block and queued in `archive/pending.jsonl`, retried at the next settle, and
dropped loudly if the bytes it promised changed underneath it. There is deliberately no daemon
retrying the queue — the next settle is the retry point — and the HTTP settle surface does not
auto-file yet; the policy is read by the CLI alone. The signing half of the wire contract moved
into `rust/warrant/src/archive_client.rs` so there is one definition of it rather than two, and the
archive re-exports it: the dependency edge still runs archive → warrant, and the agent is still
tokio-free. `warrantor-archive revoke --device <id>` landed with it, because issuing long-lived
device keys with no way to withdraw one is not a credential system.

**A local trust directory exists.** `warrantor issuer add <name> <hex>` pins a name to an issuer
key, checked out of band, into `trusted/issuers.json` under the store root; `verify --issuer <name>`
resolves the pin and every verdict prints **which anchor it used** — the pinned name and when it was
pinned, or "given on this command line" for the raw-hex form. Re-pinning a name to a different key
refuses without an explicit `--replace` that prints both keys, because two keys under one name is
exactly what an attacker who cannot forge signatures wants instead. This is deliberately **local,
TOFU-with-pinning, no network**: a directory that hands out keys over the network is a new trust
root, and that design decision has not been made. What remains open is everything beyond one
machine — a signed or shared directory, rotation, and who vouches for a name the first time in an
organisation.

What is still missing here: TLS.

**The other four needs are now built, and each took the shape that adds no trust root.**

- **Fleet summary** — shipped at the custody level (§3.3).
- **Approval routing** — shipped (§2.2b), on top of the named operators in §2.2, which is what it
  was waiting for: a requirement of "two approvers" is meaningless without principals that can be
  told apart.
- **Time anchoring** — shipped as `anchor.rs` and `warrantor anchor show|verify`. Not one of the
  three options previously written down here. An RFC 3161 authority, a transparency log and
  countersigned archive times all buy *absolute* time and all cost a new trust root or new
  infrastructure. What shipped instead is a per-store append-only hash-chained ledger that
  establishes **relative order** — if A precedes B in the chain, A was signed first, whatever
  timestamps either carries — and makes a **clock that went backwards visible** as a fault of its
  own kind. The bridge to absolute time is deliberately a human step: the head digest is
  publishable, and pasting it into a commit message or a ticket binds everything before it to a
  clock somebody else keeps. What it does not establish is printed under every rendering.
- **Trust directory** — shipped as `bundle.rs` and `warrantor issuer export|import`: a *carried
  signed file* rather than a queried service. A bundle is one machine's pins signed by that
  machine's issuer key, and it can only be imported against a key the importer had **already**
  pinned out of band. One out-of-band check buys everything the signing machine trusts; the trust
  root stays an Ed25519 key a human checked, and only the fan-out improves. A local pin is never
  overwritten by a bundle, imports are not transitive, and there is no revocation channel — because
  a channel is a service, which is the thing being refused. Every import says all three.

What is still missing here: **TLS**, and a second person on another machine still cannot reach a
loopback bind — see §2.3, where the bind is now fail-closed rather than merely warned about.

This remains the largest single gap in the product, and everything in Tier 3 assumes it.

### 2.2 Identity and per-person authorisation — **built**

For every release before this one: one bearer token per server run, unscoped. Everyone holding it
was the same principal, `--allow-settle` was all-or-nothing, and the audit trail could not say which
human settled a warrant — only that someone holding the token did.

**Built.** `warrantor operator add <name> --scope read,stop,settle,approve --note "..."` registers a
named principal holding its own token. Four scopes, separated because the person you want able to
stop a runaway agent at 3am is not necessarily the person you want able to release its work. Tokens
are stored as SHA-256 and printed exactly once: a registry that could reprint one would be a
credential store whose single theft hands over everything in it. The registry is read **per
request**, not at startup, so `operator remove` takes effect on the revoked operator's next request
— a revocation needing a restart is one nobody performs during an incident.

Every settle, void, stop and approve is appended to `actors/<warrant-id>.jsonl`, hash-chained,
naming the operator — or recording `null` when there was none, because inventing a name is worse
than admitting there is none. Verified end to end over HTTP: an approve-scoped operator is refused a
settle, a settle-scoped one is refused an approve, and a two-approval policy refuses the settle
until two *distinct named* approvers have recorded one.

**Not done, and the reason differs in each case.**

- **The actor IS now in the signed evidence envelope — and it needed no format bump.** This was
  deferred twice on the premise that it required one. It did not: `bundle_digest` is a SHA-256 over
  the canonical bundle and both receipts commit to it, so a new field is *automatically* inside the
  signature. `ReportBundle.custody` carries the actor log's head digest and its counts. Editing who
  approved breaks verification; that is what putting it there bought.
  - **The head, not the acts.** The head makes a later copy of `actors/<id>.jsonl` checkable against
    a signature taken now. Copying the acts in would put operator names inside an artifact handed to
    third parties — which is why the MCP control endpoint passes `None` deliberately: its report is
    a tool result an *agent* reads.
  - **`skip_serializing_if` is load-bearing**, and writing this found that `spend` lacks it.
    `bundle_digest` hashes a *re-serialisation*, so a `None` field that emits `"spend": null` changes
    the digest of every export written before that field existed — those reports stopped verifying
    the day it landed, silently. `custody` skips instead. `spend` is left alone and the asymmetry is
    documented: adding the skip there would repair the pre-`spend` population and break the
    post-`spend` one, and no change satisfies both.
- **A token authenticates a token, not a person.** The name is bound to a human out of band by
  whoever minted it — the same trust-on-first-use posture `warrantor issuer add` takes for issuer
  keys — and `--note` is required because that binding is the only thing making the name mean
  anything. Every rendering carries the caveat.
- **The session token still works, unscoped**, and must: otherwise registering an operator would
  lock out whoever started the server.

### 2.2c The surface for it — **built, and it was nearly the fifth wire-before-widen**

§2.2 and §2.2b recorded who acted and gated a settle on it, and for one commit gave both **no
viewer**: the console could not show an approval and could not record one. That is the pattern this
document names four times, made against a change from the same session.

`GET /v1/warrants/<id>/custody` returns the acts, the distinct approvers, what the policy requires,
and whether the chain holds — **checked server-side and reported as a value**, because a console
that verified the hash chain itself would be a second implementation of a check. The console renders
it as a standing with five kinds (unreadable, chain-broken, no-requirement, met, short), because
collapsing any two of them tells a reviewer they are done when they are not, and a broken chain
outranks everything: a store whose record of who acted has been edited must not report "approved" on
the strength of that record.

An anonymous actor renders as a sentence and never as a name. The store deliberately declines to
invent a principal; a placeholder here would invent one on its behalf.

### 2.2b Approval routing — **built on top of 2.2**

`approvals.json` (`required`, `settler_may_approve`) and `warrantor approve <warrant-id>`. A settle
is refused until the requirement is met — **on the CLI path as well as the API path**, because
gating only the console would have made the mechanism decorative: the same person could settle from
a terminal on the same machine. By default the settler does not count as an approver. Anonymous
approvals cannot satisfy a requirement above one, because every terminal caller on one machine is
the same unnamed principal and they cannot be told apart; the refusal names that and names the
remedy. A **void is never gated** — discarding staged work is the safe direction, and requiring
review to throw a runaway's output away would leave its staged effects queued while approvals are
collected.

Notifications (§3.2) already exist, so a human who is not watching the window can be told a decision
is waiting. What is still absent is any *routing* of that decision to a particular person: the
webhook fires, and who picks it up is an organisational question this build does not model.

### 2.3 TLS — **built behind a feature; the bind is fail-closed without it**

There is still no TLS. The token protects access, not bytes on the wire.

What changed is the default. A bind beyond loopback used to print a thorough warning and start the
server anyway; it is now a **refusal**, and the acknowledgement is
`--i-accept-cleartext-on-this-network`, named after what it admits rather than what it enables. The
argument is not about how loud a warning is: the token crosses in the clear on every request, a
warning is read once by the person who typed the command and then their terminal closes while the
server keeps running, and an intercepted token produces no incident to notice — the traffic is well
formed, the token is valid, and until §2.2 the audit trail could not say which human acted. The
refusal is checked before the keys are loaded and before a token is minted, so a refused bind leaves
no token file behind.

**And TLS is now built**, behind a feature that is off by default — `--tls-cert` / `--tls-key`,
verified end to end at TLS 1.3 with `TLS_AES_256_GCM_SHA384`.

The reason it had been deferred turned out to be false, and that is the more useful finding.
"Adding a TLS stack to a seven-dependency crate" was the objection; **`rustls` was already in the
tree**, pulled by `ureq`'s `tls` feature since the archive client existed. Terminating TLS here
compiles code that was already being compiled and adds nothing to `Cargo.lock` but a PEM parser. The
dependency decision had been taken by a client dependency, in a direction nobody had written down,
and the premise was checkable in one grep. Deferring on a false premise is worse than deciding
either way.

Four decisions in it: a failed handshake gets **no reply** (writing an HTTP error onto a socket the
client expects encrypted would send a server-generated message in the clear to something that may
not be the client); the handshake completes on the accept thread, so a failure costs one connection
rather than a worker slot; `--tls-cert` and `--tls-key` are both-or-neither; and a build without the
feature **refuses** the flags rather than ignoring them.

What it still does not do, and the startup line says so: no certificate is issued, renewed or checked
for name, and no client certificates are required. It encrypts the transport. It does not establish
who this server is to a client — that depends on what the client already trusts, and a self-signed
certificate is indistinguishable from an attacker's until somebody pins it. A reverse proxy remains
a perfectly good answer.

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

### 3.2 Notifications — **webhooks ship, every surface fires them; email and push do not exist**

**What exists:** `notify.json` in the store root names webhook destinations (optionally with an
HMAC-SHA256 secret, so a receiver can tell Warrantor's POSTs from anyone else's), and the CLI
fires them when a warrant settles, is voided, is stopped, or when an automatic filing failed and
was queued — the one event an off-site overseer most needs pushed at them. A delivery failure
never fails the action that caused it: it prints its own block and queues in
`notify/pending.jsonl`, retried at the next notification. What leaves the machine is the event,
the warrant's id, goal, subject, state and a timestamp — never evidence bytes, never tool
arguments. A machine with no `notify.json` sees byte-for-byte today's output.

**Closed 2026-08-17.** Two of the three gaps this section listed are gone.

*Notifications from the HTTP/console surface.* `serve.rs` held zero references to `notify`: a
settle, void or stop over HTTP fired nothing at all. That was survivable while the API was a read
surface with three write routes nobody used interactively, and stopped being survivable the moment
§2.1 put Approve and Settle buttons in the console — the browser became the *expected* place to
decide and was the one place that went silent. `StoreApi::with_notifier` closes it with a plain
function pointer, exactly like `performer`: the library decides *when* and the binary owns *how*,
because `rust/warrant` carries no HTTP client and is not getting one. Payloads are byte-identical
to the CLI's, since a receiver must not be able to tell which surface a decision was taken from.

*Approval routing.* Closed by §2.1, and the `review-requested` event is the webhook that says a
warrant needs a decision — now that there is a decision to make and a way to make it from where
the notification lands.

**What is still missing:** email and mobile push. A webhook can front both, and nothing here speaks
them directly.

### 3.3 No multi-machine or multi-repo view — **the custody-level half shipped**

`GET /v1/summary` at the evidence archive — and `warrantor archive summary` on the client —
answers the part of the decision-maker's question an evidence relay can answer honestly: **what
reached custody** — artifacts, warrants, devices, first and last filing, by kind, by device,
computed from the same store read the per-warrant listing uses so summary and listings can never
disagree. It is authenticated like every route, an unreadable store refuses rather than
summarising as zero, and the render says in its heading and its footer that it is an account of
custody records, not a verdict: "what did our agents file, from where, when" is answerable; "what
did our agents DO" is a question about evidence, answered by fetching and verifying it.

What is still missing: per-repo views (nothing records which repository a warrant ran against
beyond the warrant record itself), time-bounded queries (the summary is all-time; the signature
covers the path and no archive route reads a query parameter — a deliberate limitation until a
route design takes that on), and any aggregation of local-machine data (`/v1/summary/daily`
covers one store on one machine, unchanged).

### 3.4 Retention — **the inventory and the prune both ship; `logs/` is covered**

`warrantor holdings` now answers "what do you keep, where, and how much of it": every one of the
twenty locations the store writes to, what each contains, whether it is signed and hash-chained, how
many files and bytes, how old the oldest is, how many could not be read (counted separately, never
folded into the total), plus the warrants by state and by recorded subject, and the worktrees that
are still on disk in each repository.

Three things it makes visible that nothing reported before:

- **Deleting is not uniform.** `stops/`, `spend/` and `daemons/` decide a verdict by their own
  existence — remove a stop record and the notary's containment gate goes from deny to pass; remove a
  ledger and a spent budget resets to zero; remove a completion record and a finished run reads as
  unsupervised. Removing one of those changes an answer rather than losing one, and `holdings` labels
  them `FLIPS-VERDICT`.
- **`settle` never removes a worktree** — only `void` does (`settle.rs` calls `Worktree::remove`
  from `void`/`void_on_breach` only). Settled worktrees accumulate in every repository a warrant was
  granted against; `holdings` counts them.
- **`logs/<id>.log` is the class most worth a window and the one with no integrity consequence**:
  raw agent stdout and stderr, unsigned, in no evidence bundle, and the most likely to hold source,
  prompts and secrets. It is `NoIntegrityConsequence`, so `warrantor prune` deletes it under a
  `retention.json` window — verified against a backdated log. That heading said "nothing prunes"
  for longer than it was true.

**Three classes were added on 2026-08-17 and the inventory had to grow with them.** `actors/`,
`runs/` and `reviews/` are store locations `holdings` did not know about, which would have made its
"every location" claim quietly false. The compiler is what caught it: `ArtifactClass` is matched
exhaustively in four places, so a new variant cannot be added without stating what it holds, where,
and what deleting it costs. `actors/` and `runs/` are `LosesEvidence` — deleting a run record makes
an unguarded run indistinguishable from one that never happened, which is the exact confusion
`runs` was added to end. `reviews/` is the one genuinely disposable class: losing a marker costs a
duplicate notification.

**The prune half has shipped, gated to the only classes it can honestly delete.**
`retention.json` (the archive's `retention_policy` shape: `enabled` separate from
`window_seconds`, deleting anything only when both say so) is the policy;
`warrantor prune` is the enforcement — **dry run by default**, `--apply` to act. The gate is in
the code, not the config: the job deletes only `NoIntegrityConsequence` classes (`logs/` today),
refuses every other class by construction, and prints the refusals with their effects so an
operator reads what is NOT going as easily as what is. `holdings` now states the truth per class
under the policy in force: the window and the command for prunable classes, "never removed by
warrantor" for everything else, the old no-authority sentence when no policy exists, and a BROKEN
line when one exists and will not parse.

What is deliberately **not** shipped: pruning of any class a verdict, an answer or a piece of
evidence depends on. Extending the gate to `staged/` — the first class worth asking for —
requires writing the chain witness forward into a tombstone at deletion time, and that design is
recorded below with the other facts. The archive's own `retention_policy` table also remains
unwired by anything server-side: the local answer came first, and the server half should read
this one before growing its own.

Two facts worth recording for whoever writes the prune:

- The archive already has the right policy shape and nothing reads it. `rust/archive` ships a
  `retention_policy` table with `enabled` as a separate boolean from `window_seconds`, and
  `RetentionPolicy::deletes_anything() == enabled && window > 0` — the absent-limit rule, already
  correct. `retention_policy()` is called from `tests/append_only.rs` and nowhere else, and
  `rust/warrant` has no archive client at all. Adding a deletion job there would be a fifth
  built-but-uncalled component; the local answer comes first.
- A prune must not be able to break a verification chain silently. The staged-effect log is the case
  that used to be silent, and is now not: `StoredWarrant.staged_chain` witnesses the head and count
  outside the file, so a removed or truncated log is a refusal instead of "0 staged effect(s)". Any
  prune of `staged/` has to write that witness forward into a tombstone, or it re-opens the hole.

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

§4.3 below has since moved too: the store-wide aggregate these signals feed now has a client, and
the two routes stopped being the only way to read them. §4.2 is not unchanged either — it has been
run.

### 4.1b The guard is measurable where it runs — **built**

Every figure this product quotes about its guard came from a Python harness, against Hugging Face
corpora, on another machine. An operator could not check it without Python, the corpora, a token and
an afternoon — and it measured a configuration this crate did not run for eight releases.

`warrantor guard doctor` proves the chain is connected: attach, resolve the model digest, classify
three probes including the jailbreak case `parse_guard_response` exists for. `warrantor guard bench
--cases <file.jsonl>` measures it, over cases the operator supplies, with **Wilson intervals** —
never a point estimate alone, because 0.85 from 20 cases and 0.85 from 2,000 look identical and mean
different things. Recall and FPR over separate denominators, per-category recall (the published
weakest class is 0.4298 and one aggregate could not find it), and an unclassified case **excluded**
rather than counted as a miss: a backend that was down is a failed measurement, not poor recall.

It reports **parity**, not quality, and says so: the cases are the operator's, because a set shipped
with the product is a set the product can be tuned against. It says "consistent with", never
"matches".

**It found a defect on its first live run.** `MEASURED_NUM_CTX` had corrected the library default to
8192; the CLI kept its own literal `4096` fallback, so every guard the CLI attached still ran at the
unmeasured configuration — the fix surviving its own fix, one layer up. Only a command that prints
the running configuration could have caught it. Both sites now read the constant, pinned by a test.

### 4.1c Re-measuring against the corpora is blocked on a credential, not on compute

`warrantor guard bench` measures the shipped configuration against cases an operator supplies. What
it cannot do is re-run **WildGuardTest** and **ExpGuardTest**, which is what would confirm the
published 0.8152 / 0.0923 under the corrected context window.

The blocker is stated by the code that would do it. `warrantor_ml.datasets` opens with *"Both primary
corpora are gated behind Hugging Face click-through terms"*, and the WildGuardMix spec records:
*"Gate is auto-approved on submit — no human reviewer — but still requires a logged-in account, an
accepted form, and a read token on the machine."* There is no `HF_TOKEN` on this machine and no
Hugging Face cache at all, so the fetch fails with HTTP 401 before any model is called.

That makes it a **credential step, not a compute step**: accepting terms under an account is
something only the account holder can do. Once a token is present the run is one command per corpus
against the local Ollama, and it is the only outstanding item on this page that is a task rather than
a decision or a wait.

### 4.2 A fine-tune has been run, and the gate rejected it — **done, and informative**

No longer true that "no adapter has been trained". Run `weak-2026-08-13a` (PR #37) trained
`guard-0.6b-weak-category` on Modal A100 — 38,694 rows, one epoch, 2 h 28 m, ~$7 — and the parity
gate **rejected** it at exit 1. The whole path from corpus to verdict is now exercised end to end,
including the adapter → GGUF → Ollama bridge that did not previously exist.

The rejection is the useful part. Against the **same-size** baseline the adapter was *worse*:
recall 0.8488 → 0.8329, with the false-positive rate falling too (0.0624 → 0.0519) — a more
permissive gate, which is the direction this substrate's own rule says fails silently.

**The cause was the target vocabulary, not the method.** The corpora label rows harmful or not, so
rendered targets carry only `Unsafe`/`Safe`. One epoch of that extinguished Qwen3Guard's third
severity outright: **49 `Controversial` verdicts became 0** across 1,699 samples. Worse for a
governance product, the documented `Controversial=SAFE` policy knob silently became a **no-op** —
with no such verdicts left to act on it reports a recall identical to the headline row, where on
the base model it moves recall 0.8488 → 0.8011. An operator lever stopped working and nothing
announced it.

Rendering `Controversial` as a third target class is **not available**: WildGuardMix's
`prompt_harm_agreement` column exists only in its *test* split and ExpGuardMix has no equivalent,
so there is no borderline signal in either training corpus. All four guard recipes therefore now
set `supervise_severity=False` — the severity line stays in the input and is masked in the loss —
and run `catonly-2026-08-13b` is testing that.

Two measurements landed alongside, and they correct each other. On WildGuardTest the 4B is **not**
measurably better than the 0.6B (z = −0.363); on ExpGuardTest it **is** (z = −2.539). Parameter
count buys nothing on general safety and 4.5 points of recall on professional-vertical content —
so for a product aimed at regulated verticals, **the 4B earns its 3.2 GB**. Quoting either corpus
alone gives a confident wrong answer to the packaging question.

Still open here: seven of the eight models are untrained. Four are cold-start blocked on real
warrant history — and **the pipeline for that history now exists**, which it did not.
`build_corpus.py` builds from Hugging Face parquet and nothing read this store, so the wait and the
work were stacked and only the wait was written down. `warrantor guard export-corpus` is the missing
half: the cold start is blocked on data *arriving* rather than on data arriving and then a module
being built.

It refuses the obvious implementation. Exporting the guard's own verdict as a label would train the
next model on this one's misses — one adversarial case in five at the measured recall — and the miss
would become invisible, because the model and its labels would agree. The only labels are human
decisions the store already holds (a settle, a void), they are **warrant-level supervision on
call-level examples**, and every row carries that granularity so a recipe can weight or discard it.
The first real export showed the weakness at once: one harmful and one benign call, both labelled
harmful by a single void, with `guard_said` recording that the guard had them right. No content is
exported, only digests. `sufficient_for_training` counts *labelled* rows and says the thing that
actually closes the gap: using the product. And `Unqualified Professional Advice` — the weakest
measured class at 0.4298 and the headline target of both weak-category recipes — is **unreachable
from WildGuardMix**, which has no such category; reaching it needs an ExpGuard corpus, and the
gate refuses cross-corpus scoring until an ExpGuard baseline is bound to a recipe.

### 4.3 A non-developer surface for model intelligence — **partly done**

No longer true that decision-makers cannot see refusal quality at all. The console now has a second
destination, **Refusals & guard**, over `/v1/summary/refusals?since=&until=`: for a chosen month it
shows which bounds refused and whether the bound or the agent is probably wrong, and — separately,
with the mode on every row and no verdict anywhere near it — what the guard model flagged about the
calls the warrant *allowed*.

Two things that fix required, and both were real defects rather than plumbing. The route accepted a
query string and **ignored** it, so a month view built on top of it would have answered 200 with the
all-time aggregate under a month heading; and the payload carried `enforcing` as a bare boolean,
which is `any(..)` over the whole store, so no client could honour the three-valued blocking posture
the server had already worked out. Both are fixed at the source.

**What the view deliberately does not answer is the second half of the original sentence.** It shows
what the guard *caught* and what nothing *looked at* — sessions where the backend was down, replies
that were not verdicts, calls past the per-session cap. It shows no estimate of what the guard looked
at and got **wrong**, because live traffic here carries no labels: the measured 0.8152 recall is a
figure about WildGuardTest, and multiplying it by live counts would produce a number with no
measurement behind it on the surface that least tolerates one. **That remains true and is not a gap
to close.**

**Runs with no guard attached — closed 2026-08-17.** This section used to end saying the count
"needs a per-warrant *run* timestamp, and the only one the store holds is `claims.issued_at`". The
difficulty was sharper than a missing timestamp: the guard writes an attach record when it attaches,
so a *guarded* run was visible and an unguarded run left **nothing behind at all**. Absence of a
guard record was indistinguishable from absence of a run, and the two mean opposite things.

`rust/warrant/src/runs.rs` writes `runs/<warrant-id>.jsonl` at the start of every supervised
session, with `guard: null` exactly when nothing was watching — a positive record of an unwatched
run, which no absence could establish. It surfaces as a **third block** on
`/v1/summary/refusals` (`total`, `guarded`, `unguarded`, `warrants`, `unreadable_lines`) and as one
sentence in the console. A third block rather than a field on `guard`, because everything in that
block is counted *from* guard records and is silent about sessions the guard was never in; putting
`unguarded` inside it would make the guard object partly a statement about its own absence.

`unguarded` is never rendered as "missed". An unguarded run produced no signal at all, so nothing is
known about what happened inside it beyond what the bounds refused — a gap in observation, not a
count of failures.

---

## The honest summary

The **substrate is real** and the **single-machine loop is complete**. Most of what is missing is
still what makes it a product rather than a tool: it installs but announces itself with an operating
system warning, it cannot be reached by a second person, and it cannot say who did what.

**What the 2026-08-14 revision changed, and the pattern in it.** Five PRs merged. Two gaps closed
outright (§1.3 first run, §1.4 refresh), two moved from "absent" to "built but unreachable"
(§2.1 the archive has no client, §4.1 the guard is observe-only), and one closed with a result
worth more than the feature (§4.2, a rejected fine-tune that diagnosed its own cause).

The recurring shape is worth naming because it has now happened three times: **a component is
built, is correct, and is not wired to anything that would exercise it.** The ~20 substrate crates
orphaned from the warrant, the guard benchmarked but never called during a run, and now an
evidence archive with no client. Each merge felt like progress and moved no user-visible line.
The next unit of work in this document that changes what a person can *do* is not another
component — it is a caller for one that already exists.

The ordering matters. Packaging (1.1–1.2) was the cheapest visible win and is now done to the point
where a reviewer can install and launch it; what remains of 1.1 is a purchase, not a build.

**2.1 was the one that decided whether this is a product, and it is closed** (2026-08-17). A second
person can now be told a warrant needs them, see what they would be approving, decide it from a
browser, and have the decision land — with the two-person rule enforced by the same code the queue
renders from. The recurring shape named above was broken once on purpose in the process: the queue
shipped with a CLI and a route and no client, and that was caught and fixed *one commit later*
rather than one release later.

**What now decides whether it is trustworthy is §3.1.** `write_paths` and `budget_cents_observed`
are Observed, not enforced; there is no netns, no seccomp and no firewall. Every other open item is
smaller than it: §2.4 is a token-scoping change on one surface, §3.4 is a retention window for
`logs/`, §3.2's remainder is two transports a webhook can already front, and §1.1 is a purchase.
§3.1 is the only one where the product's central sentence — "the agent is bounded" — is stronger
than what the code earns without composing with a sandbox.
