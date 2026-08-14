# RFC W1 — Surfaces, and whether Warrantor needs a backend

**Status:** accepted
**Date:** 2026-08-13

This is the first RFC in the **W series**, which covers the warrant primitive. The existing
A/C/E/F/N/R/S/T/X series describe the twelve-plane component portfolio; none of them describe
`rust/warrant`, which is the spine the product now rests on. That gap is why this document exists.

## Background

Stated first, because everything below is derived from it rather than from a plan.

| Surface | State | Evidence |
|---|---|---|
| **Local agent** | Real, ~10.9k lines | `rust/warrant` — grant, supervise, stage, settle, stop, spend, egress, MCP, and `warrantor serve` |
| **Browser console** | New, this RFC's companion change | `rust/warrant/src/console/`, served same-origin by the agent |
| **Desktop app** | Did not exist | one mention of "electron" in the whole repository, in a `serve.rs` comment |
| **Web app** | Did not exist | `typescript/console` is a 263-line library modelling AARs, Rego policies and tenant-guard — a *different* architecture, consumed by nothing |
| **Model intelligence** | Real, in progress | `python/warrantor_ml`, `ml/` |

`warrantor serve` exposes twelve `/v1` routes over loopback HTTP. Exactly three mutate — `settle`,
`void`, `stop` — the three acts that require a human. There is deliberately no `grant` over HTTP.

Three properties in `serve.rs` are load-bearing, and every decision here is shaped to preserve them:

- **Grant never crosses the wire.** Grant mints authority and holds the issuer key. The moment it is
  network-reachable, warrant-minting authority lives in a network-reachable process.
- **Verification happens only in Rust.** A client renders `verified` and never derives it. A
  renderer that checked signatures itself would be a second implementation of the verifier, and a
  second implementation can disagree with the first. When two verifiers disagree a human must decide
  which to believe — the exact situation this product exists to prevent.
- **There is no CORS header, ever.** One would let any page in the user's browser reach a loopback
  API that can hold settle authority.

## Goals

1. Give the product a surface a non-developer can use, without weakening the boundary above.
2. Answer whether a backend is required, and if so bound it precisely.
3. Record what must never move server-side, so a later change cannot erode it by increments.

**Non-goals.** Replacing the CLI, which remains the only way to grant. Shipping a packaged desktop
binary (see Milestones). Any change to the verification path.

## Detailed Design

### The surfaces

All three are **viewers over the same local agent**, differing only in how they are launched.

- **CLI** — the developer surface, and the only one that can `grant`. It is the trust root: a human
  at a terminal.
- **Browser console** — served same-origin from `/` by `warrantor serve`, token delivered in the URL
  fragment. This is the multi-user oversight surface.
- **Desktop** — `warrantor console`: the same server, which additionally opens the browser. It
  removes the two steps nobody outside engineering will perform, which are starting a daemon and
  pasting a hex token.

The no-CORS rule forecloses the obvious alternative and is worth stating plainly: **a hosted web app
can never talk to the local agent from a browser.** Not "should not" — cannot, because the browser
blocks the cross-origin read and the fix that would allow it is the thing that must not be done. So
the console assets are compiled into the binary and served same-origin. That is forced, not chosen.

### Does this need a backend?

**Yes — for five things, each physically impossible on one machine.** Not for convenience, and not
for any reason a control plane is usually built.

1. **Multi-machine oversight.** `serve.rs` binds loopback. Its own docstring promises "a second
   person, a desktop application, a browser client" — but a second person *on another machine*
   cannot reach a loopback socket. That promise is false today, and it is the core product claim.
2. **Trust anchoring.** `serve.rs` states that a signature verifying "does not establish that the
   issuer should be trusted, **which has to come from somewhere else**." Which key belongs to which
   human is a directory. It cannot be local, because a local answer is one the audited party
   controls.
3. **Durable evidence custody.** Evidence in `~/.warrantor` dies with the laptop, and is held by the
   very person being audited.
4. **Async approval routing.** Reaching a human who is not at that terminal requires something that
   outlives the terminal.
5. **Independent time anchoring.** `checked_at` comes from a clock the agent's own machine controls.

### What must never move server-side

Moving any of these collapses the trust model, and no amount of hardening compensates:

- **`grant`** — holds the issuer key. Already refused over HTTP.
- **verification** — stays in Rust, client-side.
- **the settle key** — release authority.
- **enforcement and containment** — properties of the machine the agent runs on.

### Therefore: a relay, a directory and an archive

The backend holds only **signed artifacts it cannot forge**. Every client re-verifies locally with
the same Rust verifier, against a trust anchor obtained from the directory and pinned by the
operator.

> **Design target: compromise of the backend must degrade availability, never integrity.**

An attacker with full control of the server can withhold evidence, delay an approval or serve a
stale list. They cannot forge a warrant, make a tampered report verify, mint authority, or release
staged effects. If any of those becomes possible, the design is wrong.

A consequence worth naming: the backend can then be operated by a customer, by us, or by a third
party in any jurisdiction without changing the security argument. That is what makes it compatible
with sovereign deployment rather than a barrier to it.

### What the backend must not be

`go/defstack-cloud` (X11) is a multi-tenant SaaS control plane with per-plan GPU quotas and tenant
lifecycle management. It belongs to the twelve-plane architecture and is **not** the backend
described here. Adopting it would make the server an authority over tenants — the property this
design forbids. The two should not be conflated merely because both are "the cloud bit".

### Audiences

**Developers** use the CLI and MCP; everything is already available to them.

**Non-developers** (reviewers, operators, risk functions) use the console. The binding constraint is
that they must never be asked to evaluate a signature: they are shown a verdict computed in Rust, a
sentence explaining what it means, and the three acts. Where the system cannot answer they see
`unknown` — never a guess dressed as a fact.

**Decision-makers** use the summaries and the archive. Their question is not "is this warrant valid"
but "what did our agents do this quarter, and what did we refuse" — `/v1/summary/refusals` and
`/v1/summary/daily` locally, aggregated centrally. This is the audience for whom the backend's
independence matters most: evidence shown to an examiner must not be evidence their own engineers
could have edited.

### Relationship to model intelligence

`python/warrantor_ml` produces judgements about *content*; the warrant substrate produces evidence
about *authority* and *effects*. They meet at exactly one place: a model's judgement can become a
**refusal signal** recorded against a warrant, which is the shape `record_refusals` already expects.

The boundary that matters: **a model's output is never a verdict.** A refusal is evidence that
something was declined and why. Integrity remains an Ed25519 question with a three-valued answer,
and no classifier score is ever folded into it. Fine-tuning improves the quality of refusals; it
must not touch the verification path.

## Dependencies

- `rust/warrant` — the store, the verifier, and `serve.rs`. No new crate dependency is introduced by
  the console: the assets are `include_str!`-ed and the HTTP layer is the existing one.
- No JavaScript build step, framework, bundler or package manager. The console is plain ES modules
  and CSS, which keeps the audit surface of the oversight UI readable in full. `node --test` is not
  a violation of that rule and the console's behaviour tests use it: it is the runtime's own runner,
  it installs nothing, there is no `package.json` beside the assets, and `desktop/test/policy.test.js`
  already runs under it here. Reading the rule as "no test runner either" is what left `emptyKind`
  untested, and three of its four rungs were wrong.
- The future backend depends on `ed25519-dalek` verification and the evidence bundle format already
  produced by `report --export`; it introduces no new cryptographic primitive.

## Threat Model

| Threat | Mitigation | Residual |
|---|---|---|
| A hostile page in the user's browser reaches the loopback API | No CORS header at all; `frame-ancestors 'none'` and `X-Frame-Options: DENY` so it cannot be framed and driven either | None known for the browser path |
| The console's token is exfiltrated by injected script | `connect-src 'self'` with `default-src 'none'`: a script that somehow executed has nowhere to send it — no beacon, image ping or websocket | A browser bug that ignores CSP |
| The token leaks through a process listing | It is never passed in an argv. `warrantor console` writes a redirect shim beside the token in the same 0700 directory and hands the browser a *path* | A user who can read the 0700 directory already holds the token |
| The token leaks through logs or `Referer` | Delivered in the URL fragment, which is never sent to a server; erased from the address bar and history on load; held in memory, not `localStorage` | A screenshot taken between navigation and erase |
| Unauthenticated caller enumerates warrant ids | `/v1` still answers 401 *before* the route resolves; the three console paths return fixed bytes and are asserted byte-identical across stores | None known |
| The supervised agent reads the token and calls the API | Unchanged from `serve.rs`, and not claimed to be fixed: under a same-UID model it is not fully fixable. The answer is that the server holds no settle key unless `--allow-settle` was typed, so the token yields a viewer | An agent on an `--allow-settle` server |
| A compromised backend forges evidence | Clients re-verify locally against a pinned anchor; the server holds only signed artifacts | Withholding and delay — availability, by design |
| A second verifier disagrees with the first | No cryptography above the Rust line, in any surface | None, while the rule holds |

## API

No `/v1` route is added, changed or removed. The API surface is exactly as before.

Three new **unauthenticated** paths serve fixed assets, and nothing else:

| Path | Method | Type |
|---|---|---|
| `/` and `/index.html` | GET | `text/html; charset=utf-8` |
| `/console.css` | GET | `text/css; charset=utf-8` |
| `/console.js` | GET | `text/javascript; charset=utf-8` |

Each carries `Content-Security-Policy`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and
inherits `no-store` and `nosniff` from the shared writer. Any other method is `405` with `Allow:
GET`. Any other path falls through to the token check.

`Response` gains a third constructor for static bytes. It carries no verification envelope, because
an asset makes no claim that could be verified, and both halves of its payload are `'static` so
nothing off the filesystem can become one.

New CLI verb: `warrantor console`, taking the same flags as `serve`.

## Testing

`rust/warrant/tests/console.rs`, sixteen tests. The load-bearing one is
`serving_the_console_does_not_make_the_api_reachable_without_a_token`: six `/v1` routes, including
`settle`, are asserted to still refuse an anonymous caller. If a future refactor makes
`console_asset` match too eagerly — a wildcard, a prefix test, a fallthrough to `index.html` for
unknown paths — it fails on the exact request an attacker would send.

`the_console_is_byte_identical_across_stores_because_it_carries_no_store_data` tests the claim that
makes unauthenticated serving safe, rather than asserting it in a comment: two servers on different
roots, one holding a warrant and one empty, must answer byte-identically.

`the_console_carries_no_inline_script_handler_or_style_because_the_policy_forbids_them` and
`the_console_loads_nothing_from_off_this_origin` guard the policy from the one direction nothing
else covers. `script-src 'self'` carries no `unsafe-inline`, so an `onclick=` on a button, a
`style=` attribute or an icon fetched from a CDN breaks *silently in the browser* while every other
test here passes. These assert over the served bytes: exactly one `<script`, and it has a `src`; no
`on…=` attribute; no `style=` or `<style`; no off-origin `src`, `href`, `url()` or `@import`.

Five tests assert the first-run panel's prose, because that prose is the product's own statement of
its boundary: that granting is deliberately absent rather than missing, that the reason is the
minting of authority and the issuer key, that the grant line appears exactly as it is typed, that
`--write` is described as containment at settle rather than refusal at write, and — the one added
after review — that the lede claims only the strengths `bound_strengths()` actually holds.

That last test exists because the lede did not. It said "nothing it does is visible outside that
copy until a person settles the warrant, and external effects are staged rather than performed", and
neither half is true: there is no network namespace, no seccomp filter and no firewall anywhere in
this crate, and `proxy.rs::decide()` returns `Decision::Forward` for any call whose class is not in
`staged_classes` or whose tool is absent from `EffectRegistry::github()` — so under the exact grant
line the panel printed, `Financial`, `Destructive` and `Physical` effects were performed on the
spot. Prose that promises a property the code does not enforce is a defect of the same severity as
a wrong signature check, and this is the first thing a non-developer reads. The test now pins the
three strength tiers by name, pins that the mediated tier says what it does *not* hold, and pins the
overclaims out in the words they would return in. The grant line gained `--repo .` in the same pass:
`cmd_grant` creates a worktree only when `--repo` is given, so the printed line made no worktree at
all while the paragraph above it described one.

`an_empty_store_and_an_empty_filter_are_different_sentences` pins that the four causes of an empty
list have four wordings and that neither of the two most easily confused is a substring of the
other. `the_inline_attribute_guards_see_an_attribute_however_its_tag_is_wrapped` pins the reach of
the two byte guards above, which read a single literal space while their doc comment claimed
"whitespace-delimited" — a handler on its own line was invisible to the only guard that exists for
it.

`emptyKind`'s branch selection is exercised by `rust/warrant/src/console/console.test.js` under
`node --test`, added after review found three of its four rungs wrong or unreachable while every
Rust test passed. It is not a JavaScript runner in the sense §Dependencies forbids: nothing is
installed, no `package.json` sits beside the assets, and the same runner already gates
`desktop/test/policy.test.js`. The file stubs the DOM itself and boots `console.js` as the browser
does, so it covers both the pure decision (`listFacts`, `emptyKind`) and the rendered result: that
a 200 with an unparseable body shows the error paragraph and never "No warrants on this machine
yet."; that a filtered empty view over a store holding a corrupt file stays a filtered view with
its **Show all**; that an agent which is not answering explains itself, starts polling anyway and
recovers without a reload; and that a store which empties under the console takes the detail pane's
release controls with it. Every one of those fails against the code as it was.

The rest cover content types, the policy headers, the absence of a CORS header, method refusal, the
`/index.html` alias, and that presenting a token yields no different document.

Manual verification, recorded because parts of it cannot be unit-tested: a warrant was granted, the
server started, and the console loaded in Chrome. The list, verdict, report and staged-effect
bundles and the three acts render; the fragment is erased after load; no CSP violation is reported.
The launcher was verified through the full chain — shim, redirect carrying the fragment,
authenticated console.

The empty-store path is the one state a machine in use cannot reach, so it is reached by pointing
the binary at a fresh store root — `WarrantStore::default_root` reads `HOME`, or `USERPROFILE` on
Windows. Against a live `warrantor serve` on such a root, the four inputs `emptyKind` reads were
each produced and observed: unfiltered and empty (`200`, zero rows, zero unreadable → first-run);
`?state=held` on the same store (same triple with a filter on → filtered); one warrant restored
under the running server (one row → the panel's clearing input, no restart); and an unparseable file
in `warrants/` (zero rows, `unreadable_records: 1` → unreadable). The `error` rung was **not**
exercised live: producing a non-200 from the list route needs an induced store failure, and the
rung's justification was read off `list_warrants`'s `self.internal(...)` path rather than off a run.
That reading is what missed the two ways into the rung that mattered more — a 200 whose body did not
parse, and a `fetch` that rejected — both of which are now covered by `console.test.js` rather than
by a justification.

**Not yet verified for this change, and stated rather than implied:** the panel's rendering in a
real browser, and the copy button's clipboard path and its selection fallback. Those need a DOM the
stub does not model, and the coverage above stops at the bytes served, the JSON answered, and the
elements the stub does model. The **Show all** round trip and the chip round trip are covered by
`console.test.js`.

A first-run gap this work did *not* close, found while reaching that state: on a machine that has
never run any warrant-touching command there is no issuer key, and `warrantor serve` refuses to
start rather than minting one — correctly, since a server that minted an identity on first use would
sign evidence with a key nobody chose. So the true first contact for a brand-new user is that CLI
refusal, not this panel. The panel covers the keyed-but-empty store, which is what a reviewer,
a pruned store or an `mcp`-first setup actually presents. Closing the other half belongs with
packaging (`docs/W1-delivery-gaps.md` §1.1–1.2), not with the console.

## Deployment

No new artifact and no new port. The console ships inside the existing `warrantor` binary, which
keeps `deploy/airgap` working unchanged: there is no CDN, no bundle to fetch and no npm install on
the target.

`warrantor serve` behaves exactly as before apart from serving the three asset paths.
`warrantor console` additionally opens a browser and writes a redirect shim into the existing 0700
`serve/` directory, removed on shutdown alongside the token file.

Release authority remains opt-in: settle and void refuse unless `--allow-settle` was typed, and the
console disables those buttons and says why.

The desktop installers configured in Milestone 4 are a new artifact but not a new deployment story: the
console still ships inside the `warrantor` binary, so `deploy/airgap` is unchanged, and an installer
is simply that same binary with a window around it. The shell starts the agent as a viewer and never
passes `--allow-settle`, on any launch path — spawn arguments and installer shortcuts alike.

## Milestones

1. **Browser console, same-origin** — done, this RFC's companion change.
2. **`warrantor console`** — done.
3. **Electron desktop shell** — done, in `desktop/`. It wraps this console rather than
   reimplementing it, because a second viewer is a second thing that can misrender a verdict.

   The cost is real and is accepted deliberately rather than waved through: a security product that
   ships its own Chromium owns that patch cadence. Electron 33 carried 21 high-severity advisories;
   the pin is 43.4.0, which audits clean, and **`npm audit` in `desktop/` now runs in CI on every
   pull request** rather than only on the release checklist — reporting there, blocking in the
   release workflow, because the advisory feed is a live external service and a new publication in
   electron-builder's tree must not stop unrelated work across the repository. `warrantor console`
   remains the
   zero-dependency path to the same console for anyone who would rather not run a bundled browser
   at all.

   The shell's security decisions live in `desktop/src/policy.js`, which imports nothing, so CI
   gates them on every pull request with no Electron download and no display.
4. **Packaging** — **written, not yet exercised.** The configuration for a Windows NSIS installer
   (per-user, no elevation), a macOS dmg for arm64 and x64, and a Linux AppImage and deb exists, in
   `desktop/electron-builder.config.cjs` and `.github/workflows/desktop-release.yml`. **That
   workflow has never run** — `workflow_dispatch` is unavailable until the file is on the default
   branch — and **no installer has been produced, installed or launched on any platform.** The only
   build performed by hand was a Windows `--dir` run with a stand-in for the agent, which yields an
   unpacked directory rather than an installer. The macOS and Linux legs are entirely unexercised,
   and the macOS leg carried a real defect for as long as it was described as done: `identity: null`
   means *skip signing*, not ad-hoc, and an invalidly-signed bundle does not execute on Apple
   Silicon at all. This milestone is done when a dispatch has built all four legs and one installer
   per platform has been launched on a machine with no `warrantor` on `PATH` — the rehearsal in
   RELEASING.md, which no gate can perform for us.

   The `warrantor` binary is compiled on the same runner that packages it and ships **inside** the
   app, and the shell prefers that copy over `WARRANTOR_BIN` and over `PATH`: verification happens
   only in that binary, so choosing the binary chooses the verifier, and an installed app must not
   be silently re-pointed at a different one by an environment variable any parent process can set.
   That ordering is code and is tested. That it survives into a produced installer is configuration,
   and is unobserved until the dispatch runs.

   **Signing, notarisation and the update channel remain not done.** Signing is procurement rather
   than engineering; the update channel is deliberately blocked behind it, because an update channel
   over an unsigned artifact is an unauthenticated code-execution channel pointed at a machine that
   runs a supervised agent. What to buy, and the config lines that change once it exists, are in
   [../../desktop/SIGNING.md](../../desktop/SIGNING.md). Until then a tagged release publishes
   per-platform SHA256SUMS and a build-provenance attestation — which say where a file came from,
   not who stands behind it, and that difference is stated rather than blurred.

   See the remaining delivery gaps in [../W1-delivery-gaps.md](../W1-delivery-gaps.md).
5. **Backend, in the order the five needs bite:** evidence archive (custody) → directory (trust
   anchoring) → approval routing → time anchoring → fleet summaries.

Each backend stage ships only if a client can still verify without it. That test is what keeps the
relay from quietly becoming an authority.
