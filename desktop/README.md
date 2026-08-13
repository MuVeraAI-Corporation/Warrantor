# Warrantor desktop

An Electron shell around the console that `warrantor serve` already serves.

```bash
cd desktop
npm install          # Electron and electron-builder; nothing else is needed
npm start            # starts the agent, opens the window
npm test             # policy and packaging tests — no Electron, no display
```

`WARRANTOR_BIN` points at the `warrantor` binary when it is not on `PATH` — in a build from source.
In an installed build it cannot override the bundled agent; see *Which agent it runs* below.
`WARRANTOR_DESKTOP_TRACE=/path/to/log` traces startup, for when the window does not appear.

## What it is

A window, a child process, and a policy. It starts `warrantor serve --port 0`, reads the session
token from that process's stdout, and points a locked-down window at the console.

It is **not** a second implementation of the console, and must not become one. The console renders
a verdict computed in Rust and never derives one. A shell that re-rendered any of that would be a
second viewer, and a second viewer is a second thing that can misrender a verdict at the exact
moment a human is deciding whether to release an agent's work. Everything visible in the window is
served by the agent.

## Why it exists, given `warrantor console`

`warrantor console` already opens a browser. It needs a terminal to start it. This removes the
terminal, which is the whole difference between a surface an engineer can use and one a reviewer, a
risk function or an auditor can. That is the entire delta, and it is worth one small program.

## Security posture

The renderer is sandboxed, with context isolation on and Node integration off. There is **no
preload script**: the console needs nothing from this process, because it talks to the agent over
HTTP like any other client. That is what keeps the shell substitutable for a browser and keeps the
renderer's reach at zero.

Navigation is pinned to the agent's origin, new windows are refused, webviews cannot attach, and
every permission request is denied.

Release authority is **not** requested. The shell starts a viewer; arming settle is something an
operator does deliberately at a terminal, having read what it means. A desktop icon that silently
held release authority would make the safest-looking surface the most dangerous one.

## Which agent it runs

In order, and the order is the point:

1. **the copy bundled inside the installed app** — `<resources>/warrantor[.exe]`, in a packaged
   build only;
2. **`WARRANTOR_BIN`**, when it is set to a path that exists;
3. **`warrantor` on `PATH`**, which is what `npm start` uses.

Verification happens only in Rust and only in that binary, so choosing the binary chooses the
verifier. An installed application must therefore not be silently re-pointed at a different agent by
an environment variable that any parent process can set — which is why the bundled copy outranks
`WARRANTOR_BIN` rather than the other way round.

**There is no fallthrough.** If the chosen candidate is missing — a damaged install, or a typo in
`WARRANTOR_BIN` — the app reports it and stops, rather than quietly running whatever `warrantor`
happens to be on `PATH`. The consequence, stated plainly: **in a packaged build `WARRANTOR_BIN`
cannot override the bundled agent.** Anyone who needs a different agent should run `warrantor
console`, or this shell from source.

The shell does not hash, checksum or signature-check the bundled binary, and must not start. That
would be a second verifier above the Rust line, and two verifiers can disagree — leaving a human to
decide which to believe, which is the situation this product exists to prevent. Integrity of that
file is the installer's job, the operating system's, and (once §3 of [SIGNING.md](SIGNING.md) is
paid for) the code signature's.

## Packaging

```bash
# 1. Build the agent and put it where electron-builder expects it.
cd ../rust && cargo build --release --bin warrantor
mkdir -p ../desktop/vendor/x64            # or arm64, matching your machine
cp target/release/warrantor ../desktop/vendor/x64/

# 2. Build.
cd ../desktop
npm run pack         # unpacked app in dist/, fast, for checking the bundle
npm run dist         # real installers in dist/
```

`vendor/` and `dist/` are gitignored: a committed executable in the source tree of a security
substrate is an unreviewed, unattested binary that nothing in CI ever looks at.

`.github/workflows/desktop-release.yml` is written to build four legs — Linux x64, macOS arm64,
macOS x64, Windows x64 — compiling the agent on the same runner that packages it, so the bundled
agent always matches the app's architecture. It then asserts the agent really is inside the produced
app, and executable, because a pattern that stops matching (or a mode lost in a copy) produces a
perfectly good installer whose only symptom is an error dialog on a reviewer's machine.

**That workflow has not run yet.** `workflow_dispatch` is unavailable until the file is on the
default branch, so no installer has been produced, installed or launched on any platform — the
macOS and Linux legs have never executed at all. Treat every sentence above as describing
configuration until the rehearsal in [RELEASING.md](../RELEASING.md) has been done.

The installers are **unsigned**. SmartScreen and Gatekeeper will warn.
[SIGNING.md](SIGNING.md) says what that costs, what to buy, and the config lines that change once
the certificates exist. There is no update channel and there must not be one before signing: an
update channel over an unsigned artifact is an unauthenticated code-execution channel.

The icon in `build/icon.png` is provisional — a geometric mark, generated by `build/make-icon.mjs`
so it is reviewable rather than an opaque blob, and claiming no brand that does not exist.

## Why the policy is a separate module

`src/policy.js` imports nothing, and holds every decision that matters: which URL the window may
navigate to, which permissions are granted, which line of the agent's output carries the token, and
how the token is redacted from forwarded logs.

Those are exactly the decisions that become untestable when written inline in an Electron callback
— which is where they normally live. As pure functions they run under `node --test` with no
Electron, no download and no display, which is also what lets CI gate them on every pull request
without a 150 MB Chromium install.

The test that earns its place is the lookalike-origin one. `http://127.0.0.1:8787.evil.com/` starts
with the expected text and is a different host; a prefix comparison — the obvious implementation —
admits it. Comparing parsed origins makes that class impossible rather than guarded against.

## On shipping a browser engine

A security product that ships its own Chromium owns that patch cadence. This is not hypothetical:
Electron 33, current at the time of writing, carried **21 high-severity advisories**. The pin here
is 43.4.0, which `npm audit` reports clean.

That is the standing cost of this directory, and it has to be paid deliberately: **`npm audit` in
`desktop/` now runs in CI on every pull request**, not only on the release checklist, and a release
must not ship on a vulnerable pin. It costs the CI job nothing — `npm audit` reads
`package-lock.json` and needs no `node_modules` — and it catches a lockfile that has drifted from
`package.json` before the release workflow tries to `npm ci` it.

It **reports** in CI and **blocks** in the release workflow. An advisory published anywhere in
electron-builder's build-tool tree turns that step red with no change to this repository, and none
of the remedies — a newer `electron-builder`, a scoped `overrides` entry, holding the release — is
something an unrelated contributor can apply, so it must not stop Rust or Python work from merging.
The property is kept where it bites: `desktop-release.yml` fails hard on it. The deterministic half
— that the lockfile still resolves Electron inside the audited `^43.4.0` — is asserted offline by
`test/packaging.test.js`, which does block. The policy module already blunts
several of the advisory classes — permissions are all denied, window open is refused — but a
renderer CVE is a renderer CVE.

`warrantor console` remains the zero-dependency path for anyone who would rather not run this at
all, and both surfaces show the same console.
