# Warrantor desktop

An Electron shell around the console that `warrantor serve` already serves.

```bash
cd desktop
npm install          # Electron only; nothing else is needed
npm start            # starts the agent, opens the window
npm test             # policy tests — no Electron, no display
```

`WARRANTOR_BIN` points at the `warrantor` binary when it is not on `PATH`.
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
`desktop/` is part of the release checklist, and a release must not ship on a vulnerable pin.** The
policy module already blunts several of the advisory classes — permissions are all denied, window
open is refused — but a renderer CVE is a renderer CVE.

`warrantor console` remains the zero-dependency path for anyone who would rather not run this at
all, and both surfaces show the same console.
