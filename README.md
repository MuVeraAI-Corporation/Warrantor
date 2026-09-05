# Warrantor

[![CI](https://github.com/MuVeraAI-Corporation/Warrantor/actions/workflows/ci.yml/badge.svg)](https://github.com/MuVeraAI-Corporation/Warrantor/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/warrantor-warrant?logo=rust&label=crates.io)](https://crates.io/crates/warrantor-warrant)
[![npm](https://img.shields.io/npm/v/%40warrantor%2Fmcp-server?logo=npm&label=npm)](https://www.npmjs.com/package/@warrantor/mcp-server)
[![PyPI](https://img.shields.io/pypi/v/warrantor-agent?logo=pypi&logoColor=white&label=PyPI)](https://pypi.org/project/warrantor-agent/)
[![docs.rs](https://img.shields.io/docsrs/warrantor-warrant?logo=docsdotrs&label=docs.rs)](https://docs.rs/warrantor-warrant)
[![Release](https://img.shields.io/github/v/release/MuVeraAI-Corporation/Warrantor?label=release)](https://github.com/MuVeraAI-Corporation/Warrantor/releases/latest)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Give a coding agent bounded authority, walk away, and decide in the morning.**

Warrantor hands an AI agent a *warrant*: authority granted in advance, with hard limits, that the
agent answers for afterward. The agent works in an isolated copy of your repository. Anything
irreversible — opening a pull request, posting a comment, sending anything — is **staged, not
performed**. In the morning you see what it changed, what it wants to do, and what it was refused,
and you approve or discard.

The problem this solves is the babysitting tax: agents are now capable enough to work for hours, and
nobody can leave them alone, so a human sits and clicks *approve* until their attention runs out.

```bash
warrantor grant --goal "fix the flaky auth test" \
                --tools git,cargo --write 'src/**' --deadline 8h --repo .

warrantor run <id> -- claude -p "fix the flaky auth test"
# close your terminal. the run keeps going.

warrantor status          # in the morning
warrantor report <id>     # what changed, what it staged, what it was refused
warrantor settle <id>     # or: warrantor void <id>
```

Apache-2.0 · Rust core, Go services, Python SDKs, TypeScript tooling · every Python package has
**zero runtime dependencies**.

---

## Why a warrant, and not a permission prompt

A permission prompt asks *"may I do this?"* at the moment of doing it, which requires you to be
there. A warrant answers a different question — *"what is this agent allowed to do at all?"* — once,
in advance, so the agent can work while you sleep.

Four properties make that safe rather than reckless:

**An absent limit means *none*, never *unlimited*.** An empty egress list is no network access, not
unrestricted access. This is what makes an honest *"it cannot do X"* statement possible at all.

**Irreversible actions are staged.** The agent asks to open a pull request and receives a handle
(`pr://staged/…`) instead of a pull request. The real call happens at settle, if you settle. You
cannot un-send an email; you can decline to send it.

**The agent cannot settle its own warrant.** It holds an act-scoped token with no settle field —
there is no message it can send that widens its own authority. The settle key is separate, and on
the MCP agent endpoint the lifecycle tools are not merely denied, they are *absent from the tool
list*.

**Every limit says how it is held, and what that does not cover.** Three tiers, and no rendering
in this product collapses them. The table is generated from `bound_strengths()` in
`rust/warrant/src/lib.rs` and a test fails if it drifts.

<!-- bound-tiers:begin -->
| Bound | Tier | What the tier does not cover |
|---|---|---|
| `tools` | mediated | held only for calls that traverse the MCP proxy; a shell or a harness built-in reaches past it, and no netns, seccomp or firewall stands behind it |
| `write_paths` | observed | measured and reported after the fact; nothing refuses the action as it happens |
| `egress_hosts` | mediated | held only for calls that traverse the MCP proxy; a shell or a harness built-in reaches past it, and no netns, seccomp or firewall stands behind it |
| `staged_classes` | mediated | held only for calls that traverse the MCP proxy; a shell or a harness built-in reaches past it, and no netns, seccomp or firewall stands behind it |
| `expires_at` | enforced | held by cryptography or the operating system; holds against an agent that tries to route around it |
| `delegation_depth` | enforced | held by cryptography or the operating system; holds against an agent that tries to route around it |
| `budget_cents_observed` | observed | measured and reported after the fact; nothing refuses the action as it happens |
<!-- bound-tiers:end -->

A limit you believe in that does not hold is worse than no limit.

---

## Start here

| You are… | Go to |
|---|---|
| A developer who wants to try it | [Quickstart](#quickstart) |
| Using Claude Code, Codex or Cursor | [Connect your agent](#connect-your-agent) |
| Overseeing agents — risk, compliance, audit, security | [`docs/non-developer-platform.html`](docs/non-developer-platform.html) |
| Wondering what actually works | [Project status](#project-status) — we would rather you hear the gaps from us |
| Wanting to contribute | [CONTRIBUTING.md](CONTRIBUTING.md) and [where help is most useful](#where-help-is-most-useful) |

If you oversee agents rather than run them, read the honest note in that document first: **the web
console is not built yet.** Today that role is served by the CLI and by evidence exports.

---

## See it do something first

Two commands, no cloud account, no signup:

```bash
make sigstore-up     # local transparency log (MySQL + Trillian + Rekor, ~1GB)
make demo            # sign an action, record it, verify the proof
```

`make demo` signs a payload, records it in the log, then **asks the log to prove the entry exists** —
reading its answer rather than our own. It prints the inclusion proof, the log-signed timestamp, and
the curl commands to check the result yourself.

It also prints what was *not* proven. The log attests that a record exists at a point in time; it
does not attest that the action described really happened. Binding a record to a real action is the
agent runtime's job. If a dependency is missing, the demo names the exact command that fixes it and
exits 2 rather than reporting a skipped green gate.

---

## Quickstart

Requires Rust (stable) and git.

```bash
git clone https://github.com/MuVeraAI-Corporation/Warrantor.git
cd Warrantor/rust
cargo build -p warrantor-warrant
```

Grant a warrant against a real repository. It creates an isolated git worktree, so nothing the agent
does touches your working copy:

```bash
warrantor grant --goal "fix the flaky auth test" \
                --tools git,cargo \
                --write 'src/**' \
                --egress crates.io \
                --deadline 8h \
                --repo .
```

Run any agent under it. The supervisor detaches from your terminal — closing the terminal ends your
*view* of the run, not the run:

```bash
warrantor run <warrant-id> -- claude -p "fix the flaky auth test"
```

In the morning:

```bash
warrantor status              # what is running, what stopped and needs a decision
warrantor report <id>         # changes, staged effects, refused requests
warrantor settle <id>         # perform the staged effects, in dependency order
warrantor void <id>           # discard the work; keep the record of what it intended
```

If a settle fails halfway the warrant goes to **Held**, not Settled, and stops at the boundary rather
than trying to compensate. The report says exactly which effects are real and which were never
attempted.

The refused-request list is worth reading even when a run succeeds. One refusal of a tool is an agent
reaching for something it should not have; twenty refusals of the same tool means the bounds were
drawn wrong and you wasted its night.

---

## Connect your agent

Warrantor speaks MCP, so any MCP-capable client reaches it natively.

**Your own agent** — register `warrantor mcp`. You get `warrant_grant`, `warrant_status`,
`warrant_report`, `warrant_settle`, `warrant_void`. This endpoint holds the settle key, so register
it only in an agent *you* are driving.

**A supervised agent** — `warrantor mcp --agent <id>` publishes only that warrant's own tools,
policed, with no lifecycle tool present at all.

For Python users there is also a session harness that wraps the agent process directly and reads the
config file your agent already has — `CLAUDE.md`, `AGENTS.md` or `.cursorrules`:

```bash
warrantor-harness run --dir . "claude -p 'fix the failing test'"
```

It holds the agent under an OS-enforced lifetime link, so the agent cannot outlive its supervisor.

---

## Project status

v1.0.0, open-sourced early on purpose.

| Area | State |
|---|---|
| Warrant core — grant, run, report, settle, void, staging, worktree isolation | **Works.** 98 tests, verified against real processes |
| Supervision — detached daemon, OS lifetime link, deadline enforcement | **Works.** Windows job objects; Linux `setsid` + `PR_SET_PDEATHSIG` |
| MCP — transport, control and agent endpoints | **Works.** Upstream forwarding not implemented yet |
| GitHub adapter — PRs, comments, reviews, labels at settle | **Works** |
| Python SDKs — harness, agent SDK, LangChain, vLLM, Hugging Face, Jira/Linear, OCSF, K8s admission | **Work.** 4 of 12 on PyPI; the rest held by PyPI's new-project quota |
| Web console for non-developers | **Not built.** Data model and reducers exist; no UI in this repository |
| Published packages | **crates.io** 4/4 · **npm** 3/3 · **PyPI** 4/12 · prebuilt binaries for Linux, macOS (arm64 + x86_64) and Windows on the [v1.0.0 release](https://github.com/MuVeraAI-Corporation/Warrantor/releases/tag/v1.0.0) |

### Things that will bite you today

- **8 of the 12 Python packages are not on PyPI yet.** PyPI limits how many new projects an account
  may create in a rolling window, and that window is still closed. Every other channel is complete.
- **There is no web UI.** Everything is CLI, SDK or MCP.
- **`docker compose up` defines 17 services, and three of them are not services.**
  `flight-recorder`'s container is a health stub that answers every path identically;
  `kill-switch` and `credential-vault` are one-shot CLIs that exit. They are deliberately left
  unwired rather than connected to something that would treat their replies as real.
- **Outside Windows and Linux there is no kernel-enforced parent-death link.** The supervisor says so
  at start rather than implying a guarantee it cannot make.
- **About a third of the components in this repository are not wired into anything.** Many are
  standalone libraries where that is correct; some are not. The census is in
  [`docs/oss-readiness.html`](docs/oss-readiness.html).

Gaps are tracked openly: [`docs/integrations-inventory.html`](docs/integrations-inventory.html)
measures every integration surface and names what is built but unreachable.

---

## Repository layout

```
rust/          the core. `warrant/` is the primitive; trust-core, kill-switch,
               credential-vault, flight-recorder are the security components
python/        SDKs and integrations (warrantor_*) plus research components
go/            services: agent-identity, tee-serve, tenant-guard, fleet-marshal, …
typescript/    mcp-server, mcp-gateway, console (headless), arena
proto/         protocol contracts, generated into all four languages
docs/          design, architecture, and the honest inventories
deploy/        compose, helm, systemd, spire, modal
```

Cross-language contracts are generated from one protobuf source. `make check-protocols` rejects
drift and `make conformance` runs a shared test-vector matrix across Rust, Go, Python and
TypeScript — which is why a receipt emitted by the Python SDK verifies in the Go service.

---

## Development

```bash
make setup        # validate toolchains, install locked TS dependencies
make build        # every compiled workspace
make test         # Rust + Python + Go + TypeScript
make lint         # all four
make conformance  # cross-language vector matrix
make help         # everything else
```

One top-level command regardless of how many languages are present. Missing toolchains, an empty
project inventory and failed checks are fail-closed — never reported as a skipped green gate.

**Low-memory machines:** the Rust workspace is large. If you hit `failed to mmap / paging file too
small`, build with `CARGO_BUILD_JOBS=1 cargo build -j 1`.

---

## Where help is most useful

Ranked by how much they unblock, not by size:

1. **The web console.** Data model, view reducers and API client exist and are tested; nothing
   consumes them. The biggest gap, and well specified in
   [`docs/non-developer-platform.html`](docs/non-developer-platform.html).
2. **A read API over the warrant store.** Today it is JSON files under `~/.warrantor` on one machine;
   multi-user oversight needs a service.
3. **Upstream MCP forwarding.** The proxy decides correctly, but permitted pass-through calls have
   nowhere to go and currently say so.
4. **More settle adapters.** GitHub exists; GitLab, Jira and Slack are next, and `EffectPerformer` is
   a small trait.
5. **Lifetime-link coverage on macOS**, which falls back to `setsid` with no parent-death guarantee.

---

## Security

Please **do not** open a public issue for a vulnerability — see [SECURITY.md](SECURITY.md).

The threat model is written down in
[`docs/cross-cutting/21-threat-model.md`](docs/cross-cutting/21-threat-model.md). The property most
worth attacking is settle-authority separation: if you can make a supervised agent settle its own
warrant, that is the bug we most want to hear about.

---

## Governance and standards

Apache-2.0. Every commit needs a [DCO](https://developercertificate.org/) sign-off (`git commit -s`),
enforced in CI, plus conventional commit prefixes. See [CONTRIBUTING.md](CONTRIBUTING.md),
[GOVERNANCE.md](GOVERNANCE.md), [MAINTAINERS.md](MAINTAINERS.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Questions and support: [SUPPORT.md](SUPPORT.md).

Evidence is emitted as OCSF 1.9.0 (`class_uid 6003`), so it lands in Splunk, Sentinel or Chronicle
without a translation layer.

---

## A note on the name

This project is consolidating under the name **Warrantor**. Older documents and code paths still say
*Warrantor* or *Warrantor* — earlier names for the same work. They mean the same thing; the rename is in
progress and tracked openly. Provenance for how four earlier strategy portfolios were reconciled into
one component catalogue lives in
[`docs/00-reconciliation-matrix.md`](docs/00-reconciliation-matrix.md), which is maintainer history
rather than something you need to read to use this.
