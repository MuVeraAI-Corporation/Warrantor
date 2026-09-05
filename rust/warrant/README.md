# warrantor-warrant

**Give a coding agent bounded authority, walk away, and decide in the morning.**

A *warrant* is authority granted in advance, with hard limits, that the agent answers for
afterward. The agent works in an isolated git worktree. Anything irreversible — opening a pull
request, posting a comment, sending anything — is **staged, not performed**. In the morning you see
what changed, what it wants to do, and what it was refused, and you approve or discard.

```bash
cargo install warrantor-warrant

warrantor grant --goal "fix the flaky auth test" \
                --tools git,cargo --write 'src/**' --deadline 8h --repo .

warrantor run <id> -- claude -p "fix the flaky auth test"
# close your terminal. the run keeps going.

warrantor status          # in the morning
warrantor report <id>     # what changed, what it staged, what it was refused
warrantor settle <id>     # or: warrantor void <id>
```

## Why a warrant instead of a permission prompt

A permission prompt asks *"may I do this?"* at the moment of doing it, which requires you to be
there. A warrant answers a different question — *"what is this agent allowed to do at all?"* — once,
in advance, so the agent can work while you sleep.

Four properties make that safe rather than reckless.

**An absent limit means *none*, never *unlimited*.** An empty egress list is no network access. This
is what makes an honest *"it cannot do X"* statement possible at all.

**Irreversible actions are staged.** The agent asks to open a pull request and receives a typed
handle (`pr://staged/…`) instead of a pull request. It can compose further work against that handle —
a comment, a label — and at settle the real calls are issued in dependency order, with handles
resolved to the identifiers the API actually returned. You cannot un-send an email; you can decline
to send it.

**The agent cannot settle its own warrant.** It holds an act-scoped `CapabilityToken` with no settle
field — there is no message it can send that widens its own authority. Over MCP, the lifecycle tools
are not merely denied on the agent endpoint; they are absent from `tools/list`, so there is no name
to call.

**Every limit reports whether it is *enforced* or only *observed*.** Tools, write paths, egress and
deadline are enforced — the system refuses. Budget is observed, because model API calls do not pass
through this crate, so a spend ceiling is a measurement rather than a wall. `bound_strengths()`
returns which is which. A limit you believe in that does not hold is worse than no limit.

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

## Partial failure

If a settle fails halfway the warrant enters **Held** — not Settled, not Void — and stops at the
boundary rather than attempting to compensate. `SettleReport` names exactly which effects are real
and which were never attempted. Compensation assumes reversibility that external effects do not
offer, so the design reports the boundary instead of pretending to undo it.

## Supervision

`warrantor run` detaches the supervisor from your terminal, and holds the agent under an OS-enforced
lifetime link so it cannot outlive that supervisor:

| Platform | Mechanism | Agent survives supervisor being killed? |
|---|---|---|
| Windows | Job object, `KILL_ON_JOB_CLOSE` | No — the kernel closes the handle |
| Linux | `setsid` + `PR_SET_PDEATHSIG` | No, for the direct child |
| Other | `setsid` only | **Yes** — reported honestly rather than assumed |

That last row is deliberate. On a platform with no kernel parent-death link the supervisor says so
at start instead of implying a guarantee it cannot make.

## As a library

```rust
use warrantor_warrant::{Warrant, WarrantBounds, SideEffectClass};
```

`WarrantBounds` is the authority; `StagingQueue` holds effects until settle; `EffectPerformer` is the
trait an adapter implements to perform them. A GitHub adapter ships with the crate.

## Status

Pre-1.0. The core lifecycle, staging, worktree isolation, supervision and MCP transport work and are
covered by tests verified against real processes. Upstream MCP forwarding is not implemented yet, and
a permitted pass-through call reports the missing upstream rather than returning a success-shaped
nothing.

Licensed under Apache-2.0. Source, issues and the full documentation:
<https://github.com/MuVeraAI-Corporation/Warrantor>
