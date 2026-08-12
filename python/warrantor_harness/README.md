# warrantor-harness

Wrap a coding agent session — Claude Code, OpenAI Codex, Cursor — so that what it does is bounded,
recorded, and cannot outlive its supervisor.

Where an MCP server governs individual tool calls, the harness governs the *session*: it owns the
agent process, watches everything it runs, and holds the whole process tree under an OS-enforced
lifetime link.

```bash
pip install warrantor-harness
```

No runtime dependencies. Python 3.11+.

## Why the process link matters

The failure this exists to prevent is quiet: your supervisor dies — crash, `kill -9`, a closed
laptop — and the agent keeps going. Unsupervised, past its deadline, still holding whatever
credentials it was given, with nothing left watching.

So the link is made by the kernel, not by a `finally:` block:

| Platform | Mechanism | Agent survives supervisor being killed? |
|---|---|---|
| Windows | Job object with `KILL_ON_JOB_CLOSE` | No — the kernel closes the handle |
| Linux | `setsid` + `PR_SET_PDEATHSIG` | No, for the direct child |
| Other | `setsid` only | **Yes** — reported honestly rather than assumed |

That last row is deliberate. On a platform with no kernel parent-death link the harness says so
instead of implying a guarantee it cannot make. `PR_SET_PDEATHSIG` also only signals the immediate
child, so grandchildren are reached via the session id rather than individually — stated because
the difference matters if your agent spawns build tools.

## Use

```python
from warrantor_harness import HarnessConfig, AgentType, secure_session

config = HarnessConfig(
    agent_type=AgentType.CLAUDE_CODE,
    working_dir=".",
    allowed_tools=["git", "cargo", "python"],
    kill_on_secret_exposure=True,
    max_duration_seconds=3600,
)

with secure_session(config) as session:
    result = session.run_agent("claude -p 'fix the flaky auth test'")

# The context manager closes the session and returns what happened.
```

Within a session the harness enforces the tool allowlist, records every file access, scans output
for credentials, emits an Agent Action Receipt per action, and terminates the whole tree on
timeout or on a secret being exposed.

`kill_on_secret_exposure` defaults to `True`: an agent that has printed a live credential has
already leaked it, and the useful response is to stop before it is used again.

## Read the agent's own config

The harness reads the config file your agent already has, so the bounds live where you edit them:

```python
from warrantor_harness import parse_claude_code_config, parse_codex_config, parse_cursor_config

config = parse_claude_code_config(".")   # CLAUDE.md
config = parse_codex_config(".")         # AGENTS.md
config = parse_cursor_config(".")        # .cursorrules
```

## CLI

```bash
# Generate a config file for your agent, pre-populated with the security envelope
warrantor-harness config --agent claude_code --dir .

# Run a command in a secured session
warrantor-harness run --dir . --timeout 3600 "claude -p 'fix the failing test'"
```

## What this does not do

It does not stage irreversible effects, isolate the working tree, or give you a settle/void
decision at the end. That is the `warrantor` CLI's job — the harness bounds a session, the warrant
bounds *authority*, and staged effects are how an agent gets to attempt something irreversible
without it happening yet.

Use the harness when you want an existing agent workflow watched and bounded. Reach for a warrant
when you want to walk away.

## License

Apache-2.0
