# Getting help

## Where to ask

| What you have | Where it goes |
|---|---|
| A question about how to use it | GitHub Discussions → Q&A |
| Something is broken | GitHub Issues, with the template |
| An idea or a request | GitHub Discussions → Ideas, before opening an issue |
| A security vulnerability | **Not a public issue.** See [SECURITY.md](SECURITY.md) |
| A question about contributing | [CONTRIBUTING.md](CONTRIBUTING.md), then Discussions |

## Before you file a bug

Two commands make almost every report actionable, and without them we will only ask for them:

```bash
warrantor --version
warrantor status
```

Then tell us three things: what you expected, what happened, and what you ran. If a warrant is
involved, `warrantor report <id>` output is the single most useful thing you can paste — it shows the
bounds, the staged effects, and the refused requests together.

**Please redact before pasting.** Reports include tool names, file paths and goals. They do not
include the contents of files or any key material, but paths and goals can be sensitive on their own.

## Things that are usually not bugs

Worth checking first, because these come up often and each has a real reason behind it:

**"The agent was refused and I did not expect it."** Look at the `bound` in the message. An absent
limit means *none* in this system, not *unlimited* — an empty egress list is no network access. This
is deliberate, and it is what lets the tool state honestly what an agent cannot do.

**"My budget limit did not stop anything."** Budget is *measured*, not *enforced*, and is labelled
that way everywhere it appears. Model API calls do not pass through us, so we can report spend but
cannot refuse it.

**"The settle only did some of the work."** That is the design. On a partial failure the warrant goes
to **Held**, stops at the boundary, and reports which effects are real. It does not attempt to
compensate, because most external effects cannot be undone.

**"My agent died when I closed my terminal."** Use `warrantor run`, not `warrantor supervise`. `run`
detaches; `supervise` is the daemon body and stays in the foreground, which is what systemd wants.

**"The build ran out of memory."** The Rust workspace is large. Try
`CARGO_BUILD_JOBS=1 cargo build -j 1`.

## Response expectations

This is a pre-1.0 project maintained by a small team. We aim to acknowledge issues within a few
working days. Security reports are triaged ahead of everything else.

We would rather tell you a known gap than have you find it: the current honest state of the platform
is in [`docs/integrations-inventory.html`](docs/integrations-inventory.html) and
[`docs/oss-readiness.html`](docs/oss-readiness.html). If your problem is one of those, saying so in
the issue is still useful — it tells us which gaps people actually hit.

## Commercial support

None yet.
