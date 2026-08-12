# Warrantor under systemd

`warrantor run` detaches its supervisor from the terminal, so closing the terminal ends your view
of a run rather than the run. It does not survive a reboot, and it is not a service you can
enumerate, restart, or read logs from with the usual tools. These units close that.

Two files, doing two different jobs:

| Unit | Job |
|---|---|
| `warrantor@.service` | Supervise one warrant as a first-class service |
| `warrantor-reconcile.{service,timer}` | Report warrants that nothing is supervising |

## Install

These are **user** units, and that is not a convenience choice. The warrant store is
`~/.warrantor`, the issuer and settle keys are yours, the worktree is in your checkout, and the
settle authority is you personally. A system-scope version would run all of it as root in the wrong
home with the wrong keys. There isn't a correct one.

```bash
mkdir -p ~/.config/systemd/user
cp warrantor@.service warrantor-reconcile.service warrantor-reconcile.timer \
   ~/.config/systemd/user/
systemctl --user daemon-reload
```

Then enable lingering, or systemd will stop your user services when you log out — killing the run
these units exist to protect:

```bash
sudo loginctl enable-linger "$USER"
```

## Supervising a warrant

Grant it first; the unit supervises an existing warrant, it does not create one.

```bash
warrantor grant --goal "fix the flaky auth test" --tools git,cargo \
                --write 'src/**' --deadline 8h --repo .
```

The unit needs to know what command to run. It reads one file per warrant:

```bash
mkdir -p ~/.warrantor/run
echo 'WARRANTOR_AGENT_COMMAND=claude -p "fix the flaky auth test"' \
  > ~/.warrantor/run/wrt_0bf079be9e95b7e5.env

systemctl --user start warrantor@wrt_0bf079be9e95b7e5
journalctl --user -u warrantor@wrt_0bf079be9e95b7e5 -f
```

Stopping the unit stops the whole agent tree, including anything it spawned:

```bash
systemctl --user stop warrantor@wrt_0bf079be9e95b7e5
```

That is `KillMode=control-group`. The default, `process`, would signal only the supervisor and leave
build tools, language servers and test runners running — the same orphan the job object exists to
prevent, reintroduced through a unit file.

## Two things these units deliberately do not do

**They do not restart a failed run.** `Restart=no` is a refusal, not an omission. An agent
interrupted mid-task has unknown state: it may have half-applied an edit, or staged three effects of
a five-effect sequence. Restarting it re-runs work that may already be done, against a worktree
nobody has looked at. Warrantor reports an interrupted warrant and asks you to settle or void it; a
`Restart=` line would silently overrule that.

**They do not resume after a reboot.** Same reason. What the reconcile timer gives you is not
recovery — it is *visibility*. The failure being fixed is not that a run stopped; the agent died
with its supervisor, so nothing is running unsupervised. The failure is the silence afterwards,
while you believe work is still progressing.

```bash
systemctl --user enable --now warrantor-reconcile.timer
journalctl --user -u warrantor-reconcile
```

It runs two minutes after your session starts and every thirty minutes after that. Half an hour,
not half a minute: nothing is at risk while you wait, only your knowledge of it.

## Hardening

`warrantor@.service` bounds what the *supervisor* can reach. What the *agent* may do is the
warrant's job — they are different boundaries and conflating them produces failures that read as
agent misbehaviour.

`ProtectHome` is deliberately absent from the template. The agent writes to a git worktree inside
the repository being fixed, somewhere in `$HOME`, at a path not known when the unit was written.
`ProtectHome=read-only` would fail every legitimate write and look like a broken agent rather than a
sandbox denial.

To tighten it for one repo, use a drop-in — systemd does not expand variables in these directives,
so the path has to be literal:

```bash
systemctl --user edit warrantor@wrt_0bf079be9e95b7e5
```

```ini
[Service]
ProtectHome=read-only
ReadWritePaths=%h/.warrantor %h/src/your-repo
```

## Why the unit calls `supervise`, not `run`

`warrantor run` forks a detached supervisor, because a terminal is not one. systemd *is* one. Under
`run`, systemd would watch the launching process exit and mark the unit dead while the agent was
still going — the exact orphan the design forbids. `supervise` is the daemon body: it stays in the
foreground and holds the agent under the OS lifetime link, which is what systemd needs to track.

## Platform note

Linux only. On Linux the lifetime link is `setsid` + `PR_SET_PDEATHSIG`; on Windows it is a job
object with `KILL_ON_JOB_CLOSE`, and `warrantor run` is the supported path there. Run
`warrantor run --help` — the linkage in force is reported at start, including when a platform cannot
guarantee one.
