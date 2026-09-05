# The opus lane's critical path runs through one task the project cannot execute

Measured 2026-09-05 from `docs/task-routing.json` and `scripts/task_status.py`, with `origin/main`
at `e4b5f10` (Phase 0 complete, Task 5.1 landed).

## The finding

**7 of the 32 opus-routed tasks are reachable without human action. The other 25 sit behind
Task 3.2, which is routed `human` and needs hardware this project does not have.**

`resolve_blocks()` in `scripts/task_status.py:226` clears a phase gate only when **every** task in
the predecessor phase is DONE:

```python
phase_done = {
    p for p in {t.phase for t in tasks}
    if all(t.state == "DONE" for t in tasks if t.phase == p)
}
```

Phase 3 contains seven tasks. Six are GLM's. The seventh is **Task 3.2, "Hardware-backed custody
adapter behind a `Signer` trait"**, routed `human` with this reason recorded in `routing_notes`:

> "Needs a TPM or an OS keystore observed executing. macOS has never been installed or launched in
> this project."

And Phase 3 is a predecessor of phases 5, 6, 8, 9, 10, 12, 13 and 14 — **67 of the 117 tasks.**

## The dependency graph, measured

| phase | waits on | tasks | lanes | human-routed |
|---|---|---|---|---|
| 0 | — | 5 | glm 5 | — |
| 1 | 0 | 6 | glm 4, opus 2 | — |
| 2 | 1 | 6 | glm 5, opus 1 | — |
| 3 | 2 | 7 | glm 6, **human 1** | **3.2** |
| 4 | — | 5 | minimax 5 | — |
| 5 | 3 | 6 | glm 4, opus 2 | — |
| 6 | 4, 5 | 6 | glm 6 | — |
| 7 | 2 | 8 | glm 4, opus 4 | — |
| 8 | 2, 3 | 9 | glm 4, opus 5 | — |
| 9 | 1, 3 | 9 | glm 5, opus 4 | — |
| 10 | 1, 5 | 10 | glm 6, **human 1**, opus 3 | **10.10** |
| 11 | 4 | 13 | minimax 13 | — |
| 12 | 10 | 8 | glm 4, opus 4 | — |
| 13 | 8, 10 | 8 | glm 5, opus 3 | — |
| 14 | 9, 10, 13 | 11 | glm 6, **human 1**, opus 4 | **14.11** |

Transitive reach of each human gate:

- **Task 3.2** (phase 3) holds phases 5, 6, 8, 9, 10, 12, 13, 14 — **67 tasks**, of which **25 are
  opus**.
- **Task 10.10** (phase 10, sovereign key topologies) holds phases 12, 13, 14 — 27 tasks, a subset
  of the above.
- **Task 14.11** (insurance and settlement interface) holds nothing; phase 14 is terminal.

## Why this is a modeling error and not a real dependency

Task 3.2's own title is *"Hardware-backed custody adapter **behind a `Signer` trait**."* The trait is
the contract; the TPM adapter is one implementation of it. Every downstream task depends on the
trait, not on the hardware. Blocking 67 tasks on a keystore nobody can observe executing is the gate
being coarser than the code.

The same argument does **not** obviously extend to 10.10 and 14.11, which produce documents
containing decisions about jurisdiction and third-party obligation. Those are genuinely the owner's
to make, and a task that depends on a decision is legitimately blocked until the decision exists.

## What is reachable today without human action

Of the 32 opus tasks:

- **Phase 1** — 1.1 (in flight), 1.5 (in flight)
- **Phase 2** — 2.1, once all six Phase 1 tasks land; four of those six are GLM's
- **Phase 7** — 7.1, 7.4, 7.6, 7.7, once Phase 2 completes (phase 7 waits on phase 2 only)

That is 7 tasks. Everything else waits on 3.2.

## The options, not taken unilaterally

Changing what BLOCKED means is a scheduling decision with real consequences, so this document
records the choice rather than making it:

1. **Execute 3.2** — needs a TPM or OS keystore observed executing on this machine.
2. **Exclude human-routed tasks from phase-completion gates** — a phase counts satisfied when all
   its non-human tasks are DONE. Defensible for 3.2 specifically, because downstream work binds to
   the `Signer` trait. Weakens the gate everywhere at once, including for 10.10 and 14.11.
3. **Exempt 3.2 alone**, by name, with the reason recorded — narrowest change, and it keeps 10.10
   and 14.11 blocking as intended.

Option 3 is the recommendation: it is the smallest edit that matches what the code actually depends
on, and it does not quietly reinterpret the two gates that are genuinely decisions.

---

## Correction, 2026-09-05: this gate does not block implementation

The analysis above is correct about the dependency graph and wrong about what follows from it.

`resolve_blocks()` decides what the **status board reports**. It is a scheduling view derived from
`docs/task-routing.json`, a file written during seeding in this same program. It is not a compiler, a
CI gate, or a technical prerequisite. Nothing in it prevents a lane from writing code.

The question that actually decides whether a task can be implemented today is narrower and per-task:
**do its `Consumes` exist on the branch it would build from?** The eleven expanded opus tasks answer
that question explicitly, each in its own Consumes block, and several answer *yes* while the board
says BLOCKED:

- **Task 7.1** — its own expansion states that Steps 1-5 stand alone and Steps 6-9 need
  `rust/warrant/src/effects.rs` from Task 2.1. So five of nine steps are executable now.
- **Task 9.1** — the two `#[ignore]` reasons it converts are on `main`, and `credential-vault` is a
  crate on `main`. Executable now.
- **Task 5.3** — every artifact it attacks is on `main`, and Task 1.1 landing made its Strategy A5
  sharper rather than blocking it.

All three were started on that basis. The board still reads BLOCKED for them, and that is a defect in
the board rather than a reason to wait.

**What the gate genuinely costs.** `python scripts/task_status.py --next` is how a lane picks work
when it has no explicit list. A lane reading `--next` would see 67 tasks it cannot start. The GLM and
MiniMax lanes run from explicit task lists in their goal files rather than from `--next`, so the cost
is currently latent rather than actual.

**What is still owed, and by whom.** Task 3.2 itself needs a TPM or an OS keystore observed
executing, which is a human act on a machine that has one. That has not changed. What changed is the
claim that 25 opus tasks were waiting on it: they were waiting on a status view. The three options
recorded above are still the right options for making the board truthful, and option 3 is still the
recommendation — but it is a reporting fix, not an unblocking act, and nothing should wait for it.
