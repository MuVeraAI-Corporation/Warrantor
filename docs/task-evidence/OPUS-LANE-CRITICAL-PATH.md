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
