# Finding: the kernel kill drill cannot confirm a kill within its deadline on a busy machine

Found 2026-09-06 in the post-merge gate on `main` `03bae12` (the Task 7.6 merge), and reproduced
three times alone on the same tree: one pass, two failures. Recorded here rather than fixed,
because the failing behavior is the product being honest and the fix is a design decision.

## What happens

`rust/warrant/tests/conformance_receipt.rs::a_drill_on_this_kernel_produces_a_receipt_that_verifies_offline`
fails with:

```
DrillObservation { root_pid: 103016, descendant_pid: 62804,
  trigger_to_root_gone_ms: 18446744073709551615, trigger_to_descendant_gone_ms: 18446744073709551615,
  root_gone: false, descendant_gone: false, within_budget: false, refusal: None }
```

`refusal: None` means `TreeKiller::terminate` ran without refusing. `u64::MAX` for both timestamps
means the observation loop never saw either pid gone before its hard deadline of
`STOP_BUDGET * 2`, ten seconds. The tree was killed; the drill could not confirm it in time.

## Why

`warrantor_kill_switch_core::process_exists` on Windows spawns `tasklist.exe` for every existence
check, and `terminate` spawns it again for its own confirmation. The drill polls both pids every
25 ms, each poll paying one `tasklist` spawn. `kill-switch-core` already records that a spawn can
exceed two seconds under real-time antivirus scanning. On this machine at the time of the gate
there were 1,401 processes, four concurrent cargo test trees, and about 300 idle MCP plugin
servers; a `tasklist` enumeration under that load takes long enough that a handful of polls
exhaust the deadline. The same test passed on `main` `94119fc` twenty minutes earlier, with fewer
processes, and passed once in three reruns here.

Not attributable to the merge: Task 7.6 touched no file under `stop`, `conformance`,
`kill-switch-core` or `supervise`.

## What it means for the product, which is the part that matters

`conformance::mode_for` already derives the receipt's mode from the observation: a drill that
confirms both pids within `STOP_BUDGET` earns Enforced, and one that does not earns Advisory. On a
machine this busy, the conformance receipt would say **Advisory**, which is the honest word: a
stop whose completion cannot be observed inside the budget is not a stop the operator can rely on
inside the budget. The test asserts `root_gone && descendant_gone` unconditionally, so it turns
that honest downgrade into a red gate. That is defensible — a drill that did not look is not a
drill that passed — but it makes the gate's outcome a function of process count.

## What a fix would need to decide, and not decide here

- **Existence by handle, not by enumeration.** `OpenProcess` + `GetExitCodeProcess` on the two
  pids costs microseconds and does not scale with process count. `kill-switch-core` keeps `tasklist`
  for the image-name rail, which must enumerate; the existence rail need not. This is the likely
  fix and it is a change to a kill-switch rail, which is reviewed on its own.
- **Whether the test should follow `mode_for`.** If the receipt honestly says Advisory under load,
  the test could assert that honesty rather than the kill's timing. But the line-18 assertion is
  the only place that a tree left alive would fail loudly, and weakening it to accept "not
  observed" is the change this repository refuses by default. Leave it red until the rail is fixed.
- **CI does not see this.** The workspace runs on Ubuntu, where `process_exists` does not spawn
  `tasklist`. The Windows path is exactly the one the memory entry on ungated Windows paths warns
  about, and this finding is another instance.
