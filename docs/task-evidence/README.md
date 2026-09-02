# Exit-gate evidence

One file per completed task, named `task-N.M.md`.

`scripts/task_status.py` reads this directory. A task whose branch is merged into
`origin/main` but which has no file here is reported as **UNEVIDENCED**, and
`--check` fails the build. That is deliberate: merged is not done. Done is merged
*and* the exit gate demonstrated.

Each file records, for the task's exit gate as written in the plan:

- the gate quoted verbatim from the plan
- the command that demonstrates it, and its actual output
- the merge SHA
- anything the task did differently from the plan, and why
- the bound strength of anything it introduced (Tier A cryptographic/OS,
  Tier B chokepoint, Tier C observed) — never a stronger tier than a refusal
  point in the code supports

Paste real output. A gate asserted in prose is the failure mode this repository
has a documented history of, and this directory exists to make asserting harder
than demonstrating.
