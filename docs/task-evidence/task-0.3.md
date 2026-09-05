# Task 0.3 — Orphan census as a ratcheting CI number (seed of L8-22)

**Branch:** `feat/wiring-census` (from `origin/main` @ `26d16df`)
**Worktree:** `M:/wt-0.3`
**Date:** 2026-09-05

**Two lanes wrote this task.** The zcode lane (GLM 5.3 Flash) wrote Steps 1–5 and half of Step 6,
committing as `AumOS Wave-1 <aumos@local>` in commits `0136d07`, `7e5bfc1`, `95e5429`, `df5301f`.
This lane completed Step 6 and wrote Steps 7 and 8. The split matters for the defect recorded at
the bottom of this file, so it is stated here rather than left to `git log`.

---

## The acceptance criteria, quoted verbatim from the plan

Task 0.3 carries no separate `Exit gate.` line; its acceptance is Step 9. From
`docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md`,
`### Task 0.3`, Step 9:

> Acceptance is read off the `Rust` job log: `Test the wiring census` shows `12 passed`;
> `Assert the wiring count did not fall` prints `wiring census: 9 of 38 crates reachable from
> warrantor-warrant over 17 path edges` and exits 0 with no `::notice::`.

and, for the ratchet:

> Proof that the ratchet has teeth, once, on the PR: push a throwaway commit that deletes line 56
> of `rust/warrant/Cargo.toml` (`warrantor-spend = { path = "../spend", version = "1.0.0" }`) — the
> ratchet must fail with `::error::wiring ratchet: 8 reachable is below the recorded floor of 9`

Step 6 states its own criterion:

> Run pytest → `12 passed`; run `python tools/ci/wiring_census.py` → exit 0, one line of output.

## Its actual output

### The test suite and the gate

```
$ python -m pytest tools/ci/test_wiring_census.py -q -p no:cacheprovider
............                                                             [100%]
12 passed in 1.11s

$ python tools/ci/wiring_census.py; echo "exit=$?"
wiring census: 9 of 38 crates reachable from warrantor-warrant over 17 path edges
exit=0
```

One line of output, exit 0, no `::notice::`. The number matches
`evidence/wiring-coverage.json` (`"reachable": 9`, `"total": 38`, `"edges": 17`) and the README row
added in Step 6.

### The ratchet has teeth

Run against a manifest-only copy of the workspace rather than by editing the tree, because three
other lanes hold worktrees on this repository and a temporarily broken `rust/warrant/Cargo.toml`
is not a state to leave reachable even briefly. The census reads `Cargo.toml` and nothing else, so
a copy of the 41 manifests is a faithful subject. `--floor` still resolves to the real committed
record.

```
$ python tools/ci/wiring_census.py --workspace <scratch>/rust; echo "exit=$?"
wiring census: 9 of 38 crates reachable from warrantor-warrant over 17 path edges
exit=0

$ sed -i '56d' <scratch>/rust/warrant/Cargo.toml    # the warrantor-spend edge
$ python tools/ci/wiring_census.py --workspace <scratch>/rust; echo "exit=$?"
wiring census: 8 of 38 crates reachable from warrantor-warrant over 16 path edges
::error::wiring ratchet: 8 reachable is below the recorded floor of 9 in M:\wt-0.3\evidence\wiring-coverage.json; a crate was unwired from warrantor-warrant
exit=1
```

Both the count and the edge count fall, and the refusal names the crate relationship that changed.
This is the plan's predicted string, not a paraphrase of it.

### The lint gates

```
$ python -m ruff check --select E,F,I,B,UP,SIM,RUF --ignore E501 --line-length 100 \
    --target-version py311 tools/ci/wiring_census.py tools/ci/test_wiring_census.py
All checks passed!

$ python -m ruff format --check --line-length 100 tools/ci/wiring_census.py tools/ci/test_wiring_census.py
2 files already formatted
```

### The CI steps parse, in the specified order

```
$ python -c "import yaml; d=yaml.safe_load(open('.github/workflows/ci.yml', encoding='utf-8')); \
    print([s.get('name', s.get('uses')) for s in d['jobs']['rust']['steps']][-6:])"
['Build all targets', 'actions/setup-python@v7', 'Test the wiring census',
 'Assert the wiring count did not fall', 'Regenerate the wiring coverage record',
 'Upload wiring coverage evidence']
```

Exactly the sequence Step 7 specifies: the existing build step followed by the five inserted steps.

---

## What this task does NOT establish

**The CI half of Step 9 is not satisfied and cannot be from here.** Step 9's acceptance is read off
a `Rust` job log on a pull request, and off a push-to-`main` run for the
`Regenerate the wiring coverage record` step and the `wiring-coverage` artifact. Nothing in this
file is evidence that those steps run green on a runner. What is established is that the YAML
parses, the step order is the specified one, and the two commands those steps invoke exit 0 and 1
where they should locally. The push and the PR remain open work.

**The number counts crates, not action paths.** Quoting the plan's own closing note: the L8-22 map
— "adding an unmediated harness lowers the number visibly" — needs receipts from a live run and the
harness inventory Phase 4 builds. This is the crate-level floor under that map. Nine reachable
crates is not nine mediated effects, and the row in the README says "Capabilities reachable from
the CLI" over a number that measures linkage. That wording is broader than what is measured.

**Bound strength: Tier C, observed.** The census reads manifests. It cannot see a crate reached by
a spawned subprocess, a dynamic load, an HTTP call to a sibling service, or a Cargo feature that is
off in this configuration. A crate this tool calls orphaned may still be reachable by a path Cargo
does not describe, and a crate it calls reachable is linked, not necessarily called. The refusal
lives in a CI step, so a change that lowers the count is refused at review time, not at run time.

---

## Deviation from the plan, with its reason

**The five CI steps carry `if: runner.os == 'Linux'` guards, which Step 7's snippet does not.**
Step 7 authorizes this in its own comment:

> If a Windows runner joins this job (Task 0.2's matrix), guard these five steps with
> `if: runner.os == 'Linux'` — one measurement per push is the point.

Task 0.2 does exactly that. `chore/windows-ci-runner` rewrites the `rust` job to
`runs-on: ${{ matrix.os }}` with a two-OS matrix. The guards are written now because they are
correct in both states: on today's single Linux runner they are a no-op, and after 0.2 merges they
prevent a duplicate measurement. Writing them later would mean a green build in between that
measures the same manifests twice and reports two numbers for one push.

`if: github.event_name == 'push' && runner.os == 'Linux'` on the last two steps preserves the
plan's push-only condition and adds the OS guard, rather than replacing one with the other.

---

## The defect this task exposed, and why it was not caught by its own gate

The zcode lane's Step 1 created `tools/ci/test_wiring_census.py` with an import list that omits
`README_PATH`, though the plan's Step 1 block names it. Nothing failed at that point, because no
test used it yet. In Step 6 the lane appended the test that does:

```python
def test_real_readme_renders_the_number() -> None:
    assert readme_renders(README_PATH, census(WORKSPACE_ROOT))
```

The plan predicts what that red should look like:

> Run pytest. Expected: `1 failed, 11 passed` — `assert False` from `readme_renders`.

What it actually produced was `1 failed, 11 passed` from `NameError: name 'README_PATH' is not
defined` — the right count, the wrong reason. The count matched the plan, so the run read as
on-plan and the lane stopped there, leaving the test uncommitted and the README row unwritten.

**The rule that would have caught it is in the lane's own prompt:** *confirm it fails, and confirm
it fails for the stated reason, not for a compile error somewhere unrelated.* A `NameError` is that
compile error. It is also the mirror image of the rule Task 5.1 is built on — an attack that fails
before reaching the boundary proves nothing — and it fails the same way: the assertion under test
was never evaluated, so the red said nothing about the README at all.

Fixing the import alone would not have turned the test green. It converts a `NameError` into a real
`AssertionError`, because the README genuinely did not carry the number. The masked assertion was
true. Both halves of Step 6 were needed, and the committed CLI gate was red for the same reason:
`python tools/ci/wiring_census.py` exited 1 on `::error::README status table does not show
'reachable from the CLI | **9 of 38**'` on every commit of this branch until now.

---

## Files

| File | What changed |
|---|---|
| `tools/ci/wiring_census.py` | Steps 2–4, zcode lane. Unchanged here |
| `tools/ci/test_wiring_census.py` | `README_PATH` added to the import list; the Step 6 test committed |
| `evidence/wiring-coverage.json` | Step 5, zcode lane. Unchanged here — the floor is 9 |
| `.gitignore` | Step 5, zcode lane. `/evidence/*` plus a negation, so the record is committable |
| `README.md` | Step 6: the status-table row, and the "About a third" bullet replaced with the measured number |
| `.github/workflows/ci.yml` | Step 7: five steps in the `rust` job, OS-guarded |
| `docs/W1-delivery-gaps.md` | Step 8: the ledger entry, with what it does not measure |

Not merged. A human reviews before merge, and the PR is where Step 9's remaining half is read.
