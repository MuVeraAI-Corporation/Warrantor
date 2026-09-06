
## Post-merge gate on main `371037d` (2026-09-06)

Run on the merged tree itself, not the branch, with `CARGO_BUILD_JOBS=2` from `rust/` and the
shared `M:/wt-merge-target`. Two earlier attempts on the same tree are recorded because each was a
false result: the first reported `exit=0` with `suites=0` (cargo was not on the background shell's
PATH; the count, not the exit, exposed it), the second died with `os error 1455` and rustc exit
`0xc000012d` (the Windows commit limit, 94 of 111 GB held by other processes) before any suite ran.

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 |
| `cargo test --workspace --all-targets` | 0; 119 suites, 1547 passed, 0 failed, 20 ignored |
| `cargo test --workspace --doc` | 0; 40 suites, 1 passed, 0 failed |
| Total passing | 1548, identical to the branch gate at `6eea354` |
| Wiring census | 13 of 41 crates over 22 edges (unchanged) |
| Invariant ratchet | 82 passing at floor 82; 15 recorded findings at ceiling 15 |
| Invariant ledger | 12 invariants; enforced 2, orphaned 1, partial 8, unimplemented 1 |
| `check_docs.py` | PASS, 268 Markdown files, 58 RFCs, 81 catalogue rows |
| `check_us_english.py 44fc3b8` | ok, 1445 added lines across 9 files |

The branch gate reported 153 suites; the difference is target selection only. `--all-targets`
counts six bench and example suites that contain no tests and does not run doctests, which are the
40 suites above. The passing total is the number that has to agree, and it does.
