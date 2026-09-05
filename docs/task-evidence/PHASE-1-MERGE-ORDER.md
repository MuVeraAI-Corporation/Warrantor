# Phase 1 merge order — computed, not guessed

Six branches, and they are far more collision-dense than Phase 0's four were. Measured from each
task's own **Files** block on 2026-09-05, with `origin/main` at `e4b5f10`:

| File | Tasks that touch it |
|---|---|
| `docs/W1-delivery-gaps.md` | **all six** — 1.1, 1.2, 1.3, 1.4, 1.5, 1.6 |
| `rust/warrant/src/bin/warrantor.rs` | **five** — 1.1, 1.2, 1.3, 1.4, 1.6 |
| `rust/warrant/src/lib.rs` | **four** — 1.1, 1.2, 1.3, 1.4 |
| `rust/warrant/src/serve.rs` | 1.1, 1.3 |
| `rust/warrant/src/report.rs` | 1.1, 1.2 |
| `rust/warrant/src/mcp_endpoints.rs` | 1.2, 1.4 |
| `rust/warrant/src/proxy.rs` | 1.2, 1.4 |
| `rust/Cargo.toml` | 1.3, 1.5 |

This is Phase 4's four-branches-on-`console.js` problem again, one layer down and worse: **five
branches on one binary's entry point.** Phase 4 produced seven conflicts and a keyboard collision
that needed a written rebind plan to recover. Phase 1 will produce more unless the merges are
ordered.

## The order

**1.1 → 1.5 → 1.6 → 1.2 → 1.3 → 1.4**

Reasoning, in the order the reasons matter:

1. **1.1 first, because it is the keystone.** Its own anchor says everything in Phases 1-2 is
   meaningless until it lands. It also touches the widest surface — `lib.rs`, `report.rs`,
   `serve.rs`, `warrantor.rs`, plus new `receipts.rs`. Merging it first means the other five rebase
   onto its shape rather than it rebasing onto theirs, which is the direction that preserves the
   keystone's structure.
2. **1.5 second, because it is nearly collision-free.** Its only shared file is the gaps ledger, an
   append. It lives in `rust/delegation-chain` and `rust/evidence`, which nothing else in Phase 1
   touches. Free to land whenever it is ready.
3. **1.6 third.** Two shared files (`warrantor.rs`, the ledger) and the smallest footprint of the
   remaining four.
4. **1.2 before 1.4**, because they share `mcp_endpoints.rs` and `proxy.rs` and 1.2 is the one that
   establishes the destination catalog 1.4's budget path reads.
5. **1.3 between them** — it shares `serve.rs` with 1.1, already landed by then, and `Cargo.toml`
   with 1.5, also landed.

## The rule that matters more than the order

**Rebase-verify-merge, one at a time.** After each merge, the next branch rebases onto the new
`main` and re-runs its own full gate before merging. A branch verified against a `main` that no
longer exists is not verified.

That is not a preference. Batch-merging five individually-green pull requests broke `main` five
separate ways on 2026-08-14, and merging Task 0.3 in this session refused on the sixth way — a
README number that had gone stale because Task 0.1 changed the workspace member count underneath it.
Every one of those was two changes that were each correct and jointly wrong.

## Per-merge gate

Cargo's own exit code captured **before any pipe** — a pipeline's status is the last command's, and
piping `cargo test` through `tail` produced a false green in this session. Full log to a file.

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace -j 2          # capture $? directly, log to a file
python tools/ci/wiring_census.py
python tools/ci/check_invariant_ratchet.py
python tools/ci/check_invariants.py
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" <prose>
```

`docs/W1-delivery-gaps.md` will conflict on all six merges. It is an append per task at a distinct
offset, so the resolution is always **keep both entries**; the conflict is positional, never
semantic.

## What to watch for that the gate cannot see

The census and the ratchet catch a falling number. They do not catch a **rendered** number drifting
from the record it cites — that is what refused the Task 0.3 merge, and only because
`readme_renders` ties the README row to `evidence/wiring-coverage.json`. Phase 1 adds per-effect
receipts and a delegation algebra, both of which produce numbers that surfaces will render. If a
task publishes a count into prose, check that something asserts the prose against the record.
