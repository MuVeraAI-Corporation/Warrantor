# Task 1.5 — One delegation algebra: evidence delegates to delegation-chain (L6-01)

**Branch:** `feat/task-1.5-one-delegation-algebra` (from `origin/main` @ `e4b5f10`)
**Worktree:** `M:/wt-t15` · `CARGO_TARGET_DIR=M:/wt-t15-target`
**Date:** 2026-09-05
**Commits:** `a7d9ab2`, `fd01832`, `2cab453`, `f40f403`, `ac185ed`, `21e0b86`, `01c860b`,
`97337cd`, plus this evidence file as the final commit.

---

## The exit gate, quoted verbatim from the plan

Task 1.5's own acceptance paragraph:

> **Acceptance, restated against what the code can show:** one implementation of the chain
> intersection in Rust (`intersect_chain`), consumed by the evidence crate and therefore by
> `warrantor verify`'s offline path through `report.rs:1021`; the A2 four-deep revocation test
> passes; the B-02 property holds for 2,000 random chains with the adversarial half;
> `warrantor-delegation-chain` is reachable from `warrantor-warrant` (`cargo tree` count 1); the
> proof format is unchanged by test; the ledger names the two remaining copies rather than claiming
> they are gone.

Step 13's census statement:

> on `origin/main` the workspace goes 38 → 39 members and reachable-from-`warrantor` goes 9 → 10,
> so the orphan count stays 29 (the new member arrives wired)

Phase 1's exit gate from the phase map:

> Each of the four planes reachable from the CLI and present in a signed bundle produced by a live
> run; `warrantor verify` checks it offline

The verification gate the anchor quotes from L6-01:

> Property test: for all chains and all requested authorities, granted ⊆ every ancestor. ... a
> four-deep chain where revoking the root makes every descendant's staged action refuse at bind,
> and the deepest receipt names all four issuers (S64 §3 A2).

---

## The real output of the commands that satisfy it

### One implementation, consumed by the evidence crate

`rust/delegation-chain/src/lib.rs` now holds the only chain fold, `intersect_chain`, beside the
pairwise `intersection` it folds. `rust/evidence/src/lib.rs` computes no intersection of its own:
`narrow_chain` maps a `DelegationLink` to a `WarrantScope` (`scope_of`) and calls `intersect_chain`;
`recompute_intersection` is `narrow_chain(chain).unwrap_or_default()`; `verify_authority` calls
`narrow_chain` first and propagates its refusal. The retired `HashSet` fold survives only inside a
test, as the drift guard.

### `cargo tree` count 1, and tokio unchanged

```
$ cargo tree -p warrantor-warrant -e normal --prefix none | grep -c "^warrantor-delegation-chain "
1
$ cargo tree -p warrantor-warrant -e normal --prefix none | grep -c "^tokio "
8
```

The same command on a detached worktree of `origin/main` also prints `8`. Recorded as a number, not
as a claim: this task neither added nor removed a tokio edge.

### The four suites this task owns

From the single full-workspace run logged to `M:/wt-t15-logs/g-test.log`:

```
     Running unittests src\lib.rs (...warrantor_delegation_chain-e0f79c5cb16056fe.exe)
test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

     Running unittests src\lib.rs (...warrantor_evidence-f07a86930adb1127.exe)
running 28 tests
test result: ok. 28 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.11s

     Running tests\delegation_algebra.rs (...delegation_algebra-671f2165dfac4596.exe)
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.35s

     Running tests\four_deep_revocation.rs (...four_deep_revocation-b04b4a70e9d26e3b.exe)
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```

`delegation_algebra` is the B-02 property over `CASES = 2_000` generated chains with a fixed seed.
It asserts the generator's own coverage (`narrowing > 1_000`, `widening > 100`), so a generator that
stopped producing widening chains fails rather than passing vacuously. Each refusal assertion is
paired with an allowed control: the narrowing branch asserts the honest authority block IS accepted
before it asserts every forged variant is refused. It was watched failing against the pre-Step-7
tree before being accepted:

```
$ git checkout HEAD~2 -- rust/evidence/src/lib.rs rust/evidence/Cargo.toml
$ cargo test -p warrantor-evidence -j 2 --test delegation_algebra
error[E0432]: unresolved import `warrantor_evidence::narrow_chain`
error: could not compile `warrantor-evidence` (test "delegation_algebra") due to 1 previous error
```

### The Rust gate, every command's own exit code

```
$ cargo fmt --all -- --check                                     FMT exit=0
$ cargo clippy --workspace --all-targets -j 2 -- -D warnings     CLIPPY exit=0
$ cargo test --workspace --all-targets -j 2                      TEST exit=0
$ cargo metadata --format-version 1 --locked                     exit=0
```

`cargo test --workspace --all-targets -j 2`: 104 suites reported `test result: ok`, 1,415 tests
passed, 0 failed. Full log at `M:/wt-t15-logs/g-test.log`; the exit code was captured from cargo
itself, not from a pipeline, and the log was written whole rather than tailed.

### The Python gates

```
$ python tools/ci/wiring_census.py
wiring census: 10 of 40 crates reachable from warrantor-warrant over 18 path edges
exit=0

$ python tools/ci/check_invariant_ratchet.py
invariant ratchet: ok (65 passing at floor 65, 19 recorded findings at ceiling 19)
exit=0

$ python tools/ci/check_invariants.py
invariant ledger: 12 invariants; enforced=2, orphaned=2, partial=7, unimplemented=1
exit=0

$ python tools/ci/check_docs.py
RESULT: PASS - 260 Markdown files, 58 RFCs, 81 catalogue rows, and all local links validated
exit=0
```

The census number moved 9/39 → 10/40 over 17 → 18 edges, and **the orphan list still holds 30
entries** — `warrantor-delegation-chain` is not on it. The orphan count did not rise. The record was
rewritten by `python tools/ci/wiring_census.py --write`, never by hand, and README.md's status row
(itself a gate inside the same script) moved with it.

### The invariant corpus contract this task was told not to break

```
test i02_no_authority_expansion::the_two_intersection_implementations_still_agree ... ok
test i02_no_authority_expansion::the_chain_intersects_rather_than_unions ... ok
test i02_no_authority_expansion::a_capability_dropped_by_one_link_cannot_be_exercised ... ok
test i02_no_authority_expansion::a_forged_intersection_proof_is_refused_even_when_the_capability_set_is_honest ... ok
test i02_no_authority_expansion::both_implementations_name_this_invariant_in_their_refusal ... ok
test i02_no_authority_expansion::hop_06_a_forged_admin_token_does_not_survive_receipt_verification ... ok
test i02_no_authority_expansion::the_intersection_proof_is_recomputable_by_a_stranger ... ok

test result: ok. 65 passed; 0 failed; 19 ignored; 0 measured; 0 filtered out
```

Neither named test needed weakening, and neither was edited.
`the_two_intersection_implementations_still_agree` survives because all four of its cases still
agree under the new fold: three narrow, and its one widening case (`[["a"], ["b"]]`) is a chain
whose set intersection is also empty, so the refusing fold and the notary's set fold both return
`[]`. That agreement is a property of those four cases, not of the two implementations — see the
residual below.

### The proof format did not move, in two languages

The in-crate drift guard
(`the_delegated_fold_matches_the_retired_algorithm_on_every_narrowing_chain`) keeps the retired
`HashSet` fold verbatim and asserts, over an empty chain, a two-link chain and a four-link chain,
that the delegated fold agrees with it, that `algorithm` is still `warrantor-intersect-v1`, and that
`result_digest` is byte-identical to what a v1 verifier computes.

Cross-language, with a bundle from a real Rust run rather than a fixture:

```
$ cargo run -q -p warrantor-evidence --example issue_sample_chain
Rust issued pre_commit->post_commit chain -> ../../.evidence_interop.json
$ PYTHONPATH=src python -m pytest -q
13 passed in 0.30s
```

The Python `warrantor_evidence` set-fold verifier accepts the chain a delegated-fold Rust build
issued, with identical digests. (Without that bundle the three interop tests skip: `10 passed,
3 skipped`. Nothing in `.github/workflows/ci.yml` produces the bundle, so in CI they skip — the
plan's claim that this interop check "runs in CI's Python job" is wrong. It ran here, by hand.)

---

## Honest tier of every bound introduced

| Bound | Where it refuses | Tier | Why not higher |
|---|---|---|---|
| A widening link in a chain is refused by index | `evidence::narrow_chain` → `delegation_chain::intersect_chain` returns `Err`; `verify_authority` propagates it | **B — chokepoint** | It refuses at the moment the authority block is verified, and `warrantor verify` reaches it through `report.rs:1021`, so a caller on that path cannot get past it. It is a library `Result`, not an OS or crypto boundary: a caller that never calls `verify_authority` is not bound at all. |
| A widening chain confers nothing | `recompute_intersection` returns `[]` for such a chain | **B — chokepoint** | Same path, same caveat. |
| A revoked lineage cannot bind | `evidence::bind_authority` returns `EvidenceError::Revoked` before it builds the block | **B — chokepoint** | It refuses at the moment of the bind attempt, in the function whose whole purpose is that attempt. But nothing in the shipped binary calls `bind_authority` yet, so today it binds nothing a user reaches — see below. |
| A warrant the store never issued does not stand | `WarrantStore::is_valid` returns `false` for an unknown id | **B — chokepoint** | A predicate consulted at bind, not an enforcement boundary. |
| The `warrantor-intersect-v1` proof bytes are unchanged | the drift guard test, plus the cross-language interop run | **C — observed** | A test is evidence about the code, not a refusal in it. Nothing at runtime refuses a format change; the test is what would go red. |
| Every level of a delegation narrows resources and budget | `WarrantStore::delegate` refuses `Escalation::Resource` / `Escalation::Budget` at issue time | **C — observed, from the receipt's point of view** | The refusal is real at delegation time (Tier B there), but a `DelegationLink` carries neither field, so **no receipt evidences it**. A reader of the receipt observes capabilities and `not_after`, nothing more. |

No bound in this task is Tier A. Nothing here confines a process, holds a key, or uses the OS.

---

## What this task does NOT establish

- **The binary does not drive the multi-link path.** `rust/warrant/src/report.rs` still builds a
  one-link chain from the warrant's own bounds and calls the two total functions. `bind_authority`
  is reachable and tested; it is not yet on any path a user runs, so **no live run has produced a
  receipt carrying a four-deep chain**. The A2 gate passes as an integration test, not as a receipt
  from the product. Phase 1's exit gate ("present in a signed bundle produced by a live run") is
  therefore *not* satisfied by this task alone.
- **The notary still holds a third copy of the fold.** `rust/notary/src/lib.rs:293
  effective_capabilities` is a `HashSet` intersection over `notary::DelegationLink`, unchanged. It
  sits in the verdict path whose `Verdict::Deny { gate }` carries only the gate, so folding it in
  would change which gate fires for a widening chain. Left, and recorded.
- **The two implementations now genuinely differ on a widening chain, and only the corpus's four
  cases hide it.** `notary::effective_capabilities` returns the set intersection of a widening chain
  (which can be non-empty); `evidence::recompute_intersection` returns `[]`. For
  `[["a","b"], ["a","c"]]` the notary would say `["a"]` and the evidence crate says `[]`. The
  corpus's `the_two_intersection_implementations_still_agree` contains no such case, which is why it
  still passes. On the deciding side the seam that test guards is **wider after this task, not
  narrower** — this is the finding, and it belongs to whoever next revises the notary's chain gate.
  Recorded in `docs/W1-delivery-gaps.md` § 3.7 and named here so the passing test is not read as
  evidence of agreement in general.
- **The Python verifier diverges, and accepts what Rust refuses.** Verified 2026-09-05: on a
  two-link chain whose child claims `admin`, `warrantor_evidence.recompute_intersection` returns
  `['read']` and `verify_authority` **accepts** a self-consistent authority block. It refuses a
  Rust-produced widening block, but on the capability-set mismatch
  (`effective_capabilities [] != recomputed intersection ['read'] (I-02)`), never by naming the
  link. A widening receipt forged entirely in Python passes the Python verifier.
- **The receipt does not evidence resource or budget narrowing, or a `not_before` floor.** See the
  tier table.
- **Revocation is a bind-time refusal only.** An archived receipt issued before a revocation still
  verifies, by the crate's own doctrine. There is no revocation channel, and none is introduced: no
  new trust root, nothing fetched over a network.
- **`intersect_chain` does not interpret units.** It compares two `u64`s. The field is named
  `expires_at_ms` and the evidence crate feeds it `not_after` in epoch seconds on both sides of
  every comparison. Correct, and only because both sides come from one function (`scope_of`).
- **Windows only.** Every run above is on this Windows box. Nothing in this task is
  platform-conditional — no `#[cfg]` was added or touched — so there is no second path to test, but
  the CI ubuntu leg has not yet run this branch.

---

## Deviations from the plan, and why

1. **Member counts.** The plan says `origin/main` has 38 members and the census reads 9 of 38.
   `origin/main` @ `e4b5f10` has **39** members and `evidence/wiring-coverage.json` records 9 of 39
   with 30 orphaned (Phase 0 landed `reputation` and others after the plan was written). The change
   is the same shape: 39 → 40 members, 9 → 10 reachable, **orphans 30 → 30**.
2. **Step 13 needed two files, not zero.** The plan says the census record is "rewritten by CI on
   push-to-main; do not hand-edit it". Task 0.3 shipped `wiring_census.py` as a gate that also
   asserts README.md's status row, and it exits 1 locally until both move. Resolved the way the tool
   itself instructs — `--write` for the record, and an edit to the one README row — in a separate
   commit (`01c860b`). No JSON was hand-edited.
3. **Ledger number is `3.7`, not the plan's `3.6`.** `### 3.6` is now taken on `main` by the
   Windows-CI entry that landed from Task 0.2. `3.5` is still held by the uncommitted revision in
   the working checkout, for the reason the plan gives. `3.7` collides with neither.
4. **The plan's Python claim is contradicted and was not copied into the ledger.** See above; the
   ledger states what the run showed instead.
5. **Step 6's predicted error count was 3, actual 2.** `narrow_chain` has two call sites in that
   step's tests, not three. The *reason* matched exactly
   (`error[E0425]: cannot find function 'narrow_chain' in this scope`), which is the thing that had
   to match.
6. **`#` rather than `###` for the TOML comment** the plan wrote in `rust/evidence/Cargo.toml`. Both
   are valid TOML comments; the single hash is the file's own convention.
7. **Not done: push and open a PR.** The plan's closing line says to push the branch and open a PR.
   Held back for human review, as instructed for this run. Nothing is merged.

## Unrelated finding, not fixed here

`docs/W1-delivery-gaps.md` carries 16 Britishisms outside the carve-outs on `origin/main`
(`honour`, `authorisation`, and others) — identical count before and after this task's insertion,
which itself adds none. The US-English gate is not wired into CI for this file. Out of scope for
Task 1.5; worth its own pass.
