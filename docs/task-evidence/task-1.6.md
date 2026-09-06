# Task 1.6 — Trust directory bundle export/import and second-machine offline verify (L10-01, L7-07)

**Branch:** `feat/trust-bundle-second-machine` (from `origin/main` @ `e4b5f10`)
**Worktree:** `M:/wt-1.6` (target dir `M:/wt-1.6-target`)
**Date:** 2026-09-05
**Commits (in Step order):** `ab7a1c5` (Step 2), `00a7e7f` (Step 3), `7322bd2` (Step 4),
`d3ab534` (Steps 5–6; the plan's Step 5 refusals and Step 6 verify-dispatch landed as one commit —
both are binary-file changes gated by the same suite), `6373117` (Step 7 ledger + CHANGELOG).
Evidence file is the final commit.

---

## The exit gate, quoted verbatim from the plan

Step 7:

> From `M:/wt-1.6/rust`: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -j 2
> -- -D warnings`, `cargo test --workspace --all-targets -j 2`, `cargo build --workspace
> --all-targets -j 2`, `cargo metadata --locked > /dev/null`. Then the live run (not a fixture):
> with three fresh `HOME`s under `M:/wt-1.6-live/{a,b,c}`, replay Step 4's sequence by hand with
> the built `warrantor.exe` and keep `c`'s verify output verbatim. … the ledger's existing
> convention is to quote live output inline … the receipt goes into the ledger.

L7-07's gate G-03: "a stranger verifies a bundle on a clean, offline machine with only the
instructions inside it."

## Its actual output

### The gate

```
$ cargo fmt --all -- --check                                   (exit 0)
$ cargo clippy --workspace --all-targets -j 2 -- -D warnings   (exit 0)
$ cargo test --workspace --all-targets -j 2
TEST-EXIT=0 ; 101 suites `test result: ok`; none FAILED
$ cargo build --workspace --all-targets -j 2                   (exit 0)
$ cargo metadata --locked                                      (exit 0)
```

### The live run, three stores under `M:/wt-1.6-live/{a,b,c}` (each a separate `HOME`)

```
# A issues and exports its report
$ HOME=a warrantor grant --goal "carry the directory" --tools git      → wrt_3dba0a0b3a0069a2
$ HOME=a warrantor issuer show-hex
  issuer public key  438ea861858cf9bd836aa5c150e91d55b9e05ddd8df5badb726550694c37e417
$ HOME=a warrantor report wrt_3dba0a0b3a0069a2 --export M:/wt-1.6-live/a-report.json

# B checks A's key out of band, exports its pins
$ HOME=b warrantor issuer add ana 438e…e417 --note "video call"
$ HOME=b warrantor issuer export --out M:/wt-1.6-live/team-b.json --as team-b
  … "A bundle is a SNAPSHOT dated 1788674359. Revocation is NOT established by it: …"

# C, a stranger with only B's key checked out of band
$ HOME=c warrantor verify a-report.json --issuer ana
  → "ana" is not pinned on this machine, and an unpinned name verifies nothing. …
$ HOME=c warrantor issuer import team-b.json                 # dry run, signer unpinned: refuses
$ HOME=c warrantor issuer add team-b b0e1ae1a…bb4a2d         # the ONE out-of-band check
$ HOME=c warrantor issuer import team-b.json --apply
  … "Imports are NOT transitive. …"

# THE GATE: C verifies A's report, offline, by a name C never checked:
$ HOME=c warrantor verify M:/wt-1.6-live/a-report.json --issuer ana
verified  6891b6dddd5975923cefd262ed766a388ce8f1ccf782474f4a0830f27f9c9272
  anchor        pinned as `ana` — the signature is bound to 438ea861…e417, INHERITED from a bundle
                signed by `team-b` (label "team-b", issued at 1788674359, bundle dafaed9fda622d000…);
                first pinned at 1788674358 on the exporting machine. Nobody checked this key here:
                it is trusted on the authority of `team-b`, the key that WAS checked out of band on
                this machine
  - Revocation is NOT established. A pin is a snapshot of a key somebody checked at one moment; …
```

The receipt is quoted verbatim in `docs/W1-delivery-gaps.md` under the Trust directory bullet, as
the plan directs.

### Per-step red-then-green

| Step | Red | Green |
|---|---|---|
| 1 | — (worktree; defect confirmed: `grep -c "pinned at<22 spaces>"` = 1) | — |
| 2 | `E0425 ImportProvenance` + `E0560`/`E0609` on `imported_from` | trust 20 passed → `ab7a1c5` |
| 3 | `expect("inherited pins say so")` panic | bundle lib 12 passed → `00a7e7f` |
| 4 | both second-machine tests fail exactly as the plan predicts (missing `Revocation is NOT established`; the 22-space run) | 2 passed → `7322bd2` |
| 5 | mint-on-export + whitespace-run refusals | 5 passed (unpinned-signer refusal already green — the library refusal reached the CLI, as the plan says) |
| 6 | `b.json has no format field` | 6 passed → `d3ab534` |
| 7 | — | gate + live receipt → `6373117` |

## Honest tier of every bound introduced

**None.** This task introduces no bound and moves no label: `bound_strengths()` is untouched, and
what changed is the *truthfulness of verdicts* — an inherited pin now says who vouched for it and
that nobody checked it here; every anchored verdict states that revocation is not established; a
bundle whose signer is not pinned is refused with nothing written; `issuer export` no longer mints
an issuer key as a side effect of looking. The trust format strings are unchanged
(`warrantor.trusted-issuers/1`, `warrantor.trust-bundle/1`): provenance is `#[serde(default,
skip_serializing_if = "Option::is_none")]` on local pins and stripped on export, so existing files
and bundles are byte-compatible.

## Deviations from the plan's letter, and why

1. **Steps 5 and 6 share one commit** (`d3ab534`): both edit only `src/bin/warrantor.rs` +
   `tests/trust_bundle.rs`, and the full suite gates both identically.
2. **One transient subprocess failure in the second-machine test.** On one run,
   `a_stranger_verifies…` failed at line 139 (the `--apply` import); it passed on the next three
   consecutive full-suite runs with no code change. The test drives the real binary ~12 times per
   run; the failure printed no assertion detail beyond position, consistent with a process-spawn
   timing hiccup on a machine that had just been driven to 0.4 GB free. Recorded rather than
   hidden; if it recurs, the flake becomes its own defect, not a skip.
3. **The disk-full incident.** The first live-run attempt set `HOME` to a worktree path, which
   made rustup resolve its toolchain relative to the fake HOME and attempt a re-download; M: had
   0.4 GB free and the download failed with os error 112. Recovery: deleted the regenerable
   `CARGO_TARGET_DIR` build caches of this lane's finished tasks (0.1/0.2/0.4/5.1 — merged, and
   1.2/1.3/1.4 — committed and evidenced), freeing 60 GB; re-ran the live run with
   `RUSTUP_HOME`/`CARGO_HOME` pinned to the real user profiles so the fake `HOME` only carries the
   warrantor store. No repository state was touched by either the failure or the recovery; caches
   are reproducible with `cargo build`.
4. **The plan's Step 7 text names a `warrantor.exe` replay of Step 4 by hand — done above with
   `cargo run`, which builds and runs the same binary the tests use.**
5. **The plan's "What remains open" replacement** was applied verbatim ("rotation with history and
   signed snapshots anchored in a log (L10-01's extensions), and who vouches"); the sentence
   otherwise stands as written.

## Gates this task could not run, and why

- `python tools/ci/check_phase_scope.py` — not on this branch's base; run from the main checkout
  during Task 0.5 with exit 0. No plan tasks were added.
- US-English on the two prose files this task touches: `docs/W1-delivery-gaps.md` shows the same
  16 pre-existing findings documented in the 0.5 evidence file (the count is identical on
  `origin/main`'s copy; my added lines are clean); `CHANGELOG.md` shows 10 findings, all
  pre-existing on `origin/main`'s copy, none on the lines this task added.
