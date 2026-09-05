# Task 1.1 — Evidence and notary into the report path (keystone; L7-02 seed, L7-07)

**Branch:** `feat/t11-effect-receipts` (from `origin/main` @ `e4b5f10`)
**Worktree:** `M:/wt-t11` · **Target dir:** `M:/wt-t11-target`
**Date:** 2026-09-05

**Commits, in Step order:**

| commit | Steps | what |
|---|---|---|
| `d0fe720` | 1–2 | the receipt log, `receipts_path`, `effect_digest`, the `ReceiptSink` trait |
| `9973904` | 3–4 | `EffectWitness`, `EvidencedPerformer`, the bundle section, `with_effect_receipts` |
| `6ef90ad` | 5 | the performer's tests: durable-before, chain-after, refusal-before |
| `3752c82` | 6–7 | `verify_effect_receipts` and the seven verification tests |
| `73aa9c1` | 8 | the additive rendering |
| `138a227` | 9 | the CLI and HTTP wiring |
| (this file) | 10–11 | the live run, the ledger, the changelog, this evidence |

---

## The exit gate, quoted verbatim from the plan

Phase map, row 1 (`## Phase map`):

> | 1 | Wire before widen: the four wirings | Part 11 "Wire before widen" | L7-02, L4-02, L4-23, L4-08, L0-03, L3-03, L6-01 (dedupe), L7-07, L10-01 | Each of the four planes reachable from the CLI and present in a signed bundle produced by a live run; `warrantor verify` checks it offline |

`### Task 1.1`, closing line:

> Merge only after rebasing on `main` and re-running the full gate in the worktree (the PR CI tests against old main). Exit criterion for the phase gate: the export from Step 10 and the two `verify` transcripts are in the PR description; Task 1.2 starts from this branch's merge commit, not from this branch.

`### Task 1.1`, Step 9's gate line:

> Gate: `cd M:/wt-t11/rust && cargo fmt --all -- --check && cargo clippy --workspace --all-targets -j 2 -- -D warnings && cargo test --workspace --all-targets -j 2 && cargo build --workspace --all-targets -j 2 && cargo metadata --locked > /dev/null`.

---

## Its actual output

### The live run — reachable from the CLI, in a signed bundle, verified offline

No GitHub credential is configured on this box, so `build_performer` fell back to `NoAdapter`.
The plan permits that and says what it costs: *"that run proves the receipt path, not the effect
path, and the entry must not claim more."* Two runs were made.

**Run 1 — the receipt path.** `M:/wt-t11-store`, warrant `wrt_d891c73cbcb70a62`.

```
$ warrantor grant --root M:/wt-t11-store --goal "chain smoke" \
    --tools github.create_pr,github.comment --write "src/**" --deadline 2h
warrant  wrt_d891c73cbcb70a62
goal     chain smoke
expires  1788632583 (7200s from now)

$ warrantor stage wrt_d891c73cbcb70a62 --root M:/wt-t11-store \
    --tool github.create_pr --arg title="chain smoke" --arg head=chain-smoke --arg base=main
staged  pr://staged/wrt_d891c73cbcb70a62/1

$ warrantor stage wrt_d891c73cbcb70a62 --root M:/wt-t11-store --tool github.comment \
    --target pr://staged/wrt_d891c73cbcb70a62/1 --arg body="issued under a pre-commit receipt"
staged  comment://staged/wrt_d891c73cbcb70a62/2

$ warrantor settle wrt_d891c73cbcb70a62 --root M:/wt-t11-store        # exit 1
  FAILED      pr://staged/wrt_d891c73cbcb70a62/1: github.create_pr was not performed: set
              WARRANTOR_GITHUB_REPO=owner/repo to enable the GitHub adapter. The effect remains staged.
  unreleased  comment://staged/wrt_d891c73cbcb70a62/2

stopped at pr://staged/wrt_d891c73cbcb70a62/1 (github.create_pr): ... Effects before it are real;
effects after it were not attempted.
  receipts    2 issued to M:/wt-t11-store\receipts\wrt_d891c73cbcb70a62.jsonl

warrant is now Held
```

**Correction to the plan's own prediction, recorded because it matters for what the run shows.**
The plan's fallback paragraph says *"both effects then fail"*. They do not: `settle` stops at the
first failure by design, so effect 1 failed and effect 2 was never attempted. One chain, two
receipts, not two chains and four.

The log, read back:

```
$ python -c "..."  # phase, receipt_id[:16], parent[:16], outcome.status
0 pre_commit  06b4c5ef72ae0403 parent= -                status= -
1 post_commit 06b4c5ef72ae0403 parent= 06b4c5ef72ae0403 status= failed
```

That shared id is the defect Step 7 found by test and this artifact confirms in the field: a WAR
post-commit is the pre-commit's predicate with a new phase, a parent pointer and an outcome, so
the two carry one `receipt_id`. `verify_effect_receipts` keys on `(id, phase)` for that reason.

```
$ warrantor report wrt_d891c73cbcb70a62 --root M:/wt-t11-store --export chain.json   # exit 0
── EVIDENCE ──
  2 staged effect(s)
  chain head 218024b491d302726cd1a9513e43097c08df2155d49d926d4d38e1445a58b3ff
  1 effect receipt chain(s) from 2 receipt(s): pre-commit before each effect, post-commit after (advisory)
    pr://staged/wrt_d891c73cbcb70a62/1    failed      06b4c5ef72ae

── SIGNED EVIDENCE ──
  bundle          ec29431682a3232402ca3c00d1c614c54f83132bd4b3ea2aab122ec51566e8e5
  authority       deny (policy)
  signed by       8a5d6ab96e43ca3709c4408efe8f099661bd67ef719fa882b463e6a0ce540d76
  receipts        Ed25519 (evidence, advisory) + Ed25519 (notary, observed)
  limitations     13 recorded in the bundle
  effects         1 receipt chain(s) attached and covered by this signature's key
exported  M:/wt-t11-live/chain.json
```

That last line is quoted as it was actually printed, before the correction below. `chain.json` and
every transcript beneath it are that file, unmodified. Re-running `report` after the correction
prints, over bundle `855758ddc15247b97ed339c992e0f5270586fa9f0d8c7e47ba1ed0d593f75453` (a different
digest only because `generated_at` moved):

```
  effects         1 receipt chain(s), each signed by this same key and checked separately from the bundle digest
```

Offline, on a second store root (`M:/wt-t11-verifier`) holding none of the first root's keys —
only `chain.json` and the hex, copied across:

```
$ warrantor issuer add smoke 8a5d6ab9…540d76 --root M:/wt-t11-verifier --note "read off the first store's terminal, 2026-09"
pinned   smoke -> 8a5d6ab96e43ca3709c4408efe8f099661bd67ef719fa882b463e6a0ce540d76

$ warrantor verify chain.json --root M:/wt-t11-verifier --issuer smoke    # exit 0
verified  ec29431682a3232402ca3c00d1c614c54f83132bd4b3ea2aab122ec51566e8e5
  anchor        pinned as `smoke` — the signature is bound to 8a5d6ab9…540d76, pinned at 1788625516 …
  effects       1 receipt chain(s) verified: pre-commit before each effect, post-commit after,
                every receipt signed by the key the anchor line binds
── WHAT THIS DOES NOT ESTABLISH ──
  … 13 limitations, the last of which is:
  - 1 per-effect receipt chain(s) are attached, each advisory: the pre-commit was signed before
    settle performed the effect and the post-commit after, which records what settle did, not that
    the agent held no other way to do the same thing in the world.
```

Three tampered copies of that file, each refused with the sentence naming what went wrong:

```
$ python -c "…d['effect_receipts'].pop(1)…" ; warrantor verify chain-cut.json --issuer smoke   # exit 1
warrantor: chain-cut.json does NOT verify: evidence receipt: commit-gate violation (I-07):
the post-commit receipt for pr://staged/wrt_d891c73cbcb70a62/1 is missing from the export

$ python -c "…d['effect_receipts'].pop(0)…" ; warrantor verify chain-nopre.json --issuer smoke # exit 1
warrantor: chain-nopre.json does NOT verify: evidence receipt: commit-gate violation (I-07):
the pre-commit receipt for pr://staged/wrt_d891c73cbcb70a62/1 is missing from the export

$ python -c "…append a duplicate…"        ; warrantor verify chain-stray.json --issuer smoke   # exit 1
warrantor: chain-stray.json does NOT verify: receipt does not bind to this bundle: the export
carries 3 effect receipt(s) and the bundle lists 2; receipts the bundle does not account for are refused
```

And the same file with **no** `--issuer`, which is where the first draft of that effects line was
untrue — it claimed the anchor bound the key while the line above it said `NONE pinned`:

```
$ warrantor verify chain.json --root M:/wt-t11-verifier          # exit 0
  anchor        NONE pinned — self-consistency only; see the limitations below
  effects       1 receipt chain(s) verified: pre-commit before each effect, post-commit after,
                every receipt signed by the same key as this report -- WHICH key that is, is not
                established here
```

**Run 2 — the refusal, which is the part the enforcement rule needs.** Warrant
`wrt_29954559a1272896`, granted `--tools github.comment` only. `warrantor stage` accepted a
`github.create_pr` effect, because staging still does not consult the tool allowlist:

```
$ warrantor settle wrt_29954559a1272896 --root M:/wt-t11-store      # exit 1
  FAILED      pr://staged/wrt_29954559a1272896/1: refused by the notary at the authority gate;
              nothing was performed

warrant is now Held

$ ls M:/wt-t11-store/receipts/wrt_29954559a1272896.jsonl
ls: cannot access '…': No such file or directory
```

A refused effect reaches no adapter and gets no receipt; the message names the gate and never the
capability. **Paired with its allowed control** rather than standing alone: in run 1 the same
warrant shape let `github.create_pr` through the gate and the adapter was reached (and failed for
want of a credential), and `tests/report_evidence_chain.rs::an_effect_for_a_tool_the_warrant_does_
not_hold_is_refused_before_it_is_performed` asserts both halves in one test — the comment refused,
the pull request performed.

### A recorded finding was earned, not merely satisfied

`rust/warrant/tests/invariants/i07_evidence_precedes_commitment.rs` carried this since 2026-09-02:

```
#[ignore = "I-07 orphaned: the product never issues a pre-commit receipt (Task 1.1 / Task 2.3, 2026-09-02)"]
fn the_product_issues_a_pre_commit_before_it_acts() { ... }
```

It passes now, so the `#[ignore]` is gone and the ratchet moved in the same commit, which its own
note requires (*"Raise the floor in the same commit that earns it"*):

```
before: invariant ratchet: ok (65 passing at floor 65, 19 recorded findings at ceiling 19)
after:  invariant ratchet: ok (66 passing at floor 66, 18 recorded findings at ceiling 18)
```

The test counts call sites, not ordering, and the rewritten doc comment now says so out loud — the
ordering is measured in `report_evidence_chain.rs` instead. Two other corpus findings name Task 1.1
and **stay ignored, correctly**: `i01…the_products_own_notary_call_consults_a_revocation_source` and
`i10…the_product_remembers_the_nonces_it_has_already_seen`. `EffectWitness::verdict_context` supplies
`revoked_svids: Vec::new()` and `seen_nonces: Vec::new()`, exactly as `report::build_observed` does
and exactly as the plan's interface specifies, so this task adds a second place where those two gates
pass over an empty set rather than closing either.

**A disagreement on `origin/main`, noted rather than fixed:** `evidence/invariants.json` had I-07 at
`partial` while the Tier 5 table and the corpus `#[ignore]` both said `orphaned`. The row this task
touched now reads `partial (was orphaned; issuance earned 2026-09-05)`, which agrees with the ledger.
The other rows were left alone.

### The gates

Run at the final tree state, each exit code captured into its own file **before any pipe** — the
task brief's warning about a pipeline's exit status being the last command's:

```
$ cargo fmt --all -- --check                                   exit 0
$ cargo clippy --workspace --all-targets -j 2 -- -D warnings    exit 0    (no error line in the log)
$ cargo test --workspace --all-targets -j 2                     exit 0    102 suites, 1397 tests passed, 0 failed
$ cargo build --workspace --all-targets -j 2                    exit 0
$ cargo metadata --format-version 1 --locked                    exit 0    (Cargo.lock untouched: no dependency added)
$ python tools/ci/wiring_census.py                              exit 0
wiring census: 9 of 39 crates reachable from warrantor-warrant over 17 path edges
$ python tools/ci/check_invariant_ratchet.py                    exit 0
invariant ratchet: ok (66 passing at floor 66, 18 recorded findings at ceiling 18)
$ python tools/ci/check_invariants.py                           exit 0
invariant ledger: 12 invariants; enforced=2, orphaned=2, partial=7, unimplemented=1
```

Baseline on `origin/main` @ `e4b5f10`, measured in this worktree before the first source change:
102 suites, 1384 tests (the count differs from the brief's 133 suites / 1385 tests because
`--all-targets` excludes doc-tests). The 13 added tests are `report_evidence_chain.rs`'s 12 plus the
un-ignored corpus test.

Each exit code is the command's own, captured before any pipe.

`node verify-us-english.mjs docs/W1-delivery-gaps.md CHANGELOG.md` **exits 1 with 26 findings — and
exits 1 with the same 26 findings on `origin/main`.** Checked mechanically rather than by eye:
`git show origin/main:<both files>` into a scratch directory and re-run gives `2 file(s) · 26
finding(s) · 5 protected by carve-outs`, identical. Every flagged line is outside the ranges this
task added (gaps 624–682, changelog 12–21); the flagged lines are 248…1049 and 36…609. This task
adds no Britishism and fixes none of the pre-existing ones, which are not its scope.

### The orphan count did not rise

```
wiring census: 9 of 39 crates reachable from warrantor-warrant over 17 path edges
```

Unchanged from `origin/main`. This task adds no crate; it adds a module inside `rust/warrant` and
calls `warrantor-evidence` and `warrantor-notary`, both already on the reachable list.

---

## The honest tier of every bound this task introduces

**No bound label moved, and `bound_strengths()` is byte-identical.**
`tests/report.rs::bound_strengths_are_copied_verbatim_and_nothing_is_upgraded` and
`tests/tier_disclosure.rs` pass untouched, and `rust/warrant/src/lib.rs` is modified only by the
one line `pub mod receipts;`.

| what this task adds | tier, in the vocabulary Task 0.4 fixed | why that word and not a stronger one |
|---|---|---|
| the per-effect notary verdict at settle | the `tools` bound stays **mediated** | the refusal is real and happens before the adapter, but it guards the *staged* path only. An agent holding its own credential opens the same pull request without passing here. No netns, no seccomp, no firewall stands behind it. |
| the pre-commit-before-effect ordering (I-07) | **not** promoted; the ledger keeps I-07 `partial` | there IS a line of code that refuses — `self.sink.record(&pre)?` returns before `inner.perform` — but the guarantee is held by a *wrapper*, so it holds where callers wrap and a bare `EffectPerformer` passed to `settle()` still bypasses it. Enforced would claim the wrap is unavoidable. It is conventional. |
| the receipts themselves | `evidence::EnforcementMode::Advisory`, `notary::EnforcementMode::Observed` | derived through the existing `report::notary_mode_for` so a report and its own effects cannot disagree. **Not `Mediated`**: settle mediates the staged path, not the world, and a receipt saying `mediated` would assert non-bypassability this system does not have. `verify_export` refuses any other mode -- see the correction below, because when this row was first written it did not. |

---

## What this task does NOT establish

- **It does not show a receipt preceding a successful external effect on this machine.** No GitHub
  credential was configured, so the one live chain records a failure. What the run shows is that
  the pre-commit was durable before the adapter was called and the post-commit recorded what the
  adapter returned. The effect path is still proven only by `tests/github_adapter.rs`, which this
  task did not touch.
- **It does not make the receipt log an external recorder.** L7-02 wants the record outside the
  agent's write authority. `receipts/<id>.jsonl` is on the same disk as the agent's worktree, under
  the same UID. The archive push files the *export*, not the log.
- **It does not make the wrap unavoidable.** `settle` still accepts any `&mut dyn EffectPerformer`.
  The CLI and the HTTP route wrap; the tests deliberately do not; MCP `settle_warrant` uses
  `NoAdapter` and performs nothing, so it issues nothing. A future surface that calls `settle` with
  a bare performer would perform effects with no receipt and nothing would stop it.
- **It does not close the gap between staging and authority.** `warrantor stage` still accepts an
  effect for a tool the warrant does not hold; the refusal now happens at settle, which is later
  than it should be. Task 2.1 owns the earlier refusal.
- **It does not read the log back on the HTTP `report` route.** The CLI `report`, the automatic
  filing at settle and `verify` do; `serve.rs`'s report route does not, so a console reader sees no
  effect-evidence section. The plan scoped serve.rs to the settle route only.
- **It does not verify the log against anything outside the export.** A log truncated *before*
  `report --export` ran produces an export that lists what survived and verifies perfectly. There
  is no `StagedChainMark` equivalent for `receipts/`; the staging queue has one and this log does
  not.
- **A corrupted log blocks every later settle of that warrant, deliberately.** `ReceiptLog::open`
  signature-checks every line and refuses on the first that does not verify, and `cmd_settle` opens
  the log before it performs anything — so one edited receipt makes the warrant unsettleable until
  somebody looks at it. That is the fail-closed choice, and it is a real operational cost with no
  repair verb behind it.
- **It does not establish the signer.** `verify` with no `--issuer` checks self-consistency only,
  and now says so on the effects line as well as in the limitations — the first draft of that line
  claimed "signed by the key the anchor line binds" even when the anchor line said `NONE pinned`.
  Corrected in the final commit.

---

## Deviations from the plan's literal text

1. **Commit granularity.** The plan's Step 2 commits `receipts.rs` while `ReceiptSink` (Step 3) does
   not yet exist, and its Step 3 says outright *"write both steps before compiling"* for Steps 3–4.
   Committed that way, two commits on this branch would not build, leaving a red CI gate on every
   commit — the exact failure the task brief warns about from Task 0.3. So `ReceiptSink` and
   `EFFECT_METHOD` moved into the Step 2 commit (they are declared in `settle.rs` either way), and
   Steps 3 and 4 share one commit. Every commit on this branch compiles and every gate passes on it.
2. **`verify_effect_receipts` looks up by `(receipt_id, phase)`, not `receipt_id`.** The plan's
   version returns the pre-commit when asked for the post-commit, because the two share an id; the
   symptom was `Evidence("phase violation: post_commit must have phase=post_commit")` — a true
   error about the wrong thing. Found by the plan's own Step 6 test.
3. **The `receipts N issued to <path>` line prints only when a receipt was issued.** Printing it
   unconditionally broke `tests/autofile.rs::an_unconfigured_machine_sees_no_notification_difference`,
   which asserts a settle on an unconfigured machine says nothing about notifications: the absolute
   store path contains that test's own tempdir name, `notify-unconfigured`. The path stays — printing
   full paths is this binary's house style and the operator needs it — but a settle that issued
   nothing has no path worth naming.
4. **`--root` goes after the verb.** The plan's Step 10 writes `warrantor --root %ROOT% grant …`;
   the binary answers `unknown command "--root"`. Flags follow the command on this CLI.
5. **Four measurement artifacts were edited that Step 11 does not name:**
   `evidence/invariants.json`, `tools/ci/invariant-ratchet.json`, the Tier 5 table in
   `docs/W1-delivery-gaps.md`, and the I-07 corpus test. All four carried a sentence that stopped
   being true in commit `9973904`. Task 0.5 left I-07's gap reading *"until Task 1.1 wires evidence
   into the report path"*, and the corpus test's `#[ignore]` read *"the product never issues a
   pre-commit receipt (Task 1.1)"* — leaving those would have hidden the one measurement that says
   this task landed, which is precisely the failure the ratchet exists to prevent. The ledger
   **status stays `partial`** for the reason in the tier table above, so
   `check_invariants.py` still reports `enforced=2, orphaned=2, partial=7, unimplemented=1`; the
   ratchet moved 65/19 → 66/18 in the commit that earned it, as its own note requires.
6. **Two output sentences were corrected for truth after the first live run** (see the last bullet
   above, and `render_signature_section`, which said the chains were "covered by this signature's
   key" when they sit outside the bundle digest on purpose).

## Not done

- **Step 10's second half, `git push` and `gh pr create`, was not run.** The task brief says do not
  push and do not merge; a human reviews. The export, both `verify` transcripts and the three
  tamper transcripts are in this file instead of a PR description.

---

## Correction: this file claimed a refusal that did not exist

Recorded rather than quietly fixed, because a false claim inside a signed-bundle disclosure is the
defect this repository's whole discipline exists to prevent, and the record of how it was caught is
worth more than a clean-looking file.

**What the row above claimed when first written:** that `verify_export` refuses a per-effect receipt
carrying any enforcement mode other than `Advisory`.

**What was true:** nothing anywhere read a per-effect receipt's `binding.enforcement_mode`.
`verify_effect_receipts` checked the signing key, the handle, the tool, the subject, the chain and
the status, and stopped. `evidence::check_mode_honesty` does not cover the case either -- it refuses
an *advisory* receipt that claims non-bypassability, never a *mediated* one, so
`check_mode_honesty(mediated_receipt, true)` returns `Ok`. And the report-level mode checks at
`report.rs:1136-1155` operate on `export.evidence_receipt`, the report's own atomic receipt, which
already existed on `main`.

So a chain re-signed with **the report's own issuer key** and `enforcement_mode = Mediated` passed
`verify_export`, passed `verify_export_signed_by`, and passed `check_mode_honesty(.., true)` -- while
the signed bundle still read *"each advisory"*, because `with_effect_receipts` wrote that word as a
string literal. A receipt could assert non-bypassability this system does not have, every verifier
would accept it, and the human-readable sentence beside it would say the opposite.

**How it was caught.** Three independent adversarial reviews of this branch -- claim-honesty,
evidence-truth and test-rigor -- found the same gap without seeing each other's work, and each proved
it by construction rather than by reading. test-rigor set `refuted=true` on that basis, which is why
this branch was not merged as it stood.

**What changed.**

1. `verify_effect_receipts` now refuses any per-effect receipt whose mode is not `Advisory`, on both
   the anchor-free and the pinned-key paths, and the error names the mode as the reason.
2. `with_effect_receipts` derives the mode word from the receipts instead of hardcoding it. A bundle
   that somehow holds a mixed set now says so rather than reading `advisory` regardless.
3. Two tests pin both, in `rust/warrant/tests/report_evidence_chain.rs`:
   `a_per_effect_receipt_claiming_mediated_is_refused_even_under_the_reports_own_key` carries the
   allowed control inline -- the unmodified export must verify first, so the refusal cannot pass by
   refusing everything -- and `the_bundles_sentence_about_the_receipts_names_the_mode_they_actually_carry`
   fails if the word ever becomes a literal again.

**Gate after the correction**, each cargo exit code captured before any pipe:

```
cargo fmt --check                            exit 0
cargo clippy --all-targets -- -D warnings    exit 0
cargo test --workspace -j 2                  exit 0
  134 suites, 1400 passing, 0 failed, 23 ignored
python tools/ci/wiring_census.py             9 of 39 crates over 17 path edges - unchanged
python tools/ci/check_invariant_ratchet.py   66 passing at floor 66, 18 findings at ceiling 18
python tools/ci/check_invariants.py          12 invariants; enforced=2 orphaned=2 partial=7 unimplemented=1
```

**What is still not claimed.** The refusal is a verifier check, so its tier is unchanged: a reader
who runs `verify_export` learns the mode is truthful. It does not stop a party who never runs the
verifier from believing a bundle they did not check, and it does not make the per-effect bound
stronger than Tier B -- `settle` still mediates the staged path and not the world.
