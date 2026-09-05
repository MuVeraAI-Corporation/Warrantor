# Task 5.1 — Invariant attack corpus in CI

**Branch:** `feat/task-5.1-invariant-corpus` (from `origin/main` @ `26d16df`)
**Worktree:** `M:/wt-task-5.1`
**Date:** 2026-09-02

---

## The exit gate, quoted verbatim from the plan

From `docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md`,
`### Task 5.1: Invariant attack corpus in CI`:

> **Exit gate.** Twelve suites exist, run in CI, the passing set ratchets, and every currently
> failing invariant is named in the ledger rather than hidden.

### Its actual output

Twelve suites exist, one per invariant, and the corpus enforces that itself rather than by
inspection — `fixture::every_invariant_has_a_suite_module` reads the directory:

```
$ ls rust/warrant/tests/invariants/
fixture.rs   harness.rs   main.rs   round_zero.rs   scenario.rs
i01_active_identity.rs                 i07_evidence_precedes_commitment.rs
i02_no_authority_expansion.rs          i08_non_delegable_human_authority.rs
i03_purpose_bound_data_use.rs          i09_failure_is_safe.rs
i04_current_policy.rs                  i10_replay_is_detectable.rs
i05_bounded_revocation_latency.rs      i11_self_change_is_governed.rs
i06_exact_artifact_identity.rs         i12_safe_state_is_reachable.rs
```

They run:

```
$ cargo test -p warrantor-warrant --test invariants -j 2
test result: ok. 65 passed; 0 failed; 19 ignored; 0 measured; 0 filtered out; finished in 0.10s
```

The passing set ratchets, and the ratchet has teeth on both counters — demonstrated by temporarily
falsifying the baseline and observing the refusal:

```
$ python tools/ci/check_invariant_ratchet.py
invariant ratchet: ok (65 passing at floor 65, 19 recorded findings at ceiling 19)

$ # with passing_floor temporarily raised to 70:
invariant ratchet: FAILED
  - the passing count fell from 70 to 65. The corpus guarantee set may only tighten.
exit=1

$ # with ignored_ceiling temporarily lowered to 15:
invariant ratchet: FAILED
  - the ignored count rose from 15 to 19. Every ignored test is an unfixed invariant violation,
    so this is a widening gap even though the passing count held.
exit=1
```

It is wired as a required gate. `.github/workflows/ci.yml` gains an `invariants` job, and
`required` gains it in `needs`, in `env`, and in the loop that asserts every result is `success`:

```
$ python -c "import yaml; d=yaml.safe_load(open('.github/workflows/ci.yml')); print(d['jobs']['required']['needs'])"
['dco', 'contract-plane', 'rust', 'python', 'go', 'typescript', 'conformance', 'docs', 'desktop', 'console', 'invariants']
```

Every currently failing invariant is named in the ledger: `docs/W1-delivery-gaps.md`, new
`## Tier 5` section, one table row per invariant with its status, its finding, its honest tier and
its fixing task. The naming is enforced rather than asserted — `i03`'s
`the_absence_of_an_implementation_is_recorded_in_the_ledger` fails if I-03 gains an implementation
without the ledger entry closing, and fails if the ledger entry is deleted while the invariant is
still absent.

---

## Deviation, stated deliberately: this task ran early

The plan's dependency spine puts Phase 5 after Phase 3, and Task 5.1's stated phase entry condition
is "Phase 3 complete". This ran now, before Phases 1-3, on purpose.

The corpus is a measuring instrument. An instrument built after the thing it measures claims to be
fixed can only confirm the claim; an instrument built before it establishes what was true first.
Nineteen of the findings below are statements about `origin/main` @ `26d16df` that could not have
been made later with the same authority, because by then the code would have moved and the question
would be whether the fix worked rather than whether the gap existed.

Nothing is promoted by this. Phase 5 is not marked started, no invariant is marked enforced, and no
invariant is fixed here — fixing is Phases 1-3 and doing it here would collide with the lane holding
those files.

The cost of running early is real and is stated: the corpus cannot exercise the recorder or the
response policy (Task 3.4, Task 3.5), because neither exists. Those two surfaces have no suite
coverage and will need cases added when they land.

---

## The nineteen findings

Eleven of the twelve invariants have at least one. I-02 has none.

Each is an `#[ignore]` test naming its invariant, its fixing task and the date, and each **fails**
when run. That was verified rather than assumed:

```
$ cargo test -p warrantor-warrant --test invariants -j 2 -- --ignored
test result: FAILED. 0 passed; 19 failed; 0 ignored; 0 measured; 65 filtered out
```

Zero of the nineteen pass. A "finding" that would pass if run is a fabricated finding, and this is
the check that rules them out.

| # | Invariant | Test | What it demonstrates |
|---|---|---|---|
| 1 | I-01 | `the_products_own_notary_call_consults_a_revocation_source` | `report.rs:753` sets `revoked_svids: Vec::new()`. The Identity gate searches an empty set on the only path in the binary that reaches it. |
| 2 | I-01 | `the_local_subject_is_an_issued_identity_rather_than_a_constant` | `DEFAULT_CLI_SUBJECT` is a compile-time string. Nothing issued it, nothing can revoke it. |
| 3 | I-03 | `the_authorization_request_carries_a_purpose` | The request the notary adjudicates has no purpose and no data class. |
| 4 | I-03 | `hop_02_a_shared_cache_read_for_another_purpose_is_refused` | Two grants issued for different purposes are byte-identical; `contains` cannot tell them apart. |
| 5 | I-03 | `hop_10_the_receipt_labels_the_provenance_of_what_drove_the_action` | The operation block records what was done, never where the instruction came from. |
| 6 | I-03 | `the_receipt_carries_the_purpose_the_data_was_tagged_with` | The WAR predicate has no purpose section. |
| 7 | I-04 | `the_product_evaluates_policy_more_than_once_per_action` | One `notary::verdict` call in `rust/warrant/src`. One evaluation cannot be both the start check and the commit check. |
| 8 | I-04 | `the_post_commit_receipt_records_its_own_policy_evaluation` | `issue_post_commit` clones the predicate, so `decision.evaluated_at` is identical on both receipts (`left: 1700000000, right: 1700000000`). |
| 9 | I-05 | `hop_05_the_product_links_a_credential_vault_that_can_revoke` | `credential-vault` implements the 1-second budget and is not in `warrant`'s dependency graph. |
| 10 | I-05 | `a_revocation_source_exists_for_the_identity_half` | No revocation source, no propagation, no replica set. |
| 11 | I-06 | `the_product_submits_artifacts_to_the_artifacts_gate` | `artifacts: Vec::new()` and `verified_artifacts: Vec::new()`. The gate iterates an empty list on every action. |
| 12 | I-07 | `the_product_issues_a_pre_commit_before_it_acts` | Zero calls to `issue_pre_commit` in `rust/warrant/src`. |
| 13 | I-08 | `the_envelope_validator_checks_more_than_the_presence_of_an_approval` | `authority_spec::validate` step 4 tests `approvals.is_empty()` and nothing else. |
| 14 | I-08 | `an_approval_names_the_human_who_gave_it` | `notary::Approval` is two caller-supplied booleans. Humanness is unrepresentable. |
| 15 | I-09 | `the_product_links_the_preflight_that_refuses_an_unmeasured_boundary` | `eval-guard` is not linked by the binary. |
| 16 | I-10 | `the_product_remembers_the_nonces_it_has_already_seen` | `seen_nonces: Vec::new()`. Every call is the first call. |
| 17 | I-11 | `every_denial_reason_the_broker_renders_can_actually_be_reached` | `AgentCannotAmendCatalog`, `CatalogInvalidSignature` and `RedirectOutOfSet` are declared, rendered as prose, and constructed nowhere. |
| 18 | I-11 | `hop_04_a_redirect_out_of_the_resolved_set_is_refused` | `EgressRequest` has no redirect field, so the broker cannot observe hop 4 at all. |
| 19 | I-12 | `the_kill_path_is_stronger_than_advisory` | `STOP_ENFORCEMENT_MODE == "advisory"`. |

### Two violations recorded as *passing* tests, on purpose

`hop_07_the_broker_beneath_it_accepts_a_catalog_the_caller_extended` and
`an_unsigned_catalog_is_accepted_without_comment` demonstrate I-11 violations and pass. They use
`harness::reached_the_boundary_unrefused`, which asserts the attack **succeeded**. When the
invariant is enforced they start failing, with a message telling whoever fixed it to convert the
test, close the ledger entry and raise the ratchet. A finding that silently goes stale is a finding
nobody closes.

---

## The rule that makes the adversarial tests worth anything

Every attack runs twice: once with the attack backed out (the control, which must be allowed) and
once with it applied. `harness::refused_at_the_boundary` fails loudly on a refused control:

> the CONTROL was refused, so the attack never reached the boundary and its refusal proves nothing.
> This is a false pass. Fix the attack so the control is allowed; never weaken the assertion.

This caught a real false pass during construction. `a_child_warrant_cannot_widen_the_bounds_it_was_delegated`
gave parent and child the same `delegation_depth: 1`, and the control failed with
`Err(AuthorityExpanded("delegation_depth: child 1 must be below parent 1"))` — the attack was being
refused on the depth check and never reached the destination comparison it claimed to test. Without
the control it would have shipped green and asserted nothing.

Two attacks needed extra work to reach their boundary, and both say so in a comment:

* `an_orphan_post_commit_is_refused` re-signs the forged receipt via `scenario::sign_as_attacker`,
  because `verify_chain` checks both signatures **before** the commit gate. A hand-edited orphan is
  refused for being unsigned and never reaches the gate — a green result proving nothing. The test
  then calls `verify_receipt` on the forgery and asserts it verifies, proving the refusal came from
  the commit gate, and asserts the error text contains `orphan; I-07`.
* `every_denial_reason_the_broker_renders_can_actually_be_reached` first asserts that three
  *reachable* reasons are found by the same probe. If the probe were broken, every assertion after
  it would be a false pass.

---

## Full gate output

```
$ cargo fmt --all -- --check
(clean)

$ cargo clippy --workspace --all-targets -j 2 -- -D warnings
Finished `dev` profile [unoptimized + debuginfo] target(s)

$ cargo test --workspace --all-targets -j 2
exit=0 — 97 test binaries, 1351 passed, 0 failed, 24 ignored
(24 = the corpus's 19 findings plus 5 that were already ignored on origin/main)

$ python -m ruff check --select E,F,I,B,UP,SIM,RUF --line-length 100 tools/ci/check_invariant_ratchet.py
All checks passed!

$ python tools/ci/check_docs.py
RESULT: PASS — 254 Markdown files, 58 RFCs, 81 catalogue rows, and all local links validated
```

No existing test was deleted, skipped or weakened. The workspace test count rose by the corpus's
own 84 targets and by nothing else.

---

## Things that were not as the plan described, stated rather than smoothed over

1. **The `eval-guard` refusal string.** Task 0.5's Interfaces section quotes
   `"eval-guard: REFUSING to start the agent (invariant I-09: failure is safe; an unmeasured
   boundary is not a passing boundary)."` The text on `origin/main` at `rust/eval-guard/src/cli.rs:52`
   is the shorter `"eval-guard: REFUSING to start the agent (invariant I-09: failure is safe)."`
   The code is the source of record; the suite asserts the shorter form and the discrepancy is
   noted at the assertion.

2. **`evidence/invariants.json` does not exist on `origin/main`.** Task 0.5's ledger has not landed,
   so the corpus could not cite it. `fixture.rs` transcribes the twelve statements directly from
   `docs/02-architecture.md` §3 instead, and `statements_match_the_architecture_doc` re-parses that
   table at test time and refuses any divergence. This is a stronger anti-drift mechanism than
   citing the ledger would have been, and it will compose with the ledger when Task 0.5 lands.

3. **`docs/W1-delivery-gaps.md` carries 16 pre-existing Britishisms** (`behaviours`, `organisation`,
   `authorisation`, `labelled`, `judgement`, `honour`, and others at lines 318-939), which
   `verify-us-english.mjs` flags. None are in the Tier 5 section this task added, which is clean.
   They are left alone deliberately: fixing them would put a large unrelated diff on the file three
   other lanes are committing to concurrently. Reported, not silently repaired.

4. **`.github/workflows/ci.yml:327`** names a job "Browser console behaviour". Pre-existing; not
   touched, same reason.

5. **`python scripts/task_status.py --check` could not be run against this branch.** Neither
   `scripts/task_status.py` nor `docs/TASK-STATUS.md` is on `origin/main` — the script exists only
   in the dirty `docs/content-program-p9-fold` working tree, uncommitted, so it is not in this
   worktree to run. The requirement it enforces is met regardless: the script resolves evidence at
   `docs/task-evidence/task-{task_id}.md` (`scripts/task_status.py:95, 221`), and this file is at
   `docs/task-evidence/task-5.1.md`. It will be found when the board lands.

---

## Files

New, and owned by this task alone:

* `rust/warrant/tests/invariants/` — 17 files. `main.rs` (the test target root),
  `fixture.rs`, `harness.rs`, `scenario.rs`, `round_zero.rs`, and twelve suites.
* `tools/ci/check_invariant_ratchet.py` — the ratchet gate.
* `tools/ci/invariant-ratchet.json` — the baseline: `passing_floor: 65`, `ignored_ceiling: 19`.
* `docs/task-evidence/task-5.1.md` — this file.

Modified, minimally:

* `.github/workflows/ci.yml` — one job added; `required` extended by one entry in three places. No
  existing job restructured.
* `docs/W1-delivery-gaps.md` — one section appended at the end of the file. Appending was chosen
  over inserting entries into the existing tiers precisely because three other lanes commit to this
  file; each finding carries its honest tier inline instead.

No file owned by another lane was edited. `rust/Cargo.toml`, `rust/Cargo.lock`, `report.rs`,
`lib.rs`, `warrantor.rs`, `serve.rs`, `console.js`, `operators.rs`, `review.rs`, `notify.rs`,
`guard.rs` and `spend.rs` were read and never written. `cargo metadata` was not run and `Cargo.lock`
was not regenerated — the corpus adds no dependency, which is why it did not need to.

---

## Numbering

The suites cover the twelve **formal** invariants I-01…I-12 from `docs/02-architecture.md` §3. The
master blueprint's four **platform** invariants P1-P4 map onto I-02, I-07 and I-11+I-12 and are a
different set; neither was renumbered into the other, and this corpus tests only the first.
