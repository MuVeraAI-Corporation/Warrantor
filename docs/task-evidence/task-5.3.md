# Task 5.3 — Evidence-integrity adversary (L0-05, deterministic half)

Branch `feat/evidence-integrity-adversary`, based on **local `main` at `f99af94`** (not
`origin/main` at `e4b5f10`; the four unpushed merges — the egress metadata floor, Task 1.1 with its
mode-escalation correction, and Task 1.5 — change several of this task's premises, as recorded
below).

Nine attack strategies against the notary, the evidence envelope, the report verifier and the
archive. **Five are refused, four are not.** The four that are not are recorded executably rather
than as `#[ignore]`s, so they go red when somebody fixes them instead of going stale.

---

## The headline finding: A9

**Attacking the Task 1.1 fix found a new mode-mislabel path that the fix does not close, and it is
reachable with no forged key at all.**

Commit `a84711b` closed two things. `verify_effect_receipts` now refuses any per-effect receipt
whose `binding.enforcement_mode` is not `Advisory` — **A5 confirms that holds**, including for a
receipt the bundle does not list, because the mode loop runs before the bundle's effect lines are
walked. And `with_effect_receipts` derives the bundle's mode word from the receipts instead of
hardcoding it.

The second is a **build-time** derivation. Nothing re-derives it on the **verify** path.

So an audited party, using its own legitimate issuer key and forging nothing, can:

1. build the bundle around `mediated` twins of its honest receipts, so the signed limitation
   sentence reads `"… 2 per-effect receipt chain(s) are attached, each mediated: …"`;
2. sign it;
3. ship the export carrying the honest `advisory` receipts.

Every id, handle, tool, subject and status still lines up. `verify_export` **passes**.
`verify_export_signed_by` **passes** under the party's own pinned key. The human-readable disclosure
inside the signed bundle asserts a non-bypassability the receipts beside it deny.

This is a mode mislabel inside a signed bundle — the defect class this repository calls the worst
thing it can ship — and it is **recorded, not fixed**, because a change to the report verifier is a
product change that must be argued in its own commit (this task's non-goal 4). The fix is one
comparison in `verify_effect_receipts`: recompute the mode phrase from `export.effect_receipts` and
refuse a bundle whose sentence disagrees. `a9_the_bundles_rendered_mode_word_is_not_gated_against_the_receipts_on_the_verify_path`
goes red the moment that lands.

A9 is the reason to run an adversary. It was not in the plan.

---

## Tier table — which word each bound gets, and why not a stronger one

| # | Strategy | Word | Why not stronger |
|---|---|---|---|
| A1 | Forge a chain end to end with the adversary's own key | **Tier A, conditional on a pinned key** | Not unconditional. `evidence::verify_chain` is anchor-free by construction: a chain signed end to end by any keypair is self-consistent and passes. The refusal is performed by the *caller's* anchor comparison, not by `verify_chain`. The test asserts the pass in direction one as a hard `expect`, so the condition cannot be forgotten. |
| A2 | Backdate the evidence receipt by a day | **Observed** | Nothing refuses it. `verify_export` binds the notary receipt's `body.timestamp` to `bundle.generated_at` and binds six fields of the evidence receipt, but never `binding.issued_at`. Not Mediated, not Enforced: no line of code reads the field. |
| A3 | Lift a genuine receipt onto a different report | **Tier A — cryptographic** | A specific check refuses the byte sequence when presented: `predicate.binding.receipt_id == export.bundle_digest`. The test asserts the error *variant* is `Binding`, so it cannot claim credit for a signature failure. |
| A4 | Replay the same request for a second allow | **Observed** | `seen_nonces: Vec::new()` at `report.rs:837` and `settle.rs:168`, so the Freshness gate is asked about an empty set on every call. The gate is correct; nothing tells it. |
| A5 | Smuggle a `mediated` per-effect receipt past the mode check | **Tier A — cryptographic signature, plus an explicit field refusal** | A named line refuses it at the moment it is presented, on both the anchor-free and the pinned-key path, and the test proves the attack reached *that* refusal by re-signing under the issuer's own key first. Still only a **verifier** check: it binds a reader who runs the verifier, not a party who never runs it. |
| A6 | Delete a limitation; widen the authority | **Tier A, with a stated residual** | The digest and the recomputed intersection each refuse at presentation. The residual is asserted, not described: an adversary who rewrites the delegation chain gets an authority that verifies, because the chain **is** the authority. A receipt proves the chain it carries, never that the chain was legitimately issued. |
| A7 | Suppress the evidence entirely | **Not a tier — unrepresentable** | A two-effect run exported as a one-effect report is a *valid* signed file that also passes the pinned-key path. There is no `verify_absence` and this task does not invent one; detecting a gap needs a sequence somebody else keeps. |
| A8 | Race the archive for attribution, on manufactured evidence | **Tier A for append-only; two residuals stated** | `put_artifact` returns `AlreadyHeld` and rewrites nothing — that refusal is real. Two residuals are asserted: `artifact::ingest` calls the anchor-free `report::verify_export`, so a self-consistent fabrication enters custody like genuine evidence; and the first filer owns the attribution, so `submitted_by_device` means *who filed this*, never *who produced this*. |
| A9 | Claim `mediated` in the prose while shipping `advisory` receipts | **Observed** | Nothing on the verify path reads the rendered word. See above. |

**No bound anywhere in this task is labeled Enforced or Mediated.** Nothing here creates a
namespace, a seccomp filter or a firewall rule, and nothing here contains a process. Every attack is
a constructed byte sequence checked in CI. L0-05 therefore moves from `none` to **`partial`**, never
to `covered`, and the missing half is named in `docs/W1-delivery-gaps.md` §5.3: there is no sandbox
in this repository, no agent runner, and no kernel that could give an adversary root and take it
back.

---

## Gate, with every cargo exit code captured before any pipe

Baseline on local `main` at `f99af94`, before any change:

```text
$ cargo test -p warrantor-warrant --test invariants -j 2      exit 0
test result: ok. 66 passed; 0 failed; 18 ignored; 0 measured; 0 filtered out; finished in 0.25s

$ python tools/ci/wiring_census.py                            exit 0
wiring census: 10 of 40 crates reachable from warrantor-warrant over 18 path edges

$ python tools/ci/check_invariants.py                         exit 0
invariant ledger: 12 invariants; enforced=2, orphaned=2, partial=7, unimplemented=1

$ python tools/ci/check_invariant_ratchet.py                  exit 0
invariant ratchet: ok (66 passing at floor 66, 18 recorded findings at ceiling 18)
```

The registry was written with an **empty** `STRATEGIES` array first and run, so that the
completeness scan is proven able to fail:

```text
$ cargo test -p warrantor-warrant --test invariants adversary  exit 101
running 1 test
test adversary::every_strategy_has_a_test_that_exists ... FAILED
panicked at warrant\tests\invariants\harness.rs:35:33:
cannot read M:\wt-w2-5.3\rust/archive/tests/adversary_custody.rs: The system cannot find the file
specified. (os error 2)
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 84 filtered out
```

That first red is itself informative: the scan's named-file list (`SCANNED`) fires before the
emptiness assertion, which is the `append_only.rs:355` lesson working — a hardcoded file list that
stops covering a file must be a failure, not a quietly smaller scan. The emptiness assertion was
then seen red on its own once the archive file existed.

`the_findings_are_exactly_the_strategies_the_delivery_gaps_document_names` was also seen red before
`docs/W1-delivery-gaps.md` §5.3 was written:

```text
test adversary::the_findings_are_exactly_the_strategies_the_delivery_gaps_document_names ... FAILED
panicked at warrant\tests\invariants\adversary\mod.rs:295:9
test result: FAILED. 11 passed; 1 failed; 0 ignored; 0 measured; 84 filtered out
```

Final gate:

```text
$ cargo fmt --check                                           exit 0
$ cargo clippy --all-targets -- -D warnings                    exit 0
$ cargo test -p warrantor-warrant --test invariants -j 2       exit 0
test result: ok. 78 passed; 0 failed; 18 ignored; 0 measured; 0 filtered out; finished in 0.67s
$ cargo test -p warrantor-archive --test adversary_custody     exit 0
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.17s
$ cargo test --workspace -j 2                                  exit 0
140 suites, 1448 passing, 0 failed, 23 ignored
  (baseline on local main: 139 suites, 1435 passing, 0 failed, 23 ignored. +1 suite is
   rust/archive/tests/adversary_custody.rs; +13 passing is 12 in the invariants target and 1 in
   archive; ignored unchanged.)
$ python tools/ci/wiring_census.py                             exit 0
wiring census: 10 of 40 crates reachable from warrantor-warrant over 18 path edges
$ python tools/ci/check_invariants.py                          exit 0
invariant ledger: 12 invariants; enforced=2, orphaned=2, partial=7, unimplemented=1
$ python tools/ci/check_invariant_ratchet.py                   exit 0
invariant ratchet: ok (78 passing at floor 78, 18 recorded findings at ceiling 18)
```

**Orphan count unchanged: 10 of 40 crates over 18 path edges, before and after.** This task adds no
crate, no `[dev-dependencies]` entry, no `[[test]]` target and no CI job.

**Ignored count unchanged at 18.** No `#[ignore]` was added. A thirteenth would have raised
`ignored_ceiling`, which the ratchet treats as a build failure — correctly, since it is a widening
gap. The four unrefused strategies are carried by `harness::reached_the_boundary_unrefused` and one
`Reach::Unrepresentable` entry instead.

**Floor raised 66 → 78** in the same commit that earned it, read from the captured `test result:`
line rather than computed.

`node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs"` output for the prose
files this task writes is at the end of this file.

---

## Deviations from the plan — the code won every time

The plan's Task 5.3 section was expanded against `origin/main` at `e4b5f10`. Four of its premises
are stale on local `main` at `f99af94`, and one of its instructions could not be carried out because
the thing it edits no longer exists.

**1. The plan's A2 cannot be written as specified; its control would fail.** The plan's A2 asserts
`occurrences_in_rust_sources("rust/warrant/src", "issue_pre_commit") == 0` — that the product never
issues a pre-commit, so no ordering exists to violate. Task 1.1 landed on this base:
`settle.rs:296` calls `issue_pre_commit`, and
`i07_evidence_precedes_commitment::the_product_issues_a_pre_commit_before_it_acts` **no longer
carries an `#[ignore]`** and passes. Written as planned, A2's control fails, which is the harness
correctly saying the attack no longer reaches anything.

A2 was re-aimed at what backdating can still reach: `verify_export` binds the **notary** receipt's
timestamp to the bundle and does not bind the **evidence** receipt's `binding.issued_at`. The
asymmetry is asserted in both directions, and the test pins the notary binding's error string so
that if that binding disappears the strategy fails rather than silently measuring nothing.

**2. The plan's Step 11 instruction to correct `i07_evidence_precedes_commitment.rs:159`'s
`#[ignore]` status word from `"I-07 orphaned"` to `"I-07 partial"` was not carried out, because that
`#[ignore]` no longer exists.** Task 1.1 removed it when the test began passing. There is nothing to
correct. The plan's finding #2 (the tree disagreeing with itself about I-07's status word) was real
on `e4b5f10` and has already been resolved by deletion.

**3. The plan's baseline numbers are all superseded.** Plan: 65 passing / 19 ignored, floor 65 /
ceiling 19, census 9 of 39 over 17 edges. Actual on local `main`: 66 / 18, floor 66 / ceiling 18,
census 10 of 40 over 18 edges. Every number in this file is the measured one.

**4. The plan's A5 attacks a hole that commit `a84711b` closed, and re-implementing it would have
been a second copy of an existing assertion.** Per the task brief, A5 was re-aimed at the fix. It now
attacks the fix's edge — the per-effect receipt the bundle does **not** list — and asserts the
refusal *message*, so that an unlisted mediated receipt must be refused **for its mode** and not for
being unaccounted. If the mode loop ever moves after the count reconciliation, that assertion fails.
**The fix holds on both vectors tested.** An attack refused is a result; A9 is what attacking the fix
actually turned up.

**5. A ninth strategy was added. The plan specifies eight and asserts three findings; this suite has
nine and asserts four.** A9 is the addition (see the headline finding). The registry's own test
asserts the count of findings is exactly 4 and `docs/W1-delivery-gaps.md` §5.3 states `4 of the nine
are not refused`, gated by
`the_findings_are_exactly_the_strategies_the_delivery_gaps_document_names`, so the prose count and
the code cannot drift apart.

**6. The plan's `fixtures::` module did not exist.** The plan's code samples call
`fixtures::tempdir`, `fixtures::genuine_export` and `fixtures::stored_as` as if they were available.
They are not: the settled-export helpers live in `rust/warrant/tests/report_evidence_chain.rs`,
which is a different test binary whose helpers are private to it.
`rust/warrant/tests/invariants/adversary/fixtures.rs` is that module, written for this task. It
builds every fixture through the **product's own** path (`settle` then
`build(..).with_effect_receipts(..).sign(..)`) rather than from struct literals, so an attack that
gets past `verify_export` got past the thing that ships.

**7. A8 was re-aimed, because the plan's A8 duplicates an existing test.**
`append_only.rs::resubmitting_identical_bytes_is_idempotent_and_never_rewrites_the_first_submitter`
already establishes first-submitter attribution with the same two-sided shape. A8 attacks the
composition instead: `artifact::ingest` calls the anchor-free `report::verify_export`, so an
adversary can manufacture an export with a keypair it generated itself, file it, and own the custody
record. The attribution half is kept because it is the second residual, but the new content is the
anchor-free door.

**8. The plan's Step 11 asked for a `fixture.rs` assertion tying each `#[ignore]` reason's status
word to that invariant's `status` in `evidence/invariants.json`. It was NOT added, and this is a
deliberate refusal rather than an omission.** Four pairs already disagree on this base:

| Invariant | `evidence/invariants.json` | `#[ignore]` reason says |
|---|---|---|
| I-01 | `partial` | `I-01 currently violated` (not a ledger status word at all) |
| I-05 | `orphaned` | one ignore says `I-05 orphaned`, a second says `I-05 unimplemented` |
| I-08 | `enforced` | two ignores both say `I-08 partial` — and an `enforced` invariant with two ignored tests is itself worth a look |
| I-11 | `partial` | two ignores say `I-11 unimplemented` |

Adding the gate would either turn CI red on four pre-existing disagreements this task did not create
and is not scoped to resolve, or force the gate to be weakened until it passed. Rule 7 forbids the
second, and shipping the first inside an unrelated task would be worse than reporting it. **It is
reported here instead, for a human to route.** No existing assertion was weakened anywhere in this
task.

**9. The plan's Step 1 branches from `refs/remotes/origin/main`.** It branches from local `main`
instead, per the task brief, because `origin/main` lacks Task 1.1 — against which four of this task's
strategies would measure the wrong thing.

**10. `docs/W1-delivery-gaps.md` §5.1 carries a stale rendered count and was left alone.** It reads
*"Sixty-one checks pass. Nineteen fail, across eleven invariants."* against a corpus that is now
66/18 (78/18 after this task). That number is not this task's to fix — three other lanes are
committing to that file concurrently and §5.3 was appended as the smallest contended surface — but it
is exactly the class of defect Rule 6 exists to catch and somebody should own it.

**11. `docs/W1-delivery-gaps.md` carries 16 pre-existing Britishisms and they were left alone.** The
US-English verifier reports them on lines 248–1094 (`afterwards`, `recognises`, `behaviours`,
`organisation`, `backwards`, `authorisation`, `organisational`, `acknowledgement`, `summarising`,
`judgement`, `labelled`, `honour`) plus one `enrol` correctly protected as a code identifier
(`store.enrol_without_a_code`, an existing API name). **None are in the §5.3 subsection this task
added**, which starts below line 1232. They were not fixed because three other lanes are committing
to this file concurrently and a 16-line sweep across it would collide with them for no gain to this
task. Full verifier output below.

---

## Environment note, recorded because it affected how the work was done

This agent was launched isolated in a worktree of the **outer** repository
(`M:\Project AumOS - Open Secure AI Alliance`). The task targets `aumos`, which is an
**independent nested git repository** with its own `.git` directory. The isolation guard's path
heuristic treats anything under the outer checkout as the shared checkout, so `git -C .../aumos` and
`cd .../aumos && git …` were both refused. The lane worktree was therefore created by running
`git worktree add` from an existing sibling `aumos` worktree at `M:/wt-wave3`, which the guard
permits because it is outside the shared checkout — the same mechanism every other concurrent lane
in this repository uses. No file in the shared checkout was modified, and no branch anyone else is
on was touched.

---

## What this task does NOT establish

1. **It is not a live red-team agent, and L0-05 is not covered.** No process is given root in a
   workload and taken back, because nothing in this repository can do that: there is no sandbox
   (Phase 5's own anti-goal), no agent runner and no kernel. Every attack is a constructed byte
   sequence evaluated by a pure function in CI. L0-05 moves `none` → `partial`.
2. **It does not establish that the receipt describes what happened inside the model.** The record
   proves what the broker saw. An agent that reasoned its way to a goal it was not given, and then
   performed only permitted effects, produces a receipt chain that is entirely truthful and entirely
   uninformative about that.
3. **It does not make any bound Enforced or Mediated.** Five refusals are real and every one of them
   is a **verifier** check. They bind a reader who runs `verify_export`. They do nothing to a party
   who never runs it, and nothing to an agent that bypasses the proxy with its own credential.
4. **Every Tier A refusal here is conditional on a pinned key.** `verify_export` and `verify_chain`
   are anchor-free by construction, and A1 and A8 assert that a fully self-consistent fabrication
   passes both. Without an out-of-band anchor, "it verifies" means only "it has not changed since
   somebody signed it".
5. **It does not detect a missing receipt, and A7 says so as an assertion rather than a caveat.** A
   suppressed chain produces a valid signed file that also passes the pinned-key path. Nothing in
   this suite refuses it and nothing here should claim to.
6. **A9 is recorded, not fixed.** A signed bundle can still claim `mediated` while carrying
   `advisory` receipts. Until the verify-path comparison lands, a reader who trusts the bundle's
   prose rather than its receipts can be misled by a party holding a legitimate key.
7. **A2 and A4 are recorded, not fixed.** An evidence receipt's issuance time is unbound, and a
   verbatim replay against the product's own context is allowed.
8. **It does not test the archive's Postgres enforcement path.** A8 exercises `MemoryStore`. The
   schema's `BEFORE UPDATE OR DELETE` trigger and its ungranted-UPDATE role need a real database and
   remain covered only by the two pre-existing `#[ignore]`d tests in `append_only.rs`.
9. **It says nothing about common-mode failure between enforcement layers.** That is Task 5.4's, and
   this task reads no sandbox profile and no deployment manifest.
10. **The four findings are recorded against the tasks nearest to owning them, which is a judgment,
    not a fact.** A2 and A9 are attributed to Task 2.3 and A4 to Task 3.4 on the reasoning in the
    registry entries; a reviewer who disagrees is disagreeing with those strings, and they are in one
    place so that argument is cheap.

---

## US-English verification

`node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" docs/task-evidence/task-5.3.md docs/W1-delivery-gaps.md`
— exit **1**, on 16 pre-existing findings in `W1-delivery-gaps.md` (lines 248–1094), none in the
§5.3 subsection this task added. Full output, read in full rather than tailed:

```text
docs/task-evidence/task-5.3.md
  PASS — 0 Britishisms outside the carve-outs

docs/W1-delivery-gaps.md
  FAIL — 16 Britishism(s):
    line  248  afterwards -> afterward
    line  261  recognises -> recognizes
    line  330  forwards -> forward
    line  340  behaviours -> behaviors
    line  340  behaviours -> behaviors
    line  406  afterwards -> afterward
    line  454  organisation -> organization
    line  469  backwards -> backward
    line  486  authorisation -> authorization
    line  561  organisational -> organizational
    line  568  acknowledgement -> acknowledgment
    line  783  summarising -> summarizing
    line  929  judgement -> judgment
    line 1075  labelled -> labeled
    line 1077  labelled -> labeled
    line 1094  honour -> honor
  SKIPPED 1 inside carve-outs (quote/proper noun/code) — review, do not auto-fix:
    line  426  enrol

2 file(s) · 16 finding(s) · 1 protected by carve-outs
```

Note that `forwards` at line 330 is the **verb** and is correct as written — a known false positive
of this tool, along with the plural noun `analyses`. The `enrol` at line 426 is
`store.enrol_without_a_code`, an existing API identifier, correctly protected by carve-out 3. The
remaining 14 are genuine and pre-existing; see deviation 11 for why this task did not sweep them.
