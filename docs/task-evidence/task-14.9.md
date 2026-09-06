# Task 14.9 — Public fact/claim/unknown ledger with versioned corrections; bilingual evidence

**Catalog items:** L10-14 (public signed fact/claim/unknown ledger with versioned corrections),
L10-10 (localized pack verifies against the same receipt digests as the source-language pack).

**Branch:** `feat/public-claim-ledger` · **Worktree:** `M:/wt-w5-14.9` ·
`CARGO_TARGET_DIR=M:/wt-w5-14.9-target` · **Base:** local `main` at `2ec0638`.

**Date:** 2026-09-05.

---

## Step 0 — the baseline, captured before anything was edited

**Deviation from the plan, recorded first because every number downstream depends on it.** The
step-form section instructs a Step 0 against `refs/remotes/origin/main` and quotes its output. That
output is stale by 65 commits: `origin/main` is at `e4b5f10` because nothing is pushed, and the
dispatch directs this lane to branch from local `main` at `2ec0638`. Every figure in the plan's Step
0 block is therefore wrong for the tree this task gates, and re-measuring changed four of them:

| Measurement | Plan (`origin/main`, `e4b5f10`) | This tree (local `main`, `2ec0638`) |
|---|---|---|
| crate directories under `rust/` | 39 | **41** |
| wiring census | 9 of 39 over 17 path edges | **13 of 41 over 22 path edges** |
| invariant ledger census | enforced=2, orphaned=2, partial=7, unimplemented=1 | **enforced=2, orphaned=1, partial=8, unimplemented=1** |
| invariant ratchet | 65 passing at floor 65, 19 findings at ceiling 19 | **82 passing at floor 82, 15 findings at ceiling 15** |

The plan's own seed values were used nowhere. Every `fact` entry in `evidence/claims.json` is
derived by `tools/ci/check_claims.py` from a record in this tree, so a stale seed could not have
survived the gate even if it had been copied in.

Commands, in order, from `M:/wt-w5-14.9`, output verbatim:

```
$ git log --oneline -1 HEAD
2ec0638 Merge branch 'feat/task-1.3' (Task 1.3, GLM lane)

$ git ls-tree -d --name-only HEAD rust/ | wc -l
41

$ python tools/ci/wiring_census.py
wiring census: 13 of 41 crates reachable from warrantor-warrant over 22 path edges
CENSUS=0

$ python tools/ci/check_invariants.py
invariant ledger: 12 invariants; enforced=2, orphaned=1, partial=8, unimplemented=1
LEDGER=0

$ python tools/ci/check_invariant_ratchet.py
    Finished `test` profile [unoptimized + debuginfo] target(s) in 9m 30s
     Running tests\invariants\main.rs (M:/wt-w5-14.9-target\debug\deps\invariants-8c3a7ff0748e70ff.exe)
invariant ratchet: ok (82 passing at floor 82, 15 recorded findings at ceiling 15)
RATCHET=0
```

### The live defects, greped before any file was edited

These are the ledger's seed entries. They are commands, not prose, because a correction ledger whose
first entries were discovered *after* the fix would be indistinguishable from a rewrite.

```
$ grep -n "Sixty-one checks pass" docs/W1-delivery-gaps.md
1245:Sixty-one checks pass. Nineteen fail, across eleven invariants. I-02 — no authority expansion — is

$ cat tools/ci/invariant-ratchet.json | python -c "import json,sys;d=json.load(sys.stdin);print(d['passing_floor'], d['ignored_ceiling'])"
82 15

$ sed -n 192p README.md
| MCP — transport, control and agent endpoints | **Works.** Upstream forwarding not implemented yet |

$ sed -n 47p docs/W1-delivery-gaps.md
It is fixed. `rust/warrant/src/upstream.rs` is a synchronous MCP client over a child process's

$ git ls-tree --name-only HEAD rust/warrant/src/ | grep upstream
rust/warrant/src/upstream.rs

$ python - <<'PY'   # which invariant suites hold a recorded finding
suites = sorted(p for p in Path("rust/warrant/tests/invariants").glob("i??_*.rs"))
PY
suites: 12
with findings: 9 [('I-01', 1), ('I-03', 4), ('I-04', 2), ('I-06', 1), ('I-08', 2), ('I-09', 1), ('I-10', 1), ('I-11', 2), ('I-12', 1)]
without: ['I-02', 'I-05', 'I-07']
total ignores in suites: 15
```

### The plan's third premise had already been fixed, and one it did not name had not

**Deviation.** The plan asserts three live defects. On local `main` only two of the three are live,
and the third was already repaired:

1. **LIVE.** `docs/W1-delivery-gaps.md:1245` renders `Sixty-one checks pass. Nineteen fail`. The
   ratchet record says 82 and 15. The plan predicted this line would read stale against a floor of
   65; against a floor of 82 it is staler still.
2. **ALREADY FIXED — the plan is wrong about this tree.** The plan says the Tier 5 table calls I-07
   `orphaned` while the ledger says `partial`. On local `main`, `docs/W1-delivery-gaps.md:1258`
   already reads `partial (was orphaned; **issuance earned 2026-09-05**)`, and the `#[ignore]` on
   `i07_evidence_precedes_commitment.rs` that the plan quotes at line 159 no longer exists — the
   suite has zero ignores. Task 1.1 landed between `e4b5f10` and `2ec0638`. CL-004 is therefore
   seeded as a **historical** correction whose current version already renders correctly, not as a
   live fix, and its Step 8 edit was not made because there was nothing to edit.
3. **LIVE.** `README.md:192` renders `Upstream forwarding not implemented yet` while
   `docs/W1-delivery-gaps.md:47` reads `It is fixed.` and `rust/warrant/src/upstream.rs` is tracked.
4. **LIVE, and the plan does not name it.** The same sentence at `docs/W1-delivery-gaps.md:1245`
   says the findings run `across eleven invariants` and that `I-02 ... is the only invariant with no
   finding against it`. Both are now false: nine of the twelve suites hold a finding, and three —
   I-02, I-05 and I-07 — hold none, because Task 9.1 and Task 1.1 converted theirs. Fixing only the
   two numbers the plan names would have left a false claim on the same line as the correction, which
   is the defect this ledger exists to catch. CL-005 gates it.

---

## What was built

| Path | New? | What it is |
|---|---|---|
| `evidence/claims.json` | new | The ledger. Format `warrantor.claim-ledger/1`, 16 entries, 9 retained corrections |
| `tools/ci/check_claims.py` | new | The gate: falsifier required, renderings recomputed, corrections append-only, two views compared |
| `tools/ci/test_check_claims.py` | new | 42 pytest cases; every refusal paired with an allowed control |
| `tools/ci/claim_locales.json` | new | The reviewed label vocabulary. Labels only, and the file says so about itself |
| `docs/public-claims.md` | new, generated | The rendered English view |
| `docs/public-claims.ar.md` | new, generated | The rendered Arabic view, same digest, same quotations |
| `docs/W1-delivery-gaps.md` | edit | Section 5.1's paragraph: three derived sentences replacing two stale ones |
| `README.md` | edit | The stale MCP row, the stale wiring bullet, a claim-ledger row, the limitation paragraph verbatim |
| `.gitignore` | edit | `!/evidence/claims.json`, without which `git add` skips the ledger in silence |
| `.github/workflows/ci.yml` | edit | Two steps in the existing `Documentation and tracker contracts` job |

No new Rust crate, no new Python package, no new workspace member.

## The bound, and the word each part of it gets

Content rule 1 applied line by line. Nothing here is Enforced or Mediated, because no line of code in
this repository refuses a false claim at the moment it is made — the checker refuses a *merge*, later,
and only where it runs.

| Bound | Word | Why not a stronger one |
|---|---|---|
| A `fact` entry's rendering matches the record it cites, on every surface it names | **Tier B — chokepoint** | `tools/ci/check_claims.py` recomputes and compares, and CI fails. It is a chokepoint, not enforcement: the edit lands in a working tree first, and a clone from that tree carries it. What escapes: a branch with checks disabled, a direct push to a repository without the workflow, and any fork |
| A published entry's text or status cannot change without a retained correction | **Tier B — chokepoint** | Same gate, same escapes. `check_corrections` refuses `version == n` with fewer than `n - 1` corrections |
| A retained superseded text cannot be softened | **Tier B — chokepoint, hash-bound** | `supersedes_digest` is a hash over the retained text, so an edited retraction no longer matches. Not Tier A: the digest is unsigned, and anyone may recompute it after editing the text. What it buys is that softening a retraction requires touching two fields, and the second one moves `head_digest` |
| A correction present in the parent revision cannot be removed | **Tier B — chokepoint, by comparison** | `check_append_only` reads the parent revision through `git show`. Detection by comparison, never prevention. Rewriting the revision compared against, by force-push or rebase, defeats it |
| Two parties comparing `head_digest` disagree after any history mutation | **Tier C — Observed** | A hash fold over content. It establishes only that two copies differ. It does not establish which is the honest one, that the head is the latest, or that nothing was rewritten before you cloned |
| Both rendered views carry the same digest and the same quotations | **Tier B — chokepoint** | Refused by the checker. In this repository the stricter regeneration comparison fires first — see the honesty note below |
| The published limitation appears verbatim wherever it is claimed to | **Tier B — chokepoint** | `check_bound_statement` reads `bound_surfaces` and refuses a surface that does not carry the paragraph. `bound_statement` is also folded into `head_digest`, so softening it moves the head |
| A claim is true | **No tier. Not bounded at all** | `fact` means "recomputed from a named record in this repository". A record can be wrong, and then the ledger renders a wrong number faithfully. `claim` and `unknown` are labels this project applied to itself |

**The one thing this ledger says about enforcement generally, gated as `CL-014`:** no netns, seccomp or
firewall enforcement exists in this repository; a bound contained at settle time is **Observed**, not
Enforced; a bound holding only for traffic through the proxy is a chokepoint bound and what bypasses
the proxy escapes it. That entry names `README.md` and both views as surfaces, so it cannot be
published in one place and softened in another.

## Every gate, verbatim, with exit codes captured before any pipe

### The gate red on real defects, before anything was fixed

This is the load-bearing capture. The ledger was written first and the checker run against the
unmodified tree, so the four surface defects were named by the gate rather than by a human reading
prose. Trimmed to the surface failures; the full run also reported the two views as missing, because
they had not been generated yet.

```
$ python tools/ci/check_claims.py
CLAIMS=1
::error::evidence/claims.json: CL-002: does not render in docs/W1-delivery-gaps.md: expected '82 checks pass and 15 are recorded findings' verbatim
::error::evidence/claims.json: CL-004: does not render in docs/W1-delivery-gaps.md: expected 'I-07 (evidence precedes commitment) is partial' verbatim
::error::evidence/claims.json: CL-005: does not render in docs/W1-delivery-gaps.md: expected '9 of the 12 invariant suites hold at least one recorded finding; I-02, I-05 and I-07 hold none' verbatim
::error::evidence/claims.json: CL-006: does not render in README.md: expected 'MCP upstream forwarding is implemented; an upstream tool the effect registry cannot class is refused only when --upstream-refuse-unclassified is set.' verbatim
::error::evidence/claims.json: CL-016: does not render in README.md: expected '13 of 41 crates link into the warrantor binary and 28 do not' verbatim
claim ledger: 29 issue(s); refusing
```

### The correction ratchet, against real git history, after the first commit

Each mutation applied to the committed tree, the gate run, the tree restored. Exit codes captured on
their own line, never read through a pipe.

```
$ python tools/ci/check_claims.py --parent-ref main          # A: the control, honest tree
no parent ledger at main; the append-only comparison has nothing to compare, because that revision does not carry the file
claim ledger: 16 claims; claim=8, fact=6, unknown=2; 9 retained corrections; head sha256:c7b4aac07485a7080be765605a126a1b87a6778751bf3f9c07d20462d562caa4
EXIT=0

$ # B: soften CL-008's retained reason to "a minor clarification"
::error::evidence/claims.json: CL-008: correction 1 was removed or altered; a retraction is retained, never deleted
claim ledger: 3 issue(s); refusing
EXIT=1

$ # C: delete CL-009's whole correction and drop it back to version 1
::error::evidence/claims.json: ledger: head_digest is stale: recorded sha256:c7b4aac0..., recomputed sha256:162af370...
::error::evidence/claims.json: CL-009: version fell; a claim version may only rise
::error::evidence/claims.json: CL-009: correction 1 was removed or altered; a retraction is retained, never deleted
claim ledger: 5 issue(s); refusing
EXIT=1

$ python tools/ci/check_claims.py --parent-ref no-such-ref   # D: no history must REFUSE, not skip
::error::evidence/claims.json: cannot resolve 'no-such-ref': the append-only comparison has no history to read. A shallow or historyless checkout must fail this gate rather than skip it.
EXIT=1

$ # E: translate one quotation in the Arabic view
::error::evidence/claims.json: views: docs/public-claims.ar.md is not what the ledger renders to; run `python tools/ci/check_claims.py --write`
EXIT=1

$ # F: edit only the head_digest line in the Arabic view
::error::evidence/claims.json: views: head_digest differs between views (ar vs en); this is a defect, not a translation note
EXIT=1

$ python tools/ci/check_claims.py --parent-ref HEAD          # G: the control again, tree restored
claim ledger: 16 claims; claim=8, fact=6, unknown=2; 9 retained corrections; head sha256:c7b4aac07485a7080be765605a126a1b87a6778751bf3f9c07d20462d562caa4
EXIT=0
```

**Honesty note on case E.** The translated quotation was refused by the regeneration comparison, not by
the cross-view quotation comparison. Inside this repository the regeneration check subsumes the
quotation check, because any hand edit to a generated view fails regeneration first. `check_views`
therefore earns its place only for a *third party comparing two received packs without the generator*,
and it is exercised as a unit
(`test_a_translated_quotation_is_refused`, `test_a_translated_superseded_text_is_refused`) rather than
end to end. Two checks, one of which is redundant here — recorded rather than presented as
independent corroboration.

### Mutation battery on the checker: eleven weakenings, all caught

The `bound_surfaces` and whitespace-normalization assertions were written *after* their code rather
than before it, which is a real deviation from test-first. Rather than claim a red I did not see, each
assertion was proved load-bearing by mutation. Every mutation was applied to a working copy of
`tools/ci/check_claims.py` and reverted; the script is not committed.

```
baseline (unmutated): exit 0
falsifier never refused                              exit 1  caught
empty falsifier.how accepted                         exit 1  caught
rendering never checked on a surface                 exit 1  caught
a fact's own text not tied to its record             exit 1  caught
version/corrections arithmetic dropped               exit 1  caught
supersedes_digest not verified                       exit 1  caught
append-only comparison of corrections dropped        exit 1  caught
bound_statement not required on its surfaces         exit 1  caught
head_digest ignores the limitation paragraph         exit 1  caught
normalization reaches across a table cell            exit 1  caught
views never compared for a translated quotation      exit 1  caught
checker restored

all mutations caught
```

---

## Deviations from the plan

Twelve, in the order they were found. The code won over the plan in every one.

1. **The plan's base is wrong for this lane, and every number in its Step 0 with it.** It says
   `refs/remotes/origin/main` in the worktree command and quotes `e4b5f10`'s output. The dispatch bases
   this lane on local `main` at `2ec0638`, 65 commits ahead. See the Step 0 table: four measurements
   changed. Nothing was copied from the plan's seed values.

2. **Only two of the plan's three "live defects" are live.** Its defect 2, the Tier 5 table calling
   I-07 `orphaned`, was already repaired on local `main`, and the `#[ignore]` it quotes at
   `i07_evidence_precedes_commitment.rs:159` no longer exists — that suite has zero ignores. CL-004 is
   seeded as a historical correction, and the Step 8 edit for it was not made because there was nothing
   to edit. The plan's Step 8 instruction *"`docs/W1-delivery-gaps.md:1109`'s I-07 row becomes
   `partial`"* would have been a no-op at best.

3. **A fourth live defect the plan does not name, on the same line as the one it does.** The sentence at
   `docs/W1-delivery-gaps.md:1245` also said the findings ran `across eleven invariants` and that I-02
   was `the only invariant with no finding against it`. Nine of twelve suites carry a finding, and three
   carry none. Fixing only the two numbers the plan names would have left a false claim on the line
   carrying the correction. `CL-005` gates it, which required a new reduction, `corpus_finding_census`.

4. **A fifth live defect, and it is the best argument for the task.** `README.md`'s wiring bullet read
   `9 of 39 crates ... names the other 30` while the status table ten lines above it — the one
   `wiring_census.py`'s `readme_renders` does assert — read `13 of 41`. Two renderings of one
   measurement in one file, one gated. `CL-016` gates the second, via a `wiring_reachability` reduction,
   because the orphan count is a subtraction and a template cannot subtract.

5. **`evidence/claims.json` needed a `.gitignore` re-include and the plan never says so.**
   `.gitignore:99` is `/evidence/*` with per-file `!` re-includes. Without `!/evidence/claims.json`,
   `git add` skips the ledger **in silence** and `git status` reports a clean tree — exactly how Task
   9.1 shipped a test reading a file the commit did not contain, which that task's own correction
   section documents. The plan's Files table lists the ledger as new and says nothing about the rule.

6. **The plan's Step 2 first test cannot pass as written.** It asserts
   `[i.message for i in issues] == ["no falsifier: ..."]` on a fixture that also names
   `docs/public-claims.md` and `evidence/wiring-coverage.json`, neither of which exists under
   `tmp_path`, so `check_claim` correctly reports three issues rather than one. The test asserts
   membership instead. Making it pass as written would have required `check_claim` to return early on a
   missing falsifier and hide every other defect in the entry.

7. **The plan's append-only comparison is a no-op in CI.** It specifies
   `git show HEAD:evidence/claims.json`. In a clean CI checkout `HEAD` *is* the commit under test, so
   that reads back the bytes the checker just read from the working tree and the comparison always
   passes. `--parent-ref` was added, defaulting to `HEAD` for a dirty local tree, and the CI step passes
   the branch base using the same `BASE_SHA` idiom the US-English step in that job already uses.

8. **The plan's `bound_statement` requirement and its localization rule contradict each other.** Step 3
   requires the paragraph to appear verbatim in *both* views; Step 9 lists it among the strings
   `claim_locales.json` localizes. Both cannot hold. Resolved the way Step 9's own rule 2 points: the
   limitation is a claim about what the gate does, so it is quoted untranslated in both views with a
   source-language marker, and `claim_locales.json` carries only a localized *heading* for it. A
   machine-translated limitation paragraph is the "reads fluent and asserts something unverified"
   failure Step 9 warns against.

9. **A strict substring test refuses the honest document.** `readme_renders` compares a literal
   substring against raw file bytes, which works only because the row it gates is one very long line.
   Every prose surface here wraps near 100 columns, and two derived sentences wrapped mid-string.
   `contains_rendering` collapses runs of whitespace on both sides: it accepts everything the strict
   form accepts, additionally survives a re-wrap, and still cannot match across a table-cell boundary
   because `|` is not whitespace. That last property is asserted
   (`test_normalization_does_not_reach_across_a_table_cell`) and mutation-tested.

10. **`bound_surfaces` was added; the plan hardcodes the two views.** The README carries the limitation
    too, and a limitation published in one place and summarized more kindly in another is the defect
    this file exists to refuse. The surfaces are listed in the ledger and gated.

11. **`ruff format --check` at ruff's default width fails on files this task does not own.**
    `tools/ci/` is outside `run_python_checks.py`'s scope — it discovers `python/*/pyproject.toml` only
    — so no CI job formats it, and `check_invariants.py` and `wiring_census.py` would both be
    reformatted at width 88. The two new files are formatted at the house width of 100 to match their
    neighbours, and `ruff check` passes at the default ruleset. **The scope gap is not fixed here**: no
    CI job lints or formats `tools/ci/`, and closing that is a change to the Python job that belongs to
    whoever owns it.

12. **The plan's Step 5 arithmetic is right that the seed undercounted and wrong about the total.** It
    predicts eight corrections. There are nine retained, across sixteen entries, because deviations 3
    and 4 each added one the plan did not know about.

---

## The corpus and the census were assessed and deliberately not moved

**No `#[ignore]` was converted, and none should have been.** All 15 recorded findings were read. Every
one names a missing runtime mechanism, and none is about documentation. The two nearest:

```
rust/warrant/tests/invariants/i11_self_change_is_governed.rs
#[ignore = "I-11 unimplemented at the broker: three DenyReason variants are rendered and never constructed (Task 2.5, 2026-09-02)"]

rust/warrant/tests/invariants/i04_current_policy.rs
#[ignore = "I-04 partial: post-commit receipts copy the pre-commit decision block, so no commit-time evaluation is provable (Task 2.3, 2026-09-02)"]
```

I-11's is the closest thing in the corpus to a claim rendered with no mechanism behind it — three
`DenyReason` variants shown to users and constructed by no decision — and it is still a Rust wiring fix
owned by Task 2.5. A ledger does not construct a variant. `passing_floor` was not raised and
`ignored_ceiling` was not lowered. **A docs task that appeared to improve either number would be the
exact defect this ledger is for.**

**The orphan count did not move**, and it was read from the tool rather than computed: this task adds no
Rust crate. Both numbers are re-measured below on the final commit.

**Left to whoever next touches I-07, recorded so it is not lost.** The plan asks whether the corpus
`#[ignore]` reason string for I-07 still disagrees with the ledger. On local `main` it does not, because
that suite no longer has an ignore. The general hazard remains and is published as `CL-015`: **no check
compares an `#[ignore]` reason string's status word against the status `evidence/invariants.json` gives
that invariant.** A reason string can say `orphaned` while the ledger says `partial` and
`check_invariants.py` passes, because it never reads the corpus text that motivated the entry. Writing
that comparison means touching the corpus from a docs task, and the corpus is the instrument, so it is
handed forward rather than done here.

---

## What this task does NOT establish

Specific, not modest. Each item is something a reader might otherwise assume from the words "signed
public claim ledger with versioned corrections".

1. **Nothing is signed.** L10-14 says "signed ledger". `head_digest` is a SHA-256 fold over content. It
   binds the file to itself and binds nothing to a signer. There is no key, no signature field, and no
   verification of one. Published as `CL-012`.

2. **Nothing is anchored.** L10-14's verification clause asks for the head to be "anchored in the
   transparency log". There is no transparency log in this repository, no anchoring service, and none
   was stood up. The consequence is precise, and it is the property a stranger actually needs: **a third
   party who holds no earlier copy cannot distinguish an honest history from a rewritten one.** Two
   parties comparing heads can disagree; a single party holding one copy learns nothing. Anchoring is
   L10-14's remainder and it is unowned in the plan as far as this lane could tell.

3. **A correction is detected, never prevented.** The append-only property is a comparison against a
   named revision. Rewriting that revision — force-push, rebase, a fork with no workflow — defeats the
   comparison. The gate refuses a merge; the rewrite exists in a working tree first, and a clone taken
   from that tree carries it.

4. **`fact` does not mean true.** It means the rendering was recomputed from a named record in this
   repository and found on every surface the entry lists. If the record is wrong, the ledger renders the
   wrong number faithfully and the gate is green. Of the records this ledger reads, only the ratchet's
   pair and the corpus scan are re-derived from an instrument; `wiring-coverage.json` is generated but
   committed, and `invariants.json` holds human-applied labels.

5. **The Arabic view is scaffolding and the ledger says so.** Only labels are localized. No claim body,
   falsifier, correction reason or superseded text is translated — deliberately, because translating a
   retraction rewrites it. **No Arabic-reading reviewer has read the file**, including its label
   vocabulary, so whether an Arabic-reading supervisor could act on it is unknown, not solved. Published
   as `CL-011` with an Arabic-reading reviewer as the named falsifier. L10-10's verification clause about
   digests matching between packs is satisfied; the useful half of a localized pack is not.

6. **The five papers are covered by reference only.** Their numbers come from runs whose records are not
   committed here, so no pointer resolves into them. Their entry is `CL-013`, status `claim`, and its
   falsifier is a committed run record appearing — which is an argument for committing them, not a claim
   that they are verified. **No paper text was read, checked, or edited by this task.** A paper is
   append-only by publication: a paper claim that proves false gets an entry here, never an edit there.

7. **The ledger does not cover the HTML deliverable estate.** `CL-007`, the standards claim propagated
   across four artifacts, was corrected in a **different repository** — the outer estate at
   `M:/Project AumOS - Open Secure AI Alliance`, commit `edeaf17`. `check_claims.py` cannot reach it, so
   that entry is a `claim` with no surface and its falsifier points at a document this gate never reads.
   Any claim published only in the HTML estate is outside this ledger entirely.

8. **Two of the nine retained texts are not verbatim quotations, and each says so in its own reason
   field.** `CL-009`'s superseded text is a paraphrase, because the row was rewritten in place before
   this ledger existed and the pre-correction bytes survive only in git history. `CL-010`'s is
   reconstructed from the retraction's description of what it said. Every other retained text is verbatim
   apart from stripped backticks, dropped bold markers, or normalized line wrapping, each noted in its
   reason. **The ledger cannot recover a retraction that predates it**; that is the argument for starting
   one, not a property it has retroactively.

9. **No seal command exists, on purpose, and the consequence cuts both ways.** A command that re-derived
   `supersedes_digest` from whatever the text currently says would let a retraction be softened and
   re-sealed in one step. So the digests were computed once at authoring time by a throwaway script. The
   consequence: anyone can still recompute a digest by hand after editing a retained text, and the only
   thing that catches it is `head_digest` moving — visible to a holder of an earlier copy, and to nobody
   else.

10. **The cross-view quotation check is redundant inside this repository.** See the honesty note above:
    regeneration fires first on any hand edit. That check earns its place only for two packs compared
    without the generator, and it is exercised as a unit rather than end to end.

11. **`tools/ci/` is still unlinted by CI.** `run_python_checks.py` discovers `python/*/pyproject.toml`
    and nothing else, so no job runs `ruff` over the directory this task adds two files to. Both new
    files pass `ruff check` and `ruff format --check --line-length 100` locally; nothing enforces that on
    the next change to them.

12. **The ledger cannot detect that a claim became false.** It detects that a *record* moved and the
    prose did not. A `claim` or `unknown` entry with no record has no such tripwire at all — eight of the
    sixteen entries are in that position, and their only mechanism is a named falsifier a human must
    choose to run. `CL-013`'s falsifier, for instance, will not fire on its own.

13. **No HTML, no verifier page, no portal.** Task 14.3's offline verify page, Task 11.9's trust center,
    Task 12.3's parity gate and Task 13.8's ownership register are all untouched and none of them has
    landed. Nothing here renders into a portal, and `evidence/claims.json` was not shaped in
    anticipation of 14.3 reading it. No ledger entry carries an owner, a retirement path or a review
    cadence, because those are 13.8's fields and two registers that disagree about who owns a control
    are worse than one.
