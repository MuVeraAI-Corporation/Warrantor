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
| `evidence/claims.json` | new | The ledger. Format `warrantor.claim-ledger/1`, 17 entries, 11 retained corrections |
| `tools/ci/check_claims.py` | new | The gate: falsifier required, renderings recomputed, the parent revision's published state compared, corrections append-only, two views compared |
| `tools/ci/test_check_claims.py` | new | 52 pytest cases; every refusal paired with an allowed control |
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
| A published entry's status, text or falsifier cannot change without a retained correction | **Tier B — chokepoint, by comparison against the parent revision** | Same gate, same escapes, and this row was itself an overclaim until 2026-09-06 — see *Continuation* below. `check_corrections` refuses `version == n` with fewer than `n - 1` corrections, which is arithmetic inside one revision and does not compare anything to what was published. `check_published_state` is what earns the row: it refuses a same-version change of status, text or falsifier, and refuses a correction whose retained text is not what the parent revision published. Weaker than the digest rows above it, because it holds only while the parent revision is reachable |
| A retained superseded **falsifier** cannot be dropped or replaced | **Tier B — chokepoint, by comparison, NOT hash-bound** | `superseded_falsifier` is compared against the parent revision and is **not** covered by `supersedes_digest`: widening `state_digest` would have changed every digest already retained in the ledger, which is rewriting retained history to close a hole about rewriting retained history. So this bound is strictly weaker than the row below it — it fails open in a checkout with no parent revision, which is why `--parent-ref` must resolve or the gate exits 1 |
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

## Continuation, 2026-09-06 — the gate published a refusal it did not perform

The first commit on this branch, `3c2baa9`, published this sentence in `README.md`:

```
tools/ci/check_claims.py refuses a commit that changes a published entry without retaining the
previous text, and refuses one that removes a retained correction.
```

The second half was true. **The first half was not.** `check_append_only` compared three things
across revisions — that every entry is still present, that no version fell, and that every retained
correction is byte-identical — and never compared the one thing a reader reads. Two holes followed
from that, and neither was visible from the code: both were found by building the rewrite by hand and
running the gate on it.

### Hole 1 — a same-version rewrite passes once `--write` has been run

`check_corrections` ties an entry's `version` to the number of corrections it carries. Leave the
version at 1 and replace the text and that arithmetic is satisfied; the version did not fall and no
correction was dropped, so `check_append_only` saw nothing either. The first run does fail — on a
stale `head_digest` and on two views that no longer match — and its error message tells the author
exactly how to clear it:

```
$ python tools/ci/check_claims.py --parent-ref HEAD          # CL-014 text replaced, version left at 1
::error::evidence/claims.json: ledger: head_digest is stale: recorded sha256:ed08e01f..., recomputed
  sha256:07261b9a...; run `python tools/ci/check_claims.py --write`
::error::evidence/claims.json: CL-014: does not render in docs/public-claims.md: expected 'Warrantor
  applies a network namespace, a seccomp filter and a firewall rule to every agent, so every bound is
  Enforced.' verbatim
[3 more]
claim ledger: 5 issue(s); refusing

$ python tools/ci/check_claims.py --write >/dev/null && python tools/ci/check_claims.py --parent-ref HEAD
claim ledger: 16 claims; claim=8, fact=6, unknown=2; 9 retained corrections; head sha256:07261b9a...
GATE_EXIT=0
```

A rewrite that inverts the repository's most carefully hedged claim into `every bound is Enforced`,
landing green, with the ledger's own error message as the instructions. **That is content rule 2
committed inside the artifact built to refuse content rule 2.**

### Hole 2 — a retained text the parent never published, self-consistent

`supersedes_digest` is computed over the `superseded_text` sitting beside it, so a fabricated pair
validates against itself. Only the parent revision knows what version 1 said.

```
$ python tools/ci/check_claims.py --write >/dev/null && python tools/ci/check_claims.py --parent-ref HEAD
claim ledger: 16 claims; claim=8, fact=6, unknown=2; 10 retained corrections; head sha256:88dd54b1...
GATE_EXIT=0
```

The correction retained `Warrantor never claimed anything about namespaces.` as version 1 of `CL-014`.
Version 1 of `CL-014` said no such thing. The mutation battery above did not catch either hole,
because a mutation battery proves the assertions you have are load-bearing and says nothing about the
assertion you never wrote.

### The failing tests, red before the fix

Five, written against the unfixed checker:

```
$ python -m pytest tools/ci/test_check_claims.py -q -p no:cacheprovider
FAILED tools/ci/test_check_claims.py::test_rewriting_a_published_text_at_the_same_version_is_refused
FAILED tools/ci/test_check_claims.py::test_rewriting_a_published_status_at_the_same_version_is_refused
FAILED tools/ci/test_check_claims.py::test_weakening_a_falsifier_at_the_same_version_is_refused
FAILED tools/ci/test_check_claims.py::test_a_correction_that_retains_a_text_the_parent_never_published_is_refused
FAILED tools/ci/test_check_claims.py::test_a_version_that_rises_with_no_correction_for_the_parent_is_refused
5 failed, 44 passed in 0.82s
```

Then two more, for the field the first five exposed — a falsifier can be replaced with one nobody
could act on without a single word of the claim moving, and the correction schema had nowhere to
retain the old one:

```
FAILED tools/ci/test_check_claims.py::test_changing_a_falsifier_with_no_retained_falsifier_is_refused
FAILED tools/ci/test_check_claims.py::test_retaining_a_falsifier_the_parent_never_published_is_refused
2 failed, 50 passed in 0.62s
```

### After the fix

`check_published_state` compares `(status, text, falsifier)` between the parent revision and this
one. Same version and any of the three moved is refused; version raised and the correction that
retains the parent's own version is selected **by its `version` field, not by its position** — a
positional lookup would read the parent's version out of whatever correction happened to sit at that
index, which the fifth failing test above is what caught. Both hand-built rewrites are now refused:

```
$ python tools/ci/check_claims.py --write >/dev/null && python tools/ci/check_claims.py --parent-ref HEAD
::error::evidence/claims.json: CL-014: status, text or falsifier changed at version 1 with no
  correction appended: a published entry changes by raising the version and retaining what the parent
  revision published, which was 'No netns, seccomp or firewall enforcement exists in this repository.
  [...]' as claim
claim ledger: 1 issue(s); refusing
GATE_EXIT=1

$ python tools/ci/check_claims.py --write >/dev/null && python tools/ci/check_claims.py --parent-ref HEAD
::error::evidence/claims.json: CL-014: correction 1 does not retain what the parent revision
  published: it retains 'Warrantor never claimed anything about namespaces.' as claim, and the parent
  published 'No netns, seccomp or firewall enforcement exists in this repository. [...]' as claim
claim ledger: 1 issue(s); refusing
GATE_EXIT=1

$ python -m pytest tools/ci/test_check_claims.py -q -p no:cacheprovider
52 passed in 0.42s
```

### The defect went into the ledger, by its own rules

`CL-017` is the gate's own property, at version 2, retaining the `README.md` sentence commit
`3c2baa9` published as version 1. Its falsifier is the experiment above: leave a version alone,
rewrite the text, run `--write`, run the gate, and an exit code of 0 falsifies the entry. The gate was
red on the unrendered `README.md` row before the row was written, which is the same order Step 8 used:

```
$ python tools/ci/check_claims.py --parent-ref HEAD
::error::evidence/claims.json: CL-017: does not render in README.md: expected "tools/ci/
  check_claims.py refuses a commit that changes a published entry's status, text or falsifier
  without raising the version and appending a correction [...]" verbatim
claim ledger: 1 issue(s); refusing
GATE_EXIT=1

$ python tools/ci/check_claims.py --parent-ref HEAD          # after README.md carries it
claim ledger: 17 claims; claim=9, fact=6, unknown=2; 11 retained corrections; head sha256:61cd4be5...
GATE_EXIT=0
```

**No assertion was weakened and no test was deleted to reach that.** One fixture changed:
`test_the_allowed_control_appending_a_correction_passes` built a parent whose text was
`9 of 39 crates reachable` and appended a correction retaining `I-07 ... is orphaned.` That fixture
did not have to be consistent while nothing read the parent's text, which is the hole restated. The
parent's text is now what the correction retains; the assertion — `== []` — is untouched.

### One claim sharpened rather than left to mislead: `CL-014`

`CL-014` published *"No netns, seccomp or firewall enforcement exists in this repository"* with a
falsifier reading *"a network namespace, seccomp filter or firewall rule is found being applied by
code under rust/"*. The sentence is true. The falsifier invites a grep that appears to fire:

```
$ grep -rn "unshare-net|net=none" rust/warrant/src/sandbox.rs | head -3
320:            Confinement::Bubblewrap => argv.push("--unshare-net".to_string()),
321:            Confinement::Firejail => argv.push("--net=none".to_string()),
539:            assert_eq!(jail.argv.iter().any(|a| a == "--net=none"), expect_netns);
```

`sandbox.rs` **derives** a confinement command line and launches nothing — its own header says
*"This module emits a command line. It enforces nothing."* — so no namespace is applied anywhere in
this repository and the entry stands. But a reader running the entry's own falsifier finds those two
lines and cannot tell that from the entry. `CL-014` is now at version 2, naming the emitting module,
with the falsifier narrowed from *mentioning* to *launching*, and version 1 retained verbatim
including its falsifier. The claim did not become false; it was published in a form its own falsifier
could not resolve, and that is worth a version.

### Fresh detached worktree at `fb6e45c` — every gate, exit code captured before any pipe

`git worktree add --detach M:/wt-g6-14.9 feat/public-claim-ledger`, one target directory
(`M:/wt-w6-14.9-target`), 363 GB free at the start and 342 GB at the end. This is the check that
catches a `.gitignore`-excluded evidence file, which is how a green implementer's run has shipped a
red branch in this repository before.

```
$ git status --porcelain
(empty)

$ git ls-files evidence/claims.json tools/ci/check_claims.py tools/ci/test_check_claims.py \
               tools/ci/claim_locales.json docs/public-claims.md docs/public-claims.ar.md
docs/public-claims.ar.md
docs/public-claims.md
evidence/claims.json
tools/ci/check_claims.py
tools/ci/claim_locales.json
tools/ci/test_check_claims.py

$ git check-ignore -v <each of those six>
not ignored: evidence/claims.json
not ignored: tools/ci/check_claims.py
not ignored: tools/ci/test_check_claims.py
not ignored: tools/ci/claim_locales.json
not ignored: docs/public-claims.md
not ignored: docs/public-claims.ar.md
```

```
$ python -m pytest tools/ci/test_check_claims.py -q -p no:cacheprovider
52 passed in 0.53s
PYTEST=0

$ python tools/ci/check_claims.py
claim ledger: 17 claims; claim=9, fact=6, unknown=2; 11 retained corrections; head sha256:61cd4be558b07b3e1cc99482c44f4e0ce599b6aab3e0a5e1f1d090df3345174f
CLAIMS_DEFAULT=0

$ python tools/ci/check_claims.py --parent-ref HEAD~1
claim ledger: 17 claims; claim=9, fact=6, unknown=2; 11 retained corrections; head sha256:61cd4be558b07b3e1cc99482c44f4e0ce599b6aab3e0a5e1f1d090df3345174f
CLAIMS_VS_PARENT=0

$ python tools/ci/check_docs.py
RESULT: PASS - 271 Markdown files, 58 RFCs, 81 catalogue rows, and all local links validated
DOCS=0

$ python tools/ci/check_invariants.py
invariant ledger: 12 invariants; enforced=2, orphaned=1, partial=8, unimplemented=1
INV=0

$ python tools/ci/wiring_census.py
wiring census: 13 of 41 crates reachable from warrantor-warrant over 22 path edges
CENSUS=0

$ python tools/ci/check_us_english.py main
us-english: 2723 added line(s) across 8 file(s), since main; matcher = vendored verify-us-english.mjs
us-english: ok
USEN=0

$ python -m pytest tools/ci/test_check_invariants.py tools/ci/test_check_us_english.py -q -p no:cacheprovider
16 passed in 18.59s
PYTEST2=0
```

```
$ cd rust && cargo fmt --check
FMT=0

$ cargo clippy --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2m 01s
CLIPPY=0
(0 lines in the log begin with `warning` or `error`)

$ cargo test --workspace -j 2
CARGO=0
```

Summed across every `test result:` line rather than read from the last one — a lane in this program
reported six failures when eight were failing by reading the final `FAILED` line:

```
suites: 150
{'passed': 1528, 'failed': 0, 'ignored': 20, 'measured': 0, 'filtered out': 0}
FAILED lines: 0
```

```
$ python tools/ci/check_invariant_ratchet.py
     Running tests\invariants\main.rs (M:/wt-w6-14.9-target\debug\deps\invariants-8c3a7ff0748e70ff.exe)
invariant ratchet: ok (82 passing at floor 82, 15 recorded findings at ceiling 15)
RATCHET=0
```

**Identical to the baseline this lane was given: 150 suites, 1528 passing, 0 failed, 20 ignored;
census 13 of 41 over 22 path edges; ratchet 82 at floor 82 and 15 at ceiling 15.** Nothing moved,
which is the correct outcome for a task that adds no crate and earns no invariant. `passing_floor`
was not raised and `ignored_ceiling` was not lowered.

### The correction ratchet, proved against this commit's own real history

Not a fixture. `check_append_only` was handed the ledger as it exists at `fb6e45c` through
`git show`, and an in-memory copy with `CL-014`'s retained correction deleted and `CL-017` removed
outright:

```
REFUSED CL-014: version fell; a claim version may only rise
REFUSED CL-014: correction 1 was removed or altered; a retraction is retained, never deleted
REFUSED CL-017: removed from the ledger; entries are append-only
```

And the allowed control is the run above it: `--parent-ref HEAD~1` exits 0 against `3c2baa9`, which
is the same comparison saying that `CL-014`'s new correction retains what `3c2baa9` actually
published and that adding `CL-017` is growth rather than a rewrite. A ratchet that refused both
would be a freeze.

### Every rendered number re-derived from its record, independently of the gate

The reductions were called directly rather than through `check_claim`, so this is a second reader
agreeing with the first:

```
wiring_reachability(evidence/wiring-coverage.json)   -> [13, 41, 28, 22]
invariant_status_census(evidence/invariants.json)    -> [2, 8, 1, 1]
corpus_finding_census(rust/warrant/tests/invariants) -> [9, 12, 'I-02, I-05 and I-07']

CL-001 -> 13 of 41 Rust workspace crates are reachable from the warrantor binary over 22 path edges
CL-002 -> 82 checks pass and 15 are recorded findings
CL-003 -> enforced=2, partial=8, orphaned=1, unimplemented=1
CL-005 -> 9 of the 12 invariant suites hold at least one recorded finding; I-02, I-05 and I-07 hold none
CL-016 -> 13 of 41 crates link into the warrantor binary and 28 do not
```
---

## Deviations from the plan

Fifteen, in the order they were found. The code won over the plan in every one.

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
    neighbors, and `ruff check` passes at the default ruleset. **The scope gap is not fixed here**: no
    CI job lints or formats `tools/ci/`, and closing that is a change to the Python job that belongs to
    whoever owns it.

12. **The plan's Step 5 arithmetic is right that the seed undercounted and wrong about the total.** It
    predicts eight corrections. There were nine retained across sixteen entries at
    `3c2baa9`, because deviations 3 and 4 each added one the plan did not know about, and eleven across
    seventeen after deviation 13.

13. **The plan's own `check_append_only` body is incomplete in exactly the way that matters, and
    implementing it verbatim produced a gate that passed a silent rewrite.** Step 6 quotes a function
    that compares presence, version direction and retained corrections. Every line of it is right and
    the set is not sufficient: nothing in it reads the parent revision's `text`. The plan's Bound
    strength section then states the property that body does not deliver — *"a commit that changes a
    published claim's text or status without appending a correction that retains the previous text is
    refused"* — so the plan asserts the bound and specifies a body that does not earn it. The first
    commit on this branch implemented the body and published the assertion. See *Continuation* above;
    `check_published_state` is the missing comparison and it is not in the plan.

14. **The dispatched worktree path could not be used, because the branch was already checked out.**
    `git worktree add M:/wt-w6-14.9 feat/public-claim-ledger` is refused — `fatal: 'feat/public-claim-ledger'
    is already used by worktree at 'M:/wt-w5-14.9'`, the checkout of the lane that produced `3c2baa9`.
    The branch was moved with `git worktree move M:/wt-w5-14.9 M:/wt-w6-14.9` rather than creating a
    second checkout of one branch, which preserved an uncommitted edit to this evidence file (a single
    US-English fix, `neighbours` to `neighbors`, plus the two environment hazards at the end). No other
    lane's worktree was touched and `git config user.name` was never run.

15. **One correction fixture the dispatch named is not available on this base and was NOT
    reconstructed.** The dispatch lists Task 2.1's retraction of a module header claiming the kernel
    *"authorizes, checks and receipts syscalls"* among the real corrections to seed. It is not in this
    tree: `docs/task-evidence/task-2.1.md` does not exist at `2ec0638`, and
    `grep -rn "authorizes, checks and receipts" .` over every `.md` and `.rs` file returns nothing —
    Task 2.1 lives on the unlanded `feat/effect-decomposition-registry`. Quoting it from the dispatch
    message would have produced a retained text whose only source is a chat message, which is the
    invented fixture this task forbids. It is left for whichever lane merges Task 2.1, which will hold
    the bytes.

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

14. **A retained falsifier is compared, never hashed, and that is strictly weaker.**
    `superseded_falsifier` is checked against the parent revision only. `state_digest` covers an
    entry's id, version, status and text — widening it to cover the falsifier would have changed every
    `supersedes_digest` already retained in `evidence/claims.json`, which is rewriting retained history
    in order to close a hole about rewriting retained history. The consequence: a holder of an earlier
    copy still sees `head_digest` move if the current falsifier changes, but a softened
    *retained* falsifier inside a correction is caught only while the parent revision is reachable.

15. **A new entry's history is unattested, and so is any intermediate version.** `CL-017` arrives at
    version 2 carrying a version 1 that no earlier revision of this file contains, because the entry
    itself is new — the append-only comparison has nothing to compare a new id against, by
    construction. The same holds for a version that rises by more than one in a single revision: only
    the parent's own version is compared, and any version between it and the new one is retained on the
    author's word plus its own self-consistent digest. `CL-017`'s text says this about itself.

16. **The append-only comparison is only as good as the revision it is pointed at.** `--parent-ref`
    defaults to `HEAD`, which is right for an uncommitted working tree and a no-op in a clean checkout,
    where `HEAD` *is* the commit under test. CI passes the branch base for that reason and the checker
    exits 1 rather than skipping when the ref cannot be resolved — but nothing prevents a future caller
    from passing a ref that makes the comparison trivially pass. The ratchet is a convention enforced at
    one call site, not a property of the file.

---

## Two environment hazards this run hit, recorded because they corrupt evidence rather than code

**1. `/tmp` is shared across concurrent lanes on this machine, and a second lane truncated this
lane's captured cargo output.** Gate output was first written to `/tmp/ws.log`. Partway through the
run that file contained *only* lines from `M:\wt-w3-13.7`, another worktree — a concurrent session's
`> /tmp/ws.log` had replaced it. The capture was unrecoverable and the run was repeated with output
under this session's own scratchpad directory.

```
$ grep -o "M:.wt-[a-z0-9.-]*" /tmp/ws.log | sort -u
M:\wt-w3-13.7
```

Nothing about the branch was wrong; the *evidence* was. A lane that had read the tail of that file
and reported it would have published another lane's numbers as its own — the precise failure mode
this task exists to gate, arriving through the toolchain instead of through prose. **Every gate log
in this file was captured under
`<session scratchpad>/w5-149/`, never `/tmp`.** Concurrent lanes on this box should do the same.

**2. The disk filled during the run.** `M:` reached 100% with 33 MB free while `cargo clippy` was
linking, and both clippy and the workspace test aborted with `os error 112`:

```
Caused by:
  There is not enough space on the disk. (os error 112)
CLIPPY=101
CARGO=101
```

`cargo clean -p warrantor-warrant` inside this lane's own target directory reclaimed 623.7 MiB and
the gates were re-run. Space then continued to fall as other lanes built — from 11 GB to under 500 MB
over the following half hour — so the cargo results below were obtained in a race with them. Two
requests to remove reclaimable directories elsewhere on the disk (including
`M:/wt-x-149-target`, which the dispatch identified as an orphaned target directory with no worktree)
were **denied by the permission system, and no attempt was made to work around that**. Nothing outside
this lane's own target directory was deleted.
