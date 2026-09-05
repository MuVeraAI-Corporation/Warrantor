# Task 9.1 — Bounded revocation with a stated SLA (I-05, L6-04)

**Branch:** `feat/bounded-revocation` (from **local** `main` @ `f99af94`, not `origin/main` @ `e4b5f10`)
**Worktree:** `M:/wt-w2-9.1` · `CARGO_TARGET_DIR=M:/wt-w2-9.1-target` (implementation, through `cb17524`)
**Correction worktree:** `M:/wt-fix-91` · `CARGO_TARGET_DIR=M:/wt-fix-91-target` (review fixes: `53f9ea4`, `d642b48`, `b2213d8`, and this file's own commit)
**Date:** 2026-09-05 (implementation), 2026-09-05 (correction after adversarial review)

The plan's baselines were captured at `origin/main` (`9 of 39` crates, `65 passing / 19 ignored`).
This branch is based on local `main`, which carries four unpushed merges, so every baseline in this
file was re-measured here and differs from the plan's. Where a number differs, this file's is the
one that was measured.

---

## Correction after adversarial review (2026-09-05)

Three review lenses each returned REFUTED. **Every finding reproduced**, none was disputed as
wrong, and the numbers below this section were re-captured at the corrected tip rather than left as
they were. What follows is the written record of what was claimed, what was true, how it was caught,
and what changed. Nothing here was edited quietly.

### 1. CI-BREAKING — the branch did not pass its own suite

**Claimed:** the gate block below recorded `cargo test -p warrantor-warrant --test revocation_latency`
→ `ok. 4 passed` and the workspace → `1460 passed; 0 failed`. The Files section listed
`evidence/revocation-latency.json` as created. `evidence/invariants.json`'s I-05 gap pointed a reader
at it.

**True:** the file was never committed. `.gitignore:98` is `/evidence/*` with `!` re-includes for only
`wiring-coverage.json` and `invariants.json`, so `git add` skipped it in silence and `git status`
reported a clean tree with the file present *or* absent. On a fresh worktree of `cb17524`:

```text
$ cargo test -p warrantor-warrant --test revocation_latency
EXIT=101
test result: FAILED. 3 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out
panicked at warrant\tests\revocation_latency.rs:140:59:
read M:\...\evidence\revocation-latency.json: The system cannot find the file specified. (os error 2)
```

CI runs `cargo test --workspace --all-targets` (`.github/workflows/ci.yml:157`), so the branch as
committed was RED on the pipeline, and the committed, CI-checked ledger cited a file the repository
did not contain.

**How it was caught:** the reviewer checked the branch out into a worktree that had never held the
generated file. The implementer's own tree had it, untracked and ignored, which is why the recorded
green run was real and worthless.

**Changed:** a `!/evidence/revocation-latency.json` re-include, carrying a comment naming this
failure so the next committed evidence artifact does not repeat it; the file generated and committed;
verified in a fresh detached worktree with `git status --porcelain` empty and
`git ls-files evidence/` listing all three files (`53f9ea4`).

### 2. A rendered sentence asserting something it never read (the Task 1.1 shape, again)

**Claimed:** `limitations()`'s strongest arm — "*{n} subject(s) are revoked in this machine's journal
({path}), so the Identity gate denies every verdict computed after the record reached disk*", plus
"*The subject revoked is the constant this build presents as its principal, not an issued SVID.*"

**True:** the arm fired on `!section.revoked_svids.is_empty()` and never asked whether any revoked
subject equaled this warrant's `claims.subject`, which is the only string gate 2 compares
(`notary/src/lib.rs:211`). Reproduced with the shipped binary and an exported bundle:

```text
$ warrantor revoke --svid spiffe://someone/else --root <store A>
$ warrantor report <wrt> --root <store A> --export bundle.json
  authority       allow (all nine gates passed)

allowed: True  denied_gate: None
subject: spiffe://muveraai.com/agent/local
revoked set: ['spiffe://someone/else']
LIMITATION: 1 subject(s) are revoked in this machine's journal (...), so the Identity gate denies
            every verdict computed after the record reached disk ...
            The subject revoked is the constant this build presents as its principal, not an
            issued SVID.
```

Both clauses were false of that bundle, in the same bundle as the `authority_check` that contradicted
them. The second was a hardcoded string about a value it never read: `grant --subject` and
`revoke --svid` both accept arbitrary strings.

**How it was caught:** by running the product, not by reading it. And the corpus could not have
caught it — **every** test in `tests/revocation.rs` revoked the warrant's own subject, so the one case
where the sentence and the verdict can disagree had no test at all.

**Changed:** the match now splits on a READ of the set against `stored.warrant.claims.subject`, with a
separate arm for a non-empty set that excludes it; the constant-versus-issued clause is chosen by
comparing the subject to `DEFAULT_CLI_SUBJECT`/`DEFAULT_MCP_SUBJECT`. Two tests added —
`a_revocation_for_another_subject_is_not_rendered_as_a_denial` (allowed control = a non-empty set that
excludes the subject; attack = the same set plus the subject) and
`the_constant_versus_issued_clause_is_read_off_the_subject`. Reverting the new arm makes the first
fail with the bundle above (`d642b48`).

### 3. "THIS machine" was really "this store"

**Claimed:** `REVOKE_DISCLOSURE` (a const annotated *"Nothing in this build may soften it"*) said
"*Every verdict THIS machine computes … denies at gate Identity for that subject*", and the report,
`revoke --list`, `revoke --at` and the USAGE text all used the same scope word.

**True:** the journal is `<root>/revocations.jsonl` and `--root` is accepted on every command.
Demonstrated on ONE machine:

```text
$ warrantor revoke --svid spiffe://muveraai.com/agent/local --root <store A>
$ warrantor report <wrt in store A> --root <store A>   ->  authority  deny (identity)
$ warrantor grant  ... --root <store B>
$ warrantor report <wrt in store B> --root <store B>   ->  authority  allow (all nine gates passed)
```

Same machine, same subject, opposite verdicts. The within-store control/attack pair holds (allow
before the revocation, `deny (identity)` after), so this was a scope overclaim in a shipped sentence,
not a broken gate.

**Changed:** every one of those surfaces says STORE, and each also states that the revocation does not
reach a second store on the same machine — a disclosure that did not exist before. The machine clause
is kept everywhere it appeared. `not_covered` in the generated evidence record gained the same line,
and `revocation_latency.rs` asserts it is there (`53f9ea4`, `d642b48`).

### 4. The credential budget does not bind a shipped path

**Claimed:** the W1 gaps I-05 row — "*`warrant` reads `credential-vault`'s `fsync`'d revocation
journal, so the 1-second budget binds a shipped path*" — repeated in the i05 corpus header ("both
halves are now reachable") and its hop-05 doc comment.

**True:** `REVOKE_BUDGET` is compared in exactly two places, `Vault::revoke` (`lib.rs:606`) and
`Vault::revoke_all` (`lib.rs:637`). `grep -rn "Vault\b" rust/warrant/src` returns nothing. The
binary's whole use of the crate is `JournalOp`, `JournalRecord`, `RevocationJournal`,
`CredentialError` and `REVOKE_BUDGET` read as a number to print. `RevocationStore::revoke` times
nothing. What the dependency edge bought is the journal FORMAT; the budget is still orphaned.

**Changed:** the row, the corpus header, the hop-05 doc comment and the ledger's I-05 gap all say so,
and the "still needs a shipped caller" clause is now in the handed-on column (`b2213d8`).

### 5. `adjudications_between` was decoration

**Claimed:** deviation 5 changed a public design on the grounds that the plan's counter "would have
been a hard-coded zero", and `report.rs:89` says the counter exists so the number is *counted*.

**True:** the only assertion on the field was `assert_eq!(latency.adjudications_between, 0)` in a test
that computes no verdict, so a hard-coded zero satisfied it. Mutating
`ADJUDICATIONS.fetch_add(1, Ordering::SeqCst)` to `let _ = &ADJUDICATIONS;` left the entire
`warrantor-warrant` package green — 40 suites, 0 failing.

**Changed:** `adjudications_between_counts_verdicts_rather_than_assuming_zero` revokes, builds a
report through the product's own path inside the measurement window, and asserts both that
`adjudications_computed()` strictly increased and that the field is `>= 1`. Under the mutation above
it fails at `revocation.rs:407`. It asserts `>= 1` rather than `== 1` because `ADJUDICATIONS` is
process-global and this binary runs its tests in parallel; the strict-increase assertion beside it is
the exact one, and both fail on a no-op counter (`d642b48`).

### 6. Two citations and one count that did not reproduce

* **`i01_active_identity.rs:151`** in item 6 of "does NOT establish" spoke of the ignore that
  *remains*, i.e. current state, but `:151` is its line at the baseline `f99af94`. On the shipped tree
  it is at `:162`; line 151 is prose inside an assertion message. Item 6 now cites `:162`, and the
  earlier baseline-scoped mention is labeled as such.
* **`check_docs.py`** was recorded as `263 Markdown files`. The committed tree reports **264** — the
  number was captured before this very file was added. Corrected, and re-captured at the tip.
* Two Britishisms ("honouring", "labelled") sat on `report.rs` doc-comment lines this branch rewrote.
  **Partly disputed:** the reviewer called them "introduced" by Task 9.1; `git show
  f99af94:rust/warrant/src/report.rs | grep -n "honouring\|labelled"` shows both words already there
  at `:695` and `:703`, on lines the branch later re-wrapped. They were not introduced — but they are
  on lines this branch touched, so they are corrected to US spelling. The verifier now reports **zero
  Britishisms on any line this branch adds**; five remain in `report.rs` on lines the branch never
  touched (`behaviour`, `authorised` ×2, `authorises`, `honouring` at `:855`) and are deliberately
  left, per the rule that a pre-existing Britishism in a touched file is not this branch's to sweep.

### What the review confirmed, and is worth keeping

The Tier B / Tier C labeling; no `bound_strengths()` row added and the README bounds table untouched;
`check_invariants.py` would have accepted `enforced` and the ledger chose `partial`; the ratchet's
69/15 read from the corpus's own line; the census's `11 of 40 … 19 path edges`; `within_sla =
propagated && elapsed <= sla` genuinely closing the never-arrived-inside-the-bound hole; the fourth
`limitations` arm for an unreadable journal; and five independent mutations each turning the suite red.
Every baseline in the before/after table reproduced from git.

---

## The specification: the two `#[ignore]` reasons, verbatim

These are quoted before anything else because they *are* the specification, and this task's success
is defined as making both assertions true without touching either assertion.

From `rust/warrant/tests/invariants/i05_bounded_revocation_latency.rs`, at `:84` and `:102` on
`f99af94`:

```
#[ignore = "I-05 orphaned: credential-vault is not linked by the warrantor binary, so hop 5 has no boundary (2026-09-02)"]
```

```
#[ignore = "I-05 unimplemented: no revocation source exists for the identity half (Task 3.1, 2026-09-02)"]
```

Converting the second necessarily converts a **third**, in `i01_active_identity.rs:134`, because it
asserts byte-for-byte the same thing (`!report.contains("revoked_svids: Vec::new()")`):

```
#[ignore = "I-01 currently violated: revoked_svids is hardcoded empty in report.rs (Task 1.1 / Task 3.1, 2026-09-02)"]
```

`i01_active_identity.rs:151`'s second ignore **stays** (that is its line **on `f99af94`**; on the
shipped tree the same attribute is at `:162`): the CLI subject is still a compile-time constant, and
that is Task 3.1's.

### Both shown failing first, before any code was written

```text
$ cargo test -p warrantor-warrant --test invariants -j 2 -- --ignored i05        # exit 101

running 2 tests
test i05_bounded_revocation_latency::hop_05_the_product_links_a_credential_vault_that_can_revoke ... FAILED
test i05_bounded_revocation_latency::a_revocation_source_exists_for_the_identity_half ... FAILED

---- hop_05_the_product_links_a_credential_vault_that_can_revoke stdout ----
panicked at warrant\tests\invariants\i05_bounded_revocation_latency.rs:87:5:
I-05's credential half lives in a crate the product does not link, so a shared credential has
nothing to revoke it. The 1-second budget binds no shipped code path.

---- a_revocation_source_exists_for_the_identity_half stdout ----
panicked at warrant\tests\invariants\i05_bounded_revocation_latency.rs:105:5:
the only consumer of the Identity gate supplies a revocation set that is empty by construction,
so the five-second propagation bound governs nothing.

test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 82 filtered out
```

The new measurement test was also written first and shown red:

```text
$ cargo test -p warrantor-warrant --test revocation_latency                     # exit 101
error[E0432]: unresolved import `warrantor_warrant::revoke`
error[E0432]: unresolved import `warrantor_warrant::IDENTITY_REVOCATION_SLA`
```

### And the refusal test was proved non-vacuous

Both converted string assertions could be satisfied by deleting a string and changing no behavior.
To prove `tests/revocation.rs` is what backs them, the seam was temporarily reverted to
`revoked_svids: Vec::new()` and the suite re-run:

```text
test a_revoked_subject_is_refused_at_the_identity_gate_on_the_products_own_path ... FAILED
  a revoked subject was still allowed on the product's own report path
test result: FAILED. 6 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out
```

Exactly one test fails, and it is the behavioral one. The seam was then restored.

---

## The gate, verbatim, with exit codes captured before any pipe

**Re-captured at the corrected tip** (`M:/wt-fix-91`, after the four correction commits). The numbers
the implementation recorded are superseded where they differ; each difference is named in the
correction section above. Every number below reproduces on the commit this file documents.

```text
$ cargo fmt --all -- --check
FMT_CHECK=0

$ cargo clippy --workspace --all-targets -- -D warnings
CLIPPY=0

$ cargo test --workspace -j 2 > log 2>&1; echo $?
WORKSPACE_EXIT=0
  141 suites; 1463 passed; 0 failed; 20 ignored
  (summed with: sed -n 's/^test result: ok\. \([0-9]*\) passed; \([0-9]*\) failed; \([0-9]*\) ignored.*/\1 \2 \3/p' | awk ...)

$ cargo test -p warrantor-credential-vault
EXIT=0
test result: ok. 30 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.01s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.02s

$ cargo test -p warrantor-credential-vault --no-default-features
EXIT=0
test result: ok. 27 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.03s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.02s

$ cargo build -p warrantor-credential-vault --no-default-features --bins
EXIT=0
warning: target filter `bins` specified, but no targets matched; this is a no-op

$ cargo test -p warrantor-warrant --test invariants -j 2
EXIT=0
test result: ok. 69 passed; 0 failed; 15 ignored; 0 measured; 0 filtered out; finished in 0.16s

$ cargo test -p warrantor-warrant --test revocation
EXIT=0
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.67s

$ cargo test -p warrantor-warrant --test revocation_latency
EXIT=0
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.28s

$ cargo test -p warrantor-warrant --test instructions
EXIT=0
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.21s

$ python tools/ci/wiring_census.py
wiring census: 11 of 40 crates reachable from warrantor-warrant over 19 path edges
EXIT=0

$ python -m pytest tools/ci/test_wiring_census.py -q -p no:cacheprovider
12 passed in 0.64s

$ python tools/ci/check_invariants.py
invariant ledger: 12 invariants; enforced=2, orphaned=1, partial=8, unimplemented=1
EXIT=0

$ python -m pytest tools/ci/test_check_invariants.py -q -p no:cacheprovider
8 passed in 0.30s

$ python tools/ci/check_invariant_ratchet.py --show-findings
invariant ratchet: ok (69 passing at floor 69, 15 recorded findings at ceiling 15)
RATCHET_EXIT=0

$ python tools/ci/check_docs.py
RESULT: PASS - 264 Markdown files, 58 RFCs, 81 catalogue rows, and all local links validated
EXIT=0
```

The recorded file count was `263` until the correction: that number was captured before this very
file was added to the tree, so it described a tree one file short of the one that shipped. The gate
passed either way, which is why nothing caught it. It is `264` on the commit this file documents.

### The ratchet floor was READ, never computed

`check_invariant_ratchet.py` fails on an improvement as loudly as on a regression, so a floor set
one too low would have failed. The floor and ceiling written into
`tools/ci/invariant-ratchet.json` (`69` / `15`) were taken from the corpus's own
`test result:` line quoted above — not from arithmetic on the baseline. That the numbers happen to
equal `66 + 3` and `18 - 3` is a *check* on the three conversions having had no side effects, not
the source of the values.

### Before and after

| measure | before (local `main` @ `f99af94`) | after |
|---|---|---|
| workspace suites | 139 | 141 |
| workspace passing | 1435 | 1463 |
| workspace failed | 0 | 0 |
| workspace ignored | 23 | 20 |
| invariant corpus | 66 passing, 18 ignored | **69 passing, 15 ignored** |
| ratchet floor / ceiling | 66 / 18 | **69 / 15** |
| wiring census | 10 of 40 over 18 edges | **11 of 40 over 19 edges** |
| invariant ledger | enforced=2, orphaned=2, partial=7, unimplemented=1 | enforced=2, **orphaned=1, partial=8**, unimplemented=1 |
| `warrantor-warrant` normal-dep packages | 156 | **157** |

The 28 new passing tests are: 3 converted corpus findings, 8 unit tests in `revoke.rs`, 13 in
`tests/revocation.rs`, and 4 in `tests/revocation_latency.rs`. (It was 25 before the correction: the
three added in `d642b48` are the non-intersecting revoked set, the constant-versus-issued clause, and
the adjudication count.)

### The orphan count fell rather than rose

`reachable` 10 → 11, and the `orphaned` array loses `warrantor-credential-vault`, 30 → 29.
`README.md:196` was updated in the same commit — `**10 of 40**` → `**11 of 40**` and
"the other 30" → "the other 29" — because `wiring_census.py:196` refuses a build in which the
rendered number and the measured one disagree.

### The edge's dependency cost, measured

```text
$ cargo tree -p warrantor-warrant -e normal --prefix none | awk 'NF{print $1}' | sort -u | wc -l
156        # before
157        # after

$ cargo tree -p warrantor-warrant -e normal -i regex
warning: nothing to print.      # both before AND after: `regex` never enters the graph

$ cargo tree -p warrantor-warrant -e normal -i clap
clap v4.6.6
└── warrantor-trust-core v1.0.0
    └── warrantor-warrant v1.0.0     # already present before this task; the gate costs nothing here

$ git diff rust/Cargo.lock
+ "warrantor-credential-vault",     # one line, inside warrantor-warrant's dependency list
```

The four crates the feature gate kept out are `aho-corasick`, `regex`, `regex-automata` and
`regex-syntax`, all reachable only from `scan_for_exposed_credentials`. Without
`default-features = false` the count would have gone 156 → 161. The 7-external-dependency,
tokio-free posture is unchanged.

The gate is a real partition rather than a rename: the default feature set runs 30 + 3 tests exactly
as before, and `--no-default-features` runs 27 + 3 — the three scanner tests disappear with the
scanner they test.

### A real measured run of the operator surface

Re-captured at the corrected tip, so the disclosure below is the one that ships:

```text
$ warrantor revoke --svid spiffe://muveraai.com/agent/local --root <scratch>
revoked   spiffe://muveraai.com/agent/local
  sequence           0
  durable at         1788644375 (epoch seconds)
  journal            <scratch>\revocations.jsonl
  measured latency   304.6µs to this process's first read
  adjudications in between  0 (verdicts this process computed between durability and that read)
  stated bound       5s -- inside it
  what this does:
    Every verdict computed against THIS STORE -- the journal named above -- after the record
    reached disk denies at gate Identity for that subject. The refusal is a chokepoint in
    `warrantor_notary::verdict`, not an operating-system bound.
  what it does NOT do:
    It does not recall a credential already used -- revocation bounds future use only. It
    does not reach a copy held by a third party, does not close a session already open, and
    does not terminate a process. It does not propagate to any other machine: this build
    links no fan-out, so the latency above is this process's, not a fleet's. It does not
    reach a SECOND STORE on this same machine either: `--root` is accepted on every command,
    each store root holds its own journal, and the same subject reads as unrevoked under a
    different root. The egress broker does not consult the revocation set at all. An agent
    that never asks for a verdict is never refused. The journal records WHEN a subject was
    revoked, not WHO revoked it: it is keyed by subject, and the per-warrant actor log is not.
```

Four runs across the two trees measured 676.3µs, 468.3µs, 372.8µs and 304.6µs, all against a stated
5s bound, all with `adjudications_between = 0`. A reviewer measured 9.19ms on the same code, which is
a factor of twenty and still two orders inside the bound — which is the point. A number this far
inside its bound is not evidence that the bound is tight; it is evidence that the bound is not the
thing under strain on one machine. What the bound is *for* is a case this build cannot produce, which
is why the breach is exercised by injection instead — see the tier table.

---

## Tier table: which word each bound gets, and why not a stronger one

| bound | word | why not stronger |
|---|---|---|
| A revoked subject is refused at the notary's Identity gate | **Mediated** (Tier B, chokepoint) | `warrantor_notary::verdict` returns `Deny { gate: Identity }` — a specific line of code refusing a specific request at the moment it is adjudicated, so it is not merely Observed. It is **not** `Enforced`: an agent that never asks for a verdict is never refused, and nothing here terminates a process, closes a socket, drops a connection, or invalidates a bearer token held elsewhere. There is no netns, seccomp or firewall anywhere in this repository. |
| Revocation propagates within 5 s (`IDENTITY_REVOCATION_SLA`) | **Observed** (Tier C) | Nothing in this build delivers a revocation record to a second process, let alone a second machine. The measurement is this process's own read of its own file. "Propagates to all replicas in <5s" is measured against exactly one replica. |
| Revocation survives a restart | **Observed** | The journal is `fsync`'d before a revocation is acknowledged and replayed at open, and a unit test drops and reopens the store. That is a property of the file, which nothing in this build refuses to delete or rewrite outside the process — an operator with filesystem access can truncate it, and `open` will then report a shorter set rather than refuse. |
| Non-revocation at a past epoch is provable from the log | **Observed** | It is a true reading of an append-only local file, and it is only as strong as that file. There is no anchor, no countersignature and no second copy: a reader is trusting one STORE's journal — not one machine's, and not a proof against tampering. |
| Egress-path revocation | **not claimed at all** | `egress::decide` takes a request and a destination catalog and no revocation input. This task does not give it one, and `evidence/revocation-latency.json` records the enforcement point as `consults_revocation: false` rather than omitting it. |

**No new `bound_strengths()` row.** Revocation is a property of the existing Identity gate, not a new
bound on the warrant, so the README bounds table and `tests/tier_disclosure.rs` are untouched.
Rendering the SLA for an operator is Task 11.10.

**No new trust root.** The revocation list is an append-only JSONL file under one warrant store root,
appended by an operator and read by the adjudications that go through **that store**. It is not a
directory, not a CA, and not an authority anyone else consults. It establishes: every verdict *this
process* computes *against that store* after `sync_all` returns denies at gate Identity for that
subject, and non-revocation at any past epoch is answerable from the file alone. It establishes
nothing about a second store on the same machine, which has its own journal and reads the same subject
as unrevoked.

**Every refusal is paired with an allowed control.** `tests/revocation.rs`'s attack half is preceded
by a control built through the same function with nothing revoked, which must be `allowed`; a verifier
that refused everything would fail it. `tests/revocation_latency.rs`'s breach case is preceded by an
in-budget control which must report `within_sla: true`.

---

## Deviations from the plan

Nine, all recorded because in each case the code won.

1. **Base branch.** The plan cuts from `origin/main` @ `e4b5f10`. The task brief directed local
   `main` @ `f99af94`. Every baseline number in this file was re-measured accordingly; the plan's
   `9 of 39` / `65 / 19` / `17 edges` do not appear anywhere in this branch.

2. **The ratchet is 69/15, not the plan's 68/16.** Same cause: local `main` starts at 66/18, not
   65/19. The numbers were read from the corpus's `test result:` line.

3. **`build_observed` takes a struct, not an eighth parameter.** The plan specified
   "`build_observed` gains an eighth parameter". Clippy refuses it:

   ```text
   error: this function has too many arguments (8/7)
      --> warrant\src\report.rs:854:1
   ```

   The repository has **no existing `#[allow(clippy::too_many_arguments)]`**, so suppressing the lint
   would have introduced the first one. Instead the three observed sections are grouped into
   `pub struct Observed { spend, custody, revocation }`, which brings the count to six and makes
   `Observed::default()` read more plainly than three bare `None`s. Every call site changed shape
   rather than gaining an argument. **This is a public API change to `build_observed` beyond what the
   plan authorized, and a reviewer should look at it as such.**

4. **`RevocationLatency` carries a fifth field, `propagated`.** The plan listed four. Without it, a
   store whose read does not find the subject would report a tiny `elapsed_nanos` and — on the plan's
   formula — `within_sla: true`, i.e. a revocation that never arrived reported as inside the bound.
   `within_sla` is now `propagated && elapsed <= sla`, and a unit test asserts a silent source is
   never called inside the bound.

5. **`adjudications_between` is counted by a process-global `AtomicU64` in `report.rs`, not by a
   `note_adjudication` method on the store.** The plan's design cannot work: `build_observed` receives
   an already-materialized `Option<RevocationSection>`, never a `&mut RevocationStore`, so no report
   path could have incremented a per-store counter and the number would have been a hard-coded zero.
   The counter is incremented at the one place in the binary that computes a verdict, so
   `adjudications_computed()` is a real count. Process-global is also the true scope of the fact: the
   question is how many actions *this process* adjudicated, which has nothing to do with which store
   the read went through.

   **Corrected after review:** this deviation's justification was sound and its mechanism was
   UNTESTED. The only assertion on the field expected `0` in a test that computes no verdict, so a
   hard-coded zero — the very thing the deviation was written to avoid — satisfied the entire package.
   `adjudications_between_counts_verdicts_rather_than_assuming_zero` now fails under that mutation.
   A deviation that changes a public design on the strength of a mechanism owes a test that the
   mechanism works; this one did not have it.

6. **`warrantor revoke` does NOT append to the per-warrant actor log.** The plan said it should,
   "so `CustodySection` covers who revoked". It cannot: `operators::record(root, warrant_id, ...)` is
   keyed by warrant id and `Act` has no `Revoke` variant, while a revocation names a *subject* and has
   no warrant id. Rather than invent one, the command states the gap in its own output — *"The journal
   records WHEN a subject was revoked, not WHO revoked it"* — and a CLI test asserts that sentence is
   present. **This is a real gap, not a design choice I am pleased with:** there is no attribution on
   a revocation in this build.

7. **`tests/revocation.rs` uses local fixtures, not `fixture::open_warrant_store`.** The plan's
   sketch calls a helper that does not exist anywhere in the repository. The file builds its own
   `stored()` / `queue_at()` / `issuer()` helpers in the shape `tests/report.rs` already uses.

8. **A fourth arm was added to the `limitations()` match, and a `source_readable` field to
   `RevocationSection`.** The plan specified three arms. A journal that opens and is then corrupted
   underneath the store yields an empty set through `revoked_svids()`, which under the plan's three
   arms would have rendered as "consulted and holds no revoked subject" — an I/O failure reported as a
   clean bill of health. The fourth arm says *"could NOT be read … Treat this report as having checked
   nothing"*, and a test drives it.

9. **`tests/instructions.rs` gained four entries in `ACCEPTED_FLAGS`.** Not in the plan's Files list.
   The full workspace run caught it, correctly: that test refuses a build whose usage text names a
   flag the parser does not accept. All four (`svid`, `list`, `at`, `write-evidence`) are read by
   `cmd_revoke`. **No assertion was weakened** — the flags were added to a list of things that must be
   wired, and they are wired.

Also worth naming, though not a deviation: `evidence/revocation-latency.json` is **generated** by
`warrantor revoke --write-evidence <path>` from `revoke::latency_evidence()`, and
`tests/revocation_latency.rs` refuses a build in which the committed file and that function disagree.
The plan showed the file as a hand-written literal with `"samples": 0` placeholders; a hand-written
file with no gate is exactly the drift the "rendered number must be gated against its record" rule
exists to prevent, so the placeholder `p50`/`p99`/`samples` fields were dropped rather than committed
as zeros a reader could mistake for measurements. **And the generated file was not committed** — see
correction 1: a gate that reads a file the commit does not contain fails every build but the author's.

**Two test locators were adapted in the correction, and neither was weakened.** Both are called out in
the test bodies as well as here, because a changed assertion is the thing a reviewer must be able to
see:

* `the_revoked_arm_states_every_thing_the_revocation_does_not_reach` searched for `"revoked in this
  machine's journal"`, the exact string the scope correction replaces. Its required-clause list is
  unchanged and **grew** by `"does not reach another store on this same machine"`.
* `the_cli_lists_what_it_revoked_and_says_what_the_revocation_misses` required `"not WHO\n
  revoked it"` — an assertion on the column a sentence happens to wrap at, which the rewrap broke. It
  now requires `"records WHEN a subject was"` and `"not WHO revoked it"` separately, plus the store
  clause, and keeps the machine clause it already had. The claim asserted is the same claim; only the
  wrap-dependence is gone.

**No other existing assertion was weakened anywhere in this task.** The three `#[ignore]` attributes were
removed and their `FINDING` doc comments rewritten as `FIXED BY` notes; the assertion bodies are
byte-identical. `credential-vault`'s `REVOKE_BUDGET` line and its
`"a revoked credential MUST stay revoked across a restart (I-05)"` string are untouched, because
`i05_bounded_revocation_latency.rs` greps that file for both.

---

## What this task does NOT establish

Specifically, not modestly.

1. **It does not establish that a revocation reaches any second process, on this machine or any
   other.** There is no broker, no replica set and no fan-out in this build. Every latency in
   `evidence/revocation-latency.json` and in every report is one process reading one file it wrote
   itself. The blueprint's "propagates to all replicas in <5s" is measured against one replica, and
   calling that a measurement of the clause would be false. Cross-machine revocation is Task 9.5.

2. **It does not establish that any real revocation has ever taken 304µs.** The four numbers in this
   file are from warm scratch directories on one Windows box with nothing else contending for the
   disk, and a reviewer on other hardware measured 9.19ms from the same code. `p50`/`p99`/`samples`
   are deliberately absent from the evidence file rather than present as zeros. There is no
   distribution here — there are four samples of one operation on one machine.

3. **It does not establish the SLA is *tight*.** A 5-second bound met in under a millisecond tells you
   the bound is not binding on this path, not that the system is fast under load. The breach case is
   reached only by injecting a deliberately slow `RevocationSource`; no real condition in this build
   has ever breached it, and none is known to.

4. **It does not recall a credential already used.** This is the blueprint's own residual for this
   item and it is untouched: revocation bounds future use only. An action already committed under a
   subject that is now revoked stays committed, and its receipts stay valid.

5. **It does not reach a credential a third party holds, close an open session, terminate a process,
   or drop a socket.** The refusal is a chokepoint at adjudication. An agent that acts without asking
   for a verdict is not bound by it, which is Tier B's whole meaning and the mediation ceiling this
   project has already recorded.

6. **It does not revoke an issued identity.** The DEFAULT subject is `DEFAULT_CLI_SUBJECT` /
   `DEFAULT_MCP_SUBJECT`, compile-time constants. Nothing issued them, nothing binds them to a
   workload, and revoking one revokes *every* local action that took the default, because they all
   present the same string. `grant --subject` and `revoke --svid` do accept arbitrary strings, so a
   revoked subject is not necessarily the constant — it is necessarily an unissued string, which is
   the weaker and true statement, and the one the report now derives rather than asserts.
   `i01_active_identity.rs:162`'s remaining `#[ignore]` is exactly this and is Task 3.1's (`:151` on
   the `f99af94` baseline; the citation drifted and is corrected).

7. **It does not make the egress path revocation-aware.** `egress::decide` never sees the revocation
   set. An agent whose subject is revoked can still be *allowed* by the egress broker, because that
   decision does not ask. The evidence file records this as an enforcement point with
   `consults_revocation: false` rather than pretending there is one point. Task 7.7.

8. **It does not say who revoked anything.** See deviation 6. The journal is keyed by subject and
   carries only the op and the epoch. There is no operator name, no signature over the record, and no
   entry in the hash-chained actor log — so a revocation cannot be attributed, and an unauthorized
   local write to that file is indistinguishable from an operator's act.

9. **It does not protect the journal from tampering.** The file is plain JSONL under the store root.
   Truncating it un-revokes subjects, and `open` will report the shorter set. Monotonicity is a
   property of how this code *writes*, not a property anything enforces about the file. There is no
   anchor over it and no signature.

10. **It does not make revocation `Enforced` in any tier sense**, and the ledger says `partial`
    rather than `enforced` for exactly that reason. `check_invariants.py` would have accepted
    `enforced` — the crates it cites are linked — so this is a claim chosen down, not one the gate
    forced.

11. **`seen_nonces` is still `Vec::new()`** in the same `VerdictContext` literal this task edited.
    The freshness gate still sees an empty replay set. That is I-10's finding, untouched here, and the
    existing limitation line still says so.

12. **The Windows filesystem paths in this task are untested by CI.** CI runs the workspace on
    ubuntu only, so `RevocationStore::open`, the journal append and every `#[cfg(windows)]` path
    beneath them are exercised on this box and nowhere in the pipeline. Every scratch journal in the
    tests lives under `std::env::temp_dir()` rather than in the repository, so a concurrent lane's
    `cargo` cannot race them, but that is a hazard avoided rather than a platform covered.

Added after the adversarial review, because a reviewer showed each of these:

13. **It does not bound a subject beyond ONE STORE.** The journal is `<root>/revocations.jsonl` and
    `--root` is accepted on every command, so the same subject revoked in store A is allowed in store
    B on the same machine — demonstrated, not inferred (correction 3). The word "machine" was wrong in
    the shipped disclosure, the report, `--list`, `--at` and the USAGE text; all now say store, and all
    now say that a second store on the same host is not reached. A multi-root operator, or a service
    running on a different root than the CLI, is the case that made this matter.

14. **It does not bring the 1-second credential budget into a shipped path.** Linking
    `credential-vault` bought its journal FORMAT. `REVOKE_BUDGET` is still compared only inside
    `Vault::revoke` and `Vault::revoke_all`, nothing in `rust/warrant/src` constructs a `Vault`, and
    `RevocationStore::revoke` times nothing and refuses nothing on duration. Only the 5-second identity
    SLA is measured anywhere in the product. The W1 gaps row said the opposite until the correction
    (correction 4); the credential half of I-05 remains orphaned in the sense that matters, and no task
    currently owns giving the budget a caller.

15. **It does not attribute a revocation to an operator, and this is not fixed.** See deviation 6 and
    item 8; naming it twice is deliberate. Nothing signs a revocation record, so an unauthorized local
    write to the journal is indistinguishable from an operator's act, in both directions: an
    unauthorized *revocation* is as invisible as an unauthorized *deletion*.

16. **A `limitations` sentence is only as true as the test behind it.** Two of this task's four
    defects were in sentences inside a signed bundle, and neither was reachable by any test in the
    file — because every test revoked the warrant's own subject. The general lesson, recorded so the
    next task does not need the same review: a rendered string that asserts something about a value
    must inspect that value, and the test corpus must contain the case where the string and the value
    disagree. Both now exist for this arm; nothing guarantees they exist for the other twelve
    limitation lines in the same function.

---

## Files

Created:

- `rust/warrant/src/revoke.rs` — `RevocationStore`, `RevocationRecord`, `RevocationSource`,
  `RevocationLatency`, `measure`, `latency_evidence`, and 8 unit tests.
- `rust/warrant/tests/revocation.rs` — 13 tests: the refusal with its allowed control, the digest
  binding, one per `limitations()` arm (five arms now), the non-intersecting revoked set with its
  allowed control, the constant-versus-issued clause, the adjudication count, and three driving
  `warrantor revoke`.
- `rust/warrant/tests/revocation_latency.rs` — 4 tests: the in-SLA measurement, the injected breach
  with its in-budget control, the evidence record's own counts and scope, and the file-versus-code gate.
- `evidence/revocation-latency.json` — format `warrantor.revocation-latency/1`, generated by
  `warrantor revoke --write-evidence`. **Committed in `53f9ea4`, not in `cb17524`** — see correction 1.
- `docs/task-evidence/task-9.1.md` — this file.

Modified: `rust/credential-vault/Cargo.toml`, `rust/credential-vault/src/lib.rs`,
`rust/warrant/Cargo.toml`, `rust/Cargo.lock`, `rust/warrant/src/lib.rs`,
`rust/warrant/src/report.rs`, `rust/warrant/src/bin/warrantor.rs`,
`rust/warrant/src/mcp_endpoints.rs`, `rust/warrant/src/serve.rs`,
`rust/warrant/tests/report.rs`, `rust/warrant/tests/spend.rs`,
`rust/warrant/tests/staged_chain.rs`, `rust/warrant/tests/instructions.rs`,
`rust/warrant/tests/invariants/i05_bounded_revocation_latency.rs`,
`rust/warrant/tests/invariants/i01_active_identity.rs`, `tools/ci/invariant-ratchet.json`,
`tools/ci/check_invariants.py`, `evidence/invariants.json`, `evidence/wiring-coverage.json`,
`README.md`, `docs/W1-delivery-gaps.md`, and — in the correction commits —
`.gitignore`, `rust/warrant/src/revoke.rs`, `rust/warrant/tests/revocation.rs`,
`rust/warrant/tests/revocation_latency.rs`.

---

## Handed on

- **Task 3.1** — an issued SVID instead of `DEFAULT_CLI_SUBJECT`, so a revocation names one agent
  rather than every local action.
- **Task 7.7** — `egress::decide` consulting the revocation set, which would make the second
  enforcement point in `evidence/revocation-latency.json` a real one.
- **Task 9.5** — cross-machine revocation, which is where "propagates to all replicas" stops being
  measured against one replica.
- **Task 11.10** — rendering the SLA to an operator.
- **Unclaimed by any task:** attribution on a revocation (deviation 6), integrity protection for the
  journal (item 9 above), and a shipped caller for `credential-vault`'s 1-second revoke budget
  (item 14, added after review). All three are gaps this task opens or leaves open by shipping the
  surface, and none is assigned.
