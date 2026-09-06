# Task 1.6 — Trust directory bundle export/import and second-machine offline verify (L10-01, L7-07)

**Branch:** `feat/trust-bundle-second-machine` (from `origin/main` @ `e4b5f10`)
**Worktree:** `M:/wt-1.6` (target dir `M:/wt-1.6-target`)
**Date:** 2026-09-05 (measured on the pre-rebase tip `b4e4c33`)
**SUPERSEDED BY THE REBASE SECTION AT THE END OF THIS FILE.** Every commit hash and every
gate number above was measured on `b4e4c33`, which sat 115 commits behind local `main` and is
no longer this branch's tip. The tip this file now describes is `b2bea1a`, rebased onto local
`main` @ `6f41384`.
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
  # SUPERSEDED: measured on b4e4c33. The rebased tip's count is in the rebase section below.
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


---

# Rebase onto local `main`, 2026-09-06 — every number below supersedes the numbers above

The sections above were measured on the pre-rebase tip `b4e4c33`, which sat 115 commits behind
local `main`. That tip is no longer on this branch. **Every gate number and every commit hash in
the sections above is superseded by this section**; nothing above was deleted, because the record
of what was measured on which tip is itself evidence.

**Branch:** `feat/trust-bundle-second-machine`, rebased onto **local** `main` @ `6f41384` — not
`origin/main`, which is more than a hundred commits behind and would have measured nothing.
**Worktree:** `M:/wt-1.6` · **Build dir:** `M:/wt-rv-1.6-target`, this lane's own; a target dir
shared between worktrees makes cargo alias their path crates.
**Tip this file describes:** `b2bea1a`

**`main` moved four times during this lane, so the branch was rebased five times and the full gate
was run six times.** Four other lanes were merging while this one ran, and the rule is to rebase onto
whatever `main` is now and re-measure every number, never to keep one taken against an earlier tip:

| rebased onto | what `main` had added | outcome |
|---|---|---|
| `2463504` | the state at the start of this lane | two conflicts, resolved below; full gate green |
| `03bae12` | 25 commits — Task 12.3 and Task 7.6 | no conflict; **test gate red for a defect belonging to `main`** — see below |
| `ca937c6` | 3 docs-and-board commits | no conflict; full gate green |
| `8c0fbc3` | Task 7.4, the substrate-mutating adapters | no conflict; the kill drill flaked once, green on the immediate re-run |
| `6f41384` | `main`'s own fix for the same harness-listing regression this lane had fixed | one conflict in `tests/instructions.rs`, resolved by taking `main`'s fix whole; `cargo fmt` then went red on that file, fixed in `b2bea1a`, and the gate below is the run after it |

**Every number in this section was measured on `b2bea1a`; none was carried across from an earlier
pass.** The superseded passes' logs are kept beside this one under
`.../Temp/rv16-{firstpass,pass2,pass3,pass4,pass5}-superseded/` and are not the numbers below.

## The commits, after the rebase

Six commits went in and six came out, each with its original author (`GLM 5.3 Flash (zcode)
<glm@local>`), its original subject and its `Signed-off-by` trailer. Three review commits sit on
top; they are authored by this review lane, not by the GLM lane.

| commit | subject |
|---|---|
| `b2bea1a` | Claude Code (Opus 5) style(tests): rustfmt the harness-listing test main landed one line over the limit |
| `8dbcfb8` | Claude Code (Opus 5) docs(verify): drop a doc line the anchor_line rewrite left behind |
| `8c4d522` | Claude Code (Opus 5) fix(verify): the rebase brought two new anchored verdicts under this branch's rule |
| `68db8b4` | GLM 5.3 Flash (zcode) docs(evidence): record task 1.6's gate, the three-store receipt, and the disk incident |
| `8f57add` | GLM 5.3 Flash (zcode) docs(gaps): the trust bundle has now been carried between stores and verified |
| `6b6cb9b` | GLM 5.3 Flash (zcode) feat(verify): read a trust bundle by its format |
| `698b17a` | GLM 5.3 Flash (zcode) feat(verify): an inherited pin says so, and every anchored verdict states revocation is not established |
| `0f9cdbe` | GLM 5.3 Flash (zcode) feat(trust): import records provenance; export strips it |
| `fa7bf44` | GLM 5.3 Flash (zcode) feat(trust): a pin records whether it was checked here or inherited |

Verified rather than assumed: the six subjects and their order are identical before and after all five
rebases, and each of the six carries exactly one `Signed-off-by:` line. Nothing was squashed,
reworded, dropped, or amended. Two notes on the review commits, neither touching a GLM-authored
commit: the first two were re-made once, before either had been gated, because `git commit -s`
appended a second `Signed-off-by` *after* the `Co-Authored-By` trailer and pushed it off the last
line (the resulting tree is byte-identical); and this session's attribution guidance rotated while
the lane ran, which is why two of the review commits credit `Claude Fable 5.1` and the third
`Claude Opus 5`. A fourth review commit existed and was dropped — see conflict 3.

## The conflicts, and how each was resolved

Two conflicts were in the first rebase, onto `2463504`, and one in the fifth. Rebases two, three
and four applied every commit with no conflict at all.

**1. `rust/warrant/src/bin/warrantor.rs` — the `verify` dispatch table.** Four hunks, all inside
`cmd_verify` and the block of `verify_*` helpers below it. `main` had added three arms since this
branch's base (destination catalog, conformance receipt, effect registry) and the two helper
functions behind two of them; this branch adds a trust-bundle arm and `verify_trust_bundle`.
**Both sides kept in full.** The merged match holds all six recognized formats plus the
effect-registry refusal; the "warrantor verify reads ..." sentence lists six format constants
rather than `main`'s five or this branch's four; all three helper functions are present. Nothing
from `main` was discarded, and no arm was reordered in a way that changes which one matches — the
arms are guard-based and mutually exclusive.

**2. `docs/W1-delivery-gaps.md` — the "what remains open" sentence in the trust-directory
paragraph.** Two edits to one sentence: `main` had changed `organisation` to `organization` under
the US-English rule; this branch had rewritten the first half to name L10-01's extensions. **Both
kept**: the branch's new first half with `main`'s US spelling. Every section `main` added to that
file since this branch's base survives — §3.1c, the metadata and link-local floor with the adapter
conformance kit over `rust/warrant/src/effect_sdk.rs`, among them. `git diff main..HEAD --
docs/W1-delivery-gaps.md` shows exactly two hunks, both this branch's own.

**3. `rust/warrant/tests/instructions.rs` — `main` fixed the same defect this lane had fixed, and
`main`'s fix won.** While this lane's gate was running, `main` landed `6f41384`, its own repair of
the harness-listing regression described below. **Resolved by taking `main`'s version whole**, which
left this lane's commit with nothing to apply, so the rebase dropped it as empty. That is the only
commit dropped anywhere in this lane and it is one this lane wrote minutes earlier; all six
GLM-authored commits are intact. `git diff main..HEAD -- rust/warrant/tests/instructions.rs` is now
empty: the file on this branch is `main`'s file, byte for byte. The two fixes were independent and
agree on the diagnosis and on the standard — `main`'s matches an aligned row by its column padding,
this lane's matched it by its coverage phrase, and both keep the `>= 10` assertion and the original
intent. `main`'s is the one that ships.

**No census artifact conflicted.** This branch adds no crate and no dependency edge, so `README.md`'s
census numbers and `evidence/wiring-coverage.json` were untouched on both sides and needed no
`--write` rewrite. The census was run on the merged tree anyway and the orphan count did not rise:
``.

**No ratchet number was picked.** This branch converts no `#[ignore]` and adds none, so the pair
stays where `main` has it. It was read off the merged corpus's own `test result:` line rather than
computed: ``.

## The exit gate, quoted verbatim from the plan

`### Task 1.6`, Step 7 of
`docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md`:

> **Step 7 — Gate, ledger, live receipt.** From `M:/wt-1.6/rust`: `cargo fmt --all -- --check`,
> `cargo clippy --workspace --all-targets -j 2 -- -D warnings`, `cargo test --workspace
> --all-targets -j 2`, `cargo build --workspace --all-targets -j 2`, `cargo metadata --locked >
> /dev/null`. Then the live run (not a fixture): with three fresh `HOME`s under
> `M:/wt-1.6-live/{a,b,c}`, replay Step 4's sequence by hand with the built `warrantor.exe` and
> keep `c`'s verify output verbatim.

and, closing the same step:

> Push and open the PR; merge only after rebasing on `main` (PR CI tests against old main).

The blueprint anchor the task is measured against, from the section's opening paragraph:

> verified by "a bundle signed by an unpinned key is refused ... the output states that no
> revocation is established," and L7-07's gate G-03, "a stranger verifies a bundle on a clean,
> offline machine with only the instructions inside it."

## Does something on this branch perform THAT run? — **RUN, and one gate item is red**

**The cargo half: RUN on this tip, `b2bea1a`.** Transcripts at
`C:/Users/MuVeraAICorporation/AppData/Local/Temp/rv16/{fmt,clippy,test,testnff,doc,build,metadata}.log`,
each exit code appended to `exits.txt` **before any pipe**. Suite counts are read from the
`test result:` lines, never from an exit code — a run that exits 0 with zero suites did not run.

```
cargo fmt --all -- --check                             exit 0
cargo clippy --workspace --all-targets -- -D warnings  exit 0
cargo test --workspace --all-targets                   exit 101  RED  81 suites reached before it stopped, 943 passed, 1 failed, 4 ignored
cargo test --workspace --all-targets --no-fail-fast    exit 101  RED  124 suites, 1604 passed, 1 failed, 20 ignored
cargo test --workspace --doc                           exit 0   40 suites, 1 passed, 0 failed, 0 ignored
cargo build --workspace --all-targets                  exit 0
cargo metadata --format-version 1 --locked             exit 0   (Cargo.lock untouched: no dependency added)
python ../tools/ci/wiring_census.py                    
python tools/ci/check_invariant_ratchet.py             
python tools/ci/check_invariants.py                    
python tools/ci/check_docs.py                          
python tools/ci/check_us_english.py main               
```

**The test gate is red, and its one red suite is not this branch's.** The prescribed command
fail-fasts, so it reached only 81 of the workspace's 124 suites; the `--no-fail-fast`
run measured all 124 and found **exactly one** failing test in the whole workspace,
`conformance_receipt.rs::a_drill_on_this_kernel_produces_a_receipt_that_verifies_offline`. That is
the finding `main` itself records — see the corrections section below. Every other suite is green:
1604 passing tests, 20 ignored, and the ignored count is exactly the ratchet's ceiling.
The `--no-fail-fast` run is reported here rather than a lucky green re-run, because enumerating every
suite is the stronger measurement and because "run it again until it passes" is the thing this
repository's discipline exists to refuse. (It did pass, complete and green, on the fourth rebase's
re-run — 124 suites, 1605 passing, 0 failed — and that is recorded rather than presented as the
result.)

`rust/warrant/tests/trust_bundle.rs` ran 6 of 6 passing and `rust/warrant/tests/trust.rs` 20 of 20 on
every pass. **The flake the pre-rebase evidence recorded did not recur:**
`a_stranger_verifies_a_report_with_a_pin_inherited_from_a_bundle` passed on all six gate passes. It
stays a recorded flake rather than a closed one — six green runs do not retire a process-spawn
timing hazard, and the kill drill in the same workspace is the proof of that.

**The live-run half: RUN on 2026-09-05, and re-derived here from its artifacts rather than
re-quoted.** The three stores are still on disk at `M:/wt-1.6-live/{a,b,c}` with `a-report.json`
and `team-b.json` beside them, so every figure in the receipt quoted in `docs/W1-delivery-gaps.md`
was checked against the bytes it came from:

| what the receipt says | re-derived from | agrees |
|---|---|---|
| `verified 6891b6dddd5975923cefd262ed766a388ce8f1ccf782474f4a0830f27f9c9272` | `a-report.json`'s own `bundle_digest` field — for a report export `verify` prints the bundle digest, not the file digest | yes |
| the signature bound to `438ea861…c37e417` | `a-report.json` → `evidence_receipt.signature.public_key`, and the `ana` pin's `key` in the stranger's directory | yes |
| `INHERITED from a bundle signed by \`team-b\`` | `c/.warrantor/trusted/issuers.json` → `ana.imported_from.signer_name` = `team-b` | yes |
| `bundle dafaed9fda622d0007ec01c439b957675fdac088ae75deba681f666d25f01719` | `sha256(team-b.json)` computed here, and `ana.imported_from.bundle_digest` | yes |
| `issued at 1788674359` | `team-b.json` → `claims.issued_at` | yes |
| `first pinned at 1788674358 on the exporting machine` | `team-b.json` → `claims.issuers.ana.pinned_at` — the exporter's moment, not the import moment | yes |
| the signer key `b0e1ae1a…6ebb4a2d` the stranger pinned by hand | `team-b.json` → `signed_by` | yes |

The receipt is derived from the record rather than written beside it: nothing in it disagrees with
the artifacts. Worth recording because it nearly read as a mismatch — the file digest of
`a-report.json` is `6f5dd402a0c37c1108eb8b3650b42d45f3f5ec2d04e4e8f3019c2caea063df39`, and that is
deliberately *not* what the verdict prints.

**The plan's `warrantor.exe`-by-hand wording:** the live run used `cargo run`, which builds and runs
the same binary the tests drive. Recorded as a deviation on the pre-rebase tip and unchanged by
either rebase.

## Both halves of `698b17a`'s claim, checked in the shipped output

Checked through the binary, not only in a library test, because the defect this task exists to
close was a *rendering* that was untrue of the record it did not read.

**Half one — an imported pin is distinguishable from one checked locally.** Three shipped renderings
distinguish them, and each was exercised through the real binary:

- `verify --issuer <name>`'s anchor line. Inherited: `INHERITED from a bundle signed by
  \`team-b\` … Nobody checked this key here`. Local: `pinned at <t> by whoever ran \`issuer add\`
  on this machine (trust on first use …)`. Both tests assert the **absence** of the other sentence
  as well as the presence of their own — `a_local_pin_reads_as_checked_here` fails if a local pin
  ever says `INHERITED`, and `a_stranger_verifies_…` fails if an inherited pin ever says `trust on
  first use`. A rendering that printed both, or neither, would not pass.
- `issuer list`'s `NOTE` column, which for an inherited pin reads `imported from a bundle signed by
  \`team-b\` (issued_by "team-b", at …); the exporter's own note was: video call`. The exporter's
  note is **replaced**, not appended: "checked on a video call" is true of the exporting machine and
  false here, and carrying it over unqualified is exactly how an inherited pin would come to read as
  a locally-checked one.
- `issuer import --apply`'s report, which names the bundle, names the signer it resolved **by key**,
  and says imports are not transitive.

On disk the distinction is structural rather than textual. In the live stranger's directory `ana`
carries an `imported_from` object — `signer_name` `team-b`, `issued_at` 1788674359, `bundle_digest`
`dafaed9f…` — and `team-b`, pinned by hand, has no such field.
`trust::PinnedIssuer::imported_from` is an `Option<ImportProvenance>` with `skip_serializing_if`, so
`None` is the shape a local pin has rather than a value that might be confused with an absent one,
and `a_directory_without_provenance_still_loads_and_its_pins_are_local` pins that a directory
written before the field existed still loads, reads local, and does not gain the field when saved.

**Half two — no verdict implies revocation was checked.** No arm mentions revocation as something
checked. What is printed is `Revocation is NOT established. A pin is a snapshot of a key somebody
checked at one moment; there is no revocation channel and there will not be one …`. It is one
`const` — `PIN_REVOCATION_LIMITATION` — rendered from one place, so the wording cannot drift between
arms. After `8c4d522`, **every** arm of `cmd_verify` that takes an anchor prints it when a pin was
the anchor: report, spend, stop and trust bundle through `print_anchor_limitations`; catalog and
conformance through `print_pin_revocation_limitation`. The effect-registry arm refuses and renders
no verdict at all. `issuer export` and `issuer import` say it too — at the moment the snapshot is
made, and at the moment it is taken on.

**The export-strips-provenance claim, checked by reading what export writes.** `bundle::export` maps
every pin through `PinnedIssuer { imported_from: None, ..pin.clone() }` **before** the claims are
signed, so the stripping happens inside the signed pre-image rather than after it: provenance is the
importer's record and the signed bytes never cover an unsigned claim. Confirmed three ways rather
than one — by reading `export`; by
`an_imported_pin_records_where_it_came_from_and_a_re_export_does_not_carry_it`, which re-exports a
directory holding an inherited pin and asserts the serialized wire string does not contain
`imported_from` at all; and on the live artifact, `team-b.json`, written by the real CLI, in which
the substring `imported_from` does not appear.

## Two corrections the rebase itself made necessary

**`8c4d522` — two anchored verdicts `main` added did not say what a pin cannot know.** Commit
`698b17a` asserts in its own subject that *every* anchored verdict states revocation is not
established, and on the tip it was written against that was true: `verify` had three arms and this
branch added a fourth, and all four printed it. Local `main` has since added two arms that accept
`--issuer` and check the signature against that pin — `verify_catalog_file` and
`verify_conformance_export` — and neither printed it. The rebase therefore made this branch's own
sentence false about the merged tree, which is the failure this repository has shipped three times:
a claim that was true when written and stopped being true underneath itself. Fixed by giving those
two arms the revocation sentence whenever a pin was the anchor. Deliberately **not**
`print_anchor_limitations`: those arms render no anchor line, and the catalog arm with no `--issuer`
falls back to this machine's own issuer key, so `NO_ANCHOR_LIMITATION`'s "nothing here says WHICH key
signed it" would be a false sentence there — and a limitation that is untrue is worse than one that
is missing. No test asserted the universal property, so nothing went red; the defect was found by
reading the commit's claim against the merged dispatch table.

**`8dbcfb8` — a duplicated doc line.** The commit that rewrote `anchor_line` left the old one-line
doc comment above the new three-clause one, so rustdoc rendered the sentence twice. Separated from
the fix above so a reviewer can see at a glance that it changes no output.

**A third red the rebase surfaced, now `main`'s to own.**
`rust/warrant/tests/instructions.rs::every_harness_the_registry_lists_can_be_shown` scraped
`warrantor agents list` for harness ids by taking the first word of every two-space-indented line.
Task 7.6 (`bef63b2`, on `main`) added an indented `COMPUTER USE:` paragraph to that listing, so the
scraper read `Computer` as a harness id, asked `agents show` for it, and the binary correctly refused
a name no registry holds:

```
thread 'every_harness_the_registry_lists_can_be_shown' panicked at warrant/tests/instructions.rs:288:9:
`agents list` names `Computer` and `agents show Computer` refuses it:
warrantor: no harness "Computer". `warrantor agents list` names them all.
```

**Established rather than assumed to be `main`'s:** `git diff main..HEAD` touched neither
`tests/instructions.rs` nor `cmd_agents_list` nor `rust/warrant/src/computer_use.rs`, so `agents
list`'s bytes on this branch were `main`'s bytes and the test failed on `main` alone. This lane fixed
it so the branch could be proved green on a tree that was not; `main` then landed its own fix
(`6f41384`) for the same defect, and this lane's commit was dropped in favor of it. Recorded because
the diagnosis is worth keeping even though the code is no longer this branch's: `main`'s message adds
the reason it merged at all — the post-merge gate on the 7.6 tree fail-fasted on the kill-drill flake
in another test binary and never reached this suite.

**One more red, which is `main`'s and is deliberately not fixed anywhere.** On the fourth rebase
`rust/warrant/tests/conformance_receipt.rs::a_drill_on_this_kernel_produces_a_receipt_that_verifies_offline`
failed with `root_gone: false, refusal: None` and both timings at `u64::MAX`. That is the finding
`main` records at `docs/task-evidence/finding-kill-drill-confirmation-under-load.md`: on Windows,
`process_exists` spawns `tasklist.exe` per poll, and on a box running four cargo trees the drill
cannot confirm the kill inside its ten-second deadline. `main`'s own decision is to leave it red
until the kill-switch existence rail stops enumerating, because the honest receipt under that load
says Advisory and weakening the assertion is the change this repository refuses by default. It is
not touched here. **The decision rule for this lane was fixed before the re-run rather than after:**
run the workspace suite once more, report both outcomes whatever they are, and treat the gate as
green only if the final complete run is green and the only red anywhere is that documented drill.
The re-run was green at 124 suites with 0 failures, and the earlier red is reported here rather than
quietly replaced.

## The honest tier of every bound this task touches

**No bound label moved and `bound_strengths()` is byte-identical** — `git diff main..HEAD` touches
neither `rust/warrant/src/lib.rs` nor `rust/warrant/src/report.rs`. What changed is the truthfulness
of verdicts, not the strength of any bound. The mechanisms the task does introduce, in the
vocabulary Task 0.4 fixed:

| mechanism | tier | what escapes it |
|---|---|---|
| the Ed25519 signature over a bundle's `claims` | **Enforced** — `bundle::parse` refuses cryptographically at the moment of attempt, and no amount of editing produces a passing bundle without the signing key | It binds *bytes to a key* and nothing more. It does not bind the key to a person, does not establish that the keys inside are the right keys, and cannot know the signing key was compromised after it was pinned. The verdict says all three out loud. |
| `issuer import` refusing a bundle whose signer is not pinned here | **Mediated** — an in-process refusal in this product's own code, resolving the signer by key against `trusted/issuers.json` | Anything that writes `trusted/issuers.json` directly, or runs `issuer add`, bypasses it entirely. The file sits under the same UID as the agent with no OS bound behind it: no netns, no seccomp, no ACL anywhere in this path. |
| `issuer export` refusing to mint an issuer key | **Mediated** — a refusal in `cmd_issuer_export`, which moved from `load_or_create_key` to `load_key` | `warrantor grant` still creates the key, and any caller can write `keys/issuer.key` by another route. What the refusal buys is that *looking* never mints. It is not a bound on key creation. |
| the inherited-pin sentence and the revocation sentence in a verdict | **Observed** — rendered at read time from `imported_from` and from the fact that an anchor was used | They report what the local record says. A hand-edited `trusted/issuers.json` with `imported_from` deleted makes an inherited pin render as locally checked, and nothing detects it: the directory is not signed. |

## What this task does NOT establish

- **It does not establish revocation, and does not try.** No verdict can tell whether a pinned key
  was compromised after it was pinned. The design refuses the channel that would say so, on the
  ground that a channel is a service and a service everyone consults sits above the signatures. The
  only remedy is local: `warrantor issuer remove <name>`.
- **It does not make the trust directory tamper-evident.** `trusted/issuers.json` is unsigned and
  writable by whatever runs as this user. Deleting an `imported_from` object turns an inherited pin
  into one that renders as locally checked; adding a pin by hand needs no bundle at all. Every claim
  about provenance is a claim about what the file says, not about how it came to say it.
- **It does not establish that the exporter checked anything.** `issued_by` is a label the exporter
  typed, printed as `(a label the exporter chose, not an identity)`. The authenticated part is the
  key that signed. An exporter who pinned carelessly exports that carelessness, and one out-of-band
  check buys all of it — the trade the design makes on purpose, not a gap in this implementation.
- **It does not distinguish an inherited pin on every surface that mentions a pin.** `verify`'s
  anchor line, `issuer list`'s note and `issuer import`'s report do. Two do not: the `issuer add`
  conflict message (`<name> is already pinned to <key> (pinned at <t>)`) and `issuer remove`'s
  confirmation both print the key and the moment without saying whether the pin was inherited.
  Neither *claims* local checking, so neither is false — but a reader who sees only those two cannot
  tell. Left alone deliberately: they are outside the task's verdict paths, and inventing the
  sentence in a lane whose job was the rebase would ship wording nobody had reviewed.
- **It puts no bound in front of anything an agent does.** Nothing here refuses an effect, an egress
  or a spend. It changes what a verifier is told about the key it verified with. An agent holding its
  own credential is untouched by every line of it.
- **It does not verify a bundle against anything outside the bundle.** A bundle is a snapshot: a key
  removed from the exporter's directory after export still travels in the file, and a stale bundle
  verifies exactly as well as a fresh one. `issued_at` is the only signal, and it is the exporter's
  clock.
- **`verify <bundle>` exits 0 for an intact bundle from a signer nobody here pinned.** That is the
  deliberate design the plan records — the exit code is the verifier's statement about the bytes, and
  the `signer NOT pinned here` line is the statement about trust. A caller reading only the exit code
  learns nothing about whether the file may be imported.
- **The receipt is one run on one machine.** Three stores under three `HOME`s on the same Windows
  box, not three machines and not an air-gapped one. "Offline" holds in the sense that nothing in
  the path opens a socket; it was not demonstrated by pulling a cable.

## Gates not run on this tip, and why

- `cargo build --workspace --all-targets` and `cargo metadata --locked` sit outside this lane's
  standard list but inside the plan's Step 7; both were run, and both are in the table above.
- `python tools/ci/check_phase_scope.py` — as recorded on the pre-rebase tip, this branch adds no
  plan task, and the gate lives on the main checkout.
- Nothing was skipped for want of disk. `disk_guard.py --require 80` and `--require-commit 5` ran
  before every cargo invocation. `--require-commit` refused twice across the two passes and was
  waited out, not worked around: no cache belonging to this or any other lane was deleted, and no
  process was killed.
