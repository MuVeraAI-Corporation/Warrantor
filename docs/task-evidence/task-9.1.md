# Task 9.1 — Bounded revocation with a stated SLA (I-05, L6-04)

**Branch:** `feat/bounded-revocation` (from **local** `main` @ `f99af94`, not `origin/main` @ `e4b5f10`)
**Worktree:** `M:/wt-w2-9.1` · `CARGO_TARGET_DIR=M:/wt-w2-9.1-target`
**Date:** 2026-09-05

The plan's baselines were captured at `origin/main` (`9 of 39` crates, `65 passing / 19 ignored`).
This branch is based on local `main`, which carries four unpushed merges, so every baseline in this
file was re-measured here and differs from the plan's. Where a number differs, this file's is the
one that was measured.

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

`i01_active_identity.rs:151`'s second ignore **stays**: the CLI subject is still a compile-time
constant, and that is Task 3.1's.

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

```text
$ cargo fmt --all -- --check
FMT_CHECK=0

$ cargo clippy --all-targets -- -D warnings
CLIPPY=0

$ cargo test --workspace -j 2 > log 2>&1; echo $?
WORKSPACE_EXIT=0
  141 suites; 1460 passed; 0 failed; 20 ignored
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
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.74s

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
RESULT: PASS - 263 Markdown files, 58 RFCs, 81 catalogue rows, and all local links validated
EXIT=0
```

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
| workspace passing | 1435 | 1460 |
| workspace failed | 0 | 0 |
| workspace ignored | 23 | 20 |
| invariant corpus | 66 passing, 18 ignored | **69 passing, 15 ignored** |
| ratchet floor / ceiling | 66 / 18 | **69 / 15** |
| wiring census | 10 of 40 over 18 edges | **11 of 40 over 19 edges** |
| invariant ledger | enforced=2, orphaned=2, partial=7, unimplemented=1 | enforced=2, **orphaned=1, partial=8**, unimplemented=1 |
| `warrantor-warrant` normal-dep packages | 156 | **157** |

The 25 new passing tests are: 3 converted corpus findings, 8 unit tests in `revoke.rs`, 10 in
`tests/revocation.rs`, and 4 in `tests/revocation_latency.rs`.

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

```text
$ warrantor revoke --root <scratch> --svid spiffe://muveraai.com/agent/local
revoked   spiffe://muveraai.com/agent/local
  sequence           0
  durable at         1788636327 (epoch seconds)
  journal            <scratch>\revocations.jsonl
  measured latency   468.3µs to this process's first read
  adjudications in between  0 (verdicts this process computed between durability and that read)
  stated bound       5s -- inside it
  what this does:
    Every verdict THIS machine computes after the record above reached disk denies at gate
    Identity for that subject. The refusal is a chokepoint in `warrantor_notary::verdict`,
    not an operating-system bound.
  what it does NOT do:
    It does not recall a credential already used -- revocation bounds future use only. It
    does not reach a copy held by a third party, does not close a session already open, and
    does not terminate a process. It does not propagate to any other machine: this build
    links no fan-out, so the latency above is this process's, not a fleet's. The egress
    broker does not consult the revocation set at all. An agent that never asks for a
    verdict is never refused. The journal records WHEN a subject was revoked, not WHO
    revoked it: it is keyed by subject, and the per-warrant actor log is not.
```

Two runs measured 676.3µs and 468.3µs, both against a stated 5s bound, both with
`adjudications_between = 0`. A number this far inside its bound is not evidence that the bound is
tight; it is evidence that the bound is not the thing under strain on one machine. What the bound is
*for* is a case this build cannot produce, which is why the breach is exercised by injection
instead — see the tier table.

---

## Tier table: which word each bound gets, and why not a stronger one

| bound | word | why not stronger |
|---|---|---|
| A revoked subject is refused at the notary's Identity gate | **Mediated** (Tier B, chokepoint) | `warrantor_notary::verdict` returns `Deny { gate: Identity }` — a specific line of code refusing a specific request at the moment it is adjudicated, so it is not merely Observed. It is **not** `Enforced`: an agent that never asks for a verdict is never refused, and nothing here terminates a process, closes a socket, drops a connection, or invalidates a bearer token held elsewhere. There is no netns, seccomp or firewall anywhere in this repository. |
| Revocation propagates within 5 s (`IDENTITY_REVOCATION_SLA`) | **Observed** (Tier C) | Nothing in this build delivers a revocation record to a second process, let alone a second machine. The measurement is this process's own read of its own file. "Propagates to all replicas in <5s" is measured against exactly one replica. |
| Revocation survives a restart | **Observed** | The journal is `fsync`'d before a revocation is acknowledged and replayed at open, and a unit test drops and reopens the store. That is a property of the file, which nothing in this build refuses to delete or rewrite outside the process — an operator with filesystem access can truncate it, and `open` will then report a shorter set rather than refuse. |
| Non-revocation at a past epoch is provable from the log | **Observed** | It is a true reading of an append-only local file, and it is only as strong as that file. There is no anchor, no countersignature and no second copy: a reader is trusting one machine's journal, not a proof against tampering. |
| Egress-path revocation | **not claimed at all** | `egress::decide` takes a request and a destination catalog and no revocation input. This task does not give it one, and `evidence/revocation-latency.json` records the enforcement point as `consults_revocation: false` rather than omitting it. |

**No new `bound_strengths()` row.** Revocation is a property of the existing Identity gate, not a new
bound on the warrant, so the README bounds table and `tests/tier_disclosure.rs` are untouched.
Rendering the SLA for an operator is Task 11.10.

**No new trust root.** The revocation list is an append-only JSONL file under one warrant store root,
appended by an operator on this machine and read by this machine's adjudications. It is not a
directory, not a CA, and not an authority anyone else consults. It establishes: every verdict *this
process* computes after `sync_all` returns denies at gate Identity for that subject, and
non-revocation at any past epoch is answerable from the file alone.

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
as zeros a reader could mistake for measurements.

**No existing assertion was weakened anywhere in this task.** The three `#[ignore]` attributes were
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

2. **It does not establish that any real revocation has ever taken 468µs.** The two numbers in this
   file are from a warm scratch directory on one Windows box with nothing else contending for the
   disk. `p50`/`p99`/`samples` are deliberately absent from the evidence file rather than present as
   zeros. There is no distribution here — there is one sample, twice.

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

6. **It does not revoke an issued identity.** The subject is `DEFAULT_CLI_SUBJECT` /
   `DEFAULT_MCP_SUBJECT`, compile-time constants. Nothing issued them, nothing binds them to a
   workload, and revoking one revokes *every* local action, because they all present the same string.
   `i01_active_identity.rs:151`'s remaining `#[ignore]` is exactly this and is Task 3.1's.

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

---

## Files

Created:

- `rust/warrant/src/revoke.rs` — `RevocationStore`, `RevocationRecord`, `RevocationSource`,
  `RevocationLatency`, `measure`, `latency_evidence`, and 8 unit tests.
- `rust/warrant/tests/revocation.rs` — 10 tests: the refusal with its allowed control, the digest
  binding, one per `limitations()` arm, and three driving `warrantor revoke`.
- `rust/warrant/tests/revocation_latency.rs` — 4 tests: the in-SLA measurement, the injected breach
  with its in-budget control, the evidence record's own counts, and the file-versus-code gate.
- `evidence/revocation-latency.json` — format `warrantor.revocation-latency/1`, generated.
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
`README.md`, `docs/W1-delivery-gaps.md`.

---

## Handed on

- **Task 3.1** — an issued SVID instead of `DEFAULT_CLI_SUBJECT`, so a revocation names one agent
  rather than every local action.
- **Task 7.7** — `egress::decide` consulting the revocation set, which would make the second
  enforcement point in `evidence/revocation-latency.json` a real one.
- **Task 9.5** — cross-machine revocation, which is where "propagates to all replicas" stops being
  measured against one replica.
- **Task 11.10** — rendering the SLA to an operator.
- **Unclaimed by any task:** attribution on a revocation (deviation 6) and integrity protection for
  the journal (item 9 above). Both are gaps this task opens by shipping the surface, and neither is
  assigned.
