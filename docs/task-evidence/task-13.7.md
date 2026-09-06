# Task 13.7 — scorer/grader isolation and anti-gaming; reward-hacking monitor (L11-10, L11-12)

Branch `feat/scorer-isolation`, from local `main` at `f9c3523`. Measured on Windows 11, 2026-09-05.

## The premise correction, before anything else

The seed for this task said: *"the isolation this task needs may already exist in the repository and
be unreachable."* Both halves are wrong, and the code is the arbiter.

**`warrantor-eval-guard` performs no isolation.** Its own module documentation is the refutation
(`rust/eval-guard/src/lib.rs`, before this branch touched it): *"It does not perform the checks.
`run_preflight` takes `CheckResults` as an input: four booleans the caller has already decided … It
has no eBPF, opens no sockets, inspects no namespaces, and cannot observe the sandbox at all."* On
`main` the crate is two files, `lib.rs` and `cli.rs`. There is no `probes.rs`.

**And it was not unreachable — it was shipped, and by default it fabricated a pass.** "Orphaned" in
the wiring census means "not linked by the `warrantor` binary", which is narrower than "unreachable".
`eval-guard` is a released binary: `.github/workflows/release.yml:31` builds it and line 55 lists it
by name. Its CLI built `CheckResults::all_pass()` unconditionally and flipped one boolean only if
`--skip` was passed. So the crate the census called orphaned was the one artifact in this repository
that already published an unmeasured containment claim to a user.

Wiring it in as-is would have raised the census count by putting a signed falsehood on the product's
main path. The fabrication is fixed first, in commit 1; the wire follows.

## Boundary — the two neighboring tasks this one does not cover

1. **Task 5.3 owns the evidence-integrity adversary.** It attacks the receipt chain from inside the
   workload: forge, suppress, replay, race, spoof. This task never attacks the receipt graph. If the
   isolation record built here can be forged, that is 5.3's finding to produce and 5.3's
   `rust/warrant/tests/invariants/adversary/` to hold it. No adversary suite is added here.
2. **Task 14.10 owns the evaluating organization, and owns the receipt envelope.** 14.10 is the same
   argument one layer out: the evaluator's independence from us, and a pre-run conformance receipt
   signed by a key pinned out of band. This task stops at one process boundary on one machine and
   defines no receipt format. `scorer::Escalation` is a plain JSONL record until 14.10 lands, and
   `notary::SignatureEnvelope` is deliberately not reused for it — a third envelope shape would be
   the verification bug 14.10 warns about.
3. **Neither is this task the objective's validity (Task 8.5) nor the guard's accuracy (Task 12.4).**
   This task assumes the objective is correct and reports no recall or false-positive figure.

## Baseline, measured on this branch's base

```
144 test suites, 1507 passing, 0 failed, 20 ignored
wiring census: 12 of 40 crates reachable from warrantor-warrant over 20 path edges
invariant ratchet: ok (82 passing at floor 82, 15 recorded findings at ceiling 15)
invariant ledger: 12 invariants; enforced=2, orphaned=1, partial=8, unimplemented=1
```

## The shipped binary's two behaviors, before the fix

Both halves are recorded, because a report quoting only the refusal makes `eval-guard` look like a
control and a report quoting only the pass makes it look useless. Run on Windows, in no sandbox:

```
$ cargo run -q -p warrantor-eval-guard --bin eval-guard -- --agent scorer-under-test
passed_checks: ['network_isolation', 'filesystem_boundary', 'process_isolation', 'egress_attestation']
results: [True, True, True, True]
timestamp: 1788650811
sig_len: 64 vk_len: 32
fields: ['nonce', 'passed_checks', 'results', 'signature', 'timestamp', 'verifying_key']
exit 0

$ cargo run -q -p warrantor-eval-guard --bin eval-guard -- --agent scorer-under-test --skip network
eval-guard: pre-flight FAILED for agent 'scorer-under-test' — boundary check failed: NetworkIsolation
eval-guard: REFUSING to start the agent (invariant I-09: failure is safe).
exit 1
```

The refusal path is real and tested. The pass path is a signature over four booleans nobody
measured, and there was no field in the record that could have said so.

## After the fix

```
$ eval-guard --agent x
error: the following required arguments were not provided:
  --provenance <measured:<probe> | asserted:<who>>
exit 2

$ eval-guard --agent x --provenance asserted:operator:vj
eval-guard: refusing to sign anything. This crate performs no probes (see its module docs), so the
four boundary results can only come from the caller -- and it will not invent them. Pass
--assume-all-pass to declare, on the record and inside the signature, that you are asserting four
boundaries you did not measure here.
exit 2

$ eval-guard --agent x --provenance asserted:operator:vj --assume-all-pass
provenance: {'kind': 'asserted', 'by': 'operator:vj'}
results: [True, True, True, True]
eval-guard: this attestation is asserted by "operator:vj" -- nothing measured this boundary; a named
party asserted it and the signature covers the assertion, not the boundary
exit 0

$ eval-guard --agent x --provenance measured:netns-probe/1 --assume-all-pass --skip network
eval-guard: pre-flight FAILED for agent 'x' — boundary check failed: NetworkIsolation
eval-guard: REFUSING to start the agent (invariant I-09: failure is safe).
exit 1
```

`Provenance::Measured` is **not** a claim that the crate measured anything. It records that the
caller says a named probe produced the boolean. The crate opens no sockets, so it cannot tell a real
probe from an invented probe name; what changed is that the claim is attributed and non-omittable, so
a reviewer can go looking for `netns-probe/1` and find that it does not exist. That is weaker than
measurement and stronger than silence, and `Provenance`'s own doc comment says so.

## The tier table — which word each bound gets, and why not a stronger one

`crate::scorer::isolation` returns three properties. `strength` is `Option<BoundStrength>`, so a
property with no tier word is representable; `held_by` is `Os { mechanism } | OurCode | NothingYet`.

| Property | Tier | Held by | Why not stronger |
|---|---|---|---|
| `scorer_inputs_not_writable` (a confinement asserted, store outside the worktree) | **Enforced** | Operating system — `bwrap` binds `/` read-only with the worktree as the only read-write hole, so a write to `~/.warrantor/guard/*.jsonl` fails with `EROFS` at the syscall | Nothing stronger exists, but it is conditional twice over. This process **did not launch** the profile and cannot tell whether the operator did, so the tier is Enforced *given* a launched profile — an assertion, tagged `Provenance::Asserted`, never `Measured`. And it is about writes only: the read-only root leaves every one of those files readable. |
| `scorer_inputs_not_writable` (no confinement, **or** a store inside the worktree) | **Observed** | Warrantor | Nothing refuses the write as it happens: same UID is same UID. What is measured is thin and named as thin — a line edited badly enough not to parse is counted in `unreadable_lines`, and a deleted run file makes an unguarded run indistinguishable from a run that never happened. A careful edit is invisible. |
| `scorer_credentials_not_readable` | **no tier word at all** | **Nothing** | Not `Observed`. "Observed" implies something measures the read, and nothing in this repository looks at it, let alone refuses it. `--ro-bind / /` mounts `$HOME`, so `~/.warrantor/keys/settle.key` is readable to any process at this UID — a confinement profile included. Read-only is not unreadable. |
| `scorer_not_reachable_over_network` (empty egress allowlist, confinement asserted) | **Enforced** | Operating system — the profile emits `--unshare-net` | Holds only because the warrant grants **zero** hosts. A network namespace has no host allowlist, so `sandbox.rs` deliberately does not emit one when any host is permitted — emitting it would deny egress the warrant grants. Same launch caveat as above. |
| `scorer_not_reachable_over_network` (any host permitted, or no confinement) | **Mediated** | Warrantor | Held at the MCP proxy. `BoundStrength::Mediated.caveat()` verbatim: *"held only for calls that traverse the MCP proxy; a shell or a harness built-in reaches past it, and no netns, seccomp or firewall stands behind it."* |
| The reward-hacking monitor (`scorer::trend`, `scorer::escalate`) | **Observed** | Warrantor | It reads durable logs after the fact. Nothing in it refuses an action as it happens, nothing stops a run, and nothing quarantines a checkpoint (that is Task 12.6). L11-12's *"mandatory as a stop trigger"* is a duty on the human named in the escalation, and `ESCALATION_NOTE` says so on every record. |
| The threshold's before-the-run ordering | **Enforced, at our own boundary** — i.e. **Tier B/Mediated in the honest reading** | Warrantor | `trend_checked` refuses a threshold registered after the earliest run, and `register_threshold` refuses to replace an existing one. Both are refusals in our code at the moment of the attempt, so they are real; they are not host-enforced, and anyone with filesystem access deletes `scorer/threshold.json` and re-registers. `ArtifactClass::Scorer`'s deletion note says exactly that. |
| The anti-gaming label boundary (`corpus::rows_from` never writes a guard verdict into `label`) | **A convention in our code — Tier C** | Warrantor | It is a property of one function. Nothing outside it refuses a caller that sets `Row::label` directly, and `Row` is a public struct with public fields. It is now pinned by a test outside the corpus module, which is what makes the convention load-bearing rather than incidental — but a convention is what it is, and calling it a control would be the overclaim this task was told to avoid. |

**The sentence that ships with every rendered isolation record** (`scorer::ISOLATION_RECORD_CAVEAT`,
printed by `warrantor scorer` under the properties and the tier legend):

> This record states which party held each isolation property and by what mechanism. It does not
> establish that the sandbox was launched: no netns, seccomp or firewall is implemented here, the
> filesystem property is held by an operating system this process cannot interrogate, and the
> scorer's signing key remains readable to any process running as the same user.

## The pre-flight refuses on the product's own path, and that is the output

`scorer::preflight` maps `eval-guard`'s four boundary names onto this product's three facts. The
mapping is a documented table in the function's own rustdoc, and `property_behind` makes it a function
so a renderer can derive a refusal's explanation from it:

| `eval-guard` check | property |
|---|---|
| `NetworkIsolation` | `scorer_not_reachable_over_network` |
| `EgressAttestation` | `scorer_not_reachable_over_network` — the same fact; this product has one |
| `FilesystemBoundary` | `scorer_inputs_not_writable` |
| `ProcessIsolation` | `scorer_credentials_not_readable` |

The last arm is the least comfortable and is named as such in the code. Because that property is held
by nothing, **the best case this product can construct still fails the pre-flight**, and it fails
naming `ProcessIsolation`. Invariant I-09 says failure is safe; a pass here would be signing the gap.
The control in the same test hands `preflight` a hand-built all-`Enforced` set and gets a signature,
so it is a gate rather than a brick.

## Which of the two anti-gaming assertions was already true on `main`

Recorded honestly rather than presented as new:

* `a_guard_verdict_never_becomes_a_label_even_when_it_is_the_only_evidence` — **already true.**
  `corpus.rs` was written to hold it and its module doc names the trap. What this task adds is that
  the property is asserted from **outside** the corpus module, so a refactor filling `label` from
  `guard_said` goes red instead of silently training the next guard on this guard's misses.
* `a_principal_without_settle_scope_cannot_produce_the_state_that_becomes_a_label` — **already true**
  of `operators.rs`, and also pinned from outside for the first time. `Scope::Settle` and
  `Scope::Approve` were separated in §2.2; what was missing was any test connecting that separation
  to `corpus.rs`'s label derivation, which is the reason the separation matters here.

Neither is new mechanism. The new mechanism in this task is the eval-guard provenance, the
`scorer_credentials` disclosure, the wire, and the monitor.

## Orphan accounting

Read from `python tools/ci/wiring_census.py`, never computed:

```
before: wiring census: 12 of 40 crates reachable from warrantor-warrant over 20 path edges
after:  wiring census: 13 of 40 crates reachable from warrantor-warrant over 21 path edges
```

`warrantor-eval-guard` became reachable. **`warrantor-sandbox-runtime` stays orphaned on purpose**,
and the reason is written into `rust/warrant/Cargo.toml` beside the edge that was added, so the next
census reader does not "fix" it: linking it pulls `wasmtime = "=47.0.3"` with cranelift into a
manifest whose comments defend a minimal dependency posture crate by crate, in order to bound a
**WebAssembly guest** — while the grader in this product is a native process reading a JSONL file. It
is consulted as the *reference* for what an attempt-time refusal looks like
(`SandboxError::ImportDenied` at admission, `CAPABILITY_DENIED_MARKER` at the call itself) and it is
not linked. So the orphan count fell by one, not by two.

`cargo metadata --format-version 1 --locked` succeeds and `rust/Cargo.lock` gains **one line** — the
edge itself, inside `warrantor-warrant`'s dependency list, with no new `[[package]]` block.
`cargo tree -p warrantor-warrant -e normal` goes from 162 to 163 unique entries and the one new entry
is `warrantor-eval-guard`.

## Deviations from the plan

1. **The plan's Step 3 test would have passed on the unfixed code.** It compared the canonical signing
   bytes of two `run_preflight` calls; each call draws a fresh 16-byte nonce, so those differ
   unconditionally. The test pins nonce, results and timestamp instead and carries a determinism
   control, so the inequality is about the provenance rather than about randomness.
2. **`--assume-all-pass` is a second required flag the plan did not ask for.** `--provenance` alone
   would have let `--provenance asserted:me` restore the old behavior in one word. Naming who is
   speaking and declaring four unmeasured boundaries true are different acts, so they are different
   flags.
3. **`Property::strength` is `Option<BoundStrength>`, not `BoundStrength`.** The plan's `Produces`
   sketch had it non-optional; the plan's own **Bound strength** section requires
   `scorer_credentials_not_readable` to ship "with no tier word at all". The `Option` implements the
   normative half.
4. **`bound_strengths()` is NOT extended,** though the plan's `Files` list says it should be. It is
   the list of bounds a **warrant** carries, and `sandbox.rs`'s
   `every_bound_the_product_reports_is_spoken_about_by_every_profile` requires every entry in it to
   get a per-profile divergence. Adding scorer property names there would force every confinement
   profile to speak about them as though a warrant could grant them, and would move a tier by adding a
   name. A test pins `bound_strengths()` at seven entries and asserts `scorer_credentials` is not one.
5. **`Property::render` pads to 34 columns rather than calling `render_bound`.** `render_bound` pads
   to 24, and `scorer_credentials_not_readable` is 31 characters — the first live run printed
   `scorer_inputs_not_writableobserved`. The tier **word** still comes from `BoundStrength::word`, and
   a test asserts the two agree, so there is still one vocabulary.
6. **`retention::ALL_CLASSES` grows 20 → 21** with `ArtifactClass::Scorer`. The plan said to prefer
   appending beside an existing class; none fits. The threshold and the escalations are durable, and a
   store directory `warrantor holdings` does not count is one nobody prunes or answers for.
7. **Plan Steps 8 through 11 landed in one commit.** They cannot each stand alone:
   `tools/ci/check_invariants.py`'s `WARRANT_REACHABLE_CRATES` is what decides whether an `orphaned`
   ledger entry is a lie, so the wire, that constant, and I-09's status have to move together or one
   commit ships a ledger entry the check was written to catch.
8. **Cargo.lock changed by one line.** The plan expected none. It is the edge, not a version.
9. **`CARGO_TARGET_DIR` is on `C:`, not `M:`.** `M:` hit 100% full mid-run (`os error 112`, 2.1 GB
   free of 1.2 TB) and cargo failed to write fingerprints. Nothing was deleted to make room; the
   target directory moved. `M:/wt-w3-13.7/rust/target` from the first half of the run is still there.
10. **The plan's expected exit-gate numbers were measured against `origin/main` (`e4b5f10`, census
    9/39, ratchet 65/19).** This branch is from local `main` at `f9c3523`, where the baseline is census
    12/40 and ratchet 82/15. Every number here was re-derived from the tools on this branch rather
    than adjusted to match the plan.
11. **Two defects were found by running the command, not by testing the derivation** — the
    NetworkIsolation/ProcessIsolation prose mismatch and the unpadded name column. Both were Rule 2
    shaped: a sentence written beside a record rather than read out of it. `property_behind` and a
    totality test over `BoundaryCheck::ALL` are the mechanism now.

## What this task does NOT establish

* **It does not establish that any agent was contained.** Every `Enforced` here is conditional on a
  confinement profile that an operator asserts with `--confined` and that this process cannot verify
  was launched. There is no netns, no seccomp and no firewall anywhere in this repository. Containment
  composes with an external sandbox, and if that sandbox is not started, every property in this record
  degrades to `Observed` or worse while the record still says what the operator told it.
* **It does not stop a scored agent reading the scorer's signing key.** That is the finding, not the
  fix. `~/.warrantor/keys/settle.key` remains readable to any process at the same UID, inside a
  confinement profile as much as outside one. What changed is that the profile now *says so*.
* **It does not make `eval-guard` measure anything.** No probe was written. `run_preflight` still
  takes four booleans as an input and signs them; all that is new is that the record cannot omit who
  supplied them. `Provenance::Measured` is a caller's word about a probe this crate cannot see.
* **It does not establish that the escalated principal is independent.** `escalate` refuses to address
  an operator holding `Settle`, which is real, and the registry is a local JSON file whose tokens are
  stored as SHA-256. An operator token authenticates a **token**, not a person, and the file is on a
  filesystem the agent can read. `ESCALATION_NOTE` states this on every record.
* **It does not stop the run.** L11-12 asks for a checkpoint quarantine; that is Task 12.6. This task
  produces the escalation and says which half it produced.
* **It does not pin the threshold to an evaluation bill of materials.** `bom_digest` is `None`,
  because the digest-pinned BOM is Task 13.5 and does not exist. The field is empty rather than filled
  with something plausible.
* **The threshold's before-the-run ordering is enforced only against `warrantor`'s own reads.** Delete
  `scorer/threshold.json` and register a new one and the ordering check passes against whatever runs
  remain. Nothing signs the threshold and nothing anchors it.
* **The probing rate is a proxy and a coarse one.** It is durable refusals divided by recorded runs.
  It sees nothing an agent did that no bound refused, which is most of what a reward-hacking agent
  would do, and a warrant with refusals and no recorded run is reported at its raw refusal count.
  It has been tested against synthetic logs and has never been run against a real training trace.
* **No isolation property was verified on a Linux kernel by this task.** `sandbox.rs`'s bubblewrap
  claims were executed once, on one 6.18 kernel, in August; nothing in this task re-ran them, and
  nothing here has executed `bwrap` at all.
* **It reports no guard accuracy figure,** by design: that is Task 12.4's, carrying the 2026-08-30
  measurements.

## Gate output, verbatim, with exit codes

See the section below, which was captured last in a fresh detached worktree.

