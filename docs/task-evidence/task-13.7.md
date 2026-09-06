# Task 13.7 — scorer/grader isolation and anti-gaming; reward-hacking monitor (L11-10, L11-12)

Branch `feat/scorer-isolation`, from local `main` at `f9c3523`. Measured on Windows 11, 2026-09-05; **corrected after adversarial review on 2026-09-06**, and
every number in this file re-measured at the corrected tip. The review and what it changed are the
next section. **Rebased onto `main` at `065961b` by the review lane on 2026-09-06; every
number re-measured on the rebased tree is in the last section of this file.**

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

## CORRECTION — the adversarial review refuted this branch, and eleven findings were reproduced

Two review lenses read this branch at `2ebf69b` and both set `refuted=true`; neither would have merged
it. The claim-honesty lens rated itself **high** severity, and it was right to: three of the four worst
findings were about what a record or a document *says*, and the worst of those was the tier word itself.

**Every one of the eleven was reproduced before anything was changed, with the reviewer's own command,
and none was disputed.** They are ten rows below rather than eleven because both lenses reported the
vacuous disclosure gate (CH-5 and TR-2 are one defect). Four were reproduced through the shipped binary
(CH-1 to CH-4), four through a deliberate mutation or probe of the committed code (CH-5/TR-2, TR-1,
TR-3, TR-4), and two by reading it (CH-6, TR-5). The reproductions ran in a detached worktree at
`2ebf69b` (`M:/wt-w6-13.7`), so what they measured was the committed branch and not a work tree.

Where a reviewer showed a label outrunning its mechanism, **the label changed** — never the mechanism's
description. Of the two false `Enforced` tiers, the filesystem one is now `Observed` held by warrantor
and the network one `Mediated`, each for the reason the record states. No test was weakened and none
deleted to earn a number anywhere in this pass.

| # | What was claimed | What was true, and what showed it | What changed |
|---|---|---|---|
| **CH-1** | `scorer_inputs_not_writable` reaches `Enforced`, `HeldBy::Os`, with a `bwrap` mechanism ending "fails with `EROFS` at the syscall", whenever `--confined` is passed and the store root is outside the worktree. | The mechanism is unreachable for the warrants it was printed over. `sandbox::check_worktree` refuses every worktree that is not an absolute POSIX path, so `warrantor sandbox` exits 1 on exactly the stores where `warrantor scorer --confined` printed `enforced`, and `cmd_scorer` never called that refusal. Reproduced: the scorer printed `enforced / held by operating system / bubblewrap binds ... EROFS at the syscall` and `warrantor sandbox <id> --root <same store>` exited 1 on the same warrant, on the platform this task was measured on. | `Enforced` now requires four facts, not two, and the second is the refusal `cmd_sandbox` already used. Anything less is `Observed` held by warrantor, and the record names the command that refuses the same path. Pinned by a unit test with a POSIX control and by a CLI test that measures the sandbox refusal in the same run rather than assuming it. |
| **CH-2** | `ISOLATION_RECORD_CAVEAT` is "the sentence that ships wherever an isolation record is rendered", and it states "the filesystem property is held by an operating system this process cannot interrogate". | It was a hardcoded literal printed under **every** record, including the default unconfined one whose own lines two rows above read `scorer_inputs_not_writable observed`, `held by warrantor`, and "nothing refuses a write to the guard and run logs as it happens". Reproduced verbatim from `warrantor scorer <id>`. Two of the three configurations contradicted the record they shipped with, in the reassuring direction. This is the Task 1.1 / Task 9.1 defect in the one sentence the module docs called centralized. | `scorer::isolation_caveat(&properties)` derives every holder clause from that property's own `HeldBy`. The only literal left, `ISOLATION_REPOSITORY_CAVEAT`, describes the source tree rather than the record. An absent property is reported as absent rather than skipped. |
| **CH-3** | The pre-flight is "reachable as `warrantor scorer <id>`, where it refuses — on the boundary standing for `scorer_credentials_not_readable`" (`docs/W1-delivery-gaps.md` I-09 row, and the CI-checked note in `evidence/invariants.json`). | The bare command refuses on `NetworkIsolation`. Unconfined, `scorer_not_reachable_over_network` is `Mediated` and `run_preflight` walks `BoundaryCheck::ALL` in order, so the network boundary fails first — a refusal on a property that IS held, at a weaker tier than the gate accepts. Reproduced: bare → `boundary check failed: NetworkIsolation`; `--confined` → `ProcessIsolation`. | Both records corrected to name the invocation each boundary belongs to, with the four-invocation table above. `the_bare_command_refuses_on_the_boundary_it_actually_refuses_on` pins both through the shipped binary. |
| **CH-4** | `Property::not_covered` is "what this property does NOT cover. Never empty — a tier word alone is read at full strength", rendered under a `NOT` label. | For the `Enforced` network property the field was built from `BoundStrength::Enforced.caveat()` — the tier legend's definition, not a caveat. Reproduced verbatim: `NOT      held by cryptography or the operating system; holds against an agent that tries to route around it And a namespace is all-or-nothing: ...`, i.e. the product's strongest guarantee under a `NOT` prefix, with the same text printed three lines below as the legend. | The field now says what a network namespace does not cover: sockets only, all-or-nothing, zero-host-conditional, and conditional on a profile this process did not launch. The `Mediated` arm's "or no confinement is in force" disjunction is likewise derived and named instead of offered as a guess. |
| **CH-5 / TR-2** | `the_isolation_caveat_names_the_three_things_that_are_not_implemented` keeps netns, seccomp, the firewall and the readable key in the shipped disclosure. | The assertion was `contains(fragment) \|\| contains("same user")` over a constant ending "readable to any process running as the same user", so the right disjunct was unconditionally true and every iteration passed whatever the sentence said. Reproduced by deleting "no netns, seccomp or firewall is implemented here, " from the shipped sentence: 41 suites, **844 passed, 0 failed**. | No `\|\|`. The gate runs over every record `isolation()` can produce, checks five fragments including "does not establish", and the deletion mutation now reds it. |
| **CH-6** | `Provenance::Asserted { by }` documents `by` as the field that exists to stop an anonymous assertion, and `scorer::preflight` is the product's call site. | `cmd_scorer` passed `format!("operator-at-cli:{id}")` — the id of the warrant being **graded**, which names no party. Read at `rust/warrant/src/bin/warrantor.rs:4431` on the committed branch. | `--confined` now requires `--asserted-by <name>`, resolved against the operator registry and refused when unknown; the unconfined path names the component and says in its own text that no party asserted anything. |
| **TR-1** | "`Property::render` pads to 34 columns … a test asserts the two agree" — the regression fix for the live `scorer_inputs_not_writableobserved` defect. | The test only ever rendered the 26-character name. Reproduced: `NAME_COLUMN` 34 → 33 and the rebuilt binary printed `scorer_not_reachable_over_networkmediated` — the exact shipped defect — with 41 suites and **844 passed, 0 failed**. The mutation-detecting boundary sat at column 27. | The test loops over all three names in all four renderings and asserts as arithmetic that the column clears the longest name, so 34 is derived rather than asserted. The 34 → 33 mutation now reds it. |
| **TR-3** | "`Enforced` … ONLY when a confinement is asserted AND the store root is outside the worktree; the code checks both". | The check is a lowercased string prefix over two paths of different kinds: `--root` is taken verbatim, `StoredWarrant::worktree` is absolute. A store the operator placed **inside** the worktree and named relatively was not a prefix of it, so the record reported `Enforced` / `HeldBy::Os` over a store sitting in the profile's one read-write hole. Reproduced with a probe asserting `Enforced` for store root `.warrantor/wrt_w1/store` against the absolute worktree: it passed on the committed code. | An uncomparable pair fails closed and the record says which path it could not place. `is_rooted` answers for the string rather than for the host, so the same record does not change tier between Windows and Linux. |
| **TR-4** | `a_principal_without_settle_scope_cannot_produce_the_state_that_becomes_a_label` — "pinned from outside for the first time", connecting scope separation to `corpus.rs`'s label derivation. | A tautology over its own fixture: it inserted the scopes it then asserted, and `Operator::allows` is `self.scopes.contains(&scope)`. It called no settle path, no `corpus` function and nothing in `serve`. Reproduced: mutating `serve::required_scope` so `"settle" \| "void"` maps to `None` left `scorer_isolation` at **14 passed, 0 failed** while five pre-existing tests in `identity.rs` went red. | Rewritten to drive the real `handle_scoped` handler with a minted approve-only token: 403, `WarrantState` unchanged, no label in `corpus::rows_from` — with the settle-scoped control that does produce `LabelSource::WarrantVoided`. The same mutation now reds it. |
| **TR-5** | "`ACCEPTED_FLAGS` gained `confined` and `register-threshold` … that test refuses a flag the usage text names and the parser does not accept, and it went red until the flags were real." | The gate compares the usage text against a hand-maintained constant — its own comment says so — so it goes green the moment a name joins the list, whether or not anything reads it. The flags *are* read, but that gate is not what establishes it, and `cmd_scorer` had no behavior test at all. Read from the test's own comment and confirmed by grep: no test outside `scorer_isolation.rs` names `scorer`. | The claim is corrected below. Four tests now read the real binary's output through `CARGO_BIN_EXE_warrantor`, covering the tier, the caveat, the boundary and the asserting party, each with a control. |

### The corrected record, verbatim

`warrantor scorer <id>` on this branch's tip, unconfined, against a store outside the worktree. The
two lines the review found contradicting each other are the tier line and the caveat, and they now
agree because the second is read out of the first:

```
$ warrantor scorer wrt_2571ce99ce033a49 --root M:/wt-w3-13.7/.warrantor-probe3
scorer isolation for wrt_2571ce99ce033a49
  store     M:/wt-w3-13.7/.warrantor-probe3
  worktree  M:\wt-w3-13.7\.warrantor\wrt_2571ce99ce033a49
  confined  no -- nothing is composed with

  scorer_inputs_not_writable        observed
    held by  warrantor
    NOT      no confinement is in force, so nothing refuses a write to the guard and run logs as it
             happens: same UID is same UID. ...
  scorer_credentials_not_readable   no tier -- held by nothing
  ...
This record states which party held each isolation property and by what mechanism. It does not
establish that any sandbox was launched: no netns, seccomp or firewall is implemented anywhere in this
repository, so every property above either composes with an external sandbox this process cannot
verify was started, or is held by nothing at all. On THIS record: the filesystem property is held by
warrantor, which means nothing refuses a write to the grader's inputs at the moment it happens: same
UID is same UID; and the scorer's signing key remains readable to any process running as the same
user.

pre-flight REFUSED - boundary check failed: NetworkIsolation
  eval-guard's NetworkIsolation stands for scorer_not_reachable_over_network in this record, and that
  property is mediated, held by warrantor.
    ... No network namespace is emitted here, and the scorer is reachable by anything that can open a
    socket, because no confinement is asserted at all.
  This is invariant I-09 firing on the product's own path rather than a wiring fault: the pre-flight
  passes only on Enforced, and this property carries a weaker tier, so passing here would sign a bound
  stronger than the one the record states.
...
EXIT 1: the record above printed in full and the pre-flight refused, so this command exits non-zero.
It exited 0 before, under a usage line calling this pre-flight fail-closed -- a wrapper that gated an
agent launch on it would have launched. A usage error exits 1 as well, so do not read the code as the
reason: read the REFUSED line. ...
exit 1
```

The same warrant with `--confined`, on this Windows worktree, is the finding CH-1 case. No line of it
says `enforced` or `operating system`, and it exits 1 either way: without `--asserted-by` because no
party is named, and with a registered operator on `NetworkIsolation` — **not** on the credential
boundary, because with no profile possible the network property is `Mediated` and is checked first.
That is the fourth row of the invocation table above, measured:

```
$ warrantor scorer wrt_2571ce99ce033a49 --root ... --confined
  confined  bubblewrap -- ASSERTED, but no profile this repository writes can name this worktree, so
            no property below is held by an operating system

  scorer_inputs_not_writable        observed
    held by  warrantor
    NOT      you asserted a bubblewrap profile, but no confinement this repository writes can name
             this worktree, so the operating-system mechanism that would hold this property cannot be
             installed by any command here: `warrantor sandbox M:\wt-w3-13.7\.warrantor\wrt_...`
             refuses the same path and exits 1. ...
  scorer_not_reachable_over_network mediated
...
warrantor: --confined asserts that a confinement profile is in force, and the pre-flight signs WHO
asserted it. Name a registered operator with --asserted-by <name> (`warrantor operator list`).
Refusing rather than naming the warrant being graded, which is what this printed before: the subject
of a grading is not a party to it, and a signature over four booleans whose source is unnamed is the
one case that attestation actively misleads.
exit 1
```

### Two defects of the same class, found by re-reading the corrected output

Neither is a review finding. Both are label-outruns-mechanism defects the review's own standard
catches, and both are in what the command *says* rather than in what it decides:

* **The record's first line claimed a composition the record denied.** `--confined` printed
  `confined  bubblewrap` immediately above properties saying no profile this repository writes can
  name this worktree and that nothing below is held by an operating system. The header is the line a
  reader takes first. It is now derived from the same `check_worktree` call, and reads either
  `bubblewrap -- ASSERTED by you; this process cannot check it` or `bubblewrap -- ASSERTED, but no
  profile this repository writes can name this worktree, so no property below is held by an operating
  system`. Both arms are asserted in the CLI test that already drove both.
* **A fail-closed pre-flight exited 0.** The command printed `pre-flight REFUSED` and returned
  success, under a usage line offering "a fail-closed pre-flight over them". A wrapper gating an agent
  launch on `warrantor scorer <id>` — which is what those words invite — would have launched the
  agent. It now exits 1, prints why, and says not to read the code as the reason because a usage error
  exits 1 too. Every invocation refuses today, and the usage text says so.

The second one is the more instructive: the refusal was *reachable as text and not as a status*, which
is the same reachability question the review asked about the `Enforced` tier, one layer out.

### The mutations that show the new gates can fail

Every fix above is a claim about a gate, so each was mutated after the fix and had to go red. Nine
mutations, nine reds. The first seven are mutations that were **green** on `2ebf69b`; the last two are
of the code this pass added:

| Mutation | Red |
|---|---|
| `NAME_COLUMN` 34 → 33 | `render_matches_the_shared_tier_vocabulary_and_leaves_a_gap_between_name_and_tier` |
| "no netns, seccomp or firewall is" deleted from `ISOLATION_REPOSITORY_CAVEAT` | `the_isolation_caveat_names_the_three_things_that_are_not_implemented` |
| `unprofilable` forced to `None` (the reachability condition removed) | `an_asserted_confinement_over_an_unprofilable_worktree_is_not_enforced`, and `the_scorer_command_refuses_enforced_for_a_worktree_the_sandbox_command_also_refuses` at the CLI |
| `comparable` forced to `true` | `a_store_root_that_cannot_be_placed_relative_to_the_worktree_is_not_enforced` |
| `asserted_by`'s registry lookup skipped | `the_asserting_party_must_be_a_registered_operator_and_is_never_the_graded_warrant`, and `the_preflight_refuses_to_name_the_graded_warrant_as_the_party_that_asserted_the_confinement` at the CLI |
| `isolation_caveat`'s `HeldBy::OurCode` clause returns the `Os` clause | `the_shipped_caveat_names_the_holder_the_record_names_and_never_a_stronger_one`, and `the_rendered_caveat_names_the_holder_the_rendered_record_names` at the CLI |
| `serve::required_scope`: `"settle" \| "void" => None` | `a_principal_without_settle_scope_cannot_produce_the_state_that_becomes_a_label` — the test that stayed green under this exact mutation before |
| the `confined` header's qualifier stops reading `check_worktree` | `the_scorer_command_refuses_enforced_for_a_worktree_the_sandbox_command_also_refuses` |
| the pre-flight refusal returns `ExitCode::SUCCESS` again | `a_refused_preflight_exits_non_zero_and_still_prints_the_whole_record` |

All mutations were reverted; the numbers below are from the reverted tree.

### What the correction pass did NOT do

* **It did not make anything measure containment.** `Enforced` is still an operator's assertion about a
  kernel. What changed is that the assertion can no longer be made about a kernel no command here can
  configure, and that the party making it has a name in the registry. No netns, seccomp or firewall was
  added; none exists in this repository.
* **It did not verify a single property on a Linux kernel.** Both `Enforced` arms remain conditional on
  a profile this process did not launch, and nothing in this pass executed `bwrap`.
* **It did not close the credential gap.** `~/.warrantor/keys/settle.key` is still readable at the same
  UID, which is why the pre-flight still refuses.
* **It did not re-audit the seven findings the claim-honesty lens explicitly cleared** — the provenance
  binding, the two CLI refusals, `preflight`'s `enforced()` reading the record, the sandbox `Gap`, and
  the census and ledger numbers. Those were checked by the reviewer and left alone.

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
| `scorer_inputs_not_writable` (a confinement asserted, a profile for this worktree is one `sandbox.rs` will write, and the store root is placeable outside it) | **Enforced** | Operating system — `bwrap` binds `/` read-only with the worktree as the only read-write hole, so a write to `~/.warrantor/guard/*.jsonl` fails with `EROFS` at the syscall | Nothing stronger exists, but it is conditional twice over. This process **did not launch** the profile and cannot tell whether the operator did, so the tier is Enforced *given* a launched profile — an assertion, tagged `Provenance::Asserted`, never `Measured`. And it is about writes only: the read-only root leaves every one of those files readable. |
| `scorer_inputs_not_writable` (no confinement, **or** a worktree no confinement here will name, **or** a store root that cannot be placed relative to the worktree, **or** a store inside it) | **Observed** | Warrantor | Nothing refuses the write as it happens: same UID is same UID. What is measured is thin and named as thin — a line edited badly enough not to parse is counted in `unreadable_lines`, and a deleted run file makes an unguarded run indistinguishable from a run that never happened. A careful edit is invisible. |
| `scorer_credentials_not_readable` | **no tier word at all** | **Nothing** | Not `Observed`. "Observed" implies something measures the read, and nothing in this repository looks at it, let alone refuses it. `--ro-bind / /` mounts `$HOME`, so `~/.warrantor/keys/settle.key` is readable to any process at this UID — a confinement profile included. Read-only is not unreadable. |
| `scorer_not_reachable_over_network` (empty egress allowlist, confinement asserted, profile writable for this worktree) | **Enforced** | Operating system — the profile emits `--unshare-net` | Holds only because the warrant grants **zero** hosts. A network namespace has no host allowlist, so `sandbox.rs` deliberately does not emit one when any host is permitted — emitting it would deny egress the warrant grants. Same launch caveat as above. |
| `scorer_not_reachable_over_network` (any host permitted, or no confinement, or a worktree no profile here can name) | **Mediated** | Warrantor | Held at the MCP proxy. `BoundStrength::Mediated.caveat()` verbatim: *"held only for calls that traverse the MCP proxy; a shell or a harness built-in reaches past it, and no netns, seccomp or firewall stands behind it."* |
| The reward-hacking monitor (`scorer::trend`, `scorer::escalate`) | **Observed** | Warrantor | It reads durable logs after the fact. Nothing in it refuses an action as it happens, nothing stops a run, and nothing quarantines a checkpoint (that is Task 12.6). L11-12's *"mandatory as a stop trigger"* is a duty on the human named in the escalation, and `ESCALATION_NOTE` says so on every record. |
| The threshold's before-the-run ordering | **Enforced, at our own boundary** — i.e. **Tier B/Mediated in the honest reading** | Warrantor | `trend_checked` refuses a threshold registered after the earliest run, and `register_threshold` refuses to replace an existing one. Both are refusals in our code at the moment of the attempt, so they are real; they are not host-enforced, and anyone with filesystem access deletes `scorer/threshold.json` and re-registers. `ArtifactClass::Scorer`'s deletion note says exactly that. |
| The anti-gaming label boundary (`corpus::rows_from` never writes a guard verdict into `label`) | **A convention in our code — Tier C** | Warrantor | It is a property of one function. Nothing outside it refuses a caller that sets `Row::label` directly, and `Row` is a public struct with public fields. It is now pinned by a test outside the corpus module, which is what makes the convention load-bearing rather than incidental — but a convention is what it is, and calling it a control would be the overclaim this task was told to avoid. |

**The sentence that ships with every rendered isolation record** (`scorer::isolation_caveat`,
printed by `warrantor scorer` under the properties and the tier legend). It was a constant and is now
DERIVED from the record it ships with; see the correction below for why. Verbatim from
`warrantor scorer <id>` with no flags, at this branch's final commit:

> This record states which party held each isolation property and by what mechanism. It does not
> establish that any sandbox was launched: no netns, seccomp or firewall is implemented anywhere in
> this repository, so every property above either composes with an external sandbox this process cannot
> verify was started, or is held by nothing at all. On THIS record: the filesystem property is held by
> warrantor, which means nothing refuses a write to the grader's inputs at the moment it happens: same
> UID is same UID; and the scorer's signing key remains readable to any process running as the same
> user.

The clause after "On THIS record" is read out of each property's own `HeldBy`. Under `--confined` on a
worktree a profile can name, the same position reads *"the filesystem property is held by an operating
system this process cannot interrogate"* — because there the record says it is.

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

**Which boundary a given invocation refuses on — the sentence this file got right and two other records
got wrong.** `run_preflight` walks `BoundaryCheck::ALL` in order and stops at the first failure, so the
boundary a user sees depends on the invocation:

| invocation | boundary that fails | why |
|---|---|---|
| `warrantor scorer <id>` | `NetworkIsolation` | unconfined, `scorer_not_reachable_over_network` is `Mediated`, and it is checked first. The property IS held — at a weaker tier than the pre-flight accepts. |
| `warrantor scorer <id> --confined --asserted-by <operator>`, zero egress hosts, store outside a worktree a profile can name | `ProcessIsolation` | the credential property is held by nothing at any tier. This is the case above. |
| the same with any egress host granted | `NetworkIsolation` | the namespace is deliberately not emitted. |
| the same on a worktree no confinement here will name | `NetworkIsolation` | no profile exists, so neither the bind nor the namespace does. |

`docs/W1-delivery-gaps.md`'s I-09 row and `evidence/invariants.json`'s I-09 note both asserted the
credential boundary of the *bare* command. Both are corrected, and
`the_bare_command_refuses_on_the_boundary_it_actually_refuses_on` now pins both invocations through the
shipped binary.

## Which of the two anti-gaming assertions was already true on `main`

Recorded honestly rather than presented as new:

* `a_guard_verdict_never_becomes_a_label_even_when_it_is_the_only_evidence` — **already true.**
  `corpus.rs` was written to hold it and its module doc names the trap. What this task adds is that
  the property is asserted from **outside** the corpus module, so a refactor filling `label` from
  `guard_said` goes red instead of silently training the next guard on this guard's misses.
* `a_principal_without_settle_scope_cannot_produce_the_state_that_becomes_a_label` — **already true**
  of `operators.rs`. `Scope::Settle` and `Scope::Approve` were separated in §2.2; what was missing was
  any test connecting that separation to `corpus.rs`'s label derivation, which is the reason the
  separation matters here. **Corrected after review: the first version of this test made that
  connection nowhere.** It built its own registry and asserted a set membership over scopes it had
  inserted itself — `Operator::allows` is `self.scopes.contains(&scope)` — touching no settle path, no
  `corpus` function and nothing in `serve`. It now drives the real HTTP handler (`handle_scoped`) with a
  minted approve-only token, asserts 403 and an unchanged `WarrantState`, reads `corpus::rows_from`
  afterward to show no label appeared, and carries the settle-scoped control that does produce
  `LabelSource::WarrantVoided`. Mutating `serve::required_scope` to drop `Scope::Settle` reds it.

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
   to 24, and the longest of the three names, `scorer_not_reachable_over_network`, is 33 characters —
   the first live run printed `scorer_inputs_not_writableobserved`. The tier **word** still comes from
   `BoundStrength::word`, and a test asserts the two agree, so there is still one vocabulary.
   **Corrected after review:** the regression test only ever rendered the 26-character name, so
   `NAME_COLUMN` could be cut to 33 and the shipped defect returned for the 33-character name with the
   whole package green. It now loops over all three names and asserts `NAME_COLUMN` exceeds the longest;
   the 34 → 33 mutation reds it.
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

**Re-captured at the corrected tip.** The run below is from a **fresh detached worktree** at
`M:/wt-g6-13.7`, created with `git worktree add --detach M:/wt-g6-13.7 feat/scorer-isolation` after the
correction commits, and every number in this document is that run's. The pre-correction run at
`b4873d4` / `2ebf69b` gave 145 / 1534 / 0 / 19 with the same census, ratchet and ledger lines; the
review reproduced it independently at `M:/wt-v3-13.7-test-rigor`, to the digit. This is the check that
caught the worst defect of the previous wave: a `.gitignore`-excluded evidence file that `git add`
skipped silently, leaving the implementer green and the branch red for everyone else.

```
$ git status --porcelain
                                        # empty
$ git ls-files <every path a test opens>
README.md
docs/W1-delivery-gaps.md
docs/task-evidence/task-13.7.md
docs/task-evidence/task-5.3.md
evidence/invariants.json
evidence/wiring-coverage.json
rust/eval-guard/src/cli.rs
rust/eval-guard/src/lib.rs
rust/warrant/Cargo.toml
rust/warrant/src/scorer.rs
rust/warrant/tests/scorer_isolation.rs
tools/ci/invariant-ratchet.json
                                        # all twelve TRACKED
$ git check-ignore -v <the same twelve>
CHECK_IGNORE=1                          # exit 1 = no ignore rule matched any of them
    # the re-run at this tip checked SEVENTEEN: the twelve plus src/bin/warrantor.rs, src/sandbox.rs,
    # src/serve.rs, tests/instructions.rs and tests/invariants/i09_failure_is_safe.rs, which the
    # correction pass reads or writes. `git ls-files` returned 17 of 17 and check-ignore matched none.

$ cd rust && cargo fmt --check
FMT=0
$ cargo clippy --all-targets -- -D warnings > cl.log 2>&1
CLIPPY=0
$ cargo test --workspace -j 2 > ws.log 2>&1
CARGO=0
    # 145 suites: passed=1545 failed=0 ignored=19
    # (base was 144 / 1507 / 0 / 20 -- one new suite, +38 passing, one ignore converted;
    #  1534 of those before the correction pass, +11 from its gates)

$ cd .. && python tools/ci/wiring_census.py
wiring census: 13 of 40 crates reachable from warrantor-warrant over 21 path edges
CENSUS=0
$ python tools/ci/check_invariant_ratchet.py
invariant ratchet: ok (83 passing at floor 83, 14 recorded findings at ceiling 14)
RATCHET=0
$ python tools/ci/check_invariants.py
invariant ledger: 12 invariants; enforced=2, orphaned=0, partial=9, unimplemented=1
LEDGER=0
$ python tools/ci/check_us_english.py main
us-english: 4102 added line(s) across 16 file(s), since main; matcher = vendored verify-us-english.mjs
us-english: ok
USEN=0
    # this gate diffs `main...HEAD` -- COMMITTED content -- and the count includes this document, so a
    # number read from a dirty tree understates: this line first said 3890, measured before the docs
    # commit. `ok` is the load-bearing half; it was NOT ok at first (two 'afterwards', now 'afterward').
$ python tools/ci/check_docs.py
RESULT: PASS - 267 Markdown files, 58 RFCs, 81 catalogue rows, and all local links validated
DOCS=0

$ python -m pytest tools/ci/test_wiring_census.py tools/ci/test_check_invariants.py \
                   tools/ci/test_check_us_english.py -q -p no:cacheprovider
28 passed in 31.83s
$ python -m ruff check tools/ci/
All checks passed!
```

`orphaned=0` in the ledger line is the one number worth pausing on: I-09 was the last `orphaned`
entry, and it moved to `partial`, not to `enforced`. The gap text says why in as many words.

**One environmental failure, recorded rather than hidden.** The first `cargo test --workspace -j 2` in
the fresh worktree died with `rustc-LLVM ERROR: out of memory` / `STATUS_STACK_BUFFER_OVERRUN` while
compiling `warrantor-warrant`. It is a host resource failure, not a code failure — the same class as
this box's recorded fork-exhaustion hazard — and the retry at `-j 1` is the run above. Nothing was
changed between the two runs.

## Red-before-green, and two mutation checks

Four assertions were seen failing for the right reason before the code that satisfies them existed:

```
tests::a_measured_pass_and_an_asserted_pass_do_not_produce_the_same_signed_bytes ... FAILED
  left:  [1,0,0,0, 2,0,0,0, 3,0,0,0, 4,0,0,0, 7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, 1,1,1,1, 0,241,83,101,0,0,0,0]
  right: [1,0,0,0, 2,0,0,0, 3,0,0,0, 4,0,0,0, 7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, 1,1,1,1, 0,241,83,101,0,0,0,0]
  # byte-identical: the provenance was not in the signed bytes at all

tests::an_attestation_relabelled_as_a_different_source_no_longer_verifies ... FAILED
  # the relabelled attestation still verified

the_profile_leaves_the_settle_key_readable_and_must_name_that_gap ... FAILED
  # the seven divergences the profile emitted were write_paths, egress_hosts, tools,
  # staged_classes, budget_cents_observed, delegation_depth, expires_at -- none about the store

adversary::the_documents_ordinal_for_the_next_ignore_is_read_from_the_ratchet_and_not_from_the_plan ... FAILED
  # the ceiling had moved 15 -> 14 and both gated sentences still said 15/16
```

The Step 10 monitor tests were written after the module rather than before it, which is a departure
from test-first and is recorded as such. To show they have teeth, two deliberate mutations were driven
against the finished code and each produced exactly one red test:

| Mutation | Result |
|---|---|
| `escalate` finds any operator holding `Stop`, dropping `&& !allows(Settle)` | `an_escalation_is_addressed_to_an_operator_who_cannot_settle_the_warrant_being_graded` FAILED — `left: "releaser"`, `right: "env-owner"`. The registry deliberately lists a `releaser` holding **both** `Stop` and `Settle` **first**, which is what gives the assertion teeth. |
| `trend_checked`'s ordering comparison disabled | `a_threshold_registered_after_the_first_run_is_refused` FAILED — returned `Ok(ProbingTrend { … registered_at: 1786000100 })` where `Err(ThresholdRegisteredAfterTheRun { run_at: 1786000000, … })` was required. |

Both mutations were reverted; the run above is the reverted tree.

**Nine further mutations** — one per gate the correction pass added or repaired — are in the
CORRECTION section's own table above.

## The base moved under this branch, and every number here is against `f9c3523`

*Superseded on 2026-09-06: the review lane rebased this branch onto `main` at `065961b`, and the
numbers against the merged tree are in the last section of this file. The paragraph below is left as
the branch wrote it, because it says what was true at the time and why it mattered.*

`main` was at `f9c3523` when this branch was cut and is at `2ec0638` now: two further merges landed
from another lane while this work ran (Task 1.2 `feat/egress-capability-catalog`, Task 1.3
`feat/task-1.3`). This branch is **not** rebased onto them, and `git merge-base main HEAD` is still
`f9c3523`.

So every measurement in this document — 145 suites / **1545** passing / 19 ignored, census 13 of 40
over 21 edges, ratchet 83/14 — is against `f9c3523`, and none of it is evidence about the merge. (1534
before the correction pass; the eleven new tests are the findings' gates, the record's own header and
the exit code. The suite count, the ignore count, the census and the ratchet did not move: the
correction touched no crate boundary and no invariant-corpus file.) That
distinction is not pedantic here: this project has already had five green branches batch-merged and
break `main` five ways, because PR CI tests *branch plus old main*. The two landed merges touch
`rust/warrant/src/stop.rs`, `src/report.rs`, `src/serve.rs`, `tests/instructions.rs` and the invariant
corpus, and `tests/instructions.rs` and the ratchet counters are both files this branch also changes.

**Whoever merges must rebase onto the current `main`, re-derive `passing_floor` and `ignored_ceiling`
from the merged corpus's own `test result:` line rather than from this document, and re-run the census
before believing 13.** The one number that should be stable across the rebase is the direction: the
orphan count fell by one, and `warrantor-sandbox-runtime` is still an orphan on purpose.

## No existing assertion was weakened

The one test that changed status is the I-09 finding, and its assertion is byte-identical to the
ignored form: `manifest.contains("warrantor-eval-guard")`. Three assertions were **added** beside it.
`tests/instructions.rs::ACCEPTED_FLAGS` gained `confined` and `register-threshold`, and
`--asserted-by` in this pass. **Corrected after review (TR-5): that gate does not establish that the
parser accepts anything.** It compares the usage text against a hand-maintained constant — its own
comment says "listed rather than derived because this binary's parser is a hand-written map" — so it
goes green the moment a name joins the list, whether or not any code reads the flag. It went red only
because the usage text named a flag the list did not. The flags are in fact read (`args.flags` in
`cmd_scorer`), and what establishes that is the four behavior tests over the real binary added in this
pass, not that gate.

---

## Rebased onto `main` at `065961b` — the review lane, 2026-09-06

Everything above this line was measured on the branch against its own base. This section is the
review lane's record: the branch brought onto today's `main`, every number below re-measured on the
rebased tree, and the plan's exit gate run verbatim rather than inferred from the
workspace gate. Worktree `M:/wt-w3-13.7`, shared target directory `M:/wt-review-shared-target`.

`main` moved four times while this lane ran (`92b6018` → `775bfeb` → `9bac709` → `9292b03` → `065961b`;
the second move brought the implementation plan itself onto `main` at `docs/superpowers/plans/`, the
third is four docs/CI commits and the fourth a US-English sweep over thirty-two documents, none touching
a Rust file), so the rebase was done four times and the last is the one recorded here.
`git merge-base HEAD main` is `065961b`. The cargo gate below was run at `53c3d72`, the
tip after the second rebase; `git diff 53c3d72 HEAD -- rust/` is empty, so its inputs are byte-identical
to this tip, and the Python gates were re-run at this tip.

### Commits, rebased, in plan-step order

| commit | plan steps | what |
|---|---|---|
| `7c6a603` | 3–4 | `eval-guard` refuses to sign four booleans whose source is unnamed (`Provenance` in the signed bytes) |
| `4fcc92e` | 6 | `sandbox.rs` names the credential a read-only root leaves in reach (`Divergence::Gap` for the store) |
| `ebf1de2` | 5, 7–11 | the wire, `scorer::{isolation, preflight, trend, escalate}`, the I-09 conversion, ratchet 83/14, ledger I-09 `partial` |
| `94de02a` | 12 | evidence: the tier table, the deviations, what is not established |
| `7c6b776` | 12 | evidence: the fresh-worktree gate, red-before-green, two mutation checks |
| `ecfe996` | review | `Enforced` requires a profile `sandbox::check_worktree` accepts and a placeable store root (CH-1, TR-3) |
| `6a00b4e` | review | `--confined` requires `--asserted-by`, resolved against the operator registry (CH-6) |
| `1c1a8b7` | review | four CLI tests through the shipped binary; the scope test drives `handle_scoped` (TR-4, TR-5) |
| `7c38c38` | review | the record's `confined` header is derived from the same `check_worktree` call |
| `522cacc` | review | a refused pre-flight exits 1 |
| `d6474ed` | review | evidence: the eleven findings and the re-measured numbers |
| `5e5b220` | review | evidence: the us-english count re-measured from a committed tree |
| `60d6159` | review | evidence: the fresh-worktree check covered seventeen paths |
| (this file) | this lane | this section |

The SHAs above are the post-rebase ones; the pre-rebase SHAs quoted earlier in this document
(`b75c194`, `2ebf69b`, `b4873d4`, `7b624d3` …) name the same changes on the branch's original base.

### The exit gate, quoted verbatim from the plan

`### Task 13.7`, `#### Exit gate` (on `main` at `docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md`, byte-identical to the copy at `M:/wt-wave3`):

> `cargo test -p warrantor-warrant --test scorer_isolation --test invariants -j 2 && python tools/ci/wiring_census.py && python tools/ci/check_invariant_ratchet.py`
> must print three things together: every isolation test passing **with its allowed control also
> passing**, `wiring census: 10 of 39 crates reachable`, and `invariant ratchet: ok (66 passing at
> floor 66, 18 recorded findings at ceiling 18)` — and `cargo run -p warrantor-eval-guard --bin
> eval-guard -- --agent x` must exit non-zero with no attestation on stdout, because a caller who
> names no provenance can no longer be handed a signature.

The plan's own Step 1 says what to do with its literal numbers: *"If the census prints anything but
9, another lane has landed a wire and Step 8's expected numbers move by that much — re-derive them,
do not adjust the assertion to match."* The numbers below are re-derived from the tools on the
rebased tree; `10 of 39` and `66/18` were the plan's expectation against `origin/main` at `e4b5f10`.

### Status of that acceptance: RUN

Nothing on the branch performs the exit gate as one run: the workspace test gate subsumes the two
test targets, and no test drives the `eval-guard` binary with `--agent x` (the only binary-driving
tests, `rust/warrant/tests/scorer_isolation.rs:788`, drive `warrantor`). The transcript earlier in
this document under "After the fix" was the implementer's manual run on the branch's own base. So
this lane ran the exit gate verbatim on the rebased tree, each exit code captured before any pipe.
The transcript is in this section, below, and the raw logs are the lane's scratch output
(`gate-out3/`, `acceptance-out/`), which is not tracked.

**Clause 1 — the three commands together:**

```
$ cd rust && cargo test -p warrantor-warrant --test scorer_isolation --test invariants -j 2
Running tests\invariants\main.rs (M:/wt-review-shared-target\debug\deps\invariants-034918dab9d3a6da.exe)
test result: ok. 83 passed; 0 failed; 14 ignored; 0 measured; 0 filtered out; finished in 1.05s
Running tests\scorer_isolation.rs (M:/wt-review-shared-target\debug\deps\scorer_isolation-83bd63c0f79b2b58.exe)
test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.21s
exit 0
$ python ../tools/ci/wiring_census.py
wiring census: 14 of 41 crates reachable from warrantor-warrant over 23 path edges
exit 0
$ cd .. && python tools/ci/check_invariant_ratchet.py
(first run, exit 1) ValueError: cargo test produced no `test result:` line; the corpus did not run
    # raised by the tool before it printed the corpus output, 90 s into a window in which clause 2 below
    # was `Blocking waiting for file lock on build directory` -- another lane was building into the shared
    # target directory. Re-run under the same guard after freshening this tree's sources:
$ python tools/ci/check_invariant_ratchet.py
test result: ok. 83 passed; 0 failed; 14 ignored; 0 measured; 0 filtered out; finished in 0.91s
invariant ratchet: ok (83 passing at floor 83, 14 recorded findings at ceiling 14)
exit 0 (re-run; the first attempt is recorded above)
```

Every isolation test passes with its allowed control. The controls are assertions inside the same
test or the test written beside it: `with_no_confinement_nothing_is_enforced_and_one_property_is_held_by_nothing`
is the unconfined control the plan's Step 9 sketch names for
`every_property_carries_a_caveat_and_only_an_os_mechanism_earns_enforced`; `an_escalation_is_addressed_to_an_operator_who_cannot_settle_the_warrant_being_graded`
holds the only-settler refusal; `a_principal_without_settle_scope_cannot_produce_the_state_that_becomes_a_label`
holds the settle-scoped control that does produce `LabelSource::WarrantVoided`; the four CLI tests
each drive the shipped `warrantor` with a passing and a refusing invocation.

**Clause 2 — a caller who names no provenance is handed no signature:**

```
$ cd rust && cargo run -p warrantor-eval-guard --bin eval-guard -- --agent x
stdout: 0 bytes
stderr:
Blocking waiting for file lock on build directory
error: the following required arguments were not provided:
  --provenance <measured:<probe> | asserted:<who>>

Usage: eval-guard.exe --agent <AGENT> --provenance <measured:<probe> | asserted:<who>>

For more information, try '--help'.
error: process didn't exit successfully: `M:/wt-review-shared-target\debug\eval-guard.exe --agent x` (exit code: 2)
exit 2
```

Exit 2 is `clap`'s usage-error code: the binary refuses at argument parsing because
`--provenance` is required, which is stronger than the plan asked for (it asked for non-zero) and is
the reason nothing reaches stdout. The ledger may cite Task 13.7 as built on the strength of this
run; what it may not cite is anything the tier table says it does not establish.

### What the rebase changed, and how each conflict was resolved

Two files conflicted, both census artifacts, both resolved the same way: take `main`'s copy, then
let the tool re-measure. Nothing was picked.

* **`evidence/wiring-coverage.json`.** `main` recorded `13 of 41 over 22 edges` (a crate landed on
  `main` after this branch was cut, and one more wire); the branch recorded `13 of 40 over 21`
  against its own base. `python ../tools/ci/wiring_census.py --write` on the merged manifests
  wrote **`14 of 41 crates reachable from warrantor-warrant over 23 path edges`**. The orphan list
  is `main`'s minus `warrantor-eval-guard` — 27 orphans, down from 28. The count did not rise.
* **`README.md`, line 196.** The status-table cell the census gate reads. Transcribed from the tool's
  output: `**14 of 41**` and `the other 27`. `wiring_census.py` refuses the tree when that cell and
  its measurement disagree, and it passed.
* **`docs/task-evidence/task-5.3.md`** did not conflict but is worth naming, because Task 5.3 is
  already merged and this branch edits its evidence. The edit is the one
  `adversary::the_documents_ordinal_for_the_next_ignore_is_read_from_the_ratchet_and_not_from_the_plan`
  requires: that test reads `ignored_ceiling` from the ratchet, counts the corpus's `#[ignore]`
  attributes, and requires both documents to carry the sentence *"`ignored_ceiling` is N, so ignore
  number N+1 would raise it"*. `main`'s copy says 15/16; the merged corpus holds 14 ignores; the
  branch's copy says 14/15 and records that the sentence was rebuilt twice. Verified against `main`
  rather than re-applied: `git diff main -- docs/task-evidence/task-5.3.md` is the three hunks
  quoted in the branch's own commit and nothing else.
* **`tools/ci/invariant-ratchet.json`** merged without conflict at the branch's 83/14, and the
  ratchet re-measured it on the merged corpus rather than trusting the file — see the gate line
  below. `main`'s ratchet was still 82/15, so no other lane moved the corpus in between.
* **No code conflicted.** `rust/warrant/src/bin/warrantor.rs`, `src/lib.rs`, `tests/instructions.rs`
  and `rust/Cargo.lock` auto-merged; both behaviors are present and the gate below is what shows
  they compose.

### A finding this lane made about the shared target directory, recorded because it will bite the next lane

The first gate run on the rebased tree failed with errors that were false on their face:
`unresolved import warrantor_eval_guard::Provenance` (this branch adds it) and
`missing fields causality and predicate_version in initializer of WarPredicate` (no such fields
exist on this tree or on `main`; they exist only on another lane's branch, `2576093`). The shared
target directory held `libwarrantor_evidence-*.rmeta` and `libwarrantor_eval_guard-*.rmeta`
artifacts stamped within the same minutes as this lane's build.

The mechanism: cargo hashes a path crate's identity **relative to the workspace root**, so every
`M:/wt-*` worktree with the same layout produces the same artifact filenames in
`M:/wt-review-shared-target`, and freshness is decided by source mtime against the artifact. A
worktree whose sources are older than another lane's artifact — every freshly rebased worktree,
whose checkout predates the other lane's build — silently links the other lane's crate. This is not
a defect in the branch and it is not fixed here; it is the cost of the shared directory that the
disk-space rule buys. The workaround this lane used, and every number below is from it: bump this
tree's source mtimes (`touch` on every `.rs` and `Cargo.toml` under `rust/`) immediately before
each cargo step, so cargo rebuilds this tree's crates. It leaves git clean (mtimes are not content),
it costs a rebuild of the workspace crates per step, and it does not protect a lane that builds
*after* this one — that lane needs the same touch.

### The gate, on the rebased tree, exit codes captured before any pipe

Disk guard before every cargo invocation (`--require 60` and `--require-commit 6`): every attempt
returned OK on the first try. `CARGO_BUILD_JOBS=2`.

```
$ cd rust && cargo fmt --all -- --check                              exit 0
$ cargo clippy --workspace --all-targets -- -D warnings              exit 0
$ cargo test --workspace --all-targets                               exit 0
    120 suites: passed=1585 failed=0 ignored=19
$ cargo test --workspace --doc                                       exit 0
    40 suites: passed=1 failed=0 ignored=0
$ python ../tools/ci/wiring_census.py
wiring census: 14 of 41 crates reachable from warrantor-warrant over 23 path edges                                                       exit 0
$ cd .. && python tools/ci/check_invariant_ratchet.py --show-findings
invariant ratchet: ok (83 passing at floor 83, 14 recorded findings at ceiling 14)                                                      exit 0
$ python tools/ci/check_invariants.py
invariant ledger: 12 invariants; enforced=2, orphaned=0, partial=9, unimplemented=1                                                       exit 0
$ python tools/ci/check_docs.py
RESULT: PASS — 299 Markdown files, 58 RFCs, 81 catalogue rows, and all local links validated                                                         exit 0
$ python tools/ci/check_us_english.py main
us-english: 4102 added line(s) across 16 file(s), since main; matcher = vendored verify-us-english.mjs
us-english: ok                                                        exit 0
```

The ratchet's `--show-findings` run prints `test failed` for the recorded findings by design (they
fail on purpose); the `invariant ratchet:` line is the verdict. The `git status --porcelain` after
the run is empty.

### The tier table, restated with what escapes each bound

The full table with the reasons is earlier in this document; this is the one-line form the ledger
reads, in the Task 0.4 vocabulary, and each `Mediated` row names what escapes it because the
vocabulary requires it.

| bound | tier | what escapes it |
|---|---|---|
| `scorer_inputs_not_writable`, confinement asserted by a registered operator, profile `check_worktree` accepts, store root placeable outside the worktree | Enforced (given a launched profile; the launch is `Provenance::Asserted`) | reads — the root is read-only, not unreadable; and any process outside the profile |
| `scorer_inputs_not_writable`, otherwise | Observed | every write; a careful edit is invisible, a deleted run file is indistinguishable from no run |
| `scorer_credentials_not_readable` | no tier — held by nothing | every read of `~/.warrantor/keys/settle.key` at the same UID, inside a profile or out |
| `scorer_not_reachable_over_network`, zero egress hosts, confinement asserted, profile writable | Enforced (given a launched profile) | anything outside the namespace; the property vanishes the moment one host is granted |
| `scorer_not_reachable_over_network`, otherwise | Mediated | a shell or a harness built-in reaches past the MCP proxy; no netns, seccomp or firewall stands behind it |
| the reward-hacking monitor | Observed | everything it did not refuse — it reads logs after the fact and stops nothing |
| the threshold's before-the-run ordering | Mediated (a refusal in our code at the attempt) | anyone with filesystem access who deletes `scorer/threshold.json` and re-registers |
| the anti-gaming label boundary (`corpus::rows_from`) | Observed (a convention in one function) | any caller that sets `Row::label` directly; the struct's fields are public |
| the pre-flight (`scorer::preflight` over `eval-guard`) | Mediated (a refusal in our code; signs an assertion, never a measurement) | a launcher that does not call `warrantor scorer`; and the assertion itself, which no probe checks |

### What this lane does NOT establish

* It re-ran the gates and the exit gate; it did not re-run the nine mutation checks or the
  red-before-green sequence. Those stand as the branch recorded them.
* It executed no `bwrap`. Every `Enforced` above is still conditional on a profile this process did
  not launch, and the box is Windows.
* It did not verify the branch's claim-by-claim corrections beyond what the gates measure.
* It did not run the Python unit tests under `tools/ci/test_*.py` (the plan's Step 12 lists them;
  the lane's gate list does not), nor `ruff`.
