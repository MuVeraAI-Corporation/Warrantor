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

## Boundary — the two neighbouring tasks this one does not cover

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
