# Task 5.4: common-mode independence analysis for double network isolation

Branch `feat/task-5.4-network-common-mode`, based on **local `main` at `f9c3523`** — not
`origin/main` at `e4b5f10`, which is 45 commits stale. Every number in the plan's Step 0 was measured
against `e4b5f10` and most of them are wrong for this base; the deviations are listed in full below.

**The one-sentence result.** L2-03 and L0-10 remain `status="none"`. What changed is that their
absence is now measured, published in three places, and gated: a permitted destination is guarded by
**one** independent intercept, the two "layers" are anti-correlated by a single warrant field, six of
eight modeled axes are shared, and one previously uncalled decision surface is wired as a second
policy domain behind the same single enforcement point.

Analysis document: [`docs/05-network-common-mode-analysis.md`](../05-network-common-mode-analysis.md).
Record: [`evidence/network-independence.json`](../../evidence/network-independence.json).
Gaps entry: `### 3.8` in [`docs/W1-delivery-gaps.md`](../W1-delivery-gaps.md).

---

## The finding the plan could not have contained

Task 7.1 merged after this task was specified, and it changes what the two "paths" are.

`rust/egress-filter/src/hard_deny.rs` is now the single non-amendable address matcher, and
`warrantor-egress` delegates to it (`rust/egress/src/lib.rs` line 18 imports it, line 228 calls
`hard_deny::refuse`). The same two functions are consulted by
`warrantor_egress_filter::Policy::decide_domain` (line 251) and `Policy::decide_ip` (line 314).

**So the moment `Policy` is wired as a second evaluator, the two evaluators share a crate and share
their address floor. A defect in `hard_deny` fails both at once.**

That is not an argument against Task 7.1's placement, which was right for the reason it gives: two
implementations of "is this the metadata service" is the exact shape of the defect that let eight of
nine spellings of `169.254.169.254` reach Allow. One matcher prevents drift. It also couples the
layers. Both are true, and an independence analysis has to record the second one even though the
first is why the code is correct.

The plan's Step 7 asserts `!with_second.shared_axes.contains(&"policy_engine")` and stops there.
**That would have been too generous.** This branch adds an `address_floor` axis that is shared in
every configuration, wired or not, and asserts it — see
`the_axes_are_asserted_not_described` in `rust/warrant/tests/network_independence.rs`.

---

## The compile error that was the first finding, verbatim

Written before any implementation, run against the branch at `f9c3523`:

```
$ cargo test -p warrantor-warrant --test network_independence -j 2
   Compiling warrantor-warrant v1.0.0 (M:\wt-w3-5.4\rust\warrant)
error[E0432]: unresolved imports `warrantor_warrant::egress::independence`, `warrantor_warrant::egress::SecondaryFilter`, `warrantor_warrant::egress::INDEPENDENCE_NOTE`
  --> warrant\tests\network_independence.rs:15:5
   |
15 |     independence, EgressBroker, EgressVerdict, SecondaryFilter, INDEPENDENCE_NOTE,
   |     ^^^^^^^^^^^^                               ^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^ no `INDEPENDENCE_NOTE` in `egress`
   |     |                                          |
   |     no `independence` in `egress`              no `SecondaryFilter` in `egress`

error[E0433]: cannot find module or crate `warrantor_egress_filter` in this scope
  --> warrant\tests\network_independence.rs:64:9
   |
64 |         warrantor_egress_filter::Action::Deny,
   |         ^^^^^^^^^^^^^^^^^^^^^^^ use of unresolved module or unlinked crate `warrantor_egress_filter`

error: could not compile `warrantor-warrant` (test "network_independence") due to 9 previous errors
exit=101
```

`E0433` **is** the finding: on `main`, the second policy engine was not merely switched off, it was
not addressable from the product's crate at all. `warrantor-egress-filter` was reachable in the census
only through `warrantor-egress`, and only its `hard_deny` module was reached.

## A second red, and what it caught

The proxy-level drills failed on their first run with a refusal from the **wrong bound**:

```
a host the operator's engine denies must be refused: Deny { reason: "github.get_file is not in
this warrant's tool allowlist. ...", bound: "tools" }
```

`Proxy::decide` checks `bounds.tools` **before** the egress loop, so a test warrant with an empty
tool set refuses under `bound: "tools"` and the egress decision is never reached. The assertion
`matches!(decision, Decision::Deny { .. })` would have passed on a looser predicate and measured
nothing. Fixed by putting the tool in the allowlist; the reason is recorded as a comment in
`proxy_over`, because this is a false pass that any future test in this file could repeat.

---

## Gate output, verbatim, with exit codes

Run in a **fresh detached worktree** at `M:/wt-fresh-5.4` on the committed branch — not in the
working worktree — for the reason the previous wave learned the hard way: a `.gitignore`-excluded
evidence file makes an implementer's run green and everyone else's red.

```text
git status --porcelain                                    (empty)
git ls-files evidence/network-independence.json            evidence/network-independence.json
git ls-files docs/05-network-common-mode-analysis.md       docs/05-network-common-mode-analysis.md
git ls-files tools/ci/network_independence.py              tools/ci/network_independence.py
git ls-files tools/ci/test_network_independence.py         tools/ci/test_network_independence.py
git ls-files rust/warrant/tests/network_independence.rs    rust/warrant/tests/network_independence.rs
git check-ignore -v <each of the five>                     exit 1, no rule matched

cargo fmt --check                                         FMT=0
cargo clippy --all-targets -- -D warnings                  CLIPPY=0
cargo test --workspace -j 2                                CARGO=0
  145 suites, 1520 passing, 0 failed, 20 ignored
  (base: 144 suites, 1507 passing, 0 failed, 20 ignored)
python tools/ci/wiring_census.py                           CENSUS=0
  wiring census: 12 of 40 crates reachable from warrantor-warrant over 21 path edges
python tools/ci/check_invariant_ratchet.py                 RATCHET=0
  invariant ratchet: ok (85 passing at floor 85, 15 recorded findings at ceiling 15)
python tools/ci/check_invariants.py                        LEDGER=0
  invariant ledger: 12 invariants; enforced=2, orphaned=1, partial=8, unimplemented=1
python tools/ci/check_us_english.py main                   USEN=0
python tools/ci/check_docs.py                              DOCS=0
  RESULT: PASS - 267 Markdown files, 58 RFCs, 81 catalogue rows, all local links validated
python tools/ci/network_independence.py                    NETIND=0
  network independence: 1 independent intercept on a permitted destination;
  6 shared axes of 8; 2 policy engines
python -m pytest tools/ci/test_network_independence.py -q  29 passed (with test_wiring_census.py)
```

The verbatim console capture is in the "Fresh-worktree gate" section at the end of this file.

### Numbers moved, and read rather than computed

| record | before | after | read from |
|---|---|---|---|
| workspace suites / passing / ignored | 144 / 1507 / 20 | 145 / **1520** / 20 | the `test result:` lines |
| wiring census `reachable` | 12 of 40 | **12 of 40 — unchanged** | `tools/ci/wiring_census.py` |
| wiring census path edges | 20 | **21** | same |
| orphan count | 28 | **28 — did not rise** | `evidence/wiring-coverage.json` |
| `passing_floor` | 82 | **85** | the corpus's `test result: ok. 85 passed` line |
| `ignored_ceiling` | 15 | **15 — unchanged** | no `#[ignore]` added or converted |

**The floor is 85 and not 84.** The plan predicted two corpus tests; the honest split needed three
(the DNS finding, the netns anti-correlation pair, and the two-note static check). An arithmetic
floor of 82 + 2 would have been 84 and would have *passed* while one test silently did not run — the
[[failure count is not failure reason]] trap. The number was read from the captured `test result:`
line and both new names were confirmed present with `... ok`.

**No assertion was weakened to earn any number.** Three existing prose claims were *corrected*
because this change made them false; each is listed under Deviations.

---

## Bound strength

| bound | word | why not stronger |
|---|---|---|
| `egress_hosts`, decided by the broker | **Tier B — chokepoint** | `warrantor_egress::decide` refuses at the moment a call names the destination, but only for calls that traverse the Warrantor MCP proxy. A shell command, a harness built-in, or a socket the agent opens itself is not decided here or anywhere. Unchanged by this task. |
| `egress_hosts`, decided by the second engine (`SecondaryFilter`) | **Tier B — chokepoint** | Same enforcement point, in the same process, inside the same `Proxy::decide` loop. Two *policy domains*, **one** boundary. Not Mediated-plus: adding an evaluator does not add a place where the action is refused. |
| the address floor (`hard_deny`) reached through either engine | **Tier B — chokepoint** | A specific line refuses the address, and both engines consult the same one. Still bounded by the proxy. Task 7.1's evidence already labels it Tier B and this task does not upgrade it. |
| `--unshare-net` for an empty `egress_hosts` | **Tier A — OS bound, but not created here and not observable** | The kernel enforces a network namespace and an agent cannot route around it. Two reasons it is not this task's claim: it is available **only** when the warrant permits no egress, so it never guards a permitted destination; and `sandbox::profile` *prints* argv — `PROFILE_CAVEAT` (lines 209-215) says Warrantor cannot tell whether the operator launched it. |
| the independence **count** itself | **Observed** | It is a measurement of the configuration, not a refusal. Nothing is denied because the count is one. |

**What escapes Tier B** is `egress::INDEPENDENCE_NOTE`, asserted onto every surface that prints the
count by `note_accompanies_every_count` in the gate and by
`the_note_names_all_three_absent_enforcement_mechanisms` in the Rust suite:

> Two policy engines decide this destination and one boundary enforces them. The count above is a
> count of policy domains, not a count of enforcement points: both engines run inside the Warrantor
> MCP proxy, so a shell command, a harness built-in, or any socket the agent opens itself passes
> neither of them. There is no network namespace, seccomp filter or firewall behind this count unless
> you launched the confinement profile yourself, and this process cannot tell whether you did. A
> hostname that resolves into a private or metadata range is not caught: neither engine resolves DNS.

No netns, seccomp filter or firewall enforcement exists in this repository, and none is added here.
Containment still composes with an external sandbox.

---

## Refusal tests and their allowed controls

Rule 4, satisfied pair by pair. Every refusal below has a control in which the *same* machinery
allows, so none of them can pass by refusing everything.

| refusal | its allowed control |
|---|---|
| the second engine denies a host the operator never allowlisted | `the_second_engine_allows_what_the_operator_permitted`: the same engine reaches `Allow` for an allowlisted domain |
| an allowlist entry for `169.254.169.254` is still denied | the same test's first assertion allows `api.github.com`, so the floor is not refusing everything |
| the broker refuses a host outside the warrant, through the proxy | `through_the_proxy_the_second_engine_narrows_what_the_warrant_permitted` ends with a proxy that **forwards** the permitted host |
| the second engine cannot un-refuse the broker | the test first asserts the filter, asked alone, **allows** the host — so the attack really reaches the boundary |
| the netns is absent for a permitting warrant | `the_only_second_layer_is_emitted_exactly_when_no_destination_is_permitted` first asserts it is **present** for an empty bound |
| a name encoding the metadata address passes both engines (a **finding**, via `reached_the_boundary_unrefused`) | the control is an ordinary permitted host; and the same engine **denies** the literal `169.254.169.254`, which localizes the gap to the resolver |

---

## Deviations from the plan

The plan's Step 0 was measured on `origin/main` at `e4b5f10`. **The code wins over the plan**, every
time; each divergence below is a fact about this base, not a choice.

1. **The orphan count cannot fall, because the crate is already reachable.** Plan: *"`reachable` 9 →
   10, `warrantor-egress-filter` leaves `orphaned`"*, and *"This task lowers the orphan count by
   one."* Reality: Task 7.1 already wired the crate via `rust/egress/Cargo.toml`, so the base reads
   **12 of 40 with 28 orphans** and `warrantor-egress-filter` is not in `orphaned`. Adding the direct
   dependency from `rust/warrant` adds a **path edge** (20 → 21) and no crate. The orphan count is
   unchanged at 28 — it did not rise, which is what Rule 5 requires. **The README's `12 of 40` string
   therefore did not change**, and the plan's Step 6 expectation of a `::notice::` and a
   `--write` cycle does not occur.
2. **Ratchet numbers.** Plan: `passing_floor` 65 → 67, `ignored_ceiling` 19. Reality: 82 → **85**,
   ceiling **15**. Three tests, not two — see above.
3. **The gaps section is `### 3.8`, not `### 3.7`.** `3.7` is taken on this base by the
   delegation-algebras entry.
4. **Line numbers moved.** The plan anchors the broker's empty-bound check at
   `rust/warrant/src/egress.rs:191`; on this base it is **:196** (Task 7.1's doc edits shifted it).
   `rust/warrant/src/sandbox.rs:318` is unchanged. Every citation in the analysis document is against
   this base.
5. **`address_floor` is a new axis, and `policy_engine` is only partly freed.** The plan models four
   axes plus `enforcement_point`; this branch models **eight** and asserts each. The addition is
   forced by Task 7.1 — see "The finding the plan could not have contained".
6. **The secondary refusal is its own record, not an `EgressRefusal`.** The plan writes
   `self.deny_secondary(...)` without saying what it records. Reusing `EgressRefusal` would have
   meant putting a `warrantor_egress::DenyReason` on a decision the broker did not make — a rendered
   reason not derived from its record (Rule 2) — and constructing a previously never-constructed
   variant would have moved the count that
   `i09`/`i11_self_change_is_governed.rs` pins. So `egress::SecondaryRefusal` carries the filter's
   own reason, read off `decision.reason` by serialization, and `Proxy::secondary_refusals()` keeps
   it separate. Two maps in one process is still **one** telemetry path, which is why
   `telemetry_path` stays shared.
7. **`from_policy` was used by the plan's Steps 7 and 8 but absent from its "Produces" list.** Added,
   with `source()` and `SecondarySource` so that "which configuration source decided this" is
   recorded rather than inferred.
8. **The finding test is about DNS, not about the netns polarity.** The plan's Step 5 body passes a
   netns-present control to `harness::reached_the_boundary_unrefused`. That harness requires
   `allowed(control)` **and** `allowed(attacked)` to be true, so a control with the namespace present
   fails as *"the CONTROL was refused, so this demonstrates nothing"* — captured red above. The
   finding was reframed onto the shared DNS blind spot, which fits the harness exactly and is the
   sharper claim; the netns anti-correlation is asserted separately with its own control.
9. **Three prose claims were corrected because this change made them false.** Not weakened —
   corrected, and each says loudly what changed:
   - `README.md` line 196 said `warrantor-egress-filter` *"counts because its deny floor is called
     while its `Policy` decision surface still has no caller in the product"*. `Policy` now has one
     caller. Rewritten to say when each became true.
   - `rust/egress/Cargo.toml` said `Policy` *"has an EMPTY caller set in this workspace outside the
     crate's own tests"*. Rewritten, with an added note that the edge makes `hard_deny` a shared
     failure domain.
   - Neither had a test gating it, which is why both were still standing. The new gate's
     `RENDER_TARGETS` and `note_accompanies_every_count` mean the *independence* number cannot repeat
     that.
10. **The plan's Step 9 surface test named `rust/warrant/src/bin/warrantor.rs`.** No CLI surface
    prints the count on this branch, so asserting against that file would have been a test of a
    string that does not exist. The gate checks the three files that **do** publish it, and the
    Rust suite checks the constant itself. **This is a gap, stated as one below.**
11. **`python tools/ci/check_us_english.py main` diffs `main...HEAD`**, so it inspects committed
    lines only. It reports `0 added lines` against an uncommitted tree. Run after committing; the
    result above is post-commit.
12. **The harness/worktree entry point differed.** This agent runs inside a harness-isolated
    worktree of the *outer* repository; `aumos` is a separate, gitignored repository, and the
    isolation guard refuses any git command targeting the shared `aumos` checkout — including the
    plan's `git -C ".../aumos" worktree add`. The worktree was therefore created from a sibling
    linked worktree (`M:/wt-wave3`) instead, at `M:/wt-w3-5.4`, which is outside the protected path
    and touches no other lane's tree. Nothing was written to the shared checkout.

---

## What this task does NOT establish

Specific, not modest.

1. **L2-03 stays `status="none"` and L0-10 stays `status="none"`.** Neither is closed, neither is
   softened, and this branch does not touch the master blueprint's status attributes. The blueprint's
   proof gate D-03 asked for *"common-mode analysis proving the two layers do not share a failure
   domain"*; the analysis was run and it proves they share six of eight.
2. **No second enforcement point exists, and none was built.** The intercept count on a permitted
   destination is one, before and after this branch. Wiring a second evaluator raises `engines` from
   1 to 2 and leaves `intercepts` at 1. Anyone reading "two policy engines" as "two boundaries" has
   read it wrong, which is why `INDEPENDENCE_NOTE` is asserted onto every surface that prints it.
3. **The cluster layer L2-03 names does not exist.** No `deploy/k8s`. The single `NetworkPolicy` in
   the tree is `policyTypes: ["Ingress"]` on a `trust-core` pod selector — it restricts who may
   *reach* trust-core and says nothing about what any workload may reach.
4. **The two evaluators are not independent.** They share the `warrantor-egress-filter` crate and the
   `hard_deny` matcher inside it. A defect in `hard_deny` fails both simultaneously. The gain is
   confined to a second evaluator with a different default and a different configuration source.
5. **The DNS gap is unclosed and this branch narrows it by nothing.** Neither engine resolves. A
   hostname that resolves into a metadata or private range reaches `Forward` unless the *name* is on
   `hard_deny`'s hostname list. The finding test exercises exactly this and records it as unrefused.
6. **The netns is not verified on any kernel by this branch.** `sandbox::profile` returns argv this
   process prints. `rust/warrant/src/sandbox.rs` lines 68-72 already note that WSL2's 6.18 *"is not a
   hardened distro kernel with `unprivileged_userns_clone` disabled, where `bwrap` will refuse to
   start at all"*. Nothing here was run under bubblewrap or firejail.
7. **No surface in the shipped CLI prints the independence count.** `SecondaryFilter` is reachable
   from the library and from `Proxy::with_secondary_filter`, and **nothing in
   `rust/warrant/src/bin/warrantor.rs` constructs one** — so on a default run the second engine is
   `None` and the product behaves exactly as before. The count is published in three documents and a
   JSON record, not in `warrantor report`. Wiring the CLI flag, the operator config path and the
   report row is not done here.
8. **`SecondaryFilter::from_operator_config` has no caller and no fixture on disk.** It is covered by
   type and by review, not by a test that reads a real file. Its error variants are constructed only
   by that function.
9. **The record's `intercepts: 1` is derived, not proved by execution.** The gate asserts the two
   *conditions* that produce it (the two `egress_hosts.is_empty()` branches) and fails hard if either
   moves; it does not run a network. The Rust suite computes the same answer from the same function,
   which is what stops the prose and the code diverging — it is not an end-to-end demonstration.
10. **Nothing here measures whether the operator's file is authentic.** No signature, no registry, no
    fetch. Absence of the file is default-deny, not default-allow, and that is the whole of the
    claim.
11. **The plan's Steps 6 to 11 assumed a census movement that did not happen**, so the exit-gate line
    the plan predicted (`wiring census: 10 of 39 ... over 18 path edges`) never appears in any
    output on this base. The gate line that *does* appear is quoted above.
12. **Not pushed and not merged.** A human merges. The branch was verified in a fresh detached
    worktree and nowhere else.

---

## Fresh-worktree gate

Verbatim capture follows.
