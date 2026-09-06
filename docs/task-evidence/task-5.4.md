# Task 5.4: common-mode independence analysis for double network isolation

> **Rebased 2026-09-06** onto `main` at `065961b`; the merged-tree gate and the three conflict
> resolutions are in *Review lane, phase 1*. **A second adversarial review refuted this branch
> again on 2026-09-06** (three lenses, twenty findings); every finding, its reproduction, its fix
> or its refutation, and the regate on the final tip are in the last section, *Review lane,
> phase 3: corrections after the second adversarial review*. Where a sentence above is marked
> **[corrected, phase 3]** the section at the end carries the derivation.

Branch `feat/task-5.4-network-common-mode`, based on **local `main` at `f9c3523`** — not
`origin/main` at `e4b5f10`, which is 45 commits stale. Every number in the plan's Step 0 was measured
against `e4b5f10` and most of them are wrong for this base; the deviations are listed in full below.

**The one-sentence result.** L2-03 and L0-10 remain `status="none"`. What changed is that their
absence is now measured, published in three places, and gated: a permitted destination is guarded by
**one** independent intercept, the two "layers" are anti-correlated by a single warrant field, seven of
eight modeled axes are shared in a shipped run and six once a second engine is wired (**[corrected,
phase 3]**: the first cut published only the wired configuration's six), and one previously uncalled
decision surface is reachable as a second policy domain behind the same single enforcement point --
reachable, not reached: the shipped binary wires no secondary filter, so one engine decides in the
product and two do once a caller of the library wires the second (no CLI flag or configuration path
reaches it; "once an operator wires" was the first cut's wording, withdrawn in phase 3). That distinction is a review correction; the first cut of this document published the operator
number as the product'''s. See the CORRECTION section.

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

## A third red, and it is the one the fresh-worktree gate exists for

`the_notes_refuse_to_imply_a_second_boundary` passed in the working worktree and **failed in the
fresh detached checkout**:

```
rust/warrant/src/egress.rs no longer contains "There is no network \
     namespace, seccomp
filter or firewall: an agent that opens a socket itself is not bound by \
     them.".
test result: FAILED. 84 passed; 1 failed; 15 ignored
```

The first version asserted a `harness::source_contains` fragment **spanning two source lines**. This
repository checks out **CRLF** on Windows, so the file the test read had `

` line endings and a
needle containing `
` could not match. The author's worktree held the files as written, with LF, so
it was green there.

```
$ file rust/warrant/src/egress.rs      (fresh checkout)
Unicode text, UTF-8 text, with CRLF line terminators
CRLF count: 869   bare LF: 0
```

**This is [[windows rust paths are ungated]] in miniature, and it would have shipped green.** CI runs
the workspace on Linux, where the checkout is LF, so the gate that would have caught it does not run
on the platform where it breaks — the same shape as the kill-switch contract breach that memory
records.

Fixed by asserting the **constants' runtime values** rather than their source text. Both notes are
`pub const &str`, and a string continuation elides its newline, so the values contain no line breaks
at all: the assertion is now both portable and stronger, because it survives any reformatting of the
source. A source-text assertion is the right tool only for something with no runtime representation,
and neither note is that. The reasoning is recorded in the test's own doc comment so the next author
does not reintroduce it.

Audited the rest of this branch for the same fragility:
- `tools/ci/network_independence.py` is safe by construction. `Path.read_text()` opens in universal-
  newline mode, so `

` is translated to `
` before any needle is matched — including the one
  `RENDER_TARGETS` needle that deliberately spans a line break.
- `rust/warrant/tests/network_independence.rs` reads `INDEPENDENCE_NOTE` as a value, never as source.
- The only remaining `source_contains` in `i09` is the pre-existing single-line one on
  `eval-guard/src/cli.rs`, untouched.

---

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
  RESULT: PASS - 268 Markdown files, 58 RFCs, 81 catalogue rows, all local links validated
python tools/ci/network_independence.py                    NETIND=0
  network independence: 1 independent intercept on a permitted destination;
  6 shared axes of 8; 2 policy engines
python -m pytest test_network_independence.py test_wiring_census.py  29 passed
```

The verbatim console capture is in the "Fresh-worktree gate" section at the end of this file.

### Numbers moved, and read rather than computed

| record | before | after the task | after the review fix | read from |
|---|---|---|---|---|
| workspace suites / passing / ignored | 144 / 1507 / 20 | 145 / 1520 / 20 | 145 / **1525** / 20 | every `test result:` line, summed |
| `network_independence` suite | — | 10 | **15** | that target's `test result:` line |
| gate pytest | — | 17 | **30** | `pytest -q` |
| wiring census `reachable` | 12 of 40 | 12 of 40 — unchanged | **12 of 40 — unchanged** | `tools/ci/wiring_census.py` |
| wiring census path edges | 20 | 21 | **21 — unchanged** | same |
| orphan count | 28 | 28 — did not rise | **28 — did not rise** | `evidence/wiring-coverage.json` |
| `passing_floor` | 82 | 85 | **85 — unchanged** | the corpus's `test result: ok. 85 passed` line |
| `ignored_ceiling` | 15 | 15 — unchanged | **15 — unchanged** | no `#[ignore]` added or converted |
| record: engines on a permitted host | — | `2` | **split: 1 in the product, 2 once wired** | `evidence/network-independence.json` |

The review fix adds **five** Rust tests and **thirteen** gate tests and moves the corpus floor by
nothing: all five new Rust tests are in `tests/network_independence.rs`, which is not the I-09 corpus,
so `passing_floor` stays 85 and `ignored_ceiling` stays 15. `1525 - 1520 = 5` is that arithmetic, and
it was read from the summed `test result:` lines rather than computed from an intention -- the
[[failure count is not failure reason]] rule applies to successes too.

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

**What escapes Tier B** is `egress::INDEPENDENCE_NOTE`. Its two load-bearing clauses are required
within twelve lines of the rendered count on each of the **three render targets the gate names**
(`docs/05`, `README.md`, `docs/W1-delivery-gaps.md`) by `note_accompanies_every_count`; this evidence
file is not a render target and transcribes the gate's output without being one (**[corrected, phase
3]**: the first cut said "every surface that publishes it"). Its value is asserted by
`the_note_names_all_three_absent_enforcement_mechanisms` and
`the_notes_refuse_to_imply_a_second_boundary` in the Rust suite, and `docs/05`'s paragraph is
required to be this value verbatim by `analysis_paragraph_is_the_constant`. The value, byte-verbatim
from `rust/warrant/src/egress.rs` at the final tip (the first cut's quotation added backticks the
constant does not carry, and quoted a value that said "Two policy engines decide" -- both corrected
in phase 3):

> The count above is a count of enforcement points acting on a destination this warrant permits. Every policy engine that decides a destination -- the broker always, and a second engine only once one is wired -- runs inside the Warrantor MCP proxy at that one point, so the engine count is a count of policy domains and is not a second boundary: a shell command, a harness built-in, or any socket the agent opens itself passes neither the proxy nor any engine inside it. There is no network namespace, seccomp filter or firewall behind this count, and the confinement profile does not add one for a warrant that permits any host -- it omits --unshare-net precisely then. A hostname that resolves into a private or metadata range is not caught: no engine at that point resolves DNS.

**CORRECTED, twice.** This section used to claim the note was *"asserted onto every surface that
prints the count"* by those two mechanisms. Neither did what the sentence said: the gate accepted the
bare token `INDEPENDENCE_NOTE` and skipped README entirely, and the named Rust test only ever read the
constant's own value and inspected no surface (findings C3 and T3). And the paragraph quoted here was
the withdrawn one -- it mislabeled the number it accompanied and offered an unavailable remedy
(findings C1 and C5).

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
| the broker refuses a host outside the warrant, through the proxy | `through_the_proxy_the_second_engine_narrows_what_the_warrant_permitted` ends with a proxy that returns `Decision::Forward` for the permitted host |
| the second engine cannot un-refuse the broker | the test first asserts the filter, asked alone, **allows** the host — so the attack really reaches the boundary |
| the netns is absent for a permitting warrant | `the_only_second_layer_is_emitted_exactly_when_no_destination_is_permitted` first asserts it is **present** for an empty bound |
| a name encoding the metadata address passes both engines (a **finding**, via `reached_the_boundary_unrefused`) | the control is an ordinary permitted host; and the same engine **denies** the literal `169.254.169.254`, which localizes the gap to the resolver |

---

## CORRECTION: the adversarial review refuted this task, twelve findings, both lenses

Two review lenses ran independently against `82118f8` and both set `refuted=true`. Both confirmed the
engineering and the numbers -- every gate output above reproduced in their own fresh worktrees, no
test function was deleted, no assertion was weakened, and the disclosure list held on every point they
tested. What failed was the **prose pinned to the record**, and one CI rule that pinned the wrong
words in place. That is where this project's defects cluster, and this task shipped four of them.

**Reproduce-before-fix.** Every one of the twelve was re-run at `82118f8` with the reviewer's own
command, in a detached worktree at that commit, before anything was changed. **Nothing was disputed:
twelve findings, twelve reproductions.** Then each was re-run against the fix and had to go red.

### The two that made this not mergeable

**C1 -- the one sentence the gate existed to enforce mislabeled the number it accompanied, in the
unsafe direction.** `egress::INDEPENDENCE_NOTE` opened *"The count above is a count of policy domains,
not a count of enforcement points"*, and `note_accompanies_every_count` forced that clause onto all
three render targets.

- *Claimed:* the published count does not bound enforcement points.
- *True:* every surface the gate polices publishes exactly **one** number, `Independence::intercepts`,
  and that number **is** the enforcement-point count. The engine count is required on no surface. The
  machine record sitting beside it said so in capitals: `evidence/network-independence.json`'s own
  note reads *"The count is a count of ENFORCEMENT POINTS acting on a destination the warrant permits,
  not of policy engines"*.
- *How it was caught:* a reviewer read the record and the constant side by side and printed both.
  Reproduced here by the same command. Not by a test -- two Rust tests and one CI rule were holding
  the wrong wording **in place**, in the exact spot the branch itself calls *"the single most damaging
  misreading this repository can ship"*.
- *What changed:* the policy-domain clause is attached to the engine count, the number it is true of.
  The withdrawn wording is now **refused** by `REFUSED_CAVEAT_CLAUSES` in the gate and by two value
  assertions in the Rust suite, so it cannot come back. `egress::independence_sentence` renders each
  number under the label of the field it was read out of -- including the empty-bound case, where two
  layers stand and nothing is permitted for either to guard, because rendering that `2` as a double
  network path is the overclaim this whole analysis refuses.

**C2 -- the self-enforcement promise was false for two of the three exit conditions the analysis names
for itself.**

- *Claimed:* `i09_failure_is_safe.rs` *"starts failing the day either half is fixed: a resolver on the
  egress path, or a second enforcement point that acts on a permitted host"*; `docs/05` section 7
  *"When any of these lands ... starts failing on purpose"*; W1 3.8 *"it goes red the day a real second
  enforcement point lands rather than going stale."*
- *True:* `harness::reached_the_boundary_unrefused` goes red only when `allowed(attacked)` flips, and
  the predicate handed to it is the closure `broker_allows && filter_allows` -- closed over exactly the
  two in-process policy engines. No enforcement point, kernel layer or cluster policy is an input.
- *How it was caught:* the reviewer landed exit condition 2 -- a real cluster egress `NetworkPolicy`
  under `deploy/k8s` with `policyTypes: ["Egress"]` -- and the finding test stayed green, the corpus
  stayed at 85 passed / 15 ignored, and the gate went on printing `1 ... ok`. Reproduced here exactly:
  `GATE_WITH_CLUSTER_POLICY=0`, `85 passed`, `a_name_that_encodes... ok`. The two prose facts that
  carry the conclusion (*no `deploy/k8s` directory*, *exactly one `NetworkPolicy` in the tree*) were
  ungated and **false throughout that run**.
- *What changed:* the cluster half of the finding has an assertion that can actually go red, in the
  one place that can read a YAML file: `network_independence.py::cluster_layer_absent` fails the build
  when a `NetworkPolicy` this analysis does not know about appears **and** when the single one it names
  disappears. The three overstated sentences now say which exit condition each mechanism can see.

### The other ten

| # | lens | claimed | true | now |
|---|---|---|---|---|
| C3 | claim-honesty | `INDEPENDENCE_NOTE` is *"asserted onto every surface that prints the count"* | the rule accepted the bare token `INDEPENDENCE_NOTE` anywhere in the file: `See \`INDEPENDENCE_NOTE\`` appended after every real clause was stripped left the gate at exit 0 | both clauses required, within twelve lines of the rendered count; the cross-reference token is not an accepted clause |
| C4 | both | Deviation 4: *"every citation in the analysis document is against this base"* | all four `proxy.rs` anchors were **pre-change** numbers: `227-234` (loop, really 284) landed inside `deny_secondary`, a function that did not exist when the anchor was written, and the code block quoted under it was the pre-change loop with the new engine missing; `236-243` -> 310, `119-120` -> 129, `110-112` -> 115/117. Every non-`proxy.rs` citation was correct, which is the tell | `citations_resolve` finds each construct's real line in the source and fails the build when the document cites a different one; seven anchors are derived this way |
| C5 | claim-honesty | the note's remedy clause *"unless you launched the confinement profile yourself"* | true as written and misleading in the overclaiming direction: `sandbox::profile` omits `--unshare-net` for **any** warrant that permits a host, which is the only configuration this count is about, so the remedy is never available | the clause reads *"the confinement profile does not add one for a warrant that permits any host"*, asserted by value, and the old wording is refused |
| T1 | test-rigor | `SecondaryRefusal::new` *"derived from the decision, not written beside it"* | only `DefaultDeny` was ever exercised and the one assertion was `rule.contains("default_deny")`; replacing the serialization with a hardcoded `"\"default_deny\""` literal left **all 833** package tests and the gate green | two reasons drive the same serialization, the rendered rules must differ, and the sentence must carry this record's own rule |
| T2 | test-rigor | two assertions pin *"the non-amendable floor"* / *"`hard_deny::refuse_ip` runs before the allowlist"* | `169.254.169.254` is in `DEFAULT_CANARY_IPS` and the canary check runs first, so both observed `CanaryIp` -- a refusal that reads a **configured field** -- and both asserted only the action. Deleting the whole `hard_deny::refuse_ip` arm left both 5.4 suites green (85 + 10) while Task 7.1's suite went red with **6 failures**. `address_floor` was this branch's headline new axis and nothing behavioral held it | the canary refusal is named as the canary list; the floor is asserted on `169.254.1.1` and `fd00:beef::1`, which no canary list covers, with `deny_private_egress(false)` and the address allowlisted, so nothing but the floor can produce the Deny -- plus an allowed control on a routable address |
| T3 | test-rigor | `note_accompanies_every_count` guards every render target | its presence test was `if "independent" not in text` -- case-sensitive. README's only occurrence is the capitalized row title and it contains no lowercase `independent` at all, so **README was silently exempt**: stripping every clause from README left exit 0 while the identical edit to either other target exited 1. The gate's own negative test used a lowercase synthetic fixture, so it passed while the one surface most likely to be read out of context was skipped | there is no presence heuristic -- every render target publishes the count by construction and `renders_agree` proves it, so every one carries the caveat unconditionally. The regression test's fixture is capitalized on purpose |
| T4 | test-rigor | see C4 | see C4 | see C4 |
| T5 | test-rigor | Deviation 7: `SecondarySource` exists *"so that which configuration source decided this is recorded rather than inferred"*, and `as_str`'s doc: *"the word used in `Independence` and in the machine-readable record"* | the word appeared in neither. `Independence` had five fields and no source field, the JSON record had no such key, `source()` had **zero callers in the workspace**, and `pub` hid that from both `dead_code` and `clippy -D warnings`. The attribution was declared and dropped | `Independence::configuration_sources` carries it, the record publishes `configuration_sources_the_product_runs`, and three sources are asserted apart (`compiled_default`, `inline_policy`, `operator_file`) |
| T6 | test-rigor | `SecondaryRefusal.count` is *"how many times this exact refusal happened"*; `secondary_refusals()` returns them *"most frequent first"* | no test ever produced a repeated refusal or a second distinct one. No-oping `.and_modify(\|existing\| existing.count += 1)` **and** deleting the whole `out.sort_by(...)` left all 833 package tests green at once -- verbatim the previous wave's finding about the broker's counter | one test refuses twice for one destination and once for another, asserting `count == 2`, `count == 1`, and the order; then reverses the counts, because `api.github.com < registry.npmjs.org` means key order would put the right row first for the wrong reason |
| T7 | test-rigor | README: *"Two policy engines decide a permitted destination"*; record: `policy_engines_on_a_permitted_host: 2` | false for **every run of the shipped binary**. `Proxy::new` sets `secondary: None`, `warrantor.rs` contains zero occurrences of `SecondaryFilter`, and `with_secondary_filter` has exactly one caller and it is a test. `measure()` hardcoded `engines = 2` and justified it from the two `policy_engine` probes -- which prove the call site consults a filter *when one is present*, never that anything sets one. The disclosure list said this loudly; the two gated surfaces did not, so the gate that exists to stop prose/code drift **passed on the drifted claim** | `engines_the_product_runs()` greps the product sources (`rust/*/src/**`, tests excluded) for `.with_secondary_filter(`; the record publishes `policy_engines_the_product_runs: 1` and `policy_engines_when_an_operator_wires_one: 2` as separate fields, because one number with a footnote is what let the drift stand. README says one in a shipped run and two once an operator wires it |

### Every mutation the reviewers left surviving, re-run against the fix

A fix that does not turn the reviewer's own command red is a fix nobody can check. Each row was run in
this worktree at `50ef8b9`, reverted after each run, with an unmutated control run last.

```text
CAUGHT   exit=1    T3   README caveat stripped              (was exit 0 at 82118f8)
CAUGHT   exit=1    C3   bare `See INDEPENDENCE_NOTE`        (was exit 0)
CAUGHT   exit=1    C1   withdrawn clause beside the count   (was REQUIRED at 82118f8)
CAUGHT   exit=1    C2   cluster egress NetworkPolicy added  (was exit 0, corpus 85 green)
CAUGHT   exit=1    C2   the named NetworkPolicy deleted     (was unchecked entirely)
CAUGHT   exit=1    T4   proxy.rs anchor set back to 227-234 (was unchecked entirely)
CAUGHT   exit=1    T7   record publishes the operator count (was the published value)
CAUGHT   exit=1    C1   withdrawn clause ADDED beside a correct one, on the real docs/05 surface
CONTROL  exit=0         unmutated tree: network independence: ok

CAUGHT   exit=101  T1   SecondaryRefusal.rule hardcoded     -> the_rendered_rule_is_the_engine_s_own_reason_and_not_one_literal
CAUGHT   exit=101  T6   counter no-oped AND sort deleted    -> a_repeated_refusal_is_counted_and_the_most_frequent_is_reported_first
CAUGHT   exit=101  T2   hard_deny::refuse_ip arm deleted    -> i09 finding test AND the_second_engine_allows_what_the_operator_permitted
CAUGHT   exit=101  C1   withdrawn INDEPENDENCE_NOTE value   -> the_notes_refuse_to_imply_a_second_boundary
CAUGHT   exit=101  T5   configuration_sources push removed  -> the_measurement_records_which_configuration_source_each_engine_read
                                                              AND the_second_engine_can_be_built_from_a_real_operator_file
CAUGHT   exit=101  --   configuration_sources hardcoded     -> same two
CAUGHT   exit=101  --   independence_sentence labels swapped -> the_count_sentence_labels_each_number_with_the_field_it_came_from
CONTROL  exit=0         unmutated tree: 85 passed / 15 ignored, 15 passed
```

`git status --porcelain` was empty after each revert, checked by the same script.

The second C1 row is the one that isolates the **refusal** rule from the requirement rule. The first
C1 row replaces the correct clause with the withdrawn one, so the required-clause check alone would
catch it; the second leaves the correct clause in place and *adds* the withdrawn one beside the count,
which only `REFUSED_CAVEAT_CLAUSES` can see. It reports: *"labels the count on line 226 with the
withdrawn clause ... Quoting it to record why it was withdrawn is fine, more than 12 lines from the
count."*

### One scope decision, stated rather than left implicit

The withdrawn clauses are refused **within the caveat window** around the rendered count, not
file-wide. A document that records *why* a clause was withdrawn has to be able to quote it, and both
published documents now do; what a clause may never do again is sit beside the count as its label,
which is the only place it did harm. `egress::INDEPENDENCE_NOTE`'s own value is asserted
unconditionally in the Rust suite, which is the authoritative place, and the pytest suite exercises
both directions of the window rule.

A second, smaller decision: the required and refused clauses are matched against **flowed** text --
one line, single-spaced, Markdown line furniture removed. This was forced by the fix itself. A
correction paragraph in `docs/05` quoted the withdrawn wording verbatim and the refusal did **not**
fire, because the quote had wrapped mid-clause; the same accident had already hidden a *required*
clause in the new W1 paragraph. Evasion by accident is still evasion.

### What the review did NOT establish

- **No mechanism was wrong.** Both lenses confirmed the deny-only contract, that `hard_deny` really is
  reached through both evaluators, that the second engine cannot widen the warrant, that no CLI
  surface constructs a `SecondaryFilter`, and that every path a test opens is tracked and unignored.
  14 of 20 mutations were already caught at `82118f8`, including all eight independence-axis flips.
- **The count did not move and must not.** `intercepts` is still 1. Nothing in this correction closes
  L2-03 or L0-10, and the engine-count split is a disclosure, not a capability.
- **`from_operator_config` is exercised now, but only against a file this test writes.** No signature,
  no registry, no authenticity claim -- see item 10 of the disclosure list, which is unchanged.

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
   `rust/warrant/src/sandbox.rs:318` is unchanged. **CORRECTED:** this entry used to end *"every
   citation in the analysis document is against this base"*, and all four `proxy.rs` anchors were
   pre-change numbers -- see finding C4. Anchors are derived by `citations_resolve` now, so the claim
   is made by a check rather than by an assurance.
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
   recorded rather than inferred. **CORRECTED:** at `82118f8` it was inferred by nobody and recorded
   nowhere -- `source()` had zero callers and the word appeared in neither `Independence` nor the JSON
   record, though `as_str`'s doc claimed both. See finding T5. It is carried in
   `Independence::configuration_sources` and in the record now, and asserted per source.
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
   destination is one, before and after this branch. Wiring a second evaluator raises the engine count
   from 1 to 2 and leaves `intercepts` at 1. **And the shipped binary wires none**: the engine count
   in the product is **one**, published as its own field. Anyone reading "two policy engines" as "two
   boundaries" has read it wrong, which is why the clauses of `INDEPENDENCE_NOTE` are required beside
   the count wherever it is published.
3. **The cluster layer L2-03 names does not exist.** No `deploy/k8s`. The single `NetworkPolicy` in
   the tree is `policyTypes: ["Ingress"]` on a `trust-core` pod selector — it restricts who may
   *reach* trust-core and says nothing about what any workload may reach. Both halves are asserted by
   `cluster_layer_absent` now rather than stated here: at `82118f8` this was prose with nothing behind
   it, and it was **false during a reviewer's run while every gate stayed green** (finding C2).
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
8. **`SecondaryFilter::from_operator_config` has no caller in the product.** **CORRECTED in part:**
   it had no fixture either, so the second engine's whole justification -- a source that did not read
   the signed claims -- was exercised by no test that opens a real file (finding T5).
   `the_second_engine_can_be_built_from_a_real_operator_file` now writes a policy to disk, builds the
   filter from it, asserts an allow and a deny through it, records the source as `operator_file`, and
   asserts that a **malformed** file refuses to build a filter rather than falling back to one that
   permits more. What is still true: nothing in the product calls it, and its remaining error variants
   are constructed only by that function.
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

Run at `M:/wt-g6-5.4`, a **detached** worktree of `feat/task-5.4-network-common-mode` at `950ab00`,
created from the shared checkout and never written to by hand. This capture supersedes the one taken
at `6864ec1`; the review-fix commits changed nine files and every number below was re-measured rather
than carried forward.

```text
$ cd M:/wt-g6-5.4 && git log --oneline -1
950ab00 docs(evidence): record the correction, because a task refuted twice must say what was wrong

### git status --porcelain
(empty, before and after every command below)

### git ls-files (every path a test or the gate opens)
README.md
deploy/spire/trust-domain-config.yaml
docs/05-network-common-mode-analysis.md
docs/W1-delivery-gaps.md
docs/task-evidence/task-5.4.md
evidence/invariants.json
evidence/network-independence.json
evidence/wiring-coverage.json
rust/egress-filter/src/lib.rs
rust/egress/src/lib.rs
rust/warrant/Cargo.toml
rust/warrant/src/egress.rs
rust/warrant/src/proxy.rs
rust/warrant/src/sandbox.rs
rust/warrant/tests/invariants/i09_failure_is_safe.rs
rust/warrant/tests/network_independence.rs
tools/ci/invariant-ratchet.json
tools/ci/network_independence.py
tools/ci/test_network_independence.py

### git check-ignore -v (all nineteen)
CHECK_IGNORE=1        # 1 = no rule matched any path

### cargo fmt --check
FMT=0

### cargo clippy --all-targets -- -D warnings
CLIPPY=0
0 lines matching '^error'

### cargo test --workspace -j 2        (exit captured BEFORE any pipe)
CARGO=0
suites: 145  passed: 1525  failed: 0  ignored: 20      # summed over every `test result:` line

### python tools/ci/wiring_census.py
wiring census: 12 of 40 crates reachable from warrantor-warrant over 21 path edges
CENSUS=0

### python tools/ci/check_invariant_ratchet.py
invariant ratchet: ok (85 passing at floor 85, 15 recorded findings at ceiling 15)
RATCHET=0

### python tools/ci/check_invariants.py
invariant ledger: 12 invariants; enforced=2, orphaned=1, partial=8, unimplemented=1
LEDGER=0

### python tools/ci/check_us_english.py main
us-english: 3723 added line(s) across 13 file(s), since main; matcher = vendored verify-us-english.mjs
us-english: ok
USEN=0

### python tools/ci/check_docs.py
RESULT: PASS - 268 Markdown files, 58 RFCs, 81 catalogue rows, and all local links validated
DOCS=0

### python tools/ci/network_independence.py
network independence: 1 independent intercept on a permitted destination; 6 shared axes of 8;
  1 policy engine decides in the product, 2 once an operator wires the second
NETIND=0

### python -m pytest tools/ci/test_network_independence.py tools/ci/test_wiring_census.py -q
  (run from rust/, exactly as CI invokes it)
42 passed
PYTEST=0
```

Two later commits existed when this was written (the one that pastes this capture into this file, and one that adds the fifteenth mutation row above); the branch has grown since -- see the commit tables in phases 1 and 3. Nothing outside this
markdown block changed, and `check_docs.py`, `check_us_english.py main` and
`network_independence.py` were re-run at that commit -- the three gates a markdown edit can move --
with identical output. `RUST_MIN_STACK=33554432` was exported for every cargo command: without it
`rustc` aborts compiling `syn` with `STATUS_STACK_BUFFER_OVERRUN` on this box, which is the known
Windows hazard and nothing to do with this branch.

### The gate was also seen red, deliberately

A gate that has only ever been green proves nothing. Two directions were captured when the task was
first written, and both still hold:

```text
$ # a stale rendered count in the README
::error::network independence: README.md: does not contain
  '| Independent network intercepts on a permitted destination | **1**'
GATE_WITH_STALE_README=1

$ # the second engine unwired -- a moved mechanism, not a different answer
::error::network independence: rust/warrant/Cargo.toml:
  'warrantor-egress-filter = { path = "../egress-filter"' is gone
  (policy_engine: the second evaluator is reachable from the product at all)
network independence: the mechanisms this record is derived from have moved. Re-read the sources
  and docs/05-network-common-mode-analysis.md before recording anything: a number whose
  derivation is stale is worse than no number.
GATE_WITH_UNWIRED_ENGINE=1
```

The second is the more important direction. A gate that recomputed a *fresh* number after its
derivation moved would keep publishing a measured-looking value that nothing supports; this one
refuses to publish at all.

**And fifteen more reds, one per surviving mutation**, in the CORRECTION section above. Those are the
ones that matter for this branch's second pass: seven of them were **exit 0 at `82118f8`**, which is
what "refuted" meant.

### Not pushed, not merged

Seven commits on `feat/task-5.4-network-common-mode` when this was written (twelve after phase 1,
twenty-one after phase 3), based on local `main` at `f9c3523`: four for
the task, and three for the adversarial-review correction -- the fix, the record of what was wrong,
and this capture. A human merges. Per [[merging parallel PRs safely]], rebase on the then-current `main` and re-run this gate
before merging — Task 1.2 is editing `rust/warrant/src/egress.rs`, which this branch also edits, and
PR CI tests the branch against the *old* main.

---

## Review lane, phase 1: rebased onto `main` at `065961b` (2026-09-06)

Everything above this line was measured on the branch as built, from local `main` at `f9c3523`.
This section is the review lane's own record: the branch brought onto today's `main`, the three
conflicts and how each was settled, and the full gate re-run on the rebased tree in worktree
`M:/wt-w3-5.4` with the shared target `M:/wt-review-shared-target`. Where a number below disagrees
with one above, the one below is the merged tree's and the one above is the branch's, and both are
correct for the tree they were read from.

**Branch:** `feat/task-5.4-network-common-mode` · **Was:** `289cc88` on `main` @ `f9c3523` ·
**Now:** rebased onto `main` @ `065961b` (45 commits ahead of the old base; see *main moved four times* below)
**Worktree:** `M:/wt-w3-5.4` · **Target dir:** `M:/wt-review-shared-target` (shared, `CARGO_BUILD_JOBS=2`)

**Commits, in order, after the rebase:**

| commit | was | what |
|---|---|---|
| `84d32c5` | `2905bd6` | the measurement, the second engine, the gate, the record, the analysis document |
| `7687e51` | `4aee0b5` | US-English on this branch's added lines |
| `a71d8ac` | `6864ec1` | the two egress notes asserted by value, because CRLF broke the source match |
| `55101de` | `82118f8` | the first fresh-worktree gate capture |
| `a9cea87` | `50ef8b9` | the review fix: label each count with the number it is true of |
| `408f8e7` | `950ab00` | the record of the twelve-finding refutation |
| `6557511` | `7281d93` | the second fresh-worktree gate capture |
| `e159068` | `289cc88` | the fifteenth mutation row |
| `16f12ea` | (new) | the four `proxy.rs` anchors the rebase moved, re-derived; the merged loop quoted |
| `cad254a` | (new) | the wiring record re-measured on the rebased tree: `edges` 22 → 23 |
| `60b8d4c` | (new) | this section, as first written against `main` @ `92b6018` |
| (this file) | (new) | this section brought onto `main` @ `065961b`; the gate re-run in full |

### The exit gate, quoted verbatim from the plan

`### Task 5.4`, the **Exit gate** paragraph:

> **Exit gate.** `python tools/ci/network_independence.py && cargo test -p warrantor-warrant --test network_independence -j 2 && python tools/ci/check_invariant_ratchet.py && python tools/ci/wiring_census.py` exits 0, with the ratchet line reading `invariant ratchet: ok (67 passing at floor 67, 19 recorded findings at ceiling 19)` and the census line reading `wiring census: 10 of 39 crates reachable`; any rendered independence count that does not match `evidence/network-independence.json` fails the first command by name.

**RUN.** The chain was run verbatim on the rebased tree (labeled HEAD `60b8d4c` when written; the transcript file was captured after `d36bddd` was committed, and the two trees differ only in this file, which the chain does not read -- **[corrected, phase 3]**, which re-runs the chain at the final tip), from the repository root
with the census invoked from `rust/` as CI does; the transcript is the block below, captured with
the exit code taken before any pipe. The first clause holds: the chain exits 0. The two literal
lines the plan predicts do **not** appear and cannot on any base after `e4b5f10`, because the plan
measured them on `origin/main` at `e4b5f10` and both numbers were overtaken before this branch was
cut (Deviations 1 and 2 above). The lines that do appear are the merged tree's own, read from the
output rather than predicted:

```text
$ python tools/ci/network_independence.py \
    && (cd rust && cargo test -p warrantor-warrant --test network_independence -j 2) \
    && python tools/ci/check_invariant_ratchet.py \
    && (cd rust && python ../tools/ci/wiring_census.py); echo "EXITGATE_EXIT=$?"
network independence: 1 independent intercept on a permitted destination; 6 shared axes of 8;
  1 policy engine decides in the product, 2 once an operator wires the second
network independence: ok
     Running tests\network_independence.rs
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
test result: ok. 85 passed; 0 failed; 15 ignored; 0 measured; 0 filtered out; finished in 0.41s
invariant ratchet: ok (85 passing at floor 85, 15 recorded findings at ceiling 15)
wiring census: 13 of 41 crates reachable from warrantor-warrant over 23 path edges
EXITGATE_EXIT=0
```

The third clause — a rendered count that disagrees with the record fails the first command by name
— was exercised on this tree by the rebase itself: `network_independence.py` exited 1 with four
`does not cite ... line N` errors the moment `main`'s `proxy.rs` changes moved the anchors, and went
green only after `16f12ea` re-derived them (**[corrected, phase 3]**: the first cut cited `0c342ab`, a pre-rebase hash that is not on the branch). That is the gate refusing a stale derivation, which is
the behavior the branch claims for it.

So: the plan's run is performed and its exit condition is met; its two predicted numbers are stale
predictions, not unmet conditions, and a ledger entry that cites this task should cite the lines
above, not the plan's.

### `main` moved four times while this lane ran

`main` was `92b6018` when the lane started and `065961b` when it finished, seven commits: `775bfeb`
(one Britishism in the 2.1 evidence -- omitted from the first cut of this list) and `9bac709` (the
plan and its expansions), `68272e6` + `b950b36` (the US-English gate refuses a dirty tree; Task 2.1's
evidence), `ed7c068` + `9292b03` (Britishisms on old lines of the delivery-gaps file), then `065961b`
(American English across thirty-two documents). The first rebase produced the three conflicts below;
the other three were conflict-free because their hunks did not overlap this branch's -- **not**
because the file sets were disjoint, which the first cut claimed: `ed7c068`, `9292b03` and `065961b`
all edit `docs/W1-delivery-gaps.md`, which this branch also edits (`comm -12` of the two `--name-only`
lists prints exactly that file). **[corrected, phase 3]**
**`rust/` on `main` is byte-identical from `9bac709` through `065961b`** (`git diff 9bac709 main
-- rust` is empty), so every cargo run in this section tested exactly the Rust tree that HEAD holds.
The non-cargo gates and the plan's exit-gate chain were re-run at the final HEAD; the full cargo gate
was run at bases `9bac709` and `9292b03` and not repeated for `065961b`, which changed no file cargo
reads. `wiring_census.py --write` on the final tree changed nothing. The lane checked
`git merge-base --is-ancestor main HEAD` last, so a fifth move after that check is possible and would
need another rebase before merge.

### The rebase: three conflicts, each settled by the rule for its kind

| file | kind | settled how |
|---|---|---|
| `.gitignore` | union | `main`'s two new un-ignore lines (`stop-*.json`, `conformance-*.json`) kept, and this branch's `network-independence.json` un-ignore appended after them |
| `README.md` | census artifact | `main`'s numbers taken for the census row (`13 of 41`, `28` orphaned) at each of the three commits that touched the row; this branch's prose tail on that row and its new "Independent network intercepts" row kept; then the record re-measured by `wiring_census.py --write` (`cad254a`; the first cut cited the pre-rebase hash `a7cabad`) |
| `rust/warrant/src/proxy.rs` | code, three hunks | **both behaviors kept.** `main`'s Task 2.1 fields (`vocabulary`, `pending`, `resolved_names`) and methods (`with_vocabulary`, `resolve_destinations`, `take_egress_decisions`) stand beside this branch's `secondary_refusals` field and `deny_secondary`. In `decide`, `main`'s `pending.push` of the broker's verdict runs first, the broker's `Deny` returns, and this branch's second engine runs after — the same order both sides had on their own |

Every test on both sides passes on the merged tree: `main`'s `egress_broker_wiring` (which drains
`take_egress_decisions`) and this branch's `network_independence` (15) and the three `i09` tests are
all in the 1565 below with `0 failed`.

**One interaction the merge creates, stated rather than left to be found.** `EgressDecision` is
defined as *"One broker decision"* and its `verdict` is *"The broker's verdict"*. On the merged tree
a call the second engine refuses therefore leaves an `Allow` row in `egress/<warrant>.jsonl` (the
broker allowed) beside its row in `Proxy::secondary_refusals` (the filter refused), and the endpoint
that drains one holds the other. That is consistent with the record's own definition and it does not
mislabel a tier, but a reader of the log alone would see a permitted destination that was not
forwarded. It cannot occur in a shipped run, because the shipped binary wires no secondary filter.
Recording the filter's reason in the log would mean putting a `warrantor_egress::DenyReason` on a
decision the broker did not make (Deviation 6), so nothing was changed; it is added to the
not-established list below and to `docs/05` beside the merged loop.

### A hazard of the shared target directory, and how it was kept out of this record

The first `cargo clippy` on the rebased tree failed with `missing fields causality and
predicate_version in initializer of warrantor_evidence::WarPredicate` — fields that exist in **no**
file of this worktree (`grep -rn predicate_version rust` finds nothing). Cargo hashes a path
dependency relative to the workspace root, so every `M:/wt-*` worktree shares one metadata hash for
`warrantor-evidence` in `M:/wt-review-shared-target`, and freshness is decided by mtime: a checkout
older than another lane's build looks fresh, and the other lane's rlib is linked. Every source file
under `rust/` was touched before each cargo step so that all 41 workspace crates were rebuilt from
this worktree; the clippy log shows 41 `Checking`/`Compiling` lines and no reuse. A green result
from an rlib compiled elsewhere would have been a false pass, and a red one from it — which is what
happened — is the only reason it was noticed.

### The shared target raced this gate once, and the failure it produced was not this tree's

The first full run on the final tree exited `TEST=101` and `DOC=1`. Two tests in
`rust/warrant/tests/instructions.rs` failed: the usage text of `warrantor.exe` named a `scorer`
command and `--asserted-by`, `--confined`, `--register-threshold` flags that the parser in this tree
does not accept. None of those strings exists in this worktree (`grep -rl` finds zero files); all
of them exist in Task 13.7's worktrees, and `M:/wt-review-shared-target/debug/warrantor.exe` had
been rewritten eighteen seconds before the check. That test runs `CARGO_BIN_EXE_warrantor`, which
is one path for every worktree sharing the target, so it compared another lane's binary against
this lane's source. The doc-test failure was the same race from the other side: `extern location
for warrantor_api does not exist: ...libwarrantor_api-cad523720e39a4c8.rlib`, an rlib another
lane's build replaced between two of this run's steps (`Blocking waiting for file lock` appears
three times in that log). Cargo stopped at the first failed test binary, so that run's sum (91
suites, 1096 passed, 2 failed, 4 ignored) is partial and is not the number recorded below.

Both were re-run from this worktree's sources after touching them: `--test instructions` 6 passed,
`--doc` 40 suites 1 passed, both exit 0. The whole `--all-targets` gate was then run twice more on
the same Rust tree, plain and with `--no-fail-fast`, and the same two tests failed both times on
the same foreign `scorer` binary (rewritten at 06:33:21 and 06:41:56, mid-run each time); every
other suite passed, and `--test instructions` alone passed again immediately after. The race is a
property of the shared target with seventy worktrees on it, not of this branch, and it can recur on
any lane's run: a lane that sees `instructions.rs` name a command its tree lacks should check the
binary's mtime before reading the failure as its own.

### The full gate on the rebased tree, exactly as measured

Guard before every cargo invocation: `disk guard: 292.4 GB free on M:\, require 60 GB -> OK` and
`15.4–16.2 GB of commit charge available, require 6 GB -> OK`. Every exit code was captured before
any pipe. `git status --porcelain` was empty before the gate and after every command.

```text
cargo fmt --all -- --check                                  FMT=0
cargo clippy --workspace --all-targets -- -D warnings       CLIPPY=0   (41 crates rebuilt here)
cargo test --workspace --all-targets   (base 9bac709, same rust/) CARGO=0
  120 suites, 1565 passed, 0 failed, 20 ignored             (summed over every `test result:` line)
cargo test --workspace --all-targets --no-fail-fast (base 9292b03) CARGO=101, the race above
  120 suites, 1563 passed, 2 failed, 20 ignored; the 2 are instructions.rs on a foreign binary,
  and `cargo test -p warrantor-warrant --test instructions` right after: 1 suite, 6 passed, exit 0
cargo test --workspace --doc           (bases 9bac709 and 9292b03) DOC=0
  40 suites, 1 passed, 0 failed, 0 ignored
  => 160 suites, 1566 passed, 0 failed, 20 ignored on the green run; the only run that did not
     exit 0 failed on two tests of another worktree's binary and on nothing in this tree
  network_independence: 15 passed          invariants corpus: 85 passed, 15 ignored
(cd rust && python ../tools/ci/wiring_census.py)            CENSUS=0
  wiring census: 13 of 41 crates reachable from warrantor-warrant over 23 path edges
python tools/ci/check_invariant_ratchet.py --show-findings  RATCHET=0
  invariant ratchet: ok (85 passing at floor 85, 15 recorded findings at ceiling 15)
  (its findings run prints `test result: FAILED. 1 passed; 14 failed` by design)
python tools/ci/check_invariants.py                         LEDGER=0
  invariant ledger: 12 invariants; enforced=2, orphaned=1, partial=8, unimplemented=1
python tools/ci/check_docs.py                               DOCS=0
  RESULT: PASS - 301 Markdown files, 58 RFCs, 81 catalogue rows, and all local links validated
python tools/ci/check_us_english.py main                    USEN=0
  us-english: ok
python tools/ci/network_independence.py                     NETIND=0   (red on the first rebase until the anchors were re-derived; green since)
  1 independent intercept on a permitted destination; 6 shared axes of 8;
  1 policy engine decides in the product, 2 once an operator wires the second
(cd rust && python -m pytest ../tools/ci/test_network_independence.py \
    ../tools/ci/test_wiring_census.py ../tools/ci/test_check_us_english.py -q)
                                                            PYTEST=0   54 passed
```

**Numbers that moved from the branch's own capture, and why.** Suites `145 → 160` and passing
`1525 → 1566`: the cargo run was on base `9bac709`, 40 commits past `f9c3523` (Task 2.1's decision log
among them; the first cut said 38, which is the count to `92b6018`, the base this section was first
written against -- 45 is the count to `065961b`; **[corrected, phase 3]**), and this gate ran `--all-targets`
plus `--doc` separately, so the two captures are not the same command; neither is wrong. Census
`12 of 40 → 13 of 41` and edges `21 → 23`: `main` added a crate and an edge; this branch's edge is
still exactly one of the 23, and orphans are `28` on both, so the count did not rise. Ratchet
`85 / 15`: unchanged, read from the merged corpus's own line — `main` is at `82`, this branch raises
it to `85`, and the merged corpus really has 85 passing. `docs` `268 → 301` files: `main`'s.

### The tier of every bound, on the merged tree

Unchanged from the "Bound strength" table above, and re-read against the merged `proxy.rs` rather
than carried forward. Each row states what escapes it, because a Tier B row without that sentence is
the defect this repository has shipped three times.

| bound | tier | what escapes it |
|---|---|---|
| `egress_hosts`, the broker | **Mediated** (Tier B) | any call that does not traverse the Warrantor MCP proxy: a shell command, a harness built-in, a socket the agent opens itself; and any hostname that resolves into a private or metadata range, because the broker does not resolve DNS |
| `egress_hosts`, the second engine (booked under `secondary_filter` since phase 3) | **Mediated** (Tier B), same point | exactly the same set — it runs inside the same `Proxy::decide` loop, after the broker, deny-only; it adds a policy domain and no place of refusal. In a shipped run it is not wired at all |
| the address floor (`hard_deny`) through either engine | **Mediated** (Tier B) | the same set again, plus: a defect in `hard_deny` escapes both engines at once, because both consult the one matcher |
| `--unshare-net` for an empty `egress_hosts` | **Enforced** (Tier A) — not created here, not observable here | nothing at the socket layer, if the operator launched the printed profile; everything, if they did not, and this process cannot tell which. Never present for a warrant that permits any host |
| the independence count | **Observed** | it refuses nothing; it is a measurement of the configuration |
| the egress decision log (`main`'s, now beside this branch's maps) | **Observed** | it records the broker's verdict after the fact; a secondary refusal is not in it, and no call is stopped by it |

### What this task does NOT establish (additions from the review lane)

Items 1–12 above stand. Added on the merged tree:

13. **The decision log does not record the second engine.** See the interaction paragraph above: an
    `Allow` row can stand in `egress/<warrant>.jsonl` for a call `secondary_refusals` shows refused.
    Cannot occur in a shipped run; can occur the day an operator wires the filter.
14. **This gate ran in the lane's worktree, on Windows, once.** Not a fresh detached checkout as the
    two captures above were, and not on Linux where CI runs. The tree was clean before and after every
    command, every path the tests open is tracked, and the CRLF fragility was retired at `a71d8ac` (the first cut cited the pre-rebase hash `86487dd`);
    but the `#[cfg(windows)]` blind spot memory records cuts the other way too — nothing here proves
    the Linux run.
15. **`edges: 23` is a count of manifest edges, not of calls.** The census reads `Cargo.toml`; it
    cannot see that the edge this branch adds is exercised only when a filter is present.

### Not pushed, not merged

Twelve commits on `feat/task-5.4-network-common-mode` at the end of phase 1 (twenty-one after phase 3),
now on `main` @ `065961b`. Nothing was pushed, nothing was merged, and this lane wrote to no other
worktree. (The converse did not hold: during the second review another session wrote into *this*
worktree -- see phase 3, finding E7.) A human merges, one branch at a
time, per [[merging parallel PRs safely]].

---

## Review lane, phase 3: corrections after the second adversarial review (2026-09-06)

Three adversarial lenses reviewed the phase-1 tip `d36bddd`: claim-honesty (six findings), test-rigor
by mutation (seven findings) and evidence-truth (seven findings). Two of the twenty are the same
defect seen from two sides (the Rust cross-check that did not exist), and two more overlap (the
pre-rebase hashes), so the section below closes **eighteen distinct findings**. Every one was
reproduced at `d36bddd` with the reviewer's own command before anything was changed; the four
surviving cargo mutations were re-applied to the clean tip in this lane's own target directory
(`M:/wt-rv-5.4-target`, `-j 2`, disk guard before each) and each recompiled `warrantor-warrant` and
exited 0 -- **four reproductions, four survivors**, files restored byte-identical. Nothing was
disputed outright; one reviewer statement was found to understate the defect and one to misread a
sentence, and both are recorded under the finding rather than argued with.

**What the review established, again:** the figures were right and the words were wrong. The
intercept count, the engine count in the product, the census, the ratchet and every gate output
reproduced. What failed was a constant that stated a number true of a configuration the product does
not run, a comment naming a test that did not exist, a bound label naming the bound that had just
permitted the destination, four documented properties no test constrained, one vacuous derivation,
one ungated tier word, and six numbers or hashes in this file that were carried instead of measured.

**Commits, in order, on top of `d36bddd`** (identity from env vars, `git commit -s`, no push):

| commit | finding(s) | what |
|---|---|---|
| `a6c469a` | C1, R7 | `INDEPENDENCE_NOTE` names no engine count; `docs/05`'s paragraph is required to BE the constant; the escape clause is asserted by value in Rust |
| `3f9e224` | C2 = T6 | `the_gate_agrees_with_the_rust_answer` exists and reads the record; the record publishes the shared axes per configuration (7 in the product, 6 once wired) |
| `1042600` | C4 | a second-engine refusal is booked under `secondary_filter`, printed naming the engine, and written down with destination and rule |
| `eb77bcc` | (C4 follow-up), C7-anchor | the four `proxy.rs` anchors the previous commit moved, and the stale `lib.rs` anchor, re-derived -- the gate refused the tree until they were |
| `969dca2` | Y7 | the egress tier word `docs/05` cites is in the citation needle, so `Enforced` on the page fails the build |
| `3c91d86` | P2 | the broker-before-second-engine order is asserted where both engines would refuse |
| `69fab3d` | R5, R6 | `normalized` is asserted against the engine's own decision; an absent operator file is `Err(Unreadable)` |
| `eabdc71` | Y2, C5 | an empty product scan is refused; the configuration source is read off the constructor; "an operator wires" withdrawn, field renamed `policy_engines_once_the_second_is_wired` |
| (this file) | C3, C6, E1-E7 | every evidence correction below, and the regate on the final tip |

### Every finding, reproduced and closed

Identifiers: **C** claim-honesty, **T/P/R/Y** test-rigor (the reviewer's own mutation labels),
**E** evidence-truth. "Reproduced" is the command that showed it at `d36bddd`; "closed" is what
changed and where.

| # | claimed | true, as reproduced | closed |
|---|---|---|---|
| **C1** false-claim | `INDEPENDENCE_NOTE` "carries only the clauses that hold in every configuration" and is "printed under the count on every surface"; its value: "Two policy engines decide at that one point"; `docs/05` line 30 "through **both** engines", section 6 "Two policy engines decide" | `Proxy::new` sets `secondary: None`; `grep -c SecondaryFilter rust/warrant/src/bin/warrantor.rs` = 0; the record publishes `policy_engines_the_product_runs: 1`; no product code references the constant (grep: only tests and two doc comments). The T7 correction reached README, W1 and the record and never reached the constant or `docs/05` | `a6c469a`: the constant names no count and no engine plurality (asserted: no digit, none of seven spelled-out counts); its doc says where it is *required* (three render targets, twelve lines) instead of where it is printed (nowhere). `docs/05` sections 1 and 5 state that a shipped run decides with one engine, and its section-6 paragraph is now required to be the constant's value by `analysis_paragraph_is_the_constant`, which reads the literal out of `egress.rs` and joins the continuations |
| **C2 = T6** false-claim | `network_independence.py:113`: "`the_gate_agrees_with_the_rust_answer` in the Rust suite is what keeps the two from drifting"; `egress.rs:574`: "the function the machine-readable record and the drills both read" | `grep -rn the_gate_agrees_with_the_rust_answer` found only the comment. The record is written from the Python `SHARED` literal and a hardcoded `intercepts=1`; flipping `clock` to `False` and running `--write` produced a publishable record disagreeing with `independence()` with nothing red | `3f9e224`: the test exists, reads `evidence/network-independence.json` and asserts every field against `independence()` for the product, the wired and the empty-bound configurations. Writing it exposed that the record's one `shared_axes` list was the *wired* answer (6 of 8) beside a *product* engine count (1); the record now carries `shared_axes_the_product_runs` (7) and `shared_axes_once_the_second_is_wired` (6). W1's "six of the eight ... only `credential` is not" (six shared, one not, of eight) states both configurations. Proof: `clock` flipped + `--write` -> `the_gate_agrees_with_the_rust_answer ... FAILED`, 15 passed, 1 failed, exit 101; Python and record restored byte-identical |
| **C3** number-mismatch | `d36bddd`: "brings every SHA in the section onto main"; `0c342ab`, `a7cabad`, `86487dd` cited; "Two later commits exist"; "Seven commits"; chain "run at HEAD d36bddd" (record) vs "HEAD `60b8d4c`" (file) | `git merge-base --is-ancestor` -> not-in-branch for all three (their rebased forms are `16f12ea`, `cad254a`, `a71d8ac`); `git diff --stat 60b8d4c d36bddd` touches only this file | this file: the three hashes replaced with the ones on the branch, each marked; the two commit counts dated; the HEAD label corrected and the chain re-run at the final tip below |
| **C4** minor | `deny_secondary`: "The bound label is still `egress_hosts`: it names the bound that refused" | the warrant's `egress_hosts` bound *permitted* the host: the broker returned `Allow` and `egress_refusals()` is empty (the suite's own assertion). The CLI printed `denied <tool> xN (egress_hosts)`. **The reviewer's "and persists that request" understated it:** `record_refusals` drops `egress_hosts` authority requests on purpose (the broker's refusals are written from `EgressRefusal`), and a second-engine refusal has no `EgressRefusal`, so it was written down **nowhere** | `1042600`: `proxy::SECONDARY_FILTER_BOUND` = `"secondary_filter"`; `serve::record_secondary_refusals` writes each one as an `Egress` record under that bound with destination, argument and the engine's own rule; `AgentEndpoint::secondary_refusals`; the CLI records and prints them naming the engine. Test: in-memory label beside the broker's control, then `record_refusals` writes 0 for the session and `record_secondary_refusals` writes 1, read back. Latent in every shipped run |
| **C5** minor | `egress.rs:297`: "the gate publishes the second source"; README/record: "two decide once an operator wires the second" | `measure()` hardcoded `operator_file` for any product `.with_secondary_filter(`; a wiring from `default_deny()` would be published as reading a file it never opened. No operator can wire it: no CLI flag, no config path, no product caller of `from_operator_config` (`grep -c` = 0) | `eabdc71`: the source is read off the constructor the wiring file calls (three constructors, mirroring `SecondarySource::as_str`); a wiring with none or two is refused, not guessed. Field renamed `policy_engines_once_the_second_is_wired`; the gate line, the record's note, README and W1 say "once a caller of the library wires the second (no CLI flag or configuration path reaches it today)" |
| **C6** minor | this file: clauses "required ... on every surface that publishes it" | `RENDER_TARGETS` names three files; this file publishes the count on five lines and is not one of them; its line 12 sits two hundred lines from the clauses | this file: the sentence names the three render targets and says this file is not one. Not made a render target: an evidence file transcribes gate output, and requiring the caveat beside every transcript line would gate the transcript rather than the claim. `docs/05` and the constant's doc say the same |
| **P2** untested | "the broker's arm above returns before this runs" | the only attribution test wired a filter that *allowed* the outside host; moving the second engine ahead of the broker left three suites green twice. Reproduced here: `MUTATION P2: exit=0` on the clean tip | `3c91d86`: a test where both engines would refuse (warrant permits one host, default-deny filter, call to a host outside the warrant) asserts the warrant's bound refused, the broker's map holds it, the second engine's map is empty, and the agent's sentence names no engine that did not decide; then the permitted-host control on the same proxy. Under the mutation: 18 passed, 2 failed, exit 101 |
| **R5** untested | `normalized`: "the form the filter actually decided against, which makes a normalization bypass visible" | no test read the field; `String::new()` left both suites green. Reproduced: `exit=0` | `69fab3d`: `API.GitHub.COM.` is placed in the warrant bound (the broker matches the bound verbatim and never normalizes, so the odd form has to be permitted to reach the second engine -- noted in the test), and the recorded form must equal the engine's own `decide(odd).normalized` and differ from the destination as named. Under the mutation: `assertion left == right failed`, 19 passed, 1 failed, exit 101 |
| **R6** untested | `SecondaryConfigError`: "never a silent fallback"; `from_operator_config`: a missing file "is **not** an error to be swallowed" | only `Malformed` was asserted; `return Ok(Self::default_deny())` for an unreadable path left both suites green. Reproduced: `exit=0` | `69fab3d`: an absent path must be `Err(Unreadable { path })` naming the file, and the rendered error must carry the path. Under the mutation: 18 passed, 2 failed, exit 101 |
| **R7** untested | the constant "is the bounding sentence for a Mediated bound"; Task 0.4 requires the escape clause | six clauses were pinned in Rust, not "passes neither"; `passes through both` left both suites green. Reproduced: `exit=0` | `a6c469a`: the escape clause is asserted by value in `network_independence.rs` and in the I-09 corpus. Under the mutation (re-pointed at the new wording): `the_notes_refuse_to_imply_a_second_boundary ... FAILED`, 84 passed, 1 failed, exit 101 |
| **Y2** vacuous | `engines_the_product_runs`: "Derived now, from the product sources alone" | with `product_sources()` returning `[]` the gate printed the good answer and all 30 pytest cases passed. Reproduced: `exit=0`, `30 passed` | `eabdc71`: `wiring_sources()` refuses an empty scan and a scan that did not include `rust/warrant/src/proxy.rs`; `main()` reports the refusal by name and exits 1. Under the mutation: `::error::network independence: the product-source scan found no Rust files`, exit 1, pytest 7 failed |
| **Y7** untested | `docs/05` line 162 cites `("egress_hosts", BoundStrength::Mediated)` at `lib.rs` line 692 | `Enforced` on the page passed the gate, `check_invariants.py`, `check_docs.py` and pytest. Reproduced: `exit=0`. And line 692 is the `write_paths` arm; the egress arm is 695 | `969dca2` (+ `eb77bcc`): the tier word is in the citation needle; the page must cite the word the source holds at the line it is on. Under the mutation: exit 1 naming `lib.rs` line 695; pytest 4 failed |
| **E1** false-claim | "the other three were conflict-free, because none of those commits touches a file this branch touches" | `comm -12` of `git diff --name-only 92b6018..065961b` and `main..HEAD` prints `docs/W1-delivery-gaps.md` | this file: conflict-free because the hunks did not overlap, and the shared file is named |
| **E2** number-mismatch | "main gained 38 commits" | `f9c3523..92b6018` = 38, `..9bac709` = 40 (the cargo run's base), `..065961b` = 45 | this file: 40, with the other two counts and what each is the count of |
| **E3** minor | the seven commits `92b6018..065961b` listed as six | `git log --oneline 92b6018..065961b` has 7; `775bfeb` was missing | this file: listed |
| **E4** minor | three hashes not on the branch | same as C3 | same as C3 |
| **E5** minor | chain transcript labeled HEAD `60b8d4c` | the log's mtime (06:46:13) is after `d36bddd` (06:44:50); the trees differ only in this file | this file: the label corrected; the chain re-run at the final tip below |
| **E6** minor | the `INDEPENDENCE_NOTE` blockquote "byte-verbatim" | backticks around `--unshare-net` that the constant does not carry | this file: re-quoted from the final constant, no backticks; `docs/05`'s copy is now gated against the constant so a Markdown paraphrase cannot recur there |
| **E7** untested | this file: "no other worktree was written to" | **the sentence describes this lane's writes and stays true; the reviewer read it as a claim about others' writes, which it never was.** The hazard behind the reading is real: at 07:55:26 another session changed `"policy_engine" => secondary.is_none()` to `=> true` in *this* worktree's `egress.rs` while the reviewer's cargo run was compiling -- the shape of a test-rigor mutation from another session on the same worktree ([[concurrent session hazard]]). It was restored and the tree sha-matched the baseline afterward | nothing in code. This file records it, and the regate below was bracketed by a sha256 of every tracked file except this one, before and after, so a foreign write during the run would have been named rather than absorbed |

**Two things found while closing, not in any finding.** (1) `docs/05` cited `lib.rs` line 692 for
the egress tier arm; the arm is on 695 and 692 is `write_paths`. The claim-honesty lens had marked
that anchor verified. (2) The broker matches the warrant bound verbatim and never normalizes: a call
naming `API.GitHub.COM.` under a bound of `api.github.com` is refused as `NotInCatalog`. That refuses
in the safe direction and is not changed here; the R5 test records it.

### The mutation table at the final tip

Every row was run at `the final tip` in this lane's target directory after the full gate below, by the
same runner (`mutate.py`: one byte-exact replacement, the command, restore, sha256 compared). The
cargo rows run `cargo test -p warrantor-warrant --test network_independence --test invariants -j 2
--no-fail-fast`; every one recompiled `warrantor-warrant`.

```text
MUTATION P2: exit=101 restored=identical sha256=2c4e515e40b7
    test result: ok. 85 passed; 0 failed; 15 ignored; 0 measured; 0 filtered out; finished in 0.70s
    test the_broker_decides_before_the_second_engine_so_a_refusal_is_attributed_to_the_engine_that_made_it ... FAILED
    test a_second_engine_refusal_is_attributed_to_the_engine_in_memory_and_on_disk ... FAILED
    test result: FAILED. 18 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
MUTATION R5: exit=101 restored=identical sha256=fa0a76c25eb0
    test result: ok. 85 passed; 0 failed; 15 ignored; 0 measured; 0 filtered out; finished in 0.52s
    test the_normalized_form_travels_with_the_refusal_and_is_the_form_the_engine_decided_against ... FAILED
    test result: FAILED. 19 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
MUTATION R6: exit=101 restored=identical sha256=fa0a76c25eb0
    test result: ok. 85 passed; 0 failed; 15 ignored; 0 measured; 0 filtered out; finished in 0.52s
    test an_unreadable_operator_file_is_a_refusal_to_build_a_filter_and_not_a_silent_default ... FAILED
    test result: FAILED. 19 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
MUTATION R7: exit=101 restored=identical sha256=fa0a76c25eb0
    test i09_failure_is_safe::the_notes_refuse_to_imply_a_second_boundary ... FAILED
    test result: FAILED. 84 passed; 1 failed; 15 ignored; 0 measured; 0 filtered out; finished in 0.53s
    test the_note_names_all_three_absent_enforcement_mechanisms ... FAILED
    test result: FAILED. 19 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
MUTATION P3b: exit=101 restored=identical sha256=2c4e515e40b7
    test result: ok. 85 passed; 0 failed; 15 ignored; 0 measured; 0 filtered out; finished in 0.49s
    test a_second_engine_refusal_is_attributed_to_the_engine_in_memory_and_on_disk ... FAILED
    test the_rendered_rule_is_the_engine_s_own_reason_and_not_one_literal ... FAILED
    test through_the_proxy_the_second_engine_narrows_what_the_warrant_permitted ... FAILED
    test the_normalized_form_travels_with_the_refusal_and_is_the_form_the_engine_decided_against ... FAILED
    test result: FAILED. 16 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
MUTATION Y2: exit=1 restored=identical sha256=33e382c6e3d6
    ::error::network independence: the product-source scan found no Rust files under rust/*/src; the engine count cannot be derived from nothing and is not publ
    FAILED tools/ci/test_network_independence.py::test_the_real_repository_passes_the_gate
    FAILED tools/ci/test_network_independence.py::test_the_recorded_measurement_is_the_measured_one
    FAILED tools/ci/test_network_independence.py::test_the_engine_count_the_product_runs_is_derived_from_the_product_sources
    FAILED tools/ci/test_network_independence.py::test_write_then_gate_round_trips
    FAILED tools/ci/test_network_independence.py::test_a_tampered_record_field_fails_the_gate
    FAILED tools/ci/test_network_independence.py::test_measure_is_a_pure_function_of_the_sources
    ::error::network independence: the product-source scan found no Rust files under rust/*/src; the engine count cannot be derived from nothing and is not publ
MUTATION Y7: exit=1 restored=identical sha256=324734dc6b5f
    ::error::network independence: docs/05-network-common-mode-analysis.md: does not cite rust/warrant/src/lib.rs line 695 for '("egress_hosts", BoundStrength::
    ::error::network independence: docs/05-network-common-mode-analysis.md: does not cite rust/warrant/src/lib.rs line 695 for '("egress_hosts", BoundStrength::
    FAILED tools/ci/test_network_independence.py::test_the_real_repository_passes_the_gate
    FAILED tools/ci/test_network_independence.py::test_every_citation_anchor_resolves_in_the_real_tree
    FAILED tools/ci/test_network_independence.py::test_the_egress_tier_word_the_analysis_cites_is_derived_from_the_source
    FAILED tools/ci/test_network_independence.py::test_write_then_gate_round_trips
    ::error::network independence: docs/05-network-common-mode-analysis.md: does not cite rust/warrant/src/lib.rs line 695 for '("egress_hosts", BoundStrength::
MUTATION D1: exit=1 restored=identical sha256=324734dc6b5f
    ::error::network independence: docs/05-network-common-mode-analysis.md: the paragraph it calls egress::INDEPENDENCE_NOTE is not the constant's value. Expect
MUTATION M2: exit=0 restored=identical sha256=33e382c6e3d6
    test the_gate_agrees_with_the_rust_answer ... FAILED
    test result: FAILED. 19 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
evidence/network-independence.json: OK
STATUS_END=[]
```

### The full gate on the final tip, exactly as measured

Worktree `M:/wt-w3-5.4`, target `M:/wt-rv-5.4-target` (this lane's alone), `CARGO_BUILD_JOBS=2`,
`disk_guard.py --require 100 && --require-commit 6` before every cargo invocation (all OK; the
lowest reading across both runs was 9.1 GB of commit charge). Every exit code captured before any pipe. `git status --porcelain`
was empty before the gate and after it (this file excepted, which cargo does not read). The cargo
gate ran at the code tip `eabdc71`, and the commit that adds this section changes only this file, so `git diff eabdc71 HEAD -- rust tools evidence README.md docs/05-network-common-mode-analysis.md docs/W1-delivery-gaps.md` is empty at the final tip: the cargo gate tested exactly the tree the final tip holds outside this file. The non-cargo gates were run again on the final tree with this file in place, and their lines are the ones below.

```text
cargo fmt --all -- --check                                  FMT=0
cargo clippy --workspace --all-targets -- -D warnings       CLIPPY=0
cargo test --workspace --all-targets                        CARGO=0
  120 suites, 1570 passed, 0 failed, 20 ignored   (summed over every `test result:` line)
cargo test --workspace --doc                                DOC=0
  40 suites, 1 passed, 0 failed, 0 ignored
  => 160 suites, 1571 passed, 0 failed, 20 ignored
  network_independence: 20 passed          invariants corpus: 85 passed, 15 ignored
(cd rust && python ../tools/ci/wiring_census.py)            CENSUS=0
  wiring census: 13 of 41 crates reachable from warrantor-warrant over 23 path edges
python tools/ci/check_invariant_ratchet.py --show-findings  RATCHET=0
  invariant ratchet: ok (85 passing at floor 85, 15 recorded findings at ceiling 15)
  (its findings run prints `test result: FAILED. 1 passed; 14 failed` by design)
python tools/ci/check_invariants.py                         LEDGER=0
  invariant ledger: 12 invariants; enforced=2, orphaned=1, partial=8, unimplemented=1
python tools/ci/check_docs.py                               DOCS=0
  RESULT: PASS - 301 Markdown files, 58 RFCs, 81 catalogue rows, and all local links validated
python tools/ci/check_us_english.py main                    USEN=0   (at eabdc71, before this file changed)
  us-english: 4858 added line(s) across 16 file(s), since main; matcher = vendored verify-us-english.mjs
python tools/ci/check_us_english.py --files docs/task-evidence/task-5.4.md   (this file, every line, before commit)
  us-english: ok
  (the main-mode run at the final tip cannot be quoted by the commit it measures; it is in the LANE_STATUS record)
python tools/ci/network_independence.py                     NETIND=0
  network independence: 1 independent intercept on a permitted destination; 7 shared axes of 8 in the product, 6 once the second engine is wired; 1 policy engine decides in the product, 2 once a caller of the library wires the second (no CLI flag or configuration path reaches it today)
(cd rust && python -m pytest ../tools/ci/test_network_independence.py \
    ../tools/ci/test_wiring_census.py ../tools/ci/test_check_us_english.py -q)
                                                            PYTEST=0   61 passed in 43.98s
```

Tracked-tree checksum before and after the cargo gate (every tracked file except this one):
`TRACKED_TREE_UNCHANGED_DURING_GATE` on the first run, `TRACKED_TREE_UNCHANGED_DURING_GATE` on the second.

**The first `cargo test --workspace --all-targets` on this tip exited 101 and is not the number
above.** It stopped at suite 74 (831 passed, 1 failed, 4 ignored, fail-fast) on
`supervise::tests::job_object_kills_the_child_tree_when_the_supervisor_drops` in
`warrantor-warrant --lib`: *"ping ... (grandchild) survived the job handle closing"* -- a
`#[cfg(windows)]` job-object test with a five-second budget, in a file this branch does not touch
(`git diff main..HEAD -- rust/warrant/src/supervise.rs` is empty), which passed in phase 1's run and
which CI never executes ([[windows rust paths are ungated]]). Run alone immediately afterward it
exited 0 both times (`LIB_ALONE_1=0`, `LIB_ALONE_2=0`), and the whole workspace was then re-run with `--no-fail-fast`; the sums
above are that second run's, and its `--doc` run is the second one too. The box was carrying this
lane's cargo plus at least one other lane's during the first run (commit charge read as low as
9.1 GB at a guard), which is the environment that test's budget is sensitive to. It is
reported here rather than absorbed: a lane that sees it should check the box's load before reading
it as its own.

**Numbers that moved from phase 1, and why.** `network_independence` suite `15 -> 20`: five
tests added (the cross-check, the order, the normalized form, the unreadable file, the durable
record). Passing `1566 -> 1571`: those five and nothing removed. pytest `54 -> 61`: seven
cases added to `test_network_independence.py` (the constant read from source, the paragraph gated
both ways, the tier word, the constructor-derived source, the refused wiring, the refused empty scan).
Ratchet `85 / 15`: unchanged, because the new Rust tests live in `network_independence.rs`, not the
I-09 corpus; the corpus gained assertions, not tests. Census `13 of 41 / 23 edges`: unchanged, no
manifest touched. Gate line: `7 shared axes of 8 in the product, 6 once the second engine is wired`
replaces `6 shared axes of 8`, for the reason under C2.

### The exit gate, re-run verbatim at `the final tip`

```text
network independence: 1 independent intercept on a permitted destination; 7 shared axes of 8 in the product, 6 once the second engine is wired; 1 policy engine decides in the product, 2 once a caller of the library wires the second (no CLI flag or configuration path reaches it today)
network independence: ok
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.45s
     Running tests\network_independence.rs (M:/wt-rv-5.4-target\debug\deps\network_independence-cbfc73113ec1a119.exe)

running 20 tests
test a_no_egress_warrant_is_the_only_two_layer_case_and_it_guards_nothing ... ok
test a_repeated_refusal_is_counted_and_the_most_frequent_is_reported_first ... ok
test drill_two_layer_b_removed_and_layer_a_must_still_refuse ... ok
test drill_one_layer_a_removed_and_something_else_must_still_refuse ... ok
test the_axes_are_asserted_not_described ... ok
test the_broker_decides_before_the_second_engine_so_a_refusal_is_attributed_to_the_engine_that_made_it ... ok
test the_count_sentence_labels_each_number_with_the_field_it_came_from ... ok
test the_normalized_form_travels_with_the_refusal_and_is_the_form_the_engine_decided_against ... ok
test the_gate_agrees_with_the_rust_answer ... ok
test the_measurement_records_which_configuration_source_each_engine_read ... ok
test the_note_names_all_three_absent_enforcement_mechanisms ... ok
test the_proxy_reports_the_independence_of_the_configuration_it_is_actually_running ... ok
test the_rendered_rule_is_the_engine_s_own_reason_and_not_one_literal ... ok
test the_second_engine_allows_what_the_operator_permitted ... ok
test an_unreadable_operator_file_is_a_refusal_to_build_a_filter_and_not_a_silent_default ... ok
test the_second_engine_can_never_overturn_the_broker ... ok
test through_the_proxy_the_second_engine_narrows_what_the_warrant_permitted ... ok
test through_the_proxy_the_second_engine_cannot_overturn_the_broker ... ok
test the_second_engine_can_be_built_from_a_real_operator_file ... ok
test a_second_engine_refusal_is_attributed_to_the_engine_in_memory_and_on_disk ... ok

test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s


running 100 tests
test adversary::every_finding_names_the_task_that_closes_it_and_no_finding_claims_a_refusal ... ok
test adversary::the_module_doc_states_the_number_of_strategies_this_suite_actually_has ... ok
test fixture::every_invariant_has_a_suite_module ... ok
test i01_active_identity::the_local_subject_is_an_issued_identity_rather_than_a_constant ... ignored, I-01 currently violated: the CLI subject is a hardcoded constant, not an issued SVID (Task 3.1, 2026-09-02)
test i01_active_identity::an_absent_svid_is_refused ... ok
test i01_active_identity::an_expired_svid_cannot_carry_an_otherwise_valid_action ... ok
test adversary::every_strategy_has_a_test_that_exists ... ok
test fixture::statements_match_the_architecture_doc ... ok
test i01_active_identity::the_identity_gate_is_declared_against_this_invariant ... ok
test i03_purpose_bound_data_use::hop_02_a_shared_cache_read_for_another_purpose_is_refused ... ignored, I-03 unimplemented: bounds carry no purpose, so hop 2 is invisible to the boundary (2026-09-02)
test i03_purpose_bound_data_use::hop_10_the_receipt_labels_the_provenance_of_what_drove_the_action ... ignored, I-03 unimplemented: receipts carry no provenance label for what drove the action (Task 2.6, 2026-09-02)
test i03_purpose_bound_data_use::the_authorization_request_carries_a_purpose ... ignored, I-03 unimplemented: no purpose field on the authorization request; no plan task fixes it (2026-09-02)
test i03_purpose_bound_data_use::the_receipt_carries_the_purpose_the_data_was_tagged_with ... ignored, I-03 unimplemented: the WAR predicate has no purpose field (2026-09-02)
test i01_active_identity::the_products_own_notary_call_consults_a_revocation_source ... ok
test i01_active_identity::hop_09_a_reused_third_party_credential_is_refused_at_the_identity_gate ... ok
test i03_purpose_bound_data_use::the_notary_has_no_purpose_gate_and_does_not_pretend_to ... ok
test i04_current_policy::a_policy_denial_refuses_the_action ... ok
test i04_current_policy::a_policy_that_changes_after_the_start_check_denies_at_the_second_evaluation ... ok
test i04_current_policy::the_post_commit_receipt_records_its_own_policy_evaluation ... ignored, I-04 partial: post-commit receipts copy the pre-commit decision block, so no commit-time evaluation is provable (Task 2.3, 2026-09-02)
test i02_no_authority_expansion::a_capability_dropped_by_one_link_cannot_be_exercised ... ok
test i04_current_policy::the_product_evaluates_policy_more_than_once_per_action ... ignored, I-04 partial: one notary call per action, so policy is never re-evaluated at commit (Task 2.3, 2026-09-02)
test i04_current_policy::an_indeterminate_policy_is_a_denial_rather_than_a_pass ... ok
test i05_bounded_revocation_latency::a_revocation_is_effective_within_the_decision_that_sees_it ... ok
test i02_no_authority_expansion::a_forged_intersection_proof_is_refused_even_when_the_capability_set_is_honest ... ok
test adversary::the_findings_are_exactly_the_strategies_the_delivery_gaps_document_names ... ok
test i04_current_policy::the_policy_gate_is_declared_as_evaluated_now ... ok
test i05_bounded_revocation_latency::a_revocation_landing_between_the_start_check_and_the_commit_stops_the_commit ... ok
test i05_bounded_revocation_latency::hop_05_the_product_links_a_credential_vault_that_can_revoke ... ok
test i06_exact_artifact_identity::an_unverified_digest_is_refused ... ok
test i02_no_authority_expansion::the_chain_intersects_rather_than_unions ... ok
test i02_no_authority_expansion::both_implementations_name_this_invariant_in_their_refusal ... ok
test i02_no_authority_expansion::hop_06_a_forged_admin_token_does_not_survive_receipt_verification ... ok
test i06_exact_artifact_identity::a_requester_cannot_vouch_for_its_own_artifact ... ok
test i06_exact_artifact_identity::the_product_submits_artifacts_to_the_artifacts_gate ... ignored, I-06 partial: the product supplies no artifacts and no verified set, so the gate never fires (Task 2.2 / Task 2.4, 2026-09-02)
test i05_bounded_revocation_latency::the_credential_revocation_budget_is_declared_as_one_second ... ok
test i03_purpose_bound_data_use::hop_03_a_directory_name_channel_is_invisible_to_the_egress_boundary ... ok
test i05_bounded_revocation_latency::a_revocation_source_exists_for_the_identity_half ... ok
test i02_no_authority_expansion::the_intersection_proof_is_recomputable_by_a_stranger ... ok
test i02_no_authority_expansion::the_two_intersection_implementations_still_agree ... ok
test i08_non_delegable_human_authority::an_approval_names_the_human_who_gave_it ... ignored, I-08 partial: an approval carries no approver identity, so humanness is unrepresentable (Task 3.3, 2026-09-02)
test i06_exact_artifact_identity::the_artifacts_gate_is_declared_against_this_invariant ... ok
test i06_exact_artifact_identity::hop_08_a_substituted_plugin_body_is_refused_at_the_artifacts_gate ... ok
test adversary::the_documents_ordinal_for_the_next_ignore_is_read_from_the_ratchet_and_not_from_the_plan ... ok
test i07_evidence_precedes_commitment::the_commit_gate_names_this_invariant_in_its_refusal ... ok
test i08_non_delegable_human_authority::an_invalid_approval_does_not_satisfy_the_gate ... ok
test i08_non_delegable_human_authority::the_envelope_validator_checks_more_than_the_presence_of_an_approval ... ignored, I-08 partial: authority-spec accepts any non-empty approvals list (Task 3.3 / Task 4.1, 2026-09-02)
test i08_non_delegable_human_authority::an_approval_that_was_itself_delegated_does_not_satisfy_the_gate ... ok
test i08_non_delegable_human_authority::a_critical_action_with_no_approval_is_refused ... ok
test adversary::substitution::a4_the_product_context_allows_a_verbatim_replay ... ok
test i07_evidence_precedes_commitment::the_parent_receipt_field_is_the_proof_of_ordering ... ok
test i08_non_delegable_human_authority::the_consequential_classes_are_the_ones_the_invariant_names ... ok
test i09_failure_is_safe::an_unavailable_catalog_denies_rather_than_permits ... ok
test i09_failure_is_safe::an_undeclared_budget_is_a_ceiling_of_zero_rather_than_unlimited ... ok
test i09_failure_is_safe::an_empty_egress_allowlist_permits_nothing_rather_than_everything ... ok
test i09_failure_is_safe::hop_01_an_impossible_task_fails_closed_rather_than_finding_a_route ... ok
test i09_failure_is_safe::a_name_that_encodes_the_metadata_address_passes_both_engines_because_neither_resolves_dns ... ok
test i09_failure_is_safe::the_product_links_the_preflight_that_refuses_an_unmeasured_boundary ... ignored, I-09 orphaned: eval-guard's fail-closed preflight is not linked by the warrantor binary (2026-09-02)
test i05_bounded_revocation_latency::the_receipt_proves_which_action_the_revocation_stopped ... ok
test i10_replay_is_detectable::the_product_remembers_the_nonces_it_has_already_seen ... ignored, I-10 partial: seen_nonces is hardcoded empty in report.rs, so no replay is detectable (Task 1.1 / Task 3.4, 2026-09-02)
test i09_failure_is_safe::the_notes_refuse_to_imply_a_second_boundary ... ok
test i09_failure_is_safe::the_only_second_layer_is_emitted_exactly_when_no_destination_is_permitted ... ok
test i10_replay_is_detectable::the_freshness_gate_is_declared_against_this_invariant ... ok
test i11_self_change_is_governed::every_denial_reason_the_broker_renders_can_actually_be_reached ... ignored, I-11 unimplemented at the broker: three DenyReason variants are rendered and never constructed (Task 2.5, 2026-09-02)
test i11_self_change_is_governed::hop_04_a_redirect_out_of_the_resolved_set_is_refused ... ignored, I-11 unimplemented: the broker cannot observe a redirect, so hop 4 has no boundary (Task 2.5 / Task 5.2, 2026-09-02)
test i11_self_change_is_governed::a_child_warrant_cannot_widen_the_bounds_it_was_delegated ... ok
test i11_self_change_is_governed::an_unsigned_catalog_is_accepted_without_comment ... ok
test i11_self_change_is_governed::hop_07_persistent_admin_users_cannot_be_added_to_a_warrant_derived_catalog ... ok
test i11_self_change_is_governed::hop_07_the_broker_beneath_it_accepts_a_catalog_the_caller_extended ... ok
test i11_self_change_is_governed::the_capability_token_has_no_field_that_could_grant_settle_authority ... ok
test i11_self_change_is_governed::the_catalog_amendment_refusal_names_this_invariant ... ok
test i06_exact_artifact_identity::the_receipt_records_the_refusal_without_naming_the_digest_that_failed ... ok
test i09_failure_is_safe::the_egress_receipt_records_which_failure_closed_the_action ... ok
test i07_evidence_precedes_commitment::the_product_issues_a_pre_commit_before_it_acts ... ok
test i01_active_identity::the_receipt_records_the_identity_that_was_refused ... ok
test i09_failure_is_safe::the_preflight_refusal_names_this_invariant ... ok
test i10_replay_is_detectable::the_receipt_carries_the_nonce_that_makes_the_replay_visible ... ok
test i08_non_delegable_human_authority::the_receipt_records_that_approval_was_the_gate_that_refused ... ok
test i10_replay_is_detectable::a_captured_request_replayed_verbatim_is_refused ... ok
test i10_replay_is_detectable::a_replay_with_a_refreshed_timestamp_is_still_refused_on_the_nonce ... ok
test i10_replay_is_detectable::a_timestamp_outside_the_window_is_refused_in_both_directions ... ok
test i12_safe_state_is_reachable::a_containment_pass_cannot_be_claimed_without_substantiated_elicitation ... ok
test i12_safe_state_is_reachable::a_report_claiming_no_blind_spots_is_refused_outright ... ok
test i12_safe_state_is_reachable::the_kill_path_is_stronger_than_advisory ... ignored, I-12 partial: promotion is per kernel via a drill receipt, and no kernel has earned one yet — this machine's drill cannot (existence checks measured at ~2.2s/tasklist exceed the budget); re-recorded 2026-09-05, Task 1.3
test i12_safe_state_is_reachable::containment_holds_when_the_identity_plane_is_the_thing_that_failed ... ok
test i12_safe_state_is_reachable::a_contained_scope_refuses_an_otherwise_perfect_request ... ok
test i12_safe_state_is_reachable::the_containment_gate_is_declared_against_this_invariant ... ok
test round_zero::the_chain_is_ten_hops_in_the_order_the_incident_ran_them ... ok
test round_zero::every_hop_has_a_test ... ok
test i07_evidence_precedes_commitment::a_two_phase_chain_verifies_end_to_end ... ok
test i03_purpose_bound_data_use::the_absence_of_an_implementation_is_recorded_in_the_ledger ... ok
test i12_safe_state_is_reachable::the_conformance_report_records_the_enforcement_mode_of_the_kill_path ... ok
test i07_evidence_precedes_commitment::a_post_commit_pointing_at_a_different_pre_commit_is_refused ... ok
test i07_evidence_precedes_commitment::an_orphan_post_commit_is_refused ... ok
test adversary::forgery::a1_a_chain_forged_end_to_end_verifies_and_is_caught_only_by_the_anchor ... ok
test adversary::mislabeling::a6_a_removed_limitation_fails_on_the_digest_and_a_forged_intersection_fails_on_the_proof ... ok
test adversary::substitution::a3_a_genuine_receipt_lifted_onto_a_different_report_is_refused_as_a_binding ... ok
test adversary::absence::a7_a_suppressed_receipt_is_indistinguishable_from_a_run_that_never_happened ... ok
test adversary::forgery::a2_the_evidence_receipts_issuance_time_is_not_bound_to_the_report_it_covers ... ok
test adversary::mislabeling::a9_the_bundles_rendered_mode_word_is_not_gated_against_the_receipts_on_the_verify_path ... ok
test adversary::mislabeling::a5_a_mediated_per_effect_receipt_is_refused_even_when_the_bundle_does_not_list_it ... ok

test result: ok. 85 passed; 0 failed; 15 ignored; 0 measured; 0 filtered out; finished in 0.53s

    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.45s
     Running tests\invariants\main.rs (M:/wt-rv-5.4-target\debug\deps\invariants-a12a230b95869f37.exe)

invariant ratchet: ok (85 passing at floor 85, 15 recorded findings at ceiling 15)
wiring census: 13 of 41 crates reachable from warrantor-warrant over 23 path edges
EXITGATE_EXIT=0
```

### The tier of every bound, re-read on the final tip

Unchanged in tier from phase 1; two rows re-read against the changed code. Each Mediated row states
what escapes it.

| bound | tier | what escapes it |
|---|---|---|
| `egress_hosts`, the broker | **Mediated** (Tier B) | any call that does not traverse the Warrantor MCP proxy: a shell command, a harness built-in, a socket the agent opens itself; any hostname that resolves into a private or metadata range, because the broker does not resolve DNS; and a host written in a form the bound does not carry verbatim is refused rather than normalized, which is the safe direction |
| the second engine, booked under `secondary_filter` | **Mediated** (Tier B), same point | exactly the same set: it runs inside the same `Proxy::decide` loop, after the broker, deny-only; it adds a policy domain and no place of refusal. In a shipped run it is not wired at all, and no CLI flag or configuration path can wire it -- only a Rust caller of the library |
| the address floor (`hard_deny`) through either engine | **Mediated** (Tier B) | the same set again, plus a defect in `hard_deny` escapes both engines at once |
| `--unshare-net` for an empty `egress_hosts` | **Enforced** (Tier A) -- not created here, not observable here | nothing at the socket layer if the operator launched the printed profile; everything if they did not, and this process cannot tell which. Never present for a warrant that permits any host |
| the independence count | **Observed** | it refuses nothing; a measurement of the configuration |
| the refusal log, now including second-engine refusals | **Observed** | written once at session end, unsigned, unchained; a refusal it lacks costs a tuning signal, not a guarantee, and no call is stopped by it |

### What phase 3 does NOT establish

Items 1-15 above stand. Added:

16. **The shipped binary still wires no second engine.** Everything under C4 and C5 is exercised by
    tests and by nothing a user runs; the record says `policy_engines_the_product_runs: 1` and that
    number did not move.
17. **`INDEPENDENCE_NOTE` is still rendered by no product code.** What changed is that its doc says
    so, and that the one Markdown copy which claimed to be the constant is now gated against it. The
    other two render targets carry the two required clauses in their own words, as before.
18. **The anchors will move again.** Any line added above the destination loop in `proxy.rs` shifts
    four citations in `docs/05`, and the gate refuses the tree until they are re-derived. That is the
    intended behavior and it happened once inside this phase (`eb77bcc`).
19. **The mutation table is the reviewer's mutations plus the ones that closed them, at this tip.**
    It does not establish that no other survivor exists.

### Not pushed, not merged

Twenty-one commits on `feat/task-5.4-network-common-mode`, on `main` @ `065961b`, which did not
move during this phase (`git merge-base --is-ancestor main HEAD` holds; checked last). Nothing was
pushed, nothing was merged, and this lane wrote to no other worktree. A human merges, one branch at a
time, per [[merging parallel PRs safely]].
