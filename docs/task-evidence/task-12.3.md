# Task 12.3 — Continuous promotion with an enforced parity gate; deployment-configuration parity

Branch `feat/deployment-configuration-parity-w6`, written on local `main` at `5d3e44d` and rebased onto
`main` at `065961b` on 2026-09-06 (section 9, which re-measures every gate on the rebased tip).
Items addressed: continuous promotion with an enforced parity gate (L9-03) and
deployment-configuration parity (L9-08).

The task in one sentence: **the promotion gate held the candidate's own recorded serving
configuration in a field and read nothing out of it, and the deploy step required no parity
receipt at all.** Both are closed here with the code already on `main`, and the enforced line in
each case is named below.

---

## 0. The five findings this task was dispatched with, checked against the code

The dispatch asked for every recorded finding to be verified before being repeated, and for
anything recorded nowhere to be said plainly. Four of the five check out as stated or as
corrected; **one is recorded nowhere in this repository and is therefore not an exit gate here.**

### Finding 1 — "quantization changes verdicts at the deployed `Q4_K_M`" — VERIFIED

This is the only axis in this task with a measured effect, and it is the axis the gate is for.

```
$ grep -rn "not verdict-neutral\|verdicts per thousand" docs/ | head
docs/content-program/drafts/T-03-measuring-guard-models-paper.md:555:`R13` **`Q4_K_M`, the deployed default, is not verdict-neutral**: 4 and 11 items per thousand differ
docs/content-program/drafts/T-03-measuring-guard-models-paper.md:699:`R32` **The deployed default is not verdict-neutral in any model measured.** 21 conditions, 1,000
docs/content-program/drafts/T-03-measuring-guard-models-paper.md:710:Between **4 and 18 verdicts per thousand** change at the precision most deployments serve.
```

`R33` records that the *direction* does not generalize across model families, so a deployer may
assume neither that quantization errs safe nor that it errs conservative. That is why a
configuration difference on this axis is a refusal here and not a warning.

### Finding 2 — "`num_ctx` must be pinned at 8192" — TRUE AS A PIN, FALSE AS A FINDING

The repository says so in its own voice, and the sweep has since run:

```
$ grep -rn "NOT a finding" docs/ | head -1
docs/content-program/01-track-technical.md:172:... ⚠️ **`num_ctx` pinning is NOT a finding** — it is a deployment decision and a
config-divergence incident, with no sensitivity sweep behind it. Listing it as evidence is how an
unmeasured claim reaches an abstract ...

$ grep -rn "0 of 493" docs/ | head -1
docs/content-program/drafts/T-03-measuring-guard-models-paper.md:613:`R23` Five `num_ctx` values × two
models × 493 common items: **decision-change rate 0 of 493 at every value**
```

So `num_ctx` is carried and compared here **for reproducibility**, and it is documented as such in
`serving.py`. It could not carry this task's exit gate: putting the one unmeasured axis in front of
the one measured axis is how an unmeasured claim reaches a signed bundle. It is also *already*
pinned across the language boundary by `rust/warrant/tests/guard_parity.rs`, whose header records
the eight-release divergence it exists to prevent.

### Finding 3 — "all five trained recipes were unpromotable" — NOT ON THIS BRANCH

```
$ git ls-tree -r --name-only main docs/ | grep -c 'model-inventory-reconciliation'
0
$ grep -rn "one promotion, four refusals" docs/ | head -1
docs/warrantor-pending-items-2026-08-22.html:99:full five-recipe fine-tuning sweep today — one promotion, four refusals, every verdict recorded
```

What `main` records is **one promotion and four refusals, every verdict with a decision digest**.
The `none promotable` correction lives on an unmerged branch. A task branching from `main` may not
cite it as a landed record, and nothing here depends on it. This mattered for a design decision:
see the receipting deviation in §5.

### Finding 4 — "category specialization HURT" — VERIFIED, and it belongs to Task 12.2

```
$ grep -n "does not merely fail" docs/content-program/drafts/T-03-measuring-guard-models-paper.md
64:**Fifth**, category specialization does not merely fail to help; at equal data volume it **hurts**.
```

True, and named here only so nobody re-litigates it on this branch. This task never changes what a
corpus contains, adds no training row, and re-examines no specialization result.

### Finding 5 — "severity instability was the dominant failure mode" — RECORDED NOWHERE

```
$ grep -rn "severity instab" --include=*.md --include=*.py --include=*.rs --include=*.html --include=*.json .
$ echo $?
1
```

**Not one match anywhere in the tree.** An unrecorded measurement cannot be an exit gate, so it is
not one here, and no test or gate in this branch asserts anything about any severity field. The
dominant failure mode `main` *does* record is corpus composition —
`docs/warrantor-pending-items-2026-08-22.html` Finding 1, the weak-category recipe going 0-for-3
and trading targeted-category recall for overall recall. Task 12.4 owns severity stability; its own
anchor states that its record lives on an unmerged branch.

---

## 1. Baselines on `main` at `5d3e44d`, captured before any edit

```
$ python tools/ci/wiring_census.py
wiring census: 13 of 41 crates reachable from warrantor-warrant over 22 path edges

$ python tools/ci/check_invariants.py
invariant ledger: 12 invariants; enforced=2, orphaned=1, partial=8, unimplemented=1

$ python -c "import json;d=json.load(open('tools/ci/invariant-ratchet.json'));print(d['passing_floor'], d['ignored_ceiling'])"
82 15

$ PYTHONPATH=.../src python -m pytest python/warrantor_ml/tests -q --ignore=.../test_bounds_interop.py
609 passed in 13.51s
```

**The editable install points at another worktree, and every pass is void until it is corrected.**
Captured verbatim, and this was the first command run:

```
$ cd M:/wt-w6-12.3 && python -c "import warrantor_ml.parity as p; print(p.__file__)"
M:\wt-2point1\python\warrantor_ml\src\warrantor_ml\parity.py

$ PYTHONPATH="M:/wt-w6-12.3/python/warrantor_ml/src" python -c "import warrantor_ml.parity as p; print(p.__file__)"
M:\wt-w6-12.3\python\warrantor_ml\src\warrantor_ml\parity.py
```

Every Python invocation in this task carries that prefix.

---

## 2. The two gaps, with the code that proves each

### Finding A — the gate loaded the candidate's serving configuration and threw it away

`parity.py:129` declared the field and `parity.py:223` filled it. Nothing read it:

```
$ grep -n "\.backend" python/warrantor_ml/src/warrantor_ml/parity.py
277:    baseline_lane = str(baseline.backend.get("lane", ""))
278:    baseline_precision = str(baseline.backend.get("precision", ""))
410:        error_rate = candidate.backend_error_count / candidate.scored_samples
414:            f"{candidate.backend_error_count} backend errors over "

$ grep -n "\.backend" python/warrantor_ml/src/warrantor_ml/programme.py
(no output; exit 1)
```

Lines 277-278 read the **baseline's** backend. Lines 410 and 414 read `backend_error_count`, a
different field. `candidate.backend` was read by no line of source.

### Finding B — nothing compared quantization anywhere in the promotion or deploy path

```
$ grep -rn "num_ctx\|quantis\|quantiz" python/warrantor_ml/src/warrantor_ml/parity.py \
        python/warrantor_ml/src/warrantor_ml/deploy_model.py \
        python/warrantor_ml/src/warrantor_ml/model_card.py
$ echo $?
1
```

`rust/warrant/src/guard.rs:161` holds `pub const MEASURED_NUM_CTX: u32 = 8192;` and `GuardKnobs`
has **no quantization field at all**, so `guard_parity.rs` bound seven knobs and not this one.

### Finding C — quantization was compared only through a string the operator typed

`baselines.py:210-220` records nine keys per baseline. `_lane_matches` (`parity.py:274-294`)
compared exactly two of them, `lane` and `precision`, and `baselines.py` says so in its own
comment. Both arrived from argv: `programme.py:234` was
`parser.add_argument("--precision", required=True)`. **The candidate's quantization was whatever
the operator declared it to be.**

### Finding D — no candidate result document recorded its quantization

```
$ python -c "import json; d=json.load(open('eval_results/warrantor-guard-0.6b-expguard-weak-exp06-2026-08-22a.json',encoding='utf-8')); print(sorted(d['backend'])); print('quantisation' in d['backend']); print(d['backend']['model'])"
['endpoint', 'kind', 'model', 'options', 'seed']
False
warrantor-guard-0.6b-expguard-weak-exp06-2026-08-22a
```

`evaluate.py`'s `descriptor()` emitted no quantization field, and the five candidate tags carry no
quantization label. The two baseline documents carry no field either — but their **tags** do
(`hf.co/mradermacher/Qwen3Guard-Gen-4B-GGUF:Q4_K_M`), which is the distinction the census reports.

### Finding E — the deploy step required no parity receipt

```
$ grep -n "parity\|ParityDecision\|decision_digest" python/warrantor_ml/src/warrantor_ml/deploy_model.py
$ echo $?
1
```

Zero references. `build_registration` refused on an incomplete model card and a malformed weights
digest, and on nothing else.

### Finding F — the generated adapter pinned nothing

`_ADAPTER_TEMPLATE` emitted `SCANNER_ID`, `MODEL_DIGEST`, `ENDPOINT`, `REQUEST_TIMEOUT_MS` and
`OPERATING_THRESHOLD`, and no serving knob. `GuardTransport` hands the request to the caller, so
the `warrantor guard` CLI path was pinned by `MEASURED_NUM_CTX` while **the registered
`ContentScanner` path was not pinned at all.**

---

## 3. Test first: the failure that proves the field was dead

Written before any production edit, and run against `main`'s `parity_gate`:

```
$ PYTHONPATH=.../src python -m pytest python/warrantor_ml/tests/test_parity.py -q -k different_context_length
>       assert decision.verdict == "insufficient_evidence"
E       AssertionError: assert 'promote' == 'insufficient_evidence'
E
E         - insufficient_evidence
E         + promote
1 failed, 30 deselected in 0.19s
```

A candidate whose own result document records `num_ctx: 4096` **promoted**. That is the proof
`candidate.backend` was dead, not a style preference.

The Rust binding was made to fail first too. Pointing `evaluate.py`'s defaults at `serving.py`
removes the literals `guard_parity.rs` parses:

```
$ cargo test -p warrantor-warrant --test guard_parity
assertion `left == right` failed: the Python evaluator's num_ctx default moved; ...
  left: "serving.NUM_CTX"
 right: "8192"
assertion `left == right` failed: greedy decoding is the determinism contract; ...
  left: "serving.TEMPERATURE"
 right: "0.0"
test result: FAILED. 2 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out
```

**That failure is the proof the existing binding was live.** It was fixed with a second
`include_str!` and a `serving.NAME` resolver, never with a deleted assertion.

The two *new* Rust tests passed on their first run, which proves nothing, so both were mutated:

| Mutation | Result |
|---|---|
| `QUANTIZATION: Final[str] = "Q4_K_M"` → `"Q8_0"` | `the_quantization_the_python_side_declares_is_the_one_this_crate_serves` FAILED — `left: "\"Q8_0\"" right: "\"Q4_K_M\""` |
| `TOP_P` renamed to `TOP_P_RENAMED` | 3 tests FAILED — *"serving.py no longer declares TOP_P: the deployed configuration this crate is bound to is not the one the promotion gate compares against"* |

Both reverted; the suite is green at `8 passed; 0 failed`.

---

## 4. The exit gate, verbatim

```
$ python tools/ci/check_deployment_parity.py
REGISTRATION REFUSED
parity verdict is 'insufficient_evidence'; only 'promote' may be registered. An adapter with no gate receipt is an adapter whose ScannerVerdict.model_digest binds to a number nobody compared -- and `insufficient_evidence` is not a weaker 'promote', it is the gate saying it could not tell.
deployment parity: 7 documents scanned; 2 parity, 5 refused (quantisation is absent from the recorded configuration); deployed digest sha256:823ab30e9a648515bb5fd66aa6bb50330bbb0aeaed30a06351318d0788f30350 matches record; MEASURED_NUM_CTX 8192 == DEPLOYED num_ctx 8192
  parity   expguard-2026-08-21.json: records the deployed configuration on every compared key
  refused  warrantor-guard-0.6b-adversarial-adv06-2026-08-22a.json: quantisation is absent from the recorded configuration (this build serves 'Q4_K_M'); an absent field is a mismatch, never a match
  refused  warrantor-guard-0.6b-expguard-weak-exp06-2026-08-22a.json: quantisation is absent from the recorded configuration (this build serves 'Q4_K_M'); an absent field is a mismatch, never a match
  refused  warrantor-guard-0.6b-weak-category-local-2026-08-22a.json: quantisation is absent from the recorded configuration (this build serves 'Q4_K_M'); an absent field is a mismatch, never a match
  refused  warrantor-guard-4b-adversarial-adv4b-2026-08-22a.json: quantisation is absent from the recorded configuration (this build serves 'Q4_K_M'); an absent field is a mismatch, never a match
  refused  warrantor-guard-4b-weak-category-weak4b-2026-08-22b.json: quantisation is absent from the recorded configuration (this build serves 'Q4_K_M'); an absent field is a mismatch, never a match
  parity   wildguard-2026-08-21.json: records the deployed configuration on every compared key
  [1/4] ok: counts match the record (7/2/5)
  [2/4] ok: a divergent quantization is refused and receipted; the matching control promotes
registration: C:\Users\MUVERA~1\AppData\Local\Temp\tmpa64zpde7\registration.json
adapter: C:\Users\MUVERA~1\AppData\Local\Temp\tmpa64zpde7\adapter.rs
This adapter is ADDITIVE. It adds a ContentScanner implementation and modifies no enforcement code. Whoever builds the scanner slice must also remove this scanner when it is unhealthy -- owner on record: PLACEHOLDER -- the component that builds the &[Box<dyn ContentScanner>] slice owns removal of dead scanners.
  [3/4] ok: registration without a promote receipt writes no document and no adapter; the promote control writes both
  [4/4] ok: the deployed digest matches its record and the Rust constant agrees
deployment parity: PASS. This compares RECORDS, not processes -- it does not observe a serving process, and it cannot detect a per-request context override, a re-quantized GGUF under an unchanged tag, or a scanner reached by any path other than the generated adapter.
EXIT=0
```

The `REGISTRATION REFUSED` and `registration:`/`adapter:` lines are the CLI's own stdout from
check 3 driving the real `deploy_model.main` twice — once to be refused, once as the allowed
control. They are the mechanism, not noise.

**The five named refusals and the reason for each.** All five 2026-08-22 candidate documents —
`0.6b-adversarial-adv06`, `0.6b-expguard-weak-exp06`, `0.6b-weak-category-local`,
`4b-adversarial-adv4b`, `4b-weak-category-weak4b` — are refused for the same single reason:
`quantisation is absent from the recorded configuration`. Their `descriptor()` predates
`SCHEMA_VERSION 2` and their Ollama tags carry no quantization label, so the one axis with a
measured effect was never recorded for any of them. **Whether their 0.50 GB / 2.78 GB inventory
size against the baselines' 0.48 GB / 2.72 GB is a merged adapter's extra tensors or a different
quantization cannot be determined from anything in the pipeline** — that is the defect, stated
without overclaiming what the sizes prove.

## Baselines re-measured after the change

```
$ python tools/ci/wiring_census.py
wiring census: 13 of 41 crates reachable from warrantor-warrant over 22 path edges

$ python tools/ci/check_invariants.py
invariant ledger: 12 invariants; enforced=2, orphaned=1, partial=8, unimplemented=1
```

Unchanged, as required: no crate is added, no recorded invariant violation is converted, no
`#[ignore]` is added or removed, and `tools/ci/invariant-ratchet.json` stays at `passing_floor: 82`
/ `ignored_ceiling: 15`. Raising the floor here would be a claim without a mechanism.

---

## 5. Tier table — why each bound gets its word and not a stronger one

| Bound | Word | The line that earns it, and why not the stronger word |
|---|---|---|
| A promotion whose recorded configuration differs from `serving.DEPLOYED` | **Tier B, chokepoint** | `parity.py`, inside `parity_gate`'s precondition block: `if configuration_problems := serving.configuration_mismatch(recorded): blocking.append(...)` → verdict `insufficient_evidence`, `parity_main` exits 3. It refuses **at the moment of attempt**, so not merely Observed. It is not Enforced because it binds only promotions that pass through `warrantor-ml-parity`: a candidate registered by hand does not reach this line. |
| A registration without a `promote` parity receipt | **Tier B, chokepoint** | `deploy_model.build_registration`: `if verdict != "promote": raise RegistrationError(...)`, before any write. Same shape, same limit — it binds only registrations built through this function. |
| A registration whose receipt records a configuration this build does not serve | **Tier B, chokepoint** | Same function, third check: `if configuration_problems := serving.configuration_mismatch(receipt_configuration): raise RegistrationError(...)`. |
| An operator-declared `--precision` contradicting the artifact | **Tier B, chokepoint** | `parity_gate`'s `if declared_precision is not None and declared_precision != candidate.precision` → blocking precondition, receipted. Composed with the other preconditions rather than short-circuiting them, so it cannot mask a second defect. |
| Rust constants agreeing with the Python record | **Tier B, at build** | `guard_parity.rs` fails `cargo test` when they diverge. A refused **build** is a real refusal at a real chokepoint (CI); it says nothing about what a deployed binary is doing. |
| What a serving process actually runs | **Tier C, observed** | Nothing here measures a running process. The gate compares a configuration an evaluator *wrote into a document* against a configuration this repository *declares* it serves. **What escapes:** a different Ollama client, a `num_ctx` or `temperature` override on the individual request, a re-quantized GGUF pushed under an unchanged tag, and any scanner reached by a path other than the generated adapter. |
| The registration document's `serving` block | **Derived from the receipt, not declared** | `to_dict` renders `self.parity_receipt["recorded_serving_configuration"]`, and `null` when there is no receipt. Rendering `serving.DEPLOYED` there would let a `ScannerRegistration` constructed directly — with the defaulted empty receipt — publish a configuration nothing was promoted at. `build_registration` cannot produce that, but the dataclass can; the last two tests in `test_deploy_model.py` are the refusal and its control. |
| The generated adapter's `SERVED_*` constants | **Tier C, observed** | They are `pub const` declarations. `GuardTransport` is the caller's boxed closure, so the adapter *cannot* send them. The generated file says so in its own comment — *"these are values the caller MUST send -- this adapter cannot enforce them"* — and a test asserts that sentence is present, which is what keeps the claim labeled Tier C. |

**There is no namespace, seccomp or firewall enforcement anywhere in this repository, and none is
added here.**

**No new trust root.** `serving.DEPLOYED` is a repository-declared record, not an attestation. It
is signed by nothing. It establishes that this checkout's evaluator, its promotion gate, its
generated adapter and its Rust CLI read one value — so a divergence between them is a diff rather
than an argument.

### The sentence that ships in the product

Present verbatim in the registration document's `notes` and asserted by
`test_registration_succeeds_with_a_promote_receipt_at_the_deployed_configuration`:

> This gate compares the configuration recorded in the evaluation document against the
> configuration this build declares it serves. It does not observe the serving process. It cannot
> detect a context length overridden per request, a model re-quantized under an unchanged tag, or a
> scanner reached by any path other than the generated adapter — and it gates only capabilities
> present in the evaluation set.

---

## 6. Deviations from the step-form plan

Every one of these is a case where the code won.

1. **The branch name was already taken by an uncommitted prior lane.**
   `git worktree add M:/wt-w6-12.3 -b feat/deployment-configuration-parity main` failed —
   `fatal: a branch named 'feat/deployment-configuration-parity' already exists`. That branch has
   **zero commits of its own** (`git log --oneline main..feat/... | wc -l` → `0`, and its tip
   `2ec0638` is an ancestor of `main`), but the worktree `M:/wt-w6-12.3`'s predecessor
   `M:/wt-w5-12.3` holds ~15 uncommitted files implementing this same task. **That work was not
   touched.** This branch is `feat/deployment-configuration-parity-w6` and the implementation here
   is independent. This is the recorded concurrent-session hazard, and it means two worktrees now
   hold competing implementations of Task 12.3 — a fact whoever merges needs.

2. **The plan's anchor document is not on this branch, and neither identifier appears anywhere.**
   The Anchor quotes `docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html` lines
   5091-5099 and 5151-5159 verbatim. That file does not exist:
   `git ls-tree -r --name-only main docs/html/ | grep -c master-2026-09-01` → `0`, and
   `grep -rn "L9-03"` matched nothing in the tree before this task wrote the string. **The
   verification texts this task implements could not be checked against the repository** — only
   against the plan that quotes them. Implemented to the plan's text, with the contradiction in it
   resolved as item 3.

3. **The plan's exit criterion 2 contradicts the item it implements, and was corrected.** It
   requires that a refused promotion "exits non-zero and **writes no decision document**". L9-03's
   own verification sentence requires that "the refusal **is receipted**", and `main`'s only record
   of this pipeline is auditable *because* its four refusals were written down with decision
   digests. A refusal that writes nothing is an unreceipted refusal. **Implemented as: the refusal
   IS receipted** — the decision document records the verdict, the naming reason and a digest — and
   what a refusal must not produce is a *registration* or an *adapter*, which is what
   `build_registration` enforces and what check 3 of the gate proves. Recorded loudly because the
   plan's wording, taken literally, would have deleted an existing auditability property.

4. **The plan's expected gate line is wrong: it predicted `2 parity, 5 refused` for a reason that
   does not hold.** With a strict reader — explicit fields only — **all seven** documents refuse,
   because *neither* baseline document carries a `quantisation` field either. The 2/5 split is real
   but comes from a third place the fact is written: the Ollama model tag. So
   `serving.recorded_serving_configuration` reads the tag as a last resort, narrowly
   (`quantisation_in_tag` accepts `Q4_K_M`/`Q8_0`/`F16`/`IQ4_XS` and rejects `:latest`, `:v2` and
   an unlabeled name). Recovering a value from the one place it is recorded is not defaulting;
   collapsing "the tag says Q4_K_M" and "nothing says anything" into one refusal would have lost
   the distinction the gate exists to draw.

5. **`serving.DEPLOYED` has seven keys, not the plan's "nine".** The plan's own `REQUIRED_KEYS` is
   seven, and `lane`/`precision` are already compared by `_lane_matches`. Keys nobody compares are
   decoration in a record whose whole purpose is comparison.

6. **The plan's predicted Rust failure was the wrong one.** It expected
   `the_python_source_is_still_shaped_the_way_these_assertions_read_it` to fail with *"cannot read
   the Python default for num_ctx"*. That test **passed** — `python_default` still finds the line
   and returns `"serving.NUM_CTX"`. The four *value* assertions failed instead. The shape guard
   does not catch an indirection, only a reformat; worth knowing, because a reader of the plan
   would have concluded the shape guard covers this class.

7. **`rust/warrant/src/guard.rs` has no `default_model_tag()`.** The plan's Step 5 test calls it.
   The real symbol is `pub const DEFAULT_GUARD_MODEL` at `guard.rs:83`; the assertion uses that.

8. **`test_parity.py` has no `_result_document()` / `_load()` helpers**, which the plan's Step 3
   and Step 6 test bodies call. It has `_candidate()`, which builds a `CandidateResult` directly.
   The tests were written against the real fixture, with a `_backend_at()` helper added that shapes
   a `backend` block the way `descriptor()` actually writes one.

9. **The plan's Step 0 baselines are stale.** It states census `10 of 40 ... 18 path edges`,
   ledger `orphaned=2, partial=7`, and ratchet `66/18`, from base `b04164d`. On `main` at `5d3e44d`
   the real numbers are `13 of 41 ... 22 path edges`, `orphaned=1, partial=8`, and `82/15`. Its
   instruction that "the wiring census must still print 10 of 40" is therefore unsatisfiable as
   written; what this task actually holds constant is the *current* numbers.

10. **`_candidate()`'s and `test_programme.py`'s fixtures changed, and no assertion was weakened.**
    Both left `backend` empty, faithful to `main` where the field was dead. With absence now a
    refusal, an empty default would make ~40 unrelated tests fail on a configuration precondition
    instead of on the rule each was written to check. `test_programme.py`'s three document builders
    now record `OllamaGuardBackend(...).descriptor()` — the real producer's output — rather than a
    hand-written block, for the same reason `test_load_candidate_result...` already uses
    `build_eval_set_descriptor`. No assertion was removed or relaxed; no test was deleted.

11. **`evaluate.SCHEMA_VERSION` moved 1 → 2**, which the plan calls for and which changes
    `result_digest` for documents produced from now on. Deliberate: a schema that could not tell a
    version-1 document (no quantization recorded) from a version-2 one would let the gate read "did
    not say" as "said `Q4_K_M`".

12. **One Rule 2 risk found and closed during self-review, not by a test.** The registration
    document's `serving` block initially rendered `dict(serving.DEPLOYED)`. `build_registration`
    refuses a receipt whose configuration differs, so the two are always equal for anything it
    produces -- but a `ScannerRegistration` constructed directly, with the defaulted empty receipt,
    would have published a `serving` block asserting a configuration nothing was promoted at. It now
    renders the receipt's own `recorded_serving_configuration`, and `null` when there is no receipt.
    Same failure class as the Task 9.1 bundle that read `denied_gate: null` beside a sentence saying
    the gate denied.

13. **Backslash mangling, twice.** Heredocs through this shell dropped the `\n` from
    `f"INSUFFICIENT EVIDENCE\n{error}"`, producing an unterminated f-string. Fixed with two `print`
    calls. Consistent with the recorded hazard; the in-file gates caught it immediately.

---

## 7. What this task does NOT establish

Specific, not modest.

- **It does not establish that any model was served at `Q4_K_M`, 8192, seed 0.** It establishes
  that four *records* in this checkout say so and a machine now compares them. `serving.DEPLOYED`
  is signed by nothing and attested by nothing.
- **It does not observe a serving process, at any point.** A `num_ctx` or `temperature` override on
  an individual HTTP request, a different Ollama client, a re-quantized GGUF pushed under an
  unchanged tag, or an `ollama` server with its own defaults — none of these is observed and none
  is refused. The `SERVED_*` constants in the generated adapter are declarations the *caller* must
  honor; `GuardTransport` is the caller's closure and the adapter cannot send them.
- **It does not close the promotion path against a hand-registered scanner.** Both refusals are
  Tier B chokepoints in Python functions. A `ContentScanner` written by hand, or a registration
  document produced by any means other than `build_registration`, reaches the substrate without
  passing either.
- **It does not determine what the five 2026-08-22 candidates were actually served at.** It
  determines that the pipeline never recorded it. The 0.50 GB / 2.78 GB versus 0.48 GB / 2.72 GB
  inventory gap is *consistent with* a merged adapter's extra tensors and *consistent with* a
  different quantization, and nothing in the pipeline can separate the two.
- **It does not decide the disposition of those five candidates.** That is Task 12.6's graduation
  ladder. This task produces the configuration verdict that ladder consumes; it builds no rung and
  records no checkpoint disposition.
- **It does not re-run, re-score or re-train anything.** No GPU was touched. Every test here runs
  offline against committed documents, so the recall and false-positive figures the gate compares
  are the previously recorded ones, not fresh measurements.
- **It asserts nothing about any severity field**, adversarial phrasing, or advisory boundary —
  Task 12.4's axes, on which the record this branch carries is silent (see §0, Finding 5). The two
  gates therefore cannot both claim the same refusal.
- **It does not make `num_ctx` a measured exit criterion.** `R23` measured it inert at 0 of 493
  decision changes. It is compared for reproducibility only, and this document and `serving.py`
  both say so.
- **It does not verify L9-04's claim** that "every published figure carries the configuration that
  produced it". `model_card.REQUIRED_FIELDS` still carries no serving-configuration field, so the
  card validator does not enforce that. Named so this task does not inherit the claim.
- **It converts no recorded invariant violation, and adds no wiring.** The census and the ledger
  are byte-identical before and after. Nothing here makes any of the twelve invariants more
  enforced than it was.
- **It does not verify the blueprint text it implements.** The anchor document is not on this
  branch (§6, item 2). The verification sentences were read from the plan, not from the record.

---

## 8. Fresh detached-worktree verification

Run in `M:/wt-g6-12.3`, a detached checkout of the committed branch, reusing the one build
directory `M:/wt-w6-12.3-target`. Free space at start of the last build: 300 GB.

```
$ git status --porcelain
(empty)

$ git check-ignore -v eval_results/wildguard-2026-08-21.json tools/ci/deployment-parity.json     tools/ci/check_deployment_parity.py tools/ci/test_check_deployment_parity.py     python/warrantor_ml/src/warrantor_ml/serving.py python/warrantor_ml/tests/test_serving.py     docs/task-evidence/task-12.3.md rust/warrant/tests/guard_parity.rs
(no match for any path)

$ python -c "import warrantor_ml.parity as p; print(p.__file__)"
M:\wt-g6-12.3\python\warrantor_ml\src\warrantor_ml\parity.py

$ python tools/ci/check_deployment_parity.py            # THE EXIT GATE
deployment parity: PASS ...                             EXIT=0

$ python -m pytest python/warrantor_ml/tests tools/ci/test_check_deployment_parity.py -q
647 passed

$ python tools/ci/run_python_checks.py format | lint | test
RESULT: PASS 54/54 Python projects passed format
RESULT: PASS 54/54 Python projects passed lint
RESULT: PASS 54/54 Python projects passed test

$ cd rust && cargo fmt --check;  echo FMT=$?
FMT=0
$ cargo clippy --all-targets -- -D warnings;  echo CLIPPY=$?
CLIPPY=0
$ cargo test --workspace -j 2;  echo CARGO=$?
CARGO=0
```

**Every `test result:` line summed, not the last one read:**

| | suites | passing | failed | ignored |
|---|---|---|---|---|
| `main` baseline | 150 | 1528 | 0 | 20 |
| this branch | 150 | 1530 | 0 | 20 |

The `+2` is exactly the two new `guard_parity.rs` assertions
(`the_quantization_the_python_side_declares_is_the_one_this_crate_serves` and
`the_deployed_record_declares_every_key_the_python_gate_compares`); that suite reports
`8 passed; 0 failed`. `ignored` is unchanged at 20, so no `#[ignore]` was added or removed. The
Rust figures were captured at `00addca`; the only change since is one Markdown table row in this
file, which no Rust target reads.

```
$ python tools/ci/wiring_census.py
wiring census: 13 of 41 crates reachable from warrantor-warrant over 22 path edges

$ python tools/ci/check_invariant_ratchet.py
invariant ratchet: ok (82 passing at floor 82, 15 recorded findings at ceiling 15)

$ python tools/ci/check_invariants.py
invariant ledger: 12 invariants; enforced=2, orphaned=1, partial=8, unimplemented=1

$ python tools/ci/check_us_english.py main
us-english: 2250 added line(s) across 16 file(s), since main; matcher = vendored verify-us-english.mjs
us-english: ok

$ python tools/ci/check_docs.py
RESULT: PASS 269 Markdown files, 58 RFCs, 81 catalogue rows, and all local links validated
```

**The orphan count did not rise** — read from `wiring_census.py`, not computed: `orphaned=1` before
and after. Census, ratchet and ledger are all identical to the pre-change baselines in §1.

`python/warrantor_ml/tests/test_bounds_interop.py` is excluded from the pytest line above and only
from that line: it fails collection without `.bounds_interop.json`, which
`cargo run -p warrantor-warrant --example emit_bounds_vectors` produces. It is unmodified by this
task, and the workspace `cargo test` above covers the Rust side of that binding.

The gate is wired into `.github/workflows/ci.yml` — `Check deployment-configuration parity` and
`Test the deployment-parity gate` — so it runs rather than merely existing.

---

## 9. Rebased onto `main` at `065961b` — the gate re-measured on `ff8a6ac`

Review lane, 2026-09-06. Everything in this section was measured on the rebased tip `ff8a6ac`
in `M:/wt-w6-12.3` with the lane's own build directory `M:/wt-rv-12.3-target`. Nothing in §1–§8
was re-numbered: those figures describe the tips they name.

**Commits on the branch after the rebase:**

| commit | was | what |
|---|---|---|
| `ff8a6ac` | `96f54ed` | the whole task, replayed onto `065961b` |
| (this section) | — | evidence only; no file a cargo target reads |

**The rebase.** `git rebase main` replayed one commit and stopped once, on
`.github/workflows/ci.yml`: `main` had inserted `Test the disk guard` directly after `Test the
US-English gate`, the same anchor this branch inserted `Check deployment-configuration parity` and
`Test the deployment-parity gate` after. Both were kept, `main`'s step first, this branch's two
after it; nothing else in the file moved. No Rust, Python, census artifact or ratchet record
conflicted — `git diff 065961b ff8a6ac --stat -- rust/` is `guard_parity.rs` alone, and
`README.md`, `evidence/wiring-coverage.json` and `tools/ci/invariant-ratchet.json` are untouched
by the branch. `git status --porcelain` was empty before the rebase and after it.

**The full gate, each exit code captured before any pipe.** Disk guard first, every time:
`disk_guard.py --require 100` → 231–252 GB free; `--require-commit 6` → 7.4–18.1 GB available.

```
$ cd rust && cargo fmt --all -- --check;                              echo FMT=$?
FMT=0
$ cargo clippy --workspace --all-targets -- -D warnings;              echo CLIPPY=$?
CLIPPY=0                      # fresh build in M:/wt-rv-12.3-target, 5m 52s
$ cargo test --workspace --all-targets;                               echo CARGO=$?
CARGO=0                       # the fourth full run; the first three exited 101 on one live-drill suite -- section 9.1
$ cargo test --workspace --doc;                                       echo DOC=$?
DOC=0
```

**Every `test result:` line summed, not the last one read** — on `ff8a6ac`:

| run | suites | passed | failed | ignored |
|---|---|---|---|---|
| `cargo test --workspace --all-targets`, the green run the gate is reported on | 119 | 1549 | 0 | 20 |
| the same command, third run, fail-fast stopped at the drill | 79 | 927 | 1 | 4 |
| the same with `--no-fail-fast`, red, so every suite was enumerated while the drill was red | 119 | 1546 | 3 | 20 |
| `cargo test --workspace --doc` | 40 | 1 | 0 | 0 |

The three rows of the workspace command differ in exactly one binary,
`rust/warrant/tests/conformance_receipt.rs` (3 tests); the other 118 suites are 1546 passed, 0
failed, 20 ignored in both enumerated rows. `ignored` is 20 on this tip as it was in §8: no
`#[ignore]` was added or removed by the branch or by the rebase.

```
$ (cd rust && python ../tools/ci/wiring_census.py)
wiring census: 13 of 41 crates reachable from warrantor-warrant over 22 path edges
$ python tools/ci/check_invariant_ratchet.py --show-findings          # read the "invariant ratchet:" line
invariant ratchet: ok (82 passing at floor 82, 15 recorded findings at ceiling 15)
$ python tools/ci/check_invariants.py
invariant ledger: 12 invariants; enforced=2, orphaned=1, partial=8, unimplemented=1
$ python tools/ci/check_docs.py
RESULT: PASS 300 Markdown files, 58 RFCs, 81 catalogue rows, and all local links validated
$ python tools/ci/check_us_english.py main
us-english: 2330 added line(s) across 16 file(s), since main; matcher = vendored verify-us-english.mjs
us-english: ok
```

The orphan count did not rise: `orphaned=1` in §1, in §8, and here. The census line is
byte-identical to the pre-rebase one, as it must be for a branch that adds no crate and no edge.
`check_docs.py` counts 300 Markdown files where §8 counted 269: `main` added thirty-one documents
between `5d3e44d` and `065961b`, none of them this branch's.

**The task's own exit gate, on this tip**, with the editable-install check first because §1 says
why:

```
$ PYTHONPATH=M:/wt-w6-12.3/python/warrantor_ml/src python -c "import warrantor_ml.parity as p; print(p.__file__)"
M:/wt-w6-12.3/python/warrantor_ml/src/warrantor_ml/parity.py      (printed with backslashes)

$ python tools/ci/check_deployment_parity.py;  echo EXIT=$?
deployment parity: 7 documents scanned; 2 parity, 5 refused (quantisation is absent from the recorded configuration); deployed digest sha256:823ab30e9a648515bb5fd66aa6bb50330bbb0aeaed30a06351318d0788f30350 matches record; MEASURED_NUM_CTX 8192 == DEPLOYED num_ctx 8192
  [1/4] ok: counts match the record (7/2/5)
  [2/4] ok: a divergent quantization is refused and receipted; the matching control promotes
  [3/4] ok: registration without a promote receipt writes no document and no adapter; the promote control writes both
  [4/4] ok: the deployed digest matches its record and the Rust constant agrees
deployment parity: PASS. This compares RECORDS, not processes -- ...
EXIT=0

$ python -m pytest python/warrantor_ml/tests tools/ci/test_check_deployment_parity.py -q --ignore=python/warrantor_ml/tests/test_bounds_interop.py
647 passed in 12.11s
$ python -m pytest tools/ci/test_disk_guard.py tools/ci/test_check_us_english.py tools/ci/test_check_invariants.py -q
27 passed in 48.91s
```

Same seven documents, same 2/5 split, same digest, same five refusals for the same one reason as
§4. The `guard_parity` suite this branch extends is inside the 1549: `8 passed; 0 failed`.

### 9.1 The suite that was red on eight runs and green on the ninth, and why it is the box

`conformance_receipt.rs` holds three tests, all of which begin by running
`warrantor_warrant::conformance::drill` — a **live kill drill**: spawn `powershell`, which starts
a hidden `ping -n 60`; wait up to 10 s for the descendant's pid to land in a file; `taskkill` the
root; then poll `tasklist` for both pids for at most `2 × STOP_BUDGET` = 10 s. It carries no
`#[ignore]`, and it is `#[cfg(windows)]`-pathed: CI runs it on ubuntu through `sh`/`ps`, so this
Windows path is one the repository's gate has never exercised (the memory note "Windows Rust
paths are ungated" records the same gap).

On this tip the binary was run ten times in a row. The first exited 101 with a log another lane
overwrote (§9.2), so only its exit code is cited. Seven more were red — three inside full
workspace runs, four standalone — in two shapes:

```
drill: Encode("the drill's descendant never reported its pid")          # pid not written within 10 s
DrillObservation { ..., trigger_to_root_gone_ms: 18446744073709551615,
  trigger_to_descendant_gone_ms: 18446744073709551615, root_gone: false,
  descendant_gone: false, within_budget: false, refusal: None }          # pid written; nothing observed in 10 s
```

The ninth, standalone, was `3 passed; 0 failed`, and the tenth — the full workspace run started
immediately after it — exited 0 with the drill green inside it: the first row of the table above.

`refusal: None` means `taskkill` reported success; `u64::MAX` on both timestamps means the poll
loop never once saw either pid absent before its deadline. Whether that is a tree that survived
or a tree the loop could not look at in time is decided by measuring the two spawns the loop is
made of, on this box, in the same hour:

```
$ powershell -NoProfile -Command "1"      x3     4926 ms   5121 ms   12663 ms     (drill's pid deadline: 10 000 ms)
$ tasklist /FI "PID eq 4" /NH /FO CSV     x3     4125 ms   3559 ms    3228 ms     (drill's observation window: 10 000 ms, two spawns per poll)
```

A PowerShell start that takes 5–12.7 s against a 10 s deadline is the first shape. A `tasklist`
that takes 3.2–4.1 s per spawn, two per poll iteration, after `terminate`'s own confirmation has
already spent part of the same window, is the second: the loop gets at most one look, and "not
seen gone" is recorded as `false`. The source comment in `drill` names exactly this hazard
(*"tasklist measured at ~2.2s/spawn under real-time AV"*); during the red runs it was nearly
double that.

Three facts fix the attribution:

1. **The code is byte-identical to `main`.** `git diff 065961b ff8a6ac --stat -- rust/warrant/src/conformance.rs rust/warrant/src/stop.rs rust/warrant/tests/conformance_receipt.rs rust/kill-switch-core` is empty, and the only Rust file this branch changes (`guard_parity.rs`) is a different test binary that links nothing the drill runs.
2. **This suite was green on this box before.** §8 recorded 150 suites, 0 failed at `00addca`, and `conformance_receipt.rs` (`8606790`, 2026-09-05) is an ancestor of that tip's base `5d3e44d` — so it ran and passed here, on the same kernel, the day before.
3. **The red runs track the machine's spawn latency, not the tree.** 297 `node.exe` processes and three other lanes' `cargo` were resident during the red runs; the green run came after they had thinned. Nothing in the worktree changed between the eighth run and the ninth.

**What this does and does not license.** The gate as written exited 0 on this tip, with every
suite enumerated and the drill green inside the run, so the workspace gate is reported green and
the ledger may cite it. What is also true, and stays in this file rather than being smoothed
over: on this box the drill is a load-dependent test, eight red runs preceded the green one, and
a reviewer re-running the gate here under a parallel wave should expect exit 101 from this one
binary and should read the failure shape before concluding anything about the tree.

One observation on `main`'s test, recorded rather than acted on because it is not this task's
file: the drill's own contract says a slow kernel *"honestly earns Advisory — and the receipt
verifies either way"*, but the first assertion in the test (`root_gone && descendant_gone`)
fires before that derivation, so a box that cannot observe within budget fails the test instead
of earning the Advisory receipt the code was written to produce. Whether that is the intended
strictness or a gap in the Windows path is a question for the lane that owns `conformance.rs`.

### 9.2 A process hazard found here, so the next lane does not repeat it

The scratchpad directory this session was given is shared by every lane of the wave. The first
`cargo test` log written to `<scratchpad>/test.log` was overwritten mid-run by another lane's run
of the same command from `M:/wt-w6-10.1` into `M:/wt-rv-10.1-target`; only the per-task exit code
file was private. Every number above comes from runs into a lane-private subdirectory, each log
checked for this worktree's path before it was read. No number from the clobbered log appears in
this file.
