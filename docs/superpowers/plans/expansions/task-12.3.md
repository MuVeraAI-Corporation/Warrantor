### Task 12.3: Continuous promotion with an enforced parity gate; deployment-configuration parity (L9-03, L9-08)

**Anchor.** Both items are `status=partial`, `core`, W2. Quoted verbatim from
`docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html`, lines 5091-5099 and 5151-5159:

```html
<article class="item" id="L9-03" data-stratum="L9" data-plane="A" data-status="partial" data-novelty="core" data-wave="W2" data-loop="L1">
  <h4>Continuous promotion pipeline with an enforced parity gate</h4>
  <p class="verify"><b>Verification</b> An adapter attempting registration without a parity-gate receipt is refused by the deploy step and the refusal is receipted; a promotion whose criterion was edited after the run is unregisterable.</p>
  <p class="anchor"><b>Anchor</b> One promotion, four recorded refusals; a monotonicity check once reported noise at p ≈ 0.69 as a reversal, which is why the criterion is registered first</p>

<article class="item" id="L9-08" data-stratum="L9" data-plane="A" data-status="partial" data-novelty="core" data-wave="W2" data-loop="L5">
  <h4>Deployment-configuration parity</h4>
  <p class="verify"><b>Verification</b> The gate refuses a promotion whose evaluation configuration differs from the serving configuration in quantization or context length; the served model's digest matches the evaluated one.</p>
  <p class="anchor"><b>Anchor</b> Measured: quantization changed verdicts at the deployed setting</p>
```

**The seed carries five findings into this task. One is verified, one belongs to Task 12.2, and three
are wrong.** Each is checked against the code and the record below, and the corrections change what
this task builds. `premise_contradicted` is therefore true.

1. **"Quantization changes verdicts at the deployed `Q4_K_M`" — VERIFIED, and it is the only axis
   here with a measured effect.** `docs/content-program/drafts/T-03-measuring-guard-models-paper.md:555-556`
   records it as `R13`: *"`Q4_K_M`, the deployed default, is not verdict-neutral: 4 and 11 items per
   thousand differ from `f16`."* Lines 700-712 record `R32` across five models from three publishers:
   *"Between 4 and 18 verdicts per thousand change at the precision most deployments serve"*, and
   `R33` at lines 714-726 records that **the direction does not generalize** — ShieldGemma 9B moves
   17/0 safety-adverse while ShieldGemma 2B moves 0/18 usability-adverse. A deployer can assume
   neither that quantization errs safe nor that it errs conservative. This is the finding the gate is
   for.
2. **"Category specialization measurably hurt" — VERIFIED, and it is Task 12.2's premise, not this
   task's.** `T-03-measuring-guard-models-paper.md:64`: *"category specialization does not merely fail
   to help; at equal data volume it hurts."* Named here only so nobody re-litigates it in this branch.
3. **"`num_ctx` must be pinned at 8192 — an unpinned context length has already changed results
   here" — WRONG, and the repository says so twice in its own voice.**
   `docs/content-program/01-track-technical.md:172` carries the warning verbatim: **`⚠️ num_ctx
   pinning is NOT a finding — it is a deployment decision and a config-divergence incident, with no
   sensitivity sweep behind it. Listing it as evidence is how an unmeasured claim reaches an
   abstract.`** And the sweep has since run: `T-03-measuring-guard-models-paper.md:613-615` reports
   **`R23`** — *"Five `num_ctx` values × two models × 493 common items: decision-change rate 0 of 493
   at every value"*. The eight-release divergence is recorded at `docs/W1-delivery-gaps.md:967-970` as
   a configuration-management defect, not a measured effect. **`num_ctx` therefore cannot carry this
   task's exit gate.** It is a reproducibility field, it is *already* pinned across the language
   boundary (Step 0, Finding B), and putting the one unmeasured axis in front of the one measured axis
   is how an unmeasured claim reaches a signed bundle.
4. **"Five recipes were trained and none was promotable" — WRONG as stated on this branch.**
   `docs/warrantor-pending-items-2026-08-22.html:99` records the 2026-08-22 sweep as *"one promotion,
   four refusals, every verdict recorded with decision digests"*, naming `guard-0.6b-expguard-weak`
   run `exp06-2026-08-22a`, and the blueprint's own L9-03 anchor agrees: *"One promotion, four
   recorded refusals."* The `none promotable` verdict is a **later** correction dated 2026-09-01, and
   it is **not on `main`**: `git ls-tree -r --name-only main docs/ | grep -c
   'model-inventory-reconciliation'` returns `0`. It lives on `docs/content-program-p9-fold` at
   `f455fa8`, where `docs/model-inventory-reconciliation-2026-09-01.md:126` reads *"~~one apparently
   promotable~~ — **none promotable**"*. A task branching from `main` may not cite it as a landed
   record. Task 12.4 carries that document in; this task does not need it, because the promotion it
   audits is the one `main` records.
5. **"Severity instability was the dominant failure mode" — recorded NOWHERE on this branch, and it is
   not this task's axis anyway.** `grep -rn "severity instab\|severity field flips" --include=*.md
   --include=*.py --include=*.rs --include=*.html .` returns nothing on `main`. **Task 12.4 owns
   severity stability and has already been expanded**; its own Anchor states that the record lives on
   an unmerged branch. The dominant failure mode `main` actually records is corpus composition:
   `docs/warrantor-pending-items-2026-08-22.html` Finding 1 — *"the weak-category recipe is 0-for-3
   ... the corpus trades targeted-category recall for overall recall ... catastrophic forgetting, not
   a training accident."* An unrecorded measurement cannot be an exit gate, so it is not one here.

**What this leaves as the task.** The blind parity gate already exists and is good — 640 lines,
two-sided, with `insufficient_evidence` as a first-class verdict, and a per-category floor check. What
does not exist is any comparison between **the configuration a candidate was evaluated at** and **the
configuration the product serves**. The gate loads the candidate's own recorded serving configuration
into a field and then discards it, and the deploy step requires no parity receipt at all. Those are
the two gaps, and both are closable with the code already on `main`.

---

**Step 0.** Run every command below in a detached worktree on **local `main`** (`b04164d`), not
`origin/main` (`e4b5f10`, stale). Read in full: `python/warrantor_ml/` in breadth first, then
`parity.py` (640 lines), `deploy_model.py` (456 lines), `evaluate.py` (781 lines), `baselines.py`
(505 lines), `programme.py` (344 lines), `recipes.py` (580 lines), and `rust/eval-guard/src/lib.rs`
(361 lines).

```bash
export PATH="$PATH:/c/Users/MuVeraAICorporation/.cargo/bin"
cd "M:/Project AumOS - Open Secure AI Alliance/aumos"
git worktree add --detach M:/wt-e-12.3 main
cd M:/wt-e-12.3 && export CARGO_TARGET_DIR=M:/wt-e-12.3-target
git ls-tree --name-only main rust/ | wc -l        # 49 entries
git ls-tree --name-only -d main rust/ | wc -l     # 40 crates
git ls-tree --name-only main rust/ | grep -c 'rust/guard$'   # 0 — there is no rust/guard
git ls-files python/warrantor_ml | wc -l          # 59 tracked files
```

**The editable install points at another worktree, and every pass is void until you fix it.**
Captured verbatim, and this is the first command to run:

```
$ cd M:/wt-e-12.3/python/warrantor_ml && python -c "import warrantor_ml.parity as p; print(p.__file__)"
M:\wt-2point1\python\warrantor_ml\src\warrantor_ml\parity.py
```

Every `pytest` and every `warrantor-ml-*` console script in this checkout runs **`M:/wt-2point1`'s**
code. Prefix `PYTHONPATH="M:/wt-e-12.3/python/warrantor_ml/src"` on every Python invocation in this
task, and re-print `p.__file__` after any environment change:

```
$ PYTHONPATH="M:/wt-e-12.3/python/warrantor_ml/src" python -c "import warrantor_ml.parity as p; print(p.__file__)"
M:\wt-e-12.3\python\warrantor_ml\src\warrantor_ml\parity.py

$ PYTHONPATH=".../src" python -m pytest tests/ -q --ignore=tests/test_bounds_interop.py
609 passed in 10.93s
```

`tests/test_bounds_interop.py` fails collection without `.bounds_interop.json`, which
`cargo run -p warrantor-warrant --example emit_bounds_vectors` produces. It fails rather than skips on
purpose; ignore it only for the fast loop, never in the exit gate.

**Baselines on this branch, captured:**

```
$ python tools/ci/wiring_census.py
wiring census: 10 of 40 crates reachable from warrantor-warrant over 18 path edges

$ python tools/ci/check_invariants.py
invariant ledger: 12 invariants; enforced=2, orphaned=2, partial=7, unimplemented=1

$ cat tools/ci/invariant-ratchet.json
{ "passing_floor": 66, "ignored_ceiling": 18, ... }
```

**Finding A — the gate loads the candidate's serving configuration and throws it away.**
`parity.py:129` declares the field and `parity.py:223` fills it:

```python
# python/warrantor_ml/src/warrantor_ml/parity.py:129
    backend: Mapping[str, Any] = field(default_factory=dict)
# python/warrantor_ml/src/warrantor_ml/parity.py:223
        backend=dict(document.get("backend", {})),
```

Nothing reads it. Captured:

```
$ grep -rn "\.backend" python/warrantor_ml/src/warrantor_ml/parity.py
parity.py:277:    baseline_lane = str(baseline.backend.get("lane", ""))
parity.py:278:    baseline_precision = str(baseline.backend.get("precision", ""))
parity.py:410:        error_rate = candidate.backend_error_count / candidate.scored_samples
parity.py:414:            f"{candidate.backend_error_count} backend errors over "
```

The same grep against `programme.py` returns nothing at all. Lines 277-278 read the **baseline's**
backend. Lines 410 and 414 read `backend_error_count`, a different field. `candidate.backend` is read by no line of source and asserted by no test
(`test_parity.py:500` puts `"backend": {"kind": "ollama"}` into a fixture and never looks at the
loaded value). The gate holds the evidence and does not consult it.

**Finding B — the one thing that does compare evaluated against deployed is a `cargo test`, and it
covers seven knobs, none of them quantization.** `rust/warrant/tests/guard_parity.rs` (182 lines)
makes `evaluate.py` a compile-time input via `include_str!` at line 32 and asserts
`GuardKnobs::default()` matches the Python literal for `num_ctx`, `num_predict`, `seed`,
`temperature`, `top_p`, `top_k` and `controversial_is_harmful`. Its own header states the defect it
exists to prevent — `rust/warrant/tests/guard_parity.rs:5-9`:

```rust
//! This crate shipped `num_ctx: 4096` for eight releases while every published figure was measured
//! at 8192 by `python/warrantor_ml`. The consequence was not that the guard was worse — it was that
//! **nobody knew what it was**, because the configuration in production was not the configuration
//! any measurement was taken under
```

So the seed's premise 3 is not merely unmeasured, it is **already discharged** on the axis it names.
`rust/warrant/src/guard.rs:161` holds `pub const MEASURED_NUM_CTX: u32 = 8192;` and `guard.rs:171-196`
declares `GuardKnobs` — which has **no quantization field at all**. Confirmed:

```
$ grep -rn "num_ctx\|quantis\|quantiz" python/warrantor_ml/src/warrantor_ml/parity.py \
        python/warrantor_ml/src/warrantor_ml/deploy_model.py \
        python/warrantor_ml/src/warrantor_ml/model_card.py
(no output; exit 0)
```

**Finding C — quantization is compared, but only through a string the operator types.**
`baselines.py:198-220` records the full serving configuration of every baseline:

```python
# python/warrantor_ml/src/warrantor_ml/baselines.py:210-220
    return {
        "kind": "ollama", "model": model,
        "quantisation": "Q4_K_M", "num_ctx": 8192,
        "temperature": 0.0, "top_k": 1, "seed": 0,
        "lane": "local-rtx5080", "precision": "gguf-q4_k_m",
    }
```

`_lane_matches` (`parity.py:274-294`) compares exactly two of those nine keys — `lane` and
`precision` — and `baselines.py:202-204` says so in its own comment: *"Nothing refused it —
`warrantor_ml.parity._lane_matches` reads only `lane` and `precision`."* Both come from argv, not from
the artifact: `programme.py:234` is `parser.add_argument("--precision", required=True)` and
`programme.py:266` passes `precision=arguments.precision` straight into `load_candidate_result`.
**The candidate's quantization is whatever the operator declares it to be**, and `quantisation`,
`num_ctx`, `temperature`, `top_k` and `seed` are recorded on the baseline and compared against nothing.

**Finding D — no candidate result document records its quantization, so there is nothing to compare
even if the gate looked.** Captured over the committed evidence:

```
$ python -c "import json; d=json.load(open('eval_results/warrantor-guard-0.6b-expguard-weak-exp06-2026-08-22a.json',encoding='utf-8')); print(sorted(d['backend'])); print('quantisation' in d['backend']); print(d['backend']['model'])"
['endpoint', 'kind', 'model', 'options', 'seed']
False
warrantor-guard-0.6b-expguard-weak-exp06-2026-08-22a
```

The two baseline documents name their quantization inside the model tag
(`hf.co/mradermacher/Qwen3Guard-Gen-4B-GGUF:Q4_K_M`). The five candidate tags carry **no quantization
label at all**. `evaluate.py:275-283` (`descriptor()`) is the function that writes this block and it
emits no quantization field. And the deployed inventory disagrees on size with the baselines those
candidates were compared against — `docs/model-inventory-reconciliation-2026-09-01.md:23-31` (on
`docs/content-program-p9-fold`, cited as context and not as a landed record) lists the `Q4_K_M`
baselines at **0.48 GB / 2.72 GB** and every 2026-08-22 candidate at **0.50 GB / 2.78 GB**. Whether
that gap is a merged adapter's extra tensors or a different quantization **cannot be determined from
anything in the pipeline**, because the candidate declares nothing. That is the defect, stated without
overclaiming what the sizes prove.

**Finding E — the promotion the pipeline granted, re-run here.** Against the promoted candidate's own
committed result document, with this worktree's code:

```
$ PYTHONPATH=".../src" python -c "...parity_main(['--result','eval_results/warrantor-guard-0.6b-expguard-weak-exp06-2026-08-22a.json','--recipe','guard-0.6b-expguard-weak','--lane','local-rtx5080','--precision','gguf-q4_k_m','--manifest-digest','sha256:0…0','--breakdown-key','expguard_breakdowns'])"
"verdict": "insufficient_evidence"
"reasons": ["1 eval row(s) appear in the training corpus (0 distinct collisions) …"]
"counts": {"candidate": {"caught": 982, "positives": 1256, "false_positives": 56, "negatives": 1019},
           "baseline":  {"caught": 898, "positives": 1256, "false_positives": 89, "negatives": 1019}}
"decision_digest": "sha256:cf73155bc7e6ca3861807b4422e80a7f1747609712d296c6c2895ff15617bcfd"
EXIT=3
```

982/1256 = 0.7818 against 898/1256 = 0.7150, and 56/1019 = 0.0550 against 89/1019 = 0.0873 —
reproducing the recorded promotion to four places. The refusal here is the leakage precondition firing
because the corpora were not supplied, which is correct behavior and **not** a configuration refusal:
`--precision gguf-q4_k_m` was accepted without challenge against a document that records no
quantization. Exit 3, not 1, because `insufficient_evidence` and `reject` are deliberately different
codes (`programme.py:311`).

**Finding F — the deploy step requires no parity receipt.** L9-03's verification text says an adapter
without one *"is refused by the deploy step."* Captured:

```
$ grep -rn "parity\|ParityDecision\|decision_digest" python/warrantor_ml/src/warrantor_ml/deploy_model.py
deploy_model.py:304:  let gated_by_category = labels.iter().any(...)
deploy_model.py:310:  (severity_harmful || gated_by_category, categories, gated_by_category)
deploy_model.py:340:  let (is_harmful, flagged_categories, gated_by_category) = Self::parse(&raw);
deploy_model.py:350:  detail: Some(format!("gated_by_category={{gated_by_category}}")),
```

Four hits, all the substring `gate` inside `gated_by_category` in the generated Rust template. There
is **no** reference to a parity decision anywhere in the deploy path. `build_registration`
(`deploy_model.py:144-210`) refuses on an incomplete model card and on a malformed weights digest, and
on nothing else. `model_card.py`'s `REQUIRED_FIELDS` carries `evaluation.recall`,
`evaluation.eval_set_digest`, `evaluation.result_digest` and six more — and **no serving-configuration
field** — so L9-04's `status=built` claim that *"every published figure carries the configuration that
produced it: context length, seed, quantization, sampling profile"* is not enforced by the card
validator. That is L9-04's problem to answer; it is named here so this task does not inherit its claim.

**Finding G — the generated adapter pins nothing.** `_ADAPTER_TEMPLATE` (`deploy_model.py:223-358`)
emits `SCANNER_ID`, `MODEL_DIGEST`, `ENDPOINT`, `REQUEST_TIMEOUT_MS` and `OPERATING_THRESHOLD` — and
no `num_ctx`, `seed`, `temperature`, `top_p`, `top_k` or quantization.
`GuardTransport = Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>` (line 241) hands the HTTP
request to the caller, so a registered scanner runs at whatever the caller's client and the Ollama
server default to. The `warrantor guard` CLI path is pinned by `MEASURED_NUM_CTX`; **the registered
`ContentScanner` path is not pinned at all.**

**Finding H — `rust/eval-guard` is not the guard evaluator, and must not be wired to.** Its own docs,
`rust/eval-guard/src/lib.rs:8-11`: *"It does not perform the checks. `run_preflight` takes
`CheckResults` as an input: four booleans the caller has already decided ... It has no eBPF, opens no
sockets, inspects no namespaces, and cannot observe the sandbox at all."* It notarizes a sandbox
pre-flight assertion over `NetworkIsolation`, `FilesystemBoundary`, `ProcessIsolation` and
`EgressAttestation` (`lib.rs:40-49`). Its refusal shape is the right shape to copy — `run_preflight`
(`lib.rs:187-190`) returns `Err(EvalGuardError::CheckFailed(check))` before signing anything — but it
has nothing to do with model promotion. It is read here so nobody bolts a promotion gate onto it. Its
`#[ignore]` at `rust/warrant/tests/invariants/i09_failure_is_safe.rs:196` reads *"I-09 orphaned:
eval-guard's fail-closed preflight is not linked by the warrantor binary (2026-09-02)"* — a wiring
defect **this task does not convert**, because this task adds no Rust link.

---

**Non-goals.**

- **The refusal corpus and `per-plane specialist corpora` — Task 12.2.** This task never changes what
  a corpus contains, never adds a training row, and never re-examines the specialization result. It
  reads corpora only for the leakage precondition that already exists.
- **Adversarial phrasing and severity stability — Task 12.4, already expanded.** Read its section
  before starting. It owns `paired_analysis.py`, the severity census over `eval_results/*.json`, and
  the `severity_classes_lost` defect. This task asserts nothing about any severity field, and its exit
  gate touches no severity axis, so the two gates cannot both claim the same refusal.
- **The graduation ladder and the `not-promotable` rung — Task 12.6.** The seed's Step 5 ("'not
  promotable' is a representable outcome") is 12.6's exit gate verbatim and is deleted from this task.
  This task produces the configuration verdict 12.6's ladder consumes; it builds no rung, records no
  checkpoint disposition, and does not decide what happens to the five historical candidates.
- **The external benchmark harness and the evaluation bill of materials — Task 14.2.** This task adds
  no new scoring path. `score_candidate` (`parity.py:227-247`) stays the single documented way to
  produce a comparable result, for the reason its own docstring gives.
- **Guard-model exposure, poisoning and membership inference — Task 12.5.** Nothing here reasons about
  what a guard leaks about the receipts it was trained on.
- **Not choosing or training a model, and not re-running any of the five recipes.** No GPU is touched.
  Every test in this task runs offline against committed documents.

---

**Files.**

- `python/warrantor_ml/src/warrantor_ml/serving.py` — **new.** The single deployed-configuration
  record and its digest.
- `python/warrantor_ml/src/warrantor_ml/evaluate.py` — `OllamaGuardBackend` defaults derive from
  `serving.py`; `descriptor()` emits the quantization field.
- `python/warrantor_ml/src/warrantor_ml/parity.py` — the configuration refusal inside `parity_gate`.
- `python/warrantor_ml/src/warrantor_ml/deploy_model.py` — the parity-receipt refusal in
  `build_registration`; serving constants in the generated adapter.
- `python/warrantor_ml/src/warrantor_ml/programme.py` — `--precision` becomes an optional cross-check
  of the document rather than the source of truth.
- `python/warrantor_ml/tests/test_serving.py` (new), `test_parity.py`, `test_deploy_model.py`,
  `test_evaluate.py`.
- `rust/warrant/tests/guard_parity.rs` — extended to bind the Rust side to `serving.py`.
- `tools/ci/check_deployment_parity.py`, `tools/ci/test_check_deployment_parity.py` and
  `tools/ci/deployment-parity.json` — the CI gate, its test, and the record its rendered number is
  checked against.
- `docs/task-evidence/task-12.3.md` — the evidence file.

**No new crate. No new Rust dependency.** The wiring census must still print `10 of 40 crates
reachable ... over 18 path edges`, and `tools/ci/invariant-ratchet.json` stays at `passing_floor: 66`,
`ignored_ceiling: 18`.

---

**Consumes / Produces.**

Consumes, all landed on `main` at `b04164d`:

```python
# python/warrantor_ml/src/warrantor_ml/parity.py:296-302
def parity_gate(
    candidate: CandidateResult,
    gate_slice: str,
    leakage: LeakageReport,
    baseline_id: str | None = None,
    minimum_positives: int = MINIMUM_POSITIVES,
) -> ParityDecision:

# python/warrantor_ml/src/warrantor_ml/parity.py:167-175
def load_candidate_result(
    path: Path, candidate_id: str, baseline_id: str, lane: str,
    precision: str, manifest_digest: str,
    breakdown_key: str = "wildguard_breakdowns",
) -> CandidateResult:

# python/warrantor_ml/src/warrantor_ml/deploy_model.py:144-150
def build_registration(
    card: dict[str, Any], endpoint: str, scanner_id: str | None = None,
    model_ref: str | None = None, request_timeout_ms: int = 5_000,
) -> ScannerRegistration:

# python/warrantor_ml/src/warrantor_ml/evaluate.py:275-283
    def descriptor(self) -> dict[str, Any]:   # writes the result document's `backend` block

# python/warrantor_ml/src/warrantor_ml/baselines.py:198  _ollama_backend(model) -> dict[str, Any]
# python/warrantor_ml/src/warrantor_ml/baselines.py:498  get_baseline(baseline_id) -> MeasuredBaseline
# python/warrantor_ml/src/warrantor_ml/stats.py:81       significant_improvement(...)
# rust/warrant/src/guard.rs:161                          pub const MEASURED_NUM_CTX: u32 = 8192;
```

Produces:

```python
# python/warrantor_ml/src/warrantor_ml/serving.py  (new)
DEPLOYED: Final[Mapping[str, Any]]           # the one deployed serving configuration
def deployed_digest() -> str                 # sha256 over canonical_json(DEPLOYED)
def configuration_mismatch(recorded: Mapping[str, Any]) -> tuple[str, ...]
    """Every field on which a recorded configuration differs from DEPLOYED, or is absent.
    Empty tuple means parity. Absence is a mismatch, never a match."""

# python/warrantor_ml/src/warrantor_ml/deploy_model.py  (extended signature)
def build_registration(
    card: dict[str, Any], endpoint: str, parity_receipt: Mapping[str, Any],
    scanner_id: str | None = None, model_ref: str | None = None,
    request_timeout_ms: int = 5_000,
) -> ScannerRegistration
    """Raises RegistrationError unless parity_receipt["verdict"] == "promote"."""
```

**Nothing this task consumes is unlanded.** Task 12.4's `paired_analysis.py` and the two 2026-09-01
findings documents are **not** on `main` — that is why no step here depends on them, and why no exit
gate here mentions severity. Task 12.6's ladder does not exist yet and this task does not need it: the
configuration verdict is written into the decision document 12.6 will later read, so the dependency
runs 12.3 → 12.6 and never the other way.

---

**Bound strength.**

**Tier B, chokepoint, at two points in the release path — and Tier C, observed, for everything after
those points.**

- **Tier B, `warrantor-ml-parity`.** `parity_gate` returns `insufficient_evidence` and `parity_main`
  exits 3 **without writing a decision document**, at the moment a promotion is attempted, when the
  candidate's recorded serving configuration is absent or differs from `serving.DEPLOYED`. That is a
  specific line refusing at the moment of attempt. It binds only promotions that pass through this
  CLI; a candidate registered by hand does not.
- **Tier B, `build_registration`.** It raises `RegistrationError` before emitting a registration
  document or a Rust adapter when the parity receipt is missing, malformed, or carries a verdict other
  than `promote`. Same shape, same limit.
- **Tier C, observed, for serve time.** Nothing here measures a running process. The gate compares two
  **records**: a configuration the evaluator wrote into a result document, and a configuration this
  repository declares to be the deployed one. A serving process started outside the generated
  adapter — a different Ollama client, a `num_ctx` override on the request, a re-quantized GGUF pushed
  under an unchanged tag — is not observed and is not refused. There is **no** namespace, seccomp or
  firewall enforcement anywhere in this repository, and none is added here.
- **The build-time binding is Tier B at build, not at run.** `guard_parity.rs` fails `cargo test` when
  the Rust constants and the Python literals disagree. That refuses a **build**, which is a real
  refusal with a real chokepoint (CI), and it says nothing about what a deployed binary is doing.

**No new trust root.** `serving.DEPLOYED` is a repository-declared record, not an attestation. It
establishes that *this checkout's evaluator, its promotion gate, its generated adapter and its Rust
CLI all read one value*. It does not establish that the value is what any machine ran, and it is signed
by nothing. The weaker local version is the honest one: a single in-repo declaration with a digest, so
a divergence is a diff rather than an argument.

**No new orphan.** No crate is added; the census holds at 10 of 40 over 18 path edges. No recorded
invariant violation is converted, so `passing_floor` stays 66 and `ignored_ceiling` stays 18. A
thirteenth ignore would raise the ceiling and fail the build; none is added.

**The sentence that ships in the product, verbatim, in the decision document and in the registration
document's `notes`:**

> This gate compares the configuration recorded in the evaluation document against the configuration
> this build declares it serves. It does not observe the serving process. It cannot detect a context
> length overridden per request, a model re-quantized under an unchanged tag, or a scanner reached by
> any path other than the generated adapter — and it gates only capabilities present in the evaluation
> set.

---

**Exit gate.** One command decides pass or fail:

```
python tools/ci/check_deployment_parity.py
```

It passes only when all four hold, and prints one line naming each:

1. Every result document under `eval_results/` is classified `parity` or `refused`, with the reason
   named, and the counts equal the recorded expectation in `tools/ci/deployment-parity.json` — the
   rendered number is gated against its record and a drift fails the build.
2. A promotion attempt whose recorded configuration differs from `serving.DEPLOYED` in quantization
   exits non-zero and writes no decision document.
3. A registration attempt with no `promote` parity receipt raises `RegistrationError` and writes no
   registration and no adapter.
4. `serving.deployed_digest()` equals the digest recorded in `tools/ci/deployment-parity.json`, and
   `rust/warrant/src/guard.rs`'s `MEASURED_NUM_CTX` equals `DEPLOYED["num_ctx"]`.

Expected first line, with the numbers this branch's evidence produces:

```
deployment parity: 7 documents scanned; 2 parity, 5 refused (no serving quantization recorded);
  deployed digest sha256:… matches record; MEASURED_NUM_CTX 8192 == DEPLOYED num_ctx
```

---

- [ ] **Step 1 — Worktree and branch.** No production edit happens outside it.

  ```bash
  export PATH="$PATH:/c/Users/MuVeraAICorporation/.cargo/bin"
  cd "M:/Project AumOS - Open Secure AI Alliance/aumos"
  git worktree add M:/wt-12.3 -b feat/deployment-configuration-parity main
  cd M:/wt-12.3 && export CARGO_TARGET_DIR=M:/wt-12.3-target
  export PYTHONPATH="M:/wt-12.3/python/warrantor_ml/src"
  python -c "import warrantor_ml.parity as p; print(p.__file__)"   # MUST print M:\wt-12.3\...
  ```

  **Test intent:** none yet. The step is complete only when `p.__file__` names this worktree, because
  every later assertion is void otherwise — see Step 0's captured `M:\wt-2point1` result.

- [ ] **Step 2 — Record Step 0 verbatim into the evidence file, before writing any code.**
  `docs/task-evidence/task-12.3.md` opens with the eight findings above, each with its command and its
  captured output, and with the three corrected premises stated as corrections rather than quietly
  dropped. The three baseline lines (`wiring census`, `invariant ledger`, ratchet floor and ceiling)
  are pasted in as the numbers the exit gate is compared against at the end.

  **Test intent:** the evidence file is an input to the exit gate, not a report. Step 10 re-runs the
  three baseline commands and diffs their output against what this step pasted; a drift fails. The
  mechanism is the diff, not the prose.

- [ ] **Step 3 — Failing test: the gate ignores the candidate's own recorded configuration.** This is
  the test that proves Finding A is a defect and not a style preference. It must fail on `main`.

  ```python
  # python/warrantor_ml/tests/test_parity.py
  def test_a_candidate_whose_document_records_a_different_context_length_is_refused() -> None:
      """The gate holds `candidate.backend` and, on `main`, reads nothing out of it.

      This is not hypothetical drift: this repository shipped num_ctx 4096 for eight releases
      while every published figure came from 8192 (rust/warrant/tests/guard_parity.rs:5-9). The
      Rust side is pinned against evaluate.py by that test; the PROMOTION path is pinned against
      nothing, so a result document produced at any context length promotes.
      """
      document = _result_document(caught=990, positives=1256, false_positives=40, negatives=1019)
      document["backend"] = {
          "kind": "ollama",
          "model": "warrantor-guard-0.6b-expguard-weak-exp06-2026-08-22a",
          "quantisation": "Q4_K_M",
          "seed": 0,
          "options": {"temperature": 0.0, "top_p": 1.0, "top_k": 1,
                      "seed": 0, "num_predict": 64, "num_ctx": 4096},
      }
      decision = parity_gate(_load(document), "overall", _clean_leakage())
      assert decision.verdict == "insufficient_evidence"
      assert any("num_ctx" in reason and "4096" in reason for reason in decision.reasons), (
          "the gate must name the field and both values; 'configuration mismatch' is not a "
          "reason an operator can act on"
      )
      assert decision.evidence["deployed_configuration_digest"]
  ```

  **Test intent:** fail with `assert decision.verdict == 'insufficient_evidence'` receiving
  `'promote'`. Record that failure in the evidence file — it is the proof the field was dead.

- [ ] **Step 4 — `serving.py`: one declared deployed configuration, with a digest.** Nine keys, in the
  shape `baselines._ollama_backend` already uses so the two are comparable without a translation
  layer. `evaluate.OllamaGuardBackend`'s defaults are then **derived** from it rather than repeated
  next to it — by construction rather than by agreement, which is the phrase `programme._read_corpus`
  already uses for the same class of defect.

  ```python
  # python/warrantor_ml/src/warrantor_ml/serving.py
  """The one place the deployed serving configuration is written down.

  Four things read a serving configuration in this repository and, before this module, four things
  declared one: evaluate.OllamaGuardBackend's dataclass defaults, baselines._ollama_backend's
  literal, rust/warrant/src/guard.rs's GuardKnobs, and whatever HTTP client a caller hands to the
  generated ContentScanner adapter. Three of the four were bound to each other by
  rust/warrant/tests/guard_parity.rs. The fourth was bound to nothing, and the promotion gate
  compared none of them.
  """
  QUANTIZATION: str = "Q4_K_M"
  NUM_CTX: int = 8192
  SEED: int = 0
  NUM_PREDICT: int = 64

  #: Absence is a mismatch. A recorded configuration that omits a key is not a configuration that
  #: agrees on it, and treating the two the same is how the 4096 release shipped.
  REQUIRED_KEYS: Final[tuple[str, ...]] = (
      "quantisation", "num_ctx", "seed", "num_predict", "temperature", "top_p", "top_k",
  )

  def configuration_mismatch(recorded: Mapping[str, Any]) -> tuple[str, ...]:
      """Field-by-field differences against DEPLOYED. Empty means parity."""
  ```

  **Test intent:** `test_serving.py` asserts that an empty input yields one entry per required key
  rather than an empty tuple. That single assertion is the whole design: absence must never read as
  agreement.

  ```python
  def test_an_absent_field_is_a_mismatch_and_not_a_match() -> None:
      missing = configuration_mismatch({})
      assert len(missing) == len(REQUIRED_KEYS)
      assert all("absent" in entry for entry in missing)

  def test_the_deployed_record_agrees_with_itself() -> None:
      assert configuration_mismatch(DEPLOYED) == ()
  ```

- [ ] **Step 5 — Extend `guard_parity.rs` to read `serving.py`, and let it fail first.** Pointing
  `evaluate.py`'s defaults at `serving.py` removes the literal `num_ctx: int = 8192` that
  `guard_parity.rs:39-58` parses, so
  `the_python_source_is_still_shaped_the_way_these_assertions_read_it` fails with *"cannot read the
  Python default for num_ctx: the parity comparison is not being made."* **That failure is the proof
  the binding was live**, and it is recorded in the evidence file before being fixed. The fix is a
  second `include_str!`, never a deleted assertion.

  ```rust
  // rust/warrant/tests/guard_parity.rs
  /// The Python evaluator, as a compile-time string.
  const EVALUATE_PY: &str = include_str!("../../../python/warrantor_ml/src/warrantor_ml/evaluate.py");
  /// The declared deployed configuration, as a compile-time string. Added when evaluate.py stopped
  /// carrying its own literals: these assertions must follow the value, not the file it used to
  /// live in.
  const SERVING_PY: &str = include_str!("../../../python/warrantor_ml/src/warrantor_ml/serving.py");

  #[test]
  fn the_quantization_the_python_side_declares_is_the_one_this_crate_serves() {
      // The axis nothing pinned. num_ctx was pinned twice and then measured inert -- 0 of 493
      // decision changes across a sixteenfold range, both models. Quantization was pinned nowhere
      // and moves 4 to 18 verdicts per thousand at the deployed default, in a direction that
      // differs by model family. GuardKnobs has no quantization field, so this asserts against the
      // model tag the CLI resolves rather than against a knob that does not exist.
      let declared = python_default_in(SERVING_PY, "QUANTIZATION")
          .expect("serving.py declares QUANTIZATION");
      assert_eq!(declared, "\"Q4_K_M\"");
      assert!(
          warrantor_warrant::guard::default_model_tag().contains("Q4_K_M"),
          "the CLI's default guard model tag must name the quantization the Python side declares \
           it measured at; an unlabeled tag is a configuration nobody can check"
      );
  }
  ```

  **Test intent:** two failures, in order — first the reformat failure that proves the old binding was
  doing work, then this new test failing until `serving.py` and the CLI's default tag agree. Both are
  captured in the evidence file. `cargo test -p warrantor-warrant --test guard_parity` is the command.

- [ ] **Step 6 — The refusal, with its allowed control.** `parity_gate` gains one blocking
  precondition, placed with the others at `parity.py:361-421` so it composes with them rather than
  short-circuiting them. The reason string names the field, both values, and the measured effect,
  because a refusal an operator cannot act on gets bypassed rather than fixed.

  ```python
  # python/warrantor_ml/src/warrantor_ml/parity.py, inside parity_gate's precondition block
  recorded = _recorded_serving_configuration(candidate.backend)
  evidence["recorded_serving_configuration"] = recorded
  evidence["deployed_configuration_digest"] = serving.deployed_digest()
  if mismatches := serving.configuration_mismatch(recorded):
      blocking.append(
          "the candidate was evaluated at a configuration this build does not serve: "
          + "; ".join(mismatches)
          + ". Quantization is not verdict-neutral at the deployed default -- between 4 and 18 "
          "verdicts per thousand change at Q4_K_M across five measured models, and the DIRECTION "
          "does not generalize, so this cannot be waved through as 'probably safer'. A promotion "
          "measured at a configuration the product does not serve is a promotion of a model that "
          "does not ship."
      )
  ```

  Paired allowed control, in the same commit, and it must promote:

  ```python
  def test_a_candidate_recorded_at_the_deployed_configuration_still_promotes() -> None:
      """The allowed control for the refusal above. A gate that refuses everything is not a gate."""
      document = _result_document(caught=990, positives=1256, false_positives=40, negatives=1019)
      document["backend"] = _backend_at(serving.DEPLOYED)
      decision = parity_gate(_load(document), "overall", _clean_leakage())
      assert decision.verdict == "promote", decision.reasons
      assert decision.evidence["recorded_serving_configuration"]["quantisation"] == "Q4_K_M"
      assert decision.evidence["deployed_configuration_digest"] == serving.deployed_digest()
  ```

  **Test intent:** Step 3's refusal turns green, this control stays green, and all 51 existing
  `test_parity.py` and `test_deploy_model.py` assertions still pass. If an existing test breaks, its
  fixture was relying on the absent field and the fixture is what changes — never the refusal.

- [ ] **Step 7 — `--precision` stops being the source of truth.** `programme.py:234` currently makes
  the operator's string authoritative. It becomes an optional cross-check: when supplied it must equal
  what the document records, and a disagreement is itself a refusal. `evaluate.descriptor()` gains the
  quantization field so future documents can be checked at all, and the schema bump is recorded
  because it changes `result_digest`.

  ```python
  # python/warrantor_ml/src/warrantor_ml/evaluate.py, descriptor()
  return {
      "kind": "ollama",
      "model": self.model,
      "endpoint": self.endpoint,
      "seed": self.seed,
      # Added at SCHEMA_VERSION 2. The five 2026-08-22 candidate documents record no quantization
      # at all -- their Ollama tags carry no label -- so the gate could not have compared it even
      # if it had looked. Resolved from the tag when the tag names it, and from --quantization
      # otherwise; NEVER defaulted, because a defaulted value would make every historical document
      # silently agree with whatever this build happens to serve.
      "quantisation": self.quantisation,
      "options": self._options(),
  }
  ```

  ```python
  def test_the_operator_cannot_declare_a_precision_the_document_contradicts(tmp_path) -> None:
      document = _result_document(caught=990, positives=1256, false_positives=40, negatives=1019)
      document["backend"] = _backend_at({**serving.DEPLOYED, "quantisation": "Q8_0"})
      decision_path = tmp_path / "decision.json"
      exit_code = parity_main([*_base_arguments(document), "--precision", "gguf-q4_k_m",
                               "--out", str(decision_path)])
      assert exit_code == 3
      assert not decision_path.exists(), "a refused promotion writes no decision document"

  def test_the_document_alone_is_enough_and_precision_may_be_omitted(tmp_path) -> None:
      """Allowed control: the artifact decides, not argv. Omitting --precision must still work."""
      document = _result_document(caught=990, positives=1256, false_positives=40, negatives=1019)
      document["backend"] = _backend_at(serving.DEPLOYED)
      assert parity_main([*_base_arguments(document)]) == 0
  ```

  **Test intent:** the declared string and the recorded value disagree, and the gate refuses on the
  recorded one. The paired control proves the same call promotes when `--precision` is omitted
  entirely, which is the point — the artifact, not the argument vector, decides.

- [ ] **Step 8 — The deploy step refuses without a `promote` receipt.** This is L9-03's verification
  text, which nothing on `main` implements (Finding F). `build_registration` takes the receipt, and
  every refusal precedes every write.

  ```python
  # python/warrantor_ml/src/warrantor_ml/deploy_model.py, in build_registration
  verdict = str(parity_receipt.get("verdict", ""))
  if verdict != "promote":
      raise RegistrationError(
          f"parity verdict is {verdict!r}; only 'promote' may be registered. An adapter with no "
          "gate receipt is an adapter whose ScannerVerdict.model_digest binds to a number nobody "
          "compared -- and `insufficient_evidence` is not a weaker 'promote', it is the gate "
          "saying it could not tell."
      )
  if not is_wellformed_digest(str(parity_receipt.get("decision_digest", ""))):
      raise RegistrationError(
          "the parity receipt carries no well-formed decision_digest, so the registration would "
          "cite evidence that cannot be re-audited"
      )
  recorded = parity_receipt.get("recorded_serving_configuration", {})
  if serving.configuration_mismatch(recorded):
      raise RegistrationError(
          "the promoted candidate was evaluated at a configuration this build does not serve: "
          + "; ".join(serving.configuration_mismatch(recorded))
      )
  ```

  ```python
  def test_registration_is_refused_without_a_promote_receipt() -> None:
      for verdict in ("reject", "insufficient_evidence", ""):
          with pytest.raises(RegistrationError, match="only 'promote' may be registered"):
              build_registration(example_card(), endpoint=ENDPOINT,
                                 parity_receipt={"verdict": verdict})

  def test_registration_succeeds_with_a_promote_receipt_at_the_deployed_configuration() -> None:
      """The allowed control. The refusal above is worthless if nothing can be registered."""
      receipt = {"verdict": "promote", "decision_digest": f"sha256:{'a' * 64}",
                 "recorded_serving_configuration": dict(serving.DEPLOYED)}
      registration = build_registration(example_card(), endpoint=ENDPOINT, parity_receipt=receipt)
      body = registration.to_dict()
      assert body["parity_receipt"]["decision_digest"] == receipt["decision_digest"]
      assert body["serving"]["num_ctx"] == 8192
      assert any("does not observe the serving process" in note for note in body["notes"])
  ```

  **Test intent:** three refusals and one allowance, and the refused paths write nothing —
  `write_registration` is never reached, so no partial document exists on disk to be mistaken for a
  registration. The third assertion in the control is the mechanism for the Tier C half of the claim:
  the honesty sentence is in the shipped document, not only in this plan.

- [ ] **Step 9 — The generated adapter carries the serving constants, and says what they do not do.**
  Finding G: the `warrantor guard` CLI is pinned and the registered `ContentScanner` path is not.

  ```rust
  // added to _ADAPTER_TEMPLATE in deploy_model.py
  /// The serving configuration this scanner was PROMOTED at. The transport closure is the
  /// caller's, so these are values the caller MUST send -- this adapter cannot enforce them.
  /// Sending different ones serves a model nobody measured.
  pub const SERVED_QUANTIZATION: &'static str = "{quantisation}";
  pub const SERVED_NUM_CTX: u32 = {num_ctx};
  pub const SERVED_SEED: i64 = {seed};
  pub const SERVED_NUM_PREDICT: u32 = {num_predict};
  ```

  ```python
  def test_the_generated_adapter_names_the_configuration_it_was_promoted_at() -> None:
      source = render_rust_adapter(_promoted_registration())
      assert f"SERVED_NUM_CTX: u32 = {serving.NUM_CTX};" in source
      assert f'SERVED_QUANTIZATION: &\'static str = "{serving.QUANTIZATION}";' in source
      assert "this adapter cannot enforce them" in source, (
          "the comment is the mechanism for the Tier C half of the claim: the constants are "
          "declarative and the closure is the caller's, and the generated file has to say so "
          "or a later reader will upgrade it to enforcement in their head"
      )
  ```

  **Test intent:** the constants are present and equal `serving.DEPLOYED`, and the honesty comment is
  present. **This step adds no enforcement.** It is a Tier C observed claim, and the assertion on the
  comment is what keeps it labeled that way.

- [ ] **Step 10 — CI gate, ratchet, census, evidence, `git commit -s`.** One command, one line, and
  the rendered number checked against its record.

  ```bash
  cd M:/wt-12.3 && export PYTHONPATH="M:/wt-12.3/python/warrantor_ml/src"
  python -c "import warrantor_ml.parity as p; print(p.__file__)"      # this worktree, or stop
  python -m pytest python/warrantor_ml/tests -q                        # 609 + new, 0 failed
  cargo test -p warrantor-warrant --test guard_parity
  python tools/ci/check_deployment_parity.py                           # THE EXIT GATE
  python -m pytest tools/ci/test_check_deployment_parity.py -q
  python tools/ci/wiring_census.py       # 10 of 40 crates ... 18 path edges — unchanged
  python tools/ci/check_invariants.py    # 12 invariants; enforced=2, orphaned=2, partial=7, unimplemented=1
  python tools/ci/check_invariant_ratchet.py   # floor 66, ceiling 18 — READ from the test line
  python tools/ci/check_us_english.py --files docs/task-evidence/task-12.3.md
  git add -A && git commit -s -m "feat(ml): refuse a promotion evaluated at a configuration the build does not serve"
  ```

  ```python
  # tools/ci/check_deployment_parity.py — the rendered number is gated against its record
  recorded = json.loads(RECORD.read_text(encoding="utf-8"))
  if (scanned, parity, refused) != (recorded["scanned"], recorded["parity"], recorded["refused"]):
      print(f"deployment parity: counts moved -- scanned {scanned} parity {parity} refused "
            f"{refused}, record says {recorded['scanned']}/{recorded['parity']}/"
            f"{recorded['refused']}. A number this gate prints must match the number it was "
            "recorded against, or the printed one is decoration. Update the record in the same "
            "commit that earns it.")
      return 1
  if serving.deployed_digest() != recorded["deployed_digest"]:
      print("deployment parity: the deployed configuration changed and every published figure was "
            "measured at the old one. Re-measure, or do not move it.")
      return 1
  ```

  **Test intent:** `tools/ci/test_check_deployment_parity.py` asserts the script returns 1 when the
  record disagrees and 0 when it agrees, over a temporary directory rather than the real
  `eval_results/`. `tools/ci/invariant-ratchet.json` is **unchanged** — this task converts no recorded
  violation, so raising `passing_floor` would be a claim without a mechanism, and the 18 existing
  `#[ignore]`s in `rust/warrant/tests/invariants/` are untouched. The evidence file closes with the
  five refused documents named, the reason for each, and the three premises the seed got wrong, so a
  reader of the plan does not carry them forward into Task 12.6.
