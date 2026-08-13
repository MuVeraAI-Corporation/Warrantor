# RFC W2 — Model-intelligence pipelines: eight models, three lanes, one gate

Status: implemented (pipelines and harness; no training run executed)
Component: W10 content-moderation plane, and the substrate models that serve W1
Supersedes: nothing. Extends the model-intelligence lane established in `ml/README.md`.

## Background

The model-intelligence lane already has a dataset registry, a recall-first evaluator, a signed
AIBOM, a VRAM-aware training planner, and two benchmarks that measured a real baseline on real
held-out data. What it does not have is a way to **improve** anything and prove that it did.

The measured baseline is the reason to try. Qwen3Guard-Gen-4B on WildGuardTest posts recall
0.8554 overall — and 0.8152 under adversarial phrasing, where the false-positive rate
simultaneously quadruples from 0.0224 to 0.0923. On ExpGuardTest it posts 0.7596, dragged there
by one class: `Unqualified Professional Advice` at 0.4298 against 0.7947 for everything else.
Those are not aggregate disappointments; they are named, located weaknesses with row counts
attached, which is exactly the shape of problem an adapter can address.

Separately, four capabilities the substrate promises are not backed by a model at all. The most
concrete is `/v1/summary/refusals`, which serves the sentence *"the same wall in more than one
run is usually a bound that is wrong rather than an agent that is wrong"* — a sentence produced
by comparing two constants, `REPEATED_OCCURRENCES = 5` and `SPREAD_WARRANTS = 2`. It reads like
a judgement and is a threshold.

This RFC specifies the data pipelines, training recipes and blind parity-eval harness for eight
models, and the refusals that keep them from doing more harm than good. **No training run is
executed and no remote job is dispatched by any code described here.** Everything is inert until
an orchestrator acts on it.

### Relationship to the surfaces RFC (W1)

W1 governs where verdicts come from, and this RFC is subordinate to it on every point. Two of
its constraints do structural work here rather than appearing as warnings:

- **A model's output is never a verdict.** Model judgements become *signals* recorded against a
  warrant. Integrity remains an Ed25519 question with a three-valued answer — `ok`, `failed`,
  `unknown` — and `unknown` is never rendered as `failed`.
- **Verification happens only in Rust, client-side.** No signature check, no key, and no digest
  comparison lives above the Rust line, because a second verifier can disagree with the first
  and then a human has to decide which to believe.

Models 6 and 8 are the two that press hardest on those, and the Detailed Design below explains
how each is made structurally unable to violate them rather than merely instructed not to.

## Goals

1. **Eight models, honestly counted as five pipelines.** Four guard adapters share one corpus
   builder and one recipe shape; the four substrate models each need their own.
2. **Reproducible and portable across three lanes** — local RTX 5080 (16 GB), Kaggle
   (T4/P100, 12-hour session cap, 30 GPU-h/week), Modal (A100). A recipe is data with a digest,
   so a Kaggle run and a Modal run of "the same recipe" are provably the same recipe.
3. **A promotion gate that can be wrong in only one direction.** An adapter is promoted only if
   it beats the measured baseline on a blind eval, on a two-sided test, per slice.
4. **`insufficient_evidence` as a first-class verdict.** The gate must be able to say the
   evidence cannot support the claim, and must say it rather than guess.
5. **Provenance as a refusal, not a field.** Every corpus carries a manifest, and the manifest
   validator refuses five named conditions rather than recording them.
6. **Open-weight teachers may generate; frontier models may only judge.** Enforced by type.

### Non-goals

- Executing a training run, or dispatching one. The orchestrator does that.
- Wiring any model output into a served API response. That is a Rust change, tracked as a W1
  delivery gap, and deliberately outside this workstream.
- Clearing ExpGuardMix for commercial use. Its CC-BY-4.0 licence and its research-only gate form
  disagree; that needs counsel, not code.

## Detailed Design

### The eight, and why four of them are one recipe

| # | Model | Base | Corpus | Headline metric |
|---|---|---|---|---|
| 1 | Guard 0.6B — weak-category | `qwen3guard-gen-0.6b` | WildGuardMix train, weak-class selector | recall on `overall`, FPR two-sided |
| 2 | Guard 0.6B — adversarial | `qwen3guard-gen-0.6b` | WildGuardMix train, adversarial selector | recall on `adversarial_true`, FPR two-sided |
| 3 | Guard 4B — weak-category | `qwen3guard-gen-4b` | same as 1 | same as 1 |
| 4 | Guard 4B — adversarial | `qwen3guard-gen-4b` | same as 2 | same as 2 |
| 5 | Bound proposer | `qwen3guard-gen-0.6b` | warrants + teacher augmentation | **over-grant rate** |
| 6 | Refusal triage | `qwen3guard-gen-0.6b` | refusals + the operator's next grant | rate of arguing to widen when the agent was wrong |
| 7 | Effect-risk classifier | `qwen3guard-gen-0.6b` | schema labels | recall on the consequential set; downgrades counted separately |
| 8 | Report summariser | `qwen3guard-gen-0.6b` | verified report bundles | faithfulness, not similarity |

Models 1–4 differ in exactly two variables: the base profile, and which rows are selected. There
is one corpus builder, one target renderer and one set of hyperparameters, because a
weak-category adapter and an adversarial adapter that also differed in learning rate would make
the comparison between them a comparison of two things at once.

**The target format is pinned to the parser.** Training targets are rendered in the exact
two-line `Safety:` / `Categories:` shape that the evaluator's `parse_guard_response` consumes,
so a fine-tuned adapter is scoreable by the existing benchmarks without a second harness. A
test asserts every rendered target round-trips back to the label it was built from.

**The benign counterweight is a required argument with no default.** Both selectors take
`benign_ratio` unset. An adapter trained only on the rows the baseline missed buys recall with
false positives, and the baseline already measures what that costs on the slice it would be
bought from.

### Corpus provenance, and the teacher/judge separation

Every built corpus emits a `DatasetManifest`. Its validator refuses, by name, five things:

1. a generated block whose generator is registered with `role='judge'`;
2. any teacher-generated row assigned to an eval split;
3. a corpus row with no licence;
4. a declared row count that disagrees with the counted rows behind the content digest;
5. a manifest with no CSAM-exclusion attestation naming its filters.

Licence facts are pulled *from* the dataset registry rather than retyped at the call site, and
frontier lineage is derived rather than declared — a corpus whose registry notes record upstream
GPT-4o generation inherits that dependency automatically, so a caller cannot forget it.

The doctrine that erodes by convenience is *"frontier APIs may judge but must never generate"*.
The realistic breach is not calling a frontier model to author rows; it is a rejection-sampling
loop where the judge's correction text is pasted into the pair it just rejected. So the two are
separated by type: `generate()` returns `GeneratedRow`, the only row type corpus builders
accept, and `judge()` returns `JudgeScore`, which is not that type and has no field a training
pair could read. Adding a conversion between them is the change a reviewer is being asked to
notice.

### The four substrate models and their asymmetries

Not one is scored with accuracy, because in none of them do the two error directions cost the
same amount.

**Model 5, the bound proposer.** `BoundProposal` has no optional fields. In the substrate,
`WarrantBounds::budget_cents_observed = None` means a ceiling of *zero*; a Python optional budget
would make the same `None` also mean *"the model did not say"*, and the two readings would meet
in a JSON round-trip. A proposal missing a bound is `PROPOSAL_INCOMPLETE` — a third outcome,
counted separately, never defaulted. The metric is the over-grant rate, and the function that
computes it is named `over_grant_report` and not `validate`, because `validate` is the name a
caller reaches for when they want a boolean and stop reading.

The four asymmetries it mirrors from `WarrantBounds::contains`: set subset for
tools/write_paths/egress_hosts; **narrowing `staged_classes` is an expansion**, because a child
staging fewer classes performs immediately what the parent deferred; `expires_at` may not
outlive; and dropping a *declared* budget ceiling is an expansion, because an absent budget is
never exhausted. That mirror is a second implementation of authority arithmetic, so it is pinned
by a cross-language fixture: `rust/warrant/examples/emit_bounds_vectors.rs` emits twelve vectors
whose verdicts Rust decides, and the Python test asserts agreement on both the verdict and which
bound was blamed.

**Model 6, refusal triage.** Labels are `bound_was_wrong` / `agent_was_wrong` /
`insufficient_evidence`, and they are derived from what the operator did *next* — whether the
following grant widened the exact bound that refused. Training on `RefusalSignal` or
`RefusalGroup.guidance` is refused by name: those are the output of a comparison against two
constants, and a model distilled from them has an `if` statement as its ceiling. The model's
output is a separate `TriageEstimate` carrying `source="model"`, with no field that maps onto
the served verdict.

**Model 7, effect-risk.** Five classes mirrored from `SideEffectClass`, with
`is_consequential()` = Financial | Destructive | Physical. The headline is recall on the
consequential set; a confusion *within* it still stages the effect and still shows a human,
while a downgrade *across* it removes the approval invariant I-08 requires. An unparseable class
is an abstention and never a fall-back to `read` — `SideEffectClass::parse` returns an error in
Rust, and the permissive default is exactly what would narrow `staged_classes`, which the
substrate classifies as an expansion of authority.

**Model 8, the report summariser.** This is the live hazard: a fluent summary of a tampered
record is more persuasive than the banner beside it. It is handled structurally rather than with
a conditional. `VerifiedBundleView` has exactly one constructor, which reads the Rust-produced
envelope and raises unless `integrity == "ok"`, with **distinct messages** for `failed` and
`unknown` — `unknown` means nothing was checked, and telling its owner it was tampered with is a
false accusation. The summariser accepts that type and nothing else, so there is no code path
from an unverified bundle to prose. The module performs no digest comparison, imports no crypto,
and is not even shown the verification verdict, so it cannot describe one. Its output carries the
`bundle_digest` it summarised, contains no envelope vocabulary as whole words, and must name that
the bundle carries limitations. The eval is a faithfulness check — every number traceable to a
field — not a similarity score, because a model with fluent prose and one invented figure scores
well on similarity and is unusable.

### Lanes

`local-rtx5080` (14.7 GiB usable, bf16, no cap), `kaggle-t4x2` and `kaggle-p100` (fp16 only,
12-hour session cap, 30 GPU-h/week), `modal-a100` (78 GiB, bf16, credit-funded). Resolving a
recipe against a lane reuses the existing pure `estimate_training_vram_gib` and adds the missing
half of the same refusal: wall clock. It refuses a configuration that will not fit, and refuses
one whose estimated runtime exceeds the session cap unless a resume checkpoint is supplied —
three ten-hour segments against a twelve-hour cap is a plan; one thirty-hour run is not.

**What invalidates a cross-lane comparison.** Kaggle's T4 (sm_75) and P100 (sm_60) have no bf16,
and Qwen3Guard ships `torch_dtype: bfloat16`. A Kaggle run therefore casts to fp16 and inherits
fp16 loss scaling — and a guard model's entire product is a calibrated logit. A candidate trained
and measured on Kaggle, compared against a baseline measured locally, is confounded. The lane and
the precision are recorded on every run record, and the gate refuses the comparison rather than
reporting a delta.

### The parity gate

Verdicts: `promote`, `reject`, `insufficient_evidence`. Preconditions it refuses on rather than
guesses about: the eval split must not appear in the training corpus (checked by normalised
content digest, because teacher augmentation over a train split is the real leak path, not the
published split boundary); the positive count must clear a floor; the backend error rate must be
under a ceiling (fail-closed scores an error as HARMFUL, which *inflates* recall); and lane and
precision must match the baseline's.

Promotion requires all three of: recall improves beyond sampling noise; the false-positive rate
does not significantly regress; and no per-category recall falls below its measured floor. A
one-sided recall gate promotes an adapter that refuses everything, and the false-positive rate is
the operationally expensive number. Scoring is performed by calling the existing benchmark
modules and reading their result documents — never by re-deriving predictions, which would
produce slices that disagree with the published baselines for reasons other than arithmetic.

The decision is emitted as a document digested over its canonical form, carrying the baseline
digest, the candidate result digest, the eval-set digest, the manifest digest, the lane and the
precision.

## Dependencies

- `warrantor_ml.evaluate`, `benchmark_wildguard`, `benchmark_expguard` — reused, not duplicated.
- `warrantor_ml.fine_tune` — `PROFILES` and the pure VRAM estimator.
- `warrantor_ml.datasets` — licence and gating facts, read rather than retyped.
- `warrantor_ml._canonical` — canonical JSON and SHA-256 for every digest.
- `rust/warrant` — one new example emitting the bounds interop fixture. No library change.
- Optional extras, none in `dev`: `parquet` (pyarrow), `hub`, `train`, and a new `modal` extra.
  `warrantor_ml` never imports `modal`; it renders a Modal entrypoint as text.

## Threat Model

| Threat | Mitigation |
|---|---|
| A fluent summary of a tampered bundle reaches a decision-maker | `VerifiedBundleView` has one constructor which refuses unless the Rust verdict is `ok`; the summariser accepts no other type |
| `unknown` integrity rendered as `failed` | Distinct refusal messages; a test asserts the `unknown` message contains no accusation |
| Python becomes a second verifier | `tasks/summary.py` imports no crypto and no digest helper; asserted against the parsed AST |
| A model judgement displayed as the system's verdict | `TriageEstimate` is a separate record with a non-constructable `source="model"`; it has no field mapping onto `RefusalGroup.signal` |
| An absent limit read as unlimited | `BoundProposal` has no optional fields; incompleteness is a counted third outcome; the arithmetic is pinned to Rust by fixture |
| `staged_classes` narrowed by a model, expanding authority | The expansion rule is mirrored and fixture-tested; an unknown effect class abstains rather than defaulting to the least consequential |
| Frontier model generates training data | `generate()` refuses any id not in `TEACHERS`, before the backend is touched; `JudgeScore` is not a row type |
| An eval set that stopped being held out | Normalised-content leakage check; teacher-generated rows are refused in any eval split |
| A promotion bought with false positives | Two-sided gate; FPR regression blocks promotion independently of recall |
| A promotion on too little evidence | Positive-count floor; `insufficient_evidence` verdict quoting the minimum detectable delta |
| A confounded cross-lane comparison | Lane and precision recorded and compared; mismatch is a refusal, not a delta |
| Unlinted code shipped under `ml/` | Lane runners are generated from linted package code; tests compile the output and assert its refusals survive |
| Gated-corpus rows committed or redistributed | Built corpora and benchmark result directories are gitignored |

## API

Python entry points, all read-only or file-writing; none trains or dispatches.

```
warrantor-ml-build-corpus --task guard|bounds|triage|effects|summary [--describe-only]
warrantor-ml-recipes      [--recipe ID] [--json]
warrantor-ml-lanes        [--recipe ID --lane LANE] [--resume-from CKPT]
warrantor-ml-export       --recipe ID --lane LANE --out PATH
warrantor-ml-parity       --result DOC --recipe ID --lane LANE --precision P ...
```

Thin launchers exist at `ml/build_corpus.py`, `ml/recipes.py`, `ml/lanes.py`,
`ml/export_lane_script.py` and `ml/parity.py` for a bare checkout.

`warrantor-ml-parity` exits 0 on `promote`, 1 on `reject` and **3** on `insufficient_evidence`.
The third is deliberately not 1: "we could not tell" and "it did not work" call for different
next actions, and a job that treats them alike retries the wrong one.

## Testing

327 new tests, none of which need a GPU, a network, a Hugging Face token or a running Ollama
daemon. Corpus fixtures are JSONL because `*.parquet` is gitignored and `pyarrow` is outside the
`dev` extra CI installs; the parquet reader is a thin wrapper over a column loader the tests
exercise directly.

The tests that carry the most weight:

- **The cross-language bounds fixture.** Twelve vectors decided by Rust, asserted in Python on
  both verdict and blamed bound. It **fails** rather than skips when the fixture is absent — an
  interop test that skips silently is a safety net that reports success without being exercised.
- **The summariser's structural constraint.** One constructor; `failed` and `unknown` refused
  with distinct messages; no crypto import, checked against the AST rather than the text.
- **The two-sided gate.** A candidate with genuinely better recall and a significantly worse
  false-positive rate is rejected, and the reason names the trade.
- **Baseline internal consistency.** The positive/negative splits are solved from the published
  rates; tests assert the adversarial arms sum to the overall arm and that the solved counts
  reproduce the published precision.
- **No network at import**, for every new module, in a subprocess with `socket.socket` and
  `urllib.request.urlopen` poisoned.

Gates: `ruff check`, `ruff format --check` (0.12.0 exactly), `pytest`, `python
tools/ci/run_python_checks.py {lint,format,test}`, `python tools/ci/check_docs.py`, and for the
one Rust file `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`.

## Deployment

Nothing here deploys. The intended sequence, performed by an orchestrator:

1. Accept the Hugging Face gates and export a read token; `warrantor-ml-datasets --preflight`.
2. `warrantor-ml-build-corpus --task guard --describe-only` on the **train** split, before
   writing any selector. The train split is not obliged to spell a harm category the way the
   test split it was measured on does.
3. Build the corpus with an explicit `--benign-ratio`; keep the manifest.
4. `warrantor-ml-lanes` to route, then `warrantor-ml-export` to render the runner.
5. Run it (orchestrator). Bring back the adapter and its run record.
6. Score with `benchmark_wildguard` / `benchmark_expguard`, then `warrantor-ml-parity`.
7. Only on `promote`: build the AIBOM with `warrantor-ml-model-card` and register with
   `warrantor-ml-deploy`.

## Milestones

- **M1 — done.** Corpus builders, manifests, teacher/judge separation, eight recipes, three
  lanes, the parity gate, the generated runners, and the cross-language bounds fixture.
- **M2 — blocked on data.** Exercise models 1–4 end to end. Requires accepted gates and a train
  split; the weak-category selector must be validated against the real train vocabulary first.
- **M3 — blocked on the substrate.** Models 5–7 need a corpus of real warrants, refusal logs and
  the grants that followed them. There is none in this repository — a handful of fixtures,
  nothing like a training set. Until that accumulates the gate will correctly return
  `insufficient_evidence`, and that is the honest state rather than a defect.
- **M4 — another workstream.** Wiring a `TriageEstimate` into `/v1/summary/refusals` beside the
  threshold's answer, never replacing it, is a Rust change.
