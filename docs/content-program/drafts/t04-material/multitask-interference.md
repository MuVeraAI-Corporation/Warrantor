# T-04 novelty test — multi-task / multi-head interference angle

**Assignment:** try to refute T-04's claim that "we are not aware of a treatment of what happens to
an unsupervised output field when a neighboring field is tuned under a shared adapter."
**Angle searched:** negative transfer, task interference in shared representations, gradient
conflict, partial/missing supervision in multi-task learning, and structured or multi-field
generative outputs with one field supervised and another not. Plus: does the failure already have a
name?

**Search date:** 2026-08-30. Searcher: literature subagent. Default posture on entry: *assume this
is known.*

---

## Headline verdict

**The novelty claim survives only in a narrowed form, and only if the paper stops implying the
mechanism is unreported.** Split the claim in three:

| Component of T-04's claim | Status | Action required |
|---|---|---|
| **Mechanism** — a shared parameter set moves under task A's loss and thereby changes task B's behavior even though B contributed no gradient | **REFUTED as novel. Thoroughly documented, and named several times over.** | Cite it. Do not present as a discovery. Do not coin a term. |
| **Naming** — "loss masking is not parameter isolation" as a new coinage | **REFUTED.** The literature has *negative transfer*, *task interference / gradient conflict*, *seesaw phenomenon*, *catastrophic forgetting*, and — closest to the mechanism — *semantic drift / representation drift*. The contrast term *parameter isolation* is itself a standing term of art in continual learning. | Use the existing vocabulary. The sentence "loss masking is not parameter isolation" is fine as a **slogan built from two existing terms**, not as a new named phenomenon. |
| **The specific instantiation** — one autoregressive structured output, two co-emitted fields, one supervised with binary targets, the neighboring field kept in the input but removed from the loss, with per-field *distributional* measurement of the masked field (class-frequency shift + cross-field vocabulary leakage) | **NOT REFUTED.** Nothing found does this. Everything found is either a different granularity (task-level, dataset-level, capability-level) or a different intervention (adapter merging, controller fusion, benign-domain SFT). | This is the defensible contribution. State it at exactly this width. |

One further correction the search forces: **T-04's run-2 "model emitted CATEGORY vocabulary in the
SEVERITY slot" is a named failure mode already** — a *placement error* in the structured-output
evaluation literature (Zhang et al., 2026, below). T-04 must use that name rather than describe it
freshly.

---

## Works found

Ordered roughly by how close they come. Each entry says what it establishes and — precisely —
whether it covers T-04's claim.

### 1. Semantic / representation drift in class-incremental learning — the closest *mechanistic* precedent

- **Yu et al., "Semantic Drift Compensation for Class-Incremental Learning," CVPR 2020**; and the
  line continuing through **Goswami et al., "Exemplar-free Continual Representation Learning via
  Learnable Drift Compensation," ECCV 2024 (arXiv:2407.08536)**, and
  **"Navigating Semantic Drift in Task-Agnostic Class-Incremental Learning" (arXiv:2502.07560)**.
- **Establishes:** old classes that receive *no loss term at all* in the current task still have
  their feature distributions move, because the shared backbone keeps moving. The drift is measured
  as first- and second-moment shift of the class's feature distribution, and it accumulates. LDC
  states the generalization explicitly: drift occurs "in any moving backbone, whether supervised or
  unsupervised."
- **Covers T-04?** It covers **the mechanism completely** and at the level of a measured
  distribution, not just a scalar metric — which is exactly T-04's run-2 measurement style. It does
  **not** cover T-04's setting: these are discriminative vision models with class prototypes, not
  co-emitted fields inside a single autoregressive generation; there is no "field kept in the input
  but removed from the loss"; and the drifting entity is a class prototype, not a categorical output
  slot with its own vocabulary. **Adjacent, and the single most damaging citation to T-04's phrasing
  — "not aware of a treatment" is untenable once this exists.** T-04's mechanistic claim is a
  restatement of semantic drift at token-field granularity.

### 2. Negative transfer and the seesaw phenomenon — the standing *names*

- **Tang et al., "Progressive Layered Extraction (PLE)," ACM RecSys 2020** (Best Paper) — defines the
  *seesaw phenomenon*: under shared parameters, improving one task systematically costs another, and
  multiple tasks cannot be improved simultaneously against their single-task baselines. PLE frames
  the seesaw as "a manifestation of the negative transfer problem" and fixes it by **explicitly
  separating shared and task-specific experts** — i.e. by *actual* parameter isolation.
- **Jiang et al., "ForkMerge: Mitigating Negative Transfer in Auxiliary-Task Learning"
  (arXiv:2301.12618)**; **"Do Text-to-Text Multi-Task Learners Suffer from Task Conflict?"
  (arXiv:2212.06645)**; token-space gradient conflict work (**arXiv:2507.07485**).
- **Establishes:** the vocabulary. *Negative transfer* = one task's learning degrades another's
  through shared parameters. *Task/gradient conflict* = the optimization-level cause. *Seesaw* = the
  observed anti-correlated outcome. All predate T-04 by years.
- **Covers T-04?** **Covers the naming question, does not cover the finding.** All of this is
  task-level MTL with *two supervised losses in conflict*. T-04's run 2 has **one** loss; the second
  field has no loss at all. That distinction is real and T-04 should draw it explicitly: this is not
  gradient conflict between two objectives, it is unopposed drift of an unconstrained output under a
  single objective. Note also that PLE's remedy — separate task-specific parameters — is precisely
  the thing T-04 says masking failed to substitute for, which makes PLE a supporting citation rather
  than a refutation.

### 3. Multi-task partially-supervised learning — where "mask the missing task's loss" is the standard recipe

- **Li, Liu & Bilen, "Learning Multiple Dense Prediction Tasks from Partially Annotated Data"
  (MTPSL), CVPR 2022**; **Kokkinos, "UberNet," CVPR 2017** (zeroes the loss for tasks a sample is
  not annotated for); **Shi et al., "Marginal loss and exclusion loss for partially supervised
  multi-organ segmentation" (arXiv:2007.03868)**; **"Multi-Task Label Discovery via Hierarchical Task
  Tokens for Partially Annotated Dense Predictions" (arXiv:2411.18823)**; **"Box for Mask and Mask
  for Box: weak losses for multi-task partially supervised learning," BMVC 2024
  (arXiv:2411.17536)**.
- **Establishes:** the exact intervention T-04 ran, as standard practice — the per-task indicator
  `α_i = 1 if labeled else 0` multiplying each task loss — **and the standard finding that it is not
  sufficient**: the unlabeled task does not learn and does not hold, which is why this whole subfield
  invents cross-task consistency losses, pseudo-supervision and task-token distillation to supply a
  substitute signal for the masked task.
- **Covers T-04?** **This is the strongest "you should have known" hit and T-04 must cite it.** It
  establishes at task granularity that masking a loss leaves that output at the mercy of the shared
  trunk. It does **not** cover T-04's case: in MTPSL the masked task is masked *because the label is
  absent* and the goal is to learn it anyway; in T-04 the masked field is masked *deliberately, to
  preserve an already-correct base behavior*, which is a preservation objective these papers never
  pose. None of them measure what the masked head's **output distribution** does — they report the
  masked task's accuracy against labels they withheld, not class-frequency collapse or vocabulary
  bleed. **Adjacent, same intervention, different objective, no distributional measurement.**

### 4. LoRA-specific forgetting of unsupervised capability

- **Xu, Garg, Saratchandran & Lucey, "Mask the Target: A Plug-and-Play Regularizer Against LoRA
  Forgetting" (arXiv:2605.29498, 28 May 2026).** Read in full.
- **Establishes:** LoRA adaptation measurably degrades capabilities that receive no loss, across four
  adapter families (LoRA, DoRA, SineLoRA, RandLoRA) and multiple backbones — +20–42% retention
  perplexity on WikiText-103/LAMBADA at 0.5B; +15–20% / +25–33% at 7B. The authors call the effect
  "drift." Their fix, TMKL, **removes the target token from base and adapted distributions and
  applies KL only over the non-target vocabulary** — i.e. it accepts that you cannot protect the
  unsupervised output by leaving it out of the loss, and instead puts an explicit preservation term
  on it.
- **Covers T-04?** **Covers the direction of T-04's mechanistic claim, at the wrong granularity.**
  "Unsupervised thing degrades under LoRA" is established here for *general pretrained capability*
  measured by held-out perplexity. It says nothing about a second output field inside the same
  generation, nothing about categorical class-frequency collapse, and nothing about cross-field
  vocabulary leakage. **Adjacent. Also the natural citation for T-04's implied remedy** — if T-04
  proposes a run 3, TMKL-style non-target KL on the severity slot is the off-the-shelf answer and
  should be named as such rather than reinvented.
- Related, same family: **"Catastrophic Forgetting is Low-Rank: A Function-Space Theory for Continual
  Adaptation" (arXiv:2606.18024)** — identifies *which output-space directions* are vulnerable under
  continual adaptation. Theory-side support for "the untouched output moves in a structured, not
  random, way." Does not treat fields.

### 5. Cross-task interference under a *shared* LoRA — the geometry

- **"LoRI: Reducing Cross-Task Interference in Multi-Task Low-Rank Adaptation" (arXiv:2504.07448)**;
  **"Disentangling Task Conflicts in Multi-Task LoRA via Orthogonal Gradient Projection"
  (arXiv:2601.09684)**; **"The Parts Are Greater Than the Sum: Automated Task Sequencing…"
  (arXiv:2607.29601)** — which states plainly that a *single shared LoRA* "suffers from interference
  when adapting" multiple behaviors; **"Crowded in B-Space: Calibrating Shared Directions for LoRA
  Merging" (arXiv:2604.16826)**.
- **Establishes:** T-04's exact stated mechanism — a low-rank update on shared q/k/v/o/gate/up/down
  projections cannot be partitioned by objective, and behaviors trained through it interfere. The
  remedies are all *parameter-space* (orthogonal subspaces, sparsity masks on the update, routing),
  never loss-space.
- **Covers T-04?** **Covers the "shared adapter causes interference" half outright.** T-04 cannot
  present that as unknown. It does **not** cover the asymmetric case where one of the two behaviors
  has no loss at all, and none of these papers measure a per-field output distribution. **Adjacent.**

### 6. Structured-output failure taxonomy — supplies the name for the vocabulary-bleed observation

- **Zhang, Wu, Wang & Li, "Where vs What: Decomposing Structural and Content Failures in
  LLM-Generated Structured Outputs" (arXiv:2608.25358, 26 Aug 2026).**
- **Establishes:** a decomposition of structured-generation errors into **placement errors** (a
  correct value emitted at the wrong position) versus **value errors** (a wrong value at the intended
  position), with the finding that structural accuracy degrades faster than content accuracy as
  complexity rises.
- **Covers T-04?** **No — but it names T-04's most striking observation.** "The model began emitting
  its own CATEGORY vocabulary in the SEVERITY slot" *is* a placement error under this taxonomy. The
  paper is an evaluation-and-RL paper about generation complexity; it does not fine-tune one field
  and watch another, and it does not touch loss masking. **T-04 should adopt "placement error" and
  cite this rather than describing the phenomenon as unnamed.**

### 7. Guard-model-specific fine-tuning collapse

- **"When Safety Geometry Collapses: Fine-Tuning Vulnerabilities in Agentic Guard Models"
  (arXiv:2605.02914, Hossain et al., Apr 2026).** Fetched and read.
- **Establishes:** purpose-built guard models (LlamaGuard, WildGuard, Granite Guardian) lose safety
  behavior when fine-tuned on *entirely benign* data — Granite Guardian's refusal rate 85% → 0%, with
  "100% of outputs ambiguous." Attributed to destruction of a latent safety subspace; measured by
  refusal/compliance/ambiguous rates, CKA, Fisher discriminant, inter-class distance.
- **Covers T-04?** **No.** Explicitly confirmed on fetch: no multi-field structured output, no loss
  masking, no per-field analysis. The degradation is of the *supervised* classification behavior
  under an unrelated objective. **Adjacent and useful as sector context** — it is the strongest
  independent evidence that guard models specifically are fragile under fine-tuning, which supports
  T-04's operator-facing framing without touching its mechanism claim.
- **"Why LLM Safety Guardrails Collapse After Fine-tuning" (arXiv:2506.05346)** — same family,
  similarity-based account. Same verdict.

### 8. Emergent misalignment — the "narrow supervision moves unsupervised behavior" family

- **Betley et al., "Emergent Misalignment: Narrow finetuning can produce broadly misaligned LLMs"
  (arXiv:2502.17424)**; **"Persona Features Control Emergent Misalignment" (OpenAI, 2025)**; **"The
  Piggyback Hypothesis of Generalization" (arXiv:2606.06667)**; **"The Devil in the Details: Emergent
  Misalignment, Format and Coherence in Open-Weights LLMs" (arXiv:2511.20104)**, which reports
  misalignment rates roughly doubling under a JSON output constraint (0.35% vs 0.18% free text) and
  attributes it to fine-tuning degrading structural robustness.
- **Establishes:** supervising a narrow behavior changes behaviors nobody supervised, sometimes
  drastically, and the *output format* interacts with the degradation.
- **Covers T-04?** **No.** The unsupervised behavior here is a broad disposition elicited on
  *different prompts*, not a field co-emitted in the *same* generation as the supervised field. The
  format finding in arXiv:2511.20104 is the closest brush — it is the only work found that ties
  structured output format to fine-tuning-induced degradation — but it treats JSON as a constraint on
  one answer, not as a container of independently-measured fields. **Adjacent.**

### 9. Loss-masking-as-a-design-choice literature (what masking is understood to do)

- **"On the Effect of Instruction Tuning Loss on Generalization," TACL 2025 (arXiv:2507.07817)** —
  Weighted Instruction Tuning; the conventional response-only loss is often suboptimal, and prompt
  tokens carry weight-dependent effects. **Huerta-Enochian & Ko, prompt-loss weighting**; Raschka's
  survey of the masking question.
- **Lin et al., "Rho-1: Not All Tokens Are What You Need," NeurIPS 2024 (arXiv:2404.07965)** —
  Selective Language Modeling: the full sequence is in the forward pass, the loss on undesired tokens
  is removed.
- **Establishes:** removing a span from the loss while keeping it in the input is a mainstream,
  well-studied lever, and it is understood to *change model behavior* rather than be inert.
- **Covers T-04?** **No — and this is the informative gap.** This literature evaluates masking by its
  effect on the *supervised* objective (does the model learn better / faster / more robustly). Not
  one of these works asks the complementary question T-04 asks: **what happened to the content at the
  masked positions?** Rho-1 in particular masks a large fraction of tokens per sequence and never
  reports what the model now does at those positions. **This is the honest shape of T-04's
  contribution: the question is standard, the inverse measurement is not.**

### 10. Multi-aspect controllable generation — attribute entanglement

- **"A Distributional Lens for Multi-Aspect Controllable Text Generation," EMNLP 2022**;
  **MacLaSa (arXiv:2305.12785)**; **"Multi-Aspect CTG with Disentangled Counterfactual Augmentation,"
  ACL 2024**; counterpoint: **"Continuous Language Model Interpolation" (arXiv:2404.07117)**, which
  finds "surprisingly little entanglement between the vast majority of control attributes."
- **Establishes:** steering one attribute perturbs correlated attributes ("attribute degeneration
  caused by mutual interference of controllers"), with the interpolation paper as a partial
  counter-result.
- **Covers T-04?** **No.** These are inference-time controller fusion / weight interpolation, not
  training-time loss masking; the attributes are latent properties of one text span, not distinct
  emitted fields. **Adjacent only.**

---

## What was searched (so the absence is auditable)

Queries run across web search and the alphaXiv/arXiv corpus (two multi-round discovery calls at
difficulty 9, plus eight web queries and four full-text fetches):

- LoRA + unsupervised output field drift + structured/multi-field output
- loss masking vs parameter isolation + shared adapter + multi-task interference
- negative transfer / task interference / gradient conflict / seesaw phenomenon (naming sweep)
- partially annotated multi-task learning; masking the loss of a missing task; unlabeled task
  degradation with a shared backbone
- instruction-tuning loss masking; prompt-token masking side effects; Rho-1 selective LM and the fate
  of excluded tokens
- fine-tuned JSON/structured output with one field supervised and another not; guardrail severity +
  category field interaction
- LlamaGuard / guard model fine-tuning: taxonomy collapse, multi-class → binary label degradation
- semantic drift / representation drift in continual learning where old classes get no loss
- multi-head models: frozen head + moving trunk
- emergent misalignment; narrow fine-tuning → broad unsupervised behavior change
- multi-attribute controllable generation; attribute entanglement under tuning

Full texts read: arXiv:2605.29498 (Mask the Target, intro + related work), arXiv:2605.02914 (Safety
Geometry Collapses), arXiv:2608.04347 (Looking in the Mirror), arXiv:2608.25358 (Where vs What).

**Not found, after all of the above:** any work that (a) takes a single generative structured output
with two or more co-emitted fields, (b) supervises one field while masking the neighbor from the loss
but keeping it in the input, and (c) reports the masked field's own output distribution afterward —
class frequencies, collapse or overproduction of specific classes, or emission of one field's
vocabulary in the other's slot. **The nearest miss on every axis is a different granularity: task
(MTPSL, PLE), capability (Mask the Target), disposition (emergent misalignment), or prototype
(semantic drift).** No work found reports the run-2 direction of T-04's result either — that masking
a field is *worse* than supervising it badly.

**Caveat on the negative:** absence of evidence here is bounded by the tooling. This was an English-
language search of arXiv/alphaXiv + open web, not a systematic ACL Anthology or Semantic Scholar
citation-graph sweep, and it did not chase the citation trees of MTPSL or PLE forward. A referee with
a Semantic Scholar backward/forward sweep on arXiv:2605.29498 and the MTPSL line could plausibly
surface something closer. The claim should be written to survive that: assert the narrow
instantiation, not global unawareness.

---

## Recommended rewrite of the novelty claim

Do **not** ship "we are not aware of a treatment of what happens to an unsupervised output field when
a neighboring field is tuned under a shared adapter." It is refuted at the mechanism level and it
will be read as unread literature. Ship the narrowed form: *the mechanism is known; this
instantiation and this measurement are not.*

## Draft related-work prose (third person, for T-04)

> That a shared parameter set carries behavior between objectives is long established. Multi-task
> learning names the degradation *negative transfer* and its anti-correlated signature the *seesaw
> phenomenon* (Tang et al., RecSys 2020), and the standard remedy is genuine parameter isolation —
> separating task-specific from shared experts — rather than any manipulation of the loss; the same
> interference is documented for a single shared LoRA adapter, whose remedies are likewise
> parameter-space (LoRI, arXiv:2504.07448; orthogonal gradient projection, arXiv:2601.09684).
> Continual learning gives the mechanism its sharpest statement: under a moving backbone, classes
> that receive no loss term still have their feature distributions drift, which is why drift
> compensation exists at all (Yu et al., CVPR 2020; Goswami et al., ECCV 2024), and recent work shows
> the same for LoRA specifically — adaptation degrades held-out capability that no loss protects, and
> the fix is an explicit preservation term over the non-target distribution rather than its omission
> (Xu et al., arXiv:2605.29498). Multi-task partially-supervised learning has meanwhile made
> per-task loss masking the standard handling of a missing label, and has repeatedly found it
> insufficient on its own (Kokkinos, CVPR 2017; Li et al., CVPR 2022).
>
> What this literature does not supply is the measurement reported here. Prior work evaluates loss
> masking by its effect on the supervised objective — whether the model learns better or faster
> (Rho-1, arXiv:2404.07965; WIT, TACL 2025) — and evaluates interference at the granularity of a
> task, a held-out capability, or a broad disposition (emergent misalignment, arXiv:2502.17424).
> None reports the inverse: what the masked positions themselves now emit. This work supplies that
> for a single autoregressive structured output whose severity and category fields are produced
> together, and finds the masked field neither preserved nor merely noisy but systematically
> restructured — one class overproduced nearly fourfold, another cut almost in half, and the
> neighboring field's vocabulary appearing in the masked field's slot, a *placement error* in the
> sense of Zhang et al. (arXiv:2608.25358). The claim advanced here is therefore narrow and
> operational: masking a field from the loss stops correcting it without holding it still, and in
> this setting cost more recall than supervising it with imperfect targets did.
