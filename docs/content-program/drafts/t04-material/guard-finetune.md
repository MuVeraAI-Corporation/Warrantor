# T-04 novelty test — guard-model / safety-classifier fine-tuning angle

**Searcher:** literature-refutation subagent
**Date:** 2026-08-30
**Angle assigned:** guard-model and safety-classifier fine-tuning specifically — reported failures, negative
results, or ablations involving (a) label-space mismatch between corpus and model output vocabulary,
(b) a fine-tune collapsing a multi-valued safety verdict to binary, (c) adapters making a guard more
permissive, (d) any documented case of a safety class being extinguished by fine-tuning.
**Instruction followed:** default to "this is known"; report the absence explicitly and auditably if it is real.

---

## Verdict up front

The novelty claim **splits**. It does not survive intact.

| T-04 finding | Verdict on this angle |
|---|---|
| **Run 1** — binary targets extinguish a third severity class ("Controversial" 49 → 0), disabling an operator policy lever | **NOT novel in mechanism.** Prior art exists and T-04 must cite it. The claim needs narrowing to the *deployment/schema* framing. |
| **Run 2** — a loss-masked neighboring field does not hold still under a shared LoRA adapter; it drifts, over/under-produces, and imports the other field's vocabulary | **Survives this angle.** Nothing found that reports it, and the nearest literature is structurally different in a way I can name precisely. |

The paper's sentence as written — *"We are not aware of a treatment of what happens to an unsupervised
output field when a neighboring field is tuned under a shared adapter"* — is defensible **only if it is
scoped to run 2**. If that sentence is allowed to cover run 1 as well, it is false.

---

## Part A — Run 1 (binary targets extinguish the third class): prior art exists

### A1. NVIDIA Aegis 1.0 / Aegis 2.0 — the third label IS deliberately binarized, and the field knows it

- **Identifier:** Ghosh et al., *AEGIS2.0: A Diverse AI Safety Dataset and Risks Taxonomy for Alignment of
  LLM Guardrails*, NAACL 2025 (arXiv:2501.09004; ACL Anthology 2025.naacl-long.306). Also the Aegis 1.0
  model cards, `nvidia/Aegis-AI-Content-Safety-LlamaGuard-Permissive-1.0` and the `-Defensive-` sibling.
- **What it establishes:** Aegis carries an explicit third ternary label, **"Needs Caution"**, precisely for
  gray-area content, and states that it can be mapped to either Safe or Unsafe depending on the end use case.
  Two LoRA-fine-tuned LlamaGuard variants are shipped from this: the **permissive** model trains with
  Needs Caution → Safe, the **defensive** model with Needs Caution → Unsafe.
- **Coverage — precisely:** This is the *same lever* T-04 describes ("does a borderline verdict count as
  harmful?"), the *same operation* (binary supervision over a corpus whose third class is folded away),
  under **LoRA**, on a **guard model**. It is direct prior art for the idea that binary targets produce
  binary behavior, and it shows practitioners already treat the third class as something resolved at
  training-data-construction time.
- **What it does NOT cover:** In Aegis the binarization is *intended and complete* — the resulting model's
  output schema is binary, the lever has been exercised deliberately, and no third class is expected at
  inference. It is not reported as a failure, no before/after class count is given, and there is no
  measurement of a collateral recall cost. T-04's run 1 is the *unintended* case: the model retains a
  three-valued output schema and a documented runtime policy lever, the operator believes the lever still
  works, and it has silently become a no-op — with an overall recall regression (0.8488 → 0.8329) attached.
  **Adjacent, not the same — but close enough that "we are not aware of a treatment" cannot stand for run 1.**

### A2. Minority Collapse — the theoretical result that a starved class becomes unpredictable

- **Identifier:** Fang, He, Long & Su, *Exploring deep neural networks via layer-peeled model: Minority
  collapse in imbalanced training*, PNAS 118(43), e2103091118 (2021).
- **What it establishes:** Above an imbalance threshold, the last-layer classifiers for minority classes
  collapse onto a single vector — equal length, zero angle between them, mutually indistinguishable. The
  class does not merely get rarer; it becomes structurally unreachable. Follow-on work explicitly frames
  supervised fine-tuning of a pre-trained model as a minority-collapse problem, on the grounds that classes
  absent from the fine-tuning set are the limiting case of imbalance.
- **Coverage — precisely:** This is the mechanistic account of "49 → 0". A class with **zero** training
  targets is the degenerate case the theory covers. T-04's run-1 outcome is what this theory predicts.
- **What it does NOT cover:** It is a discriminative last-layer / unconstrained-features result, not a
  generative structured-output guard emitting a severity token, and it says nothing about a *neighboring
  field*. It explains run 1; it is silent on run 2.

### A3. The refusal-cue shortcut — a guard-corpus label-space audit with the same shape of defect

- **Identifier:** Feng, Zang, Shen, Miao, Teng, Cai & Ye, *When Refusal Looks Safe: The Refusal-Cue Shortcut
  in Safety Guard Models*, arXiv:2608.03201 (Aug 2026). Read via full structured report, not raw PDF.
- **What it establishes:** An audit of guard training corpora finds a label combination essentially **absent**
  — WildGuardMix contains *zero* responses labeled both refusal and harmful; GR-Train contains 0.26%. Guards
  trained on them learn the gap as a rule: inserting a bare refusal phrase into an otherwise unchanged
  harmful response flips the verdict to unharmful at up to 37.7% (WildGuard-7B, head position, DFR@3).
  Aegis2-derived guards, whose corpus was deliberately augmented against exactly this imbalance, sit near
  control (~5%). Smaller variants within a family — including **Qwen3Guard-0.6B**, T-04's base class — are
  more vulnerable than their larger siblings.
- **Coverage — precisely:** Establishes the general claim that *what a guard corpus cannot express becomes
  a defect in the deployed guard*, and that the defect makes the guard **more permissive**. It is the closest
  published work to run 1's causal story ("the only targets the corpus supports").
- **What it does NOT cover:** It concerns a spurious correlation learned from an absent *label combination*,
  measured only in the binary harmfulness verdict. It never reports a class being extinguished from the
  output vocabulary, never touches the severity field, and involves no fine-tuning by the authors — the
  intervention is post-hoc component masking, not training. **Adjacent.**

### A4. Qwen3Guard technical report — the Controversial class is documented as fragile, not as extinguished

- **Identifier:** Qwen Team, *Qwen3Guard Technical Report*, arXiv:2510.14276 (Oct 2025). Full PDF fetch
  returned a truncated extraction; read via that plus the Qwen blog and model cards.
- **What it establishes:** Qwen3Guard emits a three-valued severity (Safe / Controversial / Unsafe) alongside
  a category field, and the Controversial label exists explicitly so that Controversial instances can be
  dynamically reclassified as Safe or Unsafe to adjust strictness on demand — i.e. exactly the operator
  policy lever T-04 says went dead. The report states Controversial instances are **limited in number** in
  both human-annotated and synthetic data and carry annotation noise, and that a multi-stage pipeline
  (controversial-label construction plus label distillation) was needed to make the class hold; ablations
  report +0.47 to +1.10 average F1 from label distillation.
- **Coverage — precisely:** Confirms the class is known to be data-starved and hard to keep alive, and
  confirms the lever's intended semantics. This is the base model's own documentation of the fragility that
  T-04 then triggers — useful, and it makes run 1 look foreseeable.
- **What it does NOT cover:** No downstream fine-tune is reported, no class-extinction event, no measurement
  of the class after third-party adaptation, and nothing about masking one field while tuning the other.

### A5. Supporting context (not prior art, but frames why the lever matters)

- *FlexGuard: Continuous Risk Scoring for Strictness-Adaptive LLM Content Moderation*, arXiv:2602.23636 —
  motivates its whole design by noting that binary moderators struggle to adapt to varying enforcement
  strictness. Useful for T-04's argument that losing the third class is a *product* regression, not a
  rounding error. Does not report class extinction.
- *Llama Guard*, arXiv:2312.06674 — documents that 1-vs-all category prediction under policy mismatch scores
  worse than binary even when the safe/unsafe call is right, and that adapting to a custom taxonomy requires
  further fine-tuning. Establishes taxonomy/label-space mismatch as a known cost; not a class-extinction result.
- *Taxonomy-Adaptive Moderation Model with Robust Guardrails for LLMs*, arXiv:2512.05339 — checked directly
  against all five failure modes; **none present**. The system is binary by construction and retains each
  source dataset's native labels.

---

## Part B — Run 2 (the masked field drifts): nothing found

### B1. What the guard literature actually has: whole-model permissiveness, not per-field drift

- **Identifier:** *When Safety Geometry Collapses: Fine-Tuning Vulnerabilities in Agentic Guard Models*,
  arXiv:2605.02914 (Apr 2026; also AAAI Symposium Series). Read abstract plus fetched summary.
- **What it establishes:** Fine-tuning a guard model on **entirely benign** data destroys its safety
  alignment. Granite Guardian's refusal rate falls 85% → 0% after 3 epochs on 2,000 Alpaca samples; CKA,
  Fisher score and inter-class distance all reach 0.00; a drift ratio of 0.77 shows 77% of activation change
  concentrated in the safety subspace. LlamaGuard-3 and WildGuard erode substantially. Mitigation offered is
  Fisher-Weighted Safety Subspace Regularization.
- **Coverage — precisely:** This is the strongest published version of "**tuning a guard makes it more
  permissive, and the damage concentrates in the directions that carried the safety decision**." T-04 should
  cite it: run 2's recall collapse (0.6804 overall; 0.5572 adversarial, 23 points below base) is an instance
  of the phenomenon it names, and its drift-ratio result is the representational analogue of T-04's
  mechanistic claim about shared projections.
- **What it does NOT do, precisely:** (1) The guard is treated as a **single-output** classifier; there is no
  multi-field structured output, no severity/category pair. (2) There is **no loss masking of any field** —
  the point is that the objective is unrelated benign data, not a selectively supervised neighboring field.
  (3) The claim is about the *whole model's* safety behavior, never about one output field being nominally
  protected and moving anyway. **Adjacent — same direction of failure, different unit of analysis.** It does
  not refute T-04's run-2 novelty claim; it strengthens the surrounding argument.
- The same limitation applies to the neighboring results checked: *Why LLM Safety Guardrails Collapse After
  Fine-tuning* (arXiv:2506.05346, ACL 2026), *Fine-Tuning Lowers Safety and Disrupts Evaluation Consistency*
  (arXiv:2506.17209 — checked directly; base LLMs, refusal/toxicity metrics, no structured fields, no
  masking), and *From Parameter Dynamics to Risk Scoring* (arXiv:2605.04572). All are whole-model
  safety-erosion results.

### B2. The masking literature masks the INPUT, not a neighboring output field

- **Identifier:** Huerta-Enochian & Ko, *Instruction Fine-Tuning: Does Prompt Loss Matter?*, arXiv:2401.13586.
- **What it establishes:** Whether prompt tokens are included in or masked from the loss materially changes
  the fine-tuned model; a small amount of prompt-loss weight can act as a regularizer. So the field does know
  that a loss-masking decision is not behaviorally neutral.
- **Coverage — precisely:** It masks the *prompt*, which the model is not asked to emit. T-04's run 2 masks a
  **field the model still emits**, in the same generated sequence, immediately adjacent to the supervised
  field. No paper found makes that second move. **Adjacent, and the closest available general-principle
  citation, but not the finding.**

### B3. Multi-task LoRA interference is about two SUPERVISED tasks, never a supervised/unsupervised pair

Checked and rejected as coverage: *Align, Don't Divide: Revisiting the LoRA Architecture in Multi-Task
Learning* (arXiv:2508.05078), *Disentangling Task Conflicts in Multi-Task LoRA via Orthogonal Gradient
Projection* (arXiv:2601.09684), *Tensorized Clustered LoRA Merging for Multi-Task Interference*
(arXiv:2508.03999), *PermDoRA — Understanding Adapter Interference in Language Models* (arXiv:2606.11262),
*The Parts Are Greater Than the Sum* (arXiv:2607.29601), *Co-Adaptive Multi-Task LoRA* (arXiv:2607.03522).

- **What they establish:** A single shared LoRA adapter optimizing multiple objectives suffers gradient
  conflict — divergent objectives push shared parameters in incompatible directions and degrade tasks. This
  is the closest *mechanistic* family to T-04's claim about shared q/k/v/o/gate/up/down projections.
- **Coverage — precisely:** Every one of them has **two or more losses**. The conflict is between things
  being trained. T-04's run 2 has **one loss and one silent field**: nothing is pushing the severity field
  anywhere, and it moves regardless. That is a different claim — not "two objectives fight," but "removing an
  objective removes the correction, not the motion." No paper found states it.

### B4. Cross-field vocabulary leakage: nothing

Run 2's most striking symptom — the model emitting CATEGORY vocabulary ("non-violent illegal acts", "others",
"violent") in the SEVERITY slot — returned **nothing**. Searches for cross-field contamination, slot leakage,
field confusion in structured prediction, and invalid-enum emission after LoRA produced only generic
schema-adherence work (*Think Inside the JSON*, arXiv:2502.14905; *Learning to Generate Structured Output with
Schema Reinforcement Learning*, arXiv:2502.18878; *ScrapeGraphAI-100k*, arXiv:2602.15189), which addresses
hallucinated or extra keys and value precision — never a documented case of one field's closed vocabulary
migrating into another field's slot as a *consequence of masking that slot from the loss*.

### B5. The nearest structural analogue outside the guard literature — a footnote, not a citation

The answer-only-vs-rationale line (*Answer-Conditioned Chains of Thought Degrade Verifiable-Reasoning
Distillation*, arXiv:2607.14552; *Better Accuracies, Worse Reasoning: A Step-Level Audit of Medical
Chain-of-Thought Distillation*, arXiv:2605.28301) is the only body of work found where a **compact supervised
field sits beside a rich, weakly-or-un-supervised field in the same output** and the weakly supervised part
degrades. But in both cases the rationale *is* in the loss — weakly supervised or answer-conditioned, not
masked — and the degradation is measured as reasoning faithfulness, not as a class distribution shifting or a
vocabulary migrating. T-04 may invoke it as an analogy; it is not prior art for the claim.

---

## What was searched (so the absence is auditable)

Web search against an August 2026 index, plus the alphaXiv corpus: ~14 distinct queries and 2 multi-round
paper-discovery calls, covering — guard/safety-classifier fine-tuning failures and negative results; severity
class collapse and class extinction; Qwen3Guard "Controversial" and its degradation; Aegis "Needs Caution"
binarization; Llama Guard custom-taxonomy and label-space mismatch; adapters/LoRA making guards more
permissive; multi-task LoRA shared-adapter interference and unsupervised/auxiliary-head degradation; loss
masking vs parameter isolation; prompt-loss masking; partial output supervision; structured-JSON schema drift
and invalid enum emission; cross-field and slot vocabulary contamination; minority collapse and rare-label
extinction in LLM classifiers; answer-only SFT degrading rationales.

Papers read beyond the title: arXiv:2605.02914, arXiv:2608.03201 (full structured report), arXiv:2506.17209,
arXiv:2512.05339 — plus abstract, blog, or model-card level for arXiv:2510.14276, arXiv:2501.09004,
arXiv:2312.06674, arXiv:2602.23636, arXiv:2401.13586, and the multi-task LoRA set.

**Caveats on this pass.** Several hits are 2026 preprints read at abstract or extracted-report level rather
than full PDF. The Qwen3Guard PDF extraction truncated and its Controversial-label ablation section was not
read in full — if that section turns out to report a class-loss event under adaptation, run 1's position
weakens further and should be re-checked before publication. I did not search patents, non-English venues, or
vendor engineering blogs and GitHub issue trackers beyond what surfaced incidentally; a practitioner bug
report of run 2's symptom could plausibly exist there and would not have appeared in this pass.

---

## Draft related-work prose for T-04 (third person, US English)

> Both failures have partial antecedents, and the run-1 result is the better documented of the two. That
> binary supervision yields binary behavior is established practice rather than a discovery: NVIDIA's Aegis
> guardrail datasets carry an explicit third "Needs Caution" label and ship two LoRA-tuned LlamaGuard
> variants differing only in whether that label was folded into Safe or into Unsafe, and Fang et al.'s
> minority-collapse analysis shows that a class starved below an imbalance threshold has its classifier
> collapse into an indistinguishable direction, the degenerate case being a class with no training targets at
> all. What appears not to have been reported is the deployment form of that result: a guard that retains a
> three-valued output schema and a documented runtime strictness lever, tuned on a corpus that cannot express
> the third value, silently loses the class while the schema and the lever remain in place, at a measurable
> cost to overall recall. The run-2 result is less well covered. Guard-side work establishes that fine-tuning
> erodes a guard's safety behavior — Granite Guardian's refusal rate falls from 85% to zero on two thousand
> benign samples, with 77% of the resulting activation change concentrated in the safety subspace — and the
> multi-task LoRA literature establishes that a shared adapter carrying several objectives suffers gradient
> conflict, but every such result concerns either the model as a whole or two fields that are both being
> trained. No treatment was found of a field that is emitted but excluded from the loss while a neighboring
> field in the same structured output is tuned through the same shared projections, and none of the reviewed
> work reports the specific symptom observed here, in which the protected field's class distribution shifts
> in both directions and the model begins emitting the neighboring field's closed vocabulary in the protected
> field's slot.
