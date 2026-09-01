# T-04 novelty check — PEFT/LoRA mechanics angle

**Angle assigned:** what LoRA adapts, and what that entails for selective or partial supervision —
target modules, adapter parameter interference, catastrophic forgetting under PEFT, selective loss
masking, label masking in instruction tuning, completion-only vs full-sequence loss, and the
`-100` / `ignore_index` convention.

**Question under test:** T-04 claims *"We are not aware of a treatment of what happens to an
unsupervised output field when a neighboring field is tuned under a shared adapter."*

**Verdict up front: the claim does not survive. It must be dropped and replaced with a narrowed
one.** A May 2026 arXiv preprint is a direct treatment of exactly that configuration — same adapter
placement, same two-field structured completion, same loss-masking manipulation, and it measures the
masked field. T-04 must cite it. Three narrower components of T-04's result do appear to be
unclaimed, and are listed under *What survives* below.

---

## 1. The disqualifying hit

### arXiv:2605.21127 — *Reasoning-Trace Collapse: Evaluating the Loss of Explicit Reasoning During Fine-Tuning* (submitted 20 May 2026)

**Configuration, verbatim from the paper.** Full-precision LoRA, `r = 16`, `alpha = 16`, dropout 0,
applied to "the standard attention and MLP projection layers used in transformer fine-tuning" — i.e.
the same shared q/k/v/o/gate/up/down surface T-04's mechanistic claim rests on. Four open-weight
reasoning models (Qwen3-8B, Llama-R1-8B, Nemotron-7B, Olmo-3-7B). The output is a two-field
structured completion the paper writes as `y = (r, a)`: a reasoning field inside `<think>...</think>`
followed by a final answer field.

**The manipulation is T-04's run 2.** In the `masked-think` condition, "the empty reasoning region is
excluded from the loss while the final answer remains supervised." The field is present in the target
sequence and excluded from the cross-entropy — not deleted, not re-targeted. The neighboring field is
supervised normally. That is loss masking of one output field under a shared adapter while its
neighbor is tuned.

**What it establishes about the masked field.** It does not hold still, and the paper measures how it
fails:

- For Llama-R1-8B, "both masking strategies avoid the complete Chemistry reasoning collapse seen
  under standard fine-tuning, though final Chemistry VR reaches only 61% for both `masked-think` and
  `response-only`."
- For Olmo-3-7B, "`Masked-think` preserves more final valid reasoning than `response-only`
  (67% vs. 53%), although both show sharp drops during training."
- The masked field's *failure mode changes*, not just its rate: "masking also changes the failure
  profile: rather than collapsing into empty or missing reasoning, most remaining invalid traces are
  truncated."
- Stated as a conclusion: "Masking is therefore a practical mitigation, not a complete solution."

**Precisely how this bears on T-04.** It covers the general claim T-04 asserts is untreated. An
unsupervised output field, masked from the loss and left in the target, measurably moves — in rate
and in kind — while a neighboring field is tuned under a shared LoRA adapter over attention and MLP
projections. T-04 cannot say no treatment exists.

**Precisely what it does *not* cover.**

1. *It does not make the mechanistic claim.* The paper never attributes residual drift to shared
   adapter parameters, never argues that loss masking is not parameter isolation, and offers no
   mechanism at all — it is an evaluation-and-tooling paper (it ships `ThinkPack`). The causal story
   T-04 tells is not told there.
2. *Opposite sign against a different baseline.* There, masking is the **mitigation**: the unmasked
   baseline supervises an *empty* `<think>` block, so the target itself teaches the field to vanish,
   and removing that target helps. In T-04 there is no degenerate target — the corpus supplies no
   severity label at all — and masking is **worse** than the coarsened-supervision baseline (recall
   0.6804 vs. 0.8329). The two papers are the two halves of the same mechanism seen from opposite
   baselines. T-04's is the sharper demonstration that masking is not preservation, because T-04 has
   no competing explanation from a degenerate target.
3. *Structural validity, not a class distribution.* The paper's metrics are valid / empty / missing /
   truncated on a free-text span. It never measures a categorical enum's per-class counts, and
   nothing in it corresponds to a documented operator-policy lever silently becoming a no-op.
4. *No cross-field vocabulary bleed.* Nothing there resembles the tuned field's label vocabulary
   appearing in the masked field's slot.

**One more thing worth quoting.** The paper itself says the area is thin: "Loss masking has been
suggested for this purpose [2, 19], but its effectiveness for preventing the loss of explicit
reasoning during fine-tuning remains under-explored." Its two citations for the *practice* are a blog
post (Bahree 2025) and a vendor document (ModelScope, *Qwen3 Best Practices*, 2026) — not research.
So: thin, folkloric, recently opened — but **not** unclaimed. A May 2026 paper saying a thing is
under-explored is not license for an August 2026 paper to say it is untreated.

---

## 2. Works that establish the mechanism in weaker or adjacent form

### Sebastian Raschka, *When to mask prompt tokens during SFT* (FAQ, sebastianraschka.com)

The clearest plain statement of the negative half of T-04's mechanism, though about the prompt span
rather than an output field: "Masking therefore removes the direct next-token targets in the prompt
region. It does not stop the model from learning how the prompt affects the answer," and a loss mask
"does not remove the prompt from the model input, and it does not block response tokens from
attending to the prompt." **Covers:** that masking is a targets-only operation. **Does not cover:**
any claim that the masked span's own output behavior drifts, and no experiment.

### Huerta-Enochian & Ko, *Instruction Fine-Tuning: Does Prompt Loss Matter?* (EMNLP 2024, arXiv:2401.13586)

Sweeps a continuous prompt-loss weight and finds a significant negative quadratic relationship
between PLW and performance on short-completion data, with small non-zero PLW (0.01–0.1) beating full
masking. **Covers:** that fully zeroing the loss on a span is not a neutral act — it is a point on a
weighting curve, and often not the best point. **Does not cover:** an *output* field; and the
measured quantity is downstream task accuracy, never the model's behavior on the masked span itself.

### Biderman et al., *LoRA Learns Less and Forgets Less* (TMLR 2024, arXiv:2405.09673)

Establishes the target-module fact T-04's mechanism relies on — targeting all transformer modules
including MLPs substantially outperforms attention-only — and that LoRA mitigates but does not
eliminate forgetting outside the target domain, while helping maintain more diverse generations.
**Covers:** that the adapted surface is shared and that adaptation moves untargeted behavior.
**Does not cover:** anything about fields within a single structured completion. This is the correct
citation for "a LoRA adapter modifies projections that both fields share," not for the finding.

### arXiv:2603.09684 — *On Catastrophic Forgetting in Low-Rank Decomposition-Based PEFT*

Controlled comparison across low-rank PEFT methods; LoRA mitigates but does not eliminate degradation
of capabilities outside the fine-tuning domain, and the learned correction is static and
input-agnostic. **Covers:** untuned behavior moves under LoRA. **Does not cover:** within-completion
field structure or loss masking.

### arXiv:2605.29498 — *Mask the Target: A Plug-and-Play Regularizer Against LoRA Forgetting* (May 2026)

Despite the title, "mask the target" means excluding the ground-truth token from a KL term, not
masking a span from cross-entropy. Its relevance is to T-04's **run 1**: it shows that ordinary
cross-entropy destroys the base model's relative preferences among alternative tokens, and that a
loss-level intervention is needed to preserve them. That is the shape of run 1's class extinction —
binary targets flattening a third class the base model emitted 49 times. **Does not cover:** run 2 at
all.

### arXiv:2505.20355 — *GraLoRA*

States that LoRA's low-rank bottleneck "introduces gradient entanglement to the unrelated input
channels and distorts gradient propagation." **Adjacent, and easy to over-claim from:** the
entanglement described is across *input channels* of a weight matrix, not across output fields of a
generated sequence. Cite it for the general fact that a single low-rank factor couples things that
are semantically unrelated; do not cite it as evidence for the field-level result.

### arXiv:2504.07448 (LoRI), arXiv:2607.29601 (multi-policy task sequencing), QR-LoRA (arXiv:2507.04599)

The multi-task-interference family: a single shared LoRA is a shared optimization space, divergent
objectives impose conflicting updates on the same low-rank factors, and the standard remedy is some
form of actual parameter isolation (sparse task masks, orthogonal subspaces, structured
decomposition). **Covers:** that isolation, when you want it, has to be built into the parameters —
which is T-04's point restated from the other direction. **Does not cover:** the case where the
"tasks" are two fields of one completion and one of them has no loss at all.

### Betley et al., *Emergent Misalignment* (arXiv:2502.17424; Nature, 2025)

Narrow LoRA fine-tuning on one objective produces broad behavioral change on unrelated prompts.
**Adjacent:** it is the strongest existing demonstration that supervision on X moves behavior on
not-X under a shared adapter. **Not the same finding:** the affected behavior is a different
distribution of prompts, not a co-emitted field in the same structured output, and there is no
masking manipulation.

### Mode-collapse / diversity-under-SFT literature — arXiv:2605.00195 (*Diversity in LLMs under SFT*), arXiv:2608.11426 (*Is Convergence Inevitable?*), OpenReview `3pDMYjpOxk` (*Attributing Mode Collapse in the Fine-Tuning...*)

Cross-entropy SFT systematically suppresses low-frequency patterns and alternative plausible outputs.
**This substantially covers T-04's run 1.** A minority class disappearing after fine-tuning on
targets that never contain it is the documented, expected behavior of cross-entropy — T-04 should
present run 1 as an *instance* with an operator-governance consequence (a documented policy lever
becoming a silent no-op), not as a novel learning-dynamics finding.

### HuggingFace TRL — `completion_only_loss` / `assistant_only_loss`

The `-100` `ignore_index` convention is documented purely as a masking mechanism; TRL's own issue
tracker records silent-failure bugs around it (issues 3781, 3728, 3927). Nothing in the docs claims
or examines behavioral preservation on the masked span. **Establishes:** the convention is documented
as arithmetic over the loss, never as a behavioral guarantee — which is worth one sentence in T-04,
since the guarantee is the thing practitioners assume.

---

## 3. What survives

Three components, in descending order of confidence:

1. **The cross-field vocabulary bleed.** The tuned field's label vocabulary ("non-violent illegal
   acts", "others", "violent") appearing in the masked field's slot. Nothing found anywhere describes
   a masked field adopting its neighbor's label space. This is the strongest unclaimed observation.
2. **The measured class distribution of a masked categorical enum.** arXiv:2605.21127 measures
   structural validity of a free-text span; nothing found measures per-class counts of a masked enum
   against the base model's counts (Controversial 49 to 187, Unsafe 650 to 367). The governance
   framing — a masked field is a *policy surface*, and its silent movement invalidates a documented
   operator lever — is also unclaimed.
3. **The explicit mechanistic statement.** "Loss masking is not parameter isolation" is not asserted
   in the literature found, only implied by the Raschka FAQ and demonstrated without explanation by
   arXiv:2605.21127. T-04 may claim to state and support it, provided it credits arXiv:2605.21127
   with the prior empirical demonstration.

**Recommended edit.** Delete "We are not aware of a treatment of what happens to an unsupervised
output field when a neighboring field is tuned under a shared adapter." Replace with a claim scoped
to (1)–(3), and cite arXiv:2605.21127, Raschka's FAQ, arXiv:2401.13586, and arXiv:2405.09673.

---

## 4. Draft related-work prose (third person, US English)

> The closest prior treatment is *Reasoning-Trace Collapse* (arXiv:2605.21127), which fine-tunes four
> open-weight reasoning models with a rank-16 LoRA over the standard attention and MLP projections on
> two-field completions of the form (reasoning, answer), masks the reasoning field from the loss
> while supervising the answer, and reports that the masked field still degrades sharply during
> training — valid-reasoning rates falling to 61–67 percent and the residual failure mode shifting
> from empty traces to truncated ones. That work frames masking as a partial mitigation and offers no
> mechanism; the present results reach the same conclusion from the opposite baseline, where the
> masked field has no degenerate target competing to explain the drift, and attribute it to the
> shared low-rank update over projections both fields read from. Related evidence is adjacent rather
> than equivalent: Biderman et al. (arXiv:2405.09673) establish that adapting all attention and MLP
> projections moves behavior outside the tuned domain, Huerta-Enochian and Ko (EMNLP 2024) show that
> zeroing the loss on a span is a point on a weighting curve rather than a neutral act, and the
> supervised-fine-tuning diversity literature (arXiv:2605.00195, arXiv:2608.11426) already accounts
> for the extinction of a minority class under coarsened targets. What appears undocumented is
> field-level: the per-class distribution of a masked categorical enum measured against the base
> model, and the migration of the supervised field's label vocabulary into the masked field's slot.

---

## 5. Search log (for auditability)

Queries run, all August 2026, via web search plus the alphaXiv corpus (two ranked discovery calls):

- LoRA shared adapter interference between output fields; loss masking vs parameter isolation
- `ignore_index` -100 loss masking in instruction tuning, documented effects on masked tokens
- "loss masking does not prevent the model from changing behavior on masked tokens"
- fine-tuning structured JSON output degrading an unsupervised field; multi-field label shift
- emergent misalignment / narrow fine-tuning changing unrelated behavior under LoRA
- "LoRA Learns Less and Forgets Less" — target modules and forgetting
- multi-task learning with partially labeled data; negative transfer on a shared trunk
- fine-tuning one attribute collapsing label diversity in another; multi-label generation collapse
- answer-only supervision degrading chain-of-thought; reasoning-trace drift
- LoRA entanglement of output fields via shared low-rank update in structured prediction
- "Instruction Fine-Tuning: Does Prompt Loss Matter?" / prompt loss weight
- TRL `completion_only_loss` caveats; masked tokens still affecting behavior
- catastrophic forgetting under PEFT/LoRA — surveys and empirical studies
- Llama Guard / ShieldGemma / Aegis fine-tuning, severity and category field degradation
- unsupervised output slot drift under a co-emitted tuned field, guard classifiers, 2026
- alphaXiv ranked discovery x2: (a) masked/unsupervised output field under a shared LoRA adapter;
  (b) minority-class extinction under coarsened binary supervision in structured classifiers

Fetched and read rather than judged from title: arXiv:2605.21127 (abstract plus full HTML body —
introduction, related work, Experiment 2, discussion, appendix training config and masking examples),
arXiv:2505.20355, arXiv:2605.29498, arXiv:2608.17804, arXiv:2605.00195, the Raschka FAQ, and the
*To Mask or Not to Mask* write-up. OpenReview `3pDMYjpOxk` and the TACL paper *On the Effect of
Instruction Tuning Loss on Generalization* returned a bot-check page and HTTP 403 respectively and
are cited here only from search summaries — **both should be re-checked by hand before T-04 cites
them.**

**Absence claimed explicitly:** across all of the above, no work was found that (a) measures the
per-class output distribution of a loss-masked categorical field against the base model's, (b)
reports a masked field adopting a neighboring field's label vocabulary, or (c) states in terms that
loss masking is not parameter isolation. The general phenomenon T-04 claims is untreated **is**
treated, by arXiv:2605.21127.
