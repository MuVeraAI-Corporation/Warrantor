# What Guard Benchmarks Cannot See: Six Controlled Experiments in Guard Model Evaluation

**Research paper · Draft 4 (cross-family ceiling, noise floor) · 2026-08-31 · Vikram Jha**
*Catalog ref: T-03 · target: IEEE SaTML 2027 — abstract 22 Sep 2026, full submission 29 Sep 2026*

> **Draft 1 was a pre-registration.** Sections 1–4 and 7–9 were frozen before any run executed.
> This draft populates Section 5 with measured results and rewrites Sections 6, 8 and 9 against
> them. **Two pre-registered findings did not survive contact with the data and are withdrawn in
> place**, with the withdrawal stated rather than the claim quietly adjusted.
>
> Every experiment below was pre-registered and hashed before its data existed. Hashes are listed
> in §7. Amendments are recorded as dated addenda, never as edits.

---

## Abstract

Guard models — small classifiers that screen agent inputs and outputs for unsafe content — are
increasingly the primary runtime control in agentic systems, and frequently the only control that
operates on content rather than capability. We report six controlled experiments whose common
result is that **standard guard evaluation systematically understates fragility**, in ways that are
specific, measurable, and invisible to the instruments the field currently uses.

**First**, semantically preserving rephrasing does not make guards over-trigger; it makes them
**blind**, and the two failure directions are wildly asymmetric. On benign inputs the false-positive
rate is unchanged (1.00×, 95% CI [0.45, 4.20]) with symmetric item-level churn. On unsafe inputs
using the *same* transformations, the false-negative rate rises 1.42× and 1.46× across two model
scales, with 33-versus-7 and 43-versus-10 item-level discordance (McNemar p ≈ 2×10⁻⁵ and 3×10⁻⁶).
**A team measuring only false positives would have concluded the guard was phrasing-robust.**

**Second, this asymmetry is a property of guard models as a class, not of one publisher.** Across a
four-model panel spanning **three families and three publishers** — Llama Guard 3, ShieldGemma (2B
and 9B), and Qwen3Guard as a family control — evaluated on the *same* 1,799 items, benign discordance
was **never** significantly skewed and unsafe discordance was **always** significantly skewed toward
evasion (p from 5.6×10⁻⁷ to 2.0×10⁻⁹). Two results fall out of the panel that the single-family
experiments could not produce. **Evasions transfer**: a rephrasing defeating one guard defeats a
guard from a different publisher at **2.5–6× above that guard's base rate**, so defense-in-depth
across heterogeneous guards buys much less than independence would imply. And **guards agree on
benign content and disagree on unsafe content** — 95–99% per-item agreement on benign originals
against 35–83% on unsafe ones, with two well-configured guards from different publishers disagreeing
on 22% of unsafe items.

**Third**, that floor is far from the ceiling, **in every family tested**. Best-of-16 selection over
the same transformation families evades **71.6% to 96.9%** of the unsafe content each of **six
models across three publishers** originally caught — 77.0% and 85.4% for the two Qwen3Guard scales
first measured, and 89.8% (Llama Guard 3 8B), 96.9% (ShieldGemma 2B), 96.2% (ShieldGemma 9B) and
71.7% (Qwen3Guard 8B) on extension. In every model, **systemic evasion outnumbers fragile evasion**:
more items are defeated by eight or more of sixteen candidates than by only one or two. A
decomposition shows most of the gap comes not from the search budget but from **decoding
temperature**: at a fixed budget of four candidates, sampling at temperature 1.0 rather than greedily
raises evasion by 37.3 points, while quadrupling the budget adds 14.3 more. Any robustness
evaluation that rephrases deterministically understates its own bound by roughly that margin.

**Fourth**, quantization changes safety verdicts, and it does so in **every one of five models across
three families**. At `Q4_K_M` — the default in most local serving stacks — between 4 and 18 verdicts
per thousand differ from that model's own `f16` reference. Published guard benchmarks that do not
state their quantization are under-specified. **The direction of the change, however, is a model
property rather than a rule**: one model's disagreements at `Q2_K` are 84-to-0 safety regressions,
another runs *usability*-adverse until it reverses at the extreme, and a third is symmetric
throughout — so a deployer can assume neither that quantization errs safe nor that it errs
conservative. Tolerance clusters by **family**, not by size: a 0.6B model is more quantization-stable
than both an 8B and a 9B.

**Fifth**, category specialization does not merely fail to help; at equal data volume it **hurts**.
Reallocating a guard's training distribution toward a coherent harm cluster degraded accuracy in
both models and both replication splits, cost 8–20 points across seven non-target categories, and
produced **no gain on the targeted categories**.

**Sixth**, and contrary to our own pre-registered expectation, guard decisions are **not** sensitive
to context-window configuration on a standard benchmark — zero decision changes across a sixteenfold
range — because such corpora contain no inputs long enough to reach even the smallest window. The
hazard is not absent; it is invisible to the instruments used to look for it. **Concurrent work
[LongGuard] supersedes this observation**, constructing the long-input benchmark we identify as
missing and measuring guardrail failure across it; we report our null as confirmatory and cite
theirs as the result. **We then build the instrument our null showed was missing** and replicate
them on two models they did not test: placed in inputs up to 32k tokens, the same payloads that are
caught 100% of the time unframed are missed at up to 32%, with **19 of 60 payloads degrading and 0
improving at both scales** (*p* < 0.0001). **The null was a property of the corpus, not of the
guards.** Notably, this is the one hazard we measure where **scale does not help at all** — the
payload-level degradation is identical at 0.6B and 4B — which makes reaching for a larger guard the
wrong reflex here specifically.

**What is novel here is narrower than an earlier draft claimed.** Paraphrase sensitivity
[GuardMeaning], quantization's effect on safety [QuantTemp], long-context guardrail failure
[LongGuard] and specialization harm [SafetyGeom] are all established. **Our contribution is the
asymmetry between the two failure directions, the cross-family transfer of evasions, the
floor-and-ceiling decomposition, and a measured reproducibility floor.** Section 2 states which
claims we withdrew and why.

Cutting across all six: **aggregate rates conceal per-item instability.** Two independent
experiments, neither designed to show it, produced pooled rates identical to four decimal places
while 4–6.7% of individual verdicts moved. We release the harness, transformation specifications,
dataset manifests, model bills of materials, pinned environments, per-item outputs, and every
pre-registration hash — and we report the withdrawn findings and rejected runs alongside the
accepted ones.

**Keywords:** guard models, content moderation, agentic AI, adversarial robustness, quantization,
reproducibility

---

## 1. Introduction

An agentic system has two broad classes of runtime control. **Capability controls** bound what the
system can do: authorization, sandboxing, egress filtering, autonomy budgets. **Content controls**
inspect what passes through: guard models that classify inputs and outputs and gate the pipeline.

Capability controls are the stronger class, because they bind regardless of what the content says.
They are also more expensive to deploy, requiring operating-system or network position many
deployments do not have. The practical consequence is that a large share of production agentic
systems rely on a guard model as their principal runtime control.

That makes how guards are *measured* a security question, not a benchmarking question. This paper
asks whether standard evaluation practice tells a deployer what they need to know, and finds six
specific places where it does not.

**The organizing observation.** Guard evaluation reports aggregate rates: false-positive rate,
false-negative rate, F1 on a fixed corpus. Two of our experiments produced aggregate rates that were
**identical to four decimal places** across conditions while a twentieth of the individual verdicts
changed. An aggregate rate is a sum over items; it is preserved exactly when errors are exchanged
rather than eliminated. A guard whose verdicts churn under a perturbation is not stable, and the
standard metric cannot distinguish it from one that is.

**Contributions.**

1. A paired benign/unsafe rephrasing design showing that guard fragility under rephrasing is almost
   entirely on the false-negative side, with the false-positive side flat (§5.1, §5.2).
2. A **cross-family panel** over the same items, establishing that the asymmetry holds across three
   publishers, that evasions **transfer** between families well above chance, and that guards agree
   on benign content while disagreeing sharply on unsafe content (§5.7).
3. A floor-and-ceiling pair on identical items, with a decomposition isolating decoding temperature
   from search budget (§5.3).
4. A quantization measurement that **holds the serving runtime constant** so weight precision is the
   only variable, and reports **per-item verdict agreement** rather than aggregate rates (§5.4).
   That quantization affects safety is established [QuantTemp, QResafe, QFair]; the runtime-controlled
   design and the per-item statistic are what we add.
5. A category-specialization result that is negative rather than null, with a mechanism (§5.5).
6. A null on context-window sensitivity together with the corpus property that makes it a null,
   which relocates rather than dissolves the hazard (§5.6).

**What we withdraw.** Draft 1 pre-registered that rephrasing raises false-positive rate
substantially, and that context configuration is a live reproducibility confound. **Both are
withdrawn on our own data**, in §5.2 and §5.6 respectively.

---

## 2. Related work

The 2026 literature on agent-runtime security organizes into three strands. We position against each
and note where our work is **not** novel.

**Runtime invariants and execution control.** Recent work defines explicit, testable security
invariants for MCP-style agent runtimes — metadata non-authority, grant-backed approval, canonical
resources, principal binding, scoped capability invocation, data-flow authorization, deny-path audit
and explicit protocol state — implemented in a reference runtime and benchmarked against modeled
attacks [HCP]. That work operates on **capability controls**; ours operates on **content controls**.
They are complementary and neither substitutes for the other. We make no claim about invariant
completeness.

**Protocol composition.** Formal analysis of agent-protocol composition, with protocol-derived checks
expressed as TLA+ invariants and counterexamples replayed against production SDKs, has established
that composition across agent protocols is under-specified [AgentThread]. **We do not claim novelty
on that observation**, and we do not address protocol conformance.

**Evidence sufficiency.** Benchmarks exist for whether governance evidence emitted by agent runtimes
suffices to reconstruct decision-level properties rather than merely being present [DEMM-Bench].
Guard decisions are one input to such evidence; our contribution is upstream of it.

**Runtime defenses against indirect injection.** Frameworks for defending tool-augmented agents
against indirect prompt injection [ClawGuard] treat guard-like components as system elements.
That work does not, to our reading, measure guard behavior under the conditions we test.

**Guard model evaluation, and what is already established.** An earlier draft of this paper asserted
four gaps in the literature. **Three of them do not exist**, and we state that here rather than in a
limitations section.

**Paraphrase sensitivity is established.** Pinneri and Louizos [GuardMeaning] show that
meaning-preserving paraphrases cause large fluctuations in guard safety scores across six
open-source guard models, name the phenomenon a *label flip*, and propose self-supervised training
that reduces semantic variability by ~58%. **The claim that rephrasing destabilizes guard verdicts is
theirs, not ours**, and they additionally supply a working defense where two of ours fail (§5.10,
§6.5).

**Where we refine rather than repeat them.** Their headline metric, Label Flip Rate, is defined as
the proportion of original responses for which at least one paraphrase crosses the decision
boundary. **That definition is direction-agnostic.** They observe flips "to unsafe, or vice versa"
and bin the rate by original score region, but do not separate the two directions in their results.

**A direction-agnostic flip rate pools a usability failure with a security failure, and we measure
that the two behave completely differently**: benign→flagged is flat at 1.00× with symmetric
item-level churn, while caught→missed rises 1.42×/1.46× with 6:1 discordance at *p* ≈ 10⁻⁵,
replicated across three publishers (§5.1, §5.7). A single pooled rate reports those as one
phenomenon. **This asymmetry is our primary contribution, and it is a refinement of [GuardMeaning]
rather than a displacement of it.**

**Their binning also supports our §5.10 hazard.** They report flip rates highest in the ambiguous
score region (0.25–0.75), which is independent evidence that instability concentrates on borderline
items — the population-dependence we flag as unmeasured for the reproducibility floor.

**Quantization's effect on safety is established.** A factorial analysis of quantization and sampling
temperature on safety alignment [QuantTemp] makes essentially the argument we make in §6.4, and
further work addresses quantization-induced safety risk and its repair [QResafe] and fairness and
safety under quantization [QFair]. **Our earlier claim that prior work does not control serving
quantization was wrong and is withdrawn.**

**Long-context guardrail failure is established.** LongGuard [LongGuard] evaluates 15 guardrails over
a 0.25k–32k grid, finds unsafe recall dropping more than 50% on average, attributes it to
proportional dilution via a paired control design, traces an attention→logit→behavior mechanism, and
supplies training-free mitigations. **This supersedes our §5.6 context finding**, which observed only
that standard corpora are too short to exhibit the hazard.

**We replicate it rather than compete with it** (§5.11), on two models they did not evaluate, and
report the replication as such. The one design element we add is a **0× control** — the payload with
no surrounding text — which a needle-in-haystack grid does not have and which anchors every cell to an
absolute floor instead of a relative baseline. **The phenomenon, its mechanism and its mitigation are
theirs.**

**Specialization harm has an adjacent precedent.** Fine-tuning a guard on benign in-domain data can
collapse its safety geometry [SafetyGeom]. Our §5.5 differs in mechanism — we hold label balance
constant and vary only the composition of the unsafe half — but the direction of the finding is not
new.

**What we claim as ours, narrowly:**

1. **The asymmetry.** Prior work reports label flips in both directions. We measure that the two
   directions are **wildly unequal** — false-positive rate unchanged, false-negative rate up 1.42×
   with 6:1 item-level discordance — replicated across three families (§5.1, §5.7).
2. **Cross-family evasion transfer** at 2.5–6× base rate, which undermines the independence
   assumption behind stacking heterogeneous guards (§5.7, §6.5).
3. **The floor-and-ceiling pair on identical items**, with the decomposition showing decoding
   temperature dominates search budget (§5.3).
4. **A measured reproducibility floor** for guard evaluation (§5.10), for which we found no prior
   art.

Everything else in this paper is confirmatory, and is presented as such.

**What we are not claiming.** We do not claim guards are ineffective, that specialization can never
help, that our results transfer to guard families we did not test, or that our adversarial ceiling
is a worst case. §8 states the generalization boundary explicitly and narrowly.

---

## 3. Threat model and scope

**System under study.** A guard model deployed inline in an agentic pipeline, classifying either
model-bound input (including tool output re-entering context) or model-emitted output, and returning
a decision that gates the pipeline.

**Adversary.** An adversary who can influence content the guard will classify — a document the agent
reads, a tool response, a ticket, a code comment, a web page — and who can rephrase that content
freely while preserving meaning. The adversary **cannot** modify the guard, its weights, its
configuration, or the pipeline. This is the indirect-injection adversary, and the one guards are
actually deployed against.

**Two failure modes, and why the asymmetry between them is the point.**

- **False negative:** unsafe content classified safe. Directly exploitable.
- **False positive:** benign content classified unsafe. Usually treated as a usability cost. We
  treat it as a security failure too, because its operational consequence is predictable: a guard
  that fires often on benign content gets tuned down or switched off, converting a usability problem
  into an absent control.

Draft 1 expected the second mode to carry the interesting result. **The data says the first does**,
and that the field's habit of measuring benign-side robustness is why the first has been missed.

**Out of scope.** Weight-level attack on the guard; multi-turn attacks accumulating across a
session; multimodal content; and the capability-control layer entirely.

---

## 4. Methodology

All specifications were frozen and hashed before their data existed. Where a design changed, the
change is a dated addendum to the frozen document with its reason, not an edit (§7.2).

### 4.1 Models

Two parameter scales of one guard family — **Qwen3Guard-Gen-0.6B** and **Qwen3Guard-Gen-4B** — so
scale effects separate from the effect under test. All checkpoints carry a Model BOM recording base
model, dataset manifest hash, training configuration, adapter rank and target modules, and the
environment hash.

Guards are served at `num_ctx` 8192, seed 0, temperature 0, **fail-closed** (an unparseable output
is scored harmful; fail-open would turn a dead backend into perfect recall), with `Controversial`
scored harmful. This configuration is identical across every run in the program except where it is
the variable under test (§4.5).

### 4.2 Corpora

**WildGuardMix** (public) for the rephrasing, evasion and quantization experiments. **Aegis AI
Content Safety Dataset 1.0** (public) for specialization.

⚠️ **A licensing constraint resolved by substitution, not by ignoring it.** Draft 1 specified an
expanded mixture for the specialization experiment. That corpus is recorded in our own registry as
`commercial_clearance = "NOT CLEARED"` — its CC-BY-4.0 license and its research-only gate form
disagree — and it does not resolve on the Hub. Rather than quietly substitute, the change of axis it
forced is recorded as a dated amendment (§4.4).

Category labels are normalized to a common taxonomy before comparison. **The normalization map is
published**, because it is where a category-distribution confound would hide.

### 4.3 Experiments 2 and 2-B — rephrasing, both directions

**H2.** Semantically preserving rephrasing changes guard verdicts.

**Transformation set (frozen, sha256 `48ce3dae`).** Five families applied mechanically at
temperature 0, one draw each: **T1** register shift, **T2** indirection, **T3** hedging, **T4**
embedding within a larger benign frame, **T5** technical framing.

**The set is non-adaptive by construction.** It was designed and frozen for a false-positive
experiment *before any guard had been evaluated on anything*. No transformation was selected, tuned
or retained because it defeated a guard. Every effect it produces is therefore a lower bound.

> **An amendment worth stating.** Version 1 of the set was withdrawn: T2 and T4 returned the input
> unchanged, because "preserve the meaning exactly" was read by the generator as "change nothing."
> The API success flag could not detect this — it reports transport success, not semantic change.
> Version 2 was written with the reason recorded, and re-verified by measuring similarity directly.

**E2 (benign arm).** 150 benign items × 5 transformations = 750 rephrasings. Primary quantity: FPR
on originals vs. their own rephrasings, paired, with bootstrap CI on the ratio; decomposed by
transformation, with **T4 reported separately and never pooled** because it lengthens inputs several
fold and any T4 effect is confounded with length.

**E2-B (evasion arm, pre-registered separately at `cdc94f66`).** The identical transformation set
applied to 150 unsafe items whose original verdicts were already measured. E2's own data motivated
it: two benign items were flagged as originals and **cleared** by rephrasing, and the same mechanism
applied to unsafe text is evasion.

**Statistical treatment.** The originals are 150 items, so their rate interval is wide and an
unpaired comparison is under-powered. **Each item is its own control**, so the reported test is
McNemar on item-level discordance.

### 4.4 Experiment 1 — specialization, category-controlled

**H1.** A guard tuned on a concentrated harm cluster outperforms a general guard on that cluster.

**Amendment, dated and recorded (`9240fabd`, addenda to `0df38fc3`).** Draft 1 specified *vertical*
specialization — finance, clinical, legal. That corpus is inaccessible and not cleared (§4.2), so the
axis moved to **harm category**. The underlying question is unchanged; the axis is not. **A null on
categories is not a null on domains**, and the vertical question remains open.

**Target cluster, fixed before any measurement:** `Hate/Identity Hate`, `Harassment`, `Profanity`,
`Threat` — four forms of directed interpersonal hostility, jointly distinct from the other clusters.
Selected on semantic coherence and volume, **not** on baseline performance; selecting weak categories
after measuring them would guarantee the result.

**Two corpora, identical in everything but composition.** `G-cat` concentrates the target cluster;
`G-gen` is stratified across all categories. **Both n≈2,790 at 71.4% unsafe** — the corpus-wide
ratio.

> **A confound caught before training, not after.** The first `G-cat` construction came out 100%
> unsafe, because membership in the target cluster implies a harm label. Training one adapter on
> only-unsafe data and comparing it against one that saw both would have measured the label balance,
> not specialization. Both corpora now hold label balance constant; the only difference is the
> composition of the unsafe half, roughly a twofold concentration. **`G-gen` retains target content
> rather than excluding it** — a general guard that has never seen hate speech is not a general
> guard, and beating one would prove nothing. The contrast under test is concentration, not presence.

**Replication.** A second independently seeded split, generated before any result was seen. An effect
in one split and not the other is reported as **unreplicated**.

### 4.5 Experiment M3 — quantization

**H3.** Per-item verdict agreement with an `f16` reference decreases as quantization deepens.

**The confound this design exists to eliminate.** The obvious implementation serves `f16` through
`transformers` and the K-quants through `llama.cpp`. **That measures runtime, not precision.**
Instead every condition — `f16` included — is a GGUF from a single publisher, converted from one set
of source weights, served through one Ollama/llama.cpp build on one accelerator class.

**Ladder:** `F16`, `Q8_0`, `Q6_K`, `Q5_K_M`, `Q4_K_M`, `Q3_K_M`, `Q2_K`, monotone in bits per weight,
× two models = 14 conditions × 1,000 items stratified on the harm label.

**`f16` is the reference condition, not ground truth about safety.** Every number is an agreement
between precisions; none establishes that the `f16` verdict is correct.

### 4.6 Experiment M2 — the adversarial ceiling

**H4.** Selecting among many candidate rewrites using the guard's own verdict evades substantially
more than five fixed transformations.

**Paired with the floor by construction:** the same 150 unsafe items as E2-B, and four of the same
five families. n = 16 candidates per item (4 families × 4 seeds) at **temperature 1.0**; an item
counts as evaded if any candidate is missed. Denominator is the **126 and 123 items each guard
originally caught** — an item already missed cannot be evaded.

**This is selection-based best-of-n, not feedback-guided search.** The generator never sees a guard
verdict while generating. Feedback-guided, gradient-access and transfer attackers are all strictly
stronger, so **even the ceiling is a lower bound on a determined adversary.**

**T2 is excluded from the ceiling**, recorded as a dated addendum: the floor found it *below*
baseline in both models, so a quarter of a fixed budget would go to the family that helps the guard.
The floor is therefore reported twice — all five families, and the family-matched four — and the gap
is computed against the matched one.

### 4.7 Experiment 3 — context-length sensitivity

**H5.** Guard decisions vary with context-window configuration on identical input. Hold input fixed;
sweep `num_ctx` across 2048–32768 at fixed seed.

**Experiment P3-X — the long-input extension.** H5 varies the *window* on a fixed input; P3-X varies
the *input* inside a fixed window, which is the condition H5 could not reach on a standard corpus.
60 payloads, each caught unframed by both models, across lengths {0, 1k, 4k, 16k, 32k} × positions
{0%, 25%, 50%, 75%, 100%} — 21 cells, 1,260 inputs per model. **Filler is one benign corpus reused in
every cell**, so filler content is constant and only quantity and placement vary; that is what
separates dilution from displacement. `num_ctx` is 32768 throughout, held constant across all cells
and **disclosed as not comparable to this paper's other tables** (§5.11). The primary quantity is
miss rate as a joint function of length and position, with the 0× cell as an absolute floor, and
**unparsed rate per cell reported first** — above 5% a cell is a generation failure rather than a
measurement and is suppressed.

### 4.8 Experiment M1 — the cross-family panel

**H6.** The benign/unsafe asymmetry is a property of guard models as a class rather than of one
publisher's training data.

**The same 1,799 items, not a new sample** — the 150 benign originals, 750 benign rephrasings, 150
unsafe originals and 749 unsafe rephrasings already run through Qwen3Guard. **Reusing identical
items is the design**: a fresh sample would confound a family difference with an item-difficulty
difference, and the asymmetry is a within-item contrast.

**Panel.** Llama Guard 3 8B (Meta), ShieldGemma 2B and 9B (Google), and **Qwen3Guard-Gen-8B as a
family control** — a third scale of a family already measured, included to distinguish a family
effect from a scale effect, and explicitly **not** counted as independent evidence for H6.

**Per-family parsing is where a bias would enter, and two rules constrain it.** Each family emits a
different format — `safe` / `unsafe
S<n>`, a Yes/No policy answer, or two `Safety:` / `Categories:`
lines — so one parser cannot read all three. Each parser was written **from that family's published
specification before that family was run**, and unparseable output is scored harmful for every
family alike; fail-open would let a family with a broken parser report perfect recall. Unparsed rate
is reported per family before any other number, and a family above 5% is reported as a parsing
failure rather than a measurement.

**A format probe, declared in advance.** Running a spec-derived parser blind risks losing an entire
family to a template mismatch. Ten items per family — **benign originals only**, a population in
which the direction of the effect under test cannot be observed — were inspected for output *shape*,
their outputs discarded and re-evaluated in the full run. No parser required correction, so the
prohibition on post-hoc parser adjustment never came into play.

⚠️ **Quantization is not held constant across families**, because each publisher ships different
default GGUFs. §5.4 establishes that quantization moves verdicts by 4–11 per thousand at Q4-class
precision — an order of magnitude below the effects under test here, but not zero, and reported as a
limitation rather than assumed away.

### 4.9 Pinned environment

Fixed framework and CUDA versions pinned **at source** rather than by resolver. Not incidental rigor:
a floating framework/CUDA pairing in our environment script had previously changed what "the same
environment" meant between two runs, and that defect is disclosed in the artifact.

---

## 5. Results

Every run below completed with zero errored samples and zero backend errors except where stated.

### 5.1 The headline: rephrasing fragility is asymmetric

Same guards, same frozen transformation set, same generator, same seed, same evaluation settings.
**Only the input population differs.**

| | benign arm (E2) | evasion arm (E2-B) |
|---|---|---|
| 4B ratio | **1.00×** [0.45, 4.20] | **1.42×** |
| 0.6B ratio | 1.13× [0.55, 3.60] | **1.46×** |
| 4B items with phrasing-dependent verdicts | 4.0% | **26.7%** |
| 0.6B | 6.7% | **35.3%** |
| Direction (4B) | 6 flips each way — symmetric | **60 vs 10** |
| Paired significance (4B) | symmetric by inspection | **p = 2.1 × 10⁻⁵** |

**Rephrasing does not make these guards over-trigger. It makes them blind.**

### 5.2 Experiment 2 — the benign arm, and a withdrawn finding

`R1` **FPR is unchanged.** 4B: 0.0333 (5/150) → 0.0333 (25/750). Not approximately — 5/150 and
25/750 are both exactly 0.0333. 0.6B: 0.0400 → 0.0453. Amplification **1.00× [0.45, 4.20]** and
**1.13× [0.55, 3.60]**.

`R2` **The aggregate is stable because the flips cancel, not because the guard is.** For the 4B, four
items went clean → flagged (6 pair-flips) and two went flagged → cleared (6 pair-flips). Three of the
five original false positives were flagged under all five transformations; two flipped under three
each.

`R3` Per transformation, all ratios lie between 0.80× and 1.67×. **T2 is the largest in both models**,
which matters because T2 has the *highest* surface similarity to the original (median 0.741) — it
wraps the original clause in a reporting frame and leaves its wording nearly intact.

> **Finding 2 as originally stated is withdrawn.** Draft 1 claimed rephrasing "raises false-positive
> rate substantially." It does not. Draft 1 also cited a **4.12× false-positive gap** measured on
> WildGuardTest's own `adversarial` flag (0.0224 vs 0.0923, n=1699). That is a **between-population**
> comparison, not a paired rephrasing effect, and this experiment provides **no support** for a
> fourfold paired effect.
>
> **It does not refute it either.** With five false positives in the baseline the interval reaches
> 4.20. The honest claim is *no support for, and under-powered to exclude*. An earlier internal
> analysis of ours said "refutes"; that was wrong and is corrected here, because a paper about
> unsupported inference cannot afford to make one.

### 5.3 Experiment 2-B and M2 — the evasion floor and ceiling

`R4` **Floor.** FNR rises from 0.1600 to 0.2270 (4B) and 0.1800 to 0.2630 (0.6B) — **1.42×** and
**1.46×**. Of the items each guard originally caught, **26.2% (33/126)** and **35.0% (43/123)** can
be slipped past it by at least one of five generic rewrites.

`R5` **The asymmetry is the finding, and the test is paired.**

| | evasion (b) | recovery (c) | exact binomial | McNemar χ² |
|---|---|---|---|---|
| 4B | 33 | 7 | 2.1 × 10⁻⁵ | 15.62 |
| 0.6B | 43 | 10 | 2.8 × 10⁻⁶ | 19.32 |

`R6` **T2 is below baseline in both models** (0.92×, 0.81×): wrapping unsafe content in a reporting
frame makes these guards *better* at catching it. The strongest family differs by model — T5 for the
4B, T4 for the 0.6B — so a defense tuned to one model's weak spot would not transfer.

`R7` **Ceiling.** Best-of-16 evades **77.0% (97/126)** [0.689, 0.835] and **85.4% (105/123)**
[0.781, 0.905], against family-matched floors of 25.4% and 35.0% — gaps of **+51.6** and **+50.4**
points. The ceiling nearly strictly dominates: only 2 items per model were evaded by the floor and
not the ceiling.

`R8` **The decomposition, which is the more useful result.** Holding budget fixed at four candidates
separates temperature from search:

| | floor: 4 cand, temp 0.0 | 4 cand, **temp 1.0** | 16 cand, temp 1.0 |
|---|---|---|---|
| 4B | 25.4% | **62.7%** | 77.0% |
| 0.6B | 35.0% | **65.9%** | 85.4% |

**Temperature effect at fixed budget: +37.3 and +30.9 points. Budget effect 4→16: +14.3 and +19.5.**
Most of the gap is decoding temperature, not search budget.

`R9` **Evasion is mostly systemic, not fragile.** Of the 4B's 16 candidates per item: 29 items never
evaded, 24 evaded by only 1–2 candidates (*fragile*), **38 evaded by 8 or more** (*systemic*), and
**12 evaded by all 16**. For the systemic group — and absolutely for the 12 — detection depended
entirely on the original surface form, and no retry- or ensemble-based defense recovers it.

`R10` **T4 dominates** at candidate level: 0.5079 (4B) and 0.6199 (0.6B) miss rate, roughly double any
other family. T4 was *not* the strongest family on the floor for the 4B; under sampling its variance
is what makes it effective.

`R11` **Realized budget was below nominal.** Temperature-1.0 sampling sometimes returns byte-identical
text across seeds: mean **15.17** distinct candidates of 16 nominal, 37 of 150 items below 16. This
makes the ceiling **conservative**, not inflated.

### 5.4 Experiment M3 — quantization changes safety verdicts

`R12` Per-item agreement with the `f16` reference, 1,000 items:

| | Q8_0 | Q6_K | Q5_K_M | **Q4_K_M** | Q3_K_M | Q2_K |
|---|---|---|---|---|---|---|
| **4B** | **1.0000** | 0.9980 | 0.9980 | **0.9960** | 0.9930 | 0.9700 |
| **0.6B** | **0.9960** | 0.9980 | 0.9870 | **0.9890** | 0.9620 | 0.5150 |

`R13` **`Q4_K_M`, the deployed default, is not verdict-neutral**: 4 and 11 items per thousand differ
from `f16`.

`R14` **"Q8_0 is lossless" is false for the small model.** The 4B agrees perfectly; the 0.6B does not,
and three of its four disagreements are safety regressions. It is a property of the model, not the
quantization.

`R15` **At the aggressive end the direction is safety-adverse — in this family.** At `Q3_K_M`, misses
dominate in both models: 6 safety regressions against 1 usability for the 4B, 30 against 8 for the
0.6B. **§5.8 shows this does not generalize**, and the claim is scoped to Qwen3Guard accordingly.

`R16` **The 0.6B at `Q2_K` is model collapse, not verdict drift**, and the distinction was checked
before the row was interpreted. 137 of 1,000 outputs were unparseable (including fullwidth Unicode in
the verdict field); under fail-closed a naive read gives FPR 0.6124 and "the guard became
over-restrictive." Recomputed on parseable outputs only, it agrees with its own reference at
**0.5006 [0.4673, 0.5339]** — chance. **Every condition from `F16` through `Q3_K_M` had zero backend
errors in both models**, so all agreement figures above that rung are clean.

`R17` **The apparent non-monotonicity is not a finding.** The 0.6B scores lower at `Q5_K_M` than at
`Q4_K_M` despite more bits. The pre-registration said in advance that a non-monotone curve would be
reportable. It is not: 13 disagreements versus 11, intervals almost fully overlapping. Recorded
because the prediction was made, and resolved against itself.

### 5.5 Experiment 1 — specialization hurts

`R18` All four comparisons negative, both models, both splits:

| | G-cat | G-gen | naive Δ | macro Δ | target-cluster Δ |
|---|---|---|---|---|---|
| 0.6B split A | 0.8324 | 0.8949 | −0.0626 | −0.0856 | +0.0075 |
| 0.6B split B | 0.8465 | 0.8941 | −0.0475 | −0.0469 | +0.0112 |
| 4B split A | 0.8449 | 0.8882 | −0.0434 | −0.0780 | +0.0075 |
| 4B split B | 0.8590 | 0.8916 | −0.0325 | −0.0642 | −0.0075 |

`R19` **The mechanism.** 4B split A: `G-cat` recall 0.8276 against `G-gen` 0.9079 — 146 missed unsafe
items against 78 — while its *false-positive* rate is **lower** (0.1136 vs 0.1591). It did not
sharpen; it moved its operating point toward "safe."

`R20` **No gain where the gain was supposed to be.** Per category, `G-cat` is worse on seven
non-target categories by 8–20 points (Suicide/Self-Harm −0.20, Needs Caution −0.13, Controlled
Substances −0.12, Violence −0.10, Criminal Planning −0.09) and, on its four target categories,
gained +0.014 and +0.017, was flat on one, and **declined 0.083 on Threat**.

`R21` **The pre-registered quantity did not fire as anticipated.** §4.4 defined the reported finding
as the difference between naive and reweighted deltas, on the theory that a naive *gain* might vanish
under reweighting. There was no gain to be an artifact of. The quantity is informative in the other
direction — positive, meaning the naive aggregate **flatters** `G-cat`, whose damage concentrates in
rarer categories that prevalence weighting under-counts. **For the 0.6B it is unreplicated**
(+0.0231, −0.0006) and is reported as such.

`R22` **Sanity check.** Both base models produced **1,199 unparsed outputs of 1,199** in the
fine-tune's bare continuation format, scoring 0.7064 purely because fail-closed counts unparsed as
harmful and 70.6% of the split is unsafe. Against 1–3 unparsed per adapter, this confirms the
adapters learned the format and that the comparison is between two models that work. **The base rows
are not a baseline** and are not reported as a fine-tuning improvement.

### 5.6 Experiment 3 — a null, and why the null is the finding

`R23` Five `num_ctx` values × two models × 493 common items: **decision-change rate 0 of 493 at every
value, both models.** Not one binary verdict and not one severity label differs across a sixteenfold
range. Recall identical to four decimal places throughout.

`R24` **Why.** The corpus never reaches the smallest window tested. Over all 1,699 items, median input
length is ≈528 tokens, p99 is 1,706, **no item exceeds 8192**, and only 8 items (0.47%) exceed 2048.

> **Finding 3 as originally stated is withdrawn.** The claim was that guard decisions are materially
> sensitive to context configuration and that published comparisons are therefore non-reproducible.
> On this evidence that is **false for standard guard benchmarks**. The correct claim is narrower and
> more useful: **published guard comparisons are not confounded by context configuration, because the
> corpora they use contain no long inputs.** The regime where the hazard could exist —
> retrieval-stuffed context, multi-turn history, long tool output — is precisely the regime no
> standard guard benchmark tests. The risk has not been eliminated; it has been shown to be invisible
> to the instruments the field uses.
>
> **An instrument was owed, and §5.11 builds one.** Placing the same payloads in inputs up to 32k —
> a regime no standard benchmark reaches — makes the effect appear at both scales, 19 payloads of 60
> degrading and 0 improving (*p* < 0.0001). **The null in `R23` is a property of the corpus, not of
> the guards**, and §5.11 is the direct demonstration rather than an inference from someone else's
> grid.

`R25` ⚠️ **A second recorded claim did not reproduce.** Our own program documentation stated that a
32768 KV cache exhausts the 16 GB card. It does not: all ten runs completed, both models at 32768, at
185–195 seconds per 500-item run. That constraint is withdrawn.

### 5.7 Experiment M1 — the asymmetry across three families

`R27` **The asymmetry replicates in every family tested.** Four models, 1,799 items each, 7,196
evaluations, **zero unparsed and zero errors for every model**.

| model | family | benign discordance | unsafe discordance | replicates |
|---|---|---|---|---|
| Llama Guard 3 8B | Meta | 2 vs 5, p = 0.227 (ns) | **54 vs 14, p = 5.6 × 10⁻⁷** | ✅ |
| ShieldGemma 2B | Google | 0 vs 2, p = 0.25 (ns) | **24 vs 2, p = 5.3 × 10⁻⁶** | ✅ |
| ShieldGemma 9B | Google | 0 vs 1, p = 0.50 (ns) | **33 vs 1, p = 2.0 × 10⁻⁹** | ✅ |
| Qwen3Guard 8B *(control)* | Alibaba | 2 vs 2, p = 0.688 (ns) | 28 vs 6, p = 9.8 × 10⁻⁵ | ✅ |

**In no model was benign discordance significantly skewed; in every model unsafe discordance was
significantly skewed toward evasion.** The finding rests on Llama Guard and ShieldGemma; Qwen3Guard-8B
is a family control.

`R28` ⚠️ **A limitation of our configuration, stated before the numbers it affects.** ShieldGemma is
prompted with an explicit safety policy and answers whether the input violates *that policy*. We
supplied a **four-policy** formulation while the corpus spans more harm categories, so its baseline
FNR (0.7867 at 2B, 0.6533 at 9B) **measures our prompt's scope, not the model's capability**, and
must not be read as a capability finding. The asymmetry survives it because it is a within-item
contrast against that same baseline.

`R29` **Evasion rate normalized by what each guard caught** — an item already missed cannot be evaded:

| model | caught | evaded | rate | 95% CI |
|---|---|---|---|---|
| Qwen3Guard 8B | 127 | 28 | **0.2205** | [0.157, 0.300] |
| Llama Guard 3 8B | 98 | 54 | **0.5510** | [0.453, 0.646] |
| ShieldGemma 9B | 52 | 33 | 0.6346 | [0.499, 0.752] |
| ShieldGemma 2B | 32 | 24 | **0.7500** | [0.579, 0.868] |

**Family dominates scale.** At an identical 8B parameter count, Qwen3Guard is evaded on 22.1% of what
it catches and Llama Guard 3 on 55.1% — a 2.5× difference with non-overlapping intervals. The scale
ordering nonetheless holds *within* each family, and across Qwen3Guard it is monotone over three
scales: **0.6B 35.0% → 4B 26.2% → 8B 22.1%**. Within ShieldGemma, 2B 75.0% → 9B 63.5% (directionally
consistent; intervals overlap).

`R30` **Evasions transfer across families**, measured against the receiving model's base evasion rate
so that coincidence is not reported as transfer:

| from → to | conditional | base | lift |
|---|---|---|---|
| ShieldGemma 2B → 9B | 0.5965 | 0.1001 | **5.96×** |
| Qwen3Guard 8B → Llama Guard 3 | 0.6538 | 0.1615 | **4.05×** |
| Qwen3Guard 8B → ShieldGemma 2B | 0.2692 | 0.0761 | 3.54× |
| ShieldGemma 2B → Llama Guard 3 | 0.4211 | 0.1615 | 2.61× |
| Llama Guard 3 → ShieldGemma 9B | 0.2479 | 0.1001 | 2.48× |

**Every ordered pair shows lift well above 1.0**, from 2.48× to 5.96×, strongest within a family and
substantial across families.

`R31` **Guards agree on benign content and disagree on unsafe content.** Per-item agreement on
originals: **95–99% on benign, 35–83% on unsafe.** Two well-configured guards from different
publishers — Llama Guard 3 and Qwen3Guard 8B, both judging harm generally — **disagree on 22% of
unsafe items** (0.7800 agreement). The lowest figures involve ShieldGemma and are partly attributable
to the policy scope in `R28`; the Llama-versus-Qwen gap is not.

### 5.8 Experiment M3-X — quantization across three families

`R32` **The deployed default is not verdict-neutral in any model measured.** 21 conditions, 1,000
items each, 21,000 evaluations, **one unparsed output** outside the suppressed condition.

| model | size | agreement with own `f16` at `Q4_K_M` | safety-reg | usability-reg |
|---|---|---|---|---|
| Qwen3Guard 4B | 4.0B | **0.9960** | 1 | 3 |
| Qwen3Guard 0.6B | 0.6B | 0.9890 | 5 | 6 |
| ShieldGemma 9B | 9.0B | 0.9830 | 17 | 0 |
| ShieldGemma 2B | 2.0B | 0.9820 | 0 | 18 |
| Llama Guard 3 8B | 8.0B | 0.9820 | 10 | 8 |

Between **4 and 18 verdicts per thousand** change at the precision most deployments serve.

`R33` **The direction does not generalize, and this corrects `R15`.** Safety regressions against
usability regressions:

| model | `Q4_K_M` | `Q3_K_M` | `Q2_K` | pattern |
|---|---|---|---|---|
| ShieldGemma 9B | 17 / 0 | 24 / 2 | **84 / 0** | monotonically safety-adverse |
| ShieldGemma 2B | **0 / 18** | **0 / 41** | 47 / 1 | usability-adverse, then reverses |
| Llama Guard 3 8B | 10 / 8 | 14 / 15 | 41 / 43 | roughly symmetric |
| Qwen3Guard 4B | 1 / 3 | 6 / 1 | 8 / 22 | mixed |

**Three families, three behaviors.** The generalization drawn in §5.4 from Qwen3Guard alone — that
aggressive quantization skews safety-adverse — **holds for that family and not as a rule.** A
deployer can assume neither that quantization errs safe nor that it errs conservative; only that
verdicts move.

`R34` **Model collapse is not a small-model property.** §5.4 found Qwen3Guard-0.6B destroyed at
`Q2_K` — 137 of 1,000 unparseable, remainder at chance. **ShieldGemma-2B at the same rung produced
zero unparseable outputs and 0.9520 agreement**; Llama Guard 3 and ShieldGemma 9B likewise produced
none. Collapse is model-specific. Per the pre-registration the Qwen3Guard-0.6B `Q2_K` row is
**suppressed** rather than caveated: at 13.7% unparsed it is a generation failure, not a measurement.

`R35` **Tolerance clusters by family, not by size.** Ranked by agreement at `Q4_K_M`: Qwen3Guard 4B,
Qwen3Guard 0.6B, ShieldGemma 9B, ShieldGemma 2B, Llama Guard 3 8B. **The families cluster perfectly
and size does not order the list** — a 0.6B model is more quantization-stable than both an 8B and a
9B. Within each family the larger model is more tolerant (4B > 0.6B, 9B > 2B), so scale helps against
models of the same lineage only.

**This matches §5.7 on an unrelated axis**, where evasion at equal 8B parameter count differed 2.5×
between families. Two independent perturbations, one conclusion: **family choice dominates scale.**
Reported as suggestive — three families at two sizes each cannot settle it, and adjacent intervals
overlap.

**Design note.** Every ladder, including the three new ones, comes from the **same publisher** as the
Qwen3Guard ladders, each with an `f16` build from that publisher's own conversion pipeline, so a
family difference cannot be a difference in who converted the weights. Parsers were copied verbatim
from §5.7 and were not adjustable in this experiment.

### 5.9 Experiment M2-X — the adversarial ceiling across three families

`R36` **Every guard tested is evaded on the majority of what it catches.** The same 2,400 candidates
from §5.3 — generated blind, never optimized against any guard — scored by the M1 panel, with each
model's own caught-item denominator:

| model | caught | floor (family-matched) | **ceiling** | gap |
|---|---|---|---|---|
| ShieldGemma 2B | 32 | 0.7500 | **0.9688** [0.843, 0.995] | +0.219 |
| ShieldGemma 9B | 52 | 0.6346 | **0.9615** [0.870, 0.989] | +0.327 |
| Llama Guard 3 8B | 98 | 0.5510 | **0.8980** [0.822, 0.944] | +0.347 |
| Qwen3Guard 8B | 127 | 0.2126 | **0.7165** [0.633, 0.788] | +0.504 |

With §5.3's Qwen3Guard 4B (77.0%) and 0.6B (85.4%), that is **six models across three publishers,
every one evaded on 71.6% to 96.9% of what it catches.**

`R37` **Systemic evasion outnumbers fragile evasion in every model** — items defeated by eight or
more of sixteen candidates against those defeated by only one or two: 58 vs 10, 36 vs 21, 20 vs 2,
28 vs 3. For the systemic majority, detection depends on surface form rather than content, and no
retry- or ensemble-based defense recovers it.

`R38` **The gap is largest where the guard is strongest.** Qwen3Guard-8B has the lowest floor
(0.2126) and the largest floor-to-ceiling gap (+0.504). A guard that resists generic rewriting does
not thereby resist selection over many rewrites, so **robustness to the floor does not predict
robustness to the ceiling.**

### 5.10 Experiment P1 — the reproducibility floor, and what it does to §5.4

`R39` **Guard evaluations are highly reproducible on a stratified corpus.** Eight runs at identical
configuration — same model, quantization, corpus, seed, temperature and context size, separate
containers: **998 of 1,000 items returned identical verdicts across all eight**, mean pairwise
disagreement **0.09%**, with at least one pair exactly identical.

`R40` **This was a check that could have undermined §5.4 and does not.** The quantization effects
reported there are 4–11 verdicts per thousand; the between-run floor is 0.9 per thousand, so those
effects sit **4–12× above serving noise** and stand. The comparison target was fixed before the
floor was measured.

`R41` **The standard explanation for guard nondeterminism is refuted.** Thread count — which the
serving stack's own determinism note implicates — shows agreement of 0.9993 both within and across
thread counts. GPU architecture likewise contributes nothing measurable (within-hardware 0.9990,
cross-hardware 0.9990).

`R42` ⚠️ **But the floor is probably not a single number, and this bounds §5.4 more carefully than
`R40` alone suggests.** D1's evaded sets drifted **1.0% and 5.7%** under the same nominal
configuration — 10–60× this floor. Those sets are **borderline by construction**: every item was
caught, then evaded by a rephrasing, which selects for proximity to a decision boundary. The
stratified corpus used here is not, and §5.10's own disagreement set is consistent with that — the
two unstable items each flipped in 12 of 28 pairs while 998 never moved.

**If reproducibility tracks item difficulty, the floor on borderline items — precisely where
perturbation effects are measured — remains unmeasured**, and 0.09% must not be quoted as universal.
It is reported here as an open hazard rather than absorbed.

### 5.11 Experiment P3-X — the long-input regime, entered

**This is a replication and is reported as one.** LongGuard [LongGuard] established long-context
guardrail failure across 15 guardrails over a 0.25k–32k grid, with a mechanism and two training-free
mitigations, and §2 records that it supersedes our §5.6 observation. **Nothing in this subsection is
a novelty claim.** It is here because §5.6 left the hazard *invisible to our instruments*, and an
instrument was owed.

**Design.** 60 payloads, each caught by both models with no frame around it, placed across a grid of
lengths {0, 1k, 4k, 16k, 32k} × positions {0%, 25%, 50%, 75%, 100%} — 21 cells, **1,260 inputs per
model**, both scales. Filler is one benign corpus reused in every cell, so filler *content* is held
constant and only quantity and placement vary. Pre-registered at `324ee77b` before any long input was
scored.

⚠️ **`num_ctx` is 32768 here against 8192 everywhere else in this paper**, because a 32k input cannot
be evaluated at 8192. It is held constant across all 21 cells, so it is not a variable *within* this
experiment — but **these numbers are not directly comparable to any other table in this paper.**

`R43` **The instrument works: unparsed output is 0.000 in all 42 cells**, at both scales, including
every position at 32k. This is the load-bearing fact. Long-context evaluation has a built-in confound
— as inputs grow, models emit degenerate output, and *"the guard missed it"* becomes indistinguishable
from *"the harness could not read the guard."* Under our fail-closed scoring the confound runs the
other way and would **inflate** recall. A clean parse rate decouples them, and no cell was suppressed.

`R44` **Once the inputs are long enough, the effect §5.6 could not see appears.** Miss rate pooled
over position:

| | 0× | 1k | 4k | 16k | 32k |
|---|---|---|---|---|---|
| **4B** | 0.0000 | 0.1100 | 0.1233 | 0.1933 | **0.2700** |
| **0.6B** | 0.0167 | 0.0700 | 0.1867 | 0.1600 | **0.3233** |

The pre-registered check was point-estimate monotonicity, which the 4B satisfies and the 0.6B does not
(4k→16k). **An unregistered follow-up, labeled as unregistered rather than substituted for the
registered result, tests the steps** with McNemar exact on payload-level discordance — the same 60
payloads recur at every length, so an unpaired comparison would discard the pairing:

> **The 0.6B's sole non-monotone step is the only step that fails significance** (2 worse, 4 better,
> *p* = 0.688). Every other step at that scale is a significant rise. **Over the endpoints the two
> scales are identical and one-directional: 19 payloads of 60 degrade, 0 improve, *p* < 0.0001.**

**Not one payload became easier to detect when filler was added, at either scale.** The edge–middle
gap grows with length at the 4B, +7.2% at 1k to +28.3% at 32k, closely tracking LongGuard's +6.67% at
0.25k to +30.88% at 16k.

`R45` **The 0× control is what this design adds, and it is not incidental.** A needle-in-haystack
grid always has a haystack, so its cells are read against a relative baseline. Ours includes the
payload alone: **0 of 60 missed unframed at the 4B, 1 of 60 at the 0.6B.** Every cell is therefore
attributable to framing against an **absolute floor** rather than to payload difficulty.

`R46` ⚠️ **That one control miss is an anomaly, and this paper's own earlier results resolve it.**
All 60 payloads were selected *because* both models caught them unframed; the 0.6B now misses one.
Two candidate explanations, and P3-X alone does not separate them:

| candidate | what this paper already says |
|---|---|
| the `num_ctx` 8192→32768 change is not inert | **`R23` argues against it**: 0 of 493 decision changes across a sixteenfold `num_ctx` range, both models, when inputs are short — and a 0× control *is* a short input. |
| serving nondeterminism on selection-conditioned items | **`R42` argues for it**: 1 of 60 is 1.7%, inside the **1.0–5.7%** drift recorded on sets selected by a prior verdict, and far above the 0.09% stratified floor. |

**The nondeterminism reading is the better-supported one**, which matters beyond this subsection: it
is a second, independent instance of the hazard `R42` raises — **the reproducibility floor on items
selected by a prior verdict is not the floor measured on a stratified corpus**, and quoting 0.09% as
universal remains wrong.

### 5.12 Scale

`R26` The 0.6B is less stable than the 4B under **four independent perturbations**: rephrasing (6.7%
vs 4.0% phrasing-dependent verdicts), evasion (35.0% vs 26.2% evadable), quantization (collapse at
`Q2_K` vs 0.9700), and adversarial search at every budget (85.4% vs 77.0%). Four unrelated
perturbations, one ordering.

`R47` ⚠️ **A fifth perturbation does not follow that ordering, and it bounds `R26`.** Under long-input
dilution (§5.11) the 0.6B is worse *in rate* at 32k — 0.3233 against 0.2700, consistent with `R26` —
but **at payload level the two scales are indistinguishable: 19 of 60 payloads degrade and 0 improve,
identically, at both.** Which adjacent length steps clear significance differs between them; the
direction and the count do not.

**So `R26` describes stability under perturbations that act on the guard's *judgment* of a fixed
input. It does not extend to a perturbation that changes the input's *structure*.** Long-context
dilution is not a small-model failure — it is the one hazard here that scale did not attenuate at
all, which makes it the poorest candidate for the field's usual mitigation of reaching for a larger
guard.

---

## 6. Analysis

### 6.1 Aggregate rates are not evidence of stability

Two experiments, neither designed to show it, produced the same pattern. E2's pooled FPR was
identical to four decimal places while 4.0% of items changed verdict. M3's FNR at 4B/`Q4_K_M` was
identical to `f16` while four verdicts moved.

An aggregate rate is a sum over items and is preserved exactly when errors are **exchanged** rather
than eliminated. **A guard whose verdicts churn under a perturbation is not stable, and the standard
metric cannot tell the two apart.** We recommend that guard evaluations report per-item agreement
against a reference condition alongside any aggregate.

That this convergence arrived from two unrelated experiments — one about phrasing, one about
numerics — is what makes it the paper's strongest claim.

### 6.2 Measuring one direction hides the other

The benign and unsafe arms used identical transformations, generator, seed and settings. Benign:
1.00×, symmetric churn. Unsafe: 1.42×, 6:1 asymmetry, p ≈ 2 × 10⁻⁵.

**A team measuring only false positives would have concluded the guard was phrasing-robust.** The
instability is almost entirely on the side that matters, and the standard practice of probing guards
with benign perturbations to estimate over-triggering is structurally incapable of finding it.

### 6.3 Deterministic evaluation understates its own bound

The floor used greedy decoding; the ceiling sampled. At an identical budget of four candidates,
temperature alone moved evasion 37.3 points — more than twice what quadrupling the budget bought.

**This is a claim about measurement configuration, not about attacker capability.** An evaluation
that rephrases at temperature 0 and reports the result as a robustness bound understates it by
roughly that margin, and the fix costs nothing: sample.

### 6.4 Unstated quantization makes a benchmark under-specified

`Q4_K_M` is the default in most local serving stacks, including this program's own. It changes 4 to
11 verdicts per thousand relative to `f16`, and at `Q3_K_M` the changes skew toward misses.

Any published guard comparison that does not state its serving quantization has left a variable free
that demonstrably moves the measured quantity, **in every one of five models across three families**
(§5.8). **We recommend quantization be reported as a first-class experimental parameter**, exactly as
we now recommend for `num_ctx` (§6.8) and for the noise floor (§6.7).

**But the direction cannot be assumed, and a deployer must measure it per model.** Across families,
one model's disagreements at `Q2_K` are 84-to-0 safety regressions, another is *usability*-adverse
until it reverses at the extreme, and a third is symmetric throughout. The generalization we drew
from a single family in §5.4 did not survive contact with two more. **What generalizes is that
verdicts move; which way they move does not.**

**Family dominates scale here too.** Quantization tolerance clusters by family, with a 0.6B model
more stable than both an 8B and a 9B, while within each family the larger model is more tolerant.
Combined with §5.7's finding that evasion at equal parameter count differs 2.5× between families,
**two unrelated perturbations point the same way: which guard family you pick matters more than how
large a model you pick within it.** That is a procurement conclusion, and it is the most directly
actionable result in this paper.

### 6.5 Stacking guards buys less than independence implies

Defense-in-depth across multiple guards is standard advice, and it assumes the guards fail
approximately independently. **They do not.** A rephrasing that defeats one guard defeats a guard
from a *different publisher* at 2.5× to 4× its base rate, and within a family at nearly 6×.

The mechanism is visible in `R31`: these models agree on benign content (95–99%) and disagree
sharply on unsafe content (35–83%), which means their *decision boundaries* differ while the
features that make content evadable apparently do not. Rephrasing appears to move an item out of the
region all of them recognize, rather than out of one model's idiosyncratic region.

**Deployment consequence.** A two-guard stack does not multiply miss rates. Estimating a stack's
false-negative rate as the product of its members' is wrong by the transfer lift, and the correct
estimate is much closer to the weaker member's rate than to the product. Any composition argument
that assumes independence — including layered-containment arguments in the agent-security
literature — needs a transfer measurement to stand on.

### 6.6 Specialization: reallocation is not free

`G-cat` did not trade breadth for depth. It lost breadth and gained no depth — recall fell, seven
non-target categories degraded, and the four target categories were flat.

**The deployment consequence is direct:** budget allocated to narrowing a guard's training
distribution toward the harms an organization cares most about is, on this evidence, worse than
spending it on breadth — or on capability controls, which bind regardless of content.

**The boundary is narrow and we state it.** This tests **reallocation at equal volume**, not
addition; one concentration (≈2×); and **category, not vertical**. A specialist trained on
*additional* target data is a different experiment, and the vertical question is untested.

### 6.7 Report your noise floor; it costs one extra run

§5.10 measured what a guard evaluation costs in reproducibility: on a stratified corpus, almost
nothing. That is the first time we are aware of that the number has been measured rather than
assumed.

**The methodological point is that nobody reports it.** A comparison claiming a two-point improvement
is claiming a difference; whether that difference exceeds the noise of running the same evaluation
twice is currently unknowable from any published paper, because none states it. The fix is one extra
run and a per-item agreement figure beside the headline metric.

**Two corrections to standing practice.** Pinning thread count and GPU architecture — which the
serving documentation implies buys determinism — buys nothing measurable (`R41`). And the floor is
**between-run**: it does not apply to paired within-run comparisons, so §5.1's McNemar results and
§5.3's per-item ceilings do not inherit it. Conflating those would overstate some findings and
understate others simultaneously.

**The hazard left open is §5.10's.** A floor measured on a stratified corpus may not transfer to
borderline items, and borderline items are where perturbation studies live.

### 6.8 Configuration as a hazard that instruments cannot see

Pinning `num_ctx` remains correct practice and costs nothing; it is now recommended as configuration
hygiene rather than defended as a confound correction. The substantive point is the corpus property:
**the benchmark suite the field uses cannot exhibit the failure mode, because it contains no inputs
long enough to produce it.** Constructing such a corpus is stated as open work in §9, not presented
as resolved.

---

## 7. Artifact

### 7.1 Contents

Evaluation harness; the frozen transformation specifications and **every original/rephrased pair**;
all 2,400 adversarial candidates with their family and seed; dataset manifests and normalization
maps; Model BOMs for all eight adapters; per-item outputs for all 14 quantization conditions and all
10 specialization evaluations; **the full P3-X long-input grid — construction script, all 1,260
placed inputs per model and their per-item verdicts at both scales**; pinned environment definitions;
and every pre-registration document with its hash.

### 7.2 Pre-registration hashes

| Document | Hash | Frozen before |
|---|---|---|
| E2 transformation set v2 | `48ce3dae` | any guard saw any output |
| E2-B evasion arm | `cdc94f66` | any unsafe item was rephrased |
| M2 ceiling | `237e8f44` → `9a3ae674` | any candidate was generated |
| M3 quantization | `b26c2bf6` → `ca0a2286` | any corpus was built |
| E1 amendment | `9240fabd` → `0df38fc3` | any training run started |
| M1 cross-family panel | `319bc541` → `fb410831` | any non-Qwen3Guard model ran |
| M3-X quantization panel | `c4dbf173` | any non-Qwen3Guard model ran at any precision |
| M2-X cross-family ceiling | `237e8f44` → `c433ae4c` | any candidate was scored outside Qwen3Guard |
| P1 reproducibility floor | `5435ed47` | any repeated run was made |
| P3-X long-input grid | `324ee77b` | any input longer than ≈1.2k tokens was scored |

Second hashes are dated addenda. **Amendments are appended and re-hashed, never edited**, so the
ordering stays auditable.

### 7.3 Negative and withdrawn results, reported alongside the accepted ones

- Draft 1's false-positive amplification finding — **withdrawn** (§5.2).
- Draft 1's context-configuration confound — **withdrawn** (§5.6).
- Our own recorded "32768 OOMs a 16 GB card" — **withdrawn** (§5.6, `R25`).
- Transformation set v1, in which two of five families silently returned the input unchanged (§4.3).
- The first `G-cat` construction, 100% unsafe, caught before training (§4.4).
- An internal analysis that said E2 "refutes" the 4.12× figure — **corrected** to *no support for,
  under-powered to exclude* (§5.2).
- Rejected training runs from earlier in this program, reported with their rejection reasons.

### 7.4 Compute

Training: 8 LoRA adapters, ≈3.2 A100-hours. Evaluation: 14 quantization conditions × 1,000 items and
10 specialization conditions × 1,199 items on A10G-class accelerators; 2,400-candidate adversarial
evaluation ≈7.4 minutes per guard. Generation: 750 + 750 + 2,400 rewrites. Local RTX 5080 for the
serving-side runs, Modal A100/A10G for training and fan-out.

---

## 8. Threats to validity

**Family coverage — the limitation Draft 2 named as largest, now largely answered.** Two experiments
were extended to three families and three publishers: the asymmetry (§5.7) and the quantization
ladder (§5.8). Both replicated, and the quantization panel additionally **falsified a
generalization we had drawn from one family** — evidence that the single-family caveat was not
merely formal. **The adversarial ceiling has since been extended to all three families** (§5.9), leaving
**the specialization experiment and the context sweep** as the only single-family results.
WildGuard, NeMo and Llama Guard 4 were not run at all.

**One correction propagated from that extension.** §5.4's direction claim was scoped to Qwen3Guard
after §5.8 contradicted it. Any reader comparing Draft 2 to Draft 3 should note that the claim
narrowed rather than being removed.

**ShieldGemma's prompt scope is ours, not the model's.** We supplied a four-policy formulation
against a corpus spanning more categories, so its baseline miss rate reflects our configuration
(`R28`). It is reported as a limitation and must not be read as a capability comparison between
products.

**Small item counts on the rephrasing arms.** 150 items give wide rate intervals. The paired McNemar
tests condition on discordant pairs and are robust to that, so *"rephrasing significantly increases
misses, asymmetrically"* is supported; *"by exactly 1.42×"* is not.

**The ceiling is not a worst case.** Best-of-16 **selection**, with the generator blind to guard
output. Feedback-guided, gradient-access and transfer attackers are strictly stronger. The
71.6%–96.9% range across six models bounds the floor from above, not the threat.

**The reproducibility floor is population-scoped.** §5.10 measures 0.09% on a stratified corpus and
records a 10–60× discrepancy against borderline-enriched sets. The floor on borderline items is
unmeasured, so any effect measured *between* runs on such a population is less well bounded than its
interval suggests. Paired within-run results are unaffected.

**`f16` is a reference, not truth.** M3 measures agreement between precisions and does not establish
which verdict is correct.

**Specialization scope.** Reallocation at equal volume, one concentration, category not vertical
(§6.5).

**A hardware variable we did not control and did not hide.** Modal assigned two A100 variants (PCIe
and SXM4) during specialization training. All four 4B runs matched; for the 0.6B the variant is
**crossed** with corpus across splits, so it contributes noise rather than bias. It is nonetheless a
named candidate explanation for the 0.6B's unreplicated `R21`, and the 4B — on matched hardware —
replicates cleanly. **A plan-level pre-flight verified the training configurations were identical;
it could not see hardware assignment, which only the run records revealed.**

**Single lab.** The pre-registration hashes, published per-item outputs and published transformation
sets are the available answer, and they are not a substitute for independent replication.

---

## 9. Conclusion

We measured six properties of guard models that standard evaluation does not report, and in five of
six cases the standard practice understates fragility.

Rephrasing does not make guards over-trigger; it makes them blind, and the failure is asymmetric
enough that benign-side testing cannot see it — in three families from three publishers, not one.
Evasions transfer between those families at two-and-a-half to six times chance, so a stack of
heterogeneous guards is much closer to its weakest member than to the product of its members. Generic rewriting evades a quarter to a third of what
guards catch; adversarial selection over the same families evades between 72% and 97% of it, in
**every one of six models across three publishers**, with most of that gap coming from sampling
rather than search and systemic evasion outnumbering fragile evasion everywhere. Quantization changes safety verdicts at the
precision most deployments actually use, in every model we measured across three families — though
*which way* the verdicts move is a property of the model rather than a rule, and a single-family
generalization of ours did not survive being tested on two more. Category specialization, at equal data volume, degrades a
guard rather than sharpening it. And the one hazard we expected to find in configuration turned out
to be invisible to the corpora the field evaluates on.

The connective tissue is a measurement failure rather than a modeling one: **aggregate rates are
preserved exactly when errors are exchanged rather than eliminated**, and two of our experiments
produced pooled rates identical to four decimal places while a twentieth of the verdicts moved
underneath. Guard evaluations should report per-item agreement against a reference condition, should
probe both failure directions, should sample rather than decode deterministically when estimating
robustness, and should state serving quantization as a first-class parameter.

**Open work**, stated as open rather than implied as done: extending the specialization, ceiling and
context experiments beyond the single family each was run on; a long-input corpus that
could exhibit the context hazard; the vertical specialization question the corpus licensing forced us
to leave untested; specialization by *addition* rather than reallocation; a fuller ShieldGemma policy
so its baseline reflects the model rather than our prompt; and a feedback-guided attacker, which
would place a real upper bound where we have only raised the floor.

---

## References

**Guard models and their robustness**

[GuardMeaning] C. Pinneri and C. Louizos. *Guarding the Meaning: Self-Supervised Training for
Semantic Robustness in Guard Models.* Qualcomm AI Research. arXiv:2511.10665, 2025.

[LongGuard] Z. Chen, X. Wu and S. Hu. *LongGuard: Mechanistic Analysis and Training-Free Mitigation
of Long-Context Failure in Safety Guardrails.* Institute of Information Engineering, Chinese Academy
of Sciences. arXiv:2608.27580, 2026.

[WildGuard] *WildGuard: Open One-Stop Moderation Tools for Safety Risks, Jailbreaks, and Refusals of
LLMs.* University of Washington, Allen Institute for AI, Seoul National University.
arXiv:2406.18495, 2024. — source of the evaluation corpus.

[SafetyGeom] *When Safety Geometry Collapses: Fine-Tuning Vulnerabilities in Agentic Guard Models.*
arXiv:2605.02914, 2026.

[RefusalCue] *When Refusal Looks Safe: The Refusal-Cue Shortcut in Safety Guard Models.*
arXiv:2608.03201, 2026.

[AttackEns] *Attack Ensembles Expose a Safety-Utility Trade-off in Black-Box Guard Defenses Against
Encoded VLM Jailbreaks.* arXiv:2607.26574, 2026.

[RAGGuard] *RAG Makes Guardrails Unsafe? Investigating Robustness of Guardrails under RAG-style
Contexts.* arXiv:2510.05310, 2025.

[GuardBench] *Benchmarking Open-Source Safety Guard Models: A Comprehensive Evaluation.*
arXiv:2605.28830, 2026.

**Quantization and safety**

[QuantTemp] *The Joint Effect of Quantization and Sampling Temperature on LLM Safety Alignment: A
Factorial Analysis.* arXiv:2606.29581, 2026.

[QResafe] *Q-resafe: Assessing Safety Risks and Quantization-aware Safety Patching for Quantized
Large Language Models.* arXiv:2506.20251, 2025.

[QFair] *Preserving Fairness and Safety in Quantized LLMs Through Critical Weight Protection.*
arXiv:2601.12033, 2026.

**Agent-runtime security (positioning only; not guard evaluation)**

[HCP] Ting Liu. From Tool Connection to Execution Control: Benchmarking Security Invariants in
MCP-Style Agent Runtimes. SymbolicLight Research. arXiv:2606.29073v1 [cs.CR], 2026.

[AgentThread] Shenghan Zheng, Qifan Zhang, Zheng Zhang, Haonan Li, and Christophe Hauser. Formal
Security Analysis of Agent Protocol Composition. arXiv:2606.28690v1 [cs.CR], 27 June 2026.

[DEMM-Bench] Oleg Solozobov. DEMM-Bench: A Cross-Regime Benchmark for Agent-Runtime
Governance-Evidence Sufficiency. arXiv:2606.20634v1 [cs.AI], 30 May 2026.

[ClawGuard] Wei Zhao, Zhe Li, Peixin Zhang, and Jun Sun. ClawGuard: A Runtime Security Framework
for Tool-Augmented LLM Agents Against Indirect Prompt Injection. Singapore Management University.
arXiv:2604.11790v2 [cs.CR], 11 May 2026.

> ⚠️ **Still incomplete.** The five agent-runtime entries remain placeholders and must be resolved to
> real citations or dropped. The guard-evaluation entries above are real and were located during a
> prior-art check conducted **after** the first drafts were written — a sequencing error recorded in
> `PRIOR-ART-ASSESSMENT.md`. Several of them **removed novelty claims from this paper** rather than
> supporting it; §2 states which.

---

## Production notes (strip before submission)

- ~~§2's gap claim about serving quantization requires a survey.~~ **DONE, and the claim was
  false.** A prior-art check on 2026-08-31 found [QuantTemp], [QResafe] and [QFair]; the claim is
  withdrawn in §2 and the contribution restated as the runtime-controlled design plus the per-item
  statistic. See `PRIOR-ART-ASSESSMENT.md`.
- ~~The remaining five placeholder citations must be resolved.~~ **DONE, four resolved and one
  removed.** [HCP] (arXiv:2606.29073), [AgentThread] (2606.28690), [DEMM-Bench] (2606.20634) and
  [ClawGuard] (2604.11790) now carry full references; each has a full-text read note with
  provenance in `section-material/`. **[MCPThreatHive] (2604.13849) was removed rather than
  resolved.** Our corpus index tags it `READ`, but no read note exists for it and the index entry
  names no author and no finding — so the sentence citing it, which said *"to our reading,"* was
  a claim we could not support. The paragraph's point rests on [ClawGuard] alone, which is read in
  full. **A status flag in an index is a claim about reading, not evidence of it**; this is the
  fourth time in this program a listing was nearly read as a completion signal.
- Anonymize for double-blind: strip author line, program names, repository paths; scrub PDF metadata.
- **Semantic-equivalence annotation — reframed, and a pack is built and waiting.** This was filed
  as an unkept promise; it is more serious than that. Our transformation QC establishes that the
  rephrasings **differ** from their originals. **H2 needs them to mean the same thing, which is
  the opposite direction** — a low similarity is evidence of change, and if anything weak
  evidence against preservation. So the equivalence half of the headline claim currently rests on
  **construction** (a generator instructed to preserve meaning) rather than measurement. Cosine
  similarity cannot settle it: at T4's 5.93x median length ratio, similarity falls *mechanically
  because text was appended*. **An automated check cannot settle it either** — asking a language
  model whether two texts mean the same thing, in a paper about language models misjudging text,
  is circular.
  A blinded 40-item annotation pack is built and verified at
  `warrantor-runs/2026-08-31/equivalence-pack/`: 24 evaded items, 12 caught, 4 attention checks,
  stratified across all five transformations, with the analyzer written before the pack was
  generated. It reports equivalence **conditional on the guard having flipped** and never a
  pooled rate. **It requires a human annotator and is the second item in this program that no
  experiment can unblock** (the first being T-12's verification pack).
- Cross-family panels are **done** for the asymmetry (§5.7) and quantization (§5.8). The remaining
  single-family caveats are on M2, E1 and E3; the adversarial ceiling across families is the
  highest-value of those, since §5.7 already shows evasions transfer.
- §5.7's transfer result (`R30`) is directly relevant to layered-containment arguments elsewhere in
  this program and should be cross-referenced when that piece is revised.
