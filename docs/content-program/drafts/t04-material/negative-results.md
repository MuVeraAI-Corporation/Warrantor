# T-04 — Negative-results venues and genre convention

**Search angle:** negative-results and reproducibility venues in ML safety and security with live
2026–2027 deadlines; plus prior negative-results papers on fine-tuning safety models, to establish
both the venue and the framing convention T-04 should adopt.

**Searched:** 2026-08-30. Tools: WebSearch, WebFetch (direct CFP fetches), alphaXiv paper discovery
(two multi-facet queries) and full-text retrieval.

---

## 1. Verdict on the novelty claim

The claim under test:

> "We are not aware of a treatment of what happens to an unsupervised output field when a
> neighboring field is tuned under a shared adapter."

**Verdict: SURVIVES, but must be narrowed on two fronts and must add three citations.**

Nothing found states, tests, or measures the specific proposition — that masking a *structured
output field* from the loss fails to hold that field still, because the shared adapter keeps moving
it. No paper in this sweep runs a masked-field ablation on a multi-field generative classifier, and
no paper measures a per-field label distribution before and after a masked run. On my angle, that
part of the claim is intact.

Two things it can no longer claim, however:

**(a) The mechanism is not novel and must not be presented as a discovery.** That a shared
low-rank update produces cross-objective interference is established: TIES-merging and DARE both
exist specifically to resolve task-vector interference; DPI (arXiv 2601.17777) names the "seesaw
effect" across heterogeneous SFT tasks; PermDoRA (arXiv 2606.11262) tests and bounds the
parameter-space-geometry account of adapter interference; "Parameter Importance is Not Static"
(arXiv 2604.14010) builds parameter isolation for SFT precisely because task interference and
forgetting are the default. T-04's mechanistic paragraph is an *application* of a known mechanism
to an undocumented case. Phrase it that way.

**(b) Run 1's finding was explicitly predicted in print four months earlier.** This is the
load-bearing correction. *Asymmetric Collapse in Model Merging: When Refusal Overwrites Recognition*
(COLM 2026, arXiv 2607.27240) closes by stating that any safety-relevant capability requiring
graduated judgment — it names toxicity scoring, content classification, risk triage — may be
vulnerable to being overwritten by a coarser behavioral objective. T-04 run 1 is exactly that: a
three-class graded severity field extinguished by binary supervision. The mechanism differs
(weight-space merging under magnitude asymmetry vs. a single LoRA run under binary targets), so
T-04 is not scooped — but run 1 is now a *confirming instance of a stated prediction in a second,
more common training regime*, not an unanticipated result. Presenting run 1 as a surprise after
this paper is published would repeat the failure this program has already committed once.

The defensible novelty statement, post-search:

> Coarse supervision overwriting a graded safety field has been predicted and observed under model
> merging (Choudhary et al., COLM 2026). We confirm it under single-run LoRA. We are not aware of
> prior work that then asks the natural remedial question — whether masking the graded field from
> the loss preserves it — and measures the answer.

---

## 2. Works found

### 2.1 Directly bearing on the claim

**[arXiv 2607.27240] Asymmetric Collapse in Model Merging: When Refusal Overwrites Recognition.**
Choudhary, Fonseca, Seo, Sharma, Choudhary. COLM 2026. Two Gemma-3-1B-IT full fine-tunes — CARES
four-class graded medical harm classification, and WildJailbreak binary refusal — merged with
Linear, SLERP, TIES, DARE-TIES. Across all four methods refusal transfers (81–85% attack
resistance) while graded classification collapses (at most 12.9%, down from 77.0% in the CARES
fine-tune; TIES and DARE-TIES reach 0.6–0.8%). Task vectors are near-orthogonal (cosine 0.011);
the cause is magnitude asymmetry — the refusal task vector carries 4–5x larger per-layer L2 norms,
so magnitude-sensitive merge rules favor it. A head-necessity analysis shows 49–65% of
CARES-essential head positions survive the merge and still fail to classify: "structural retention
does not imply functional preservation."
*Covers:* the phenomenon of a coarse binary safety objective destroying a graded safety field, and
the explicit prediction that risk-triage-style graded fields are generally vulnerable.
*Does not cover:* loss masking, partial supervision, unsupervised fields, LoRA, or a single
training run — both objectives are fully supervised, in separate models, combined post hoc in
weight space.
**This is the one citation T-04 cannot omit.**

**[arXiv 2502.13458] ThinkGuard: Deliberative Slow Thinking Leads to Cautious Guardrails.**
Compares critique-augmented fine-tuning of LlamaGuard against a label-only fine-tuned LlamaGuard 3
baseline. Reports (Appendix B) that the label-only model emits category labels but fails to provide
detailed explanations, reducing interpretability; and (Table 1) that it underperforms on Toxic Chat
and OpenAI Moderation (72.3% avg F1 / 76.8% AUPRC vs. 75.5% / 79.5%).
*Covers:* the closest published observation that a guard model's second output field degrades when
only the label is supervised.
*Does not cover:* the claim. The explanation field is absent from the label-only targets entirely —
this is a training-data-format contrast, not a masked-loss ablation. Nothing is retained in the
input and excluded from the loss, no distribution over a policy-bearing field is measured before
and after, and the observation appears as an interpretability side-note in service of the positive
result rather than as a finding.

**[arXiv 2605.02914] When Safety Geometry Collapses: Fine-Tuning Vulnerabilities in Agentic Guard
Models.** LlamaGuard, WildGuard and Granite Guardian fine-tuned on 2,000 benign Alpaca examples for
three epochs lose safety alignment entirely (Granite Guardian refusal 85% to 0%); the latent
harmful–benign boundary in activation space is destroyed.
*Covers:* benign, non-adversarial fine-tuning silently voiding a guard model's safety property —
the general hazard class T-04 sits in.
*Does not cover:* the claim. Single task loss, no multi-field output, no masking, no unsupervised
field. Verified against the paper text: there is no treatment of loss masking or field-specific
masking anywhere in it, and the degradation studied is in latent geometry, not in a held-out
output field.

### 2.2 Mechanism prior art (cite to disclaim mechanism novelty)

- **[arXiv 2601.17777] DPI: Exploiting Parameter Heterogeneity for Interference-Free Fine-Tuning** —
  names the "seesaw effect" from conflicting objectives across heterogeneous SFT tasks.
- **[arXiv 2606.11262] PermDoRA — Understanding Adapter Interference in Language Models: Limits of
  Parameter-Space Geometry** — tests, and bounds, the parameter-space explanation of adapter
  interference. Also itself a negative-results-shaped paper ("Limits of...").
- **[arXiv 2604.14010] Parameter Importance is Not Static: Evolving Parameter Isolation for
  Supervised Fine-Tuning** — parameter isolation exists as a technique *because* shared-parameter
  SFT interferes. Useful for the rhetorical move: real parameter isolation is a named, engineered
  thing; loss masking is not it.
- **TIES-merging (Yadav et al., NeurIPS 2023) and DARE (Yu et al., 2024)** — canonical task-vector
  interference references, reachable through 2607.27240's bibliography.

### 2.3 Adjacent but different (mention only if space allows; do not overclaim)

- **[arXiv 2307.12976 / TACL 2024] Evaluating the Ripple Effects of Knowledge Editing in Language
  Models** (Cohen et al.). Editing one fact perturbs semantically related, non-targeted outputs;
  the RippleEdits metric set includes Forgetfulness and Relation Specificity precisely to measure
  unintended impact on untargeted knowledge. Same *shape* of argument — a targeted intervention
  moves what it did not target — in a different regime (single-fact editing, not multi-field
  supervised fine-tuning).
- **Partially-annotated NER / the unlabeled-entity problem** (e.g. arXiv 2208.02934, arXiv
  2005.00502, arXiv 2204.09081). Long-standing finding that excluding unlabeled spans from the loss
  corrupts the classifier. Note the direction is the *reverse* of T-04's: there, masking damages the
  supervised classes; T-04 asks what happens to the masked field itself. Cite carefully or not at all.
- **[NeurIPS 2024, arXiv 2405.14394] Instruction Tuning With Loss Over Instructions.** The nearest
  study of what changes when you change which tokens carry loss — but the masked region is the
  prompt, not a second output field, and the measured effect is downstream benchmark performance,
  not the distribution of the masked region's own predictions.
- **[arXiv 2604.24902] Safety Drift After Fine-Tuning: Evidence from High-Stakes Domains** —
  domain fine-tuning degrades safety properties that were assessed only on base models. Background,
  not overlap.

### 2.4 Genre exemplar — how a negative-results safety paper is framed

**[arXiv 2606.30449] Internal-State Probes Read the Situation, Not the Action: Three Negative
Results for Pre-Action Misalignment Monitoring.** Fomin, David, LeVi (Zenity). Published at the
Second Workshop on Agents in the Wild (AIWILD) at ICML 2026. This is the template T-04 should copy:

1. **The title carries the finding, not the topic.** A claim ("Read the Situation, Not the Action")
   plus an explicit count of negative results.
2. **A scope statement in the contributions list, not buried in Limitations.** Verbatim: "An
   explicit scope statement: we do not show that no internal pre-action signal exists, only that
   these natural probe families do not yield a robust one under the tests we ran." T-04's analogue:
   *we do not show that no masking scheme can preserve an unsupervised field, only that naive loss
   masking under a shared LoRA adapter does not, in this setting.*
3. **Several independent instances, framed as a recurring failure mode rather than one benchmark.**
   T-04 has two runs; it should say plainly that two is two, and that the mechanism, not the count,
   carries the generalization.
4. **Every non-rejection labeled as such.** "Non-rejections such as the calm-versus-random
   comparison are not equivalence tests." T-04 must apply this to any field it reports as unchanged.
5. **A Limitations section enumerating what was not varied** — model families, layers, scenario
   count — and stating which claims are therefore untested. T-04 owes the same for: one base model,
   one corpus, one adapter configuration, one rank, no seed replication.

Also useful as convention-setting, though not ML-safety: **Position: Embracing Negative Results in
Machine Learning** (arXiv 2406.03980), which argues predictive performance alone is a poor indicator
of a publication's worth and proposes concrete community measures; **Perspectives on Negative
Research Results in Pervasive Computing** (arXiv 2210.05708); and the **ACM Workshop on Negative
Results in Network Measurements (NetNeg)** at SIGCOMM 2026, which demonstrates that a top-tier
systems and security community will stand up a dedicated negative-results venue.

---

## 3. Venues — which accept negative results, and what is still live

Today is 2026-08-30. Deadlines are marked LIVE or PASSED accordingly.

| Venue | Deadline | Status | Negative results explicitly welcome? | Fit |
|---|---|---|---|---|
| **AIWILD @ NeurIPS 2026** (Third Workshop on Agents in the Wild: Safety, Security, and Beyond), Sydney, Dec 11–12 | **Sep 5, 2026 AoE** (extended from Aug 29); notification Sep 29 | **LIVE — 6 days** | Not as a named category, but the ICML 2026 edition published the flagship negative-results paper above (2606.30449) — the strongest available evidence of fit | **Best immediate target.** Non-archival, so it does not burn the work for SaTML. 9 pages regular / 4 pages short, references and supplementary excluded |
| **IEEE SaTML 2027**, early May 2027 | Abstract **Sep 22, 2026**; paper **Sep 29, 2026** | **LIVE** | No. Topic list only; research / SoK ("SoK:") / position ("Position:") types, 12 pages of body text | Full-paper home. Open science is mandatory: anonymized artifact within 3 days of submission, Zenodo deposit on acceptance — T-04's runs must be release-ready. A separate LLM-use disclosure section is required |
| **TMLR** (journal) | Rolling, no deadline | **LIVE** | Effectively yes, by construction. The criteria are (1) "Are the claims made in the submission supported by accurate, convincing and clear evidence?" and (2) would at least some of TMLR's audience be interested — and "Papers should be accepted if they meet the criteria, even if the contribution or significance of the work is modest." Significance is explicitly not a bar | Best archival fallback for a two-run negative result. TMLR rejects papers that "incorrectly claim novelty over existing published work" — which is exactly why §1(b) must be fixed before submission |
| **FLMSec @ NeurIPS 2026** (Foundations of Language Model Security), Paris, Dec 12–13 | Aug 27, 2026 | **PASSED** | **Yes — explicitly.** The CFP welcomes negative results and limitations, and runs a "Fundamental Limits" track including impossibility results | Excellent fit; watch for a 2027 edition. Non-archival, 8 pages |
| **TAE / TAI-Eval @ NeurIPS 2026** ("Can We Trust AI Evaluation?"), Sydney | Aug 29, 2026 | **PASSED (by one day)** | Not stated; treats evaluation itself as the object of study, including measurement and causal validity | Strong conceptual fit for the "a documented operator policy lever silently became a no-op" framing |
| **ICBINB @ ICLR 2026** ("Where Large Language Models need to improve") | Jan 31, 2026 | **PASSED** | **Yes — it is the entire premise.** Named tracks include Alignment ("failures in safety tuning and adversarial robustness") and "any well-supported finding that challenges prevailing assumptions or exposes key limitations of LLMs" | The genre-native venue. Watch for an **ICLR 2027 edition**; expect a CFP around Dec 2026 – Feb 2027 |
| **ICBINB-BIO @ NeurIPS 2026** (Failure Modes of AI in Biology), Sydney | Sep 2–3, 2026 | LIVE but **out of scope** | Yes | Biology only. Not a fit |
| **AISec 2026** @ ACM CCS, The Hague, Nov 15 | Jul 24, 2026 | **PASSED** | No named category; research / position and open-problem / SoK / new benchmark tracks, 10+2 pages ACM double-column, plus a required GenAI-use declaration paragraph | Natural security home. **AISec 2027 CFP expected around July 2027** |
| **USENIX Security '27** | Multiple cycles | LIVE | CFP page returns HTTP 403 to automated fetch; **unverified**. Solicits SoK papers. Do not assert a negative-results policy without a manual read | Too heavy for a two-run result unless folded into a larger paper |
| **NetNeg @ SIGCOMM 2026** (Negative Results in Network Measurements) | — | — | Yes, by definition | Out of scope; cite only as evidence that the genre is institutionalized in security-adjacent systems research |

### Recommended sequence

1. **AIWILD @ NeurIPS 2026, short or regular paper, by Sep 5.** Non-archival, so it costs nothing
   downstream and buys reviewer feedback from the exact community that accepted 2606.30449.
2. **SaTML 2027 by Sep 29** as the archival research paper — *only if* the run 2 masking result is
   the spine and run 1 is framed as confirming Choudhary et al. Prepare the anonymized artifact now;
   it is due within three days of submission.
3. **TMLR** if SaTML rejects. Its stated criteria are the most favorable in existence for a correct,
   modest, negative finding — and the least forgiving of an unnarrowed novelty claim.

---

## 4. What was searched (for auditability)

Queries run, so the absence is checkable rather than assumed.

**Venue queries:** negative results workshop machine learning 2026 call for papers; "I Can't
Believe It's Not Better" workshop NeurIPS 2026; TMLR negative results policy; USENIX Security 2027
CFP negative results; SaTML 2027 CFP; AISec 2026 CCS CFP negative results; AIWILD NeurIPS 2026 CFP;
TAI-Eval NeurIPS 2026 CFP; Foundations of Language Model Security NeurIPS 2026; ICBINB NeurIPS 2026
deadline.

**Direct CFP fetches:** sites.google.com/view/icbinb-2026; satml.org/call-for-papers; aisec.cc;
jmlr.org/tmlr/editorial-policies.html; agentwild-workshop.github.io/neurips2026; flmsec.github.io;
blog.neurips.cc NeurIPS 2026 workshop announcement; aiworkshoptracker.com NeurIPS listing. The
usenix.org CFP returned HTTP 403 and is the one unverified row in the table above.

**Claim queries:** LoRA fine-tuning catastrophic forgetting safety guard model degrades other output
field; loss masking does not prevent drift unsupervised field shared adapter; guard model structured
output safety label and category field fine-tuning degrades category prediction; fine-tuning one
output field structured JSON collapses other field; "Instruction Tuning With Loss Over
Instructions"; ripple effects knowledge editing non-targeted outputs; partially annotated sequence
labeling unlabeled tokens excluded from loss.

**alphaXiv discovery, query 1:** LoRA / loss masking / unsupervised output field / guard model /
severity / category / structured output / negative results / fine-tuning safety classifier — 13
results, all screened, three fetched in full.

**alphaXiv discovery, query 2:** loss masking / partial supervision / shared adapter / field drift /
multi-field structured prediction / auxiliary label degradation / parameter isolation / LoRA
interference — 12 results, all screened. Returned adapter-interference and parameter-isolation
*method* papers only; **no paper matching the masked-output-field question**.

**Full text read:** 2607.27240 (complete, including both appendices); 2606.30449 (abstract,
contributions, related work, limitations); 2605.02914 (targeted read for any masking or
unsupervised-field treatment — none present); 2502.13458 (targeted read of the label-only baseline
discussion and Appendix B).

**Explicit statement of absence:** on this angle, nothing was found that covers the claim. No work
located here excludes a structured output field from the fine-tuning loss while keeping it in the
output, and then measures whether that field's distribution is preserved. The absence is reported
as a result of the queries listed above, not assumed.

**Not searched — gaps another angle should close:** ACL/EMNLP anthology full text for multi-task
slot-filling and joint intent–slot models, where a "tune one slot, watch another" ablation is most
likely to exist without being labeled as such; and the older multi-task-learning literature on
auxiliary-task negative transfer, which may contain the finding in pre-LLM vocabulary.

---

## 5. Draft related-work prose for T-04 (third person, US English)

> Coarse safety supervision overwriting a finer-grained one has been observed in weight space:
> Choudhary et al. (COLM 2026) merge a graded four-level harm classifier with a binary refusal
> model and find that refusal transfers across every standard merging method while graded
> classification collapses to at or below chance, concluding that any safety capability requiring
> graduated judgment — they name toxicity scoring and risk triage — is vulnerable to being
> overwritten by a coarser objective. Run 1 below confirms that prediction in the more common
> single-run setting, where no merge occurs and the coarse objective is simply the only supervision
> the corpus supports. The mechanism is likewise not new: cross-objective interference under shared
> parameters is the premise of task-vector trimming and of parameter-isolation methods for
> supervised fine-tuning. What appears to be undocumented is the remedy this suggests and its
> failure — the closest guard-model precedent, ThinkGuard, notes only that a label-only fine-tune
> stops producing usable explanations, and the authors are not aware of prior work that excludes a
> policy-bearing output field from the loss while retaining it in the output, and then measures
> whether that field's distribution is in fact preserved.
