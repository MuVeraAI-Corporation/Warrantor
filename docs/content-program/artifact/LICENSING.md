# Artifact licensing — what can be redistributed, and one open question

**Written 2026-08-31 while assembling the Zenodo bundle for T-03. Verified against the Hugging Face
dataset cards, not against memory or the paper text.**

---

## 1. Verified positions

| Corpus | License | Gated | Verified how |
|---|---|---|---|
| **Aegis AI Content Safety 1.0** (nvidia) | **CC-BY-4.0** | **No**, no gate prompt | HF dataset card, 2026-08-31 |
| **WildGuardMix** (allenai) | **ODC-By-1.0** | **Yes** — `gated: auto`, with an `extra_gated_prompt` | HF dataset card, 2026-08-31 |

**Aegis is freely redistributable with attribution.** Everything E1 derives from it — the `G-cat`
and `G-gen` corpora, both replication splits, the test split, the rendered training pairs — ships in
this bundle with a CC-BY-4.0 attribution notice.

**WildGuardMix is not straightforwardly redistributable.** ODC-By governs the *database*, not the
underlying content, and the Hub applies a click-through gate on top of it. The gate is
auto-approved, so it is not a review barrier — but it is a term the downloader accepts, and
publishing the source text in an open bundle would let a reader bypass a condition the publisher
chose to impose.

## 2. The bundle is therefore two-tier

**Tier A — ships now.** Nothing here reproduces gated source text.

- All six pre-registration documents with their hash chains.
- All experiment code: Modal apps, corpus builders, analyzers, transformation specifications.
- **All model verdicts**, for every item in every condition — these are our measurements, not the
  corpus.
- **Source item IDs and row indices** into WildGuardMix, which make every result reproducible by a
  reader who accepts the gate themselves.
- Everything Aegis-derived (CC-BY-4.0, attributed).
- All `RESULTS.md` documents, Model BOMs, environment pins.

**Tier B — held pending a decision (§3).** WildGuardMix source text, and the rephrasings and
adversarial candidates derived from it.

**Reproducibility survives the split.** A reader accepts the WildGuardMix gate, runs the included
builder against the published row indices to reconstruct the exact item sets, then runs the
included generation scripts against the frozen transformation specs and seeds. Tier A contains
every number in the paper and every input needed to regenerate Tier B.

## 3. The open question, for a human to decide

⚠️ **May we publish the 1,499 rephrasings and 2,400 adversarial candidates derived from
WildGuardMix?**

Arguments each way, stated plainly rather than resolved:

- **For.** They are text our generator produced, not corpus rows. ODC-By explicitly permits
  derivative databases with attribution. T-03 §7.1 promises "every original/rephrased pair"
  precisely so a reader can judge semantic equivalence independently — a scientific function the
  paper depends on, and which Tier A does not serve.
- **Against.** Each rephrasing is meaning-preserving by construction, so it carries the semantic
  content of a gated row. Publishing the pairs — original alongside rephrasing — is much harder to
  defend than publishing rephrasings alone, because the pair *contains* the source text verbatim.

**This is a licensing judgment with real exposure and it is not ours to make unilaterally.** Until
it is decided, Tier B stays out of the bundle.

## 4. Consequence for the paper, which must be fixed either way

**T-03 §7.1 currently promises "every original/rephrased pair."** If Tier B is withheld, that
promise is false as written and must be changed to what the artifact actually contains: item IDs,
verdicts, specifications and regeneration scripts. Shipping a paper that promises data the artifact
does not include would be a defect an artifact-evaluation committee would catch immediately.

**Three options, in order of preference:**

1. **Publish rephrasings only, not originals**, with source IDs so a gated reader can pair them.
   Preserves most of the scientific function; avoids republishing gated rows verbatim.
2. **Ask AllenAI directly.** The gate is auto-approved, which suggests the intent is attribution and
   traceability rather than restriction. A written answer settles it permanently and costs one email.
3. **Withhold Tier B entirely** and amend §7.1. Safest, weakest artifact.

**Recommendation: option 2, with option 1 as the interim position.** It is the only route that ends
with certainty rather than with our own reading of a license.

## 5. Model licenses

All evaluated models are open-weight and were used for evaluation, not redistribution — no model
weights are included in this bundle. The eight LoRA adapters trained for E1 derive from Qwen3Guard
base models; **their redistribution terms follow the base model license and have not yet been
verified.** They are excluded from Tier A until that check is done, and their Model BOMs, which
contain no weights, ship instead.

## 6. Attribution notices carried in the bundle

- Aegis AI Content Safety Dataset 1.0 © NVIDIA, CC-BY-4.0.
- WildGuardMix © Allen Institute for AI, ODC-By-1.0 — referenced by row index, not redistributed.
- Model outputs and all derived measurements: released under CC-BY-4.0 by the authors.
- Code: Apache-2.0.
