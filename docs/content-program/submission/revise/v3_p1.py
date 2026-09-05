"""P1 v3 — what the artifact shows that the summary statistics hid, plus the uncertainty the
paper never stated.

Every number below was recomputed from the 18 per-item run files on the `warrantor-p1` volume
on 2026-09-05 (scratch script `p1_all.py`): the two unstable items are m0489 and m0749, each
returning its minority verdict in runs A3 and A7, and in exactly four of the eighteen runs
overall, always together; every flip is a Safe/Controversial flip; Wilson 95% on 2/1000 is
[0.055%, 0.726%]. Also moves the Artifact section and the prior-art scope note ahead of the
References heading, because the builder drops everything after that heading and neither ever
reached the published PDF.
"""
from _lib import main

EDITS = [
    ("**Research paper · 2026-08-31 · Vikram Jha**",
     "**Research paper · 2026-09-05 · Vikram Jha**"),

    # --- abstract: uncertainty, and where the floor lives ---------------------------------
    ("**The floor is small: 998 of 1,000 items returned identical verdicts across eight independent runs**,\n"
     "for a mean pairwise disagreement of **0.09%**. Differences above roughly 0.1% between separately-run\n"
     "guard evaluations are therefore real, not noise.",
     "**The floor is small: 998 of 1,000 items returned identical verdicts across eight independent runs**,\n"
     "for a mean pairwise disagreement of **0.09%**; the Wilson 95% interval on the per-item instability\n"
     "rate, 2 in 1,000, is [0.05%, 0.73%]. A between-run difference of several tenths of a percent on a\n"
     "corpus like this one is therefore real, not noise; one below the interval's upper bound is not yet\n"
     "distinguishable from the floor."),

    ("changes nothing measurable.\n\n**The paper's remaining contribution is a discrepancy",
     "changes nothing measurable.\n\n"
     "**Where the floor lives is more informative than its size.** The two unstable items do not flip\n"
     "independently: across all eighteen runs, both flip together, in the same four runs, and every flip\n"
     "crosses the model's own `Safe`/`Controversial` boundary — the undecided class of its three-valued\n"
     "severity. Under the alternative policy setting that scores `Controversial` as safe, one of the two\n"
     "would not count as a flip at all. The floor is a property of runs rather than of items, and it\n"
     "lives in the boundary class.\n\n"
     "**The paper's remaining contribution is a discrepancy"),

    # --- contributions ---------------------------------------------------------------------
    ("1. **The first measurement, to our knowledge, of guard-evaluation reproducibility**: 998/1,000 items\n"
     "   unanimous across eight independent runs, 0.09% mean pairwise disagreement (§4).",
     "1. **The first measurement, to our knowledge, of guard-evaluation reproducibility**: 998/1,000 items\n"
     "   unanimous across eight independent runs, 0.09% mean pairwise disagreement (§4) — and, from the\n"
     "   per-item record, that the two unstable items flip together, in the same runs, at the\n"
     "   `Safe`/`Controversial` boundary (§4.2)."),

    # --- related work: the scope note that never shipped, and a vague survey claim -------------
    ("**Guard model evaluation** is largely benchmark-aggregate. In our survey it reports model, corpus and\n"
     "metric, and does not report serving configuration beyond the model tag, does not repeat runs, and\n"
     "does not state a noise floor.",
     "**Guard model evaluation** is largely benchmark-aggregate. In the guard-evaluation papers we examined\n"
     "([WildGuard], [GuardBench]) it reports model, corpus and metric, and does not report serving\n"
     "configuration beyond the model tag, does not repeat runs, and does not state a noise floor."),

    ("**What we do not claim.** We do not claim guard evaluations are unreliable",
     "**Scope of the prior-art check.** The claim above that we found no prior measurement of\n"
     "repeated-run verdict agreement for guard classifiers rests on a keyword search of the\n"
     "guard-evaluation and quantization literature conducted on 2026-08-31, **after** this experiment\n"
     "ran. It is not a systematic survey. The systems literature on serving nondeterminism is substantial\n"
     "and we do not claim novelty on the existence of the phenomenon — only on measuring its magnitude\n"
     "for a safety decision, and on the population-dependence hazard in §5.\n\n"
     "**What we do not claim.** We do not claim guard evaluations are unreliable"),

    # --- method: the stack, and the gap in our own reporting ---------------------------------
    ("would think to report — model, quantization, corpus, seed, temperature, context size — is fixed and\n"
     "identical. The drift measured is the drift nobody controls for.",
     "would think to report — model, quantization, corpus, seed, temperature, context size — is fixed and\n"
     "identical. The drift measured is the drift nobody controls for.\n\n"
     "**Serving stack.** Ollama over llama.cpp, the `Q4_K_M` GGUF from a public conversion, one\n"
     "container per run on a serverless GPU provider. The run records carry the model tag, `num_ctx`,\n"
     "seed, thread setting, and per-item raw output; **they do not carry the Ollama or llama.cpp\n"
     "version**, and it was not pinned. §6 asks every evaluation to report the stack version. This one\n"
     "cannot, and the omission is stated rather than repaired after the fact."),

    # --- results: uncertainty row ------------------------------------------------------------
    ("| Items ever disagreeing | **2 / 1,000** |",
     "| Items ever disagreeing | **2 / 1,000** — Wilson 95% [0.05%, 0.73%] |"),

    # --- §4.2: the per-item record --------------------------------------------------------
    ("The two disagreeing items were not different items in different pairs. **Each disagreed in 12 of the\n"
     "28 pairs**, while the remaining 998 were unanimous everywhere.\n\n"
     "This distinction is not cosmetic. A floor of 0.09% spread thinly across nine hundred items would\n"
     "imply pervasive low-level instability. **A floor of 0.09% concentrated in two items that flip\n"
     "roughly half the time implies a small set of genuinely borderline inputs and a stable remainder** —\n"
     "and it is the second, which is why §5's population argument follows.",
     "The two disagreeing items were not different items in different pairs. **Each disagreed in 12 of the\n"
     "28 pairs**, while the remaining 998 were unanimous everywhere. Twelve disagreeing pairs is the\n"
     "signature of a two-against-six split: each item returned its minority verdict in **two of the\n"
     "eight runs**, not in half of them.\n\n"
     "This distinction is not cosmetic. A floor of 0.09% spread thinly across nine hundred items would\n"
     "imply pervasive low-level instability. **A floor of 0.09% concentrated in two items implies a small\n"
     "set of genuinely borderline inputs and a stable remainder** — and it is the second, which is why\n"
     "§5's population argument follows.\n\n"
     "**The two items flip together, and the unit of instability is the run.** Reading the per-item\n"
     "verdicts rather than the summary statistics shows three things the counts above do not:\n\n"
     "| | item `m0489` (labeled benign) | item `m0749` (labeled harmful) |\n"
     "|---|---|---|\n"
     "| majority verdict, 6 of 8 runs | `Safe`, no category | `Controversial`, *Unethical Acts* — scored harmful |\n"
     "| minority verdict, 2 of 8 runs | `Controversial`, *Jailbreak* — scored harmful | `Safe`, no category |\n"
     "| runs returning the minority verdict | A3, A7 | **A3, A7** |\n\n"
     "1. **Both items flip in the same two runs.** Runs A3 and A7 differ from the other six on both\n"
     "   items, and no run differs on only one. Across all eighteen runs in the experiment — arms B and\n"
     "   C included — the same two items are the only unstable ones; they flip in four runs (A3, A7, one\n"
     "   `num_thread=8` run and one L4 run), and they always flip together. Every run falls into one of\n"
     "   two states, fourteen in one and four in the other. That is the signature of a run-level\n"
     "   property — something about the container a run landed in — not of two items each drawing an\n"
     "   independent coin.\n"
     "2. **Every flip crosses the `Safe`/`Controversial` boundary.** Qwen3Guard emits a three-valued\n"
     "   severity; `Controversial` is the model's own undecided class, and the harness scores it harmful.\n"
     "   Neither item ever moves between `Safe` and `Unsafe`. The whole measured floor is a property of\n"
     "   the boundary class.\n"
     "3. **One of the two flips is a category flip as much as a severity flip.** `m0489`'s minority\n"
     "   verdict carries the *Jailbreak* category, which the harness gates as harmful regardless of\n"
     "   severity. Under the alternative policy that scores `Controversial` as safe, `m0489` would still\n"
     "   count as a flip and `m0749` would not: the floor would be one item in a thousand, and *which*\n"
     "   item is unstable would depend on a policy setting rather than on the model.\n\n"
     "The two-state structure is not explained by anything the design varied. The four minority-state\n"
     "runs include a cold-cache run and three warm-cache runs, an unpinned and a pinned thread count, and\n"
     "one of two L4 runs whose sibling on identical hardware stayed in the majority state."),

    # --- §4.4: arms B and C see the same two items -----------------------------------------
    ("**Two different GPU architectures produce the same verdicts as one architecture produces on repeat.**",
     "**Two different GPU architectures produce the same verdicts as one architecture produces on repeat.**\n\n"
     "In both arms the only disagreeing items are the same two as in arm A, and in each arm exactly one\n"
     "run — the second `num_thread=8` run, and the second L4 run — sits in the minority state of §4.2.\n"
     "Thread count and GPU type do not create instability of their own; they inherit the same two-state\n"
     "behavior at the same two items."),

    # --- §5.3: a second measurement, and a sharper hypothesis --------------------------------
    ("but it makes the population-dependence hypothesis considerably more plausible than our two unstable\n"
     "items alone would.",
     "but it makes the population-dependence hypothesis considerably more plausible than our two unstable\n"
     "items alone would.\n\n"
     "**A second measurement on a second corpus.** A companion study [Ladder] repeated the eight-replicate\n"
     "protocol with the same model and quantization on its own 1,000-item, adversarially weighted corpus\n"
     "and found 0.107% mean pairwise disagreement with, again, exactly two items ever unstable. Two\n"
     "corpora, two floors within 0.02 percentage points of each other, two unstable items each — and in\n"
     "this paper's data both sit at the `Safe`/`Controversial` boundary (§4.2). The population hypothesis\n"
     "is therefore sharper than \"borderline items\": the floor appears to live in the model's own undecided\n"
     "class, and a corpus's floor is a function of how many of its items the model files there."),

    # --- §5.4: the policy artifact ---------------------------------------------------------
    ("- **Any between-run difference below ~0.1% on a stratified corpus is not reportable**, and any such\n"
     "  difference on a borderline-enriched set is currently **unbounded** by evidence.",
     "- **Any between-run difference below ~0.1% on a stratified corpus is not reportable**, and any such\n"
     "  difference on a borderline-enriched set is currently **unbounded** by evidence.\n"
     "- **The floor is partly a policy artifact.** Both unstable verdicts are `Controversial` verdicts, and\n"
     "  the harness's `controversial_is_harmful` setting decides whether one of them counts (§4.2). A\n"
     "  companion paper [Masking] shows that fine-tuned guards in the same program lose the `Controversial`\n"
     "  class altogether; on such a model this floor would be zero and the setting inoperative. A reported\n"
     "  floor should state the severity policy it was scored under."),

    # --- §7: the items were inspected; runs are a small sample too ----------------------------
    ("**We cannot rule out that the two unstable items are corpus artifacts** — malformed text, unusual\n"
     "tokenization — rather than genuinely borderline content. Inspecting them is a next step and would\n"
     "sharpen §5.",
     "**The two unstable items were inspected at the verdict level, not the text level.** Both are\n"
     "`Controversial`-boundary verdicts (§4.2), which is the borderline signature §5 predicts, and the\n"
     "corpus is access-gated so their text is not reproduced here. A malformed-text explanation would\n"
     "have to account for both items flipping in the same runs, which it does not.\n\n"
     "**Eight runs is also a small sample of run states.** Four of eighteen runs sat in the minority state\n"
     "(Wilson 95% [9%, 45%]); the rate at which a fresh container lands there is not well estimated, and\n"
     "nothing in the run records identifies what differs about those four."),

    # --- conclusion ------------------------------------------------------------------------
    ("**What survives is narrower and more useful than the claim we expected to make.** The disagreement\n"
     "is concentrated in a tiny number of borderline items rather than spread across the corpus, and a\n"
     "prior measurement on a set composed *entirely* of borderline items showed drift ten to sixty times\n"
     "higher.",
     "**What survives is narrower and more useful than the claim we expected to make.** The disagreement\n"
     "is concentrated in two items rather than spread across the corpus — two items that flip together,\n"
     "in the same runs, at the model's own `Safe`/`Controversial` boundary — and a prior measurement on\n"
     "a set composed *entirely* of borderline items showed drift ten to sixty times higher."),

    ("**Open work:** the borderline-item floor (§5.3); cross-stack floors for vLLM and transformers;\n"
     "inspection of the two unstable items; and whether the floor scales with model size, since the prior\n"
     "0.6B observation was five times the 4B's.",
     "**Open work:** the borderline-item floor (§5.3); cross-stack floors for vLLM and transformers; the\n"
     "run-level state that moves both items at once, which is a container-level cause rather than an\n"
     "item-level one (§4.2); and whether the floor scales with model size, since the prior 0.6B\n"
     "observation was five times the 4B's."),

    # --- references: drop the uncited entry, add the two companion preprints; move Artifact up ----
    ("[LongGuard] Z. Chen, X. Wu and S. Hu. *LongGuard: Mechanistic Analysis and Training-Free Mitigation\n"
     "of Long-Context Failure in Safety Guardrails.* arXiv:2608.27580, 2026.\n\n"
     "> ⚠️ **Scope of the prior-art check, stated honestly.** The claim in §1 and §2 that we found no prior\n"
     "> measurement of *repeated-run verdict agreement for guard classifiers* rests on a keyword search of\n"
     "> the guard-evaluation and quantization literature conducted on 2026-08-31, **after** this\n"
     "> experiment ran. It is not a systematic survey. The systems literature on serving nondeterminism is\n"
     "> substantial and we do not claim novelty on the existence of the phenomenon — only on measuring its\n"
     "> magnitude for a safety decision, and on the population-dependence hazard in §5.\n\n"
     "---\n\n"
     "## Artifact\n\n"
     "Per-item verdicts for all 18 runs; the pre-registration and its hash; the corpus row indices; the\n"
     "estimator implementing §6. Source corpus is public but access-gated, so item indices are published\n"
     "rather than item text, with a rebuild script.",
     "[Ladder] V. Jha. *One Ladder, Opposite Directions: Directional Churn in Quantized Guard Classifiers, and What a Paired Equivalence Standard Costs When Applied to Them.* Preprint, Zenodo, 2026. doi:10.5281/zenodo.22258101.\n\n"
     "[Masking] V. Jha. *Masking a Field's Loss Does Not Isolate That Field.* Preprint, Zenodo, 2026. doi:10.5281/zenodo.22258107."),

    ("---\n\n## References\n\n[WildGuard]",
     "---\n\n## Artifact\n\n"
     "Per-item verdicts for all 18 runs, including the raw two-line output behind every verdict; the\n"
     "pre-registration and its hash; the corpus row indices; the estimator implementing §6; and the\n"
     "script that recomputes every figure in §4 from the run files, including the two-state structure of\n"
     "§4.2. Source corpus is public but access-gated, so item indices are published rather than item\n"
     "text, with a rebuild script.\n\n"
     "---\n\n## References\n\n[WildGuard]"),
]

main("P1-reproducibility-floor-paper.md", EDITS)
