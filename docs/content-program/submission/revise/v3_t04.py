"""T-04 v3 — fold in the pre-registered follow-up the paper's own revision note prescribed and
the paper never received; correct what arm A actually retrains; state the hyperparameters and
the gate's comparator; add the third masked run whose per-item outputs survive.

Verified 2026-09-05: T04-X2 stage-2 records on volume `warrantor-t04x2-evals` give Safe/Unsafe
379/817 (0.6B, 3 unparsed) and 426/771 (4B, 2 unparsed), base `Qwen/Qwen3Guard-Gen-*`, greedy,
fail-closed — matching the revision note. The run arm A reproduces is
`warrantor-guard-0.6b-expguard-weak-exp06-2026-08-22a` (unsafe 1038, safe 1237, no
`controversial`), not run 1. The local masked run is
`warrantor-guard-0.6b-weak-category-local-2026-08-22a`: controversial 231, safe 1070, unsafe 386,
`others` 11, `unethical acts` 1, recall 0.7374 — all in the released verdicts dataset. LoRA
constants from the recipe: rank 16, alpha 32, dropout 0.05, lr 1e-4, batch 2 × accumulation 8.
"""
from _lib import main

EDITS = [
    ("**Research paper (short) · 2026-09-01 · Vikram Jha**",
     "**Research paper (short) · 2026-09-05 · Vikram Jha**"),

    # --- abstract -----------------------------------------------------------------------------
    ("We report all five runs, the automated gate's verdicts, and the corpus property that blocked the\n"
     "intended repair.",
     "A pre-registered follow-up on a different corpus and serving stack, at both scales, reproduces the\n"
     "condition from a format-competent checkpoint: with the severity line contributing nothing to the\n"
     "loss, the field moved significantly in both models, and every one of the 111 moved verdicts became\n"
     "more permissive. Masking does not preserve a field. Whether the movement varies with adapter rank\n"
     "remains untested.\n\n"
     "We report all five runs, the automated gate's verdicts, the follow-up, and the corpus property that\n"
     "blocked the intended repair."),

    # --- setup: hyperparameters -----------------------------------------------------------------
    ("**Model.** A 0.6B parameter generative guard model, fine-tuned with LoRA. A same-size untuned\n"
     "baseline is retained deliberately:",
     "**Model.** A 0.6B parameter generative guard model, fine-tuned with LoRA: rank 16, alpha 32, dropout\n"
     "0.05, learning rate 1 × 10⁻⁴, batch 2 with gradient accumulation 8, one epoch, over the query, key,\n"
     "value, output, gate, up and down projections of every layer. A same-size untuned baseline is\n"
     "retained deliberately:"),

    # --- §3.1: what the gate compared against -------------------------------------------------
    ("The first clause is a discipline worth naming: **the gate refuses to call an unresolvable difference\n"
     "an improvement**, and says so in the language of what the test set can resolve.",
     "The comparator in the first clause, 0.8554, is the untuned **4B**'s recall on the same split — the\n"
     "lane's registered baseline at the time. §3.2 compares against the untuned 0.6B, the same-size\n"
     "comparator §2 argues for, at 0.8488; the gate's verdict is the same against either.\n\n"
     "The first clause is a discipline worth naming: **the gate refuses to call an unresolvable difference\n"
     "an improvement**, and says so in the language of what the test set can resolve."),

    # --- §3.3: the class the lever acts on is where the floor lives -----------------------------
    ("For a system whose purpose is to be auditable, a control that\n"
     "reports success while having no effect is a worse failure than one that breaks loudly.",
     "For a system whose purpose is to be auditable, a control that\n"
     "reports success while having no effect is a worse failure than one that breaks loudly.\n\n"
     "The class the lever acts on is also where a guard's measurement noise lives. A companion study\n"
     "[ReproFloor] finds that the only verdicts that change between repeated runs of the untuned model\n"
     "are `Safe`/`Controversial` boundary verdicts, so a fine-tune that removes the class removes the\n"
     "measured floor along with the control — and a floor of zero on such a model measures the loss, not\n"
     "stability."),

    # --- §4.3: the mechanism is an account, not a demonstration ---------------------------------
    ("Every output field rides the same weights. Loss masking is not a form of parameter isolation and\n"
     "should not be reasoned about as one.",
     "Every output field rides the same weights. Loss masking is not a form of parameter isolation and\n"
     "should not be reasoned about as one.\n\n"
     "The weight-sharing account is mechanistic rather than demonstrated. The experiment that would\n"
     "demonstrate it — training the two fields with separate adapters, as a positive control — was\n"
     "deferred and is unrun (§7). What §5 establishes is that no single-adapter module choice preserves\n"
     "the field, not that weight sharing is the cause."),

    # --- §5.1 / §5.2: which corpus, and which run arm A reproduces ------------------------------
    ("Three arms, identical in everything but the adapter's target modules. Same base model, same 11,272-row\n"
     "training corpus, rank 16, alpha 32, bf16, one epoch, single A100.",
     "Three arms, identical in everything but the adapter's target modules. Same base model, same 11,272-row\n"
     "training corpus — ⚠️ a different corpus from runs 1 and 2: rows drawn from the mixture's second member\n"
     "alone, whose held-out split scores runs 3–5 below, rather than the 38,694-row mixture of §2 — rank 16,\n"
     "alpha 32, bf16, one epoch, single A100."),

    ("| **A** control | `q,k,v,o,gate,up,down` | the configuration of run 1, retrained |",
     "| **A** control | `q,k,v,o,gate,up,down` | run 1's adapter configuration, retrained on this corpus |"),

    ("Arm A is a retrain of run 1's configuration, ten days later, on different hardware.",
     "Arm A retrains run 1's adapter configuration on the 11,272-row corpus. The run it reproduces is not\n"
     "run 1 but an earlier training run on that same corpus, from 2026-08-22, whose evaluation on the\n"
     "second test set had shown the same collapse; arm A repeats it ten days later on different hardware."),

    ("| original run | 31 | 115 | 1038 | 122 → **0** |",
     "| earlier run, 2026-08-22 | 31 | 115 | 1038 | 122 → **0** |"),

    # --- §5.5: wrong section number ----------------------------------------------------------------
    ("The mechanistic claim of §7 is now an empirical one, and the weaker reading of \"separate parameters\"",
     "The mechanistic claim of §4.3 is now an empirical one, and the weaker reading of \"separate parameters\""),

    # --- §7: the follow-up, and the failure mode found on the way to it -------------------------------
    ("**One adapter rank tested.** §5 tests target-module choice and the prediction holds: attention-only\n"
     "and MLP-only each destroy the class outright, so for target modules the claim is empirical. **The\n"
     "rank dimension is untested.** All three arms ran at rank 16, alpha 32; we do not know what a much\n"
     "larger or much smaller adapter does, and §5's result gives no reason to expect rank to behave like\n"
     "target-module choice.",
     "**One adapter rank tested, and the condition reproduced elsewhere.** §5 tests target-module choice\n"
     "and the prediction holds: attention-only and MLP-only each destroy the class outright, so for target\n"
     "modules the claim is empirical. A follow-up experiment (T04-X2, pre-registered `2a223cac`) reproduced\n"
     "the **condition** on a different corpus — Aegis, ungated, CC-BY-4.0 — and a different serving stack,\n"
     "at two scales. Starting from a format-competent checkpoint of each model, one epoch with the severity\n"
     "line masked in the loss moved its distribution significantly in both: χ² = 10.48 (0.6B) and 14.67\n"
     "(4B), df = 2, *p* < 0.05, total variation distance 0.042 and 0.051. It moved **safety-adversely,\n"
     "with all 111 moved verdicts going `Unsafe` → `Safe`** — 50 in the 0.6B, 61 in the 4B — and none the\n"
     "other way, while emission of the field held at 99.8% in both. The claim that a masked field does not\n"
     "hold still is therefore no longer purely mechanistic. Scale did not protect the field; the larger\n"
     "model drifted slightly more. Only half of this paper's direction claim was testable there: Aegis is\n"
     "two-valued, so both stages emit zero `Controversial` verdicts by construction and the\n"
     "`Controversial`-up half needs a three-valued corpus. **The rank dimension is untested.** All three\n"
     "arms and both follow-up runs ran at rank 16, alpha 32; we do not know what a much larger or much\n"
     "smaller adapter does, and §5's result gives no reason to expect rank to behave like target-module\n"
     "choice.\n\n"
     "**A distinct failure mode, found while attempting the sweep.** A first attempt at that follow-up\n"
     "(T04-X) masked the field during fine-tuning that was *teaching* the output format rather than\n"
     "perturbing an established one, and the masked field was never emitted at all — 0 of 1,199 items\n"
     "across eleven configurations spanning rank {4, 16, 64}, two target-module sets and both scales — with\n"
     "the supervised field degraded alongside it, to between 11% and 51% emission against 99.8%. The\n"
     "mechanism is structural: the target is `Safety: …` followed by `Categories: …`, so the model must\n"
     "emit the masked line before it can reach the supervised one. The untuned base emits the bare format\n"
     "on 0 of 1,199 items, so that sweep had no reference distribution and could not compute its\n"
     "pre-registered statistic; the design error was foreseeable from an earlier result in the same\n"
     "program, which had labeled exactly those rows *not a baseline*, and it is reported rather than\n"
     "omitted. Practitioners masking part of a structured target during format acquisition should expect\n"
     "loss of the whole structure, not selective preservation."),

    ("The adapters\n"
     "from the two rejected training runs were not retained, so the tuned-model figures in sections 3 and 4\n"
     "remain as recorded and are **not** independently re-verified. Reproducing those requires re-training,\n"
     "which is out of scope here and is stated as an open item rather than absorbed.",
     "The adapters\n"
     "from the two rejected training runs were not retained, so the tuned-model figures in sections 3 and 4\n"
     "remain as recorded and are **not** independently re-verified. Reproducing those requires re-training,\n"
     "which is out of scope here and is stated as an open item rather than absorbed.\n\n"
     "One further instance does exist with its per-item outputs retained. A third run with the severity\n"
     "line masked, trained locally on 2026-08-22 and scored on the same 1,699-item split, emitted\n"
     "`Controversial` 231 against the base model's 49, `Unsafe` 386 against 650, and category vocabulary —\n"
     "`others` eleven times, `unethical acts` once — in the severity slot, at an overall recall of 0.7374.\n"
     "It is run 2's signature at different magnitudes, from a run whose 1,699 verdicts are in the released\n"
     "dataset. It does not re-derive run 2's figures; it shows the signature is not unique to them."),

    # --- references ---------------------------------------------------------------------------------
    ("[Zhang et al. 2026] Y. Zhang et al. *Where vs What: Decomposing Structural and Content Failures in\n"
     "LLM-Generated Structured Outputs.* arXiv:2608.25358, 2026.",
     "[Zhang et al. 2026] Y. Zhang et al. *Where vs What: Decomposing Structural and Content Failures in\n"
     "LLM-Generated Structured Outputs.* arXiv:2608.25358, 2026.\n\n"
     "[ReproFloor] V. Jha. *How Reproducible Is a Guard Evaluation? A Measured Floor, and Where It Isn't Small.* Preprint, Zenodo, 2026. doi:10.5281/zenodo.22258094."),
]

main("T-04-masking-does-not-isolate.md", EDITS)
