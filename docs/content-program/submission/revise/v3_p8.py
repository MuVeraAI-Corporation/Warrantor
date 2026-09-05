"""P8 v3 — a miscounted contribution list, three references to a section that does not exist,
one wrong cross-reference, the margin definition §5.8 never gave, and the companion floor.

The §5.8 coefficient table was re-fitted on 2026-09-05 from the margin capture on volume
`warrantor-p9` (OLS of quantized on reference margin, per bit-width) and reproduces every c and
b to three decimals; the safe/unsafe token ids in that record are what the margin definition
below is written from.
"""
from _lib import main

EDITS = [
    ("**Research paper · 2026-08-31 · Vikram Jha**",
     "**Research paper · 2026-09-05 · Vikram Jha**"),

    ("produces findings neither could have observed, and two of the three below are work the sources\n"
     "**named as outstanding and did not do**.",
     "produces findings neither could have observed, and two of the four below are work the sources\n"
     "**named as outstanding and did not do**."),

    # --- §5.6: the companion floor, cited by record rather than by manuscript ---------------
    ("`R11` Against this program's stratified serving-noise floor of 0.09% [T-03 §5.10], 29 of 30 cells\n"
     "clear.",
     "`R11` Against this program's stratified serving-noise floor of 0.09% [T-03 §5.10], reported in\n"
     "full as [ReproFloor], 29 of 30 cells clear."),

    ("`R13` **The floor on this corpus is 0.107% mean pairwise disagreement — 1.07 items in 1,000 — with\n"
     "just 2 items ever unstable across all eight runs** (Wilson 95% [0.055%, 0.726%]).",
     "`R13` **The floor on this corpus is 0.107% mean pairwise disagreement — 1.07 items in 1,000 — with\n"
     "just 2 items ever unstable across all eight runs** (Wilson 95% [0.055%, 0.726%]). The companion\n"
     "measurement on a stratified corpus [ReproFloor] found 0.09% with the same count of two unstable\n"
     "items, and on inspection both of its items were `Safe`/`Controversial` boundary verdicts that\n"
     "flipped together in the same runs — the floor there is a property of the run and of the model's\n"
     "undecided class, not of scattered items. Whether the two items here share that structure is\n"
     "checkable from the released replicates and is left as recorded."),

    # --- §5.8: what a margin is -------------------------------------------------------------
    ("**Pre-registered at `34dc31e7` before any logit was captured.** Two guards × seven precisions\n"
     "× 1,000 items, RTN quantization at group size 64, served through transformers. Zero null margins.",
     "**Pre-registered at `34dc31e7` before any logit was captured.** Two guards × seven precisions\n"
     "× 1,000 items, RTN quantization at group size 64, served through transformers. The margin for an\n"
     "item is the difference between the logits of the `Unsafe` and `Safe` verdict tokens at the position\n"
     "where the verdict is generated, so its sign is the verdict and its magnitude the model's confidence\n"
     "in it; the precisions are 16 bits (the reference) and 8, 6, 5, 4, 3 and 2. Zero null margins."),

    # --- §6: wrong section number ----------------------------------------------------------
    ("**And measure your own floor.** Ours differed by more than an order of magnitude depending on which\n"
     "prior corpus we imported it from, and only measurement settled it (§5.5).",
     "**And measure your own floor.** Ours differed by more than an order of magnitude depending on which\n"
     "prior corpus we imported it from, and only measurement settled it (§5.6)."),

    # --- §7: there is no §0 ------------------------------------------------------------------
    ("1. **The instrument is not ours** (§0, §1), and neither is the cross-scheme audit.",
     "1. **The instrument is not ours** (the prefatory note, §1), and neither is the cross-scheme audit."),

    ("**Nothing here\n   generalizes to AWQ, GPTQ or NF4**, and §0 explains why we did not extend.",
     "**Nothing here\n   generalizes to AWQ, GPTQ or NF4**, and the prefatory note explains why we did not extend."),

    ("For completeness, the probes that *did* fail are [QualityProxy] §4.4's four: entropy shift",
     "For completeness, [QualityProxy] §4.4 reports four mechanism probes of its own that failed to\n"
     "   localize their effect: entropy shift"),

    # --- references ---------------------------------------------------------------------------
    ("[T-03] V. Jha. *Measuring Guard Models: Asymmetry, Transfer, and the Instruments That Cannot See\n"
     "Them.* Manuscript, 2026. — source of the corpus, the ladder, and all 35 cells of per-item verdicts.",
     "[T-03] V. Jha. *Measuring Guard Models: Asymmetry, Transfer, and the Instruments That Cannot See\n"
     "Them.* Manuscript, 2026. — source of the corpus, the ladder, and all 35 cells of per-item verdicts.\n\n"
     "[ReproFloor] V. Jha. *How Reproducible Is a Guard Evaluation? A Measured Floor, and Where It Isn't Small.* Preprint, Zenodo, 2026. doi:10.5281/zenodo.22258094."),
]

main("P8-quantization-equivalence-paper.md", EDITS)
