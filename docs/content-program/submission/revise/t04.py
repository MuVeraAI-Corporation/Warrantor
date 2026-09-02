"""T-04 — remove revision bookkeeping; fix three substantive defects a reviewer would catch.

The substantive ones, beyond the bookkeeping:
  - "four months apart" for two baseline runs dated 2026-08-13 and 2026-08-30. Seventeen days.
  - §6 listed target-module choice as an open route two sections after §5.5 closed it, and said no
    corpus with a third severity value exists three sections after §3.5 named one.
  - "Four narrower contributions survive" above a list of five.
  - A double-blind note ("no author, institution or repository is identified") printed under the
    author's name, affiliation and ORCID.
"""
from _lib import main

EDITS = [
    ("**Research paper (short) · Draft 2 · 2026-09-01 · Vikram Jha**\n"
     "*Draft 2 adds §5: a three-arm target-module ablation that discharges the principal limitation of Draft 1. One of the three isolation routes §6 offered is closed by it.*\n",
     "**Research paper (short) · 2026-09-01 · Vikram Jha**\n"),

    ("> Written in third person for double-blind. Model, corpus and infrastructure names are given; no\n"
     "> author, institution or repository is identified.\n\n",
     ""),

    ("**⚠️ Novelty, bounded first.** That loss masking fails to isolate a field under a shared adapter is\n"
     "**documented concurrently**, and that binary targets produce binary behavior is **established\n"
     "practice**. §8 withdraws the broader claim an earlier draft made and cites the work that refutes it.\n"
     "Four narrower contributions survive:",
     "**Novelty, bounded first.** That loss masking fails to isolate a field under a shared adapter is\n"
     "**documented concurrently**, and that binary targets produce binary behavior is **established\n"
     "practice**. §8 states the contribution at that narrower width and cites the concurrent work.\n"
     "Five narrower contributions survive:"),

    ("**Correction, 2026-08-30: the constraint is corpus-specific, not general.** The paragraph above is\n"
     "accurate about the two corpora in this program's mixture, and an earlier draft over-generalized it to\n"
     "\"any practitioner attempting a graded severity output from these corpora.\" A survey of public\n"
     "alternatives refutes that. The Aegis AI Content Safety Dataset 1.0 carries",
     "**The constraint is corpus-specific, not general.** The paragraph above is accurate about the two\n"
     "corpora in this mixture and does not generalize beyond them. A survey of public alternatives shows\n"
     "why. The Aegis AI Content Safety Dataset 1.0 carries"),

    ("*This correction does not rescue the runs. Both were trained on the mixture described above and both\n"
     "failed for the reasons given. It removes an over-claimed generalization from the analysis of why.*",
     "*This does not rescue the runs: both were trained on the mixture described above and both failed\n"
     "for the reasons given.*"),

    ("§7 of an earlier draft of this paper named a limitation and made a prediction under it:\n"
     "\n"
     "> *One adapter configuration tested. A different rank or a different target-module set might reduce\n"
     "> the leakage. **It should not eliminate it**, since the projections producing both fields overlap\n"
     "> under every standard configuration we are aware of — but we did not test that, and the claim is\n"
     "> therefore mechanistic rather than empirical.*\n"
     "\n"
     "We have now tested it. The prediction holds, and the route it was hedging is closed.",
     "The mechanistic account in §4.3 makes a prediction: a different target-module set might reduce the\n"
     "leakage but should not eliminate it, since the projections producing both fields overlap under every\n"
     "standard configuration we are aware of. Left there, the claim is mechanistic rather than empirical.\n"
     "This section tests it. The prediction holds, and the route it was hedging is closed."),

    ("**Isolation requires separate parameters, not a flag.** Three routes remain, and none of them is a\n"
     "third setting of the masking option:\n"
     "\n"
     "1. **A second adapter** carrying the severity field, with its own parameters.\n"
     "2. **Target modules that do not carry severity** — which requires knowing which projections produce\n"
     "   which field, and is a real open question at this scale.\n"
     "3. **A corpus that can supervise all three severity values** — which, per §3.5, does not currently\n"
     "   exist in the public guard mixtures.",
     "**Isolation requires separate parameters, not a flag.** Of three candidate routes, none is a third\n"
     "setting of the masking option, and §5 closes one:\n"
     "\n"
     "1. **A second adapter** carrying the severity field, with its own parameters — untested, and the\n"
     "   only surviving structural route.\n"
     "2. **Target modules that do not carry severity** — closed by §5: no such set exists among the\n"
     "   projections a LoRA adapter addresses here.\n"
     "3. **A corpus that can supervise all three severity values** — which, per §3.5, exists (Aegis\n"
     "   carries a third value in its train split) but is not the mixture used here."),

    ("**One adapter configuration tested — DISCHARGED for target modules, standing for rank.** This\n"
     "limitation previously read: *\"A different rank or a different target-module set might reduce the\n"
     "leakage. It should not eliminate it... but we did not test that, and the claim is therefore\n"
     "mechanistic rather than empirical.\"* §5 tests the target-module half and the prediction holds:\n"
     "attention-only and MLP-only each eliminate nothing and each destroy the class outright, so for\n"
     "target modules the claim is now empirical. **The rank half is still untested.** All three arms ran\n"
     "at rank 16, alpha 32; we do not know what a much larger or much smaller adapter does, and §5's\n"
     "result gives no reason to expect rank to behave like target-module choice.",
     "**One adapter rank tested.** §5 tests target-module choice and the prediction holds: attention-only\n"
     "and MLP-only each destroy the class outright, so for target modules the claim is empirical. **The\n"
     "rank dimension is untested.** All three arms ran at rank 16, alpha 32; we do not know what a much\n"
     "larger or much smaller adapter does, and §5's result gives no reason to expect rank to behave like\n"
     "target-module choice."),

    ("**The evaluations were re-run, and they reproduce.** An earlier version of this section reported that\n"
     "the raw per-item outputs no longer existed: the results directory had been excluded from version\n"
     "control and never committed, so every figure survived only as recorded prose and as hand-transcribed\n"
     "literals whose per-class counts were back-computed from published rates.",
     "**The baseline evaluations were re-run, and they reproduce.** The original per-item outputs were not\n"
     "retained — the results directory was never committed — so the figures in §2–§4 survived as recorded\n"
     "rates and as hand-transcribed counts back-computed from them."),

    ("paper ships an artifact rather than an apology, and its baseline numbers are now measured twice, four\n"
     "months apart, on the same configuration.",
     "paper ships an artifact, and its baseline numbers are measured twice, seventeen days apart, on the\n"
     "same configuration."),

    ("An earlier draft of this section claimed that no treatment existed of what happens to an unsupervised\n"
     "output field when a neighboring field is tuned under a shared adapter. **That claim does not survive\n"
     "a literature check and has been withdrawn.** *Reasoning-Trace Collapse* (arXiv:2605.21127) runs the",
     "The closest prior treatment of what happens to an unsupervised output field when a neighboring\n"
     "field is tuned under a shared adapter is *Reasoning-Trace Collapse* (arXiv:2605.21127), which runs the"),
]

main("T-04-masking-does-not-isolate.md", EDITS)
