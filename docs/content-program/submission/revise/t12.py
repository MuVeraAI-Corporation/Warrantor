"""T-12 — fill or honestly state every placeholder; fix the broken title block and a dangling §3.5.1.

The substantive ones:
  - "Human verification: ___ of 9 load-bearing rows verified, ___ overturned." Literal blanks. The
    count cannot be invented, so the paper now says the verification is not complete in this
    version -- and §3.5, which claimed it WAS done, is made consistent with §10.
  - Two orphan "###" lines after the title, one of which the build took as the subtitle and the
    other of which rendered as a stray heading before the abstract.
  - "(Table A1, appendix -- 10 rows.)" x4: placeholders standing where a cross-reference belongs.
  - A heading numbered 3.5.2 with no 3.5 or 3.5.1, and two references to the nonexistent §3.5.1.
  - A link to a repository file, an internal label ("T-01") and a paragraph about reading schedule
    "elsewhere in this program" -- none of which a reader of the PDF can resolve.
"""
from _lib import main

EDITS = [
    ("**Systematization · Draft 1 · 2026-09-01 · Vikram Jha**",
     "**Systematization · 2026-09-01 · Vikram Jha**"),

    ("> instrument are released as an anonymized artifact. No component",
     "> instrument are released as an artifact. No component"),

    ("---\n"
     "### Where agent containment actually binds\n"
     "\n"
     "### Adjudicating the guarantees of execution controls for autonomous coding agents\n"
     "\n"
     "\n"
     "\n"
     "---\n",
     "### Where agent containment actually binds: adjudicating the guarantees of execution controls for autonomous coding agents\n"
     "\n"
     "---\n"),

    ("**The frozen action surface.** Seven effectors, frozen 2026-08-30 as [`ACTION-SURFACE-v1.0`](ACTION-SURFACE-v1.md)\n"
     "and published with the artifact. That document also reconciles this enumeration with T-01’s\n"
     "instrumentation classes, so the derived scores here and the measured score in §9 share a denominator:",
     "**The frozen action surface.** Seven effectors, frozen 2026-08-30 as `ACTION-SURFACE-v1.0` and\n"
     "published with the artifact. That document also reconciles this enumeration with the\n"
     "instrumentation classes used to measure the §9 system, so the derived scores here and the measured\n"
     "score in §9 share a denominator:"),

    ("### 3.5.2 Coding method: machine coding, disclosed, with human verification on load-bearing rows",
     "### 3.5 Coding method: machine coding, disclosed, with human verification on load-bearing rows"),

    ("is **verified by a human coder against the\n"
     "recorded spans**, who confirms, corrects or rejects each verdict. The count of **overturned rows is\n"
     "reported** in this section. A non-zero count is evidence the layer is real rather than ceremonial; a\n"
     "zero count would itself require explanation.",
     "is **designated for verification by a human coder against the\n"
     "recorded spans**, who confirms, corrects or rejects each verdict. The count of **overturned rows is\n"
     "reported in §10**. A non-zero count is evidence the layer is real rather than ceremonial; a\n"
     "zero count would itself require explanation."),

    ("> **Pilot-populated 2026-08-30.** Numbers below carry their sample size. The full coverage pass runs\n"
     "> October–November; corpus freeze 15 November. Nothing here is a final result and every figure is\n"
     "> labeled with what produced it.",
     "> **Scope of this version.** Numbers below carry their sample size: fifteen works scored in full,\n"
     "> selected for tier-axis power. The full coverage pass runs October–November and the corpus freezes\n"
     "> on 15 November; every figure is labeled with what produced it."),

    ("*(Table A1, appendix — 10 rows.)*",
     "*The ten rows are given in Table A1 (Appendix).*"),

    ("*(Table A2, appendix — 4 rows.)*",
     "*The four shapes are given in Table A2 (Appendix).*"),

    ("*(Table A3, appendix — 15 rows.)*",
     "*The fifteen rows are given in Table A3 (Appendix).*"),

    ("*(Table A4, appendix — 5 rows.)*",
     "*The five shapes are given in Table A4 (Appendix).*"),

    ("**Deferred, and stated as deferred.** A bypass demonstration on representative systems, one per tier, would convert this paper from analysis into analysis-with-evidence, and it does not fit the present cycle. It is named here rather than omitted because the weakest-link rule makes a falsifiable prediction — a system scored B-T3 should fall to a subprocess spawn that never traverses its chokepoint — and the honest position is that the prediction is published before the demonstration, not after.\n"
     "\n"
     "**Why this exists.** It converts the paper from analysis into analysis-with-evidence, and it is the\n"
     "difference between a borderline and a clear accept. It also disciplines the weakest-link rule: if the\n"
     "rule predicts a system is proxy-tier, a subprocess spawn should defeat it, and that is demonstrable\n"
     "rather than argued.",
     "**Not included in this version.** A bypass demonstration on representative systems, one per tier, would convert this paper from analysis into analysis-with-evidence. It is named here rather than omitted because the weakest-link rule makes a falsifiable prediction — a system scored B-T3 should fall to a subprocess spawn that never traverses its chokepoint — and the prediction is published before the demonstration, not after."),

    ("> **Double-blind note (strip at camera-ready, replace with disclosure).** This section is written in\n"
     "> third person per §3.5.1. One scored system is the authors'; the relationship is declared to the\n"
     "> chair through the conflict-of-interest mechanism and disclosed in the camera-ready. Nothing in the\n"
     "> scoring procedure differs for it.",
     "> **Double-blind note.** This section is written in third person. One scored system is the\n"
     "> authors'; the relationship is declared to the chair through the conflict-of-interest mechanism and\n"
     "> will be disclosed in the camera-ready. Nothing in the scoring procedure differs for it."),

    ("**Machine coding with human verification.** All coding was performed by opposed-stance LLM agents;\n"
     "the nine works carrying headline findings are human-verified against recorded spans (§3.5.2).",
     "**Machine coding with human verification.** All coding was performed by opposed-stance LLM agents;\n"
     "the nine works carrying headline findings are designated for human verification against recorded\n"
     "spans (§3.5)."),

    ("**Human verification: ___ of 9 load-bearing rows verified, ___ overturned.** The nine works carrying headline claims are verified by a human coder against the recorded verbatim spans before submission. The overturned count is reported here whatever it is; a count of zero is stated together with the reason it is credible, since a verification layer that never overturns anything is indistinguishable from one that was not performed.",
     "**Human verification of the nine load-bearing rows is not complete in this version.** The nine works carrying headline claims are designated for verification by a human coder against the recorded verbatim spans. The overturned count will be reported whatever it is; a count of zero will be stated together with the reason it is credible, since a verification layer that never overturns anything is indistinguishable from one that was not performed."),

    ("**Reads that discharge debt elsewhere in this program.** HCP (arXiv:2606.29073), DEMM-Bench\n"
     "(arXiv:2606.20634) and ClawGuard (arXiv:2604.11790) are all in-corpus rows under G1–G4. Reading them\n"
     "inside this schedule costs nothing additional and settles open positioning questions for two other\n"
     "papers at the same time.\n",
     ""),

    ("as recorded there, not as summarised in this paper's tables.",
     "as recorded there, not as summarized in this paper's tables."),
]

main("T-12-SUBMISSION-satml2027.md", EDITS)
