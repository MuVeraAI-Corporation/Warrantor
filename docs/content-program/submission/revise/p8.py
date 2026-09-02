"""P8 — remove revision bookkeeping; fix the self-contradicting Limitation 7 and the 3-vs-4 count."""
from _lib import main

EDITS = [
    ("**Draft 2 · 2026-08-31 · Vikram Jha**\n"
     "*Draft 2 follows a complete read of [Certify]. Three claims corrected, all against us, and one result added that Draft 1 could not have found. Corrections are marked in place.*\n",
     "**Research paper · 2026-08-31 · Vikram Jha**\n"),

    ("> ⚠️ **Draft 1 was written on a partial read of [Certify] and was wrong three times.** Finishing\n"
     "> §3.5–§3.8, §4 and §9 corrected: the ratio we compared against (§5.1), the fact that we reported\n"
     "> required sample sizes **without ever running the test they size** (§5.4), and the population we may\n"
     "> extrapolate from (§7). **Every correction ran against us.** It also produced §5.5, the strongest\n"
     "> result in the paper, which a partial read could not have reached.\n",
     "> **A full reading of [Certify] §3.5–§3.8, §4 and §9 corrected three things in this analysis**: the\n"
     "> comparison statistic (§5.1), the requirement that a sized test actually be run rather than merely\n"
     "> sized (§5.4–§5.5), and the population we may extrapolate from (§7). **Every correction ran against\n"
     "> us.** The full reading also produced §5.5, the strongest result in the paper.\n"),

    ("**First, their headline ratio does not transfer, though smaller than Draft 1 claimed.** Computed as\n"
     "they compute it — the median of finite cellwise ratios — guard verdict churn runs **1.86× the net\n"
     "accuracy delta** against their **3.85×**. ⚠️ Draft 1 reported 1.4× against their 5.40×, comparing a\n"
     "cellwise median to a ratio-of-medians and partitioning by verdict direction rather than by\n"
     "correctness. **Both figures are now computed both ways against their matching statistic** (ratio of\n"
     "medians: ours 2.75×, theirs 5.40×).\n",
     "**First, their headline ratio does not transfer.** Computed as they compute it — the median of\n"
     "finite cellwise ratios — guard verdict churn runs **1.86× the net accuracy delta** against their\n"
     "**3.85×**. **Both figures are computed both ways against their matching statistic** (ratio of\n"
     "medians: ours 2.75×, theirs 5.40×); comparing a cellwise median to a ratio-of-medians, or\n"
     "partitioning by verdict direction rather than by correctness, overstates the gap.\n"),

    ("**Three things remain, and we claim only these:**",
     "**Four things remain, and we claim only these:**"),

    ("### 5.1 The ratio does not transfer, and Draft 1 compared the wrong number",
     "### 5.1 The ratio does not transfer, and which statistic is compared matters"),

    ("⚠️ **Draft 1 reported 1.4× against 5.40×** — a cellwise median against a ratio-of-medians, and\n"
     "computed on a net delta partitioned by *verdict* direction rather than by *correctness*. Their net\n"
     "delta is an accuracy delta. **Corrected, the gap is about 2×, not about 4×.**\n",
     "**A cellwise median set against a ratio-of-medians, on a net delta partitioned by *verdict*\n"
     "direction rather than by *correctness*, reads as 1.4× against 5.40× — a gap of about 4×.** Their\n"
     "net delta is an accuracy delta. **Matched statistic to statistic, the gap is about 2×.**\n"),

    ("Their §3.6 adds the constraint Draft 1 missed:",
     "Their §3.6 adds a further constraint:"),

    ("⚠️ **Draft 1 reported required sample sizes and stopped there.** [Certify] §3.6 forecloses that:\n",
     "**Reporting required sample sizes is not sufficient.** [Certify] §3.6 is explicit:\n"),

    ("count makes the test informative, and the test still has to be run and to pass.\"* **We ran it.**",
     "count makes the test informative, and the test still has to be run and to pass.\"* **So we ran it.**"),

    ("⚠️ **An earlier draft of this paper said we could not test this. We since did.**\n"
     "[MarginShrink]'s law is fitted on",
     "[MarginShrink]'s law is fitted on"),

    ("7. **A mechanism exists and it is not ours; we do not test whether it reaches guards.** ⚠️ **An\n"
     "   earlier draft of this paper claimed the direction was unexplained. That was wrong.**\n"
     "   **[MarginShrink] supply the mechanism**:",
     "7. **The mechanism is not ours, and our test of its reach ran on a different serving stack.**\n"
     "   **[MarginShrink] supply the mechanism**:"),

    ("Them.* Draft 4, 2026-08-31. — source of the corpus, the ladder, and all 35 cells of per-item verdicts.",
     "Them.* Manuscript, 2026. — source of the corpus, the ladder, and all 35 cells of per-item verdicts."),
]

main("P8-quantization-equivalence-paper.md", EDITS)
