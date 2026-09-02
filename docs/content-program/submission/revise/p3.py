"""P3 — remove revision bookkeeping; keep every retraction as a statement about the data."""
from _lib import main

EDITS = [
    ("**Replication note · Draft 3 · 2026-08-31 · Vikram Jha**",
     "**Replication note · 2026-08-31 · Vikram Jha**"),

    ("> ⚠️ **Drafted as a novel-contribution paper; it is not one.** A prior-art check run after Draft 1\n"
     "> found **LongGuard** [LongGuard], published 2026-08-27 — four days before this work — which\n",
     "> **This note is a replication, not a novel contribution.** A prior-art check found\n"
     "> **LongGuard** [LongGuard], published 2026-08-27 — four days before this work — which\n"),

    ("> **The measurements below stand; the novelty claim does not.** Draft 2 repositions this as a\n"
     "> replication at short context on two models LongGuard did not test, and **retracts Draft 1's claim\n"
     "> to have refuted length dilution** (§4.2). Full assessment in `PRIOR-ART-ASSESSMENT.md`.\n",
     "> **The measurements below stand; the novelty claim does not.** This note is positioned as a\n"
     "> replication at short context on two models LongGuard did not test, and **retracts an initial\n"
     "> claim to have refuted length dilution** (§4.2).\n"),

    ("> **Draft 3 tests that retraction instead of conceding it.** A follow-up run (P3-X, §4.2.1) extends",
     "> **The retraction is then tested instead of conceded.** A follow-up run (P3-X, §4.2.1) extends"),

    ("Draft 1 reported miss rate as non-monotone in",
     "the short-range grid showed miss rate non-monotone in"),

    ("and concluded that dilution is refuted.",
     "and we initially concluded that dilution is refuted."),

    ("**We claim no novelty on the positional phenomenon, its mechanism, or its mitigation.**",
     "**We claim no novelty on the positional phenomenon, its mechanism, or its mitigation.** This\n"
     "note was drafted before its prior-art check; LongGuard predates it by four days and supersedes\n"
     "its central claim, which is recorded here rather than absorbed."),

    ("⚠️ **Draft 1 read this as refuting dilution. That reading is retracted.** Our largest cell is",
     "**Read alone, this appears to refute dilution. That reading is retracted.** Our largest cell is"),

    ("Draft 1's non-monotonicity was a small-range artifact.",
     "The short-range non-monotonicity was a small-range artifact."),

    ("\n> **On the sequencing.** Draft 1 was written before any prior-art check. LongGuard predates it by\n"
     "> four days and supersedes its central claim. This is recorded rather than quietly absorbed, and the\n"
     "> program has since added a literature gate before first draft rather than after.\n",
     "\n"),
]

main("P3-position-not-length-paper.md", EDITS)
