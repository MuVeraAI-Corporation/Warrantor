"""P3 v3 — paired tests from the per-item record, the 0.6B's one exception, and three
statements that contradicted the note's own replication framing.

Recomputed 2026-09-05 from `p3-4b.json`, `p3-06b.json` (volume `warrantor-p3`) and the two
P3-X files (`warrantor-p3x`), scratch scripts `p3_analyze.py` and `p3x_defs.py`. The P3-X
payload-level unit that reproduces the note's 19:0 and 2:4 counts exactly is "missed at any
of the five positions"; it was not defined in the text and now is.
"""
from _lib import main

EDITS = [
    ("**Replication note · 2026-08-31 · Vikram Jha**",
     "**Replication note · 2026-09-05 · Vikram Jha**"),

    ("**We retract a claim, and then test the retraction.** the short-range grid showed miss rate non-monotone in\n"
     "length",
     "**We retract a claim, and then test the retraction.** The short-range grid showed miss rate non-monotone in\n"
     "length"),

    # --- P3-X design: which 60, which positions, what the unit is -------------------------
    ("(P3-X, pre-registered `324ee77b`): the same 60 payloads across lengths {0, 1k, 4k, 16k, 32k} × five\n"
     "positions, 1,260 inputs per model at both scales.",
     "(P3-X, pre-registered `324ee77b`): the first 60 of the 100 payloads by identifier, across lengths\n"
     "{0, 1k, 4k, 16k, 32k} × five positions — 0%, 25%, 50%, 75% and 100% of the way through the frame —\n"
     "1,260 inputs per model at both scales. Sixty rather than a hundred was a budget decision; the subset\n"
     "is taken by identifier, not by any property of the payloads, and 14 of the 60 had been missed\n"
     "somewhere in the short-range grid by at least one model, against 24 of the 100."),

    ("| **0.6B** | 0.0167 | 0.0700 | 0.1867 | 0.1600 | 0.3233 |\n\n"
     "**The 4B is monotone.** The 0.6B has one decrease, at 4k→16k. An unregistered follow-up — reported as\n"
     "unregistered — tests the steps with McNemar exact on payload-level discordance, since the same 60\n"
     "payloads recur at every length:",
     "| **0.6B** | 0.0167 | 0.0700 | 0.1867 | 0.1600 | 0.3233 |\n\n"
     "The 0.6B misses **1 of 60** bare payloads at `num_ctx` 32768 where it missed 0 of 100 at 8192\n"
     "(§4.1): one item, inside the control's interval either way, but the only movement in a control cell\n"
     "anywhere in this note, and a reminder that `num_ctx` is a serving parameter with an effect of its\n"
     "own.\n\n"
     "**The 4B is monotone in the pooled rates.** The 0.6B has one decrease, at 4k→16k. An unregistered\n"
     "follow-up — reported as unregistered — tests the steps with McNemar exact on payload-level\n"
     "discordance, since the same 60 payloads recur at every length. **The unit is the payload: it counts\n"
     "as missed at a length if it is missed at any of the five positions**, each step compares every\n"
     "payload's indicator at the two lengths, and the discordant payloads are tested against a fair coin,\n"
     "two-sided:"),

    ("> easier to detect when filler was added, at either scale.\n\n"
     "The edge–middle gap grows with length at the 4B",
     "> easier to detect when filler was added, at either scale.\n\n"
     "Two qualifications belong beside that. On the same test the 4B's individual steps are not all\n"
     "significant either — 1k→4k is 4 payloads worse against 0 better (*p* = 0.125) and 16k→32k is 7\n"
     "against 1 (*p* = 0.070) — so \"monotone\" is a statement about the pooled point estimates, and the\n"
     "endpoint comparison is what carries the inference. And **30 of the 4B's 60 payloads and 28 of the\n"
     "0.6B's are missed at some length and position**, against 21 and 16 of 100 in the short-range grid:\n"
     "the long range more than doubles the share of payloads the guard ever loses.\n\n"
     "The edge–middle gap grows with length at the 4B"),

    # --- §4.3: intervals, the dependence problem, and the paired tests that resolve it ------
    ("*(Fisher exact, one-sided.)*\n\n"
     "**The ordering is middle ≫ start > end, and it holds at every individual length in both models:**\n\n"
     "| 4B | start | middle | end |\n"
     "|---|---|---|---|\n"
     "| 1× | 0.0200 | 0.0900 | 0.0200 |\n"
     "| 4× | 0.0500 | **0.1800** | 0.0500 |\n"
     "| 16× | 0.0600 | 0.1200 | 0.0200 |",
     "*(Fisher exact, one-sided.)*\n\n"
     "Risk ratios with 95% intervals: 4B middle/end **4.33** [2.14, 8.79], middle/start 3.00 [1.64, 5.50];\n"
     "0.6B middle/end **2.64** [1.34, 5.18], middle/start 1.81 [1.01, 3.27].\n\n"
     "⚠️ **The pooled cells count each payload three times**, once per length, so the Fisher tests and\n"
     "these intervals treat 300 dependent observations as independent. The paired tests do not.\n"
     "**Paired on matched (payload, length) cells, the direction has no exceptions in the 4B:** of the\n"
     "cells where the middle and end verdicts differ, the 4B is missed in the middle and caught at the\n"
     "end in **30 of 30** (exact *p* = 9.3 × 10⁻¹⁰), and missed in the middle and caught at the start in\n"
     "26 of 26 (*p* = 1.5 × 10⁻⁸); the 0.6B runs 19 to 1 (*p* = 2.0 × 10⁻⁵) and 18 to 5\n"
     "(*p* = 5.3 × 10⁻³). Collapsed to payloads, 19 of the 4B's 100 are missed more often in the middle\n"
     "than at the end and none the reverse; the 0.6B's run 13 to 1. The effect is also concentrated:\n"
     "**21 of 100 payloads (4B) and 16 of 100 (0.6B) are ever missed** in a framed cell, and the other\n"
     "four-fifths are caught in every one.\n\n"
     "**The ordering is middle ≫ start > end. It holds at every individual length in the 4B, and at 4×\n"
     "and 16× in the 0.6B; at 1× the 0.6B's start and middle cells are within one item of each other,\n"
     "6 against 5 of 100, which is the one cell in the grid where position does not order the effect:**\n\n"
     "| 4B | start | middle | end |\n"
     "|---|---|---|---|\n"
     "| 1× | 0.0200 | 0.0900 | 0.0200 |\n"
     "| 4× | 0.0500 | **0.1800** | 0.0500 |\n"
     "| 16× | 0.0600 | 0.1200 | 0.0200 |\n\n"
     "| 0.6B | start | middle | end |\n"
     "|---|---|---|---|\n"
     "| 1× | 0.0600 | 0.0500 | 0.0200 |\n"
     "| 4× | 0.0800 | **0.1200** | 0.0500 |\n"
     "| 16× | 0.0200 | **0.1200** | 0.0400 |"),

    # --- §5.1: the note claimed novelty in the same sentence it replicated ------------------
    ("appearance in a *classification* task with a safety consequence is, to our reading, new — and it\n"
     "means the guard is not failing to *understand* the payload.",
     "appearance in a *classification* task with a safety consequence is LongGuard's finding, which this\n"
     "note replicates at the short end of their range — and it means the guard is not failing to\n"
     "*understand* the payload."),

    # --- §5.3: the defense already exists ---------------------------------------------------
    ("We have not tested that. It is stated as the obvious follow-up, and it is cheap.",
     "We have not tested that. LongGuard implements a chunked-detection defense of exactly this shape and\n"
     "reports that it recovers most of the loss on their panel; whether it does on these two models is\n"
     "the obvious follow-up, and it is cheap."),

    # --- §6: the dependence threat, stated ---------------------------------------------------
    ("**Absolute rates are small.** A 13% pooled middle-position miss rate",
     "**The pooled comparisons are not independent.** Each payload appears in every cell, so a 300-item\n"
     "pooled cell is 100 payloads observed three times and the Fisher intervals in §4.3 are too narrow.\n"
     "The matched-cell and payload-level paired tests reported beside them are the stricter test, and\n"
     "they reach the same conclusion with a stronger signal.\n\n"
     "**Absolute rates are small.** A 13% pooled middle-position miss rate"),

    # --- conclusion -------------------------------------------------------------------------
    ("model that catches it **100% of the time** with no frame at all. The ordering holds at every length,\n"
     "in both model scales, and the effect is significant at *p* < 10⁻⁵.",
     "model that catches it **100% of the time** with no frame at all. The ordering holds at every length\n"
     "in the larger model and at all but the shortest in the smaller one, and on the paired test the 4B\n"
     "has no exceptions: 30 of 30 discordant cells fall the same way."),
]

main("P3-position-not-length-paper.md", EDITS)
