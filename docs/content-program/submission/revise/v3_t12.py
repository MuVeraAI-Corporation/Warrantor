"""T-12 v3 — one scored work mislabeled as the authors' own in six places, a placement
distribution that contradicted its own text, a contribution the paper does not deliver, a
stale method section, and a cited work with no reference entry.

Established 2026-09-05 from the coding records in `drafts/corpus-codings/`: the fifteenth
scored work is AIP (arXiv:2603.24775) — its Schneider surrogate is the token-chain predicate in
Table A3 row 9 verbatim — coded A1 by the charitable coder and A4 by the conservative one, and
the pair arithmetic in §6.3.1 (69 / 16 / 20 of 105) only balances with AIP adjudicated A1. The
paper had relabeled it "the section 9 system", which is a different system that is not one of
the fifteen.
"""
from _lib import main

EDITS = [
    ("**Systematization · 2026-09-01 · Vikram Jha**",
     "**Systematization · 2026-09-05 · Vikram Jha**"),

    ("6. **A small empirical artifact** (§8) demonstrating bypass on representative systems, one per tier.",
     "6. **A falsifiable prediction** (§8): a system scored B-T3 should fall to a subprocess spawn that\n"
     "   never traverses its chokepoint. The bypass demonstration that would test it, one representative\n"
     "   system per tier, is not included in this version; the prediction is published before it."),

    ("Full text\nwas retrieved on 30 of 30 codings.",
     "Full text\nwas retrieved on 30 of 30 codings in the decisive pass, and on 50 of 50 across both passes."),

    ("**Screening.** ~60 candidates identified by systematic search across cs.CR, cs.AI and cs.SE, plus\n"
     "citation chasing from the prior systematization and from the classical spine. Screened to ~45 by\n"
     "full-text application of G1–G4. **Expected attrition 10–20%**, and the excluded set is published with\n"
     "the gate that excluded each.",
     "**Screening.** 322 candidate records from four discovery modalities — mechanism-first search across\n"
     "cs.CR, cs.AI and cs.SE, a systematic database sweep, venue and industry search, and seed mining from\n"
     "the prior systematization and the classical spine. 55 were screened by full-text application of\n"
     "G1–G4; 49 entered the corpus and 6 were excluded, each with the gate that excluded it. §5.1 discloses\n"
     "that the remaining 267 candidates were not screened, and why."),

    ("**Coding.** Two coders, independent, on all three axes plus the evidence grade. Cohen's κ per axis.\n"
     "Disagreements adjudicated by discussion, on the record, published in the artifact.",
     "**Coding.** Two opposed-stance machine coders (§3.5), independent, on all three axes plus the evidence\n"
     "grade, every cell carrying a verbatim span. Agreement is reported per axis as a stance-divergence\n"
     "measurement, and as Cohen's κ only where the marginals support one. Disagreements are adjudicated on\n"
     "the record and published in the artifact, and the nine works carrying headline findings are\n"
     "designated for human verification against the recorded spans (§3.5, §10)."),

    ("§5A needs one more sentence before the full pass.",
     "the depth rule will carry one more clarifying sentence before the full pass."),

    # --- §6.3.1: the fifteenth work, named; the robustness table, completed -------------------------
    ("**A1** — AgentCgroup. **A3** — Separation-of-Powers. The §9\n"
     "system takes no placement in the composition matrix.",
     "**A1** — AgentCgroup, AIP. **A3** — Separation-of-Powers. The\n"
     "system the authors know well (§9) is scored in that section and is not one of the fifteen, so it\n"
     "takes no place in the matrix."),

    ("The count depends on two adjudications where the coders disagreed, in opposite directions on the same\n"
     "species of evidence",
     "The count depends on three adjudications where the coders disagreed, two of them in opposite\n"
     "directions on the same species of evidence"),

    ("| PAuth | **A4** | A2 | **A4** | 1 A4 × 11 A2 → **11 pairs** |",
     "| PAuth | **A4** | A2 | **A4** | 1 A4 × 11 A2 → **11 pairs** |\n"
     "| AIP | A1 | **A4** | **A1** | 3 A4 × 10 A2 → **30 pairs** |"),

    ("Neither flip changes the qualitative result",
     "No single flip changes the qualitative result"),

    # --- §7.4.6 ---------------------------------------------------------------------------------------
    ("and it is\nalso the only work whose primary adversary placement is A1.",
     "and it is\none of the two works, with AIP, whose primary adversary placement is A1."),

    # --- tables: six cells that named the wrong system ---------------------------------------------
    ("MiniScope, SEAgent, AARM, PAuth, the section 9 system, Separation-of-Powers, TDX trusted plane, Heartbeat-Bound Credentials, Grimlock",
     "MiniScope, SEAgent, AARM, PAuth, AIP, Separation-of-Powers, TDX trusted plane, Heartbeat-Bound Credentials, Grimlock"),

    ("| the section 9 system — 1 |",
     "| AIP — 1 |"),

    ("| The section 9 system | Grimlock, Separation-of-Powers, TDX trusted plane | 1 |",
     "| AIP | Grimlock, Separation-of-Powers, TDX trusted plane | 1 |"),

    ("| 9 | The section 9 system | Per-invocation token-chain validation",
     "| 9 | AIP | Per-invocation token-chain validation"),

    ("MiniScope, the section 9 system, PAuth, Grimlock, SEAgent, Caging the Agents, Sandlock, AARM",
     "MiniScope, AIP, PAuth, Grimlock, SEAgent, Caging the Agents, Sandlock, AARM"),

    ("| AgentCgroup, the section 9 system | 2 |",
     "| AgentCgroup, AIP | 2 |"),

    # --- references: the entry AgentThread never had ---------------------------------------------
    ("**This list is not the corpus.** The screened corpus is *n* = 49 (§5.2). The 23 works below\n"
     "are those identified by arXiv identifier somewhere in this paper or its coding records —\n"
     "all 15 works carrying a full two-coder record, plus 8 cited in the text.",
     "**This list is not the corpus.** The screened corpus is *n* = 49 (§5.2). The 24 works below\n"
     "are those identified by arXiv identifier somewhere in this paper or its coding records —\n"
     "all 15 works carrying a full two-coder record, plus 9 cited in the text."),

    ("[DEMM-Bench] Oleg Solozobov.",
     "[AgentThread] Shenghan Zheng, Qifan Zhang, Zheng Zhang, Haonan Li and Christophe Hauser. *Formal Security Analysis of Agent Protocol Composition.* arXiv:2606.28690, 2026.\n\n"
     "[DEMM-Bench] Oleg Solozobov."),
]

main("T-12-SUBMISSION-satml2027.md", EDITS)
