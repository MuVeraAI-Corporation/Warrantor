"""P6 v3 — a reference to a section that does not exist, the strata the difficulty control
uses, and a survivor count that is reported three ways without saying which test each is."""
from _lib import main

EDITS = [
    ("**Research paper · 2026-08-31 · Vikram Jha**",
     "**Research paper · 2026-09-05 · Vikram Jha**"),

    ("**Our design is theirs.** For each pair, stratify by a leave-out difficulty score — how many of the\n"
     "*other four* guards miss that item — which keeps the stratifier independent of the pair under test.",
     "**Our design is theirs.** For each pair, stratify by a leave-out difficulty score — how many of the\n"
     "*other four* guards miss that item, giving five strata from 0 to 4 — which keeps the stratifier\n"
     "independent of the pair under test."),

    ("`R7` **10 of 15 pairs retain significant association after conditioning**, against their 1 of 15. The\n"
     "survivors are structured by family:",
     "`R7` **10 of 15 pairs retain significant association after conditioning** on the permutation test of\n"
     "the stratified φ, against their 1 of 15; §5.5b re-runs the comparison with their own estimator and\n"
     "finds 8, or 10 on a cluster-robust interval. The survivors are structured by family:"),

    ("1. **The headline is a replication.** [LayeredEns] published it first and developed it further (§0).",
     "1. **The headline is a replication.** [LayeredEns] published it first and developed it further\n"
     "   (prefatory note)."),
]

main("P6-composition-independence-paper.md", EDITS)
