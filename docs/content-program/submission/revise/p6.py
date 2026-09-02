"""P6 — remove revision bookkeeping and struck text; every withdrawal stays as a plain statement."""
from _lib import main

EDITS = [
    ("**Draft 3 · 2026-08-31 · Vikram Jha**\n"
     "*Draft 2 revised Draft 1 throughout after reading [LayeredEns] §11 in full; three claims were withdrawn. Draft 3 re-runs the stratification with their own CMH estimator (§5.5b), which turned the paper from a contrast with their result into a convergence with it. All withdrawals are marked in place.*\n",
     "**Research paper · 2026-08-31 · Vikram Jha**\n"),

    ("> **What is left, and it is narrower than Draft 1 claimed.** Their §11.6 runs the difficulty",
     "> **What is left is narrower than a first reading suggested.** Their §11.6 runs the difficulty"),

    ("> ⚠️ **Draft 1 claimed our result was the *opposite* of theirs. That claim is withdrawn** (§5.5,\n"
     "> §5.5b). It was wrong twice over: their §11.6 is underpowered by their own statement, and once the\n"
     "> same estimator is used the two findings agree.\n",
     "> **Our result is not the opposite of theirs, though an initial analysis read it that way** (§5.5,\n"
     "> §5.5b). That reading was wrong twice over: their §11.6 is underpowered by their own statement, and\n"
     "> once the same estimator is used the two findings agree.\n"),

    ("⚠️ **Draft 1 of this paper asserted that φ carries no such ceiling. That was wrong, and the correction\n"
     "comes from [LayeredEns] §11.1**, which gives the bound above,",
     "**φ carries a ceiling too, and the bound comes from [LayeredEns] §11.1**, which gives the bound above,"),

    ("⚠️ **Draft 1 claimed the two groups do not overlap. That claim is withdrawn.** On the normalized",
     "**The two groups overlap.** On the normalized"),

    ("**Reading it against their result.** Ours is not the opposite of theirs, and Draft 1 was wrong to say\n"
     "so. **Given their stated power limitation,",
     "**Reading it against their result.** Ours is not the opposite of theirs. **Given their stated power\n"
     "limitation,"),

    ("#### Where this converges with [LayeredEns], which Draft 1 missed entirely",
     "#### Where this converges with [LayeredEns]"),

    ("**So both studies find the same thing, and Draft 1's framing was wrong.** Shared training",
     "**So both studies find the same thing.** Shared training"),

    ("2. ~~Our reading of [LayeredEns] is partial.~~ **Closed. Their §11 is now read in full, and it\n"
     "   changed three things in this paper**: it supplied the φ_max bound we had denied existed (§5.4), it\n"
     "   showed the family contrast is confounded with that bound (§5.5), and it revealed that their §11.6\n"
     "   is underpowered by their own account — which retired Draft 1's claim that our result was the\n"
     "   opposite of theirs. **Every correction ran against us**, which is the expected direction when a\n"
     "   claim is checked against the source rather than a summary of it.\n",
     "2. **Three claims were withdrawn on a full reading of [LayeredEns] §11**: that φ carries no\n"
     "   marginal ceiling (§5.4), that the family groups do not overlap (§5.5), and that our\n"
     "   stratification result is the opposite of theirs — their §11.6 is underpowered by their own\n"
     "   account. **Every correction ran against us**, which is the expected direction when a claim is\n"
     "   checked against the source rather than a summary of it.\n"),

    ("Machine Learning 51(2), 2003. — cited via [LayeredEns] §4.3;\n"
     "not read in the original for this draft.",
     "Machine Learning 51(2), 2003. — cited via [LayeredEns] §4.3."),

    ("International Journal of Machine Learning and Cybernetics 1, 2010. —\n"
     "cited via [LayeredEns] §4.3; not read in the original for this draft.",
     "International Journal of Machine Learning and Cybernetics 1, 2010. —\n"
     "cited via [LayeredEns] §4.3."),

    ("Them.* Draft 4, 2026-08-31. — source of the corpus, the transformation set, and four of the six",
     "Them.* Manuscript, 2026. — source of the corpus, the transformation set, and four of the six"),
]

main("P6-composition-independence-paper.md", EDITS)
