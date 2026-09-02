"""P1 byline normalisation, and two "this draft" self-references in P6 the gate pattern did not cover.

Found by a wider grep after the first pass, not by the gate. The gate has since gained the pattern.
"""
import sys

from _lib import revise

rc = 0
rc |= revise("P1-reproducibility-floor-paper.md", [
    ("**Research paper · Draft 1 · 2026-08-31 · Vikram Jha**",
     "**Research paper · 2026-08-31 · Vikram Jha**"),
])
rc |= revise("P6-composition-independence-paper.md", [
    ("> A literature check run **before** this draft surfaced **Alotaibi et al. [LayeredEns]**, published",
     "> A literature check run **before** this analysis surfaced **Alotaibi et al. [LayeredEns]**, published"),
    ("> developed considerably further.** Their §11 is read in full for this draft.",
     "> developed considerably further.** Their §11 is read in full."),
])
sys.exit(rc)
