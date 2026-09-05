"""T-04 v3, second pass — the arm table's rationale cell grew in v3_t04 and pushed the modules
column 9pt into the margin (the only new overfull box in the rebuild). Shortened to the
original's width; the sentence under the table already says what the cell no longer does."""
from _lib import main

EDITS = [
    ("| **A** control | `q,k,v,o,gate,up,down` | run 1's adapter configuration, retrained on this corpus |",
     "| **A** control | `q,k,v,o,gate,up,down` | run 1's configuration, retrained here |"),
    # US English, per the house rule; the verifier flagged it and it predates this revision.
    ("arms B and C would be cancelled rather than",
     "arms B and C would be canceled rather than"),
]

main("T-04-masking-does-not-isolate.md", EDITS)
