"""P8, second pass — one sentence the build gate found that the first pass missed."""
from _lib import main

EDITS = [
    ("*is* the decision was untested by them or by anyone**, and an earlier draft of this paper listed it\n"
     "   as a gap we could not close. We closed it. **The law is theirs;",
     "*is* the decision was untested by them or by anyone.** **The law is theirs;"),
]

main("P8-quantization-equivalence-paper.md", EDITS)
