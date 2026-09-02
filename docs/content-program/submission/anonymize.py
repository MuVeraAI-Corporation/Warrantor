#!/usr/bin/env python3
"""Anonymize the five finished papers for double-blind submission.

DESIGN RULE: every replacement is an EXPLICIT pattern, never a blind sweep, and the OUTPUT is
re-scanned against a deny list afterwards. A silent no-op here means an identifying string ships in
a submission, which is the one failure that cannot be corrected after the fact.

WHAT IS REMOVED
  1. The author byline.
  2. Self-citations to unpublished companion work, rewritten to anonymous keys WITH THEIR SECTION
     LOCATORS PRESERVED. Third-party citations are untouched; anonymizing those would damage the
     paper.
  3. Possessive framing that identifies a coordinated body of work by one group ("this program",
     "our own prior work"). Referring to companion work in the third person is standard under
     double-blind; claiming it as ours is what deanonymizes.

WHAT IS DELIBERATELY KEPT
  - Pre-registration hashes. They identify a frozen document, not a person, and they are the
    paper's evidence of pre-registration. A reviewer cannot resolve a bare SHA-256 to an author.
  - Dates, every third-party citation, and every number.

TWO DEFECTS THIS FILE NOW GUARDS AGAINST, both found while writing it:
  - A bare bracket pattern for the companion-paper key matched only the closing-bracket form and
    left seven citations such as "[T-03 section 5.7]" dangling against an [Anon-A] reference entry.
    The locator forms are handled explicitly and the locator text is preserved.
  - Editing this script through a shell heredoc turned a backreference into a literal 0x01 byte,
    which was then written into the output markdown. The deny list now rejects control bytes.
"""
from __future__ import annotations

import io
import os
import re
import sys

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "drafts")
OUT = os.path.dirname(os.path.abspath(__file__))

#: The publication set. P2 excluded on purpose; see to_latex.py for why.
PAPERS = [
    "P1-reproducibility-floor-paper.md",
    "P3-position-not-length-paper.md",
    "P6-composition-independence-paper.md",
    "P8-quantization-equivalence-paper.md",
    "T-12-SUBMISSION-satml2027.md",
]

BYLINE = re.compile(r"\*\*(?:Research paper|Replication note|Systematization|Draft) [^\n]*?Vikram Jha\*\*")
ANON_BYLINE = "**Anonymous submission — under double-blind review**"

#: (pattern, replacement) applied in order. Order matters: reference-list entries before inline
#: citation keys, specific phrasings before the backstops.
RULES = [
    # The companion entry reads "Manuscript, 2026." in the named sources (it once read
    # "Draft 4, 2026-08-31", which was revision bookkeeping and was removed from every paper).
    (r"\[T-03\] V\. Jha\. \*Measuring Guard Models: Asymmetry, Transfer, and the Instruments That\s+"
     r"Cannot See\s+Them\.\* Manuscript, 2026\.",
     "[Anon-A] Anonymous. *Companion submission; title withheld for review.* Under review, 2026."),
    (r"\[T-03([^\]]*)\]", "[Anon-A\\g<1>]"),
    (r"\[T-04([^\]]*)\]", "[Anon-B\\g<1>]"),
    (r"\[T-12([^\]]*)\]", "[Anon-C\\g<1>]"),
    # Bare PROSE references, e.g. "T-03 `R42` records ...". The bracketed rules above cannot see
    # these, and the deny list caught one in P8 after the first clean run. Written as a citation so
    # the sentence still reads correctly.
    (r"(?<!\[)\bT-03\b", "[Anon-A]"),
    (r"(?<!\[)\bT-04\b", "[Anon-B]"),
    (r"(?<!\[)\bT-12\b", "[Anon-C]"),
    # T-01 caught by the deny list on the first T-12 run, in prose rather
    # than in brackets: "reconciles this enumeration with T-01's classes".
    (r"(?<!\[)T-01(?![0-9])", "[Anon-D]"),

    (r"our own prior work documents", "companion work documents"),
    (r"What this means for our own prior work", "What this means for the companion studies"),
    (r"results from the same program", "results from the companion studies"),
    (r"[Pp]rior work in this program", "Companion work"),
    (r"experiments in this program", "companion experiments"),
    (r"the others in this program", "the others in this series"),
    (r"other corpora in this program", "other corpora in the companion studies"),
    (r"every other measurement in this program", "every other measurement in the companion studies"),
    (r"used throughout this program", "used throughout the companion studies"),
    (r"confound this program was built to eliminate",
     "confound the companion studies were built to eliminate"),
    (r"Most findings in this program", "Most findings in the companion studies"),
    (r"this program's stratified serving-noise floor",
     "the companion studies' stratified serving-noise floor"),
    (r"this program recorded", "the companion studies recorded"),
    (r"in this program", "in the companion studies"),
    (r"this program", "the companion studies"),
]

def flex(pat: str) -> str:
    """Let a literal space in a pattern match ANY run of whitespace, including a newline.

    ⚠️ THIS EXISTS BECAUSE OF A REAL MISS. The source markdown is hard-wrapped near 100 columns, so
    a phrase like "Prior work in this program" is stored as "Prior work in this\\nprogram". Every
    rule below originally used a literal space, so the replacements skipped those instances AND the
    deny-list scan reported the file clean. The survivors were only caught by scanning the built
    PDF, where LaTeX had reflowed the text and the line break was gone.

    The lesson generalizes: a checker that reads the source cannot see a defect the source's line
    wrapping creates. Both this function and the PDF-level check in verify_submission.py exist for
    that reason and neither replaces the other.
    """
    return re.sub(r"[ ]+", r"\\s+", pat)


NOTE = (
    "\n> **Anonymization note.** Author, affiliation and the identity of companion submissions are\n"
    "> withheld for double-blind review. Citations of the form `[Anon-*]` are unpublished companion\n"
    "> work by the same authors and are anonymized accordingly; **all third-party citations are\n"
    "> intact**. Pre-registration hashes are retained deliberately: they are this paper's evidence\n"
    "> of pre-registration, and a SHA-256 identifies a frozen document rather than a person.\n"
)

CONTROL = "[" + "".join(chr(c) for c in list(range(0, 9)) + [11, 12] + list(range(14, 32))) + "]"

#: Nothing here may survive into an anonymized file. Checked against the OUTPUT, not the input.
DENY = [
    (r"Vikram", "author name"),
    (r"\bJha\b", "author name"),
    (r"MuVeraAI", "organization"),
    (r"AumOS", "program name"),
    (r"Warrantor", "program name"),
    (r"warrantor-runs", "repository path"),
    (r"C:[\\/]Users", "local path"),
    (r"M:[\\/]Project", "local path"),
    (r"this program", "possessive program framing"),
    (r"our own prior work", "possessive program framing"),
    (r"\bT-\d\d\b", "internal companion-paper label"),
    (CONTROL, "control byte -- a shell heredoc once injected one of these"),
]


def anonymize(name):
    src = io.open(os.path.join(SRC, name), encoding="utf-8").read()
    out, log = src, []

    new, n = BYLINE.subn(ANON_BYLINE, out)
    if n:
        log.append(f"{n:>3}x  author byline removed")
    out = new

    for pat, rep in RULES:
        new, n = re.subn(flex(pat), rep, out)
        if n:
            log.append(f"{n:>3}x  {pat[:60]}")
        out = new

    m = re.search(re.escape(ANON_BYLINE) + r"\n", out)
    if m:
        out = out[:m.end()] + NOTE + out[m.end():]
        log.append("  +  anonymization note inserted")
    return out, log


def main():
    failures = 0
    for name in PAPERS:
        out, log = anonymize(name)
        # Every anonymized output MUST be named distinctly from its source. The original
        # rule only rewrote "-paper.md", so a differently-named draft kept its own
        # filename -- harmless only because OUT is a different directory, and one layout
        # change away from overwriting the draft it was generated from.
        anon_name = (name.replace("-paper.md", "-anon.md") if name.endswith("-paper.md")
                     else name[:-3] + "-anon.md")
        assert anon_name != name, "anonymized output must not reuse the source filename"
        dest = os.path.join(OUT, anon_name)
        io.open(dest, "w", encoding="utf-8", newline="\n").write(out)
        print("=" * 90)
        print(f"{name}\n   -> {os.path.basename(dest)}   ({len(out.split())} words)")
        for line in log:
            print("   " + line)

        hits = []
        for pat, why in DENY:
            # flex() here too: the deny scan missed line-wrapped phrases for the same reason the
            # replacements did, and reported a file clean that still said "this program".
            for mm in re.finditer(flex(pat), out, re.I):
                ctx = re.sub(r"\s+", " ", out[max(0, mm.start() - 40):mm.end() + 40])
                hits.append(f"[{why}] ...{ctx}...")
        if hits:
            failures += 1
            print(f"   DENY-LIST HITS: {len(hits)}")
            for h in hits[:8]:
                print("      " + h)
        else:
            print("   deny-list scan: CLEAN")

    print("\n" + "=" * 90)
    if failures:
        print(f"FAILED: {failures} file(s) still contain identifying content. Nothing may ship.")
        return 1
    print(f"All {len(PAPERS)} papers anonymized. No deny-list pattern survives in any output.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
