#!/usr/bin/env python3
"""Build the NON-ANONYMOUS preprint set, for a preprint server.

⚠️ THIS BUILD CARRIES THE AUTHOR NAME. It is the exact opposite of the submission build and the two
must never be confused. They are kept in separate trees for that reason alone:

    tex/           anonymous   — for double-blind submission
    tex-preprint/  NAMED       — for a preprint server

DESIGN: built from `../drafts/` DIRECTLY, not by reversing `anonymize.py`. Un-anonymizing an
anonymized file would be a lossy inverse of a lossy transform -- the section locators, the citation
keys and the possessive phrasing were all rewritten, and reconstructing them would be guesswork.
The drafts are already the named version, so the named build starts there and only removes the
things that are internal rather than authorial.

REMOVED FROM A PREPRINT (internal, not authorial):
  - production notes: working notes to ourselves about what still needs doing
  - the catalog reference line, which carries internal routing and names venues being targeted

KEPT (this is the point of the named build):
  - the author byline, rendered as a proper author block
  - real citation keys and the reference entries that define them
  - every pre-registration hash, every number, every withdrawn-claim marker
"""
from __future__ import annotations

import io
import os
import re
import sys

D = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, D)
import to_latex as T   # noqa: E402  -- shared conversion, deliberately not duplicated

DRAFTS = os.path.join(os.path.dirname(D), "drafts")
OUT = os.path.join(D, "tex-preprint")

PAPERS = [
    ("P1", "P1-reproducibility-floor-paper.md"),
    ("P2", "P2-input-variation-defense-paper.md"),
    ("P3", "P3-position-not-length-paper.md"),
    ("P6", "P6-composition-independence-paper.md"),
    ("P8", "P8-quantization-equivalence-paper.md"),
    ("T04", "T-04-masking-does-not-isolate.md"),
    ("T12", "T-12-SUBMISSION-satml2027.md"),
]

# ---------------------------------------------------------------------------
# Author identity. NAMED BUILD ONLY.
#
# These live here rather than in the shared `to_latex.py` on purpose: the anonymous
# submission build imports that module, and a constant it can import is a constant it
# can leak. Keeping identity in the named-only path makes anonymity a property of the
# module graph rather than of anyone remembering to strip a field.
#
# The byline in each source markdown stays the authority for WHO wrote the paper -- the
# build refuses if it cannot read one. What follows is the contact and licence detail a
# markdown byline has nowhere to put.
# ---------------------------------------------------------------------------
AFFILIATION = "MuVeraAI"
EMAIL = "vikram@muveraai.com"
ORCID = "0009-0004-3959-6099"
LICENCE_NAME = "CC BY 4.0"
LICENCE_URL = "https://creativecommons.org/licenses/by/4.0/"

BYLINE = re.compile(
    r"\*\*(?:Research paper|Replication note|Systematization|Draft)[^\n]*?·\s*(\d{4}-\d{2}-\d{2})\s*·\s*([^*\n]+?)\*\*")

NOTE = (
    "\n> **Preprint.** This is the named version of a paper prepared for peer review. The anonymized\n"
    "> submission build is identical in content; only the author block, the companion-paper citation\n"
    "> keys and the anonymization note differ.\n")


def build(tag, name):
    md = io.open(os.path.join(DRAFTS, name), encoding="utf-8").read()

    m = BYLINE.search(md)
    if not m:
        raise AssertionError(f"{tag}: no byline found -- refusing to build a named version whose "
                             f"author cannot be read from the source")
    date, author = m.group(1), m.group(2).strip()

    tm = re.search(r"^# (.+)$", md, flags=re.M)
    title = tm.group(1).strip()
    after = md[tm.end():]
    h2 = re.search(r"^## ", after, flags=re.M)
    sub = re.search(r"^### (.+)$", after[:h2.start()] if h2 else after, flags=re.M)
    subtitle = sub.group(1).strip() if sub else ""

    md = T.strip_production_notes(md)
    # The double-blind line is a submission artifact, not content. It must not survive
    # into a named preprint that carries the author's name three lines above it.
    md = re.sub(r"^\*Submitted to .*double-blind review\.\*\s*$", "",
                md, flags=re.M)
    md = re.sub(r"^# .+$", "", md, count=1, flags=re.M)
    if sub:
        md = md.replace("### " + subtitle, "", 1)
    md = re.sub(r"^\*Catalog ref:[^\n]*\*\s*$", "", md, flags=re.M)
    md = BYLINE.sub("", md, count=1)
    # put the preprint note where the byline was
    md = re.sub(r"(^\s*\n)", NOTE + r"\1", md, count=1)

    body_md, refs = T.split_references(md)
    body = T.postprocess(T.to_latex(T.preprocess(body_md)))
    body, n_wide = T.widen_all(body)          # one-column, so longtable stays: no float conversion

    t_title = T.postprocess(T.to_latex(title)).strip()
    t_sub = T.postprocess(T.to_latex(subtitle)).strip() if subtitle else ""
    t_author = T.postprocess(T.to_latex(author)).strip()

    bib = ""
    if refs:
        # ⚠️ `\raggedright` is deliberate and load-bearing, not styling. A reference entry ends in
        # an unbreakable token -- "arXiv:2605.28830," -- and justified text cannot break before one,
        # so TeX overfulls rather than stretch the line: P1 ran 29.9pt, about 1cm, into the margin.
        # Ragged-right removes the stretch requirement entirely, and is the conventional setting for
        # a bibliography in any case. The two-column submission tree does not need this because its
        # narrower measure gives the line breaker more places to break.
        parts = ["\n\\section*{References}\n\\small\n"
                 "\\begin{description}[leftmargin=1.4em,labelindent=0pt,itemsep=2pt]\n"
                 "\\raggedright"]
        for k, v in refs:
            parts.append("\\item[{[%s]}] %s"
                         % (T.postprocess(T.to_latex(k)).strip(),
                            T.postprocess(T.to_latex(v)).strip()))
        parts.append("\\end{description}\n")
        bib = "\n".join(parts)

    doc = [f"% PREPRINT (NAMED) -- {tag}. Generated by build_preprint.py; do not edit by hand.",
           "% The anonymous submission build of this paper is in ../tex/.",
           "\\input{../preamble-preprint}",
           "\\title{\\vspace{-2em}" + t_title
           + (r"\\[0.35em]{\large\normalfont " + t_sub + "}" if t_sub else "") + "}",
           "\\author{" + t_author
           + "\\\\[0.30em]{\\normalsize " + AFFILIATION + "}"
           + "\\\\[0.18em]{\\small ORCID~\\href{https://orcid.org/"
           + ORCID + "}{" + ORCID + "}}"
           + "\\\\[0.18em]{\\small Corresponding author:~\\href{mailto:"
           + EMAIL + "}{" + EMAIL + "}}}",
           "\\date{" + date + "}",
           "\\begin{document}",
           "\\maketitle",
           "\\begin{center}\\small\\vspace{-1.1em}",
           "\\textcopyright~" + date[:4] + " " + t_author
           + ". Licensed under \\href{" + LICENCE_URL + "}{" + LICENCE_NAME + "}.",
           "\\end{center}",
           body]
    if bib:
        doc.append(bib)
    doc.append("\\end{document}")
    out = "\n".join(doc)

    bad = T.residual_unicode(out)
    os.makedirs(OUT, exist_ok=True)
    io.open(os.path.join(OUT, f"{tag}.tex"), "w", encoding="utf-8", newline="\n").write(out)
    status = "unicode: clean" if not bad else f"RESIDUAL UNICODE: {list(bad)[:5]}"
    print(f"  {tag}: author={t_author!r} date={date}  {n_wide} widened  {status}")
    return not bad


def main():
    print("Building the NAMED preprint set -> tex-preprint/")
    ok = True
    for tag, name in PAPERS:
        ok &= build(tag, name)
    print("\nAll built." if ok else "\nFAILED: residual unicode.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
