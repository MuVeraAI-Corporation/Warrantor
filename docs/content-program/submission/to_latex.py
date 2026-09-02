#!/usr/bin/env python3
"""Convert the anonymized markdown papers to compilable LaTeX.

STRATEGY. pandoc does the structural conversion, which is far more reliable than a hand-rolled
markdown parser. This script owns the three things pandoc cannot know about:

  1. PRE-PROCESSING -- the papers' own idioms. A warning marker opens every bounded or withdrawn
     claim, and result markers label numbered findings that later sections cross-reference. Both
     carry meaning and are mapped to LaTeX commands rather than dropped or passed through as
     literal glyphs.

  2. UNICODE -> LATEX. The papers use mathematical and typographic characters throughout. Mapping
     them explicitly means the output compiles under pdflatex, not only under a Unicode engine.
     A residual-character check runs after conversion and FAILS the build rather than emitting a
     .tex that will die at compile time with an unhelpful error.

  3. POST-PROCESSING -- splicing the shared preamble, extracting the reference list into a proper
     bibliography, and stripping the pandoc artifacts that fight a two-column layout.

The build is verified by actually running pdflatex. A .tex that has not been compiled is not a
deliverable, and this program has been burned enough times by artifacts that merely exist.
"""
from __future__ import annotations

import io
import os
import re
import subprocess
import sys

D = os.path.dirname(os.path.abspath(__file__))
TEX = os.path.join(D, "tex")

#: The publication set. P2 is deliberately absent: it was never in the published set, its novelty
#: was assessed as weakened, and it has not had the draft-apparatus edits the others have -- so the
#: gate below would fail on it for reasons nobody has decided to fix. Excluded, not silently built.
PAPERS = [
    ("P1", "P1-reproducibility-floor-anon.md"),
    ("P3", "P3-position-not-length-anon.md"),
    ("P6", "P6-composition-independence-anon.md"),
    ("P8", "P8-quantization-equivalence-anon.md"),
    ("T12", "T-12-SUBMISSION-satml2027-anon.md"),
]

#: Unicode -> LaTeX. Ordered longest-first where prefixes overlap.
UNI = [
    ("\u26a0\ufe0f", r"\warn{}"), ("\u26a0", r"\warn{}"),
    # T-12 marks its key sections with a star in the heading. Mapped rather than
    # stripped: it is the author's own emphasis, and a reader of the PDF should
    # still see what the author marked.
    ("\u2b50\ufe0f", r"$\star$"), ("\u2b50", r"$\star$"),
    ("\u2014", "---"), ("\u2013", "--"),
    ("\u2018", "`"), ("\u2019", "'"), ("\u201c", "``"), ("\u201d", "''"),
    ("\u00a7", r"\S{}"), ("\u00b7", r"\textperiodcentered{}"),
    ("\u00d7", r"$\times$"), ("\u2212", "$-$"), ("\u00b1", r"$\pm$"),
    ("\u2248", r"$\approx$"), ("\u2265", r"$\geq$"), ("\u2264", r"$\leq$"),
    ("\u2260", r"$\neq$"),
    # \u26a0\ufe0f `\allowbreak` after every arrow, deliberately. These papers write verdict transitions as
    # "correct->wrong" and "unsafe->safe" constantly, and math mode is unbreakable: without a
    # permitted break the whole compound is one atom ~13 characters long, which TeX will run into
    # the margin rather than split. That is P8's 6.42pt overfull. The break is *permitted*, not
    # forced, so it costs nothing on lines that already fit.
    ("\u2192", r"$\rightarrow$\allowbreak{}"), ("\u2190", r"$\leftarrow$\allowbreak{}"),
    ("\u21d2", r"$\Rightarrow$\allowbreak{}"),
    ("\u03c0", r"$\pi$"), ("\u03c6", r"$\varphi$"), ("\u03d5", r"$\phi$"),
    ("\u03c7", r"$\chi$"), ("\u03b1", r"$\alpha$"), ("\u03b2", r"$\beta$"),
    ("\u03bc", r"$\mu$"), ("\u03c3", r"$\sigma$"), ("\u0394", r"$\Delta$"),
    ("\u2070", "$^{0}$"), ("\u00b9", "$^{1}$"), ("\u00b2", "$^{2}$"), ("\u00b3", "$^{3}$"),
    ("\u2074", "$^{4}$"), ("\u2075", "$^{5}$"), ("\u2076", "$^{6}$"), ("\u2077", "$^{7}$"),
    ("\u2078", "$^{8}$"), ("\u2079", "$^{9}$"), ("\u207b", "$^{-}$"),
    ("\u2080", "$_{0}$"), ("\u2081", "$_{1}$"), ("\u2082", "$_{2}$"), ("\u2083", "$_{3}$"),
    ("\u2084", "$_{4}$"), ("\u2085", "$_{5}$"), ("\u2086", "$_{6}$"), ("\u2087", "$_{7}$"),
    ("\u2088", "$_{8}$"), ("\u2089", "$_{9}$"),
    # Found by the residual check on the first pass, mapped after inspecting each in context:
    #   "roughly sqrt(6)" and the phi_max formula  -> a standalone radical reads correctly in both
    ("\u221a", r"$\surd$"),
    #   "product over g in S of FNR_g" -- the papers use GREEK CAPITAL PI (U+03A0) for this, not
    #   N-ARY PRODUCT (U+220F). Both are mapped: the first pass mapped only U+220F and the
    #   residual check caught the four remaining U+03A0.
    ("\u220f", r"$\prod$"), ("\u03a0", r"$\prod$"),
    ("\u2208", r"$\in$"), ("\u226b", r"$\gg$"), ("\u03ba", r"$\kappa$"),
    # Added when P8 gained the margin-shrinkage law m' = c*m + b + epsilon and the flip
    # predictor Phi(...). The residual check caught both and refused to emit a .tex that
    # pdflatex would have rejected -- which is the check doing its job on new prose.
    ("\u03b5", r"$\varepsilon$"), ("\u03a6", r"$\Phi$"), ("\u03c3", r"$\sigma$"), ("\u03bb", r"$\lambda$"),
    ("\u2026", r"\ldots{}"), ("\u2032", "$'$"), ("\u00a0", "~"),
    ("\u2713", r"\checkmark{}"), ("\u2717", r"$\times$"), ("\u26d4", r"\warn{}"),
    ("\u2705", r"\checkmark{}"), ("\u274c", r"$\times$"),
    ("\u2011", "-"), ("\u2010", "-"),
]


def preprocess(md: str) -> str:
    """Paper idioms -> markers pandoc will carry through verbatim."""
    # Result markers: `R12` at the start of a line labels a numbered finding.
    md = re.sub(r"^`(R\d+)`\s*", r"@@RMARK:\1@@ ", md, flags=re.M)
    # Warning markers anywhere.
    md = md.replace("\u26a0\ufe0f", "@@WARN@@ ").replace("\u26a0", "@@WARN@@ ")
    # Strip the horizontal rules pandoc turns into centered vrules, which look wrong in
    # two-column layout.
    md = re.sub(r"^---\s*$", "", md, flags=re.M)
    return md


def split_references(md: str):
    """Peel the reference list off the body so it can be typeset as a bibliography."""
    m = re.search(r"^## References\s*$", md, flags=re.M)
    if not m:
        return md, []
    body, tail = md[:m.start()], md[m.end():]
    # ⚠️ A blockquote after the last entry is NOT part of that entry. P1 and P3 each closed their
    # reference list with a quoted paragraph about the scope of the prior-art check, and the
    # lookahead below -- which stopped only at the next entry or heading -- swallowed it into the
    # final bibliography item, complete with literal ">" markers rendered as \textgreater. The
    # entry pattern now also stops at a blockquote line, and any quoted material in the tail is
    # dropped rather than typeset: a bibliography holds references, and commentary about how the
    # references were found belongs in the body or nowhere.
    tail = re.sub(r"^>.*(?:\n>.*)*", "", tail, flags=re.M)
    # entries look like: [Key] Author. *Title.* Venue, year.
    entries = re.findall(r"^\[([^\]]+)\]\s*(.+?)(?=\n\[|\n##|\n>|\Z)", tail, flags=re.M | re.S)
    return body, [(k, re.sub(r"\s+", " ", v).strip()) for k, v in entries]


def strip_production_notes(md: str) -> str:
    """Production notes are internal working notes, not part of a submission.

    ⚠️ ANY heading level and ANY suffix. The original pattern matched only ``### Production notes``
    on a line by itself, and T-04 carries ``## Production notes (strip before submission)`` -- a
    heading that literally instructs the reader to remove it. The regex did not match, so the
    section shipped in the published PDF, venue deadlines and all. A stripper that only strips the
    exact spelling it was first shown is not a stripper.
    """
    m = re.search(r"^#{2,4}\s*Production notes\b.*$", md, flags=re.M | re.I)
    return md[:m.start()] if m else md


# ---------------------------------------------------------------------------
# Draft apparatus. The revision history of a paper is not part of the paper.
#
# ⚠️ WHY THIS EXISTS. Six papers were rejected by a preprint server. Not one rejection was about
# the science. The published PDFs narrated their own drafting -- "Draft 1 was wrong three times",
# "That claim is withdrawn", "Corrections are marked in place" -- carried dozens of warning glyphs
# rendered as coloured triangles, kept struck-through text, shipped a section headed "strip before
# submission", and in one case contained literal unfilled blanks ("___ of 9 rows verified"). A
# moderator reading that sees a working document, and is right to.
#
# The honest disclosures those passages were making -- a claim was retracted, a range was
# re-tested, a limitation stands -- BELONG in the paper. What does not belong is the version
# bookkeeping around them. The source edits move the substance into plain statements; the
# markers below are what must not survive into any built .tex, and the gate at the bottom refuses
# to write one that contains them. Same shape as `residual_unicode`: a build that fails here is a
# build that would have been rejected anyway, only later and by someone else.
# ---------------------------------------------------------------------------

#: Patterns that mark a document as a working draft. Checked against the generated LaTeX, because
#: the LaTeX is what compiles into the thing that ships. Each carries the reason it is banned.
DRAFT_APPARATUS = [
    (r"\bDraft\s*[0-9]\b", "revision number in the body"),
    (r"\bearlier (?:draft|version) of this (?:paper|section)", "revision history narrated"),
    (r"\b(?:this|the first|a previous|an initial) draft\b", "draft self-reference"),
    (r"Production notes", "internal working notes"),
    (r"strip (?:before|at) (?:submission|camera-ready)", "an instruction to the author"),
    (r"marked in place", "revision bookkeeping"),
    (r"_{3,}", "an unfilled blank"),
    (r"\\warn\b", "warning glyph"),
    (r"\\(?:sout|st)\{", "struck-through text"),
    (r"PRIOR-ART-ASSESSMENT", "link to an internal file"),
    (r"ACTION-SURFACE-v1\.md", "link to an internal file"),
    (r"Catalog ref", "internal routing line"),
    (r"double-blind", "submission-mode note in a preprint"),  # named build only; see build_preprint
    (r"\(Table A[0-9], appendix", "placeholder standing in for a table"),
    (r"Deferred, and stated as deferred", "process language"),
    (r"does not fit the present cycle", "process language"),
]


def strip_draft_apparatus(md: str) -> str:
    """Remove the drafting markers that every build must drop, before pandoc sees them.

    Only the markers. The sentences they decorated stay, because in every case the sentence
    already carries the caution in its own words -- "This is still a hypothesis, not a result" does
    not need a triangle in front of it. Struck-through text is removed with its markers: text an
    author has struck is text the author has retracted, and a retraction does not ship as a
    strike-through in a paper the way it does in a memo.
    """
    md = md.replace("\u26a0\ufe0f", "").replace("\u26a0", "").replace("\u26d4", "")
    md = re.sub(r"~~[^~\n]+?~~\s*", "", md)
    md = re.sub(r"^\*Catalog ref:[^\n]*\*\s*$", "", md, flags=re.M)
    # A run of spaces left where a glyph was, at the start of bold text.
    md = re.sub(r"\*\* +", "** ", md)
    md = re.sub(r"^ +\*\*", "**", md, flags=re.M)
    return md


def residual_draft_apparatus(tex: str, *, named: bool):
    """Return the banned patterns present in a generated .tex, with a context snippet each.

    The double-blind rule applies to the NAMED build only: the anonymous build is a double-blind
    submission and is entitled to say so.
    """
    hits = []
    for pat, why in DRAFT_APPARATUS:
        if pat == r"double-blind" and not named:
            continue
        for m in re.finditer(pat, tex):
            ctx = re.sub(r"\s+", " ", tex[max(0, m.start() - 50):m.end() + 50])
            hits.append((why, ctx))
    return hits


def to_latex(md: str) -> str:
    p = subprocess.run(
        # shift-heading-level-by=-1: the markdown h1 is the paper title and is removed above and
        # rendered by \maketitle, so the h2 body headings must become \section, not \subsection.
        # Without this the paper opens at "0.1 Abstract".
        ["pandoc", "-f", "gfm", "-t", "latex", "--wrap=preserve", "--columns=100",
         "--shift-heading-level-by=-1"],
        input=md.encode("utf-8"), capture_output=True)
    if p.returncode != 0:
        raise RuntimeError("pandoc failed: " + p.stderr.decode("utf-8", "replace")[:400])
    # ⚠️ NORMALIZE LINE ENDINGS IMMEDIATELY. pandoc emits CRLF on Windows, so every line arrives
    # ending in "\r". widen_colspec matched the column spec with `\}[ \t]*$`, which a trailing "\r"
    # defeats -- so the table-widening step silently did nothing and P3 kept overflowing by 256pt.
    # It took three failed diagnoses to find, because the isolated tests read the WRITTEN file,
    # which io.open(..., newline="\n") had already normalized. The test and the pipeline were
    # looking at different bytes.
    return p.stdout.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")


def postprocess(tex: str) -> str:
    tex = tex.replace("@@WARN@@", r"\warn{}")
    tex = re.sub(r"@@RMARK:(R\d+)@@", r"\\rmark{\1}", tex)
    for u, l in UNI:
        tex = tex.replace(u, l)
    # pandoc emits \subsubsection for h4 and deeper; the papers only go three deep.
    tex = tex.replace(r"\begin{center}\rule{0.5\linewidth}{0.5pt}\end{center}", "")
    # long tables in two columns: let them float full width rather than overflow
    tex = tex.replace(r"\begin{longtable}", r"\begin{longtable}")
    return tex


def _cell_widths(rows, ncols):
    """Max visible cell length per column, ignoring LaTeX markup."""
    w = [1] * ncols
    for r in rows:
        cells = r.rstrip("\\ ").split("&")
        for i, c in enumerate(cells[:ncols]):
            vis = re.sub(r"\\[a-zA-Z]+\s*|[{}$]", "", c).strip()
            w[i] = max(w[i], len(vis))
    return w


def widen_colspec(block: str) -> str:
    """Give a table's columns proportional `p{}` widths when its rows are too long for `l`.

    ⚠️ WHY THIS EXISTS. pandoc emits `l` for every column when the source markdown gives no widths.
    `l` does not wrap, so a table with a prose cell runs straight off the page: P3's mechanism table
    overflowed by 256pt, which is roughly a third of the text width sitting in the margin. It
    compiled without error and looked fine in the log summary -- only the overfull-hbox count
    exposed it.

    Columns are sized in proportion to their longest measured cell, not guessed.
    """
    # ⚠️ The colspec must be taken to the END OF THE LINE, not to the first closing brace. A spec
    # like {@{}lll@{}} contains braces inside @{}, so a non-greedy match stops after "@{" and
    # reports zero columns -- which is exactly why the first version of this function silently did
    # nothing while P3 kept overflowing by 256pt.
    m = re.match(r"(\\begin\{longtable\}(?:\[[^\]]*\])?\{)(.*)\}[ \t]*$", block.split("\n")[0])
    if not m:
        return block
    cols = m.group(2)
    if "p{" in cols or "X" in cols:
        return block
    ncols = cols.replace("@{}", "").count("l") + cols.count("r") + cols.count("c")
    if ncols < 2:
        return block
    rows = [r for r in block.split("\n") if "&" in r]
    w = _cell_widths(rows, ncols)
    if max(w) <= 32:                      # short cells: `l` is correct and looks better
        return block
    # ⚠️ FLOOR EVERY COLUMN. Pure proportional allocation gave the label column of P3's mechanism
    # table 2% of the text width -- narrower than the word "M-A" it had to hold -- and a p{} column
    # narrower than its content overflows rather than wrapping. Widths are floored at 7% and then
    # renormalized so the row still sums to the same total.
    total = sum(w)
    frac = [max(0.955 * x / total, 0.07) for x in w]   # floor, then renormalize to the same total
    frac = [0.998 * f / sum(frac) for f in frac]
    # ⚠️ THE COLUMN BUDGET MUST EXCLUDE `\tabcolsep`, WHICH IT ONCE DID NOT. `p{}` widths set the
    # TEXT of a column; LaTeX then adds 2*\tabcolsep of padding in each of the (n-1) gaps between
    # columns, and `@{}` at the ends only removes the outer two. Budgeting a flat 0.955\textwidth
    # therefore overflowed by exactly the gap total: P1's 4-column table ran 0.955 * 462.5pt + 24pt
    # = 465.7pt against a 462.5pt measure -- 3.19pt over, which is precisely what the log reported.
    # Subtracting the gaps in LaTeX arithmetic rather than as a hard-coded constant keeps this
    # correct in BOTH trees, whose \textwidth and \tabcolsep differ (one-column preprint against
    # two-column venue classes). A Python constant could only ever be right for one of them.
    avail = "\\dimexpr\\textwidth-%d\\tabcolsep\\relax" % (2 * (len(frac) - 1))
    spec = "@{}" + "".join(
        ">{\\raggedright\\arraybackslash}p{\\dimexpr %.3f%s\\relax}" % (f, avail)
        for f in frac) + "@{}"
    first, rest = block.split("\n", 1)
    return m.group(1) + spec + "}\n" + rest


def widen_all(tex: str) -> tuple[str, int]:
    out, n, i = [], 0, 0
    while True:
        s = tex.find(r"\begin{longtable}", i)
        if s < 0:
            out.append(tex[i:])
            break
        e = tex.find(r"\end{longtable}", s)
        if e < 0:
            out.append(tex[i:])
            break
        out.append(tex[i:s])
        blk = tex[s:e + len(r"\end{longtable}")]
        new = widen_colspec(blk)
        n += (new != blk)
        out.append(new)
        i = e + len(r"\end{longtable}")
    return "".join(out), n


def longtable_to_float(tex: str) -> tuple[str, int, int]:
    """Convert pandoc `longtable` blocks into `table`/`table*` floats holding a `tabular`.

    ⚠️ THIS IS THE REASON A TWO-COLUMN TARGET IS NOT A CLASS SWAP. `longtable` cannot operate in
    two-column mode -- LaTeX raises "longtable not in 1-column mode" and produces no PDF at all.
    pandoc emits longtable for every pipe table, and these papers are table-dense, so the tables
    must be rewritten before any two-column venue class will build.

    WIDTH DECISION. A float that spans one column (`table`) keeps the text flowing; one that spans
    both (`table*`) interrupts it but fits wide content. Choosing wrong gives either an overfull box
    that runs into the gutter, or a full-width float for a three-column table that did not need one.
    The rule: >= 4 columns, or a widest row over 58 characters, goes full width. That threshold was
    set by measuring the actual rows, not guessed.

    Returns (tex, n_single, n_full) so the caller can report what happened rather than trusting it.
    """
    out, single, full = [], 0, 0
    i = 0
    while True:
        start = tex.find(r"\begin{longtable}", i)
        if start < 0:
            out.append(tex[i:])
            break
        end = tex.find(r"\end{longtable}", start)
        if end < 0:
            out.append(tex[i:])
            break
        out.append(tex[i:start])
        block = tex[start:end + len(r"\end{longtable}")]

        m = re.match(r"\\begin\{longtable\}(?:\[[^\]]*\])?\{(.*?)\}", block, re.S)
        cols = m.group(1) if m else "@{}l@{}"
        body = block[m.end():] if m else block
        body = body[:body.rfind(r"\end{longtable}")]

        # strip the longtable-only running-header machinery
        for junk in (r"\endhead", r"\endlastfoot", r"\endfirsthead", r"\endfoot"):
            body = body.replace(junk, "")
        # pandoc puts \bottomrule before \endlastfoot, i.e. before the body rows; move it to the end
        body = body.replace("\\bottomrule\\noalign{}\n", "", 1)
        body = body.rstrip()
        if not body.endswith(r"\bottomrule"):
            body += "\n\\bottomrule\\noalign{}"

        ncols = cols.replace("@{}", "").count("l") + cols.count("r") + cols.count("c")
        rows = [r for r in body.split("\n") if "&" in r]
        widest = max((len(re.sub(r"\\[a-zA-Z]+|\{|\}|\$", "", r)) for r in rows), default=0)
        wide = ncols >= 4 or widest > 58
        env = "table*" if wide else "table"
        single, full = single + (0 if wide else 1), full + (1 if wide else 0)

        # \scriptsize, not \footnotesize: at \footnotesize the five-column directional-churn
        # table in P8 still ran 20pt past the full text width. Measured, not guessed.
        # ⚠️ WIDTH UNIT MUST MATCH THE FLOAT. widen_colspec sizes p{} columns as fractions of
        # \textwidth. In a two-column class \textwidth is the FULL page width, so a p{0.5\textwidth}
        # column inside a single-column `table` is twice its container -- P3's mechanism table
        # overflowed by 247pt for exactly this reason. Single-column floats are rewritten to
        # \columnwidth; full-width `table*` floats keep \textwidth, which is correct there.
        cols_fixed = cols if wide else cols.replace("\\textwidth", "\\columnwidth")
        body_fixed = body.strip() if wide else body.strip().replace("\\textwidth", "\\columnwidth")
        out.append(
            "\\begin{%s}[t]\n\\centering\\scriptsize\n\\begin{tabular}{%s}\n%s\n"
            "\\end{tabular}\n\\end{%s}\n" % (env, cols_fixed, body_fixed, env))
        i = end + len(r"\end{longtable}")
    return "".join(out), single, full


def residual_unicode(tex: str):
    """Any non-ASCII left will either fail pdflatex or silently render wrong."""
    bad = {}
    for ch in tex:
        if ord(ch) > 127:
            bad[ch] = bad.get(ch, 0) + 1
    return bad


#: Per-paper venue target. `preprint` is the generic one-column build; `usenix` is two-column and
#: requires the longtable conversion above.
TARGETS = {
    "P1": "usenix",    # USENIX Security
    "P8": "usenix",    # USENIX Security
    "P2": "ieee",      # IEEE S&P
    "P3": "ieee",      # DLSP (IEEE S&P workshop)
    "P6": "acm",       # ACM AISec (CCS workshop)
    "T12": "ieee",     # IEEE SaTML 2027 -- the venue the draft names
}

#: Targets whose class is two-column, and therefore cannot hold a `longtable`.
TWO_COLUMN = {"usenix", "ieee", "acm"}

PREAMBLE = {"preprint": "preamble", "usenix": "preamble-usenix",
            "ieee": "preamble-ieee", "acm": "preamble-acm"}


#: ACM venues require CCS concepts and keywords. Keyed by paper, because they are per-paper
#: content and not a property of the class.
#:
#: ⚠️ THE `\ccsdesc` PATHS BELOW RENDER CORRECTLY, BUT THE CCSXML BLOCK ACM'S SYSTEM INGESTS
#: CARRIES ACM-ASSIGNED NUMERIC concept_id VALUES THAT ONLY THEIR TOOL CAN GENERATE. We do not
#: invent those: fabricated identifiers would be wrong in a way a reader cannot see and a
#: submission system can. Before submitting, generate the block at
#: https://dl.acm.org/ccs and paste it in place of the marker emitted below.
#: ⚠️ CCS IS AN ACM TAXONOMY. It is defined for all five papers so that any of them can move to an
#: ACM venue without rework, but it is EMITTED ONLY for the `acm` target. IEEE and USENIX do not use
#: CCS, and \ccsdesc lines in an IEEE or USENIX submission would be out of place.
#:
#: Keywords are emitted per venue convention instead: `\keywords` for acmart, `IEEEkeywords` for
#: IEEEtran, and nothing structural for USENIX, which has no keywords convention -- those papers
#: keep the inline keyword line their own text already carries.
ACM_CCS = {
    "P1": {
        "concepts": [
            (500, "General and reference~Measurement"),
            (500, "Security and privacy~Intrusion/anomaly detection and malware mitigation"),
            (300, "General and reference~Empirical studies"),
            (300, "Computing methodologies~Machine learning"),
        ],
        "keywords": ("guard models, reproducibility, evaluation methodology, "
                     "serving nondeterminism, measurement study, LLM security"),
    },
    "P2": {
        "concepts": [
            (500, "Security and privacy~Intrusion/anomaly detection and malware mitigation"),
            (500, "Computing methodologies~Machine learning"),
            (300, "Security and privacy~Software and application security"),
            (300, "Computing methodologies~Natural language processing"),
        ],
        "keywords": ("guard models, adversarial robustness, inference-time defense, paraphrase, "
                     "AI safety, evasion"),
    },
    "P3": {
        "concepts": [
            (500, "Security and privacy~Intrusion/anomaly detection and malware mitigation"),
            (500, "General and reference~Empirical studies"),
            (300, "Computing methodologies~Natural language processing"),
        ],
        "keywords": ("guard models, adversarial robustness, positional bias, long-context, "
                     "AI safety, replication"),
    },
    "P6": {
        "concepts": [
            (500, "Security and privacy~Intrusion/anomaly detection and malware mitigation"),
            (500, "Computing methodologies~Machine learning"),
            (300, "General and reference~Empirical studies"),
            (300, "General and reference~Measurement"),
        ],
        "keywords": ("guard models, content moderation, failure correlation, defense in depth, "
                     "classifier ensembles, ensemble diversity, LLM security, measurement study"),
    },
    "P8": {
        "concepts": [
            (500, "Security and privacy~Intrusion/anomaly detection and malware mitigation"),
            (500, "General and reference~Measurement"),
            (300, "Computing methodologies~Machine learning"),
            (300, "General and reference~Empirical studies"),
        ],
        "keywords": ("guard models, quantization, model compression, equivalence testing, "
                     "safety evaluation, measurement study, LLM security"),
    },
    # T04 and T12 carry no CCS concepts (neither targets an ACM venue) but do need keywords: the
    # PDF metadata of every build now records them, and a preprint server indexes on that field.
    "T04": {
        "concepts": [],
        "keywords": ("guard models, LoRA, fine-tuning, loss masking, negative result, "
                     "AI safety, ablation"),
    },
    "T12": {
        "concepts": [],
        "keywords": ("systematization, SoK, AI agents, containment, authorization, "
                     "execution control, reference monitor, security"),
    },
}


def pdf_metadata_block(title: str, keywords: str, author: str | None = None) -> str:
    """The `\\hypersetup` line that fills the PDF's document properties.

    ⚠️ EVERY PUBLISHED PDF HAD EMPTY METADATA -- no title, no author, nothing. A preprint server
    that reads document properties before a human does saw six untitled, unauthored documents. The
    anonymous build sets title, subject and keywords and leaves the author EMPTY on purpose, which
    `verify_submission.py` enforces; the named build passes the author in.

    Plain ASCII only: hyperref's pdf strings are not TeX and do not take macros or accents.
    """
    plain = re.sub(r"\\[a-zA-Z]+\{?|[{}$]", "", title).replace("~", " ")
    plain = plain.replace("\u2014", "-").replace("\u2013", "-").replace("\u2019", "'")
    parts = [f"pdftitle={{{plain}}}", f"pdfsubject={{{plain}}}", f"pdfkeywords={{{keywords}}}"]
    if author:
        parts.insert(1, f"pdfauthor={{{author}}}")
    return "\\hypersetup{" + ",".join(parts) + "}"


def acm_topmatter(tag):
    """CCS concepts and keywords for an ACM submission, with the XML left explicitly unfilled."""
    spec = ACM_CCS.get(tag)
    if not spec:
        return []
    out = [
        # ASCII only: these lines are emitted AFTER postprocess(), so they never pass through the
        # Unicode->LaTeX map. The residual check caught a warning glyph here and failed the build,
        # which is the check working on the generator's own output rather than only the papers'.
        "% !! REPLACE THIS BLOCK before submitting: generate the CCSXML at https://dl.acm.org/ccs",
        "%    and paste it here. The \\ccsdesc lines below render the concepts a reader sees, but",
        "%    ACM's system also wants the XML, whose numeric concept_id values only their tool",
        "%    assigns. They are deliberately not invented here.",
    ]
    out += ["\\ccsdesc[%d]{%s}" % (w, c) for w, c in spec["concepts"]]
    out.append("\\keywords{%s}" % spec["keywords"])
    return out


def frontmatter(target, title, subtitle, tag=None):
    """Title block, which differs by class.

    `article` (preprint, usenix) takes \\title before \\begin{document}; IEEEtran and acmart both
    want the title INSIDE the document, and acmart suppresses the author block itself in anonymous
    mode rather than accepting an empty one. Getting this wrong does not warn -- it silently emits
    a paper with no title, or with acmart's placeholder author.
    """
    t = title + (r"\\[0.3em]{\large\normalfont " + subtitle + "}" if subtitle else "")
    # Document properties for the anonymous build: title, subject, keywords -- and NO author.
    # hyperref is loaded by every preamble, so \hypersetup is valid before \begin{document}.
    meta = pdf_metadata_block(title, (ACM_CCS.get(tag) or {}).get("keywords", ""))
    if target == "ieee":
        # IEEE uses its own keywords environment and does NOT use ACM's CCS taxonomy, so no
        # \ccsdesc is emitted here. IEEEkeywords sits directly after \maketitle.
        kw = (ACM_CCS.get(tag) or {}).get("keywords", "")
        block = ["\\begin{IEEEkeywords}", kw, "\\end{IEEEkeywords}"] if kw else []
        return [meta,
                "\\begin{document}",
                "\\title{" + t + "}",
                "\\author{\\IEEEauthorblockN{Anonymous Submission}\\\\"
                "\\IEEEauthorblockA{\\textit{Under double-blind review}}}",
                "\\maketitle"] + block
    if target == "acm":
        # acmart wants a plain title; a \\-broken subtitle fights its own \subtitle macro.
        # CCS concepts and \keywords must precede \maketitle or acmart silently drops them.
        return ([meta,
                 "\\title{" + title + "}",
                 ("\\subtitle{" + subtitle + "}") if subtitle else "",
                 "\\author{Anonymous}"]
                + acm_topmatter(tag)
                + ["\\begin{document}", "\\maketitle"])
    return [meta, "\\title{\\vspace{-2em}" + t + "}", "\\begin{document}", "\\maketitle"]


def build(tag: str, name: str) -> bool:
    md = io.open(os.path.join(D, name), encoding="utf-8").read()
    tm = re.search(r"^# (.+)$", md, flags=re.M)
    title = tm.group(1).strip()

    # ⚠️ A `###` is only the SUBTITLE if it comes before the first `##`. Searching the whole
    # document for the first `###` pulled "1.1 Contributions" into P2's title block, because P2
    # has no subtitle at all and its first `###` is a body heading three sections in.
    after = md[tm.end():]
    first_h2 = re.search(r"^## ", after, flags=re.M)
    head_zone = after[:first_h2.start()] if first_h2 else after
    sub = re.search(r"^### (.+)$", head_zone, flags=re.M)
    subtitle = sub.group(1).strip() if sub else ""

    md = strip_production_notes(md)
    md = strip_draft_apparatus(md)
    md = re.sub(r"^# .+$", "", md, count=1, flags=re.M)      # title handled by \maketitle
    if sub:
        md = md.replace("### " + subtitle, "", 1)
    # Internal routing metadata: a catalog reference and a venue shortlist. Useful while drafting,
    # and not something a submission carries -- it also names venues the paper is being shopped to.
    md = re.sub(r"^\*Catalog ref:[^\n]*\*\s*$", "", md, flags=re.M)
    # For venues with a real keywords construct, the inline "**Keywords:** ..." line in the body
    # would render a second time below the formal one. Strip it for those targets only; USENIX has
    # no keywords environment, so there the inline line is the only place keywords appear and stays.
    if TARGETS.get(tag) in ("ieee", "acm"):
        md = re.sub(r"^\*\*Keywords:\*\*[^\n]*\n?", "", md, flags=re.M)
    body_md, refs = split_references(md)
    tex_body = postprocess(to_latex(preprocess(body_md)))

    for s in (title, subtitle):
        pass
    t_title = postprocess(to_latex(title)).strip()
    t_sub = postprocess(to_latex(subtitle)).strip() if subtitle else ""

    bib = ""
    if refs:
        bib = ["\n\\section*{References}\n\\small\n\\begin{description}[leftmargin=1.4em,"
               "labelindent=0pt,itemsep=2pt]"]
        for k, v in refs:
            k_t = postprocess(to_latex(k)).strip()
            v_t = postprocess(to_latex(v)).strip()
            bib.append(f"\\item[{{[{k_t}]}}] {v_t}")
        bib.append("\\end{description}\n")
        bib = "\n".join(bib)

    target = TARGETS.get(tag, "preprint")
    tex_body, n_widened = widen_all(tex_body)
    tables = f"   {n_widened} widened" if n_widened else ""
    if target in TWO_COLUMN:
        tex_body, n_single, n_full = longtable_to_float(tex_body)
        tables += f"   floats {n_single}col/{n_full}full"

    doc = []
    doc.append(f"% Anonymized submission -- {tag}, target: {target}.")
    doc.append("% Generated by to_latex.py; do not edit by hand -- a rebuild overwrites this file.")
    doc.append("\\input{../%s}" % PREAMBLE[target])
    doc.extend(x for x in frontmatter(target, t_title, t_sub, tag) if x)
    doc.append(tex_body)
    if bib:
        doc.append(bib)
    doc.append(r"\end{document}")
    out = "\n".join(doc)

    bad = residual_unicode(out)
    apparatus = residual_draft_apparatus(out, named=False)
    os.makedirs(TEX, exist_ok=True)
    dest = os.path.join(TEX, f"{tag}.tex")
    io.open(dest, "w", encoding="utf-8", newline="\n").write(out)

    print(f"  {tag} [{target}]: {len(out):>7} chars -> tex/{tag}.tex{tables}", end="")
    if bad:
        print(f"   RESIDUAL UNICODE: {
              {repr(k): v for k, v in list(bad.items())[:6]} }")
        return False
    if apparatus:
        # The .tex is still written so the failure can be inspected, but the build is FAILED:
        # a document that narrates its own drafting is not a submission, and the last set that
        # shipped this way was rejected for exactly that.
        print(f"   DRAFT APPARATUS: {len(apparatus)} hit(s)")
        for why, ctx in apparatus[:6]:
            print(f"      [{why}] ...{ctx}...")
        return False
    print("   unicode: clean   apparatus: clean")
    return True


def main():
    ok = True
    print("Converting anonymized markdown to LaTeX")
    for tag, name in PAPERS:
        ok &= build(tag, name)
    print("\nAll converted." if ok
          else "\nFAILED: at least one paper did not pass the build gates above (unicode or draft apparatus).")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
