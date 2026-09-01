# Anonymized submission build

**Five papers, anonymized for double-blind review and typeset to compiled PDF. Built 2026-08-31.**

⚠️ **Rebuilt 2026-08-31 after P8 absorbed the margin-capture experiment (§5.8).** P8 went
from 6 pages to 8 and gained two tables. **The other four papers are unchanged** — their page
counts in the table below are identical across the rebuild, which is the check that the rebuild
touched only what it should have.

Everything here is generated. **Edit the source drafts in `../drafts/`, never the files in this
directory** — a rebuild overwrites them.

---

## What is here

| file | what it is |
|---|---|
| `anonymize.py` | drafts → anonymized markdown, with an audit log and an output deny-list scan |
| `to_latex.py` | anonymized markdown → LaTeX, via pandoc plus this program's own idioms |
| `preamble*.tex` | four preambles, one per venue class; see *How the venue builds work* |
| `verify_submission.py` | reads the **built PDFs** and checks they are anonymous and complete |
| `*-anon.md` | the anonymized markdown, five files |
| `tex/*.tex`, `tex/*.pdf` | the generated LaTeX and the compiled PDFs |

## Rebuild

```
python anonymize.py          # drafts -> *-anon.md          (exits 1 on any deny-list hit)
python to_latex.py           # *-anon.md -> tex/*.tex       (exits 1 on residual Unicode)
cd tex && for p in P1 P2 P3 P6 P8; do pdflatex -interaction=nonstopmode $p.tex; done
cd .. && python verify_submission.py    # reads the PDFs    (exits 1 on any hit)
```

Run `pdflatex` twice per paper if you add cross-references; the current build needs one pass.

## Output

| paper | pages | title |
|---|---|---|
| **P1** | 5 | How Reproducible Is a Guard Evaluation? |
| **P2** | 4 | Vary the Input, Not the Decoding |
| **P3** | 5 | Position, Not Length |
| **P6** | 7 | Shared Lineage, Not Shared Category, Makes Guards Fail Together |
| **P8** | 8 | One Ladder, Opposite Directions |

**All five now build two-column against a venue class**, which is why every page count fell from the
earlier one-column preprint build. The one-column `preamble.tex` is retained for any paper without a
target.

## What anonymization does, and does not, remove

**Removed.** The author byline. Self-citations to unpublished companion work, rewritten to
`[Anon-A]`, `[Anon-B]`, `[Anon-C]` **with their section locators preserved** — `[T-03 §5.7]` becomes
`[Anon-A §5.7]`, not a bare key. Possessive framing that identifies a coordinated body of work by
one group ("this program", "our own prior work"); referring to companion work in the third person is
standard under double-blind, claiming it as ours is what deanonymizes.

**Kept, deliberately.** Every pre-registration hash — they are each paper's evidence of
pre-registration, and a reviewer cannot resolve a SHA-256 to a person. Every third-party citation.
Every number. Dates.

**Also kept: strikethrough.** The papers strike through withdrawn claims rather than deleting them,
so a reader can see what was retracted. That is content, and `ulem` is loaded to render it.

## Nine defects this pipeline was built to catch, all of which it caught

1. **A citation pattern that only matched the closing-bracket form**, leaving seven references such
   as `[T-03 §5.7]` dangling against an `[Anon-A]` reference entry.
2. **Bare prose references** (`T-03 \`R42\` records ...`) that no bracketed rule could see. Caught by
   the deny list after a run that had already reported clean.
3. **Line-wrapped phrases.** The source markdown is hard-wrapped near 100 columns, so
   `"Prior work in this program"` is stored as `"Prior work in this\nprogram"`. Every pattern used a
   literal space, so the replacements skipped those instances **and the markdown deny-list scan
   reported the file clean**. They were caught only by scanning the built PDF, where LaTeX had
   reflowed the text. `flex()` in `anonymize.py` now makes every literal space match any whitespace.
4. **A control byte written into a submission file.** Editing `anonymize.py` through a shell heredoc
   turned a regex backreference into a literal `0x01`, which went into the output markdown. The deny
   list now rejects control bytes, and this pipeline is edited with file tools rather than heredocs.

5. **A column budget that ignored `\tabcolsep`.** `widen_colspec` allocated a flat `0.955\textwidth`
   across a table's `p{}` columns. But `p{}` sets the width of a column's *text*, and LaTeX then adds
   `2\tabcolsep` of padding in each of the *(n−1)* gaps between columns — `@{}` at the ends removes
   only the outer two. P1's four-column table therefore came to `0.955 × 462.5pt + 24pt = 465.7pt`
   against a 462.5pt measure: **3.19pt over, which is exactly the `3.18707pt` the log reported.** The
   budget is now `\dimexpr\textwidth-2(n−1)\tabcolsep\relax` in LaTeX arithmetic rather than a Python
   constant, **because the two trees have different `\textwidth` and different `\tabcolsep`, so no
   single constant can be right for both.**
6. **A reference entry that could not be broken.** `[GuardBench]` ends in `arXiv:2605.28830,` — an
   unbreakable token. Justified text cannot break before one, so TeX overfulls rather than stretch:
   **P1's preprint ran 29.9pt, about 1cm, into the margin.** The reference list is now set
   ragged-right, which removes the stretch requirement at its source and is the conventional setting
   for a bibliography anyway. **Only the preprint was affected** — the two-column submission tree has
   a narrower measure, which gives the line breaker more places to break.

7. **An arrow that welded two words into one unbreakable atom.** These papers write verdict
   transitions constantly — `correct→wrong`, `unsafe→safe` — and the arrow converts to math mode,
   which TeX will not break. The compound became a single ~13-character atom that ran **6.42pt** into
   the margin rather than split. Every arrow now emits `\allowbreak` after it. The break is
   *permitted*, not forced, so it costs nothing on a line that already fits.
8. **`\tabcolsep` charged on both sides of every column.** P6's two widest tables keep natural `l`
   columns — correctly, since their cells are short enough that `widen_colspec` should leave them
   alone — but at six columns the gaps alone cost `10 × \tabcolsep`, or 40pt at 4pt. Content plus
   gaps ran 3.5–5.5pt past the measure. The preprint now uses 3pt, freeing 10pt. **Tables with
   explicit `p{}` widths were unaffected either way**, because defect 5 had already made their spec
   track `\tabcolsep` symbolically.
9. **No last-resort stretch, so TeX gave up instead of loosening.** A narrow two-column measure
   carrying an unhyphenatable token (`10-of-15`) left no break within tolerance, and TeX's response
   to that is to overflow the margin, not to set a loose line. `\emergencystretch=1.5em` in all four
   active preambles grants slack **only on the final pass**, so it is a no-op on every paragraph that
   already fits. Verified: it removed the last two overfulls **without introducing a single underfull
   box anywhere.**

⚠️ **Every one of these was invisible to every check except the overfull-hbox count.** Each paper
compiled with exit code 0, produced a correct-looking PDF, and passed the anonymity verifier. **A
build that succeeds is not a build that is right**, which is the same lesson as the four above in a
different layer.

✅ **Current state: zero overfull boxes and zero underfull boxes across all ten documents**, both
trees, with page counts unchanged from before the fixes. That is the number to watch on any future
rebuild — a nonzero count means something moved.

**The general lesson, which is why `verify_submission.py` reads PDFs and not markdown:** a checker
that reads the source cannot see a defect the source's own formatting creates. Both layers exist and
neither replaces the other.


## Two build trees, and they are opposite

| tree | author | for |
|---|---|---|
| `tex/` | **anonymous** | double-blind submission |
| `tex-preprint/` | **NAMED** | a preprint server |

`build_preprint.py` builds the named set from `../drafts/` **directly**, not by reversing
`anonymize.py`. Un-anonymizing would be a lossy inverse of a lossy transform: section locators,
citation keys and possessive phrasing were all rewritten, and reconstructing them would be guesswork.
The drafts are already the named version, so the named build starts there.

It removes only what is internal rather than authorial: production notes, and the catalog line that
names venues being targeted. It keeps the byline, the real citation keys, every hash and every number.

⚠️ **Check which tree a PDF came from before sending it anywhere.** The two are content-identical and
differ only in the author block, the companion-citation keys, and the anonymization note. A named PDF
sent to a double-blind venue is not recoverable.

## Venue targets

| paper | venue | class | pages | why |
|---|---|---|---|---|
| **P1** | **USENIX Security** | reproduced USENIX layout | 5 | full measurement paper |
| **P2** | **IEEE S&P** | **official `IEEEtran`** | 4 | the only one of the five not pre-empted: a failed defense, a mechanism for why, and a working defense |
| **P3** | **DLSP** (IEEE S&P workshop) | **official `IEEEtran`** | 5 | self-declared replication note; DLSP welcomes replication and negative results |
| **P6** | **ACM AISec** (CCS workshop) | **official `acmart`** | 7 | short measurement paper converging with prior art |
| **P8** | **USENIX Security** | reproduced USENIX layout | 6 | full measurement paper |

Targets live in `TARGETS` at the top of `to_latex.py`; changing one is a single line. Any target in
`TWO_COLUMN` is routed through `longtable_to_float()` automatically.

**Overfull hboxes: 0 in P1, P2, P3 and P8; 2 in P6, worst 3.3pt** — under half a percent of column
width and not visible at print size.

### ⚠️ Before submitting

**P2, P3 and P6 use the OFFICIAL vendor classes** (`IEEEtran`, `acmart`), both installed here, so
their layout is the real thing rather than a reproduction. Still check per venue and cycle:

- the **page limit** — this machine cannot browse a CFP, and none of these limits is verified here
- whether the cycle wants a venue-supplied `IEEEtran` variant rather than `[conference]`
- for `acmart`: the correct `\acmConference` line for the cycle
- **P6's CCS concepts and keywords are set** (`ACM_CCS` in `to_latex.py`) and render in
  acmart's own format. ⚠️ **The CCSXML block is deliberately NOT generated.** ACM's system
  ingests numeric `concept_id` values that only their tool at <https://dl.acm.org/ccs>
  assigns; inventing them would be wrong in a way a reader cannot see but a submission system
  can. Generate the block there and paste it over the marker comment near the top of
  `tex/P6.tex`. The `\ccsdesc` lines a reader sees are already correct and need no change.

**P1 and P8 use a reproduced USENIX layout, not the official style file.** No `usenix2019_v3.sty` is
installed and it could not be fetched. Download the current cycle's template, replace the
geometry/font block in `preamble-usenix.tex`, and recompile — pagination may shift.

## How the venue builds work

Four preambles, selected per paper by `TARGETS` in `to_latex.py`:

| preamble | class | used by |
|---|---|---|
| `preamble.tex` | `article`, one column | nothing currently; the fallback for an untargeted paper |
| `preamble-usenix.tex` | `article`, two column, reproduced USENIX geometry | P1, P8 |
| `preamble-ieee.tex` | **official `IEEEtran`**, `[conference]` | P2, P3 |
| `preamble-acm.tex` | **official `acmart`**, `[sigconf,anonymous,review]` | P6 |

⚠️ **A two-column target is not a class swap.** pandoc emits `longtable` for every pipe table and
`longtable` cannot operate in two-column mode — the build fails outright with no PDF. Any target
listed in `TWO_COLUMN` is routed through `longtable_to_float()`, which rewrites each table as a
`tabular` inside a `table` or `table*` float, chosen by measured content width.

⚠️ **Column widths are unit-sensitive.** `widen_colspec()` sizes `p{}` columns as fractions of
`\textwidth`. In a two-column class `\textwidth` is the *full page*, so a single-column float must
have those rewritten to `\columnwidth` — without it P3's mechanism table overflowed by 247pt.

⚠️ **Front matter differs by class.** `article` takes `\title` before `\begin{document}`; `IEEEtran`
and `acmart` want it inside, and `acmart` suppresses the author block itself under `anonymous`.
`frontmatter()` handles this; getting it wrong emits a paper with no title and does not warn.

⚠️ **LaTeX section numbering is off** (`secnumdepth=-2`) in every preamble. The papers carry their own
numbers in the heading text and cross-reference them in prose (`§5.4`, `§7.9`). Letting LaTeX
renumber produces `0.2 1. What this paper is` **and silently breaks every cross-reference**.

## Still outstanding before any of these is submitted

- **P1, P2, P3, P6, P8 are content-complete.** Nothing in this directory is blocked.
- **Every paper has a target** (see *Venue targets*). P2, P3 and P6 use official vendor classes;
  P1 and P8 use a reproduced USENIX layout whose official style file must still be swapped in.
- **`verify_submission.py` checks metadata and extracted text.** `Author` must be empty; `Subject`
  and `Keywords` are scanned for identifying *content* rather than required to be empty, because
  acmart legitimately writes the CCS concepts into `Subject`. An earlier version failed P6 for
  merely having a non-empty `Subject` — a false alarm about correct ACM metadata, and a reminder
  that a check should reject what is wrong rather than what is unfamiliar.
- It does **not** check for embedded fonts carrying a licensee name, nor for revision history in a
  figure. There are no figures in these five papers, so that gap is currently theoretical.
- **One British spelling survives in each of P6 and P8** (`summarise`), inside verbatim quotations
  from a cited paper. It is protected by the quotation carve-out and **must not be corrected** — the
  source spelling stands in a direct quote.
