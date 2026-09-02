# Publication set — 2026-09-01 (revision 2, rebuilt 2026-09-02)

**Vikram Jha · MuVeraAI · <vikram@muveraai.com> · ORCID [0009-0004-3959-6099](https://orcid.org/0009-0004-3959-6099)**

Six papers, each in a **named** build carrying the author block and, where one exists, an
**anonymous** build for double-blind submission. Both are generated from the same markdown
source, so they cannot drift apart in content.

## Revision 2 — why the set was rebuilt

The first revision was rejected by a preprint server. Not one rejection concerned the science; all
of it concerned the packaging, and a review of all six sources found the same defects a moderator
would:

- **Every PDF had empty document properties** — no title, no author. An indexer saw six untitled,
  unauthored documents.
- **The papers narrated their own drafting.** "Draft 1 was wrong three times", "that claim is
  withdrawn", "an earlier draft of this section claimed…" — revision bookkeeping printed as content,
  with warning glyphs and struck-through text left in.
- **Literal placeholders shipped**: unfilled blanks (`___ of 9 rows verified`), "(Table A1, appendix
  — 10 rows.)" standing where a cross-reference belonged, a section headed *strip before submission*,
  and a note reading "no author, institution or repository is identified" printed under the author's
  name and ORCID.
- **T-04 had no reference list**; sixteen works were cited inline with no bibliography.

Every retraction, correction and limitation those passages disclosed is **still in the papers** —
restated as a claim about the data rather than about a document version. Beyond the packaging, the
review corrected four substantive errors a reviewer would have caught: T-04 said its two baseline
runs were "four months apart" (seventeen days); T-04 §6 listed as open a route its own §5.5 closed;
P8's limitation 7 said the mechanism was untested and then described testing it; and T-04 named the
wrong first author on an ECCV 2024 citation. T-12's unfilled human-verification count is now stated
as incomplete rather than left blank, and its §3.5/§10 agree with each other on that.

**The build now refuses to emit any of this.** `to_latex.py` carries a deny list of draft-apparatus
patterns and fails the build on a hit; `verify_published.py` checks the PDFs themselves — document
properties, identity block, anonymity, reference section — and `publish.py` copies nothing into
this folder unless that passes.

```
python submission/anonymize.py && python submission/to_latex.py     # anonymous set, gated
python submission/build_preprint.py                                 # named set, gated
(cd submission/tex && latexmk -pdf *.tex); (cd submission/tex-preprint && latexmk -pdf *.tex)
python submission/publish.py --date 2026-09-01                      # verifies, then assembles
```

**Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)** on every paper, stated
on the PDF face. Chosen because it maximises citation and reuse and is compatible with
ACM/IEEE/USENIX preprint policies, so it does not foreclose later journal or conference
submission. It is irrevocable per released version; future versions may be licensed differently.

## The papers

| | title | status | named | anon |
|---|---|---|---|---|
| **P1** | How Reproducible Is a Guard Evaluation? A Measured Floor, and Where It Isn't Small | Novel | 7 pp | 5 pp |
| **P8** | One Ladder, Opposite Directions | Novel, narrowed | 13 pp | 8 pp |
| **T04** | Masking a Field's Loss Does Not Isolate That Field | Novel, bounded | 11 pp | — |
| **T12** | SoK: Acceptance Is Not Action | Systematization | 30 pp | 16 pp |
| **P3** | Positional Guard Evasion at Short Context: A Replication Note | Replication note | 8 pp | 9 pp |
| **P6** | Shared Lineage, Not Shared Category, Makes Guards Fail Together | Replication + extension | 13 pp | 9 pp |

Page counts are from the 2026-09-02 rebuild and verified by `verify_published.py`. The anonymous
builds are two-column venue formats (USENIX, IEEE, ACM), so their page counts are not comparable to
the one-column named preprints.

## Prior-art position, per paper

Stated because three of these six are pre-empted or bounded, and a reader who deposits them
should know which claim each one is actually making.

**P1 — Novel.** No prior work found on run-to-run verdict agreement for guard classifiers at fixed configuration. The prior-art assessment calls it the most likely of the new papers to be genuinely novel.

**P8 — Novel, narrowed.** Prior-art check run BEFORE the design found [Certify] (arXiv:2608.15046) and [QualityProxy] (arXiv:2606.10154); the planned scheme extension was cut as a result. What remains is the object neither measures: a dedicated guard classifier whose verdict IS the measurement.

**T04 — Novel, bounded.** Loss masking failing to isolate a field is documented concurrently; binary targets producing binary behaviour is established practice. Five narrower contributions survive, including the new three-arm target-module ablation (Sec. 5).

**T12 — Systematization.** Assessed as unaffected by the prior-art sweep: its value is the argument, not a priority claim.

**P3 — Replication note.** PRE-EMPTED by LongGuard (arXiv:2608.27580), published four days before P3 was written. Repositioned as a replication at short context on two models LongGuard did not test. An initial reading of the short-range data as refuting length dilution is retracted in the paper, and the retraction was then tested over the full 0–32k range and confirmed (Sec. 4.2.1).

**P6 — Replication + extension.** PRE-EMPTED by [LayeredEns] (arXiv:2608.28327), published three days before the experiment ran. Repositioned as the extension its authors nominated as most valuable: 899 items across 150 clusters against their 100 behaviors. Three claims withdrawn on a full reading of their §11 are stated as withdrawn in the paper's limitations.

## Deposit metadata

Identical for every paper. Zenodo mints a versioned DOI, so v2 of a paper stays linked to v1 —
which is the property that matters for work still under development.

```
Author        Vikram Jha
Affiliation   MuVeraAI
ORCID         0009-0004-3959-6099
Contact       vikram@muveraai.com  (corresponding author)
Licence       CC BY 4.0
Type          Preprint
Suggested     cs.CR (primary), cs.LG (secondary)
```

## What each folder holds

- `<TAG>-named.pdf` — the named preprint. Deposit this.
- `<TAG>-named.tex` — its LaTeX source. Needs `../preamble-preprint.tex`, included here.
- `<TAG>-anon.pdf` — the double-blind build, where one exists. **Do not deposit this**; it
  is for venue submission only.
- the paper's markdown source, which is the authority both builds are generated from.

## Known gap

**T12's bibliography covers 23 of the 49 screened works.** A `References` section was built on
2026-09-01 by resolving every arXiv identifier appearing in the paper or its coding records against
the arXiv API — 23 entries, comprising all 15 works that carry a full two-coder record plus 8 cited
in the text. Titles and author lists are as arXiv records them, not as this paper's tables summarise
them.

**The other 26 screened works are not enumerated anywhere in the released material.** §5.1 discloses
why: the screening payload truncated at the 55th of 322 candidate records, and its output was never
persisted. That is a disclosed process defect in the paper itself, not something introduced here, and
the corpus is explicitly **not closed** until the November freeze. The References section says so in
its own header rather than presenting 23 entries as though they were the corpus.
