# Publication set — revision 3, built 2026-09-05

**Vikram Jha · MuVeraAI · <vikram@muveraai.com> · ORCID [0009-0004-3959-6099](https://orcid.org/0009-0004-3959-6099)**

Supersedes `../published-2026-09-01/` (revision 2, the set that is currently public on Zenodo).
Same six papers, same pipeline, same licence. **Nothing here is on Zenodo yet**: the v3 records
are staged by `../zenodo_new_version.py` as drafts and published by a person. Until that happens
the concept DOIs on each PDF's face resolve to revision 2.

## Why the set was rebuilt

Revision 2 fixed the packaging. Revision 3 is a depth review of the science, done by re-deriving
the papers' figures from their own per-item artifacts rather than from their summaries. Every
number added below was recomputed from the run records on the experiment volumes on 2026-09-05,
and the scripts that did so are named in the `revise/v3_*.py` docstrings.

**Three of the six had a defect a reviewer would have stopped at.**

- **T12 mislabeled one of its fifteen scored works as the authors' own system**, in six table
  cells and one sentence. The coding record shows the work is AIP (arXiv:2603.24775) — its
  enforceability surrogate is Table A3 row 9 verbatim — and the paper's own pair arithmetic
  (69/16/20 of 105) only balances with AIP placed at A1. §9's System W is not among the fifteen.
  Corrected throughout; AIP's coder disagreement (A1 against A4) added to the robustness table.
- **P3 claimed novelty in the sentence that replicated LongGuard**, said the positional ordering
  "holds at every individual length in both models" when the 0.6B's 1× cell reverses it (start 6,
  middle 5 of 100 — the only per-length table shown was the 4B's), and ran Fisher tests on
  pooled cells that count every payload three times. Paired tests on the matched cells are now
  reported and are stronger: 30 of 30 discordant cells fall the same way in the 4B.
- **T04 said its ablation control was "a retrain of run 1"** when run 1 trained on a 38,694-row
  mixture and the control on an 11,272-row corpus; the run it reproduces is the 2026-08-22
  ExpGuard run. It also never received the follow-up its own revision note of 2026-08-31 wrote
  the paragraphs for: T04-X2 (`2a223cac`), which reproduces the masked-field drift at two scales
  on Aegis with all 111 moved verdicts going Unsafe→Safe, and T04-X, the format-acquisition
  failure mode found on the way. Both are in §7 now, verified against the stage-2 records.

**Three carried findings their own data contradicted or extended.**

- **P1's two unstable items flip together, in the same four of eighteen runs, and every flip
  crosses the Safe/Controversial boundary.** The paper had said they "flip roughly half the
  time" (12 of 28 pairs is a 2-vs-6 split, not 4-vs-4) and listed inspecting them as future
  work. The unit of instability is the run, not the item; the floor lives in the model's own
  undecided class; and under the other setting of the severity policy the floor would be one
  item, not two. The Artifact section and the prior-art scope note also never reached the v1 or
  v2 PDF — both sat after the References heading, which the builder treats as the end of the
  body. Wilson interval added; companion floor cited by DOI; the unrecorded serving-stack
  version disclosed as the gap it is.
- **P8** verified: every c and b in the §5.8 damage-law table re-fits to three decimals from the
  margin capture. The margin itself was never defined; it is now. Four cross-reference defects
  fixed (§0 does not exist; §5.5 should be §5.6; "two of the three" lists four).
- **P6**: the difficulty control's strata stated; the three survivor counts (10, 8, 10) each
  attributed to the test that produced them.

**Every paper now carries its Zenodo concept DOI on the face**, resolving to the latest version,
and the named-build verifier checks it; the anonymous-build verifier refuses any Zenodo DOI, since
a DOI resolves to the author. Companion papers are cited by DOI where a manuscript label stood
before, and the anonymizer withholds those citations under double-blind as it does the manuscript
ones.

## The papers

| | title | named | anon | Δ vs rev. 2 |
|---|---|---|---|---|
| **P1** | How Reproducible Is a Guard Evaluation? A Measured Floor, and Where It Isn't Small | 9 pp | 6 pp | +2 / +1 |
| **P8** | One Ladder, Opposite Directions | 13 pp | 8 pp | 0 / 0 |
| **T04** | Masking a Field's Loss Does Not Isolate That Field | 12 pp | — | +1 |
| **T12** | SoK: Acceptance Is Not Action | 31 pp | 15 pp | +1 / −1 |
| **P3** | Positional Guard Evasion at Short Context: A Replication Note | 9 pp | 9 pp | +1 / 0 |
| **P6** | Shared Lineage, Not Shared Category, Makes Guards Fail Together | 13 pp | 9 pp | 0 / 0 |

All eleven PDFs pass `submission/verify_published.py` (document properties, identity block and
concept DOI on the named builds, empty author and no DOI on the anonymous ones, no draft
apparatus, a References section, plausible length). All six LaTeX archives in `latex-zips/`
were extracted into an empty directory and compiled to the same page count as the PDF beside
them, by `submission/make_latex_zips.py`. Zero LaTeX errors in any build. Overfull boxes: T04 3
and T12 39 in the named tree, all in wide tables and all present in revision 2 (T04 3, T12 40);
none elsewhere in the named tree.

## Build

```
python submission/revise/v3_<tag>.py        # the edits, each matched exactly once, already applied
python submission/anonymize.py && python submission/to_latex.py
python submission/build_preprint.py
(cd submission/tex && latexmk -pdf *.tex); (cd submission/tex-preprint && latexmk -pdf *.tex)
python submission/publish.py --date 2026-09-05
python submission/make_latex_zips.py --out published-2026-09-05/latex-zips
```

## Zenodo

```
python zenodo_new_version.py --folder published-2026-09-05              # dry run
python zenodo_new_version.py --folder published-2026-09-05 --yes-create # stages six DRAFTS
```

Then open each draft, read it, and publish it — or put the draft ids in
`zenodo_publish_drafts.py` and run that. Publishing is the one irreversible step and stays a
human's. A revision under a concept DOI keeps every citation of the earlier version valid.

The token in the environment is the one pasted into chat on 2026-09-02 and should be rotated
before it is used again.

## What each folder holds

- `<TAG>-named.pdf` — the named preprint. Deposit this.
- `<TAG>-named.tex` — its LaTeX source. Needs `../preamble-preprint.tex`, included here.
- `<TAG>-anon.pdf` — the double-blind build, where one exists. Venue submission only.
- the paper's markdown source, which both builds are generated from.
- `latex-zips/<TAG>.zip` — flat, compile-verified source archive for a venue that wants LaTeX.

## Known gap, unchanged

T12's bibliography now enumerates 24 of the 49 screened works (AgentThread was cited without an
entry in revision 2). The other 25 remain unenumerated until the November corpus freeze, for the
reason §5.1 discloses. Human verification of T12's nine load-bearing rows is still incomplete and
the paper says so.
