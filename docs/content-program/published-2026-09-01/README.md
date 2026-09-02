# Publication set — 2026-09-01

**Vikram Jha · MuVeraAI · <vikram@muveraai.com> · ORCID [0009-0004-3959-6099](https://orcid.org/0009-0004-3959-6099)**

Six papers, each in a **named** build carrying the author block and, where one exists, an
**anonymous** build for double-blind submission. Both are generated from the same markdown
source, so they cannot drift apart in content.

**Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)** on every paper, stated
on the PDF face. Chosen because it maximises citation and reuse and is compatible with
ACM/IEEE/USENIX preprint policies, so it does not foreclose later journal or conference
submission. It is irrevocable per released version; future versions may be licensed differently.

## The papers

| | title | status | named | anon |
|---|---|---|---|---|
| **P1** | How Reproducible Is a Guard Evaluation? A Measured Floor, and Where It Isn't Small | Novel | 8 pp | 5 pp |
| **P8** | One Ladder, Opposite Directions | Novel, narrowed | 13 pp | 8 pp |
| **T04** | Masking a Field's Loss Does Not Isolate That Field | Novel, bounded | 11 pp | — |
| **T12** | SoK: Acceptance Is Not Action | Systematization | 30 pp | 16 pp |
| **P3** | Positional Guard Evasion at Short Context: A Replication Note | Replication note | 8 pp | 5 pp |
| **P6** | Shared Lineage, Not Shared Category, Makes Guards Fail Together | Replication + extension | 13 pp | 7 pp |

## Prior-art position, per paper

Stated because three of these six are pre-empted or bounded, and a reader who deposits them
should know which claim each one is actually making.

**P1 — Novel.** No prior work found on run-to-run verdict agreement for guard classifiers at fixed configuration. The prior-art assessment calls it the most likely of the new papers to be genuinely novel.

**P8 — Novel, narrowed.** Prior-art check run BEFORE the design found [Certify] (arXiv:2608.15046) and [QualityProxy] (arXiv:2606.10154); the planned scheme extension was cut as a result. What remains is the object neither measures: a dedicated guard classifier whose verdict IS the measurement.

**T04 — Novel, bounded.** Loss masking failing to isolate a field is documented concurrently; binary targets producing binary behaviour is established practice. Five narrower contributions survive, including the new three-arm target-module ablation (Sec. 5).

**T12 — Systematization.** Assessed as unaffected by the prior-art sweep: its value is the argument, not a priority claim.

**P3 — Replication note.** PRE-EMPTED by LongGuard (arXiv:2608.27580), published four days before P3 was written. Repositioned as a replication at short context on two models LongGuard did not test; Draft 1's refutation of length dilution is RETRACTED and the retraction was then tested and confirmed (Sec. 4.2.1).

**P6 — Replication + extension.** PRE-EMPTED by [LayeredEns] (arXiv:2608.28...), published three days before the experiment ran. Repositioned as the extension its authors nominated as most valuable: 899 items across 150 clusters against their 100 behaviours.

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

**T12 has no reference section.** It cites four arXiv identifiers inline and its 48-work
corpus lives in companion artifacts (`T-12-corpus-v1.md`, `-v2.md`), which carry no arXiv
identifiers of their own. A systematization submitted without a bibliography will draw a
reviewer comment. Building one means recovering each work's identity from
`drafts/corpus-codings/` — real work, and not something to guess at.
