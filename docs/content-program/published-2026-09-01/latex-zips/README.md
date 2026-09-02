# LaTeX source archives — for preprints.org

preprints.org does **not** accept a PDF as the manuscript file. Its Instructions for Authors:

> Files should be submitted in Microsoft Word or LaTeX format. For LaTeX files, ensure that all
> files necessary, including the .bib file, if applicable, to recreate the PDF are included in a
> zip or similar archive.

Each zip here holds `<TAG>.tex` plus `preamble-preprint.tex`, flat. The `\input{../preamble-preprint}`
in the build tree is rewritten to `\input{preamble-preprint}` **in the zip copy only** — a submitted
archive is extracted flat, so the `../` path would resolve to nothing and the compile would fail on
their side, where nobody can fix it.

Verified 2026-09-02: every zip extracted to an empty directory and compiled with `latexmk -pdf`,
producing the same page count as the published PDF — P1 7, P8 13, T04 11, T12 30, P3 8, P6 13.
No `.bib` is needed; the bibliographies are `\begin{description}` blocks, not BibTeX.

**Regenerate** with the snippet in the commit that added this folder, after any rebuild of
`submission/tex-preprint/`.
