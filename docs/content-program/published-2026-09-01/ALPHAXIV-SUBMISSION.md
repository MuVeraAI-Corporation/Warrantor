# alphaXiv resubmission — 2026-09-02

**Route, verified in a signed-in session on 2026-09-02:** My Library → **My Publications** →
**Publish a Paper**. The dialog reads *"Skip the arXiv queue — your paper is live in minutes.
Discussions, AI Overview, and Audio included. Click to select a PDF file · PDF up to 50 MB."*
Direct PDF upload; **no arXiv identifier is required.**

**The one step that needs a hand:** the dialog opens a native file picker, which a browser cannot
be driven through programmatically (the file input rejects a scripted path by design). Pick each
file below; alphaXiv extracts title, authors and abstract from the PDF itself.

## Upload these six — the `-named.pdf` in each folder, never the `-anon.pdf`

All six were rebuilt on 2026-09-02, verified by `submission/verify_published.py` (document
properties present, identity block on the face, no draft apparatus in the text), and committed as
`4d5068a`. Folder: `docs\content-program\published-2026-09-01\`

| # | file | title | pp |
|---|---|---|---|
| 1 | `P1\P1-named.pdf` | How Reproducible Is a Guard Evaluation? A Measured Floor, and Where It Isn't Small | 7 |
| 2 | `P8\P8-named.pdf` | One Ladder, Opposite Directions | 13 |
| 3 | `T04\T04-named.pdf` | Masking a Field's Loss Does Not Isolate That Field | 11 |
| 4 | `T12\T12-named.pdf` | SoK: Acceptance Is Not Action | 30 |
| 5 | `P3\P3-named.pdf` | Positional Guard Evasion at Short Context: A Replication Note | 8 |
| 6 | `P6\P6-named.pdf` | Shared Lineage, Not Shared Category, Makes Guards Fail Together | 13 |

Suggested order: P1, P8, T04, T12 first (original claims), then P3 and P6 (replication notes).

## If the form asks for anything beyond the file

Every paper: **Vikram Jha · MuVeraAI · ORCID 0009-0004-3959-6099 · vikram@muveraai.com · CC BY 4.0**.
Category: **cs.CR** (primary), **cs.LG** (secondary). Descriptions and keywords, if a field wants
them, are in `../zenodo-depositions.json` and are identical to what Zenodo will receive.

## Why the first submission was rejected, and why this one should not be

The earlier PDFs carried empty document properties, their own revision history in the body,
warning glyphs, struck-through text, unfilled blanks, a section headed "strip before submission",
and (T-04) no reference list. All of it is gone; the build now refuses to emit any of it. If a
rejection recurs, **copy the rejection text into the repo** — the earlier ones were never recorded,
which is why this review had to reconstruct the cause from the PDFs.

## Rejection record

**2026-09-02 ~08:50 PDT — P1 (`P1-named.pdf`, rebuilt 2026-09-02, verified).** Form fully completed:
title and abstract auto-extracted correctly; author "Vikram Jha" linked with "This is me"; publication
date 2026-08-31; categories computer-science / cs.CR / cs.LG; rights attestation ticked. Submitted;
the automated **Review** stage returned, verbatim:

> **Submission rejected.** This paper could not be published automatically. For false positives,
> contact contact@alphaxiv.org.

No reason is given. The review is automated. This is the same outcome as the first round, on a
PDF with none of the first round's packaging defects — so the packaging cannot be *confirmed* as the
cause, and the remaining five were **not** submitted pending an answer from alphaXiv.
