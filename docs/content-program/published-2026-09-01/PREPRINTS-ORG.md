# preprints.org — assessed, not used

**Decision 2026-09-02: these six papers are not being posted to preprints.org.** Zenodo is their
canonical home. Nothing was submitted; no compliance attestation was ticked.

## Why, in their own words

Two findings from the [Instructions for Authors](https://www.preprints.org/instructions-for-authors),
read before any attestation:

**1. It recommends against exactly this.**

> We recommend against posting the same paper to multiple preprint servers. Metrics may be
> underestimated when a manuscript is posted on multiple preprint servers, and readers may be
> confused by duplicate postings across platforms. […] it is recommended that all versions of a
> manuscript be hosted on the same preprint server to maximize transparency and ensure the
> completeness of the record.

All six are on Zenodo as `publication_type: preprint` with permanent DOIs. And a second posting
would be equally permanent:

> preprints cannot be completely removed once online. Once a digital object identifier (DOI) is
> registered, information about the preprint is permanently available.

**2. A PDF is not an accepted manuscript file.**

> Files should be submitted in Microsoft Word or LaTeX format.

This one is solved rather than blocking — see `latex-zips/`.

## What exists if this is revisited

- **`latex-zips/*.zip`** — six compliant LaTeX archives, each verified by extracting into an empty
  directory and compiling: same page counts as the published PDFs.
- **The submission flow, mapped.** Five steps: Subjects and Topics → Basic Info → Author List →
  Declarations → Manuscript Files. Account is logged in as Vikram Jha; no submissions exist; two
  empty drafts sit in *My Preprints → Draft* (one expires 2026-10-02, one 2026-09-23).
- **Two gates need a human**: the policy-compliance checkbox on the *Start a Submission* dialog,
  and the native file picker at step 5. A browser cannot drive either.
- **One open question for the author.** preprints.org follows the COPE position on AI: use of AI
  tools *"should be properly documented in the Methods section."* T-12 documents its LLM coders in
  §3.5; the other five say nothing about AI assistance in manuscript preparation. If any applies it
  belongs in the paper, not in a form field.

## Operational note

Do not guess URLs on this site. `/user/dashboard` and `/user/manuscript` both 404, and a 404 poisons
the Nuxt app so badly the submission form silently refuses to advance past step 1 — no error, no
network request. Navigate by clicking, and open a fresh tab if the form stops responding.
