# Zenodo — PUBLISHED 2026-09-02

Six **published records** in the `warrantor` community ("MuVeraAI - Warrantor"), each with a
permanent DOI. Published 2026-09-02 on Vikram's explicit instruction, after a dry-run verification
of all six against the PDFs on disk.

**These are permanent.** A published Zenodo record cannot be deleted, only tombstoned. Corrections
require publishing a *new version* under the same concept DOI, not editing these.

| | record | DOI | pp |
|---|---|---|---|
| **P1** | [22258095](https://zenodo.org/records/22258095) | [`10.5281/zenodo.22258095`](https://doi.org/10.5281/zenodo.22258095) | 7 |
| **P8** | [22258102](https://zenodo.org/records/22258102) | [`10.5281/zenodo.22258102`](https://doi.org/10.5281/zenodo.22258102) | 13 |
| **T04** | [22258108](https://zenodo.org/records/22258108) | [`10.5281/zenodo.22258108`](https://doi.org/10.5281/zenodo.22258108) | 11 |
| **T12** | [22258111](https://zenodo.org/records/22258111) | [`10.5281/zenodo.22258111`](https://doi.org/10.5281/zenodo.22258111) | 30 |
| **P3** | [22258117](https://zenodo.org/records/22258117) | [`10.5281/zenodo.22258117`](https://doi.org/10.5281/zenodo.22258117) | 8 |
| **P6** | [22258119](https://zenodo.org/records/22258119) | [`10.5281/zenodo.22258119`](https://doi.org/10.5281/zenodo.22258119) | 13 |

Verified on each record before publishing, and again after via the public API: file size matches the PDF on disk exactly; `cc-by-4.0`;
`publication` / `preprint`; creator `Jha, Vikram` with affiliation MuVeraAI and ORCID
0009-0004-3959-6099; community `warrantor`; related identifiers pointing at the GitHub repository
and the `MuVeraAI/guard-verdicts` dataset. All six now resolve publicly with
`state=published` and the correct PDF attached.

**A bug caught before it mattered.** `zenodo_deposit.py --publish` would NOT have published these
drafts: its `deposit()` creates a new deposition on every call, so it would have made six *more*
records, published those, and left the six reviewed drafts orphaned — the reviewed artifact and the
published one would have been different objects. `zenodo_publish_drafts.py` publishes by id, and
re-verifies each record against the PDF on disk immediately before the irreversible call.

**Two corrections made while depositing.** The community Vikram created is slugged `warrantor`, not
`muveraai` as the metadata assumed — the deposit script's existence check caught it before anything
was created. And the script had been sending the token as `?access_token=`, which writes a secret
into every access and proxy log it passes; it now sends an `Authorization: Bearer` header.

⚠️ **The Zenodo token in this environment is still the one pasted into a chat transcript** and
should be rotated at <https://zenodo.org/account/settings/applications/tokens>. It works, and these
drafts were created with it; rotating it does not affect them.
