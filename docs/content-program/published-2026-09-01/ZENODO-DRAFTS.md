# Zenodo drafts — created 2026-09-02

Six **unsubmitted drafts** in the `warrantor` community ("MuVeraAI - Warrantor"). Each carries its
named PDF, the full metadata block, and a **reserved** DOI.

**Nothing is published.** A Zenodo draft is editable and deletable; a *published* record can never
be deleted, only tombstoned. Publishing is the one irreversible step and is deliberately not
automated — open each draft, read it, press Publish. Or, once reviewed: `python
docs/content-program/zenodo_deposit.py --publish`.

| | draft | reserved DOI | pp |
|---|---|---|---|
| **P1** | [22258095](https://zenodo.org/deposit/22258095) | `10.5281/zenodo.22258095` | 7 |
| **P8** | [22258102](https://zenodo.org/deposit/22258102) | `10.5281/zenodo.22258102` | 13 |
| **T04** | [22258108](https://zenodo.org/deposit/22258108) | `10.5281/zenodo.22258108` | 11 |
| **T12** | [22258111](https://zenodo.org/deposit/22258111) | `10.5281/zenodo.22258111` | 30 |
| **P3** | [22258117](https://zenodo.org/deposit/22258117) | `10.5281/zenodo.22258117` | 8 |
| **P6** | [22258119](https://zenodo.org/deposit/22258119) | `10.5281/zenodo.22258119` | 13 |

Verified on each draft after upload: file size matches the PDF on disk exactly; `cc-by-4.0`;
`publication` / `preprint`; creator `Jha, Vikram` with affiliation MuVeraAI and ORCID
0009-0004-3959-6099; community `warrantor`; related identifiers pointing at the GitHub repository
and the `MuVeraAI/guard-verdicts` dataset; state `unsubmitted`.

**Two corrections made while depositing.** The community Vikram created is slugged `warrantor`, not
`muveraai` as the metadata assumed — the deposit script's existence check caught it before anything
was created. And the script had been sending the token as `?access_token=`, which writes a secret
into every access and proxy log it passes; it now sends an `Authorization: Bearer` header.

⚠️ **The Zenodo token in this environment is still the one pasted into a chat transcript** and
should be rotated at <https://zenodo.org/account/settings/applications/tokens>. It works, and these
drafts were created with it; rotating it does not affect them.
