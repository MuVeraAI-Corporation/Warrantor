# AIWILD Submission Packet — T-04

**Prepared 2026-08-30. Deadline 5 September 2026 AoE — six days.**

> **I have not submitted this and will not.** Submitting requires authenticating into OpenReview
> under your identity and putting your name on research. That is yours to do. Everything below
> exists so it takes minutes rather than an evening.

---

## 1. Verified venue facts

Confirmed against the workshop's own NeurIPS 2026 page on 2026-08-30.

| | |
|---|---|
| Venue | **AIWILD @ NeurIPS 2026** — Third Workshop on Agents in the Wild: Safety, Security, and Beyond |
| **Deadline** | **5 September 2026, Anywhere on Earth** (extended from 29 August) |
| Portal | `https://openreview.net/group?id=NeurIPS.cc/2026/Workshop/AIWILD` |
| Tracks | Regular **9 pages** · Short **4 pages**. References and supplementary excluded |
| Review | **Double-blind. Fully anonymized.** Extends to supplementary material and code. **Anonymity violations face desk rejection** |
| Archival | **Non-archival** |
| Dual submission | Permitted, provided the other venue's policy allows it |
| Template | NeurIPS, ICLR, ICML, ACL or CVPR LaTeX. NeurIPS checklist optional |
| Workshop dates | 11–13 December 2026 (Sydney / Paris / Atlanta) |

⚠️ **One correction worth noting.** A web search returned "6 September, 13:00 UTC, 10 pages." That is
wrong — it appears to conflate this edition with another. The figures above come from the workshop's
own page. **Verify once more yourself before submitting**; deadlines get extended and my read is six
days old the moment I write it.

---

## 2. What is ready

**`T-04-AIWILD-anonymous.md`** — 3,632 words, roughly **8.1 pages** of body text.

- Fits the **regular track (9pp)** with room to spare.
- Does **not** fit the short track (4pp) without cutting roughly half.
- Anonymity audit clean: no author, institution, repository, product name, internal file path, run
  identifier or companion-paper reference.
- US-English gate: pass.
- Zero placeholders. Every figure is from recorded run documents.

---

## 3. Submission metadata — copy and paste

**Title**

> Masking a Field's Loss Does Not Isolate That Field: Two Rejected LoRA Runs on a Structured-Output Guard Model

**Abstract** — use the paper's abstract verbatim; it is already written to length and already
concedes its prior work in the third paragraph.

**Suggested topic tags** (from the workshop's stated interests): agent safety and alignment ·
security vulnerabilities · benchmarking and evaluation · post-training.

**One-line pitch, if a field asks for it**

> Two rejected fine-tuning runs measuring what happens to an unsupervised output field when its
> neighbor is tuned under a shared adapter, and the governance failure that follows when a masked
> field is a policy surface.

---

## 4. Decisions only you can make

**4.1 Author list and affiliation.** Not in the anonymized file, by design. You add them at
camera-ready, not at submission.

**4.2 Does this paper go out at all?** Read §6 before deciding. It discloses that **the raw per-item
outputs no longer exist** — the results directory was never committed — so every number is
reproducible only by re-running the evaluation. That is disclosed honestly and it is a real weakness
a reviewer may press on. Non-archival status makes it a low-cost outing, but it is still your name.

**4.3 Regular or short.** Regular at 8.1pp is the natural fit. Short would need the paper cut in
half, and the section that would have to go is §3's run-1 account, which is what makes §4 legible.

**4.4 Artifact.** The workshop's anonymity policy **extends to code and supplementary material.** The
honest position is that there is no artifact to release: the raw outputs are gone. Submitting without
one is consistent with §6, but do not gesture at an artifact that does not exist.

**4.5 Dual submission.** The paper's production notes also name IEEE SaTML 2027 (29 September) and
TMLR. AIWILD permits concurrent submission; **check the other venue's policy before relying on it**,
and note that SaTML shares a deadline window with the companion systematization.

---

## 5. Format conversion — the only real work left

The paper is Markdown. The workshop wants LaTeX in one of five templates.

| Step | Note |
|---|---|
| 1. Get the NeurIPS 2026 style files | Any of the five accepted templates works; NeurIPS is the safest default |
| 2. Convert Markdown to LaTeX | `pandoc T-04-AIWILD-anonymous.md -o t04.tex` gets most of the way |
| 3. Rebuild the six tables | Pandoc's table output usually needs hand-fixing; the tables carry the argument, so check each |
| 4. Verify the anonymous build | Compile, then re-read the PDF for anything the conversion reintroduced — file paths in listings are the usual culprit |
| 5. Check page count in the real template | 8.1pp is my estimate at ~450 words per page. **Measure it, do not trust the estimate** |
| 6. Strip PDF metadata | `exiftool -all= t04.pdf`. Author fields in PDF metadata are a classic de-anonymization route and are exactly what a desk-reject policy catches |

**Step 6 is the one people forget**, and this workshop desk-rejects for anonymity violations.

---

## 6. Suggested order, given six days

| When | What |
|---|---|
| Today | Re-verify the deadline on the workshop page. Decide 4.2 — whether it goes out at all |
| Day 1–2 | Convert to LaTeX, rebuild tables, compile |
| Day 3 | Read the compiled PDF cold, as a reviewer would. Check page count and anonymity in the built artifact, not the source |
| Day 4 | Strip PDF metadata. Create or sign in to OpenReview. Submit |
| Day 5 | Buffer. **Do not plan to submit on the deadline** — AoE is generous but portals fail |

---

## 7. What I would flag to a reviewer if I were you

Three things in this paper are unusually honest, and they are its strength rather than its risk. Lead
with them rather than letting a reviewer find them:

1. **The novelty claim was withdrawn** after a literature check refuted it, and §7 says so in its
   first three sentences. The surviving contributions are stated at the width the evidence supports.
2. **Both runs failed.** The paper reports rejections, not results, and an automated gate's two
   differently-worded verdicts are what make the second run interpretable.
3. **The raw outputs are gone**, disclosed in §6 rather than papered over.

A reviewer who finds those honest will value the paper. One who does not was never going to accept a
negative-results submission.
