# Existing Estate — Inventory and Gap Analysis

> Inventory pass: **2026-08-30**. Scope agreed: this repo plus the LinkedIn Blitzkrieg project.
> The website and wider social folders were not swept and may contain further overlap.

The premise this program was almost built on — that there is no content estate yet — is wrong.
There is a large one. What follows is what exists, what is now stale, and where the actual holes
are. **Every entry in the catalog is tagged NEW, REFRAME or SUPERSEDES against this page.**

---

## 1. What exists

| Asset | Location | Volume | Character |
|---|---|---|---|
| Research papers | `aumos/docs/html/papers/` | **24** HTML papers, 7.5k–36k bytes | Position / design papers |
| Technical blog series | `aumos/docs/html/blog-series/` | **8** articles + index | Practitioner essays, component-ID mapped |
| Curated reading list | `aumos/docs/curated-reading-list.md` | **101** entries, 57 domains | Mapped to 66 component/protocol IDs |
| Component & protocol RFCs | `aumos/docs/rfcs/` | **65** documents | The technical evidence base |
| Cross-cutting docs | `aumos/docs/cross-cutting/` | 10 documents | Threat model, compliance, DID identity |
| Editorial Arsenal | Blitzkrieg `blog_topics_master.html` | **120** topics | Business track, revenue-mapped |
| Distribution channels | `aumos/docs/distribution-channels.md` | 114 lines | Packaging/registry reach, not content |

The 24 papers, in order: verifiable agent authority · cross-language canonical signing · agent
action receipt · delegation intersection semantics · attested inference pipelines · DP federated
training with TEE · confidential GPU composition · the privacy budget paradox · safetensors++ ·
tamper-evident model lineage · AI bill of materials · training-time integrity · sandbox boundary
attestation · the AI kill switch · eBPF exfiltration prevention · retrospective transcript analysis
· unified adversarial testing · conformance as a service · bias and copyright auditing · Elo arena
ranking · AAE OSAF standard · AAR OSAF standard · open harness specification · AI artifact trust
manifest.

---

## 2. The five gaps that matter

### Gap 1 — The papers argue design. None of them carry evidence. **(the big one)**

Twenty-four papers make architectural arguments. Not one is grounded in a measurement you actually
took. You have now cleared four categories of real evidence for disclosure — guard benchmark
results, architecture and code, fine-tuning runs including the negative results, and field/build
failure findings — and **none of it appears anywhere in the estate.**

This is the difference between a paper a program committee desk-rejects and one it reviews. It is
also the difference between a blog post a CISO skims and one they forward. The single highest-value
move in this program is not another topic; it is putting numbers under the arguments that already
exist.

**Consequence:** the empirical papers in Track 1 are ranked first, and several are explicitly
SUPERSEDES against existing papers rather than new titles.

### Gap 2 — The strongest US citation in the field is missing

The **NSA MCP Cybersecurity Information Sheet (20 May 2026)** does not appear in the 101-source
reading list, which was compiled on 2026-08-09 — eleven weeks later. Neither does **OCC Bulletin
2026-13 / Fed SR 26-2** appear as a primary anchor, nor **NIST COSAiS**. The list is excellent on
protocol and infrastructure primaries (SPIFFE/SPIRE, sigstore, in-toto, OCSF) and thin on the
supervisory and national-security record that a North American buyer actually cites.

### Gap 3 — Geographic imbalance, in both directions

The Blitzkrieg arsenal's regulatory spine is **India** — RBI, SEBI, IRDAI, DPDP, KYC master
directions, board accountability. It is genuinely deep there. The repo estate is **regulator-neutral
to EU-leaning**: paper 10 leads with EU AI Act compliance, paper 19 leads with EU AI Act auditing.

Both are off-doctrine. Primary markets are **US/North America, GCC and India**; the EU gets a
passing mention where factually required and leads nothing. So the estate is simultaneously
over-indexed on India in the business track, over-indexed on the EU in the technical track, and
**almost silent on the US supervisory record and the GCC entirely** — despite Saudi declaring 2026
the Year of AI and SDAIA accreditation becoming a government-contract prerequisite.

### Gap 4 — The estate predates your own hardest-won findings

These are recorded in project memory as things you learned, and none has been written up:

- **The mediation ceiling.** Full mediation of a terminal coding agent is impossible via MCP. There
  is a precise defensible claim to make instead. The estate does not make it — and several papers
  imply the stronger claim.
- **The three enforcement tiers.** "Enforced" currently conflates cryptographic bounds, OS bounds
  and proxy-chokepoint bounds. No netns/seccomp/firewall enforcement exists; the honest answer is
  composition with a sandbox. Paper 13 (sandbox boundary attestation) and paper 14 (kill switch)
  both need this distinction and neither has it.
- **No new trust root.** The design principle that unblocked identity, anchoring and the trust
  directory — build the weaker thing, name what it does not establish. This is a publishable idea
  and it is unwritten.
- **The Windows-ungated-path finding.** CI runs the whole workspace but only on Ubuntu, so every
  `#[cfg(windows)]` path was untested — and that hid a real kill-switch contract breach. This is a
  verification-claims story with teeth, and it is the kind of thing that earns trust precisely
  because it is unflattering.

### Gap 5 — Stale protocol ground under the newest work

`blog-series/07-inference-mcp-a2a-delegation.html` predates **MCP 2026-07-28**, the largest revision
since launch — stateless core, authorization hardening, Enterprise-Managed Authorization now
production-grade. The delegation argument in that article rests on assumptions the spec no longer
makes. This needs a REFRAME.

---

## 3. What is genuinely good and should not be rebuilt

Stated plainly, because the temptation with a catalog this size is to redo everything:

- The **65 RFCs** are the real asset. They are the evidence base most of the new work draws on.
- The **component/protocol ID system** (T1…X11, P1…P12) is a working spine for cross-referencing.
  The new catalog reuses it rather than inventing a parallel taxonomy.
- The **Editorial Arsenal's method** — composite cases, epitaphs, clause-by-clause regulatory
  decoding, the self-audit rubric — is strong and transferable. The business track lifts the method
  and re-points it at US/NA and GCC anchors.
- **Papers 21–24** (the OSAF standards: AAE, AAR, open harness, AATM) are the right shape for
  standards-body submission. They need a venue and a verified regulatory frame, not a rewrite.

---

## 4. Disposition of the existing 24 papers

| Disposition | Papers | Action |
|---|---|---|
| **Ground with evidence** | 01, 03, 13, 14 | Rewrite as empirical papers with measured results — Track 1 T-01…T-04 |
| **Correct a claim** | 13, 14 | Must adopt the three-tier enforcement distinction before republication |
| **Re-anchor regulator** | 10, 19 | EU-led → US/India/GCC-led; EU demoted to passing mention |
| **Venue and submit** | 21, 22, 23, 24 | Standards channel; needs the COSAiS and NSA CSI frame |
| **Hold as-is** | 02, 04–09, 11, 12, 15–18, 20 | Sound; not the constraint right now |

---

## 5. Read next

- [`04-verified-anchors.md`](04-verified-anchors.md) — every external fact this program is allowed
  to cite, verified 2026-08-30
- [`01-track-technical.md`](01-track-technical.md) — Track 1, the technical catalog
