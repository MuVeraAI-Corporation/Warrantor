# AumOS Technical Blog Series — Multi-Phase Production Plan

**Series title:** *The Open Authority & Evidence Stack*  
**Location:** `aumos/docs/html/blog-series/`  
**Doctrine:** Local-only HTML; US/India/GCC regulatory anchors; depth over stubs; no fabricated citations.

## Finite article series (8 pieces + master index)

| # | Slug | Primary clusters | Protocols | Components (examples) |
|---|------|------------------|-----------|------------------------|
| 00 | `index.html` | Master map (all) | P1–P12 | All via matrix |
| 01 | `01-verifiable-agent-authority.html` | trust / identity / policy | P1, P7, P12 | T1, T2, I1, I2, R4, R5, R6 |
| 02 | `02-runtime-containment-kill-switch.html` | runtime | P12, P7, P1 | R1–R8, S6, X2 |
| 03 | `03-confidential-gpu-attestation.html` | confidential | P12 | C1-1…C1-5, N4 |
| 04 | `04-ai-supply-chain-sbom-lightwell.html` | supply | P5, P6, P11 | S1–S9, T1 |
| 05 | `05-evidence-plane-aar-ocsf.html` | evidence | P2, P3, P4, P9 | E1, X9, X2 |
| 06 | `06-eval-redteam-veb-conformance.html` | eval | P8 | A1–A8, X5, X6 |
| 07 | `07-inference-mcp-a2a-delegation.html` | inference / multi-agent | P5, P10, P1 | N1–N4, X8, I1 |
| 08 | `08-federated-edge-sovereign-stack.html` | federated / cross-cut | P3, P11 | F1–F4, X1, X7, X10, X11 |

Every portfolio cluster and every protocol P1–P12 appears in the master index matrix (dedicated article and/or explicit section cross-link).

## Ordered phases (required pipeline)

| Phase | Name | Owner | Output artifact |
|-------|------|-------|-----------------|
| **1** | Source research | research-agent workers | `meta/phase1-research-notes.md` + scratch research logs |
| **2** | Outline freeze | implementer | This plan § series table + per-article section skeletons |
| **3** | Full draft | implementer (+ parallel writers if used) | Article HTML bodies |
| **4** | Visual enrichment | implementer | ≥2 visuals/article (SVG diagrams, matrices, protocol field maps, comparison tables) |
| **5** | Adversarial review | review subagent (separate pass) | `meta/phase5-adversarial-review.md` + scratch review log |
| **6** | Fix pass | implementer | Updated HTML + citation repairs |
| **7** | Verification gate | test suite | `test_blog_series.py` green + `{SCRATCH}` evidence files |

## Quality bar per article

1. Long-form structure: problem → architecture/protocol mechanics → threat/failure modes → AumOS mapping → implications.
2. ≥2 distinct visual blocks (not decorative: architecture SVG, flow diagram, coverage matrix, protocol field map, or comparison table).
3. ≥3 external primary citations with real URLs (RFCs, first-party eng blogs, standards docs).
4. Named AumOS component IDs and protocol IDs with concrete claims.
5. Honest gap notes where surface is AumOS-native composition.

## Distinctness from existing `papers/`

These blogs use **essay/engineering voice**, denser **in-page visuals**, and **2025–2026 primary citations** (MCP latest, A2A, OpenShell, Lightwell, OCC 2026-13, Anthropic Jul 2026 disclosures). They synthesize the portfolio for practitioners; research papers remain formal venue targets.

## Subagent dual-pass evidence

- Phase 1 research subagent outputs → `meta/phase1-research-notes.md` + `{SCRATCH}/phase1-research-subagent.log`
- Phase 5 adversarial review subagent → `meta/phase5-adversarial-review.md` + `{SCRATCH}/phase5-review-subagent.log`

## Regeneration / verify

```text
python aumos/docs/html/blog-series/meta/test_blog_series.py
```
