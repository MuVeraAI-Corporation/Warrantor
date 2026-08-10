# Source Matrix — Original Strategy Documents

This directory is a **read-only provenance index**. The original 20 strategy documents that AumOS
reconciles live one level up in the project folder (`M:\Project AumOS - Open Secure AI Alliance\`).
They are **not** copied here — they remain the immutable source of truth for what each portfolio
proposed. AumOS is the unified implementation derived from them.

## Inventory (20 files, MD5-verified)

### Markdown policy / cross-cutting docs (5 — adopted into AumOS `docs/cross-cutting/`)
| File | AumOS location |
|------|----------------|
| `13-compliance-frameworks.md` | `docs/cross-cutting/13-compliance-frameworks.md` (adopted verbatim) |
| `14-security-disclosure-policy.md` | `docs/cross-cutting/14-security-disclosure-policy.md` (adopted verbatim) |
| `15-open-source-governance.md` | `docs/cross-cutting/15-open-source-governance.md` (adopted verbatim) |
| `16-disaster-recovery.md` | `docs/cross-cutting/16-disaster-recovery.md` (adopted verbatim) |
| `gap-analysis-v3.md` | `docs/cross-cutting/gap-analysis-v3.md` (adopted verbatim; the 3 "fixed" docs it references — 17/18/19 — were absent from the folder and are authored fresh in AumOS) |

### DefStack portfolio (2 PDFs — `DefStack_Implementation_Plan.pdf` is the master; `(1)` is an abridged 17-page subset)
| File | Pages | Role |
|------|-------|------|
| `DefStack_Implementation_Plan.pdf` | 22 | **Master** — full plan, includes cross-cutting Ch.12 + Ch.13 |
| `DefStack_Implementation_Plan (1).pdf` | 17 | Abridged — content identical for shared chapters |

### OSAF War Mode strategy (2 PDFs — v2 supersedes v1)
| File | Pages | Role |
|------|-------|------|
| `OSAF_War_Mode_Strategy.pdf` | 65 | Volume 1 (foundations) |
| `OSAF_War_Mode_Strategy_v2.pdf` | 95 | Volume 1 (identical) + Volume 2 (containment, 30pp NEW) |

### AumSecure HTML strategy (4 unique + 4 byte-identical duplicates)
| File | MD5 | Role |
|------|-----|------|
| `aumsecure_open_secure_ai_alliance_oss_authority_v2.html` | — | **OSS Authority V2** — 20-component portfolio + 12 protocols + 48-repo map |
| `aumsecure_open_secure_ai_alliance_war_mode_strategy.html` | `5d6295eca70323d7a2d17f4fe69ee2ca` | **War-mode blueprint** (precursor to V2; 20 components + 11 protocols) |
| `aumsecure_open_secure_ai_alliance_authority_pressure_test_v3.html` | `1ac71242753320a389c272af3fe54e3f` | **V3 authority pressure test** — contracts 48→6 canonical repos |
| `aumsecure_rust_go_python_typescript_stack_pressure_test.html` | `09a51dd8c0f39a5303ebe73ecdfbf1b9` | **Polyglot stack red-team** — Rust+Py+TS with Go phase-gated |
| `preview.html` | `09a51dd8c0f39a5303ebe73ecdfbf1b9` | **Duplicate** of stack pressure test |
| `aumsecure_open_secure_ai_alliance_war_mode_strategy(1).html` | `5d6295eca70323d7a2d17f4fe69ee2ca` | **Duplicate** of war-mode strategy |
| `aumsecure_open_secure_ai_alliance_authority_pressure_test_v3 (1).html` | `1ac71242753320a389c272af3fe54e3f` | **Duplicate** of V3 authority test |

### PROJECT SENTINEL (1 large HTML)
| File | Size | Role |
|------|------|------|
| `sentinel-blueprint.html` | 400 KB | **10-framework blueprint** — AEGIS/NOOA-Forge/ZTAI/ATLAS/HYDRA/COLOSSEUM/FORGE/AGORA/DELTA/SENTINEL-OS |

### Other
| File | Role |
|------|------|
| `aumsecure_preview.png` | Preview render of the strategy page (not used by AumOS) |

---

## Curated reading list (max-depth external sources)

High-quality blogs, RFCs, standards, and deep technical articles for **every**
canonical component and protocol (full reconciliation inventory + P1–P12):

| Artifact | Path |
|----------|------|
| **Visual HTML index** (coverage matrix + cards) | [`../html/curated-reading-list.html`](../html/curated-reading-list.html) |
| Markdown companion | [`../curated-reading-list.md`](../curated-reading-list.md) |
| Structured source data | [`curated-sources.json`](curated-sources.json) |
| Generator | [`generate_reading_list.py`](generate_reading_list.py) |
| Verification tests | [`test_reading_list.py`](test_reading_list.py) |

Regenerate: `python aumos/docs/source-matrix/generate_reading_list.py`  
Verify: `python aumos/docs/source-matrix/test_reading_list.py`

## How the four portfolios map to AumOS

See [`../00-reconciliation-matrix.md`](../00-reconciliation-matrix.md) for the canonical mapping.
The one-paragraph summary:

- **DefStack (36-comp)** contributes the most detailed component RFCs, the 8-phase/21-month roadmap,
  the per-component language assignments, and the 144 agent-handoff-file pattern.
- **AumSecure V2 (20-comp + 12 protocols)** contributes the **normative protocol specs** (AAE, AAR,
  CPE, AMIL, SSP, AATM, ABS, VEB, AIX, MADE, PRB, CAP) and the 10-layer pressure-tested architecture.
- **AumSecure V3 (6 canonical repos)** contributes the **contraction discipline** — "freeze the
  48-repo plan, ship 6 canonical repos first, no vanity outputs" — and the 12 formal invariants
  (I-01…​I-12) that every component must satisfy.
- **PROJECT SENTINEL (10 frameworks)** contributes the **strategic/competitive analysis** and the
  co-development playbook with OSAF founders.
- **Polyglot stack test** contributes the **language doctrine**: Rust = trusted core, Python = agents
  /evals, TypeScript = console/SDK/MCP, Go = phase-gated K8s control plane. This doctrine overrides
  the per-component Go assignments in DefStack where they conflict (documented per-component in the
  reconciliation matrix and each RFC).
