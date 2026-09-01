# Track 3 — External Corpus

> Tiered source corpus, cross-mapped to the pieces each source **grounds** or **threatens**.
> Built 2026-08-30. Every entry below was surfaced in a live search this session; entries marked
> **`READ`** have not yet been read in full and must be before they are cited.

---

## The finding that reshaped this track

The repo already holds `docs/curated-reading-list.md` — 101 entries, 57 domains, mapped to all 66
component and protocol IDs. It is a genuinely good document and it is **not a research corpus.**

Measured, not asserted:

| Check against the existing 101-entry list | Result |
|---|---|
| Total arXiv references | **6** |
| Newest arXiv reference | **2503.23278 — March 2025** |
| NSA MCP Cybersecurity Information Sheet (May 2026) | **absent** |
| NIST COSAiS agent control overlays | **absent** |
| The 2026 agent-security research cluster (below) | **entirely absent** |
| OCC 2026-13 / SR 26-2 | present (4 mentions) ✅ |
| OWASP | present (9 mentions) ✅ |

So the list is strong on protocol and infrastructure primaries — SPIFFE/SPIRE, sigstore, in-toto,
OCSF, MCP, A2A — and structurally blind to the academic literature. That literature spent the first
half of 2026 publishing directly against this thesis.

**Consequence for Track 1: three pieces acquired prior art.** They are still worth writing. They are
no longer writable without a related-work section, and one of them needs its claim narrowed. This is
flagged inline below and must be reflected before drafting begins.

---

## Tiers

| Tier | Definition | Annotation depth |
|---|---|---|
| **CANON** | You cannot write with authority without having read it. It grounds or threatens a specific piece. | Full — what it establishes, its weakest point, what it does to our work |
| **WORKING** | Needed for correctness on a specific piece; consult, don't necessarily read cover to cover. | One line |
| **WATCH** | Moving; check state before each publish. | One line + what would change |

---

# CANON — Tier 1

## A. The 2026 agent-security research cluster ← **the entire gap**

### A1 · From Tool Connection to Execution Control: Benchmarking Security Invariants in MCP-Style Agent Runtimes
`arXiv 2606.29073` · June 2026 · **`READ`**

**Establishes.** Eight security invariants for MCP-style execution — metadata non-authority,
grant-backed approval, canonical resources, principal binding, scoped capability invocation,
source-and-target data-flow authorization, deny-path audit, explicit protocol state — implemented in
a reference runtime (HCP, Handle-Capability Protocol) over principals, resources, grants,
capabilities, handles, policy decisions, data-pipe checks and audit entries. Across 10 benchmark
cases: naive baseline permits all attacks, a mitigation baseline permits 6 of 10, HCP blocks 10 of
10 while preserving audit evidence. Sub-millisecond mean latencies on a local microbenchmark.

**Weakest point.** Ten benchmark cases is a small adversary set, and an in-memory microbenchmark is
not a deployment. The invariants are asserted as a set without an argument that the set is complete.

**What it does to our work.** **Grounds** T-11 and B-08 — it is independent, citable evidence that
enforcement point matters. **Threatens** T-02: it is adjacent prior art on what a runtime can
enforce. T-02 survives because its subject is different — mechanism *class* (cryptographic / OS /
proxy) and the composition rule across classes, not protocol invariants inside one class — but the
distinction must be made explicitly in the paper's first two pages or a reviewer will make it for us.

- https://arxiv.org/abs/2606.29073

### A2 · Formal Security Analysis of Agent Protocol Composition (AgentThread)
`arXiv 2606.28690` · June 2026 · **`READ`** · ⚠️ **highest-priority read in the corpus**

**Establishes.** A source-linked assurance framework from specification text to running SDKs.
Layered security scope; protocol-derived checks formalized as **TLA+ invariants**; a two-phase
checker compiling specs into model-checkable models and replaying executable counterexamples against
real SDKs through protocol adapters. Separates violated requirements from missing recommendations,
hardening gaps, and **unassigned cross-protocol responsibilities**. Across five emerging agent
protocols: **35 specification-level findings, 80 implementation tests** against production SDKs.

**Weakest point.** Protocol-conformance composition, not mechanism composition — it analyzes whether
composed protocols preserve their stated requirements, not whether the underlying enforcement
mechanisms have compatible adversary models.

**What it does to our work.** ⚠️ **Threatens T-02 hardest.** "Composition of agent protocols is
under-specified and things fall between them" is now formally established with counterexamples
replayed against real SDKs. T-02 cannot present that as a novel observation. What remains genuinely
ours is the **enforcement-tier axis** — that cryptographic, OS and proxy bounds have different
adversary classes and a composed system inherits the weakest reachable one. That is orthogonal to
TLA+ protocol conformance and it is a real contribution. **Narrow T-02's claim to the tier axis and
cite this paper as the protocol-layer complement.** Read it before writing a word of T-02.

- https://arxiv.org/abs/2606.28690

### A3 · DEMM-Bench: A Cross-Regime Benchmark for Agent-Runtime Governance-Evidence Sufficiency
`arXiv 2606.20634` · June 2026 · 41pp, 8 tables · **`READ`** · ⚠️ **direct hit on T-10**

**Establishes.** Grounded in a Decision Evidence Maturity Model, it measures whether records across
**eight evidence regimes** are *sufficient to reconstruct decision-level properties* rather than
merely present. Regimes include reasoning provenance, message-action contract traces, intent-to-
execution chains, signed delegation evidence, W3C-style provenance graphs extended to agentic
workflows, lifecycle ledger audit trails, pre-execution tool-call firewall decisions with hash-chain
audit, and capability-token replay. Normalizes via adapters, asks property questions over actor,
authority, action, policy, decision basis, resource touch, lifecycle context and verification
strength, and applies eight deterministic degradation conditions. Dataset and code on Zenodo and
Hugging Face.

**Weakest point.** Sufficiency is defined against the authors' property set; whether that set matches
what a supervisor actually demands is asserted rather than validated against a regulator.

**What it does to our work.** ⚠️ **Threatens T-10 directly.** "Logs are present but not sufficient"
is T-10's core move and this paper benchmarks it. **But it also hands T-10 its strongest possible
upgrade:** DEMM-Bench validates sufficiency against a *property set*, not against a *supervisory
demand*. T-10's contribution becomes the mapping from OCC 2026-13 / RBI June 2026 / SDAIA
evidentiary demands onto DEMM's property questions — which nobody has done and which is precisely
the gap the paper leaves open. **Reframe T-10 as "sufficient for whom" and it gets stronger, not
weaker.**

- https://arxiv.org/abs/2606.20634

### A4 · Partial Evidence Bench: Benchmarking Authorization-Limited Evidence in Agentic Systems
`arXiv 2605.05379` · May 2026 · **`READ`**

**Establishes.** Benchmarks evidence quality when authorization constraints mean the evidence
collector cannot see everything.

**What it does to our work.** **Grounds T-01 powerfully.** This is the mediation-ceiling problem
approached from the evidence side — what you can conclude when your observation is structurally
partial. T-01's coverage-measurement argument gains an academic frame it currently lacks.

- https://arxiv.org/abs/2605.05379

### A5 · A Five-Plane Reference Architecture for Runtime Governance of Production AI Agents
`arXiv 2606.12320` · June 2026 · **`READ`**

**What it does to our work.** Architectural prior art adjacent to the Warrantor plane model. **Read
before any piece describes our architecture as novel** — a plane-based reference architecture now
exists in the literature and our contribution must be stated relative to it.

- https://arxiv.org/html/2606.12320

### A6 · Behavioral Governance for Autonomous AI Agents: The AgentBound Framework
`arXiv 2606.30970` · June 2026 · **`READ`**

**What it does to our work.** Adjacent to the autonomy-perimeter concept in B-03. ⚠️ **Check before
coining.** If AgentBound already names this object, B-03 should adopt or extend the existing term
rather than introduce a competing one — a new term that duplicates an existing one is a
category-authority loss, not a win.

- https://arxiv.org/pdf/2606.30970

### A7 · Decision Evidence Maturity Model for Agentic AI: A Property-Level Method Specification
`arXiv 2605.04093` · May 2026 · **`READ`**

**What it does to our work.** The model underlying A3. Grounds the maturity-rubric structure in B-03
and B-04 — read it before publishing a competing rubric.

- https://arxiv.org/pdf/2605.04093

### A8 · MCP-SandboxScan: WASM-Based Secure Execution and Runtime Analysis for MCP Tools
`arXiv 2601.01241` · Jan 2026 · **`READ`**

**What it does to our work.** A Tier-2-adjacent enforcement mechanism that is neither OS nor proxy —
WASM isolation. **This is the open question T-02 must address:** does a WASM boundary constitute a
genuine Tier 2 bound without an OS boundary? T-02's taxonomy is incomplete until it answers this.

- https://arxiv.org/pdf/2601.01241

### A9 · ClawGuard: A Runtime Security Framework for Tool-Augmented LLM Agents Against Indirect Prompt Injection
`arXiv 2604.11790` · April 2026 · **`READ`**

**What it does to our work.** Grounds T-03 and T-07 — runtime guard framing against indirect
injection, adjacent to our guard-model program and to the NSA CSI's input-screening risk.

- https://arxiv.org/pdf/2604.11790

### A10 · MCPThreatHive: Automated Threat Intelligence for MCP Ecosystems
`arXiv 2604.13849` · April 2026 · **`READ`**

**What it does to our work.** Ecosystem-level threat data; grounds T-07's risk-to-control mapping
with observed rather than hypothesized threats.

- https://arxiv.org/pdf/2604.13849

### A11 · MCP Threat Modeling and Analyzing Vulnerabilities to Prompt Injection with Tool Poisoning
`arXiv 2603.22489` · March 2026 · **`READ`**

**What it does to our work.** Tool-poisoning threat model; grounds T-07 and the supply-chain
argument.

- https://arxiv.org/pdf/2603.22489

---

## B. The supervisory and national-security record

### B1 · OCC Bulletin 2026-13 / Fed SR 26-2 — Model Risk Management: Revised Guidance
17 April 2026 · **verified** · see [`04-verified-anchors.md`](04-verified-anchors.md) §A1

**Grounds** B-01, B-02, T-10. **The single most important document in the business track.** Read the
bulletin *and* the attached PDF; the two quotations that carry B-01 are in the guidance itself, not
the press release.

- https://www.occ.gov/news-issuances/bulletins/2026/bulletin-2026-13.html
- https://www.occ.treas.gov/news-issuances/bulletins/2026/bulletin-2026-13a.pdf
- https://www.federalreserve.gov/supervisionreg/srletters/SR2602.htm

### B2 · NSA CSI — MCP: Security Design Considerations for AI-Driven Automation
20 May 2026 · **verified** · §A2

**Grounds** T-07 entirely, plus T-01, T-02, B-01. **Weakest point:** it describes risks without
specifying controls, which is exactly why T-07 exists.

- https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF

### B3 · NIST COSAiS — Control Overlays for Securing AI Systems (concept paper)
Announced Aug 2025, overlays in development, no publication date · **verified** · §A3

**Grounds** T-08 entirely. **Threatens** T-08 if NIST publishes first — watch monthly.

- https://csrc.nist.gov/csrc/media/Projects/cosais/documents/NIST-Overlays-SecuringAI-concept-paper.pdf

### B4 · Sullivan & Cromwell — analysis of the revised MRM guidance
April 2026 · **verified**

Law-firm reading of 2026-13. **Grounds** B-01's legal framing without requiring us to give legal
advice — cite the analysis, not our own interpretation of statute.

- https://www.sullcrom.com/insights/memo/2026/April/OCC-Fed-FDIC-Issue-Revised-Guidance-Model-Risk-Management

### B5 · CRA — Model Risk Management Guidance SR 26-2: In the Era of AI
2026 · **`READ`**

Economic-consultancy reading of the same guidance. Useful counterweight; check whether it reads the
exclusion as deferral or exemption, since that is B-01's whole argument.

- https://www.crai.com/insights-events/publications/model-risk-management-guidance-sr-26-2-in-the-era-of-ai/

---

## C. Practitioner standards

### C1 · OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10)
Released 9 Dec 2025 · **verified** · §G

**Grounds** everything. This is the shared vocabulary; every control we describe should carry its
ASI identifiers. **Weakest point:** a risk list is not a control specification — which is the space
T-08 occupies.

- https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

### C2 · OWASP — The State of Agentic Security and Governance 1.0 · **`READ`**
### C3 · OWASP — The Agentic Security Solutions Landscape · **`READ`**

⚠️ **C3 is a competitive-landscape document from a neutral body.** Read it before writing T-11 or
B-08 — it may already contain the layer taxonomy those pieces propose, in which case cite it and
build rather than restate.

- https://genai.owasp.org/initiatives/agentic-security-initiative/

### C4 · MCP Specification 2026-07-28 + authorization section
**verified** · §B1 · **Grounds** T-06, T-01, T-07. Read the changelog and the authorization page.

- https://blog.modelcontextprotocol.io/posts/2026-07-28/
- https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization

---

## D. Regional regulatory canon

| # | Source | Grounds | Status |
|---|---|---|---|
| D1 | RBI FREE-AI framework (**13 Aug 2025**, advisory) | B-07 | verified |
| D2 | **RBI draft guidelines, June 2026** — AI/ML model governance | B-07 | ⚠️ **`VERIFY` — highest-priority outstanding** |
| D3 | DPDP Act 2023 + DPDP Rules 2025; consent rules **Nov 2026** | B-07, B-11 | verified |
| D4 | IT Amendment Rules 2026 (synthetic content, in force 20 Feb 2026) | B-07 | verified |
| D5 | SDAIA AI Adoption Framework + AI Ethics Principles + GenAI Guidelines | B-05, B-06 | verified |
| D6 | Saudi PDPL (in force Sept 2023) | B-05, B-06 | verified |
| D7 | DIFC Regulation 10 (fully enforced Jan 2026) | B-06 | verified |
| D8 | UAE Federal Authority for AI and Data (created June 2026) | B-06 | `VERIFY` mandate |
| D9 | UAE AI Charter 2024 / National Strategy for AI 2031 | B-06 | `READ` |

---

## E. Market and adoption framing

| # | Source | Grounds | Status |
|---|---|---|---|
| E1 | Gartner — 2026 Hype Cycle for Agentic AI | B-09 | verified |
| E2 | Gartner — top predictions for data & analytics 2026 | B-09 | verified |
| E3 | Gartner — agentic AI oversight as #1 cybersecurity trend 2026 | B-09, B-01 | verified |
| E4 | Adoption/incident statistics cluster | B-04, B-09 | ⚠️ **secondary — trace to primary, §H** |

---

# WORKING — Tier 2

## F. The existing 101-entry list — retained wholesale, not re-enumerated

[`docs/curated-reading-list.md`](../curated-reading-list.md) remains the working tier for protocol
and infrastructure primaries. It covers, at depth: SPIFFE/SPIRE and workload identity · sigstore and
in-toto · SLSA · OCSF · CycloneDX / ML-BOM · safetensors · confidential computing and NVIDIA nvtrust
· garak and PyRIT · MCP and A2A · DID:web · eBPF tooling. Mapped to all 66 component and protocol
IDs, with no uncovered IDs.

**Do not rebuild it. Do apply three corrections:**

1. **Add the CANON tier above** — the entire section A cluster, plus B2, B3, C1–C3.
2. **Re-tier by piece, not by component.** The existing mapping answers *which component does this
   inform*; the catalog needs *which piece does this ground or threaten*. Both mappings are useful;
   keep the first, add the second.
3. **Re-date it.** It is stamped 2026-08-09 and was already missing three months of primary sources
   on the day it was written. Add a freshness field per entry and a re-verification cadence.

## G. Working additions

| # | Source | For | Status |
|---|---|---|---|
| G1 | Aembit — MCP, OAuth 2.1, PKCE and the future of AI authorization | T-06 | `READ` |
| G2 | Reed Smith — analysis of the NSA MCP guidance | T-07 | `READ` |
| G3 | Cloud Security Alliance — NIST AI agent standards research notes | T-08 | `READ` |
| G4 | MetricStream — NIST AI agent standards: what CISOs need to know | T-08, B-09 | `READ` |
| G5 | NIST CAISI — AI agent security analysis (existing controls insufficient) | T-08 | `READ` |
| G6 | ISO 19650 family — BIM information management | B-10 | ⚠️ `VERIFY` before citing clauses |
| G7 | Chambers — a framework for using AI in the Indian financial sector | B-07 | `READ` |
| G8 | sec-deadlines.github.io — security venue deadline tracker | T-03, T-12 | verified, live |

---

# WATCH — Tier 3

Check state before every publish that depends on them.

| # | What | Changes what |
|---|---|---|
| W1 | **The Fed/OCC/FDIC RFI on AI model risk** | ⚠️ Publication converts B-02 from forecast to deadline. **Check weekly.** |
| W2 | **NIST COSAiS agent overlays** | Publication reframes T-08 from draft-first to commentary. **Check monthly.** |
| W3 | **RBI June 2026 draft — finalization and comment window** | B-07's entire timing argument |
| W4 | MCP specification revisions after 2026-07-28 | T-06 decays; T-01 and T-07 shift |
| W5 | OWASP ASI companion releases | T-11, B-08 taxonomy may be pre-empted |
| W6 | New arXiv in the agent-security cluster (cs.CR + cs.AI) | ⚠️ This field is publishing monthly. **Set a standing alert; the corpus went stale in five months last time.** |
| W7 | SDAIA accreditation procedure and any agentic-specific requirement | B-05, B-06 |
| W8 | UAE Federal Authority for AI and Data — first issuances | B-06 |
| W9 | IEEE S&P 2027 Cycle 2 CFP details | T-03's hard deadline |
| W10 | Vendor documentation for the differentiation pieces | T-11, B-08 — re-verify within 30 days of publishing |

---

## Corpus totals

| Tier | Count |
|---|---|
| CANON — fully annotated | **32** (A1–A11, B1–B5, C1–C4, D1–D9, E1–E4, minus overlaps) |
| WORKING — existing list retained | **101** |
| WORKING — additions | **8** |
| WATCH | **10** |
| **Total** | **≈ 143 sources, 32 at canon depth** |

## The reading order that actually matters

If you read four things before writing anything: **A2** (it narrows T-02), **A3** (it reframes
T-10), **B2** (it is T-07 entirely), **C3** (it may pre-empt T-11 and B-08). Those four determine
whether four of the twenty-seven pieces are written as proposed or written differently.
