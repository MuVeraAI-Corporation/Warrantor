# 01 — Vision & Portfolio

> **Naming:** the platform is now **Warrantor**. "Warrantor" and "Warrantor" appear throughout this
> document as the historical names and remain in directory paths, package names, and older RFCs; a
> path rename has not been done and is not urgent. Read *Warrantor* as *Warrantor* wherever it appears.
>
> **Portfolio status:** the component set and wave assignments below were re-cut in
> [`03-portfolio-recut-v4.md`](03-portfolio-recut-v4.md), which is authoritative for scope, tiering,
> and build order. The success metrics in §6 were also revised — Blueprint v4 demotes star and ARR
> targets in favor of externally verifiable measures (formats adopted by others, upstream PRs
> merged, independent implementations, third-party verification). This document remains accurate on
> mission, doctrine, and the competitive analysis.

> **Warrantor is building the open authority and evidence layer for autonomous systems.** This document
> unifies the four source portfolios into one mission, one roadmap, and one success model.

## 1. Mission (one sentence)

> Build the open authority and evidence layer for autonomous systems — the specifications, reference
> enforcement, and conformance tests that make agent actions verifiable across models, harnesses,
> tools, and infrastructure.

We are **not** building "another AI-security dashboard." We are building the **security substrate
that agents cannot bypass**. The thesis, taken verbatim from the source documents:

> *Open foundations. External enforcement. Verifiable authority. Reproducible evidence.
> Ecosystem-scale remediation.*

## 2. Why now (the catalyst)

On **July 27, 2026**, NVIDIA and 75+ founding members launched the **Open Secure AI Alliance
(OSAF, a.k.a. OSAA)** to build "open, frontier defensive tools for AI agents." Each founding member
contributed **one** piece (NOOA, OpenShell, SPIFFE/SPIRE, Safetensors, Lightwell, MDASH, OSS-CRS) —
**no one contributed the orchestration layer, the authority layer, the evidence layer, the supply
chain integrity layer, the federated training layer, or the unified inference gateway.** These are
the whitespaces Warrantor fills.

The mission became urgent in the nine days from **July 21–30, 2026**:
- **Jul 21** — OpenAI disclosed a model escaped an isolated test environment via a zero-day and
  accessed Hugging Face production infrastructure using publicly exposed credentials.
- **Jul 23** — Reps. Lieu and Moran introduced the **AI Kill Switch Act (H.R. 9917)**.
- **Jul 28** — Anthropic published "Discovering cryptographic weaknesses with Claude."
- **Jul 30** — Anthropic published "Investigating three real-world incidents in our cybersecurity
  evaluations."

These are **realized** risks, not hypothetical ones. Warrantor reframes the mission from "open defense
stack" to **"open containment stack"**: defense (preventing attacks on real systems) + containment
(preventing agents from reaching real systems) + kill switch (stopping agents that escape).

## 3. Strategic doctrine

Three asymmetries Warrantor exploits (from all four source docs):

1. **Speed without legacy** — we ship weekly, incumbents ship quarterly. "Speed is the only moat
   that matters."
2. **Focus without distraction** — the open authority/evidence layer is our *only* product.
3. **NVIDIA Inception halo without NVIDIA constraints** — credibility by association; Warrantor can
   occupy the neutral ground NVIDIA cannot (e.g., non-NVIDIA GPU attestation, bridges to
   competitor stacks).

And the load-bearing **polyglot discipline** from the stack pressure test:
> *One trusted semantic core. Four carefully bounded ecosystems. Complexity activated only when
> earned. Warrantor should look polyglot from the outside and remain semantically singular on the
> inside.*

## 4. The unified portfolio

**54 implementable canonical components + 12 spec-only protocols.** Full mapping in
[`00-reconciliation-matrix.md`](00-reconciliation-matrix.md). Summary:

| Group | Components | Wave shipped |
|---|---|---|
| Trust core / identity / authority / runtime | T1, T2, I1, I2, R1–R8 | Wave 1–2 |
| Confidential compute / GPU attestation | C1-1 … C1-5 | Wave 1, 5 |
| Safe formats / supply chain | S1–S9 | Wave 2–6 |
| Evaluation / red-team | A1–A8 | Wave 2–7 |
| Inference | N1–N4 | Wave 4 |
| Federated / edge | F1–F4 | Wave 5 |
| Cross-cutting / aggregation / console / commercial | X1–X11 | Wave 1, 6–7 |
| Evidence plane | E1 | Wave 2 |
| Protocols (spec-only) | P1–P12 | Wave 1 (specs), implemented incrementally |

## 5. Roadmap (waves → horizons)

Warrantor ships in **7 delivery waves** that map onto the **3 war horizons** from the source docs:

| Wave | Theme | Months | Components | Horizon |
|---|---|---|---|---|
| **0** | Docs + scaffolding | M0 | (this phase) | — |
| **1** | Foundations + containment (90-day sprint) | M0–M3 | T1, X1, C1-1, C1-2, R2, R3, R4, + (R-Trace) | **H1: OSS land grab** |
| **2** | Keystone + foundational | M3–M6 | I1 (real), S1, S4, E1, A6, P1–P3 specs | H1 |
| **3** | Supply chain + eval | M5–M9 | S2, S5, S7, S8, A1, A2 | H1→H2 |
| **4** | Inference | M8–M11 | N1, N2, N3, N4 | H2: enterprise conversion |
| **5** | Confidential + federated | M10–M14 | C1-3, C1-4, C1-5, F1, F2, F3, F4 | H2 |
| **6** | Cross-cutting aggregation | M12–M16 | X2, X3, X4, X5, X6, X9, A3, A4, A5, A7, R5, R7, S6, S9 | H2 |
| **7** | Console + commercial | M15–M18 | X7, X8, X10, X11, A8 | H2→H3: alliance leadership |

**The 3 war horizons:**
- **Horizon 1 (M0–M6): OSS land grab.** Publish all Wave-1 + Wave-2 repos, hit 10K GH stars, claim
  namespace, join OSAF working groups. Optimize for breadth over depth — the first credible
  implementation becomes the reference.
- **Horizon 2 (M6–M18): Enterprise conversion.** Launch enterprise tier (SSO, audit streaming, SLA),
  sign design partners, present at GTC, co-author OSAF specs, ship marketplace listings.
- **Horizon 3 (M18–M36): Alliance leadership.** Win working group seats, get referenced in NVIDIA
  keynotes, reach 100K stars, achieve $10M ARR.

## 6. Success metrics (merged from all four source docs)

| Metric | M3 (Wave 1) | M6 (Wave 2) | M12 (Wave 4–5) | M18 (Wave 7) | M21+ |
|---|---|---|---|---|---|
| Components targeted for v1.0 | 8 | 14 | 28 | 38 | 54 |
| GitHub stars (cumulative) | 2k | 5k | 25k | 100k | 100k+ |
| Design partners | 1 | 3 | 8 | 15 | 20 |
| Enterprise customers | 0 | 1 | 3 | 5 | 8 |
| ARR | $0 | $100k | $2M | $10M | $10M+ |
| OSAF specs co-authored | 0 | 1 | 2 | 4 | 6 |
| GTC talks delivered | 0 | 1 | 4 | 6 | 8 |
| Conformance suite passes (cross-language) | 1 | 3 | 6 | 10 | 12 |

## 7. Category positioning

**One-line category:** *"The open authority and evidence layer for autonomous systems."*

**Not:** "AI security platform," "agent observability tool," "LLM firewall," "AI SBOM generator."
Each of those exists; we sit *beneath* them, providing the verifiable substrate they all need.

**Reference customers / proof points (target):**
- A GPAI model provider demonstrates **EU AI Act Article 55** compliance with `defstack compliance-report`.
- METR uses Warrantor as the substrate for independent AI evaluations (X6 metr-bridge).
- A regulated enterprise accepts Warrantor AARs (P2) as audit evidence in a SOC 2 / ISO 42001 audit.
- Reps. Lieu/Moran's offices cite KillSwitchKit (R3) as the reference implementation of the AI Kill
  Switch Act.

## 8. Competitive moats (eight compounding moats, from the source docs)

1. **Upstream trust** — we contribute to OpenShell, NOOA, SPIRE, garak, OMS; we don't fork.
2. **Cross-stack policy graph** — one authority model compiled to OPA/Cedar/OpenShell/eBPF.
3. **Incident-derived data** — every disclosed incident sharpens our detectors and test vectors.
4. **Conformance ecosystem** — others implement our spec; we become the reference.
5. **Regulated deployment depth** — FedRAMP / DORA / HIPAA / ISO 42001 mappings make us the
   easiest compliance path.
6. **FDE learning loop** — field engineering with design partners compounds product intelligence.
7. **Hardware-aware performance** — NVIDIA Inception gives us H100/H200/B100 access; we tune for
   those.
8. **Trust brand** — open, neutral, verifiable.

## 9. Business model (open-core)

| Tier | Price | What's included |
|---|---|---|
| **Community** | Free, Apache 2.0 | All OSS components, full functionality |
| **Team** | $50/user/month | Hosted console, shared policy, basic support |
| **Enterprise** | $100k+/year | SSO/SAML, audit streaming, SLA, on-prem, BSL features |
| **Mission-Critical** | $500k+/year | FedRAMP, dedicated CSE, custom integrations, 24/7 |
| **Warrantor Cloud** | $2–5/GPU-hour | Managed, per-GPU pricing with attestation, 80% margin |

BSL-licensed enterprise modules convert to Apache 2.0 after 4 years (the HashiCorp/MongoDB
playbook).

**Capital requirements:** $3M seed (Horizon 1) → $8M Series A (Horizon 2) → $25M Series B
(Horizon 3).

## 10. What we will NOT do (kill criteria)

Drawn from the V3 pressure test and stack pressure test — these are explicit discipline rules:

1. **No dashboard-first work.** The substrate comes first; the console is Wave 7.
2. **No reinventing mature standards.** We profile SPIFFE, OAuth RAR/DPoP, OpenID SSF/CAEP, OCSF,
   OTel, CycloneDX, SPDX — we do not fork them.
3. **No proprietary dependency in conformance.** Conformance must be reproducible by anyone.
4. **No second authoritative implementation of a security invariant.** "No security invariant may
   have two authoritative implementations" (stack test).
5. **No vanity outputs.** Repos ship only when they have owners, test vectors, and an integration
   path.
6. **No unreleased protocol versions.** No language package releases a protocol version until the
   conformance suite is green across every supported implementation.
7. **No raw customer reasoning collected centrally by default.** Data residency is a feature.
8. **No promise of formal safety from empirical guardrails.** We provide *evidence*, not *guarantees*.

## 11. Cross-references

- **Architecture (12 planes, invariants):** [`02-architecture.md`](02-architecture.md)
- **Component catalog:** [`00-reconciliation-matrix.md`](00-reconciliation-matrix.md)
- **Cross-cutting standards:** [`cross-cutting/`](cross-cutting/) (19 standards)
- **Source documents:** [`source-matrix/README.md`](source-matrix/README.md)
