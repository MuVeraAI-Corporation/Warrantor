# Warrantor Curated Reading List — Highest-Quality Blogs, Specs & Deep Technical Articles

> Generated 2026-08-09 · v1.0.0

Primary standards/RFCs first; vendor eng blogs; security/AI research depth; not SEO listicles. US/India/GCC regulatory anchors when compliance appears.

## Stats

- Entries: **101**
- Unique domains: **57**
- Components: **54** · Protocols: **12**
- IDs covered: **66** / 66
- Uncovered: none
- Substitute-only: none

## Coverage matrix

| ID | Name | Sources | Status |
|----|------|---------|--------|
| `T1` | `trust-core` | 11 | covered |
| `T2` | `authority-spec` | 4 | covered |
| `I1` | `agent-identity` | 16 | covered |
| `I2` | `identity-bindings` | 4 | covered |
| `R1` | `secure-workspace` | 8 | covered |
| `R2` | `eval-guard` | 5 | covered |
| `R3` | `kill-switch` | 7 | covered |
| `R4` | `credential-vault` | 9 | covered |
| `R5` | `policy-compiler` | 4 | covered |
| `R6` | `policy-bridge` | 4 | covered |
| `R7` | `egress-filter` | 3 | covered |
| `R8` | `sandbox-runtime` | 6 | covered |
| `C1-1` | `nvtrust-bridge` | 5 | covered |
| `C1-2` | `cuda-gram` | 2 | covered |
| `C1-3` | `attesta-flow` | 3 | covered |
| `C1-4` | `tee-serve` | 5 | covered |
| `C1-5` | `confidential-fabric` | 6 | covered |
| `S1` | `safe-tensors-pp` | 6 | covered |
| `S2` | `provena-chain` | 8 | covered |
| `S3` | `gguf-ext` | 2 | covered |
| `S4` | `model-sbom` | 13 | covered |
| `S5` | `data-provenance-kit` | 8 | covered |
| `S6` | `exfil-guard` | 3 | covered |
| `S7` | `tamper-scan` | 4 | covered |
| `S8` | `train-guard` | 4 | covered |
| `S9` | `lightwell-bridge` | 3 | covered |
| `A1` | `safe-eval` | 16 | covered |
| `A2` | `adversaria` | 6 | covered |
| `A3` | `bias-sentinel` | 3 | covered |
| `A4` | `comply-gate` | 6 | covered |
| `A5` | `agentsec-lab` | 8 | covered |
| `A6` | `conformance` | 6 | covered |
| `A7` | `red-team-cloud` | 3 | covered |
| `A8` | `arena` | 3 | covered |
| `N1` | `open-serve-kit` | 4 | covered |
| `N2` | `bridge-rt` | 2 | covered |
| `N3` | `inference-proxy` | 3 | covered |
| `N4` | `tenant-guard` | 5 | covered |
| `F1` | `fed-core` | 3 | covered |
| `F2` | `dp-crate` | 3 | covered |
| `F3` | `edge-sentinel` | 1 | covered |
| `F4` | `fleet-marshal` | 6 | covered |
| `X1` | `defstack-cli` | 4 | covered |
| `X2` | `nooa-ext` | 4 | covered |
| `X3` | `open-harness-spec` | 5 | covered |
| `X4` | `crypto-audit-ai` | 1 | covered |
| `X5` | `retro-spec-kit` | 2 | covered |
| `X6` | `metr-bridge` | 3 | covered |
| `X7` | `console` | 1 | covered |
| `X8` | `mcp-gateway` | 8 | covered |
| `X9` | `incident-exchange` | 9 | covered |
| `X10` | `sovereign-stack` | 2 | covered |
| `X11` | `defstack-cloud` | 4 | covered |
| `E1` | `flight-recorder` | 12 | covered |
| `P1` | `aae` (Agent Authority Envelope) | 15 | covered |
| `P2` | `aar` (Agent Action Receipt) | 9 | covered |
| `P3` | `cpe` (Context Provenance Envelope) | 5 | covered |
| `P4` | `amil` (Agent Memory Integrity Ledger) | 4 | covered |
| `P5` | `ssp` (Secure Skill Package) | 8 | covered |
| `P6` | `aatm` (AI Artifact Trust Manifest) | 15 | covered |
| `P7` | `abs` (Autonomy Budget Specification) | 9 | covered |
| `P8` | `veb` (Verifiable Evaluation Bundle) | 10 | covered |
| `P9` | `aix` (Agent Incident Exchange) | 6 | covered |
| `P10` | `made` (Multi-Agent Delegation Exchange) | 10 | covered |
| `P11` | `prb` (Proof-Carrying Remediation Bundle) | 6 | covered |
| `P12` | `cap` (Capability Attestation Profile) | 8 | covered |

## Entries

### SPIFFE — Secure Production Identity Framework for Everyone

- **Author/publisher:** SPIFFE / CNCF
- **URL:** https://spiffe.io/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `I1`, `I2`, `P1`, `P12`, `R4`
- **Tags:** SPIFFE, SPIRE, zero-trust, workload-identity
- **Why it matters:** Canonical primary standard for workload identity; Warrantor I1/I2 profile SPIFFE IDs and SVIDs rather than inventing agent identity.

### SPIRE Concepts — Attestation, Agents, and Trust Domains

- **Author/publisher:** SPIFFE Project
- **URL:** https://spiffe.io/docs/latest/spire-about/spire-concepts/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `I1`, `I2`, `P12`, `C1-5`
- **Tags:** SPIRE, attestation, SVID
- **Why it matters:** Deep operational model for node/workload attestation that I2 identity-bindings must implement as the SPIRE adapter layer.

### Solving the Bottom Turtle — SPIFFE/SPIRE Book (PDF)

- **Author/publisher:** SPIFFE Community
- **URL:** https://spiffe.io/pdf/Solving-the-bottom-turtle-SPIFFE-SPIRE-Book.pdf
- **Tier:** deep-secondary
- **Date/recency:** 2022+
- **Maps to:** `I1`, `I2`, `T1`
- **Tags:** SPIFFE, deep-dive, book
- **Why it matters:** Long-form technical book on establishing universal trust; the identity substrate T1/I1 build on.

### Zero to Trusted: SPIFFE and SPIRE, Demystified

- **Author/publisher:** Spletzer
- **URL:** https://www.spletzer.com/2025/03/zero-to-trusted-spiffe-and-spire-demystified/
- **Tier:** deep-secondary
- **Date/recency:** 2025-03
- **Maps to:** `I1`, `I2`
- **Tags:** SPIFFE, explainer, SVID
- **Why it matters:** Clear 2025 explainer of SVIDs, selectors, and federation patterns useful for agent identity onboarding docs.

### Introducing the Model Context Protocol

- **Author/publisher:** Anthropic
- **URL:** https://www.anthropic.com/news/model-context-protocol
- **Tier:** canonical
- **Date/recency:** 2024-11
- **Maps to:** `X8`, `P5`, `R1`, `R8`, `P10`
- **Tags:** MCP, agents, tools
- **Why it matters:** Original announcement of MCP — the tool/context plane X8 mcp-gateway and P5 SSP must authority-gate.

### Model Context Protocol Specification (latest)

- **Author/publisher:** MCP Project
- **URL:** https://modelcontextprotocol.io/specification/latest
- **Tier:** canonical
- **Date/recency:** 2026-07
- **Maps to:** `X8`, `P5`, `P10`, `R8`
- **Tags:** MCP, specification, JSON-RPC
- **Why it matters:** Normative wire protocol for tools/resources/prompts; primary reference for X8 admission control and skill packaging (P5).

### What is the Model Context Protocol (MCP)?

- **Author/publisher:** MCP Docs
- **URL:** https://modelcontextprotocol.io/docs/2026-07-28/getting-started/intro
- **Tier:** canonical
- **Date/recency:** 2026-07
- **Maps to:** `X8`, `P5`
- **Tags:** MCP, architecture
- **Why it matters:** Architecture overview (hosts, clients, servers) for designing authority-aware MCP middleware.

### Model Context Protocol (MCP): Landscape, Security Threats, and Future Research Directions

- **Author/publisher:** arXiv
- **URL:** https://arxiv.org/pdf/2503.23278
- **Tier:** deep-secondary
- **Date/recency:** 2025-04
- **Maps to:** `X8`, `P5`, `A5`, `R1`
- **Tags:** MCP, security, threat-model
- **Why it matters:** Threat model for MCP surfaces — required reading for X8 fail-closed admission and P5 skill package signing.

### Announcing the Agent2Agent Protocol (A2A)

- **Author/publisher:** Google Developers Blog
- **URL:** https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/
- **Tier:** canonical
- **Date/recency:** 2025-04
- **Maps to:** `P10`, `I1`, `P1`, `P7`
- **Tags:** A2A, multi-agent, interoperability
- **Why it matters:** Primary announcement of A2A interoperability; maps to P10 MADE multi-agent delegation exchange.

### A2A Protocol Specification

- **Author/publisher:** A2A Project / Linux Foundation
- **URL:** https://a2a-protocol.org/latest/specification/
- **Tier:** canonical
- **Date/recency:** 2025–2026
- **Maps to:** `P10`, `P1`, `I1`, `P7`
- **Tags:** A2A, specification
- **Why it matters:** Normative A2A spec for agent-to-agent messaging; P10 MADE profiles delegation semantics on this plane.

### A2A and MCP — How the Protocols Relate

- **Author/publisher:** A2A Protocol Docs
- **URL:** https://a2a-protocol.org/latest/topics/a2a-and-mcp/
- **Tier:** canonical
- **Date/recency:** 2025+
- **Maps to:** `P10`, `X8`, `P5`
- **Tags:** A2A, MCP, architecture
- **Why it matters:** Clarifies tool-plane (MCP) vs agent-plane (A2A) split — critical for X8 + P10 architecture.

### MCP vs A2A: A Guide to AI Agent Communication Protocols

- **Author/publisher:** Auth0
- **URL:** https://auth0.com/blog/mcp-vs-a2a/
- **Tier:** deep-secondary
- **Date/recency:** 2025-07
- **Maps to:** `X8`, `P10`, `I1`, `P1`, `R4`
- **Tags:** MCP, A2A, OAuth, auth
- **Why it matters:** Security-focused comparison with OAuth angles for agent identity and delegated authority (P1/P7).

### Enforce Least-Privilege Authorization in Multi-Agent AI Chains Using Cedar

- **Author/publisher:** AWS Security Blog
- **URL:** https://aws.amazon.com/blogs/security/enforce-least-privilege-authorization-in-multi-agent-ai-chains-using-cedar/
- **Tier:** canonical
- **Date/recency:** 2026-07
- **Maps to:** `R5`, `R6`, `P7`, `P10`, `I1`, `R3`, `R4`
- **Tags:** Cedar, OPA, multi-agent, authorization, OAuth
- **Why it matters:** Three-layer Cedar + OAuth model for multi-agent chains — direct blueprint for R5/R6 policy-compiler/bridge and P7 ABS budgets.

### Cedar Policy Language

- **Author/publisher:** AWS Open Source
- **URL:** https://www.cedarpolicy.com/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `R5`, `R6`, `P1`, `P7`
- **Tags:** Cedar, policy-as-code
- **Why it matters:** Primary Cedar language home; Warrantor compiles authority to Cedar/OPA/OpenShell equivalence.

### Open Policy Agent Documentation

- **Author/publisher:** OPA / CNCF
- **URL:** https://www.openpolicyagent.org/docs/latest/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `R5`, `R6`, `R3`
- **Tags:** OPA, Rego, policy
- **Why it matters:** Rego policy engine docs; R6 decision-equivalence tests include OPA adapters.

### RFC 9396 — OAuth 2.0 Rich Authorization Requests (RAR)

- **Author/publisher:** IETF
- **URL:** https://www.rfc-editor.org/rfc/rfc9396.html
- **Tier:** canonical
- **Date/recency:** 2023
- **Maps to:** `P1`, `R4`, `I1`, `P7`
- **Tags:** OAuth, RAR, RFC
- **Why it matters:** Structured authorization_details for fine-grained scopes — profiled into P1 AAE and R4 credential brokering.

### RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)

- **Author/publisher:** IETF
- **URL:** https://www.rfc-editor.org/rfc/rfc9449.html
- **Tier:** canonical
- **Date/recency:** 2023
- **Maps to:** `R4`, `I1`, `P1`
- **Tags:** OAuth, DPoP, RFC
- **Why it matters:** Sender-constrained tokens prevent credential replay — required pattern for R4 CredentialVault and agent-scoped secrets.

### RFC 8693 — OAuth 2.0 Token Exchange

- **Author/publisher:** IETF
- **URL:** https://www.rfc-editor.org/rfc/rfc8693.html
- **Tier:** canonical
- **Date/recency:** 2020
- **Maps to:** `P10`, `P1`, `R4`, `I1`
- **Tags:** OAuth, delegation, RFC
- **Why it matters:** On-behalf-of token exchange for multi-agent delegation chains (P10 MADE).

### Security Benchmarking Authorization Policy Engines: Rego, Cedar…

- **Author/publisher:** Teleport / Trail of Bits research summary
- **URL:** https://goteleport.com/blog/benchmarking-policy-languages/
- **Tier:** deep-secondary
- **Date/recency:** 2025-06
- **Maps to:** `R5`, `R6`
- **Tags:** Cedar, Rego, security, benchmark
- **Why it matters:** Adversarial comparison of policy languages informing R6 fail-closed multi-engine adapters.

### Sigstore — Software Signing and Transparency

- **Author/publisher:** Sigstore / OpenSSF
- **URL:** https://www.sigstore.dev/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `S2`, `S4`, `T1`, `P6`, `S1`
- **Tags:** Sigstore, cosign, supply-chain
- **Why it matters:** Keyless signing + transparency stack; S2 ProvenaChain roots Merkle evidence in Rekor.

### Rekor — Immutable Transparency Log Overview

- **Author/publisher:** Sigstore Docs
- **URL:** https://docs.sigstore.dev/logging/overview/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `S2`, `P6`, `T1`, `E1`
- **Tags:** Rekor, transparency-log, Sigstore
- **Why it matters:** How Rekor records signed metadata; maps to S2 ledger and P6 AATM artifact trust manifests.

### Cosign Signing Quickstart

- **Author/publisher:** Sigstore Docs
- **URL:** https://docs.sigstore.dev/signing/quickstart/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `T1`, `S2`, `S4`, `P6`
- **Tags:** Cosign, signing
- **Why it matters:** Operational signing path for model/artifact signatures consumed by T1 trust-core verifiers.

### Machine Learning Bill of Materials (AI/ML-BOM) — CycloneDX

- **Author/publisher:** OWASP CycloneDX
- **URL:** https://cyclonedx.org/capabilities/mlbom/
- **Tier:** canonical
- **Date/recency:** 2023–2026
- **Maps to:** `S4`, `P6`, `S5`, `S1`
- **Tags:** CycloneDX, ML-BOM, SBOM, AI-BOM
- **Why it matters:** Primary AI/ML BOM capability; S4 ModelSBOM and P6 AATM align to CycloneDX ML-BOM fields.

### CycloneDX Bill of Materials Standard (ECMA-424)

- **Author/publisher:** OWASP / Ecma
- **URL:** https://cyclonedx.org/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `S4`, `P6`, `A4`
- **Tags:** CycloneDX, SBOM, ECMA-424
- **Why it matters:** Full-stack BOM standard underpinning S4 and compliance export paths.

### SPDX Specifications (incl. AI Profile)

- **Author/publisher:** Linux Foundation SPDX
- **URL:** https://spdx.dev/use/specifications/
- **Tier:** canonical
- **Date/recency:** 2024+
- **Maps to:** `S4`, `S5`, `P6`
- **Tags:** SPDX, AI-profile, SBOM
- **Why it matters:** SPDX 3.x AI/Dataset profiles as dual-standard path for S4/S5 regulatory filings.

### Safetensors — Safe Tensor Serialization Format

- **Author/publisher:** Hugging Face
- **URL:** https://huggingface.co/docs/safetensors/en/index
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `S1`, `S3`, `P6`, `S7`
- **Tags:** Safetensors, model-format, security
- **Why it matters:** Canonical safe weight format; S1 SafeTensors++ extends with __provenance__ without breaking load safety.

### Safetensors Audited as Really Safe and Becoming the Default

- **Author/publisher:** Hugging Face Blog
- **URL:** https://huggingface.co/blog/safetensors-security-audit
- **Tier:** canonical
- **Date/recency:** 2023-05
- **Maps to:** `S1`, `S7`, `T1`
- **Tags:** Safetensors, audit, security
- **Why it matters:** External security audit results establishing why pickle-replacement is non-negotiable for S1.

### Hijacking Safetensors Conversion on Hugging Face

- **Author/publisher:** HiddenLayer Research
- **URL:** https://www.hiddenlayer.com/research/silent-sabotage
- **Tier:** deep-secondary
- **Date/recency:** 2024-02
- **Maps to:** `S1`, `S7`, `S2`, `P6`
- **Tags:** Safetensors, supply-chain, adversarial
- **Why it matters:** Adversarial analysis of conversion-bot supply chain — motivates S7 tamper-scan + signed provenance beyond format safety alone.

### NVIDIA Trusted Computing / nvtrust Documentation

- **Author/publisher:** NVIDIA
- **URL:** https://docs.nvidia.com/nvtrust/index.html
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `C1-1`, `C1-2`, `C1-3`, `C1-4`, `C1-5`, `P12`
- **Tags:** NVIDIA, nvtrust, attestation, confidential-computing
- **Why it matters:** Official NVIDIA attestation documentation; primary source for C1-1 nvtrust-bridge and C1-2 cuda-gram.

### Confidential Computing on NVIDIA H100 GPUs for Secure and Trustworthy AI

- **Author/publisher:** NVIDIA Technical Blog
- **URL:** https://developer.nvidia.com/blog/confidential-computing-on-h100-gpus-for-secure-and-trustworthy-ai/
- **Tier:** canonical
- **Date/recency:** 2023-08
- **Maps to:** `C1-1`, `C1-2`, `C1-3`, `C1-4`, `C1-5`, `N4`
- **Tags:** H100, confidential-computing, NRAS, attestation
- **Why it matters:** Deep writeup of H100 CC, device identity, attestation reports, and NRAS — C1-* design bible.

### GPU Remote Attestation With Intel Trust Authority

- **Author/publisher:** Intel Trust Authority Docs
- **URL:** https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-gpu-attestation.html
- **Tier:** canonical
- **Date/recency:** 2026
- **Maps to:** `C1-3`, `C1-5`, `C1-4`, `P12`
- **Tags:** attestation, TEE, GPU, Intel
- **Why it matters:** Composite TEE+GPU attestation workflows informing C1-3 AttestaFlow multi-cloud pipelines.

### go-nvtrust — Go Library for NVIDIA GPU/NVSwitch Attestation

- **Author/publisher:** Confident Security / NVIDIA community
- **URL:** https://github.com/confidentsecurity/go-nvtrust
- **Tier:** deep-secondary
- **Date/recency:** 2025-10
- **Maps to:** `C1-1`, `C1-4`, `C1-5`
- **Tags:** nvtrust, Go, NRAS
- **Why it matters:** Open Go bindings for NRAS evidence collection — reference for C1-1 multi-language bindings.

### AI Agent Observability — Evolving Standards and Best Practices

- **Author/publisher:** OpenTelemetry Blog
- **URL:** https://opentelemetry.io/blog/2025/ai-agent-observability/
- **Tier:** canonical
- **Date/recency:** 2025-03
- **Maps to:** `E1`, `P2`, `X2`, `X9`
- **Tags:** OpenTelemetry, GenAI, observability, agents
- **Why it matters:** OTel GenAI semantic conventions for agent spans — E1 flight-recorder and P2 AAR evidence plane alignment.

### OWASP Agent Observability Standard — Trace Spec

- **Author/publisher:** OWASP AOS
- **URL:** https://owasp.github.io/www-project-agent-observability-standard/spec/trace/
- **Tier:** canonical
- **Date/recency:** 2025+
- **Maps to:** `E1`, `P2`, `P9`, `X9`
- **Tags:** OWASP, OCSF, OpenTelemetry, agents
- **Why it matters:** Agent-specific tracing standard bridging OTel and OCSF — maps to E1 and P9 AIX incident exchange.

### AOS Tracing with OCSF Extension

- **Author/publisher:** OWASP AOS
- **URL:** https://owasp.github.io/www-project-agent-observability-standard/spec/trace/extend_ocsf/
- **Tier:** canonical
- **Date/recency:** 2025+
- **Maps to:** `X9`, `P9`, `E1`, `P2`
- **Tags:** OCSF, incidents, agents
- **Why it matters:** OCSF extension path for agent events — X9 incident-exchange and P9 AIX normalize here.

### Open Cybersecurity Schema Framework (OCSF)

- **Author/publisher:** OCSF Project
- **URL:** https://schema.ocsf.io/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `X9`, `P9`, `E1`
- **Tags:** OCSF, schema, SIEM
- **Why it matters:** Primary security event schema; Warrantor profiles agent incidents as OCSF extensions rather than forking formats.

### Announcing Microsoft’s Open Automation Framework to Red Team Generative AI Systems (PyRIT)

- **Author/publisher:** Microsoft Security Blog
- **URL:** https://www.microsoft.com/en-us/security/blog/2024/02/22/announcing-microsofts-open-automation-framework-to-red-team-generative-ai-systems/
- **Tier:** canonical
- **Date/recency:** 2024-02
- **Maps to:** `A1`, `A2`, `A5`, `A7`, `P8`
- **Tags:** PyRIT, red-team, Microsoft
- **Why it matters:** Primary PyRIT announcement — A1/A2/A7 orchestration target for multi-turn adversarial testing.

### Azure/PyRIT — Python Risk Identification Toolkit

- **Author/publisher:** Microsoft Azure
- **URL:** https://github.com/Azure/PyRIT
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `A1`, `A2`, `A7`, `P8`
- **Tags:** PyRIT, GitHub, red-team
- **Why it matters:** Living codebase for multi-turn jailbreaks/scorers; A2 Adversaria unifies PyRIT with garak probes.

### NVIDIA/garak — LLM Vulnerability Scanner

- **Author/publisher:** NVIDIA
- **URL:** https://github.com/NVIDIA/garak
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `A1`, `A2`, `A5`, `A7`
- **Tags:** garak, NVIDIA, LLM-security
- **Why it matters:** Breadth scanner with 100+ probes; A1 SafeEval YAML pipelines orchestrate garak alongside HELM/PyRIT.

### HELM — Holistic Evaluation of Language Models

- **Author/publisher:** Stanford CRFM
- **URL:** https://crfm.stanford.edu/helm/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `A1`, `A8`, `P8`, `X6`
- **Tags:** HELM, evaluation, benchmarks
- **Why it matters:** Foundational multi-metric eval framework integrated into A1 SafeEval pipelines.

### AgentDojo — Agent Hijacking Benchmark (ETH Zurich)

- **Author/publisher:** ETH Zurich spylab
- **URL:** https://github.com/ethz-spylab/agentdojo
- **Tier:** canonical
- **Date/recency:** 2024+
- **Maps to:** `A5`, `A2`, `A1`, `R1`, `R8`
- **Tags:** agents, hijacking, benchmark
- **Why it matters:** 629 agent hijacking tests across tool environments — A5 agentsec-lab adversarial holdouts.

### METR — Model Evaluation & Threat Research

- **Author/publisher:** METR
- **URL:** https://metr.org/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `X6`, `A1`, `P8`, `A6`
- **Tags:** METR, evals, autonomy
- **Why it matters:** Independent evaluator org; X6 metr-bridge integration target for external eval substrate.

### Discovering cryptographic weaknesses with Claude

- **Author/publisher:** Anthropic Frontier Red Team
- **URL:** https://www.anthropic.com/research/discovering-cryptographic-weaknesses
- **Tier:** deep-secondary
- **Date/recency:** 2026-07-28
- **Maps to:** `X4`, `X5`, `A2`
- **Tags:** Anthropic, cryptanalysis, research
- **Why it matters:** Primary Anthropic research on LLM-assisted cryptanalysis; productization target for X4 CryptoAuditAI. Pair with the Jul 30 cybersecurity-eval incident writeup for X5 retrospective culture.

- **Note:** Also see https://www.anthropic.com/news/investigating-incidents-cybersecurity-evals (141,006-run retrospective) for X5 RetroSpecKit motivation.

### vLLM Documentation — High-Throughput LLM Serving

- **Author/publisher:** vLLM Project
- **URL:** https://docs.vllm.ai/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `N1`, `N2`, `N3`, `N4`
- **Tags:** vLLM, inference, serving
- **Why it matters:** Primary open serving engine behind N1/N2 OpenServeKit and BridgeRT backends.

### TensorRT-LLM Documentation

- **Author/publisher:** NVIDIA
- **URL:** https://nvidia.github.io/TensorRT-LLM/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `N2`, `N1`, `C1-4`
- **Tags:** TensorRT-LLM, NVIDIA, inference
- **Why it matters:** N2 BridgeRT must absorb TRT-LLM sampler_type and version skew; primary engine docs.

### OpenAI API Reference — Chat Completions

- **Author/publisher:** OpenAI
- **URL:** https://platform.openai.com/docs/api-reference/chat
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `N1`, `N3`
- **Tags:** OpenAI-API, inference, proxy
- **Why it matters:** De-facto wire API that N1 OpenServeKit mirrors for backend-agnostic proxying.

### NVIDIA Multi-Instance GPU (MIG) User Guide

- **Author/publisher:** NVIDIA
- **URL:** https://docs.nvidia.com/datacenter/tesla/mig-user-guide/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `N4`, `F4`, `C1-5`
- **Tags:** MIG, multi-tenant, GPU
- **Why it matters:** Hardware isolation model for N4 TenantGuard multi-tenant GPU operators.

### eBPF Documentation

- **Author/publisher:** eBPF Foundation
- **URL:** https://ebpf.io/what-is-ebpf/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `R7`, `S6`, `R2`
- **Tags:** eBPF, networking, security
- **Why it matters:** Kernel programmable dataplane for R7 egress-filter and S6 ExfilGuard.

### Cilium Tetragon — eBPF-based Security Observability & Runtime Enforcement

- **Author/publisher:** Cilium / Isovalent
- **URL:** https://tetragon.io/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `S6`, `R7`, `R2`
- **Tags:** eBPF, Tetragon, runtime-security
- **Why it matters:** Production eBPF enforcement reference overlapping S6/R7 design choices.

### Falco — Cloud Native Runtime Security

- **Author/publisher:** CNCF Falco
- **URL:** https://falco.org/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `S6`, `R2`, `R7`
- **Tags:** Falco, runtime-security, eBPF
- **Why it matters:** Syscall threat detection patterns informing S6 exfil rules and R2 sandbox boundary monitoring.

### Wasmtime — WebAssembly Runtime

- **Author/publisher:** Bytecode Alliance
- **URL:** https://wasmtime.dev/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `R8`, `R1`, `P12`
- **Tags:** WASM, Wasmtime, sandbox
- **Why it matters:** WASM runtime choice for R8 sandbox-runtime capability-scoped execution.

### Run Autonomous, Self-Evolving Agents More Safely with NVIDIA OpenShell

- **Author/publisher:** NVIDIA Technical Blog
- **URL:** https://developer.nvidia.com/blog/run-autonomous-self-evolving-agents-more-safely-with-nvidia-openshell/
- **Tier:** canonical
- **Date/recency:** 2026-03
- **Maps to:** `R1`, `R8`, `R2`, `X3`
- **Tags:** OpenShell, NVIDIA, sandbox, agents, OSAF
- **Why it matters:** Primary NVIDIA eng blog for OpenShell sandbox runtime — R1 secure-workspace and R8 sandbox-runtime profile this surface. Maps OSAF founding runtime contribution.

### Opacus — Train PyTorch Models with Differential Privacy

- **Author/publisher:** Meta / Opacus
- **URL:** https://opacus.ai/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `F2`, `F1`, `S8`
- **Tags:** differential-privacy, PyTorch, Opacus
- **Why it matters:** Primary DP training toolkit for F2 DPCrate and F1 FedCore privacy budgets.

### Flower — A Friendly Federated Learning Framework

- **Author/publisher:** Flower Labs
- **URL:** https://flower.ai/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `F1`, `F2`, `F4`
- **Tags:** federated-learning, Flower
- **Why it matters:** Mature open FL orchestration patterns for F1 FedCore multi-party training design.

### NVIDIA Jetson / EGX Edge AI Platform Docs

- **Author/publisher:** NVIDIA
- **URL:** https://developer.nvidia.com/embedded-computing
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `F3`, `F4`, `C1-1`
- **Tags:** Jetson, edge, EGX
- **Why it matters:** Edge hardware target for F3 EdgeSentinel attestation agents (<5MB Go binary).

### Kubernetes Operator Pattern

- **Author/publisher:** Kubernetes Docs
- **URL:** https://kubernetes.io/docs/concepts/extend-kubernetes/operator/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `F4`, `N4`, `I1`, `X11`
- **Tags:** Kubernetes, operators, CRD
- **Why it matters:** Control-plane pattern for F4 FleetMarshal ModelFleet CRDs and N4 TenantGuard.

### IBM and Red Hat Expand Lightwell with New Commercial Offerings

- **Author/publisher:** IBM Newsroom
- **URL:** https://newsroom.ibm.com/2026-07-08-ibm-and-red-hat-expand-lightwell-with-new-commercial-offerings-to-build-the-trust-infrastructure-for-ai-era-open-source
- **Tier:** canonical
- **Date/recency:** 2026-07-08
- **Maps to:** `S9`, `P11`, `X9`, `S4`
- **Tags:** Lightwell, IBM, Red Hat, supply-chain, SBOM, OSAF
- **Why it matters:** Primary Lightwell commercial launch (Network + Clearinghouse) for signed remediated packages and SBOMs — S9 lightwell-bridge and P11 PRB extend this patch-distribution model for AI artifacts.

### OpenID Shared Signals Framework / CAEP

- **Author/publisher:** OpenID Foundation
- **URL:** https://openid.net/sg/sharedsignals/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `R3`, `P1`, `I1`, `R4`
- **Tags:** OpenID, SSF, CAEP, revocation
- **Why it matters:** Continuous access evaluation and shared signals for revocation — maps to R3 kill-switch and P1 expiry/revocation semantics.

### MITRE ATLAS — Adversarial Threat Landscape for AI Systems

- **Author/publisher:** MITRE
- **URL:** https://atlas.mitre.org/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `X9`, `P9`, `A2`, `A5`, `S7`
- **Tags:** MITRE, ATLAS, threats, AI
- **Why it matters:** AI-specific ATT&CK-style knowledge base for X9 incident taxonomy and A2/A5 attack libraries.

### NIST AI Risk Management Framework (AI RMF 1.0)

- **Author/publisher:** NIST
- **URL:** https://www.nist.gov/itl/ai-risk-management-framework
- **Tier:** canonical
- **Date/recency:** 2023+
- **Maps to:** `A4`, `A3`, `X1`, `A1`
- **Tags:** NIST, AI-RMF, compliance, US
- **Why it matters:** US primary AI risk framework for A4 ComplyGate mappings (prefer US anchors over EU-first framing).

### clap — Command Line Argument Parser for Rust

- **Author/publisher:** clap-rs
- **URL:** https://docs.rs/clap/latest/clap/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `X1`
- **Tags:** Rust, CLI, clap
- **Why it matters:** X1 defstack-cli is Rust/clap per polyglot doctrine; canonical CLI architecture reference.

### Next.js Documentation

- **Author/publisher:** Vercel
- **URL:** https://nextjs.org/docs
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `X7`, `X11`, `A8`
- **Tags:** Next.js, TypeScript, console
- **Why it matters:** X7 console is TypeScript/Next.js; primary framework docs for enterprise policy/evidence UI.

### Chatbot Arena / LMSYS Elo Ranking Methodology

- **Author/publisher:** LMSYS / Arena
- **URL:** https://lmsys.org/blog/2023-05-03-arena/
- **Tier:** canonical
- **Date/recency:** 2023-05
- **Maps to:** `A8`, `A1`, `P8`
- **Tags:** Elo, arena, evaluation
- **Why it matters:** Elo pairwise ranking methodology underlying A8 arena leaderboard design.

### GGUF File Format Specification

- **Author/publisher:** ggml-org / llama.cpp
- **URL:** https://github.com/ggml-org/ggml/blob/master/docs/gguf.md
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `S3`, `S1`, `P6`
- **Tags:** GGUF, llama.cpp, model-format
- **Why it matters:** Canonical GGUF layout; S3 GGUF-Ext adds osaf.safety metadata blocks for llama.cpp/Ollama.

### Model Cards for Model Reporting (Mitchell et al.)

- **Author/publisher:** Google Research / arXiv
- **URL:** https://arxiv.org/abs/1810.03993
- **Tier:** canonical
- **Date/recency:** 2019
- **Maps to:** `S5`, `A3`, `S4`, `P6`
- **Tags:** model-cards, documentation, bias
- **Why it matters:** Foundational model documentation practice feeding S5 data provenance and A3 bias auditing.

### Datasheets for Datasets (Gebru et al.)

- **Author/publisher:** arXiv
- **URL:** https://arxiv.org/abs/1803.09010
- **Tier:** canonical
- **Date/recency:** 2018–2021
- **Maps to:** `S5`, `S4`, `P3`
- **Tags:** datasets, documentation, provenance
- **Why it matters:** Dataset documentation standard for S5 DataProvenanceKit lineage exports.

### HashiCorp Vault Documentation — Secrets Engines & Identity

- **Author/publisher:** HashiCorp
- **URL:** https://developer.hashicorp.com/vault/docs
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `R4`, `I1`, `R3`
- **Tags:** Vault, secrets, identity
- **Why it matters:** Industry pattern for dynamic secrets that R4 CredentialVault specializes for agent-scoped brokering.

### in-toto — Software Supply Chain Security Framework

- **Author/publisher:** in-toto / CNCF
- **URL:** https://in-toto.io/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `P11`, `S8`, `S2`, `P6`, `T1`
- **Tags:** in-toto, attestation, supply-chain
- **Why it matters:** Attestation layout for multi-step supply chains — informs P11 PRB remediation bundles and S8 train-guard attestations.

### SLSA — Supply-chain Levels for Software Artifacts

- **Author/publisher:** OpenSSF
- **URL:** https://slsa.dev/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `S2`, `S4`, `P6`, `T1`, `S8`
- **Tags:** SLSA, supply-chain, provenance
- **Why it matters:** Maturity levels for build integrity; S2/S4/P6 trust levels map cleanly onto SLSA.

### W3C PROV — Data Provenance Standard Family

- **Author/publisher:** W3C
- **URL:** https://www.w3.org/TR/prov-overview/
- **Tier:** canonical
- **Date/recency:** 2013+
- **Maps to:** `P3`, `S5`, `P4`, `E1`
- **Tags:** PROV, provenance, W3C
- **Why it matters:** Graph provenance model for P3 CPE context provenance and S5 signed JSON-LD exports.

### RFC 6962 — Certificate Transparency (Merkle log design)

- **Author/publisher:** IETF
- **URL:** https://www.rfc-editor.org/rfc/rfc6962.html
- **Tier:** canonical
- **Date/recency:** 2013
- **Maps to:** `S2`, `E1`, `P2`, `T1`
- **Tags:** Merkle, transparency, RFC
- **Why it matters:** Classic Merkle transparency log design pattern behind Rekor and S2 ProvenaChain.

### RFC 8949 — Concise Binary Object Representation (CBOR)

- **Author/publisher:** IETF
- **URL:** https://www.rfc-editor.org/rfc/rfc8949.html
- **Tier:** canonical
- **Date/recency:** 2020
- **Maps to:** `P1`, `P2`, `P3`, `P4`, `P7`, `P8`, `P10`, `P12`, `T2`
- **Tags:** CBOR, encoding, RFC
- **Why it matters:** Binary encoding used by Warrantor protocol CDDL schemas (P1–P12 machine-checkable forms).

### RFC 8610 — Concise Data Definition Language (CDDL)

- **Author/publisher:** IETF
- **URL:** https://www.rfc-editor.org/rfc/rfc8610.html
- **Tier:** canonical
- **Date/recency:** 2019
- **Maps to:** `T2`, `P1`, `P2`, `P3`, `P4`, `P5`, `P7`, `P8`, `P10`, `P11`, `P12`, `A6`
- **Tags:** CDDL, schema, RFC
- **Why it matters:** Schema language for Warrantor protocol CDDL files under specs/protocols/.

### RFC 9052 — CBOR Object Signing and Encryption (COSE)

- **Author/publisher:** IETF
- **URL:** https://www.rfc-editor.org/rfc/rfc9052.html
- **Tier:** canonical
- **Date/recency:** 2022
- **Maps to:** `T1`, `P1`, `P2`, `P6`, `E1`
- **Tags:** COSE, signing, CBOR
- **Why it matters:** Signing envelopes for compact protocol objects (AAE/AAR) verified in T1 trust-core.

### JSON-LD 1.1 — A JSON-based Serialization for Linked Data

- **Author/publisher:** W3C
- **URL:** https://www.w3.org/TR/json-ld11/
- **Tier:** canonical
- **Date/recency:** 2020
- **Maps to:** `P5`, `P6`, `P11`, `S4`, `S5`
- **Tags:** JSON-LD, linked-data
- **Why it matters:** Linked-data packaging for P5 SSP, P6 AATM, P11 PRB JSON-LD manifests.

### OCSF Schema Browser — Event Classes

- **Author/publisher:** OCSF
- **URL:** https://schema.ocsf.io/categories
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `P9`, `X9`
- **Tags:** OCSF, schema
- **Why it matters:** Event class taxonomy to extend for P9 AIX agent incident types.

### OpenAI Evals Framework

- **Author/publisher:** OpenAI
- **URL:** https://github.com/openai/evals
- **Tier:** deep-secondary
- **Date/recency:** ongoing
- **Maps to:** `A6`, `A1`, `P8`, `X3`
- **Tags:** evals, OpenAI, harness
- **Why it matters:** Early eval harness patterns informing A6 conformance packaging and P8 VEB bundles.

### UK AISI Inspect — Evaluation Framework

- **Author/publisher:** UK AI Security Institute
- **URL:** https://inspect.aisi.org.uk/
- **Tier:** canonical
- **Date/recency:** 2024+
- **Maps to:** `A1`, `A5`, `X6`, `P8`
- **Tags:** Inspect, evals, agents
- **Why it matters:** Modern agent eval framework used with AgentDojo ports; A1/X6 quality bar.

### Running Kubernetes in Air-Gapped Environments

- **Author/publisher:** Kubernetes / community best practices (SIG Cluster Lifecycle patterns)
- **URL:** https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/
- **Tier:** deep-secondary
- **Date/recency:** ongoing
- **Maps to:** `X10`, `X11`, `F4`
- **Tags:** airgap, Kubernetes, sovereign
- **Why it matters:** Offline install patterns for X10 sovereign-stack air-gapped bundles (paired with Helm/Ansible).

### Helm — The Kubernetes Package Manager

- **Author/publisher:** CNCF Helm
- **URL:** https://helm.sh/docs/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `X10`, `X11`, `F4`, `N4`
- **Tags:** Helm, Kubernetes
- **Why it matters:** Packaging for X10/X11 deploy surfaces and C1-3 Terraform-adjacent infra.

### The Digital Personal Data Protection Act, 2023 (Gazette of India)

- **Author/publisher:** Government of India / MeitY (Legislative Department gazette)
- **URL:** https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf
- **Tier:** canonical
- **Date/recency:** 2023-08-11
- **Maps to:** `F2`, `A4`, `E1`, `S5`
- **Tags:** DPDP, India, privacy, compliance
- **Why it matters:** Primary India DPDP Act text — regional privacy/data-residency anchor for F2/A4/E1/S5 (not EU-first framing).

### Model Risk Management: Revised Guidance (OCC Bulletin 2026-13)

- **Author/publisher:** OCC (interagency with Fed/FDIC)
- **URL:** https://www.occ.gov/news-issuances/bulletins/2026/bulletin-2026-13.html
- **Tier:** canonical
- **Date/recency:** 2026-04-17
- **Maps to:** `A4`, `A1`, `X1`
- **Tags:** OCC, model-risk, US, compliance
- **Why it matters:** Current US interagency model-risk guidance superseding SR 11-7; primary compliance anchor for A4 ComplyGate in banking deployments. Parallel Fed designation: SR 26-2.

- **Note:** Fed companion: https://www.federalreserve.gov/supervisionreg/srletters/SR2602.htm — cite OCC Bulletin 2026-13 / Fed SR 26-2. Generative/agentic AI deferred from this guidance scope; underlying safety-and-soundness duties remain.

### RFC 9396 — OAuth 2.0 Rich Authorization Requests (RAR)

- **Author/publisher:** IETF
- **URL:** https://www.rfc-editor.org/rfc/rfc9396.html
- **Tier:** canonical
- **Date/recency:** 2023–2026
- **Maps to:** `T2`, `P1`, `P7`, `I1`
- **Tags:** AAE, authority, RAR, SPIFFE
- **Why it matters:** Real RAR specification. Warrantor T2 authority-spec / P1 AAE compose RAR authorization_details with SPIFFE principals and Cedar multi-agent least privilege (see also cedar-agentic-aws + SPIFFE entries).

- **Note:** Warrantor composition (AAE envelope) is not this RFC alone — multi-source: RAR + SPIFFE + Cedar.

### AI Agent Observability — Evolving Standards and Best Practices

- **Author/publisher:** OpenTelemetry Blog
- **URL:** https://opentelemetry.io/blog/2025/ai-agent-observability/
- **Tier:** canonical
- **Date/recency:** 2025–2026
- **Maps to:** `P2`, `E1`, `T1`, `X2`
- **Tags:** AAR, receipts, evidence
- **Why it matters:** Real OTel GenAI agent observability writeup. P2 AAR / E1 flight-recorder compose signed action receipts from GenAI span semantics + transparency-log thinking (RFC 6962) + COSE (RFC 9052).

- **Note:** Warrantor AAR packaging is multi-source: OTel GenAI + Certificate Transparency log design + COSE signing.

### PROV-Overview: An Overview of the PROV Family of Documents

- **Author/publisher:** W3C
- **URL:** https://www.w3.org/TR/prov-overview/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `P4`, `P3`, `E1`
- **Tags:** AMIL, memory, integrity
- **Why it matters:** Real W3C PROV overview. P4 AMIL models agent memory integrity as provenance graphs with hash-chained integrity (PROV + Merkle CT patterns).

- **Note:** Warrantor AMIL has no single public twin; compose PROV + Merkle transparency designs.

### HELM — Holistic Evaluation of Language Models

- **Author/publisher:** Stanford CRFM
- **URL:** https://crfm.stanford.edu/helm/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `P8`, `A1`, `A5`, `A6`
- **Tags:** VEB, evaluation, bundles
- **Why it matters:** Real HELM evaluation framework. P8 VEB packages signed evaluation artifacts using HELM/Inspect-style content standards bound with COSE/Sigstore.

- **Note:** Warrantor VEB is a packaging/signing layer over HELM/Inspect/evals content — not a HELM feature.

### SPIRE Concepts — Attestation, Agents, and Trust Domains

- **Author/publisher:** SPIFFE Project
- **URL:** https://spiffe.io/docs/latest/spire-about/spire-concepts/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `P12`, `R1`, `R2`, `R8`, `C1-1`
- **Tags:** CAP, attestation, capabilities
- **Why it matters:** Real SPIRE concepts page. P12 CAP binds runtime capabilities to attested environments (SPIFFE selectors + sandbox + GPU CC quotes).

- **Note:** Warrantor CAP profile also draws Wasmtime capability models and NVIDIA CC attestation (separate entries).

### OpenID Shared Signals Framework Working Group

- **Author/publisher:** OpenID Foundation
- **URL:** https://openid.net/sg/sharedsignals/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `R3`, `P1`, `P7`, `I1`
- **Tags:** kill-switch, revocation, CAEP
- **Why it matters:** Real OpenID Shared Signals / CAEP home. R3 KillSwitchKit maps continuous access evaluation and emergency revoke events to this signal plane.

- **Note:** Warrantor kill-switch policy/execution layer is additional; SSF provides the continuous-evaluation event model.

### RFC 8610 — Concise Data Definition Language (CDDL)

- **Author/publisher:** IETF
- **URL:** https://www.rfc-editor.org/rfc/rfc8610.html
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `A6`, `T2`, `P1`, `P2`
- **Tags:** conformance, CDDL, testing
- **Why it matters:** Real CDDL specification used by Warrantor protocol schemas. A6 conformance suites pair CDDL schemas with multi-implementation adversarial vectors.

- **Note:** Conformance culture also follows SPIFFE multi-impl discipline; CDDL is the schema primary.

### NIST AI Risk Management Framework (AI RMF 1.0)

- **Author/publisher:** NIST
- **URL:** https://www.nist.gov/itl/ai-risk-management-framework
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `A3`, `A4`, `S5`
- **Tags:** bias, fairness, NIST
- **Why it matters:** Real NIST AI RMF. A3 BiasSentinel measurement posture tracks NIST Measure functions and model-card metrics.

- **Note:** Duplicate domain with nist-ai-rmf entry is intentional multi-map; A3-focused why text.

### SLSA — Supply-chain Levels for Software Artifacts

- **Author/publisher:** OpenSSF
- **URL:** https://slsa.dev/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `S8`, `S2`, `P6`, `F1`
- **Tags:** training, integrity, SLSA
- **Why it matters:** Real SLSA framework. S8 TrainGuard signed training attestations map onto SLSA provenance levels (with in-toto steps).

- **Note:** Also see in-toto entry for multi-step attestation layout.

### vLLM Documentation — High-Throughput LLM Serving

- **Author/publisher:** vLLM Project
- **URL:** https://docs.vllm.ai/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `N3`, `N1`, `R4`
- **Tags:** gateway, inference, proxy
- **Why it matters:** Real vLLM docs (primary open serving stack). N3 InferenceProxy industry patterns (auth, rate-limit, prompt-filter, semantic cache) sit in front of engines documented here and the OpenAI API surface.

- **Note:** Gateway behavior is composed across N1/N3 designs; this entry anchors the serving plane primary.

### Model Context Protocol Specification (latest)

- **Author/publisher:** MCP Project
- **URL:** https://modelcontextprotocol.io/specification/latest
- **Tier:** canonical
- **Date/recency:** 2025–2026
- **Maps to:** `X3`, `X8`, `A1`, `A6`
- **Tags:** harness, OSAF, agents
- **Why it matters:** Real MCP specification. X3 OpenHarnessSpec aims at vendor-neutral harness contracts; closest live tool/harness wire standard is MCP, with Inspect/evals as eval harness counterparts.

- **Note:** Warrantor OpenHarnessSpec is OSAF-proposed; not identical to MCP — multi-source with Inspect + NOOA.

### CycloneDX Bill of Materials Standard (ECMA-424)

- **Author/publisher:** OWASP / Ecma
- **URL:** https://cyclonedx.org/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `P11`, `S9`, `X9`, `S4`
- **Tags:** remediation, VEX, PRB
- **Why it matters:** Real CycloneDX standard (incl. VEX capabilities). P11 PRB packages signed remediation proofs using VEX-style status + in-toto steps + transparency logs.

- **Note:** Warrantor PRB composition also uses in-toto + Sigstore (separate entries).

### Model Context Protocol Specification (latest)

- **Author/publisher:** MCP Project
- **URL:** https://modelcontextprotocol.io/specification/latest
- **Tier:** canonical
- **Date/recency:** 2025–2026
- **Maps to:** `P5`, `X8`, `S4`, `T1`
- **Tags:** skills, MCP, SSP
- **Why it matters:** Real MCP specification for tool schemas. P5 SSP wraps tools/skills as signed packages for X8 admission — MCP tool contracts + Cosign/JSON-LD manifests.

- **Note:** Warrantor Secure Skill Package signing/packaging is multi-source with Sigstore + JSON-LD.

### MITRE ATLAS — Adversarial Threat Landscape for AI Systems

- **Author/publisher:** MITRE
- **URL:** https://atlas.mitre.org/
- **Tier:** canonical
- **Date/recency:** ongoing
- **Maps to:** `X9`, `P9`, `R3`, `A5`
- **Tags:** incidents, ATLAS, OCSF
- **Why it matters:** Real MITRE ATLAS knowledge base. X9/P9 normalize agent incidents using ATLAS techniques plus OCSF event classes.

- **Note:** Warrantor AIX incident exchange also requires OCSF schema entries.

### Industry Leaders Join Open Secure AI Alliance for AI Safety (NOOA + OpenShell)

- **Author/publisher:** NVIDIA Blog
- **URL:** https://blogs.nvidia.com/blog/open-secure-ai-alliance/
- **Tier:** canonical
- **Date/recency:** 2026-07-27
- **Maps to:** `X2`, `X3`, `R1`
- **Tags:** NOOA, OSAF, NVIDIA, agent-harness
- **Why it matters:** OSAF launch post announcing NOOA (NVIDIA Labs Object-Oriented Agent) open source harness research and alliance membership — primary for X2 nooa-ext and X3 open-harness-spec.

### Lightwell — Red Hat

- **Author/publisher:** Red Hat
- **URL:** https://www.redhat.com/en/lightwell
- **Tier:** canonical
- **Date/recency:** 2026
- **Maps to:** `S9`, `P11`, `S4`
- **Tags:** Lightwell, Red Hat, supply-chain
- **Why it matters:** Red Hat product page for Lightwell Network remediations and signed patched artifacts — second primary for S9 lightwell-bridge.

### NVIDIA Labs Object-Oriented Agents (NOOA) — GitHub

- **Author/publisher:** NVIDIA NeMo Labs
- **URL:** https://github.com/NVIDIA-NeMo/labs-OO-Agents/tree/main
- **Tier:** canonical
- **Date/recency:** 2026-07
- **Maps to:** `X2`, `X3`, `A1`
- **Tags:** NOOA, harness, NVIDIA
- **Why it matters:** Primary open-source NOOA repository (Apache 2.0) for object-oriented agent harness research — X2 nooa-ext integration target.

### Investigating three real-world incidents in our cybersecurity evaluations

- **Author/publisher:** Anthropic
- **URL:** https://www.anthropic.com/news/investigating-incidents-cybersecurity-evals
- **Tier:** canonical
- **Date/recency:** 2026-07-30
- **Maps to:** `X5`, `A1`, `R1`, `R3`, `E1`
- **Tags:** Anthropic, evaluations, incidents, containment
- **Why it matters:** Primary Anthropic disclosure reviewing 141,006 eval runs — direct catalyst for X5 RetroSpecKit and containment-focused evidence culture.

### SR 26-2: Revised Guidance on Model Risk Management

- **Author/publisher:** Federal Reserve Board
- **URL:** https://www.federalreserve.gov/supervisionreg/srletters/SR2602.htm
- **Tier:** canonical
- **Date/recency:** 2026-04-17
- **Maps to:** `A4`, `A1`, `X1`
- **Tags:** Fed, SR-26-2, model-risk, US, compliance
- **Why it matters:** Fed parallel issuance to OCC Bulletin 2026-13 — cite as Fed SR 26-2 / OCC 2026-13 for dual-audience US model-risk supervision.

