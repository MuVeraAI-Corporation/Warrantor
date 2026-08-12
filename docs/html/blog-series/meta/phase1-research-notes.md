# Phase 1 — Source Research Notes (Subagent Pass)

**Worker type:** research-agent ×3 (parallel)  
**Date:** 2026-08-09  
**Subagent IDs:**  
- `019fe768-7c85-79f3-bb53-5378b49f53e7` — authority / identity / authorization  
- `019fe768-7c85-79f3-bb53-538765b4ad22` — MCP / A2A / OpenShell / NOOA / red-team  
- `019fe768-7c85-79f3-bb53-5391a9641adf` — TEE / supply chain / evidence plane  

Full raw subagent transcripts are captured under the goal scratch dir as `phase1-research-subagent.log` (concatenated).

## Authority envelope composition (research consensus)

1. SPIRE issues short-lived SVID (SPIFFE ID) for agent process.  
2. User + task grant via OIDC → OAuth with **RAR** `authorization_details`.  
3. **DPoP** sender-constrains tokens.  
4. **RFC 8693** token exchange for OBO hops (`act` / `may_act`).  
5. **Cedar** (or OPA with equivalence tests) outside the LLM loop.  
6. **SSF/CAEP** (final Sept 2025) for continuous revoke / risk signals.

Primary URLs used in Essay 01:
- https://spiffe.io/ · https://spiffe.io/docs/latest/spire-about/spire-concepts/
- https://www.rfc-editor.org/rfc/rfc9396.html · rfc9449 · rfc8693
- https://aws.amazon.com/blogs/security/enforce-least-privilege-authorization-in-multi-agent-ai-chains-using-cedar/
- https://www.cedarpolicy.com/ · OPA docs

## Multi-agent + runtime (research consensus)

- MCP: Anthropic intro (2024-11) + spec 2026-07-28  
- A2A: Google launch 2025-04 + a2a-protocol.org + LF project  
- OpenShell: NVIDIA eng blogs 2026-03 (sandbox, policy, privacy router)  
- OSAF / NOOA: NVIDIA 2026-07-27 alliance + labs-OO-Agents + harness capabilities post  
- PyRIT / garak: Microsoft + NVIDIA primary repos/blogs  

Used in Essays 02, 07.

## TEE / supply / evidence (research consensus)

- nvtrust + H100 CC whitepaper/blog + Intel composite attestation  
- Sigstore Cosign/Rekor, CycloneDX ML-BOM, SPDX AI profile  
- Safetensors + HiddenLayer conversion-service research  
- Lightwell IBM/Red Hat 2026-05 / 2026-07  
- OTel GenAI agent observability (2025-03) + OCSF + OWASP AOS  

Used in Essays 03–06, 08.

## Gaps called out by research (honest)

| Gap | Handling in series |
|-----|-------------------|
| No single public “AAE RFC” | Essay 01: compose RAR+SPIFFE+Cedar; P1 is AumOS-native |
| NOOA is harness research, not containment | Essay 02: pair with OpenShell; X2 extends |
| CAEP says “robotic users” not “AI agent” | Essay 02: map agents to robotic subjects |
| Living specs evolve | Citations pin current primary URLs; dates in refs |

## Feed into Phase 2–4

Outline freeze = `phase-plan.md` series table. Drafts use only URLs appearing in this research pass or prior curated-sources.json (already title-aligned).
