# V1 Baseline Audit

> Audited: 2026-08-28  
> Input: [`../curated-sources.json`](../curated-sources.json)  
> Purpose: establish measurable migration requirements; this is not a quality judgment on sources
> that have not yet been individually re-verified.

## Measured baseline

| Measure | Result |
|---|---:|
| Entries | 101 |
| Unique domains | 57 |
| Legacy clusters | 12 |
| Legacy component/protocol IDs covered | 66 of 66 |
| Entries labeled `canonical` | 91 |
| Entries labeled `deep-secondary` | 10 |
| Entries with an explicit 2024–2026 year token | 33 |
| Entries with an explicit pre-2024 year token | 19 |
| Entries with no usable year or only `ongoing` | 49 |
| Exact canonical-URL duplicate groups | 13 |
| Normalized-title duplicate groups | 11 |
| Median `why` annotation length | 13 words |
| Mean `why` annotation length | 14.2 words |
| Longest `why` annotation | 28 words |

## Duplicate evidence inflation

The v1 generator counts entries rather than unique intellectual works. At least 13 canonical URLs
are reused by multiple records, usually to fill separate portfolio mappings. V2 will retain one
source and attach every applicable mapping.

| Canonical work | Duplicated v1 IDs |
|---|---|
| SPIRE Concepts | `spire-concepts`, `cap-attestation` |
| MCP specification | `mcp-spec-latest`, `x3-harness`, `p5-skills` |
| OAuth RAR / RFC 9396 | `oauth-rar`, `t2-aae-authority` |
| CycloneDX | `cyclonedx-home`, `p11-remediation` |
| OpenTelemetry agent observability article | `otel-genai-agents`, `p2-aar-receipts` |
| HELM | `helm-home`, `p8-veb` |
| vLLM documentation | `vllm-docs`, `semantic-cache-gateway` |
| OpenID Shared Signals | `ssf-caep`, `kill-switch-patterns` |
| MITRE ATLAS | `mitre-atlas`, `aegis-incident` |
| NIST AI RMF | `nist-ai-rmf`, `bias-fairness` |
| SLSA | `slsa`, `train-integrity` |
| W3C PROV | `w3c-prov`, `p4-memory-integrity` |
| CDDL / RFC 8610 | `cddl-rfc`, `conformance-testing` |

## Missing v2 evidence fields

All 101 records lack the fields required to make quality, access, and relevance auditable:

- normalized source class;
- exact publication and revision dates;
- canonical URL distinct from discovered URL;
- free-full-text and access-friction status;
- detailed summary and technical contribution;
- methodology, findings, limitations, and incentives;
- category-specific quality dimensions, score, band, and rationale;
- claim confidence;
- mappings to current W1–W6 products and current standalone capabilities;
- claims supported, challenged, or bounded;
- architectural, implementation, business, regulatory, academic, and content implications;
- relationships to duplicate, superseded, related, and conflicting sources;
- reader path and reading priority; and
- metadata, content, access, and link verification status.

## Coverage weaknesses requiring research

1. **Current taxonomy mismatch:** coverage is measured against the historical 54-component and
   12-protocol portfolio rather than the authoritative current Warrantor product model.
2. **Documentation-heavy evidence:** standards and official documentation are valuable, but the
   baseline contains only three `arxiv.org` entries and does not systematically identify
   peer-reviewed versions, methods, datasets, artifacts, or contradictory research.
3. **Recent-window uncertainty:** nearly half the entries use `ongoing` or no usable year, so they
   cannot yet be shown to satisfy the 2024-08-28 to 2026-08-28 main-window rule.
4. **Shallow annotations:** 8–28 words cannot capture technical mechanisms, methods, limitations,
   incentives, applicability, or recommendations.
5. **No claim ledger:** topical mapping is not evidence that a source supports the repository's
   actual architectural, novelty, regulatory, market, or implementation claim.
6. **No contradiction model:** the baseline cannot represent disconfirming sources, unresolved
   disputes, or scope limitations.
7. **No free-access audit:** an HTTPS URL does not prove that substantive full text is freely
   accessible.
8. **No entity analysis:** authors, institutions, venues, blogs, and research groups are not
   evaluated independently of individual sources.
9. **No current recommendation layer:** sources do not yield explicit adopt, modify, defer, reject,
   or monitor recommendations tied to repository decisions.
10. **No source-class-aware ranking:** `canonical` conflates normative authority, publisher
    authority, relevance, implementation status, and evidence quality.

## Migration requirements

- Re-verify rather than automatically promote all 101 records.
- Collapse exact and semantic duplicates before coverage calculations.
- Resolve current versions and label indispensable pre-2024 foundations separately.
- Map every verified source to current products, standalone capabilities, historical IDs, and
  claim records.
- Preserve rejected and superseded candidates with reasons to prevent repeated rediscovery.
- Generate all user-facing artifacts from schema-validated structured data.

