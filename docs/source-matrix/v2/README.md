# Warrantor Research Library v2 — Working Data

This directory is the non-destructive working area for the maximum-depth research library. The
existing v1 files in the parent directory remain untouched until v2 evidence, migration, and
rendering are verified.

## Files

- [`../research-protocol-v2.md`](../research-protocol-v2.md) — confirmed scope, quality rules,
  research method, and completion standard.
- [`baseline-audit.md`](baseline-audit.md) — measured defects and migration requirements in the
  101-entry v1 dataset.
- [`source-record.schema.json`](source-record.schema.json) — validation contract for every source.
- [`source-library.schema.json`](source-library.schema.json) — collection-level validation contract
  for the promoted source library.
- [`claim-record.schema.json`](claim-record.schema.json) — validation contract for repository
  claims and their supporting, limiting, or contradicting evidence.
- [`candidate-record.schema.json`](candidate-record.schema.json) — validation contract for
  discoveries that have not yet passed full source review and scoring.
- [`candidates.json`](candidates.json) — 201 deduplicated discoveries and review records, including
  promoted sources and explicitly bounded follow-up candidates.
- [`gap-matrix.md`](gap-matrix.md) — living coverage, weakness, and saturation control.
- [`comparator-matrix.md`](comparator-matrix.md) — feature- and evidence-level comparison of the
  twenty core systems plus specialized attack-corpus and attack-to-policy comparators changing
  novelty and build/consume decisions.
- [`artifact-review-attack-to-policy-loop.md`](artifact-review-attack-to-policy-loop.md) —
  nine-source prior-art review, Falco Talon and KubeArmor artifact receipts, current experimental
  implementation audit, threat model, state machine, metrics, standards composition and the
  decision to contradict broad novelty while retaining a narrower evidence-bound R10 profile.
- [`artifact-review-commercial-attack-to-policy-prior-art.md`](artifact-review-commercial-attack-to-policy-prior-art.md)
  — 1,100-line commercial WAF/RASP/XDR/SOAR and patent pressure test; current F5, Defender,
  Datadog and Splunk lifecycles; three older disclosure claim charts; fifty release-blocking
  vectors; adapter architecture; revised novelty, product, academic, procurement and content
  recommendations; and an explicit patent-evidence-versus-legal-opinion boundary.
- [`artifact-review-safe-aix-incident-exchange.md`](artifact-review-safe-aix-incident-exchange.md)
  — 1,000-line SAFE/AIX prior-art and implementation audit; pinned OCSF 1.9 compilation;
  reproduced X9 class/field incompatibility; ETSI AICIE schema defect analysis; OECD, AAAI,
  CISA, STIX/TAXII, CSAF, FIRST, Qatar and Saudi crosswalks; recommended layered profile;
  seventy-six release-blocking vectors; and product, research, regional and content decisions.
- [`artifact-review-runtime-aibom.md`](artifact-review-runtime-aibom.md) — 920-line runtime-AIBOM
  source canon, implementation and standards-conformance audit, reproduced CycloneDX/SPDX and
  model-signing evidence, G7/CycloneDX/SPDX field crosswalk, assurance ladder, patent prior-art
  pressure test, threat corpus, standards-composed target architecture, regional paths, roadmap,
  academic program, and the decision to contradict broad novelty and Article 55 claims.
- [`artifact-review-default-deny-egress.md`](artifact-review-default-deny-egress.md) — 798-line W5
  source canon, current-code and trust-boundary audit, eight reproduced fail-open/trust
  counterexamples, pinned OpenShell 1,504-test receipt, OpenShell/Anthropic/Cloudflare/Kubernetes/
  Cilium/Istio/Landlock comparison, CaMeL/Fides/Silent-Egress prior art, regional crosswalks,
  seven-level assurance ladder, eighty-four negative vectors, target architecture, roadmap,
  academic program, content plan, audience paths, and an OpenShell-first consume decision.
- [`artifact-review-containment-kill-switch.md`](artifact-review-containment-kill-switch.md) — W3
  source canon and current-code audit; 92-test local receipt; twelve reproduced report, trust,
  simulation, revocation, authority and deadline counterexamples; C0-C7 assurance ladder;
  KillBench, SANDBOXESCAPEBENCH, ContainmentBench, VIGIL, AgentCore, NCSC/NIST, H.R. 9917,
  QCB/CBUAE and Wasmtime comparison; sixty release-blocking vectors; effect-observed coordinator,
  product options, regional paths, roadmap, academic program, content plan and reading paths.
- [`artifact-review-agent-attack-corpora.md`](artifact-review-agent-attack-corpora.md) — deep
  review and bounded reproduction of AgentFuzz, ASB, NIST AgentDojo, Chord/Les Dissonances,
  ToolHijacker, NSA MCP guidance and the skeptical firewall/benchmark critique; defines the
  independent authority-to-effect conformance profile Warrantor should build.
- [`business-claim-matrix.md`](business-claim-matrix.md) — market, pricing, procurement, regional,
  commercialization, and compliance-claim decisions with evidence gates.
- [`artifact-review-microsoft-agent-governance-toolkit.md`](artifact-review-microsoft-agent-governance-toolkit.md)
  — pinned implementation review and core policy-engine reproduction for the broadest comparator.
- [`evaluation-receipt-prior-art-matrix.md`](evaluation-receipt-prior-art-matrix.md) — field-level
  comparison, assurance profiles, novelty correction, and adopt/modify/defer decisions for signed
  AI evaluation evidence.
- [`evaluation-harness-integrity-matrix.md`](evaluation-harness-integrity-matrix.md) — pinned
  native-output review of garak, PyRIT, Inspect AI, AgentDojo, Hawk and Every Eval Ever, separating
  semantics, hashes, storage controls, signatures, measured execution and completeness.
- [`artifact-review-every-eval-ever.md`](artifact-review-every-eval-ever.md) — paper/schema review,
  pinned 1,043-test reproduction receipt and decision to consume EEE semantics while adding a
  Warrantor assurance profile.
- [`artifact-review-aqta-attestation-spec.md`](artifact-review-aqta-attestation-spec.md) — pinned
  multi-language verifier reproduction and trust-boundary review for ATTESTATION-v1/ACTION-v1.
- [`artifact-review-aerf-v0-2.md`](artifact-review-aerf-v0-2.md) — pinned v0.2 receipt-schema,
  verifier and adversary-corpus reproduction, including accepted tag-stripping and common-mode
  context limits.
- [`artifact-review-in-toto-attestation-v1-2.md`](artifact-review-in-toto-attestation-v1-2.md) —
  current v1.2 normative-layer review, Go/Python/Rust reproduction and Bundle completeness analysis.
- [`artifact-review-aevum-v0-9.md`](artifact-review-aevum-v0-9.md) — pinned 1,930-test and
  conformance reproduction, recorder-boundary analysis and demonstrated Rekor v2 incompatibility.
- [`artifact-review-saga-ndss-2026.md`](artifact-review-saga-ndss-2026.md) — pinned token and
  policy reproduction, concurrent quota-race demonstration and bounded formal-model review.
- [`artifact-review-sentinelagent-2604-02767.md`](artifact-review-sentinelagent-2604-02767.md) —
  pinned benchmark, NLI and TLA+ reproduction; signed-authority, expiry, scope/output,
  reconstruction and holder-authentication counterexamples; and exact proof-boundary review.
- [`artifact-review-alibaba-open-agent-auth.md`](artifact-review-alibaba-open-agent-auth.md) —
  pinned 13-module build, six-service protocol and broader integration receipts; delegation,
  identity, WPT, policy, MCP, audit and standards-conformance boundary review.
- [`artifact-review-authzen-coaz-mcp.md`](artifact-review-authzen-coaz-mcp.md) — final AuthZEN,
  draft COAZ and current MCP normative review; pinned source histories; 7/10 current-core method
  coverage finding; notification wildcard, mapping trust and exact permit-to-forward gap vectors.
- [`artifact-review-authzen-pdps-mcp-gateways.md`](artifact-review-authzen-pdps-mcp-gateways.md)
  — digest-verified Cerbos and OpenFGA AuthZEN executions plus Cerbos FastMCP and Vengtoo gateway
  reproductions; final-wire interoperability, semantic loss, method coverage, post-decision
  mutation, human-approval correlation and evidence-boundary findings.
- [`machine-checked-invariants-decision-matrix.md`](machine-checked-invariants-decision-matrix.md) —
  formal-assurance evidence ladder, property obligations, consume/build decisions and mandatory
  proof-to-code release gate.
- [`artifact-review-warrantor-transparency-stack.md`](artifact-review-warrantor-transparency-stack.md)
  — version, API, advisory, bootstrap and guarantee-boundary review of the bundled Rekor stack.
- [`artifact-review-warrantor-spiffe-spire.md`](artifact-review-warrantor-spiffe-spire.md) — official
  SPIRE validator receipt, Kubernetes topology audit and SPIFFE ID-versus-SVID evidence correction.
- [`operational-trust-decision-matrix.md`](operational-trust-decision-matrix.md) — integrated
  adopt/modify/reject decisions for signing, transparency, time, workload identity, mTLS,
  authorization, mediation and event-set completeness.
- [`attestation-substrate-decision-matrix.md`](attestation-substrate-decision-matrix.md) — DSSE,
  in-toto, RATS/EAT/CMW, SCITT/COSE Receipts and AERF property map, recommended composition,
  completeness protocol and implementation roadmap.
- [`implementation-dependency-map.md`](implementation-dependency-map.md) — repository-specific
  dependency, release, observability, workload-identity, sandbox, and disclosure evidence map.
- [`candidate-ledger.schema.json`](candidate-ledger.schema.json) and
  [`claim-ledger.schema.json`](claim-ledger.schema.json) — collection-level validation contracts.
- [`rejection-record.schema.json`](rejection-record.schema.json) and
  [`rejection-ledger.schema.json`](rejection-ledger.schema.json) — explicit exclusion and
  reconsideration contracts that prevent weak-source rediscovery.
- [`sources.json`](sources.json) — 117 promoted, scored, deeply annotated source records: 47
  essential, 49 high-quality, 19 supporting and 2 gap-only; currently a verified multi-wave
  foundation rather than the completed library.
- [`claims.json`](claims.json) — 29 active repository claims with evidence reconciliation,
  including contradicted runtime-AIBOM novelty, current S4 implementation/conformance, and
  standalone Article 55 compliance claims plus contradicted W5 implementation, eBPF/Falco/
  Tetragon enforcement, present-tense non-bypassability, broad W3 absence, current containment-suite,
  cross-stack kill implementation and enacted-law/compliance claims.
- [`rejections.json`](rejections.json) — rejected, inaccessible, duplicate, retracted, and
  superseded candidates with bounded allowed uses and reconsideration triggers.
- `entities.json` — authors, institutions, venues, blogs, and research-group profiles.

## Integrity rules

1. A source is not promoted into `sources.json` until its title, authorship, date/version,
   canonical URL, free full-text access, and substantive relevance have been verified.
2. One intellectual work receives one canonical record. Preprint, conference, journal, blog, and
   repository manifestations are linked as versions rather than counted as independent evidence.
3. A repository claim is not marked `supported` merely because a source is topically related; the
   source must support the claim at its actual scope and level of strength.
4. Novelty claims remain `unresolved` until dedicated prior-art and disconfirmation searches are
   complete. Search failure is never treated as proof of nonexistence.
5. Every ranked source has a category-specific score rationale and a separate claim-confidence
   assessment.
6. Generated Markdown, HTML, essential lists, and reading paths must derive from the structured
   records rather than maintain independent source metadata.
