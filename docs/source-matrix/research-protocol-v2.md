# Warrantor Research Library v2 — Research Protocol

> Status: **Rounds 1–3 incorporated; execution started**  
> Prepared: 2026-08-28  
> Scope anchor: [`../03-portfolio-recut-v4.md`](../03-portfolio-recut-v4.md)  
> Existing-library baseline: [`curated-sources.json`](curated-sources.json)

## 1. Objective

Build a comprehensive, deeply annotated, quality-ranked evidence library for Warrantor: the
authority, enforcement, and evidence substrate for autonomous AI agents. The library must support
architecture, implementation, security assurance, prior-art analysis, standards work, enterprise
adoption, and defensible claims of novelty.

The current library is a useful provenance index, but it is not yet a maximum-depth research
library. Its 101 entries emphasize official documentation and specifications; it has limited
peer-reviewed coverage, limited counter-evidence, no explicit quality score, no claim-to-source
ledger, and short annotations. Version 2 must preserve what is valid while correcting those gaps.

## 2. Confirmed Round 1 decisions and open items

### Confirmed

- **Repository scope:** the entire repository, across every materially relevant domain rather than
  one narrowly bounded subject.
- **Uses:** product strategy, technical architecture, academic work, business work, and content
  creation. The synthesis must make recommendations rather than merely enumerate sources.
- **Reader level:** mixed. Later rounds will determine the exact reader groups and whether separate
  reading paths are required.
- **Perspective:** foundational work, state-of-the-art developments, practical implementation, and
  critical or skeptical analysis all receive coverage.
- **Publication window:** the main library covers 2024-08-28 through 2026-08-28. A separate,
  explicitly labeled appendix contains only indispensable older foundations. Continuously updated
  standards and documentation qualify when their current revision falls in the main window.
- **Geographic priority:** North America, India, and the Gulf Cooperation Council. Later rounds
  will distinguish publisher location from technical applicability and regulatory jurisdiction.
- **Access:** every included source must be freely accessible. A bibliographic record or abstract
  alone is insufficient when the substantive source is paywalled.
- **Allowed source classes:** peer-reviewed papers, preprints, conference proceedings, standards,
  specifications, government publications, university reports, vendor engineering blogs,
  independent expert blogs, think-tank reports, books or chapters, recorded talks, podcasts,
  courses, repositories, and technical documentation.
- **Vendors:** technically valuable vendor material is allowed, with commercial incentives and
  limitations labeled.
- **Balance:** academic rigor and practical usefulness have equal standing; fitness for the claim
  controls selection.
- **Collection shape:** both a comprehensive catalog and a smaller essential-reading canon.
- **Size:** no fixed source target. Quality, coverage, and evidence saturation determine the size.
- **Entity evaluation:** rank individual sources and also evaluate relevant authors, institutions,
  blogs, journals, conferences, and research groups.
- **Disagreement:** competing schools of thought and controversial claims receive explicit
  side-by-side treatment.
- **Exclusions:** no organization, business model, ideology, or jurisdiction is categorically
  excluded. Every source must still pass the quality and relevance rules.

### Confirmed in Round 2

- **Repository boundary:** inspect the outer project directory, the nested `aumos` repository,
  historical HTML/PDF strategy materials, and legacy AumOS/DefStack artifacts whenever they are
  exceptionally valuable. Analyze duplicates, obsolete documents, and superseded versions once,
  then map them to the current replacement.
- **Authority model:** the current Warrantor architecture is authoritative. Historical portfolios
  remain for provenance, prior-art comparison, and traceability.
- **Primary pillars:** W1 notary core, W2 evidence-before-commit envelope, W3 containment
  conformance, W4 policy compiler, W5 egress broker, and W6 delegation intersection all receive
  full coverage.
- **Standalone/research depth:** MCP mediation, evaluation receipts, runtime AIBOM, cross-language
  conformance, SAFE incident exchange, invariant attack corpora, bounded revocation,
  machine-checked invariants, attack-to-policy feedback loops, and confidential-computing
  attestation receive equal depth.
- **Killed portfolio:** the 21 killed components remain in the evidence map to verify whether
  consuming established technology is still the correct decision.
- **Decision pressure test:** independently challenge every build, consume, kill, merge, re-scope,
  and novelty decision. Attempt to disprove each claimed innovation through dedicated prior-art
  research before accepting a bounded novelty claim.
- **Claim verification:** fact-check material regulatory, market, incident, competitive, technical,
  and nonexistence claims across the repository.
- **Implementation tracks:** research Rust security, Go control planes, Python agent/evaluation
  systems, TypeScript and MCP, cryptography, storage, schema design, and cross-language protocols.
- **Operations tracks:** deployment, reliability, disaster recovery, observability, performance,
  scalability, secure releases, open-source governance, vulnerability disclosure, supply-chain
  security, documentation, and developer experience.
- **Business tracks:** competition, market categories, partnerships, commercialization,
  procurement, pricing, adoption barriers, and go-to-market strategy.
- **Academic tracks:** paper opportunities, research questions, hypotheses, evaluation design,
  benchmarks, and publication venues.
- **Content tracks:** evidence-derived blog series, technical explainers, whitepapers, executive
  briefs, and thought-leadership programs.
- **Outcome weighting:** architectural correctness, security assurance, defensible novelty,
  roadmap, adoption, academic credibility, commercial strategy, content authority, regulatory
  readiness, and ecosystem influence are equally important. The library may not optimize one by
  silently sacrificing another.
- **Geographic interpretation:** North America, India, and GCC priority applies to regulation,
  policy, buyers, use cases, technical ecosystems, authors, publishers, competitors, and partners.
  Within the GCC, emphasize Saudi Arabia, the UAE, and Qatar while retaining important evidence
  from Bahrain, Kuwait, and Oman.
- **Language:** English only.
- **Reader paths:** separate paths for executives/product leaders, architects, implementers,
  academic researchers, governance teams, and marketing/partnership/content teams.
- **Recommendations:** present maximum-depth options and trade-offs, then give a clear preferred
  recommendation and action classification. Surface findings that undermine current strategy,
  claims, or implementation.
- **Failure controls:** explicitly guard against unverifiable citations, weak-source padding,
  source-category confusion, duplicates, vendor capture, unsupported novelty, geographic bias,
  stale links/standards, shallow annotation, rigor/practicality imbalance, unfair rankings,
  suppressed contradictions, and recommendations detached from repository decisions.

### Still open

- search-wave, verification, link-checking, and saturation parameters;
- final artifact formats, navigation, visual presentation, location, and whether v1 files are
  replaced or preserved; and
- update cadence after the initial research library is completed.

### Confirmed in Round 3

- **Free-content gate:** substantive full content must be freely readable. Registration-only
  material may qualify only when it is genuinely free, reproducibly accessible, and uniquely
  valuable; lead-capture reports are otherwise excluded. A title or abstract alone does not
  qualify.
- **Fallback access:** authenticated archived copies may be used when the publisher URL is broken,
  with provenance and archive status clearly labeled.
- **Verifiable media:** talks, videos, podcasts, and courses require a transcript, slides, paper,
  repository, or detailed official notes sufficient to verify the material claims.
- **Repository gate:** ranked repositories require substantive documentation, accountable
  maintainers, a visible license, inspectable implementation, and technical importance or evidence
  of use. Abandoned repositories qualify only as indispensable historical foundations and are
  labeled accordingly.
- **Accountability gate:** exclude anonymous blogs, unattributed reports, unaccountable AI-generated
  content, and purely promotional material. Launch announcements may support dates, partnerships,
  or bounded first-party claims but not independent performance or safety claims.
- **Research-integrity handling:** retracted or withdrawn research is excluded from recommendations
  but may appear in a labeled integrity/controversy appendix.
- **Scoring:** use the 100-point common model in Section 7 with category-specific scorecards.
  Security relevance remains within rigor and Warrantor relevance to avoid double counting;
  engineering sources add an implementation-value subscore within those dimensions.
- **Bias handling:** commercial authorship is not an automatic penalty. Unsupported evidence,
  obscured incentives, non-reproducibility, or promotional framing affects the relevant dimensions.
- **Influence signals:** peer review is a bounded positive signal. Citation counts, venue prestige,
  stars, downloads, and social reach are contextual influence indicators, never substitutes for
  evidence quality.
- **Bands:** 90–100 essential, 80–89 high quality, 70–79 supporting, and below 70 excluded or
  retained only as clearly labeled gap evidence. A uniquely relevant sub-70 source may appear only
  in the gap tier with an explicit weakness statement.
- **Coverage-aware canon:** essential selection uses quality and portfolio coverage so crowded
  domains cannot displace important thin domains.
- **Tiered annotations:** essential entries receive approximately 600–1,200 words, high-quality
  entries 300–600 words, supporting entries 120–300 words, and older foundations 200–500 words.
- **Annotation completeness:** essential entries carry full verified citations, classification,
  detailed technical synthesis, methods, findings, limitations, incentives, Warrantor mappings,
  supported/challenged claims, architectural and business implications, related/conflicting
  evidence, audience/reading order, scoring rationale, confidence, and an adopt/modify/defer/reject/
  monitor recommendation.
- **Class-specific detail:** paper annotations include datasets, samples, baselines, metrics,
  statistical methods, artifacts, reproducibility, and follow-up questions. Standards include
  status, version, governance, maturity, security considerations, implementations, alternatives,
  and integration cost. Repositories include license, governance, activity, security posture,
  tests, architecture, dependencies, integration cost, vendor dependence, and bus factor.
  Regulatory entries identify legal status. Blog/whitepaper annotations separate demonstrated
  facts, vendor claims, interpretation, forecasts, and marketing.
- **Quotation policy:** use only short quotations when exact language matters, with page or section
  locators; prefer original synthesis.
- **Confidence:** record claim confidence separately from source quality.
- **Entity rankings:** evaluate authors and researchers by relevant work, expertise, transparency,
  influence, independence, and Warrantor relevance. Evaluate institutions separately for research,
  standards, engineering, regulation, commerce, and geography. Rank venues within fields and assess
  publishers/blogs by authorship, sourcing, corrections, depth, incentives, and consistency. Name
  leaders by role/domain rather than a misleading universal winner.

## 3. Research questions

The library must provide evidence for the following question families.

1. What established foundations and current systems are closest to each Warrantor capability?
2. Which claims are genuinely novel, which are compositions of prior art, and which are already
   implemented elsewhere?
3. Which mechanisms can make agent authority non-bypassable below the model layer?
4. What can an action receipt prove, and what can it not prove?
5. How should identity, delegated authority, revocation, policy, containment, egress, credentials,
   staging, settlement, and evidence compose?
6. What attacks, failure modes, and assurance methods apply to this composition?
7. Which standards and ecosystems should Warrantor consume, profile, extend, or avoid duplicating?
8. What evidence would enterprise security, audit, risk, compliance, and governance teams require?
9. What contradictory research or practical experience weakens Warrantor's thesis?
10. Where does the public evidence remain too thin to support a strong claim?

## 4. Coverage taxonomy

### 4.1 Current Warrantor products

- **W1 — Notary core:** canonicalization, verdict functions, signatures, identity binding, and
  trusted-computing-base minimization.
- **W2 — Evidence-before-commit envelope:** authorization evidence, delegation intersection,
  outcomes, runtime AIBOM, enforcement mode, attestation bundles, and verifiable receipts.
- **W3 — Containment conformance:** shutdown, fail-closed behavior, stop-anywhere semantics,
  elicitation, sandbagging resistance, chaos testing, and disconnected operation.
- **W4 — Cross-stack policy compiler:** policy languages, semantic equivalence, gateway/kernel
  enforcement, jurisdiction modules, and policy verification.
- **W5 — Egress broker:** default-deny networking, destination and data controls, credential
  isolation, exfiltration prevention, and model-belief-independent enforcement.
- **W6 — Delegation-chain intersection:** capability attenuation, authority inheritance,
  revocation, provenance, multi-agent delegation, and confused-deputy resistance.

### 4.2 Current standalone and added capabilities

- MCP gateway and tool mediation.
- Evaluation receipts and external scanner integration.
- Runtime-bound AI bill of materials.
- Cross-language and protocol conformance.
- SAFE finding and agent-incident exchange.
- Invariant attack corpora.
- Bounded revocation.
- Machine-checked invariants.
- Attack-finding-to-policy feedback loops.
- Independent verification CLI and developer experience.

### 4.3 Foundations and adjacent evidence

- Object-capability systems and proof-carrying authorization.
- OAuth, workload identity, zero trust, and continuous access evaluation.
- Distributed transactions, sagas, staged effects, and human approval.
- Tamper-evident logging, transparency systems, secure audit, and non-repudiation.
- Provenance, reproducibility, event schemas, and software/ML supply-chain assurance.
- Sandboxes, microVMs, containers, WebAssembly, kernel mediation, and reference monitors.
- Confidential computing, remote attestation, TEEs, and GPU attestation.
- Formal methods, model checking, policy verification, and protocol conformance.
- Agent security, prompt injection, tool poisoning, memory attacks, and multi-agent threats.
- AI control, monitoring, red teaming, evaluation science, and incident learning.
- Safety-critical shutdown, supervisory control, and resilient distributed systems.
- Enterprise governance, model risk, audit, regulation, and cyber-insurance evidence.

## 5. Source classes

Discovery and synthesis use this preference order, subject to fitness for the claim.

1. **Original evidence:** peer-reviewed papers, top-tier conference proceedings, original
   preprints with methods and artifacts, official datasets, statutes, standards, RFCs, regulatory
   records, primary incident reports, and patent publications when the question is prior art rather
   than implementation efficacy.
2. **Reference implementations:** official repositories, conformance suites, architecture
   documents, security audits, and authoritative technical documentation.
3. **Independent technical analysis:** reproducible security research, respected research-lab
   reports, deeply sourced expert analysis, and high-quality surveys or systematic reviews.
4. **First-party engineering:** technically substantive engineering blogs and whitepapers with
   concrete designs, measurements, limitations, or operational lessons.
5. **Discovery-only material:** news, marketing pages, listicles, forums, and social posts. These
   may identify leads but do not support consequential claims unless no stronger evidence exists,
   in which case the limitation must be explicit.

Source type does not determine quality by itself. A precise RFC can be stronger for a protocol
claim than a peer-reviewed paper; a reproducible systems paper can be stronger for a performance
claim than product documentation.

Patent publications receive a separate `patent` source class. They can establish an early public
disclosure, claimed mechanism, priority date, assignee history, and claim language, but they do not
establish that a product shipped, worked, scaled, was independently validated, or remains free of
other rights. Legal-status fields from aggregators are treated as search evidence rather than legal
opinions; consequential freedom-to-operate decisions require counsel and official-register review.

## 6. Inclusion and exclusion

### Include when

- the source materially informs at least one taxonomy node or consequential claim;
- authorship, publication venue, date, and canonical URL can be verified;
- the source contains technical substance beyond an announcement or product description;
- its evidence, argument, specification, implementation, or operational lesson is distinct; and
- conflicts of interest and access limitations can be labeled accurately.

### Exclude from the ranked library when

- it is an SEO listicle, unattributed aggregation, link farm, or generic overview;
- it merely repeats a stronger source without meaningful synthesis;
- the title, author, venue, date, or URL cannot be verified;
- a newer version supersedes it and the older version has no historical value;
- it makes consequential claims without visible evidence or a traceable primary source;
- it is purely promotional; or
- the material is inaccessible and its substantive claims cannot be verified.

Excluded candidates may remain in an internal rejection ledger with a reason so they are not
rediscovered repeatedly.

## 7. Quality scoring

Each included source receives dimension scores plus a written rationale. Scores rank sources
within a domain and source class; cross-class comparisons must preserve context.

| Dimension | Weight | Evaluation question |
|---|---:|---|
| Methodological or normative rigor | 20 | Are methods, definitions, assumptions, and evidence fit for the claims? |
| Technical depth | 15 | Does it expose mechanisms, protocols, measurements, proofs, or implementation detail? |
| Authority and provenance | 15 | Is it original work or an authoritative publisher for the subject? |
| Warrantor relevance | 15 | Does it materially change design, implementation, assurance, or positioning? |
| Reproducibility and inspectability | 10 | Are artifacts, data, code, test vectors, or normative language available? |
| Independence and incentive transparency | 10 | Are commercial, institutional, and ideological incentives disclosed and bounded? |
| Originality and information gain | 5 | Does it add evidence or concepts not better supplied elsewhere? |
| Durability | 5 | Is the link/version stable, citable, and likely to remain authoritative? |
| Recency or historical fitness | 5 | Is it current for a fast-moving claim or appropriately foundational? |
| **Total** | **100** | |

Quality bands:

- **90–100 — Essential:** exceptional primary or definitive evidence; default essential-reading
  candidate.
- **80–89 — High quality:** strong evidence or technical reference with only bounded limitations.
- **70–79 — Supporting:** useful and credible, but narrower, derivative, less reproducible, or
  incentive-constrained.
- **Below 70 — Discovery/gap only:** excluded from the ranked master list unless it is the only
  available evidence for a clearly labeled gap.

A numeric score never substitutes for the rationale. Legal authority, historical importance, and
normative status are recorded separately because they are not reducible to research quality.

## 8. Annotation schema

Every ranked entry should contain:

- stable identifier;
- exact title;
- complete authors or institutional author;
- publisher, venue, and source class;
- publication date, revision date, and version;
- canonical URL, DOI or standard identifier, and access date;
- open/paywalled status and artifact links;
- abstract-level summary written from verified content;
- detailed technical contribution;
- methodology, data, implementation, or normative mechanism;
- principal findings or requirements;
- limitations, threat-to-validity notes, and conflicts of interest;
- quality dimensions, total score, band, and score rationale;
- current-product mappings and historical component/protocol mappings;
- exact Warrantor claims supported, challenged, or bounded;
- architecture and implementation implications;
- relationships to superseded, supporting, and conflicting sources;
- recommended reading priority and intended reader;
- verification status and unresolved metadata or evidence gaps.

Direct quotations are optional and must be short, accurate, page- or section-located, and used only
when exact wording materially matters.

## 9. Evidence and contradiction matrix

Consequential claims receive a separate ledger with:

- claim identifier and exact wording;
- claim type: fact, inference, novelty, recommendation, legal requirement, or forecast;
- primary supporting sources;
- independent corroboration where appropriate;
- contradicting or limiting evidence;
- applicability constraints: version, jurisdiction, deployment model, threat model, or date;
- confidence level;
- unresolved gap; and
- next targeted search.

Novelty claims require explicit prior-art searches and may be reported only as bounded findings
such as "no directly equivalent public implementation was found within the searched classes and
date range." Absence of discovery is never proof of nonexistence.

## 10. Discovery and follow-up process

1. Inventory existing sources, normalize identifiers, and identify duplicates and superseded URLs.
2. Build answer slots for every taxonomy node and consequential Warrantor claim.
3. Run a first discovery wave across original research, standards, official implementations,
   independent security research, and substantive engineering sources.
4. Merge results before further searching; canonicalize URLs and cluster sources by contribution.
5. Populate the coverage, claim, contradiction, and gap matrices.
6. Run targeted follow-up waves only for thin nodes, disputed claims, missing original evidence,
   or missing counter-evidence.
7. Independently spot-check the highest-impact claims and all essential sources.
8. Annotate and score only after the relevant source or sufficient authoritative metadata has been
   inspected.
9. Record inaccessible, rejected, and superseded items separately.

## 11. Saturation and stopping criteria

There is no fixed source count. A domain is provisionally saturated when:

- every consequential claim has primary support or an explicit evidence limitation;
- foundational, current, implementation, and critical perspectives are represented where they
  exist;
- material disagreements are resolved or accurately bounded;
- the best-known standard, original research, implementation, and independent critique have been
  considered;
- recent targeted searches mostly return duplicates, derivative sources, or weaker evidence; and
- another search wave is unlikely to change the design conclusion, ranking, or confidence.

As a diagnostic rather than a quota, a mature domain will often contain multiple original research
works, normative/official references, implementation sources, and at least one independent or
adversarial perspective. Thin public evidence is recorded as a finding, not padded with low-quality
material.

## 12. Verification requirements

- Resolve every source to a canonical HTTPS URL where one exists.
- Verify titles, authors, dates, versions, venues, DOI/identifier, and access status.
- Prefer publisher pages over search-result, mirror, tracking, and transient download URLs.
- Check whether standards, specifications, and documentation have been superseded.
- Deduplicate preprint, conference, journal, blog, and repository versions while preserving the
  relationships among them.
- Recheck time-sensitive claims at synthesis time.
- Spot-check quoted text and page/section locators against the source.
- Validate structured data against a schema and test coverage calculations.
- Run link checks with bounded retries and distinguish broken, blocked, redirected, and temporarily
  unavailable URLs.
- Audit final artifacts for missing citations, unsupported claims, inconsistent scores, duplicate
  entries, rendering defects, and taxonomy gaps.

## 13. Completion standard

The v2 library is complete only when:

1. the interview decisions are incorporated or explicitly defaulted;
2. every in-scope taxonomy node has reached the saturation test or carries a documented evidence
   gap;
3. every included source is verified, classified, scored, annotated, and mapped;
4. every consequential synthesis claim is traceable through the evidence ledger;
5. competing evidence and limitations are visible rather than suppressed;
6. the essential-reading subset is derived transparently from relevance and quality;
7. structured and human-readable artifacts agree; and
8. automated and manual quality assurance find no unresolved high-severity defect.
