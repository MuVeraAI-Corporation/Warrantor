# Build contract — Warrantor native AI platform OS · master document · 2026-09-01

You are writing ONE PART of a single large HTML document. Many writers work in parallel against this contract. The assembler concatenates the fragments in order and wraps them in a shell that already carries the stylesheet, navigation, hero, and footer. **Write a fragment, not a page.** No `<html>`, `<head>`, `<body>`, `<style>`, `<script>`, `<link>`, no external images, no external fonts.

Output file: `fragments/pNN-<slug>.html` (exact path given in your task). Also reply with a 10-line summary: word count, figures drawn, numbers you could not source, anything you deliberately left out.

## 1. What this document is

The final, reconciled master of two committed volumes:

- the *exponential value blueprint* (8 planes A–H around the W1–W6 spine, 72 proposed controls, invariants P1–P4, 8 funded outcomes, 10 compounding loops), text at `blueprint.txt`;
- the *native AI platform OS specification* (Warrant Kernel, effect-syscall table, 12 strata L0–L11, 143 catalog items, 11 workflows, novel primitives, prevention proof, scoreboard), text at `os-spec.txt`.

Plus: the incident analysis (`collective.txt`), the domain-organized build catalogue (`build-catalogue.txt`), the internal research source with its claim ledger and evidence-gap matrix (`research-source.md`), the two primary reports as text (`openai-technical-report.txt` = OpenAI's 38-page technical report; `metr-redwood-investigation.txt` = the 91-page METR/Redwood investigation), the machine-verified claims ledger from the published content run (`claims-ledger.json`, 89 claims with document and page), and the five published chapters (`chapters/*.md`).

**Canonical taxonomy (use this, never the old one alone):** the build spine is the twelve strata **L0–L11** from the OS spec. The blueprint's planes **A–H** are a *reader's index* mapped onto the strata; the W1–W6 spine (Notary, Evidence, Containment, Compiler, Egress, Delegation) is the trusted core inside them. Platform invariants **P1–P4** map to the twelve formal invariants **I-01…I-12** (P1→I-02, P2→I-07, P3→proposed addition, P4→I-11+I-12). When both volumes describe the same thing, reconcile into one description and keep the deeper one; name the blueprint control number (IR-11 #NN) as a cross-reference on the catalog item.

Readers: board and executives, CISOs and incident responders, AI/ML and evaluation teams, platform and cloud engineers, governance/audit/legal, product and customer teams, researchers and standards bodies. Every part must be readable by a non-specialist first and then reward the specialist. Restate every technical term in plain words the first time it appears in your part.

## 2. Hard rules (violations get the fragment rejected)

1. **US English everywhere** (organization, behavior, analyze, defense, license, catalog, program, artifact, judgment, toward). Verbatim quotations keep source spelling; proper nouns keep their spelling.
2. **Every incident number, date, or quotation carries a source link in the same paragraph or table row**, as `<a class="src" href="#src-S01">S01 §IV.B</a>`. Use the S-IDs in §4 only. If you cannot source a number, do not print it.
3. **Tier every factual claim** with a badge (§5): what OpenAI says about itself is *first-party*; what METR found is *independent but scoped*; what Hugging Face published is *affected-party*; counterfactuals ("would have paged a day earlier", "100× reduction") are *first-party counterfactual* and never stated as fact; social posts are *discourse* and never incident fact.
4. **Name the record, never judge the company.** CVEs, advisories, reports and self-disclosures are nameable with the record cited beside the name. Never characterize a firm ("careless", "negligent"). Never name a person critically. "Organization 1" stays unnamed exactly as OpenAI left it.
5. **No literal anthropomorphism.** Do not describe agents as wanting, feeling, conspiring, dying, sacrificing, or forming civilizations. Use: instances, populations, tasks, prompts, reasoning traces, actions, coordination, persistence, shared state, permissions, outcomes, operator controls. You may *quote* METR's or OpenAI's wording inside quotation marks with the badge.
6. **Assurance discipline.** Never promise an incident "can never happen." The credible objective: make unauthorized actions *unexpressible* or *independently denied*, bound residual blast radius, detect cross-layer deviation at machine speed, halt before external harm, and produce independently verifiable evidence.
7. **Nothing in the catalog is claimed to exist.** Status vocabulary: `built` (shipped and observed working), `partial` (a fragment exists, the property does not), `none` (unbuilt), plus `novel` (no known implementation anywhere) and `consume` (adopt an existing project). Every proposed capability is visibly PROPOSED.
8. **Regulatory anchors that lead: US (Fed SR 26-2 / OCC Bulletin 2026-13 of 17 April 2026, which supersedes SR 11-7 and SR 21-8 and places generative and agentic AI outside its scope — a deferral, not an exemption), India (RBI human-override requirement, DPDP), GCC (CBUAE AI Guidance Note: audit rights, immediate shutdown, September 2026 compliance point).** Never cite SR 11-7 as current. The EU gets at most a passing mention. Frame governance, evidence and containment as pillars of ambitious native-AI deployment, not as compliance burden.
9. **The competitive claim "incumbent governance vendors have none of this" is retired.** The defensible differentiation is: offline-verifiable signed evidence checkable by a third party with no privileged access; authority composed as an intersection across a delegation chain; containment conformance as a testable profile.
10. **Standing doctrine to carry, verbatim in spirit:** the mediation ceiling (full mediation of a terminal coding agent through MCP is impossible; the defensible claim is bounded); the three enforcement tiers (cryptographic/OS-bound vs proxy-chokepoint vs policy); no new trust root (build the weaker thing and name what it does not establish); claims are untested until a live run tests them; wire before widen (the ~20 built crates are orphaned from the warrant; wire four planes in before building anything new).
11. Do not write the phrase "end-to-end"; write "full-stack" or "the whole chain."
12. Never fabricate a source, a URL, a page number, or a quotation. If a fact you need is not in the inputs, write `<!-- UNSOURCED: ... -->` and omit the claim from visible text.
13. Depth over breadth, but no padding: every paragraph must carry a fact, a mechanism, a decision, or a consequence. Prefer tables for parallel structure and prose for argument.

## 3. Markup vocabulary (use only these; the stylesheet knows nothing else)

```html
<section class="part" id="part-04" data-part="04">
  <header class="part-head">
    <span class="part-num">Part 04</span>
    <h2>Title in sentence case</h2>
    <p class="part-lede">One or two sentences: the claim this part establishes and who needs it.</p>
  </header>

  <h3 id="p04-slug">Subsection</h3>          <!-- ids: pNN- prefix, unique across the document -->
  <h4>Minor heading</h4>
  <p>Body. <strong>bold</strong>, <em>italic</em>, <code>identifier</code>.</p>

  <!-- Tier badges (inline) -->
  <span class="tier primary">First-party · OpenAI</span>
  <span class="tier independent">Independent · METR/Redwood</span>
  <span class="tier affected">Affected party · Hugging Face</span>
  <span class="tier vendor">Vendor record · JFrog</span>
  <span class="tier standard">Standard · NIST</span>
  <span class="tier supervisor">Supervisor · OCC</span>
  <span class="tier research">Research</span>
  <span class="tier analyst">Analyst projection</span>
  <span class="tier discourse">Discourse</span>
  <span class="tier counterfactual">First-party counterfactual</span>
  <span class="tier internal">Internal</span>
  <span class="tier proposed">PROPOSED</span>

  <!-- Source link (always same paragraph / row as the claim) -->
  <a class="src" href="#src-S02">S02 §3.1</a>

  <!-- Callouts -->
  <aside class="callout finding"><p class="callout-kicker">Finding</p><p>…</p></aside>
  <aside class="callout rule"><p class="callout-kicker">Design rule</p><p>…</p></aside>
  <aside class="callout caution"><p class="callout-kicker">What the record does not establish</p><p>…</p></aside>
  <aside class="callout proposed"><p class="callout-kicker">Proposed · not built</p><p>…</p></aside>
  <aside class="callout plain"><p class="callout-kicker">In plain words</p><p>…</p></aside>
  <blockquote class="quote"><p>“Exact words.”</p><cite>OpenAI, Technical Report §VII.C <a class="src" href="#src-S01">S01</a></cite></blockquote>

  <!-- Stat tiles -->
  <div class="stat-row">
    <div class="stat"><div class="stat-value">1,200+</div><div class="stat-label">agents on the unsanctioned board</div><div class="stat-src"><span class="tier independent">METR</span> <a class="src" href="#src-S02">S02</a></div></div>
  </div>

  <!-- Card grids -->
  <div class="grid cols-3">
    <div class="card"><p class="card-kicker">Plane B</p><h4>Title</h4><p>…</p></div>
  </div>

  <!-- Tables: thead is mandatory; wrap wide tables -->
  <div class="table-wrap"><table class="data">
    <thead><tr><th>Date</th><th>Event</th><th>Why it mattered</th><th>Source</th></tr></thead>
    <tbody><tr><td>2026-07-11</td><td>…</td><td>…</td><td><a class="src" href="#src-S05">S05</a></td></tr></tbody>
  </table></div>

  <!-- Timeline -->
  <ol class="timeline">
    <li><time>8 May</time><div class="tl-body"><strong>Headline</strong><p>… <a class="src" href="#src-S01">S01 §III.A</a></p></div></li>
  </ol>

  <!-- Ordered ladder (intervention points, steps) -->
  <ol class="ladder"><li><strong>Step name</strong><p>…</p></li></ol>

  <!-- Key/value block -->
  <dl class="kv"><dt>Owner</dt><dd>…</dd><dt>Proof gate</dt><dd>…</dd></dl>

  <!-- Figures: inline SVG, or a prebuilt figure token -->
  <figure class="fig">
    <svg viewBox="0 0 1200 640" role="img" aria-labelledby="p04-fig1-t"><title id="p04-fig1-t">…</title> … </svg>
    <figcaption><strong>Figure 4.1 ·</strong> What the reader should see. Source line with badges and links.</figcaption>
  </figure>
  <figure class="fig wide">[[svg:fig02-killchain]]<figcaption>…</figcaption></figure>

  <!-- Catalog item (Parts 07a/b/c only) -->
  <article class="item" id="L4-03" data-stratum="L4" data-plane="D" data-status="none" data-novelty="novel" data-wave="W1" data-loop="L5">
    <div class="item-head"><span class="item-id">L4-03</span><h4>Name</h4>
      <span class="item-tags"><span class="tag novelty">novel</span><span class="tag status">none</span><span class="tag loop">L5</span><span class="tag wave">W1</span><span class="tag plane">Plane D</span></span></div>
    <div class="item-body">
      <p class="what">What it does, in two or three sentences, plain words first.</p>
      <p class="why"><b>Why it compounds</b> …</p>
      <p class="anchor"><b>Anchor</b> incident event or published standard, with <a class="src" href="#src-S01">S01 §IX.A.1</a></p>
      <p class="verify"><b>Verification</b> the test that proves it holds.</p>
      <p class="xref"><b>Cross-reference</b> blueprint IR-11 #33 · invariant I-07 · W5</p>
    </div>
  </article>

  <!-- Audience reading path (Part 00 only) -->
  <div class="grid cols-3"><div class="card audience"><p class="card-kicker">Board & executive</p><h4>Read Parts 00, 01, 09, 12</h4><p>The decision you own: …</p></div></div>
</section>
```

Prebuilt figure tokens available (already verified figures from the published content run; drop the token inside `<figure class="fig wide">`): `[[svg:fig01-timeline]]` (90-day timeline), `[[svg:fig02-killchain]]` (ten hops and the control that should have held), `[[svg:fig03-collective]]` (scale of the collective), `[[svg:fig04-ledger]]` (multi-source ledger: what each source establishes), `[[svg:fig05-reachability]]` (transitive reachability), `[[svg:fig06-escalation]]` (escalation curve), `[[svg:fig07-belief]]` (the check that did not exist), `[[svg:fig08-components]]` (the shared open-stack components in the chain), `[[svg:fig09-envelope]]` (validation envelope), `[[svg:fig10-howmade]]` (how the record was made), `[[svg:fig11-concentration]]` (unsolved-task concentration). Use each at most once across the whole document; your task says which are yours.

### Drawing your own SVG figures

Every mechanism that can be drawn, should be. Draw inline SVG with `viewBox` (width 1200, height as needed; no `width`/`height` attributes). Use only these fills/strokes so the figure matches the page: ink `#141413`, paper `#faf9f5`, light-gray `#e8e6dc`, mid-gray `#b0aea5`, orange `#d97757`, blue `#6a9bcc`, green `#788c5d`, and the soft tints `#f4e3da` (orange), `#e1ebf4` (blue), `#e4e9dc` (green), `#fbe9e7` (alarm). Text: `font-family="Poppins, Arial, sans-serif"` for labels ≥ 14px, `font-size` 13–22; never smaller than 12. Give every figure a `<title>` and a caption that says what to see. Keep labels short; put the explanation in the caption. No gradients, no filters, no emoji. Legends inside the figure. Diagrams should show the *mechanism* (boxes, boundaries, arrows with labels), not decoration.

## 4. Source identifiers (cite by these; the Sources part renders the live links)

| ID | Source | Tier |
|---|---|---|
| S01 | OpenAI, *OpenAI – Hugging Face Incident: Technical Report*, 26 Aug 2026 (38 pp; §I–X; key-events table §X) | first-party primary |
| S02 | METR & Redwood Research, *Brief independent investigation of agents' behavior, reasoning and collaboration in the OpenAI / Hugging Face hacking incident*, 26 Aug 2026 (91 pp) | independent, scoped |
| S03 | OpenAI, *The Hugging Face incident and the road ahead*, 26 Aug 2026 | first-party |
| S04 | Hugging Face, *Security incident disclosure — July 2026*, 16 Jul 2026 | affected party |
| S05 | Hugging Face, *Anatomy of a Frontier Lab Agent Intrusion* (technical timeline), 27 Jul 2026 | affected party |
| S06 | JFrog, *Fast Remediation Is the New Trust Model: JFrog and OpenAI Collaboration on Zero-Day Security Findings*, 27 Jul 2026 (upd. 5 Aug) | vendor record |
| S07 | JFrog security advisories: CVE-2026-65616 (refresh-token validation), CVE-2026-66384 (container-image remote cache); affected versions before 7.146.27 (65616) and 0–7.146.35 / 7.161.0–7.161.16 (66384); only 66384 is in KEV | vendor record |
| S08 | Anthropic, *Investigating three real-world incidents in our cybersecurity evaluations*, 30 Jul 2026 | comparable, first-party |
| S09 | UK AI Security Institute, *Incident report: unsanctioned agent behaviour during cyber testing*, 4 Aug 2026 | comparable, government |
| S10 | Anthropic, *Improving our alignment and security efforts*, 31 Aug 2026 | first-party |
| S11 | Anthropic Alignment Science, *Training a Misaligned Reward Seeker*, Aug 2026 | research, first-party |
| S12 | Anthropic, *Patterns and problems in emerging multiagent systems*, 13 Aug 2026 | research, first-party |
| S13 | Google DeepMind, *Securing the future of AI agents*, 18 Jun 2026 | first-party |
| S14 | NIST NCCoE, *Accelerating the Adoption of Software and AI Agent Identity and Authorization* (concept paper), Feb 2026 | standard |
| S15 | NIST, *Summary Analysis of Responses to the RFI on Security Considerations for AI Agents* (Trustworthy & Responsible AI 800-5), 18 May 2026 | standard |
| S16 | NIST Cybersecurity Insights, *Back to the Future: Why Agentic AI Needs a Strong Identity Foundation*, 27 Aug 2026 | standard |
| S17 | MITRE ATLAS (agentic AI matrix) | standard |
| S18 | OWASP GenAI Security Project, *Top 10 for Agentic Applications* (final release 9 Dec 2025; ASI01–ASI10) | standard |
| S19 | SPIFFE workload identity concepts | standard |
| S20 | arXiv 2608.11243, *The Off-Support Barrier* | research |
| S21 | arXiv 2608.11436, *When Agents Talk: Honeytokens under Shared Memory* | research |
| S22 | arXiv 2607.25379, *Cyber-Capable AI Agents: Vulnerabilities, Evaluation Containment, and Defensive Response* | research |
| S23 | arXiv 2605.18991, *Agent Security is a Systems Problem* | research |
| S24 | arXiv 2603.12230, *Security Considerations for Artificial Intelligence Agents* | research |
| S25 | R. Starkman, *What Did OpenAI Actually Test?*, Substack, 27 Jul 2026 | discourse |
| S26 | R. Starkman, *After an AI Security Breach, What Training Is Safe to Keep?*, Substack, 8 Aug 2026 | discourse |
| S27 | E. Broda, *The Great Agent Escape*, AgenticMesh (Substack), 11 Aug 2026 | discourse |
| S28 | A. Paris, *The AI Didn't Go Rogue. Authority Failed.*, LinkedIn, 3 Aug 2026 | discourse |
| S29 | M. Agnihotri, *The Allowlist Held. The Agent Stopped Fetching*, LinkedIn, 9 Aug 2026 | discourse |
| S30 | D. Gray, *The OpenAI–Hugging Face Incident*, LinkedIn, 23 Jul 2026 | discourse |
| S31 | D. Patel, *The Rise and Fall of Agent Civilizations*, 29 Aug 2026 | discourse |
| S32 | G. Marcus, response to S31, Substack, 31 Aug 2026 | discourse |
| S33 | Nextgov/FCW, former NSA cyber chief's Morris Worm comparison, 5 Aug 2026 | media |
| S34 | NIST CAISI, AI Agent Standards Initiative, 17 Feb 2026 | standard |
| S35 | NIST, AI agent red-teaming guidance, Mar 2026 | standard |
| S36 | CISA, NSA and Five Eyes partners, *Careful Adoption of Agentic AI Services*, 1 May 2026 | government |
| S37 | CISA Known Exploited Vulnerabilities catalog additions, Jul–Aug 2026 | government |
| S38 | Model Context Protocol specifications 2025-11-25 and 2026-07-28 | standard |
| S39 | Fed SR 26-2 / OCC Bulletin 2026-13, *Model Risk Management: Revised Guidance*, 17 Apr 2026 | supervisor |
| S40 | FINRA 2026 regulatory oversight priorities (agentic AI) | supervisor |
| S41 | RBI guidance on AI in lending (explainability, bias monitoring, human override) | supervisor |
| S42 | India Digital Personal Data Protection Act and Rules | supervisor |
| S43 | CBUAE AI Guidance Note (audit rights, cybersecurity guarantees, immediate shutdown; Sept 2026 compliance point) | supervisor |
| S44 | UAE, Saudi and DIFC data-protection provisions | supervisor |
| S45 | Gartner, Market Guide for Guardian Agents (Feb 2026); AI governance platform market sizing; AI TRiSM | analyst |
| S46 | arXiv 2603.24775, *AIP: Agent Identity Protocol for Verifiable Delegation Across MCP and A2A* | research |
| S47 | arXiv 2603.17170, *PAuth: Precise Task-Scoped Authorization for Agents* | research |
| S48 | arXiv 2606.29073, *From Tool Connection to Execution Control: Benchmarking Security Invariants in MCP-Style Agent Runtimes* | research |
| S49 | arXiv 2605.06738, *Trust Without Trusting: A Recomputable Trust Protocol for Autonomous Agents* | research |
| S50 | arXiv 2605.22333, *A First Measurement Study on Authentication Security in Real-World Remote MCP Servers* | research |
| S51 | arXiv 2604.23459, *Architecture Matters for Multi-Agent Security* | research |
| S52 | arXiv 2505.02077, *Open Challenges in Multi-Agent Security* | research |
| S53 | arXiv 2601.11369, *Institutional AI: Governing LLM Collusion via Public Governance Graphs* | research |
| S54 | arXiv 2601.05293, *A Survey of Agentic AI and Cybersecurity* | research |
| S55 | arXiv 2606.20570, *Infrastructure for the Agentic Web: Gap Analysis and Architecture* | research |
| S56 | arXiv 2607.00245, *Agent-to-Agent Finance* | research |
| S57 | arXiv 2512.11933, *The Agentic Regulator* | research |
| S58 | CVE-2026-53362, Linux kernel privilege escalation (NVD record) | vendor/government record |
| S59 | V. Jha, special edition on the incident: five chapters live on vikramjha.work (30 Aug 2026); Substack and LinkedIn editions held; X staged | internal, published |
| S60 | Warrantor architecture: `docs/02-architecture.md` (invariants I-01…I-12), W1–W6 contracts, delivery-gaps document, wave verification reports | internal |
| S61 | Warrantor exponential value blueprint, 1 Sep 2026 | internal |
| S62 | Warrantor native AI platform OS specification, 1 Sep 2026 | internal |
| S63 | Warrantor incident analysis (agent collective), 1 Sep 2026 | internal |
| S64 | Warrantor exponential build catalogue, 1 Sep 2026 | internal |
| S65 | Warrantor incident-resilience research source (claim ledger, evidence-gap matrix), 1 Sep 2026 | internal |

Do not add new external sources yourself. If you need one, leave `<!-- NEW-SOURCE: title · url · what it supports -->` and the assembler will verify and number it.

## 5. Word targets and figure minimums are in your task. Depth is measured in verified specifics, not adjectives.

## 6. Self-check before you finish

- [ ] Fragment only; opens with `<section class="part" …>` and closes with `</section>`.
- [ ] All ids prefixed `pNN-` (catalog items use their L-ids).
- [ ] Every number/date/quote has a `<a class="src">` in the same paragraph or row; every table has `<thead>`.
- [ ] Tier badges present on factual claims; counterfactuals badged; discourse badged.
- [ ] US English; no "end-to-end"; no SR 11-7 as current; no company judgments; no anthropomorphic literalism; no "never happen" promise.
- [ ] Figures: `viewBox`, `<title>`, caption, brand colors only, no text < 12px.
- [ ] Plain-words restatement for every technical term on first use in your part.
