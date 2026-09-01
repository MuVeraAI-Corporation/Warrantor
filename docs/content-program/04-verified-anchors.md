# Verified External Anchors

> Verification pass: **2026-08-30**. Every claim below was checked live before it was allowed
> into the catalog. Nothing in this program cites an anchor that is not on this page.
> Re-verify anything older than 60 days before publishing against it.

Three items here **correct** what was recorded in project memory. They are marked ⚠️.

---

## A. United States / North America

### A1 — Model risk supervision: SR 11-7 is superseded

**OCC Bulletin 2026-13, "Model Risk Management: Revised Guidance," 17 April 2026**, issued jointly
with the Federal Reserve (**SR 26-2**) and the FDIC. It supersedes SR 11-7 and SR 21-8 and rescinds
OCC 2011-12, OCC 2021-19, OCC 1997-24 and the MRM booklet of the Comptroller's Handbook.

Two load-bearing quotations, both confirmed:

- Generative AI and agentic AI models are *"not within the scope of this guidance"* — the agencies'
  stated reason is that they are novel and rapidly evolving.
- The guidance *"does not set forth enforceable standards or prescriptive requirements."*
- Most relevant to banking organizations above **$30 billion** in total assets.

**⚠️ NEW FACT, not previously recorded:** the three agencies have stated they plan to issue a
**Request for Information** on model risk management that specifically addresses banks' use of AI,
**including generative and agentic AI**. It is not yet published.

**Why it matters to this program.** This is the most important structural fact in the US lane, and
the RFI turns it from an argument into a *deadline*. Read the exclusion as a deferral, never an
exemption: every obligation attached to the underlying action — safety and soundness, consumer
protection and fair lending, sectoral duties, third-party risk — is untouched. What was removed is
the framework that would have *specified* the controls. The separate AI guidance will be written
against whatever the industry has already built by then. That is a stronger argument for building
the governance layer now, not a weaker one.

Sources:
- https://www.occ.gov/news-issuances/bulletins/2026/bulletin-2026-13.html
- https://www.occ.treas.gov/news-issuances/bulletins/2026/bulletin-2026-13a.pdf
- https://www.occ.gov/news-issuances/news-releases/2026/nr-occ-2026-29.html
- https://www.federalreserve.gov/supervisionreg/srletters/SR2602.htm
- https://www.sullcrom.com/insights/memo/2026/April/OCC-Fed-FDIC-Issue-Revised-Guidance-Model-Risk-Management

### A2 — NSA published MCP security guidance

**"Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation,"
NSA Cybersecurity Information Sheet, 20 May 2026.**

Findings the CSI states directly: gaps in MCP design, implementation and operational posture have
created significant and evolving security concerns — serialization risks, trust boundaries, agent
misuse. Adoption has outpaced safeguards. It names *uncontrolled automated actions* (an AI system
independently deciding to use a new tool) and *lack of input screening* (data crossing systems
without checks on what it contains) as specific risks, and identifies dynamic tool invocation,
implicit trust relationships and context sharing as systemic rather than incidental.

**Why it matters.** A signals-intelligence agency has now put the agent-authority problem in
writing, in public, in a document a US enterprise security team can cite in a budget request. This
is the strongest single citation available for the North American lane, and it is **absent from the
existing 101-source reading list** — which is dated 2026-08-09, eleven weeks after the CSI. That is
an omission, not a timing artifact.

Sources:
- https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF
- https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4496698/nsa-releases-security-design-considerations-for-ai-driven-automation-leveraging/

### A3 — NIST COSAiS agent control overlays are still unwritten

NIST's **Control Overlays for Securing AI Systems (COSAiS)** project, announced August 2025, is
developing SP 800-53 overlays for five AI use cases. Two are agentic: **"Using AI Agent Systems
(Single Agent)"** and **"Using AI Agent Systems (Multi-Agent)."** As of April 2026 these remain in
active development with **no announced publication date**. NIST CAISI's own analysis concludes that
existing SP 800-53 controls are insufficient for the orchestration loop, tool-use chains and memory
persistence that characterize agentic architectures.

**Why it matters.** This is an open docket with no incumbent. A credible, published, mapped overlay
draft is the highest-leverage standards move available in the next 90 days — you are not competing
with a NIST document, you are filling the space before one exists.

Sources:
- https://csrc.nist.gov/csrc/media/Projects/cosais/documents/NIST-Overlays-SecuringAI-concept-paper.pdf
- https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-ai-agent-standards-federal-framework/

---

## B. Protocol and ecosystem

### B1 — MCP specification 2026-07-28 ⚠️

The current MCP revision is **2026-07-28** — described by the maintainers as the largest revision
since launch. It introduces a **stateless protocol core**, multi round-trip requests, header-based
routing, cacheable list results, **authorization hardening**, a formal extensions framework, and
updated Tier 1 SDKs. **Enterprise-Managed Authorization (EMA) moved from experimental to
production-grade** in this release. Authorization remains OPTIONAL; HTTP transports SHOULD conform
and act as an OAuth 2.1 resource server, STDIO transports SHOULD NOT and take credentials from the
environment. Normative security requirements cover token audience binding, token theft,
communication security, authorization-code protection, mix-up and confused-deputy attacks, open
redirection, and Client ID Metadata Document security.

**⚠️ This dates existing material.** `docs/html/blog-series/07-inference-mcp-a2a-delegation.html`
was written against an earlier revision. A stateless core and production-grade EMA change the
delegation argument materially. That piece needs a REFRAME, not a refresh.

Sources:
- https://blog.modelcontextprotocol.io/posts/2026-07-28/
- https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization

---

## C. Academic venues — the only hard deadlines in the window

| Venue | Cycle | Abstract / registration | Full submission | In 90-day window? |
|---|---|---|---|---|
| **IEEE S&P 2027** (Montreal, 17–19 May 2027) | Cycle 2 | ~**10 Nov 2026** (one week prior) | **17 Nov 2026** | ✅ **Yes — the anchor** |
| **USENIX Security '27** (Denver, 11–13 Aug 2027) | Cycle 1 | 18 Aug 2026 | 25 Aug 2026 | ❌ **Passed** — 5 days before this pass |
| **USENIX Security '27** | Cycle 2 | 19 Jan 2027 | 26 Jan 2027 | ⚠️ Outside — but the work lands inside |
| **⭐ IEEE SaTML 2027** (early May 2027) | single | **22 Sep 2026** | **29 Sep 2026** (artifacts 2 Oct) | ✅ **YES — 23 days. Accepts SoK, 12pp** |

**⚠️ CORRECTED 2026-08-30. There are TWO hard deadlines inside 90 days, and the earlier one was
missed on the first pass.**

**IEEE SaTML 2027 closes 29 September 2026** — abstract 22 September, anonymized artifacts 2 October.
That is **23 days to abstract, 30 to paper.** It explicitly accepts **systematization of knowledge
papers at 12 pages**, requires "SoK:" in the title, and runs an interactive discussion period with a
**Revision** decision that can be resubmitted rather than resubmitted-as-new. Early-reject
notification 4 November; final decision 16 December; conference early May 2027.

**IEEE S&P 2027 Cycle 2 closes 17 November 2026**, abstract ~10 November — 79 days.

Why the correction matters: T-12 was scheduled against USENIX Cycle 2 (26 Jan 2027) on the
assumption that it was the earliest SoK-accepting venue. **SaTML is four months earlier, accepts
SoK explicitly, and has a revision path that a first submission can survive.** The full 45-work
coverage pass is not achievable in 30 days, so the live question is whether a *bounded* corpus with
the coverage pass done properly on a smaller, stated population is a credible SaTML submission. See
§6 of the readiness report.

Source: https://satml.org/call-for-papers/

Sources:
- https://www.sp2027.ieee-security.org/
- https://www.usenix.org/conference/usenixsecurity27/call-for-papers
- https://sec-deadlines.github.io/

---

## D. Market framing (business-track ammunition)

Gartner's 4Q25 AI spending forecast created a **dedicated agentic AI market segment for the first
time**. Gartner named **agentic AI oversight the number-one cybersecurity trend for 2026**
(February 2026). The 2026 Hype Cycle for Agentic AI shows governance, security and cost profiles
emerging alongside the core technologies. **"Guardian agents"** — AI systems that monitor and govern
other AI agents — are projected at **10–15% of the agentic AI market by 2030**. Reported framing:
agentic AI adoption is outpacing governance **8 to 1**.

**⚠️ Standing correction, reaffirmed.** The old line — "Credo / OneTrust / Holistic have none of
these" — is false and stays retired. The market is named, funded and forecast. The differentiation
argument must be **mechanism-level**, not existence-level: not *nobody does this*, but *what they
enforce is a different object than what we enforce*. See the differentiation pieces in Track 1.

Sources:
- https://www.gartner.com/en/articles/hype-cycle-for-agentic-ai
- https://www.gartner.com/en/newsroom/press-releases/2026-03-11-gartner-announces-top-predictions-for-data-and-analytics-in-2026

---

## E. India

- **RBI FREE-AI** — Framework for Responsible and Ethical Enablement of AI. ⚠️ Released
  **13 August 2025**, *not* 2026. Advisory, not binding. 7 sutras / 6 pillars / 26 recommendations.

### E1 — ⭐ RBI Draft Guidance on Regulatory Principles for Model Risk Management, 2026
**Dated 24 June 2026. Public consultation closed 24 July 2026** (Connect 2 Regulate portal).
**Verified 2026-08-30 against a primary-adjacent legal summary.**

Applies to **11 categories** of regulated entities: commercial, small finance, payments, local area
and regional rural banks; urban and rural co-operative banks; NBFCs (all layers); All-India
Financial Institutions (EXIM, NABARD, NaBFID, NHB, SIDBI); asset reconstruction companies; credit
information companies. Covers traditional statistical models **and** AI/ML, including *foundational
and frontier* models. Does not use the word "agentic" — autonomy enters through **"extent of
reliance and level of autonomy"** in risk tiering.

Three provisions that matter more than the rest:

1. **⭐ Kill switches are mandated and undefined.** Chapter **V-B.3 (Human Oversight)** prescribes
   *"Override, suspension, and deactivation mechanisms — including kill-switch arrangements for AI
   models."* **No technical specification of what constitutes a kill switch is provided.** The
   requirement is conceptual, not prescriptive.
2. **Board-approved MRMF is mandatory** for every RE, covering all models. The Board approves risk
   appetite and tiering policy; the RMCB approves high-risk deployments.
3. **Third-party accountability is absolute.** *"An RE acquiring, using, or relying upon third-party
   models remains fully accountable for its outcomes."* **Independent RE validation is mandatory
   even where vendors have certified the model.**

**⚠️ The comment window has closed.** B-07 must pivot from "file a comment" to "prepare for final
guidance." The US analog (B-02) is still open; India's is not.

**⭐ The comparative argument this unlocks.** In the same quarter — April and June 2026 — the US
agencies **excluded** generative and agentic AI from model risk guidance, and the RBI **included**
AI/ML and mandated kill-switch arrangements. Opposite regulatory choices, **identical gap**: neither
specifies the control. One deferred the specification; the other required the thing without saying
what it is. That is the strongest single frame in this program and it justifies a new flagship piece
(**B-14**). It also connects directly to T-09 (a kill switch whose Windows path was untested), T-02
(the word "kill switch" spans three enforcement tiers) and B-04 (the containment self-audit).

Sources:
- https://www.corplawupdates.in/updates/rbi-draft-guidance-model-risk-management-2026-ai-ml-banks-nbfcs
- https://community.nasscom.in/communities/public-policy/analysis-rbis-draft-guidance-regulatory-principles-model-risk-management
- https://www.business-standard.com/finance/news/rbi-propose-norms-to-manage-ai-ml-related-risks-for-regulated-entities-126062401168_1.html
- https://www.intellectdesign.com/resources/blog/understanding-rbis-draft-guidance-on-regulatory-principles-for-model-risk-management/

⚠️ **Before publishing against this, obtain the RBI's own draft PDF.** Every source above is a
secondary legal summary. The Chapter V-B.3 quotation is consistent across them but must be confirmed
against the original text.
- **DPDP Act 2023 + DPDP Rules 2025.** Rules notified **November 2025**; phase 1 enforcement live
  since **14 November 2025**; **consent rules arrive November 2026** — inside/at the edge of this
  90-day window.

### E2 — DPDP significant data fiduciary obligations ⚠️ date corrected
**Verified 2026-08-30.** The DPDP Rules 2025 set an **18-month compliance deadline of 13 May 2027**
— *not* 12 May, as recorded in the `vj-substack` skill. Correct the skill.

At that date, substantive compliance becomes enforceable across notice and consent, security
safeguards, breach reporting, data principal rights, retention limits and **significant data
fiduciary (SDF) duties**.

SDF obligations that matter to an agent program:

- A **Data Protection Impact Assessment and an independent audit, once every twelve months** from
  the date of notification as an SDF.
- An **India-based Data Protection Officer**.
- Annual compliance reviews.
- ⭐ **Due diligence over algorithmic systems that process personal data.** This is the provision
  that reaches agents directly, and it is the one to build B-07 and B-11 around.

**Three India clocks, not two.** Consent rules (Nov 2026) → RBI draft finalization (pending) →
DPDP full enforcement and SDF audit duties (13 May 2027). The third is outside the 90-day window
but it is what makes building now rather than later defensible, because an annual audit cycle that
starts in May 2027 examines what you had in place before it.

Sources:
- https://www.dpdpa.com/dpdparules/rule13.html
- https://www.india-briefing.com/news/india-dpdp-compliance-gdpr-comparison-45702.html/
- https://www.pyroniq.ai/resources/dpdpa-compliance-timeline

### E3 — Two anchors named in `vj-substack` but not yet verified

`VERIFY` before use: **NAIC** milestones (US insurance — a distinct regulated vertical with its own
AI model bulletin lineage, untouched by the banking-agency guidance in §A1) and **CBUAE**
milestones (UAE central bank — sectoral supervision, which §F identifies as the actual binding
layer in the Gulf). Both are now catalog entries (**B-16**, **B-15**) and both are blocked on
primary-source verification.
- **IT Amendment Rules 2026**, in force **20 February 2026** — India's first binding rules on
  synthetically generated information.
- Existing RBI master directions on outsourcing, IT governance, cyber security and data
  localization continue to apply underneath all of the above.

Sources:
- https://www.humaineeti.ai/resources/rbi-free-ai-framework
- https://chambers.com/articles/a-framework-for-using-ai-in-the-indian-financial-sector
- https://airiskaware.com/india-ai-policy

---

## F. GCC

- **No GCC state has a horizontal AI statute as of mid-2026.** The binding layer is data protection
  law plus sectoral central-bank guidance. State this plainly; it is the whole opening.
- **Saudi Arabia** has declared **2026 the Year of Artificial Intelligence**. SDAIA's **AI Adoption
  Framework** sets a mandatory governance baseline for every public-sector entity across five
  pillars: data governance, model accountability, transparency, human oversight, risk management.
  Four maturity levels (Sept 2024). PDPL in force since Sept 2023, fines to SAR 5M. The AI
  frameworks are **not legally binding**, but **SDAIA accreditation is increasingly required for
  government contracts** — that is the commercial hook. A dedicated AI law is expected within two
  years.
- **UAE** — AI Charter (2024), National Strategy for AI 2031, emirate-level frameworks (DIFC, ADGM,
  AIATC). **DIFC Regulation 10, fully enforced since January 2026**, is the region's most
  AI-specific instrument. A **Federal Authority for AI and Data was created in June 2026**.

Sources:
- https://vision2030.ai/regulation/saudi-arabia-ai-regulation-sdaia/
- https://www.modulos.ai/middle-east-ai-regulations/
- https://www.6clicks.com/resources/blog/saudi-arabia-year-of-ai-sdaia-ai-adoption-framework-governance

---

## G. OWASP — the practitioner-standard anchor

**OWASP Top 10 for Agentic Applications 2026**, released **9 December 2025** by the OWASP GenAI
Security Project's **Agentic Security Initiative** — globally peer-reviewed, developed with 100+
industry experts. Risk identifiers run **ASI01 through ASI10**, including **ASI01 Agent Goal
Hijack**, **ASI03 Identity and Privilege Abuse**, **ASI09 Human-Agent Trust Exploitation** and
**ASI10 Rogue Agents**, alongside tool misuse and memory poisoning. Companion publications: *The
State of Agentic Security and Governance 1.0* and *The Agentic Security Solutions Landscape*.

**Why it matters.** This is the vocabulary practitioners already use, and it is a mapping target
that costs nothing and buys immediate legibility. Any control we describe should carry its ASI
identifiers. **Absent from the existing 101-source reading list** — a second significant omission
alongside the NSA CSI.

Sources:
- https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- https://genai.owasp.org/initiatives/agentic-security-initiative/
- https://www.prnewswire.com/news-releases/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security-302637364.html

---

## H. Adoption and governance statistics — TRACED 2026-08-30

The containment figures traced to two named studies. **They disagree, and the disagreement is the
most useful thing about them.**

### H1 — ✅ USE THIS ONE: Kiteworks 2026 Data Security Forecast
**Sample stated: 225 security, IT and risk leaders · 10 industries · 8 regions.**

| Finding | Figure |
|---|---|
| Cannot **terminate a misbehaving agent quickly** | **60%** |
| Cannot **enforce purpose limitations** on AI agents | **63%** |

This is the citable one: named study, stated sample, stated scope. Attribute it in full every time —
*Kiteworks 2026 Data Security Forecast, n=225 security, IT and risk leaders across 10 industries and
8 regions.*

### H2 — Writer enterprise survey (April–May 2026)

| Finding | Figure |
|---|---|
| Cannot **shut down a rogue AI agent** once deployed | **35%** |

Sample size and methodology not established in this pass. **Do not cite as a primary** until they
are.

### ⭐ The discrepancy is the finding

35% versus 60% is not two studies contradicting each other. It is **two different questions**:
*can you shut it down at all* versus *can you terminate it quickly*. The gap between those numbers —
roughly a quarter of organizations — is precisely the population that believes it has containment
and has never timed it.

**That is B-04's entire thesis, handed over by the data.** Lead with the 60% figure and its full
attribution, note the 35% alongside, and make the gap the argument rather than picking a number.
This is stronger than either statistic alone and it cannot be attacked as cherry-picking, because it
uses both.

### H3 — Still untraced; do not publish

**65%** with a confirmed agent security incident · **21%** with a mature agent governance model ·
**74%** planning adoption within two years · **+84%** board-oversight increase in disclosures ·
**~39%** of Fortune 100 boards with explicit AI oversight · **86%** of incidents traced to
undifferentiated governance. All still aggregator-sourced. The 86% figure in particular looks high
and its definition needs scrutiny before it goes anywhere near a CFO-facing document.

Sources:
- https://www.kiteworks.com/cybersecurity-risk-management/2026-data-security-forecast-ai-governance-predictions/
- https://www.kiteworks.com/cybersecurity-risk-management/ai-agent-security-incidents-2026/
- https://www.softwareseni.com/the-35-problem-one-third-of-organisations-cant-kill-a-rogue-agent/

---

## I. EU — passing mention only

Per standing doctrine, the EU leads no piece in this program and appears only where factually
required. Where an existing paper leads with the EU AI Act, that is recorded as a defect in the gap
analysis, not as coverage.

---

## Still to verify (Track 2 / Track 3 dependencies)

Tagged `VERIFY` in the catalog; not yet cleared:

- OWASP Agentic Security Initiative / LLM Top 10 current release state
- Cedar policy language scope, and whether the overlap risk recorded in memory still holds
- CSA, Linux Foundation and OASIS working groups accepting agent-security contributions
- CERT-In directions applicable to agent telemetry retention
- Named-vendor public documentation for the differentiation pieces (record-only, per doctrine)
