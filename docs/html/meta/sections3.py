"""Positioning, remediation and annex sections + document assembly."""
from __future__ import annotations

import pathlib

from build_critical_analysis import (AUDIT_DATE, BRANCH, COMMIT, COMPONENTS, CSS, FINDINGS, JS, OUT,
                                     PROTOCOLS, bullets, esc, md, para, sev_pill, tag)
import sections as S
import sections2 as S2


def sec_regulatory():
    return f"""
<section id="regulatory">
<div class="eyebrow">12 &middot; Regulatory</div>
<h2>The evidence regulators actually demand &mdash; and how little of it Warrantor can produce</h2>
{para("The compliance matrix in `docs/cross-cutting/13-compliance-frameworks.md` leads with the EU AI Act, DORA and "
      "NIS2, and contains **no entry** for US model-risk supervision, RBI, DPDP, CERT-In, SDAIA, NCA, CBUAE or DIFC. "
      "That is precisely inverted relative to the stated primary markets. What follows is what those regulators "
      "actually ask for, verified against primary sources where the portals allowed it.")}
<h3>United States &mdash; the deferral is an argument <em>for</em> building this, not against</h3>
{para("**OCC Bulletin 2026-13 / Fed SR 26-2, issued 17 April 2026**, supersedes SR 11-7 and SR 21-8. Two things it "
      "says change the argument. First, verbatim from p.3 footnote 3: *“Generative AI and agentic AI models are novel "
      "and rapidly evolving. As such, they are not within the scope of this guidance.”* Second, and far more useful, "
      "the same footnote continues: *“a banking organization's risk management and governance practices should guide "
      "the determination of appropriate governance and controls for any tools, processes, or systems not covered in "
      "this document.”* That is supervisors telling banks **you own this gap** — a much stronger pitch than the "
      "exclusion sentence alone, and the half Warrantor's positioning currently does not use. Note also a new **$30bn "
      "materiality threshold** that did not exist under SR 11-7. [EXTERNAL]")}
<h3>India &mdash; one obligation is already live, and the governance blueprint is public</h3>
{bullets([
 "**CERT-In Directions 20(3)/2022 are binding today**, and Annexure I item (xx) makes *“attacks or "
 "malicious/suspicious activities affecting systems/servers/software/applications related to Artificial Intelligence "
 "and Machine Learning”* mandatorily reportable **within 6 hours**. This is the single most operationally significant "
 "AI obligation in India and it needs no new regulation. The same directions require **180 days of ICT logs held "
 "inside Indian jurisdiction** — an explicit localisation requirement that an agent platform's prompt, inference and "
 "decision logs plausibly fall inside. [EXTERNAL, primary]",
 "**RBI's draft Guidance on Regulatory Principles for Model Risk Management (24 June 2026, comments closed 24 July "
 "2026)** is the blueprint to build against. It covers AI/ML and generative AI explicitly and demands: a "
 "board-approved MRM framework, a **complete model inventory** (no model may be used unless inventoried), risk "
 "tiering, independent validation reported to the board risk committee within three months, **10-year retention of "
 "decommissioned-model records**, third-party model validation with supervisor audit rights, explainability and "
 "hallucination controls, **red-teaming records**, and a **kill switch / override mechanism**. Everything on that "
 "list is buildable now. [EXTERNAL]",
 "**DPDP Rules 2025** phase in: consent managers **14 Nov 2026**, core obligations **14 May 2027**. Operative "
 "artifacts are a **72-hour Board breach report** with five prescribed elements, **one year of traffic and processing "
 "logs**, an annual DPIA plus independent audit for Significant Data Fiduciaries with observations filed to the "
 "Board, and **algorithmic due diligence** — verification that algorithmic software does not risk data-principal "
 "rights. [EXTERNAL]",
])}
<h3>Gulf &mdash; DIFC Regulation 10 is the sharpest AI obligation anywhere in these markets</h3>
{para("**DIFC Regulation 10 on Personal Data Processed through Autonomous and Semi-Autonomous Systems**, enacted "
      "September 2023 under DIFC Law No. 5 of 2020, is the only binding **pre-market certification gate on high-risk "
      "AI processing** across India and the GCC. Reg 10.3.3: no System may be used, operated, provided, offered or "
      "made commercially available for High Risk Processing unless the Commissioner has established audit and "
      "certification requirements **and the System complies with them**. Certification assesses the *System*, not the "
      "applicant; it is awarded by an Accredited Certification Body; ACB accreditation runs five years and System "
      "certification a maximum of three; EU AI Act certification can be fast-tracked. It also introduces a "
      "**Deployer** role liable for the system *“in the same way it may be liable for an employee's actions.”* "
      "[EXTERNAL, primary]")}
{para("Alongside it: **CBUAE Model Management Standards** list *Artificial Intelligence* inside the model taxonomy and "
      "apply to **every licensed UAE bank irrespective of size**, demanding a full model inventory covering "
      "third-party and historical models with unique IDs, per-step dates, named responsible parties and prior "
      "validation outcomes. **Saudi SDAIA** operates a mandatory National Register of Controllers issuing a "
      "five-year, QR-coded, publicly verifiable certificate, with 72-hour breach filing. **NCA ECC-2:2024** contains "
      "**no AI-specific subdomain** — verified against the document. [EXTERNAL]")}
<h3>How Warrantor's artifacts map</h3>
<div class="tw"><table data-sortable>
<thead><tr><th>Evidence demanded</th><th>Warrantor artifact</th><th>Fit</th></tr></thead><tbody>
<tr><td>Model inventory with risk tiering (RBI, CBUAE, OCC)</td><td>P6 AATM</td><td><strong>Partial</strong> &mdash; has the binding graph, lacks materiality, exposure and intended-use fields, which are the axes regulators tier on.</td></tr>
<tr><td>Independent validation / effective challenge</td><td>P8 VEB, X6 metr-bridge</td><td><strong>Good shape, no implementation.</strong> P8 pins the judge; nothing encodes validator <em>independence</em> or organisational standing.</td></tr>
<tr><td>Red-teaming and adversarial test records (RBI)</td><td>A2 adversaria, A7 red-team-cloud</td><td><strong>Weak</strong> &mdash; corpus not mapped to ATLAS v5.4.0 or OWASP ASI01&ndash;10; no published attack-success numbers.</td></tr>
<tr><td>Kill switch / override (RBI)</td><td>R3 kill-switch</td><td><strong>Fails</strong> &mdash; it kills nothing.</td></tr>
<tr><td>6-hour AI incident report (CERT-In)</td><td>P9 AIX, X9 incident-exchange</td><td><strong>Weak</strong> &mdash; wrong OCSF class, eight schema versions stale, stale ATLAS mapping.</td></tr>
<tr><td>Purpose limitation and consent (DPDP)</td><td>P3 CPE</td><td><strong>Strongest fit in the portfolio</strong> &mdash; <code>consent</code>, <code>sensitivity</code>, <code>allowed_uses</code>, <code>derived_from</code> map almost directly. Claimed nowhere.</td></tr>
<tr><td>Register of AI processing activities (DIFC Reg 10)</td><td>P12 CAP + P6</td><td><strong>Close</strong> &mdash; P12 is nearly purpose-built for this and is unclaimed.</td></tr>
<tr><td>Audit trail for examiners</td><td>E1 flight-recorder, Rekor anchoring</td><td><strong>Fails, dangerously</strong> &mdash; no persistence, fabricated policy field, non-functional Rekor client.</td></tr>
<tr><td>One year of processing logs, 180 days in-country</td><td>&mdash;</td><td><strong>Absent.</strong> No retention or residency control exists in the evidence plane.</td></tr>
</tbody></table></div>
<div class="danger"><div class="calltitle">The compliance trap to close first</div>
{para("`defstack-cli compliance-report` emits a **signed** map claiming `did:web:aumos.dev` attested EU AI Act, NIST "
      "AI RMF, ISO 42001, FedRAMP, DORA and NIS2 — with nothing measured. **DIFC Regulation 6.2 makes misleading "
      "public representations about certifications or adherence to codes and standards independently enforceable.** "
      "In the exact market where P12 is most valuable, overclaiming governance posture is itself the violation. Delete "
      "this before anything else in the document.")}</div>
</section>"""


def sec_standards():
    rows = [
        ("P1 AAE", "IETF Transaction Tokens (WG Last Call 2026-07-30) &middot; OIDF AuthZEN AARP + COAZ (WG drafts "
                   "2026-06-15) &middot; RFC 8693 <code>act</code> &middot; <strong>Microsoft Entra Agent ID “access "
                   "envelope” (GA)</strong> &middot; AWS AgentCore Policy (GA, 13 regions)", "Contested, closing fast"),
        ("P2 AAR", "<strong>RFC 9942 COSE Receipts + RFC 9943 SCITT (published June 2026)</strong> &middot; "
                   "<code>draft-noa-scitt-ai-agent-receipt-00</code> &middot; Claude Managed Agents append-only "
                   "out-of-container log", "Severely preempted"),
        ("P3 CPE", "C2PA 2.4 (media and datasets, not runtime context) &middot; CycloneDX data provenance", "Whitespace"),
        ("P4 AMIL", "Nothing. Cisco detects memory poisoning; nobody makes memory verifiable.", "Whitespace, demand unproven"),
        ("P5 SSP", "MCP spec 2026-07-28 <em>explicitly lacks</em> server signing, tool integrity and registry trust; "
                   "MCP Registry is preview with namespace verification only &middot; Sigstore + OCI 1.1 referrers",
         "Real hole &mdash; but AAIF owns MCP"),
        ("P6 AATM", "<strong>CycloneDX 1.7 = ECMA-424 (Dec 2025)</strong> &middot; SPDX 3.0.1 AI + Dataset profiles "
                    "&middot; OpenSSF Model Signing (NVIDIA NGC, Kaggle adopting) &middot; in-toto VSA &middot; CoSAI "
                    "Signing ML Artifacts", "Fully covered"),
        ("P7 ABS", "<strong>AWS Dogwood — temporal Cedar operators <code>count_within</code>/<code>sum_within</code>, "
                   "blogged 2026-08-06</strong> &middot; LiteLLM budgets &middot; ServiceNow circuit breakers",
         "Closing fast"),
        ("P8 VEB", "promptfoo, Inspect, HELM, lm-eval-harness — <strong>none signs, none pins the grader</strong>. "
                   "NIST AI 800-2 asks for exactly this schema and names no candidate.", "<strong>Unoccupied</strong>"),
        ("P9 AIX", "<strong>OCSF 1.9.0 (2026-08-03) shipped <code>ai_agent</code>, <code>delegation</code>, "
                   "<code>message_context</code> across 40+ classes</strong> &middot; CoSAI AI Incident Response "
                   "Framework V1.0 &middot; OWASP ASI01&ndash;10", "Severely preempted"),
        ("P10 MADE", "RFC 8693 nested <code>act</code> (since 2020) &middot; identity-chaining at RFC Editor &middot; "
                     "<strong>Okta/Auth0 Cross App Access shipping this month</strong> &middot; A2A v1.0 signed agent "
                     "cards &middot; Biscuit (Eclipse)", "Heavily preempted"),
        ("P11 PRB", "Nothing comparable found &mdash; and no evidence anyone is asking.", "Novel, unvalidated"),
        ("P12 CAP", "NVIDIA NRAS + EAT (free) &middot; Intel Trust Authority (free on 3 clouds) &middot; RFC 9334 / "
                    "RFC 9711 &middot; LF Agent Name Service (intent only) &middot; AGNTCY Agent Badges",
         "<strong>Composition unoccupied, ~12-month window</strong>"),
    ]
    tr = "".join(f"<tr><td><strong>{p}</strong></td><td>{w}</td><td>{v}</td></tr>" for p, w, v in rows)
    return f"""
<section id="standards">
<div class="eyebrow">13 &middot; Standards landscape</div>
<h2>What shipped elsewhere while this was being built</h2>
{para("Every entry below was verified against a primary source &mdash; spec repository, RFC, registry or foundation "
      "announcement &mdash; with dates. The pattern is uncomfortable: several of these landed within days of this "
      "audit.")}
<div class="tw"><table data-sortable>
<thead><tr><th>Protocol</th><th>Who already covers it</th><th>Position</th></tr></thead><tbody>{tr}</tbody></table></div>
<div class="danger"><div class="calltitle">The three questions an external standards reviewer will open with</div>
<ol>
<li><strong>&ldquo;RFC 9942 and RFC 9943 were published in June 2026. Why is an Agent Action Receipt not a
<code>COSE_Sign1</code> Signed Statement registered in a SCITT Transparency Service?&rdquo;</strong> There is currently
no answer. If P2 defines its own envelope and its own log format rather than being a SCITT profile, the first review
kills it. And <code>draft-noa-scitt-ai-agent-receipt-00</code> already applies SCITT to agent actions, recording what
the agent did, which principal authorised it and what policy governed it.</li>
<li><strong>&ldquo;RFC 8693 has expressed nested delegation chains via the <code>act</code> claim since January 2020.
What can P10 express that nested <code>act</code> plus identity-chaining cannot?&rdquo;</strong> If the answer is
attenuation, then it is a token-exchange profile, not a twelfth protocol &mdash; and Biscuit already does offline
attenuation with better cryptography than macaroons.</li>
<li><strong>&ldquo;Which standards body do you intend to standardise in?&rdquo;</strong> Twelve protocols span at least
five venues &mdash; IETF OAuth, IETF SCITT/COSE, IETF WIMSE, OIDF AuthZEN, W3C VC. A twelve-protocol suite from outside
any venue reads as a vendor framework rather than a standard. The Agentic AI Foundation governs MCP with AWS,
Anthropic, Google, Microsoft, OpenAI and Cloudflare as platinum sponsors; CoSAI has already published agent IAM and AI
incident response; CSA has published delegation with attenuation and revocation. <strong>The &ldquo;open authority
layer&rdquo; chair is occupied by four organisations, and Warrantor is in the room at none of them.</strong></li>
</ol></div>
<div class="good"><div class="calltitle">Where the ground is genuinely open</div>
{bullets([
 "**Signed, verifiable evaluation bundles (P8)** — nobody signs an eval, and nobody pins the grader. NIST named grader "
 "gaming as a live threat and prescribed only voluntary disclosure.",
 "**Composite attestation policy (P12)** — no open library composes CPU quote + multi-GPU EAT + container measurement "
 "+ **model-weight hash + serving-stack version** into one verdict. Eight attested-inference providers, eight "
 "incompatible verifiers, and CoRIM is still a draft.",
 "**Signed tool descriptors** — MCP's own spec says annotations are untrusted hints and its registry signs nothing. "
 "The signed counterpart to `ToolAnnotations` is P12's most defensible framing.",
 "**Agent memory integrity (P4)** — genuinely empty, demand unproven.",
 "**Embargo-preserving remediation attestation (P11)** — attesting a fix exists and was regression-tested *without "
 "disclosing the vulnerability* appears unsolved.",
 "**Per-retrieval context provenance with consent and taint (P3)** — and it maps directly onto DPDP.",
])}</div>
</section>"""


def sec_competitive():
    return f"""
<section id="competitive">
<div class="eyebrow">14 &middot; Competitive</div>
<h2>The field consolidated twice while this was being designed</h2>
{para("The independent-startup window in AI security has closed. Palo Alto acquired Protect AI; Cisco acquired Robust "
      "Intelligence and Astrix; SentinelOne acquired Prompt Security; Cato acquired Aim; Tenable acquired Apex; Snyk "
      "acquired Invariant Labs — whose repositories froze within seven months and were never archived. The survivors "
      "have enterprise support contracts and 24&times;7 SLAs. [EXTERNAL]")}
<h3>The hyperscaler problem, stated plainly</h3>
{bullets([
 "**AWS**: AgentCore Policy is **GA in 13 regions**, compiles natural language to Cedar, and intercepts agent-tool "
 "traffic to allow or deny each request *before* tool access — operating outside agent code. **Dogwood**, blogged "
 "2026-08-06, adds temporal Cedar operators that evaluate prior tool calls in a session. That is P1 and P7, shipped "
 "and included.",
 "**Microsoft**: Entra Agent ID is GA with identity blueprints defining owners, sponsors and an **“access envelope”** "
 "— the same phrase, the same concept — and Agent 365 logs every governance action to Purview as a compliance trail. "
 "That is P1 and much of P2.",
 "**Google**: Gemini Enterprise ships per-agent cryptographic Agent Identity, an Agent Gateway as a central "
 "enforcement point, and Model Armor at runtime.",
 "**Anthropic**: Claude Managed Agents keep an **append-only durable event log stored outside the container** "
 "recording every user message, tool call and result. That is P2, by default, inside the platform.",
 "**Cloudflare**: `cloudflare-os` was open-sourced 2026-08-05 under Apache-2.0 and took **7,059 stars in four days**. "
 "Its premise — agents receive scoped capability objects rather than raw credentials, with Gatekeeper workers holding "
 "the credential and mediating every side effect — is P1 plus credential vault plus P2 in one shipped design. Its only "
 "weakness is total Cloudflare-runtime lock-in.",
])}
<div class="danger"><div class="calltitle">Reinvention risk, ranked</div>
{para("`sandbox-runtime` against Firecracker (36k stars) and gVisor (19k). `inference-proxy` against LiteLLM (56k, "
      "Stripe and Netflix in production). `policy-bridge` against OPA (CNCF graduated) and Cedar (formally verified, "
      "AWS-backed). `safe-tensors-pp` against OpenSSF Model Signing, which signs models **without modifying the "
      "file** — directly contradicting Warrantor's own stated non-goal of forking mature standards. `nvtrust-bridge` "
      "against NVIDIA's own Apache-2.0 verifier and a free Intel Trust Authority. `credential-vault` against "
      "HashiCorp Vault, which shipped a SPIFFE secrets engine. `kill-switch` against a ServiceNow product feature. "
      "**Roughly 35–40 of the 54 components are commodity, maintained by a single-digit team.** The strategic error is "
      "not any individual component choice; it is owning 54 of them.")}</div>
<h3>The twelve buyer objections, and how many have answers</h3>
{para("A competent enterprise security architect raises roughly twelve objections: single-cloud incumbency, the Entra "
      "naming collision, who certifies conformance, twelve new wire formats no SIEM parses, self-attested receipts "
      "(the logger is the logged), operational burden across 54 components, no third-party audit of the trusted core, "
      "no published red-team numbers, no reference customers, the confidential-compute latency cost (measured at "
      "17.7% token-throughput drop and 20–30% higher latency for H100 under TDX), project longevity, and *what do I "
      "remove if I adopt this*. **Warrantor has credible answers to about two of the twelve** — and the strongest "
      "available answer to most of the rest is portability, which is real for perhaps a fifth of buyers and evaporates "
      "the moment the Agentic AI Foundation publishes a portable spec with hyperscaler signatures on it.")}
<div class="good"><div class="calltitle">The honest strategic read</div>
{para("The thesis — *the security substrate agents cannot bypass* — was defensible in 2024. As of August 2026 it is "
      "contradicted by six simultaneous developments: three hyperscalers ship agent authority and audit at GA; the "
      "Linux Foundation governs the agent protocol layer with every major lab as a platinum sponsor; CoSAI and CSA "
      "have published the identity, delegation, incident-response and artifact-signing specs; the vendor field "
      "consolidated into five platform companies; model signing became an Ecma standard; and confidential-GPU "
      "attestation is free from NVIDIA and Intel. **The move that survives contact with a buyer is verifiable "
      "evidence and cross-cloud portability — not enforcement, which is the part everyone else already ships.**")}</div>
</section>"""


def sec_blueprint():
    waves = [
        ("Stop the bleeding", "days", "danger", [
         "**Turn CI on.** Drop the `aumos/` prefix from all 34 workflow path entries — the git root *is* `aumos`, so "
         "every job currently fails before its first step. Push to a real remote. This is the highest-leverage single "
         "change available: one prefix removal activates buf breaking, SBOM, provenance, coverage, fuzzing and "
         "Dependabot simultaneously, and surfaces the lint failures nobody has ever been shown. (AX-38) &mdash; **S**",
         "**Delete every fabricated signature.** `defstack-cli compliance-report`, `flight-recorder`'s hardcoded policy "
         "decision, `eval-guard`'s `all_pass()` CLI, `attesta_flow`'s signature-less “signed attestation”, "
         "`aumos_agent`'s `_mock_sign` fallback, `aumos_hf_plugin`'s unkeyed provenance check, `fed_core`'s suffix "
         "check. (AX-11, AX-28) &mdash; **effort S, and it is the highest-liability item in the audit.**",
         "**Regrade `catalog.json` honestly.** Introduce `spec_only` / `mock_only` / `partial` / "
         "`reference_implementation` / `integrated`; move `kill-switch`, `nvtrust-bridge`, `eval-guard`, "
         "`confidential-fabric`, `egress-filter` down and `gguf-ext`, `sandbox-runtime`, `policy-bridge`, "
         "`secure-workspace`, `identity-bindings` up. (AX-12) &mdash; **S**",
         "**Delete the permissive attestation branch** in `aumos_vllm` and make the default `KeyReleasePolicy` "
         "deny-all. (AX-27, AX-06) &mdash; **S**",
         "**Change the README's Claude Code default** from `standalone` to `connected`. (AX-13) &mdash; **S**",
         "**Make catalog integrity bidirectional.** 18 source directories (~11,100 LOC) have no catalog identity, and "
         "three of the four Critical Python/Go defects live in them. Fail CI on any unclaimed source directory. "
         "(AX-37, AX-12) &mdash; **M**",
         "**Add a status line to every publication.** 38 papers, whitepapers and blog posts name reference platforms; "
         "several name mechanisms that do not exist (`paper-15` cites eBPF against zero eBPF dependencies). "
         "(AX-35) &mdash; **S**",
         "**Delete the retracted claims** from `final-verification-report.md` rather than annotating around them, and "
         "`git rm --cached` the four tracked `.pyc` files. (AX-34, AX-36) &mdash; **S**",
         "**Mark the 46 template RFCs `status: placeholder`.** They are 86% byte-identical after tokenising "
         "identifiers; a reader currently cannot distinguish a designed component from a generated one. "
         "(AX-23) &mdash; **S**",
        ]),
        ("Make the core trustworthy", "2–3 weeks", "warn", [
         "**Fix canonicalization.** Replace `serde_cbor` with `ciborium`; fail closed on decode error; bound depth "
         "explicitly; one canonicalizer consumed by all four languages. Add a differential fuzz target asserting "
         "`canonical(a) == canonical(b) ⟺ a == b`. (AX-01, AX-08, AX-21) &mdash; **M**",
         "**Add trust anchors to every verify API** and bind `key_id` to `issuer`; switch to `verify_strict`. "
         "(AX-07) &mdash; **M**",
         "**Verify envelope signatures in the MCP gateway** before policy evaluation; reject `expiry <= 0`; replace the "
         "substring approval check with approver-signature verification. (AX-02) &mdash; **M**",
         "**Delete the Zeroize wrapper**; move secrets off argv and stdout. (AX-17, AX-18) &mdash; **S**",
         "**Use a real JCS on the protocol signing path.** The declared RFC 8785 profile is plain "
         "`serde_json::to_vec`, deterministic only by accident; `serde_jcs` is already a workspace dependency and "
         "`gguf-ext` already uses it. This is on the live P1&ndash;P12 path in two languages *today* &mdash; arguably "
         "more urgent than AX-01. (AX-47) &mdash; **M**",
         "**Fix `eval-guard`'s self-description or its behaviour.** It advertises four eBPF-backed boundary checks, "
         "performs none, takes the results as an argument, carries no mock marker and has zero callers. It is the one "
         "component whose own code misrepresents it. (AX-46) &mdash; **M**",
         "**Ban fail-open idioms** workspace-wide with a clippy lint and review gate. (AX-19) &mdash; **M**",
         "**Ship the real SPIFFE module and retire the string-formatting one.** `go/identity-bindings` does genuine "
         "Workload API SVID acquisition and has zero importers; `go/agent-identity` is what the Dockerfile and Helm "
         "chart deploy. (AX-29) &mdash; **M**",
         "**Remove `shell=True` from the agent harness** and match resolved executable paths exactly rather than by "
         "one-token suffix. (AX-30) &mdash; **S**",
         "**Give the containment layer a real execution engine** &mdash; or regrade it. `kill-switch` is a "
         "`Vec<String>`; `egress-filter` is default-allow with no eBPF. (AX-05) &mdash; **XL**",
         "**Put the evidence plane on durable storage.** There is no database driver, cache client or object-store SDK "
         "anywhere in the repo; a restart un-revokes every revoked credential and `flight-recorder` never writes. P2 "
         "is meaningless until this exists. (AX-40) &mdash; **XL**",
         "**Fix the restore path** in `aumos_backup` &mdash; restore to a temp directory and swap atomically rather "
         "than deleting the destination first. (AX-45) &mdash; **S**",
        ]),
        ("Make the claims verifiable", "3–4 weeks", "note", [
         "**Rewrite the conformance runner** to execute all 40 protocol vectors in all four languages with error-code "
         "agreement, and add a real RFC 8785 vector that actually exercises each canonicalizer. (AX-03) &mdash; **M**",
         "**Write the Go and TypeScript validators** and give both `protocol-contracts` packages a manifest so they "
         "compile. (AX-26) &mdash; **L**",
         "**Generate the Markdown specs from `registry.json`** and delete the hand-written field lists; fix the "
         "dangling `.proto` and testvector references. (AX-04) &mdash; **M**",
         "**Generate one negative vector per registry constraint** and extend envelope-adversarial coverage from P1 to "
         "all twelve. (AX-10) &mdash; **M**",
         "**Make every CI gate blocking.** Add `cargo audit` and `cargo deny`, remove every `|| true`, add "
         "`helm lint`/`helm template`, add repo-wide `pytest` with real dependencies, add the codegen `--check`. "
         "(AX-16, AX-31) &mdash; **S**",
         "**Gate the artifact that is actually normative.** Buf protects four `.proto` files; `registry.json`, the "
         "twelve JSON Schemas and the twelve CDDL grammars have no breaking-change protection at all. Add a schema "
         "diff that fails on any change to a `required` list, `pattern`, `enum`, `const` or bound without a wire "
         "version bump. (AX-33) &mdash; **S**",
         "**Ship a real policy corpus.** `policies/` is an empty directory, yet `policy_digest` is a required field of "
         "every P2 receipt and `PolicyDecision.engine` enumerates OPA, Cedar and OpenShell. Until a policy exists, "
         "`policy_digest` cannot be populated honestly. (AX-32) &mdash; **M**",
         "**Make the coverage gate real** at whatever number is currently true (measured: **84.93% lines**, under the "
         "advertised 85%), add Go and TypeScript coverage, un-hardcode the single Python package, run all five fuzz "
         "targets with a committed corpus and no `continue-on-error`. (AX-44) &mdash; **M**",
         "**Benchmark the hot path.** Eleven published latency budgets, zero benchmarks, and `canonical_cbor` does "
         "three serde passes where one would do. Publish measured p99s or delete the budgets. (AX-42) &mdash; **L**",
         "**Delete the cross-cutting claims that have no code** &mdash; OTel, Kafka/CloudEvents, gRPC services, "
         "OpenAPI &mdash; and correct SLSA L3+ to the L2 the workflow actually produces. Implement the two worth "
         "having (OTel tracing, which also yields the p99s above; OpenAPI per HTTP surface). (AX-43) &mdash; **L**",
         "**Correct the stale formats and taxonomies** &mdash; CycloneDX 1.7 with `machine-learning-model` and "
         "`modelCard`, real SPDX 3.0.1 JSON-LD, OCSF 1.9 `ai_operation`/`ai_agent`, ATLAS v5.4.0. (AX-20) &mdash; **M**",
         "**Reconcile the declared wire profile with reality** &mdash; either implement RFC 8785 JCS, RFC 8949 "
         "deterministic CBOR and COSE_Sign1, or amend `registry.json` to declare the integer-only JSON profile "
         "normatively. The integer-only restriction is good design and deserves to be stated, not hidden in a "
         "test-vector manifest. Fix the empty-Merkle-root case to RFC 6962's SHA-256(&quot;&quot;) while here. "
         "(AX-09, AX-24) &mdash; **M**",
        ]),
        ("Make it adoptable", "6–8 weeks", "note", [
         "**Ship one published SDK per language** with a single seam — `wrap_tool_call(authority, fn)` — that "
         "degrades to *deny* when the control plane is unreachable, plus a worked example for Claude Agent SDK and "
         "LangGraph. (AX-14) &mdash; **L**",
         "**Fix the npm main-module check**, publish the packages, and add a clean-machine smoke test on three "
         "platforms following the README verbatim. (AX-13) &mdash; **M**",
         "**Accept MCP `2025-06-18` and `2025-03-26`**, emit tool annotations and `outputSchema`, implement OAuth 2.1 "
         "resource-server behaviour. &mdash; **M**",
         "**Rebuild the Helm chart properly** — fix the range idiom, then add RBAC, ServiceAccounts, NetworkPolicies, "
         "security contexts, CRDs and webhook configuration. (AX-25) &mdash; **M**",
         "**Add tenant identity to the inference cache key** and an adversarial two-tenant test. (AX-22) &mdash; **S**",
        ]),
        ("Concentrate on what is actually differentiated", "ongoing", "good", [
         "**Move P8 to the front.** Emit a DSSE/in-toto envelope over an Inspect `.eval` digest, pinning corpus, "
         "environment, model, harness, policy, seeds, traces and **judge**. Build on Inspect; do not compete with it. "
         "This is the only place Warrantor is ahead of the field, and NIST AI 800-2 has already described the artifact "
         "without naming a candidate. &mdash; **L**",
         "**Reframe P12 as composite attestation policy** above NVIDIA NRAS and Intel Trust Authority — never at the "
         "primitives — and position it as the *signed counterpart to MCP's self-admittedly untrusted "
         "`ToolAnnotations`*. Window is roughly twelve months. &mdash; **L**",
         "**Express P2 as a SCITT profile** (RFC 9942 / RFC 9943) or withdraw it, and engage "
         "`draft-noa-scitt-ai-agent-receipt`. **Express P6 as an in-toto predicate over CycloneDX/SPDX subjects.** "
         "**Propose P5 as an MCP extension into AAIF.** &mdash; **M each**",
         "**Delete or adopt-instead roughly 35–40 commodity components.** Firecracker or Anthropic's sandbox-runtime, "
         "LiteLLM, OPA/Cedar, Sigstore + OpenSSF Model Signing, SPIRE, NRAS/ITA, HashiCorp Vault. &mdash; **XL, and "
         "the highest-leverage decision available.**",
         "**Invest in `sovereign-stack`.** Portability, air-gap, data residency and in-country log retention are the "
         "one durable advantage, and it is the least-invested component relative to its strategic weight. &mdash; **L**",
         "**Write the adversary model the substrate does not have.** Seven of eight self-compromise scenarios are "
         "unanalysed &mdash; root-key compromise, key rotation, insider issuer, malicious policy, hostile skill, log "
         "split-view, control-plane DoS &mdash; and five of twelve invariants including I-11 (*self-change is "
         "governed*) have zero implementing code. Publish a trust-boundary diagram and an explicit residual-risk "
         "statement. (AX-39) &mdash; **XL**",
         "**Fix governance before the first tag.** Apply the licence model in files rather than prose (0 of 160 source "
         "files carry SPDX; `LICENSE` is pure Apache-2.0 while four components are announced as BSL). Apache-2.0 is "
         "irrevocable once released, so this decision has a deadline. Enforce DCO (0 of 27 commits comply), add "
         "`CODEOWNERS`, name humans, and rebrand the governance document from *Warrantor* to Warrantor. "
         "(AX-41) &mdash; **M**",
         "**Decide what &ldquo;cannot bypass&rdquo; actually means, and rewrite the claim to match.** Today enforcement "
         "is a library an agent can decline to call (AX-15). There are only three places it can genuinely live: a "
         "network chokepoint (default-deny egress with DNS control), an OS boundary (namespace and seccomp, as "
         "Anthropic's sandbox-runtime does), or a credential boundary (the agent never holds the credential &mdash; "
         "the pattern Cloudflare OS shipped). **Pick one and build there, or drop the claim.** This is an "
         "architectural decision, not a defect fix, and everything else in the positioning depends on it. &mdash; **XL**",
        ]),
    ]
    out = []
    for i, (title, dur, cls, items) in enumerate(waves, 1):
        out.append(f'<div class="{cls}"><div class="calltitle">Wave {i} &middot; {esc(title)} &middot; '
                   f'{esc(dur)}</div>{bullets(items)}</div>')
    return f"""
<section id="blueprint">
<div class="eyebrow">15 &middot; Remediation</div>
<h2>What to build, in what order, and why that order</h2>
{para("Sequenced by dependency and by risk-reduction per unit of effort, not by component ID. The ordering principle "
      "is that **credibility damage compounds faster than technical debt** — so fabricated evidence is removed before "
      "anything is built, and the catalog is made honest before anything is demonstrated.")}
{"".join(out)}
<div class="note"><div class="calltitle">The critical path in one line</div>
{para("Delete fabricated evidence &rarr; regrade the catalog &rarr; fix canonicalization &rarr; add trust anchors "
      "&rarr; run the real conformance suite &rarr; ship one SDK &rarr; then, and only then, demonstrate P8. "
      "Everything before P8 exists to make P8's signature mean something.")}</div>
</section>"""


def sec_deltas():
    return f"""
<section id="deltas">
<div class="eyebrow">16 &middot; Deltas</div>
<h2>Where this supersedes the two prior audits</h2>
{para("This document replaces `docs/html/critical-analysis.html` and "
      "`docs/html/implementation-readiness-audit-2026-08-09.html` as the reference. Both were substantially right in "
      "posture and are superseded on specifics. Where my executed findings contradict them, that contradiction is "
      "itself informative about whether the prior work was evidence-based.")}
<div class="tw"><table data-sortable>
<thead><tr><th>Prior claim</th><th>This audit</th><th>Status</th></tr></thead><tbody>
<tr><td><code>critical-analysis.html</code>: <em>&ldquo;Canonical CBOR is NOT deterministic&rdquo;</em> &mdash; <code>serde_cbor::to_vec</code> with no <code>deterministic</code> feature, so map order follows HashMap iteration (<code>canonical.rs:26-30</code>)</td>
<td>The mechanism is <strong>wrong for the current code</strong>: <code>canonical_cbor</code> now performs an explicit recursive <code>sort_value</code> and <em>is</em> deterministic for well-formed input. The real defect is far worse &mdash; <code>unwrap_or(CborValue::Null)</code> at <code>canonical.rs:67</code> collapses every payload nested &ge;127 deep to one byte, enabling universal forgery.</td>
<td><strong>Corrected and escalated</strong></td></tr>
<tr><td><code>implementation-readiness-audit</code>: <em>&ldquo;2 failing Rust tests in the current full workspace run&rdquo;</em></td>
<td><code>cargo test --workspace</code> &rarr; <strong>242 passed / 0 failed</strong>. Those tests were fixed. This is worse news, not better: a green suite now coexists with the forgery.</td>
<td><strong>Stale &mdash; contradicted</strong></td></tr>
<tr><td><code>implementation-readiness-audit</code>: <em>&ldquo;only P1 also has JSON Schema&rdquo;</em></td>
<td><strong>All twelve</strong> protocols ship <code>.md</code> + <code>.cddl</code> + <code>.schema.json</code>.</td>
<td><strong>Stale &mdash; contradicted</strong></td></tr>
<tr><td>Both: <em>&ldquo;5 canonical entries still absent as implementations: I2, R1, R6, R8, S3&rdquo;</em></td>
<td>All five <strong>exist on disk with substantial code</strong>, including <code>gguf-ext</code> at 2,918 LOC &mdash; the strongest crate in the repository &mdash; and <code>sandbox-runtime</code> at 1,014 LOC of real Wasmtime integration. Both prior audits inherited the catalog's error rather than checking the filesystem.</td>
<td><strong>Contradicted</strong></td></tr>
<tr><td>Tracker <code>AUD-004</code>: <em>&ldquo;The correctness baseline is red&rdquo;</em>, citing <code>merkle.rs</code></td>
<td>Merkle is <strong>correct</strong> against a literal RFC 6962 implementation for n=0..40, with no duplicate-leaf collision. Only the empty-tree case differs. The citation was wrong.</td>
<td><strong>Contradicted</strong></td></tr>
<tr><td>Tracker <code>AUD-001</code>: <em>&ldquo;MCP returns success-shaped mocks when controls fail&rdquo;</em>, marked <code>verified_local</code></td>
<td><strong>Half true.</strong> Genuinely fixed in <code>aumos-mcp-server</code> connected mode &mdash; typed denials, no mock fallback, 22 tests assert it. <strong>Not fixed in <code>mcp-gateway</code></strong>, which is listed as evidence on the same line and never verifies authority at all.</td>
<td><strong>Partially contradicted</strong></td></tr>
<tr><td>Tracker <code>AUD-005</code>: <em>&ldquo;MCP and A2A interoperability trail current ecosystems&rdquo;</em></td>
<td><strong>Wrong about the version</strong> &mdash; the code targets MCP <code>2026-07-28</code>, the current revision, ahead of the official SDK. Right about the surface: no annotations, no auth, no MRTR, and it rejects the two most-deployed revisions.</td>
<td><strong>Corrected</strong></td></tr>
<tr><td>Tracker <code>AUD-011</code>: <em>&ldquo;Model SBOM output trails the current format&rdquo;</em>, severity <strong>medium</strong></td>
<td>Understated. It is not a version-drift problem: the output sets <code>type: "library"</code> with ad-hoc properties and <strong>is not an ML-BOM in any CycloneDX version</strong>, while its SPDX output declares 3.0 and emits the 2.3 shape.</td>
<td><strong>Escalated</strong></td></tr>
<tr><td>Tracker <code>AUD-008</code>: <em>&ldquo;Helm is not a credible production installer&rdquo;</em></td>
<td>Understated. <strong>The chart does not render at all</strong> &mdash; reproduced &mdash; and <code>deploy/k8s/</code> is empty.</td>
<td><strong>Escalated</strong></td></tr>
<tr><td>Tracker <code>AUD-002</code>: <em>&ldquo;Green gates can mean nothing meaningful ran&rdquo;</em>, marked <code>implemented_pending_ci</code></td>
<td><strong>Still fully live.</strong> The conformance runner executes 5 of 45 available vectors and reports PASS; its one canonicalization vector instructs verifiers not to canonicalize.</td>
<td><strong>Confirmed, not closed</strong></td></tr>
</tbody></table></div>
<div class="note"><div class="calltitle">What the delta pattern says</div>
{para("Three of the prior findings were stale because the code moved; three were understated; two were wrong about "
      "mechanism while right about direction; and two propagated the catalog's own error without checking the "
      "filesystem. That is the signature of audits derived from documents rather than from execution — which is "
      "exactly the failure mode the repository's own AUD-002 describes, applied to its own audit process.")}</div>
</section>"""


def sec_annex():
    return f"""
<section id="annex">
<div class="eyebrow">17 &middot; Internal annex</div>
<h2>Claims that would not survive a hostile external review</h2>
<div class="annex">
<div class="alabel">Internal &mdash; not for external distribution</div>
{para("This section exists because the audit was commissioned as brutally honest and internal. Each item below is a "
      "claim currently made in the repository, the code that contradicts it, and what a hostile reviewer &mdash; a "
      "competing vendor, a standards body, a prospect's security team, or a journalist &mdash; would do with it.")}
{bullets([
 "**“The security substrate that agents cannot bypass.”** It is an exported class with an injected transport. Bypassing "
 "it means not calling it. Any reviewer who reads `mcp-gateway/src/index.ts` for ten minutes reaches this, and it is "
 "the headline of the project.",
 "**“The single authoritative implementation of every security invariant.”** Three incompatible canonicalizations in "
 "Rust, a fourth in Python, a fifth in Go, and six of the eight named invariants absent from the crate that claims "
 "them. The claim is in a doc comment in the same file as the forgery.",
 "**“Fail-closed on any error.”** Two lines above a `.unwrap_or` that produces a signable canonical form.",
 "**“Payloads are written to stdin, never command-line arguments.”** The same file passes the raw Ed25519 signing key "
 "in argv 150 lines later.",
 "**“The signature is verifiable cross-language via the canonical-CBOR encoding.”** `go/agent-identity` signs with "
 "`encoding/json`, and its own comment four hundred lines down admits it.",
 "**SLSA Level 3+ target, with L4 planned.** SLSA has no Level 4; the L4 definition in the compliance doc was retired "
 "from the spec in April 2023. Current is v1.2, build track topping out at L3. A reviewer reads this as *they have not "
 "opened the spec since 2023*.",
 "**“Rekor transparency log entry returned for non-repudiation”** — in every protocol spec. The entry type is "
 "misspelled `hashedrekor`, a unit test asserts the misspelling, the digest encoding is wrong, the transport is "
 "plaintext against an HTTPS-only endpoint, and `verify_entry` verifies nothing. Nothing has ever been notarised.",
 "**“Each protocol ships adversarial test vectors”** for six named classes. P2–P12 ship three files each, all of the "
 "same mechanical kind.",
 "**A signed compliance report for EU AI Act, NIST AI RMF, ISO 42001, FedRAMP, DORA and NIS2.** Nothing measured. In "
 "the Gulf this is not merely embarrassing — DIFC Regulation 6.2 makes misleading representations about adherence to "
 "standards independently enforceable.",
 "**“691 tests passing, feature-complete at v1.0.0”** (in `docs/final-verification-report.md`). 371 of 371 task "
 "checkboxes are open and one of fourteen release gates passes.",
 "**Confidential GPU attestation as a headline differentiator.** `MockBackend` is the only backend; on real hardware "
 "the Python verifier returns true for any two non-empty strings.",
 "**“Agent identity backed by SPIFFE/SPIRE.”** The module that does this has zero importers; the one that ships is "
 "`fmt.Sprintf`.",
])}
<h4>The three most likely ways this becomes public</h4>
{bullets([
 "**A security researcher fuzzes `trust-core`.** The forgery is reachable in under an hour with a structure-aware "
 "fuzzer, and the repository is Apache-2.0 and public. A CVE against a project positioning itself as *the* AI trust "
 "layer would be the story, not the bug.",
 "**A standards reviewer reads P2 after RFC 9942.** The question *“why is this not a COSE Receipt in a SCITT "
 "Transparency Service?”* has no answer today, and it is the first thing anyone from the IETF community will ask.",
 "**A prospect's security team runs `helm install`.** It fails before creating an object, which tells them nobody has "
 "ever deployed it — and that inference is correct.",
])}
<h4>What is genuinely defensible, and should be led with</h4>
{bullets([
 "The **protocol schema design** — integer-only numerics, the reused `Budget` type, real cross-field invariants, a "
 "fail-closed must-understand rule. This is better than most shipped standards and it is the strongest thing here.",
 "**`gguf-ext`** — bounded parsing, fallible allocation, checked arithmetic, tensor-overlap detection, real RFC 8785, "
 "fuzz targets, against a format with a live CVSS 9.8 CVE class. Publishable as-is.",
 "**`sandbox-runtime`** — real Wasmtime fuel and limits, WASI genuinely unlinked, signed import admission, "
 "audit-before-dispatch.",
 "**`go/identity-bindings`** — real SPIFFE done properly.",
 "**`dp-crate`** — the best test discipline in the repository.",
 "**P8 and P12** — the two places the field has not arrived yet.",
])}
{para("**The kindest accurate framing for external use:** *an open specification suite for agent authority and "
      "evidence, with reference implementations at varying maturity, published early for review.* That is defensible, "
      "invites contribution, and is true. The current framing is not true, and the gap between them is the single "
      "largest risk this project carries — larger than any individual defect in this document.")}
</div>
</section>"""


# ===========================================================================
# ASSEMBLY
# ===========================================================================
def build():
    nav = []
    for group, items in S.NAV:
        nav.append(f'<div class="grp">{group}</div>')
        for anchor, label in items:
            nav.append(f'<a href="#{anchor}">{label}</a>')
    nav_html = "".join(nav)

    body = "".join([
        S.sec_verdict(), S.sec_method(), S.sec_evidence(), S.sec_context(),
        S.sec_normative(), S.sec_protocols(), S.sec_components(),
        S2.sec_gaps(), S2.sec_crosscut(), S2.sec_devfit(), S2.sec_entfit(),
        sec_regulatory(), sec_standards(), sec_competitive(),
        sec_blueprint(), sec_deltas(), sec_annex(),
    ])

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Warrantor &mdash; Implementation &amp; Protocol Critical Analysis</title>
<meta name="description" content="Executed, source-level critical analysis of all 54 Warrantor components and 12 protocols for developer and enterprise adoption in native and agentic AI environments, with an exhaustive gap and remediation register.">
<style>{CSS}</style>
</head>
<body>
<div class="prog" id="prog"></div>
<div class="tools">
  <button id="expandBtn" type="button">Expand all</button>
  <button id="themeBtn" type="button">Theme</button>
</div>
<div class="shell">
<aside class="side">
  <div class="brand">Warrantor &mdash; Critical Analysis</div>
  <div class="brandsub">Implementation &amp; protocols &middot; {AUDIT_DATE}</div>
  <nav>{nav_html}</nav>
</aside>
<main class="main">
<div class="hero">
  <div class="eyebrow">Internal &middot; brutally honest &middot; supersedes prior audits</div>
  <h1>Warrantor: implementation and protocol critical analysis</h1>
  <p class="lede">An executed, source-level examination of all 54 components and 12 protocols &mdash; assessed for
  whether developers and enterprises can actually use them in native and agentic AI environments &mdash; with an
  exhaustive register of gaps, limitations, challenges and pending work, and the remediation plan that closes them.</p>
  <div class="meta">
    <span><strong>Repository:</strong> <code>aumos/</code></span>
    <span><strong>Commit:</strong> <code>{COMMIT[:12]}</code></span>
    <span><strong>Branch:</strong> <code>{BRANCH}</code> (dirty)</span>
    <span><strong>Evidence cut:</strong> {AUDIT_DATE}</span>
    <span><strong>Method:</strong> execution + source reading + primary-source standards review</span>
  </div>
</div>
{body}
<hr>
<p style="font-size:.8rem;color:var(--fg-3);max-width:none">
Generated by <code>docs/html/meta/build_critical_analysis.py</code>. Regenerate after editing the dataset.
Evidence tags: {tag('EXECUTED')} observed directly &middot; {tag('READ')} read at cited file:line &middot;
{tag('EXTERNAL')} primary external source &middot; {tag('INFERRED')} reasoned &middot;
{tag('UNVERIFIABLE')} stated with reason. Findings that could not be independently confirmed are tagged or omitted.
</p>
</main>
</div>
<script>{JS}</script>
</body>
</html>"""
    pathlib.Path(OUT).write_text(html_doc, encoding="utf-8")
    return OUT, len(html_doc)


if __name__ == "__main__":
    path, size = build()
    print(f"wrote {path}  ({size/1024:.0f} KB)")
    print(f"protocols={len(PROTOCOLS)} components={len(COMPONENTS)} findings={len(FINDINGS)}")
