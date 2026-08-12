"""Remaining sections + document assembly for the two adoption deliverables."""
from __future__ import annotations

import pathlib

from build_critical_analysis import bullets, esc, filter_bar, md, para, tag
import build_adoption as A


def sec_ossgate():
    return f"""
<section id="ossgate">
<div class="eyebrow">06 &middot; The developer gate</div>
<h2>The measured bar, and the one asset you already own</h2>
{para("Pulled first-hand from the GitHub, npm and PyPI APIs on 2026-08-09, not from secondary reporting. [EXTERNAL]")}
<div class="tw"><table data-sortable>
<thead><tr><th>Project</th><th>Commands to first success</th><th>Account or key?</th><th>Runs locally?</th></tr></thead><tbody>
<tr><td><strong>cloudflare-os</strong></td><td><strong>1</strong> &mdash; <code>pnpm run-local</code></td><td>No</td><td>Yes, whole stack</td></tr>
<tr><td><strong>agentgateway</strong></td><td>2 &mdash; install script, then run</td><td>No, auto-bootstraps config</td><td>Yes</td></tr>
<tr><td><strong>OPA</strong></td><td>2 &mdash; <code>brew install opa</code>, <code>opa eval "1*2+3"</code></td><td>No</td><td>Yes, offline</td></tr>
<tr><td>promptfoo</td><td>2 to start, 5 to a result</td><td>Provider key</td><td>Evals run locally</td></tr>
<tr><td>E2B</td><td>1 install &mdash; but <strong>cannot run without an API key</strong></td><td>Yes, hard gate</td><td>Terraform self-host only</td></tr>
<tr><td>SPIRE</td><td><strong>No one-command start</strong> &mdash; docs say learn the architecture first</td><td>No</td><td>Yes</td></tr>
<tr><td><strong>Warrantor today</strong></td><td><strong>&infin;</strong> &mdash; nothing published; the documented command exits 0 silently</td><td>&mdash;</td><td>&mdash;</td></tr>
</tbody></table></div>
{para("**cloudflare-os took 7,123 stars and 704 forks in four days** (open-sourced 2026-08-05, Apache-2.0) on one "
      "command and no account &mdash; with **Quick Start as README section #2, above the architecture prose**. "
      "promptfoo uses the same ordering. LiteLLM is the counterexample: its Get Started is section #6, and it won on "
      "provider breadth rather than onboarding. Copy promptfoo, not LiteLLM.")}
<div class="good"><div class="calltitle">The asset you already own and have not claimed</div>
{para("What separates credible multi-language projects from ones that quietly lose trust is **a public, dated, "
      "executable conformance suite**. Sigstore publishes theirs daily &mdash; cosign, sigstore-js and sigstore-rust "
      "at 100%, python 96%, java 95% &mdash; which is why `sigstore-go` can call itself production-ready *at 90 "
      "stars*. MCP has ten official SDKs, no conformance suite, and visible drift as a result.")}
{para("**Warrantor's conformance runner is already at 220/220 across four languages and is genuinely fail-closed** &mdash; "
      "removing a verifier yields FAIL, never a skip. That is the parity claim and the assurance story in one "
      "artifact. **Publish it, date it, badge it in the README.** Almost nobody in this space has one.")}</div>
<h3>Distribution: what is table stakes, and what is folklore</h3>
{bullets([
 "**Registry presence in every language you claim.** Downloads are the only unfakeable adoption number. Measured: "
 "`litellm` 708.5M/month on PyPI; `mcp` (Python) 324M; `@modelcontextprotocol/sdk` 200M npm; `rmcp` (Rust) ~3.2M. "
 "**The Python-to-Rust ratio for the same protocol is roughly 100:1** &mdash; tier languages by that, not by symmetry.",
 "**A one-liner that is not a language package manager** &mdash; `curl|bash`, `npx` or `uvx` &mdash; plus a single "
 "static binary on Releases and a container on ghcr.io.",
 "**Homebrew is folklore.** cosign gets 4,501 brew installs per 30 days; OPA 1,149. Against 708M/month on PyPI that "
 "is rounding error. Ship it, do not prioritise it.",
 "**Signed releases are NOT table stakes &mdash; which is precisely your opening.** OpenSSF Scorecard "
 "`Signed-Releases`: **OPA 0, SPIRE 0**, cosign 8. Adoption is demonstrably not gated on it. But for an "
 "*agent-security* substrate it is the cheapest differentiation available: `actions/attest-build-provenance` is free "
 "and makes `gh attestation verify` work out of the box.",
 "**`llms.txt` is an open gap in exactly your tier.** Anthropic, Cloudflare, Stripe, LangChain, Vercel, Snyk, Daytona "
 "and E2B all serve one. **garak, PyRIT and Guardrails AI all 404.** The security-tooling tier has not shipped "
 "agent-facing docs, and it costs an afternoon.",
])}
<h3>The two integrations worth more than the other seven</h3>
<div class="two">
<div class="card"><h4>LiteLLM <code>CustomGuardrail</code></h4>
{para("**708 million downloads a month.** Subclass `CustomGuardrail`, implement `async_pre_call_hook` and "
      "`async_post_call_success_hook`, and a user adopts you with a pip install and **six lines of YAML**. Highest "
      "leverage single integration available to this project, by a wide margin.")}</div>
<div class="card"><h4>Claude Agent SDK <code>PreToolUse</code></h4>
{para("Structurally the closest fit to agent authority and containment of any surface examined: a native "
      "`permissionDecision: allow | deny | ask | defer` with `permissionDecisionReason`, plus `updatedInput` to "
      "rewrite tool arguments. `PostToolUse` gives evidence capture on the same seam.")}</div>
</div>
<div class="danger"><div class="calltitle">The anti-pattern you are sitting in right now</div>
{para("Unpublished packages is a named failure mode; a documented-but-non-functional command is worse. For a "
      "*security* project the documentation **is** the security claim &mdash; and `npx aumos-mcp --standalone` "
      "printing nothing and exiting 0 will be found inside ninety seconds. Stars are recoverable; *&ldquo;their docs "
      "lied about what runs&rdquo;* is not. **Fix or delete that command before anything is published.**")}</div>
</section>"""


def sec_gcc():
    return f"""
<section id="gcc">
<div class="eyebrow">07 &middot; The regulatory wedge</div>
<h2>The Gulf is four years ahead of the US, and nobody serves it</h2>
<div class="good"><div class="calltitle">The finding that should reshape your positioning</div>
{para("**CBUAE Model Management Standards (Nov 2022) &sect;2.4.1 Table 1 lists &ldquo;Artificial Intelligence&rdquo; "
      "as an in-scope model type**, binding on all licensed UAE banks including Islamic institutions and foreign "
      "branches. UAE banks have owed model-risk artifacts on AI models **since 2022**. The US carved generative and "
      "agentic AI *out* of scope in April 2026. **The Gulf is ahead of the US on binding AI model governance, and has "
      "been for four years.** [EXTERNAL, primary]")}</div>
{para("The corrected picture is narrower and far more useful than &ldquo;no format exists anywhere&rdquo;: **no GCC "
      "regulator publishes a fillable template &mdash; but three of four prescribe the *contents*.** Contents without "
      "a container is exactly what a substrate can emit.")}
<div class="tw"><table data-sortable>
<thead><tr><th>Jurisdiction</th><th>Instrument</th><th>What it prescribes</th></tr></thead><tbody>
<tr><td><strong>Qatar (QCB)</strong></td><td>AI Guideline, in force 4 Sept 2024 &mdash; mandatory &ldquo;must&rdquo; language</td><td><strong>The only field-level AI Register schema in the region.</strong> Per system: risk class, role, use category, human-oversight protocol. For third-party systems: provider LEI, country of registration, governing law, parent company, contract dates &mdash; plus <strong>substitutability rated easy/difficult/impossible and a named alternate provider</strong>. Prior QCB approval before launch. &sect;17.7 explicitly requires protection against <strong>prompt injection leading to data poisoning</strong>.</td></tr>
<tr><td><strong>UAE (CBUAE)</strong></td><td>MMS (Nov 2022, binding) + AI Guidance Note (11 Feb 2026)</td><td>Model inventory with unique ID per calibration, lifecycle dates, Tier 1/2 risk tiering. <strong>Independent validation report with nine mandatory components.</strong> Model Oversight Committee minutes, quarterly, majority non-business-line. High-severity findings closed in 12 months; anything open past 6 months reported <strong>to CBUAE</strong>.</td></tr>
<tr><td><strong>Saudi (SAMA)</strong></td><td>Cyber Security Framework, Circular 381000091275</td><td><strong>No AI framework and no MRM framework exist.</strong> The &ldquo;SAMA AI Principles 2023&rdquo; cited in vendor blogs <strong>does not survive contact with the Rulebook &mdash; do not cite it</strong>. What exists is a <strong>0&ndash;5 maturity scale</strong> across 4 domains and 32 subdomains, target &ge;&nbsp;3 &mdash; the container Saudi supervisors are trained to read.</td></tr>
<tr><td><strong>DIFC</strong></td><td>Regulation 10 under DP Law No. 5 of 2020</td><td>Deployer / Operator / Provider roles; a Deployer is liable for the System <em>&ldquo;as it may be liable for an employee's actions&rdquo;</em>. Requires an <strong>Autonomous Systems Officer</strong> and &sect;4.3.6 lists the evidence: AI DPIA, risk register, <strong>algorithmic audits, processing-purpose logs</strong>, code-review records showing absence of self-defined purposes. <em>Caveat: whether an Accredited Certification Body actually exists in 2026 is UNVERIFIED.</em></td></tr>
</tbody></table></div>
<h3>Data residency &mdash; the hard, examinable anchor for attested inference</h3>
{bullets([
 "**UAE Outsourcing Regulation, Circular 14/2021, Art 6.1** &mdash; *&ldquo;Banks must ensure that the Master System "
 "of Record, which includes all Confidential Data, is continuously maintained and stored within the UAE.&rdquo;* No "
 "export without CBUAE approval **plus** written customer consent **plus** acknowledgement of foreign legal access. "
 "**Art 8.2: CBUAE generally will not permit outsourcing of risk management, compliance, internal audit or "
 "risk-taking** &mdash; read that against agentic systems that take actions.",
 "**Saudi CSF &sect;3.4.3** &mdash; *&ldquo;in principle only cloud services should be used that are located in Saudi "
 "Arabia,&rdquo;* with **SAMA approval required before signing the contract**, not after.",
 "**No hosting-attestation form exists in either jurisdiction.** The bank assembles the register entry, the "
 "non-objection letter and the contract clauses itself. **A substrate that emits a hardware-rooted attestation of "
 "where inference actually executed fills a gap the regulators created and did not fill.**",
])}
<h3>India moves the opposite way from the US, eight weeks later</h3>
{para("**RBI's Draft Guidance on Regulatory Principles for Model Risk Management, 24 June 2026** (consultation closed "
      "24 July) defines *model* expansively &mdash; &para;7(3) covers *&ldquo;algorithms, analytics, interfaces, "
      "applications, decision-based rules and other computational tools&hellip; **irrespective of whether such tools "
      "are recognised as models by the RE**&rdquo;* &mdash; explicitly scopes **foundational and frontier AI models** "
      "(&para;49), and adds *&ldquo;level of autonomy placed on model outputs&rdquo;* to risk tiering (&para;52). "
      "**The US carved agentic AI out on 17 April 2026; India scoped it in on 24 June 2026.** That is the cleanest "
      "dated regulatory contrast available anywhere. [EXTERNAL, primary]")}
{para("Build against paragraph numbers, because these are what get quoted back in an inspection: **&para;22** model "
      "inventory with upstream/downstream dependencies and *&ldquo;no model is used&hellip; unless it is part of "
      "inventory&rdquo;* &middot; **&para;23** decommissioned-model records retained **&ge;10 years** &middot; "
      "**&para;33** validation report to the board risk committee within 3 months &middot; **&para;57** enhanced AI "
      "documentation for traceability, reproducibility and auditability &middot; **&para;59(i)** prompt-injection and "
      "adversarial-input controls &middot; **&para;60(ii)** kill switch / override / suspension &middot; "
      "**&para;63** a record of *&ldquo;decisions, interventions, overrides, incidents and near misses&rdquo;* "
      "&mdash; the closest thing to an agent audit-trail requirement in Indian regulation.")}
{para("Worth quoting to any Indian partner: RBI's own survey of 127 AI-using regulated entities found only **18% "
      "maintained audit logs**, 21% monitored drift, and 14% did regular audits. The gap is not theoretical.")}
<div class="tw"><table data-sortable>
<thead><tr><th>Region</th><th>Contents specified?</th><th>Format prescribed?</th><th>Binding on AI today?</th></tr></thead><tbody>
<tr><td>US</td><td>Principles only</td><td><strong>None</strong></td><td><strong>No</strong> &mdash; genAI/agentic explicitly out of scope</td></tr>
<tr><td>India</td><td>Twice &mdash; FREE-AI &para;4.4.68, draft MRM &para;22</td><td><strong>None</strong></td><td>No &mdash; draft only; binding rules contain zero AI content</td></tr>
<tr><td>UAE</td><td>Yes &mdash; MMS &sect;4.4, &sect;10.6.1</td><td>None</td><td><strong>Yes, since Nov 2022</strong></td></tr>
<tr><td>Qatar</td><td>Yes &mdash; AI Register &sect;10.7, 14+ fields</td><td>Field-level schema</td><td><strong>Yes, since Sept 2024</strong></td></tr>
<tr><td>Saudi</td><td>CSF 0&ndash;5 maturity, 32 subdomains</td><td>Nearest to a format</td><td>No AI framework at all</td></tr>
<tr><td>DIFC</td><td>Yes &mdash; &sect;4.3.6 evidence list</td><td>Unpublished</td><td>Regime possibly not live</td></tr>
</tbody></table></div>
<div class="danger"><div class="calltitle">Two architectural requirements that are cheap now and expensive later</div>
{para("**1. The evidence store must be independently locatable per tenant.** CERT-In requires 180 days of logs held "
      "**inside Indian jurisdiction**; CBUAE requires the Master System of Record in the UAE; SAMA requires "
      "In-Kingdom by default. RBI &para;23 wants decommissioned-model records for **10 years**. **If the architecture "
      "assumes one global evidence store, that is a blocker in three of four target jurisdictions** &mdash; and it is "
      "far cheaper to fix before a pilot than after.")}
{para("**2. Timestamps need a recorded, traceable time source.** CERT-In direction (i) requires clock synchronisation "
      "to **NIC or NPL** servers. Evidence whose timestamps are not traceable to those sources is weak under that "
      "regime. Make the time source configurable and record which source signed the timestamp &mdash; a small change "
      "in the evidence record format, and a retrofit if left.")}</div>
<div class="note"><div class="calltitle">The commercial wedge, stated plainly</div>
{para("Four jurisdictions want **structurally different evidence packs from the same underlying system** &mdash; "
      "Qatar wants register fields, the UAE wants nine-component validation reports and committee minutes, Saudi "
      "wants a 0&ndash;5 maturity score, DIFC wants processing-purpose logs and algorithmic audits. **Nobody has "
      "solved emitting all of them from one telemetry layer** &mdash; not the regulators, and not Microsoft, whose "
      "compliance mapping targets EU AI Act, HIPAA and SOC 2.")}
{para("This is a better positioning than anything else in this document. It is defensible **without claiming novel "
      "enforcement technology**, it is a problem the incumbent does not address, and it turns the multi-region "
      "requirement from a burden into the product.")}</div>
<div class="danger"><div class="calltitle">And one hard blocker you need to act on</div>
{para("**Qatar QCB &sect;10.7.5 requires the AI provider's LEI, country of registration, local corporate registration "
      "number, registered address, parent company and the governing law of the licensing arrangement** &mdash; plus a "
      "named alternate provider and a substitutability rating for high-risk systems. **An unincorporated open-source "
      "project cannot populate that register.** For Qatar, a legal entity is a *precondition of deployment*, not a "
      "production nice-to-have. This is the clearest instance found anywhere of the &ldquo;no vendor entity&rdquo; "
      "risk becoming a hard regulatory blocker rather than a soft procurement preference.")}</div>
</section>"""


def sec_thesis():
    return f"""
<section id="thesis">
<div class="eyebrow">08 &middot; The thesis</div>
<h2>Where the exponential actually is</h2>
{para("Exponential value does not come from covering more surface than Microsoft. It comes from owning a primitive "
      "that becomes load-bearing for other people's systems. Three candidates survive scrutiny, and they compound.")}
<div class="card"><h3>1. Be the evidence layer, not the enforcement layer</h3>
{para("Enforcement is commodity and getting more so &mdash; Microsoft AGT, AWS AgentCore Policy at GA in 13 regions, "
      "Envoy AI Gateway v1.0, Cedar, OPA. **Verifiable evidence is not.** Nobody signs an eval. Nobody pins the "
      "grader. OCC 2026-13 explicitly puts generative and agentic AI out of scope while telling banks their own "
      "governance *&ldquo;should guide the determination of appropriate controls&rdquo;* &mdash; a supervisor saying "
      "**you own this gap**.")}
{para("The compounding move: **P8 bundles become the thing an auditor asks for by name.** Once one institution "
      "accepts a signed eval bundle as evidence, the format has a reference &mdash; and references are how formats "
      "become standards.")}</div>
<div class="card"><h3>2. Be the conformance authority for the protocols you define</h3>
{para("You already run 220 cross-language verifications, fail-closed. Sigstore proves the pattern: a public dated "
      "conformance suite lets a 90-star library credibly call itself production-ready, and makes the *suite* the "
      "neutral arbiter. If P8 or P12 gain adoption, whoever runs the conformance suite defines what compliance means "
      "&mdash; a durable position no amount of Microsoft engineering displaces.")}</div>
<div class="card"><h3>3. Be the sovereign, multi-jurisdiction evidence emitter</h3>
{para("The one advantage a US-hosted control plane structurally cannot match, and now the best-evidenced. CERT-In "
      "requires **180 days of ICT logs inside Indian jurisdiction** and makes AI/ML attacks reportable within **six "
      "hours** &mdash; today. CBUAE requires the Master System of Record inside the UAE. SAMA requires in-Kingdom "
      "cloud by default with approval *before* contract signature. And the four Gulf jurisdictions each demand a "
      "different evidence pack from the same system.")}
{para("**Portability plus multi-jurisdiction emission is the product.** `sovereign-stack` is currently the "
      "least-invested component relative to its strategic weight &mdash; the clearest misallocation in the portfolio.")}</div>
<div class="note"><div class="calltitle">What to say when a partner asks &ldquo;why not the Microsoft one?&rdquo;</div>
{para("*&ldquo;Use it &mdash; for enforcement. It is good, it is free, and we interoperate with it. What it does not "
      "give you is an artifact your auditor can verify without trusting your runtime, or a deployment your regulator "
      "will accept inside national boundaries, or one telemetry layer that emits a QCB AI Register entry, a CBUAE "
      "nine-component validation report and a DIFC processing-purpose log from the same run. That is what we "
      "do.&rdquo;* True, checkable, and it converts the competitor into a dependency rather than a rival.")}</div>
</section>"""


# ===========================================================================
# DOCUMENT 2 — THE OPERATING PLAYBOOK
# ===========================================================================
def phase(num, title, dur, cls, why, mine, yours, done):
    return f"""
<div class="{cls}" style="margin-bottom:1.4rem">
<div class="calltitle">Phase {num} &middot; {esc(title)} &middot; {esc(dur)}</div>
{para(why)}
<h4>What I do</h4>{bullets(mine)}
<h4 style="color:var(--accent)">What I need from you</h4>{bullets(yours)}
<h4>Done when</h4>{bullets(done)}
</div>"""


def sec_playbook():
    return f"""
<section id="playbook">
<div class="eyebrow">02 &middot; The sequence</div>
<h2>Six phases, dependency-ordered</h2>
{para("No calendar deadline, so this is sequenced by leverage and dependency. Each phase names exactly what I need "
      "from you before it can start &mdash; those are the real critical path, not the engineering.")}
{phase(0, "Unblock", "hours, and everything waits on it", "danger",
  "Nothing else on this list can proceed. The repository has **no git remote**, which is why CI has never executed "
  "once in 29 commits. Nothing is published, so no developer can install anything. This phase is almost entirely "
  "your inputs and almost none of my work &mdash; which is exactly why it is first.",
  ["Add the remote, push both commits, and watch the first CI run in this project's history actually execute.",
   "Fix or delete `npx aumos-mcp --standalone` &mdash; the silent no-op. **This ships before anything is published**, "
   "because for a security project a lying quickstart ends the evaluation permanently.",
   "Execute the `warrantor` namespace migration across `package.json`, `pyproject.toml`, `Cargo.toml` and the docs, "
   "resolving the `@aumos` / `@muveraai` collision.",
   "Add `SECURITY.md` with a 24h/72h/90-day SLA, `MAINTAINERS.md`, `GOVERNANCE.md`, `SUPPORT.md`, `CODEOWNERS` "
   "&mdash; these directly answer the bus-factor question and cost hours."],
  ["**The GitHub org and repo name**, and push access. One command from you unblocks six CI workflows.",
   "**Registry claims**: the `warrantor` npm org, PyPI project names, crates.io names &mdash; plus publish tokens as "
   "repository secrets (`NPM_TOKEN`, `PYPI_API_TOKEN`, `CARGO_REGISTRY_TOKEN`).",
   "**Confirm the domain** for `security.txt`, the PGP key and the issuer identity the specs reference.",
   "**Decide the git identity question**: whether to drop the local `aumos@local` override so future commits carry "
   "your real identity, as the two DCO-signed commits now do."],
  ["A green CI run is visible on a real remote.",
   "`npm view @warrantor/…` resolves. `pip install warrantor-…` works.",
   "No documented command produces silence."]) }
{phase(1, "One command that works", "1–2 weeks", "warn",
  "The measured bar is one to two commands, under five minutes, no account, fully local, with visible output. "
  "cloudflare-os took 7,123 stars in four days on exactly that. This phase is worth more than any six components.",
  ["Build the single-command local demo: `npx @warrantor/quickstart` or `uvx warrantor` &mdash; starts the gateway, "
   "wraps a sample agent, emits a real signed receipt, prints a URL.",
   "Rewrite the README with **Quick Start as section #2**, above the architecture prose (the promptfoo ordering).",
   "Ship the LiteLLM `CustomGuardrail` adapter &mdash; 708M downloads/month, six lines of YAML to adopt.",
   "Ship the Claude Agent SDK `PreToolUse` hook adapter &mdash; the closest structural fit to agent authority.",
   "Publish `llms.txt` and `llms-full.txt`. garak, PyRIT and Guardrails AI all 404 on this; it costs an afternoon "
   "and nobody in your tier has it."],
  ["**Nothing.** This phase is mine, provided Phase 0 is done.",
   "Optionally: tell me which agent framework your design partners actually run, so the third adapter is the right "
   "one rather than a guess."],
  ["A developer with no context runs one command and sees a signed receipt in under five minutes.",
   "The README's first code block works verbatim."]) }
{phase(2, "The minimum credible package", "2–4 weeks", "warn",
  "This is the artifact set an enterprise security review demands. Almost all of it is cheap, and the expensive "
  "failure mode is discovering it is missing *after* a technical pilot has already succeeded.",
  ["Signed releases via `actions/attest-build-provenance` &mdash; free, gives Scorecard `Signed-Releases: 10`, and "
   "makes `gh attestation verify` work. **OPA and SPIRE both score 0 here**; it is cheap differentiation.",
   "CycloneDX 1.6 SBOM per release satisfying **CISA's 2026 Minimum Elements** (29 July 2026) including the new "
   "SBOM Author Signature. Rewrite `model-sbom` to emit a real ML-BOM while here.",
   "Publish the **conformance suite results, dated**, on the sigstore model &mdash; and badge it. You are at 220/220 "
   "across four languages and have not told anyone.",
   "Publish **measured p50/p95/p99** for the policy decision path. Microsoft claims &lt;0.1&nbsp;ms p99; silence is "
   "read as slow. You have eleven published budgets and zero benchmarks.",
   "Complete the CSA AI-CAIQ against AICM v1.1 and commit it &mdash; converts three weeks of questionnaire "
   "ping-pong into a link.",
   "Ship an **observe-only mode**. For an authority substrate this is the difference between a pilot and an outage."],
  ["**Apply to OSTIF for a free third-party audit** &mdash; funded by OpenSSF Alpha-Omega, at no cost to the project, "
   "and they have run a programme covering 25 AI/LLM projects. Long lead time, so apply now. This converts the "
   "hardest enterprise gate into a cited artifact. **Only you can submit this.**",
   "**Decide on the legal entity.** Qatar QCB &sect;10.7.5 requires the provider's LEI and country of registration &mdash; "
   "an unincorporated project cannot be deployed there at all. If Qatar is a target market this moves ahead of "
   "everything else on this list."],
  ["A security architect can be handed a link and stops asking questions.",
   "`gh attestation verify` succeeds against a published release."]) }
{phase(3, "The evidence bet", "4–8 weeks", "good",
  "This is where the differentiation actually lives. Everything before it exists to make this credible.",
  ["**P8 as a DSSE/in-toto envelope over an Inspect `.eval` digest** &mdash; build on Inspect, do not compete with "
   "it. Pin corpus, environment, model, harness, policy, seeds, traces **and the judge**, which nothing else does.",
   "**The per-jurisdiction evidence-pack mapping** &mdash; one table: telemetry field &rarr; QCB AI Register "
   "&sect;10.7 field / CBUAE MMS &sect;10.6.1 validation component / SAMA CSF subdomain / DIFC &sect;4.3.6 item. "
   "**This is the artifact that wins a Gulf design partner and it is roughly a day of work.**",
   "OCSF 1.9 export using the native `ai_agent` and `delegation` objects &mdash; lands in Splunk, Sentinel, Elastic "
   "and Security Lake with no parser project.",
   "Re-express P2 as a **SCITT profile** (RFC 9942 / RFC 9943) rather than a parallel receipt format."],
  ["**Which design partner goes first, and which of the four use cases they care about.** This decides whether P8 or "
   "the jurisdiction mapping leads.",
   "An intro to whoever signs off on evidence at that partner &mdash; internal audit or model risk, not just "
   "engineering. They will tell you in one conversation what three months of guessing will not."],
  ["A partner's auditor accepts a signed bundle as evidence of something.",
   "One jurisdiction's evidence pack emits end-to-end from real telemetry."]) }
{phase(4, "De-mock the hard dependencies", "6–10 weeks", "note",
  "Two things cannot be de-mocked without physical resources. Everything else in the audit can be fixed with code.",
  ["Bind real NVIDIA nvTrust/NRAS attestation and verify EAT tokens with cert-chain validation against pinned "
   "reference values &mdash; replacing `MockBackend`.",
   "Stand up SPIRE and make `identity-bindings` (the real SPIFFE module, currently with zero importers) the shipped "
   "path, retiring `agent-identity`.",
   "Prove containment against a real workload on a real cluster &mdash; the Unix `SIGSTOP`/`SIGKILL` paths in the "
   "new `ExecutionEngine` compile but have never run."],
  ["**A confidential-compute VM.** Azure NCCadsH100v5 is GA in East US 2 and West Europe &mdash; you have Azure "
   "credit, and this is the single blocker on the attested-inference use case.",
   "**A Kubernetes cluster** with a SPIRE deployment for integration testing.",
   "Confirmation of which cloud the design partners actually run on, so attestation targets the right platform."],
  ["An attestation from real hardware verifies, and a token from a different platform is rejected.",
   "A real process is killed by the kill switch on Linux, in CI."]) }
{phase(5, "Standards position", "ongoing", "note",
  "The goal you named includes a standards position. This is how it is actually won, and it is cheap relative to its "
  "value.",
  ["Draft the P8 contribution as an in-toto predicate or a SCITT profile rather than a competing format.",
   "Engage the open in-toto RFC #554 `agent-decision` thread &mdash; P12 and P2 are the incumbents-in-waiting for "
   "that predicate and the registry is where it gets decided.",
   "Publish the conformance suite as the neutral arbiter for anyone implementing P8 or P12."],
  ["**A decision on venue**: CoSAI, IETF SCITT, or the Agentic AI Foundation. Each has a different cost and a "
   "different audience, and only you can decide where MuVeraAI's name should appear.",
   "Time on a working-group call. Standards are won by showing up, and that is not something I can do for you."],
  ["A P8 draft exists in a venue with a document number.",
   "Someone outside the project implements against the conformance suite."]) }
</section>"""


def sec_decisions():
    return f"""
<section id="decisions">
<div class="eyebrow">03 &middot; Decision log</div>
<h2>Open decisions only you can make</h2>
{para("Ordered by how much downstream work each unblocks. Everything else in the playbook is engineering; these are "
      "not.")}
<div class="tw"><table data-sortable>
<thead><tr><th>#</th><th>Decision</th><th>Why it cannot wait</th><th>My recommendation</th></tr></thead><tbody>
<tr><td>1</td><td><strong>GitHub org + push access</strong></td><td>Six CI workflows, all release automation, and every trust signal are blocked on this. 29 commits, zero CI runs.</td><td>Do it today. It is one command and it unblocks more than any engineering task on this list.</td></tr>
<tr><td>2</td><td><strong>Registry orgs + publish tokens</strong></td><td>Without these there is no install path, so &ldquo;developer adoption&rdquo; is structurally impossible regardless of code quality.</td><td>Claim <code>warrantor</code> on npm, PyPI and crates.io this week, before someone else does.</td></tr>
<tr><td>3</td><td><strong>Legal entity &mdash; and when</strong></td><td><strong>Qatar QCB &sect;10.7.5 requires the provider's LEI and country of registration.</strong> An unincorporated project cannot be entered in the AI Register at all.</td><td>If Qatar or the UAE is a target, this moves ahead of ISO 27001 and probably ahead of the audit.</td></tr>
<tr><td>4</td><td><strong>Which design partner is first, and which use case</strong></td><td>Decides whether Phase 3 leads with P8 or with the jurisdiction mapping &mdash; a materially different eight weeks.</td><td>Pick the one whose auditor will talk to you. The evidence use case is the defensible one.</td></tr>
<tr><td>5</td><td><strong>OSTIF audit application</strong></td><td>Long lead time; it is the hardest enterprise gate and it is free. Only you can submit.</td><td>Apply now, regardless of readiness. The queue is the constraint, not the code.</td></tr>
<tr><td>6</td><td><strong>Confidential-compute hardware</strong></td><td>The attested-inference use case cannot stop being simulated without it. You have Azure credit.</td><td>Spin up one NCCadsH100v5 in East US 2. One instance, a few days, closes a whole category of finding.</td></tr>
<tr><td>7</td><td><strong>Standards venue</strong></td><td>CoSAI, IETF SCITT and AAIF have different costs and audiences, and the in-toto <code>agent-decision</code> RFC thread is open <em>now</em>.</td><td>IETF SCITT for P2, in-toto for P8. Contribute rather than compete &mdash; you cannot out-govern a foundation.</td></tr>
<tr><td>8</td><td><strong>Git identity override</strong></td><td>Every future commit is authored as <code>Warrantor Wave-1 &lt;aumos@local&gt;</code> unless the local config override is removed. DCO sign-off under a synthetic identity is not a meaningful attestation.</td><td>Drop the override. The two commits I made already use your real identity.</td></tr>
<tr><td>9</td><td><strong>Which ~25 components survive</strong></td><td>Maintenance burden is the most likely cause of project death; three comparable projects died exactly this way.</td><td>The KEEP/THIN/CUT verdicts in the companion analysis are my recommendation. Confirm or override each.</td></tr>
</tbody></table></div>
<div class="note"><div class="calltitle">What I do not need from you</div>
{para("Worth stating explicitly, because it is most of the work: **the entire remaining engineering backlog** &mdash; "
      "36 open findings, the SDK, the adapters, the benchmarks, the SBOM, the evidence mapping, the conformance "
      "publication, the docs rewrite. None of that is blocked on you. Phase 0 and the nine decisions above are the "
      "only real critical path; everything else I can run with a small team and Claude Code.")}</div>
</section>"""


def sec_watch():
    return f"""
<section id="watch">
<div class="eyebrow">04 &middot; Standing risks</div>
<h2>What to watch, and what would change the plan</h2>
{bullets([
 "**The Agentic AI Foundation closing the MCP security gap.** MCP's 2026-07-28 spec explicitly lacks server signing, "
 "tool integrity and registry trust &mdash; and AAIF's platinum sponsors are AWS, Anthropic, Google, Microsoft, "
 "OpenAI and Cloudflare. When they fill it, P5 and parts of P1 become MCP extensions co-signed by every model "
 "provider. **Mitigation: be in that conversation rather than parallel to it.**",
 "**Microsoft AGT adding evidence.** Today it is a policy and identity runtime with no signed-evidence story. If that "
 "changes, the differentiation narrows sharply. Watch its release notes monthly.",
 "**A regulator publishing an actual template.** The moment QCB or CBUAE ships a fillable form, the "
 "multi-jurisdiction emission wedge shrinks to a formatting exercise. Currently they prescribe contents and no "
 "container &mdash; that is the window.",
 "**Someone else signing evals.** promptfoo, Inspect or an eval vendor adding attestation would close the single most "
 "defensible slot. It is cheap for them to do and nobody has.",
 "**Project decay through scope.** Three comparable projects died exactly this way &mdash; and one of them had 72,027 "
 "stars, a gutted default branch, 5,659 forks pointing at deleted code, and 440 permanently unanswerable issues. "
 "**Archive or EOL-label anything you cut, explicitly.** Research shows downstream migration is measurably faster "
 "when a project states end-of-life status rather than going quiet.",
])}
<div class="warn"><div class="calltitle">The honest summary</div>
{para("You have genuinely good protocol design, one excellent parser, a real sandbox, a real SPIFFE integration, and "
      "**a four-language conformance suite that almost nobody else in this space has**. You also have zero "
      "distribution, a competitor with Microsoft's name on it, and a quickstart that lies. **The gap between those "
      "two lists is smaller than it looks and is almost entirely unblocked by Phase 0.**")}</div>
</section>"""


def build():
    nav1 = [("Position", [("verdict", "The reframe"), ("gates", "The enterprise gate"),
                          ("ossgate", "The developer gate")]),
            ("Portfolio", [("components", "Component value"), ("surface", "Capability surface"),
                           ("devblockers", "Why devs can't start")]),
            ("Strategy", [("gcc", "The regulatory wedge"), ("thesis", "Where the exponential is")])]
    body1 = (A.sec_verdict_blockers() + A.sec_gates() + sec_ossgate() + A.sec_components()
             + A.sec_surface() + A.sec_devblockers() + sec_gcc() + sec_thesis())
    doc1 = A.shell("Adoption blockers", "Every pending item, challenge and limitation that stops a developer or an "
                   "enterprise using this &mdash; and where the exponential value actually is.",
                   nav1, body1, "Internal &middot; brutally honest &middot; companion to the critical analysis")

    nav2 = [("Plan", [("playbook", "The six phases")]),
            ("You", [("decisions", "Decision log"), ("watch", "Standing risks")])]
    body2 = sec_playbook() + sec_decisions() + sec_watch()
    doc2 = A.shell("Operating playbook", "The sequenced runbook &mdash; what I do, and exactly what I need from you "
                   "at each step.", nav2, body2, "Process document &middot; for Vikram")

    p1 = A.OUT_DIR / "adoption-blockers-2026-08-09.html"
    p2 = A.OUT_DIR / "operating-playbook-2026-08-09.html"
    p1.write_text(doc1, encoding="utf-8")
    p2.write_text(doc2, encoding="utf-8")
    return p1, len(doc1), p2, len(doc2)


if __name__ == "__main__":
    a, na, b, nb = build()
    print(f"wrote {a.name}  ({na/1024:.0f} KB)")
    print(f"wrote {b.name}  ({nb/1024:.0f} KB)")
