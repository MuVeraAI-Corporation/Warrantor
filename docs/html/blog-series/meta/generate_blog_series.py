#!/usr/bin/env python3
"""Generate the Warrantor multi-phase technical blog series (index + 8 articles).

Drives real on-disk HTML deliverables under docs/html/blog-series/.
"""

from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]  # blog-series/
META = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Portfolio inventory (SSOT: 00-reconciliation-matrix tables)
# ---------------------------------------------------------------------------
CLUSTERS: dict[str, dict[str, Any]] = {
    "trust_identity": {
        "label": "Trust / Identity / Policy",
        "components": ["T1", "T2", "I1", "I2", "R4", "R5", "R6"],
        "protocols": ["P1", "P7", "P12"],
        "article": "01-verifiable-agent-authority.html",
    },
    "runtime": {
        "label": "Runtime & Containment",
        "components": ["R1", "R2", "R3", "R7", "R8", "S6", "X2"],
        "protocols": ["P1", "P7", "P12"],
        "article": "02-runtime-containment-kill-switch.html",
    },
    "confidential": {
        "label": "Confidential Compute / TEE / GPU",
        "components": ["C1-1", "C1-2", "C1-3", "C1-4", "C1-5", "N4"],
        "protocols": ["P12"],
        "article": "03-confidential-gpu-attestation.html",
    },
    "supply": {
        "label": "Supply Chain / Formats / SBOM",
        "components": ["S1", "S2", "S3", "S4", "S5", "S7", "S8", "S9", "T1"],
        "protocols": ["P5", "P6", "P11"],
        "article": "04-ai-supply-chain-sbom-lightwell.html",
    },
    "evidence": {
        "label": "Evidence Plane",
        "components": ["E1", "X9", "X2"],
        "protocols": ["P2", "P3", "P4", "P9"],
        "article": "05-evidence-plane-aar-ocsf.html",
    },
    "eval": {
        "label": "Evaluation / Red-Team",
        "components": ["A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "X5", "X6"],
        "protocols": ["P8"],
        "article": "06-eval-redteam-veb-conformance.html",
    },
    "inference_multiagent": {
        "label": "Inference / Multi-Agent",
        "components": ["N1", "N2", "N3", "N4", "X8", "I1"],
        "protocols": ["P5", "P10", "P1"],
        "article": "07-inference-mcp-a2a-delegation.html",
    },
    "federated_crosscut": {
        "label": "Federated / Edge / Cross-Cutting",
        "components": ["F1", "F2", "F3", "F4", "X1", "X3", "X4", "X7", "X10", "X11"],
        "protocols": ["P3", "P11"],
        "article": "08-federated-edge-sovereign-stack.html",
    },
}

PROTOCOLS = {
    "P1": "AAE — Agent Authority Envelope",
    "P2": "AAR — Agent Action Receipt",
    "P3": "CPE — Context Provenance Envelope",
    "P4": "AMIL — Agent Memory Integrity Ledger",
    "P5": "SSP — Secure Skill Package",
    "P6": "AATM — AI Artifact Trust Manifest",
    "P7": "ABS — Autonomy Budget Specification",
    "P8": "VEB — Verifiable Evaluation Bundle",
    "P9": "AIX — Agent Incident Exchange",
    "P10": "MADE — Multi-Agent Delegation Exchange",
    "P11": "PRB — Proof-Carrying Remediation Bundle",
    "P12": "CAP — Capability Attestation Profile",
}

ARTICLES_META = [
    {
        "num": "01",
        "file": "01-verifiable-agent-authority.html",
        "title": "Verifiable Agent Authority: Envelopes, Budgets, and Workload Identity",
        "eyebrow": "Essay 1 of 8 · Trust / Identity / Policy",
        "lede": "Why agents need cryptographic delegation that SPIFFE + OAuth RAR + Cedar can compose—and how Warrantor AAE (P1), ABS (P7), and CAP (P12) close the gap.",
        "ids": ["T1", "T2", "I1", "I2", "R4", "R5", "R6", "P1", "P7", "P12"],
        "cluster_keys": ["trust_identity"],
    },
    {
        "num": "02",
        "file": "02-runtime-containment-kill-switch.html",
        "title": "Runtime Containment: OpenShell, Kill Switches, and eBPF Egress",
        "eyebrow": "Essay 2 of 8 · Runtime & Containment",
        "lede": "Defense without containment is incomplete. OpenShell sandboxes, continuous access evaluation, and eBPF exfil guards form the fail-closed agent runtime.",
        "ids": ["R1", "R2", "R3", "R7", "R8", "S6", "X2", "P1", "P7", "P12"],
        "cluster_keys": ["runtime"],
    },
    {
        "num": "03",
        "file": "03-confidential-gpu-attestation.html",
        "title": "Confidential GPUs: Attestation, NRAS, and Composite TEE Pipelines",
        "eyebrow": "Essay 3 of 8 · Confidential Compute",
        "lede": "H100/B200 confidential computing only matters if attestation is verifiable offline and online—nvtrust, NRAS, and multi-cloud CC fabrics.",
        "ids": ["C1-1", "C1-2", "C1-3", "C1-4", "C1-5", "N4", "P12"],
        "cluster_keys": ["confidential"],
    },
    {
        "num": "04",
        "file": "04-ai-supply-chain-sbom-lightwell.html",
        "title": "AI Supply Chain Integrity: Safetensors++, ML-BOM, Sigstore, Lightwell",
        "eyebrow": "Essay 4 of 8 · Supply Chain",
        "lede": "Weights are not “just data.” Provenance, SBOM, transparency logs, and signed remediation bundles are the control plane for model artifacts.",
        "ids": ["S1", "S2", "S3", "S4", "S5", "S7", "S8", "S9", "T1", "P5", "P6", "P11"],
        "cluster_keys": ["supply"],
    },
    {
        "num": "05",
        "file": "05-evidence-plane-aar-ocsf.html",
        "title": "The Evidence Plane: Action Receipts, Provenance Graphs, and Incident Exchange",
        "eyebrow": "Essay 5 of 8 · Evidence",
        "lede": "If you cannot produce a signed receipt for what the agent did, you do not have governance—you have vibes. AAR, OTel GenAI, OCSF, ATLAS.",
        "ids": ["E1", "X9", "X2", "P2", "P3", "P4", "P9"],
        "cluster_keys": ["evidence"],
    },
    {
        "num": "06",
        "file": "06-eval-redteam-veb-conformance.html",
        "title": "Evaluation as Evidence: garak, PyRIT, VEB, and Conformance Suites",
        "eyebrow": "Essay 6 of 8 · Eval / Red-Team",
        "lede": "Evals that cannot be packaged, signed, and replayed are theater. Verifiable evaluation bundles and multi-language conformance.",
        "ids": ["A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "X5", "X6", "P8"],
        "cluster_keys": ["eval"],
    },
    {
        "num": "07",
        "file": "07-inference-mcp-a2a-delegation.html",
        "title": "Inference Gateways and Multi-Agent Protocols: MCP, A2A, MADE",
        "eyebrow": "Essay 7 of 8 · Inference / Multi-Agent",
        "lede": "Tool plane (MCP) and agent plane (A2A) are different. Authority-aware gateways and delegation exchange keep both fail-closed.",
        "ids": ["N1", "N2", "N3", "N4", "X8", "I1", "P5", "P10", "P1"],
        "cluster_keys": ["inference_multiagent"],
    },
    {
        "num": "08",
        "file": "08-federated-edge-sovereign-stack.html",
        "title": "Federated Training, Edge Attestation, and the Sovereign Bundle",
        "eyebrow": "Essay 8 of 8 · Federated / Cross-Cutting",
        "lede": "DP budgets, Jetson-class edge agents, fleet operators, and air-gapped sovereign stacks complete the authority/evidence substrate.",
        "ids": ["F1", "F2", "F3", "F4", "X1", "X3", "X4", "X7", "X10", "X11", "P3", "P11"],
        "cluster_keys": ["federated_crosscut"],
    },
]


def chips(ids: list[str]) -> str:
    out = []
    for i in ids:
        cls = "id-chip protocol" if i.startswith("P") else "id-chip"
        out.append(f'<span class="{cls}" data-aumos-id="{html.escape(i)}">{html.escape(i)}</span>')
    return " ".join(out)


def shell(title: str, eyebrow: str, lede: str, ids: list[str], body: str, prev_next: str, refs: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{html.escape(title)} · Warrantor Blog Series</title>
  <link rel="stylesheet" href="blog-series.css">
</head>
<body>
<div class="container">
  <div class="series-bar">
    <a href="index.html">← Series index</a>
    <span class="series-pill">Warrantor · Open Authority &amp; Evidence Stack</span>
    <span>Local technical essay · 2026</span>
  </div>

  <header class="article-header">
    <div class="article-eyebrow">{html.escape(eyebrow)}</div>
    <h1>{html.escape(title)}</h1>
    <p class="article-authors">Warrantor Engineering Essays · Open Secure AI Alliance portfolio</p>
    <p class="article-affil">{html.escape(lede)}</p>
    <div class="article-meta">
      <div class="meta-item"><span class="meta-label">Maps to</span><span class="meta-value">{chips(ids)}</span></div>
      <div class="meta-item"><span class="meta-label">Pipeline</span><span class="meta-value">Research → draft → visuals → adversarial review → fix</span></div>
      <div class="meta-item"><span class="meta-label">Citations</span><span class="meta-value">Primary RFCs / eng blogs / standards</span></div>
    </div>
    <nav class="article-nav">{prev_next}</nav>
  </header>

{body}

  <section class="refs" id="refs">
    <h2>References (primary sources)</h2>
    <ol>
{refs}
    </ol>
  </section>

  <footer style="margin-top:3rem;padding-top:1rem;border-top:1px solid var(--border);font-size:0.85rem;color:var(--text-tertiary);">
    <p>Local in-repo deliverable. Not a hosted artifact. Series plan: <code>meta/phase-plan.md</code>.</p>
    <p>{prev_next}</p>
  </footer>
</div>
</body>
</html>
"""


def ref_items(items: list[tuple[str, str, str]]) -> str:
    """(title, author, url) -> <li>…"""
    lines = []
    for title, author, url in items:
        lines.append(
            f'      <li class="cite" data-cite-url="{html.escape(url)}"><strong>{html.escape(title)}</strong> — {html.escape(author)}. '
            f'<a href="{html.escape(url)}" rel="noopener noreferrer" target="_blank">{html.escape(url)}</a></li>'
        )
    return "\n".join(lines)


def nav_for(idx: int) -> str:
    prev_html = (
        f'<a href="{ARTICLES_META[idx-1]["file"]}">← Essay {ARTICLES_META[idx-1]["num"]}</a>'
        if idx > 0
        else '<a href="index.html">← Index</a>'
    )
    next_html = (
        f'<a href="{ARTICLES_META[idx+1]["file"]}">Essay {ARTICLES_META[idx+1]["num"]} →</a>'
        if idx < len(ARTICLES_META) - 1
        else '<a href="index.html">Index →</a>'
    )
    return f"{prev_html}<span></span>{next_html}"


# ========================= ARTICLE BODIES =========================

def article_01() -> tuple[str, list[tuple[str, str, str]]]:
    refs = [
        ("SPIFFE — Secure Production Identity Framework for Everyone", "SPIFFE / CNCF", "https://spiffe.io/"),
        ("SPIRE Concepts", "SPIFFE Project", "https://spiffe.io/docs/latest/spire-about/spire-concepts/"),
        ("RFC 9396 — OAuth 2.0 Rich Authorization Requests", "IETF", "https://www.rfc-editor.org/rfc/rfc9396.html"),
        ("RFC 9449 — OAuth 2.0 DPoP", "IETF", "https://www.rfc-editor.org/rfc/rfc9449.html"),
        ("RFC 8693 — OAuth 2.0 Token Exchange", "IETF", "https://www.rfc-editor.org/rfc/rfc8693.html"),
        ("Enforce least-privilege authorization in multi-agent AI chains using Cedar", "AWS Security Blog", "https://aws.amazon.com/blogs/security/enforce-least-privilege-authorization-in-multi-agent-ai-chains-using-cedar/"),
        ("Cedar Policy Language", "AWS Open Source", "https://www.cedarpolicy.com/"),
        ("Open Policy Agent Documentation", "OPA / CNCF", "https://www.openpolicyagent.org/docs/latest/"),
    ]
    body = r"""
  <div class="abstract">
    <span class="abstract-label">Thesis</span>
    <p>Agent systems fail open on authority: platforms mint coarse bearer tokens, MCP tools inherit ambient privilege, and multi-agent hops launder intent. Warrantor treats authority as a <strong>verifiable substrate</strong>—not a dashboard. This essay walks the composition of SPIFFE identity, OAuth RAR-structured scopes, DPoP-bound credentials, Cedar/OPA decision equivalence, and the Warrantor envelopes <span class="id-chip protocol">P1</span> AAE, <span class="id-chip protocol">P7</span> ABS, and <span class="id-chip protocol">P12</span> CAP.</p>
  </div>

  <div class="toc"><div class="toc-title">Contents</div>
  <ol>
    <li><a href="#problem">The authority gap in production agents</a></li>
    <li><a href="#stack">The composition stack (not a fork)</a></li>
    <li><a href="#aae">Agent Authority Envelope mechanics</a></li>
    <li><a href="#threats">Threat &amp; failure modes</a></li>
    <li><a href="#aumos">Warrantor component mapping</a></li>
    <li><a href="#impl">Implications for implementers</a></li>
  </ol></div>

  <h2 id="problem">1. The authority gap in production agents</h2>
  <p>Every relying party that honors an agent request faces the same incomplete evidence package: a platform credential that says “this SaaS may call me,” not “this human delegated this agent, for this audience, for this budget, on this attested host, until this expiry, with this revocation channel.” SPIFFE solved workload identity for services<sup><a href="#refs">[1]</a></sup>; agents add dynamic human delegation, tool graphs, and multi-hop OBO (on-behalf-of) paths that classical mTLS never modeled.</p>
  <p>OAuth’s answer is partial. Rich Authorization Requests (RAR) give structured <code>authorization_details</code><sup><a href="#refs">[3]</a></sup>; DPoP binds tokens to keys<sup><a href="#refs">[4]</a></sup>; Token Exchange scopes downstream hops<sup><a href="#refs">[5]</a></sup>. AWS’s three-layer Cedar model for multi-agent chains shows how policy can check capability, delegation path, and originating user together<sup><a href="#refs">[6]</a></sup>. None of these alone is an agent authority envelope. Warrantor’s claim is that they must be composed into a single verifiable artifact with a fail-closed verification contract.</p>

  <div class="visual" data-visual="architecture-svg">
    <div class="visual-caption">Figure 1 — Authority composition plane</div>
    <svg viewBox="0 0 840 280" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Authority stack diagram">
      <rect width="840" height="280" fill="#f8f6f2"/>
      <rect x="20" y="30" width="150" height="70" rx="8" fill="#fff" stroke="#d97757" stroke-width="2"/>
      <text x="95" y="60" text-anchor="middle" font-family="Georgia,serif" font-size="14" fill="#1a1a1a">Human principal</text>
      <text x="95" y="80" text-anchor="middle" font-family="monospace" font-size="11" fill="#737373">OIDC / MFA</text>
      <path d="M170 65 H220" stroke="#d97757" stroke-width="2" marker-end="url(#arrow)"/>
      <rect x="220" y="30" width="170" height="70" rx="8" fill="#fff" stroke="#555188" stroke-width="2"/>
      <text x="305" y="55" text-anchor="middle" font-family="Georgia,serif" font-size="13" fill="#1a1a1a">AAE (P1)</text>
      <text x="305" y="75" text-anchor="middle" font-family="monospace" font-size="10" fill="#737373">scope · audience · exp</text>
      <path d="M390 65 H440" stroke="#555188" stroke-width="2"/>
      <rect x="440" y="20" width="160" height="90" rx="8" fill="#fff" stroke="#4a6fa5" stroke-width="2"/>
      <text x="520" y="50" text-anchor="middle" font-family="Georgia,serif" font-size="13" fill="#1a1a1a">SPIFFE SVID</text>
      <text x="520" y="70" text-anchor="middle" font-family="monospace" font-size="10" fill="#737373">I1 / I2 workload ID</text>
      <text x="520" y="90" text-anchor="middle" font-family="monospace" font-size="10" fill="#737373">host selectors</text>
      <path d="M600 65 H650" stroke="#4a6fa5" stroke-width="2"/>
      <rect x="650" y="20" width="170" height="90" rx="8" fill="#fff" stroke="#5a8055" stroke-width="2"/>
      <text x="735" y="50" text-anchor="middle" font-family="Georgia,serif" font-size="13" fill="#1a1a1a">Cedar / OPA</text>
      <text x="735" y="70" text-anchor="middle" font-family="monospace" font-size="10" fill="#737373">R5 / R6 decision</text>
      <text x="735" y="90" text-anchor="middle" font-family="monospace" font-size="10" fill="#737373">fail-closed</text>
      <rect x="120" y="160" width="200" height="80" rx="8" fill="#faf0eb" stroke="#d97757"/>
      <text x="220" y="195" text-anchor="middle" font-family="Georgia,serif" font-size="13" fill="#1a1a1a">ABS (P7) budget</text>
      <text x="220" y="215" text-anchor="middle" font-family="monospace" font-size="10" fill="#737373">tokens · tools · spend</text>
      <rect x="360" y="160" width="200" height="80" rx="8" fill="#eeeef5" stroke="#555188"/>
      <text x="460" y="195" text-anchor="middle" font-family="Georgia,serif" font-size="13" fill="#1a1a1a">CAP (P12)</text>
      <text x="460" y="215" text-anchor="middle" font-family="monospace" font-size="10" fill="#737373">sandbox · TEE · selectors</text>
      <rect x="600" y="160" width="200" height="80" rx="8" fill="#edf5ed" stroke="#5a8055"/>
      <text x="700" y="195" text-anchor="middle" font-family="Georgia,serif" font-size="13" fill="#1a1a1a">R4 CredentialVault</text>
      <text x="700" y="215" text-anchor="middle" font-family="monospace" font-size="10" fill="#737373">DPoP-bound secrets</text>
      <defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#d97757"/></marker></defs>
    </svg>
  </div>

  <h2 id="stack">2. The composition stack (not a fork)</h2>
  <p>Warrantor doctrine is explicit: do not reinvent SPIFFE, OAuth, or Cedar. Profile them. <span class="id-chip">I1</span> agent-identity and <span class="id-chip">I2</span> identity-bindings attach SPIRE attestation plugins so agent pods get short-lived SVIDs. <span class="id-chip">T1</span> trust-core verifies signatures with a single Rust authoritative implementation—no dual security invariants. <span class="id-chip">T2</span> authority-spec holds the normative AAE schema (CDDL/JSON) that every language package must pass before release.</p>
  <p>Policy compilation (<span class="id-chip">R5</span>) turns regulatory/NL intent into OpenShell + OPA/Cedar rules; <span class="id-chip">R6</span> policy-bridge runs decision-equivalence tests so engines cannot disagree silently. Credential brokering (<span class="id-chip">R4</span>) issues agent-scoped secrets under DPoP-style sender constraint—stolen tokens without the proof-of-possession key are inert.</p>

  <div class="visual" data-visual="protocol-field-map">
    <div class="visual-caption">Figure 2 — AAE (P1) mandatory field map (normative sketch)</div>
    <div class="field-map">
      <div class="field"><div class="fname">iss / sub</div><div class="fdesc">Principal issuer + subject (human or service account)</div></div>
      <div class="field"><div class="fname">agent_id</div><div class="fdesc">SPIFFE ID or agent workload URI</div></div>
      <div class="field"><div class="fname">aud</div><div class="fdesc">Audience-bound relying parties</div></div>
      <div class="field"><div class="fname">scope / rar</div><div class="fdesc">RAR-shaped authorization_details</div></div>
      <div class="field"><div class="fname">nbf / exp</div><div class="fdesc">Validity window; short default TTL</div></div>
      <div class="field"><div class="fname">cap_bind</div><div class="fdesc">Hash/link to CAP attestation (P12)</div></div>
      <div class="field"><div class="fname">budget_ref</div><div class="fdesc">ABS budget id (P7)</div></div>
      <div class="field"><div class="fname">jti / rev_uri</div><div class="fdesc">Unique id + revocation endpoint</div></div>
      <div class="field"><div class="fname">sig / alg</div><div class="fdesc">COSE/JWS signature; T1 verifies</div></div>
    </div>
  </div>

  <div class="callout warning">
    <div class="callout-title">Warrantor-native composition (not an IETF standard)</div>
    <p><span class="id-chip protocol">P1</span> AAE, <span class="id-chip protocol">P7</span> ABS, and <span class="id-chip protocol">P12</span> CAP are <strong>Warrantor protocol profiles</strong>. There is no single public “Agent Authority Envelope RFC.” The normative external pieces are SPIFFE, RAR, DPoP, Token Exchange, Cedar/OPA, and SSF/CAEP. Warrantor composes them into one verification contract and ships CDDL under <code>specs/protocols/</code>.</p>
  </div>

  <h2 id="aae">3. Agent Authority Envelope mechanics</h2>
  <p>Verification is an <em>intersection</em>, not a union: principal-granted capabilities ∩ host-attested capabilities ∩ protocol-declared tool schemas. If any set is empty after intersection, deny. ABS budgets throttle cumulative tool calls, dollar spend, and data egress—counters must be atomic under concurrent tool storms. CAP binds the envelope to sandbox/TEE measurements so a token minted for a confidential GPU cannot be replayed on an unattested laptop.</p>
  <p><strong>Normative crypto for v1:</strong> prefer COSE (RFC 9052) for compact CBOR envelopes verified in <span class="id-chip">T1</span>; JWS remains an interoperability mapping, not a second authoritative implementation. Dual crypto without a single verifier path is how signature-check bugs fork silently.</p>
  <div class="callout danger">
    <div class="callout-title">Fail-closed default</div>
    <p>Missing revocation check, clock skew beyond skew budget, audience mismatch, or CAP miss → hard deny. Soft-fail “best effort authz” is how agent breaches become production incidents.</p>
  </div>
  <div class="callout">
    <div class="callout-title">US model-risk posture (banking)</div>
    <p>For US regulated deployers, OCC Bulletin 2026-13 / Fed SR 26-2 revise model-risk guidance and explicitly defer generative/agentic AI from that booklet’s scope—while safety-and-soundness and third-party risk duties remain. Authority envelopes are how you produce evidence those duties still demand.</p>
  </div>

  <h2 id="threats">4. Threat &amp; failure modes</h2>
  <div class="visual" data-visual="threat-table">
    <div class="visual-caption">Table 1 — Threats vs controls</div>
    <table>
      <thead><tr><th>Threat</th><th>Failure mode</th><th>Control</th></tr></thead>
      <tbody>
        <tr><td>Token theft / replay</td><td>Bearer reuse off host</td><td>DPoP + short TTL + CAP bind</td></tr>
        <tr><td>Scope inflation</td><td>Agent escalates tools mid-task</td><td>RAR details + ABS budget counters</td></tr>
        <tr><td>Delegation laundering</td><td>Multi-agent hop drops origin</td><td>Token exchange OBO + Cedar L2/L3</td></tr>
        <tr><td>Policy engine split-brain</td><td>OPA allows / Cedar denies</td><td>R6 decision-equivalence suite</td></tr>
        <tr><td>Dual crypto impl drift</td><td>Language packages disagree</td><td>T1 single authoritative verifier</td></tr>
      </tbody>
    </table>
  </div>

  <h2 id="aumos">5. Warrantor component mapping</h2>
  <p>Wave-1 ships <span class="id-chip">T1</span> and mocked identity; Wave-2 activates real <span class="id-chip">I1</span> SPIRE integration. Protocol specs for P1/P7/P12 live under <code>specs/protocols/</code> with CDDL and conformance vectors. Cross-language packages do not release a protocol version until the conformance suite is green—invariant I-style discipline from the stack pressure test.</p>

  <h2 id="impl">6. Implications for implementers</h2>
  <p>If you only adopt MCP without authority-aware admission, you standardized tool plugs into an ungoverned wall socket. Start with SPIFFE for the agent runtime, RAR-shaped scopes for tools, DPoP for vault egress, and a signed envelope your gateway verifies before any tool dispatch. Warrantor is the reference composition—not a competing identity product.</p>
"""
    return body, refs


def article_02() -> tuple[str, list[tuple[str, str, str]]]:
    refs = [
        ("Run Autonomous, Self-Evolving Agents More Safely with NVIDIA OpenShell", "NVIDIA Technical Blog", "https://developer.nvidia.com/blog/run-autonomous-self-evolving-agents-more-safely-with-nvidia-openshell/"),
        ("Industry Leaders Join Open Secure AI Alliance for AI Safety", "NVIDIA Blog", "https://blogs.nvidia.com/blog/open-secure-ai-alliance/"),
        ("OpenID Shared Signals Framework", "OpenID Foundation", "https://openid.net/sg/sharedsignals/"),
        ("eBPF Documentation", "eBPF Foundation", "https://ebpf.io/what-is-ebpf/"),
        ("Cilium Tetragon", "Cilium / Isovalent", "https://tetragon.io/"),
        ("Falco — Cloud Native Runtime Security", "CNCF Falco", "https://falco.org/"),
        ("Wasmtime", "Bytecode Alliance", "https://wasmtime.dev/"),
        ("Investigating three real-world incidents in our cybersecurity evaluations", "Anthropic", "https://www.anthropic.com/news/investigating-incidents-cybersecurity-evals"),
    ]
    body = r"""
  <div class="abstract">
    <span class="abstract-label">Thesis</span>
    <p>Authority without containment is paper security. After 2026 evaluation escapes and real-world unauthorized access during “simulated” cyber tests<sup><a href="#refs">[8]</a></sup>, the industry must treat sandboxes, kill switches, and egress filters as <em>load-bearing</em>. Warrantor maps OpenShell-class runtimes to <span class="id-chip">R1</span>/<span class="id-chip">R8</span>, kill-switch to <span class="id-chip">R3</span>, eBPF enforcement to <span class="id-chip">R7</span>/<span class="id-chip">S6</span>, and NOOA extensions to <span class="id-chip">X2</span>.</p>
  </div>
  <div class="toc"><div class="toc-title">Contents</div>
  <ol>
    <li><a href="#why">Why containment is the new perimeter</a></li>
    <li><a href="#openshell">OpenShell architecture for agents</a></li>
    <li><a href="#kill">Kill switches and continuous evaluation</a></li>
    <li><a href="#ebpf">eBPF egress and exfil guards</a></li>
    <li><a href="#map">Warrantor runtime map</a></li>
  </ol></div>

  <h2 id="why">1. Why containment is the new perimeter</h2>
  <p>Agents that write code, open sockets, and chain tools convert “prompt risk” into “host risk.” Network firewalls do not see intent; identity systems do not see syscalls. You need a layered runtime: capability-scoped execution (WASM/OpenShell), attested boundaries (<span class="id-chip">R2</span> eval-guard), emergency stop (<span class="id-chip">R3</span>), and kernel-visible enforcement (eBPF).</p>

  <div class="visual" data-visual="containment-layers">
    <div class="visual-caption">Figure 1 — Containment layers (outer → inner)</div>
    <svg viewBox="0 0 800 260" xmlns="http://www.w3.org/2000/svg" aria-label="Containment layers">
      <rect width="800" height="260" fill="#f8f6f2"/>
      <rect x="40" y="30" width="720" height="200" rx="12" fill="none" stroke="#b94a48" stroke-width="2" stroke-dasharray="6 4"/>
      <text x="60" y="55" font-family="monospace" font-size="12" fill="#b94a48">R7/S6 eBPF egress + exfil (host)</text>
      <rect x="80" y="70" width="640" height="140" rx="10" fill="none" stroke="#b8860b" stroke-width="2"/>
      <text x="100" y="95" font-family="monospace" font-size="12" fill="#b8860b">R3 kill-switch + CAEP/SSF revoke</text>
      <rect x="120" y="110" width="560" height="80" rx="8" fill="#fff" stroke="#d97757" stroke-width="2"/>
      <text x="400" y="145" text-anchor="middle" font-family="Georgia,serif" font-size="16" fill="#1a1a1a">R1/R8 OpenShell / WASM sandbox</text>
      <text x="400" y="168" text-anchor="middle" font-family="monospace" font-size="11" fill="#737373">R2 boundary attestation · CAP bind</text>
    </svg>
  </div>

  <h2 id="openshell">2. OpenShell architecture for agents</h2>
  <p>NVIDIA OpenShell is a secure agent runtime: out-of-process policy, sandboxes, filesystem/network/process controls, privacy routing, and audit trails—so a self-evolving agent cannot rewrite its own guardrails<sup><a href="#refs">[1]</a></sup>. The Open Secure AI Alliance (OSAF) launch introduces NOOA (NVIDIA Labs Object-Oriented Agents) as a <em>harness research</em> contribution for typed, testable agent structure—not as a containment product<sup><a href="#refs">[2]</a></sup>. Keep the distinction explicit: <strong>NOOA makes agents inspectable; OpenShell makes them containable.</strong></p>
  <p>Warrantor does not reimplement OpenShell. <span class="id-chip">R1</span> secure-workspace and <span class="id-chip">R8</span> sandbox-runtime <em>profile</em> OpenShell-class runtimes. Wasmtime<sup><a href="#refs">[7]</a></sup> is a separate portable capability plane for WASM-hosted tools—not a drop-in OpenShell equivalent. <span class="id-chip">R2</span> eval-guard attests that the configured boundary (seccomp/cgroup/OpenShell policy hash) matches CAP before high-risk tools run.</p>
  <div class="callout warning">
    <div class="callout-title">CAEP gap note</div>
    <p>OpenID CAEP final specs speak of humans <em>or robotic users</em>, not “AI agents” by name. Mapping agent sessions to robotic subjects + SSF streams is an Warrantor composition, not a CAEP feature flag.</p>
  </div>

  <h2 id="kill">3. Kill switches and continuous evaluation</h2>
  <p><span class="id-chip">R3</span> kill-switch is Warrantor’s <strong>roadmap/reference design</strong> for emergency stop (Rust core + policy hooks)—not a claim that a universal statutory kill API already ships everywhere. OpenID Shared Signals / CAEP provide continuous access evaluation events<sup><a href="#refs">[3]</a></sup>: session-revoked, risk-level-change, credential-change. Autonomy budgets (<span class="id-chip protocol">P7</span>) feed the same path: budget exhaustion is a soft kill; security signal is a hard kill; eBPF deny is a network kill.</p>
  <p><strong>Sequencing that matters:</strong> (1) freeze new tool admits, (2) revoke AAE via rev_uri / SSF, (3) drain in-flight with timeout, (4) tear sandbox, (5) emit AAR stop receipts. Skipping (5) turns kills into un-auditable folklore—exactly the opposite of an evidence substrate.</p>

  <div class="visual" data-visual="kill-flow">
    <div class="visual-caption">Table 1 — Stop classes</div>
    <table>
      <thead><tr><th>Class</th><th>Trigger</th><th>Plane</th><th>Warrantor</th></tr></thead>
      <tbody>
        <tr><td>Soft stop</td><td>ABS budget exhausted</td><td>Policy</td><td>P7 + R3 policy</td></tr>
        <tr><td>Hard stop</td><td>CAEP risk / admin panic</td><td>Control</td><td>R3 + SSF</td></tr>
        <tr><td>Network stop</td><td>Exfil pattern</td><td>Kernel</td><td>R7 / S6 eBPF</td></tr>
        <tr><td>Attest stop</td><td>CAP/measurement miss</td><td>Trust</td><td>R2 + P12</td></tr>
      </tbody>
    </table>
  </div>

  <h2 id="ebpf">4. eBPF egress and exfil guards</h2>
  <p>eBPF makes policy enforceable where agents cheat—raw sockets, unexpected DNS, data to unapproved destinations<sup><a href="#refs">[4]</a></sup>. Tetragon and Falco exemplify production patterns<sup><a href="#refs">[5,6]</a></sup>. Warrantor splits <span class="id-chip">R7</span> (policy/decision for egress) from <span class="id-chip">S6</span> ExfilGuard (eBPF enforcement) per reconciliation matrix—same story, two layers, no dual authoritative crypto.</p>

  <h2 id="map">5. Warrantor runtime map</h2>
  <p><span class="id-chip">X2</span> nooa-ext is planned production <em>adapters</em> (policy enforcer, audit streamer, identity binder, attestation hook) for NOOA-class harnesses—still not a substitute for OpenShell. Evidence of stops and boundary checks must flow to the flight recorder (Essay 5). Without that coupling, kill switches become un-auditable theater.</p>
  <p><strong>Implications:</strong> If your agent can open sockets your eBPF policy never sees, or your eval harness grants real internet “because the prompt said simulation,” you are replaying 2026 incident patterns. Containment is a product requirement, not a red-team footnote.</p>
  <div class="callout">
    <div class="callout-title">India / US data &amp; ops note</div>
    <p>Runtime logs and kill receipts often contain personal data or regulated context. India DPDP processing rules and US sectoral duties (safety-and-soundness, third-party) both argue for retention limits and residency-aware evidence stores—not “ship all transcripts to a US SaaS by default.”</p>
  </div>
"""
    return body, refs


def article_03() -> tuple[str, list[tuple[str, str, str]]]:
    refs = [
        ("NVIDIA Trusted Computing / nvtrust Documentation", "NVIDIA", "https://docs.nvidia.com/nvtrust/index.html"),
        ("Confidential Computing on NVIDIA H100 GPUs", "NVIDIA Technical Blog", "https://developer.nvidia.com/blog/confidential-computing-on-h100-gpus-for-secure-and-trustworthy-ai/"),
        ("GPU Remote Attestation With Intel Trust Authority", "Intel", "https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-gpu-attestation.html"),
        ("go-nvtrust", "Confident Security", "https://github.com/confidentsecurity/go-nvtrust"),
        ("NVIDIA MIG User Guide", "NVIDIA", "https://docs.nvidia.com/datacenter/tesla/mig-user-guide/"),
    ]
    body = r"""
  <div class="abstract">
    <span class="abstract-label">Thesis</span>
    <p>Confidential GPUs are useless as a marketing checkbox. What matters is a verifiable chain: device identity → attestation report → remote/local verification → policy-bound key release → serving path. Warrantor <span class="id-chip">C1-1</span>…<span class="id-chip">C1-5</span> implement that chain; <span class="id-chip protocol">P12</span> CAP binds it to authority envelopes.</p>
  </div>
  <div class="toc"><div class="toc-title">Contents</div>
  <ol>
    <li><a href="#why">Why GPU attestation is different</a></li>
    <li><a href="#chain">The attestation chain</a></li>
    <li><a href="#multi">Multi-cloud composite pipelines</a></li>
    <li><a href="#threats">Threats unique to CC inference</a></li>
    <li><a href="#map">Component map</a></li>
  </ol></div>

  <h2 id="why">1. Why GPU attestation is different</h2>
  <p>CPU TEEs (SEV-SNP, TDX, Nitro) do not automatically cover accelerator memory. Hopper-class confidential computing adds VRAM encryption and device attestation reports verified via NVIDIA Remote Attestation Service (NRAS) or local verifiers<sup><a href="#refs">[1,2]</a></sup>. Multi-tenant inference without MIG/attestation is shared fate<sup><a href="#refs">[5]</a></sup>.</p>

  <div class="visual" data-visual="attest-flow">
    <div class="visual-caption">Figure 1 — Attestation → key release → serve</div>
    <svg viewBox="0 0 820 200" xmlns="http://www.w3.org/2000/svg">
      <rect width="820" height="200" fill="#f8f6f2"/>
      <rect x="20" y="60" width="140" height="70" rx="8" fill="#fff" stroke="#d97757" stroke-width="2"/>
      <text x="90" y="95" text-anchor="middle" font-size="12" font-family="Georgia,serif">GPU evidence</text>
      <text x="90" y="112" text-anchor="middle" font-size="10" font-family="monospace" fill="#737373">C1-1 / C1-2</text>
      <path d="M160 95 H200" stroke="#d97757" stroke-width="2"/>
      <rect x="200" y="60" width="150" height="70" rx="8" fill="#fff" stroke="#555188" stroke-width="2"/>
      <text x="275" y="95" text-anchor="middle" font-size="12" font-family="Georgia,serif">NRAS / local</text>
      <text x="275" y="112" text-anchor="middle" font-size="10" font-family="monospace" fill="#737373">verify quote</text>
      <path d="M350 95 H390" stroke="#555188" stroke-width="2"/>
      <rect x="390" y="60" width="150" height="70" rx="8" fill="#fff" stroke="#4a6fa5" stroke-width="2"/>
      <text x="465" y="95" text-anchor="middle" font-size="12" font-family="Georgia,serif">Policy gate</text>
      <text x="465" y="112" text-anchor="middle" font-size="10" font-family="monospace" fill="#737373">CAP + AAE</text>
      <path d="M540 95 H580" stroke="#4a6fa5" stroke-width="2"/>
      <rect x="580" y="60" width="150" height="70" rx="8" fill="#fff" stroke="#5a8055" stroke-width="2"/>
      <text x="655" y="95" text-anchor="middle" font-size="12" font-family="Georgia,serif">Key release</text>
      <text x="655" y="112" text-anchor="middle" font-size="10" font-family="monospace" fill="#737373">C1-5 fabric</text>
      <path d="M730 95 H760" stroke="#5a8055" stroke-width="2"/>
      <rect x="760" y="70" width="40" height="50" rx="6" fill="#edf5ed" stroke="#5a8055"/>
      <text x="780" y="100" text-anchor="middle" font-size="11" font-family="monospace">serve</text>
    </svg>
  </div>

  <h2 id="chain">2. The attestation chain</h2>
  <p><span class="id-chip">C1-1</span> nvtrust-bridge wraps nvtrust FFI and offline/mock modes for CI. <span class="id-chip">C1-2</span> cuda-gram is the high-level Python SDK. <span class="id-chip">C1-4</span> tee-serve is TEE-backed model serving (Go sidecar). Community Go verifiers (go-nvtrust) show multi-language demand<sup><a href="#refs">[4]</a></sup>.</p>

  <h2 id="multi">3. Multi-cloud composite pipelines</h2>
  <p><span class="id-chip">C1-3</span> AttestaFlow targets end-to-end attested inference across Azure DC, AWS Nitro, GCP CC + NVIDIA GPUs. Intel Trust Authority documents composite TEE+GPU workflows<sup><a href="#refs">[3]</a></sup>. <span class="id-chip">C1-5</span> confidential-fabric is the policy-bound key release and confidential container orchestration layer.</p>

  <div class="visual" data-visual="cc-matrix">
    <div class="visual-caption">Table 1 — Component responsibilities</div>
    <table>
      <thead><tr><th>ID</th><th>Role</th><th>Wave</th></tr></thead>
      <tbody>
        <tr><td><code>C1-1</code></td><td>nvtrust verify CLI / FFI</td><td>1</td></tr>
        <tr><td><code>C1-2</code></td><td>Python attestation SDK</td><td>1</td></tr>
        <tr><td><code>C1-3</code></td><td>E2E multi-cloud pipeline</td><td>5</td></tr>
        <tr><td><code>C1-4</code></td><td>TEE model serve sidecar</td><td>5</td></tr>
        <tr><td><code>C1-5</code></td><td>Fabric + key release</td><td>5</td></tr>
        <tr><td><code>N4</code></td><td>MIG/MPS multi-tenant GPU</td><td>4</td></tr>
      </tbody>
    </table>
  </div>

  <h2 id="threats">4. Threats unique to CC inference</h2>
  <p>Stale measurements after firmware update, NRAS dependency without local fallback, accepting quotes from non-CC mode, and multi-GPU NVLink trust boundary mistakes. Policy must pin expected measurements and fail closed on mismatch—same discipline as SPIRE selectors.</p>

  <h2 id="map">5. Component map</h2>
  <p>CAP (<span class="id-chip protocol">P12</span>) is how inference proxies and kill switches learn that “this request runs on attested H100/Blackwell CC.” Without CAP bind on AAE, confidential compute is an island. Prefer local verifiers for air-gap (X10) and pin expected measurements after firmware updates—stale golden measurements are a silent fail-open.</p>
  <div class="callout">
    <div class="callout-title">GCC / sovereign deployments</div>
    <p>Sovereign AI programs care about attestation and offline verification. C1-* mock/offline modes for CI must never be confused with production accept paths: production denies when evidence is missing.</p>
  </div>
"""
    return body, refs


def article_04() -> tuple[str, list[tuple[str, str, str]]]:
    refs = [
        ("Safetensors documentation", "Hugging Face", "https://huggingface.co/docs/safetensors/en/index"),
        ("Safetensors security audit blog", "Hugging Face", "https://huggingface.co/blog/safetensors-security-audit"),
        ("Hijacking Safetensors Conversion on Hugging Face", "HiddenLayer", "https://www.hiddenlayer.com/research/silent-sabotage"),
        ("CycloneDX ML-BOM", "OWASP CycloneDX", "https://cyclonedx.org/capabilities/mlbom/"),
        ("SPDX Specifications", "Linux Foundation", "https://spdx.dev/use/specifications/"),
        ("Sigstore", "OpenSSF", "https://www.sigstore.dev/"),
        ("Rekor overview", "Sigstore Docs", "https://docs.sigstore.dev/logging/overview/"),
        ("IBM and Red Hat Expand Lightwell", "IBM Newsroom", "https://newsroom.ibm.com/2026-07-08-ibm-and-red-hat-expand-lightwell-with-new-commercial-offerings-to-build-the-trust-infrastructure-for-ai-era-open-source"),
        ("SLSA", "OpenSSF", "https://slsa.dev/"),
        ("in-toto", "CNCF", "https://in-toto.io/"),
    ]
    body = r"""
  <div class="abstract">
    <span class="abstract-label">Thesis</span>
    <p>Pickle taught us that model files can be code. Safetensors fixed load-time execution<sup><a href="#refs">[1,2]</a></sup>; conversion-service attacks showed provenance still matters<sup><a href="#refs">[3]</a></sup>. Warrantor supply chain is Safetensors++ + Merkle provenance + ML-BOM + Sigstore + Lightwell-class remediation—protocols <span class="id-chip protocol">P5</span>, <span class="id-chip protocol">P6</span>, <span class="id-chip protocol">P11</span>.</p>
  </div>
  <div class="toc"><div class="toc-title">Contents</div>
  <ol>
    <li><a href="#formats">Safe formats</a></li>
    <li><a href="#bom">AI/ML BOM</a></li>
    <li><a href="#ledger">Provenance ledgers</a></li>
    <li><a href="#remed">Remediation bundles</a></li>
    <li><a href="#map">Warrantor map</a></li>
  </ol></div>

  <h2 id="formats">1. Safe formats</h2>
  <div class="callout warning">
    <div class="callout-title">Warrantor-native extensions (not upstream standards)</div>
    <p><span class="id-chip">S1</span> <strong>SafeTensors++</strong> (proposed <code>__provenance__</code> metadata) and <span class="id-chip">S3</span> <strong>GGUF-Ext</strong> (<code>osaf.safety</code> block) are Warrantor portfolio proposals layered on real formats (Hugging Face Safetensors; ggml GGUF). They are not upstream HF or GGUF registry standards today.</p>
  </div>
  <p>Upstream Safetensors stores tensors + JSON header without pickle opcodes<sup><a href="#refs">[1,2]</a></sup>. Conversion-service attacks showed you can still poison distribution even when the format is safe<sup><a href="#refs">[3]</a></sup>. Format safety ≠ supply-chain safety—you still need signatures, lineage, and admission policy.</p>

  <div class="visual" data-visual="supply-pipeline">
    <div class="visual-caption">Figure 1 — Artifact trust pipeline</div>
    <svg viewBox="0 0 840 180" xmlns="http://www.w3.org/2000/svg">
      <rect width="840" height="180" fill="#f8f6f2"/>
      <rect x="15" y="50" width="130" height="60" rx="8" fill="#fff" stroke="#d97757" stroke-width="2"/>
      <text x="80" y="85" text-anchor="middle" font-size="12" font-family="Georgia,serif">Train / fine-tune</text>
      <path d="M145 80 H175" stroke="#d97757" stroke-width="2"/>
      <rect x="175" y="50" width="120" height="60" rx="8" fill="#fff" stroke="#555188" stroke-width="2"/>
      <text x="235" y="85" text-anchor="middle" font-size="12" font-family="Georgia,serif">S8 attest</text>
      <path d="M295 80 H325" stroke="#555188" stroke-width="2"/>
      <rect x="325" y="50" width="120" height="60" rx="8" fill="#fff" stroke="#4a6fa5" stroke-width="2"/>
      <text x="385" y="85" text-anchor="middle" font-size="12" font-family="Georgia,serif">S1 / S3 pack</text>
      <path d="M445 80 H475" stroke="#4a6fa5" stroke-width="2"/>
      <rect x="475" y="50" width="120" height="60" rx="8" fill="#fff" stroke="#5a8055" stroke-width="2"/>
      <text x="535" y="85" text-anchor="middle" font-size="12" font-family="Georgia,serif">S4 BOM + P6</text>
      <path d="M595 80 H625" stroke="#5a8055" stroke-width="2"/>
      <rect x="625" y="50" width="100" height="60" rx="8" fill="#fff" stroke="#b8860b" stroke-width="2"/>
      <text x="675" y="85" text-anchor="middle" font-size="12" font-family="Georgia,serif">S2 Rekor</text>
      <path d="M725 80 H755" stroke="#b8860b" stroke-width="2"/>
      <rect x="755" y="50" width="70" height="60" rx="8" fill="#edf5ed" stroke="#5a8055" stroke-width="2"/>
      <text x="790" y="85" text-anchor="middle" font-size="11" font-family="monospace">serve</text>
    </svg>
  </div>

  <h2 id="bom">2. AI/ML BOM</h2>
  <p>CycloneDX ML-BOM and SPDX AI/Dataset profiles are the dual standards for model+dataset inventory<sup><a href="#refs">[4,5]</a></sup>. <span class="id-chip">S4</span> ModelSBOM and <span class="id-chip protocol">P6</span> AATM align fields (architecture, datasets, licenses, hashes). <span class="id-chip">S5</span> DataProvenanceKit exports signed JSON-LD lineage (model cards / datasheets culture).</p>

  <h2 id="ledger">3. Provenance ledgers</h2>
  <p><span class="id-chip">S2</span> ProvenaChain builds tamper-evident Merkle history with roots in Sigstore Rekor<sup><a href="#refs">[6,7]</a></sup>. SLSA levels and in-toto steps frame training integrity for <span class="id-chip">S8</span><sup><a href="#refs">[9,10]</a></sup>. <span class="id-chip">S7</span> TamperScan hunts weight-level backdoors and silent fine-tunes.</p>

  <div class="visual" data-visual="bom-compare">
    <div class="visual-caption">Table 1 — BOM / ledger responsibilities</div>
    <table>
      <thead><tr><th>Surface</th><th>Standard</th><th>Warrantor</th></tr></thead>
      <tbody>
        <tr><td>ML-BOM inventory</td><td>CycloneDX / SPDX AI</td><td>S4, P6</td></tr>
        <tr><td>Transparency log</td><td>Rekor / CT design</td><td>S2, T1</td></tr>
        <tr><td>Training steps</td><td>SLSA + in-toto</td><td>S8</td></tr>
        <tr><td>Signed skills/tools</td><td>MCP + Cosign</td><td>P5, X8</td></tr>
        <tr><td>Patched deps / models</td><td>Lightwell-class</td><td>S9, P11</td></tr>
      </tbody>
    </table>
  </div>

  <h2 id="threats">4. Supply-chain threat model (explicit)</h2>
  <div class="visual" data-visual="supply-threats">
    <div class="visual-caption">Table 2 — Threats vs controls</div>
    <table>
      <thead><tr><th>Threat</th><th>Control</th></tr></thead>
      <tbody>
        <tr><td>Pickle / code-exec weights</td><td>Safetensors-only admit; block risky formats</td></tr>
        <tr><td>Conversion-bot / publish poison</td><td>Publisher attest + S2 ledger + S7 scans</td></tr>
        <tr><td>Silent fine-tune / backdoor weights</td><td>S7 TamperScan + digest pin in VEB</td></tr>
        <tr><td>Training-data exfil / poison</td><td>S5 lineage + S8 training attest (SLSA targets explicit)</td></tr>
        <tr><td>Unsigned MCP skill</td><td>P5 reject at X8</td></tr>
      </tbody>
    </table>
  </div>

  <h2 id="remed">5. Remediation bundles vs Lightwell</h2>
  <p>IBM/Red Hat Lightwell commercializes a <strong>trusted clearinghouse for remediated open-source application dependencies</strong>—digitally signed packages, SBOMs, and coordination—not a public claim that Lightwell remediates foundation-model weights at scale<sup><a href="#refs">[8]</a></sup>. That distinction is load-bearing.</p>
  <p><span class="id-chip">S9</span> lightwell-bridge and <span class="id-chip protocol">P11</span> PRB are <strong>Warrantor-proposed extensions</strong>: apply the same signed-remediation + transparency pattern to AI artifacts (adapters, skill packs, eval corpora). PRB is “VEX-inspired” status + signatures—not a claim that CSAF/VEX already defines AI weight remediation. Do not cite Lightwell as if it already ships P11.</p>

  <h2 id="map">6. Warrantor map</h2>
  <p><span class="id-chip">T1</span> verifies artifact signatures. Skills enter the gateway only as signed <span class="id-chip protocol">P5</span> SSP packages (Warrantor profile). Without this plane, eval scores and authority envelopes sit on untrusted weights. <strong>Implication:</strong> freeze a weight digest in AAE/VEB or you are authorizing ghosts.</p>
"""
    return body, refs


def article_05() -> tuple[str, list[tuple[str, str, str]]]:
    refs = [
        ("AI Agent Observability — OpenTelemetry Blog", "OpenTelemetry", "https://opentelemetry.io/blog/2025/ai-agent-observability/"),
        ("OWASP Agent Observability Standard — Trace", "OWASP", "https://owasp.github.io/www-project-agent-observability-standard/spec/trace/"),
        ("AOS Trace extend OCSF", "OWASP", "https://owasp.github.io/www-project-agent-observability-standard/spec/trace/extend_ocsf/"),
        ("OCSF Schema", "OCSF Project", "https://schema.ocsf.io/"),
        ("MITRE ATLAS", "MITRE", "https://atlas.mitre.org/"),
        ("W3C PROV Overview", "W3C", "https://www.w3.org/TR/prov-overview/"),
        ("RFC 9052 — COSE", "IETF", "https://www.rfc-editor.org/rfc/rfc9052.html"),
        ("RFC 6962 — Certificate Transparency", "IETF", "https://www.rfc-editor.org/rfc/rfc6962.html"),
    ]
    body = r"""
  <div class="abstract">
    <span class="abstract-label">Thesis</span>
    <p>Logs are not evidence. Evidence is signed, audience-aware, retention-scoped, and mappable to incident taxonomies. Warrantor evidence plane centers on <span class="id-chip">E1</span> flight-recorder emitting <span class="id-chip protocol">P2</span> AAR, with context/memory integrity (<span class="id-chip protocol">P3</span>/<span class="id-chip protocol">P4</span>) and incident exchange (<span class="id-chip protocol">P9</span> / <span class="id-chip">X9</span>).</p>
  </div>
  <div class="toc"><div class="toc-title">Contents</div>
  <ol>
    <li><a href="#gap">From telemetry to evidence</a></li>
    <li><a href="#aar">Agent Action Receipt</a></li>
    <li><a href="#prov">Context &amp; memory integrity</a></li>
    <li><a href="#inc">Incident exchange</a></li>
    <li><a href="#map">Mapping table</a></li>
  </ol></div>

  <h2 id="gap">1. From telemetry to evidence</h2>
  <p>OpenTelemetry’s GenAI observability work standardizes spans for agents<sup><a href="#refs">[1]</a></sup>. OWASP AOS pushes agent-specific trace semantics and OCSF extensions<sup><a href="#refs">[2,3]</a></sup>. That is necessary transport. Warrantor adds cryptographic receipts: COSE-signed action records<sup><a href="#refs">[7]</a></sup> with transparency-log DNA<sup><a href="#refs">[8]</a></sup>.</p>

  <div class="visual" data-visual="evidence-flow">
    <div class="visual-caption">Figure 1 — Action → receipt → incident</div>
    <svg viewBox="0 0 800 200" xmlns="http://www.w3.org/2000/svg">
      <rect width="800" height="200" fill="#f8f6f2"/>
      <rect x="30" y="60" width="150" height="70" rx="8" fill="#fff" stroke="#d97757" stroke-width="2"/>
      <text x="105" y="95" text-anchor="middle" font-size="13" font-family="Georgia,serif">Agent action</text>
      <text x="105" y="112" text-anchor="middle" font-size="10" font-family="monospace" fill="#737373">tool / model I/O</text>
      <path d="M180 95 H220" stroke="#d97757" stroke-width="2"/>
      <rect x="220" y="60" width="150" height="70" rx="8" fill="#fff" stroke="#555188" stroke-width="2"/>
      <text x="295" y="95" text-anchor="middle" font-size="13" font-family="Georgia,serif">E1 recorder</text>
      <text x="295" y="112" text-anchor="middle" font-size="10" font-family="monospace" fill="#737373">sign AAR (P2)</text>
      <path d="M370 95 H410" stroke="#555188" stroke-width="2"/>
      <rect x="410" y="60" width="150" height="70" rx="8" fill="#fff" stroke="#4a6fa5" stroke-width="2"/>
      <text x="485" y="95" text-anchor="middle" font-size="13" font-family="Georgia,serif">OTel + store</text>
      <text x="485" y="112" text-anchor="middle" font-size="10" font-family="monospace" fill="#737373">spans + receipt</text>
      <path d="M560 95 H600" stroke="#4a6fa5" stroke-width="2"/>
      <rect x="600" y="60" width="170" height="70" rx="8" fill="#fff" stroke="#b94a48" stroke-width="2"/>
      <text x="685" y="95" text-anchor="middle" font-size="13" font-family="Georgia,serif">X9 / P9 AIX</text>
      <text x="685" y="112" text-anchor="middle" font-size="10" font-family="monospace" fill="#737373">OCSF + ATLAS</text>
    </svg>
  </div>

  <h2 id="aar">2. Agent Action Receipt</h2>
  <p><span class="id-chip protocol">P2</span> AAR binds: who (AAE ref), what (tool/args hash), when, decision (allow/deny), policy version, and CAP snapshot. <span class="id-chip">E1</span> flight-recorder is the emitter; NOOA audit streamers (<span class="id-chip">X2</span>) can forward without becoming dual verifiers—T1 remains signature authority.</p>

  <div class="visual" data-visual="aar-fields">
    <div class="visual-caption">Figure 2 — AAR field map</div>
    <div class="field-map">
      <div class="field"><div class="fname">aae_jti</div><div class="fdesc">Link to authority envelope</div></div>
      <div class="field"><div class="fname">action</div><div class="fdesc">Normalized tool/API name</div></div>
      <div class="field"><div class="fname">input_hash</div><div class="fdesc">Hash of args (no raw secrets)</div></div>
      <div class="field"><div class="fname">outcome</div><div class="fdesc">allow / deny / error</div></div>
      <div class="field"><div class="fname">policy_id</div><div class="fdesc">Cedar/OPA policy version</div></div>
      <div class="field"><div class="fname">ts / sig</div><div class="fdesc">Timestamp + COSE sig</div></div>
    </div>
  </div>

  <h2 id="prov">3. Context &amp; memory integrity</h2>
  <div class="callout warning">
    <div class="callout-title">Warrantor-native (P3 / P4)</div>
    <p><span class="id-chip protocol">P3</span> CPE and <span class="id-chip protocol">P4</span> AMIL are Warrantor compositions. Foundations: W3C PROV<sup><a href="#refs">[6]</a></sup> and Merkle transparency designs<sup><a href="#refs">[8]</a></sup>—not identical public standards under those names.</p>
  </div>
  <p><strong>CPE sketch:</strong> each retrieved chunk carries <code>source_uri</code>, content hash, ranker id, and policy tags (PII class). The agent’s context window is then a PROV-style derivation graph: query → retrieval set → prompt assembly → model call. Without CPE, RAG poisoning is untraceable.</p>
  <p><strong>AMIL sketch:</strong> memory write ops append <code>(prev_root, op_hash, ts, sig)</code>. Fork/merge of agent memory requires explicit root compare—silent overwrite is a deny. “Agent forgot” becomes a ledger question, not a vibe.</p>

  <h2 id="inc">4. Incident exchange</h2>
  <p><span class="id-chip">X9</span> + <span class="id-chip protocol">P9</span> normalize agent incidents onto OCSF classes<sup><a href="#refs">[4]</a></sup> with MITRE ATLAS technique tags<sup><a href="#refs">[5]</a></sup>. That enables SIEM federation without inventing a proprietary JSON every vendor ignores. Minimum AIX fields: severity, technique ids, linked AAR jtis, affected tenants, and share boundary (internal vs ISA). Retention and redaction are first-class—DPDP and sectoral rules will punish “store full prompts forever.”</p>

  <h2 id="map">5. Mapping table</h2>
  <div class="visual" data-visual="map-table">
    <div class="visual-caption">Table 1 — Evidence surfaces</div>
    <table>
      <thead><tr><th>Protocol</th><th>Purpose</th><th>Primary consumers</th></tr></thead>
      <tbody>
        <tr><td>P2 AAR</td><td>Signed action receipt</td><td>E1, X2, auditors</td></tr>
        <tr><td>P3 CPE</td><td>Context provenance</td><td>RAG / memory systems</td></tr>
        <tr><td>P4 AMIL</td><td>Memory integrity ledger</td><td>Long-running agents</td></tr>
        <tr><td>P9 AIX</td><td>Incident exchange</td><td>X9, SOC, R3</td></tr>
      </tbody>
    </table>
  </div>
  <p><strong>Implications:</strong> Instrument with OTel GenAI conventions, seal with AAR, normalize incidents with OCSF+ATLAS, and refuse dashboards that cannot show a signed receipt for a denied tool call.</p>
"""
    return body, refs


def article_06() -> tuple[str, list[tuple[str, str, str]]]:
    refs = [
        ("Announcing PyRIT", "Microsoft Security Blog", "https://www.microsoft.com/en-us/security/blog/2024/02/22/announcing-microsofts-open-automation-framework-to-red-team-generative-ai-systems/"),
        ("Azure/PyRIT", "Microsoft", "https://github.com/Azure/PyRIT"),
        ("NVIDIA/garak", "NVIDIA", "https://github.com/NVIDIA/garak"),
        ("HELM", "Stanford CRFM", "https://crfm.stanford.edu/helm/"),
        ("AgentDojo", "ETH Zurich", "https://github.com/ethz-spylab/agentdojo"),
        ("METR", "METR", "https://metr.org/"),
        ("UK AISI Inspect", "UK AISI", "https://inspect.aisi.org.uk/"),
        ("NIST AI RMF", "NIST", "https://www.nist.gov/itl/ai-risk-management-framework"),
        ("OCC Bulletin 2026-13 Model Risk Management", "OCC", "https://www.occ.gov/news-issuances/bulletins/2026/bulletin-2026-13.html"),
        ("Investigating three real-world incidents…", "Anthropic", "https://www.anthropic.com/news/investigating-incidents-cybersecurity-evals"),
    ]
    body = r"""
  <div class="abstract">
    <span class="abstract-label">Thesis</span>
    <p>Evaluation without packaging is a slide. Warrantor treats eval as evidence: orchestrate garak/PyRIT/HELM/Inspect<sup><a href="#refs">[1–7]</a></sup>, seal results in <span class="id-chip protocol">P8</span> VEB, gate CI with <span class="id-chip">A4</span>/<span class="id-chip">A6</span>, and feed independent evaluators via <span class="id-chip">X6</span>.</p>
  </div>
  <div class="toc"><div class="toc-title">Contents</div>
  <ol>
    <li><a href="#stack">The eval tool stack</a></li>
    <li><a href="#veb">Verifiable Evaluation Bundles</a></li>
    <li><a href="#conf">Conformance as a product</a></li>
    <li><a href="#reg">US / India risk anchors</a></li>
    <li><a href="#map">Component map</a></li>
  </ol></div>

  <h2 id="stack">1. The eval tool stack</h2>
  <p>garak is breadth scanning; PyRIT is multi-turn adversarial orchestration; HELM is multi-metric baselining; AgentDojo attacks tool-using agents; Inspect is a modern harness<sup><a href="#refs">[3–7]</a></sup>. <span class="id-chip">A1</span> SafeEval YAML-orchestrates them; <span class="id-chip">A2</span> Adversaria unifies; <span class="id-chip">A5</span> agentsec-lab holds rotating adversarial benchmarks; <span class="id-chip">A7</span> is continuous red-team cloud; <span class="id-chip">A8</span> arena ranks with Elo methodology.</p>

  <div class="visual" data-visual="eval-stack">
    <div class="visual-caption">Figure 1 — From probes to sealed bundle</div>
    <svg viewBox="0 0 820 200" xmlns="http://www.w3.org/2000/svg">
      <rect width="820" height="200" fill="#f8f6f2"/>
      <rect x="20" y="50" width="120" height="90" rx="8" fill="#fff" stroke="#d97757" stroke-width="2"/>
      <text x="80" y="90" text-anchor="middle" font-size="12" font-family="Georgia,serif">Probes</text>
      <text x="80" y="110" text-anchor="middle" font-size="10" font-family="monospace" fill="#737373">garak / PyRIT</text>
      <path d="M140 95 H175" stroke="#d97757" stroke-width="2"/>
      <rect x="175" y="50" width="120" height="90" rx="8" fill="#fff" stroke="#555188" stroke-width="2"/>
      <text x="235" y="90" text-anchor="middle" font-size="12" font-family="Georgia,serif">Orchestrate</text>
      <text x="235" y="110" text-anchor="middle" font-size="10" font-family="monospace" fill="#737373">A1 / A2</text>
      <path d="M295 95 H330" stroke="#555188" stroke-width="2"/>
      <rect x="330" y="50" width="120" height="90" rx="8" fill="#fff" stroke="#4a6fa5" stroke-width="2"/>
      <text x="390" y="90" text-anchor="middle" font-size="12" font-family="Georgia,serif">Score</text>
      <text x="390" y="110" text-anchor="middle" font-size="10" font-family="monospace" fill="#737373">HELM / judges</text>
      <path d="M450 95 H485" stroke="#4a6fa5" stroke-width="2"/>
      <rect x="485" y="50" width="130" height="90" rx="8" fill="#fff" stroke="#5a8055" stroke-width="2"/>
      <text x="550" y="90" text-anchor="middle" font-size="12" font-family="Georgia,serif">Seal VEB</text>
      <text x="550" y="110" text-anchor="middle" font-size="10" font-family="monospace" fill="#737373">P8 + T1</text>
      <path d="M615 95 H650" stroke="#5a8055" stroke-width="2"/>
      <rect x="650" y="50" width="140" height="90" rx="8" fill="#fff" stroke="#b8860b" stroke-width="2"/>
      <text x="720" y="90" text-anchor="middle" font-size="12" font-family="Georgia,serif">Gate / share</text>
      <text x="720" y="110" text-anchor="middle" font-size="10" font-family="monospace" fill="#737373">A4 / A6 / X6</text>
    </svg>
  </div>

  <h2 id="veb">2. Verifiable Evaluation Bundles</h2>
  <p><span class="id-chip protocol">P8</span> VEB packages dataset pin, harness version, model digest, scores, judge prompts, and signatures. If the bundle cannot be reproduced, the number is not evidence. Anthropic’s 141k-run retrospective<sup><a href="#refs">[10]</a></sup> shows why <span class="id-chip">X5</span> RetroSpecKit must treat transcripts as first-class forensic objects.</p>

  <h2 id="conf">3. Conformance as a product</h2>
  <p><span class="id-chip">A6</span> is cross-language conformance for Warrantor protocols—not model safety alone. No language package ships a protocol version until vectors pass. That is how AAE/AAR avoid “JSON that kinda looks right.”</p>

  <div class="visual" data-visual="eval-components">
    <div class="visual-caption">Table 1 — Eval components</div>
    <table>
      <thead><tr><th>ID</th><th>Name</th><th>Role</th></tr></thead>
      <tbody>
        <tr><td>A1</td><td>safe-eval</td><td>YAML multi-tool orchestration</td></tr>
        <tr><td>A2</td><td>adversaria</td><td>Unified adversarial core</td></tr>
        <tr><td>A3</td><td>bias-sentinel</td><td>Bias / copyright audit</td></tr>
        <tr><td>A4</td><td>comply-gate</td><td>CI compliance gates</td></tr>
        <tr><td>A5</td><td>agentsec-lab</td><td>Holdout adversarial benches</td></tr>
        <tr><td>A6</td><td>conformance</td><td>Protocol multi-lang suite</td></tr>
        <tr><td>A7</td><td>red-team-cloud</td><td>Continuous adversarial SaaS</td></tr>
        <tr><td>A8</td><td>arena</td><td>Elo ranking service</td></tr>
      </tbody>
    </table>
  </div>

  <h2 id="reg">4. US / India risk anchors</h2>
  <p>US banking model-risk supervision now points to OCC Bulletin 2026-13 / Fed SR 26-2—not obsolete SR 11-7<sup><a href="#refs">[9]</a></sup>. NIST AI RMF remains the general US risk framing<sup><a href="#refs">[8]</a></sup>. India DPDP governs personal data in eval corpora (Essay 8). EU AI Act appears only as a passing export concern—not the spine.</p>

  <h2 id="map">5. Component map</h2>
  <p>VEB links to model digests from Essay 4 and AAE from Essay 1: you cannot claim “safe on version X” without binding weights and authority. Separate <strong>model safety eval</strong> (garak/PyRIT/HELM) from <strong>protocol conformance</strong> (A6): both produce evidence, different claim types. <span class="id-chip">X5</span> retrospective transcript review is how you discover eval-environment escapes after the fact—pair with containment (Essay 2), do not replace it.</p>
"""
    return body, refs


def article_07() -> tuple[str, list[tuple[str, str, str]]]:
    refs = [
        ("Introducing the Model Context Protocol", "Anthropic", "https://www.anthropic.com/news/model-context-protocol"),
        ("MCP Specification (latest)", "MCP Project", "https://modelcontextprotocol.io/specification/latest"),
        ("Announcing Agent2Agent Protocol (A2A)", "Google Developers Blog", "https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/"),
        ("A2A Protocol Specification", "A2A Project", "https://a2a-protocol.org/latest/specification/"),
        ("A2A and MCP topics", "A2A Docs", "https://a2a-protocol.org/latest/topics/a2a-and-mcp/"),
        ("MCP vs A2A", "Auth0", "https://auth0.com/blog/mcp-vs-a2a/"),
        ("vLLM Documentation", "vLLM Project", "https://docs.vllm.ai/"),
        ("TensorRT-LLM Docs", "NVIDIA", "https://nvidia.github.io/TensorRT-LLM/"),
        ("RFC 8693 — OAuth 2.0 Token Exchange", "IETF", "https://www.rfc-editor.org/rfc/rfc8693.html"),
    ]
    body = r"""
  <div class="abstract">
    <span class="abstract-label">Thesis</span>
    <p>MCP standardizes tools; A2A standardizes agent-to-agent messaging. Confusing them produces insecure gateways. Warrantor <span class="id-chip">X8</span> is authority-aware MCP admission; <span class="id-chip protocol">P10</span> MADE profiles multi-agent delegation; <span class="id-chip">N1</span>–<span class="id-chip">N3</span> are the inference edge.</p>
  </div>
  <div class="toc"><div class="toc-title">Contents</div>
  <ol>
    <li><a href="#split">MCP vs A2A split</a></li>
    <li><a href="#gateway">Authority-aware MCP gateway</a></li>
    <li><a href="#made">MADE delegation exchange</a></li>
    <li><a href="#infer">Inference stack</a></li>
    <li><a href="#threats">Threat table</a></li>
  </ol></div>

  <h2 id="split">1. MCP vs A2A split</h2>
  <p>MCP is USB-C for tools/resources/prompts<sup><a href="#refs">[1,2]</a></sup>. A2A is agent interoperability over HTTP/JSON with a formal spec and LF momentum<sup><a href="#refs">[3,4]</a></sup>. Official topic pages explain coexistence<sup><a href="#refs">[5]</a></sup>; Auth0 covers security framing<sup><a href="#refs">[6]</a></sup>. Warrantor keeps both: tools go through X8; agent peers use MADE + AAE.</p>

  <div class="visual" data-visual="mcp-a2a">
    <div class="visual-caption">Figure 1 — Two planes, one authority core</div>
    <svg viewBox="0 0 820 240" xmlns="http://www.w3.org/2000/svg">
      <rect width="820" height="240" fill="#f8f6f2"/>
      <rect x="40" y="40" width="300" height="160" rx="12" fill="#fff" stroke="#d97757" stroke-width="2"/>
      <text x="190" y="75" text-anchor="middle" font-family="Georgia,serif" font-size="16">Tool plane (MCP)</text>
      <text x="190" y="110" text-anchor="middle" font-family="monospace" font-size="12" fill="#737373">X8 mcp-gateway</text>
      <text x="190" y="135" text-anchor="middle" font-family="monospace" font-size="12" fill="#737373">P5 Secure Skill Package</text>
      <text x="190" y="160" text-anchor="middle" font-family="monospace" font-size="12" fill="#737373">AAE check before tools</text>
      <rect x="480" y="40" width="300" height="160" rx="12" fill="#fff" stroke="#555188" stroke-width="2"/>
      <text x="630" y="75" text-anchor="middle" font-family="Georgia,serif" font-size="16">Agent plane (A2A)</text>
      <text x="630" y="110" text-anchor="middle" font-family="monospace" font-size="12" fill="#737373">P10 MADE</text>
      <text x="630" y="135" text-anchor="middle" font-family="monospace" font-size="12" fill="#737373">OBO token exchange</text>
      <text x="630" y="160" text-anchor="middle" font-family="monospace" font-size="12" fill="#737373">I1 multi-agent identity</text>
      <rect x="340" y="90" width="140" height="60" rx="8" fill="#faf0eb" stroke="#d97757" stroke-width="2"/>
      <text x="410" y="125" text-anchor="middle" font-family="Georgia,serif" font-size="13">T1 / P1 AAE</text>
    </svg>
  </div>

  <h2 id="gateway">2. Authority-aware MCP gateway</h2>
  <p><span class="id-chip">X8</span> admission algorithm (fail-closed):</p>
  <ol>
    <li>Resolve skill package → verify <span class="id-chip protocol">P5</span> SSP signature (T1).</li>
    <li>Load AAE → check <code>aud</code>, <code>exp</code>, revocation, tool allow class.</li>
    <li>Intersect CAP: runtime measurement matches envelope bind.</li>
    <li>Debit ABS budget for tool class; deny on exhaust.</li>
    <li>Dispatch tool; emit AAR (Essay 5) for allow <em>and</em> deny.</li>
  </ol>
  <p>Unsigned community MCP servers are untrusted code—because they are. <span class="id-chip protocol">P5</span> is Warrantor packaging, not a claim that MCP itself ships skill signatures.</p>

  <h2 id="made">3. MADE delegation exchange</h2>
  <div class="callout warning">
    <div class="callout-title">Warrantor-native (P10 MADE)</div>
    <p>Multi-Agent Delegation Exchange is an Warrantor profile for constrained inter-agent authority. It sits <em>on</em> A2A messaging and OAuth token exchange—it is not the A2A specification itself.</p>
  </div>
  <p><strong>Sequence sketch:</strong> Agent A holds AAE<sub>A</sub>. A creates MADE with <code>parent_jti</code>, task hash, residual RAR details (strict subset), TTL, and signature. Agent B accepts only if residual ⊆ A’s grants and OBO token exchange succeeds. B’s tools at X8 use AAE<sub>B</sub> derived from MADE—not A’s full envelope. Confused-deputy fix: B cannot widen scope by asking A2A peers for “help with everything.”</p>

  <h2 id="infer">4. Inference stack</h2>
  <p><span class="id-chip">N1</span> OpenServeKit targets an OpenAI-compatible wire surface for backend-agnostic serving (ecosystem pattern; not “the OpenAI product”). <span class="id-chip">N2</span> BridgeRT abstracts vLLM/TRT-LLM<sup><a href="#refs">[7,8]</a></sup>; <span class="id-chip">N3</span> InferenceProxy adds auth, rate limits, prompt filters, semantic cache; <span class="id-chip">N4</span> TenantGuard owns MIG multi-tenancy. Authority checks belong in N3/X8—not only inside the model server process.</p>

  <div class="visual" data-visual="threats">
    <div class="visual-caption">Table 1 — Multi-agent / tool threats</div>
    <table>
      <thead><tr><th>Threat</th><th>Mitigation</th></tr></thead>
      <tbody>
        <tr><td>Malicious MCP server</td><td>P5 signed skills + X8 admit</td></tr>
        <tr><td>Confused deputy via A2A</td><td>MADE residual scope + OBO</td></tr>
        <tr><td>Prompt injection → tool fire</td><td>AAE tool allowlist + N3 filters</td></tr>
        <tr><td>Cross-tenant GPU leak</td><td>N4 MIG + CAP</td></tr>
      </tbody>
    </table>
  </div>

  <h2 id="threats">5. Implications</h2>
  <p>Ship MCP for productivity, A2A for federation, and Warrantor authority for both—or accept that interoperability multiplies blast radius. Prompt injection that fires tools is not a model-only bug; it is an admission-control bug at X8. Multi-agent OBO without residual scope is privilege laundering with better branding.</p>
  <div class="callout">
    <div class="callout-title">US / India note</div>
    <p>Tool logs and delegated actions often process personal or customer data. DPDP and US third-party / safety-and-soundness expectations both require knowing <em>which</em> agent acted under <em>which</em> residual authority—MADE + AAR, not chat screenshots.</p>
  </div>
"""
    return body, refs


def article_08() -> tuple[str, list[tuple[str, str, str]]]:
    refs = [
        ("Opacus", "Meta", "https://opacus.ai/"),
        ("Flower Federated Learning", "Flower Labs", "https://flower.ai/"),
        ("NVIDIA Jetson / embedded", "NVIDIA", "https://developer.nvidia.com/embedded-computing"),
        ("Kubernetes Operators", "Kubernetes", "https://kubernetes.io/docs/concepts/extend-kubernetes/operator/"),
        ("Helm Docs", "CNCF Helm", "https://helm.sh/docs/"),
        ("Digital Personal Data Protection Act 2023 (PDF)", "MeitY / Gazette of India", "https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf"),
        ("Fed SR 26-2 Model Risk Management", "Federal Reserve", "https://www.federalreserve.gov/supervisionreg/srletters/SR2602.htm"),
        ("Discovering cryptographic weaknesses with Claude", "Anthropic", "https://www.anthropic.com/research/discovering-cryptographic-weaknesses"),
        ("OCC Bulletin 2026-13 Model Risk Management", "OCC", "https://www.occ.gov/news-issuances/bulletins/2026/bulletin-2026-13.html"),
        ("SPIFFE", "CNCF", "https://spiffe.io/"),
    ]
    body = r"""
  <div class="abstract">
    <span class="abstract-label">Thesis</span>
    <p>Authority and evidence must travel to the edge and into air gaps. Federated training with DP (<span class="id-chip">F1</span>/<span class="id-chip">F2</span>), edge attestation agents (<span class="id-chip">F3</span>), fleet operators (<span class="id-chip">F4</span>), CLI/console/cloud (<span class="id-chip">X1</span>/<span class="id-chip">X7</span>/<span class="id-chip">X11</span>), and sovereign bundles (<span class="id-chip">X10</span>) complete the stack—with India DPDP and US model-risk anchors where data and banks meet AI.</p>
  </div>
  <div class="toc"><div class="toc-title">Contents</div>
  <ol>
    <li><a href="#fed">Federated + DP</a></li>
    <li><a href="#edge">Edge sentinel &amp; fleet</a></li>
    <li><a href="#sov">Sovereign / air-gapped</a></li>
    <li><a href="#x">Cross-cutting product surfaces</a></li>
    <li><a href="#reg">Regional anchors</a></li>
  </ol></div>

  <h2 id="fed">1. Federated + DP</h2>
  <p><span class="id-chip">F1</span> FedCore is attested federated training (PyTorch/NeMo class workloads). <span class="id-chip">F2</span> DPCrate wraps differential privacy tooling (Opacus-class)<sup><a href="#refs">[1]</a></sup> with budget dashboards. Flower-style orchestration patterns inform multi-party control planes<sup><a href="#refs">[2]</a></sup>. Context provenance (<span class="id-chip protocol">P3</span>) records which partitions contributed without leaking raw data.</p>

  <div class="visual" data-visual="fed-edge">
    <div class="visual-caption">Figure 1 — Center ↔ edge authority</div>
    <svg viewBox="0 0 820 220" xmlns="http://www.w3.org/2000/svg">
      <rect width="820" height="220" fill="#f8f6f2"/>
      <rect x="310" y="70" width="200" height="80" rx="10" fill="#fff" stroke="#d97757" stroke-width="2"/>
      <text x="410" y="105" text-anchor="middle" font-family="Georgia,serif" font-size="14">Control plane</text>
      <text x="410" y="125" text-anchor="middle" font-family="monospace" font-size="11" fill="#737373">F4 FleetMarshal · X11</text>
      <rect x="40" y="40" width="160" height="70" rx="8" fill="#fff" stroke="#555188" stroke-width="2"/>
      <text x="120" y="70" text-anchor="middle" font-size="12" font-family="Georgia,serif">Site A · F1/F2</text>
      <text x="120" y="90" text-anchor="middle" font-size="10" font-family="monospace" fill="#737373">DP + attest</text>
      <rect x="40" y="130" width="160" height="70" rx="8" fill="#fff" stroke="#555188" stroke-width="2"/>
      <text x="120" y="160" text-anchor="middle" font-size="12" font-family="Georgia,serif">Site B · F1</text>
      <text x="120" y="180" text-anchor="middle" font-size="10" font-family="monospace" fill="#737373">local data</text>
      <rect x="620" y="70" width="160" height="80" rx="8" fill="#fff" stroke="#5a8055" stroke-width="2"/>
      <text x="700" y="105" text-anchor="middle" font-size="12" font-family="Georgia,serif">Edge F3</text>
      <text x="700" y="125" text-anchor="middle" font-size="10" font-family="monospace" fill="#737373">Jetson / EGX</text>
      <path d="M200 75 H310" stroke="#555188" stroke-width="1.5"/>
      <path d="M200 165 H310" stroke="#555188" stroke-width="1.5"/>
      <path d="M510 110 H620" stroke="#5a8055" stroke-width="1.5"/>
    </svg>
  </div>

  <h2 id="edge">2. Edge sentinel &amp; fleet</h2>
  <p><span class="id-chip">F3</span> EdgeSentinel is a small Go agent for Jetson/EGX-class devices<sup><a href="#refs">[3]</a></sup>—attestation heartbeats and local policy cache. <span class="id-chip">F4</span> FleetMarshal is the K8s operator (<code>ModelFleet</code> CRD) for canary/blue-green<sup><a href="#refs">[4]</a></sup>. Edge without CAP is just remote root.</p>

  <h2 id="sov">3. Sovereign / air-gapped</h2>
  <p><span class="id-chip">X10</span> sovereign-stack packages air-gapped single-node deployment (Helm/Ansible patterns<sup><a href="#refs">[5]</a></sup>). Offline verification modes for nvtrust and Sigstore mirrors are mandatory—sovereign does not mean “skip crypto.”</p>

  <h2 id="x">4. Cross-cutting product surfaces</h2>
  <p><span class="id-chip">X1</span> defstack-cli is the operator CLI for install/verify/compliance-report (Rust implementation language choice—not a claim that a CLI framework is the product). <span class="id-chip">X7</span> console is the enterprise policy/evidence UI (Wave 7). <span class="id-chip">X11</span> defstack-cloud is managed control. <span class="id-chip">X3</span> OpenHarnessSpec aims at vendor-neutral harness contracts (NOOA/MCP-informed, Warrantor-proposed standard). <span class="id-chip">X4</span> CryptoAuditAI productizes AI-assisted cryptanalysis research directions<sup><a href="#refs">[8]</a></sup>—with the same dual-use caution Anthropic’s work implies.</p>

  <div class="visual" data-visual="x-map">
    <div class="visual-caption">Table 1 — Cross-cutting IDs</div>
    <table>
      <thead><tr><th>ID</th><th>Surface</th></tr></thead>
      <tbody>
        <tr><td>X1</td><td>CLI (clap)</td></tr>
        <tr><td>X3</td><td>Open harness spec</td></tr>
        <tr><td>X4</td><td>Crypto audit AI</td></tr>
        <tr><td>X7</td><td>Enterprise console</td></tr>
        <tr><td>X10</td><td>Sovereign air-gap bundle</td></tr>
        <tr><td>X11</td><td>Managed cloud control</td></tr>
        <tr><td>P11</td><td>Remediation into fleets</td></tr>
      </tbody>
    </table>
  </div>

  <h2 id="reg">5. Regional anchors</h2>
  <p>India DPDP Act 2023 is the primary personal-data statute for Indian deployments and data residency choices in federated designs<sup><a href="#refs">[6]</a></sup>. US institutions track Fed SR 26-2 / OCC 2026-13 for model-risk posture<sup><a href="#refs">[7]</a></sup>. GCC sovereign AI programs care about air-gap and attestation—X10/C1-* become procurement language. EU AI Act is a secondary export concern, not the series spine.</p>
  <div class="callout success">
    <div class="callout-title">Series closure</div>
    <p>Essays 1–8 cover every portfolio cluster and every protocol P1–P12 via dedicated sections or the master index matrix. Authority without evidence, evidence without supply-chain binding, and multi-agent interoperability without containment are incomplete systems. Warrantor is the open composition layer that refuses those incompletenesses.</p>
  </div>
"""
    return body, refs


ARTICLE_BUILDERS = [
    article_01,
    article_02,
    article_03,
    article_04,
    article_05,
    article_06,
    article_07,
    article_08,
]


def build_index() -> str:
    cards = []
    for meta in ARTICLES_META:
        cards.append(
            f"""
    <article class="index-card" data-article="{html.escape(meta['file'])}">
      <h3><a href="{html.escape(meta['file'])}">Essay {html.escape(meta['num'])} — {html.escape(meta['title'])}</a></h3>
      <p>{html.escape(meta['lede'])}</p>
      <div class="chips">{chips(meta['ids'][:12])}</div>
    </article>"""
        )

    # Coverage matrix rows
    rows = []
    for key, c in CLUSTERS.items():
        rows.append(
            f"<tr><td><strong>{html.escape(c['label'])}</strong></td>"
            f"<td>{html.escape(', '.join(c['components']))}</td>"
            f"<td>{html.escape(', '.join(c['protocols']))}</td>"
            f"<td><a href=\"{html.escape(c['article'])}\">{html.escape(c['article'])}</a></td>"
            f"<td class=\"coverage-ok\">Cluster essay</td></tr>"
        )
    # Depth tiers for protocols (post phase-5 honesty)
    depth = {
        "P1": "Full", "P2": "Partial", "P3": "Partial", "P4": "Partial",
        "P5": "Partial", "P6": "Partial", "P7": "Partial", "P8": "Partial",
        "P9": "Partial", "P10": "Partial", "P11": "Partial", "P12": "Partial",
    }
    for pid, name in PROTOCOLS.items():
        arts = [m["file"] for m in ARTICLES_META if pid in m["ids"]]
        d = depth.get(pid, "Partial")
        dclass = "coverage-ok" if d == "Full" else "coverage-note"
        rows.append(
            f"<tr data-protocol=\"{html.escape(pid)}\"><td><span class=\"id-chip protocol\" data-aumos-id=\"{html.escape(pid)}\">{html.escape(pid)}</span></td>"
            f"<td colspan=\"2\">{html.escape(name)}</td>"
            f"<td>{html.escape(', '.join(arts) if arts else 'see cluster map')}</td>"
            f"<td class=\"{dclass}\">Depth: {d}</td></tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Warrantor Blog Series — Open Authority &amp; Evidence Stack</title>
  <link rel="stylesheet" href="blog-series.css">
</head>
<body>
<div class="container">
  <header class="index-hero">
    <div class="article-eyebrow">Warrantor · Multi-phase technical blog series · Local deliverable</div>
    <h1>The Open Authority &amp; Evidence Stack</h1>
    <p class="lead" style="font-size:1.1rem;color:var(--text-secondary);max-width:70ch;">
      Eight deep visual essays covering every portfolio cluster and protocols P1–P12.
      Built through a six-phase pipeline (research → outline → draft → visuals → adversarial review → fix)
      with dual subagent passes. Not a reading-list index—original technical synthesis.
    </p>
    <p>
      <span class="phase-badge">Phase 1 research ✓</span>
      <span class="phase-badge">Phase 2 outline ✓</span>
      <span class="phase-badge">Phase 3 draft ✓</span>
      <span class="phase-badge">Phase 4 visuals ✓</span>
      <span class="phase-badge">Phase 5 adversarial review ✓</span>
      <span class="phase-badge">Phase 6 fix pass ✓</span>
    </p>
    <p style="font-size:0.85rem;color:var(--text-tertiary);">Phase evidence: <code>meta/phase1-research-notes.md</code>, <code>meta/phase5-adversarial-review.md</code>. Depth tiers in matrix below (not binary “green means deep”).</p>
    <p style="margin-top:1rem;font-size:0.9rem;"><a href="meta/phase-plan.md">Phase plan</a> ·
      <a href="../curated-reading-list.html">Curated external sources</a> ·
      <a href="../research-papers.html">Formal research papers</a></p>
  </header>

  <h2>Essays</h2>
  <div class="index-grid">
    {''.join(cards)}
  </div>

  <h2 id="coverage-matrix">Coverage matrix — clusters &amp; P1–P12</h2>
  <p>Every cluster and every protocol appears below with a dedicated essay mapping. Component inventory follows
  <code>00-reconciliation-matrix.md</code> tables (54 implementable IDs SSOT; vision-doc “44” is a summary figure).</p>
  <div class="visual" data-visual="master-coverage">
    <div class="visual-caption">Master coverage</div>
    <table>
      <thead><tr><th>Cluster / Protocol</th><th>Components</th><th>Protocols</th><th>Article</th><th>Status</th></tr></thead>
      <tbody>
        {''.join(rows)}
      </tbody>
    </table>
  </div>

  <h2>Protocol legend</h2>
  <ul>
    {''.join(f'<li><span class="id-chip protocol" data-aumos-id="{html.escape(p)}">{html.escape(p)}</span> {html.escape(n)}</li>' for p,n in PROTOCOLS.items())}
  </ul>

  <footer style="margin-top:3rem;padding-top:1rem;border-top:1px solid var(--border);font-size:0.85rem;color:var(--text-tertiary);">
    Generated by <code>meta/generate_blog_series.py</code>. Verify with <code>meta/test_blog_series.py</code>.
  </footer>
</div>
</body>
</html>
"""


def all_mapped_protocols() -> set[str]:
    s: set[str] = set()
    for m in ARTICLES_META:
        for i in m["ids"]:
            if i.startswith("P"):
                s.add(i)
    for c in CLUSTERS.values():
        s.update(c["protocols"])
    return s


def all_mapped_clusters() -> set[str]:
    return set(CLUSTERS.keys())


def generate_all() -> dict[str, Any]:
    ROOT.mkdir(parents=True, exist_ok=True)
    paths = []
    stats_articles = []

    index_path = ROOT / "index.html"
    index_path.write_text(build_index(), encoding="utf-8")
    paths.append(str(index_path))

    for idx, (meta, builder) in enumerate(zip(ARTICLES_META, ARTICLE_BUILDERS)):
        body, refs = builder()
        # Count visuals
        visual_count = len(re.findall(r'data-visual=', body))
        cite_count = len(refs)
        text = shell(
            meta["title"],
            meta["eyebrow"],
            meta["lede"],
            meta["ids"],
            body,
            nav_for(idx),
            ref_items(refs),
        )
        out = ROOT / meta["file"]
        out.write_text(text, encoding="utf-8")
        paths.append(str(out))
        stats_articles.append(
            {
                "file": meta["file"],
                "title": meta["title"],
                "visuals": visual_count,
                "citations": cite_count,
                "ids": meta["ids"],
                "bytes": out.stat().st_size,
                "body_chars": len(body),
            }
        )

    summary = {
        "paths": paths,
        "articles": stats_articles,
        "protocols_mapped": sorted(all_mapped_protocols()),
        "clusters_mapped": sorted(all_mapped_clusters()),
        "protocol_count": len(PROTOCOLS),
        "cluster_count": len(CLUSTERS),
    }
    (META / "series-manifest.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> int:
    summary = generate_all()
    print(json.dumps({k: summary[k] for k in summary if k != "paths"}, indent=2))
    print("paths:")
    for p in summary["paths"]:
        print(" ", p)
    missing_p = set(PROTOCOLS) - set(summary["protocols_mapped"])
    if missing_p:
        print("ERROR missing protocols", missing_p)
        return 1
    if set(summary["clusters_mapped"]) != set(CLUSTERS):
        print("ERROR cluster mismatch")
        return 1
    for a in summary["articles"]:
        if a["visuals"] < 2 or a["citations"] < 3 or a["body_chars"] < 5500:
            print("ERROR depth/visuals", a)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
