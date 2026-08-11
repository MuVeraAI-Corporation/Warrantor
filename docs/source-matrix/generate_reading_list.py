#!/usr/bin/env python3
"""Generate AumOS curated reading list HTML + Markdown from curated-sources.json.

This is the source-of-truth compiler for the deliverable; verification scripts
import coverage helpers from this module.
"""

from __future__ import annotations

import html
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]  # aumos/
DATA_PATH = Path(__file__).resolve().parent / "curated-sources.json"
HTML_OUT = ROOT / "docs" / "html" / "curated-reading-list.html"
MD_OUT = ROOT / "docs" / "curated-reading-list.md"

GROUP_LABELS = {
    "trust": "Trust Core",
    "identity": "Identity & Authority",
    "runtime": "Runtime & Enforcement",
    "confidential": "Confidential Compute & GPU Attestation",
    "supply": "Safe Formats & Supply Chain",
    "eval": "Evaluation & Red-Team",
    "inference": "Inference Stack",
    "federated": "Federated & Edge",
    "crosscut": "Cross-Cutting / Aggregation",
    "evidence": "Evidence Plane",
}

CLUSTER_ORDER = [
    "identity",
    "policy",
    "runtime",
    "confidential",
    "supply-chain",
    "evidence",
    "eval",
    "inference",
    "federated",
    "multi-agent",
    "protocols",
    "crosscut",
]


def load_data(path: Path = DATA_PATH) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def coverage_maps(data: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Map each component/protocol ID -> list of entries that map to it."""
    index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in data["entries"]:
        for mapped in entry.get("maps", []):
            index[mapped].append(entry)
    return dict(index)


def all_portfolio_ids(data: dict[str, Any]) -> tuple[list[str], list[str]]:
    components = list(data["components"].keys())
    protocols = list(data["protocols"].keys())
    return components, protocols


def coverage_status(
    data: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Per-ID coverage: entry count, gap flags, tiers present."""
    maps = coverage_maps(data)
    status: dict[str, dict[str, Any]] = {}
    components, protocols = all_portfolio_ids(data)
    for item_id in components + protocols:
        entries = maps.get(item_id, [])
        tiers = sorted({e.get("tier", "unknown") for e in entries})
        has_gap = any(e.get("gap") or e.get("tier") == "adjacent-substitute" for e in entries)
        only_substitute = bool(entries) and all(
            e.get("tier") == "adjacent-substitute" or e.get("gap") for e in entries
        )
        status[item_id] = {
            "count": len(entries),
            "tiers": tiers,
            "has_gap_note": has_gap,
            "only_substitute": only_substitute,
            "covered": len(entries) >= 1,
            "entry_ids": [e["id"] for e in entries],
        }
    return status


def unique_domains(data: dict[str, Any]) -> list[str]:
    domains: set[str] = set()
    for entry in data["entries"]:
        host = urlparse(entry["url"]).netloc.lower()
        if host.startswith("www."):
            host = host[4:]
        if host:
            domains.add(host)
    return sorted(domains)


def curation_stats(data: dict[str, Any]) -> dict[str, Any]:
    status = coverage_status(data)
    components, protocols = all_portfolio_ids(data)
    uncovered = [i for i, s in status.items() if not s["covered"]]
    substitute_only = [i for i, s in status.items() if s["only_substitute"]]
    return {
        "total_entries": len(data["entries"]),
        "unique_domains": unique_domains(data),
        "unique_domain_count": len(unique_domains(data)),
        "component_count": len(components),
        "protocol_count": len(protocols),
        "covered_ids": sum(1 for s in status.values() if s["covered"]),
        "uncovered_ids": uncovered,
        "substitute_only_ids": substitute_only,
        "canonical_entries": sum(1 for e in data["entries"] if e.get("tier") == "canonical"),
        "deep_secondary_entries": sum(
            1 for e in data["entries"] if e.get("tier") == "deep-secondary"
        ),
        "adjacent_substitute_entries": sum(
            1 for e in data["entries"] if e.get("tier") == "adjacent-substitute"
        ),
    }


def extract_ids_from_html(html_text: str) -> set[str]:
    """Extract portfolio IDs marked in data-id attributes or coverage cells."""
    found = set(re.findall(r'data-portfolio-id="([^"]+)"', html_text))
    found |= set(re.findall(r"\b(P1[0-2]|P[1-9]|C1-[1-5]|[TIRSAXNFE]\d+|T2|I2|E1)\b", html_text))
    return found


def tier_badge(tier: str) -> str:
    labels = {
        "canonical": ("Canonical primary", "tier-canonical"),
        "deep-secondary": ("Deep secondary", "tier-secondary"),
        "adjacent-substitute": ("Adjacent / gap substitute", "tier-gap"),
    }
    label, css = labels.get(tier, (tier, "tier-unknown"))
    return f'<span class="tier {css}">{html.escape(label)}</span>'


def render_entry_card(entry: dict[str, Any]) -> str:
    maps = " ".join(
        f'<span class="map-chip" data-portfolio-id="{html.escape(m)}">{html.escape(m)}</span>'
        for m in entry.get("maps", [])
    )
    tags = " ".join(f'<span class="tag">{html.escape(t)}</span>' for t in entry.get("tags", []))
    gap_note = ""
    if entry.get("gap") or entry.get("tier") == "adjacent-substitute":
        gap_note = (
            '<p class="gap-note"><strong>Coverage note:</strong> '
            "Uses adjacent ecosystem primary sources where a single public twin of the AumOS "
            "surface is still thin.</p>"
        )
    extra = ""
    if entry.get("note"):
        extra = f'<p class="entry-note">{html.escape(entry["note"])}</p>'
    return f"""
    <article class="entry-card" id="entry-{html.escape(entry['id'])}" data-entry-id="{html.escape(entry['id'])}">
      <header>
        <h4><a href="{html.escape(entry['url'])}" rel="noopener noreferrer" target="_blank">{html.escape(entry['title'])}</a></h4>
        <div class="meta">
          <span class="author">{html.escape(entry.get('author', ''))}</span>
          <span class="date">{html.escape(str(entry.get('date', '')))}</span>
          {tier_badge(entry.get('tier', ''))}
        </div>
      </header>
      <p class="why">{html.escape(entry.get('why', ''))}</p>
      {gap_note}{extra}
      <div class="maps"><span class="label">Maps to:</span> {maps}</div>
      <div class="tags">{tags}</div>
      <p class="url"><code>{html.escape(entry['url'])}</code></p>
    </article>
    """


def render_coverage_matrix(data: dict[str, Any], status: dict[str, dict[str, Any]]) -> str:
    rows: list[str] = []
    # Components by group
    by_group: dict[str, list[str]] = defaultdict(list)
    for cid, meta in data["components"].items():
        by_group[meta["group"]].append(cid)

    group_order = [
        "trust",
        "identity",
        "runtime",
        "confidential",
        "supply",
        "eval",
        "inference",
        "federated",
        "crosscut",
        "evidence",
    ]

    for group in group_order:
        label = GROUP_LABELS.get(group, group)
        rows.append(
            f'<tr class="group-row"><td colspan="5"><strong>{html.escape(label)}</strong></td></tr>'
        )
        for cid in by_group.get(group, []):
            meta = data["components"][cid]
            st = status[cid]
            css = "ok" if st["covered"] and not st["only_substitute"] else (
                "sub" if st["covered"] else "miss"
            )
            status_label = (
                "Covered"
                if st["covered"] and not st["only_substitute"]
                else ("Gap / substitute" if st["covered"] else "MISSING")
            )
            rows.append(
                f"""<tr class="{css}">
                <td data-portfolio-id="{html.escape(cid)}"><code>{html.escape(cid)}</code></td>
                <td><code>{html.escape(meta['name'])}</code></td>
                <td>Wave {html.escape(str(meta['wave']))}</td>
                <td>{st['count']}</td>
                <td>{html.escape(status_label)} · {html.escape(', '.join(st['tiers']))}</td>
                </tr>"""
            )

    rows.append(
        '<tr class="group-row"><td colspan="5"><strong>Protocols (spec-only P1–P12)</strong></td></tr>'
    )
    for pid, meta in data["protocols"].items():
        st = status[pid]
        css = "ok" if st["covered"] and not st["only_substitute"] else (
            "sub" if st["covered"] else "miss"
        )
        status_label = (
            "Covered"
            if st["covered"] and not st["only_substitute"]
            else ("Gap / substitute" if st["covered"] else "MISSING")
        )
        rows.append(
            f"""<tr class="{css}">
            <td data-portfolio-id="{html.escape(pid)}"><code>{html.escape(pid)}</code></td>
            <td><code>{html.escape(meta['name'])}</code> — {html.escape(meta['spelled'])}</td>
            <td>Spec</td>
            <td>{st['count']}</td>
            <td>{html.escape(status_label)} · {html.escape(', '.join(st['tiers']))}</td>
            </tr>"""
        )

    return "\n".join(rows)


def render_nav_chips(data: dict[str, Any]) -> str:
    chips = []
    for cid in data["components"]:
        chips.append(
            f'<a class="nav-chip" data-portfolio-id="{html.escape(cid)}" href="#matrix">{html.escape(cid)}</a>'
        )
    for pid in data["protocols"]:
        chips.append(
            f'<a class="nav-chip protocol" data-portfolio-id="{html.escape(pid)}" href="#matrix">{html.escape(pid)}</a>'
        )
    return "\n".join(chips)


def generate_html(data: dict[str, Any]) -> str:
    status = coverage_stats = coverage_status(data)
    stats = curation_stats(data)
    by_cluster: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in data["entries"]:
        by_cluster[entry.get("cluster", "misc")].append(entry)

    sections = []
    for cluster in CLUSTER_ORDER:
        if cluster not in by_cluster:
            continue
        cards = "\n".join(render_entry_card(e) for e in by_cluster[cluster])
        sections.append(
            f"""
        <section class="cluster" id="cluster-{html.escape(cluster)}">
          <h2>{html.escape(cluster.replace('-', ' ').title())}</h2>
          <div class="cards">{cards}</div>
        </section>
        """
        )

    # Also dump any leftover clusters
    for cluster, entries in by_cluster.items():
        if cluster in CLUSTER_ORDER:
            continue
        cards = "\n".join(render_entry_card(e) for e in entries)
        sections.append(
            f"""
        <section class="cluster" id="cluster-{html.escape(cluster)}">
          <h2>{html.escape(cluster.replace('-', ' ').title())}</h2>
          <div class="cards">{cards}</div>
        </section>
        """
        )

    sub_only = ", ".join(stats["substitute_only_ids"]) or "none"
    uncovered = ", ".join(stats["uncovered_ids"]) or "none"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{html.escape(data['meta']['title'])}</title>
  <link rel="stylesheet" href="aumos-docs.css">
  <style>
    :root {{ --max-width: 1100px; }}
    body {{ max-width: none; }}
    .page {{ max-width: 1100px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }}
    .hero {{
      background: linear-gradient(135deg, #faf0eb 0%, #f5f3ef 55%, #eef3fa 100%);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 2rem;
      margin-bottom: 2rem;
    }}
    .hero p.lead {{ font-size: 1.1rem; color: var(--text-secondary); max-width: 70ch; }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 0.75rem;
      margin: 1.25rem 0 0;
    }}
    .stat {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.85rem 1rem;
    }}
    .stat .n {{ font-size: 1.6rem; font-weight: 700; color: var(--accent); font-family: var(--font-serif); }}
    .stat .l {{ font-size: 0.8rem; color: var(--text-tertiary); text-transform: uppercase; letter-spacing: 0.04em; }}
    .nav-map {{
      display: flex; flex-wrap: wrap; gap: 0.35rem;
      margin: 1rem 0 2rem;
    }}
    .nav-chip {{
      font-family: var(--font-mono); font-size: 0.75rem;
      padding: 0.2rem 0.5rem; border-radius: 999px;
      background: var(--bg-secondary); border: 1px solid var(--border);
      color: var(--text-primary); text-decoration: none;
    }}
    .nav-chip.protocol {{ background: var(--blue-light); border-color: #c5d4e8; }}
    .nav-chip:hover {{ border-color: var(--accent); color: var(--accent-hover); }}
    table.coverage {{
      width: 100%; border-collapse: collapse; font-size: 0.9rem;
      background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; overflow: hidden;
    }}
    table.coverage th, table.coverage td {{
      text-align: left; padding: 0.55rem 0.75rem; border-bottom: 1px solid var(--border);
    }}
    table.coverage th {{ background: var(--bg-secondary); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.03em; }}
    table.coverage tr.group-row td {{ background: var(--accent-subtle); font-family: var(--font-serif); }}
    table.coverage tr.ok td:last-child {{ color: var(--green); }}
    table.coverage tr.sub td:last-child {{ color: var(--amber); }}
    table.coverage tr.miss td:last-child {{ color: var(--red); font-weight: 600; }}
    .diagram {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 0.75rem;
      margin: 1.5rem 0;
    }}
    .plane {{
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1rem;
      background: var(--bg-card);
      min-height: 110px;
    }}
    .plane h3 {{ font-size: 0.95rem; margin: 0 0 0.5rem; border: none; padding: 0; }}
    .plane .ids {{ font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-secondary); line-height: 1.5; }}
    .cards {{ display: grid; gap: 1rem; }}
    .entry-card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.1rem 1.25rem;
    }}
    .entry-card h4 {{ margin: 0 0 0.4rem; font-size: 1.05rem; border: none; padding: 0; }}
    .entry-card h4 a {{ color: var(--text-primary); text-decoration: none; }}
    .entry-card h4 a:hover {{ color: var(--accent); }}
    .entry-card .meta {{ display: flex; flex-wrap: wrap; gap: 0.5rem 1rem; font-size: 0.85rem; color: var(--text-tertiary); margin-bottom: 0.6rem; }}
    .tier {{ font-size: 0.72rem; font-weight: 600; padding: 0.15rem 0.5rem; border-radius: 999px; }}
    .tier-canonical {{ background: var(--green-light); color: var(--green); }}
    .tier-secondary {{ background: var(--blue-light); color: var(--blue); }}
    .tier-gap {{ background: var(--amber-light); color: var(--amber); }}
    .map-chip {{
      font-family: var(--font-mono); font-size: 0.72rem;
      background: var(--accent-light); color: #8a3d24;
      padding: 0.1rem 0.4rem; border-radius: 4px; margin-right: 0.25rem;
    }}
    .tag {{
      font-size: 0.72rem; color: var(--text-tertiary);
      background: var(--bg-secondary); padding: 0.1rem 0.4rem; border-radius: 4px; margin-right: 0.25rem;
    }}
    .maps, .tags {{ margin-top: 0.55rem; }}
    .maps .label {{ font-size: 0.8rem; color: var(--text-tertiary); margin-right: 0.35rem; }}
    .why {{ color: var(--text-secondary); margin: 0.4rem 0; }}
    .gap-note {{ background: var(--amber-light); border-left: 3px solid var(--amber); padding: 0.5rem 0.75rem; font-size: 0.9rem; }}
    .url {{ font-size: 0.8rem; margin-top: 0.5rem; word-break: break-all; }}
    .toc a {{ color: var(--blue); }}
    .legend {{ display: flex; flex-wrap: wrap; gap: 1rem; font-size: 0.85rem; margin: 0.75rem 0 1rem; }}
    .legend span::before {{ content: ""; display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 0.35rem; }}
    .legend .l-ok::before {{ background: var(--green); }}
    .legend .l-sub::before {{ background: var(--amber); }}
    .legend .l-miss::before {{ background: var(--red); }}
    footer.page-foot {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--text-tertiary); font-size: 0.85rem; }}
    @media (max-width: 640px) {{
      .hero {{ padding: 1.25rem; }}
      table.coverage {{ display: block; overflow-x: auto; }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <header class="hero">
      <p style="font-size:0.85rem;color:var(--accent);font-weight:600;letter-spacing:0.04em;text-transform:uppercase;margin:0 0 0.5rem;">AumOS · Source Matrix · Local Deliverable</p>
      <h1>{html.escape(data['meta']['title'])}</h1>
      <p class="lead">Highest-quality primary standards, RFCs, vendor engineering blogs, and deep technical analyses mapped to every implementable component and every protocol in the AumOS portfolio. Depth over listicles. Visual coverage matrix + browsable cards.</p>
      <div class="stats">
        <div class="stat"><div class="n">{stats['total_entries']}</div><div class="l">Curated entries</div></div>
        <div class="stat"><div class="n">{stats['unique_domain_count']}</div><div class="l">Unique domains</div></div>
        <div class="stat"><div class="n">{stats['component_count']}</div><div class="l">Components</div></div>
        <div class="stat"><div class="n">{stats['protocol_count']}</div><div class="l">Protocols</div></div>
        <div class="stat"><div class="n">{stats['covered_ids']}</div><div class="l">IDs covered</div></div>
        <div class="stat"><div class="n">{stats['canonical_entries']}</div><div class="l">Canonical tier</div></div>
      </div>
    </header>

    <nav class="toc">
      <h2>Contents</h2>
      <ol>
        <li><a href="#portfolio-map">Portfolio visual map</a></li>
        <li><a href="#matrix">Coverage matrix (all IDs)</a></li>
        <li><a href="#legend-quality">Quality tiers &amp; doctrine</a></li>
        <li><a href="#clusters">Deep source clusters</a></li>
        <li><a href="#gaps">Explicit gaps &amp; substitutes</a></li>
      </ol>
    </nav>

    <section id="portfolio-map">
      <h2>Portfolio visual map</h2>
      <p>Navigable index of all <strong>{stats['component_count']} implementable component IDs</strong> from
      <code>00-reconciliation-matrix.md</code> tables (SSOT; broader than the vision-doc “44”
      summary figure) + <strong>{stats['protocol_count']} protocols (P1–P12)</strong>. Jump chips link to the coverage matrix.</p>
      <div class="diagram">
        <div class="plane"><h3>Trust / Identity</h3><div class="ids">T1 T2 · I1 I2</div></div>
        <div class="plane"><h3>Runtime</h3><div class="ids">R1–R8</div></div>
        <div class="plane"><h3>Confidential</h3><div class="ids">C1-1 … C1-5</div></div>
        <div class="plane"><h3>Supply chain</h3><div class="ids">S1–S9</div></div>
        <div class="plane"><h3>Eval / red-team</h3><div class="ids">A1–A8</div></div>
        <div class="plane"><h3>Inference</h3><div class="ids">N1–N4</div></div>
        <div class="plane"><h3>Federated / edge</h3><div class="ids">F1–F4</div></div>
        <div class="plane"><h3>Cross-cutting</h3><div class="ids">X1–X11</div></div>
        <div class="plane"><h3>Evidence</h3><div class="ids">E1</div></div>
        <div class="plane"><h3>Protocols</h3><div class="ids">P1–P12 · AAE AAR CPE AMIL SSP AATM ABS VEB AIX MADE PRB CAP</div></div>
      </div>
      <div class="nav-map" id="id-nav">
        {render_nav_chips(data)}
      </div>
    </section>

    <section id="legend-quality">
      <h2>Quality tiers &amp; research doctrine</h2>
      <ul>
        <li><strong>Canonical primary</strong> — standards bodies, RFCs, official project docs, first-party eng blogs that define the surface.</li>
        <li><strong>Deep secondary</strong> — rigorous security research, long-form technical analysis, conference/arXiv writeups that are definitive on a subtopic.</li>
        <li><strong>Adjacent / gap substitute</strong> — honest note when AumOS owns a novel composition; multi-source ecosystem anchors stand in until a public twin exists.</li>
      </ul>
      <p>{html.escape(data['meta']['doctrine'])}</p>
      <p>Portfolio truth files: <code>{html.escape(', '.join(data['meta']['portfolio_truth']))}</code>. Generated {html.escape(data['meta']['generated'])} · v{html.escape(data['meta']['version'])}.</p>
    </section>

    <section id="matrix">
      <h2>Coverage matrix</h2>
      <div class="legend">
        <span class="l-ok">Covered with primary/secondary depth</span>
        <span class="l-sub">Covered via adjacent substitutes / gap notes</span>
        <span class="l-miss">Missing (must be zero)</span>
      </div>
      <table class="coverage">
        <thead>
          <tr><th>ID</th><th>Name</th><th>Wave</th><th># sources</th><th>Status / tiers</th></tr>
        </thead>
        <tbody>
          {render_coverage_matrix(data, status)}
        </tbody>
      </table>
    </section>

    <section id="gaps">
      <h2>Explicit gaps &amp; substitutes</h2>
      <p><strong>Uncovered IDs (must be empty):</strong> {html.escape(uncovered)}</p>
      <p><strong>IDs relying only on adjacent substitutes:</strong> {html.escape(sub_only)}</p>
      <p>Notable thin public surfaces called out in entries: OpenShell/NOOA deep eng docs, IBM/Red Hat Lightwell long-form, and several AumOS-native protocol envelopes (AAE/AAR/AMIL/etc.) which are composed from SPIFFE + OAuth RAR/DPoP + Cedar + OTel + OCSF + Sigstore rather than a single existing public twin.</p>
    </section>

    <div id="clusters">
      <h2>Deep source clusters</h2>
      {''.join(sections)}
    </div>

    <footer class="page-foot">
      <p>Local in-repo deliverable for Project AumOS — Open Secure AI Alliance. Not a hosted artifact.
      Companion Markdown: <code>aumos/docs/curated-reading-list.md</code>. Data: <code>aumos/docs/source-matrix/curated-sources.json</code>.</p>
      <p>Unique domains: {html.escape(', '.join(stats['unique_domains']))}</p>
    </footer>
  </div>
</body>
</html>
"""


def generate_markdown(data: dict[str, Any]) -> str:
    status = coverage_status(data)
    stats = curation_stats(data)
    lines: list[str] = [
        f"# {data['meta']['title']}",
        "",
        f"> Generated {data['meta']['generated']} · v{data['meta']['version']}",
        "",
        data["meta"]["doctrine"],
        "",
        "## Stats",
        "",
        f"- Entries: **{stats['total_entries']}**",
        f"- Unique domains: **{stats['unique_domain_count']}**",
        f"- Components: **{stats['component_count']}** · Protocols: **{stats['protocol_count']}**",
        f"- IDs covered: **{stats['covered_ids']}** / {stats['component_count'] + stats['protocol_count']}",
        f"- Uncovered: {', '.join(stats['uncovered_ids']) or 'none'}",
        f"- Substitute-only: {', '.join(stats['substitute_only_ids']) or 'none'}",
        "",
        "## Coverage matrix",
        "",
        "| ID | Name | Sources | Status |",
        "|----|------|---------|--------|",
    ]
    for cid, meta in data["components"].items():
        st = status[cid]
        flag = "covered" if st["covered"] and not st["only_substitute"] else (
            "gap/substitute" if st["covered"] else "MISSING"
        )
        lines.append(
            f"| `{cid}` | `{meta['name']}` | {st['count']} | {flag} |"
        )
    for pid, meta in data["protocols"].items():
        st = status[pid]
        flag = "covered" if st["covered"] and not st["only_substitute"] else (
            "gap/substitute" if st["covered"] else "MISSING"
        )
        lines.append(
            f"| `{pid}` | `{meta['name']}` ({meta['spelled']}) | {st['count']} | {flag} |"
        )

    lines += ["", "## Entries", ""]
    for entry in data["entries"]:
        lines += [
            f"### {entry['title']}",
            "",
            f"- **Author/publisher:** {entry.get('author', '')}",
            f"- **URL:** {entry['url']}",
            f"- **Tier:** {entry.get('tier', '')}",
            f"- **Date/recency:** {entry.get('date', '')}",
            f"- **Maps to:** {', '.join(f'`{m}`' for m in entry.get('maps', []))}",
            f"- **Tags:** {', '.join(entry.get('tags', []))}",
            f"- **Why it matters:** {entry.get('why', '')}",
            "",
        ]
        if entry.get("note"):
            lines += [f"- **Note:** {entry['note']}", ""]
    return "\n".join(lines) + "\n"


def main() -> int:
    data = load_data()
    stats = curation_stats(data)
    if stats["uncovered_ids"]:
        print("ERROR: uncovered portfolio IDs:", stats["uncovered_ids"], file=sys.stderr)
        return 1
    HTML_OUT.parent.mkdir(parents=True, exist_ok=True)
    MD_OUT.parent.mkdir(parents=True, exist_ok=True)
    HTML_OUT.write_text(generate_html(data), encoding="utf-8")
    MD_OUT.write_text(generate_markdown(data), encoding="utf-8")
    print(f"Wrote {HTML_OUT}")
    print(f"Wrote {MD_OUT}")
    print(json.dumps({k: v for k, v in stats.items() if k != "unique_domains"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
