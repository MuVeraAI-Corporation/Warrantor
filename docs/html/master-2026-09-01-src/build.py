"""Assemble the Warrantor master blueprint from the shell and the part fragments.

Usage: python build.py [--out PATH]
Checks: fragment hygiene, unique ids, thead on every table, src anchors resolve,
figure tokens resolve, catalog item counts, word counts. Exits non-zero on hard failures.
"""
from __future__ import annotations

import argparse
import html as htmlmod
import json
import re
import sys
from collections import Counter, OrderedDict
from pathlib import Path

BASE = Path(__file__).resolve().parent
FRAG = BASE / "fragments"
FIGS = BASE / "figures"

PART_ORDER = [
    ("p00", "p00-verdict.html", "The verdict, and how to read this"),
    ("p01", "p01-what-happened.html", "What happened: ninety days, hop by hop"),
    ("p02", "p02-collective.html", "The collective, the deception, the response"),
    ("p03", "p03-why-controls-failed.html", "Why every control failed"),
    ("p04", "p04-discourse.html", "The discourse and the published estate"),
    ("p05", "p05-signals.html", "The class and the 2026 signal landscape"),
    ("p06", "p06-operating-system.html", "Why an operating system: kernel, syscalls, strata"),
    ("p07a", "p07a-catalog-l0-l3.html", "Master build catalog I · L0–L3"),
    ("p07b", "p07b-catalog-l4-l7.html", "Master build catalog II · L4–L7"),
    ("p07c", "p07c-catalog-l8-l11.html", "Master build catalog III · L8–L11"),
    ("p07d", "p07d-blueprint-index.html", "Master build catalog IV · blueprint control index"),
    ("p08", "p08-workflows-primitives.html", "Workflows, primitives, enterprise graph"),
    ("p09", "p09-prevention-crosswalk.html", "Prevention proof and crosswalks"),
    ("p10", "p10-value-model.html", "Exponential value model and scoreboard"),
    ("p11", "p11-sequencing.html", "Sequencing and current state"),
    ("p12", "p12-limits-unknowns.html", "Limits, unknowns, the honest answer"),
    ("p13", "p13-sources.html", "Sources and method"),
]

CATALOG_BAR = """
<div class="catalog-bar" id="catalog-bar">
  <div class="row">
    <input type="search" placeholder="Search the catalog: item, mechanism, anchor, source id…" aria-label="Search catalog">
    <select data-key="stratum" aria-label="Stratum"><option value="all">All strata</option>
      <option value="L0">L0 · Assurance</option><option value="L1">L1 · Root of trust</option><option value="L2">L2 · Isolation</option><option value="L3">L3 · Resource governor</option><option value="L4">L4 · Effect plane</option><option value="L5">L5 · Communication</option><option value="L6">L6 · Identity &amp; authority</option><option value="L7">L7 · Evidence</option><option value="L8">L8 · Human surface</option><option value="L9">L9 · Model intelligence</option><option value="L10">L10 · Federation</option><option value="L11">L11 · Change &amp; lifecycle</option></select>
    <select data-key="plane" aria-label="Blueprint plane"><option value="all">All planes</option>
      <option value="A">A · Evaluation &amp; lifecycle</option><option value="B">B · Agent kernel &amp; authority</option><option value="C">C · Communication &amp; memory</option><option value="D">D · Execution &amp; containment</option><option value="E">E · Egress &amp; credentials</option><option value="F">F · Evidence &amp; response</option><option value="G">G · Cross-org resilience</option><option value="H">H · Enterprise value</option></select>
    <select data-key="status" aria-label="Status"><option value="all">Any status</option><option value="built">built</option><option value="partial">partial</option><option value="none">none</option></select>
    <select data-key="novelty" aria-label="Novelty"><option value="all">Any novelty</option><option value="novel">novel</option><option value="core">core</option><option value="compose">compose</option><option value="consume">consume</option></select>
    <select data-key="wave" aria-label="Wave"><option value="all">Any wave</option><option value="W1">W1 · spine</option><option value="W2">W2 · value</option><option value="W3">W3 · expansion</option><option value="W4">W4 · long horizon</option></select>
    <button type="button" data-act="expand">Expand all</button>
    <button type="button" data-act="collapse">Collapse all</button>
    <button type="button" data-act="reset">Reset</button>
    <span class="count"></span>
  </div>
</div>
"""


def strip_dims(svg: str) -> str:
    """Remove width/height on the root svg so it scales with viewBox."""
    m = re.match(r"\s*<svg[^>]*>", svg)
    if not m:
        return svg
    root = m.group(0)
    root2 = re.sub(r'\s(width|height)="[^"]*"', "", root)
    if "preserveAspectRatio" not in root2:
        root2 = root2.replace("<svg", '<svg preserveAspectRatio="xMidYMid meet"', 1)
    return root2 + svg[m.end():]


def load_fragment(name: str) -> str | None:
    p = FRAG / name
    if not p.exists():
        return None
    return p.read_text(encoding="utf-8")


def text_of(fragment: str) -> str:
    t = re.sub(r"<svg.*?</svg>", " ", fragment, flags=re.S)
    t = re.sub(r"<[^>]+>", " ", t)
    return htmlmod.unescape(t)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(BASE / "out" / "warrantor-native-ai-platform-os-master-2026-09-01.html"))
    ap.add_argument("--allow-missing", action="store_true")
    args = ap.parse_args()

    shell = (BASE / "shell.html").read_text(encoding="utf-8")
    problems: list[str] = []
    warnings: list[str] = []
    parts_html: list[str] = []
    toc: list[str] = []
    report: OrderedDict[str, dict] = OrderedDict()
    all_ids: Counter = Counter()
    fig_used: Counter = Counter()

    for key, fname, label in PART_ORDER:
        frag = load_fragment(fname)
        if frag is None:
            msg = f"missing fragment {fname}"
            (warnings if args.allow_missing else problems).append(msg)
            continue
        # hygiene
        for bad in ("html", "head", "body", "style", "script", "link"):
            if re.search(r"<" + bad + r"[\s>]", frag, flags=re.I):
                problems.append(f"{fname}: contains forbidden tag <{bad}>")
        if not re.search(r'<section class="part"', frag):
            problems.append(f"{fname}: does not open with <section class=\"part\">")
        # figure tokens
        def repl(m: re.Match) -> str:
            nm = m.group(1)
            fp = FIGS / f"{nm}.svg"
            if not fp.exists():
                problems.append(f"{fname}: unknown figure token {nm}")
                return f"<!-- missing figure {nm} -->"
            fig_used[nm] += 1
            svg = fp.read_text(encoding="utf-8")
            svg = re.sub(r"^\s*<\?xml[^>]*\?>\s*", "", svg)
            return strip_dims(svg)
        frag = re.sub(r"\[\[svg:([a-z0-9\-]+)\]\]", repl, frag)
        # mark prebuilt figures for styling
        frag = re.sub(r'<figure class="fig wide">(\s*<svg[^>]*viewBox="0 0 1600)', r'<figure class="fig wide prebuilt">\1', frag)
        # ids
        ids = re.findall(r'\sid="([^"]+)"', frag)
        for i in ids:
            all_ids[i] += 1
        # tables
        tables = re.findall(r"<table[^>]*>(.*?)</table>", frag, flags=re.S)
        for t in tables:
            if "<thead" not in t:
                problems.append(f"{fname}: table without <thead>")
        # src anchors
        srcs = re.findall(r'href="#src-(S\d+)"', frag)
        # section ids from headings
        h3s = re.findall(r'<h3[^>]*id="([^"]+)"[^>]*>(.*?)</h3>', frag, flags=re.S)
        h2 = re.search(r"<h2[^>]*>(.*?)</h2>", frag, flags=re.S)
        sec_id = re.search(r'<section class="part" id="([^"]+)"', frag)
        items = re.findall(r'<article class="item"[^>]*id="([^"]+)"', frag)
        unsourced = re.findall(r"<!--\s*UNSOURCED:(.*?)-->", frag, flags=re.S)
        newsrc = re.findall(r"<!--\s*NEW-SOURCE:(.*?)-->", frag, flags=re.S)
        words = len(text_of(frag).split())
        svgs = len(re.findall(r"<svg", frag))
        report[key] = dict(file=fname, words=words, svgs=svgs, tables=len(tables), items=len(items),
                           srcs=len(srcs), unsourced=len(unsourced), newsrc=len(newsrc), h3=len(h3s))
        # catalog bar before first catalog fragment
        if key == "p07a":
            frag = frag.replace('</header>', '</header>\n' + CATALOG_BAR, 1)
        parts_html.append(frag)
        # toc
        title = htmlmod.unescape(re.sub(r"<[^>]+>", "", h2.group(1))).strip() if h2 else label
        num = key[1:3]
        sid = sec_id.group(1) if sec_id else f"part-{key[1:]}"
        if key in ("p07b", "p07c", "p07d"):
            toc.append(f'<a href="#{sid}"><span class="n"></span>{htmlmod.escape(title)}</a>')
        else:
            toc.append(f'<a href="#{sid}"><span class="n">{num}</span>{htmlmod.escape(title)}</a>')
        for hid, htxt in h3s:
            pass  # h3s not in TOC to keep it compact

    # TOC grouping
    groups = [("The record", ["p00", "p01", "p02", "p03", "p04", "p05"]), ("The platform", ["p06", "p07a", "p07b", "p07c", "p07d", "p08", "p09"]), ("The program", ["p10", "p11", "p12", "p13"])]
    toc_by_key = dict(zip([k for k, _, _ in PART_ORDER if k in report], toc))
    toc_html = ""
    for gname, keys in groups:
        toc_html += f'<div class="grp">{gname}</div>'
        for k in keys:
            if k in toc_by_key:
                toc_html += toc_by_key[k]

    dup = [i for i, c in all_ids.items() if c > 1]
    if dup:
        problems.append(f"duplicate ids: {dup[:20]}{'…' if len(dup) > 20 else ''}")
    multi_fig = [f for f, c in fig_used.items() if c > 1]
    if multi_fig:
        warnings.append(f"prebuilt figure used more than once: {multi_fig}")

    # src anchors must resolve
    body = "\n".join(parts_html)
    src_targets = set(re.findall(r'id="src-(S\d+)"', body))
    src_refs = Counter(re.findall(r'href="#src-(S\d+)"', body))
    missing = sorted(set(src_refs) - src_targets, key=lambda s: int(s[1:]))
    if missing:
        (warnings if args.allow_missing else problems).append(f"src refs with no ledger entry: {missing}")

    # strip banner
    total_words = sum(r["words"] for r in report.values())
    total_items = sum(r["items"] for r in report.values())
    total_svgs = sum(r["svgs"] for r in report.values())
    total_tables = sum(r["tables"] for r in report.values())
    strip = (
        f'<div class="cell"><div class="k">Depth</div><div class="v">{total_words:,} words</div><div class="d">across {len(report)} parts, {total_tables} tables and {total_svgs} figures</div></div>'
        f'<div class="cell"><div class="k">Build catalog</div><div class="v">{total_items} items</div><div class="d">twelve strata L0–L11, eight planes A–H, W1–W6 spine; nothing claimed to exist unless marked built</div></div>'
        f'<div class="cell"><div class="k">Evidence</div><div class="v">{len(src_targets)} sources</div><div class="d">{sum(src_refs.values()):,} inline citations, each tiered and linked</div></div>'
        f'<div class="cell"><div class="k">Discipline</div><div class="v">No "never again"</div><div class="d">unexpressible or independently denied · bounded blast radius · machine-speed halt · verifiable evidence</div></div>'
    )

    out = shell.replace("<!--TOC-->", toc_html).replace("<!--STRIP-->", strip).replace("<!--PARTS-->", body)
    outp = Path(args.out)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(out, encoding="utf-8")

    print(json.dumps(report, indent=1))
    print(f"TOTAL words={total_words:,} items={total_items} svgs={total_svgs} tables={total_tables} sources={len(src_targets)} citations={sum(src_refs.values())}")
    print(f"prebuilt figures used: {dict(fig_used)}")
    for w in warnings:
        print("WARN:", w)
    for p in problems:
        print("FAIL:", p)
    print(f"wrote {outp} ({outp.stat().st_size:,} bytes)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
