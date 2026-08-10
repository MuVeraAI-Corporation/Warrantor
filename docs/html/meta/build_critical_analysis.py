#!/usr/bin/env python3
"""Generate the AumOS Implementation & Protocol Critical Analysis (single self-contained HTML).

Deliverable: docs/html/aumos-critical-analysis-2026-08-09.html

This generator holds the audit dataset as structured Python and renders it. Regenerate with:
    python docs/html/meta/build_critical_analysis.py

Evidence tags used throughout:
    EXECUTED     - a command was run in this audit and the stated outcome observed
    READ         - established by reading source at the cited file:line
    EXTERNAL     - established against a primary external source (spec, RFC, regulator)
    INFERRED     - reasoned from the above; not directly observed
    UNVERIFIABLE - could not be established in this environment; reason stated
"""
from __future__ import annotations

import datetime as _dt
import html
import json
import pathlib
import re

OUT = pathlib.Path(__file__).resolve().parents[1] / "aumos-critical-analysis-2026-08-09.html"
AUDIT_DATE = "9 August 2026"
COMMIT = "4d122fea81382a7c50eb374ecfb08233f65dbffe"
BRANCH = "feature/pending-items-implementation"


def esc(text: str) -> str:
    return html.escape(str(text), quote=False)


def md(text: str) -> str:
    """Minimal inline markdown: `code`, **bold**, *em*, [txt](href)."""
    out = esc(text)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    out = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", out)
    out = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", out)
    out = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2" rel="noopener">\1</a>', out)
    return out


def para(text: str) -> str:
    return f"<p>{md(text)}</p>"


def bullets(items, cls: str = "") -> str:
    lis = "".join(f"<li>{md(i)}</li>" for i in items)
    c = f' class="{cls}"' if cls else ""
    return f"<ul{c}>{lis}</ul>"


def tag(kind: str) -> str:
    return f'<span class="tag tag-{kind.lower()}">{esc(kind)}</span>'


def grade_pill(g: str) -> str:
    slug = {"A": "a", "B": "b", "C": "c", "D": "d", "F": "f"}.get(g[0].upper(), "c")
    return f'<span class="grade grade-{slug}">{esc(g)}</span>'


FIXED: dict[str, str] = {
    "AX-02": "Ed25519 verification + keyId&rarr;issuer binding added; expiry&le;0 rejected; the "
             "substring approval check replaced with an approver set and quorum; all six dead "
             "constraints enforced. 33&rarr;50 tests.",
    "AX-03": "Conformance runner extended to the protocol lane: <strong>220/220 verifications</strong> "
             "(was 20/20), 200 protocol checks across all four languages.",
    "AX-04": "Markdown specs now generated from <code>registry.json</code>. <strong>12/12 mismatches "
             "&rarr; 0</strong>; dangling <code>proto/</code> and testvector references gone; drift "
             "gated by <code>make check-protocols</code>.",
    "AX-25": "Chart renders: <code>helm lint</code> clean, <strong>26 manifests</strong> produced. "
             "<code>list</code>&rarr;<code>dict</code>, plus a <code>--}}</code> parse error, nil "
             "<code>service</code> access and a leading-slash image ref. PDB template added.",
    "AX-26": "Go and TypeScript validators written; both <code>protocol-contracts</code> packages now "
             "compile and run all 40 vectors. Go modules 11&rarr;12; eslint clean.",
    "AX-27": "Fail-open branch deleted; a real <code>QuoteCollector</code> seam added. A non-mock "
             "backend with no verifier now raises instead of returning <code>verified=True</code>. "
             "8 regression tests.",
    "AX-37": "Catalogue integrity made bidirectional and blocking; 13 untracked directories catalogued "
             "as <code>support</code> entries. <strong>unclaimed: 13 &rarr; 0</strong>.",
    "AX-38": "All 34 <code>aumos/</code> path prefixes corrected across 7 workflows and dependabot; "
             "job-name counts fixed; a DCO check job added. Every workflow parses as YAML.",
    "AX-05": "<code>ExecutionEngine</code> trait added with a real <code>LocalProcessEngine</code> that "
             "SIGSTOPs/SIGKILLs an actual pid &mdash; proven by "
             "<code>local_process_engine_actually_kills_a_real_process_ax05</code>. "
             "<code>MockExecutionEngine</code> is never a default and stamps "
             "<code>simulated: true</code> on the outcome. <code>egress-filter</code> flipped to "
             "<strong>default-deny</strong>; trailing-dot, IPv4-mapped-IPv6 and malformed-config "
             "bypasses closed; <code>NaN</code> confidence no longer <em>refuses</em> the kill; "
             "operator authentication now required explicitly.",
    "AX-40": "Append-only <code>fsync</code>'d, hash-chained evidence store. <strong>I-07 enforced in "
             "the type system</strong>: <code>PendingAction</code> has no public constructor and "
             "<code>commit</code> consumes it by value, so the commit path is unreachable for an "
             "action whose evidence was never written. Revocation journalled &mdash; a restart no "
             "longer un-revokes. The <code>jti</code> defect closed, and the test that asserted it "
             "replaced. Restart tests actually drop and reopen the store.",
    "AX-39": "<code>docs/cross-cutting/21-threat-model.md</code> written: adversary model, trust "
             "boundaries, all eight self-compromise scenarios, explicit residual risk. "
             "<strong>I-11 now enforced in code</strong> with 6 tests.",
}


def fixed_pill(fid: str) -> str:
    """Render the remediation badge for a finding that has been closed."""
    if fid not in FIXED:
        return ""
    return ('<div class="good" style="margin-top:.9rem"><div class="calltitle">'
            'Fixed &mdash; 2026-08-09, branch <code>fix/critical-findings</code></div>'
            f'<p>{FIXED[fid]}</p></div>')


def sev_pill(s: str) -> str:
    return f'<span class="sev sev-{s.lower()}">{esc(s)}</span>'


CSS = r"""
:root{
  --bg:#faf9f7; --bg-2:#f5f3ef; --card:#fff; --code-bg:#1e1e2e;
  --fg:#1a1a1a; --fg-2:#525252; --fg-3:#737373; --fg-code:#c8c8d8;
  --accent:#d97757; --accent-h:#c4623d; --accent-lt:#f4e6df; --accent-sub:#faf0eb;
  --line:#e5e2dc; --line-2:#d1ccc3;
  --green:#3f6b3a; --green-bg:#edf5ed;
  --amber:#7a5405; --amber-bg:#fdf6e8;
  --red:#a32f29;   --red-bg:#fdf1ef;
  --blue:#385781;  --blue-bg:#eef3fa;
  --purple:#5d4682; --purple-bg:#f2eef8;
  --serif:'Iowan Old Style','Palatino Linotype',Palatino,Georgia,Charter,Cambria,serif;
  --sans:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',sans-serif;
  --mono:'JetBrains Mono','SF Mono',Menlo,Consolas,'Liberation Mono',monospace;
  --wrap:1180px; --measure:74ch; --r:10px;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#16151a; --bg-2:#1d1c22; --card:#201f26; --code-bg:#121118;
    --fg:#ece9e4; --fg-2:#b4afa8; --fg-3:#8b867f; --fg-code:#d3d0e0;
    --accent:#e59176; --accent-h:#f0a68e; --accent-lt:#3a2a24; --accent-sub:#2a2220;
    --line:#312f38; --line-2:#413e4a;
    --green:#8fc088; --green-bg:#1f2b1e;
    --amber:#dcb265; --amber-bg:#2e2718;
    --red:#e58a80;   --red-bg:#31201e;
    --blue:#8fb0e0;  --blue-bg:#1c242f;
    --purple:#b9a3dd; --purple-bg:#252030;
  }
}
:root[data-theme="dark"]{
  --bg:#16151a; --bg-2:#1d1c22; --card:#201f26; --code-bg:#121118;
  --fg:#ece9e4; --fg-2:#b4afa8; --fg-3:#8b867f; --fg-code:#d3d0e0;
  --accent:#e59176; --accent-h:#f0a68e; --accent-lt:#3a2a24; --accent-sub:#2a2220;
  --line:#312f38; --line-2:#413e4a;
  --green:#8fc088; --green-bg:#1f2b1e; --amber:#dcb265; --amber-bg:#2e2718;
  --red:#e58a80; --red-bg:#31201e; --blue:#8fb0e0; --blue-bg:#1c242f;
  --purple:#b9a3dd; --purple-bg:#252030;
}
:root[data-theme="light"]{
  --bg:#faf9f7; --bg-2:#f5f3ef; --card:#fff; --code-bg:#1e1e2e;
  --fg:#1a1a1a; --fg-2:#525252; --fg-3:#737373; --fg-code:#c8c8d8;
  --accent:#d97757; --accent-h:#c4623d; --accent-lt:#f4e6df; --accent-sub:#faf0eb;
  --line:#e5e2dc; --line-2:#d1ccc3;
  --green:#3f6b3a; --green-bg:#edf5ed; --amber:#7a5405; --amber-bg:#fdf6e8;
  --red:#a32f29; --red-bg:#fdf1ef; --blue:#385781; --blue-bg:#eef3fa;
  --purple:#5d4682; --purple-bg:#f2eef8;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth;scroll-padding-top:1.5rem}
body{font-family:var(--sans);background:var(--bg);color:var(--fg);line-height:1.68;font-size:16.5px;
  -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
h1,h2,h3,h4{font-family:var(--serif);font-weight:600;line-height:1.25;letter-spacing:-.012em}
h1{font-size:2.45rem;margin-bottom:.6rem}
h2{font-size:1.72rem;margin:0 0 .9rem}
h3{font-size:1.22rem;margin:2rem 0 .6rem}
h4{font-size:1.03rem;margin:1.4rem 0 .45rem;font-family:var(--sans);font-weight:650;letter-spacing:0}
p{margin:0 0 .85rem;max-width:var(--measure)}
ul,ol{margin:0 0 .9rem 1.15rem;max-width:var(--measure)}
li{margin-bottom:.3rem}
a{color:var(--accent);text-decoration:none;border-bottom:1px solid transparent}
a:hover{color:var(--accent-h);border-bottom-color:currentColor}
code{font-family:var(--mono);font-size:.855em;background:var(--bg-2);padding:.11em .38em;
  border-radius:4px;border:1px solid var(--line);word-break:break-word}
pre{background:var(--code-bg);color:var(--fg-code);padding:1rem 1.15rem;border-radius:var(--r);
  overflow-x:auto;margin:0 0 1rem;font-size:.83rem;line-height:1.6;border:1px solid var(--line)}
pre code{background:none;border:none;padding:0;color:inherit;font-size:1em}
hr{border:none;border-top:1px solid var(--line);margin:2.2rem 0}

/* ---- shell ---- */
.shell{display:grid;grid-template-columns:290px minmax(0,1fr);gap:0;max-width:var(--wrap);margin:0 auto}
.side{position:sticky;top:0;height:100vh;overflow-y:auto;padding:1.6rem 1.1rem 3rem;
  border-right:1px solid var(--line);font-size:.83rem;background:var(--bg)}
.side::-webkit-scrollbar{width:7px}
.side::-webkit-scrollbar-thumb{background:var(--line-2);border-radius:4px}
.side .brand{font-family:var(--serif);font-size:1.02rem;font-weight:600;margin-bottom:.15rem;line-height:1.3}
.side .brandsub{color:var(--fg-3);font-size:.73rem;margin-bottom:1.1rem;letter-spacing:.02em}
.side nav a{display:block;padding:.29rem .6rem;color:var(--fg-2);border-radius:6px;
  border:none;line-height:1.38;border-left:2px solid transparent}
.side nav a:hover{background:var(--bg-2);color:var(--fg)}
.side nav a.on{color:var(--accent);background:var(--accent-sub);border-left-color:var(--accent);font-weight:550}
.side nav .grp{margin:.95rem 0 .3rem;padding-left:.6rem;font-size:.68rem;text-transform:uppercase;
  letter-spacing:.1em;color:var(--fg-3);font-weight:650}
.main{padding:2.4rem 2.6rem 6rem;min-width:0}
.prog{position:fixed;top:0;left:0;height:2px;background:var(--accent);z-index:99;width:0;transition:width .08s linear}
.tools{position:fixed;top:.9rem;right:1.1rem;z-index:100;display:flex;gap:.4rem}
.tools button{font-family:var(--sans);font-size:.74rem;padding:.36rem .68rem;border-radius:20px;
  border:1px solid var(--line-2);background:var(--card);color:var(--fg-2);cursor:pointer;line-height:1}
.tools button:hover{border-color:var(--accent);color:var(--accent)}

/* ---- section ---- */
section{margin-bottom:3.6rem;scroll-margin-top:1.2rem}
.eyebrow{font-size:.69rem;letter-spacing:.15em;text-transform:uppercase;color:var(--accent);
  font-weight:700;margin-bottom:.4rem}
.lede{font-size:1.07rem;color:var(--fg-2);max-width:var(--measure);margin-bottom:1.4rem}

/* ---- cards / callouts ---- */
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:1.15rem 1.3rem;margin:0 0 1.1rem}
.note{border-left:3px solid var(--accent);background:var(--accent-sub);padding:.9rem 1.15rem;
  border-radius:0 8px 8px 0;margin:0 0 1.1rem}
.warn{border-left:3px solid var(--amber);background:var(--amber-bg);padding:.9rem 1.15rem;border-radius:0 8px 8px 0;margin:0 0 1.1rem}
.danger{border-left:3px solid var(--red);background:var(--red-bg);padding:.9rem 1.15rem;border-radius:0 8px 8px 0;margin:0 0 1.1rem}
.good{border-left:3px solid var(--green);background:var(--green-bg);padding:.9rem 1.15rem;border-radius:0 8px 8px 0;margin:0 0 1.1rem}
.note p:last-child,.warn p:last-child,.danger p:last-child,.good p:last-child,.card p:last-child{margin-bottom:0}
.calltitle{font-weight:700;font-size:.78rem;letter-spacing:.07em;text-transform:uppercase;margin-bottom:.4rem}
.note .calltitle{color:var(--accent)} .warn .calltitle{color:var(--amber)}
.danger .calltitle{color:var(--red)} .good .calltitle{color:var(--green)}

/* ---- pills ---- */
.tag{display:inline-block;font-family:var(--mono);font-size:.63rem;letter-spacing:.06em;
  padding:.14em .48em;border-radius:4px;border:1px solid;vertical-align:middle;white-space:nowrap}
.tag-executed{color:var(--green);border-color:var(--green);background:var(--green-bg)}
.tag-read{color:var(--blue);border-color:var(--blue);background:var(--blue-bg)}
.tag-external{color:var(--purple);border-color:var(--purple);background:var(--purple-bg)}
.tag-inferred{color:var(--amber);border-color:var(--amber);background:var(--amber-bg)}
.tag-unverifiable{color:var(--fg-2);border-color:var(--line-2);background:var(--bg-2)}
.sev{display:inline-block;font-size:.66rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase;
  padding:.16em .55em;border-radius:4px;white-space:nowrap}
.sev-critical{background:var(--red);color:#fff}
.sev-high{background:var(--amber);color:#fff}
.sev-medium{background:var(--blue);color:#fff}
.sev-low{background:var(--bg-2);color:var(--fg-2);border:1px solid var(--line-2)}
.grade{display:inline-flex;align-items:center;justify-content:center;min-width:2.3rem;height:1.55rem;
  border-radius:5px;font-family:var(--mono);font-size:.78rem;font-weight:700;padding:0 .35rem}
.grade-a{background:var(--green-bg);color:var(--green);border:1px solid var(--green)}
.grade-b{background:var(--blue-bg);color:var(--blue);border:1px solid var(--blue)}
.grade-c{background:var(--amber-bg);color:var(--amber);border:1px solid var(--amber)}
.grade-d{background:var(--red-bg);color:var(--red);border:1px solid var(--red)}
.grade-f{background:var(--red);color:#fff;border:1px solid var(--red)}
/* Dark theme inverts the solid-fill pills: the palette's dark-mode reds/ambers are light
   pastels, so white-on-pastel drops to ~2:1. Use a near-black foreground instead. */
@media (prefers-color-scheme: dark){
  .sev-critical,.sev-high,.sev-medium,.grade-f{color:#16151a}
}
:root[data-theme="dark"] .sev-critical,:root[data-theme="dark"] .sev-high,
:root[data-theme="dark"] .sev-medium,:root[data-theme="dark"] .grade-f{color:#16151a}
:root[data-theme="light"] .sev-critical,:root[data-theme="light"] .sev-high,
:root[data-theme="light"] .sev-medium,:root[data-theme="light"] .grade-f{color:#fff}

/* ---- tables ---- */
.tw{overflow-x:auto;margin:0 0 1.2rem;border:1px solid var(--line);border-radius:var(--r);background:var(--card)}
table{border-collapse:collapse;width:100%;font-size:.845rem}
th{text-align:left;padding:.62rem .8rem;background:var(--bg-2);color:var(--fg-2);font-weight:650;
  font-size:.72rem;letter-spacing:.05em;text-transform:uppercase;border-bottom:1px solid var(--line);
  position:sticky;top:0;white-space:nowrap}
td{padding:.6rem .8rem;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--bg-2)}
th.sortable{cursor:pointer;user-select:none}
th.sortable:hover{color:var(--accent)}
th.sortable::after{content:'\2195';opacity:.32;margin-left:.3em;font-size:.9em}

/* ---- filter bar ---- */
.filters{display:flex;flex-wrap:wrap;gap:.45rem;align-items:center;margin:0 0 .85rem}
.filters input[type=search]{font-family:var(--sans);font-size:.82rem;padding:.42rem .75rem;border-radius:20px;
  border:1px solid var(--line-2);background:var(--card);color:var(--fg);min-width:230px;flex:1 1 230px}
.filters input[type=search]:focus{outline:none;border-color:var(--accent)}
.chip{font-size:.74rem;padding:.32rem .68rem;border-radius:20px;border:1px solid var(--line-2);
  background:var(--card);color:var(--fg-2);cursor:pointer;line-height:1;white-space:nowrap;font-family:var(--sans)}
.chip:hover{border-color:var(--accent);color:var(--accent)}
.chip.on{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600}
.count{font-size:.76rem;color:var(--fg-3);margin-left:auto;white-space:nowrap}

/* ---- dossier ---- */
details.dos{border:1px solid var(--line);border-radius:var(--r);margin:0 0 .55rem;background:var(--card);overflow:hidden}
details.dos[open]{border-color:var(--line-2)}
details.dos>summary{cursor:pointer;padding:.72rem .95rem;display:grid;
  grid-template-columns:3.4rem 1fr auto auto;gap:.7rem;align-items:center;list-style:none;font-size:.88rem}
details.dos>summary::-webkit-details-marker{display:none}
details.dos>summary:hover{background:var(--bg-2)}
details.dos[open]>summary{border-bottom:1px solid var(--line);background:var(--bg-2)}
.dos .did{font-family:var(--mono);font-size:.76rem;color:var(--accent);font-weight:700}
.dos .dname{font-weight:600}
.dos .dpath{font-family:var(--mono);font-size:.7rem;color:var(--fg-3);display:block;font-weight:400;margin-top:.1rem}
.dos .body{padding:1.05rem 1.15rem 1.2rem}
.dos .body h4:first-child{margin-top:0}
.kv{display:grid;grid-template-columns:auto 1fr;gap:.28rem .85rem;font-size:.83rem;margin:0 0 1rem}
.kv dt{color:var(--fg-3);font-size:.71rem;text-transform:uppercase;letter-spacing:.06em;
  font-weight:650;padding-top:.16rem;white-space:nowrap}
.kv dd{margin:0}

/* ---- scorecard ---- */
.score{display:grid;grid-template-columns:repeat(auto-fit,minmax(148px,1fr));gap:.7rem;margin:0 0 1.3rem}
.sc{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:.85rem .9rem}
.sc .lbl{font-size:.7rem;text-transform:uppercase;letter-spacing:.07em;color:var(--fg-3);
  font-weight:650;margin-bottom:.42rem;line-height:1.3}
.sc .val{display:flex;align-items:center;gap:.5rem}
.sc .cmt{font-size:.75rem;color:var(--fg-2);margin-top:.42rem;line-height:1.45}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(128px,1fr));gap:.7rem;margin:0 0 1.4rem}
.st{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:.85rem .9rem;text-align:center}
.st .n{font-family:var(--serif);font-size:1.72rem;font-weight:600;color:var(--accent);line-height:1.1}
.st .l{font-size:.71rem;color:var(--fg-3);text-transform:uppercase;letter-spacing:.06em;
  margin-top:.28rem;font-weight:650;line-height:1.3}

/* ---- misc ---- */
.hero{border-bottom:1px solid var(--line);padding-bottom:1.8rem;margin-bottom:2.6rem}
.meta{display:flex;flex-wrap:wrap;gap:.35rem .9rem;font-size:.79rem;color:var(--fg-3);margin-top:1rem}
.meta span{white-space:nowrap}
.verdictbox{background:var(--card);border:2px solid var(--accent);border-radius:var(--r);
  padding:1.35rem 1.5rem;margin:0 0 1.5rem}
.verdictbox .vlbl{font-size:.7rem;letter-spacing:.14em;text-transform:uppercase;color:var(--accent);
  font-weight:700;margin-bottom:.55rem}
.verdictbox .vtxt{font-family:var(--serif);font-size:1.2rem;line-height:1.52;max-width:66ch}
.annex{border:2px dashed var(--red);border-radius:var(--r);padding:1.2rem 1.35rem;background:var(--red-bg);margin:0 0 1.3rem}
.annex .alabel{font-size:.71rem;letter-spacing:.12em;text-transform:uppercase;color:var(--red);
  font-weight:700;margin-bottom:.55rem}
.fp{font-family:var(--mono);font-size:.76rem;color:var(--fg-2);word-break:break-all}
.two{display:grid;grid-template-columns:repeat(auto-fit,minmax(290px,1fr));gap:1rem;margin-bottom:1.1rem}
.two p,.two ul{max-width:none}
.card p,.note p,.warn p,.danger p,.good p,.dos .body p{max-width:none}

@media (max-width:1000px){
  .shell{grid-template-columns:1fr}
  .side{position:static;height:auto;border-right:none;border-bottom:1px solid var(--line);padding-bottom:1rem}
  .side nav{column-count:2;column-gap:1rem}
  .main{padding:1.6rem 1.15rem 4rem}
  details.dos>summary{grid-template-columns:3rem 1fr;row-gap:.3rem}
}
@media print{
  .side,.tools,.prog,.filters{display:none!important}
  .shell{display:block;max-width:none}
  .main{padding:0}
  body{font-size:10.5pt;background:#fff;color:#000}
  details.dos{break-inside:avoid;border-color:#bbb}
  details.dos>summary{background:#f4f4f4}
  section{break-before:auto;margin-bottom:1.4rem}
  pre{white-space:pre-wrap;word-break:break-word;background:#f6f6f6;color:#111;border:1px solid #ccc}
  a{color:#000;border:none}
  .verdictbox,.annex{break-inside:avoid}
}
"""

JS = r"""
(function(){
  // theme toggle
  var root=document.documentElement, tbtn=document.getElementById('themeBtn');
  tbtn && tbtn.addEventListener('click',function(){
    var cur=root.getAttribute('data-theme');
    if(!cur){cur=window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';}
    root.setAttribute('data-theme',cur==='dark'?'light':'dark');
  });
  // expand / collapse all
  var ebtn=document.getElementById('expandBtn');
  ebtn && ebtn.addEventListener('click',function(){
    var ds=document.querySelectorAll('details.dos'), any=false;
    ds.forEach(function(d){ if(!d.open) any=true; });
    ds.forEach(function(d){ d.open=any; });
    ebtn.textContent = any ? 'Collapse all' : 'Expand all';
  });
  // Print/PDF must contain the substance, not 100 collapsed summaries. Open every dossier
  // (and un-hide any filtered-out rows) before printing, then restore the reading state.
  var printState=null;
  window.addEventListener('beforeprint',function(){
    var ds=[].slice.call(document.querySelectorAll('details.dos'));
    var hidden=[].slice.call(document.querySelectorAll('[data-facets]')).filter(function(e){
      return e.style.display==='none'; });
    printState={open:ds.map(function(d){return d.open;}),hidden:hidden};
    ds.forEach(function(d){ d.open=true; });
    hidden.forEach(function(e){ e.style.display=''; });
  });
  window.addEventListener('afterprint',function(){
    if(!printState) return;
    var ds=[].slice.call(document.querySelectorAll('details.dos'));
    ds.forEach(function(d,i){ d.open=printState.open[i]; });
    printState.hidden.forEach(function(e){ e.style.display='none'; });
    printState=null;
  });
  // reading progress
  var bar=document.getElementById('prog');
  function onScroll(){
    var h=document.documentElement.scrollHeight-window.innerHeight;
    if(bar) bar.style.width = (h>0 ? (window.scrollY/h*100) : 0)+'%';
  }
  window.addEventListener('scroll',onScroll,{passive:true}); onScroll();
  // active nav
  var links=[].slice.call(document.querySelectorAll('.side nav a[href^="#"]'));
  var secs=links.map(function(a){return document.getElementById(a.getAttribute('href').slice(1));});
  var obs=new IntersectionObserver(function(es){
    es.forEach(function(e){
      if(!e.isIntersecting) return;
      links.forEach(function(l){l.classList.remove('on');});
      var i=secs.indexOf(e.target);
      if(i>=0) links[i].classList.add('on');
    });
  },{rootMargin:'-8% 0px -80% 0px',threshold:0});
  secs.forEach(function(s){ if(s) obs.observe(s); });

  // ---- filterable collections ----
  document.querySelectorAll('[data-filter-scope]').forEach(function(scope){
    var q=scope.querySelector('input[type=search]');
    var chips=[].slice.call(scope.querySelectorAll('.chip'));
    var items=[].slice.call(scope.querySelectorAll('[data-facets]'));
    var counter=scope.querySelector('.count');
    var active={};
    function apply(){
      var term=(q&&q.value||'').toLowerCase().trim();
      var shown=0;
      items.forEach(function(it){
        var facets=(it.getAttribute('data-facets')||'').toLowerCase();
        var text=(it.getAttribute('data-text')||it.textContent||'').toLowerCase();
        var ok=true;
        for(var g in active){
          if(active[g] && facets.indexOf(g+':'+active[g])<0){ ok=false; break; }
        }
        if(ok && term && text.indexOf(term)<0) ok=false;
        it.style.display = ok ? '' : 'none';
        if(ok) shown++;
      });
      if(counter) counter.textContent = shown+' of '+items.length+' shown';
    }
    chips.forEach(function(c){
      c.addEventListener('click',function(){
        var g=c.getAttribute('data-group'), v=c.getAttribute('data-val');
        if(active[g]===v){ active[g]=null; c.classList.remove('on'); }
        else{
          chips.forEach(function(o){ if(o.getAttribute('data-group')===g) o.classList.remove('on'); });
          active[g]=v; c.classList.add('on');
        }
        apply();
      });
    });
    q && q.addEventListener('input',apply);
    apply();
  });

  // ---- sortable tables ----
  document.querySelectorAll('table[data-sortable]').forEach(function(tb){
    tb.querySelectorAll('th').forEach(function(th,idx){
      th.classList.add('sortable');
      th.setAttribute('tabindex','0');
      th.setAttribute('role','columnheader');
      th.setAttribute('aria-sort','none');
      var dir=1;
      th.addEventListener('keydown',function(e){
        if(e.key==='Enter'||e.key===' '){ e.preventDefault(); th.click(); }
      });
      th.addEventListener('click',function(){
        tb.querySelectorAll('th').forEach(function(o){ o.setAttribute('aria-sort','none'); });
        th.setAttribute('aria-sort', dir===1?'ascending':'descending');
        var body=tb.tBodies[0];
        var rows=[].slice.call(body.rows);
        rows.sort(function(a,b){
          var x=(a.cells[idx].getAttribute('data-sort')||a.cells[idx].textContent).trim();
          var y=(b.cells[idx].getAttribute('data-sort')||b.cells[idx].textContent).trim();
          var nx=parseFloat(x), ny=parseFloat(y);
          if(!isNaN(nx)&&!isNaN(ny)) return (nx-ny)*dir;
          return x.localeCompare(y)*dir;
        });
        rows.forEach(function(r){ body.appendChild(r); });
        dir=-dir;
      });
    });
  });
})();
"""

# ===========================================================================
# PROTOCOL DOSSIERS  (P1-P12)
# ===========================================================================
# grade: A real+sound | B sound spec, thin proof | C material defects
#        D preempted or broken | F not what it claims
PROTOCOLS = [
    dict(
        pid="P1", slug="aae", name="Agent Authority Envelope", grade="C-",
        purpose="Bound, revocable authority for one agent subject.",
        rule="P1_APPROVAL_FOR_CONSEQUENTIAL_ACTION",
        artefacts="md + cddl + schema.json + 7 vectors (the only protocol with adversarial envelope vectors)",
        claim="Signed, task-specific delegation: who may act, for whom, on what, with which budget, until when, "
              "with which approvals — revocable, and enforced everywhere.",
        reality=[
            "The **normative layer contradicts itself**. `specs/protocols/P1-aae.md:27` lists mandatory fields "
            "`spend_budget, time_budget, token_budget, geography, expiry`. `registry.json` requires `budget` (a 7-field "
            "object), `geographies` (array), `expires_at`. Neither name set is a superset of the other. [EXECUTED]",
            "`P1-aae.md:24` says the normative schema lives at `proto/aumos/protocols/v1/aae.proto`. **That file does "
            "not exist** — `proto/` contains only `aar.proto`, `report.proto`, `agent.proto`, `signing.proto`. [EXECUTED]",
            "The TypeScript gateway implemented the **markdown** field names (`spendBudget`, `timeBudgetSeconds`, "
            "`geography`, `expiry`) — so the divergence is not hypothetical, it already produced an incompatible "
            "implementation. [READ]",
            "`mcp-gateway/src/index.ts:526` accepts the envelope as a **plain caller-supplied object with no signature "
            "field**. No Ed25519 verification, no issuer trust check, no revocation check. A forged envelope from "
            "`spiffe://evil.example` authorised a `destructive`-class tool. [READ]",
            "Six declared constraints — `spendBudget`, `timeBudgetSeconds`, `tokenBudget`, `geography`, "
            "`delegationDepth`, `dataClasses` — plus `revocationHandle` are declared, typed, documented and **never "
            "read** by any enforcement path. [READ]",
            "`authority-spec` (Rust) enforces expiry, side-effect class, approvals and delegation depth — but **not** "
            "budget ceilings, geographies, data classes or revocation. [READ]",
            "**Revocation does not exist.** `authority-spec/src/lib.rs:25` defers it to component I1; there is no I1 "
            "crate in the Rust workspace. `revocation_handle` is signed, regex-validated, and never consulted. [READ]",
            "**No replay defence.** `nonce` and `message_id` are required fields whose only purpose is replay "
            "protection. No nonce cache and no message-id uniqueness store exists anywhere in the repo. [READ]",
        ],
        external="**Contested and closing fast.** `draft-ietf-oauth-transaction-tokens-11` entered IETF WG Last Call on "
                 "2026-07-30 — a signed, short-lived, per-call, explicitly non-escalating authority token. OIDF AuthZEN "
                 "**AARP** and **COAZ** (a profile for MCP tool authorization specifically) were approved as WG drafts "
                 "2026-06-15. And **Microsoft Entra Agent ID is GA with a feature it literally calls an "
                 "“access envelope”.** AWS AgentCore Policy is GA in 13 regions doing Cedar-based tool-call "
                 "interception. [EXTERNAL]",
        verdict="The best-specified idea in the portfolio and the worst-executed. The schema is genuinely good; the "
                "enforcement is absent in TypeScript, partial in Rust, and the two normative documents disagree. "
                "Externally, a GA Microsoft feature already uses the same name for the same concept.",
    ),
    dict(
        pid="P2", slug="aar", name="Agent Action Receipt", grade="D",
        purpose="Precommit and final tamper-evident action evidence.",
        rule="P2_PHASE_OUTCOME_CONSISTENCY",
        artefacts="md + cddl + 3 vectors; the only protocol with a real `.proto`",
        claim="Every consequential action produces a signed, tamper-evident receipt, written durably BEFORE the action "
              "commits (invariant I-07), anchored in a transparency log.",
        reality=[
            "**Zero receipt binding in TypeScript.** `mcp-gateway` emits no receipts at all. `aumos-mcp-server` exposes "
            "`aumos_emit_receipt` as *a tool the agent may choose to call*. I-07 is enforced by asking the agent "
            "nicely — the agent being the entity the system exists to constrain. [READ]",
            "`flight-recorder` — the Rust evidence crate — has **no persistence whatsoever**. Its own stated invariant "
            "I-07 (“durable BEFORE commit”) is disclaimed in a comment at `lib.rs:331`. [READ]",
            "`flight-recorder/src/lib.rs:351` **hardcodes** `PolicyDecision { engine: \"opa\", decision: \"allow\", "
            "policy_hash_hex: \"\", matched_rules: [] }` into every receipt and signs it. No policy engine was "
            "consulted. That fabricated value is exported to OCSF as the `policy` field — the exact record a compliance "
            "reviewer would rely on most. [READ]",
            "The Rekor anchoring that every protocol spec promises is **non-functional**: the entry type is misspelled "
            "`hashedrekor` (correct: `hashedrekord`) and a unit test asserts the misspelling; the digest is base64 "
            "where Rekor requires hex; the default transport is plaintext TCP against an HTTPS-only endpoint; and "
            "`verify_entry` merely checks the server echoed back the log index the client already had. [READ]",
            "Receipts are signed by **the agent's own runtime** — the logger is the logged.",
        ],
        external="**Severely preempted — this is the existential one.** **RFC 9942 (COSE Receipts)** and **RFC 9943 "
                 "(SCITT Architecture)** were published as Standards-Track RFCs in **June 2026**. The word "
                 "“Receipt” is now defined in the RFC series. `draft-noa-scitt-ai-agent-receipt-00` "
                 "(2026-06-23) already applies SCITT to AI-agent action receipts with hash-chained `COSE_Sign1` "
                 "statements recording what the agent did, which principal authorised it and what policy governed it. "
                 "Separately, Claude Managed Agents ship an append-only event log stored **outside** the container. "
                 "[EXTERNAL]",
        verdict="A published RFC pair already owns this ground, an individual I-D already applies it to agents, and the "
                "AumOS implementation fabricates the policy field, never persists, and never reaches a real "
                "transparency log. P2 must become a SCITT/COSE profile or be withdrawn.",
    ),
    dict(
        pid="P3", slug="cpe", name="Context Provenance Envelope", grade="B-",
        purpose="Purpose-bound provenance through retrieval and transformation.",
        rule="P3_PURPOSE_AND_PROVENANCE_CONSISTENCY",
        artefacts="md + cddl + schema + 3 vectors",
        claim="Every piece of context carries its source, consent state, sensitivity, taints, allowed uses and full "
              "transformation chain.",
        reality=[
            "Markdown/registry field split as with every protocol: md says `acquisition_time, allowed_use, confidence, "
            "integrity, taint`; registry requires `acquired_at, allowed_uses, confidence_micros, content_digest, "
            "taints`. [EXECUTED]",
            "`confidence_micros` as a bounded integer (0..1_000_000) is a genuinely good design choice — it sidesteps "
            "float canonicalisation entirely, which is the single hardest part of RFC 8785. [READ]",
            "No runtime binds CPE to an actual retrieval path. There is no RAG adapter, no retriever middleware, no "
            "vector-store integration. The envelope is defined and unproduced. [READ]",
        ],
        external="**Genuine whitespace, and the best regulatory fit in the portfolio.** C2PA 2.4 (April 2026) covers "
                 "media and, via the collection data hash assertion, training datasets — but nothing covers "
                 "per-retrieval runtime context with consent, taint and allowed-use. `consent` / `sensitivity` / "
                 "`allowed_uses` / `derived_from` map unusually cleanly onto **India's DPDP purpose-limitation and "
                 "consent-manager regime** (Rules in force 14 May 2027). AumOS claims this nowhere. [EXTERNAL]",
        verdict="Under-claimed rather than over-claimed. The schema is sound, the design decisions are deliberate, and "
                "the regulatory fit is the strongest of any protocol here. It is simply not wired to anything that "
                "retrieves context.",
    ),
    dict(
        pid="P4", slug="amil", name="Agent Memory Integrity Ledger", grade="B-",
        purpose="Hash-linked memory records with poisoning quarantine semantics.",
        rule="P4_CHAIN_AND_QUARANTINE_CONSISTENCY",
        artefacts="md + cddl + schema + 3 vectors",
        claim="Agent memory is an append-only hash-linked ledger with contradiction links, quarantine states, "
              "supersession, retention limits and consent revocation.",
        reality=[
            "Schema is coherent and the quarantine state machine (`clean` / `quarantined` / `resolved`) is well-formed. "
            "[READ]",
            "No memory store implements it. There is no adapter for any vector database, agent-memory framework or "
            "conversation store in the repo. [READ]",
            "`retention_until` and `consent_revoked` are the right fields for a privacy regime, and nothing enforces "
            "them. [READ]",
        ],
        external="**Genuinely empty ground — no open-source project addresses agent-memory integrity at all.** Cisco AI "
                 "Defense *detects* memory-poisoning attempts; nobody makes memory verifiable. OWASP ranks it ASI06 in "
                 "the 2026 Agentic Top 10. **Caveat worth stating plainly:** an empty slot in a hot market often means "
                 "nobody is buying rather than nobody thought of it. [EXTERNAL]",
        verdict="Real whitespace with unproven demand. Cheapest genuine differentiation available, but validate that "
                "anyone will pay before building the ledger.",
    ),
    dict(
        pid="P5", slug="ssp", name="Secure Skill Package", grade="C",
        purpose="Content-addressed, permission-scoped, revocable skill distribution.",
        rule="P5_PERMISSION_AND_REVOCATION_CONSISTENCY",
        artefacts="md + cddl + schema + 3 vectors",
        claim="Skills ship content-addressed, permission-scoped, publisher-signed, with an AI-SBOM and evaluation "
              "bundle attached, and are revocable.",
        reality=[
            "Schema references `ai_sbom` and `evaluation_bundle` as `ArtifactReference`s — correct composition, and the "
            "cleanest cross-protocol linkage in the set. [READ]",
            "No packaging tool, no registry, no installer, no revocation service exists. [READ]",
            "`runtime` enum (`wasm`/`python`/`node`/`container`) is not connected to `sandbox-runtime`, despite that "
            "crate being the one component that could actually enforce it. [READ]",
        ],
        external="**The one place the MCP ecosystem has left a real hole.** The MCP spec finalised 2026-07-28 "
                 "explicitly lacks server signing, tool integrity, capability attenuation and registry trust; the "
                 "official MCP Registry is still PREVIEW with GitHub-OAuth/DNS namespace verification only — no "
                 "signing, no attestation. **But** the Agentic AI Foundation governs MCP with AWS, Anthropic, Google, "
                 "Microsoft, OpenAI and Cloudflare as platinum sponsors, and closing this hole is on their roadmap. "
                 "Sigstore + OCI 1.1 referrers is the obvious substrate. [EXTERNAL]",
        verdict="Correct problem, correct shape, and a closing window. This should be an MCP extension proposed into "
                "AAIF, not a twelfth AumOS protocol.",
    ),
    dict(
        pid="P6", slug="aatm", name="AI Artifact Trust Manifest", grade="D+",
        purpose="Exact identity and provenance for the complete AI artifact graph.",
        rule="P6_REQUIRED_ROLES_AND_UNIQUE_ARTIFACTS",
        artefacts="md + cddl + schema + 3 vectors",
        claim="One signed manifest binding model, dataset, tokenizer, prompt, adapter, container, policy, skill and "
              "evaluation into a single verifiable graph.",
        reality=[
            "The binding-graph idea is the genuinely novel part and the schema expresses it well (`artifacts` minItems "
            "2, `roles` minItems 2, `root_digest`). [READ]",
            "`model-sbom` emits **CycloneDX 1.5** with `\"type\": \"library\"` and model metadata stuffed into ad-hoc "
            "`properties` key/value pairs. CycloneDX has had `\"type\": \"machine-learning-model\"` and a structured "
            "`modelCard` **since 1.5** — so this is not version drift, it is **not an ML-BOM in any version**. [READ]",
            "The SPDX output sets `\"spdxVersion\": \"SPDX-3.0\"` but emits the SPDX 2.3 JSON shape (top-level "
            "`packages` + `relationships` + `SPDXID`). SPDX 3.0.1 mandates JSON-LD with an `@context`. It uses neither "
            "the AI Profile nor the Dataset Profile. [READ]",
        ],
        external="**Fully covered.** `sigstore/model-transparency` is the OpenSSF project (v1.0, Apr 2025) with NVIDIA "
                 "NGC and Google Kaggle adopting, and **CycloneDX 1.7 became ECMA-424, an international standard, in "
                 "December 2025**. SPDX 3.0.1 ships AI and Dataset profiles. CoSAI published “Signing ML "
                 "Artifacts”. Competing with an Ecma standard is not a plan. [EXTERNAL]",
        verdict="The residual idea — one signed graph binding all nine artifact roles — is real. Everything else is "
                "reinvention, and the implementation does not emit a valid ML-BOM in any specification version. Express "
                "P6 as an in-toto predicate over CycloneDX/SPDX subjects.",
    ),
    dict(
        pid="P7", slug="abs", name="Autonomy Budget Specification", grade="C+",
        purpose="Machine-enforceable ceilings for autonomous execution.",
        rule="P7_RISK_REQUIRES_APPROVAL",
        artefacts="md + cddl + schema + 3 vectors",
        claim="Machine-enforceable ceilings on steps, wall-clock, tokens, money, external calls, data volume and "
              "irreversible actions, with replenishment policy and risk-gated approval.",
        reality=[
            "The 7-field `Budget` object is well-designed, all-integer (`money_minor`, not floats) and reused "
            "consistently across P1, P7 and P10. This is the best type in the registry. [READ]",
            "**Nothing enforces a budget anywhere in the codebase.** Budgets are signed, validated against schema, "
            "carried through delegation attenuation checks — and never decremented, metered or checked against actual "
            "consumption by any runtime. [READ]",
            "The TypeScript gateway flattened the 7-field budget to 3 and silently dropped `steps`, `external_calls`, "
            "`data_bytes` and `irreversible_actions`. [READ]",
        ],
        external="**Closing fast.** **AWS Dogwood** — an open-source temporal extension to Cedar with `count_within` "
                 "and `sum_within` operators that evaluate prior tool calls in a session — shipped inside GA AgentCore "
                 "Policy, blogged **2026-08-06, three days before this audit**. That is an autonomy budget expressed as "
                 "a policy language. LiteLLM has per-key/team budgets at 56k stars. ServiceNow shipped kill switches "
                 "and circuit breakers in May 2026. [EXTERNAL]",
        verdict="Good type design, zero enforcement, and AWS shipped the enforcement three days ago. The `Budget` "
                "object is worth keeping as a vocabulary; the protocol is not worth defending.",
    ),
    dict(
        pid="P8", slug="veb", name="Verifiable Evaluation Bundle", grade="B+",
        purpose="Reproducible evaluation evidence bound to exact inputs.",
        rule="P8_ASSERTION_COUNTS_MATCH",
        artefacts="md + cddl + schema + 3 vectors",
        claim="An eval result signed and bound to the exact corpus, environment, model, harness, policy, seeds, traces "
              "and judge that produced it.",
        reality=[
            "**The best-specified protocol in the set.** Every input that determines an eval outcome is pinned as an "
            "`ArtifactReference` with a digest — including `judge`, which nothing else in the industry pins. [READ]",
            "`P8_ASSERTION_COUNTS_MATCH` is a real cross-field invariant, not a shape check. [READ]",
            "No runtime produces a VEB. `eval-guard` — the crate nominally responsible — attests to boundary checks "
            "that are **function arguments**, and its CLI hardcodes `CheckResults::all_pass()` then signs it with a "
            "freshly generated throwaway key. [READ]",
            "It is sequenced in Wave 6, behind `metr-bridge` — i.e. the strongest differentiator is gated behind an "
            "integration with an evaluator that has since moved to Inspect. [READ]",
        ],
        external="**Nobody has preempted this. It is the single strongest claim in the portfolio.** promptfoo (24.1k "
                 "stars, used by OpenAI and Anthropic), Inspect (UK AISI, 0.3.255 released 2026-08-09), HELM and "
                 "lm-eval-harness all market *reproducibility*; none emit a signed or independently verifiable bundle, "
                 "and none pin the grader. METR retired Vivaria for Hawk, which is built on Inspect. **NIST AI 800-2 "
                 "(ipd, 2026-01-30) enumerates exactly what belongs in such a bundle, names grader gaming as a live "
                 "threat, says an interoperable schema “may improve clarity and ease of replication” — "
                 "and names no candidate.** [EXTERNAL]",
        verdict="Move this to Wave 1. It is the only protocol where AumOS is ahead of the field rather than behind it, "
                "the regulatory pull is explicit and dated, and the shortest credible path is a DSSE/in-toto envelope "
                "over an Inspect `.eval` digest — build on Inspect, do not compete with it.",
    ),
    dict(
        pid="P9", slug="aix", name="Agent Incident Exchange", grade="D",
        purpose="Normalized, attributable agent-security incident exchange.",
        rule="P9_INCIDENT_TIMELINE_CONSISTENCY",
        artefacts="md + cddl + schema + 3 vectors",
        claim="A normalized, attributable exchange format for agent-security incidents, grounded in OCSF and MITRE "
              "ATLAS.",
        reality=[
            "The schema **requires** `ocsf_class_uid` but validates it as `{\"type\":\"integer\",\"minimum\":1}` — "
            "**any positive integer passes**. The protocol's entire claim to OCSF grounding is unenforced. [READ]",
            "The Python implementation hardcodes `OCSF_CLASS_UID = 3003` with `OCSF_CATEGORY_UID = 3` commented as "
            "“Application Security”. In OCSF, **3003 is Authorize Session** in the Identity & Access "
            "Management category. It is not an incident class, and category 3 is not Application Security. [READ]",
            "`OCSF_VERSION` is pinned to **1.1.0**; current is **1.9.0** (2026-08-03) — eight minor versions. [READ]",
            "The ATLAS mapping uses only the 2023-era technique set (T0019/T0020/T0037/T0043/T0048/T0050/T0051). "
            "`TOOL_ABUSE` does not map to **AML.T0098** (AI Agent Tool Credential Harvesting) and `EXFILTRATION` does "
            "not map to **AML.T0086** (Exfiltration via AI Agent Tool Invocation). The regex format is current; the "
            "curated content is three years stale. [READ / EXTERNAL]",
            "The six incident types map almost 1:1 onto OWASP ASI01/02/03/06/10 without citing them. [EXTERNAL]",
        ],
        external="**Severely preempted, and by six days.** **OCSF 1.9.0 (2026-08-03)** added the `ai_agent` object, "
                 "AI messages, `delegation` and `message_context` (including MCP) to the `ai_operation` profile, "
                 "applicable across 40+ classes. CoSAI published **AI Incident Response Framework V1.0**. CSA is now a "
                 "CVE Numbering Authority. [EXTERNAL]",
        verdict="The weakest protocol. It claims OCSF grounding it does not validate, maps to an OCSF class that means "
                "something else entirely, pins an eight-version-old schema, and OCSF shipped native agent objects six "
                "days before this audit. There is no answer to “what does P9 carry that an OCSF 1.9 event plus a "
                "DSSE signature does not?”",
    ),
    dict(
        pid="P10", slug="made", name="Multi-Agent Delegation Exchange", grade="C-",
        purpose="Explicitly attenuated, attributable delegation between agents.",
        rule="P10_DELEGATION_MUST_ATTENUATE",
        artefacts="md + cddl + schema + 3 vectors",
        claim="Delegation between agents must strictly attenuate authority; chains are attributable and depth-bounded.",
        reality=[
            "`P10_DELEGATION_MUST_ATTENUATE` is the most valuable invariant in the whole registry — monotonic "
            "narrowing is exactly the right rule. [READ]",
            "**Rust and Python disagree on how to check it.** Rust's `budget_attenuates` compares exactly 7 named "
            "fields; Python iterates generically over parent keys. Add a field to `Budget` and Python enforces it while "
            "Rust silently does not. Two authoritative implementations, divergent semantics. [READ]",
            "No delegation runtime exists. Nothing issues, accepts, or revokes a delegation. [READ]",
        ],
        external="**Heavily preempted at the mechanism layer.** RFC 8693's nested `act` claim has expressed delegation "
                 "chains since **January 2020**; `draft-ietf-oauth-identity-chaining-17` is IESG-approved and at the "
                 "RFC Editor; **Okta/Auth0 Cross App Access reaches customers this month**; A2A v1.0 owns the "
                 "agent-to-agent wire with signed Agent Cards and 150+ orgs; CSA specified OAuth 2.1 `actor_token` "
                 "chains with JIT attenuation in Aug 2025; and **Biscuit** (Eclipse) solved offline attenuation years "
                 "ago with better cryptography than macaroons. [EXTERNAL]",
        verdict="The right invariant, expressed as the wrong artifact. Contributing attenuation semantics to Biscuit "
                "(stale since 2025-10-21) or proposing a token-exchange profile would achieve more than a competing "
                "wire format.",
    ),
    dict(
        pid="P11", slug="prb", name="Proof-Carrying Remediation Bundle", grade="B",
        purpose="Content-addressed remediation with reproduction and regression proof.",
        rule="P11_EMBARGO_AND_EVIDENCE_CONSISTENCY",
        artefacts="md + cddl + schema + 3 vectors",
        claim="A remediation ships with its reproducer, root cause, patch, tests, regression evidence and build "
              "provenance — under embargo until coordinated disclosure.",
        reality=[
            "Most fields are a composition of existing in-toto predicates (`VULNS`, `Test Result`, `SVR`, `Release`, "
            "SLSA Provenance). [EXTERNAL]",
            "**`embargo_until` + `disclosure_status` is the genuinely novel primitive** — attesting that a fix exists "
            "and was regression-tested *without disclosing the vulnerability* is unsolved anywhere I could find. [EXTERNAL]",
            "No implementation. Nothing produces or consumes a PRB. [READ]",
        ],
        external="Nothing comparable found in any standards body, vendor product or OSS project. **Also: no evidence "
                 "that anyone is asking for it.** [EXTERNAL]",
        verdict="Genuinely novel and genuinely unvalidated. Treat as a research bet, not a roadmap commitment — novelty "
                "with no demonstrated demand is not a moat.",
    ),
    dict(
        pid="P12", slug="cap", name="Capability Attestation Profile", grade="C+",
        purpose="Evidence-bound declaration of runtime capabilities and enforcement.",
        rule="P12_RUNTIME_AND_NETWORK_BOUNDARY",
        artefacts="md + cddl + schema + 3 vectors",
        claim="A signed, evidence-bound statement of what a runtime actually is: sandbox type, memory isolation, "
              "network policy, model identity, attestation evidence.",
        reality=[
            "Couples `sandbox`, `memory_isolation` and `NetworkPolicy` (with `egress_default` defaulting to `deny`) "
            "into one signed statement — architecturally the right shape. [READ]",
            "`attestation_evidence` is an `ArtifactReference`. The only thing that could produce it — `nvtrust-bridge` "
            "— has exactly one backend, `MockBackend`, whose verification is "
            "`report.attestation_bytes == b\"aumos-mock-attestation\"`, with no FFI, no `nvtrust` and no NRAS client in "
            "its dependencies. `#![forbid(unsafe_code)]` makes the required FFI structurally impossible. [EXECUTED]",
            "`confidential-fabric` never parses a quote, never checks a cert chain, never verifies a signature; its "
            "“attestation” is SHA-256 of the struct you handed it compared to a field inside that same "
            "struct. [READ]",
        ],
        external="**Primitives are commoditised and free; composition is a real but closing gap.** NVIDIA NRAS issues "
                 "signed EAT tokens (Apache-2.0); Intel Trust Authority is GA and free on Azure, GCP and IBM Cloud; "
                 "RFC 9334 (RATS) and RFC 9711 (EAT) are the standards. **But no open library composes CPU quote + "
                 "multi-GPU EAT + container measurement + model-weight hash + serving-stack version into one policy "
                 "verdict** — eight attested-inference providers, eight incompatible verifiers. CoRIM is still "
                 "`draft-ietf-rats-corim-11`. Veraison, CoCo Trustee and Google's GA Prompt Encryption SDK are all "
                 "racing for this slot: **~12-month half-life.** [EXTERNAL]",
        verdict="AumOS's second-strongest claim — but only *above* the attestation primitives, never at them. "
                "`nvtrust-bridge` is pure reinvention; composite AI-aware attestation policy is not. The signed "
                "counterpart to MCP's self-admittedly untrusted `ToolAnnotations` is the defensible framing.",
    ),
]

# ===========================================================================
# GAP / FINDING REGISTER
# blocks: integrate | deploy | trust | scale | claim
# effort: S | M | L | XL
# ===========================================================================
FINDINGS = [
    dict(
        fid="AX-01", sev="High", title="Latent universal signature forgery in the trusted core",
        area="Trust core", blocks="trust", gate="G3 Correctness · G10 Security assurance", effort="S",
        evidence="EXECUTED",
        where="`rust/trust-core/src/canonical.rs:67`",
        what="`serde_cbor::from_slice(&serde_cbor::to_vec(value)?).unwrap_or(CborValue::Null)`. The serde_cbor "
             "*deserializer* has a hard 128-level recursion limit; the *serializer* has none. Any payload nested "
             "≥127 deep fails to round-trip and `unwrap_or` silently substitutes CBOR `null`, so `canonical_cbor` "
             "returns `Ok([0xf6])` — one byte — for every such input.",
        scenario="I signed `{side_effect_class:\"read\", money_minor:0, irreversible_actions:0}` at nesting depth 127 "
                 "and verified the resulting signature against "
                 "`{side_effect_class:\"destructive\", money_minor:100000000, irreversible_actions:9999}`. "
                 "**Both verified `true`.** The depth-1 control correctly returned `false`.",
        blast="**Scoped honestly: this is a latent defect, not a currently-reachable exploit.** I traced every caller. "
              "The P1&ndash;P12 protocol path is *unaffected* &mdash; `protocol-contracts` signs with "
              "`serde_json::to_vec`, and `serde_json` hits the **same 127-level recursion limit but propagates a "
              "proper `Err`** (verified: `recursion limit exceeded at line 1 column 645`). `authority-spec` uses its "
              "own canonicalizer. The `trust-core` CLI calls `ed25519_dalek::SigningKey::sign()` on raw stdin bytes, "
              "bypassing `canonical_cbor` entirely. And `gguf-ext`, `sandbox-runtime` and `secure-workspace` all pass "
              "bounded-depth structs. **I could not identify a currently-reachable exploit path.** "
              "What makes it Critical anyway is that it sits in the public `sign`/`verify` API of the crate the README "
              "designates *“the single authoritative implementation of every security invariant”*, it is silent, and "
              "it goes live the moment anyone signs a map with user-influenced nesting &mdash; a receipt's "
              "`extensions`, a context envelope's provenance metadata, a skill manifest. Note that "
              "`extensions` is `{\"type\":\"object\",\"additionalProperties\":true}`, so arbitrary nesting is "
              "schema-valid. The doc comment two lines above reads *\"Fails closed on any error.\"* "
              "**And the bitter irony: the blast radius is contained today only because the repository violates its "
              "own single-authority rule (AX-08). Fix AX-08 by routing everything through `trust-core` as the README "
              "demands, and this becomes universal.** The correct sequencing is therefore AX-01 before AX-08, never "
              "the reverse.",
        fix="Replace `serde_cbor` (unmaintained since 2021, RUSTSEC-2021-0127) with `ciborium`, which implements RFC "
            "8949 deterministic encoding properly. Make the canonicalizer return `Err` on any decode failure — never a "
            "default. Add an explicit depth bound with a typed error. Add a differential fuzz target asserting "
            "`canonical(a) == canonical(b) ⟺ a == b` rather than the current \"does not panic\" target.",
        accept="A test that signs at depths 1, 126, 127, 128, 1000 and asserts cross-payload verification **fails** at "
               "every depth; `cargo audit` clean of RUSTSEC-2021-0127.",
    ),
    dict(
        fid="AX-02", sev="Critical", title="The MCP gateway never verifies the authority it enforces",
        area="Developer surface", blocks="trust", gate="G5 Fail-closed controls", effort="M",
        evidence="READ",
        where="`typescript/mcp-gateway/src/index.ts:526`",
        what="`authorize(call, aae)` takes the Agent Authority Envelope as a **plain caller-supplied object**. The "
             "TypeScript type has no `signature` field at all. There is no Ed25519 verification, no issuer trust "
             "check, no revocation check, and no call to any identity service.",
        scenario="A fabricated envelope with `issuer: \"spiffe://evil.example/i-made-this-up\"` and no signature "
                 "authorised a `destructive`-class tool call, which was then forwarded. The envelope is self-asserted, "
                 "so any caller simply declares its own permissions.",
        blast="Defeats P1 entirely at the one place a developer actually integrates. Compounded by `expiry: 0` "
              "disabling expiry (`index.ts:534`) — which the test fixture itself ships (`index.test.ts:59`, "
              "`expiry: 0, // 0 = no expiry enforcement`) — and by the I-08 approval check being "
              "`approvals.some(a => a.includes(scope.toolSvid))`, a substring match of an *approver* string against "
              "the *tool's* SVID.",
        fix="Add `signature` to the envelope type and verify it against a trust bundle before any policy evaluation. "
            "Treat `expiry <= 0` as invalid, not as \"disabled\". Replace the `.includes()` approval check with "
            "verification of approver signatures over the request digest. Enforce or delete the six dead constraints "
            "(`spendBudget`, `tokenBudget`, `timeBudgetSeconds`, `geography`, `delegationDepth`, `dataClasses`).",
        accept="Tests proving a forged envelope, an expired envelope, an `expiry: 0` envelope and a wrong-approver "
               "envelope are each **denied**; every registry-required field enforced.",
    ),
    dict(
        fid="AX-03", sev="High",
        title="Protocol conformance covers 2 of the 4 languages the project claims parity for",
        area="Assurance", blocks="claim", gate="G4 Protocol conformance", effort="M",
        evidence="EXECUTED",
        where="`tools/conformance/run.py:24`, `specs/protocols/P*.md:52`",
        what="**This finding was substantially reframed after adversarial review, and the correction is worth stating "
             "plainly.** My first draft called this a false gate. It is not. `tools/conformance/run.py` hardcodes "
             "`testvectors/T1` and reports `vectors: 5` → `PASS — 20/20 verifications`, and every surface discloses "
             "that scope honestly: the Makefile target says *“vector matrix”*, the CI job is named "
             "*“Cross-language conformance (20 checks)”* (5 &times; 4 languages, arithmetic it prints in full), and "
             "`testvectors/README.md:51` states outright — *“Current implemented scope: five T1 vectors… The other "
             "directories shown in the target layout remain pending and **must not be inferred from this T1 "
             "result**.”* That is a model disclosure and it deserves credit.",
        scenario="The real defect is narrower and still material. The 40 protocol vectors **do** execute — in "
                 "`rust/protocol-contracts/tests/vectors.rs` (which asserts all 40 and their exact error codes; I ran "
                 "it: `every_protocol_vector_matches_the_expected_outcome ... ok`) and in the Python validator. They "
                 "do **not** execute in Go or TypeScript, and they are **never compared across languages**. So a "
                 "project whose value proposition is that independent implementations interoperate proves conformance "
                 "in **2 of the 4 languages it claims parity for** — and the two that are missing are exactly the two "
                 "whose `protocol-contracts` packages do not compile at all (AX-26).",
        blast="Where the documentation *does* over-claim is the protocol prose, not the runner: every "
              "`specs/protocols/P*.md:52` asserts *“Conformance is enforced by A6 (the cross-language conformance "
              "suite) against every language implementation that consumes the protocol”* and points at "
              "`testvectors/P1/` &mdash; **a directory that does not exist**. That sentence is false in all twelve "
              "files. Two CI job labels are also simply wrong: *“Python (34 projects)”* against 35 discovered and "
              "*“Go (10 modules)”* against 11 &mdash; a miscount signals that discovery and reporting have drifted "
              "apart. And per AX-38 none of these jobs has ever executed.",
        fix="Extend the runner to load `testvectors/protocols/manifest.json` and execute all 40 vectors in all four "
            "languages, comparing outcome **and** error code against `errors.json`. Ship the missing Python/Go/TS "
            "validators. Fail the run if any language is absent rather than silently narrowing scope.",
        accept="`run.py` reports 40 × 4 = 160 protocol verifications plus the 20 T1 verifications, with per-language "
               "error-code agreement.",
    ),
    dict(
        fid="AX-04", sev="Critical", title="Two normative documents disagree for all twelve protocols",
        area="Normative layer", blocks="integrate", gate="G4 Protocol conformance", effort="M",
        evidence="EXECUTED",
        where="`specs/protocols/P*-*.md` vs `specs/protocols/registry.json`",
        what="Every protocol's Markdown spec carries a \"Mandatory fields\" block that disagrees with the machine-"
             "readable registry. **12 of 12 mismatch.** P1's prose requires `spend_budget, time_budget, token_budget, "
             "geography, expiry`; the registry requires `budget, geographies, expires_at`. P2's prose requires "
             "`authority_hash, tool_or_api_op, context_commitment, deterministic_checks, approver`; the registry "
             "requires `authority_digest, operation, context_digest, checks, approvers, phase, parent_receipt`.",
        scenario="This is not theoretical. The TypeScript gateway implemented the **Markdown** names — `spendBudget`, "
                 "`timeBudgetSeconds`, `geography`, `expiry` — producing an implementation incompatible with the "
                 "registry, with the 7-field `Budget` flattened to 3 and four fields silently dropped. An independent "
                 "implementer reading the prose builds the wrong protocol.",
        blast="Root cause of the single largest class of implementation divergence in the repository. Also: the prose "
              "points at `proto/aumos/protocols/v1/aae.proto`, which does not exist, and at `testvectors/P1/`, which "
              "does not exist.",
        fix="Declare `registry.json` + the JSON Schemas canonical and **generate** the Markdown from them, as the "
            "CDDL already is. Delete the hand-written mandatory-field blocks. Fix the dangling schema and vector "
            "paths. Add a CI check that fails if prose and registry diverge.",
        accept="A CI job that regenerates all 12 `.md` from the registry and fails on any diff; zero broken internal "
               "references.",
    ),
    dict(
        fid="AX-05", sev="Critical", title="Containment controls do not contain",
        area="Runtime", blocks="trust", gate="G9 Containment", effort="XL",
        evidence="EXECUTED",
        where="`rust/kill-switch/src/lib.rs:174`",
        what="The entire execution layer is a literal vector of strings — `[\"suspend_model\", \"unload_gpu_memory\", "
             "\"kill_pod\", \"isolate_network_namespace\", \"wipe_transient_memory\"]` — followed by `Ok`. The source "
             "comment says so: *\"Wave-1 mock execution: record the canonical 5 actions without actually doing them.\"* "
             "A grep for `Command|signal|kube|libc|process::` returns **0**.",
        scenario="An operator triggers the kill switch during an incident. The CLI exits 0 and reports success. "
                 "Nothing was suspended, unloaded, killed, isolated or wiped. The `<5s budget` test asserts "
                 "`actions_taken.len() == 6`.",
        blast="Same pattern in `egress-filter` (\"eBPF egress enforcement\" with zero eBPF dependencies, a 4-entry "
              "`Vec<String>` suffix match in userspace, **default-allow**) and `exfil-guard` (real detector algorithms, "
              "zero enforcement, and nothing in the repo calls `evaluate`).",
        fix="Introduce an `ExecutionEngine` trait with real backends (process signals, Kubernetes API, cgroup freezer, "
            "network namespace) and make the mock an explicitly-named test double. Flip `egress-filter` to "
            "default-deny. Until then, regrade all three in `catalog.json` from `reference_implementation` to "
            "`mock_only` — **the code is honest; the catalog is not.**",
        accept="An integration test that starts a real workload, triggers the kill switch, and asserts the process is "
               "gone and the namespace isolated.",
    ),
    dict(
        fid="AX-06", sev="High", title="Confidential-compute attestation is entirely simulated",
        area="Confidential compute", blocks="trust", gate="G10 Security assurance", effort="XL",
        evidence="EXECUTED",
        where="`rust/nvtrust-bridge/src/lib.rs:150`, `rust/confidential-fabric/src/lib.rs:177`",
        what="`nvtrust-bridge` has exactly one backend, `MockBackend`. Its verification is "
             "`report.attestation_bytes == b\"aumos-mock-attestation\"`. There is no `extern \"C\"`, no `bindgen`, no "
             "`links=`, no feature flag, and no NRAS HTTP client in `Cargo.toml`; `#![forbid(unsafe_code)]` makes the "
             "required FFI structurally impossible. `confidential-fabric` never parses a quote, never validates a cert "
             "chain and never verifies a signature — its \"attestation\" is SHA-256 of the struct you passed in, "
             "compared to a field inside that same struct.",
        scenario="Any deployment claiming attested GPU inference is attesting nothing. `confidential-fabric`'s default "
                 "`KeyReleasePolicy` sets every constraint empty and the code documents that empty means "
                 "*do not check* — **the default policy releases keys to any attestation under ten minutes old**, and "
                 "a test asserts this as correct behaviour.",
        blast="Directly contradicts the confidential-compute pillar, which is one of the project's four headline "
              "differentiators.",
        fix="Either bind real NVIDIA nvTrust/NRAS and verify EAT tokens with cert-chain validation and measurement "
            "comparison against pinned reference values, or delete the components and consume NVIDIA's Apache-2.0 "
            "verifier and Intel Trust Authority directly. Make the default `KeyReleasePolicy` deny-all.",
        accept="Verification of a real, externally-produced attestation token, with a negative test using a token from "
               "a different platform.",
    ),
    dict(
        fid="AX-07", sev="High", title="Five verifiers self-verify while four sibling components do it correctly",
        area="Supply chain", blocks="trust", gate="G11 Supply-chain verification", effort="M",
        evidence="READ",
        where="`provena-chain/src/lib.rs:371`, `safe-tensors-pp/src/lib.rs:210`, `gguf-ext/src/profile.rs:525`, "
              "`eval-guard/src/lib.rs:202`, `flight-recorder/src/lib.rs:396`",
        what="Every signature-verifying crate reads the public key **out of the artifact it is verifying**. None of the "
             "five public `verify` APIs accepts an expected key, a trust bundle, or an allowed-signer list.",
        scenario="Re-sign a poisoned model with your own freshly generated keypair. `gguf-ext verify` prints "
                 "`\"ok\": true` and exits 0. The signature is valid; it just says nothing about who signed.",
        blast="This is an **inconsistency, not ignorance** — a correction from adversarial review. Four sibling "
              "components in the same workspace already take the anchor from the caller and get it right: "
              "`protocol-contracts` (`ProtocolValidator::new(&registry, keyring)`, unknown key → `UnknownKey`), "
              "`sandbox-runtime` and `secure-workspace` (`TrustCorePolicyVerifier::new(verifying_key)`), and "
              "`authority-spec` (`ValidateOptions::issuer_verifying_key`). So the pattern is understood; five crates "
              "simply do not follow it. What is genuinely absent is anywhere to defer to: a search across `docs/`, "
              "`docs/rfcs/` and `docs/cross-cutting/` for a trust-anchor, keyring or key-distribution design returns "
              "**nothing**. `gguf-ext`'s `VerifyPolicy` carries limits, clock skew and max age but **no allowed-key "
              "set**, so a caller could not supply an anchor even if it wanted to.",
        fix="Add a required `expected_signer` / trust-bundle parameter to every verify API. Resolve `key_id` against "
            "the claimed `issuer` (currently unbound — any key in the keyring signs for any agent). Switch "
            "`ed25519_dalek::verify` to `verify_strict` (currently **zero** uses repo-wide) to reject small-order and "
            "non-canonical signatures.",
        accept="Negative tests where a correctly-formed signature from an untrusted key is rejected by all five crates.",
    ),
    dict(
        fid="AX-08", sev="High", title="Three incompatible canonicalizations inside a single-authority repo",
        area="Trust core", blocks="trust", gate="G4 Protocol conformance", effort="M",
        evidence="EXECUTED",
        where="`trust-core/src/canonical.rs:64`, `authority-spec/src/lib.rs:204`, "
              "`protocol-contracts/src/validation.rs:468`",
        what="`trust-core` does CBOR via a `Value` round-trip; `authority-spec` calls `serde_cbor::to_vec` directly on "
             "a `serde_json::Value` and **does not depend on trust-core at all**; `protocol-contracts` uses "
             "`serde_json::to_vec` with the signature blanked. Byte-level divergence between the first two was "
             "demonstrated.",
        scenario="A `trust-core`-signed authority envelope does not verify in `authority-spec`, and vice versa. The "
                 "README's own stated kill criterion is *\"No security invariant may have two authoritative "
                 "implementations.\"* There are three, plus a full independent 377-line Python validator that diverges "
                 "from Rust on `1.0`-as-integer and on trailing-newline regex anchoring.",
        blast="Cross-language interoperability, which is the entire product.",
        fix="One canonicalizer in `trust-core`, consumed by every other crate and mirrored bit-for-bit in "
            "Python/Go/TS against shared vectors. Delete the other two.",
        accept="A conformance vector set proving byte-identical canonical output across all four languages for the "
               "full P1–P12 corpus, including the `1.0` and trailing-newline edge cases.",
    ),
    dict(
        fid="AX-09", sev="High", title="The declared wire signature profile is implemented nowhere",
        area="Normative layer", blocks="integrate", gate="G4 Protocol conformance", effort="L",
        evidence="EXECUTED",
        where="`specs/protocols/registry.json:10-12`",
        what="The registry declares `json_canonicalization: \"RFC8785\"`, "
             "`cbor_canonicalization: \"RFC8949-core-deterministic\"` and `cbor_container: \"COSE_Sign1\"`. A repo-wide "
             "grep for `cose|Sign1` returns **zero hits in Rust**. Real RFC 8785 exists only in `gguf-ext`, which is "
             "outside the signing path. `testvectors/protocols/manifest.json:4` quietly downgrades the claim to "
             "`\"RFC8785-compatible integer-only profile\"`.",
        scenario="An independent implementer builds to the registry, implements full RFC 8785 and COSE_Sign1, and "
                 "cannot interoperate with any AumOS implementation.",
        blast="Also a documentation defect in the *strengthening* direction: the integer-only restriction is genuinely "
              "good design — every numeric payload field is deliberately an integer (`confidence_micros`, "
              "`money_minor`, `expected_risk_micros`), which sidesteps RFC 8785's hardest part. The registry simply "
              "does not say so.",
        fix="Either implement the declared profile, or amend the registry to declare the integer-only profile "
            "normatively and document the numeric-domain restriction as a deliberate constraint. Do not leave the two "
            "documents disagreeing.",
        accept="Registry, manifest and implementation agree; a third-party implementer can build from the registry "
               "alone and pass the vectors.",
    ),
    dict(
        fid="AX-10", sev="High", title="Negative test coverage is one mechanical mutation per protocol",
        area="Assurance", blocks="claim", gate="G4 · G3", effort="M",
        evidence="READ",
        where="`tools/protocols/generate_vectors.py:306`",
        what="Negative vectors are produced by deleting *\"the lexicographically first payload field\"*. So 12 of "
             "roughly 569 registry constraints have any must-reject vector, and all 12 are the same kind of rejection.",
        scenario="Zero vectors exercise any `pattern`, any `enum`, any `minimum`/`maximum` (including "
                 "`delegation_depth` 0..32 and `confidence_micros` 0..1e6), any `minItems`, any `uniqueItems`, "
                 "`additionalProperties` rejection, or type confusion. Six of the twelve error codes in `errors.json` "
                 "are never produced by any vector. Envelope-level adversarial coverage — expired, downgrade, unknown "
                 "critical extension, tampered signature — exists for **P1 only**.",
        blast="Meanwhile every protocol spec claims it ships six classes of adversarial vector (replay, tampering, "
              "confused deputy, privilege amplification, downgrade, cross-context replay). P2–P12 ship three files each.",
        fix="Generate one must-reject vector per constraint from the registry automatically, and assert the specific "
            "error code. Extend the P1 envelope-adversarial set to all twelve protocols.",
        accept="Every registry constraint has a negative vector; every `errors.json` code is produced by at least one "
               "vector; all run in all four languages.",
    ),
    dict(
        fid="AX-11", sev="High", title="Compliance output is fabricated and signed",
        area="Evidence", blocks="claim", gate="G13 Regulatory evidence", effort="M",
        evidence="READ",
        where="`rust/defstack-cli/src/main.rs:175`, `rust/flight-recorder/src/lib.rs:351`, "
              "`rust/eval-guard/src/cli.rs:26`",
        what="`defstack-cli compliance-report` emits a hardcoded map claiming `\"signed_by\": \"did:web:aumos.dev\"` "
             "for EU AI Act, NIST AI RMF, ISO 42001, FedRAMP, DORA and NIS2 — nothing measured. `defstack verify` with "
             "no arguments prints `[ok]` for all eight components unconditionally. `defstack test` discards every "
             "failure (`let _ = ...status()`) and exits 0. `flight-recorder` hardcodes an `engine: \"opa\", decision: "
             "\"allow\"` policy decision into every receipt and signs it, with no policy engine consulted. "
             "`eval-guard`'s CLI hardcodes `CheckResults::all_pass()` and signs it with a freshly generated throwaway "
             "key.",
        scenario="An auditor is handed a cryptographically signed compliance report attesting to controls that were "
                 "never evaluated. This is the single highest-liability finding in the audit — worse than a missing "
                 "control, because it manufactures false assurance.",
        blast="Regulatory, contractual and reputational. Note that **DIFC Regulation 6.2 makes misleading public "
              "representations about certifications or adherence to standards independently enforceable** — in the "
              "GCC, overclaiming governance posture is itself the violation.",
        fix="Delete every hardcoded compliance and check result. A report must be derived from executed evidence or "
            "must not be emitted. Never sign a value that was not measured.",
        accept="`compliance-report` fails closed when no evidence exists; `defstack test` propagates exit codes.",
    ),
    dict(
        fid="AX-12", sev="High", title="The catalog is wrong in both directions",
        area="Governance", blocks="claim", gate="G1 Catalogue integrity", effort="S",
        evidence="EXECUTED",
        where="`docs/implementation/catalog.json`, `docs/implementation/tracker.json`",
        what="**Over-claims:** 49 entries are graded `reference_implementation`, including `kill-switch` (kills "
             "nothing), `nvtrust-bridge` (100% mock), `credential-vault` (all three backends return "
             "`BackendUnavailable … \"not yet wired (task 03)\"`), `inference-proxy` (no HTTP stack at all). "
             "**Under-claims:** five entries are graded `unimplemented` with empty `source_paths` while substantial "
             "code exists on disk — `rust/secure-workspace` (1,304 LOC), `rust/policy-bridge` (651), "
             "`rust/sandbox-runtime` (1,014), `rust/gguf-ext` (2,918 — the strongest crate in the repo), and "
             "`go/identity-bindings` (a real Go module with tests).",
        scenario="`catalog_integrity: passed: true` and `missing_catalog_artifacts: 0` are vacuous — the check verifies "
                 "that listed paths exist, never that existing code is listed.",
        blast="Every status document, roadmap and readiness claim derives from this file.",
        fix="Introduce honest status values (`spec_only`, `mock_only`, `partial`, `reference_implementation`, "
            "`integrated`) and regrade all 66 against executed evidence. Make catalog integrity bidirectional: fail if "
            "a source directory exists that no entry claims.",
        accept="Bidirectional integrity check in CI; every `reference_implementation` grade backed by a named "
               "executed test.",
    ),
    dict(
        fid="AX-13", sev="High", title="Nothing is installable — the documented entry points do not work",
        area="Developer experience", blocks="integrate", gate="G14 Release usability", effort="M",
        evidence="EXECUTED",
        where="`typescript/mcp-server/src/index.ts:1460`, `README.md`, `Makefile`",
        what="`npx aumos-mcp --standalone` — the README's own run command — is a **silent no-op on every platform**. "
             "`index.ts:1460` compares `process.argv[1]` (the npm-installed symlink) against `import.meta.url` (the "
             "resolved realpath); npm always symlinks bins, so `isMain` is false and the server never starts. It "
             "prints nothing and exits 0. Separately, all four npm packages 404 — nothing is published — so the "
             "README's copy-paste Claude Code config resolves to a registry error.",
        scenario="A developer follows the documented quick start and gets silence. An MCP client sees a process that "
                 "produces no output and exits cleanly.",
        blast="Compounded by `make` not existing on a clean Windows box, so the documented `make conformance` "
              "one-command gate cannot run at all; and `npm run lint` fails on a clean checkout with 37 errors, all in "
              "`protocol-contracts/src/generated.ts` — an orphaned file with no `package.json`, absent from workspaces "
              "and tsconfig references, imported by nothing — which reds the CI job at step one.",
        fix="Use `pathToFileURL(realpathSync(argv[1]))` for the main-module check. Publish the packages or remove the "
            "install instructions. Add `protocol-contracts` to the workspace or delete it. Provide a "
            "`make`-free entry point (a `task`/`just`/npm-script runner) for Windows.",
        accept="A clean-machine smoke test on Linux, macOS and Windows that follows the README verbatim and reaches a "
               "working server.",
    ),
    dict(
        fid="AX-14", sev="High", title="No SDK and no agent-framework integration path exists",
        area="Developer experience", blocks="integrate", gate="G14 Release usability", effort="L",
        evidence="EXECUTED",
        where="`typescript/`, `python/`",
        what="`README.md:62` states TypeScript \"owns … SDK ergonomics\". There is no `@aumos/sdk`, no client "
             "library, no `AumosClient`. For Claude Agent SDK, OpenAI Agents SDK, LangGraph, CrewAI or AutoGen there "
             "is **no adapter, no middleware, no hook, no example and no documentation**.",
        scenario="The integration question — \"I have an agent loop; how do I wrap it in AumOS authority and receipts "
                 "without forking my framework?\" — has no answer in the repository.",
        blast="This is the difference between a specification and an adoptable product. Every one of the four "
              "integration targets requires a tool-call interceptor; none is provided.",
        fix="Ship one thin, published SDK per language with a single documented seam: `wrap_tool_call(authority, fn)`. "
            "Provide one worked example per framework. Prefer a middleware shape that degrades to *deny* when the "
            "control plane is unreachable.",
        accept="A published package plus a runnable example for at least Claude Agent SDK and LangGraph, each with a "
               "test proving fail-closed behaviour when the control plane is down.",
    ),
    dict(
        fid="AX-15", sev="High", title="Bypass is trivial — the substrate is a library, not a chokepoint",
        area="Architecture", blocks="trust", gate="G5 · G9", effort="XL",
        evidence="READ",
        where="`typescript/mcp-gateway/src/index.ts`, `typescript/mcp-server/src/index.ts:1270`",
        what="`McpGateway` is an exported class with an injected transport. There is no proxy process, no listener, no "
             "egress control, no interception. An agent simply opens its own connection to the tool server. Nothing "
             "observes it. `aumos-mcp-server`'s own handler performs protocol-metadata validation and **no authority "
             "check whatsoever** — any process on the stdio pipe can invoke `aumos_kill` or `aumos_revoke_identity` "
             "with no SVID, no envelope and no token.",
        scenario="The project's central claim is *\"the security substrate that agents cannot bypass.\"* Bypassing it "
                 "requires not calling it.",
        blast="This is the thesis, and it is currently unsupported by the code. Enforcement that an agent can decline "
              "to invoke is advice, not containment.",
        fix="Enforcement must live where the agent cannot route around it: a network chokepoint (egress proxy with "
            "default-deny and DNS control), an OS boundary (namespace/seccomp, as Anthropic's sandbox-runtime does), "
            "or a credential boundary (the agent never holds the credential — the pattern Cloudflare OS shipped). A "
            "library the agent chooses to call cannot deliver the claim.",
        accept="A red-team test where an agent with arbitrary code execution attempts direct tool access and fails.",
    ),
    dict(
        fid="AX-16", sev="Medium", title="Every supply-chain and coverage gate is non-blocking",
        area="CI / assurance", blocks="claim", gate="G2 · G11 · G12", effort="S",
        evidence="EXECUTED",
        where="`.github/workflows/`",
        what="No `cargo audit`, no `cargo deny`, no `deny.toml` anywhere in the repository. The workflow named "
             "`aumos-security.yml` runs fmt/clippy/test and a `cargo install … || true`; it audits nothing. "
             "`coverage.yml:35` is `cargo llvm-cov … || true` with a comment deferring the real gate to \"Wave-2\". "
             "`sbom.yml` and `release.yml` end their SBOM steps in `|| true`. The protocol codegen `--check` appears "
             "in neither the Makefile `verify` target nor any workflow.",
        scenario="The repo claims a ≥85% coverage gate and SLSA Level 3+. Neither is enforced, and **SLSA has no Level "
                 "4** — `docs/cross-cutting/13-compliance-frameworks.md:102` defines an L4 that was retired from the "
                 "spec in April 2023. Current SLSA is v1.2 (approved 2025-11-12) and the build track tops out at L3.",
        blast="Green CI signifies almost nothing, which is the mechanism behind every other over-claim in this audit.",
        fix="Add `cargo audit` and `cargo deny` as blocking jobs. Remove every `|| true`. Gate coverage at a real "
            "threshold. Add the codegen check to `verify`. Correct the SLSA references to v1.2 / L3.",
        accept="CI red on a known-vulnerable dependency, on coverage regression, and on hand-edited generated code.",
    ),
    dict(
        fid="AX-17", sev="Medium", title="Zeroize is worse than absent — it installs a publicly-known key",
        area="Trust core", blocks="trust", gate="G10", effort="S",
        evidence="READ",
        where="`rust/trust-core/src/signing.rs:35`",
        what="`Drop::drop` executes `let _ = self.inner.to_bytes();` — which **copies the secret onto the stack and "
             "discards it**, zeroizing nothing and creating an extra copy. `Zeroize::zeroize` does "
             "`*self = Self { inner: SigningKey::from_bytes(&[0u8; 32]) }`, leaving the original bytes in place and "
             "replacing the key with the **all-zeros Ed25519 secret key**.",
        scenario="Any `sign()` call after `zeroize()` produces valid signatures under a key every attacker knows.",
        blast="The justifying comment at `signing.rs:25` claims dalek 2.x lacks `Zeroize` — and the crate's own "
              "`Cargo.toml` enables `ed25519-dalek` `features = [\"rand_core\", \"zeroize\"]`. The entire wrapper is "
              "unnecessary and actively harmful.",
        fix="Delete the wrapper and use dalek's own `Zeroize` implementation.",
        accept="A test asserting the key material is unusable after zeroize.",
    ),
    dict(
        fid="AX-18", sev="Medium", title="Secrets on the command line and on stdout",
        area="Runtime", blocks="deploy", gate="G10", effort="S",
        evidence="READ",
        where="`trust-core/src/cli.rs:31`, `typescript/mcp-server/src/index.ts:630`, "
              "`provena-chain/src/lib.rs:202`",
        what="The Rust CLI takes `--key <hex secret>` as an argv parameter and prints the Ed25519 private key to "
             "stdout at `cli.rs:93`. The TypeScript server passes the raw signing key in `argv` to an exec'd binary — "
             "contradicting its own comment 150 lines earlier claiming *\"Payloads are written to stdin, never "
             "command-line arguments.\"* `provena-chain` writes the ledger's private key to disk in plaintext with "
             "default permissions.",
        scenario="Any local user reads the signing key via `ps` or `/proc/*/cmdline`; CI logs and shell history retain "
                 "it.",
        blast="Key compromise is total compromise for a signing-based trust model.",
        fix="Secrets via stdin, environment, or a key-management interface only. Never argv, never stdout. File "
            "permissions `0o600` plus zeroize on drop.",
        accept="A lint or test that fails if any secret-bearing parameter is declared as a positional/flag argument.",
    ),
    dict(
        fid="AX-19", sev="Medium", title="Fail-open paths throughout the control components",
        area="Runtime", blocks="trust", gate="G5", effort="L",
        evidence="READ",
        where="multiple",
        what="A representative sample: `authority-spec/src/lib.rs:166` and `credential-vault/src/lib.rs:333` both do "
             "`now_epoch().unwrap_or(0)` — a clock before the epoch yields `now = 0`, so **every expired credential "
             "and every expired authority validates**. `credential-vault/src/lib.rs:372` returns early on an empty "
             "`jti`, making any credential deserialized without one **permanently unrevocable** — and a test asserts "
             "this as intended. `exfil-guard/src/lib.rs:609` silently disables the entire volume monitor on a "
             "non-monotonic clock, and `:332` runs the entropy detector only when the payload is all-printable, "
             "structurally exempting encrypted and compressed payloads — i.e. what exfiltration actually looks like. "
             "`confidential-fabric`'s default key-release policy checks nothing.",
        scenario="Each individually is a bug; collectively they are a pattern — the error path is the permissive path.",
        blast="`policy-bridge` gets this right (`lib.rs:76` is default-deny) and `egress-filter` gets it backwards "
              "(`lib.rs:161` terminal branch is `Allow`) **in the same workspace**.",
        fix="Adopt a workspace-wide rule: no `unwrap_or`, `unwrap_or_default` or `.ok()` on any path that produces a "
            "security decision. Add a clippy lint and a review gate. Make every default deny.",
        accept="A fault-injection test suite that breaks the clock, the mutex, the parser and the transport, and "
               "asserts denial in every case.",
    ),
    dict(
        fid="AX-20", sev="Medium", title="Format and taxonomy staleness across the evidence layer",
        area="Interop", blocks="integrate", gate="G13", effort="M",
        evidence="EXTERNAL",
        where="`python/model_sbom`, `python/warrantor_ocsf`, `python/incident_exchange`",
        what="ModelSBOM emits **CycloneDX 1.5** (current 1.7, ECMA-424, Oct 2025) with `\"type\": \"library\"` and "
             "ad-hoc `properties` — it is **not an ML-BOM in any version**, despite `machine-learning-model` and "
             "`modelCard` existing since 1.5. Its SPDX output declares `SPDX-3.0` while emitting the SPDX 2.3 shape. "
             "`OCSF_VERSION` is pinned to **1.1.0** (current **1.9.0**, 2026-08-03). `OCSF_CLASS_UID = 3003` is "
             "commented \"Incident class\" — **3003 is Authorize Session, in the IAM category**. The ATLAS mapping uses "
             "the 2023 technique set and misses `AML.T0086` and `AML.T0098`, the agentic techniques that actually "
             "describe AumOS's threat model.",
        scenario="No downstream tool will parse these as the artifacts they claim to be.",
        blast="Undermines exactly the interoperability that justifies the evidence layer's existence.",
        fix="Regenerate against current schema versions; emit `machine-learning-model` + `modelCard`; adopt OCSF 1.9's "
            "native `ai_agent` object and `ai_operation` profile; validate `ocsf_class_uid` against a real class "
            "registry rather than `minimum: 1`; refresh ATLAS mappings to v5.4.0.",
        accept="Output validates against the official CycloneDX 1.7, SPDX 3.0.1 and OCSF 1.9 schemas in CI.",
    ),
    dict(
        fid="AX-21", sev="Medium", title="Stack overflow in the crypto hot path is an unrecoverable abort",
        area="Trust core", blocks="scale", gate="G12 Reliability", effort="S",
        evidence="EXECUTED",
        where="`rust/trust-core/src/canonical.rs:33`",
        what="`sort_value` recurses without a depth bound. In a debug build I triggered a stack overflow at nesting "
             "depth ~127; with a 256 MB stack the deserializer limit is reached first. `[profile.release] "
             "panic = \"abort\"` plus `strip = true` makes this an unrecoverable process kill with no symbols.",
        scenario="An attacker-supplied deeply-nested envelope terminates the verifying process. Denial of service on "
                 "the component every other component depends on.",
        blast="The existing fuzz target only asserts \"does not panic\" and runs for **60 seconds** in CI — it is "
              "structurally incapable of finding AX-01 and barely capable of finding this.",
        fix="Iterative traversal or an explicit depth limit with a typed error, enforced before any allocation. "
            "Increase fuzz duration materially and add a structure-aware target.",
        accept="A test at depth 10^6 that returns a typed error rather than aborting.",
    ),
    dict(
        fid="AX-22", sev="Medium", title="Cross-tenant cache leak in the inference path",
        area="Inference", blocks="deploy", gate="G7 Tenant isolation", effort="S",
        evidence="READ",
        where="`rust/inference-proxy/src/lib.rs:285`",
        what="The semantic cache key is `sha256(model | prompt)`. **Tenant identity is not part of the key.** "
             "`handle()` authenticates the caller, then serves tenant A's cached completion to tenant B on a matching "
             "prompt without ever contacting the backend.",
        scenario="Two tenants submit the same prompt; the second receives the first's model output. In a regulated "
                 "multi-tenant deployment this is a data-segregation breach.",
        blast="The crate's own test uses a single identity and therefore cannot observe it. Note `inference-proxy` is "
              "not actually a proxy — it has no tokio, hyper, axum or reqwest, and `handle()` takes a closure as "
              "\"upstream\".",
        fix="Include tenant identity (and any authority-scoped context) in the cache key. Add a two-tenant negative "
            "test.",
        accept="A test proving tenant B misses the cache on tenant A's prompt.",
    ),
    dict(
        fid="AX-23", sev="Medium", title="Documentation volume is auto-generated and outruns reality",
        area="Governance", blocks="claim", gate="G12", effort="M",
        evidence="EXECUTED",
        where="`docs/rfcs/`",
        what="**46 of 54 RFCs are exactly 98 lines** — one template with the nouns swapped. Only eight have authored "
             "content. `check_docs.py` reports `PASS — 170 Markdown files, 54 RFCs, 66 catalogue rows, and all "
             "local links validated`, which measures structure, never substance.",
        scenario="The correlation is the finding: the longest RFC (`S3-gguf-ext.md`, 228 lines) belongs to the one "
                 "crate rated fully real, and the second longest (`I1-agent-identity.md`, 171) to the most substantive "
                 "Go module. **Where a design was actually written, code was actually built.**",
        blast="A reader cannot distinguish designed components from generated placeholders, which is precisely the "
              "distinction that matters.",
        fix="Mark template RFCs explicitly as `status: placeholder`. Require an authored design before a component "
            "may be graded above `spec_only`.",
        accept="Every component graded `reference_implementation` or higher has a non-template RFC.",
    ),
    dict(
        fid="AX-24", sev="Low", title="Empty Merkle root collides with a zero-initialized buffer",
        area="Trust core", blocks="trust", gate="G3", effort="S",
        evidence="EXECUTED",
        where="`rust/trust-core/src/merkle.rs:38`",
        what="`merkle_root(&[])` returns 32 zero bytes. RFC 6962 §2.1 specifies `SHA-256(\"\")` = `e3b0c442…b855`. "
             "Verified against a literal RFC 6962 implementation for n = 0..40: **one mismatch, at n=0 only.** The "
             "algorithm is otherwise correct and has no CVE-2012-2459 duplicate-leaf collision.",
        scenario="A default-constructed or zero-initialized `[u8; 32]` root buffer is indistinguishable from a "
                 "legitimately computed empty-log root.",
        blast="Low in isolation. Worth noting the module also provides **no inclusion proof, no consistency proof and "
              "no verifier** — 46 lines of logic for something whose stated purpose is anchoring a transparency log.",
        fix="Return `SHA-256(\"\")` for the empty case. Add inclusion and consistency proofs with verifiers.",
        accept="RFC 6962 test vectors pass, including n=0, plus proof verification round-trips.",
    ),
]

# ===========================================================================
# COMPONENT DOSSIERS (54)
# real: REAL | PARTIAL | CHASSIS | STUB | MOCK | ORPHAN
# ===========================================================================
def C(cid, name, domain, lang, path, tracker, real, grade, loc, claim, found, gap, ev="READ"):
    return dict(cid=cid, name=name, domain=domain, lang=lang, path=path, tracker=tracker,
                real=real, grade=grade, loc=loc, claim=claim, found=found, gap=gap, ev=ev)


COMPONENTS = [
    # ---------------- TRUST ----------------
    C("T1", "trust-core", "Trust", "Rust", "rust/trust-core", "reference_implementation", "PARTIAL", "F", "1,607",
      "The single authoritative implementation of every security invariant: canonicalization, signing, attestation "
      "verification, revocation enforcement, capability mediation.",
      ["**Contains a demonstrated universal signature forgery** (AX-01) — I signed a benign payload and verified a "
       "malicious one against it. [EXECUTED]",
       "`lib.rs:12` exports only `canonical, merkle, rekor, signing, verification`. **Six of the eight invariants it "
       "is declared authoritative for do not exist in it** — no attestation verification, no revocation, no capability "
       "mediation, no expiry, no nonce/replay, no COSE.",
       "Merkle is genuinely correct (verified against a literal RFC 6962 implementation for n=0..40; one mismatch at "
       "n=0 only, no duplicate-leaf collision). [EXECUTED]",
       "The Rekor client has demonstrably never run against a real Rekor: entry type misspelled `hashedrekor`, with a "
       "**test asserting the misspelling**; base64 digest where hex is required; plaintext TCP against an HTTPS "
       "endpoint; `verify_entry` checks only that the server echoed back the log index the client already had.",
       "`Zeroize` installs the all-zeros Ed25519 secret key (AX-17)."],
      ["Replace `serde_cbor` with `ciborium`; fail closed on decode error.",
       "Implement or stop claiming the six missing invariants.",
       "Rewrite the Rekor client against Rekor v2 (GA 2025-10-10, tile-backed, year-sharded) with real inclusion-proof "
       "verification, or delete it.",
       "Delete the Zeroize wrapper and use dalek's own."], ev="EXECUTED"),
    C("T2", "authority-spec", "Trust", "Rust", "rust/authority-spec", "reference_implementation", "PARTIAL", "C-", "508",
      "Normative enforcement of P1 authority-envelope semantics.",
      ["Enforces expiry, side-effect class, I-08 approval and delegation depth.",
       "Does **not** enforce budget ceilings, geographies, data classes or revocation — all signed, none read.",
       "**Ships its own second canonicalizer** and does not depend on `trust-core` at all, producing byte-divergent "
       "output (AX-08). [EXECUTED]",
       "`now_epoch().unwrap_or(0)` means a clock before the epoch validates every expired envelope."],
      ["Consume `trust-core`'s canonicalizer; delete the local one.",
       "Enforce budget, geography, data-class and revocation, or remove them from the schema.",
       "Fail closed on clock error."], ev="EXECUTED"),
    # ---------------- IDENTITY ----------------
    C("I1", "agent-identity", "Identity", "Go", "go/agent-identity", "reference_implementation", "PARTIAL", "C+", "831+607",
      "SPIFFE/SPIRE-backed cryptographic identity for every agent.",
      ["The most substantive Go module, and one of only eight components with an authored (non-template) RFC — a "
       "correlation that holds repo-wide.",
       "The registry mandates `^spiffe://` subjects everywhere, but **SPIRE issues identity by matching "
       "kernel-observable selectors against pre-registered entries**. An ephemeral agent task has no distinguishing "
       "selector, so per-task SPIFFE IDs are structurally unattestable. [EXTERNAL]",
       "Revocation — which `authority-spec` explicitly defers to this component — is not reachable from the Rust "
       "trust core; there is no I1 crate in the Rust workspace."],
      ["Decide and document whether a subject names the long-lived workload or the ephemeral task, and how the latter "
       "is attested.",
       "Expose revocation over a real interface the trusted core can call.",
       "Align with `draft-ietf-oauth-spiffe-client-auth` (WG-adopted 2026-06-15) and consider WIT-SVID "
       "proof-of-possession over bearer SVIDs."]),
    C("I2", "identity-bindings", "Identity", "Go", "go/identity-bindings", "unimplemented", "PARTIAL", "C", "282+219",
      "Language bindings for agent identity.",
      ["**The tracker grades this `unimplemented` with empty `source_paths`, yet `go/identity-bindings` exists with a "
       "`go.mod`, 282 LOC and 219 lines of tests.** [EXECUTED]",
       "One of five entries the catalog under-reports (AX-12)."],
      ["Regrade in `catalog.json`; make catalog integrity bidirectional."], ev="EXECUTED"),
    # ---------------- RUNTIME ----------------
    C("R1", "secure-workspace", "Runtime", "Rust", "rust/secure-workspace", "unimplemented", "CHASSIS", "C", "1,304",
      "Isolated, credential-brokered agent workspace with approval gates and append-only evidence.",
      ["Tracker says `unimplemented`; 1,304 LOC exist. [EXECUTED]",
       "Careful validation and sequencing around five injected traits — **four of which have no implementation "
       "anywhere**. Enforces nothing on its own.",
       "Not wired to `sandbox-runtime`, despite the two RFCs each naming the other.",
       "`lib.rs:580` discards a credential-revocation failure on the sandbox-failure path, leaving a live lease; the "
       "same function rigorously aggregates revoke failures fifty lines later.",
       "`request_digest` is computed over the request **including** `approval_ref` — circular, so any real approval "
       "gate must ignore the digest, making the \"approval bound to the exact request\" property fail-open by "
       "construction."],
      ["Implement the four missing traits or mark the component `spec_only`.",
       "Wire to `sandbox-runtime`.",
       "Exclude `approval_ref` from the digest it is meant to bind."], ev="EXECUTED"),
    C("R2", "eval-guard", "Runtime", "Rust", "rust/eval-guard", "reference_implementation", "STUB", "F", "397",
      "Signed attestation that runtime boundary checks passed.",
      ["**The most misleading crate in the repository.** The four \"boundary checks\" are **function arguments** "
       "(`lib.rs:166`) — the caller asserts them.",
       "The shipped CLI hardcodes `CheckResults::all_pass()` (`cli.rs:26`) and signs it with a **freshly generated "
       "throwaway key** (`cli.rs:39`).",
       "The signature covers the constant `BoundaryCheck::ALL`, not `self.passed_checks` — so the one field consumers "
       "actually read is the one field the signature omits.",
       "`#![forbid(unsafe_code)]` on a crate whose stated job requires eBPF."],
      ["Measure something. Until it does, regrade to `mock_only` and remove the signing path entirely — a signature "
       "over an unmeasured claim is worse than no signature."]),
    C("R3", "kill-switch", "Runtime", "Rust", "rust/kill-switch", "reference_implementation", "MOCK", "F", "539",
      "Sub-5-second containment: suspend model, unload GPU memory, kill pod, isolate network, wipe memory.",
      ["**It kills nothing** (AX-05). The execution layer is a literal `Vec<String>` of five action names followed by "
       "`Ok`. Grep for `Command|signal|kube|libc|process::` returns **0**. [EXECUTED]",
       "The source comment is honest: *\"Wave-1 mock execution: record the canonical 5 actions without actually doing "
       "them.\"* **The catalog is what over-claims.**",
       "`confidence: f64` is never range-validated — `NaN` makes every comparison false and the kill is *refused*.",
       "`operator` and `clearance` are unauthenticated argv strings."],
      ["Add an `ExecutionEngine` trait with real backends; make the mock an explicit test double.",
       "Validate `confidence` and authenticate the operator.",
       "Regrade to `mock_only` immediately — this is the component named for the AI Kill Switch Act."], ev="EXECUTED"),
    C("R4", "credential-vault", "Runtime", "Rust", "rust/credential-vault", "reference_implementation", "STUB", "D", "886",
      "Short-lived, bound, revocable credentials for agents.",
      ["All three named backends unconditionally return `Err(BackendUnavailable(… \"not yet wired (task 03)\"))`. No "
       "`vaultrs`, no `aws-sdk`, no `kube` dependency.",
       "SPIFFE/task/IP binding is **stored and never checked**.",
       "`#[serde(default)] pub jti: String` plus an early `Ok(())` on empty `jti` makes any credential deserialized "
       "without one **permanently unrevocable** — and a test asserts this as intended.",
       "The `<1s` revocation SLO test times a `HashSet::drain` and asserts nothing."],
      ["Wire at least one real backend, or consume HashiCorp Vault (which shipped a SPIFFE secrets engine).",
       "Enforce the bindings. Reject empty `jti`."]),
    C("R5", "policy-compiler", "Runtime", "Python", "python/policy_compiler", "reference_implementation", "PARTIAL", "C", "407+155",
      "Compiles governance policy to Rego / Cedar / OpenShell.",
      ["Real Python with reasonable test ratio (155 test lines to 407 source).",
       "Sits outside the Rust trust boundary while producing artifacts the trust boundary depends on — the "
       "`policy_digest` in P2 receipts.",
       "No evidence any compiled policy is executed by a real engine anywhere in the repo."],
      ["Prove round-trip: compile a policy, execute it in real OPA and real Cedar, and assert identical decisions."]),
    C("R6", "policy-bridge", "Runtime", "Rust", "rust/policy-bridge", "unimplemented", "PARTIAL", "C+", "651",
      "Dual-engine policy evaluation with divergence detection.",
      ["Tracker says `unimplemented`; 651 LOC exist. [EXECUTED]",
       "The reference evaluator is real and **correctly default-deny** (`lib.rs:76`) — one of the few genuinely "
       "fail-closed defaults in the workspace.",
       "The \"bridge\" is a stub: **zero `EngineClient` implementations**, no OPA or Cedar dependency, an unparsed "
       "Rego string, and a headline test that compares the reference engine to itself three times.",
       "Divergence detection compares only `allowed` and `policy_digest`, **never `matched_rule_ids`** — two engines "
       "that allow for different reasons are reported equivalent.",
       "Unnormalized prefix matching: `repo://project/../project/secrets/key` matches the allow rule and misses the "
       "deny rule."],
      ["Implement at least one real engine client.", "Compare matched rules, not just the verdict.",
       "Normalize paths before matching (`secure-workspace` already implements this)."], ev="EXECUTED"),
    C("R7", "egress-filter", "Runtime", "Rust", "rust/egress-filter", "reference_implementation", "MOCK", "F", "437",
      "eBPF-backed default-deny egress enforcement.",
      ["**Zero eBPF dependencies.** A 4-entry `Vec<String>` and a suffix match, in userspace.",
       "**Default-allow** (`lib.rs:161` terminal branch is `Action::Allow`) — the opposite polarity to `policy-bridge` "
       "in the same workspace.",
       "`\"pastebin.com.\"` (trailing dot) bypasses the blocklist; `::ffff:10.0.0.1` bypasses private-egress denial; "
       "`deny_private_egress` is **false by default** \"so loopback health checks work in tests\".",
       "One of the four default canary IPs, `fd00:aumos::1`, **is not valid IPv6** — `u`, `m`, `o`, `s` are not hex "
       "digits — and is silently dropped by a `.ok()` filter. Four advertised, three loaded."],
      ["Default-deny. Normalize hostnames and IPv4-mapped IPv6. Fail loudly on malformed configuration.",
       "Either implement real eBPF or adopt Anthropic's `sandbox-runtime` OS-level approach and stop claiming eBPF."]),
    C("R8", "sandbox-runtime", "Runtime", "Rust", "rust/sandbox-runtime", "unimplemented", "REAL", "B+", "1,014",
      "WASM-isolated tool execution with fuel metering and capability admission.",
      ["Tracker says `unimplemented`; 1,014 LOC of **genuinely real Wasmtime integration** exist. [EXECUTED]",
       "Fuel is set and enforced; `StoreLimits` installed; **WASI genuinely not linked** (verified: no `wasmtime_wasi` "
       "dependency); imports admitted against a signed policy; capabilities index-addressed rather than "
       "string-addressed; audit-before-dispatch is fatal on failure.",
       "Correctly appends evidence on every early-return path — a discipline `secure-workspace` fails at.",
       "`wasmtime` is exact-pinned `=45.0.1`, blocking security patches on a JIT."],
      ["Regrade — this is one of the two best crates in the repo and the catalog says it does not exist.",
       "Wire it to `secure-workspace` and to P5's `runtime` enum.",
       "Relax the exact pin to a patch-compatible range."], ev="EXECUTED"),
    # ---------------- CONFIDENTIAL ----------------
    C("C1-1", "nvtrust-bridge", "Confidential", "Rust", "rust/nvtrust-bridge", "reference_implementation", "MOCK", "F", "366",
      "Bridge to NVIDIA confidential-GPU attestation.",
      ["**100% mock** (AX-06). One backend, `MockBackend`; verification is "
       "`attestation_bytes == b\"aumos-mock-attestation\"`. No FFI, no `bindgen`, no `links=`, no feature flag, no "
       "NRAS client in `Cargo.toml`. [EXECUTED]",
       "`#![forbid(unsafe_code)]` makes the required FFI structurally impossible — the lint is proof the real "
       "implementation was never attempted.",
       "The doc comment claims a `Real` implementation exists. **No such type exists.**"],
      ["Bind real nvTrust/NRAS and verify EAT tokens, or delete and consume NVIDIA's Apache-2.0 verifier directly. "
       "Note NVIDIA's Python `nv-attestation-sdk` reaches end-of-support 2026-09-15."], ev="EXECUTED"),
    C("C1-2", "cuda-gram", "Confidential", "Python", "python/cuda_gram", "reference_implementation", "STUB", "D", "202+149",
      "GPU memory isolation and residency guarantees.",
      ["202 source lines for a component whose claim requires driver-level or hypervisor-level enforcement.",
       "5 stub markers in a 202-line package."],
      ["State plainly what it measures versus what it enforces, and regrade."]),
    C("C1-3", "attesta-flow", "Confidential", "Python", "python/attesta_flow", "reference_implementation", "STUB", "D", "156+69",
      "Attestation workflow orchestration.",
      ["156 source lines — the smallest package in the Python tree — with 4 stub markers.",
       "Sits outside the trust boundary while orchestrating attestation, which is a trust-boundary concern."],
      ["Fold into the Rust attestation path or mark `spec_only`."]),
    C("C1-4", "tee-serve", "Confidential", "Go", "go/tee-serve", "reference_implementation", "PARTIAL", "C", "667+434",
      "TEE-backed model serving.",
      ["Substantial Go module with a good test ratio (434 test lines to 667).",
       "Depends on the attestation layer being real, which it is not (C1-1, C1-5)."],
      ["Re-verify once real attestation exists; today its guarantees are inherited from a mock."]),
    C("C1-5", "confidential-fabric", "Confidential", "Rust", "rust/confidential-fabric", "reference_implementation", "STUB", "F", "929",
      "Attested key release and encrypted model delivery.",
      ["Never parses a quote, never checks a cert chain, never verifies a signature. \"Attestation\" is SHA-256 of the "
       "struct you handed it compared to a field inside that same struct.",
       "`FabricError::SignatureInvalid` is declared and **never constructed**.",
       "**No cipher crate at all** — `release_key` returns a `\"sha256:…\"` *string*, so \"encrypted model delivery\" "
       "is impossible in principle.",
       "The default `KeyReleasePolicy` sets every constraint empty, and the code documents empty as *do not check* — "
       "**it releases keys to any attestation under ten minutes old**, and a test asserts this as correct."],
      ["Default-deny the key-release policy. Implement real evidence parsing or delete. Never ship a component whose "
       "name promises encryption and which has no cipher."]),
    # ---------------- SUPPLY CHAIN ----------------
    C("S1", "safe-tensors-pp", "Supply chain", "Rust", "rust/safe-tensors-pp", "reference_implementation", "PARTIAL", "C-", "331",
      "Safetensors with embedded provenance.",
      ["Real Ed25519 binding of header to data digest.",
       "**Does not parse Safetensors** — `data_offsets`, `dtype` and `shape` are never inspected, so the "
       "format-level DoS class it exists to prevent is unaddressed. Unbounded `read_to_end`.",
       "No trust anchor (AX-07): verifies against a key read from the artifact.",
       "**Reinvention.** OpenSSF Model Signing signs models with detached Sigstore bundles **without modifying the "
       "file**, and NVIDIA NGC and Google Kaggle are adopting it. An in-file provenance block forks the format and "
       "breaks digest stability — violating the project's own stated non-goal of forking mature standards. [EXTERNAL]"],
      ["Adopt OpenSSF Model Signing. If in-file metadata is still wanted, follow `gguf-ext`'s namespaced-extension "
       "pattern, which gets this right."]),
    C("S2", "provena-chain", "Supply chain", "Rust", "rust/provena-chain", "reference_implementation", "PARTIAL", "C", "796",
      "Tamper-evident provenance ledger anchored in a transparency log.",
      ["Real Ed25519, length-prefixed canonical encoding and RFC 6962 domain separation — competent work.",
       "**Zero Rekor**: no HTTP dependency, no dependency on `trust-core`. \"Anchoring\" is two caller-invented "
       "strings.",
       "**Persists its Ed25519 private key to disk in plaintext** with default permissions, no `0o600`, no zeroize."],
      ["Real transparency-log anchoring or drop the claim. Protect the key at rest."]),
    C("S3", "gguf-ext", "Supply chain", "Rust", "rust/gguf-ext", "unimplemented", "REAL", "A-", "2,918",
      "Bounded GGUF parsing with a namespaced safety-metadata profile.",
      ["**The strongest crate in the repository — and the tracker says it does not exist.** [EXECUTED]",
       "`try_reserve_exact` throughout; checked arithmetic on every attacker-controlled multiply; tensor-range overlap "
       "detection; **real RFC 8785 JCS with round-trip enforcement**; domain separation; 2 fuzz targets; a 7-case "
       "adversarial corpus. The only crate with zero `unwrap`/`expect` in non-test code.",
       "Its RFC (`S3-gguf-ext.md`, 228 lines) is the only one in the repo that is not the 98-line template. "
       "**Designed, therefore built.**",
       "Genuine whitespace externally: the GGUF/GGML parser class has a live CVE history, including CVE-2026-5760 "
       "(CVSS 9.8, SSTI→RCE via a Jinja2 chat-template field). [EXTERNAL]",
       "Still inherits AX-07: no trust anchor on verify."],
      ["Regrade to `reference_implementation` and treat as the quality bar for the rest of the workspace.",
       "Add an expected-signer parameter to `verify`.",
       "Upstream the safety profile — this is publishable work."], ev="EXECUTED"),
    C("S4", "model-sbom", "Supply chain", "Python", "python/model_sbom", "reference_implementation", "PARTIAL", "D+", "353+128",
      "CycloneDX and SPDX AI bill of materials.",
      ["Emits **CycloneDX 1.5** with `\"type\": \"library\"` and ad-hoc `properties`. **It is not an ML-BOM in any "
       "version** — `machine-learning-model` and structured `modelCard` have existed since 1.5. [READ/EXTERNAL]",
       "Declares `\"spdxVersion\": \"SPDX-3.0\"` while emitting the SPDX 2.3 JSON shape; uses neither the AI Profile "
       "nor the Dataset Profile.",
       "Current CycloneDX is **1.7 — ECMA-424, an international standard since December 2025**. The tracker files this "
       "as medium-severity \"version drift\"; it is a format-validity failure. [EXTERNAL]"],
      ["Emit `machine-learning-model` + `modelCard` at CycloneDX 1.7; emit real SPDX 3.0.1 JSON-LD with `@context`.",
       "Validate output against the official schemas in CI."]),
    C("S5", "data-provenance-kit", "Supply chain", "Python", "python/data_provenance_kit", "reference_implementation", "PARTIAL", "C", "273+116",
      "Dataset lineage and consent tracking.",
      ["Reasonable size and test ratio; no stub markers.",
       "Does not reference C2PA, whose 2.4 release (April 2026) includes a collection data hash assertion explicitly "
       "covering training datasets. [EXTERNAL]"],
      ["Align with C2PA and the SPDX 3.0.1 Dataset Profile rather than defining bespoke lineage."]),
    C("S6", "exfil-guard", "Supply chain", "Rust", "rust/exfil-guard", "reference_implementation", "MOCK", "D", "907",
      "Runtime exfiltration detection and prevention.",
      ["No Falco, no Tetragon, no eBPF. Real detector algorithms, **zero enforcement**, and **nothing in the repo "
       "calls `evaluate`**.",
       "`lib.rs:332`: the entropy detector runs only `if window.iter().all(is_printable)` — **encrypted and compressed "
       "payloads, which is what exfiltration actually looks like, are structurally exempt.**",
       "`lib.rs:609`: a non-monotonic caller-supplied clock **silently disables the entire volume monitor**, no log, "
       "no counter; a 10 GB transfer then returns `allowed: true`.",
       "Unknown destination ⇒ both domain blocklist and volume monitor skipped ⇒ allow.",
       "Release-mode integer overflow at `lib.rs:371,482` wraps silently (no `overflow-checks`), so the hourly cap "
       "never fires."],
      ["Invert the entropy gate — high entropy is the signal, not the exemption.",
       "Fail closed on clock and on unknown destinations. Enable `overflow-checks`.",
       "Wire `evaluate` into an actual data path or mark `spec_only`."]),
    C("S7", "tamper-scan", "Supply chain", "Python", "python/tamper_scan", "reference_implementation", "PARTIAL", "C", "411+124",
      "Model and artifact tamper detection.",
      ["Real Python, no stub markers.",
       "Overlaps commercial model scanners (Protect AI/Palo Alto, HiddenLayer) that ship this as a product. [EXTERNAL]"],
      ["Differentiate against commercial scanners or narrow the scope to what the trust model uniquely needs."]),
    C("S8", "train-guard", "Supply chain", "Python", "python/train_guard", "reference_implementation", "PARTIAL", "C", "348+131",
      "Training-time integrity controls.",
      ["Real Python, no stub markers.",
       "Training-time integrity is genuinely under-served, but nothing binds this to P6 or to a real training run."],
      ["Bind output to P6 artifacts and produce a signed statement a third party can check."]),
    C("S9", "lightwell-bridge", "Supply chain", "Go", "go/lightwell-bridge", "reference_implementation", "PARTIAL", "C", "306+185",
      "AI supply-chain bridge.",
      ["Real Go module with tests.", "Purpose is under-specified in a 98-line template RFC."],
      ["Write a real design before extending."]),
    # ---------------- ASSURANCE ----------------
    C("A1", "safe-eval", "Assurance", "Python", "python/safe_eval", "reference_implementation", "PARTIAL", "C", "414+157",
      "Safety evaluation harness.",
      ["Real Python, no stub markers, decent test ratio.",
       "Does not produce a P8 Verifiable Evaluation Bundle — the protocol it most obviously should feed."],
      ["Emit signed P8 bundles. This is the shortest path to the project's strongest differentiator."]),
    C("A2", "adversaria", "Assurance", "Python", "python/adversaria", "reference_implementation", "PARTIAL", "C+", "563+151",
      "Adversarial attack generation.",
      ["563 lines, the largest assurance package, no stub markers.",
       "Not mapped to MITRE ATLAS v5.4.0's 60+ agentic techniques or to OWASP's 2026 Agentic Top 10 (ASI01–ASI10). "
       "[EXTERNAL]"],
      ["Map the corpus to ATLAS v5.4.0 and ASI01–ASI10; publish attack-success-rate numbers the way LlamaFirewall did."]),
    C("A3", "bias-sentinel", "Assurance", "Python", "python/bias_sentinel", "reference_implementation", "PARTIAL", "C", "397+138",
      "Bias and fairness evaluation.",
      ["Real Python; 2 stub markers.",
       "Fairness testing is explicitly demanded by **RBI's draft Model Risk Management Guidance (24 June 2026)** and "
       "by SDAIA's AI Ethics Principles — a strong, unclaimed regulatory hook. [EXTERNAL]"],
      ["Emit evidence in the shape RBI MRM and DIFC Reg 10 reviewers ask for."]),
    C("A4", "comply-gate", "Assurance", "Python", "python/comply_gate", "reference_implementation", "PARTIAL", "D", "405+202",
      "Compliance gating and reporting.",
      ["Adjacent to the fabricated compliance output in `defstack-cli` (AX-11).",
       "The compliance matrix it serves leads with EU AI Act, DORA and NIS2 and contains **no entry** for OCC 2026-13 "
       "/ Fed SR 26-2, RBI, DPDP, SDAIA, NCA or DIFC Regulation 10 — i.e. none of the stated primary markets. "
       "[EXTERNAL]"],
      ["Rebuild the control mapping around US model-risk supervision, RBI/DPDP/CERT-In, and GCC (DIFC Reg 10, SDAIA "
       "PDPL, CBUAE MMS).",
       "Never emit a report not derived from executed evidence."]),
    C("A5", "agentsec-lab", "Assurance", "Python", "python/agentsec_lab", "reference_implementation", "PARTIAL", "C", "428+121",
      "Agent security research lab.",
      ["Real Python, no stub markers."],
      ["Publish reproducible results; a lab with no published findings is indistinguishable from a scaffold."]),
    C("A6", "conformance", "Assurance", "Tools", "tools/conformance", "reference_implementation", "PARTIAL", "D", "404",
      "The cross-language conformance suite — the gate the whole interop claim rests on.",
      ["**Runs 5 T1 vectors and reports `PASS — 20/20`, while 40 protocol vectors go unexecuted** (AX-03). "
       "`T1_VECTOR_DIRECTORY` is hardcoded. [EXECUTED]",
       "`verify_python.py` (59 lines), `verify_go.go` (62), `verify_typescript.ts` (107), `verify_rust.rs` (48) — "
       "**none contains a single reference to any protocol**. [EXECUTED]",
       "The `protocol_tck` Rust binary its docs advertise is dead code referenced only by its own `Cargo.toml`."],
      ["Execute all 40 protocol vectors in all four languages and compare error codes. This single fix converts the "
       "project's central claim from asserted to demonstrated."], ev="EXECUTED"),
    C("A7", "red-team-cloud", "Assurance", "Python", "python/red_team_cloud", "reference_implementation", "STUB", "D", "476+179",
      "Cloud-scale red teaming.",
      ["7 stub markers, the highest count in the Python tree apart from `aumos_vllm`."],
      ["Red-teaming evidence is explicitly demanded by RBI MRM. Make this real or drop it."]),
    C("A8", "arena", "Assurance", "TypeScript", "typescript/arena", "reference_implementation", "PARTIAL", "C", "276",
      "Competitive agent-security arena.",
      ["Real but tiny — a 276-line Elo library. 32 tests pass. [EXECUTED]",
       "Its own doc-comment admits \"HTTP/scoreboard UI is task 03\". There is no arena."],
      ["Ship the scoreboard or rename the component to what it is: an Elo library."], ev="EXECUTED"),
    # ---------------- INFERENCE ----------------
    C("N1", "open-serve-kit", "Inference", "Go", "go/open-serve-kit", "reference_implementation", "PARTIAL", "C-", "329+118",
      "Open model-serving toolkit.",
      ["Weakest test ratio in the Go tree (118 test lines to 329).",
       "Competes with vLLM/TGI/Triton, which is not a winnable fight. [EXTERNAL]"],
      ["Integrate with existing servers rather than reimplementing serving."]),
    C("N2", "bridge-rt", "Inference", "Python", "python/bridge_rt", "reference_implementation", "PARTIAL", "C", "306+104",
      "Runtime bridge for inference.",
      ["Real Python, no stub markers, thin tests."], ["Define the boundary this bridges; the RFC is a template."]),
    C("N3", "inference-proxy", "Inference", "Rust", "rust/inference-proxy", "reference_implementation", "STUB", "D", "590",
      "Policy-enforcing inference proxy with caching and rate limiting.",
      ["**Not a proxy.** No tokio, hyper, axum or reqwest. `handle()` takes a closure as \"upstream\".",
       "**Cross-tenant cache leak** (AX-22): the cache key is `sha256(model|prompt)` with no tenant identity.",
       "2 of 6 claimed middlewares (audit, fallback) do not exist. \"Semantic cache\" is exact-match SHA-256.",
       "`DenyAllAuth` as the default is **the one genuinely fail-closed default in the workspace** — credit where due.",
       "LiteLLM has 56k stars and Stripe and Netflix in production. [EXTERNAL]"],
      ["Add tenant identity to the cache key immediately — this is a data-segregation bug.",
       "Adopt LiteLLM and contribute policy hooks rather than building a proxy."]),
    C("N4", "tenant-guard", "Inference", "Go", "go/tenant-guard", "reference_implementation", "PARTIAL", "C", "273+143",
      "Multi-tenant isolation enforcement.",
      ["Real Go module.",
       "Release gate **G7 Tenant isolation is `open`**, and AX-22 is a live cross-tenant leak elsewhere in the "
       "inference path — so isolation is not currently enforced end to end."],
      ["Add an adversarial two-tenant test across the whole inference path, not just this module."]),
    # ---------------- FEDERATION ----------------
    C("F1", "fed-core", "Federation", "Python", "python/fed_core", "reference_implementation", "PARTIAL", "C+", "577+389",
      "Federated learning core.",
      ["Strong test ratio (389 to 577); 3 stub markers."], ["Bind aggregation evidence to P6/P8."]),
    C("F2", "dp-crate", "Federation", "Python", "python/dp_crate", "reference_implementation", "PARTIAL", "B-", "531+458",
      "Differential privacy toolkit.",
      ["**The best test ratio in the repository** — 458 test lines to 531 source. 1 stub marker.",
       "DP is a domain where correctness is provable, and the test discipline reflects that."],
      ["Publish the privacy-accounting proofs; state the composition model explicitly."]),
    C("F3", "edge-sentinel", "Federation", "Go", "go/edge-sentinel", "reference_implementation", "PARTIAL", "C+", "689+452",
      "Edge fleet security agent.", ["Substantial Go module with a good test ratio."],
      ["Depends on revocation and containment being real; neither is."]),
    C("F4", "fleet-marshal", "Federation", "Go", "go/fleet-marshal", "reference_implementation", "PARTIAL", "C+", "661+590",
      "Fleet state and policy distribution.",
      ["Excellent test ratio (590 to 661) — among the best in the repo.",
       "This is the Go activation-gate use case the README explicitly permits, and it is one of the better-built "
       "modules."],
      ["Prove revocation fan-out against the stated `<5s` identity and `<1s` credential budgets with a real test."]),
    # ---------------- EXTENSIONS / EVIDENCE ----------------
    C("X1", "defstack-cli", "Extensions", "Rust", "rust/defstack-cli", "reference_implementation", "STUB", "F", "599",
      "The operator-facing CLI.",
      ["**Fabricates compliance evidence** (AX-11): `compliance-report` emits a hardcoded map claiming "
       "`\"signed_by\": \"did:web:aumos.dev\"` for EU AI Act, NIST AI RMF, ISO 42001, FedRAMP, DORA and NIS2.",
       "`verify` with no arguments prints `[ok]` for all eight components unconditionally.",
       "**`test` discards every failure** (`let _ = ...status()`) and prints \"Test suite complete.\" with exit 0.",
       "`install`, `upgrade` and `privacy` print plans and do nothing. **Zero unit tests** in 599 lines."],
      ["Delete all fabricated output. Propagate exit codes. This is the operator's primary surface and it currently "
       "manufactures false assurance."]),
    C("X2", "nooa-ext", "Extensions", "Python", "python/nooa_ext", "reference_implementation", "PARTIAL", "C", "532+212",
      "Observability extensions.", ["Real Python; 5 stub markers."],
      ["Align with OpenTelemetry GenAI semantic conventions and carry the same trace IDs as receipts."]),
    C("X3", "open-harness-spec", "Extensions", "Python", "python/open_harness_spec", "reference_implementation", "PARTIAL", "C+", "366+185",
      "Open evaluation-harness specification.",
      ["Real Python, no stub markers.",
       "Directly adjacent to P8 — the strongest protocol — and to Inspect, which is now the de-facto substrate for UK "
       "AISI and METR's Hawk. [EXTERNAL]"],
      ["Build on Inspect's `.eval` format rather than competing with it; sign a digest of it."]),
    C("X4", "crypto-audit-ai", "Extensions", "Python", "python/crypto_audit_ai", "reference_implementation", "PARTIAL", "C", "415+149",
      "Cryptographic audit tooling.",
      ["2 stub markers.",
       "Pointed irony: this component exists, and no tool in the repo caught AX-01, AX-08 or AX-17 in the trusted core."],
      ["Point it at `rust/trust-core` first."]),
    C("X5", "retro-spec-kit", "Extensions", "Python", "python/retro_spec_kit", "reference_implementation", "PARTIAL", "C", "433+148",
      "Retrospective specification tooling.", ["Real Python, no stub markers."], ["Under-specified purpose."]),
    C("X6", "metr-bridge", "Extensions", "Python", "python/metr_bridge", "reference_implementation", "PARTIAL", "C-", "348+137",
      "Bridge to METR evaluation methodology.",
      ["3 stub markers.",
       "**METR retired Vivaria in favour of Hawk, which is built on Inspect**, and the METR Task Standard never "
       "reached v1.0.0. This bridge targets a moving and partly abandoned target — and P8 is sequenced *behind* it. "
       "[EXTERNAL]"],
      ["Re-target at Inspect directly and unblock P8, which should not be gated behind this."]),
    C("X7", "console", "Extensions", "TypeScript", "typescript/console", "reference_implementation", "STUB", "D", "263",
      "Enterprise policy and evidence console.",
      ["**A console with no console.** 263 lines of types, a reducer and three `fetch` wrappers. No React, no Next.js, "
       "no UI. Its own doc-comment says \"React/Next.js component layer is task 03\". 12 tests pass. [EXECUTED]",
       "Its receipt type diverges from P2: `authorityHashHex`, `toolOrApiOp`, `emittedAt`, `signatureHex` — and "
       "**`phase` is absent**, which is the field that encodes the before-commit rule."],
      ["Either build the UI or rename the component. Align the receipt type with the registry."], ev="EXECUTED"),
    C("X8", "mcp-gateway", "Extensions", "TypeScript", "typescript/mcp-gateway + aumos-mcp-server", "reference_implementation", "PARTIAL", "D", "634 + 1,476",
      "MCP middleware binding authority and receipts to tool calls — the primary developer integration surface.",
      ["**The gateway never verifies the authority it enforces** (AX-02). A forged envelope authorised a destructive "
       "tool call. [READ]",
       "`aumos-mcp-server` is genuinely good in one respect: **connected mode really does fail closed**, returning "
       "typed denials with no mock fallback, and 22 tests assert it. That half of AUD-001 is honestly closed. [EXECUTED]",
       "But `AUMOS_MODE=standalone` still returns hardcoded security *passes* (`verified: true`, "
       "`status: 'compliant'`, `passed: true`, `triggered: true` while killing nothing) — **and the README's own "
       "Claude Code snippet ships `\"AUMOS_MODE\": \"standalone\"`**, so the copy-paste default hands an agent a "
       "control plane that always says yes.",
       "Targets MCP **2026-07-28**, the current revision — ahead of the official SDK. But it **rejects `2025-06-18` "
       "and `2025-03-26`**, the two most-deployed revisions, so real clients cannot connect. [EXECUTED]",
       "No `outputSchema`, no tool annotations — grep for `readOnlyHint|destructiveHint|idempotentHint` returns **0**. "
       "For a product whose thesis is the read/write/financial/destructive/physical ladder, not tagging `aumos_kill` "
       "with `destructiveHint: true` is a self-inflicted wound.",
       "**No authorization at all** — the spec mandates OAuth 2.1 + RFC 9728 + RFC 8707 audience validation; the "
       "transport sends no `Authorization` header and does no metadata discovery."],
      ["Verify envelope signatures before any policy evaluation.",
       "Accept `2025-06-18` and `2025-03-26`. Emit tool annotations and `outputSchema`.",
       "Implement OAuth 2.1 resource-server behaviour.",
       "Change the README default from `standalone` to `connected`."], ev="EXECUTED"),
    C("X9", "incident-exchange", "Extensions", "Python", "python/incident_exchange", "reference_implementation", "PARTIAL", "D", "277+145",
      "P9 incident exchange implementation.",
      ["Hardcodes `OCSF_CLASS_UID = 3003` commented as an incident class in \"Application Security\". **3003 is "
       "Authorize Session, in Identity & Access Management.** [READ/EXTERNAL]",
       "OCSF pinned to 1.1.0; current is 1.9.0, which shipped a native `ai_agent` object six days before this audit."],
      ["Adopt OCSF 1.9 `ai_operation` + `ai_agent`; use Incident Finding [2005] if an incident class is wanted."]),
    C("X10", "sovereign-stack", "Extensions", "Go", "go/sovereign-stack", "reference_implementation", "PARTIAL", "C", "255+270",
      "Sovereign deployment packaging.",
      ["More test lines than source — unusual and good.",
       "Sovereignty and portability are, per the competitive analysis, AumOS's **only durable non-technical "
       "advantage**. This component is under-invested relative to that. [EXTERNAL]"],
      ["Invest here. Air-gap, data-residency and in-country log retention (CERT-In requires 180 days of ICT logs held "
       "**inside Indian jurisdiction**) are concrete, defensible requirements."]),
    C("X11", "defstack-cloud", "Extensions", "Go", "go/defstack-cloud", "reference_implementation", "PARTIAL", "C", "310+286",
      "Managed cloud control plane.", ["Real Go module with a good test ratio."],
      ["Release gate G8 (durable evidence) and G10 (no durable control-plane data layer) are both open; this is where "
       "that work lands."]),
    C("E1", "flight-recorder", "Evidence", "Rust", "rust/flight-recorder", "reference_implementation", "STUB", "F", "655",
      "Signed, durable evidence written before an action commits (invariant I-07).",
      ["**Zero persistence.** Its own stated invariant — durable *before* commit — is disclaimed in a comment at "
       "`lib.rs:331`.",
       "**Fabricates the policy decision it signs** (AX-11): every receipt claims `engine: \"opa\", decision: "
       "\"allow\"` with no policy engine consulted, and that value is exported to OCSF as `policy`.",
       "`approvers`, `artifact_versions` and `rollback_pointer` are unreachable constants.",
       "`decode_hex_or_warn` emits **empty bytes on the wire for a malformed signature** — downstream sees "
       "\"unsigned\" rather than \"tampered\"."],
      ["Persist before returning. Never sign a value that was not measured. Make the checked encoder the only public "
       "API."]),
]


# ===========================================================================
# RENDERERS
# ===========================================================================
def render_protocol(p):
    body = []
    body.append('<dl class="kv">')
    body.append(f"<dt>Purpose</dt><dd>{md(p['purpose'])}</dd>")
    body.append(f"<dt>Invariant</dt><dd><code>{esc(p['rule'])}</code></dd>")
    body.append(f"<dt>Artefacts</dt><dd>{md(p['artefacts'])}</dd>")
    body.append("</dl>")
    body.append("<h4>What it claims</h4>" + para(p["claim"]))
    body.append("<h4>What is actually there</h4>" + bullets(p["reality"]))
    body.append("<h4>The external picture</h4>" + para(p["external"]))
    body.append(f'<div class="danger"><div class="calltitle">Verdict</div>{para(p["verdict"])}</div>')
    facets = f"grade:{p['grade'][0].lower()}"
    text = f"{p['pid']} {p['name']} {p['purpose']} {p['verdict']}"
    return (
        f'<details class="dos" data-facets="{facets}" data-text="{esc(text)}">'
        f'<summary><span class="did">{esc(p["pid"])}</span>'
        f'<span class="dname">{esc(p["name"])}<span class="dpath">specs/protocols/{esc(p["pid"])}-{esc(p["slug"])}.*</span></span>'
        f"{grade_pill(p['grade'])}</summary>"
        f'<div class="body">{"".join(body)}</div></details>'
    )


def render_component(c):
    body = []
    body.append('<dl class="kv">')
    body.append(f"<dt>Domain</dt><dd>{esc(c['domain'])} &middot; {esc(c['lang'])}</dd>")
    body.append(f"<dt>Source</dt><dd><code>{esc(c['path'])}</code> &middot; {esc(c['loc'])} LOC</dd>")
    body.append(f"<dt>Tracker says</dt><dd><code>{esc(c['tracker'])}</code></dd>")
    body.append(f"<dt>This audit</dt><dd><strong>{esc(c['real'])}</strong> {tag(c['ev'])}</dd>")
    body.append("</dl>")
    body.append("<h4>What it claims</h4>" + para(c["claim"]))
    body.append("<h4>What this audit found</h4>" + bullets(c["found"]))
    body.append("<h4>What must be implemented</h4>" + bullets(c["gap"]))
    mismatch = ""
    if c["tracker"] == "reference_implementation" and c["real"] in ("MOCK", "STUB"):
        mismatch = ' <span class="sev sev-critical">MISGRADED</span>'
    elif c["tracker"] == "unimplemented" and c["real"] in ("REAL", "PARTIAL", "CHASSIS"):
        mismatch = ' <span class="sev sev-medium">UNDER-REPORTED</span>'
    facets = f"domain:{c['domain'].lower().replace(' ', '-')} lang:{c['lang'].lower()} real:{c['real'].lower()} grade:{c['grade'][0].lower()}"
    text = f"{c['cid']} {c['name']} {c['path']} {c['domain']} {c['lang']} {c['claim']}"
    return (
        f'<details class="dos" data-facets="{facets}" data-text="{esc(text)}">'
        f'<summary><span class="did">{esc(c["cid"])}</span>'
        f'<span class="dname">{esc(c["name"])}{mismatch}<span class="dpath">{esc(c["path"])}</span></span>'
        f'<span class="tag tag-read">{esc(c["real"])}</span>{grade_pill(c["grade"])}</summary>'
        f'<div class="body">{"".join(body)}</div></details>'
    )


def render_finding(f):
    body = []
    body.append('<dl class="kv">')
    body.append(f"<dt>Severity</dt><dd>{sev_pill(f['sev'])} &middot; blocks <strong>{esc(f['blocks'])}</strong></dd>")
    body.append(f"<dt>Area</dt><dd>{esc(f['area'])}</dd>")
    body.append(f"<dt>Release gate</dt><dd>{esc(f['gate'])}</dd>")
    body.append(f"<dt>Location</dt><dd>{md(f['where'])}</dd>")
    body.append(f"<dt>Evidence</dt><dd>{tag(f['evidence'])}</dd>")
    body.append(f"<dt>Effort</dt><dd><strong>{esc(f['effort'])}</strong></dd>")
    body.append("</dl>")
    body.append("<h4>The defect</h4>" + para(f["what"]))
    body.append("<h4>Failure scenario</h4>" + para(f["scenario"]))
    body.append("<h4>Blast radius</h4>" + para(f["blast"]))
    body.append(f'<div class="good"><div class="calltitle">Remediation</div>{para(f["fix"])}'
                f'<p><strong>Acceptance:</strong> {md(f["accept"])}</p></div>')
    body.append(fixed_pill(f["fid"]))
    facets = f"sev:{f['sev'].lower()} blocks:{f['blocks']} effort:{f['effort'].lower()}"
    text = f"{f['fid']} {f['title']} {f['area']} {f['what']} {f['scenario']}"
    return (
        f'<details class="dos" data-facets="{facets}" data-text="{esc(text)}">'
        f'<summary><span class="did">{esc(f["fid"])}</span>'
        f'<span class="dname">{esc(f["title"])}'
        f'{" <span class='sev sev-low' style='background:var(--green);color:#fff'>FIXED</span>" if f["fid"] in FIXED else ""}'
        f'<span class="dpath">{esc(f["area"])} &middot; {esc(f["gate"])}</span></span>'
        f'{sev_pill(f["sev"])}<span class="tag tag-unverifiable" title="effort">{esc(f["effort"])}</span></summary>'
        f'<div class="body">{"".join(body)}</div></details>'
    )


def filter_bar(scope_id, groups, placeholder):
    chips = []
    for gname, vals in groups:
        for v, label in vals:
            chips.append(f'<button class="chip" data-group="{gname}" data-val="{v}">{esc(label)}</button>')
    return (
        f'<div class="filters">'
        f'<input type="search" placeholder="{esc(placeholder)}" aria-label="{esc(placeholder)}">'
        + "".join(chips) + '<span class="count"></span></div>'
    )
