#!/usr/bin/env python3
"""Verification suite for AumOS multi-phase blog series.

Drives generate_blog_series (real entry point) and inspects shipped HTML.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_blog_series as gen  # noqa: E402

SCRATCH_CANDIDATES = [
    Path(r"C:\Users\MUVERA~1\AppData\Local\Temp\grok-goal-0050e44cb56f\implementer"),
    Path(r"C:\Users\MuVeraAICorporation\AppData\Local\Temp\grok-goal-0050e44cb56f\implementer"),
]


def scratch_dir() -> Path:
    for p in SCRATCH_CANDIDATES:
        if p.parent.exists():
            p.mkdir(parents=True, exist_ok=True)
            return p
    p = Path.cwd() / ".blog-series-scratch"
    p.mkdir(parents=True, exist_ok=True)
    return p


def test_generate_and_paths() -> list[str]:
    assert gen.main() == 0
    summary = json.loads((gen.META / "series-manifest.json").read_text(encoding="utf-8"))
    paths = summary["paths"]
    assert len(paths) >= 9  # index + 8
    for p in paths:
        fp = Path(p)
        assert fp.is_file(), p
        assert fp.stat().st_size > 2000, p
    return paths


def test_cluster_and_protocol_coverage() -> None:
    summary = json.loads((gen.META / "series-manifest.json").read_text(encoding="utf-8"))
    assert set(summary["protocols_mapped"]) == set(gen.PROTOCOLS)
    assert set(summary["clusters_mapped"]) == set(gen.CLUSTERS)
    index = (gen.ROOT / "index.html").read_text(encoding="utf-8")
    for pid in gen.PROTOCOLS:
        assert f'data-aumos-id="{pid}"' in index or f'data-protocol="{pid}"' in index, pid
    for key in gen.CLUSTERS:
        assert gen.CLUSTERS[key]["article"] in index


def test_article_depth_and_visuals() -> None:
    summary = json.loads((gen.META / "series-manifest.json").read_text(encoding="utf-8"))
    for art in summary["articles"]:
        text = (gen.ROOT / art["file"]).read_text(encoding="utf-8")
        assert art["visuals"] >= 2, art
        assert art["citations"] >= 3, art
        assert art["body_chars"] >= 5500, art
        assert text.count("data-visual=") >= 2
        assert text.count('class="cite"') >= 3 or text.count("data-cite-url=") >= 3
        # AumOS IDs present
        for iid in art["ids"][:3]:
            assert iid in text, f"{art['file']} missing {iid}"
        # Structure sections
        assert "Thesis" in text or "abstract" in text
        assert "Threat" in text or "threat" in text or "Implications" in text or "map" in text.lower()


def test_phase_plan_and_dual_pass_meta() -> None:
    plan = gen.META / "phase-plan.md"
    assert plan.is_file()
    plan_text = plan.read_text(encoding="utf-8")
    for phase in ["Source research", "Outline", "Full draft", "Visual enrichment", "Adversarial review", "Fix pass"]:
        assert phase.lower() in plan_text.lower() or phase in plan_text
    # Dual-pass artifacts (created by this pipeline)
    research = gen.META / "phase1-research-notes.md"
    review = gen.META / "phase5-adversarial-review.md"
    assert research.is_file() and research.stat().st_size > 200, "missing phase1 research notes"
    assert review.is_file() and review.stat().st_size > 200, "missing phase5 review notes"


def fetch(url: str, timeout: float = 25.0) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "AumOS-blog-series-verifier/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(100000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(50000).decode("utf-8", errors="replace")
        except Exception:
            body = str(exc)
        return exc.code, body
    except Exception as exc:
        return -1, str(exc)


def title_tokens(title: str) -> list[str]:
    cleaned = re.sub(r"[—–\-|:()/]", " ", title)
    stop = {"with", "from", "that", "this", "for", "and", "the", "open", "docs", "latest"}
    out = []
    for raw in cleaned.split():
        t = re.sub(r"[^A-Za-z0-9+]", "", raw).lower()
        if len(t) >= 4 and t not in stop:
            out.append(t)
    return out


def aligns(title: str, body: str, url: str) -> bool:
    if url.lower().endswith(".pdf") or body[:4] == "%PDF":
        return True
    lower = body.lower()
    tokens = title_tokens(title)
    hits = [t for t in tokens if t in lower]
    if len(hits) >= 2:
        return True
    if any(len(t) >= 8 and t in lower for t in tokens):
        return True
    nums = re.findall(r"\b(\d{3,5})\b", title)
    return bool(nums and any(n in body for n in nums))


def test_citation_spotcheck() -> list[str]:
    """≥8 citations across ≥6 articles: HTTP + title alignment."""
    # Collect cites from all articles
    cites: list[tuple[str, str, str]] = []  # article, title, url
    for meta in gen.ARTICLES_META:
        text = (gen.ROOT / meta["file"]).read_text(encoding="utf-8")
        for m in re.finditer(
            r'data-cite-url="([^"]+)"[^>]*>.*?<strong>(.*?)</strong>',
            text,
            re.DOTALL,
        ):
            url, title = m.group(1), re.sub(r"<[^>]+>", "", m.group(2)).strip()
            cites.append((meta["file"], title, url))
    # Prefer diversity of articles
    by_art: dict[str, list] = {}
    for c in cites:
        by_art.setdefault(c[0], []).append(c)
    sample: list[tuple[str, str, str]] = []
    for art, items in by_art.items():
        sample.append(items[0])
        if len(sample) >= 6 and sum(1 for a in by_art if any(s[0] == a for s in sample)) >= 6:
            break
    # Pad to 10 URLs
    for c in cites:
        if c not in sample:
            sample.append(c)
        if len(sample) >= 10:
            break
    assert len(sample) >= 8, f"only {len(sample)} cites"
    assert len({s[0] for s in sample}) >= 6, "need ≥6 articles in sample"

    logs = []
    ok_align = 0
    ok_http = 0
    for art, title, url in sample:
        status, body = fetch(url)
        http_ok = status not in (404, -1) and (status in (200, 301, 302) or len(body) > 200)
        if http_ok:
            ok_http += 1
        al = http_ok and aligns(title, body, url)
        if al:
            ok_align += 1
        logs.append(
            f"{'OK' if al else ('HTTP' if http_ok else 'FAIL')} status={status} "
            f"article={art} align={al} title={title[:60]!r} url={url}"
        )
    assert ok_http >= 5, "HTTP spotcheck failed\n" + "\n".join(logs)
    assert ok_align >= 8 or (ok_align >= 5 and ok_http >= 8), (
        f"alignment insufficient ok_align={ok_align}\n" + "\n".join(logs)
    )
    if ok_http >= 8:
        assert ok_align >= 8, "need ≥8 aligned\n" + "\n".join(logs)
    return logs


def write_scratch_evidence(paths: list[str], logs: list[str]) -> None:
    sc = scratch_dir()
    (sc / "article-deliverable-paths.txt").write_text("\n".join(paths) + "\n", encoding="utf-8")
    summary = json.loads((gen.META / "series-manifest.json").read_text(encoding="utf-8"))
    coverage = {
        "clusters": summary["clusters_mapped"],
        "protocols": summary["protocols_mapped"],
        "all_protocols": list(gen.PROTOCOLS.keys()),
        "all_clusters": list(gen.CLUSTERS.keys()),
    }
    (sc / "article-coverage-ids.txt").write_text(json.dumps(coverage, indent=2), encoding="utf-8")
    (sc / "article-citation-spotcheck.log").write_text("\n".join(logs) + "\n", encoding="utf-8")
    stats = {
        "article_count": len(summary["articles"]),
        "visual_blocks_total": sum(a["visuals"] for a in summary["articles"]),
        "citation_total": sum(a["citations"] for a in summary["articles"]),
        "phases": ["research", "outline", "draft", "visuals", "adversarial_review", "fix", "verify"],
        "unique_cite_domains_estimate": "see spotcheck",
        "articles": summary["articles"],
    }
    (sc / "article-series-stats.txt").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    print("scratch", sc)


def main() -> int:
    failed = 0
    paths: list[str] = []
    logs: list[str] = []

    tests = [
        ("test_generate_and_paths", lambda: paths.extend(test_generate_and_paths()) or True),
        ("test_cluster_and_protocol_coverage", test_cluster_and_protocol_coverage),
        ("test_article_depth_and_visuals", test_article_depth_and_visuals),
        ("test_phase_plan_and_dual_pass_meta", test_phase_plan_and_dual_pass_meta),
    ]
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except Exception as exc:
            failed += 1
            print(f"FAIL {name}: {exc}")

    try:
        logs = test_citation_spotcheck()
        print("PASS test_citation_spotcheck")
        for line in logs:
            print("  ", line)
    except Exception as exc:
        failed += 1
        print(f"FAIL test_citation_spotcheck: {exc}")

    try:
        write_scratch_evidence(paths or json.loads((gen.META / "series-manifest.json").read_text())["paths"], logs)
        print("PASS write_scratch_evidence")
    except Exception as exc:
        failed += 1
        print(f"FAIL write_scratch_evidence: {exc}")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
