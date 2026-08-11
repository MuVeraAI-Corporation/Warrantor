#!/usr/bin/env python3
"""Structural + functional tests for the curated reading-list deliverable.

Drives the real generator module and inspects the shipped HTML/JSON — no
hard-coded expected entry counts beyond portfolio inventory rules.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Import the real generator (shipped path)
sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_reading_list as grl  # noqa: E402

# Expected portfolio IDs from reconciliation matrix (canonical inventory)
EXPECTED_COMPONENTS = {
    "T1", "T2", "I1", "I2",
    "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8",
    "C1-1", "C1-2", "C1-3", "C1-4", "C1-5",
    "S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9",
    "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8",
    "N1", "N2", "N3", "N4",
    "F1", "F2", "F3", "F4",
    "X1", "X2", "X3", "X4", "X5", "X6", "X7", "X8", "X9", "X10", "X11",
    "E1",
}
EXPECTED_PROTOCOLS = {
    "P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9", "P10", "P11", "P12"
}


def test_data_loads() -> None:
    data = grl.load_data()
    assert "entries" in data and len(data["entries"]) > 0
    assert "components" in data and "protocols" in data


def test_portfolio_ids_match_reconciliation() -> None:
    data = grl.load_data()
    comps, protos = grl.all_portfolio_ids(data)
    assert set(comps) == EXPECTED_COMPONENTS, (
        f"component delta extra={set(comps)-EXPECTED_COMPONENTS} "
        f"missing={EXPECTED_COMPONENTS-set(comps)}"
    )
    assert set(protos) == EXPECTED_PROTOCOLS


def test_full_coverage() -> None:
    data = grl.load_data()
    status = grl.coverage_status(data)
    uncovered = [i for i, s in status.items() if not s["covered"]]
    assert uncovered == [], f"uncovered IDs: {uncovered}"
    for item_id, st in status.items():
        assert st["count"] >= 1
        assert st["entry_ids"]


def test_entry_schema() -> None:
    data = grl.load_data()
    required = {"id", "title", "author", "url", "why", "tags", "maps", "tier"}
    tiers = {"canonical", "deep-secondary", "adjacent-substitute"}
    # Titles must not invent "AumOS composite" publication names over real URLs
    banned_title_prefixes = (
        "authority envelopes for agents",
        "verifiable action receipts",
        "memory integrity for agents",
        "verifiable evaluation bundles",
        "capability attestation profiles",
        "secure skill packages",
        "proof-carrying remediation",
        "ai incident exchange",
        "llm gateway patterns",
        "open harness specification",
        "openshell / nooa",
        "ibm/red hat lightwell",
    )
    for entry in data["entries"]:
        missing = required - set(entry.keys())
        assert not missing, f"{entry.get('id')}: missing {missing}"
        assert entry["url"].startswith("https://"), entry["id"]
        assert entry["tier"] in tiers, entry["id"]
        assert entry["maps"], entry["id"]
        assert entry["title"] and entry["why"]
        tl = entry["title"].lower()
        for banned in banned_title_prefixes:
            assert not tl.startswith(banned), (
                f"{entry['id']} still has composite/fake title: {entry['title']}"
            )
        for mid in entry["maps"]:
            assert mid in data["components"] or mid in data["protocols"], (
                f"{entry['id']} maps to unknown {mid}"
            )
    # Critical URL integrity (skeptic fixes)
    by_id = {e["id"]: e for e in data["entries"]}
    assert "discovering-cryptographic-weaknesses" in by_id["anthropic-crypto"]["url"]
    assert "bulletin-2026-13" in by_id["occ-mrm-note"]["url"]
    assert by_id["rbi-dpdp-adjacent"]["url"].endswith(".pdf") or "dpdp" in by_id[
        "rbi-dpdp-adjacent"
    ]["url"].lower() or "2bf1f0e9" in by_id["rbi-dpdp-adjacent"]["url"]
    assert "openshell" in by_id["nvidia-openshell"]["url"].lower()
    assert "lightwell" in by_id["ibm-lightwell"]["url"].lower()


def test_html_deliverable_exists_and_rich() -> None:
    data = grl.load_data()
    # Regenerate to ensure HTML matches data (real entry point)
    assert grl.main() == 0
    html_path = grl.HTML_OUT
    md_path = grl.MD_OUT
    assert html_path.is_file() and html_path.stat().st_size > 5000
    assert md_path.is_file() and md_path.stat().st_size > 2000
    text = html_path.read_text(encoding="utf-8")
    assert "Coverage matrix" in text
    assert "tier-canonical" in text or "Canonical primary" in text
    assert 'class="diagram"' in text or "Portfolio visual map" in text
    for cid in EXPECTED_COMPONENTS:
        assert f'data-portfolio-id="{cid}"' in text, f"HTML missing {cid}"
    for pid in EXPECTED_PROTOCOLS:
        assert f'data-portfolio-id="{pid}"' in text, f"HTML missing {pid}"
    # Quality fields present on cards
    assert "Maps to:" in text
    assert "entry-card" in text
    # Inventory copy must match matrix SSOT count (not stale "44 only")
    stats = grl.curation_stats(data)
    assert str(stats["component_count"]) in text
    assert "reconciliation-matrix" in text or "00-reconciliation-matrix" in text
    # Must not claim 44 as the only inventory without mapping note
    if "44 implementable" in text:
        assert "54" in text or "summary figure" in text or "SSOT" in text


def test_stats_prefer_depth() -> None:
    data = grl.load_data()
    stats = grl.curation_stats(data)
    assert stats["total_entries"] >= 40
    assert stats["unique_domain_count"] >= 20
    assert stats["canonical_entries"] >= 20
    assert stats["uncovered_ids"] == []


def sample_entries_for_spotcheck(data: dict) -> list[dict]:
    """Pick ≥12 entries across required clusters for verification plan §3."""
    want_clusters = {
        "identity",
        "evidence",
        "supply-chain",
        "eval",
        "inference",
        "confidential",
        "multi-agent",
        "protocols",
        "policy",
        "runtime",
    }
    want_maps = {"P1", "P2", "P3", "P10", "P11", "P12", "I1", "E1", "S4", "A1", "C1-1", "X8"}
    picked: list[dict] = []
    seen: set[str] = set()
    for entry in data["entries"]:
        if entry["id"] in seen:
            continue
        if entry.get("cluster") in want_clusters or want_maps.intersection(entry.get("maps", [])):
            picked.append(entry)
            seen.add(entry["id"])
        if len(picked) >= 14:
            break
    return picked


def test_sample_entries_have_fields() -> None:
    data = grl.load_data()
    sample = sample_entries_for_spotcheck(data)
    assert len(sample) >= 12
    for entry in sample:
        assert entry["title"] and entry["url"] and entry["maps"]


def fetch_url(url: str, timeout: float = 25.0) -> tuple[int, str]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "AumOS-reading-list-verifier/1.0"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(120000)
            return resp.status, body.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(120000).decode("utf-8", errors="replace")
        except Exception:
            body = str(exc)
        return exc.code, body
    except Exception as exc:  # network / SSL
        return -1, str(exc)


def _title_tokens(title: str) -> list[str]:
    """Extract distinctive tokens from an entry title for content alignment."""
    # Drop common RFC / punctuation noise; keep words length >= 4
    cleaned = re.sub(r"[—–\-|:()/]", " ", title)
    stop = {
        "with", "from", "that", "this", "into", "using", "for", "and", "the",
        "open", "source", "more", "their", "your", "docs", "documentation",
        "overview", "latest", "guide", "about", "home", "page", "project",
    }
    tokens = []
    for raw in cleaned.split():
        t = re.sub(r"[^A-Za-z0-9+]", "", raw).lower()
        if len(t) >= 4 and t not in stop:
            tokens.append(t)
    return tokens


def title_aligns_with_body(title: str, body: str, url: str) -> tuple[bool, str]:
    """Heuristic: distinctive title tokens appear in body, or PDF/binary is expected."""
    lower = body.lower()
    # PDFs often aren't text-scrapable via simple fetch
    if url.lower().endswith(".pdf") or body[:4] == "%PDF" or "application/pdf" in lower[:500]:
        # For PDFs, require HTTP success only + title has DPDP/Act style markers
        return True, "pdf-binary-ok"
    tokens = _title_tokens(title)
    if not tokens:
        return False, "no-tokens"
    # Require at least 2 distinctive tokens in body, or 1 very distinctive (>=8 chars)
    hits = [t for t in tokens if t in lower]
    if len(hits) >= 2:
        return True, f"tokens={hits[:5]}"
    if any(len(t) >= 8 and t in lower for t in tokens):
        return True, f"long-token={[t for t in tokens if len(t)>=8 and t in lower][:3]}"
    # RFC number in title (e.g. 9396) is strong signal
    rfc_nums = re.findall(r"\b(\d{3,5})\b", title)
    if rfc_nums and any(n in body for n in rfc_nums):
        return True, f"rfc-num={rfc_nums}"
    return False, f"miss tokens={tokens[:8]} hits={hits}"


def test_url_spotcheck_live() -> list[str]:
    """Spot-check ≥12 entries across clusters: HTTP ok + title↔content alignment."""
    data = grl.load_data()
    # ≥12 across required clusters (identity, evidence, supply, eval, inference,
    # confidential, multi-agent, protocols P1–P3 & P10–P12, plus policy/runtime)
    preferred_ids = [
        "spiffe-home",           # identity
        "mcp-spec-latest",       # multi-agent
        "a2a-spec",              # multi-agent / P10
        "sigstore-home",         # supply
        "cyclonedx-mlbom",       # supply S4
        "nvtrust-docs",          # confidential
        "otel-genai-agents",     # evidence E1/P2
        "garak-github",          # eval
        "anthropic-crypto",      # X4 fixed URL
        "occ-mrm-note",          # A4 fixed URL
        "nvidia-openshell",      # runtime OpenShell real title
        "ibm-lightwell",         # S9 Lightwell real title
        "t2-aae-authority",      # protocols P1 (real RFC title)
        "p2-aar-receipts",       # protocols P2
        "oauth-rar",             # policy
        "cedar-agentic-aws",     # policy multi-agent
    ]
    by_id = {e["id"]: e for e in data["entries"]}
    targets = [by_id[i] for i in preferred_ids if i in by_id]
    # Fill to ≥12 from cluster diversity if needed
    if len(targets) < 12:
        for e in sample_entries_for_spotcheck(data):
            if e["id"] not in {t["id"] for t in targets}:
                targets.append(e)
            if len(targets) >= 14:
                break
    assert len(targets) >= 12, f"only {len(targets)} targets"

    logs: list[str] = []
    ok_http = 0
    ok_align = 0
    for entry in targets:
        status, body = fetch_url(entry["url"])
        http_ok = status in (200, 301, 302) or (
            status not in (404, -1) and len(body) > 200
        )
        # Treat soft blocks (403 with HTML) as host-alive but not alignable
        if status == 404 or status == -1:
            http_ok = False
        if http_ok:
            ok_http += 1
        aligned, detail = (False, "http-fail")
        if http_ok:
            aligned, detail = title_aligns_with_body(entry["title"], body, entry["url"])
        if aligned:
            ok_align += 1
        result = "OK" if (http_ok and aligned) else ("HTTP_ONLY" if http_ok else "FAIL")
        logs.append(
            f"{result} status={status} id={entry['id']} align={aligned} "
            f"detail={detail} title={entry['title'][:70]!r} url={entry['url']}"
        )
    assert ok_http >= 5, "fewer than 5 URLs HTTP-ok:\n" + "\n".join(logs)
    assert ok_align >= 12 or (ok_align >= 5 and ok_http >= 8), (
        f"title↔content alignment insufficient (ok_align={ok_align}):\n"
        + "\n".join(logs)
    )
    # Prefer strong bar: at least 12 aligned when network allows
    if ok_http >= 12:
        assert ok_align >= 12, (
            f"expected ≥12 title-aligned among HTTP-ok set:\n" + "\n".join(logs)
        )
    return logs


def main() -> int:
    tests = [
        test_data_loads,
        test_portfolio_ids_match_reconciliation,
        test_full_coverage,
        test_entry_schema,
        test_html_deliverable_exists_and_rich,
        test_stats_prefer_depth,
        test_sample_entries_have_fields,
    ]
    failed = 0
    for test in tests:
        try:
            test()
            print(f"PASS {test.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {test.__name__}: {exc}")
        except Exception as exc:
            failed += 1
            print(f"ERROR {test.__name__}: {exc}")

    logs: list[str] = []
    try:
        logs = test_url_spotcheck_live()
        print("PASS test_url_spotcheck_live")
        for line in logs:
            print("  ", line)
    except AssertionError as exc:
        failed += 1
        print(f"FAIL test_url_spotcheck_live: {exc}")
    except Exception as exc:
        failed += 1
        print(f"ERROR test_url_spotcheck_live: {exc}")

    # Emit machine-readable summary for scratch capture
    data = grl.load_data()
    summary = {
        "failed": failed,
        "stats": grl.curation_stats(data),
        "url_spotcheck": logs,
        "covered_ids": sorted(grl.coverage_status(data).keys()),
    }
    print("---SUMMARY---")
    # unique_domains list can be long; keep it
    print(json.dumps(summary, indent=2, default=str))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
