#!/usr/bin/env python3
"""Inspect the shipped implementation-audit HTML (not a copy, not a fixture).

Drives the real file at aumos/docs/html/warrantor-implementation-audit-and-pending-2026-08-19.html
and asserts the gating observations from the 2026-08-19 audit goal.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

HTML_DIR = Path(__file__).resolve().parent.parent
SHIPPED = HTML_DIR / "warrantor-implementation-audit-and-pending-2026-08-19.html"
AUMOS_ROOT = HTML_DIR.parent.parent
WORKSPACE_ROOT = AUMOS_ROOT.parent

MIN_CHARS = 40_000
COVERAGE = ("rust", "python", "go", "typescript", "desktop")
CLASS_LABELS = (
    "engineering",
    "product-decision",
    "procurement-or-credential",
    "unfixable-under-current-model",
)
SKIP_CITE = re.compile(
    r"^(https?:|w1\b|rfc\b|head\b|dea7cdd|wrt_|spiffe:|get |post |sha256:)",
    re.IGNORECASE,
)
PATHISH = re.compile(
    r"(?:aumos/|[A-Za-z0-9_.-]+/(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+|[A-Za-z0-9_.-]+\.(?:rs|py|js|ts|md|html|cjs|yml|yaml|toml|proto|json|css))"
)


def shipped_html() -> str:
    assert SHIPPED.is_file(), f"missing shipped HTML: {SHIPPED}"
    return SHIPPED.read_text(encoding="utf-8")


def candidate_roots() -> list[Path]:
    return [WORKSPACE_ROOT, AUMOS_ROOT, HTML_DIR]


def resolve_citation(cite: str) -> Path | None:
    cleaned = cite.strip().strip("`").replace("\\", "/")
    if not cleaned or SKIP_CITE.search(cleaned):
        return None
    if " " in cleaned and not cleaned.endswith((".rs", ".py", ".js", ".md", ".html")):
        return None
    if not PATHISH.search(cleaned) and "/" not in cleaned and "\\" not in cleaned:
        return None
    # W1 section labels like "W1 §3.1"
    if cleaned.lower().startswith("w1"):
        return None
    for root in candidate_roots():
        for variant in (cleaned, cleaned.removeprefix("aumos/")):
            path = (root / variant).resolve()
            try:
                path.relative_to(WORKSPACE_ROOT.resolve())
            except ValueError:
                continue
            if path.exists():
                return path
    return None


def test_document_shell() -> None:
    text = shipped_html()
    head = text[:800].lower()
    assert "<!doctype html>" in head, "missing doctype"
    assert re.search(r"<html\b[^>]*\blang=", text, re.IGNORECASE), "missing lang="
    title_match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    assert title_match, "missing title"
    title = re.sub(r"\s+", " ", title_match.group(1)).lower()
    assert "implementation" in title or "analysis" in title, title
    assert "pending" in title, title


def test_anthropic_tokens() -> None:
    text = shipped_html()
    assert "#d97757" in text or "--accent" in text
    assert "#faf9f7" in text or "--bg-primary" in text
    assert "Georgia" in text or "--font-serif" in text or "font-serif" in text
    assert "serif" in text.lower()


def test_regions_and_depth() -> None:
    text = shipped_html()
    assert len(text) >= MIN_CHARS, f"stub document: {len(text)} < {MIN_CHARS}"
    assert 'id="analysis-rust-warrant"' in text
    assert 'id="analysis-python"' in text
    assert 'id="analysis-go"' in text
    assert 'id="analysis-typescript"' in text
    assert 'id="analysis-desktop"' in text
    assert 'id="analysis-ml-guard"' in text
    assert 'id="pending"' in text
    assert "current implementation" in text.lower() or "implementation analysis" in text.lower()
    assert "pending" in text.lower()


def test_coverage_strings() -> None:
    text = shipped_html().lower()
    for word in COVERAGE:
        assert word in text, f"missing coverage string {word!r}"
    assert "guard" in text and ("ml / guard" in text or "ml/guard" in text or "warrantor_ml" in text)


def test_head_and_date() -> None:
    text = shipped_html()
    assert "dea7cdd" in text
    assert "2026-08-19" in text


def test_pending_items_and_classes() -> None:
    text = shipped_html()
    pending = text.split('id="pending"', 1)[1]
    for label in CLASS_LABELS:
        assert label in pending, f"pending region missing class {label}"
    item_ids = re.findall(r'id="(pending-[a-z0-9-]+)"', pending)
    assert len(set(item_ids)) >= 8, f"too few named pending items: {item_ids}"
    # Still-open W1 items must not be described as shipped in the pending register.
    forbidden_shipped = (
        "§3.1 is closed",
        "sandbox observation is shipped",
        "http settle auto-file is shipped",
        "change feed is shipped",
        "enforcing guard is on by default",
    )
    lowered = pending.lower()
    for phrase in forbidden_shipped:
        assert phrase not in lowered, phrase
    # Spot-check still-open W1 / HANDOFF items are described as open in the shipped page.
    still_open = (
        "w1 §3.1 is not closed",
        "no installer has been installed or launched on macos",
        "do not auto-file",
        "deliberately off",
        "hf_token",
    )
    whole = text.lower()
    for phrase in still_open:
        assert phrase in whole, f"missing still-open wording: {phrase}"


def test_path_citations_resolve() -> None:
    text = shipped_html()
    cites = re.findall(r"<code>([^<]{3,160})</code>", text)
    resolved: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw in cites:
        if raw in seen:
            continue
        seen.add(raw)
        path = resolve_citation(raw)
        if path is not None:
            resolved.append((raw, str(path)))
    assert len(resolved) >= 15, (
        f"only {len(resolved)} citations resolved under the workspace; "
        f"sample={cites[:12]}"
    )


def main() -> int:
    tests = [
        test_document_shell,
        test_anthropic_tokens,
        test_regions_and_depth,
        test_coverage_strings,
        test_head_and_date,
        test_pending_items_and_classes,
        test_path_citations_resolve,
    ]
    failed = 0
    for fn in tests:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {fn.__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001 — report unexpected errors as test failures
            failed += 1
            print(f"ERROR {fn.__name__}: {type(exc).__name__}: {exc}")
    print(f"shipped={SHIPPED}")
    print(f"{len(tests) - failed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
