"""Tests for bias-sentinel: BOLD/HONEST/CrowS-Pairs/WinoBias + n-gram copyright."""

from __future__ import annotations

from bias_sentinel import (
    bold_detect,
    copyright_detect,
    crows_pairs_detect,
    honest_detect,
    run_bias_audit,
    run_copyright_audit,
    winobias_detect,
)


# ---------- BOLD ----------
def test_bold_counts_identity_mentions() -> None:
    samples = ["the woman is a doctor", "the man is a nurse", "an asian engineer"]
    findings = bold_detect(samples)
    groups = {f.evidence[0].split(":")[0] for f in findings}
    assert "gender" in groups
    assert "race" in groups


def test_bold_returns_empty_when_no_identity() -> None:
    findings = bold_detect(["the weather is nice"])
    assert findings == []


# ---------- HONEST ----------
def test_honest_flags_co_occurrence() -> None:
    samples = ["the muslim man was violent", "an asian student studied"]
    findings = honest_detect(samples)
    assert findings
    # at least one sample has identity + negative co-occurrence
    f = findings[0]
    assert f.score > 0
    assert f.severity in ("low", "medium", "high", "critical")


def test_honest_clean_when_no_co_occurrence() -> None:
    samples = ["the doctor was kind", "the engineer was brilliant"]
    findings = honest_detect(samples)
    assert findings[0].score == 0.0
    assert findings[0].severity == "info"


# ---------- CrowS-Pairs ----------
def test_crows_pairs_flags_stereo_negatives() -> None:
    pairs = [
        ("the black man was violent", "the white man was kind"),
        ("the doctor was skilled", "the doctor was skilled"),
    ]
    findings = crows_pairs_detect(pairs)
    assert findings[0].score == 0.5
    assert findings[0].severity == "critical"


def test_crows_pairs_clean_for_balanced_pairs() -> None:
    pairs = [
        ("the engineer was skilled", "the nurse was skilled"),
        ("the doctor was kind", "the doctor was kind"),
    ]
    findings = crows_pairs_detect(pairs)
    assert findings[0].score == 0.0


# ---------- WinoBias ----------
def test_winobias_detects_gender_skew() -> None:
    # 3 male-pronouned occupations vs 1 female-pronouned => skew 0.5
    samples = [
        "the doctor said he is tired",
        "the engineer said he is happy",
        "the ceo said he is busy",
        "the nurse said she is here",
    ]
    findings = winobias_detect(samples)
    f = findings[0]
    assert f.score > 0
    assert f.severity == "high"  # >= 0.3


def test_winobias_clean_for_balanced_pronouns() -> None:
    samples = [
        "the doctor said he is here",
        "the doctor said she is here",
    ]
    findings = winobias_detect(samples)
    assert findings[0].score == 0.0


def test_winobias_info_when_no_occupations() -> None:
    findings = winobias_detect(["the cat is on the mat"])
    assert findings[0].severity == "info"


# ---------- run_bias_audit ----------
def test_run_bias_audit_aggregates_all_detectors() -> None:
    samples = ["the muslim man was violent", "the nurse said she is happy"]
    report = run_bias_audit(samples)
    detectors = {f.detector for f in report.findings}
    assert "BOLD" in detectors
    assert "HONEST" in detectors
    assert "WinoBias" in detectors


def test_run_bias_audit_includes_crows_when_pairs_given() -> None:
    report = run_bias_audit(["x"], pairs=[("black violent", "white kind")])
    detectors = {f.detector for f in report.findings}
    assert "CrowS-Pairs" in detectors


# ---------- copyright_detect ----------
def test_copyright_flags_verbatim_ngram_overlap() -> None:
    ref = "the quick brown fox jumps over the lazy dog every single day at noon"
    sample = "I copied: the quick brown fox jumps over the lazy dog every single day at noon!"
    findings = copyright_detect([sample], {"book1": ref}, n=5)
    assert findings
    assert "book1" in findings[0].evidence[0]


def test_copyright_clean_for_no_overlap() -> None:
    ref = "completely different text about another topic entirely"
    sample = "this sample shares no five-word span with the reference at all"
    findings = copyright_detect([sample], {"book1": ref}, n=5)
    assert findings == []


def test_run_copyright_audit_report_passed_flag() -> None:
    ref = "a b c d e f g h i j k l m"
    sample = "a b c d e f g h i j k l m"
    report = run_copyright_audit([sample], {"x": ref}, n=5)
    assert not report.passed  # high/critical finding present


def test_run_copyright_audit_clean() -> None:
    report = run_copyright_audit(["hello there"], {"r": "goodbye now"}, n=3)
    assert report.passed
