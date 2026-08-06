"""Tests for crypto-audit-ai: implementation audit, stress test, dependency scan."""

from __future__ import annotations

from crypto_audit_ai import (
    AuditMode,
    Finding,
    Severity,
    StressCase,
    audit,
    audit_implementation,
    scan_dependencies,
    stress_test,
)


# ---------- IMPLEMENTATION_AUDIT ----------
def test_detects_hardcoded_api_key() -> None:
    files = {"app.py": 'api_key = "sk-1234567890abcdef"'}
    report = audit_implementation(files)
    ids = {f.rule_id for f in report.findings}
    assert "CRYPT001" in ids
    finding = next(f for f in report.findings if f.rule_id == "CRYPT001")
    assert finding.severity == Severity.HIGH
    assert finding.cwe == "CWE-798"
    assert finding.line == 1


def test_detects_ecb_mode() -> None:
    files = {"crypto.py": "cipher = AES.new(key, AES.MODE_ECB)"}
    report = audit_implementation(files)
    ids = {f.rule_id for f in report.findings}
    assert "CRYPT002" in ids


def test_detects_md5_and_sha1() -> None:
    files = {
        "h.py": "h = hashlib.md5(data)",
        "h2.py": "h = sha1(b'x')",
    }
    report = audit_implementation(files)
    md5 = [f for f in report.findings if f.rule_id == "CRYPT003"]
    assert len(md5) >= 2
    assert all(f.severity == Severity.MEDIUM for f in md5)


def test_detects_insecure_prng() -> None:
    files = {"t.py": "tok = ''.join(random.choice(alphabet) for _ in range(32))"}
    report = audit_implementation(files)
    assert any(f.rule_id == "CRYPT004" for f in report.findings)


def test_detects_short_rsa_key() -> None:
    files = {"k.py": "private = RSA.generate(2048)"}
    report = audit_implementation(files)
    rsa = [f for f in report.findings if f.rule_id == "CRYPT005"]
    assert len(rsa) == 1


def test_does_not_flag_strong_rsa_key() -> None:
    files = {"k.py": "private = RSA.generate(4096)"}
    report = audit_implementation(files)
    rsa = [f for f in report.findings if f.rule_id == "CRYPT005"]
    assert rsa == []


def test_implementation_report_passed_only_when_no_high() -> None:
    files = {"t.py": "# all clear"}
    report = audit_implementation(files)
    assert report.passed
    assert report.critical_count == 0


def test_by_severity_groups_findings() -> None:
    files = {
        "a.py": 'password = "supersecretvalue"',
        "b.py": "h = hashlib.md5(b'x')",
    }
    report = audit_implementation(files)
    sev = report.by_severity()
    assert sev["high"] >= 1
    assert sev["medium"] >= 1


# ---------- ALGORITHM_STRESS_TEST ----------
def test_stress_test_fails_on_ecb_invariant() -> None:
    cases = [
        StressCase(
            primitive="AES-128-ECB-detector",
            name="equal-blocks",
            input_hex="00" * 32,
            expected_hex="00" * 32,
            should_pass=False,
        )
    ]
    report = stress_test(cases)
    assert report.critical_count == 1
    assert report.findings[0].rule_id == "STRESS001"


def test_stress_test_passes_with_all_green_cases() -> None:
    cases = [
        StressCase(primitive="RSA-key-size", name="ok", input_hex="x", expected_hex="y", should_pass=True)
    ]
    report = stress_test(cases)
    assert report.passed
    assert report.findings == []


def test_default_stress_cases_run_without_error() -> None:
    report = stress_test()
    assert report.mode == AuditMode.ALGORITHM_STRESS_TEST


# ---------- DEPENDENCY_SCAN ----------
def test_dependency_scan_flags_known_vulnerable_version() -> None:
    report = scan_dependencies({"pycryptodome": "3.6.5"})
    ids = {f.rule_id for f in report.findings}
    assert "DEPCVE-2018-15505" in ids


def test_dependency_scan_skips_fixed_version() -> None:
    report = scan_dependencies({"pycryptodome": "3.6.6"})
    assert report.findings == []


def test_dependency_scan_handles_critical_severity() -> None:
    report = scan_dependencies({"openssl": "1.1.1h"})
    assert any(f.severity == Severity.CRITICAL for f in report.findings)


def test_dependency_scan_reports_unknown_package_clean() -> None:
    report = scan_dependencies({"unknown-pkg": "1.0.0"})
    assert report.findings == []
    assert report.passed


# ---------- Top-level driver ----------
def test_audit_dispatches_by_mode() -> None:
    r1 = audit(AuditMode.IMPLEMENTATION_AUDIT, files={"a.py": 'pw = "secretvalue123"'})
    assert r1.mode == AuditMode.IMPLEMENTATION_AUDIT
    assert not r1.passed

    r2 = audit(AuditMode.DEPENDENCY_SCAN, dependencies={"openssl": "1.1.1a"})
    assert not r2.passed

    r3 = audit(AuditMode.ALGORITHM_STRESS_TEST)
    assert r3.mode == AuditMode.ALGORITHM_STRESS_TEST
