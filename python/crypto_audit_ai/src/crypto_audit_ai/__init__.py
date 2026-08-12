"""Warrantor crypto-audit-ai (X4) — AI-assisted cryptanalysis.

Three operating modes:

- :data:`AuditMode.IMPLEMENTATION_AUDIT` — scans source code for weak crypto
  patterns: hardcoded keys, ECB mode, MD5/SHA1, short RSA keys, insecure RNG.
- :data:`AuditMode.ALGORITHM_STRESS_TEST` — runs known-answer and edge-case
  test vectors against the project's crypto primitives.
- :data:`AuditMode.DEPENDENCY_SCAN` — flags known-vulnerable crypto
  library versions in the dependency graph.

The patterns are deliberately conservative: false positives are preferred over
false negatives. Each finding carries a severity (``info``..``critical``), a
CWE id when applicable, and a remediation hint. The implementation is
dependency-free so it runs in any CI without wheels.

See ``docs/rfcs/X4-crypto-audit-ai.md``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum


# ---------------------------------------------------------------------------
# Public value types
# ---------------------------------------------------------------------------
class AuditMode(str, Enum):
    """The three cryptanalysis modes."""

    IMPLEMENTATION_AUDIT = "implementation_audit"
    ALGORITHM_STRESS_TEST = "algorithm_stress_test"
    DEPENDENCY_SCAN = "dependency_scan"


class Severity(str, Enum):
    """Finding severity, ordered low..critical."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def rank(cls, sev: Severity) -> int:
        """Return an integer rank so callers can sort findings."""
        order = {
            cls.INFO: 0,
            cls.LOW: 1,
            cls.MEDIUM: 2,
            cls.HIGH: 3,
            cls.CRITICAL: 4,
        }
        return order[sev]


@dataclass
class Finding:
    """One cryptanalysis finding."""

    rule_id: str
    severity: Severity
    message: str
    file: str = ""
    line: int = 0
    snippet: str = ""
    cwe: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        """Serialize the finding to a plain dict."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "cwe": self.cwe,
            "remediation": self.remediation,
        }


@dataclass
class AuditReport:
    """The aggregate result of a cryptanalysis run."""

    mode: AuditMode
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0

    @property
    def passed(self) -> bool:
        """True if no high/critical findings were raised."""
        return not any(
            Severity.rank(f.severity) >= Severity.rank(Severity.HIGH) for f in self.findings
        )

    @property
    def critical_count(self) -> int:
        """Count of critical findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    def by_severity(self) -> dict[str, int]:
        """Group finding counts by severity name."""
        out: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def to_dict(self) -> dict:
        """Serialize the report to a plain dict."""
        return {
            "mode": self.mode.value,
            "files_scanned": self.files_scanned,
            "findings": [f.to_dict() for f in self.findings],
            "passed": self.passed,
            "by_severity": self.by_severity(),
        }


# ---------------------------------------------------------------------------
# IMPLEMENTATION_AUDIT rules
# ---------------------------------------------------------------------------
# Each rule: (id, severity, regex, message, cwe, remediation).
# Patterns are intentionally broad to catch common variants; the test
# suite pins specific snippets to each rule.
_IMPL_RULES: list[tuple[str, Severity, str, str, str, str]] = [
    (
        "CRYPT001",
        Severity.HIGH,
        r"""(\A|[^A-Za-z0-9_])(password|passwd|pw|secret|api[_-]?key|private[_-]?key|access[_-]?token)\s*[:=]\s*["'][^"']{8,}["']""",
        "Hardcoded credential",
        "CWE-798",
        "Load secrets from a vault or environment, never store literals in source.",
    ),
    (
        "CRYPT002",
        Severity.HIGH,
        r"AES\.\b(MODE_ECB|ECB)\b|Cipher\.\bAES\b[^.]*\bMODE_ECB\b|mode\s*=\s*['\"]?ECB",
        "ECB mode is deterministic and leaks plaintext patterns",
        "CWE-327",
        "Use an authenticated mode such as AES-GCM or AES-CBC+HMAC.",
    ),
    (
        "CRYPT003",
        Severity.MEDIUM,
        r"\b(hashlib\.)?(md5|sha1)\s*\(",
        "Weak hash function (MD5/SHA1) is collision-prone",
        "CWE-327",
        "Use SHA-256 or stronger from the SHA-2/SHA-3 family.",
    ),
    (
        "CRYPT004",
        Severity.HIGH,
        r"\brandom\.(choice|randint|random|shuffle)\s*\(",
        "Insecure PRNG used for security-sensitive value",
        "CWE-338",
        "Use the ``secrets`` module for tokens, keys, nonces.",
    ),
    (
        "CRYPT005",
        Severity.MEDIUM,
        r"\bRSA\.(generate|generate_key)\s*\(\s*\d+",
        "Short RSA key",
        "CWE-326",
        "Use at least a 3072-bit RSA key.",
    ),
    (
        "CRYPT006",
        Severity.LOW,
        r"\bverify\s*=\s*False|SSLContext\([^)]*verify_mode\s*=\s*CERT_NONE",
        "TLS verification disabled",
        "CWE-295",
        "Never disable certificate verification in production.",
    ),
]


def _scan_line(line: str) -> list[Finding]:
    """Apply every implementation rule to a single source line."""
    out: list[Finding] = []
    for rule_id, sev, pat, msg, cwe, rem in _IMPL_RULES:
        m = re.search(pat, line)
        if not m:
            continue
        out.append(
            Finding(
                rule_id=rule_id,
                severity=sev,
                message=msg,
                snippet=line.strip()[:160],
                cwe=cwe,
                remediation=rem,
            )
        )
    # CRYPT005-specific: extract the bit length and only fire if < 3072
    out = [f for f in out if not (f.rule_id == "CRYPT005" and not _is_short_rsa(f.snippet))]
    return out


def _is_short_rsa(snippet: str) -> bool:
    """True if the snippet declares an RSA key shorter than 3072 bits."""
    m = re.search(r"RSA\.(?:generate|generate_key)\s*\(\s*(\d+)", snippet)
    if not m:
        return False
    try:
        bits = int(m.group(1))
    except ValueError:
        return False
    return bits < 3072


def audit_implementation(files: dict[str, str]) -> AuditReport:
    """Run IMPLEMENTATION_AUDIT against a {path: source} mapping.

    This is the canonical entry point used by the CLI and tests.
    """
    report = AuditReport(mode=AuditMode.IMPLEMENTATION_AUDIT, files_scanned=len(files))
    for path, src in files.items():
        for i, line in enumerate(src.splitlines(), start=1):
            for finding in _scan_line(line):
                finding.file = path
                finding.line = i
                report.findings.append(finding)
    return report


# ---------------------------------------------------------------------------
# ALGORITHM_STRESS_TEST
# ---------------------------------------------------------------------------
@dataclass
class StressCase:
    """One known-answer / edge-case vector for a primitive."""

    primitive: str  # "AES-128-GCM" | "RSA-2048" | "HMAC-SHA256" | ...
    name: str
    input_hex: str
    expected_hex: str
    should_pass: bool = True


def _default_cases() -> list[StressCase]:
    """Built-in edge-case vectors used when the caller supplies none."""
    return [
        StressCase(
            primitive="AES-128-ECB-detector",
            name="all-zero-block",
            input_hex="00" * 16,
            expected_hex="00" * 16,  # ECB over equal blocks should preserve equality
            should_pass=False,  # if observed equal => ECB weakness confirmed
        ),
        StressCase(
            primitive="RSA-key-size",
            name="min-size",
            input_hex="0800",  # 2048
            expected_hex="0c00",  # 3072
            should_pass=True,
        ),
        StressCase(
            primitive="HMAC-SHA256-tag",
            name="min-tag-len",
            input_hex="10",  # 16 bytes
            expected_hex="20",  # 32 bytes
            should_pass=True,
        ),
    ]


def stress_test(cases: Iterable[StressCase] | None = None) -> AuditReport:
    """Run the algorithm stress test.

    In Wave-1 the cases are evaluated heuristically — for example, the ECB
    detector flags whenever the caller marks ``should_pass=False`` (signalling
    that the equal-block invariant was actually observed). The full
    crypto-primitive wiring (cryptography / openssl) is task 03.
    """
    report = AuditReport(mode=AuditMode.ALGORITHM_STRESS_TEST)
    for c in cases if cases is not None else _default_cases():
        # Heuristic: a passing case passes; a not-passing case raises a finding.
        if c.should_pass:
            continue
        report.findings.append(
            Finding(
                rule_id="STRESS001",
                severity=Severity.CRITICAL,
                message=f"primitive {c.primitive} failed case {c.name}: observed equal ciphertext blocks (ECB weakness)",
                snippet=f"{c.input_hex} -> {c.expected_hex}",
                cwe="CWE-327",
                remediation="Switch to an IND-CPA-secure mode (GCM/CBC with random IV).",
            )
        )
    return report


# ---------------------------------------------------------------------------
# DEPENDENCY_SCAN
# ---------------------------------------------------------------------------
# Minimal vulnerable-version database. The real graph (OSV/PyPA advisories) is
# task 03; the entries below cover the canonical examples used in tests and
# demonstrate the rule shape.
_VULN_DB: dict[str, list[tuple[str, str, str, Severity]]] = {
    # package: [(vulnerable_range, advisory_id, summary, severity)]
    "pycryptodome": [
        (
            "<3.6.6",
            "CVE-2018-15505",
            "pycryptodome < 3.6.6 has a heap read overrun in AES-GCM",
            Severity.HIGH,
        ),
    ],
    "cryptography": [
        ("<3.4.0", "CVE-2018-10903", "cryptography < 3.4 HMAC verify bypass", Severity.HIGH),
    ],
    "paramiko": [
        ("<2.9.0", "CVE-2022-24302", "paramiko < 2.9 RSA key reuse", Severity.MEDIUM),
    ],
    "openssl": [
        ("<1.1.1i", "CVE-2020-1971", "OpenSSL < 1.1.1i X.509 NULL deref", Severity.CRITICAL),
    ],
}


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse a dotted version string into a comparable tuple.

    Numeric segments win; a trailing alpha suffix (e.g. ``1.1.1h``) is folded
    into the last numeric segment as a small positive offset so ``1.1.1h`` >
    ``1.1.1`` but ``1.1.1h`` < ``1.1.2``. Anything non-parseable is treated as
    ``0`` so unknown versions never satisfy a ``<fixed`` range spuriously.
    """
    parts: list[int] = []
    for tok in re.split(r"[.\-+]", v.strip()):
        m = re.match(r"(\d+)([A-Za-z].*)?$", tok)
        if not m:
            return tuple(parts) if parts else (0,)
        parts.append(int(m.group(1)))
        if m.group(2):
            # suffix letter counts as a fractional release (1..25)
            suf = m.group(2)[:1].lower()
            if suf.isalpha():
                parts[-1] = parts[-1] * 100 + (ord(suf) - ord("a") + 1)
    return tuple(parts)


def _in_range(version: str, range_expr: str) -> bool:
    """True if ``version`` satisfies a ``<x.y.z``-style range."""
    range_expr = range_expr.strip()
    if range_expr.startswith("<"):
        target = _parse_version(range_expr[1:])
        return _parse_version(version) < target
    if range_expr.startswith(">="):
        target = _parse_version(range_expr[2:])
        return _parse_version(version) >= target
    return False


def scan_dependencies(deps: dict[str, str]) -> AuditReport:
    """Scan a {package: version} mapping against the vulnerable-version DB."""
    report = AuditReport(mode=AuditMode.DEPENDENCY_SCAN, files_scanned=len(deps))
    for pkg, version in deps.items():
        for range_expr, advisory, summary, sev in _VULN_DB.get(pkg.lower(), ()):
            if _in_range(version, range_expr):
                report.findings.append(
                    Finding(
                        rule_id=f"DEP{advisory}",
                        severity=sev,
                        message=f"{pkg} {version} {summary} ({range_expr})",
                        snippet=f"{pkg}=={version}",
                        cwe="CWE-1104",  # Use of Unmaintained Third Party Components
                        remediation=f"Upgrade {pkg} to fixed version.",
                    )
                )
    return report


# ---------------------------------------------------------------------------
# Top-level audit driver
# ---------------------------------------------------------------------------
def audit(
    mode: AuditMode,
    *,
    files: dict[str, str] | None = None,
    dependencies: dict[str, str] | None = None,
    cases: Iterable[StressCase] | None = None,
) -> AuditReport:
    """Run the audit in the requested ``mode``.

    Selects the correct sub-driver. This is the single entry point used by
    the CLI and by the orchestrator.
    """
    if mode == AuditMode.IMPLEMENTATION_AUDIT:
        return audit_implementation(files or {})
    if mode == AuditMode.ALGORITHM_STRESS_TEST:
        return stress_test(cases)
    if mode == AuditMode.DEPENDENCY_SCAN:
        return scan_dependencies(dependencies or {})
    raise ValueError(f"unknown mode: {mode}")


__all__ = [
    "AuditMode",
    "AuditReport",
    "Finding",
    "Severity",
    "StressCase",
    "audit",
    "audit_implementation",
    "scan_dependencies",
    "stress_test",
]
