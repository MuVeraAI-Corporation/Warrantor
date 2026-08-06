"""AumOS comply-gate (A4) — CI/CD compliance gates.

Parses a ``.complygate.yml`` config and enforces four gate types:

- :data:`GateType.TEST_COVERAGE`  — minimum line coverage threshold.
- :data:`GateType.SBOM_PRESENT`   — requires an SBOM file to exist.
- :data:`GateType.EVAL_PASSED`    — requires the latest eval run to pass.
- :data:`GateType.DISCLOSURE_FILED` — requires a vulnerability disclosure.

Plus **break-glass overrides**: a gate failure can be overridden, but only
with two mandatory approvers (no single-approver bypasses).

The YAML parser is a minimal hand-rolled parser so the package stays
dependency-free in CI; the optional ``pyyaml`` extra enables strict YAML
parsing for production use (task 03).

See ``docs/rfcs/A4-comply-gate.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


# ---------------------------------------------------------------------------
# Gate model
# ---------------------------------------------------------------------------
class GateType(str, Enum):
    """The four compliance gate types."""

    TEST_COVERAGE = "test-coverage"
    SBOM_PRESENT = "sbom-present"
    EVAL_PASSED = "eval-passed"
    DISCLOSURE_FILED = "disclosure-filed"


class GateStatus(str, Enum):
    """Per-gate evaluation status."""

    PASS = "pass"
    FAIL = "fail"
    SKIPPED = "skipped"
    OVERRIDE_APPLIED = "override_applied"


# ---------------------------------------------------------------------------
# Config types
# ---------------------------------------------------------------------------
@dataclass
class GateConfig:
    """The configured threshold/expectation for one gate."""

    type: GateType
    enabled: bool = True
    threshold: float = 0.0
    path: str = ""
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize the gate config to a plain dict."""
        return {
            "type": self.type.value,
            "enabled": self.enabled,
            "threshold": self.threshold,
            "path": self.path,
            "description": self.description,
        }


@dataclass
class ComplyGateConfig:
    """The full ``.complygate.yml`` config."""

    version: str = "1"
    gates: list[GateConfig] = field(default_factory=list)
    require_approvers: int = 2
    override_ttl_hours: int = 24

    def gate(self, gate_type: GateType) -> GateConfig | None:
        """Look up the gate config for ``gate_type``."""
        for g in self.gates:
            if g.type == gate_type:
                return g
        return None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the config to a plain dict."""
        return {
            "version": self.version,
            "require_approvers": self.require_approvers,
            "override_ttl_hours": self.override_ttl_hours,
            "gates": [g.to_dict() for g in self.gates],
        }


# ---------------------------------------------------------------------------
# Minimal YAML parser (no pyyaml dependency for the simple schema we use).
# ---------------------------------------------------------------------------
def parse_config(text: str) -> ComplyGateConfig:
    """Parse a ``.complygate.yml`` document into a :class:`ComplyGateConfig`.

    Accepts the canonical schema::

        version: "1"
        require_approvers: 2
        override_ttl_hours: 24
        gates:
          - type: test-coverage
            enabled: true
            threshold: 0.8
          - type: sbom-present
            enabled: true
            path: sbom.spdx.json
          - type: eval-passed
            enabled: true
          - type: disclosure-filed
            enabled: true

    Unknown keys are ignored; missing keys take defaults. The parser is
    line-oriented and limited to the schema above; for full YAML, install
    the ``yaml`` extra and call :func:`parse_config_yaml`.
    """
    cfg = ComplyGateConfig()
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        stripped = line.strip()
        if stripped.startswith("version:"):
            cfg.version = _scalar(stripped.split(":", 1)[1].strip())
        elif stripped.startswith("require_approvers:"):
            cfg.require_approvers = int(_scalar(stripped.split(":", 1)[1].strip()))
        elif stripped.startswith("override_ttl_hours:"):
            cfg.override_ttl_hours = int(_scalar(stripped.split(":", 1)[1].strip()))
        elif stripped == "gates:" or stripped.startswith("gates:"):
            # consume following "- type: ..." block
            i += 1
            while i < len(lines):
                gl = lines[i]
                if not gl.startswith(" ") and not gl.startswith("\t") and not gl.startswith("-"):
                    break  # back to top-level
                if gl.lstrip().startswith("- type:") or gl.lstrip().startswith("-type:"):
                    gate = _parse_gate_block(gl, lines, i)
                    cfg.gates.append(gate)
                i += 1
            continue
        i += 1
    return cfg


def _scalar(raw: str) -> Any:
    """Strip quotes from a scalar value, return string."""
    s = raw.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    return s


def _parse_gate_block(first_line: str, lines: list[str], start: int) -> GateConfig:
    """Parse a single gate block beginning at ``first_line`` (``- type: ...``)."""
    gtype_raw = ""
    enabled = True
    threshold = 0.0
    path = ""
    description = ""
    # First line carries the type.
    body = first_line.lstrip().lstrip("-").strip()
    if body.startswith("type:"):
        gtype_raw = _scalar(body.split(":", 1)[1].strip())
    # Walk forward grabbing same-block indented key: value pairs.
    base_indent = len(first_line) - len(first_line.lstrip(" "))
    j = start + 1
    while j < len(lines):
        ln = lines[j]
        if ln.lstrip().startswith("- "):
            break
        if not (ln.startswith(" " * (base_indent + 2)) or ln.startswith("\t" * (base_indent + 1))):
            if ln.strip() == "":
                j += 1
                continue
            break
        s = ln.strip()
        if s.startswith("enabled:"):
            enabled = _scalar(s.split(":", 1)[1].strip()).lower() in ("true", "yes", "1")
        elif s.startswith("threshold:"):
            threshold = float(_scalar(s.split(":", 1)[1].strip()))
        elif s.startswith("path:"):
            path = _scalar(s.split(":", 1)[1].strip())
        elif s.startswith("description:"):
            description = _scalar(s.split(":", 1)[1].strip())
        j += 1
    try:
        gt = GateType(gtype_raw)
    except ValueError:
        gt = GateType.TEST_COVERAGE
    return GateConfig(
        type=gt,
        enabled=enabled,
        threshold=threshold,
        path=path,
        description=description,
    )


# ---------------------------------------------------------------------------
# Gate evaluation
# ---------------------------------------------------------------------------
@dataclass
class GateResult:
    """The result of evaluating one gate."""

    gate_type: GateType
    status: GateStatus
    message: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        """True if the gate passed or was overridden."""
        return self.status in (GateStatus.PASS, GateStatus.OVERRIDE_APPLIED)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the result to a plain dict."""
        return {
            "gate_type": self.gate_type.value,
            "status": self.status.value,
            "message": self.message,
            "detail": dict(self.detail),
        }


# Evidence suppliers — pluggable so callers wire in real CI evidence.
CoverageProvider = Callable[[], float]
"""Returns the current line-coverage fraction (0..1)."""

FileExistsProvider = Callable[[str], bool]
"""Returns True if a file exists at ``path``."""

EvalResultProvider = Callable[[], bool]
"""Returns True if the latest eval run passed."""


@dataclass
class EvidenceProviders:
    """Pluggable evidence suppliers for the four gate types."""

    coverage: CoverageProvider | None = None
    file_exists: FileExistsProvider | None = None
    eval_passed: EvalResultProvider | None = None


def evaluate_gate(
    gate: GateConfig,
    evidence: EvidenceProviders,
) -> GateResult:
    """Evaluate one gate using the supplied evidence providers."""
    if not gate.enabled:
        return GateResult(gate.type, GateStatus.SKIPPED, "gate disabled in config")
    if gate.type == GateType.TEST_COVERAGE:
        if evidence.coverage is None:
            return GateResult(gate.type, GateStatus.FAIL, "no coverage provider wired")
        cov = evidence.coverage()
        if cov >= gate.threshold:
            return GateResult(
                gate.type,
                GateStatus.PASS,
                f"coverage {cov:.2%} >= threshold {gate.threshold:.2%}",
                detail={"coverage": cov, "threshold": gate.threshold},
            )
        return GateResult(
            gate.type,
            GateStatus.FAIL,
            f"coverage {cov:.2%} < threshold {gate.threshold:.2%}",
            detail={"coverage": cov, "threshold": gate.threshold},
        )
    if gate.type == GateType.SBOM_PRESENT:
        if evidence.file_exists is None:
            return GateResult(gate.type, GateStatus.FAIL, "no file-exists provider wired")
        path = gate.path or "sbom.spdx.json"
        if evidence.file_exists(path):
            return GateResult(gate.type, GateStatus.PASS, f"sbom present at {path}")
        return GateResult(gate.type, GateStatus.FAIL, f"sbom missing at {path}")
    if gate.type == GateType.EVAL_PASSED:
        if evidence.eval_passed is None:
            return GateResult(gate.type, GateStatus.FAIL, "no eval-passed provider wired")
        ok = evidence.eval_passed()
        if ok:
            return GateResult(gate.type, GateStatus.PASS, "latest eval passed")
        return GateResult(gate.type, GateStatus.FAIL, "latest eval failed")
    if gate.type == GateType.DISCLOSURE_FILED:
        if evidence.file_exists is None:
            return GateResult(gate.type, GateStatus.FAIL, "no file-exists provider wired")
        path = gate.path or "DISCLOSURE.md"
        if evidence.file_exists(path):
            return GateResult(gate.type, GateStatus.PASS, f"disclosure filed at {path}")
        return GateResult(gate.type, GateStatus.FAIL, f"disclosure missing at {path}")
    return GateResult(gate.type, GateStatus.SKIPPED, "unknown gate type")


# ---------------------------------------------------------------------------
# Break-glass override
# ---------------------------------------------------------------------------
@dataclass
class Override:
    """A break-glass override request for a failing gate."""

    gate_type: GateType
    reason: str
    approvers: list[str] = field(default_factory=list)
    expires_at_hours: int = 24


class OverrideError(Exception):
    """Raised when an override is invalid."""


def apply_override(result: GateResult, override: Override, require_approvers: int = 2) -> GateResult:
    """Apply ``override`` to ``result`` if it is valid.

    An override is valid iff the gate is failing, the reason is non-empty, and
    at least ``require_approvers`` distinct approvers signed it. Otherwise
    :class:`OverrideError` is raised and the original failing result is left
    intact.
    """
    if result.status != GateStatus.FAIL:
        raise OverrideError("override can only be applied to a failing gate")
    if not override.reason.strip():
        raise OverrideError("override reason must not be empty")
    distinct = {a.strip() for a in override.approvers if a.strip()}
    if len(distinct) < require_approvers:
        raise OverrideError(
            f"override requires {require_approvers} distinct approvers, got {len(distinct)}"
        )
    return GateResult(
        gate_type=result.gate_type,
        status=GateStatus.OVERRIDE_APPLIED,
        message=f"override applied: {override.reason}",
        detail={
            **result.detail,
            "approvers": sorted(distinct),
            "expires_at_hours": override.expires_at_hours,
        },
    )


# ---------------------------------------------------------------------------
# Top-level driver
# ---------------------------------------------------------------------------
@dataclass
class PipelineReport:
    """The aggregate result of evaluating every gate in a config."""

    results: list[GateResult] = field(default_factory=list)
    config_version: str = "1"

    @property
    def passed(self) -> bool:
        """True if every gate passed or was overridden."""
        return all(r.passed for r in self.results)

    @property
    def failed_gates(self) -> list[GateResult]:
        """The gates that are still failing (not overridden)."""
        return [r for r in self.results if r.status == GateStatus.FAIL]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report to a plain dict."""
        return {
            "config_version": self.config_version,
            "passed": self.passed,
            "results": [r.to_dict() for r in self.results],
        }


def run_pipeline(
    config: ComplyGateConfig,
    evidence: EvidenceProviders,
) -> PipelineReport:
    """Evaluate every enabled gate in ``config``."""
    report = PipelineReport(config_version=config.version)
    for gate in config.gates:
        report.results.append(evaluate_gate(gate, evidence))
    return report


__all__ = [
    "ComplyGateConfig",
    "EvidenceProviders",
    "GateConfig",
    "GateResult",
    "GateStatus",
    "GateType",
    "Override",
    "OverrideError",
    "PipelineReport",
    "apply_override",
    "evaluate_gate",
    "parse_config",
    "run_pipeline",
]
