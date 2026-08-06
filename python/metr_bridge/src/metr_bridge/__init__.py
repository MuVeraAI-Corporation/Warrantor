"""AumOS metr-bridge (X6) — METR evaluation integration.

Four components:

- :class:`METREvalAdapter` — translates a METR task spec into a
  :class:`SafeEvalPipeline` so METR tasks run under the AumOS evaluation harness.
- :class:`TranscriptExporter` — exports an AumOS agent transcript into the
  METR JSONL transcript format.
- :class:`RiskReportBridge` — translates an AumOS risk report into the METR
  risk schema.
- :class:`IndependentVerifier` — second-source check that re-runs the eval
  with a different seed and confirms the score is reproducible.

The METR wire formats are intentionally minimal: they cover the fields METR
task scripts consume (``task_id``, ``max_steps``, ``success_threshold``,
``evaluations``). The full METR schema is task 03 once the METR runner is
installed; the bridge is mockable so unit tests run fully in-process.

See ``docs/rfcs/X6-metr-bridge.md``.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol


# ---------------------------------------------------------------------------
# METR spec model
# ---------------------------------------------------------------------------
@dataclass
class METRTaskSpec:
    """A METR task specification.

    Mirrors the canonical METR task format. ``evaluations`` is a list of
    named checks (``safety``, ``goal_completion``, ...) each with a passing
    threshold.
    """

    task_id: str
    description: str
    max_steps: int = 50
    success_threshold: float = 0.8
    evaluations: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SafeEvalPipeline:
    """An AumOS safe_eval pipeline (subset — enough to run METR tasks)."""

    target: str
    stages: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# METREvalAdapter
# ---------------------------------------------------------------------------
class METREvalAdapter:
    """Translates a METR task spec into a safe_eval pipeline.

    Each METR ``evaluation`` becomes one safe_eval stage with ``type=eval``.
    The adapter preserves ``max_steps`` and ``success_threshold`` as pipeline
    metadata so the downstream runner enforces them.
    """

    def adapt(self, spec: METRTaskSpec, target: str = "model://default") -> SafeEvalPipeline:
        """Translate ``spec`` into a :class:`SafeEvalPipeline`."""
        stages: list[dict[str, Any]] = []
        for ev in spec.evaluations:
            stages.append(
                {
                    "type": "eval",
                    "name": ev.get("name", "unnamed"),
                    "metric": ev.get("metric", "score"),
                    "threshold": ev.get("threshold", spec.success_threshold),
                    "weight": float(ev.get("weight", 1.0)),
                }
            )
        # always include the success threshold as the final gate
        stages.append(
            {
                "type": "gate",
                "name": "overall_success",
                "metric": "overall_score",
                "threshold": spec.success_threshold,
            }
        )
        return SafeEvalPipeline(
            target=target,
            stages=stages,
            metadata={
                "source": "metr",
                "task_id": spec.task_id,
                "max_steps": spec.max_steps,
                "success_threshold": spec.success_threshold,
                "description": spec.description,
                "metr_metadata": dict(spec.metadata),
            },
        )


# ---------------------------------------------------------------------------
# TranscriptExporter
# ---------------------------------------------------------------------------
@dataclass
class AgentStep:
    """One step in an AumOS agent transcript."""

    step: int
    role: str  # "user" | "assistant" | "tool" | "system"
    content: str
    tool: str = ""
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


class TranscriptExporter:
    """Exports an AumOS agent transcript to METR JSONL format.

    The METR format is one JSON object per line with the fields ``step``,
    ``role``, ``content``, ``tool`` (optional) and ``timestamp``. ``export``
    returns the JSONL bytes; ``export_lines`` returns the parsed dicts.
    """

    def export_lines(self, steps: list[AgentStep]) -> list[dict[str, Any]]:
        """Return the METR transcript as a list of dict records."""
        out: list[dict[str, Any]] = []
        for s in steps:
            rec: dict[str, Any] = {
                "step": s.step,
                "role": s.role,
                "content": s.content,
                "timestamp": s.timestamp,
            }
            if s.tool:
                rec["tool"] = s.tool
            out.append(rec)
        return out

    def export(self, steps: list[AgentStep]) -> bytes:
        """Serialize the METR transcript as JSONL bytes."""
        lines = [json.dumps(r, sort_keys=True) for r in self.export_lines(steps)]
        return ("\n".join(lines) + "\n").encode("utf-8")


# ---------------------------------------------------------------------------
# RiskReportBridge
# ---------------------------------------------------------------------------
@dataclass
class AumOSFinding:
    """An AumOS risk finding (subset of the full AumOS risk schema)."""

    rule_id: str
    severity: str  # "info" | "low" | "medium" | "high" | "critical"
    message: str
    cwe: str = ""
    atlas: str = ""  # MITRE ATLAS technique id (e.g. "AML.T0051")
    file: str = ""
    line: int = 0


@dataclass
class AumOSRiskReport:
    """An AumOS risk report (subset)."""

    target: str
    findings: list[AumOSFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to plain dict."""
        return {
            "target": self.target,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "message": f.message,
                    "cwe": f.cwe,
                    "atlas": f.atlas,
                    "file": f.file,
                    "line": f.line,
                }
                for f in self.findings
            ],
        }


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class RiskReportBridge:
    """Translates an AumOS risk report into the METR risk schema.

    The METR risk schema is a flat list of ``{severity, message, tags}``
    records sorted by severity. The bridge adds the MITRE ATLAS / CWE tags
    METR's dashboards group on.
    """

    def to_metr(self, report: AumOSRiskReport) -> dict[str, Any]:
        """Translate ``report`` to the METR risk schema dict."""
        records = [
            {
                "severity": f.severity,
                "message": f.message,
                "tags": self._tags(f),
                "source": "aumos",
                "rule_id": f.rule_id,
            }
            for f in report.findings
        ]
        records.sort(key=lambda r: (_SEVERITY_ORDER.get(r["severity"], 99), r["rule_id"]))
        return {
            "target": report.target,
            "schema": "metr.risk.v1",
            "findings": records,
            "summary": self._summary(records),
        }

    @staticmethod
    def _tags(f: AumOSFinding) -> list[str]:
        """Build the METR tag list (cwe/atlas ids) for a finding."""
        tags: list[str] = []
        if f.cwe:
            tags.append(f.cwe)
        if f.atlas:
            tags.append(f.atlas)
        return tags

    @staticmethod
    def _summary(records: list[dict[str, Any]]) -> dict[str, int]:
        """Count findings per severity."""
        out: dict[str, int] = {}
        for r in records:
            out[r["severity"]] = out.get(r["severity"], 0) + 1
        return out


# ---------------------------------------------------------------------------
# IndependentVerifier
# ---------------------------------------------------------------------------
class EvalRunner(Protocol):
    """The interface for the underlying evaluation runner.

    Wave-1 ships a deterministic in-process runner; task 03 swaps in the
    real safe_eval pipeline executor.
    """

    def run(self, pipeline: SafeEvalPipeline, seed: int) -> float:
        """Run ``pipeline`` with the supplied ``seed`` and return the score."""
        ...


class _DeterministicRunner:
    """An in-process runner that derives the score deterministically from the
    pipeline+seed (used by tests and as the Wave-1 default)."""

    def run(self, pipeline: SafeEvalPipeline, seed: int) -> float:
        h = hashlib.sha256(f"{pipeline.target}|{seed}".encode("utf-8")).digest()
        # First 4 bytes -> score in [0,1] to 4 dp. Stable for a given (target, seed).
        n = int.from_bytes(h[:4], "big") / float(2**32)
        score = round(n, 4)
        return score


@dataclass
class VerificationResult:
    """The result of an :class:`IndependentVerifier` run."""

    reproduced: bool
    primary_score: float
    secondary_score: float
    delta: float
    tolerance: float

    def to_dict(self) -> dict[str, Any]:
        """Serialize to plain dict."""
        return {
            "reproduced": self.reproduced,
            "primary_score": self.primary_score,
            "secondary_score": self.secondary_score,
            "delta": self.delta,
            "tolerance": self.tolerance,
        }


class IndependentVerifier:
    """Re-runs a pipeline with a different seed and confirms the score is reproducible.

    Two runs (primary, secondary) with different seeds must agree within
    ``tolerance`` (default 0.05). A disagreement flags the primary eval as
    non-reproducible — the canonical signal of a flaky or gaming-prone eval.
    """

    def __init__(
        self,
        runner: EvalRunner | None = None,
        tolerance: float = 0.05,
        secondary_seed: int = 99,
    ) -> None:
        self._runner = runner or _DeterministicRunner()
        self._tolerance = float(tolerance)
        self._secondary_seed = int(secondary_seed)

    def verify(self, pipeline: SafeEvalPipeline, primary_seed: int) -> VerificationResult:
        """Run the pipeline twice and compare."""
        primary = self._runner.run(pipeline, primary_seed)
        secondary = self._runner.run(pipeline, self._secondary_seed)
        delta = abs(primary - secondary)
        return VerificationResult(
            reproduced=delta <= self._tolerance,
            primary_score=primary,
            secondary_score=secondary,
            delta=delta,
            tolerance=self._tolerance,
        )


# ---------------------------------------------------------------------------
# Convenience: build a METR task spec id
# ---------------------------------------------------------------------------
def new_task_id(prefix: str = "metr") -> str:
    """Mint a new METR task id of the form ``prefix-<uuid8>``."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


__all__ = [
    "AgentStep",
    "AumOSFinding",
    "AumOSRiskReport",
    "EvalRunner",
    "IndependentVerifier",
    "METREvalAdapter",
    "METRTaskSpec",
    "RiskReportBridge",
    "SafeEvalPipeline",
    "TranscriptExporter",
    "VerificationResult",
    "new_task_id",
]
