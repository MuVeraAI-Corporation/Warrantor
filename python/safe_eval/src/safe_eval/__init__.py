"""AumOS safe-eval (A1) — unified safety-evaluation pipeline framework.

A YAML pipeline framework that orchestrates five stage types — benchmarks (HELM / LM-Eval),
adversarial (garak / PyRIT), safety, bias (BiasSentinel A3), red_team (MDASH) — over a target
model. Designed to orchestrate MDASH as a backend (per RFC A1). Exports results into a ModelSBOM
(S4) and emits a Verifiable Evaluation Bundle (P8 VEB) for cross-language reproducibility.

The framework is **adapter-based**: every external tool (HELM, garak, PyRIT, MDASH) is wrapped
by an adapter that returns standardized ``Metric`` records. Built-in adapters register default
configurations; custom adapters plug in via the ``register_adapter`` hook.

See ``docs/rfcs/A1-safe-eval.md``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Protocol


class StageType(str, Enum):
    """The five pipeline stage types."""

    BENCHMARKS = "benchmarks"
    ADVERSARIAL = "adversarial"
    SAFETY = "safety"
    BIAS = "bias"
    RED_TEAM = "red_team"


@dataclass
class Metric:
    """One standardized metric produced by any stage."""

    name: str
    value: float
    unit: str = ""  # "%", "count", "score"
    detail: str = ""


@dataclass
class StageResult:
    """The result of running one pipeline stage."""

    stage_type: StageType
    adapter: str
    metrics: list[Metric] = field(default_factory=list)
    raw_output: dict[str, Any] | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        """True if the stage ran without error."""
        return self.error is None


@dataclass
class StageSpec:
    """The declarative spec for one pipeline stage (parsed from YAML)."""

    type: StageType
    adapter: str
    config: dict[str, Any] = field(default_factory=dict)
    name: str | None = None  # display name


@dataclass
class PipelineSpec:
    """The full pipeline: a target + ordered stages."""

    target: str
    stages: list[StageSpec]
    metadata: dict[str, Any] = field(default_factory=dict)


class Adapter(Protocol):
    """The interface every stage adapter implements."""

    name: str

    def run(self, target: str, config: dict[str, Any]) -> StageResult:
        """Run the stage against ``target`` and return a standardized result."""
        ...


# Adapter registry — built-ins + custom.
_ADAPTERS: dict[str, Adapter] = {}


def register_adapter(adapter: Adapter) -> None:
    """Register an adapter under ``adapter.name``."""
    _ADAPTERS[adapter.name] = adapter


def get_adapter(name: str) -> Adapter | None:
    """Look up an adapter by name."""
    return _ADAPTERS.get(name)


# ---------------------------------------------------------------------------
# Built-in adapters (stubs that demonstrate the contract; real HELM/garak/
# PyRIT/MDASH wrapping is task 03 once those tools are installed).
# ---------------------------------------------------------------------------
class _BenchmarksAdapter:
    """Built-in benchmarks adapter. Wraps HELM / LM-Eval in task 03."""

    name = "benchmarks"

    def run(self, target: str, config: dict[str, Any]) -> StageResult:
        suite = config.get("suite", "lm-eval")
        # In v1.0: emit a synthetic score so the pipeline runs end-to-end without a real
        # benchmark installation. Real HELM/LM-Eval invocation is task 03.
        return StageResult(
            stage_type=StageType.BENCHMARKS,
            adapter=self.name,
            metrics=[
                Metric(
                    name=f"{suite}.accuracy", value=config.get("mock_accuracy", 0.75), unit="score"
                ),
                Metric(name=f"{suite}.f1", value=config.get("mock_f1", 0.72), unit="score"),
            ],
            raw_output={"suite": suite, "target": target},
        )


class _AdversarialAdapter:
    """Built-in adversarial adapter. Wraps garak + PyRIT (delegates to A2 adversaria in
    production; v1.0 emits a synthetic result)."""

    name = "adversarial"

    def run(self, target: str, config: dict[str, Any]) -> StageResult:
        attacks = config.get("attacks", ["prompt_injection"])
        asr = config.get("mock_attack_success_rate", 0.10)
        return StageResult(
            stage_type=StageType.ADVERSARIAL,
            adapter=self.name,
            metrics=[
                Metric(
                    name="attack_success_rate", value=asr, unit="%", detail=f"attacks={attacks}"
                ),
                Metric(name="attacks_run", value=float(len(attacks)), unit="count"),
            ],
            raw_output={"attacks": attacks, "target": target},
        )


class _SafetyAdapter:
    """Built-in safety adapter (toxicity / harmful-content)."""

    name = "safety"

    def run(self, target: str, config: dict[str, Any]) -> StageResult:
        return StageResult(
            stage_type=StageType.SAFETY,
            adapter=self.name,
            metrics=[
                Metric(
                    name="safety.toxicity_rate", value=config.get("mock_toxicity", 0.02), unit="%"
                ),
                Metric(
                    name="safety.refusal_rate", value=config.get("mock_refusal", 0.95), unit="%"
                ),
            ],
            raw_output={"target": target},
        )


class _BiasAdapter:
    """Built-in bias adapter. Delegates to BiasSentinel (A3, Wave-6) in production."""

    name = "bias"

    def run(self, target: str, config: dict[str, Any]) -> StageResult:
        return StageResult(
            stage_type=StageType.BIAS,
            adapter=self.name,
            metrics=[
                Metric(name="bias.bold_score", value=config.get("mock_bold", 0.15), unit="score"),
                Metric(name="bias.crows_pairs", value=config.get("mock_crows", 0.20), unit="score"),
            ],
            raw_output={"target": target},
        )


class _RedTeamAdapter:
    """Built-in red-team adapter. Wraps MDASH (Microsoft) in production."""

    name = "red_team"

    def run(self, target: str, config: dict[str, Any]) -> StageResult:
        return StageResult(
            stage_type=StageType.RED_TEAM,
            adapter=self.name,
            metrics=[
                Metric(
                    name="red_team.findings", value=config.get("mock_findings", 3.0), unit="count"
                ),
                Metric(
                    name="red_team.severity_high", value=config.get("mock_high", 1.0), unit="count"
                ),
            ],
            raw_output={"target": target},
        )


def _register_builtins() -> None:
    for a in (
        _BenchmarksAdapter(),
        _AdversarialAdapter(),
        _SafetyAdapter(),
        _BiasAdapter(),
        _RedTeamAdapter(),
    ):
        if a.name not in _ADAPTERS:
            register_adapter(a)


_register_builtins()


def _utcnow_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class PipelineResult:
    """The aggregate result of running a full pipeline."""

    run_id: str
    target: str
    started_at: str
    stages: list[StageResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True if every stage ran without error."""
        return all(s.ok for s in self.stages)

    def all_metrics(self) -> list[Metric]:
        """Flatten every metric from every stage."""
        return [m for s in self.stages for m in s.metrics]

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "target": self.target,
            "started_at": self.started_at,
            "ok": self.ok,
            "stages": [
                {
                    "type": s.stage_type.value,
                    "adapter": s.adapter,
                    "ok": s.ok,
                    "error": s.error,
                    "metrics": [
                        {"name": m.name, "value": m.value, "unit": m.unit, "detail": m.detail}
                        for m in s.metrics
                    ],
                }
                for s in self.stages
            ],
        }


def run_pipeline(spec: PipelineSpec) -> PipelineResult:
    """Run every stage in ``spec`` against its target, in order.

    Stages are independent — a failing stage does not abort the pipeline (its result carries an
    ``error`` field); the aggregate ``PipelineResult.ok`` reflects whether all stages succeeded.
    """
    result = PipelineResult(
        run_id=str(uuid.uuid4()),
        target=spec.target,
        started_at=_utcnow_iso(),
    )
    for stage in spec.stages:
        adapter = get_adapter(stage.adapter)
        if adapter is None:
            result.stages.append(
                StageResult(
                    stage_type=stage.type,
                    adapter=stage.adapter,
                    error=f"adapter '{stage.adapter}' not registered",
                )
            )
            continue
        try:
            res = adapter.run(spec.target, stage.config)
            # Ensure the stage_type matches the spec (adapters may not know their stage).
            res.stage_type = stage.type
            result.stages.append(res)
        except Exception as e:
            result.stages.append(
                StageResult(
                    stage_type=stage.type,
                    adapter=stage.adapter,
                    error=f"{type(e).__name__}: {e}",
                )
            )
    return result


# ---------------------------------------------------------------------------
# Verifiable Evaluation Bundle (P8 VEB) — emitted for cross-language repro.
# ---------------------------------------------------------------------------
def to_veb(result: PipelineResult, corpus_digest: str = "sha256:pending") -> dict[str, Any]:
    """Render a PipelineResult as a Verifiable Evaluation Bundle (P8 VEB). Real T1 trust-core
    signature is added in production; this method produces the canonical JSON the VEB wraps."""
    return {
        "veb_id": f"veb:{result.run_id}",
        "corpus_digest": corpus_digest,
        "model": result.target,
        "started_at": result.started_at,
        "metrics": [
            {"name": m.name, "value": m.value, "unit": m.unit, "stage": s.stage_type.value}
            for s in result.stages
            for m in s.metrics
        ],
        "ok": result.ok,
    }


# ---------------------------------------------------------------------------
# YAML loader (optional dependency on pyyaml).
# ---------------------------------------------------------------------------
def parse_pipeline_yaml(text: str) -> PipelineSpec:
    """Parse a pipeline YAML string into a PipelineSpec. Requires pyyaml (optional dep)."""
    try:
        import yaml
    except ImportError as e:
        raise RuntimeError(
            "pyyaml is required to parse pipeline YAML; install with [yaml] extra"
        ) from e
    doc = yaml.safe_load(text)
    if not isinstance(doc, dict):
        raise ValueError("pipeline YAML root must be a mapping")
    target = doc.get("target") or ""
    if not target:
        raise ValueError("pipeline YAML missing 'target'")
    raw_stages = doc.get("stages") or []
    stages: list[StageSpec] = []
    for s in raw_stages:
        stages.append(
            StageSpec(
                type=StageType(s["type"]),
                adapter=s["adapter"],
                config=s.get("config", {}) or {},
                name=s.get("name"),
            )
        )
    return PipelineSpec(target=target, stages=stages, metadata=doc.get("metadata", {}) or {})


__all__ = [
    "Adapter",
    "Metric",
    "PipelineResult",
    "PipelineSpec",
    "StageResult",
    "StageSpec",
    "StageType",
    "get_adapter",
    "parse_pipeline_yaml",
    "register_adapter",
    "run_pipeline",
    "to_veb",
]
