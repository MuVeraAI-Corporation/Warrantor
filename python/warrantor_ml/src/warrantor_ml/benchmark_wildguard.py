"""Benchmark a guard model on the real WildGuardTest held-out split.

Why this module exists at all
-----------------------------
The first baseline in this lane scored Qwen3Guard-Gen-4B at 1.0 recall and 1.0 precision on 52
hand-written prompts, and correctly refused to conclude anything from it: a purpose-built guard
acing a hand-written set proves the set was easy, not that the guard is good. The ICLR 2026
workshop benchmark (arXiv:2605.28830) measures this same model at **83.97% recall over 79,331
samples** -- roughly one unsafe item in six gets through. Every Phase-2 decision lives inside
that ~16% tail, so the only evaluation worth running is one that probes it.

WildGuardTest is that probe. It is human-annotated, held out, and -- decisively -- 47% of its
rows are *adversarial*: jailbreak-wrapped restatements of a harmful request, which is exactly
where a guard is supposed to be weakest and exactly what an aggregate number hides.

Three tasks, one measurement
----------------------------
WildGuard carries three independent labels: ``prompt_harm_label`` (is the user's request
harmful), ``response_harm_label`` (is the model's answer harmful) and ``response_refusal_label``
(did the model refuse). This module measures **prompt harmfulness** as primary, because that is
the decision a deny gate in front of a model actually performs: it sees the request, and it has
to decide before any response exists. The other two labels are carried through so a response-
moderation run can reuse the same loader, but they are not the headline.

Discipline
----------
* Rows whose label is null (annotators failed to reach 2-of-3 agreement) are **excluded and
  counted**, never coerced to safe. There are 26 of them in the test split.
* Parse failures are tallied separately and never scored as correct. Under the default
  fail-closed policy an unparseable response counts as HARMFUL, which *inflates* recall -- so
  the report also states recall with parse failures excluded entirely, and the two must be read
  together.
* Every breakdown is computed from the same single pass over the model. There is no second
  harness and no second set of predictions to drift apart.
"""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ._canonical import sha256_file
from .evaluate import (
    DEFAULT_OLLAMA_ENDPOINT,
    DEFAULT_OLLAMA_MODEL,
    EvalSample,
    EvaluationResult,
    KeywordStubBackend,
    OllamaGuardBackend,
    SampleOutcome,
    evaluate,
)
from .metrics import MetricSummary, confusion_matrix, summarize

__all__ = [
    "PARSE_FAILURE_MARKER",
    "WILDGUARD_TEST_FILE",
    "WILDGUARD_TEST_REPO",
    "WildGuardRow",
    "build_eval_set_descriptor",
    "build_parser",
    "load_wildguard_test",
    "main",
    "resolve_test_parquet",
    "slice_summary",
    "stratified_sample",
    "to_eval_samples",
]

WILDGUARD_TEST_REPO = "allenai/wildguardmix"
WILDGUARD_TEST_FILE = "test/wildguard_test.parquet"

#: Substring of the :class:`~warrantor_ml.evaluate.BackendError` message raised when the guard
#: replied but the reply carried neither a ``Safety:`` verdict nor a ``Categories:`` line. Used
#: to separate *parse* failures from *transport* failures in the report, because they mean
#: different things: one is a model that answered off-format, the other is a dead daemon.
PARSE_FAILURE_MARKER = "guard response contained neither"

_HARM_LABELS = {"harmful": True, "unharmful": False}


@dataclass(frozen=True)
class WildGuardRow:
    """One WildGuardTest row, with the label vocabulary preserved verbatim.

    The label fields are ``str | None`` on purpose. ``None`` means the three annotators did not
    reach agreement, and that is a different fact from "unharmful". Collapsing the two is the
    single easiest way to manufacture a flattering recall number on this corpus.
    """

    row_index: int
    prompt: str
    response: str
    adversarial: bool
    prompt_harm_label: str | None
    response_harm_label: str | None
    response_refusal_label: str | None
    subcategory: str

    @property
    def sample_id(self) -> str:
        """Zero-padded id so sorted-by-id order equals file order."""

        return f"wgt-{self.row_index:05d}"


def resolve_test_parquet(local_path: Path | None = None) -> Path:
    """Locate the WildGuardTest parquet, preferring an explicit path over the Hub cache.

    The download is gated (auto-approved, but still requires an accepted form and a read token).
    This function never accepts the gate for you; if the file is not cached and no token is
    present, ``huggingface_hub`` raises and the caller sees why.
    """

    if local_path is not None:
        if not local_path.exists():
            raise FileNotFoundError(f"{local_path}: not found")
        return local_path
    os.environ.setdefault("HF_HOME", "M:/hf")
    from huggingface_hub import hf_hub_download

    # Cache first, network second. A cached corpus must not become unreachable because the Hub
    # is having a bad minute, and an eval that silently re-downloads is an eval whose input can
    # change under it between runs.
    for local_only in (True, False):
        try:
            return Path(
                hf_hub_download(
                    repo_id=WILDGUARD_TEST_REPO,
                    filename=WILDGUARD_TEST_FILE,
                    repo_type="dataset",
                    local_files_only=local_only,
                )
            )
        except Exception:  # an offline cache miss falls through to the network attempt
            if not local_only:
                raise
    raise RuntimeError("unreachable")


def load_wildguard_test(path: Path) -> tuple[WildGuardRow, ...]:
    """Read the parquet into rows, in file order, with no label coercion.

    ``pyarrow`` is imported lazily so importing this module -- and therefore running the test
    suite -- does not require it. It is not in the ``dev`` extra for the same reason ``torch``
    is not: CI installs ``dev`` only.
    """

    import pyarrow.parquet as pq

    table = pq.read_table(path)
    required = {
        "prompt",
        "response",
        "adversarial",
        "prompt_harm_label",
        "response_harm_label",
        "response_refusal_label",
        "subcategory",
    }
    missing = required - set(table.column_names)
    if missing:
        raise ValueError(f"{path}: missing expected columns {sorted(missing)}")
    columns = table.to_pydict()
    return tuple(
        WildGuardRow(
            row_index=index,
            prompt=columns["prompt"][index],
            response=columns["response"][index],
            adversarial=bool(columns["adversarial"][index]),
            prompt_harm_label=columns["prompt_harm_label"][index],
            response_harm_label=columns["response_harm_label"][index],
            response_refusal_label=columns["response_refusal_label"][index],
            subcategory=columns["subcategory"][index] or "",
        )
        for index in range(table.num_rows)
    )


def to_eval_samples(rows: Sequence[WildGuardRow]) -> tuple[tuple[EvalSample, ...], tuple[str, ...]]:
    """Project rows onto prompt-harmfulness eval samples, dropping unlabelled rows.

    Returns the samples and the ids that were dropped, so the caller can report the exclusion
    rather than quietly shrink its denominator.

    The ground-truth category attached to each positive is WildGuard's ``subcategory``. It is
    only attached to harmful rows: unharmful rows carry the literal subcategory ``"benign"``,
    which is not a harm category, and :func:`~warrantor_ml.metrics.per_category_recall` scores
    positives only in any case.
    """

    samples: list[EvalSample] = []
    dropped: list[str] = []
    for row in rows:
        unsafe = _HARM_LABELS.get(row.prompt_harm_label or "")
        if unsafe is None:
            dropped.append(row.sample_id)
            continue
        samples.append(
            EvalSample(
                sample_id=row.sample_id,
                text=row.prompt,
                unsafe=unsafe,
                categories=(row.subcategory,) if unsafe and row.subcategory else (),
            )
        )
    return tuple(sorted(samples, key=lambda sample: sample.sample_id)), tuple(dropped)


def stratified_sample(
    rows: Sequence[WildGuardRow],
    size: int,
    seed: int = 0,
) -> tuple[WildGuardRow, ...]:
    """A deterministic stratified subsample preserving the label x adversarial proportions.

    Stratification is over the (``prompt_harm_label``, ``adversarial``) cross-product -- the
    four cells that the report breaks down by. Sampling uniformly at random would let the
    adversarial-harmful cell, the one the whole exercise is about, drift by chance.

    Determinism comes from a seeded :class:`random.Random` over rows in file order, so the same
    ``(size, seed)`` always yields the same subset for a given corpus.
    """

    import random

    if size >= len(rows):
        return tuple(rows)
    strata: dict[tuple[str | None, bool], list[WildGuardRow]] = {}
    for row in rows:
        strata.setdefault((row.prompt_harm_label, row.adversarial), []).append(row)
    total = len(rows)
    chosen: list[WildGuardRow] = []
    for key in sorted(strata, key=str):
        bucket = strata[key]
        take = round(size * len(bucket) / total)
        rng = random.Random(f"{seed}:{key}")
        chosen.extend(rng.sample(bucket, min(take, len(bucket))))
    return tuple(sorted(chosen, key=lambda row: row.row_index))


def slice_summary(
    outcomes: Sequence[SampleOutcome],
    keep: Callable[[SampleOutcome], bool],
) -> MetricSummary:
    """Recompute the headline metrics over a subset of an already-executed run.

    Every breakdown in the report goes through this function, over the outcomes of one pass. No
    slice is produced by a second inference run, so no slice can disagree with the aggregate for
    any reason other than arithmetic.
    """

    selected = [outcome for outcome in outcomes if keep(outcome)]
    return summarize(
        confusion_matrix(
            [outcome.expected_unsafe for outcome in selected],
            [outcome.predicted_unsafe for outcome in selected],
        )
    )


def _severity_counts(outcomes: Sequence[SampleOutcome]) -> dict[str, int]:
    """How many of each ``Safety:`` verdict the guard actually emitted.

    Worth reporting because Qwen3Guard has three severities, not two, and the third one --
    ``Controversial`` -- is a policy choice dressed as a measurement. See
    :func:`_controversial_scored_safe`.
    """

    counts: dict[str, int] = {}
    for outcome in outcomes:
        counts[outcome.severity] = counts.get(outcome.severity, 0) + 1
    return dict(sorted(counts.items()))


def _controversial_scored_safe(outcomes: Sequence[SampleOutcome]) -> MetricSummary:
    """What the numbers would be if ``Controversial`` were treated as SAFE.

    The evaluator's default resolves ``Controversial`` towards denial, which is the correct
    default for a deny gate but is a *decision*, and it is the kind of decision that quietly
    supplies recall. This slice prices it: the gap between this summary and the headline is
    exactly how much of the reported recall is bought by that one policy line, and how much
    false-positive rate it costs.

    Recomputed from the recorded severity and category-gate flags of the same single pass -- no
    second inference run.
    """

    predictions = [
        # `errored` keeps its fail-closed verdict so this slice differs from the headline in
        # exactly one variable: the treatment of Controversial.
        outcome.errored or outcome.severity == "unsafe" or outcome.gated_by_category
        for outcome in outcomes
    ]
    return summarize(
        confusion_matrix([outcome.expected_unsafe for outcome in outcomes], predictions)
    )


def _format_summary(label: str, summary: MetricSummary) -> str:
    """One aligned report line, recall first."""

    matrix = summary.matrix
    return (
        f"  {label:<26} recall={summary.recall:.4f}  miss={matrix.false_negative:>4d}/"
        f"{matrix.actual_positive:<4d}  precision={summary.precision:.4f}  "
        f"F1={summary.f1:.4f}  FPR={summary.false_positive_rate:.4f}  n={matrix.total}"
    )


def _breakdowns(
    result: EvaluationResult,
    rows_by_id: dict[str, WildGuardRow],
) -> dict[str, dict[str, Any]]:
    """Every slice the report needs, computed from the single pass in ``result``."""

    outcomes = result.outcomes
    parse_failures = {
        outcome.sample_id
        for outcome in outcomes
        if outcome.errored and PARSE_FAILURE_MARKER in outcome.error_message
    }
    transport_failures = {
        outcome.sample_id for outcome in outcomes if outcome.errored
    } - parse_failures

    def by_adversarial(flag: bool) -> Callable[[SampleOutcome], bool]:
        return lambda outcome: rows_by_id[outcome.sample_id].adversarial is flag

    breakdowns: dict[str, dict[str, Any]] = {
        "overall": slice_summary(outcomes, lambda _: True).to_dict(),
        "adversarial_true": slice_summary(outcomes, by_adversarial(True)).to_dict(),
        "adversarial_false": slice_summary(outcomes, by_adversarial(False)).to_dict(),
        "excluding_all_backend_errors": slice_summary(
            outcomes, lambda outcome: not outcome.errored
        ).to_dict(),
    }
    subcategories: dict[str, dict[str, Any]] = {}
    for name in sorted({rows_by_id[o.sample_id].subcategory for o in outcomes}):
        if not name or name == "benign":
            continue
        subcategories[name] = slice_summary(
            outcomes,
            lambda outcome, target=name: rows_by_id[outcome.sample_id].subcategory == target,
        ).to_dict()
    breakdowns["by_subcategory"] = subcategories
    breakdowns["severity_counts"] = _severity_counts(outcomes)
    breakdowns["controversial_scored_safe"] = _controversial_scored_safe(outcomes).to_dict()
    breakdowns["failures"] = {
        "parse_failure_ids": sorted(parse_failures),
        "transport_failure_ids": sorted(transport_failures),
        "parse_failure_count": len(parse_failures),
        "transport_failure_count": len(transport_failures),
        "policy": "fail-closed: an errored sample is scored HARMFUL, which inflates recall. "
        "Read 'excluding_all_backend_errors' alongside 'overall'.",
    }
    return breakdowns


def _print_report(breakdowns: dict[str, dict[str, Any]], header: dict[str, Any]) -> None:
    """Human-readable report. Recall first, aggregates never alone."""

    print("=" * 96)
    for key, value in header.items():
        print(f"{key:<28} {value}")
    print("=" * 96)
    print("PROMPT HARMFULNESS (the decision a deny gate performs)")
    for key in ("overall", "adversarial_false", "adversarial_true"):
        summary = MetricSummary(**_rehydrate(breakdowns[key]))
        print(_format_summary(key, summary))
    print("-" * 96)
    print("with backend/parse errors removed from the denominator entirely:")
    summary = MetricSummary(**_rehydrate(breakdowns["excluding_all_backend_errors"]))
    print(_format_summary("no-error subset", summary))
    print("-" * 96)
    print(f"severity verdicts emitted: {breakdowns['severity_counts']}")
    summary = MetricSummary(**_rehydrate(breakdowns["controversial_scored_safe"]))
    print(_format_summary("if Controversial=SAFE", summary))
    print("-" * 96)
    print("recall by WildGuard subcategory (worst first):")
    ranked = sorted(
        breakdowns["by_subcategory"].items(),
        key=lambda item: (item[1]["recall"], item[0]),
    )
    for name, payload in ranked:
        matrix = payload["confusion_matrix"]
        print(
            f"  {name:<70} {payload['recall']:.4f}  "
            f"({matrix['true_positive']}/{matrix['true_positive'] + matrix['false_negative']})"
        )
    failures = breakdowns["failures"]
    print("-" * 96)
    print(
        f"parse failures: {failures['parse_failure_count']}   "
        f"transport failures: {failures['transport_failure_count']}   "
        f"({failures['policy']})"
    )
    print("=" * 96)


def _rehydrate(payload: dict[str, Any]) -> dict[str, Any]:
    """Rebuild a :class:`MetricSummary` kwargs dict from its serialised form."""

    from .metrics import ConfusionMatrix

    matrix = dict(payload["confusion_matrix"])
    matrix.pop("total", None)
    return {
        key: payload[key]
        for key in ("recall", "miss_rate", "precision", "f1", "false_positive_rate", "accuracy")
    } | {"matrix": ConfusionMatrix(**matrix)}


def build_parser() -> argparse.ArgumentParser:
    """CLI for ``warrantor-ml-benchmark-wildguard``."""

    parser = argparse.ArgumentParser(
        prog="warrantor-ml-benchmark-wildguard",
        description="Evaluate a guard model on the real WildGuardTest split. Recall first.",
    )
    parser.add_argument("--parquet", type=Path, help="local parquet path (default: HF cache)")
    parser.add_argument("--backend", choices=("ollama", "stub"), default="ollama")
    parser.add_argument("--model", default=DEFAULT_OLLAMA_MODEL)
    parser.add_argument("--endpoint", default=DEFAULT_OLLAMA_ENDPOINT)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--num-ctx", type=int, default=8192)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument(
        "--sample-size",
        type=int,
        help="deterministic stratified subsample size (default: the full split)",
    )
    parser.add_argument("--out", type=Path, help="write the JSON result document here")
    return parser


def build_eval_set_descriptor(
    path: Path,
    rows: Sequence[WildGuardRow],
    selected: Sequence[WildGuardRow],
    dropped: Sequence[str],
) -> dict[str, Any]:
    """The ``eval_set`` block written into the result document.

    ``digest`` and ``source`` are not decoration and they are not optional.

    ``digest`` is the SHA-256 of the split file itself. The parity gate's decision record is
    sold as pinning a promotion to the evidence behind it, and the eval set IS the evidence; the
    field it reads (``eval_set.digest``) used to be written by nothing but the generic
    ``evaluate`` CLI, so every document this module produced left it empty and every decision
    recorded ``eval_set_digest: ""``.

    ``source`` is what binds the document to a baseline: ``parity.corpus_digest_of`` parses it
    back into the ``(corpus, split)`` pair ``MeasuredBaseline`` stores, so an ExpGuardTest result
    can no longer be scored against the WildGuardTest baseline every guard recipe declares.

    Extracted from ``main`` so both facts are testable without a parquet, a Hub token or a GPU.
    """

    return {
        "source": f"{WILDGUARD_TEST_REPO}:{WILDGUARD_TEST_FILE}",
        "digest": sha256_file(path),
        "local_path": str(path),
        "task": "prompt_harm_label",
        "rows_in_split": len(rows),
        "rows_selected": len(selected),
        "rows_dropped_null_label": len(dropped),
        "dropped_ids": list(dropped),
    }


def main(argv: list[str] | None = None) -> int:
    """Entry point: load, evaluate, break down, report."""

    arguments = build_parser().parse_args(argv)
    path = resolve_test_parquet(arguments.parquet)
    rows = load_wildguard_test(path)
    selected = (
        stratified_sample(rows, arguments.sample_size, seed=arguments.seed)
        if arguments.sample_size
        else rows
    )
    samples, dropped = to_eval_samples(selected)
    rows_by_id = {row.sample_id: row for row in selected}

    backend: Any
    if arguments.backend == "stub":
        backend = KeywordStubBackend(seed=arguments.seed)
    else:
        backend = OllamaGuardBackend(
            model=arguments.model,
            endpoint=arguments.endpoint,
            seed=arguments.seed,
            timeout_seconds=arguments.timeout,
            num_ctx=arguments.num_ctx,
        )

    result = evaluate(
        samples,
        backend,
        seed=arguments.seed,
        fail_closed=True,
        eval_set_descriptor=build_eval_set_descriptor(path, rows, selected, dropped),
    )
    breakdowns = _breakdowns(result, rows_by_id)
    header = {
        "model": arguments.model if arguments.backend == "ollama" else "keyword-stub",
        "corpus": f"{WILDGUARD_TEST_REPO} {WILDGUARD_TEST_FILE}",
        "task": "prompt harmfulness (primary)",
        "rows in split": len(rows),
        "rows scored": len(samples),
        "rows dropped (null label)": len(dropped),
        "seed": arguments.seed,
        "wall clock (s)": result.wall_clock_seconds,
    }
    _print_report(breakdowns, header)

    if arguments.out is not None:
        document = result.to_dict()
        document["wildguard_breakdowns"] = breakdowns
        document["wildguard_row_metadata"] = {
            outcome.sample_id: {
                "adversarial": rows_by_id[outcome.sample_id].adversarial,
                "subcategory": rows_by_id[outcome.sample_id].subcategory,
                "response_harm_label": rows_by_id[outcome.sample_id].response_harm_label,
                "response_refusal_label": rows_by_id[outcome.sample_id].response_refusal_label,
            }
            for outcome in result.outcomes
        }
        arguments.out.parent.mkdir(parents=True, exist_ok=True)
        arguments.out.write_text(
            json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"result: {arguments.out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
