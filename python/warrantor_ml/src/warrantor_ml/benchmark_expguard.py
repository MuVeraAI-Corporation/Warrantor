"""Benchmark a guard model on the real ExpGuardTest split, broken down by vertical domain.

Why this module exists
----------------------
:mod:`warrantor_ml.benchmark_wildguard` answers "how does a general guard do on a general
adversarial corpus". This module answers a narrower and more expensive question: **does a
general-purpose guard degrade on specialised professional content, and in which vertical?**

That question decides whether the finance / healthcare / legal packs can ship one shared guard
or need their own tuned models. It is not answerable from an aggregate. A guard that scores 0.90
recall overall while sitting at 0.75 on healthcare is a guard that ships a broken healthcare
pack, and the aggregate is precisely the number that hides it.

The hypothesis under test
-------------------------
*A general guard has a higher false-negative rate on domain-specific harmful content, because
the harm is expressed in professional vocabulary the guard was not trained on.* Structured
billing fraud reads like accounting. A request to falsify a clinical note reads like charting.
If the hypothesis holds, per-domain recall separates; if it does not, the packs share a model.

What the corpus actually contains (verified, not assumed)
---------------------------------------------------------
The ``domain`` column carries exactly **three** values -- ``finance``, ``healthcare``, ``law``.
Two consequences that the module refuses to paper over:

* The legal vertical is spelled ``law``, not ``legal``.
* **There is no general / non-vertical band.** Every row is domain-specific, so this corpus
  cannot supply the in-corpus control the comparison would ideally use. The general-band
  baseline has to come from a different corpus (WildGuardTest), and cross-corpus deltas confound
  domain with corpus construction. :func:`domain_comparison` therefore compares the three
  verticals *against each other*, which is the only controlled contrast available here, and the
  report says so rather than inventing a fourth band.

Discipline
----------
* Rows with a blank or unrecognised ``prompt_label`` are **excluded and counted**, never coerced
  to safe.
* Parse failures are tallied separately and never scored as correct. Under fail-closed an
  unparseable reply counts HARMFUL, which *inflates* recall -- so every slice is also reported
  with errors removed from the denominator.
* Per-domain recall carries a **Wilson score interval**. With ~300-600 positives per domain a
  two- or three-point gap is noise, and the report is required to be able to say so with a
  number instead of a shrug.
* Every breakdown comes from one pass over the model. There is no second harness.
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
from .benchmark_wildguard import PARSE_FAILURE_MARKER, slice_summary
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
from .metrics import MetricSummary
from .stats import two_proportion_z as _two_proportion_z
from .stats import wilson_interval

__all__ = [
    "EXPGUARD_DOMAINS",
    "EXPGUARD_TEST_FILE",
    "EXPGUARD_TEST_REPO",
    "ExpGuardRow",
    "build_eval_set_descriptor",
    "build_parser",
    "describe_corpus",
    "domain_comparison",
    "load_expguard_test",
    "main",
    "resolve_test_parquet",
    "stratified_sample",
    "to_eval_samples",
    "wilson_interval",
]

EXPGUARD_TEST_REPO = "6rightjade/expguardmix"
EXPGUARD_TEST_FILE = "expguardtest.parquet"

#: The three values actually present in the ``domain`` column, verified against the split.
#: There is no general band; see the module docstring.
EXPGUARD_DOMAINS = ("finance", "healthcare", "law")

_HARM_LABELS = {"unsafe": True, "safe": False}


@dataclass(frozen=True)
class ExpGuardRow:
    """One ExpGuardTest row with the label vocabulary preserved verbatim.

    ``response_label`` is ``""`` for roughly half the split (prompt-only rows). That blank is
    kept as a blank rather than mapped to "safe"; it means the row carries no response-side
    ground truth at all, which is a different fact from "the response was fine".
    """

    row_index: int
    prompt: str
    response: str
    prompt_label: str
    response_label: str
    prompt_category: str
    response_category: str
    domain: str
    scenario: str

    @property
    def sample_id(self) -> str:
        """Zero-padded id so sorted-by-id order equals file order."""

        return f"egt-{self.row_index:05d}"


def resolve_test_parquet(local_path: Path | None = None) -> Path:
    """Locate the ExpGuardTest parquet, preferring an explicit path over the Hub cache.

    Cache first, network second, for the same reason as the WildGuard loader: an eval whose
    input can silently re-download is an eval whose input can change under it between runs.
    """

    if local_path is not None:
        if not local_path.exists():
            raise FileNotFoundError(f"{local_path}: not found")
        return local_path
    os.environ.setdefault("HF_HOME", "M:/hf")
    from huggingface_hub import hf_hub_download

    for local_only in (True, False):
        try:
            return Path(
                hf_hub_download(
                    repo_id=EXPGUARD_TEST_REPO,
                    filename=EXPGUARD_TEST_FILE,
                    repo_type="dataset",
                    local_files_only=local_only,
                )
            )
        except Exception:  # offline cache miss falls through to the network attempt
            if not local_only:
                raise
    raise RuntimeError("unreachable")


def load_expguard_test(path: Path) -> tuple[ExpGuardRow, ...]:
    """Read the parquet into rows, in file order, with no label coercion.

    ``pyarrow`` is imported lazily and read through :class:`pyarrow.parquet.ParquetFile` rather
    than :func:`pyarrow.parquet.read_table`. The latter routes through ``pyarrow.dataset``,
    which drags in the pandas shim; on a box with an exhausted commit charge that import is what
    fails, not the read. The direct reader needs neither pandas nor numpy beyond pyarrow's own.
    """

    import pyarrow.parquet as pq

    table = pq.ParquetFile(path).read()
    required = {
        "prompt",
        "response",
        "prompt_label",
        "response_label",
        "prompt_category",
        "response_category",
        "domain",
        "scenario",
    }
    missing = required - set(table.column_names)
    if missing:
        raise ValueError(f"{path}: missing expected columns {sorted(missing)}")
    columns = table.to_pydict()

    def cell(name: str, index: int) -> str:
        value = columns[name][index]
        return "" if value is None else str(value)

    return tuple(
        ExpGuardRow(
            row_index=index,
            prompt=cell("prompt", index),
            response=cell("response", index),
            prompt_label=cell("prompt_label", index).strip().lower(),
            response_label=cell("response_label", index).strip().lower(),
            prompt_category=cell("prompt_category", index),
            response_category=cell("response_category", index),
            domain=cell("domain", index).strip().lower(),
            scenario=cell("scenario", index),
        )
        for index in range(table.num_rows)
    )


def describe_corpus(rows: Sequence[ExpGuardRow]) -> dict[str, Any]:
    """The schema facts the report has to state before it is allowed to evaluate anything.

    Distinct values and cross-tabs, computed from the loaded rows rather than assumed from a
    dataset card. The task brief named the legal domain ``legal`` and expected a general band;
    the corpus disagrees on both counts, and that disagreement only surfaces if this runs first.
    """

    from collections import Counter

    domains = Counter(row.domain for row in rows)
    return {
        "row_count": len(rows),
        "domain_values": dict(sorted(domains.items())),
        "prompt_label_values": dict(sorted(Counter(row.prompt_label for row in rows).items())),
        "response_label_values": dict(
            sorted(Counter(row.response_label or "<blank>" for row in rows).items())
        ),
        "prompt_category_values": dict(
            sorted(Counter(row.prompt_category for row in rows).items(), key=lambda kv: -kv[1])
        ),
        "domain_x_prompt_label": {
            f"{domain}/{label}": count
            for (domain, label), count in sorted(
                Counter((row.domain, row.prompt_label) for row in rows).items()
            )
        },
        "general_band_present": False,
        "general_band_note": "The domain column has no general/non-vertical value. Every row is "
        "domain-specific, so this corpus supplies no in-corpus control band. Any 'general' "
        "comparison must come from a different corpus and is confounded by corpus construction.",
    }


def to_eval_samples(
    rows: Sequence[ExpGuardRow],
) -> tuple[tuple[EvalSample, ...], tuple[str, ...]]:
    """Project rows onto prompt-harmfulness eval samples, dropping unlabelled rows.

    Returns the samples and the dropped ids, so the caller reports the exclusion rather than
    quietly shrinking its denominator. The ground-truth category attached to each positive is
    ExpGuard's ``prompt_category``; the literal ``Unharmful`` category is not attached, because
    it is not a harm category and per-category recall scores positives only.
    """

    samples: list[EvalSample] = []
    dropped: list[str] = []
    for row in rows:
        unsafe = _HARM_LABELS.get(row.prompt_label)
        if unsafe is None:
            dropped.append(row.sample_id)
            continue
        category = row.prompt_category.strip().lower()
        samples.append(
            EvalSample(
                sample_id=row.sample_id,
                text=row.prompt,
                unsafe=unsafe,
                categories=(category,) if unsafe and category and category != "unharmful" else (),
            )
        )
    return tuple(sorted(samples, key=lambda sample: sample.sample_id)), tuple(dropped)


def stratified_sample(
    rows: Sequence[ExpGuardRow],
    size: int,
    seed: int = 0,
) -> tuple[ExpGuardRow, ...]:
    """A deterministic stratified subsample preserving the domain x label proportions.

    Stratification is over the (``domain``, ``prompt_label``) cross-product -- the six cells the
    report breaks down by. Uniform sampling would let the per-domain positive counts drift by
    chance, which is fatal when the per-domain positive count is exactly what sets the width of
    the confidence interval the conclusion rests on.
    """

    import random

    if size >= len(rows):
        return tuple(rows)
    strata: dict[tuple[str, str], list[ExpGuardRow]] = {}
    for row in rows:
        strata.setdefault((row.domain, row.prompt_label), []).append(row)
    total = len(rows)
    chosen: list[ExpGuardRow] = []
    for key in sorted(strata):
        bucket = strata[key]
        take = round(size * len(bucket) / total)
        rng = random.Random(f"{seed}:{key}")
        chosen.extend(rng.sample(bucket, min(take, len(bucket))))
    return tuple(sorted(chosen, key=lambda row: row.row_index))


# ---------------------------------------------------------------------------
# Is the gap real?
# ---------------------------------------------------------------------------


# `wilson_interval` and `_two_proportion_z` now live in `warrantor_ml.stats` and are imported
# above rather than defined here. They are re-exported under their original names because the
# parity gate needs the same arithmetic, and a second copy is how the per-domain table and the
# promotion decision start disagreeing about whether a gap is real.


def domain_comparison(per_domain: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Pairwise recall contrasts between domains, with an explicit noise verdict.

    Takes the serialised per-domain summaries and answers the only question the per-domain table
    is there to answer: *is the spread bigger than sampling noise at these counts?* A verdict of
    ``within_noise`` is a real finding -- it says the verticals can share one guard -- and it is
    reported as loudly as a separation would be.
    """

    arms: dict[str, tuple[int, int]] = {}
    for name, payload in per_domain.items():
        matrix = payload["confusion_matrix"]
        caught = int(matrix["true_positive"])
        positives = caught + int(matrix["false_negative"])
        arms[name] = (caught, positives)

    intervals = {
        name: {
            "recall": (caught / positives) if positives else 0.0,
            "caught": caught,
            "positives": positives,
            "wilson_95": list(wilson_interval(caught, positives)),
        }
        for name, (caught, positives) in sorted(arms.items())
    }

    pairs: dict[str, Any] = {}
    names = sorted(arms)
    for index, left in enumerate(names):
        for right in names[index + 1 :]:
            caught_l, total_l = arms[left]
            caught_r, total_r = arms[right]
            statistic = _two_proportion_z(caught_l, total_l, caught_r, total_r)
            significant = statistic is not None and abs(statistic) >= 1.96
            pairs[f"{left}_vs_{right}"] = {
                "recall_delta": (
                    (caught_l / total_l if total_l else 0.0)
                    - (caught_r / total_r if total_r else 0.0)
                ),
                "z": statistic,
                "significant_at_95": significant,
                "verdict": "separated" if significant else "within noise",
            }

    recalls = [payload["recall"] for payload in intervals.values() if payload["positives"]]
    any_significant = any(pair["significant_at_95"] for pair in pairs.values())
    return {
        "per_domain_recall": intervals,
        "pairwise": pairs,
        "recall_spread": (max(recalls) - min(recalls)) if recalls else 0.0,
        "any_pair_separated_at_95": any_significant,
        "verdict": (
            "At least one domain pair separates beyond sampling noise; the per-domain gap is "
            "real at these counts."
            if any_significant
            else "No domain pair separates at 95%. The spread is consistent with sampling noise "
            "at these positive counts -- do not read a story into it."
        ),
    }


# ---------------------------------------------------------------------------
# Breakdowns and report
# ---------------------------------------------------------------------------


def _format_summary(label: str, summary: MetricSummary) -> str:
    """One aligned report line, recall first."""

    matrix = summary.matrix
    return (
        f"  {label:<24} recall={summary.recall:.4f}  miss={matrix.false_negative:>4d}/"
        f"{matrix.actual_positive:<4d}  precision={summary.precision:.4f}  "
        f"F1={summary.f1:.4f}  FPR={summary.false_positive_rate:.4f}  n={matrix.total}"
    )


def _breakdowns(
    result: EvaluationResult,
    rows_by_id: dict[str, ExpGuardRow],
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

    def in_domain(name: str) -> Callable[[SampleOutcome], bool]:
        return lambda outcome: rows_by_id[outcome.sample_id].domain == name

    present_domains = sorted({rows_by_id[outcome.sample_id].domain for outcome in outcomes})
    per_domain = {
        name: slice_summary(outcomes, in_domain(name)).to_dict() for name in present_domains
    }
    per_domain_clean = {
        name: slice_summary(
            outcomes,
            lambda outcome, target=name: rows_by_id[outcome.sample_id].domain == target
            and not outcome.errored,
        ).to_dict()
        for name in present_domains
    }

    categories: dict[str, dict[str, Any]] = {}
    for name in sorted({rows_by_id[o.sample_id].prompt_category for o in outcomes}):
        if not name or name.lower() == "unharmful":
            continue
        categories[name] = slice_summary(
            outcomes,
            lambda outcome, target=name: rows_by_id[outcome.sample_id].prompt_category == target,
        ).to_dict()

    breakdowns: dict[str, dict[str, Any]] = {
        "overall": slice_summary(outcomes, lambda _: True).to_dict(),
        "excluding_all_backend_errors": slice_summary(
            outcomes, lambda outcome: not outcome.errored
        ).to_dict(),
        "by_domain": per_domain,
        "by_domain_excluding_errors": per_domain_clean,
        "by_prompt_category": categories,
        "domain_significance": domain_comparison(per_domain),
        "severity_mix": {
            severity: sum(1 for outcome in outcomes if outcome.severity == severity)
            for severity in sorted({outcome.severity for outcome in outcomes})
        },
        "failures": {
            "parse_failure_ids": sorted(parse_failures),
            "transport_failure_ids": sorted(transport_failures),
            "parse_failure_count": len(parse_failures),
            "transport_failure_count": len(transport_failures),
            "parse_failures_by_domain": {
                name: sum(1 for sid in parse_failures if rows_by_id[sid].domain == name)
                for name in present_domains
            },
            "policy": "fail-closed: an errored sample is scored HARMFUL, which inflates recall. "
            "Read 'by_domain_excluding_errors' alongside 'by_domain'.",
        },
    }
    return breakdowns


def _rehydrate(payload: dict[str, Any]) -> MetricSummary:
    """Rebuild a :class:`MetricSummary` from its serialised form."""

    from .metrics import ConfusionMatrix

    matrix = dict(payload["confusion_matrix"])
    matrix.pop("total", None)
    return MetricSummary(
        **{
            key: payload[key]
            for key in ("recall", "miss_rate", "precision", "f1", "false_positive_rate", "accuracy")
        },
        matrix=ConfusionMatrix(**matrix),
    )


def _print_report(
    breakdowns: dict[str, dict[str, Any]],
    header: dict[str, Any],
    corpus: dict[str, Any],
) -> None:
    """Human-readable report. Schema first, then recall, aggregates never alone."""

    print("=" * 100)
    print("CORPUS SCHEMA (inspected, not assumed)")
    print(f"  rows                 {corpus['row_count']}")
    print(f"  domain               {corpus['domain_values']}")
    print(f"  prompt_label         {corpus['prompt_label_values']}")
    print(f"  response_label       {corpus['response_label_values']}")
    print(f"  domain x label       {corpus['domain_x_prompt_label']}")
    print(f"  general band         {corpus['general_band_note']}")
    print("=" * 100)
    for key, value in header.items():
        print(f"{key:<28} {value}")
    print("=" * 100)
    print("PROMPT HARMFULNESS (the decision a deny gate performs)")
    print(_format_summary("overall", _rehydrate(breakdowns["overall"])))
    print(
        _format_summary(
            "overall (no errors)", _rehydrate(breakdowns["excluding_all_backend_errors"])
        )
    )
    print("-" * 100)
    print("BY DOMAIN (worst recall first) -- the measurement this run exists for:")
    ranked = sorted(breakdowns["by_domain"].items(), key=lambda item: (item[1]["recall"], item[0]))
    for name, payload in ranked:
        print(_format_summary(name, _rehydrate(payload)))
    print("-" * 100)
    significance = breakdowns["domain_significance"]
    print("IS THE PER-DOMAIN GAP REAL?")
    for name, payload in significance["per_domain_recall"].items():
        low, high = payload["wilson_95"]
        print(
            f"  {name:<24} recall={payload['recall']:.4f}  "
            f"95% CI [{low:.4f}, {high:.4f}]  ({payload['caught']}/{payload['positives']})"
        )
    for name, payload in significance["pairwise"].items():
        statistic = payload["z"]
        rendered = "n/a" if statistic is None else f"{statistic:+.2f}"
        print(
            f"  {name:<24} delta={payload['recall_delta']:+.4f}  z={rendered:>7}  "
            f"-> {payload['verdict']}"
        )
    print(f"  spread={significance['recall_spread']:.4f}")
    print(f"  VERDICT: {significance['verdict']}")
    print("-" * 100)
    print("recall by ExpGuard prompt_category (worst first):")
    for name, payload in sorted(
        breakdowns["by_prompt_category"].items(), key=lambda item: (item[1]["recall"], item[0])
    ):
        matrix = payload["confusion_matrix"]
        positives = matrix["true_positive"] + matrix["false_negative"]
        print(f"  {name:<46} {payload['recall']:.4f}  ({matrix['true_positive']}/{positives})")
    failures = breakdowns["failures"]
    print("-" * 100)
    print(
        f"parse failures: {failures['parse_failure_count']} "
        f"{failures['parse_failures_by_domain']}   "
        f"transport failures: {failures['transport_failure_count']}"
    )
    print(f"  {failures['policy']}")
    print(f"severity mix: {breakdowns['severity_mix']}")
    print("=" * 100)


def build_parser() -> argparse.ArgumentParser:
    """CLI for ``warrantor-ml-benchmark-expguard``."""

    parser = argparse.ArgumentParser(
        prog="warrantor-ml-benchmark-expguard",
        description="Evaluate a guard model on the real ExpGuardTest split, by domain. "
        "Recall first.",
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
    parser.add_argument(
        "--describe-only",
        action="store_true",
        help="print the corpus schema and exit without touching the model",
    )
    parser.add_argument("--out", type=Path, help="write the JSON result document here")
    return parser


def build_eval_set_descriptor(
    path: Path,
    rows: Sequence[ExpGuardRow],
    selected: Sequence[ExpGuardRow],
    dropped: Sequence[str],
    sample_size: int | None,
    seed: int,
) -> dict[str, Any]:
    """The ``eval_set`` block written into the result document.

    Same contract as ``benchmark_wildguard.build_eval_set_descriptor``, and it matters more here.
    ``source`` is the only thing that tells the parity gate this document was scored on
    ExpGuardTest -- every guard recipe declares the WildGuardTest baseline, and without the
    binding an ExpGuard recall figure was compared against WildGuard numbers and promoted.
    ``digest`` is the SHA-256 of the split file, so the decision can be re-audited against the
    exact bytes it was scored on.
    """

    return {
        "source": f"{EXPGUARD_TEST_REPO}:{EXPGUARD_TEST_FILE}",
        "digest": sha256_file(path),
        "local_path": str(path),
        "task": "prompt_label (prompt harmfulness)",
        "rows_in_split": len(rows),
        "rows_selected": len(selected),
        "rows_dropped_unlabelled": len(dropped),
        "dropped_ids": list(dropped),
        "sampling": (
            f"deterministic stratified by (domain, prompt_label), size={sample_size}, seed={seed}"
            if sample_size
            else "full split, no sampling"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    """Entry point: inspect the schema, evaluate, break down by domain, report."""

    arguments = build_parser().parse_args(argv)
    path = resolve_test_parquet(arguments.parquet)
    rows = load_expguard_test(path)
    corpus = describe_corpus(rows)

    if arguments.describe_only:
        print(json.dumps(corpus, indent=2, ensure_ascii=False))
        return 0

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
        eval_set_descriptor=build_eval_set_descriptor(
            path, rows, selected, dropped, arguments.sample_size, arguments.seed
        ),
    )
    breakdowns = _breakdowns(result, rows_by_id)
    header = {
        "model": arguments.model if arguments.backend == "ollama" else "keyword-stub",
        "corpus": f"{EXPGUARD_TEST_REPO} {EXPGUARD_TEST_FILE}",
        "task": "prompt harmfulness (primary)",
        "rows in split": len(rows),
        "rows scored": len(samples),
        "rows dropped (unlabelled)": len(dropped),
        "sampling": result.eval_set["sampling"],
        "seed": arguments.seed,
        "wall clock (s)": result.wall_clock_seconds,
    }
    _print_report(breakdowns, header, corpus)

    if arguments.out is not None:
        document = result.to_dict()
        document["expguard_corpus"] = corpus
        document["expguard_breakdowns"] = breakdowns
        document["expguard_row_metadata"] = {
            outcome.sample_id: {
                "domain": rows_by_id[outcome.sample_id].domain,
                "prompt_category": rows_by_id[outcome.sample_id].prompt_category,
                "scenario": rows_by_id[outcome.sample_id].scenario,
                "response_label": rows_by_id[outcome.sample_id].response_label,
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
