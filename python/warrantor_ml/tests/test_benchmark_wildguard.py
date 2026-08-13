"""WildGuardTest benchmark tests: label handling, stratification, slicing, failure accounting.

None of this needs pyarrow, a download, a GPU, or a running Ollama daemon. The parquet reader
is the only part that needs pyarrow and it is imported lazily, so the rest of the module is
testable on the CI box exactly as it runs on the eval box.
"""

from __future__ import annotations

from pathlib import Path

from warrantor_ml import benchmark_wildguard as bw
from warrantor_ml._canonical import is_wellformed_digest, sha256_file
from warrantor_ml.baselines import get_baseline
from warrantor_ml.evaluate import SampleOutcome
from warrantor_ml.parity import corpus_digest_of


def _row(
    index: int,
    *,
    label: str | None = "harmful",
    adversarial: bool = False,
    subcategory: str = "cyberattack",
) -> bw.WildGuardRow:
    return bw.WildGuardRow(
        row_index=index,
        prompt=f"prompt {index}",
        response=f"response {index}",
        adversarial=adversarial,
        prompt_harm_label=label,
        response_harm_label="unharmful",
        response_refusal_label="compliance",
        subcategory=subcategory,
    )


# ---------------------------------------------------------------------------
# Label handling -- where a flattering number would come from
# ---------------------------------------------------------------------------


def test_null_prompt_harm_label_is_dropped_not_coerced_to_safe() -> None:
    """26 real test rows have no annotator majority. Calling them safe would be a free win."""

    rows = [_row(0), _row(1, label=None), _row(2, label="unharmful")]
    samples, dropped = bw.to_eval_samples(rows)
    assert dropped == ("wgt-00001",)
    assert [sample.sample_id for sample in samples] == ["wgt-00000", "wgt-00002"]
    assert [sample.unsafe for sample in samples] == [True, False]


def test_unknown_label_vocabulary_is_dropped_rather_than_guessed() -> None:
    samples, dropped = bw.to_eval_samples([_row(0, label="probably_fine")])
    assert samples == ()
    assert dropped == ("wgt-00000",)


def test_subcategory_is_attached_only_to_positives() -> None:
    """`benign` is not a harm category, and recall by category scores positives only."""

    samples, _ = bw.to_eval_samples(
        [_row(0, subcategory="cyberattack"), _row(1, label="unharmful", subcategory="benign")]
    )
    assert samples[0].categories == ("cyberattack",)
    assert samples[1].categories == ()


def test_samples_are_returned_in_sorted_id_order() -> None:
    samples, _ = bw.to_eval_samples([_row(9), _row(0), _row(3)])
    assert [sample.sample_id for sample in samples] == ["wgt-00000", "wgt-00003", "wgt-00009"]


# ---------------------------------------------------------------------------
# Stratification
# ---------------------------------------------------------------------------


def test_stratified_sample_preserves_the_adversarial_harmful_cell() -> None:
    """Uniform sampling would let the cell the whole exercise is about drift by chance."""

    rows = (
        [_row(index, label="harmful", adversarial=True) for index in range(100)]
        + [_row(100 + index, label="harmful", adversarial=False) for index in range(100)]
        + [_row(200 + index, label="unharmful", adversarial=True) for index in range(200)]
        + [_row(400 + index, label="unharmful", adversarial=False) for index in range(600)]
    )
    chosen = bw.stratified_sample(rows, 100, seed=0)
    assert len(chosen) == 100
    cells = {(row.prompt_harm_label, row.adversarial): 0 for row in rows}
    for row in chosen:
        cells[(row.prompt_harm_label, row.adversarial)] += 1
    assert cells[("harmful", True)] == 10
    assert cells[("harmful", False)] == 10
    assert cells[("unharmful", True)] == 20
    assert cells[("unharmful", False)] == 60


def test_stratified_sample_is_deterministic_for_a_seed() -> None:
    rows = [_row(index, adversarial=index % 2 == 0) for index in range(50)]
    first = bw.stratified_sample(rows, 20, seed=0)
    second = bw.stratified_sample(rows, 20, seed=0)
    assert [row.row_index for row in first] == [row.row_index for row in second]
    assert [row.row_index for row in first] != [
        row.row_index for row in bw.stratified_sample(rows, 20, seed=1)
    ]


def test_stratified_sample_returns_everything_when_size_exceeds_the_corpus() -> None:
    rows = [_row(index) for index in range(5)]
    assert len(bw.stratified_sample(rows, 500)) == 5


def test_stratified_sample_emits_rows_in_file_order() -> None:
    rows = [_row(index) for index in range(100)]
    chosen = bw.stratified_sample(rows, 20, seed=0)
    assert [row.row_index for row in chosen] == sorted(row.row_index for row in chosen)


# ---------------------------------------------------------------------------
# Slicing
# ---------------------------------------------------------------------------


def _outcome(sample_id: str, expected: bool, predicted: bool, **kwargs: object) -> SampleOutcome:
    return SampleOutcome(
        sample_id=sample_id,
        expected_unsafe=expected,
        predicted_unsafe=predicted,
        severity=str(kwargs.get("severity", "safe")),
        categories=(),
        gated_by_category=False,
        errored=bool(kwargs.get("errored", False)),
        error_message=str(kwargs.get("error_message", "")),
    )


def test_slice_summary_recomputes_metrics_over_a_subset() -> None:
    outcomes = [
        _outcome("a", True, True),
        _outcome("b", True, False),
        _outcome("c", False, False),
        _outcome("d", False, True),
    ]
    everything = bw.slice_summary(outcomes, lambda _: True)
    assert everything.recall == 0.5
    caught_only = bw.slice_summary(outcomes, lambda outcome: outcome.sample_id in {"a", "c"})
    assert caught_only.recall == 1.0
    assert caught_only.matrix.total == 2


def test_rehydrate_round_trips_a_serialised_summary() -> None:
    original = bw.slice_summary(
        [_outcome("a", True, False), _outcome("b", False, False)], _keep_all
    )
    rebuilt = bw._rehydrate(original.to_dict())
    assert rebuilt["recall"] == original.recall
    assert rebuilt["matrix"] == original.matrix


def _keep_all(_: SampleOutcome) -> bool:
    return True


# ---------------------------------------------------------------------------
# Failure accounting -- a parse failure is never a correct answer
# ---------------------------------------------------------------------------


def test_parse_failures_are_separated_from_transport_failures() -> None:
    """They mean different things: a model answering off-format, versus a dead daemon."""

    outcomes = (
        _outcome("wgt-00000", True, True),
        _outcome(
            "wgt-00001",
            True,
            True,
            errored=True,
            error_message=f"{bw.PARSE_FAILURE_MARKER} a 'Safety:' verdict",
        ),
        _outcome(
            "wgt-00002",
            False,
            True,
            errored=True,
            error_message="ollama request to http://127.0.0.1:11434 failed: timed out",
        ),
    )
    result = _FakeResult(outcomes)
    rows_by_id = {
        "wgt-00000": _row(0),
        "wgt-00001": _row(1),
        "wgt-00002": _row(2, label="unharmful", subcategory="benign"),
    }
    breakdowns = bw._breakdowns(result, rows_by_id)
    failures = breakdowns["failures"]
    assert failures["parse_failure_ids"] == ["wgt-00001"]
    assert failures["transport_failure_ids"] == ["wgt-00002"]


def test_error_free_slice_removes_fail_closed_credit_from_recall() -> None:
    """Fail-closed scores an errored sample HARMFUL, which is a free true positive. Both
    numbers have to be on the page or the inflation is invisible."""

    outcomes = (
        _outcome("wgt-00000", True, False),
        _outcome(
            "wgt-00001",
            True,
            True,
            errored=True,
            error_message=f"{bw.PARSE_FAILURE_MARKER} a 'Safety:' verdict",
        ),
    )
    breakdowns = bw._breakdowns(_FakeResult(outcomes), {"wgt-00000": _row(0), "wgt-00001": _row(1)})
    assert breakdowns["overall"]["recall"] == 0.5
    assert breakdowns["excluding_all_backend_errors"]["recall"] == 0.0


def test_breakdowns_split_on_adversarial() -> None:
    outcomes = (
        _outcome("wgt-00000", True, True),
        _outcome("wgt-00001", True, False),
    )
    rows_by_id = {"wgt-00000": _row(0, adversarial=False), "wgt-00001": _row(1, adversarial=True)}
    breakdowns = bw._breakdowns(_FakeResult(outcomes), rows_by_id)
    assert breakdowns["adversarial_false"]["recall"] == 1.0
    assert breakdowns["adversarial_true"]["recall"] == 0.0


def test_benign_subcategory_is_excluded_from_the_harm_category_table() -> None:
    outcomes = (_outcome("wgt-00000", True, True), _outcome("wgt-00001", False, False))
    rows_by_id = {
        "wgt-00000": _row(0, subcategory="cyberattack"),
        "wgt-00001": _row(1, label="unharmful", subcategory="benign"),
    }
    breakdowns = bw._breakdowns(_FakeResult(outcomes), rows_by_id)
    assert set(breakdowns["by_subcategory"]) == {"cyberattack"}


# ---------------------------------------------------------------------------
# The Controversial severity -- a policy choice that quietly supplies recall
# ---------------------------------------------------------------------------


def test_controversial_slice_prices_the_deny_default() -> None:
    """Qwen3Guard emits three severities. Treating the third as harmful is correct for a deny
    gate and is also a decision; the gap between the two slices is what that decision buys."""

    outcomes = (
        _outcome("wgt-00000", True, True, severity="controversial"),
        _outcome("wgt-00001", False, True, severity="controversial"),
        _outcome("wgt-00002", True, True, severity="unsafe"),
    )
    breakdowns = bw._breakdowns(
        _FakeResult(outcomes),
        {"wgt-00000": _row(0), "wgt-00001": _row(1, label="unharmful"), "wgt-00002": _row(2)},
    )
    assert breakdowns["overall"]["recall"] == 1.0
    assert breakdowns["overall"]["false_positive_rate"] == 1.0
    assert breakdowns["controversial_scored_safe"]["recall"] == 0.5
    assert breakdowns["controversial_scored_safe"]["false_positive_rate"] == 0.0


def test_controversial_slice_keeps_errors_fail_closed() -> None:
    """It must differ from the headline in exactly one variable, or it prices two things."""

    outcomes = (
        _outcome(
            "wgt-00000", True, True, errored=True, error_message="timed out", severity="error"
        ),
    )
    breakdowns = bw._breakdowns(_FakeResult(outcomes), {"wgt-00000": _row(0)})
    assert breakdowns["controversial_scored_safe"]["recall"] == 1.0


def test_severity_counts_report_what_the_guard_actually_said() -> None:
    outcomes = (
        _outcome("wgt-00000", True, True, severity="unsafe"),
        _outcome("wgt-00001", False, False, severity="safe"),
        _outcome("wgt-00002", True, True, severity="controversial"),
        _outcome("wgt-00003", True, True, severity="safe"),
    )
    counts = bw._breakdowns(
        _FakeResult(outcomes),
        {outcome.sample_id: _row(index) for index, outcome in enumerate(outcomes)},
    )["severity_counts"]
    assert counts == {"controversial": 1, "safe": 2, "unsafe": 1}


class _FakeResult:
    """The one attribute :func:`bw._breakdowns` reads, without running an evaluation."""

    def __init__(self, outcomes: tuple[SampleOutcome, ...]) -> None:
        self.outcomes = outcomes


# ── the eval-set descriptor is what pins a decision to its evidence ─────────────────────


def test_the_eval_set_descriptor_carries_a_digest_of_the_split_it_scored(tmp_path: Path) -> None:
    """`parity.load_candidate_result` reads `eval_set.digest`, and this module never wrote it.

    Only the generic `evaluate.py` CLI added the key, so every document this benchmark produced
    left it absent and every parity decision recorded `eval_set_digest: ""` -- the field sold as
    pinning a promotion to the evidence behind it.
    """

    parquet = tmp_path / "wildguard_test.parquet"
    parquet.write_bytes(b"bytes are enough to have a digest")
    descriptor = bw.build_eval_set_descriptor(parquet, range(1725), range(1699), ["a", "b"])

    assert descriptor["digest"] == sha256_file(parquet)
    assert is_wellformed_digest(descriptor["digest"])
    assert descriptor["rows_in_split"] == 1725
    assert descriptor["rows_dropped_null_label"] == 2


def test_the_eval_set_descriptor_names_the_corpus_the_parity_gate_binds_against(
    tmp_path: Path,
) -> None:
    """`source` is what stops an ExpGuardTest result being scored against this baseline."""

    parquet = tmp_path / "wildguard_test.parquet"
    parquet.write_bytes(b"x")
    descriptor = bw.build_eval_set_descriptor(parquet, [], [], [])

    assert descriptor["source"] == f"{bw.WILDGUARD_TEST_REPO}:{bw.WILDGUARD_TEST_FILE}"
    assert (
        corpus_digest_of(descriptor["source"])
        == get_baseline("wildguardtest-qwen3guard-gen-4b").corpus_digest
    )
