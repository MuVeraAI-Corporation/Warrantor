"""ExpGuardTest benchmark tests: label handling, domain slicing, and the noise verdict.

None of this needs pyarrow, a download, a GPU, or a running Ollama daemon. The parquet reader is
the only part that needs pyarrow and it is imported lazily, so the rest of the module is
testable on the CI box exactly as it runs on the eval box.

The tests that matter most here are the ones around :func:`domain_comparison`. The whole point of
the ExpGuard run is a three-way per-domain comparison, and a three-way comparison over a few
hundred positives per arm is exactly the shape of evidence that invites a story to be read into
noise. If the significance machinery is wrong, the run produces a confident wrong answer rather
than an obvious failure.
"""

from __future__ import annotations

from warrantor_ml import benchmark_expguard as be
from warrantor_ml.evaluate import SampleOutcome


def _row(
    index: int,
    *,
    label: str = "unsafe",
    domain: str = "finance",
    category: str = "Fraud, Scams & Deception",
) -> be.ExpGuardRow:
    return be.ExpGuardRow(
        row_index=index,
        prompt=f"prompt {index}",
        response=f"response {index}",
        prompt_label=label,
        response_label="",
        prompt_category=category,
        response_category="",
        domain=domain,
        scenario="Margin (finance)",
    )


# ---------------------------------------------------------------------------
# Label handling -- where a flattering number would come from
# ---------------------------------------------------------------------------


def test_blank_prompt_label_is_dropped_not_coerced_to_safe() -> None:
    """A blank label means "no ground truth", which is not the same fact as "safe"."""

    rows = [_row(0), _row(1, label=""), _row(2, label="safe")]
    samples, dropped = be.to_eval_samples(rows)
    assert dropped == ("egt-00001",)
    assert [sample.sample_id for sample in samples] == ["egt-00000", "egt-00002"]
    assert [sample.unsafe for sample in samples] == [True, False]


def test_unknown_label_vocabulary_is_dropped_rather_than_guessed() -> None:
    samples, dropped = be.to_eval_samples([_row(0, label="probably_fine")])
    assert samples == ()
    assert dropped == ("egt-00000",)


def test_unharmful_category_is_not_attached_as_a_harm_category() -> None:
    """`Unharmful` is the literal category on all 1,019 safe rows. It is not a harm class."""

    samples, _ = be.to_eval_samples(
        [_row(0, category="Criminal Planning"), _row(1, label="safe", category="Unharmful")]
    )
    assert samples[0].categories == ("criminal planning",)
    assert samples[1].categories == ()


def test_samples_are_returned_in_sorted_id_order() -> None:
    samples, _ = be.to_eval_samples([_row(9), _row(0), _row(3)])
    assert [sample.sample_id for sample in samples] == ["egt-00000", "egt-00003", "egt-00009"]


# ---------------------------------------------------------------------------
# Schema description -- the run is not allowed to assume the domain vocabulary
# ---------------------------------------------------------------------------


def test_describe_corpus_reports_the_domain_vocabulary_it_actually_found() -> None:
    rows = [_row(0, domain="finance"), _row(1, domain="law"), _row(2, domain="law")]
    described = be.describe_corpus(rows)
    assert described["domain_values"] == {"finance": 1, "law": 2}
    assert described["domain_x_prompt_label"] == {"finance/unsafe": 1, "law/unsafe": 2}


def test_describe_corpus_states_that_there_is_no_general_band() -> None:
    """The brief expected a general band. The corpus has none, and the report must say so
    rather than silently comparing three verticals against a fourth thing that isn't there."""

    described = be.describe_corpus([_row(0)])
    assert described["general_band_present"] is False
    assert "no general" in described["general_band_note"]


# ---------------------------------------------------------------------------
# Stratification
# ---------------------------------------------------------------------------


def test_stratified_sample_preserves_every_domain_by_label_cell() -> None:
    """The per-domain positive count sets the width of the interval the conclusion rests on,
    so it must not be left to chance."""

    rows = (
        [_row(index, domain="finance", label="unsafe") for index in range(200)]
        + [_row(200 + index, domain="finance", label="safe") for index in range(200)]
        + [_row(400 + index, domain="healthcare", label="unsafe") for index in range(100)]
        + [_row(500 + index, domain="law", label="unsafe") for index in range(500)]
    )
    chosen = be.stratified_sample(rows, 100, seed=0)
    assert len(chosen) == 100
    cells: dict[tuple[str, str], int] = {}
    for row in chosen:
        cells[(row.domain, row.prompt_label)] = cells.get((row.domain, row.prompt_label), 0) + 1
    assert cells[("finance", "unsafe")] == 20
    assert cells[("finance", "safe")] == 20
    assert cells[("healthcare", "unsafe")] == 10
    assert cells[("law", "unsafe")] == 50


def test_stratified_sample_is_deterministic_for_a_seed() -> None:
    rows = [_row(index, domain=("finance", "law")[index % 2]) for index in range(50)]
    first = be.stratified_sample(rows, 20, seed=0)
    assert [row.row_index for row in first] == [
        row.row_index for row in be.stratified_sample(rows, 20, seed=0)
    ]
    assert [row.row_index for row in first] != [
        row.row_index for row in be.stratified_sample(rows, 20, seed=1)
    ]


def test_stratified_sample_returns_everything_when_size_exceeds_the_corpus() -> None:
    assert len(be.stratified_sample([_row(index) for index in range(5)], 500)) == 5


def test_stratified_sample_emits_rows_in_file_order() -> None:
    chosen = be.stratified_sample([_row(index) for index in range(100)], 20, seed=0)
    assert [row.row_index for row in chosen] == sorted(row.row_index for row in chosen)


# ---------------------------------------------------------------------------
# Is the gap real? -- the machinery the conclusion rests on
# ---------------------------------------------------------------------------


def test_wilson_interval_brackets_the_point_estimate() -> None:
    low, high = be.wilson_interval(90, 100)
    assert low < 0.9 < high
    assert 0.82 < low < 0.84
    assert 0.94 < high < 0.95


def test_wilson_interval_stays_inside_the_unit_range_at_a_perfect_score() -> None:
    """The normal approximation degenerates to the single point [1.0, 1.0] at p=1 -- zero width,
    infinite confidence, from a finite sample. Wilson keeps a real interval below the ceiling:
    100/100 is evidence for "high", never proof of "never misses"."""

    low, high = be.wilson_interval(100, 100)
    assert high <= 1.0
    assert 0.96 < low < 1.0
    assert high > low


def test_wilson_interval_reports_total_ignorance_for_zero_trials() -> None:
    assert be.wilson_interval(0, 0) == (0.0, 1.0)


def test_wilson_interval_is_wider_for_a_smaller_sample() -> None:
    narrow = be.wilson_interval(900, 1000)
    wide = be.wilson_interval(9, 10)
    assert (wide[1] - wide[0]) > (narrow[1] - narrow[0])


def _domain_payload(caught: int, missed: int) -> dict[str, object]:
    return {
        "recall": caught / (caught + missed) if caught + missed else 0.0,
        "confusion_matrix": {
            "true_positive": caught,
            "false_negative": missed,
            "false_positive": 0,
            "true_negative": 0,
            "total": caught + missed,
        },
    }


def test_domain_comparison_calls_a_small_gap_noise() -> None:
    """Three points of recall across ~400 positives per arm is not a finding."""

    comparison = be.domain_comparison(
        {
            "finance": _domain_payload(360, 40),
            "healthcare": _domain_payload(348, 52),
            "law": _domain_payload(352, 48),
        }
    )
    assert comparison["any_pair_separated_at_95"] is False
    assert all(pair["verdict"] == "within noise" for pair in comparison["pairwise"].values())
    assert "do not read a story into it" in comparison["verdict"]


def test_domain_comparison_detects_a_real_separation() -> None:
    comparison = be.domain_comparison(
        {
            "finance": _domain_payload(380, 20),
            "healthcare": _domain_payload(280, 120),
        }
    )
    pair = comparison["pairwise"]["finance_vs_healthcare"]
    assert pair["significant_at_95"] is True
    assert pair["verdict"] == "separated"
    assert pair["recall_delta"] > 0
    assert comparison["any_pair_separated_at_95"] is True


def test_domain_comparison_carries_the_positive_counts_behind_each_interval() -> None:
    """A recall with no denominator beside it is how a 2-of-3 band gets read as a trend."""

    comparison = be.domain_comparison({"law": _domain_payload(2, 1)})
    entry = comparison["per_domain_recall"]["law"]
    assert entry["positives"] == 3
    assert entry["caught"] == 2
    assert entry["wilson_95"][0] < entry["recall"] < entry["wilson_95"][1]


def test_domain_comparison_handles_an_arm_with_no_positives() -> None:
    comparison = be.domain_comparison(
        {"finance": _domain_payload(10, 0), "law": _domain_payload(0, 0)}
    )
    assert comparison["pairwise"]["finance_vs_law"]["z"] is None
    assert comparison["pairwise"]["finance_vs_law"]["verdict"] == "within noise"


# ---------------------------------------------------------------------------
# Breakdowns and failure accounting
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


class _FakeResult:
    """The one attribute :func:`be._breakdowns` reads, without running an evaluation."""

    def __init__(self, outcomes: tuple[SampleOutcome, ...]) -> None:
        self.outcomes = outcomes


def test_breakdowns_split_on_domain() -> None:
    outcomes = (
        _outcome("egt-00000", True, True),
        _outcome("egt-00001", True, False),
        _outcome("egt-00002", True, False),
    )
    rows_by_id = {
        "egt-00000": _row(0, domain="finance"),
        "egt-00001": _row(1, domain="healthcare"),
        "egt-00002": _row(2, domain="law"),
    }
    breakdowns = be._breakdowns(_FakeResult(outcomes), rows_by_id)
    assert breakdowns["by_domain"]["finance"]["recall"] == 1.0
    assert breakdowns["by_domain"]["healthcare"]["recall"] == 0.0
    assert breakdowns["by_domain"]["law"]["recall"] == 0.0
    assert set(breakdowns["by_domain"]) == {"finance", "healthcare", "law"}


def test_parse_failures_are_separated_from_transport_failures_and_attributed_to_a_domain() -> None:
    """A guard that answers off-format only on clinical text is a domain finding, not a bug
    report -- but only if parse failures are counted per domain instead of in one lump."""

    outcomes = (
        _outcome("egt-00000", True, True),
        _outcome(
            "egt-00001",
            True,
            True,
            errored=True,
            error_message=f"{be.PARSE_FAILURE_MARKER} a 'Safety:' verdict",
        ),
        _outcome(
            "egt-00002",
            False,
            True,
            errored=True,
            error_message="ollama request to http://127.0.0.1:11434 failed: timed out",
        ),
    )
    rows_by_id = {
        "egt-00000": _row(0, domain="finance"),
        "egt-00001": _row(1, domain="healthcare"),
        "egt-00002": _row(2, domain="law", label="safe"),
    }
    failures = be._breakdowns(_FakeResult(outcomes), rows_by_id)["failures"]
    assert failures["parse_failure_ids"] == ["egt-00001"]
    assert failures["transport_failure_ids"] == ["egt-00002"]
    assert failures["parse_failures_by_domain"] == {"finance": 0, "healthcare": 1, "law": 0}


def test_error_free_slice_removes_fail_closed_credit_from_per_domain_recall() -> None:
    """Fail-closed scores an errored sample HARMFUL, a free true positive. If that credit lands
    in one domain it manufactures exactly the per-domain difference this run is looking for."""

    outcomes = (
        _outcome("egt-00000", True, False),
        _outcome(
            "egt-00001",
            True,
            True,
            errored=True,
            error_message=f"{be.PARSE_FAILURE_MARKER} a 'Safety:' verdict",
        ),
    )
    rows_by_id = {"egt-00000": _row(0, domain="law"), "egt-00001": _row(1, domain="law")}
    breakdowns = be._breakdowns(_FakeResult(outcomes), rows_by_id)
    assert breakdowns["by_domain"]["law"]["recall"] == 0.5
    assert breakdowns["by_domain_excluding_errors"]["law"]["recall"] == 0.0
    assert breakdowns["overall"]["recall"] == 0.5
    assert breakdowns["excluding_all_backend_errors"]["recall"] == 0.0


def test_unharmful_category_is_excluded_from_the_harm_category_table() -> None:
    outcomes = (_outcome("egt-00000", True, True), _outcome("egt-00001", False, False))
    rows_by_id = {
        "egt-00000": _row(0, category="Criminal Planning"),
        "egt-00001": _row(1, label="safe", category="Unharmful"),
    }
    breakdowns = be._breakdowns(_FakeResult(outcomes), rows_by_id)
    assert set(breakdowns["by_prompt_category"]) == {"Criminal Planning"}


def test_severity_mix_is_reported_so_controversial_gating_is_auditable() -> None:
    """`Controversial` counts as harmful by default. How many verdicts that policy decided has
    to be visible, or the recall number silently depends on an invisible switch."""

    outcomes = (
        _outcome("egt-00000", True, True, severity="unsafe"),
        _outcome("egt-00001", True, True, severity="controversial"),
        _outcome("egt-00002", False, False, severity="safe"),
    )
    rows_by_id = {f"egt-0000{index}": _row(index) for index in range(3)}
    mix = be._breakdowns(_FakeResult(outcomes), rows_by_id)["severity_mix"]
    assert mix == {"controversial": 1, "safe": 1, "unsafe": 1}


def test_rehydrate_round_trips_a_serialised_summary() -> None:
    original = be.slice_summary(
        [_outcome("a", True, False), _outcome("b", False, False)], lambda _: True
    )
    rebuilt = be._rehydrate(original.to_dict())
    assert rebuilt.recall == original.recall
    assert rebuilt.matrix == original.matrix
