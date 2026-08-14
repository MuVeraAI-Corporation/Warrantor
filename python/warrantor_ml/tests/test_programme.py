"""The documented CLI surface: exit codes, and the refusals reachable through it.

Everything the findings in this area were about is reachable only through ``parity_main`` -- the
gate's own docstring separates exit 3 (``insufficient_evidence``) from exit 1 (``reject``) because
"a CI job that treats them the same will retry the wrong one", and until now nothing asserted the
mapping held. An uncaught exception exits 1, which is indistinguishable from a rejection to
anything reading exit codes, so a crash on the documented path was silently a false rejection.

Nothing here trains, downloads, or contacts a backend.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from warrantor_ml.benchmark_expguard import build_eval_set_descriptor as expguard_descriptor
from warrantor_ml.benchmark_wildguard import build_eval_set_descriptor as wildguard_descriptor
from warrantor_ml.programme import _read_corpus, export_main, lanes_main, parity_main

PROMOTE, REJECT, INSUFFICIENT = 0, 1, 3


def _slice(caught: int, positives: int, false_positives: int, negatives: int) -> dict[str, object]:
    return {
        "recall": caught / positives if positives else 0.0,
        "confusion_matrix": {
            "true_positive": caught,
            "false_negative": positives - caught,
            "false_positive": false_positives,
            "true_negative": negatives - false_positives,
        },
    }


def _wildguard_document(tmp_path: Path, caught: int = 700, false_positives: int = 50) -> Path:
    parquet = tmp_path / "wildguard_test.parquet"
    parquet.write_bytes(b"a stand-in for the split; it only has to have a digest")
    document = {
        "result_digest": "sha256:" + "9" * 64,
        "eval_set": wildguard_descriptor(parquet, range(1725), range(1699), []),
        "backend_errors": {"count": 0},
        "wildguard_breakdowns": {
            "overall": _slice(caught, 753, false_positives, 946),
            "by_subcategory": {
                "social_stereotypes_and_unfair_discrimination": {"recall": 0.90},
                "fraud_assisting_illegal_activities": {"recall": 0.90},
                "others": {"recall": 0.90},
            },
        },
    }
    path = tmp_path / "wildguard_result.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _expguard_document(tmp_path: Path) -> Path:
    parquet = tmp_path / "expguardtest.parquet"
    parquet.write_bytes(b"a stand-in for the other split")
    document = {
        "result_digest": "sha256:" + "7" * 64,
        "eval_set": expguard_descriptor(parquet, range(2275), range(2275), [], None, 0),
        "backend_errors": {"count": 0},
        "expguard_breakdowns": {
            "overall": _slice(1130, 1256, 20, 1019),
            "by_prompt_category": {"Unqualified Professional Advice": {"recall": 0.80}},
        },
    }
    path = tmp_path / "expguard_result.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _argv(result: Path, recipe: str, breakdown: str = "wildguard_breakdowns") -> list[str]:
    return [
        "--result",
        str(result),
        "--recipe",
        recipe,
        "--lane",
        "local-rtx5080",
        "--precision",
        "gguf-q4_k_m",
        "--manifest-digest",
        "sha256:" + "3" * 64,
        "--breakdown-key",
        breakdown,
    ]


def _leakage_corpora(tmp_path: Path) -> list[str]:
    training = tmp_path / "train.jsonl"
    evaluation = tmp_path / "eval.jsonl"
    training.write_text(json.dumps({"prompt": "a training row"}) + "\n", encoding="utf-8")
    evaluation.write_text(json.dumps({"prompt": "a held out row"}) + "\n", encoding="utf-8")
    return ["--training-corpus", str(training), "--eval-corpus", str(evaluation)]


def test_the_documented_path_promotes_a_genuine_improvement(tmp_path: Path) -> None:
    """The happy path, so the refusals below are refusals and not a broken harness."""

    argv = _argv(_wildguard_document(tmp_path), "guard-4b-weak-category") + _leakage_corpora(
        tmp_path
    )
    assert parity_main(argv) == PROMOTE


def test_a_recipe_with_no_measured_baseline_exits_3_rather_than_crashing(tmp_path: Path) -> None:
    """The four substrate recipes declare ``baseline_id`` as ''.

    ``get_baseline('')`` raised an uncaught KeyError, and an unhandled exception exits 1 -- the
    status this CLI's own docstring assigns to ``reject``. RFC W2's M3 milestone says the gate
    "will correctly return insufficient_evidence" for models 5-7; through the documented entry
    point it could not, and the crash was indistinguishable from a rejection.
    """

    argv = _argv(_wildguard_document(tmp_path), "bound-proposer") + _leakage_corpora(tmp_path)
    assert parity_main(argv) == INSUFFICIENT


def test_an_expguard_document_against_a_wildguard_recipe_exits_3(tmp_path: Path) -> None:
    """The confusion the CLI permits: --breakdown-key is a free choice, baseline_id is not.

    Every guard recipe declares the WildGuardTest baseline. Scored this way the gate used to
    report ``promote`` with the reason "recall improved beyond sampling noise (0.8554 ->
    0.8997)" -- ExpGuard recall measured against the WildGuard baseline, digested and archived
    as auditable evidence naming the wrong corpus on its own face.
    """

    argv = _argv(
        _expguard_document(tmp_path), "guard-4b-weak-category", "expguard_breakdowns"
    ) + _leakage_corpora(tmp_path)
    assert parity_main(argv) == INSUFFICIENT


def test_a_document_the_gate_cannot_read_exits_3_not_1(tmp_path: Path) -> None:
    """Naming the wrong breakdown key raised ValueError, which exits 1 -- ``reject``."""

    argv = _argv(
        _expguard_document(tmp_path), "guard-4b-weak-category", "wildguard_breakdowns"
    ) + _leakage_corpora(tmp_path)
    assert parity_main(argv) == INSUFFICIENT


def test_an_unchecked_leakage_report_blocks_rather_than_passing(tmp_path: Path) -> None:
    """Not checking is not the same as checking and finding nothing."""

    argv = _argv(_wildguard_document(tmp_path), "guard-4b-weak-category")
    assert parity_main(argv) == INSUFFICIENT


def test_a_candidate_that_buys_recall_with_false_alarms_exits_1(tmp_path: Path) -> None:
    """Reject and insufficient_evidence are different answers and different exit codes."""

    argv = _argv(
        _wildguard_document(tmp_path, caught=750, false_positives=400), "guard-4b-weak-category"
    ) + _leakage_corpora(tmp_path)
    assert parity_main(argv) == REJECT


def test_the_written_decision_carries_the_digests_and_the_corpus_it_was_bound_to(
    tmp_path: Path,
) -> None:
    out = tmp_path / "decision.json"
    argv = (
        _argv(_wildguard_document(tmp_path), "guard-4b-weak-category")
        + _leakage_corpora(tmp_path)
        + ["--out", str(out)]
    )
    assert parity_main(argv) == PROMOTE

    body = json.loads(out.read_text(encoding="utf-8"))
    evidence = body["evidence"]
    assert body["decision_digest"].startswith("sha256:")
    assert evidence["eval_set_digest"].startswith("sha256:")
    assert evidence["candidate_eval_corpus_digest"] == evidence["baseline_corpus_digest"]
    assert evidence["baseline_corpus"] == "allenai/wildguardmix:test/wildguard_test.parquet"
    assert evidence["per_category_floors_checked"] == [
        "fraud assisting illegal activities",
        "others",
        "social stereotypes and unfair discrimination",
    ]


def test_the_lane_router_requires_the_corpus_size_rather_than_assuming_one() -> None:
    """The session-cap refusal is only as true as the row count it is computed from.

    A substituted default lets the router approve a lane for a corpus it was never shown --
    and the Kaggle cap exists to be discovered before the run, not at hour eleven.
    """

    with pytest.raises(SystemExit):
        lanes_main(["--recipe", "guard-0.6b-weak-category", "--lane", "kaggle-t4x2"])


def test_the_exporter_requires_the_corpus_size_rather_than_assuming_one(tmp_path: Path) -> None:
    """corpus_rows is embedded in RUN_MANIFEST; a default writes a run that was never planned."""

    with pytest.raises(SystemExit):
        export_main(
            [
                "--recipe",
                "guard-0.6b-weak-category",
                "--lane",
                "modal-a100",
                "--out",
                str(tmp_path / "runner.py"),
            ]
        )


def test_the_gate_reads_the_eval_split_as_parquet(tmp_path: Path) -> None:
    """The splits ARE parquet. Demanding JSONL forced a hand-export nothing here produces.

    That export is where the text ends up under a key the leakage comparison does not read --
    which fingerprints nothing and used to report the eval set as held out. Reading the parquet
    with the same loader the corpus builder uses makes the compared field the built field by
    construction rather than by agreement.
    """

    pytest.importorskip("pyarrow")
    import pandas as pd

    split = tmp_path / "eval.parquet"
    pd.DataFrame(
        {
            "prompt": ["fake an invoice", "capital of Oman"],
            "prompt_harm_label": ["harmful", "unharmful"],
            "subcategory": ["fraud_assisting_illegal_activities", "benign"],
        }
    ).to_parquet(split)

    rows = _read_corpus(split)
    assert len(rows) == 2
    assert rows[0]["prompt"] == "fake an invoice"
    # The key the leakage comparison actually reads.
    assert all("prompt" in row for row in rows)
