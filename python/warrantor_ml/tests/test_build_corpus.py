"""The corpus CLI: describe first, refuse loudly, and never write a corpus without a manifest."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from warrantor_ml.build_corpus import ExcessiveLeakageError, build_guard_corpus, main
from warrantor_ml.tasks.guard import GuardCorpusRow


def _rows() -> tuple[GuardCorpusRow, ...]:
    return (
        GuardCorpusRow(
            "r0", "advise on my dose", "harmful", False, "Unqualified Professional Advice"
        ),
        GuardCorpusRow(
            "r1", "fake an invoice", "harmful", True, "fraud_assisting_illegal_activities"
        ),
        GuardCorpusRow("r2", "capital of Oman", "unharmful", False, "benign"),
        GuardCorpusRow("r3", "summarise this", "unharmful", True, "benign"),
    )


def _write_split(path: Path) -> Path:
    records = [
        {
            "prompt": "advise on my dose",
            "prompt_harm_label": "harmful",
            "adversarial": False,
            "subcategory": "Unqualified Professional Advice",
        },
        {
            "prompt": "fake an invoice",
            "prompt_harm_label": "harmful",
            "adversarial": True,
            "subcategory": "fraud_assisting_illegal_activities",
        },
        {
            "prompt": "capital of Oman",
            "prompt_harm_label": "unharmful",
            "adversarial": False,
            "subcategory": "benign",
        },
        {
            "prompt": "summarise this",
            "prompt_harm_label": "unharmful",
            "adversarial": True,
            "subcategory": "benign",
        },
    ]
    path.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")
    return path


def test_building_a_weak_category_corpus_emits_a_valid_manifest(tmp_path: Path) -> None:
    manifest, summary = build_guard_corpus(
        _rows(), "weak-category", 1.0, tmp_path / "corpus.jsonl", "wildguardmix", "train"
    )
    assert summary["pairs_written"] == summary["positives"] + summary["benign_counterweight"]
    assert summary["positives"] == 2
    assert manifest.manifest_digest.startswith("sha256:")
    assert (tmp_path / "corpus.jsonl").exists()


def test_the_manifest_records_that_the_corpus_is_not_commercially_cleared(
    tmp_path: Path,
) -> None:
    """WildGuardMix's click-through is narrower than ODC-By."""

    manifest, _ = build_guard_corpus(
        _rows(), "weak-category", 0.0, tmp_path / "c.jsonl", "wildguardmix", "train"
    )
    assert manifest.commercially_cleared is False


def test_the_manifest_reconciles_the_declared_count_against_the_written_rows(
    tmp_path: Path,
) -> None:
    manifest, summary = build_guard_corpus(
        _rows(), "adversarial", 1.0, tmp_path / "c.jsonl", "wildguardmix", "train"
    )
    assert manifest.declared_rows == summary["pairs_written"]


def test_an_expguard_corpus_inherits_the_frontier_lineage(tmp_path: Path) -> None:
    manifest, _ = build_guard_corpus(
        _rows(), "weak-category", 0.0, tmp_path / "c.jsonl", "expguardmix", "train"
    )
    assert any("gpt-4o" in item.lower() for item in manifest.frontier_lineage)


def test_an_unknown_selector_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown guard selector"):
        build_guard_corpus(_rows(), "vibes", 1.0, tmp_path / "c.jsonl", "wildguardmix", "train")


# ── the CLI ─────────────────────────────────────────────────────────────────────────────


def test_describe_only_writes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    split = _write_split(tmp_path / "split.jsonl")
    assert main(["--task", "guard", "--rows", str(split), "--describe-only"]) == 0
    described = json.loads(capsys.readouterr().out)
    assert described["row_count"] == 4
    assert described["adversarial_column_present"] is True
    assert not (tmp_path / "corpus.jsonl").exists()


def test_the_cli_requires_a_benign_ratio(tmp_path: Path) -> None:
    """argparse exits 2. There is no default because zero has to be written down."""

    split = _write_split(tmp_path / "split.jsonl")
    with pytest.raises(SystemExit):
        main(
            [
                "--task",
                "guard",
                "--rows",
                str(split),
                "--selector",
                "weak-category",
                "--out",
                str(tmp_path / "c.jsonl"),
            ]
        )


def test_the_cli_builds_a_corpus_and_writes_a_manifest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    split = _write_split(tmp_path / "split.jsonl")
    code = main(
        [
            "--task",
            "guard",
            "--rows",
            str(split),
            "--selector",
            "weak-category",
            "--benign-ratio",
            "1.0",
            "--out",
            str(tmp_path / "corpus.jsonl"),
            "--manifest",
            str(tmp_path / "manifest.json"),
        ]
    )
    assert code == 0
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["format"] == "warrantor.dataset-manifest/1"
    assert manifest["manifest_digest"].startswith("sha256:")
    assert manifest["csam_exclusion"]["attested"] is True
    assert capsys.readouterr().out


def test_a_selector_that_matches_nothing_exits_non_zero_rather_than_writing_an_empty_corpus(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An empty corpus and a broken selector look identical on disk."""

    split = tmp_path / "split.jsonl"
    split.write_text(
        json.dumps({"prompt": "x", "prompt_harm_label": "harmful", "subcategory": "unrelated"})
        + "\n",
        encoding="utf-8",
    )
    code = main(
        [
            "--task",
            "guard",
            "--rows",
            str(split),
            "--selector",
            "weak-category",
            "--benign-ratio",
            "0",
            "--out",
            str(tmp_path / "corpus.jsonl"),
        ]
    )
    assert code == 2
    assert "CORPUS NOT BUILT" in capsys.readouterr().out


def test_a_substrate_task_says_there_is_no_corpus_rather_than_emitting_an_empty_one(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The honest state, stated: the pipeline is built and cannot yet be exercised."""

    assert main(["--task", "bounds"]) == 0
    output = capsys.readouterr().out
    assert "no corpus of real warrants" in output
    assert "insufficient_evidence" in output


def test_a_row_that_appears_in_the_eval_split_is_excluded_before_selection(
    tmp_path: Path,
) -> None:
    """The gate refuses a leaked corpus after training. The builder refuses to make one."""

    output = tmp_path / "corpus.jsonl"
    manifest, summary = build_guard_corpus(
        _rows(),
        "weak-category",
        1.0,
        output,
        "wildguardmix",
        "train",
        # One collision in a realistically-sized eval split: 1/201 is an upstream duplicate,
        # which is repairable. The ceiling is a fraction OF THE EVAL SET, so a tiny eval split
        # can never repair anything -- one leaked row out of a hundred really is alarming.
        eval_prompts=("Advise on my dose!", *(f"unrelated eval prompt {n}" for n in range(200))),
    )

    # Normalised comparison: the eval row differs by case and punctuation and is still the
    # same row. Matching on raw text would let exactly that variant through.
    assert summary["leakage"]["excluded_row_count"] == 1
    assert summary["leakage"]["excluded_row_ids"] == ["r0"]
    written = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert not any(pair["row_id"] == "r0" for pair in written)
    assert any("hold-out verified at build time" in note for note in manifest.sources[0].notes)


def test_a_corpus_built_without_an_eval_split_records_that_holdout_was_not_verified(
    tmp_path: Path,
) -> None:
    """Silent about hold-out and checked-and-clean are different facts, so they read differently."""

    manifest, summary = build_guard_corpus(
        _rows(), "weak-category", 1.0, tmp_path / "corpus.jsonl", "wildguardmix", "train"
    )

    assert summary["leakage"] is None
    assert any("hold-out NOT verified" in note for note in manifest.sources[0].notes)


def test_an_overlap_too_large_to_be_a_duplicate_is_refused_rather_than_repaired(
    tmp_path: Path,
) -> None:
    """Dropping thousands of rows would read in the manifest exactly like dropping one."""

    # Every eval prompt collides, which is what a mis-supplied split looks like.
    with pytest.raises(ExcessiveLeakageError) as refusal:
        build_guard_corpus(
            _rows(),
            "weak-category",
            1.0,
            tmp_path / "corpus.jsonl",
            "wildguardmix",
            "train",
            eval_prompts=("advise on my dose", "fake an invoice"),
        )

    assert "not the held-out pair" in str(refusal.value)
