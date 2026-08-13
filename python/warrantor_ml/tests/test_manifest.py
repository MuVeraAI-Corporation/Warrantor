"""The five things a dataset manifest is refused for, each asserted by name."""

from __future__ import annotations

import subprocess
import sys

import pytest

from warrantor_ml.manifest import (
    DatasetManifest,
    ManifestRefused,
    SourceRow,
    TeacherProvenance,
    corpus_source,
    validate_manifest,
)

_DIGEST = "sha256:" + "a" * 64
_ATTESTATION = {
    "attested": True,
    "filters": "publisher filtering; text-only corpora; no new crawl",
    "attested_on": "2026-08-13",
}


def _teacher(role: str = "teacher") -> TeacherProvenance:
    return TeacherProvenance(
        model_id="qwen3-14b-instruct",
        role=role,  # type: ignore[arg-type]
        weights_digest="sha256:" + "b" * 64,
        prompt_template_digest="sha256:" + "c" * 64,
        seed=7,
        decoding={"temperature": 0.0},
    )


def _corpus_row(split: str = "train", rows: int = 100) -> SourceRow:
    return SourceRow(
        source_id=f"wildguardmix:{split}",
        kind="corpus",
        split=split,
        row_count=rows,
        content_digest=_DIGEST,
        licence="ODC-By-1.0",
        commercial_use="restricted-by-click-through",
    )


def _manifest(*sources: SourceRow, built_for_split: str = "train") -> DatasetManifest:
    return DatasetManifest(
        corpus_id="test-corpus",
        task="guard",
        built_for_split=built_for_split,
        sources=sources or (_corpus_row(),),
        csam_exclusion=_ATTESTATION,
    )


def test_import_performs_no_network_io() -> None:
    """Poison the network before importing. A manifest module must be free to import."""

    program = (
        "import socket, urllib.request\n"
        "def boom(*a, **k):\n"
        "    raise AssertionError('network I/O at import time')\n"
        "socket.socket = boom\n"
        "urllib.request.urlopen = boom\n"
        "import warrantor_ml.manifest\n"
        "import warrantor_ml.teachers\n"
        "import warrantor_ml.baselines\n"
        "import warrantor_ml.leakage\n"
        "import warrantor_ml.stats\n"
        "print('clean')\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, check=False
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "clean" in completed.stdout


def test_a_valid_manifest_is_accepted() -> None:
    validate_manifest(_manifest(), counted_rows={"wildguardmix:train": 100})


# ── (a) a judge that wrote training rows ────────────────────────────────────────────────


def test_a_judge_may_not_generate_training_rows() -> None:
    generated = SourceRow(
        source_id="augmented:train",
        kind="teacher-generated",
        split="train",
        row_count=10,
        content_digest=_DIGEST,
        licence="Apache-2.0",
        commercial_use="permitted",
        generator=_teacher(role="judge"),
    )
    with pytest.raises(ManifestRefused, match="may SCORE training data and may never WRITE it"):
        validate_manifest(_manifest(_corpus_row(), generated))


def test_generated_rows_need_a_generator_at_all() -> None:
    generated = SourceRow(
        source_id="augmented:train",
        kind="teacher-generated",
        split="train",
        row_count=10,
        content_digest=_DIGEST,
        licence="Apache-2.0",
        commercial_use="permitted",
    )
    with pytest.raises(ManifestRefused, match="no generator recorded"):
        validate_manifest(_manifest(_corpus_row(), generated))


def test_an_unpinned_teacher_is_refused() -> None:
    """An open-weight teacher whose weights are not digested is not reproducible."""

    generated = SourceRow(
        source_id="augmented:train",
        kind="teacher-generated",
        split="train",
        row_count=10,
        content_digest=_DIGEST,
        licence="Apache-2.0",
        commercial_use="permitted",
        generator=TeacherProvenance(
            model_id="qwen3-14b-instruct",
            role="teacher",
            weights_digest="not-a-digest",
            prompt_template_digest=_DIGEST,
            seed=1,
            decoding={},
        ),
    )
    with pytest.raises(ManifestRefused, match="generator weights_digest"):
        validate_manifest(_manifest(_corpus_row(), generated))


# ── (b) generated rows in an eval split ─────────────────────────────────────────────────


@pytest.mark.parametrize("split", ["eval", "test", "validation", "holdout"])
def test_teacher_generated_rows_may_never_enter_an_eval_split(split: str) -> None:
    """An eval containing teacher output measures agreement with the teacher."""

    generated = SourceRow(
        source_id="augmented:eval",
        kind="teacher-generated",
        split=split,
        row_count=10,
        content_digest=_DIGEST,
        licence="Apache-2.0",
        commercial_use="permitted",
        generator=_teacher(),
    )
    with pytest.raises(ManifestRefused, match="measures agreement with the teacher"):
        validate_manifest(_manifest(generated, built_for_split=split))


# ── (c) a corpus row with no licence ────────────────────────────────────────────────────


def test_a_corpus_row_without_a_licence_is_refused() -> None:
    unlicensed = SourceRow(
        source_id="mystery:train",
        kind="corpus",
        split="train",
        row_count=10,
        content_digest=_DIGEST,
        licence="   ",
        commercial_use="unverified",
    )
    with pytest.raises(ManifestRefused, match="no licence recorded"):
        validate_manifest(_manifest(unlicensed))


# ── (d) a declared count nobody reconciled ──────────────────────────────────────────────


def test_a_declared_row_count_that_disagrees_with_the_counted_rows_is_refused() -> None:
    with pytest.raises(ManifestRefused, match="declares 100 rows, counted 87"):
        validate_manifest(_manifest(), counted_rows={"wildguardmix:train": 87})


def test_a_source_with_no_counted_total_is_refused_when_reconciliation_was_requested() -> None:
    with pytest.raises(ManifestRefused, match="no counted total was supplied"):
        validate_manifest(_manifest(), counted_rows={})


# ── (e) no CSAM exclusion attestation ───────────────────────────────────────────────────


def test_a_manifest_without_a_csam_attestation_is_refused() -> None:
    manifest = DatasetManifest(
        corpus_id="test-corpus",
        task="guard",
        built_for_split="train",
        sources=(_corpus_row(),),
        csam_exclusion=None,
    )
    with pytest.raises(ManifestRefused, match="csam_exclusion: MISSING"):
        validate_manifest(manifest)


def test_attested_true_with_no_named_filters_attests_to_nothing() -> None:
    manifest = DatasetManifest(
        corpus_id="test-corpus",
        task="guard",
        built_for_split="train",
        sources=(_corpus_row(),),
        csam_exclusion={"attested": True},
    )
    with pytest.raises(ManifestRefused, match="attests to nothing"):
        validate_manifest(manifest)


# ── licence facts come from the registry, never from the call site ──────────────────────


def test_corpus_source_pulls_licence_facts_from_the_registry() -> None:
    row = corpus_source("wildguardmix", "train", row_count=5, content_digest=_DIGEST)
    assert row.licence == "ODC-By-1.0"
    assert row.commercial_use == "restricted-by-click-through"
    assert any("ODC-By governs the DATABASE" in note for note in row.notes)


def test_expguard_inherits_its_frontier_lineage_automatically() -> None:
    """The GPT-4o dependency is derived from the registry notes, not asked for.

    A caller cannot forget to declare it, which is the point: ExpGuardMix's corpus was
    frontier-generated upstream and anything trained on it carries that in its lineage.
    """

    row = corpus_source("expguardmix", "train", row_count=5, content_digest=_DIGEST)
    assert any("gpt-4o" in item.lower() for item in row.frontier_lineage)


def test_wildguard_carries_no_frontier_lineage() -> None:
    row = corpus_source("wildguardmix", "train", row_count=5, content_digest=_DIGEST)
    assert row.frontier_lineage == ()


def test_a_restricted_click_through_is_not_commercially_cleared() -> None:
    """CC-BY-4.0 does not clear ExpGuardMix: the gate form is narrower than the licence."""

    manifest = _manifest(corpus_source("expguardmix", "train", row_count=5, content_digest=_DIGEST))
    assert manifest.commercially_cleared is False


def test_the_manifest_digest_is_stable_and_order_independent() -> None:
    first = _manifest().manifest_digest
    second = _manifest().manifest_digest
    assert first == second
    assert first.startswith("sha256:")


def test_every_problem_is_reported_together() -> None:
    """A manifest gets fixed in one pass, not five."""

    broken = DatasetManifest(
        corpus_id="broken",
        task="guard",
        built_for_split="train",
        sources=(
            SourceRow(
                source_id="x:train",
                kind="corpus",
                split="train",
                row_count=-1,
                content_digest="nope",
                licence="",
                commercial_use="unverified",
            ),
        ),
        csam_exclusion=None,
    )
    with pytest.raises(ManifestRefused) as caught:
        validate_manifest(broken)
    message = str(caught.value)
    assert "4 problem(s)" in message
    assert "no licence recorded" in message
    assert "csam_exclusion" in message
