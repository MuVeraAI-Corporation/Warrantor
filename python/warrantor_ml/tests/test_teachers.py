"""The data doctrine, asserted as type and refusal rather than as documentation."""

from __future__ import annotations

from typing import Any

import pytest

from warrantor_ml import teachers
from warrantor_ml.teachers import (
    FrontierGenerationRefused,
    GeneratedRow,
    JudgeScore,
    UnknownJudgeError,
    generate,
    judge,
)


class _RecordingBackend:
    """A deterministic offline teacher backend. Never touches the network."""

    def __init__(self) -> None:
        self.seen: list[str] = []

    def descriptor(self) -> dict[str, Any]:
        return {"kind": "test-stub", "endpoint": "127.0.0.1", "num_ctx": 4096}

    def complete(self, prompt: str) -> str:
        self.seen.append(prompt)
        return f"completion for {prompt}"


def test_a_judge_cannot_generate_and_the_message_says_why() -> None:
    backend = _RecordingBackend()
    with pytest.raises(FrontierGenerationRefused, match="registered as a JUDGE"):
        generate(
            "frontier-judge",
            [("r1", "prompt")],
            backend,
            prompt_template="t",
            seed=1,
        )
    assert backend.seen == [], "the backend must not be touched before the id is checked"


def test_an_unregistered_model_cannot_generate() -> None:
    with pytest.raises(FrontierGenerationRefused, match="not a registered open-weight teacher"):
        generate(
            "some-hosted-model",
            [("r1", "prompt")],
            _RecordingBackend(),
            prompt_template="t",
            seed=1,
        )


def test_a_registered_teacher_generates_rows_and_a_provenance_block() -> None:
    rows, provenance = generate(
        "qwen3-14b-instruct",
        [("r1", "first"), ("r2", "second")],
        _RecordingBackend(),
        prompt_template="TEMPLATE v1",
        seed=42,
    )
    assert [row.row_id for row in rows] == ["r1", "r2"]
    assert all(isinstance(row, GeneratedRow) for row in rows)
    assert all(row.teacher_id == "qwen3-14b-instruct" for row in rows)
    assert provenance.role == "teacher"
    assert provenance.seed == 42
    # The backend descriptor rides along: num_ctx and the endpoint change the output, and a
    # provenance block that omits them overstates what it pins.
    assert provenance.decoding["backend"]["num_ctx"] == 4096


def test_the_prompt_template_is_digested_into_provenance() -> None:
    """Two runs of one teacher with different prompts produce different corpora."""

    _, first = generate(
        "qwen3-14b-instruct", [("r", "p")], _RecordingBackend(), prompt_template="A", seed=1
    )
    _, second = generate(
        "qwen3-14b-instruct", [("r", "p")], _RecordingBackend(), prompt_template="B", seed=1
    )
    assert first.prompt_template_digest != second.prompt_template_digest


def test_a_judge_score_is_not_a_generated_row() -> None:
    """The structural claim: a judge's output has no type any corpus builder accepts."""

    score = judge("frontier-judge", "sample-1", 0.2, "the target contradicts the prompt")
    assert isinstance(score, JudgeScore)
    assert not isinstance(score, GeneratedRow)
    # And the two types share no field that would let one be substituted for the other.
    assert not hasattr(score, "target")
    assert not hasattr(score, "teacher_id")


def test_a_judge_score_serialises_with_its_own_disclaimer() -> None:
    payload = judge("frontier-judge", "s", 0.5, "why").to_dict()
    assert payload["usable_as_training_data"] is False


def test_an_unregistered_judge_is_refused() -> None:
    with pytest.raises(UnknownJudgeError):
        judge("some-other-api", "s", 0.5, "why")


def test_a_teacher_may_not_be_used_as_a_judge() -> None:
    """A row judged by the model that wrote it is a measurement of nothing."""

    with pytest.raises(UnknownJudgeError):
        judge("qwen3-14b-instruct", "s", 0.5, "why")


def test_every_teacher_has_open_weights_and_a_digest_shaped_pin() -> None:
    for spec in teachers.TEACHERS.values():
        assert spec.open_weights is True
        assert spec.weights_digest.startswith("sha256:")
        assert len(spec.weights_digest) == len("sha256:") + 64


def test_no_judge_claims_open_weights() -> None:
    """A hosted model has no weights anyone can digest, which is why it cannot teach."""

    for spec in teachers.JUDGES.values():
        assert spec.open_weights is False
        assert spec.weights_digest == ""


def test_the_teacher_and_judge_rosters_do_not_overlap() -> None:
    assert not set(teachers.TEACHERS) & set(teachers.JUDGES)


def test_the_roster_digest_is_stable() -> None:
    assert teachers.roster_digest() == teachers.roster_digest()
    assert teachers.roster_digest().startswith("sha256:")
