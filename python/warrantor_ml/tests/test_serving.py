"""The deployed serving configuration record, and the rule that absence is never agreement."""

from __future__ import annotations

from typing import Any

import pytest

from warrantor_ml import serving
from warrantor_ml._canonical import canonical_json, sha256_text
from warrantor_ml.baselines import get_baseline
from warrantor_ml.evaluate import OllamaGuardBackend


def test_an_absent_field_is_a_mismatch_and_not_a_match() -> None:
    """The whole design, in one assertion.

    The five 2026-08-22 candidate result documents record no quantization at all. If an absent
    field read as agreement, all five would compare equal to whatever this build serves, and the
    gate would report parity it never checked.
    """

    missing = serving.configuration_mismatch({})
    assert len(missing) == len(serving.REQUIRED_KEYS)
    assert all("absent" in entry for entry in missing)
    for key in serving.REQUIRED_KEYS:
        assert any(entry.startswith(f"{key} is absent") for entry in missing), key


def test_the_deployed_record_agrees_with_itself() -> None:
    assert serving.configuration_mismatch(serving.DEPLOYED) == ()


def test_a_partial_configuration_is_refused_on_exactly_the_keys_it_omits() -> None:
    """Allowed control for the absence rule: the fields that ARE recorded do not also fail."""

    recorded = {"quantisation": serving.QUANTIZATION, "num_ctx": serving.NUM_CTX}
    problems = serving.configuration_mismatch(recorded)
    assert len(problems) == len(serving.REQUIRED_KEYS) - 2
    assert not any(entry.startswith("quantisation") for entry in problems)
    assert not any(entry.startswith("num_ctx") for entry in problems)


def test_a_mismatch_names_the_field_and_both_values() -> None:
    """A refusal an operator cannot act on gets bypassed rather than fixed."""

    (problem,) = serving.configuration_mismatch({**serving.DEPLOYED, "quantisation": "Q8_0"})
    assert "quantisation" in problem
    assert "Q8_0" in problem
    assert serving.QUANTIZATION in problem


def test_an_integer_temperature_of_zero_is_the_same_temperature_as_a_float_zero() -> None:
    """Allowed control. JSON round-trips 0.0 as 0 sometimes; that is not a configuration change."""

    assert serving.configuration_mismatch({**serving.DEPLOYED, "temperature": 0}) == ()
    assert serving.configuration_mismatch({**serving.DEPLOYED, "top_p": 1}) == ()


def test_a_boolean_never_passes_for_the_integer_it_equals() -> None:
    """``True == 1`` in Python. A ``top_k`` of ``True`` is not a ``top_k`` of 1."""

    problems = serving.configuration_mismatch({**serving.DEPLOYED, "top_k": True})
    assert len(problems) == 1
    assert "top_k" in problems[0]


def test_the_evaluator_that_produced_every_published_figure_is_at_the_deployed_configuration() -> (
    None
):
    """The binding that makes the record a record rather than an opinion.

    ``OllamaGuardBackend`` is the backend both benchmark modules score through. If its defaults
    could differ from :data:`serving.DEPLOYED`, then the gate would be comparing candidates
    against a configuration nothing was measured at.
    """

    backend = OllamaGuardBackend(model="hf.co/example:Q4_K_M")
    recorded = serving.recorded_serving_configuration(backend.descriptor())
    assert serving.configuration_mismatch(recorded) == ()


def test_the_measured_baselines_declare_the_deployed_configuration_on_the_keys_they_carry() -> None:
    """``baselines._ollama_backend`` holds its own literal; this is what keeps the two equal.

    It records five of the seven comparison keys (no ``top_p``, no ``num_predict``), so the
    assertion is scoped to what it declares. Scoping it is not weakening it: the point is that a
    key it DOES declare may never disagree, and a future key it gains is caught by the same loop.
    """

    for baseline_id in ("wildguardtest-qwen3guard-gen-4b", "expguardtest-qwen3guard-gen-4b"):
        declared: dict[str, Any] = dict(get_baseline(baseline_id).backend)
        overlapping = {
            key: value for key, value in declared.items() if key in serving.REQUIRED_KEYS
        }
        assert overlapping, baseline_id
        for key, value in overlapping.items():
            assert serving.configuration_mismatch({**serving.DEPLOYED, key: value}) == (), (
                f"baseline {baseline_id} declares {key}={value!r}, which is not what "
                f"serving.DEPLOYED serves"
            )


def test_the_digest_is_stable_and_moves_when_the_record_moves(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The name promised movement and the body asserted only a prefix and self-equality.

    Replacing the function's body with a constant digest passed the whole suite: the CI test
    writes whatever ``deployed_digest()`` returns into its own sandbox record, so the property
    was held by the committed ``deployment-parity.json`` and not by any test. Two assertions fix
    that -- the digest is the canonical digest OF the record, and moving one field moves it.
    """

    assert serving.deployed_digest().startswith("sha256:")
    assert serving.deployed_digest() == serving.deployed_digest()
    assert serving.deployed_digest() == sha256_text(canonical_json(dict(serving.DEPLOYED)))

    unchanged = serving.deployed_digest()
    monkeypatch.setattr(serving, "DEPLOYED", {**serving.DEPLOYED, "num_ctx": 4096})
    moved = serving.deployed_digest()
    assert moved != unchanged, "a digest that does not move with the record pins nothing"
    assert moved == sha256_text(canonical_json(dict(serving.DEPLOYED)))


def test_the_descriptor_shape_and_the_baseline_shape_are_both_readable() -> None:
    """Two shapes are in circulation and both are read, rather than one being declared wrong."""

    nested = {
        "kind": "ollama",
        "quantisation": "Q4_K_M",
        "seed": 0,
        "options": {
            "temperature": 0.0,
            "top_p": 1.0,
            "top_k": 1,
            "seed": 0,
            "num_predict": 64,
            "num_ctx": 8192,
        },
    }
    flat = {
        "kind": "ollama",
        "quantisation": "Q4_K_M",
        "num_ctx": 8192,
        "temperature": 0.0,
        "top_k": 1,
        "top_p": 1.0,
        "num_predict": 64,
        "seed": 0,
    }
    assert serving.configuration_mismatch(serving.recorded_serving_configuration(nested)) == ()
    assert serving.configuration_mismatch(serving.recorded_serving_configuration(flat)) == ()


def test_a_key_present_nowhere_is_omitted_rather_than_defaulted() -> None:
    """The flattener must not invent values, or the mismatch check has nothing left to catch."""

    recorded = serving.recorded_serving_configuration({"kind": "ollama", "model": "x"})
    assert recorded == {}


def test_the_five_committed_candidate_documents_record_no_quantization() -> None:
    """Finding D, as an assertion rather than a paragraph.

    This is the state of the evidence on this branch: every 2026-08-22 candidate document is
    missing the one axis with a measured effect. If a future run makes this test fail, the
    pipeline started recording quantization and the recorded expectation in
    ``tools/ci/deployment-parity.json`` has to move in the same commit.
    """

    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[3] / "eval_results"
    candidates = sorted(root.glob("warrantor-guard-*.json"))
    assert len(candidates) == 5, sorted(path.name for path in candidates)
    for path in candidates:
        backend = json.loads(path.read_text(encoding="utf-8")).get("backend", {})
        recorded = serving.recorded_serving_configuration(backend)
        assert "quantisation" not in recorded, path.name
        assert any(
            "quantisation is absent" in entry for entry in serving.configuration_mismatch(recorded)
        ), path.name


def test_the_two_baseline_documents_name_their_quantization_in_their_tag() -> None:
    """The paired control for the test above, and the distinction the census reports.

    Neither baseline document carries a ``quantisation`` FIELD -- both were written by the
    version-1 ``descriptor()``. Their tags name ``Q4_K_M``, which is where the fact was actually
    recorded, and reading it there is what separates them from the five unlabeled candidates.
    """

    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[3] / "eval_results"
    for name in ("wildguard-2026-08-21.json", "expguard-2026-08-21.json"):
        backend = json.loads((root / name).read_text(encoding="utf-8"))["backend"]
        assert "quantisation" not in backend, name
        recorded = serving.recorded_serving_configuration(backend)
        assert recorded["quantisation"] == "Q4_K_M", name
        assert serving.configuration_mismatch(recorded) == (), name


def test_the_tag_reader_refuses_to_turn_a_version_suffix_into_a_configuration_claim() -> None:
    """Narrow on purpose. A wrong-and-unchecked provenance field is worse than an absent one."""

    assert serving.quantisation_in_tag("hf.co/x/Qwen3Guard-Gen-4B-GGUF:Q4_K_M") == "Q4_K_M"
    assert serving.quantisation_in_tag("some/model:Q8_0") == "Q8_0"
    assert serving.quantisation_in_tag("some/model:IQ4_XS") == "IQ4_XS"
    assert serving.quantisation_in_tag("some/model:F16") == "F16"
    for tag in (
        "warrantor-guard-0.6b-expguard-weak-exp06-2026-08-22a",
        "some/model:latest",
        "some/model:v2",
        "some/model:",
        "",
        "qwen3guard",
        # A model NAME whose suffix starts with the same letter as a quantization label. The
        # first reader asked only whether the suffix started with Q and held a digit, so these
        # two were recorded as quantizations called "Qwen3" and "Qwen3-4B" and written into the
        # result document as provenance -- a wrong-and-unchecked field, which this function's own
        # docstring calls worse than an absent one.
        "hf.co/some/repo:Qwen3",
        "hf.co/some/repo:Qwen3-4B",
        "some/model:F8",
        "some/model:Q",
    ):
        assert serving.quantisation_in_tag(tag) is None, tag
    # The shapes it must still read, including the ones no committed tag uses yet.
    for tag, expected in (
        ("some/model:Q6_K", "Q6_K"),
        ("some/model:BF16", "BF16"),
        ("some/model:F32", "F32"),
        ("some/model:q4_k_m", "q4_k_m"),
    ):
        assert serving.quantisation_in_tag(tag) == expected, tag


def test_the_descriptor_records_no_quantization_for_a_name_shaped_suffix() -> None:
    """The evaluator writes this field into a signed result document, so a guess ships as fact.

    ``OllamaGuardBackend`` resolves the quantization from the tag when the tag names one. With
    the first-letter reader, ``:Qwen3`` resolved to "Qwen3" and the descriptor recorded it. The
    gate would still have refused the document -- Qwen3 is not Q4_K_M -- so no false parity was
    reachable; what shipped was a false provenance value in the document itself.
    """

    assert "quantisation" not in OllamaGuardBackend(model="hf.co/some/repo:Qwen3").descriptor()
    assert (
        OllamaGuardBackend(model="hf.co/some/repo:Qwen3", quantisation="Q4_K_M").descriptor()[
            "quantisation"
        ]
        == "Q4_K_M"
    ), "an operator who says what is served is still recorded; only guessing is refused"


def test_the_baseline_literal_carries_five_keys_and_is_refused_on_the_other_two() -> None:
    """The count in ``recorded_serving_configuration``'s docstring, asserted rather than asserted at.

    The docstring used to say ``baselines._ollama_backend`` "writes all of them flat". It writes
    five of the seven, and the gate's own reader refuses the literal on the two it omits. The
    sentence is now the true one, and this is the assertion that keeps it true: a key the literal
    gains, or loses, changes this test before it changes the prose.
    """

    for baseline_id in ("wildguardtest-qwen3guard-gen-4b", "expguardtest-qwen3guard-gen-4b"):
        recorded = serving.recorded_serving_configuration(get_baseline(baseline_id).backend)
        assert set(recorded) == {"quantisation", "num_ctx", "seed", "temperature", "top_k"}
        missing = [
            problem.split(" is absent", 1)[0]
            for problem in serving.configuration_mismatch(recorded)
            if " is absent" in problem
        ]
        assert missing == ["num_predict", "top_p"], missing
        assert len(serving.configuration_mismatch(recorded)) == len(missing), (
            "the literal must disagree on nothing it does declare; only the omissions refuse"
        )
