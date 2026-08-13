"""The model card must refuse to emit an incomplete AIBOM.

The central test is parameterised over every required field: delete it, and the builder must
name it and refuse. That is the property worth defending -- a blank field in an accountability
artifact is worse than a loud failure.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warrantor_ml import model_card as mc


def _complete_card() -> dict[str, Any]:
    """The example card with its placeholder metrics replaced by plausible values."""

    card = copy.deepcopy(mc.example_card())
    card["identity"]["weights_digest"] = "sha256:" + "ab" * 32
    card["base_model"]["revision"] = "c" * 40
    card["evaluation"].update(
        {
            "recall": 0.8397,
            "precision": 0.7412,
            "f1": 0.7877,
            "false_negative_rate": 0.1603,
            "sample_count": 1725,
            "per_category_recall": {"violence": 0.91, "jailbreak": 0.77},
        }
    )
    card["bias_audit"]["score"] = 0.03
    card["carbon"]["training"].update(
        {"energy_wh": 1450.0, "co2_grams": 620.0, "region": "us-central"}
    )
    card["carbon"]["inference"]["model_efficiency_wh_per_1k"] = 0.42
    return card


def _delete(card: dict[str, Any], path: str) -> None:
    """Remove a dotted path from a card."""

    segments = path.split(".")
    node: Any = card
    for segment in segments[:-1]:
        node = node[segment]
    del node[segments[-1]]


def test_the_complete_card_validates_and_emits() -> None:
    card = _complete_card()
    assert mc.validate_card(card) == ()
    body = mc.build_aibom(card)
    assert body["aibom_version"] == mc.AIBOM_VERSION
    assert body["card"]["evaluation"]["recall"] == 0.8397


def test_the_shipped_example_is_structurally_complete() -> None:
    """The template must be a valid shape even though its values are placeholders."""

    assert mc.validate_card(mc.example_card()) == ()


@pytest.mark.parametrize("rule", mc.REQUIRED_FIELDS, ids=lambda rule: rule.path)
def test_every_required_field_is_actually_required(rule: mc.FieldRule) -> None:
    card = _complete_card()
    _delete(card, rule.path)
    problems = mc.validate_card(card)
    assert any(problem.startswith(f"{rule.path}: MISSING") for problem in problems), (
        f"deleting {rule.path} did not produce a MISSING problem"
    )
    with pytest.raises(mc.IncompleteModelCardError) as excinfo:
        mc.build_aibom(card)
    assert rule.path in str(excinfo.value)


def test_the_refusal_reports_every_problem_at_once() -> None:
    card = _complete_card()
    _delete(card, "identity.weights_digest")
    _delete(card, "evaluation.recall")
    _delete(card, "csam_exclusion.attested")
    with pytest.raises(mc.IncompleteModelCardError) as excinfo:
        mc.build_aibom(card)
    assert len(excinfo.value.problems) >= 3
    message = str(excinfo.value)
    for path in ("identity.weights_digest", "evaluation.recall", "csam_exclusion.attested"):
        assert path in message


def test_a_blank_value_is_as_bad_as_a_missing_one() -> None:
    card = _complete_card()
    card["derived_artifact"]["licence_compatibility_argument"] = "   "
    problems = mc.validate_card(card)
    assert any("derived_artifact.licence_compatibility_argument" in item for item in problems)


def test_csam_attestation_cannot_be_falsy_or_stringly_true() -> None:
    for value in (False, "true", 1, None):
        card = _complete_card()
        card["csam_exclusion"]["attested"] = value
        assert any("csam_exclusion.attested" in item for item in mc.validate_card(card))


def test_weights_digest_must_be_a_real_digest() -> None:
    for value in ("sha256:short", "ab" * 32, "sha256:" + "Z" * 64, "sha256:my-model"):
        card = _complete_card()
        card["identity"]["weights_digest"] = value
        assert any("identity.weights_digest" in item for item in mc.validate_card(card))


def test_base_model_revision_must_be_pinned() -> None:
    for floating in ("main", "master", "latest", "HEAD", "v1.0"):
        card = _complete_card()
        card["base_model"]["revision"] = floating
        problems = mc.validate_card(card)
        assert any("base_model.revision" in item for item in problems), floating


def test_recall_must_be_a_probability() -> None:
    for value in (-0.1, 1.5, "0.8", True, None):
        card = _complete_card()
        card["evaluation"]["recall"] = value
        assert any("evaluation.recall" in item for item in mc.validate_card(card))


def test_placeholder_explanation_is_rejected() -> None:
    card = _complete_card()
    card["right_to_explanation"]["explanation"] = mc.PLACEHOLDER_EXPLANATION
    problems = mc.validate_card(card)
    assert any("right_to_explanation.explanation" in item for item in problems)


def test_svid_under_a_protected_prefix_is_rejected() -> None:
    for prefix in mc.SELF_CHANGE_PROTECTED_PREFIXES:
        card = _complete_card()
        card["sg1"]["svid"] = f"{prefix}/content-scanner"
        problems = mc.validate_card(card)
        assert any("sg1.svid" in item for item in problems), prefix


def test_svid_must_be_a_spiffe_id() -> None:
    card = _complete_card()
    card["sg1"]["svid"] = "https://warrantor.io/ai/content-scanner"
    assert any("sg1.svid" in item for item in mc.validate_card(card))


def test_the_conventional_ai_svid_is_accepted() -> None:
    card = _complete_card()
    card["sg1"]["svid"] = "spiffe://warrantor.io/ai/content-scanner"
    assert mc.validate_card(card) == ()


def test_empty_consequential_outputs_is_rejected() -> None:
    """SG1's `receipting || consequential_outputs.is_empty()` makes an empty list auto-pass."""

    card = _complete_card()
    card["sg1"]["consequential_outputs"] = []
    assert any("sg1.consequential_outputs" in item for item in mc.validate_card(card))


def test_kill_switchable_and_receipting_must_be_true() -> None:
    for field_name in ("kill_switchable", "receipting"):
        card = _complete_card()
        card["sg1"][field_name] = False
        assert any(f"sg1.{field_name}" in item for item in mc.validate_card(card))


def test_platform_component_must_be_one_of_the_closed_four() -> None:
    card = _complete_card()
    card["sg1"]["platform_component"] = "content_scanner"
    problems = mc.validate_card(card)
    assert any("sg1.platform_component" in item for item in problems)
    for known in mc.PLATFORM_COMPONENTS:
        good = _complete_card()
        good["sg1"]["platform_component"] = known
        assert mc.validate_card(good) == ()


def test_bias_checker_cannot_be_the_model_itself() -> None:
    card = _complete_card()
    card["bias_audit"]["checker_model_digest"] = card["identity"]["weights_digest"]
    problems = mc.validate_card(card)
    assert any("cannot be its own bias checker" in item for item in problems)


def test_bias_audit_checked_false_is_a_silent_pass_and_is_rejected() -> None:
    card = _complete_card()
    card["bias_audit"]["checked"] = False
    assert any("bias_audit.checked" in item for item in mc.validate_card(card))


def test_datasets_must_be_a_non_empty_list_of_complete_rows() -> None:
    card = _complete_card()
    card["datasets"] = []
    assert any(item.startswith("datasets:") for item in mc.validate_card(card))

    card = _complete_card()
    del card["datasets"][0]["licence"]
    assert any("datasets[0].licence" in item for item in mc.validate_card(card))

    card = _complete_card()
    card["datasets"][1]["digest"] = "not-a-digest"
    assert any("datasets[1].digest" in item for item in mc.validate_card(card))

    card = _complete_card()
    card["datasets"][0]["gated"] = "yes"
    assert any("datasets[0].gated" in item for item in mc.validate_card(card))


def test_dataset_rows_carry_the_licence_the_sbom_cannot_hold() -> None:
    card = _complete_card()
    rows = {row["dataset_id"]: row for row in card["datasets"]}
    assert rows["wildguardmix"]["licence"] == "ODC-By-1.0"
    assert rows["expguardmix"]["licence"] == "CC-BY-4.0"
    assert "research" in rows["expguardmix"]["commercial_use"].lower()


def test_aibom_states_its_schema_gaps() -> None:
    body = mc.build_aibom(_complete_card())
    gaps = " ".join(body["schema_gaps"]).lower()
    assert "single spdx string" in gaps
    assert "training energy" in gaps
    assert "no error channel" in gaps


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def _key_bytes() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes_raw()


def test_signature_round_trips() -> None:
    body = mc.build_aibom(_complete_card())
    envelope = mc.sign_aibom(body, _key_bytes())
    mc.verify_aibom(envelope)
    assert envelope["signature_algorithm"] == "Ed25519"
    assert len(envelope["signature_public_key"]) == 64
    assert len(envelope["signature_value"]) == 128


def test_a_tampered_body_fails_verification() -> None:
    body = mc.build_aibom(_complete_card())
    envelope = mc.sign_aibom(body, _key_bytes())
    envelope["body"]["card"]["evaluation"]["recall"] = 0.99
    with pytest.raises(ValueError, match="does not verify"):
        mc.verify_aibom(envelope)


def test_signature_is_independent_of_key_ordering() -> None:
    """Canonicalisation means a re-serialised body still verifies."""

    body = mc.build_aibom(_complete_card())
    envelope = mc.sign_aibom(body, _key_bytes())
    reordered = json.loads(json.dumps(envelope["body"], sort_keys=False))
    mc.verify_aibom({**envelope, "body": reordered})


def test_short_key_is_rejected() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        mc.sign_aibom({"a": 1}, b"\x00" * 16)


def test_malformed_envelope_is_rejected() -> None:
    with pytest.raises(ValueError, match="missing its body"):
        mc.verify_aibom({"signature_public_key": "00", "signature_value": "ff"})


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_template_then_validate(tmp_path: Path) -> None:
    template = tmp_path / "card.json"
    assert mc.main(["--template", str(template)]) == 0
    assert mc.main(["--card", str(template), "--validate-only"]) == 0


def test_cli_refuses_an_incomplete_card(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    card = _complete_card()
    _delete(card, "evaluation.recall")
    path = tmp_path / "card.json"
    path.write_text(json.dumps(card), encoding="utf-8")
    assert mc.main(["--card", str(path)]) == 1
    assert "evaluation.recall" in capsys.readouterr().err


def test_cli_signs_when_given_a_key(tmp_path: Path) -> None:
    card_path = tmp_path / "card.json"
    card_path.write_text(json.dumps(_complete_card()), encoding="utf-8")
    key_path = tmp_path / "key.hex"
    key_path.write_text(_key_bytes().hex(), encoding="utf-8")
    out = tmp_path / "aibom.json"
    assert (
        mc.main(["--card", str(card_path), "--signing-key", str(key_path), "--out", str(out)]) == 0
    )
    mc.verify_aibom(json.loads(out.read_text(encoding="utf-8")))


def test_cli_fields_listing_names_every_rule(capsys: pytest.CaptureFixture[str]) -> None:
    assert mc.main(["--fields"]) == 0
    printed = capsys.readouterr().out
    for rule in mc.REQUIRED_FIELDS:
        assert rule.path in printed
