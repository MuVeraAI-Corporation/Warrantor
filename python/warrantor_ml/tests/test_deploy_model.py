"""Registering a fine-tuned adapter behind ContentScanner without touching enforcement code."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from warrantor_ml import deploy_model as dm
from warrantor_ml import model_card as mc


def _complete_card() -> dict[str, Any]:
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


def _registration() -> dm.ScannerRegistration:
    return dm.build_registration(_complete_card(), endpoint="http://127.0.0.1:11434/api/chat")


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_registration_binds_the_scanner_to_the_card_digest() -> None:
    registration = _registration()
    assert registration.model_digest == "sha256:" + "ab" * 32
    assert registration.card_digest.startswith("sha256:")
    assert registration.svid == "spiffe://warrantor.io/ai/content-scanner"
    assert registration.consequential_outputs == ("moderation_verdict",)


def test_registration_defaults_to_fail_closed() -> None:
    """scan() has no error channel, so a scanner that cannot answer must deny."""

    assert _registration().failure_mode == "deny"


def test_registration_names_who_removes_a_dead_scanner() -> None:
    """decide() only fails closed on an EMPTY slice, so somebody must own removal."""

    assert _registration().registry_owner


def test_registration_refuses_an_incomplete_card() -> None:
    card = _complete_card()
    del card["evaluation"]["recall"]
    with pytest.raises(mc.IncompleteModelCardError, match="evaluation.recall"):
        dm.build_registration(card, endpoint="http://127.0.0.1:11434/api/chat")


def test_registration_refuses_a_bogus_model_digest() -> None:
    card = _complete_card()
    card["identity"]["weights_digest"] = "sha256:warrantor-guard"
    # Caught by card validation first; the message must still name the field.
    with pytest.raises((mc.IncompleteModelCardError, dm.RegistrationError)) as excinfo:
        dm.build_registration(card, endpoint="http://127.0.0.1:11434/api/chat")
    assert "weights_digest" in str(excinfo.value)


def test_registration_rejects_an_invented_harm_category_variant() -> None:
    card = _complete_card()
    card["harm_category_map"]["fraud"] = "HarmCategory::Fraud"
    with pytest.raises(dm.RegistrationError, match="named HarmCategory variants"):
        dm.build_registration(card, endpoint="http://127.0.0.1:11434/api/chat")


def test_registration_accepts_custom_categories_for_the_domain_packs() -> None:
    registration = _registration()
    assert registration.harm_category_map["finance"].startswith("HarmCategory::Custom")
    assert registration.harm_category_map["violent"] == "HarmCategory::Violence"


def test_gating_categories_include_jailbreak() -> None:
    assert "jailbreak" in _registration().gating_categories


def test_registration_carries_the_advisory_declaration() -> None:
    declaration = _registration().advisory_declaration.lower()
    assert "advisory" in declaration
    assert "never" in declaration


def test_registration_document_serialises(tmp_path: Path) -> None:
    path = dm.write_registration(_registration(), tmp_path / "nested" / "registration.json")
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["registration_version"] == dm.REGISTRATION_VERSION
    assert document["failure_mode"] == "deny"
    assert document["transport"]["endpoint"].startswith("http://127.0.0.1")
    assert document["sg1"]["consequential_outputs"] == ["moderation_verdict"]


def test_card_digest_changes_with_the_card() -> None:
    first = _registration().card_digest
    card = _complete_card()
    card["evaluation"]["recall"] = 0.9
    second = dm.build_registration(card, endpoint="http://127.0.0.1:11434/api/chat").card_digest
    assert first != second


# ---------------------------------------------------------------------------
# The generated Rust adapter
# ---------------------------------------------------------------------------


def test_adapter_implements_the_trait_with_the_exact_two_methods() -> None:
    source = dm.render_rust_adapter(_registration())
    assert "impl ContentScanner for" in source
    assert "fn scan(&self, content: &str) -> ScannerVerdict" in source
    assert "fn id(&self) -> &str" in source
    # &self, not &mut self -- inference state must be interior-mutable or injected.
    assert "fn scan(&mut self" not in source


def test_adapter_is_send_and_sync_compatible() -> None:
    """ContentScanner has a Send + Sync supertrait; the injected transport must satisfy it."""

    source = dm.render_rust_adapter(_registration())
    assert "Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>" in source


def test_adapter_touches_no_enforcement_code() -> None:
    source = dm.render_rust_adapter(_registration())
    for symbol in ("fn decide", "enum DenyReason", "fn issue_receipt", "fn verify_receipt"):
        assert symbol not in source
    assert "do not edit by hand" in source


def test_adapter_returns_harmful_on_transport_failure() -> None:
    """The silent-allow trap: a broken scanner that returns is_harmful:false."""

    source = dm.render_rust_adapter(_registration())
    unavailable = source[source.index("fn unavailable") : source.index("impl ContentScanner")]
    assert "is_harmful: true" in unavailable
    assert "confidence: 1.0" in unavailable
    assert "FAIL-CLOSED" in source


def test_adapter_consumes_both_verdict_axes() -> None:
    source = dm.render_rust_adapter(_registration())
    assert "gated_by_category" in source
    assert '"safety"' in source
    assert '"categories"' in source
    assert '"jailbreak"' in source


def test_adapter_embeds_the_pinned_digest_and_threshold() -> None:
    registration = _registration()
    source = dm.render_rust_adapter(registration)
    assert f'MODEL_DIGEST: &\'static str = "{registration.model_digest}"' in source
    assert "OPERATING_THRESHOLD" in source
    assert "cannot raise" in source  # the deny_threshold caveat is stated in the source


def test_adapter_maps_every_declared_category() -> None:
    registration = _registration()
    source = dm.render_rust_adapter(registration)
    for label in registration.harm_category_map:
        assert f'"{label}" =>' in source


def test_adapter_struct_name_is_valid_rust() -> None:
    registration = _registration()
    source = dm.render_rust_adapter(registration)
    name = source.split("pub struct ")[1].split(" ")[0]
    assert name[0].isupper()
    assert name.isidentifier()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_emits_registration_and_adapter(tmp_path: Path) -> None:
    card_path = tmp_path / "card.json"
    card_path.write_text(json.dumps(_complete_card()), encoding="utf-8")
    registration_path = tmp_path / "registration.json"
    adapter_path = tmp_path / "adapter.rs"
    exit_code = dm.main(
        [
            "--card",
            str(card_path),
            "--out",
            str(registration_path),
            "--emit-adapter",
            str(adapter_path),
        ]
    )
    assert exit_code == 0
    assert json.loads(registration_path.read_text(encoding="utf-8"))["failure_mode"] == "deny"
    assert "impl ContentScanner for" in adapter_path.read_text(encoding="utf-8")


def test_cli_refuses_an_incomplete_card(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    card = _complete_card()
    del card["sg1"]["consequential_outputs"]
    card_path = tmp_path / "card.json"
    card_path.write_text(json.dumps(card), encoding="utf-8")
    assert dm.main(["--card", str(card_path)]) == 1
    assert "REGISTRATION REFUSED" in capsys.readouterr().err
