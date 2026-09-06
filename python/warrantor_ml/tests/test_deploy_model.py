"""Registering a fine-tuned adapter behind ContentScanner without touching enforcement code."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from warrantor_ml import deploy_model as dm
from warrantor_ml import model_card as mc
from warrantor_ml import serving


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


def _promote_receipt() -> dict[str, Any]:
    """The decision document warrantor-ml-parity writes for a promotion at the deployed setting."""

    return {
        "verdict": "promote",
        "decision_digest": "sha256:" + "a" * 64,
        "recorded_serving_configuration": dict(serving.DEPLOYED),
    }


def _write_receipt(tmp_path: Path, receipt: dict[str, Any] | None = None) -> Path:
    path = tmp_path / "parity-decision.json"
    path.write_text(
        json.dumps(receipt if receipt is not None else _promote_receipt()), encoding="utf-8"
    )
    return path


def _registration() -> dm.ScannerRegistration:
    return dm.build_registration(
        _complete_card(),
        endpoint="http://127.0.0.1:11434/api/chat",
        parity_receipt=_promote_receipt(),
    )


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
        dm.build_registration(
            card,
            endpoint="http://127.0.0.1:11434/api/chat",
            parity_receipt=_promote_receipt(),
        )


def test_registration_refuses_a_bogus_model_digest() -> None:
    card = _complete_card()
    card["identity"]["weights_digest"] = "sha256:warrantor-guard"
    # Caught by card validation first; the message must still name the field.
    with pytest.raises((mc.IncompleteModelCardError, dm.RegistrationError)) as excinfo:
        dm.build_registration(
            card,
            endpoint="http://127.0.0.1:11434/api/chat",
            parity_receipt=_promote_receipt(),
        )
    assert "weights_digest" in str(excinfo.value)


def test_registration_rejects_an_invented_harm_category_variant() -> None:
    card = _complete_card()
    card["harm_category_map"]["fraud"] = "HarmCategory::Fraud"
    with pytest.raises(dm.RegistrationError, match="named HarmCategory variants"):
        dm.build_registration(
            card,
            endpoint="http://127.0.0.1:11434/api/chat",
            parity_receipt=_promote_receipt(),
        )


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
    second = dm.build_registration(
        card,
        endpoint="http://127.0.0.1:11434/api/chat",
        parity_receipt=_promote_receipt(),
    ).card_digest
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
            "--parity-receipt",
            str(_write_receipt(tmp_path)),
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
    assert (
        dm.main(["--card", str(card_path), "--parity-receipt", str(_write_receipt(tmp_path))]) == 1
    )
    assert "REGISTRATION REFUSED" in capsys.readouterr().err


# ── the parity-receipt refusal (Task 12.3, L9-03) ────────────────────────────────────────

_ENDPOINT = "http://127.0.0.1:11434/api/chat"


def test_registration_is_refused_without_a_promote_receipt() -> None:
    """L9-03's verification text, which nothing in this module implemented before Task 12.3.

    ``insufficient_evidence`` is the case that matters: it is not a weaker ``promote``, it is the
    gate saying it could not tell, and it is the verdict the promoted 2026-08-22 candidate's own
    committed document reproduces today when the leakage corpora are not supplied.
    """

    for verdict in ("reject", "insufficient_evidence", ""):
        with pytest.raises(dm.RegistrationError, match="only 'promote' may be registered"):
            dm.build_registration(
                _complete_card(), endpoint=_ENDPOINT, parity_receipt={"verdict": verdict}
            )


def test_registration_is_refused_when_the_receipt_carries_no_auditable_digest() -> None:
    for digest in ("", "not-a-digest", "sha256:tooshort", "sha1:" + "a" * 40):
        with pytest.raises(dm.RegistrationError, match="no well-formed decision_digest"):
            dm.build_registration(
                _complete_card(),
                endpoint=_ENDPOINT,
                parity_receipt={"verdict": "promote", "decision_digest": digest},
            )


def test_registration_is_refused_when_the_promoted_configuration_is_not_the_served_one() -> None:
    """A receipt that says 'promote' about a different configuration is a receipt for a
    different model."""

    receipt = _promote_receipt()
    receipt["recorded_serving_configuration"] = {**serving.DEPLOYED, "quantisation": "Q8_0"}
    with pytest.raises(dm.RegistrationError, match="does not serve"):
        dm.build_registration(_complete_card(), endpoint=_ENDPOINT, parity_receipt=receipt)

    receipt["recorded_serving_configuration"] = {}
    with pytest.raises(dm.RegistrationError, match="does not serve"):
        dm.build_registration(_complete_card(), endpoint=_ENDPOINT, parity_receipt=receipt)


def test_registration_succeeds_with_a_promote_receipt_at_the_deployed_configuration() -> None:
    """The allowed control. The refusals above are worthless if nothing can be registered."""

    receipt = _promote_receipt()
    registration = dm.build_registration(
        _complete_card(), endpoint=_ENDPOINT, parity_receipt=receipt
    )
    body = registration.to_dict()
    assert body["parity_receipt"]["decision_digest"] == receipt["decision_digest"]
    assert body["parity_receipt"]["verdict"] == "promote"
    assert body["serving"]["num_ctx"] == 8192
    assert body["serving"]["quantisation"] == "Q4_K_M"
    assert body["deployed_configuration_digest"] == serving.deployed_digest()
    # The Tier C half of the claim ships in the document, not only in the plan.
    assert any("does not observe the serving process" in note for note in body["notes"])


def test_a_refused_registration_writes_neither_a_document_nor_an_adapter(tmp_path: Path) -> None:
    """Every check precedes every write, so nothing partial survives a refusal."""

    card_path = tmp_path / "card.json"
    card_path.write_text(json.dumps(_complete_card()), encoding="utf-8")
    receipt_path = _write_receipt(tmp_path, {"verdict": "insufficient_evidence"})
    registration_path = tmp_path / "registration.json"
    adapter_path = tmp_path / "adapter.rs"

    exit_code = dm.main(
        [
            "--card",
            str(card_path),
            "--parity-receipt",
            str(receipt_path),
            "--out",
            str(registration_path),
            "--emit-adapter",
            str(adapter_path),
        ]
    )
    assert exit_code == 1
    assert not registration_path.exists()
    assert not adapter_path.exists()


def test_the_generated_adapter_names_the_configuration_it_was_promoted_at() -> None:
    source = dm.render_rust_adapter(
        dm.build_registration(
            _complete_card(), endpoint=_ENDPOINT, parity_receipt=_promote_receipt()
        )
    )
    assert f"SERVED_NUM_CTX: u32 = {serving.NUM_CTX};" in source
    assert f'SERVED_QUANTIZATION: &\'static str = "{serving.QUANTIZATION}";' in source
    assert f"SERVED_SEED: i64 = {serving.SEED};" in source
    assert f"SERVED_NUM_PREDICT: u32 = {serving.NUM_PREDICT};" in source
    assert "this adapter cannot enforce them" in source, (
        "the comment is the mechanism for the Tier C half of the claim: the constants are "
        "declarative and the closure is the caller's, and the generated file has to say so "
        "or a later reader will upgrade it to enforcement in their head"
    )


def test_a_registration_with_no_receipt_publishes_no_serving_configuration() -> None:
    """Rule 2: a rendered value is derived from the record it describes.

    ``build_registration`` cannot produce this -- it refuses without a promote receipt -- but a
    ``ScannerRegistration`` constructed directly can, and rendering ``serving.DEPLOYED`` there
    would publish a configuration nothing was promoted at. The field says ``null`` instead.
    """

    bare = dm.ScannerRegistration(
        scanner_id="x",
        model_digest="sha256:" + "ab" * 32,
        model_ref="x:1",
        endpoint=_ENDPOINT,
        request_timeout_ms=5_000,
        failure_mode="deny",
        harm_category_map={},
        gating_categories=(),
        operating_threshold=0.5,
        svid="svid",
        consequential_outputs=(),
        card_digest="sha256:" + "cd" * 32,
        advisory_declaration="advises",
        registry_owner="owner",
    )
    body = bare.to_dict()
    assert body["parity_receipt"] == {}
    assert body["serving"] is None


def test_the_registered_serving_block_is_the_receipts_and_not_the_declared_record() -> None:
    """The allowed control: with a receipt, the block is present and equals what was promoted."""

    receipt = _promote_receipt()
    body = dm.build_registration(
        _complete_card(), endpoint=_ENDPOINT, parity_receipt=receipt
    ).to_dict()
    assert body["serving"] == receipt["recorded_serving_configuration"]
    assert body["serving"] == dict(serving.DEPLOYED)


def _bare_registration(**overrides: Any) -> dm.ScannerRegistration:
    """A ``ScannerRegistration`` built directly, which is the path ``build_registration`` guards."""

    fields: dict[str, Any] = {
        "scanner_id": "x",
        "model_digest": "sha256:" + "ab" * 32,
        "model_ref": "x:1",
        "endpoint": _ENDPOINT,
        "request_timeout_ms": 5_000,
        "failure_mode": "deny",
        "harm_category_map": {},
        "gating_categories": (),
        "operating_threshold": 0.5,
        "svid": "svid",
        "consequential_outputs": (),
        "card_digest": "sha256:" + "cd" * 32,
        "advisory_declaration": "advises",
        "registry_owner": "owner",
    }
    fields.update(overrides)
    return dm.ScannerRegistration(**fields)


def test_the_adapters_served_constants_are_the_receipts_and_not_the_declared_record() -> None:
    """Rule 2 again, in the adapter this time: derived from the record, not written beside it.

    ``to_dict`` was fixed to render the receipt and ``render_rust_adapter`` was left reading
    :data:`serving.DEPLOYED`, so one object published two different answers to the same question:
    the registration document said ``Q8_0`` / 4096 and the adapter said ``Q4_K_M`` / 8192, under a
    comment asserting these are what it was promoted at. ``build_registration`` refuses this
    receipt, so only the direct construction path can reach it -- the same path that made the
    ``serving`` block a derived value.
    """

    promoted_elsewhere = dict(serving.DEPLOYED, quantisation="Q8_0", num_ctx=4096)
    registration = _bare_registration(
        parity_receipt={
            "verdict": "promote",
            "decision_digest": "sha256:" + "a" * 64,
            "recorded_serving_configuration": promoted_elsewhere,
        }
    )
    source = dm.render_rust_adapter(registration)
    assert 'SERVED_QUANTIZATION: &\'static str = "Q8_0";' in source
    assert "SERVED_NUM_CTX: u32 = 4096;" in source
    assert f'SERVED_QUANTIZATION: &\'static str = "{serving.QUANTIZATION}";' not in source
    assert f"SERVED_NUM_CTX: u32 = {serving.NUM_CTX};" not in source
    assert registration.to_dict()["serving"] == promoted_elsewhere, (
        "the document and the adapter must answer the same question the same way, or one of "
        "them is decoration"
    )


def test_an_adapter_is_refused_when_no_receipt_names_a_promoted_configuration() -> None:
    """A registration with no receipt has no promoted configuration, so it gets no adapter."""

    with pytest.raises(dm.RegistrationError) as refusal:
        dm.render_rust_adapter(_bare_registration())
    assert "no parity receipt" in str(refusal.value)

    with pytest.raises(dm.RegistrationError) as partial:
        dm.render_rust_adapter(
            _bare_registration(
                parity_receipt={
                    "verdict": "promote",
                    "decision_digest": "sha256:" + "a" * 64,
                    "recorded_serving_configuration": {"quantisation": serving.QUANTIZATION},
                }
            )
        )
    assert "num_ctx" in str(partial.value)
