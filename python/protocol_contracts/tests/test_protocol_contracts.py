"""Reference validator coverage over every retained P1-P12 vector."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from protocol_contracts.validation import JsonObject, ProtocolValidator

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
VECTOR_ROOT = REPOSITORY_ROOT / "testvectors" / "protocols"
SCHEMA_ROOT = REPOSITORY_ROOT / "specs" / "protocols"


def load_manifest() -> JsonObject:
    """Load the deterministic protocol vector manifest."""

    return cast(
        JsonObject,
        json.loads((VECTOR_ROOT / "manifest.json").read_text(encoding="utf-8")),
    )


def test_all_protocol_vectors_match_expected_results() -> None:
    """Every positive, negative, and adversarial vector has the expected outcome."""

    manifest = load_manifest()
    keyring = {
        key_id: bytes.fromhex(cast(str, encoded_key))
        for key_id, encoded_key in cast(JsonObject, manifest["keyring"]).items()
    }
    validator = ProtocolValidator(SCHEMA_ROOT, keyring)
    entries = cast(list[JsonObject], manifest["vectors"])
    assert len(entries) == 40
    assert {cast(str, entry["protocol"]) for entry in entries} == {
        f"P{number}" for number in range(1, 13)
    }
    assert {cast(str, entry["category"]) for entry in entries} == {
        "positive",
        "negative",
        "adversarial",
    }
    for entry in entries:
        vector_path = VECTOR_ROOT / cast(str, entry["path"])
        vector_record = cast(JsonObject, json.loads(vector_path.read_text(encoding="utf-8")))
        result = validator.validate(
            vector_record["document"],
            cast(str, vector_record["protocol"]),
            cast(int, vector_record["validation_time"]),
        )
        expected_valid = vector_record["expected"] == "valid"
        assert result.valid is expected_valid, f"{entry['id']}: {result}"
        if not expected_valid:
            assert result.error_code == vector_record["expected_error"], (
                f"{entry['id']}: expected {vector_record['expected_error']}, got {result}"
            )


def test_unknown_key_fails_closed() -> None:
    """A missing trust key never becomes an unsigned success."""

    manifest = load_manifest()
    first_entry = cast(JsonObject, cast(list[JsonObject], manifest["vectors"])[0])
    vector_record = cast(
        JsonObject,
        json.loads((VECTOR_ROOT / cast(str, first_entry["path"])).read_text(encoding="utf-8")),
    )
    result = ProtocolValidator(SCHEMA_ROOT, {}).validate(
        vector_record["document"],
        cast(str, vector_record["protocol"]),
        cast(int, vector_record["validation_time"]),
    )
    assert not result.valid
    assert result.error_code == "UNKNOWN_KEY"
