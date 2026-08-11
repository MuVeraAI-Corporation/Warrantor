"""Independent JSON-Schema and semantic validator for P1-P12 envelopes."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from typing import Literal, TypeAlias, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator

JsonScalar: TypeAlias = str | int | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]
ErrorCode: TypeAlias = Literal[
    "MALFORMED_DOCUMENT",
    "COMMON_SCHEMA",
    "UNSUPPORTED_PROTOCOL",
    "PROTOCOL_MISMATCH",
    "UNSUPPORTED_VERSION",
    "PAYLOAD_SCHEMA",
    "SEMANTIC_RULE",
    "NOT_YET_VALID",
    "EXPIRED",
    "UNKNOWN_CRITICAL_EXTENSION",
    "UNKNOWN_KEY",
    "INVALID_SIGNATURE",
]


@dataclass(frozen=True)
class ValidationResult:
    """Stable validation outcome shared with the TCK."""

    valid: bool
    error_code: ErrorCode | None
    detail: str


def canonical_signing_bytes(document: Mapping[str, JsonValue]) -> bytes:
    """Return the integer-only RFC 8785-compatible JSON signing form."""

    signing_document = copy.deepcopy(dict(document))
    signature = signing_document.get("signature")
    if not isinstance(signature, dict):
        raise ValueError("signature must be an object")
    signature["value"] = ""
    return json.dumps(
        signing_document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def invalid(error_code: ErrorCode, detail: str) -> ValidationResult:
    """Build a stable invalid result."""

    return ValidationResult(False, error_code, detail)


def object_field(document: JsonObject, key: str) -> JsonObject:
    """Return a required object field after schema validation."""

    return cast(JsonObject, document[key])


def string_field(document: JsonObject, key: str) -> str:
    """Return a required string field after schema validation."""

    return cast(str, document[key])


def integer_field(document: JsonObject, key: str) -> int:
    """Return a required integer field after schema validation."""

    return cast(int, document[key])


def array_field(document: JsonObject, key: str) -> list[JsonValue]:
    """Return a required array field after schema validation."""

    return cast(list[JsonValue], document[key])


class ProtocolValidator:
    """Validate structural, semantic, temporal, extension, and signature rules."""

    def __init__(
        self,
        schema_directory: Path,
        keyring: Mapping[str, bytes],
        supported_critical_extensions: frozenset[str] = frozenset(),
    ) -> None:
        """Load all 12 schemas and bind a caller-owned verification keyring."""

        self._schemas: dict[str, Draft202012Validator] = {}
        for number in range(1, 13):
            matches = list(schema_directory.glob(f"P{number}-*.schema.json"))
            if len(matches) != 1:
                raise ValueError(f"P{number} must resolve to exactly one JSON Schema")
            schema: object = json.loads(matches[0].read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            self._schemas[f"P{number}"] = Draft202012Validator(schema)
        self._keyring = dict(keyring)
        self._supported_critical_extensions = supported_critical_extensions

    def validate(
        self,
        document: object,
        expected_protocol: str,
        validation_time: int,
    ) -> ValidationResult:
        """Validate one document in a deterministic fail-closed order."""

        if not isinstance(document, dict) or not all(isinstance(key, str) for key in document):
            return invalid("MALFORMED_DOCUMENT", "document must be a JSON object")
        typed_document = cast(JsonObject, document)
        protocol = typed_document.get("protocol")
        if not isinstance(protocol, str) or protocol not in self._schemas:
            return invalid("UNSUPPORTED_PROTOCOL", "unknown protocol identifier")
        if protocol != expected_protocol:
            return invalid(
                "PROTOCOL_MISMATCH",
                f"document declares {protocol}; lane requires {expected_protocol}",
            )
        if typed_document.get("version") != "1.0.0":
            return invalid("UNSUPPORTED_VERSION", "only wire version 1.0.0 is accepted")

        errors = sorted(
            self._schemas[protocol].iter_errors(typed_document),
            key=lambda error: list(error.absolute_path),
        )
        if errors:
            first_error = errors[0]
            path = list(first_error.absolute_path)
            code: ErrorCode = "PAYLOAD_SCHEMA" if path[:1] == ["payload"] else "COMMON_SCHEMA"
            location = ".".join(str(part) for part in path) or "$"
            return invalid(code, f"{location}: {first_error.message}")

        semantic_detail = validate_semantics(protocol, typed_document)
        if semantic_detail is not None:
            return invalid("SEMANTIC_RULE", semantic_detail)
        issued_at = integer_field(typed_document, "issued_at")
        expires_at = integer_field(typed_document, "expires_at")
        if expires_at <= issued_at:
            return invalid("COMMON_SCHEMA", "expires_at must be greater than issued_at")
        if validation_time < issued_at:
            return invalid("NOT_YET_VALID", "validation time precedes issued_at")
        if validation_time >= expires_at:
            return invalid("EXPIRED", "validation time is at or after expires_at")

        critical_extensions = cast(list[str], typed_document["critical_extensions"])
        unsupported_extensions = sorted(
            set(critical_extensions) - self._supported_critical_extensions
        )
        if unsupported_extensions:
            return invalid(
                "UNKNOWN_CRITICAL_EXTENSION",
                "unsupported critical extensions: " + ", ".join(unsupported_extensions),
            )
        return self._verify_signature(typed_document)

    def _verify_signature(self, document: JsonObject) -> ValidationResult:
        """Resolve and verify the detached Ed25519 signature."""

        signature = object_field(document, "signature")
        key_id = string_field(signature, "key_id")
        key_bytes = self._keyring.get(key_id)
        if key_bytes is None:
            return invalid("UNKNOWN_KEY", f"key id is not resolvable: {key_id}")
        try:
            signature_bytes = bytes.fromhex(string_field(signature, "value"))
            Ed25519PublicKey.from_public_bytes(key_bytes).verify(
                signature_bytes,
                canonical_signing_bytes(document),
            )
        except (ValueError, InvalidSignature):
            return invalid("INVALID_SIGNATURE", "Ed25519 verification failed")
        return ValidationResult(True, None, "valid")


def validate_semantics(protocol: str, document: JsonObject) -> str | None:
    """Evaluate the protocol-specific cross-field invariant."""

    payload = object_field(document, "payload")
    validators = {
        "P1": validate_p1,
        "P2": validate_p2,
        "P3": validate_p3,
        "P4": validate_p4,
        "P5": validate_p5,
        "P6": validate_p6,
        "P7": validate_p7,
        "P8": validate_p8,
        "P9": validate_p9,
        "P10": validate_p10,
        "P11": validate_p11,
        "P12": validate_p12,
    }
    return validators[protocol](payload, document)


def validate_p1(payload: JsonObject, _document: JsonObject) -> str | None:
    """Require approval for consequential authority."""

    consequence = string_field(payload, "side_effect_class")
    if consequence in {"financial", "destructive", "physical"} and not array_field(
        payload, "approvals"
    ):
        return "consequential authority requires at least one approver"
    return None


def validate_p2(payload: JsonObject, _document: JsonObject) -> str | None:
    """Keep precommit and final receipt phases unambiguous."""

    phase = string_field(payload, "phase")
    outcome = string_field(payload, "outcome")
    parent = string_field(payload, "parent_receipt")
    if phase == "precommit" and (outcome != "pending" or parent):
        return "precommit receipts must be pending and have no parent"
    if phase == "final" and (outcome == "pending" or not parent):
        return "final receipts require a terminal outcome and parent precommit receipt"
    return None


def validate_p3(payload: JsonObject, _document: JsonObject) -> str | None:
    """Require consent for sensitive context and a linked transform chain."""

    if string_field(payload, "sensitivity") in {"L2", "L3", "L4"} and not cast(
        bool, payload["consent"]
    ):
        return "L2-L4 context requires affirmative consent"
    transformations = cast(list[JsonObject], payload["transformations"])
    for previous, current in pairwise(transformations):
        if previous["output_digest"] != current["input_digest"]:
            return "transformation digest chain is discontinuous"
    return None


def validate_p4(payload: JsonObject, _document: JsonObject) -> str | None:
    """Validate hash-chain genesis and consent quarantine semantics."""

    sequence = integer_field(payload, "sequence")
    previous = string_field(payload, "previous_digest")
    if (sequence == 0 and previous) or (sequence > 0 and not previous.startswith("sha256:")):
        return "previous_digest must be empty only for sequence zero"
    if (
        cast(bool, payload["consent_revoked"])
        and string_field(payload, "quarantine_state") != "quarantined"
    ):
        return "consent-revoked memory must be quarantined"
    return None


def validate_p5(payload: JsonObject, _document: JsonObject) -> str | None:
    """Bind declared runtime to the exact executable media type."""

    runtime = string_field(payload, "runtime")
    media_type = string_field(object_field(payload, "code"), "media_type")
    expected_media_types = {
        "wasm": {"application/wasm"},
        "python": {"text/x-python", "application/vnd.aumos.python"},
        "node": {"text/javascript", "application/javascript"},
        "container": {"application/vnd.oci.image.manifest.v1+json"},
    }
    if media_type not in expected_media_types[runtime]:
        return "runtime does not match the content-addressed code media type"
    return None


def validate_p6(payload: JsonObject, _document: JsonObject) -> str | None:
    """Require unique role/artifact pairs including model and policy."""

    roles = cast(list[str], payload["roles"])
    artifacts = cast(list[JsonObject], payload["artifacts"])
    digests = [string_field(artifact_record, "digest") for artifact_record in artifacts]
    if len(roles) != len(artifacts) or len(set(roles)) != len(roles):
        return "artifact roles must be unique and align one-to-one with artifacts"
    if not {"model", "policy"} <= set(roles):
        return "artifact graph must contain model and policy roles"
    if len(set(digests)) != len(digests):
        return "artifact digests must be unique"
    return None


def validate_p7(payload: JsonObject, _document: JsonObject) -> str | None:
    """Require explicit approval for high risk or administrative authority."""

    high_risk = integer_field(payload, "expected_risk_micros") >= 500_000
    administrative = string_field(payload, "privilege") == "admin"
    if (high_risk or administrative) and not cast(bool, payload["approval_required"]):
        return "high-risk or administrative budgets must require approval"
    return None


def validate_p8(payload: JsonObject, _document: JsonObject) -> str | None:
    """Bind summary counts to the signed assertion set."""

    assertions = cast(list[JsonObject], payload["assertions"])
    passed = sum(1 for assertion in assertions if cast(bool, assertion["passed"]))
    failed = len(assertions) - passed
    if passed != integer_field(payload, "passed_count") or failed != integer_field(
        payload, "failed_count"
    ):
        return "assertion summary counts do not match signed assertions"
    return None


def validate_p9(payload: JsonObject, _document: JsonObject) -> str | None:
    """Reject impossible incident containment timelines."""

    status = string_field(payload, "containment_status")
    contained_at = integer_field(payload, "contained_at")
    detected_at = integer_field(payload, "detected_at")
    if status == "open" and contained_at != 0:
        return "open incidents cannot declare a containment timestamp"
    if status != "open" and contained_at < detected_at:
        return "contained incidents cannot predate detection"
    return None


def validate_p10(payload: JsonObject, _document: JsonObject) -> str | None:
    """Enforce chain identity, quorum, depth, and budget attenuation."""

    chain = cast(list[str], payload["delegation_chain"])
    hop_count = integer_field(payload, "hop_count")
    if chain[0] != payload["delegator"] or chain[-1] != payload["delegatee"]:
        return "delegation chain endpoints must match delegator and delegatee"
    if hop_count != len(chain) - 1 or hop_count > integer_field(payload, "max_depth"):
        return "hop count must match the chain and remain within max depth"
    if integer_field(payload, "quorum") > len(array_field(payload, "approvals")):
        return "approval quorum is not satisfied"
    parent = object_field(payload, "parent_budget")
    delegated = object_field(payload, "delegated_budget")
    for key in parent:
        if integer_field(delegated, key) > integer_field(parent, key):
            return f"delegated budget expands parent ceiling at {key}"
    return None


def validate_p11(payload: JsonObject, document: JsonObject) -> str | None:
    """Keep embargo state consistent with the signed disclosure state."""

    embargo_until = integer_field(payload, "embargo_until")
    disclosure_status = string_field(payload, "disclosure_status")
    issued_at = integer_field(document, "issued_at")
    if disclosure_status == "embargoed" and embargo_until <= issued_at:
        return "embargoed remediation requires a future embargo timestamp"
    if disclosure_status != "embargoed" and embargo_until > issued_at:
        return "non-embargoed remediation cannot carry a future embargo"
    return None


def validate_p12(payload: JsonObject, document: JsonObject) -> str | None:
    """Bind capability validity to the envelope and fail-closed network profile."""

    if integer_field(payload, "valid_until") > integer_field(document, "expires_at"):
        return "capability validity cannot exceed envelope expiry"
    network = object_field(payload, "network")
    if string_field(network, "egress_default") != "deny":
        return "capability network policy must default deny"
    sandbox = string_field(payload, "sandbox")
    memory_isolation = string_field(payload, "memory_isolation")
    if sandbox == "wasm" and memory_isolation != "wasm":
        return "Wasm sandbox must attest Wasm memory isolation"
    if sandbox == "tee" and memory_isolation != "tee":
        return "TEE sandbox must attest TEE memory isolation"
    return None
