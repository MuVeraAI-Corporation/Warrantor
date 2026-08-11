#!/usr/bin/env python3
"""Generate deterministic signed P1-P12 conformance vectors."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import TypeAlias, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
VECTOR_ROOT = REPOSITORY_ROOT / "testvectors" / "protocols"
ISSUED_AT = 1_893_456_000
EXPIRES_AT = ISSUED_AT + 3_600
VALIDATION_TIME = ISSUED_AT + 60
KEY_ID = "urn:aumos:key:protocol-tck-ed25519-1"
PRIVATE_SEED = bytes(range(32))

JsonScalar: TypeAlias = str | int | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]
Mutation: TypeAlias = Callable[[JsonObject], None]


def parse_arguments() -> argparse.Namespace:
    """Parse vector generator arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    return parser.parse_args()


def digest(marker: str) -> str:
    """Return a deterministic SHA-256 digest marker."""

    return "sha256:" + hashlib.sha256(marker.encode("utf-8")).hexdigest()


def artifact(name: str, marker: str) -> JsonObject:
    """Build one exact artifact reference."""

    return {
        "uri": f"oci://registry.example.org/aumos/{name}:1.0.0",
        "digest": digest(marker),
        "media_type": "application/vnd.oci.image.manifest.v1+json",
        "version": "1.0.0",
        "license": "Apache-2.0",
    }


def budget(multiplier: int = 1) -> JsonObject:
    """Build a bounded autonomy budget."""

    return {
        "steps": 20 * multiplier,
        "wall_clock_seconds": 600 * multiplier,
        "tokens": 20_000 * multiplier,
        "money_minor": 5_000 * multiplier,
        "external_calls": 10 * multiplier,
        "data_bytes": 1_048_576 * multiplier,
        "irreversible_actions": 0,
    }


def base_payloads() -> dict[str, JsonObject]:
    """Return one semantically valid payload for every protocol."""

    return {
        "P1": {
            "subject": "spiffe://example.org/agent/researcher",
            "purpose": "analyze approved dataset",
            "resources": ["urn:aumos:dataset:approved"],
            "tools": ["spiffe://example.org/tool/search"],
            "data_classes": ["L1"],
            "side_effect_class": "write",
            "budget": budget(),
            "geographies": ["US"],
            "delegation_depth": 1,
            "approvals": [],
            "revocation_handle": "urn:aumos:revoke:aae-001",
        },
        "P2": {
            "phase": "precommit",
            "actor": "spiffe://example.org/agent/researcher",
            "authority_digest": digest("p1-aae"),
            "artifact_digests": [digest("model"), digest("tool")],
            "context_digest": digest("context"),
            "policy_decision": {
                "engine": "opa",
                "decision": "allow",
                "policy_digest": digest("policy"),
                "matched_rules": ["allow-approved-dataset"],
            },
            "operation": "dataset.write_summary",
            "checks": [
                {
                    "name": "authority-current",
                    "passed": True,
                    "detail_digest": digest("authority-check"),
                }
            ],
            "approvers": [],
            "outcome": "pending",
            "rollback_pointer": "",
            "parent_receipt": "",
        },
        "P3": {
            "source_identity": "urn:aumos:source:approved-corpus",
            "acquired_at": ISSUED_AT - 60,
            "consent": True,
            "sensitivity": "L1",
            "content_digest": digest("context-source"),
            "confidence_micros": 900_000,
            "transformations": [
                {
                    "operation": "normalize",
                    "implementation": "urn:aumos:transform:normalize-v1",
                    "input_digest": digest("context-source"),
                    "output_digest": digest("context-normalized"),
                    "applied_at": ISSUED_AT - 30,
                }
            ],
            "derived_from": [digest("parent-context")],
            "taints": [],
            "allowed_uses": ["analysis"],
        },
        "P4": {
            "sequence": 1,
            "previous_digest": digest("memory-record-0"),
            "owner": "spiffe://example.org/agent/researcher",
            "content_digest": digest("memory-record-1"),
            "confidence_micros": 800_000,
            "contradiction_links": [],
            "provenance_digest": digest("p3-context"),
            "quarantine_state": "clean",
            "supersedes": "",
            "retention_until": EXPIRES_AT + 86_400,
            "consent_revoked": False,
        },
        "P5": {
            "name": "approved-search",
            "package": artifact("skill-package", "skill-package"),
            "instructions_digest": digest("skill-instructions"),
            "code": {
                **artifact("skill-code", "skill-code"),
                "media_type": "application/wasm",
            },
            "runtime": "wasm",
            "tools": ["search"],
            "permissions": ["net:search.example.org"],
            "publisher_identity": "spiffe://example.org/publisher/security",
            "ai_sbom": artifact("skill-sbom", "skill-sbom"),
            "evaluation_bundle": artifact("skill-eval", "skill-eval"),
            "limitations": ["approved corpus only"],
            "revocation_handle": "urn:aumos:revoke:ssp-001",
        },
        "P6": {
            "artifacts": [artifact("model", "model"), artifact("policy", "policy")],
            "roles": ["model", "policy"],
            "root_digest": digest("artifact-graph-root"),
            "build_provenance": artifact("provenance", "provenance"),
            "deployment_attestations": [artifact("attestation", "attestation")],
        },
        "P7": {
            "budget": budget(),
            "currency": "USD",
            "privilege": "write",
            "expected_risk_micros": 300_000,
            "approval_required": False,
            "replenishment": "manual",
        },
        "P8": {
            "corpus": artifact("eval-corpus", "eval-corpus"),
            "environment": artifact("eval-environment", "eval-environment"),
            "model": artifact("eval-model", "eval-model"),
            "harness": artifact("eval-harness", "eval-harness"),
            "policy": artifact("eval-policy", "eval-policy"),
            "seeds": [42],
            "trace_digests": [digest("eval-trace")],
            "judge": artifact("eval-judge", "eval-judge"),
            "assertions": [
                {
                    "name": "no-secret-output",
                    "expected_digest": digest("expected"),
                    "actual_digest": digest("expected"),
                    "passed": True,
                }
            ],
            "passed_count": 1,
            "failed_count": 0,
        },
        "P9": {
            "incident_type": "tool_abuse",
            "severity": "high",
            "agent": "spiffe://example.org/agent/researcher",
            "authority_digest": digest("p1-aae"),
            "evidence_refs": ["urn:aumos:receipt:001"],
            "mitre_atlas_ids": ["AML.T0051"],
            "ocsf_class_uid": 6003,
            "detected_at": ISSUED_AT - 120,
            "contained_at": ISSUED_AT - 60,
            "containment_status": "contained",
        },
        "P10": {
            "delegator": "spiffe://example.org/agent/planner",
            "delegatee": "spiffe://example.org/agent/researcher",
            "parent_authority_digest": digest("parent-authority"),
            "delegation_chain": [
                "spiffe://example.org/agent/planner",
                "spiffe://example.org/agent/researcher",
            ],
            "hop_count": 1,
            "max_depth": 2,
            "capabilities": ["dataset:read"],
            "parent_budget": budget(2),
            "delegated_budget": budget(),
            "quorum": 1,
            "approvals": ["spiffe://example.org/approver/security"],
            "evidence_requirements": ["P2"],
            "result_digest": "",
            "status": "accepted",
        },
        "P11": {
            "reproducer": artifact("reproducer", "reproducer"),
            "root_cause_digest": digest("root-cause"),
            "affected_versions": ["1.0.0"],
            "patch": artifact("patch", "patch"),
            "tests": [artifact("regression-test", "regression-test")],
            "regression_evidence": artifact("regression-veb", "regression-veb"),
            "build_provenance": artifact("patch-provenance", "patch-provenance"),
            "embargo_until": 0,
            "disclosure_status": "public",
        },
        "P12": {
            "subject": "spiffe://example.org/agent/researcher",
            "runtime": "wasmtime-45.0.1",
            "tools": ["search"],
            "policy_digest": digest("runtime-policy"),
            "credential_types": ["oauth2"],
            "network": {
                "egress_default": "deny",
                "allowlist": ["search.example.org:443"],
                "blocklist": [],
                "dns_policy": "allowlisted",
            },
            "memory_isolation": "wasm",
            "model": artifact("runtime-model", "runtime-model"),
            "sandbox": "wasm",
            "attestation_evidence": artifact(
                "runtime-attestation", "runtime-attestation"
            ),
            "valid_until": EXPIRES_AT - 60,
        },
    }


def protocol_document(protocol: str, payload: JsonObject) -> JsonObject:
    """Build an unsigned protocol envelope."""

    number = int(protocol.removeprefix("P"))
    return {
        "protocol": protocol,
        "version": "1.0.0",
        "message_id": f"00000000-0000-4000-8000-{number:012d}",
        "issuer": "spiffe://example.org/control-plane",
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
        "nonce": hashlib.sha256(f"{protocol}-nonce".encode()).hexdigest(),
        "payload": payload,
        "critical_extensions": [],
        "extensions": {},
        "signature": {"algorithm": "Ed25519", "key_id": KEY_ID, "value": ""},
    }


def canonical_signing_bytes(document: JsonObject) -> bytes:
    """Return the v1 JSON signing form with an empty signature value."""

    signing_document = copy.deepcopy(document)
    signature = cast(JsonObject, signing_document["signature"])
    signature["value"] = ""
    return json.dumps(
        signing_document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sign_document(document: JsonObject, private_key: Ed25519PrivateKey) -> None:
    """Attach a deterministic Ed25519 signature to a document."""

    signature = private_key.sign(canonical_signing_bytes(document)).hex()
    cast(JsonObject, document["signature"])["value"] = signature


def missing_required_mutation(document: JsonObject) -> None:
    """Remove the lexicographically first payload field."""

    payload = cast(JsonObject, document["payload"])
    del payload[sorted(payload)[0]]


def semantic_mutations() -> dict[str, Mutation]:
    """Return one cross-field adversarial mutation per protocol."""

    def mutate(protocol: str, callback: Mutation) -> Mutation:
        del protocol
        return callback

    return {
        "P1": mutate("P1", lambda document: cast(JsonObject, document["payload"]).update({"side_effect_class": "destructive", "approvals": []})),
        "P2": mutate("P2", lambda document: cast(JsonObject, document["payload"]).update({"phase": "precommit", "outcome": "committed"})),
        "P3": mutate("P3", lambda document: cast(JsonObject, document["payload"]).update({"consent": False, "sensitivity": "L3"})),
        "P4": mutate("P4", lambda document: cast(JsonObject, document["payload"]).update({"consent_revoked": True, "quarantine_state": "clean"})),
        "P5": mutate("P5", lambda document: cast(JsonObject, document["payload"]).update({"runtime": "python"})),
        "P6": mutate("P6", lambda document: cast(JsonObject, document["payload"]).update({"roles": ["model", "model"]})),
        "P7": mutate("P7", lambda document: cast(JsonObject, document["payload"]).update({"expected_risk_micros": 900_000, "approval_required": False})),
        "P8": mutate("P8", lambda document: cast(JsonObject, document["payload"]).update({"passed_count": 0, "failed_count": 0})),
        "P9": mutate("P9", lambda document: cast(JsonObject, document["payload"]).update({"contained_at": ISSUED_AT - 180})),
        "P10": mutate("P10", lambda document: cast(JsonObject, cast(JsonObject, document["payload"])["delegated_budget"]).update({"tokens": 100_000})),
        "P11": mutate("P11", lambda document: cast(JsonObject, document["payload"]).update({"embargo_until": EXPIRES_AT + 86_400, "disclosure_status": "public"})),
        "P12": mutate("P12", lambda document: cast(JsonObject, document["payload"]).update({"valid_until": EXPIRES_AT + 60})),
    }


def vector(
    identifier: str,
    category: str,
    protocol: str,
    expected: str,
    expected_error: str,
    document: JsonObject,
) -> JsonObject:
    """Build one TCK vector record."""

    return {
        "id": identifier,
        "category": category,
        "protocol": protocol,
        "expected": expected,
        "expected_error": expected_error,
        "validation_time": VALIDATION_TIME,
        "document": document,
    }


def generated_vectors() -> tuple[JsonObject, dict[Path, str]]:
    """Build keyring, manifest, and every vector file."""

    private_key = Ed25519PrivateKey.from_private_bytes(PRIVATE_SEED)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    vectors: list[JsonObject] = []
    payloads = base_payloads()
    mutations = semantic_mutations()
    for protocol, payload in payloads.items():
        valid_document = protocol_document(protocol, copy.deepcopy(payload))
        sign_document(valid_document, private_key)
        vectors.append(
            vector(
                f"{protocol}-positive-001",
                "positive",
                protocol,
                "valid",
                "",
                valid_document,
            )
        )

        negative_document = protocol_document(protocol, copy.deepcopy(payload))
        missing_required_mutation(negative_document)
        sign_document(negative_document, private_key)
        vectors.append(
            vector(
                f"{protocol}-negative-schema-001",
                "negative",
                protocol,
                "invalid",
                "PAYLOAD_SCHEMA",
                negative_document,
            )
        )

        adversarial_document = protocol_document(protocol, copy.deepcopy(payload))
        mutations[protocol](adversarial_document)
        sign_document(adversarial_document, private_key)
        vectors.append(
            vector(
                f"{protocol}-adversarial-semantic-001",
                "adversarial",
                protocol,
                "invalid",
                "SEMANTIC_RULE",
                adversarial_document,
            )
        )

    p1_payload = payloads["P1"]
    common_cases: list[tuple[str, str, Mutation]] = [
        (
            "P1-adversarial-unknown-critical-extension-002",
            "UNKNOWN_CRITICAL_EXTENSION",
            lambda document: cast(list[JsonValue], document["critical_extensions"]).append("urn:aumos:extension:unknown"),
        ),
        (
            "P1-adversarial-expired-003",
            "EXPIRED",
            lambda document: document.update({"expires_at": VALIDATION_TIME}),
        ),
        (
            "P1-adversarial-version-downgrade-004",
            "UNSUPPORTED_VERSION",
            lambda document: document.update({"version": "0.9.0"}),
        ),
    ]
    for identifier, expected_error, mutation in common_cases:
        document = protocol_document("P1", copy.deepcopy(p1_payload))
        mutation(document)
        sign_document(document, private_key)
        vectors.append(
            vector(identifier, "adversarial", "P1", "invalid", expected_error, document)
        )

    signature_document = protocol_document("P1", copy.deepcopy(p1_payload))
    sign_document(signature_document, private_key)
    signature = cast(JsonObject, signature_document["signature"])
    signature_value = cast(str, signature["value"])
    signature["value"] = ("0" if signature_value[0] != "0" else "1") + signature_value[1:]
    vectors.append(
        vector(
            "P1-adversarial-invalid-signature-005",
            "adversarial",
            "P1",
            "invalid",
            "INVALID_SIGNATURE",
            signature_document,
        )
    )

    files: dict[Path, str] = {}
    manifest_entries: list[JsonObject] = []
    for vector_record in vectors:
        protocol = cast(str, vector_record["protocol"])
        identifier = cast(str, vector_record["id"])
        relative_path = Path(protocol) / f"{identifier}.json"
        files[VECTOR_ROOT / relative_path] = (
            json.dumps(vector_record, indent=2, ensure_ascii=False) + "\n"
        )
        manifest_entries.append(
            {
                "id": identifier,
                "protocol": protocol,
                "category": vector_record["category"],
                "expected": vector_record["expected"],
                "expected_error": vector_record["expected_error"],
                "path": relative_path.as_posix(),
            }
        )
    manifest: JsonObject = {
        "schema_version": 1,
        "wire_version": "1.0.0",
        "canonicalization": "RFC8785-compatible integer-only profile",
        "keyring": {KEY_ID: public_key.hex()},
        "vector_count": len(vectors),
        "vectors": manifest_entries,
    }
    files[VECTOR_ROOT / "manifest.json"] = (
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    )
    return manifest, files


def write_files(files: dict[Path, str]) -> None:
    """Write deterministic vector artifacts."""

    for path, content in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
    print(f"protocol vectors: generated {len(files) - 1} vectors and manifest")


def check_files(files: dict[Path, str]) -> int:
    """Reject missing, stale, or unexpected vector files."""

    stale = [
        path
        for path, content in files.items()
        if not path.is_file() or path.read_text(encoding="utf-8") != content
    ]
    expected = set(files)
    unexpected = {
        path for path in VECTOR_ROOT.rglob("*.json") if path not in expected
    }
    for path in sorted(stale):
        print(f"stale protocol vector: {path.relative_to(REPOSITORY_ROOT)}")
    for path in sorted(unexpected):
        print(f"unexpected protocol vector: {path.relative_to(REPOSITORY_ROOT)}")
    if stale or unexpected:
        return 1
    print(f"protocol vectors: PASS - {len(files) - 1} vectors are current")
    return 0


def main() -> int:
    """Generate or verify the signed protocol vector suite."""

    arguments = parse_arguments()
    try:
        _manifest, files = generated_vectors()
        if arguments.write:
            write_files(files)
            return 0
        return check_files(files)
    except (OSError, ValueError, TypeError) as error:
        print(f"protocol vector generation failed: {error}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
