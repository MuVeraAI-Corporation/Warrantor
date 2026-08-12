"""Agent Manifest (``agent.yaml``) — the OpenAPI for agents.

A declarative, signed, receipted description of what an agent *is*: identity, the side-effect
classes it may use, the policies that bind it, the model/tools/data it depends on, the runtime
attestation it requires, and its enforcement mode. An agent without a valid signed manifest cannot
obtain authority.

See ``specs/warrantor-v4/16-agent-manifest.md``. This module is the Python reference
implementation; it MUST agree with the Rust crate (``warrantor-agent-manifest``) on every
conformance vector and on the canonical-JSON bytes (so an Ed25519 signature computed in one
language verifies in the other).

Public surface:

- :func:`parse_and_validate` — parse JSON, validate against the schema rules, return the manifest dict.
- :exc:`ManifestError` — raised on any validation failure, carrying ``.code`` and ``.field``.
- :func:`canonical_json` — RFC 8785-shaped deterministic serialization.
- :func:`digest` / :func:`digest_hex` — SHA-256 of the canonical bytes.
- :func:`sign` / :func:`verify` — Ed25519 signature envelope.
- :func:`generate_keypair` — test/bootstrap keypair.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

__all__ = [
    "API_VERSION",
    "CAPABILITY_LADDER",
    "ENFORCEMENT_MODES",
    "KIND",
    "ManifestError",
    "canonical_json",
    "digest",
    "digest_hex",
    "generate_keypair",
    "parse_and_validate",
    "sign",
    "verify",
]

# ---------------------------------------------------------------------------
# Constants — the schema in code form (mirrors 16-agent-manifest.schema.json)
# ---------------------------------------------------------------------------

API_VERSION = "agent.warrantor.io/v1"
KIND = "AgentManifest"

#: The invariant I-08 side-effect-class ladder, ordered by escalating consequence.
CAPABILITY_LADDER = ("read", "write", "financial", "destructive", "physical")

#: Per spec 03 — only ``mediated`` may substantiate a containment claim.
ENFORCEMENT_MODES = ("observed", "mediated")

_ALLOWED_TOP = frozenset(
    {
        "apiVersion",
        "kind",
        "name",
        "identity",
        "capabilities",
        "policy_refs",
        "dependencies",
        "attestation",
        "enforcement_mode",
        "description",
        "version",
    }
)
_ALLOWED_DEPS = frozenset({"model", "tools", "data"})

_SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_DIGEST_RE = re.compile(r"^[a-z0-9]+:[a-f0-9]+$")

# ---------------------------------------------------------------------------
# Error model — codes match testvectors/agent-manifest/vectors.json + Rust crate
# ---------------------------------------------------------------------------


class ManifestError(Exception):
    """Raised on any manifest validation or signature failure.

    Attributes:
        code: the stable error code (matches vectors.json and the Rust crate).
        field: the offending field, where applicable (else ``None``).
    """

    def __init__(self, code: str, message: str, *, field: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.field = field

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        if self.field:
            return f"{self.code} ({self.field}): {self.args[0]}"
        return f"{self.code}: {self.args[0]}"


# ---------------------------------------------------------------------------
# Parse + validate — produces the precise error codes the vectors require
# ---------------------------------------------------------------------------


def parse_and_validate(json_str: str) -> dict[str, Any]:
    """Parse a JSON string into a validated manifest dict.

    Returns the manifest dict (only the fields that were present in the input — optional
    fields that were absent are NOT added). Raises :class:`ManifestError` on any rule
    violation, with the exact ``code`` and ``field`` the conformance vectors assert.
    """
    try:
        value = json.loads(json_str)
    except json.JSONDecodeError as exc:
        raise ManifestError("MALFORMED_JSON", f"malformed JSON: {exc}") from exc

    if not isinstance(value, dict):
        raise ManifestError("NOT_AN_OBJECT", "manifest must be a JSON object at the top level")
    return _validate_object(value)


def _validate_object(obj: dict[str, Any]) -> dict[str, Any]:
    # 1. Reject unexpected fields (additionalProperties: false).
    for key in obj:
        if key not in _ALLOWED_TOP:
            raise ManifestError("UNEXPECTED_FIELD", f"unexpected field: {key}", field=key)

    # 2. Required, string-typed scalars.
    def req_str(field: str) -> str:
        v = obj.get(field)
        if not isinstance(v, str):
            raise ManifestError(
                "MISSING_REQUIRED_FIELD", f"missing required field: {field}", field=field
            )
        return v

    api_version = req_str("apiVersion")
    kind = req_str("kind")
    name = req_str("name")
    identity = req_str("identity")
    enforcement_mode = req_str("enforcement_mode")

    if api_version != API_VERSION:
        raise ManifestError("INVALID_API_VERSION", f"expected apiVersion='{API_VERSION}'")
    if kind != KIND:
        raise ManifestError("INVALID_KIND", f"expected kind='{KIND}'")
    if not name:
        raise ManifestError("MISSING_REQUIRED_FIELD", "name must be non-empty", field="name")
    if not identity.startswith("spiffe://"):
        raise ManifestError(
            "INVALID_IDENTITY", "identity must be a spiffe:// URI", field="identity"
        )

    # 3. capabilities — non-empty, all on the ladder.
    capabilities = _require_str_array(obj, "capabilities", empty_code="EMPTY_CAPABILITIES")
    for cap in capabilities:
        if cap not in CAPABILITY_LADDER:
            raise ManifestError(
                "INVALID_CAPABILITY",
                f"invalid capability '{cap}' in capabilities: must be one of {list(CAPABILITY_LADDER)}",
                field="capabilities",
            )

    # 4. policy_refs — non-empty.
    _require_str_array(obj, "policy_refs", empty_code="EMPTY_POLICY_REFS")

    # 5. enforcement_mode enum.
    if enforcement_mode not in ENFORCEMENT_MODES:
        raise ManifestError(
            "INVALID_ENFORCEMENT_MODE",
            f"invalid enforcement_mode '{enforcement_mode}': must be one of {list(ENFORCEMENT_MODES)}",
            field="enforcement_mode",
        )

    # 6. optional version — semver.
    if "version" in obj:
        v = obj["version"]
        if not isinstance(v, str) or not _SEMVER_RE.match(v):
            raise ManifestError(
                "INVALID_VERSION",
                f"invalid version '{v}' in version: must be semver (X.Y.Z)",
                field="version",
            )

    # 7. optional dependencies.
    if "dependencies" in obj:
        dep = obj["dependencies"]
        if not isinstance(dep, dict):
            raise ManifestError(
                "INVALID_MODEL_DIGEST", "dependencies must be an object", field="dependencies"
            )
        for k in dep:
            if k not in _ALLOWED_DEPS:
                raise ManifestError(
                    "UNEXPECTED_FIELD",
                    f"unexpected field: dependencies.{k}",
                    field=f"dependencies.{k}",
                )
        model = dep.get("model")
        if model is not None and (not isinstance(model, str) or not _DIGEST_RE.match(model)):
            raise ManifestError(
                "INVALID_MODEL_DIGEST",
                f"invalid model digest '{model}': must match ^[a-z0-9]+:[a-f0-9]+$",
                field="dependencies.model",
            )
        for arr_key in ("tools", "data"):
            if arr_key in dep and not isinstance(dep[arr_key], list):
                raise ManifestError(
                    "UNEXPECTED_FIELD",
                    f"dependencies.{arr_key} must be an array",
                    field=f"dependencies.{arr_key}",
                )

    # 8. optional attestation.
    if "attestation" in obj and not isinstance(obj["attestation"], list):
        raise ManifestError("UNEXPECTED_FIELD", "attestation must be an array", field="attestation")
    if "description" in obj and not isinstance(obj.get("description"), str):
        raise ManifestError("UNEXPECTED_FIELD", "description must be a string", field="description")

    return obj


def _require_str_array(obj: dict[str, Any], field: str, *, empty_code: str) -> list[str]:
    v = obj.get(field)
    if not isinstance(v, list):
        raise ManifestError(
            "MISSING_REQUIRED_FIELD", f"missing required field: {field}", field=field
        )
    out: list[str] = []
    for item in v:
        if not isinstance(item, str):
            raise ManifestError(empty_code, f"{field} must contain only strings", field=field)
        out.append(item)
    if not out:
        raise ManifestError(empty_code, f"{field} must be non-empty", field=field)
    return out


# ---------------------------------------------------------------------------
# Canonical JSON (RFC 8785-shaped: sorted keys, compact, UTF-8) + digest
# ---------------------------------------------------------------------------


def _canonicalize(obj: Any) -> Any:
    """Recursively return a copy with all dict keys sorted, so json.dumps is deterministic."""
    if isinstance(obj, dict):
        return {k: _canonicalize(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [_canonicalize(x) for x in obj]
    return obj


def canonical_json(manifest: dict[str, Any]) -> str:
    """Deterministic serialization of the manifest.

    A third party recomputing this from the same manifest dict gets byte-identical output —
    which is what makes the signature verifiable across languages. Matches the Rust crate's
    ``canonical_json`` byte-for-byte for the same input.
    """
    return json.dumps(_canonicalize(manifest), separators=(",", ":"), ensure_ascii=False)


def digest(manifest: dict[str, Any]) -> bytes:
    """SHA-256 of the canonical-JSON bytes — the manifest digest that goes into every receipt."""
    import hashlib

    return hashlib.sha256(canonical_json(manifest).encode("utf-8")).digest()


def digest_hex(manifest: dict[str, Any]) -> str:
    """Hex-encoded digest, for embedding in receipts / manifest refs."""
    return digest(manifest).hex()


# ---------------------------------------------------------------------------
# Ed25519 signature envelope
# ---------------------------------------------------------------------------


@dataclass
class _KeyMaterial:
    """Carrier for raw Ed25519 bytes used by sign/verify; not part of the public envelope shape."""


def sign(
    manifest: dict[str, Any],
    private_key: Ed25519PrivateKey,
    key_id: str,
    *,
    issued_at: str | None = None,
    issuer: str | None = None,
    expires_at: str | None = None,
) -> dict[str, Any]:
    """Sign a manifest with an Ed25519 key.

    The returned ``signature.value`` is over ``canonical_json(manifest)``.
    """
    canonical = canonical_json(manifest).encode("utf-8")
    signature_bytes = private_key.sign(canonical)
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "manifest": manifest,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "public_key": pub_bytes.hex(),
            "value": signature_bytes.hex(),
        },
        "issued_at": issued_at,
        "issuer": issuer,
        "expires_at": expires_at,
    }


def verify(signed_manifest: dict[str, Any]) -> None:
    """Verify a signed manifest: recompute canonical JSON, verify the Ed25519 signature.

    Raises :class:`ManifestError` (code ``"SIGNATURE"`` or ``"SIGNATURE_ENVELOPE"``) on any failure.
    """
    envelope = signed_manifest.get("signature")
    if not isinstance(envelope, dict):
        raise ManifestError("SIGNATURE_ENVELOPE", "missing signature envelope")
    if envelope.get("algorithm") != "Ed25519":
        raise ManifestError(
            "SIGNATURE_ENVELOPE", f"unsupported algorithm: {envelope.get('algorithm')!r}"
        )
    try:
        pub_bytes = bytes.fromhex(envelope["public_key"])
    except (KeyError, ValueError) as exc:
        raise ManifestError("SIGNATURE_ENVELOPE", f"public_key hex: {exc}") from exc
    if len(pub_bytes) != 32:
        raise ManifestError(
            "SIGNATURE_ENVELOPE", f"public_key must be 32 bytes, got {len(pub_bytes)}"
        )
    try:
        sig_bytes = bytes.fromhex(envelope["value"])
    except (KeyError, ValueError) as exc:
        raise ManifestError("SIGNATURE_ENVELOPE", f"signature hex: {exc}") from exc
    if len(sig_bytes) != 64:
        raise ManifestError(
            "SIGNATURE_ENVELOPE", f"signature must be 64 bytes, got {len(sig_bytes)}"
        )

    manifest = signed_manifest.get("manifest")
    if not isinstance(manifest, dict):
        raise ManifestError("SIGNATURE_ENVELOPE", "signed manifest missing 'manifest' object")
    canonical = canonical_json(manifest).encode("utf-8")

    try:
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
    except ValueError as exc:
        raise ManifestError("SIGNATURE_ENVELOPE", f"public_key: {exc}") from exc

    try:
        public_key.verify(sig_bytes, canonical)
    except InvalidSignature as exc:
        raise ManifestError("SIGNATURE", "Ed25519 signature does not verify") from exc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a keypair using the OS RNG. Intended for tests and manifest-issuer bootstrap;
    production keys come from KMS/HSM."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def public_key_from_pem(pem: str | bytes) -> Ed25519PublicKey:
    """Load an Ed25519 public key from PEM (for issuers that publish their verifying key)."""
    if isinstance(pem, str):
        pem = pem.encode("utf-8")
    return serialization.load_pem_public_key(pem)  # type: ignore[return-value]
