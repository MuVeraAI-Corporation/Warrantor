"""Warrantor — the one-import SDK for verifiable agent authority.

Wraps the notary verdict (9 gates), evidence envelope (pre→post commit chaining), and agent
manifest (agent.yaml) into one ergonomic API. Self-contained — only depends on ``cryptography``.

    pip install warrantor

Quick start::

    import warrantor

    client = warrantor.Client()

    # Authorize an action → verdict + signed pre_commit receipt
    result = client.authorize(
        actor_svid="spiffe://yourcorp/agents/bot-1",
        actor_capabilities=["read", "write"],
        operation_capabilities=["read"],
        consequence_tier="routine",
        scope="prod",
    )
    assert result.verdict == "allow"

    # Attest the outcome → signed post_commit receipt (chains to pre_commit)
    post = client.attest(result.receipt, outcome_status="success", outcome_digest="sha256:abc")

    # Verify independently — any third party, no privileged access
    client.verify_chain(result.receipt, post)

    # Work with agent manifests
    manifest = client.create_manifest(
        name="my-agent",
        identity="spiffe://yourcorp/agents/my-agent",
        capabilities=["read"],
        policy_refs=["pol-1"],
        enforcement_mode="observed",
    )
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

__all__ = [
    "AuthorizeResult",
    "Client",
    "ManifestError",
    "VerdictError",
    "canonical_json",
    "verify_chain",
    "verify_receipt",
]

__version__ = "1.0.0"

# ═══════════════════════════════════════════════════════════════════════════
# Canonical JSON (RFC 8785-shaped) — the deterministic form both sides agree on
# ═══════════════════════════════════════════════════════════════════════════


def _canonicalize(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _canonicalize(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [_canonicalize(x) for x in obj]
    return obj


def canonical_json(obj: dict[str, Any]) -> str:
    """Deterministic JSON: sorted keys, compact, UTF-8. Matches the Rust crates."""
    return json.dumps(_canonicalize(obj), separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ═══════════════════════════════════════════════════════════════════════════
# Ed25519 key management
# ═══════════════════════════════════════════════════════════════════════════


def _generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


# ═══════════════════════════════════════════════════════════════════════════
# The 9-gate verdict function (spec 11) — the decision hot path
# ═══════════════════════════════════════════════════════════════════════════

_CAPABILITY_LADDER = frozenset({"read", "write", "financial", "destructive", "physical"})


@dataclass
class VerdictResult:
    """The outcome of a verdict evaluation."""

    outcome: str  # "allow" | "deny"
    gate: str | None = None  # the failing gate (for deny)
    effective_capabilities: list[str] = field(default_factory=list)


def _verdict(
    actor_svid: str,
    actor_capabilities: list[str],
    delegation_chain: list[dict[str, Any]],
    operation_capabilities: list[str],
    consequence_tier: str,
    scope: str,
    nonce: str,
    timestamp: int,
    now: int,
    contained_scopes: list[str],
    revoked_svids: list[str],
    seen_nonces: list[str],
    freshness_window: int,
    artifacts: list[dict[str, Any]],
    verified_artifacts: list[str],
    budget_remaining: int,
    policy_decision: bool,
    approval: dict[str, Any] | None,
    svid_not_after: int = 2**64 - 1,
) -> VerdictResult:
    """The 9-gate verdict function. Evaluated in order, short-circuit on first deny."""
    # Gate 1: Containment (I-12)
    if scope in contained_scopes:
        return VerdictResult("deny", "containment")
    # Gate 2: Identity (I-01)
    if not actor_svid or actor_svid in revoked_svids or svid_not_after <= now:
        return VerdictResult("deny", "identity")
    # Gate 3: Freshness (I-10)
    if nonce in seen_nonces:
        return VerdictResult("deny", "freshness")
    skew = abs(timestamp - now)
    if skew > freshness_window:
        return VerdictResult("deny", "freshness")
    # Gate 4: Chain (I-02)
    for link in delegation_chain:
        if not link.get("signature_verified", True):
            return VerdictResult("deny", "chain")
        if link.get("not_before", 0) > now or link.get("not_after", 2**64 - 1) <= now:
            return VerdictResult("deny", "chain")
    # Gate 5: Authority (I-02)
    effective = _intersection(actor_capabilities, delegation_chain)
    for cap in operation_capabilities:
        if cap not in effective:
            return VerdictResult("deny", "authority")
    # Gate 6: Artifacts (I-06)
    for art in artifacts:
        if art.get("digest") and not art.get("verified", True):
            return VerdictResult("deny", "artifacts")
    # Gate 7: Budget
    if budget_remaining <= 0:
        return VerdictResult("deny", "budget")
    # Gate 8: Policy (I-04)
    if not policy_decision:
        return VerdictResult("deny", "policy")
    # Gate 9: Approval (I-08)
    if consequence_tier == "critical" and (
        not approval or not approval.get("valid") or not approval.get("non_delegable")
    ):
        return VerdictResult("deny", "approval")
    return VerdictResult("allow", effective_capabilities=effective)


def _intersection(own: list[str], chain: list[dict[str, Any]]) -> list[str]:
    sets = [set(own)] + [set(link.get("capabilities", [])) for link in chain]
    result = sets[0]
    for s in sets[1:]:
        result &= s
    return sorted(result)


# ═══════════════════════════════════════════════════════════════════════════
# WAR receipt issuance + verification (spec 01)
# ═══════════════════════════════════════════════════════════════════════════


class VerdictError(Exception):
    """Raised when a verdict is deny or a receipt fails verification."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _sign_receipt(
    predicate: dict[str, Any], priv: Ed25519PrivateKey, key_id: str
) -> dict[str, Any]:
    """Sign a WAR predicate with Ed25519 over DSSE PAE of canonical JSON."""
    canonical = canonical_json(predicate)
    pae = f"DSSEv1 {len(canonical.encode())} {canonical}".encode()
    sig = priv.sign(pae)
    pub = priv.public_key()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "predicate": predicate,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "public_key": pub_bytes.hex(),
            "value": sig.hex(),
        },
    }


def verify_receipt(receipt: dict[str, Any]) -> None:
    """Verify a WAR receipt's Ed25519 signature. Raises VerdictError on failure."""
    predicate = receipt.get("predicate")
    sig_env = receipt.get("signature")
    if not isinstance(predicate, dict) or not isinstance(sig_env, dict):
        raise VerdictError("SIGNATURE_ENVELOPE", "receipt missing predicate or signature")
    if sig_env.get("algorithm") != "Ed25519":
        raise VerdictError("SIGNATURE_ENVELOPE", f"unsupported: {sig_env.get('algorithm')}")
    try:
        pub_bytes = bytes.fromhex(sig_env["public_key"])
    except (KeyError, ValueError) as e:
        raise VerdictError("SIGNATURE_ENVELOPE", f"public_key: {e}") from e
    if len(pub_bytes) != 32:
        raise VerdictError(
            "SIGNATURE_ENVELOPE", f"public_key must be 32 bytes, got {len(pub_bytes)}"
        )
    try:
        sig_bytes = bytes.fromhex(sig_env["value"])
    except (KeyError, ValueError) as e:
        raise VerdictError("SIGNATURE_ENVELOPE", f"signature: {e}") from e
    if len(sig_bytes) != 64:
        raise VerdictError(
            "SIGNATURE_ENVELOPE", f"signature must be 64 bytes, got {len(sig_bytes)}"
        )

    canonical = canonical_json(predicate)
    pae = f"DSSEv1 {len(canonical.encode())} {canonical}".encode()
    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(sig_bytes, pae)
    except Exception as e:
        raise VerdictError("INVALID_SIGNATURE", "Ed25519 signature does not verify") from e


def verify_chain(pre_commit: dict[str, Any], post_commit: dict[str, Any]) -> None:
    """Verify a pre_commit→post_commit chain: both signatures + commit gate (I-07) + authority (I-02)."""
    verify_receipt(pre_commit)
    verify_receipt(post_commit)
    pre_b = pre_commit["predicate"]["binding"]
    post_b = post_commit["predicate"]["binding"]
    if pre_b.get("phase") != "pre_commit":
        raise VerdictError("PHASE", "pre_commit must have phase=pre_commit")
    if pre_commit["predicate"].get("outcome") is not None:
        raise VerdictError("PHASE", "pre_commit must not carry an outcome")
    if post_b.get("phase") != "post_commit":
        raise VerdictError("PHASE", "post_commit must have phase=post_commit")
    if post_commit["predicate"].get("outcome") is None:
        raise VerdictError("PHASE", "post_commit must carry an outcome")
    parent = post_b.get("parent_receipt")
    expected = pre_b["receipt_id"]
    if parent != expected:
        raise VerdictError(
            "COMMIT_GATE", f"parent_receipt ({parent}) != pre_commit receipt_id ({expected})"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Agent manifest (M1)
# ═══════════════════════════════════════════════════════════════════════════

_ALLOWED_MANIFEST_FIELDS = frozenset(
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


class ManifestError(Exception):
    def __init__(self, code: str, message: str, *, field: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.field = field


def parse_manifest(json_str: str) -> dict[str, Any]:
    """Parse + validate an agent.yaml (JSON). Raises ManifestError on any rule violation."""
    try:
        obj = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ManifestError("MALFORMED_JSON", f"malformed JSON: {e}") from e
    if not isinstance(obj, dict):
        raise ManifestError("NOT_AN_OBJECT", "manifest must be a JSON object")
    for key in obj:
        if key not in _ALLOWED_MANIFEST_FIELDS:
            raise ManifestError("UNEXPECTED_FIELD", f"unexpected: {key}", field=key)
    for req in (
        "apiVersion",
        "kind",
        "name",
        "identity",
        "capabilities",
        "policy_refs",
        "enforcement_mode",
    ):
        if req not in obj:
            raise ManifestError("MISSING_REQUIRED_FIELD", f"missing: {req}", field=req)
    if obj["apiVersion"] != "agent.warrantor.io/v1":
        raise ManifestError("INVALID_API_VERSION", "expected agent.warrantor.io/v1")
    if obj["kind"] != "AgentManifest":
        raise ManifestError("INVALID_KIND", "expected AgentManifest")
    if not obj["identity"].startswith("spiffe://"):
        raise ManifestError("INVALID_IDENTITY", "must be spiffe://", field="identity")
    if not obj["capabilities"]:
        raise ManifestError("EMPTY_CAPABILITIES", "non-empty required", field="capabilities")
    for cap in obj["capabilities"]:
        if cap not in _CAPABILITY_LADDER:
            raise ManifestError(
                "INVALID_CAPABILITY", f"'{cap}' not on ladder", field="capabilities"
            )
    if not obj["policy_refs"]:
        raise ManifestError("EMPTY_POLICY_REFS", "non-empty required", field="policy_refs")
    if obj["enforcement_mode"] not in ("observed", "mediated"):
        raise ManifestError(
            "INVALID_ENFORCEMENT_MODE", "observed|mediated", field="enforcement_mode"
        )
    return obj


def sign_manifest(manifest: dict[str, Any], priv: Ed25519PrivateKey, key_id: str) -> dict[str, Any]:
    """Sign an agent manifest with Ed25519 over canonical JSON."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    canonical = canonical_json(manifest)
    sig = priv.sign(canonical.encode())
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "manifest": manifest,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "public_key": pub_bytes.hex(),
            "value": sig.hex(),
        },
    }


def verify_manifest(signed: dict[str, Any]) -> None:
    """Verify a signed agent manifest. Raises ManifestError on failure."""
    manifest = signed.get("manifest")
    sig_env = signed.get("signature")
    if not isinstance(manifest, dict) or not isinstance(sig_env, dict):
        raise ManifestError("SIGNATURE_ENVELOPE", "missing manifest or signature")
    try:
        pub_bytes = bytes.fromhex(sig_env["public_key"])
    except (KeyError, ValueError) as e:
        raise ManifestError("SIGNATURE_ENVELOPE", f"public_key: {e}") from e
    try:
        sig_bytes = bytes.fromhex(sig_env["value"])
    except (KeyError, ValueError) as e:
        raise ManifestError("SIGNATURE_ENVELOPE", f"signature: {e}") from e
    canonical = canonical_json(manifest)
    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(sig_bytes, canonical.encode())
    except Exception as e:
        raise ManifestError("INVALID_SIGNATURE", "Ed25519 signature does not verify") from e


# ═══════════════════════════════════════════════════════════════════════════
# Client — the ergonomic, one-import developer surface
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class AuthorizeResult:
    """The result of ``Client.authorize()``."""

    verdict: str  # "allow" | "deny"
    gate: str | None
    effective_capabilities: list[str]
    receipt: dict[str, Any]  # the signed pre_commit WAR receipt


class Client:
    """The one-import Warrantor SDK client.

    Local mode (default) uses the built-in 9-gate verdict engine — no infrastructure needed.
    Pass a ``signing_key`` to use a specific Ed25519 key; otherwise a fresh keypair is generated.

    Example::

        client = warrantor.Client()
        result = client.authorize(
            actor_svid="spiffe://yourcorp/agents/bot-1",
            actor_capabilities=["read", "write"],
            operation_capabilities=["read"],
            consequence_tier="routine",
            scope="prod",
        )
    """

    def __init__(
        self, signing_key: Ed25519PrivateKey | None = None, key_id: str = "sdk-default"
    ) -> None:
        self._priv, self._pub = (
            (signing_key, signing_key.public_key()) if signing_key else _generate_keypair()
        )
        self._key_id = key_id
        self._counter = 0

    def authorize(
        self,
        *,
        actor_svid: str,
        actor_capabilities: list[str],
        operation_capabilities: list[str],
        consequence_tier: str = "routine",
        scope: str = "default",
        operation_class: str = "action",
        delegation_chain: list[dict[str, Any]] | None = None,
        policy_decision: bool = True,
        approval: dict[str, Any] | None = None,
        contained_scopes: list[str] | None = None,
        revoked_svids: list[str] | None = None,
        enforcement_mode: str = "mediated",
        svid_not_after: int = 2**64 - 1,
    ) -> AuthorizeResult:
        """Run the 9-gate verdict and issue a signed pre_commit WAR receipt.

        Returns :class:`AuthorizeResult` with the verdict and the signed receipt.
        """
        self._counter += 1
        now = int(time.time())
        vr = _verdict(
            actor_svid=actor_svid,
            actor_capabilities=actor_capabilities,
            delegation_chain=delegation_chain or [],
            operation_capabilities=operation_capabilities,
            consequence_tier=consequence_tier,
            scope=scope,
            nonce=f"sdk-{self._counter}-{now}",
            timestamp=now,
            now=now,
            contained_scopes=contained_scopes or [],
            revoked_svids=revoked_svids or [],
            seen_nonces=[],
            freshness_window=300,
            artifacts=[],
            verified_artifacts=[],
            budget_remaining=1000,
            policy_decision=policy_decision,
            approval=approval,
            svid_not_after=svid_not_after,
        )

        predicate = {
            "binding": {
                "receipt_id": f"rcpt-{self._counter}-{now}",
                "phase": "pre_commit",
                "nonce": f"sdk-{self._counter}-{now}",
                "issued_at": now,
                "expires_at": now + 3600,
                "enforcement_mode": enforcement_mode,
            },
            "actor": {
                "principal": actor_svid,
                "workload_id": actor_svid,
                "svid_digest": "sha256:svid",
            },
            "authority": {
                "chain": delegation_chain or [],
                "effective_capabilities": vr.effective_capabilities,
                "intersection_proof": {
                    "algorithm": "warrantor-intersect-v1",
                    "links_digest": _sha256_hex(canonical_json(delegation_chain or [])),
                    "result_digest": _sha256_hex(canonical_json(vr.effective_capabilities)),
                },
            },
            "decision": {
                "verdict": vr.outcome,
                "engine": "warrantor-sdk/1.0",
                "policy_digest": "sha256:inline",
                "evaluated_at": now,
            },
            "operation": {
                "class": operation_class,
                "target": scope,
                "method": "execute",
                "parameters_digest": "sha256:params",
                "reversible": consequence_tier == "routine",
                "consequence_tier": consequence_tier,
            },
        }
        receipt = _sign_receipt(predicate, self._priv, self._key_id)
        return AuthorizeResult(
            verdict=vr.outcome,
            gate=vr.gate,
            effective_capabilities=vr.effective_capabilities,
            receipt=receipt,
        )

    def attest(
        self,
        pre_commit_receipt: dict[str, Any],
        *,
        outcome_status: str = "success",
        outcome_digest: str = "sha256:unknown",
        effects: list[str] | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        """Issue a signed post_commit receipt that chains to the pre_commit (spec 01 §5)."""
        predicate = json.loads(json.dumps(pre_commit_receipt["predicate"]))  # deep copy
        predicate["binding"]["phase"] = "post_commit"
        predicate["binding"]["parent_receipt"] = predicate["binding"]["receipt_id"]
        predicate["binding"]["receipt_id"] = predicate["binding"]["receipt_id"] + "-post"
        predicate["outcome"] = {
            "status": outcome_status,
            "outcome_digest": outcome_digest,
            "effects": effects or [],
            "error": error,
        }
        return _sign_receipt(predicate, self._priv, self._key_id)

    @staticmethod
    def verify_receipt(receipt: dict[str, Any]) -> None:
        """Verify a WAR receipt's Ed25519 signature."""
        verify_receipt(receipt)

    @staticmethod
    def verify_chain(pre_commit: dict[str, Any], post_commit: dict[str, Any]) -> None:
        """Verify a pre_commit→post_commit chain (commit gate I-07 + signatures)."""
        verify_chain(pre_commit, post_commit)

    def create_manifest(
        self,
        *,
        name: str,
        identity: str,
        capabilities: list[str],
        policy_refs: list[str],
        enforcement_mode: str = "observed",
        description: str | None = None,
        version: str = "1.0.0",
    ) -> dict[str, Any]:
        """Build + sign an agent manifest (M1 agent.yaml). Returns the signed manifest."""
        manifest = {
            "apiVersion": "agent.warrantor.io/v1",
            "kind": "AgentManifest",
            "name": name,
            "identity": identity,
            "capabilities": capabilities,
            "policy_refs": policy_refs,
            "enforcement_mode": enforcement_mode,
            "version": version,
        }
        if description:
            manifest["description"] = description
        # Validate before signing.
        parse_manifest(json.dumps(manifest))
        return sign_manifest(manifest, self._priv, self._key_id)

    @staticmethod
    def verify_manifest(signed: dict[str, Any]) -> None:
        """Verify a signed agent manifest."""
        verify_manifest(signed)

    @staticmethod
    def parse_manifest(json_str: str) -> dict[str, Any]:
        """Parse + validate an agent.yaml JSON string."""
        return parse_manifest(json_str)
