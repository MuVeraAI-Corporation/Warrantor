"""Tests for the warrantor umbrella SDK — end-to-end developer flows."""

from __future__ import annotations

import json

import pytest

import warrantor

# ---------------------------------------------------------------------------
# End-to-end: authorize → attest → verify_chain
# ---------------------------------------------------------------------------


def test_authorize_allow_attest_verify_end_to_end():
    """The core developer flow: authorize, attest, verify the chain independently."""
    client = warrantor.Client()

    result = client.authorize(
        actor_svid="spiffe://yourcorp/agents/bot-1",
        actor_capabilities=["read", "write"],
        operation_capabilities=["read"],
        consequence_tier="routine",
        scope="prod",
    )
    assert result.verdict == "allow"
    assert "read" in result.effective_capabilities
    assert result.receipt["predicate"]["binding"]["phase"] == "pre_commit"

    post = client.attest(result.receipt, outcome_status="success", outcome_digest="sha256:abc")
    assert post["predicate"]["binding"]["phase"] == "post_commit"
    assert (
        post["predicate"]["binding"]["parent_receipt"]
        == result.receipt["predicate"]["binding"]["receipt_id"]
    )
    assert post["predicate"]["outcome"]["status"] == "success"

    # Independent verification — any third party.
    warrantor.verify_chain(result.receipt, post)


def test_authorize_deny_when_capability_not_in_intersection():
    client = warrantor.Client()
    result = client.authorize(
        actor_svid="spiffe://yourcorp/agents/bot-1",
        actor_capabilities=["read"],
        operation_capabilities=["financial"],
        consequence_tier="routine",
        scope="prod",
    )
    assert result.verdict == "deny"
    assert result.gate == "authority"


def test_authorize_deny_when_scope_contained():
    client = warrantor.Client()
    result = client.authorize(
        actor_svid="spiffe://yourcorp/agents/bot-1",
        actor_capabilities=["read"],
        operation_capabilities=["read"],
        consequence_tier="routine",
        scope="prod",
        contained_scopes=["prod"],
    )
    assert result.verdict == "deny"
    assert result.gate == "containment"


def test_authorize_deny_when_policy_denies():
    client = warrantor.Client()
    result = client.authorize(
        actor_svid="spiffe://yourcorp/agents/bot-1",
        actor_capabilities=["read"],
        operation_capabilities=["read"],
        consequence_tier="routine",
        scope="prod",
        policy_decision=False,
    )
    assert result.verdict == "deny"
    assert result.gate == "policy"


def test_authorize_deny_critical_without_approval():
    client = warrantor.Client()
    result = client.authorize(
        actor_svid="spiffe://yourcorp/agents/bot-1",
        actor_capabilities=["financial"],
        operation_capabilities=["financial"],
        consequence_tier="critical",
        scope="prod",
    )
    assert result.verdict == "deny"
    assert result.gate == "approval"


def test_authorize_allow_critical_with_non_delegable_approval():
    client = warrantor.Client()
    result = client.authorize(
        actor_svid="spiffe://yourcorp/agents/bot-1",
        actor_capabilities=["financial"],
        operation_capabilities=["financial"],
        consequence_tier="critical",
        scope="prod",
        approval={"valid": True, "non_delegable": True},
    )
    assert result.verdict == "allow"


# ---------------------------------------------------------------------------
# Receipt verification — tamper detection
# ---------------------------------------------------------------------------


def test_tampered_receipt_rejected():
    client = warrantor.Client()
    result = client.authorize(
        actor_svid="spiffe://yourcorp/agents/bot-1",
        actor_capabilities=["read"],
        operation_capabilities=["read"],
        consequence_tier="routine",
        scope="prod",
    )
    result.receipt["predicate"]["actor"]["principal"] = "evil"
    with pytest.raises(warrantor.VerdictError) as exc:
        warrantor.verify_receipt(result.receipt)
    assert exc.value.code == "INVALID_SIGNATURE"


def test_orphan_post_commit_rejected():
    """A correctly-signed post_commit whose parent points to a different pre_commit is rejected."""
    client = warrantor.Client()
    # Two separate authorizations → two different pre_commit receipt_ids.
    result_a = client.authorize(
        actor_svid="spiffe://yourcorp/agents/bot-1",
        actor_capabilities=["read"],
        operation_capabilities=["read"],
        consequence_tier="routine",
        scope="prod",
    )
    result_b = client.authorize(
        actor_svid="spiffe://yourcorp/agents/bot-1",
        actor_capabilities=["read"],
        operation_capabilities=["read"],
        consequence_tier="routine",
        scope="prod",
    )
    # Post_commit from B, correctly signed, but chained to B not A.
    post_b = client.attest(result_b.receipt, outcome_status="success", outcome_digest="sha256:x")
    # Verify against A → commit-gate must fail (parent_receipt of B != receipt_id of A).
    with pytest.raises(warrantor.VerdictError) as exc:
        warrantor.verify_chain(result_a.receipt, post_b)
    assert exc.value.code == "COMMIT_GATE"


# ---------------------------------------------------------------------------
# Manifest — create + verify round-trip
# ---------------------------------------------------------------------------


def test_create_and_verify_manifest():
    client = warrantor.Client()
    signed = client.create_manifest(
        name="my-agent",
        identity="spiffe://yourcorp/agents/my-agent",
        capabilities=["read", "write"],
        policy_refs=["pol-1"],
        enforcement_mode="observed",
        description="A test agent.",
    )
    warrantor.Client.verify_manifest(signed)  # static method; any third party can verify


def test_manifest_tamper_rejected():
    client = warrantor.Client()
    signed = client.create_manifest(
        name="my-agent",
        identity="spiffe://yourcorp/agents/my-agent",
        capabilities=["read"],
        policy_refs=["pol-1"],
        enforcement_mode="observed",
    )
    signed["manifest"]["name"] = "evil-agent"
    with pytest.raises(warrantor.ManifestError) as exc:
        warrantor.Client.verify_manifest(signed)
    assert exc.value.code == "INVALID_SIGNATURE"


def test_parse_manifest_validates():
    good = json.dumps(
        {
            "apiVersion": "agent.warrantor.io/v1",
            "kind": "AgentManifest",
            "name": "x",
            "identity": "spiffe://y/z",
            "capabilities": ["read"],
            "policy_refs": ["pol"],
            "enforcement_mode": "observed",
        }
    )
    m = warrantor.Client.parse_manifest(good)
    assert m["name"] == "x"


def test_parse_manifest_rejects_bad_capability():
    bad = json.dumps(
        {
            "apiVersion": "agent.warrantor.io/v1",
            "kind": "AgentManifest",
            "name": "x",
            "identity": "spiffe://y/z",
            "capabilities": ["deploy"],
            "policy_refs": ["pol"],
            "enforcement_mode": "observed",
        }
    )
    with pytest.raises(warrantor.ManifestError) as exc:
        warrantor.Client.parse_manifest(bad)
    assert exc.value.code == "INVALID_CAPABILITY"


# ---------------------------------------------------------------------------
# Canonical JSON — determinism
# ---------------------------------------------------------------------------


def test_canonical_json_sorted_compact():
    c = warrantor.canonical_json({"b": 2, "a": 1})
    assert c == '{"a":1,"b":2}'


# ---------------------------------------------------------------------------
# Full developer scenario — a realistic agent action lifecycle
# ---------------------------------------------------------------------------


def test_full_agent_action_lifecycle():
    """A realistic end-to-end: create manifest → authorize → attest → verify chain → verify manifest."""
    client = warrantor.Client()

    # 1. Define the agent.
    manifest = client.create_manifest(
        name="refund-bot",
        identity="spiffe://yourcorp/agents/refund-bot",
        capabilities=["read", "write", "financial"],
        policy_refs=["pol-refunds"],
        enforcement_mode="mediated",
        description="Processes customer refunds up to $500.",
    )

    # 2. Authorize a routine action.
    result = client.authorize(
        actor_svid="spiffe://yourcorp/agents/refund-bot",
        actor_capabilities=["read", "write", "financial"],
        operation_capabilities=["read"],
        consequence_tier="routine",
        scope="payments",
        operation_class="query_customer",
    )
    assert result.verdict == "allow"

    # 3. Attest the outcome.
    post = client.attest(
        result.receipt, outcome_status="success", outcome_digest="sha256:refund-processed"
    )

    # 4. Independent verification of the full evidence chain.
    warrantor.verify_chain(result.receipt, post)
    warrantor.Client.verify_manifest(manifest)

    # 5. A second action — critical, with approval.
    result2 = client.authorize(
        actor_svid="spiffe://yourcorp/agents/refund-bot",
        actor_capabilities=["read", "write", "financial"],
        operation_capabilities=["financial"],
        consequence_tier="critical",
        scope="payments",
        operation_class="issue_refund",
        approval={"valid": True, "non_delegable": True},
    )
    assert result2.verdict == "allow"
    post2 = client.attest(
        result2.receipt, outcome_status="success", outcome_digest="sha256:refund-issued"
    )
    warrantor.verify_chain(result2.receipt, post2)
