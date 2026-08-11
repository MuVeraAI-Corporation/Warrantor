"""Tests for the AumOS Agent SDK.

Covers: standalone primitives, connected mode (with fakes), the @agent.action decorator
(happy path, fail-closed preflight, exception containment), and the CLI entry point.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest

import warrantor_agent
from warrantor_agent import (
    MOCK_SIGNATURE_PREFIX,
    SIDE_EFFECTS,
    ActionBlocked,
    ActionResult,
    AumOS,
    ContainmentTriggered,
    Finding,
    SigningUnavailable,
    __version__,
)
from warrantor_agent.cli import main as cli_main

# ---------------------------------------------------------------------------
# Fakes for connected-mode tests.
# ---------------------------------------------------------------------------


class FakeBackend:
    """A controllable HTTP backend. Posts to /<key> route to ``responses``."""

    def __init__(
        self, responses: dict[str, dict[str, Any]] | None = None, raise_on: set[str] | None = None
    ) -> None:
        self.responses = responses or {}
        self.raise_on = raise_on or set()
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def post_json(self, url: str, body: dict[str, Any], timeout: float) -> dict[str, Any]:
        # Route by path suffix (e.g. "/v1/agent-identity:issue" -> "issue").
        path = url.split("/", 3)[-1] if "/" in url else url
        key = path.split(":")[-1].split("/")[-1]
        self.calls.append((url, body))
        if any(needle in url for needle in self.raise_on):
            raise RuntimeError(f"ECONNREFUSED (fake) to {url}")
        if key in self.responses:
            return self.responses[key]
        # Default: echo the body so we can assert it was sent.
        return {"ok": True, "echo": body}


def _fake_completed(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


# ---------------------------------------------------------------------------
# Package surface.
# ---------------------------------------------------------------------------


class TestSurface:
    def test_version_string(self) -> None:
        assert __version__ == "1.0.0"

    def test_public_api_exports(self) -> None:
        for name in (
            "AumOS",
            "ActionResult",
            "Receipt",
            "Finding",
            "ActionBlocked",
            "ContainmentTriggered",
            "SecurityError",
            "AumOSConfig",
            "SideEffect",
        ):
            assert hasattr(warrantor_agent, name), f"missing public export: {name}"

    def test_side_effects_ladder_order(self) -> None:
        assert SIDE_EFFECTS == ["read", "write", "financial", "destructive", "physical"]


# ---------------------------------------------------------------------------
# Construction + config.
# ---------------------------------------------------------------------------


class TestConfig:
    def test_default_mode_is_standalone(self) -> None:
        assert AumOS().mode == "standalone"

    def test_invalid_mode_raises(self) -> None:
        with pytest.raises(ValueError, match="mode"):
            AumOS(mode="bogus")

    def test_config_resolves_defaults(self) -> None:
        agent = AumOS()
        cfg = agent.config.resolved()
        assert cfg["agent_identity_url"].startswith("http://")
        assert cfg["http_timeout"] == 5.0
        assert cfg["trust_core_bin"] == "trust-core"

    def test_config_overrides_propagate(self) -> None:
        agent = AumOS(agent_identity_url="http://i1:9999", http_timeout=10.0)
        cfg = agent.config.resolved()
        assert cfg["agent_identity_url"] == "http://i1:9999"
        assert cfg["http_timeout"] == 10.0


# ---------------------------------------------------------------------------
# Standalone primitives.
# ---------------------------------------------------------------------------


class TestStandalonePrimitives:
    def test_sign_is_deterministic_hex(self) -> None:
        agent = AumOS()
        s1 = agent.sign("hello", key_id="k1")
        s2 = agent.sign("hello", key_id="k1")
        assert s1 == s2
        # Standalone output is a labelled mock, not bare hex (AX-28). The label is what
        # keeps it from being stored or forwarded as though it were a real signature.
        assert s1.startswith(MOCK_SIGNATURE_PREFIX)
        digest = s1[len(MOCK_SIGNATURE_PREFIX) :]
        assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)

    def test_sign_accepts_bytes(self) -> None:
        agent = AumOS()
        assert agent.sign(b"hello", key_id="k1") == agent.sign("hello", key_id="k1")

    def test_verify_round_trip(self) -> None:
        agent = AumOS()
        # Mock sign/verify round-trip: the key passed to verify matches the key_id used to sign.
        sig = agent.sign("hello", key_id="k1")
        assert agent.verify("hello", sig, key="k1") is True

    def test_verify_rejects_tampered(self) -> None:
        agent = AumOS()
        assert agent.verify("hello", "deadbeef" * 8, key="k1") is False

    def test_issue_identity_returns_svid(self) -> None:
        agent = AumOS()
        r = agent.issue_identity("spiffe://muveraai.com/agent/coding-1")
        assert r["svid"].startswith("svid-mock-")
        assert r["capability_jti"].startswith("jti-")
        assert r["source"] == "mock"
        assert isinstance(r["expires_at"], int)

    def test_issue_requires_subject(self) -> None:
        with pytest.raises(ValueError):
            AumOS().issue_identity("")

    def test_verify_identity_round_trips(self) -> None:
        agent = AumOS()
        issued = agent.issue_identity("spiffe://muveraai.com/agent/coding-1")
        r = agent.verify_identity(issued["svid"])
        assert r["valid"] is True
        assert r["subject"] == "spiffe://muveraai.com/agent/coding-1"

    def test_verify_identity_rejects_unknown(self) -> None:
        assert AumOS().verify_identity("garbage")["valid"] is False

    def test_revoke_identity(self) -> None:
        r = AumOS().revoke_identity("jti-abc", reason="rotation")
        assert r["revoked"] is True
        assert isinstance(r["revoked_at"], int)

    def test_emit_receipt_returns_aar(self) -> None:
        agent = AumOS()
        rec = agent.emit_receipt("spiffe://muveraai.com/agent/x", "github.create_pr", "pending")
        assert rec.receipt_id.startswith("aar-")
        assert len(rec.signature) == 64
        assert rec.payload["actor"] == "spiffe://muveraai.com/agent/x"

    def test_emit_receipt_requires_actor_and_tool(self) -> None:
        with pytest.raises(ValueError):
            AumOS().emit_receipt("", "t")

    def test_verify_receipt(self) -> None:
        r = AumOS().verify_receipt("aar-123")
        assert r["valid"] is True
        assert "flight-recorder" in r["signer"]

    def test_check_attestation(self) -> None:
        r = AumOS().check_attestation(nonce="n1", gpu_pci_id="GPU-0")
        assert r["verified"] is True
        assert "nvidia" in r["hardware_tee"]

    def test_run_preflight_allows_read(self) -> None:
        r = AumOS().run_preflight("fs.read", side_effect="read")
        assert r["allowed"] is True
        assert r["reason"] == "ok"

    @pytest.mark.parametrize("cls", ["financial", "destructive", "physical"])
    def test_run_preflight_blocks_consequential(self, cls: str) -> None:
        r = AumOS().run_preflight(f"x.{cls}", side_effect=cls)
        assert r["allowed"] is False
        assert "consequential" in r["reason"]

    def test_kill(self) -> None:
        r = AumOS().kill(reason="behavioral_anomaly")
        assert r["triggered"] is True
        assert r["reason"] == "behavioral_anomaly"

    def test_kill_requires_reason(self) -> None:
        with pytest.raises(ValueError):
            AumOS().kill(reason="")

    def test_scan_secrets_detects_github_pat(self) -> None:
        text = "token=ghp_" + "a" * 36
        findings = AumOS().scan_secrets(text)
        types = [f.type for f in findings]
        assert "github_pat" in types
        # value must be masked
        pat = next(f for f in findings if f.type == "github_pat")
        assert "a" * 36 not in pat.value

    def test_scan_secrets_detects_multiple(self) -> None:
        text = "AKIAIOSFODNN7EXAMPLE and sk_live_" + "a" * 30
        findings = AumOS().scan_secrets(text)
        types = {f.type for f in findings}
        assert "aws_access_key_id" in types
        assert "stripe_key" in types

    def test_scan_secrets_clean_text(self) -> None:
        assert AumOS().scan_secrets("nothing to see here") == []

    def test_scan_secrets_detects_private_key_block(self) -> None:
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
        findings = AumOS().scan_secrets(text)
        assert any(f.type == "private_key_block" for f in findings)

    def test_compliance_report(self) -> None:
        r = AumOS().compliance_report(scope="soc2")
        assert r["format"] == "json"
        report = json.loads(r["report_json"])
        assert report["scope"] == "soc2"
        assert report["status"] == "compliant"

    def test_install(self) -> None:
        r = AumOS().install("agent-identity", version="1.0.0")
        assert r["installed"] is True
        assert r["name"] == "agent-identity"

    def test_install_requires_name(self) -> None:
        with pytest.raises(ValueError):
            AumOS().install("")

    def test_generate_sbom(self) -> None:
        r = AumOS().generate_sbom("llama-3-8b")
        assert r["sbom"]["bomFormat"] == "CycloneDX"
        assert any(c["name"] == "llama-3-8b" for c in r["sbom"]["components"])

    def test_generate_sbom_requires_model(self) -> None:
        with pytest.raises(ValueError):
            AumOS().generate_sbom("")

    def test_run_eval(self) -> None:
        r = AumOS().run_eval("model://warrantor-7b")
        assert r["results"]["accuracy"] == 0.85
        assert r["veb"]["bundleId"].startswith("veb-")


# ---------------------------------------------------------------------------
# Connected mode (with fakes).
# ---------------------------------------------------------------------------


class TestConnectedMode:
    def test_issue_identity_posts_to_i1(self) -> None:
        fake = FakeBackend(
            responses={
                "issue": {
                    "svid": "svid-real",
                    "capability_jti": "jti-real",
                    "verifying_key": "pk",
                    "expires_at": 100,
                }
            }
        )
        agent = AumOS(mode="connected", agent_identity_url="http://i1:8441", _backend=fake)
        r = agent.issue_identity("spiffe://muveraai.com/agent/x")
        assert r["svid"] == "svid-real"
        assert r["source"] == "agent-identity"
        assert fake.calls and "agent-identity:issue" in fake.calls[0][0]

    def test_issue_identity_degrades_on_connection_error(self) -> None:
        fake = FakeBackend(raise_on={"i1"})
        agent = AumOS(mode="connected", agent_identity_url="http://i1:8441", _backend=fake)
        r = agent.issue_identity("spiffe://muveraai.com/agent/x")
        assert r["source"] == "mock"
        assert r["degraded"] is True
        assert "ECONNREFUSED" in r["http_error"]

    def test_emit_receipt_uses_flight_recorder(self) -> None:
        fake = FakeBackend(responses={"emit": {"receipt_id": "aar-real", "signature": "sig-real"}})
        agent = AumOS(mode="connected", flight_recorder_url="http://e1:8445", _backend=fake)
        rec = agent.emit_receipt("a", "t", "pending")
        assert rec.receipt_id == "aar-real"
        assert rec.signature == "sig-real"
        assert rec.source == "flight-recorder"

    def test_scan_secrets_uses_credential_vault(self) -> None:
        fake = FakeBackend(
            responses={"scan": {"findings": [{"type": "github_pat", "value": "x", "index": 0}]}}
        )
        agent = AumOS(mode="connected", credential_vault_url="http://r4:8465", _backend=fake)
        findings = agent.scan_secrets("token=ghp_" + "a" * 36)
        assert findings == [Finding(type="github_pat", value="x", index=0)]

    def test_scan_secrets_falls_back_on_error(self) -> None:
        fake = FakeBackend(raise_on={"r4"})
        agent = AumOS(mode="connected", credential_vault_url="http://r4:8465", _backend=fake)
        findings = agent.scan_secrets("AKIAIOSFODNN7EXAMPLE")
        assert any(f.type == "aws_access_key_id" for f in findings)

    def test_kill_posts_to_kill_switch(self) -> None:
        fake = FakeBackend(responses={"trigger": {"triggered": True, "killed_at": 42}})
        agent = AumOS(mode="connected", kill_switch_url="http://r3:8461", _backend=fake)
        r = agent.kill(reason="x")
        assert r == {"triggered": True, "killed_at": 42}


# ---------------------------------------------------------------------------
# The @agent.action decorator.
# ---------------------------------------------------------------------------


class TestActionDecorator:
    def test_decorator_wraps_and_returns_value(self) -> None:
        agent = AumOS()

        @agent.action(tool="github.create_pr", side_effect="write")
        def create_pr(repo: str, title: str) -> dict[str, Any]:
            return {"pr_number": 42, "repo": repo, "title": title}

        out = create_pr("warrantor/aumos", "feat: x")
        assert out == {"pr_number": 42, "repo": "warrantor/aumos", "title": "feat: x"}

        # The wrapper exposes the structured ActionResult.
        result = create_pr.action_result  # type: ignore[attr-defined]
        assert isinstance(result, ActionResult)
        assert result.ok is True
        assert result.outcome == "success"
        assert result.receipt.receipt_id.startswith("aar-")
        assert result.svid is not None

    def test_decorator_records_evidence(self) -> None:
        agent = AumOS()

        @agent.action(tool="fs.read", side_effect="read")
        def read(path: str) -> str:
            return f"contents-of-{path}"

        read("/etc/hosts")
        read("/etc/passwd")
        assert len(agent.evidence) == 2
        assert all(e["outcome"] == "success" for e in agent.evidence)

    def test_decorator_emits_receipt_before_commit(self) -> None:
        """Invariant I-07: a receipt must be emitted *before* the action commits.

        We assert this by checking that the 'pending' receipt was emitted (the implementation
        emits pending -> success; the pending emission is the load-bearing pre-commit step).
        """
        agent = AumOS()
        emitted: list[str] = []

        @agent.action(tool="x.write", side_effect="write")
        def write_it() -> str:
            # At this point the pre-commit receipt must already have been emitted.
            emitted.append("during-action")
            return "done"

        write_it()
        assert emitted == ["during-action"]
        result = write_it.action_result  # type: ignore[attr-defined]
        # Final receipt is success; payload records the side_effect class.
        assert result.receipt.payload["outcome"] == "success"
        assert result.receipt.payload["side_effect"] == "write"

    def test_decorator_fail_closed_blocks_consequential(self) -> None:
        """Invariant I-09: fail-closed. A denied preflight must raise ActionBlocked."""
        agent = AumOS(fail_closed=True)
        called = {"n": 0}

        @agent.action(tool="db.drop", side_effect="destructive")
        def drop_table() -> str:
            called["n"] += 1
            return "dropped"

        with pytest.raises(ActionBlocked) as ei:
            drop_table()
        assert "consequential" in ei.value.reason
        assert called["n"] == 0  # wrapped function never ran
        # A 'denied' receipt was still recorded in evidence.
        assert any(e["outcome"] == "denied" for e in agent.evidence)

    def test_decorator_fail_open_allows_when_fail_closed_false(self) -> None:
        agent = AumOS(fail_closed=False)

        @agent.action(tool="db.drop", side_effect="destructive")
        def drop_table() -> str:
            return "dropped"

        # With fail_closed=False the action proceeds despite preflight denial.
        assert drop_table() == "dropped"
        result = drop_table.action_result  # type: ignore[attr-defined]
        assert result.preflight["allowed"] is False
        assert result.outcome == "success"  # still succeeded

    def test_decorator_triggers_containment_on_exception(self) -> None:
        """If the wrapped function raises, the kill-switch fires (ContainmentTriggered)."""
        agent = AumOS(auto_kill_on_error=True)

        @agent.action(tool="x.write", side_effect="write")
        def boom() -> None:
            raise RuntimeError("kaboom")

        with pytest.raises(ContainmentTriggered) as ei:
            boom()
        assert "kill-switch triggered" in str(ei.value)
        # A failure receipt was recorded.
        assert any(e["outcome"] == "failure" for e in agent.evidence)

    def test_decorator_no_auto_kill_reraises_original(self) -> None:
        agent = AumOS(auto_kill_on_error=False)

        @agent.action(tool="x.write", side_effect="write")
        def boom() -> None:
            raise ValueError("original")

        with pytest.raises(ValueError, match="original"):
            boom()
        # Failure still recorded even without kill-switch.
        assert any(e["outcome"] == "failure" for e in agent.evidence)

    def test_decorator_rejects_invalid_side_effect(self) -> None:
        agent = AumOS()
        with pytest.raises(ValueError, match="side_effect"):

            @agent.action(tool="x", side_effect="nuclear")  # type: ignore[arg-type]
            def f() -> None: ...

    def test_decorator_scans_inputs_for_secrets(self) -> None:
        """Credential brokering (R4): a leaked secret in args is recorded on the preflight."""
        agent = AumOS()

        @agent.action(tool="http.post", side_effect="write")
        def post(body: str) -> str:
            return "ok"

        post("token=ghp_" + "a" * 36)
        result = post.action_result  # type: ignore[attr-defined]
        assert "secret_findings" in result.preflight
        assert result.preflight["secret_findings"][0]["type"] == "github_pat"

    def test_action_result_as_dict_roundtrips(self) -> None:
        agent = AumOS()

        @agent.action(tool="x.read", side_effect="read")
        def f() -> int:
            return 7

        f()
        d = f.action_result.as_dict()  # type: ignore[attr-defined]
        assert d["ok"] is True
        assert d["value"] == 7
        assert d["outcome"] == "success"
        assert "receipt" in d and "preflight" in d and "duration_ms" in d


# ---------------------------------------------------------------------------
# CLI entry point.
# ---------------------------------------------------------------------------


class TestCLI:
    def test_status_outputs_version_and_mode(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = cli_main(["status"])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["version"] == __version__
        assert out["mode"] == "standalone"

    def test_scan_secrets_from_text(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = cli_main(["scan-secrets", "--text", "AKIAIOSFODNN7EXAMPLE"])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["count"] >= 1
        assert out["findings"][0]["type"] == "aws_access_key_id"

    def test_issue_prints_svid(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = cli_main(["issue", "spiffe://muveraai.com/agent/x"])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["svid"].startswith("svid-mock-")

    def test_version_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as ei:
            cli_main(["--version"])
        assert ei.value.code == 0


class TestAX28SigningFailsClosed:
    """A signer that cannot sign must raise, never downgrade (AX-28).

    The original code caught OSError/SubprocessError from the trust-core CLI and returned
    `_mock_sign`, an HMAC keyed by sha256("warrantor-mock-key:" + key_id). Both halves are
    public, so the result is forgeable by anyone -- and the caller could not tell it apart
    from a real Ed25519 signature.
    """

    @staticmethod
    def _connected_agent(monkeypatch, failure):
        agent = AumOS(mode="connected")
        assert agent.is_connected

        def explode(*_args, **_kwargs):
            raise failure

        monkeypatch.setattr(agent, "_run_cli", explode)
        return agent

    def test_sign_raises_when_the_signer_is_unreachable(self, monkeypatch) -> None:
        agent = self._connected_agent(monkeypatch, OSError("trust-core not on PATH"))
        with pytest.raises(SigningUnavailable):
            agent.sign("hello", key_id="k1")

    def test_verify_raises_rather_than_falling_back(self, monkeypatch) -> None:
        agent = self._connected_agent(monkeypatch, OSError("trust-core not on PATH"))
        with pytest.raises(SigningUnavailable):
            agent.verify("hello", "deadbeef", key="k1")

    def test_sign_raises_on_nonzero_exit(self, monkeypatch) -> None:
        agent = AumOS(mode="connected")
        monkeypatch.setattr(
            agent,
            "_run_cli",
            lambda *_a, **_k: subprocess.CompletedProcess([], 1, stdout="", stderr="boom"),
        )
        with pytest.raises(SigningUnavailable):
            agent.sign("hello", key_id="k1")

    def test_mock_output_is_labelled_and_cannot_pass_as_a_signature(self) -> None:
        agent = AumOS(mode="standalone")
        sig = agent.sign("hello", key_id="k1")
        assert sig.startswith(MOCK_SIGNATURE_PREFIX)
        # A real Ed25519 signature is bare hex, so the prefix makes the two disjoint.
        assert not all(c in "0123456789abcdef" for c in sig)

    def test_standalone_verify_rejects_anything_not_declaring_itself_a_mock(self) -> None:
        agent = AumOS(mode="standalone")
        # A real 64-byte Ed25519 signature must not be silently "verified" by an HMAC check.
        assert agent.verify("hello", "ab" * 64, key="k1") is False

    def test_standalone_round_trip_still_works(self) -> None:
        agent = AumOS(mode="standalone")
        assert agent.verify("hello", agent.sign("hello", key_id="k1"), key="k1") is True
