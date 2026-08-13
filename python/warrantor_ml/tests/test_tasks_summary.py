"""Model 8: there must be no code path from a tampered bundle to prose."""

from __future__ import annotations

import ast
import inspect
from typing import Any

import pytest

from warrantor_ml.tasks import summary as summary_module
from warrantor_ml.tasks.summary import (
    ENVELOPE_VOCABULARY,
    ReportSummary,
    SummaryFaithfulnessError,
    UnverifiedBundleRefused,
    VerifiedBundleView,
    check_summary,
    render_source_facts,
)


def _response(integrity: str = "ok", **overrides: Any) -> dict[str, Any]:
    """A `/v1/warrants/{id}/report` response in the shape `Response::json` produces."""

    data: dict[str, Any] = {
        "warrant_id": "w-001",
        "goal": "refactor the auth module",
        "subject": "spiffe://warrantor.io/agent/claude",
        "state": "settled",
        "issued_at": 1700000000,
        "expires_at": 1700003600,
        "staged_count": 3,
        "spend": {"cents_observed": 40},
        "bounds": {
            "tools": ["git", "cargo"],
            "write_paths": ["src/**"],
            "egress_hosts": [],
            "staged_classes": ["financial"],
            "expires_at": 1700003600,
            "delegation_depth": 2,
        },
        "limitations": [
            "the parent warrant is named but was not fetched",
            "no ledger was consulted for spend outside the recorded window",
        ],
    }
    data.update(overrides.pop("data", {}))
    payload: dict[str, Any] = {
        "verified": integrity == "ok",
        "verification": {
            "integrity": integrity,
            "liveness": "expired",
            "checked_at": 1700004000,
            "digest": "sha256:" + "d" * 64,
            "code": None if integrity == "ok" else "digest_mismatch",
            "reason": "the record's digest does not match what was signed",
        },
        "data": data,
    }
    payload.update(overrides)
    return payload


# ── the structural constraint ───────────────────────────────────────────────────────────


def test_there_is_exactly_one_constructor() -> None:
    """A second way in is a way past the refusal."""

    constructors = [
        name
        for name, member in inspect.getmembers(VerifiedBundleView)
        if isinstance(inspect.getattr_static(VerifiedBundleView, name, None), classmethod)
    ]
    assert constructors == ["from_response"]


def test_a_failed_bundle_is_refused() -> None:
    with pytest.raises(UnverifiedBundleRefused, match="CHECKED this record and the check did not"):
        VerifiedBundleView.from_response(_response(integrity="failed"))


def test_unknown_is_never_rendered_as_failed() -> None:
    """`unknown` means nothing was checked. Telling its owner it was tampered with is a lie."""

    with pytest.raises(UnverifiedBundleRefused) as caught:
        VerifiedBundleView.from_response(_response(integrity="unknown"))
    message = str(caught.value).lower()
    assert "nothing was checked" in message
    assert "is not a statement that the record is bad" in message
    for accusation in ("failed", "tampered", "altered"):
        assert accusation not in message, f"an unknown verdict must not say {accusation!r}"


def test_the_failed_and_unknown_messages_are_distinct() -> None:
    with pytest.raises(UnverifiedBundleRefused) as failed:
        VerifiedBundleView.from_response(_response(integrity="failed"))
    with pytest.raises(UnverifiedBundleRefused) as unknown:
        VerifiedBundleView.from_response(_response(integrity="unknown"))
    assert str(failed.value) != str(unknown.value)


def test_a_response_with_no_verification_envelope_is_refused() -> None:
    with pytest.raises(UnverifiedBundleRefused, match="verification happens in Rust"):
        VerifiedBundleView.from_response({"data": {}})


def test_a_verdict_with_no_digest_is_refused() -> None:
    """Without it a summary cannot be bound to its subject and can be shown against another."""

    payload = _response()
    payload["verification"]["digest"] = None
    with pytest.raises(UnverifiedBundleRefused, match="names no digest"):
        VerifiedBundleView.from_response(payload)


def test_a_bundle_with_no_limitations_is_refused() -> None:
    """ReportBundle.limitations is never empty by construction, so an empty list is not one."""

    payload = _response()
    payload["data"]["limitations"] = []
    with pytest.raises(UnverifiedBundleRefused, match="declares no limitations"):
        VerifiedBundleView.from_response(payload)


# ── verification happens only in Rust ───────────────────────────────────────────────────


def test_the_module_imports_no_crypto_and_recomputes_no_digest() -> None:
    """A second verifier above the Rust line can disagree with the first.

    Checked against the parsed AST rather than the raw text, so the module docstring is free to
    name the imports it must not have -- which is where the rule is explained.
    """

    tree = ast.parse(inspect.getsource(summary_module))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    forbidden = {"hashlib", "cryptography", "hmac", "nacl", "ed25519"}
    leaked = imported & forbidden
    assert not leaked, (
        f"tasks/summary.py imports {sorted(leaked)}. This module reads the Rust-produced "
        "envelope and refuses on it; it must never verify anything itself, because a second "
        "verifier can disagree with the first and then a human has to decide which to believe."
    )
    # It must also not reach the package's own digest helpers, which would be the same mistake
    # spelled differently.
    assert "_canonical" not in imported


def test_the_model_is_never_shown_the_verification_verdict() -> None:
    """It cannot describe a check it was not told about."""

    view = VerifiedBundleView.from_response(_response())
    facts = render_source_facts(view)
    for leaked in ("integrity", "verified", "digest", "signed_by", "checked_at"):
        assert leaked not in facts


# ── the summary is bound, traceable and carries no verdict vocabulary ───────────────────


def _summary(prose: str, digest: str | None = None) -> ReportSummary:
    return ReportSummary(
        bundle_digest=digest or ("sha256:" + "d" * 64),
        warrant_id="w-001",
        prose=prose,
        model_id="report-summariser",
    )


_GOOD_PROSE = (
    "The agent worked toward refactoring the auth module and reached a settled state. "
    "It staged 3 effects for review and its reported spend was 40 cents. "
    "This record carries 2 limitations that qualify what it establishes."
)


def test_a_faithful_summary_passes() -> None:
    view = VerifiedBundleView.from_response(_response())
    check_summary(_summary(_GOOD_PROSE), view)


def test_a_summary_bound_to_a_different_bundle_is_refused() -> None:
    view = VerifiedBundleView.from_response(_response())
    with pytest.raises(SummaryFaithfulnessError, match="shown against the wrong bundle"):
        check_summary(_summary(_GOOD_PROSE, digest="sha256:" + "e" * 64), view)


@pytest.mark.parametrize("word", ["verified", "integrity", "failed", "unknown", "tampered"])
def test_verdict_vocabulary_in_the_prose_is_refused(word: str) -> None:
    """Model text that reads like a verdict can be placed where a verdict belongs."""

    view = VerifiedBundleView.from_response(_response())
    with pytest.raises(SummaryFaithfulnessError, match="verification vocabulary"):
        check_summary(_summary(_GOOD_PROSE + f" The record is {word}."), view)


def test_the_word_boundary_match_does_not_reject_innocent_words() -> None:
    """`ok` must not reject `looked` or `broken`."""

    view = VerifiedBundleView.from_response(_response())
    prose = (
        "The reviewer looked at the run, which reached a settled state after 3 staged effects "
        "and 40 cents of reported spend. Nothing was broken. It carries 2 limitations."
    )
    check_summary(_summary(prose), view)


def test_an_invented_number_is_refused() -> None:
    """Every figure a decision-maker reads has to be traceable to a bundle field."""

    view = VerifiedBundleView.from_response(_response())
    with pytest.raises(SummaryFaithfulnessError, match="no source in the bundle"):
        check_summary(_summary(_GOOD_PROSE + " Total cost was 999 cents."), view)


def test_a_summary_that_drops_the_limitations_is_refused() -> None:
    """Silently upgrading a caveated record into a clean one."""

    view = VerifiedBundleView.from_response(_response())
    prose = "The agent settled the run, staged 3 effects and reported 40 cents of spend."
    with pytest.raises(SummaryFaithfulnessError, match="never mentions that the bundle carries"):
        check_summary(_summary(prose), view)


def test_the_serialised_summary_declares_itself_a_model_output() -> None:
    payload = _summary(_GOOD_PROSE).to_dict()
    assert payload["source"] == "model"
    assert "not itself a verdict" in payload["note"]


def test_source_numbers_include_the_bundles_own_figures() -> None:
    view = VerifiedBundleView.from_response(_response())
    permitted = view.source_numbers()
    assert "3" in permitted  # staged_count
    assert "40" in permitted  # spend
    assert "2" in permitted  # limitation count and delegation_depth
    assert "999" not in permitted


def test_the_envelope_vocabulary_covers_the_three_valued_answer() -> None:
    for word in ("ok", "failed", "unknown", "integrity", "verified"):
        assert word in ENVELOPE_VOCABULARY
