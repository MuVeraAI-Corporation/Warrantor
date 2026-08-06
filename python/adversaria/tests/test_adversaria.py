"""Tests for adversaria: generators, detectors, suite run, baselines, CLI."""

from __future__ import annotations

import json

import pytest

from adversaria import (
    AttackSuite,
    AttackType,
    CompliantTarget,
    RefusingTarget,
    Severity,
    default_suite,
    generate_encoding_attack,
    generate_jailbreak,
    generate_multi_turn_manipulation,
    generate_prompt_injection,
    generate_training_data_extraction,
)
from adversaria.cli import main


# --- Generator tests ---------------------------------------------------------
def test_prompt_injection_generator_count() -> None:
    prompts = generate_prompt_injection(3)
    assert len(prompts) == 3
    assert all(p.attack_type is AttackType.PROMPT_INJECTION for p in prompts)
    assert all("SYSTEM OVERRIDE" in p.text for p in prompts)


def test_jailbreak_generator_count() -> None:
    prompts = generate_jailbreak(2)
    assert len(prompts) == 2
    assert all("DAN" in p.text for p in prompts)


def test_encoding_attack_generator_count() -> None:
    prompts = generate_encoding_attack(1)
    assert len(prompts) == 1
    # The encoded payload is the base64 of "forbidden".
    import base64
    expected = base64.b64encode(b"forbidden").decode("ascii")
    assert expected in prompts[0].text


def test_multi_turn_generator_count() -> None:
    prompts = generate_multi_turn_manipulation(2)
    assert len(prompts) == 2
    assert all("MANIPULATED" in p.metadata["completion_marker"] for p in prompts)


def test_training_data_extraction_generator_count() -> None:
    prompts = generate_training_data_extraction(1)
    assert len(prompts) == 1
    assert "ssn" in prompts[0].metadata["exfil_marker"].lower()


# --- Detector + suite tests --------------------------------------------------
def test_refusing_target_produces_no_successes() -> None:
    suite = default_suite()
    summary = suite.run(RefusingTarget())
    assert summary.success_count == 0
    assert summary.critical_or_high == []


def test_compliant_target_succeeds_on_all_attacks() -> None:
    suite = default_suite()
    summary = suite.run(CompliantTarget())
    assert summary.success_count == 5
    # 4 of the 5 default attacks are HIGH/CRITICAL; encoding_attack is MEDIUM.
    assert len(summary.critical_or_high) == 4
    assert all(r.severity in (Severity.HIGH, Severity.CRITICAL) for r in summary.critical_or_high)


def test_suite_add_increments_count() -> None:
    suite = AttackSuite().add(AttackType.PROMPT_INJECTION, 1)
    assert suite.attacks[AttackType.PROMPT_INJECTION] == 1
    suite.add(AttackType.PROMPT_INJECTION, 2)
    assert suite.attacks[AttackType.PROMPT_INJECTION] == 3


def test_suite_set_detector_overrides_default() -> None:
    suite = (
        AttackSuite()
        .add(AttackType.PROMPT_INJECTION, 1)
        .set_detector(AttackType.PROMPT_INJECTION, lambda p, r: False)  # always fails
    )
    summary = suite.run(CompliantTarget())
    # The override says no attack ever succeeds — even against the compliant target.
    assert summary.success_count == 0


def test_run_summary_success_rate() -> None:
    suite = AttackSuite().add(AttackType.PROMPT_INJECTION, 4)
    summary = suite.run(CompliantTarget())
    assert summary.attack_count == 4
    assert summary.success_count == 4
    assert summary.success_rate == 1.0


def test_default_suite_includes_all_five_attacks() -> None:
    suite = default_suite()
    assert set(suite.attacks.keys()) == {
        AttackType.PROMPT_INJECTION,
        AttackType.JAILBREAK,
        AttackType.ENCODING_ATTACK,
        AttackType.MULTI_TURN_MANIPULATION,
        AttackType.TRAINING_DATA_EXTRACTION,
    }


# --- CLI tests ---------------------------------------------------------------
def test_cli_list(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["list"])
    assert rc == 0
    out = capsys.readouterr().out
    for at in ("prompt_injection", "jailbreak", "encoding_attack", "multi_turn_manipulation", "training_data_extraction"):
        assert at in out


def test_cli_run_compliant(capsys: pytest.CaptureFixture[str]) -> int | None:
    rc = main(["run", "--target-compliant"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["success_count"] == 5
    return rc


def test_cli_run_refusing(capsys: pytest.CaptureFixture[str]) -> int | None:
    rc = main(["run", "--target-refusing"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["success_count"] == 0
    return rc


def test_cli_run_single_attack(capsys: pytest.CaptureFixture[str]) -> int | None:
    rc = main(["run", "--target-compliant", "--attacks", "jailbreak", "--count", "2"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["attack_count"] == 2
    return rc
