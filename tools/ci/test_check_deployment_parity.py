"""The deployment-parity gate must be able to FAIL, or it is decoration.

Every test here drives the gate over a temporary directory rather than the real ``eval_results/``,
so the committed corpus is never a hidden input to a test about the gate's logic.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "tools" / "ci"))
sys.path.insert(0, str(_ROOT / "python" / "warrantor_ml" / "src"))

import check_deployment_parity as gate  # noqa: E402

from warrantor_ml import serving  # noqa: E402


def _document(backend: dict[str, Any]) -> dict[str, Any]:
    return {"result_digest": "sha256:" + "9" * 64, "backend": backend}


def _served(**overrides: Any) -> dict[str, Any]:
    configuration = {**serving.DEPLOYED, **overrides}
    return {
        "kind": "ollama",
        "model": "a-tag-that-names-nothing",
        "quantisation": configuration["quantisation"],
        "seed": configuration["seed"],
        "options": {
            "temperature": configuration["temperature"],
            "top_p": configuration["top_p"],
            "top_k": configuration["top_k"],
            "seed": configuration["seed"],
            "num_predict": configuration["num_predict"],
            "num_ctx": configuration["num_ctx"],
        },
    }


@pytest.fixture
def sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the gate at a temporary corpus and a temporary record."""

    results = tmp_path / "eval_results"
    results.mkdir()
    monkeypatch.setattr(gate, "EVAL_RESULTS", results)
    monkeypatch.setattr(gate, "RECORD", tmp_path / "deployment-parity.json")
    return tmp_path


def _write_record(sandbox: Path, **overrides: Any) -> None:
    record = {
        "scanned": 0,
        "parity": 0,
        "refused": 0,
        "deployed_digest": serving.deployed_digest(),
    }
    record.update(overrides)
    (sandbox / "deployment-parity.json").write_text(json.dumps(record), encoding="utf-8")


def test_the_gate_passes_when_every_count_and_digest_matches_its_record(sandbox: Path) -> None:
    """The allowed control. A gate that cannot pass tells nobody anything."""

    (sandbox / "eval_results" / "matching.json").write_text(
        json.dumps(_document(_served())), encoding="utf-8"
    )
    _write_record(sandbox, scanned=1, parity=1, refused=0)
    assert gate.main() == 0


def test_the_gate_fails_when_the_counts_move_away_from_the_record(sandbox: Path) -> None:
    """A number this gate prints must match the number it was recorded against."""

    (sandbox / "eval_results" / "matching.json").write_text(
        json.dumps(_document(_served())), encoding="utf-8"
    )
    (sandbox / "eval_results" / "divergent.json").write_text(
        json.dumps(_document(_served(quantisation="Q8_0"))), encoding="utf-8"
    )
    _write_record(sandbox, scanned=1, parity=1, refused=0)
    assert gate.main() == 1


def test_the_gate_fails_when_the_deployed_configuration_moves(sandbox: Path) -> None:
    """Moving the record invalidates every published figure until they are re-measured."""

    _write_record(sandbox, deployed_digest="sha256:" + "0" * 64)
    assert gate.main() == 1


def test_the_gate_fails_when_the_rust_constant_disagrees(
    sandbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The divergence that shipped for eight releases, asserted from the CI side."""

    stale = sandbox / "guard.rs"
    stale.write_text("pub const MEASURED_NUM_CTX: u32 = 4096;\n", encoding="utf-8")
    monkeypatch.setattr(gate, "GUARD_RS", stale)
    _write_record(sandbox)
    assert gate.main() == 1


def test_a_document_with_no_backend_block_is_refused_and_says_so(sandbox: Path) -> None:
    classification, reason = gate.classify({"result_digest": "sha256:" + "9" * 64})
    assert classification == "refused"
    assert "no backend block" in reason


def test_a_documents_classification_names_the_field_that_refused_it(sandbox: Path) -> None:
    classification, reason = gate.classify(_document(_served(num_ctx=4096)))
    assert classification == "refused"
    assert "num_ctx" in reason and "4096" in reason


def test_a_baseline_tag_naming_its_quantization_classifies_as_parity(sandbox: Path) -> None:
    """The distinction the census reports: the tag is where the baselines recorded it."""

    backend = _served()
    del backend["quantisation"]
    backend["model"] = "hf.co/mradermacher/Qwen3Guard-Gen-4B-GGUF:Q4_K_M"
    classification, _ = gate.classify(_document(backend))
    assert classification == "parity"

    backend["model"] = "warrantor-guard-0.6b-expguard-weak-exp06-2026-08-22a"
    classification, reason = gate.classify(_document(backend))
    assert classification == "refused"
    assert "quantisation is absent" in reason


def test_the_promotion_and_registration_checks_hold_on_the_real_code(sandbox: Path) -> None:
    """Conditions 2 and 3 read the production modules, so they are not sandboxed.

    They are asserted separately from ``main`` so that a failure names which enforcement point
    broke rather than only that the gate returned 1.
    """

    assert gate._promotion_refusal_is_receipted() is None
    assert gate._registration_refusal_writes_nothing() is None


def test_condition_2s_allowed_control_is_load_bearing(monkeypatch: pytest.MonkeyPatch) -> None:
    """A CI check that only proves refusals would pass over a gate wired shut.

    ``_promotion_refusal_is_receipted`` says exactly that in a comment above its control, and the
    only test of the function asserted that it returns ``None`` on the real code -- so deleting
    the control (``matching = divergent``) passed the whole suite. Nothing fed it a gate that
    refuses everything. This does: ``parity_gate`` is patched to refuse both candidates in the
    shape the divergent one refuses in, and the function must then name the control as the
    failure.
    """

    import warrantor_ml.parity as real_parity

    class _AlwaysRefuses:
        verdict = "insufficient_evidence"
        reasons = (
            "quantisation was recorded as 'Q8_0' and this build serves 'Q4_K_M'",
            "the promoted candidate was evaluated at a configuration this build does not serve",
        )
        decision_digest = "sha256:" + "b" * 64

    monkeypatch.setattr(real_parity, "parity_gate", lambda *_a, **_k: _AlwaysRefuses())
    problem = gate._promotion_refusal_is_receipted()
    assert problem is not None, "a gate that refuses its own control must not report a pass"
    assert "was not promoted" in problem
    assert "insufficient_evidence" in problem
