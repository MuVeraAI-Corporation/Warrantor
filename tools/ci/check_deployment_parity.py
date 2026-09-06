#!/usr/bin/env python3
"""Deployment-configuration parity gate (Task 12.3, L9-03 / L9-08).

One command decides pass or fail, and it prints one line naming each thing it checked. The four
conditions, in the order they are reported:

1. Every result document under ``eval_results/`` is classified ``parity`` or ``refused``, with the
   reason named, and the counts equal the recorded expectation in ``deployment-parity.json``. A
   rendered number that is not gated against a record is decoration; a drift fails the build.
2. A promotion attempt whose recorded configuration differs from ``serving.DEPLOYED`` in
   quantization is refused, and the refusal is RECEIPTED -- the decision document records the
   verdict, the reason and a digest. It is not silently dropped: an unreceipted refusal leaves no
   record that anyone was told, and the 2026-08-22 sweep is auditable today precisely because its
   four refusals were written down. Measured twice, because a verdict and an exit code are two
   different facts: in process through ``parity_gate``, and through the documented CLI
   ``warrantor-ml-parity``, which must exit 3 and leave the receipt on disk. Each leg carries its
   own promote control.
3. A registration attempt with no ``promote`` parity receipt raises ``RegistrationError`` and
   writes neither a registration document nor a Rust adapter.
4. ``serving.deployed_digest()`` equals the digest recorded in ``deployment-parity.json``, and
   ``rust/warrant/src/guard.rs``'s ``MEASURED_NUM_CTX`` equals ``DEPLOYED["num_ctx"]``.

WHAT THIS GATE DOES NOT DO. It compares two RECORDS: a configuration an evaluator wrote into a
result document, and a configuration this repository declares to be the deployed one. It observes
no running process. A serving process started outside the generated adapter -- a different Ollama
client, a ``num_ctx`` override on the request, a re-quantized GGUF pushed under an unchanged tag --
is neither observed nor refused. There is no namespace, seccomp or firewall enforcement anywhere in
this repository and none is added here.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "python" / "warrantor_ml" / "src"))

from warrantor_ml import deploy_model, serving  # noqa: E402
from warrantor_ml.model_card import example_card  # noqa: E402

RECORD = Path(__file__).resolve().parent / "deployment-parity.json"
EVAL_RESULTS = _ROOT / "eval_results"
GUARD_RS = _ROOT / "rust" / "warrant" / "src" / "guard.rs"


def classify(document: dict[str, Any]) -> tuple[str, str]:
    """``(classification, reason)`` for one result document."""

    backend = document.get("backend")
    if not isinstance(backend, dict):
        return "refused", "the document carries no backend block at all"
    recorded = serving.recorded_serving_configuration(backend)
    problems = serving.configuration_mismatch(recorded)
    if not problems:
        return "parity", "records the deployed configuration on every compared key"
    return "refused", problems[0]


def _scan() -> tuple[int, int, int, list[str]]:
    """Classify every result document. Returns ``(scanned, parity, refused, lines)``."""

    lines: list[str] = []
    parity = refused = 0
    paths = sorted(EVAL_RESULTS.glob("*.json"))
    for path in paths:
        classification, reason = classify(json.loads(path.read_text(encoding="utf-8")))
        if classification == "parity":
            parity += 1
        else:
            refused += 1
        lines.append(f"  {classification:8s} {path.name}: {reason}")
    return len(paths), parity, refused, lines


def _promotion_refusal_is_receipted() -> str | None:
    """Condition 2. Returns a failure message, or ``None`` when the check passes."""

    from warrantor_ml.leakage import leakage_report
    from warrantor_ml.parity import CandidateResult, corpus_digest_of, parity_gate

    def candidate(quantisation: str) -> CandidateResult:
        return CandidateResult(
            candidate_id="guard-4b-weak-category",
            baseline_id="wildguardtest-qwen3guard-gen-4b",
            lane="local-rtx5080",
            precision="gguf-q4_k_m",
            result_digest="sha256:" + "1" * 64,
            eval_set_digest="sha256:" + "2" * 64,
            eval_corpus_digest=corpus_digest_of("allenai/wildguardmix:test/wildguard_test.parquet"),
            manifest_digest="sha256:" + "3" * 64,
            slices={
                "overall": {
                    "recall": 700 / 753,
                    "confusion_matrix": {
                        "true_positive": 700,
                        "false_negative": 53,
                        "false_positive": 50,
                        "true_negative": 896,
                    },
                }
            },
            # Every measured floor the 4B WildGuard baseline declares, comfortably cleared. A
            # floor the candidate does not report is `insufficient_evidence` on its own, so a
            # control that omitted them would refuse for the wrong reason and this check would
            # pass over a configuration gate that never ran.
            per_category_recall={
                "social stereotypes and unfair discrimination": 0.90,
                "fraud assisting illegal activities": 0.90,
                "others": 0.90,
            },
            backend_error_count=0,
            scored_samples=1699,
            backend={
                "kind": "ollama",
                "model": "a-tag-that-names-nothing",
                "quantisation": quantisation,
                "seed": 0,
                "options": {
                    "temperature": 0.0,
                    "top_p": 1.0,
                    "top_k": 1,
                    "seed": 0,
                    "num_predict": 64,
                    "num_ctx": 8192,
                },
            },
        )

    clean = leakage_report([{"prompt": "training row"}], [{"prompt": "held out row"}])
    divergent = parity_gate(candidate("Q8_0"), "overall", clean)
    if divergent.verdict == "promote":
        return "a candidate at a quantization this build does not serve was PROMOTED"
    if not any("Q8_0" in reason and "Q4_K_M" in reason for reason in divergent.reasons):
        return "the refusal does not name the field and both values"
    if not divergent.decision_digest.startswith("sha256:"):
        return "the refusal carries no decision digest, so it cannot be re-audited"
    # The allowed control. A gate that refuses everything is not a gate, and a CI check that only
    # proves refusals is a CI check that would pass over a gate wired shut.
    matching = parity_gate(candidate(serving.QUANTIZATION), "overall", clean)
    if matching.verdict != "promote":
        return (
            "a candidate recorded AT the deployed configuration was not promoted "
            f"({matching.verdict}): {matching.reasons}"
        )
    return _promotion_refusal_exits_nonzero()


def _wildguard_document(directory: Path, quantisation: str) -> Path:
    """A WildGuardTest result document at ``quantisation``, built by the real producers.

    The ``eval_set`` block comes from ``benchmark_wildguard.build_eval_set_descriptor`` and the
    ``backend`` block from ``OllamaGuardBackend.descriptor``, so this fixture records what the
    evaluator records. A hand-written block would be a second shape, which is the defect this
    whole gate exists to catch.
    """

    from warrantor_ml.benchmark_wildguard import build_eval_set_descriptor
    from warrantor_ml.evaluate import DEFAULT_OLLAMA_MODEL, OllamaGuardBackend

    split = directory / "wildguard_test.parquet"
    split.write_bytes(b"a stand-in for the split; it only has to have a digest")
    document = {
        "result_digest": "sha256:" + "9" * 64,
        "eval_set": build_eval_set_descriptor(split, range(1725), range(1699), []),
        "backend_errors": {"count": 0},
        "backend": OllamaGuardBackend(
            model=DEFAULT_OLLAMA_MODEL, quantisation=quantisation
        ).descriptor(),
        "wildguard_breakdowns": {
            "overall": {
                "recall": 700 / 753,
                "confusion_matrix": {
                    "true_positive": 700,
                    "false_negative": 53,
                    "false_positive": 50,
                    "true_negative": 896,
                },
            },
            "by_subcategory": {
                "social_stereotypes_and_unfair_discrimination": {"recall": 0.90},
                "fraud_assisting_illegal_activities": {"recall": 0.90},
                "others": {"recall": 0.90},
            },
        },
    }
    path = directory / f"result-{quantisation}.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _promotion_refusal_exits_nonzero() -> str | None:
    """The plan's exit criterion 2, measured through the documented CLI rather than in process.

    The checks above call ``parity_gate`` directly and read its verdict, which measures the
    decision but not the two things the plan's criterion names: a NON-ZERO EXIT and what the
    refusal leaves on disk. Those live in ``programme.parity_main``, so this drives it.

    On the second clause this branch deviates from the plan deliberately and says so in the
    evidence file (section 6, item 3): the plan required a refused promotion to write NO decision
    document, and a refusal that writes nothing is an unreceipted refusal. The refusal here IS
    receipted -- verdict, naming reasons and a digest -- and what a refusal must not produce is a
    registration or an adapter, which condition 3 below measures. So this check asserts the exit
    code the plan requires and the receipt the item requires, and the deviation is visible in the
    assertion rather than only in prose.
    """

    from warrantor_ml.programme import parity_main

    insufficient_evidence = 3
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        training = root / "train.jsonl"
        training.write_text(json.dumps({"prompt": "a training row"}) + "\n", encoding="utf-8")
        evaluation = root / "eval.jsonl"
        evaluation.write_text(json.dumps({"prompt": "a held out row"}) + "\n", encoding="utf-8")

        def argv(result: Path, decision: Path) -> list[str]:
            return [
                "--result",
                str(result),
                "--recipe",
                "guard-4b-weak-category",
                "--lane",
                "local-rtx5080",
                "--manifest-digest",
                "sha256:" + "3" * 64,
                "--breakdown-key",
                "wildguard_breakdowns",
                "--training-corpus",
                str(training),
                "--eval-corpus",
                str(evaluation),
                "--out",
                str(decision),
            ]

        # `parity_main` prints the whole decision document, twice over. The receipt is read from
        # the file it wrote, not from the log, so its stdout goes to a buffer -- four check lines
        # under three hundred lines of JSON is a gate nobody reads.
        printed = io.StringIO()
        refused_decision = root / "refused-decision.json"
        with contextlib.redirect_stdout(printed):
            exit_code = parity_main(argv(_wildguard_document(root, "Q8_0"), refused_decision))
        if exit_code == 0:
            return "warrantor-ml-parity exited 0 for a candidate at a quantization we do not serve"
        if exit_code != insufficient_evidence:
            return (
                f"warrantor-ml-parity exited {exit_code} for a configuration mismatch; the "
                "documented code is 3 (insufficient_evidence), and 1 means the candidate was "
                "rejected on its measurements, which a CI job would retry differently"
            )
        if not refused_decision.exists():
            return "the refusal wrote no decision document, so it is unreceipted"
        receipt = json.loads(refused_decision.read_text(encoding="utf-8"))
        if receipt.get("verdict") != "insufficient_evidence":
            return f"the refusal receipt records verdict {receipt.get('verdict')!r}"
        if not str(receipt.get("decision_digest", "")).startswith("sha256:"):
            return "the refusal receipt carries no decision digest, so it cannot be re-audited"
        if not any("Q8_0" in reason for reason in receipt.get("reasons", ())):
            return "the refusal receipt does not name the configuration it refused"

        # The allowed control, through the same CLI: exit 0 at the deployed configuration.
        promoted_decision = root / "promoted-decision.json"
        with contextlib.redirect_stdout(printed):
            promoted = parity_main(
                argv(_wildguard_document(root, serving.QUANTIZATION), promoted_decision)
            )
        if promoted != 0:
            return (
                f"warrantor-ml-parity exited {promoted} for a candidate recorded AT the deployed "
                "configuration; a gate that refuses everything measures nothing"
            )
    return None


def _registration_refusal_writes_nothing() -> str | None:
    """Condition 3. Returns a failure message, or ``None`` when the check passes."""

    card = json.loads(json.dumps(example_card()))
    card["identity"]["weights_digest"] = "sha256:" + "ab" * 32
    card["base_model"]["revision"] = "c" * 40
    card["evaluation"].update(
        {
            "recall": 0.8397,
            "precision": 0.7412,
            "f1": 0.7877,
            "false_negative_rate": 0.1603,
            "sample_count": 1725,
            "per_category_recall": {"violence": 0.91, "jailbreak": 0.77},
        }
    )
    card["bias_audit"]["score"] = 0.03
    card["carbon"]["training"].update(
        {"energy_wh": 1450.0, "co2_grams": 620.0, "region": "us-central"}
    )
    card["carbon"]["inference"]["model_efficiency_wh_per_1k"] = 0.42

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        card_path = root / "card.json"
        card_path.write_text(json.dumps(card), encoding="utf-8")
        receipt_path = root / "receipt.json"
        receipt_path.write_text(json.dumps({"verdict": "insufficient_evidence"}), encoding="utf-8")
        registration_path = root / "registration.json"
        adapter_path = root / "adapter.rs"
        exit_code = deploy_model.main(
            [
                "--card",
                str(card_path),
                "--parity-receipt",
                str(receipt_path),
                "--out",
                str(registration_path),
                "--emit-adapter",
                str(adapter_path),
            ]
        )
        if exit_code == 0:
            return "a registration with an insufficient_evidence receipt SUCCEEDED"
        if registration_path.exists():
            return "a refused registration left a registration document on disk"
        if adapter_path.exists():
            return "a refused registration left a Rust adapter on disk"

        # The allowed control, in the same check.
        receipt_path.write_text(
            json.dumps(
                {
                    "verdict": "promote",
                    "decision_digest": "sha256:" + "a" * 64,
                    "recorded_serving_configuration": dict(serving.DEPLOYED),
                }
            ),
            encoding="utf-8",
        )
        if (
            deploy_model.main(
                [
                    "--card",
                    str(card_path),
                    "--parity-receipt",
                    str(receipt_path),
                    "--out",
                    str(registration_path),
                    "--emit-adapter",
                    str(adapter_path),
                ]
            )
            != 0
        ):
            return "a registration with a valid promote receipt was refused"
        if not registration_path.exists() or not adapter_path.exists():
            return "an accepted registration wrote nothing"
        adapter = adapter_path.read_text(encoding="utf-8")
        if f"SERVED_NUM_CTX: u32 = {serving.NUM_CTX};" not in adapter:
            return "the generated adapter does not carry the served context length"
        if "this adapter cannot enforce them" not in adapter:
            return (
                "the generated adapter does not say that the constants are declarative; the "
                "comment is the mechanism keeping this a Tier C observed claim"
            )
    return None


def _measured_num_ctx() -> str | None:
    """``MEASURED_NUM_CTX``'s literal from the Rust source, read rather than imported."""

    for line in GUARD_RS.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("pub const MEASURED_NUM_CTX"):
            _, _, value = stripped.partition("=")
            return value.strip().rstrip(";")
    return None


def main() -> int:
    """Run the four checks. Returns 0 only when all four hold."""

    recorded = json.loads(RECORD.read_text(encoding="utf-8"))
    scanned, parity, refused, lines = _scan()

    digest = serving.deployed_digest()
    num_ctx_literal = _measured_num_ctx()
    reason = next(
        (entry.split(": ", 1)[1] for entry in lines if entry.strip().startswith("refused")),
        "no refusals",
    )
    print(
        f"deployment parity: {scanned} documents scanned; {parity} parity, {refused} refused "
        f"({reason.split('(')[0].strip().rstrip('.')}); deployed digest {digest} "
        f"{'matches' if digest == recorded['deployed_digest'] else 'DOES NOT MATCH'} record; "
        f"MEASURED_NUM_CTX {num_ctx_literal} "
        f"{'==' if num_ctx_literal == str(serving.NUM_CTX) else '!='} DEPLOYED num_ctx "
        f"{serving.NUM_CTX}"
    )
    for line in lines:
        print(line)

    failed = False

    if (scanned, parity, refused) != (
        recorded["scanned"],
        recorded["parity"],
        recorded["refused"],
    ):
        print(
            f"deployment parity: counts moved -- scanned {scanned} parity {parity} refused "
            f"{refused}, record says {recorded['scanned']}/{recorded['parity']}/"
            f"{recorded['refused']}. A number this gate prints must match the number it was "
            "recorded against, or the printed one is decoration. Update the record in the same "
            "commit that earns it."
        )
        failed = True
    else:
        print(f"  [1/4] ok: counts match the record ({scanned}/{parity}/{refused})")

    if (problem := _promotion_refusal_is_receipted()) is not None:
        print(f"deployment parity: the promotion refusal did not hold -- {problem}")
        failed = True
    else:
        print(
            "  [2/4] ok: a divergent quantization is refused and receipted, in process and "
            "through warrantor-ml-parity (exit 3, receipt on disk); both controls promote"
        )

    if (problem := _registration_refusal_writes_nothing()) is not None:
        print(f"deployment parity: the registration refusal did not hold -- {problem}")
        failed = True
    else:
        print(
            "  [3/4] ok: registration without a promote receipt writes no document and no "
            "adapter; the promote control writes both"
        )

    if digest != recorded["deployed_digest"]:
        print(
            "deployment parity: the deployed configuration changed and every published figure was "
            f"measured at the old one. Record says {recorded['deployed_digest']}, this build "
            f"computes {digest}. Re-measure, or do not move it."
        )
        failed = True
    if num_ctx_literal != str(serving.NUM_CTX):
        print(
            f"deployment parity: MEASURED_NUM_CTX is {num_ctx_literal} and DEPLOYED['num_ctx'] is "
            f"{serving.NUM_CTX}. This crate shipped 4096 for eight releases while every published "
            "figure was measured at 8192; that is the divergence this line exists to make loud."
        )
        failed = True
    if digest == recorded["deployed_digest"] and num_ctx_literal == str(serving.NUM_CTX):
        print("  [4/4] ok: the deployed digest matches its record and the Rust constant agrees")

    if failed:
        return 1
    print(
        "deployment parity: PASS. This compares RECORDS, not processes -- it does not observe a "
        "serving process, and it cannot detect a per-request context override, a re-quantized "
        "GGUF under an unchanged tag, or a scanner reached by any path other than the generated "
        "adapter."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
