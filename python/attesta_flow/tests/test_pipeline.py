"""Tests for attesta_flow pipeline + attestation."""

from __future__ import annotations

import json

from attesta_flow import CloudProvider, MockHardwareAttestor, Pipeline, Stage


def test_pipeline_runs_all_stages() -> None:
    p = Pipeline(CloudProvider.MOCK)
    att = p.run_batch(
        model_digest="sha256:abc",
        inputs=[{"prompt": "hi"}],
        infer_fn=lambda batch: [{"text": "hello"} for _ in batch],
    )
    assert Stage.ATTEST_HARDWARE in att.stages_completed
    assert Stage.RUN_INFERENCE in att.stages_completed
    assert Stage.EMIT_ATTESTATION in att.stages_completed
    assert att.gpu_model == "mock-H100"
    assert att.model_digest == "sha256:abc"
    assert att.input_batch_digest != att.output_batch_digest


def test_attestation_to_dict_round_trips() -> None:
    p = Pipeline(CloudProvider.AZURE)
    att = p.run_batch("sha256:m", [1, 2], lambda b: [x * 2 for x in b])
    d = att.to_dict()
    assert d["cloud_provider"] == "azure"
    back = PipelineAttestation_from_dict(d)
    assert back.batch_id == att.batch_id


def PipelineAttestation_from_dict(d: dict) -> object:
    """Helper to round-trip — exercises the to_dict shape."""
    from attesta_flow import PipelineAttestation

    return PipelineAttestation(
        batch_id=d["batch_id"],
        cloud_provider=CloudProvider(d["cloud_provider"]),
        gpu_model=d["gpu_model"],
        model_digest=d["model_digest"],
        input_batch_digest=d["input_batch_digest"],
        output_batch_digest=d["output_batch_digest"],
        stages_completed=[Stage(s) for s in d["stages_completed"]],
        emitted_at=d["emitted_at"],
        pipeline_verifying_key_hex=d["pipeline_verifying_key_hex"],
    )


def test_mock_attestor_returns_pair() -> None:
    gpu, attestation = MockHardwareAttestor().attest()
    assert gpu == "mock-H100"
    assert isinstance(attestation, str)


def test_input_output_digests_differ_on_different_inputs() -> None:
    p = Pipeline(CloudProvider.MOCK)
    a1 = p.run_batch("sha256:m", [{"x": 1}], lambda b: b)
    a2 = p.run_batch("sha256:m", [{"x": 2}], lambda b: b)
    assert a1.input_batch_digest != a2.input_batch_digest


def test_attestation_is_json_serializable() -> None:
    p = Pipeline(CloudProvider.GCP)
    att = p.run_batch("sha256:m", ["q"], lambda b: ["a"])
    # Must be JSON-serializable (this is how it gets emitted over the wire).
    s = json.dumps(att.to_dict())
    assert "batch_id" in s
