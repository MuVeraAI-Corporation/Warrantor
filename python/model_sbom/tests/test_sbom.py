"""Tests for model_sbom: format generation, AI extensions, CLI."""

from __future__ import annotations

import json

import pytest

from model_sbom import Dependency, ModelInfo, SbomFormat, SbomInput, generate, to_cyclonedx, to_spdx
from model_sbom.cli import main


def sample_input() -> SbomInput:
    return SbomInput(
        model=ModelInfo(
            name="aumos-7b",
            architecture="transformer-decoder",
            parameters=7_000_000_000,
            training_data=["dataset://pile", "dataset://c4"],
            base_model="model://llama-2-7b",
            evaluations=["veb://eval-001"],
            license="Apache-2.0",
            digest="abc123",
        ),
        dependencies=[Dependency(name="transformers", version="4.40.0"), Dependency(name="tokenizers", version="0.19")],
    )


def test_cyclonedx_has_ai_extensions() -> None:
    sbom = to_cyclonedx(sample_input())
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    model = sbom["components"][0]
    props = {p["name"]: p["value"] for p in model["properties"]}
    assert props["model.architecture"] == "transformer-decoder"
    assert props["model.parameters"] == "7000000000"
    assert "dataset://pile" in props["model.training_data"]
    assert props["model.base_model"] == "model://llama-2-7b"
    assert "veb://eval-001" in props["model.evaluations"]
    assert model["licenses"] == [{"license": {"id": "Apache-2.0"}}]


def test_spdx_has_ai_annotations() -> None:
    sbom = to_spdx(sample_input())
    assert sbom["spdxVersion"] == "SPDX-3.0"
    model_pkg = sbom["packages"][0]
    comments = " ".join(a["comment"] for a in model_pkg["annotations"])
    assert "model.architecture=transformer-decoder" in comments
    assert "model.parameters=7000000000" in comments
    assert "model.base_model=model://llama-2-7b" in comments
    assert model_pkg["licenseConcluded"] == "Apache-2.0"


def test_dependencies_link_to_model() -> None:
    sbom = to_cyclonedx(sample_input())
    # First component is the model; the rest are deps.
    assert len(sbom["components"]) == 3  # model + 2 deps
    deps = sbom["dependencies"][0]["dependsOn"]
    assert "dep:transformers:4.40.0" in deps
    assert "dep:tokenizers:0.19" in deps


def test_generate_accepts_string_format() -> None:
    cd = generate(sample_input(), "cyclonedx")
    spdx = generate(sample_input(), "spdx")
    assert cd["bomFormat"] == "CycloneDX"
    assert spdx["spdxVersion"].startswith("SPDX")


def test_generate_rejects_unknown_format() -> None:
    # "csv" is not a valid SbomFormat, so the Enum constructor (or our explicit check) raises.
    with pytest.raises(ValueError):
        generate(sample_input(), "csv")


def test_cli_emits_cyclonedx_json(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main([
        "--name", "test-model",
        "--architecture", "mlp",
        "--parameters", "1000",
        "--training-data", "dataset://x",
        "--license", "MIT",
        "--dep", "torch@2.3.0",
        "--format", "cyclonedx",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    sbom = json.loads(out)
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["components"][0]["name"] == "test-model"


def test_cli_rejects_bad_dep_format(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main([
        "--name", "x", "--architecture", "x", "--parameters", "1",
        "--dep", "no-version-suffix",
    ])
    assert rc == 2
    err = capsys.readouterr().err
    assert "NAME@VERSION" in err


def test_optional_fields_default_to_empty() -> None:
    sbom = to_cyclonedx(SbomInput(model=ModelInfo(name="m", architecture="a", parameters=1)))
    props = {p["name"]: p["value"] for p in sbom["components"][0]["properties"]}
    # Only the required architecture + parameters are present.
    assert set(props) == {"model.architecture", "model.parameters"}
    assert "licenses" not in sbom["components"][0]
