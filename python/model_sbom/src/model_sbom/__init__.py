"""AumOS model-sbom (S4) — Model SBOM generator with AI extensions.

Generates CycloneDX and SPDX SBOMs with the AI-specific extensions defined in
RFC S4: ``model.architecture``, ``model.parameters``, ``model.training_data``,
``model.base_model``, ``model.evaluations``, ``model.license``. Per
``docs/cross-cutting/13-compliance-frameworks.md``, a GPAI model provider using AumOS can
demonstrate EU AI Act Article 55 compliance with the SBOM this package emits.

See ``docs/rfcs/S4-model-sbom.md``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class SbomFormat(str, Enum):
    """The two supported output formats."""

    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"


@dataclass
class ModelInfo:
    """The AI-specific extensions to a software SBOM. Maps to the ``model.*`` properties."""

    name: str
    architecture: str  # e.g. "transformer-decoder"
    parameters: int  # total parameter count
    training_data: list[str] = field(default_factory=list)  # dataset URIs / digests
    base_model: str | None = None  # parent model URI (for fine-tunes)
    evaluations: list[str] = field(default_factory=list)  # VEB (P8) / AAR references
    license: str | None = None  # SPDX license identifier
    digest: str | None = None  # content digest (sha256:...) of the weights


@dataclass
class Dependency:
    """A software dependency of the model artifact (tokenizer, runtime, library)."""

    name: str
    version: str
    digest: str | None = None


@dataclass
class SbomInput:
    """All inputs needed to generate a Model SBOM."""

    model: ModelInfo
    dependencies: list[Dependency] = field(default_factory=list)
    supplier: str = "did:web:warrantor.dev"  # who built/provided the model
    created_at: datetime | None = None  # defaults to now()


def _utcnow_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_or(input_dt: datetime | None) -> datetime:
    return input_dt if input_dt is not None else datetime.now(UTC)


def to_cyclonedx(sbom: SbomInput) -> dict[str, Any]:
    """Generate a CycloneDX 1.5 SBOM with AI extensions in a ``model`` property on the
    main component."""
    now = _now_or(sbom.created_at)
    model_component: dict[str, Any] = {
        "type": "library",
        "bom-ref": f"model:{sbom.model.name}",
        "name": sbom.model.name,
        "version": str(sbom.model.parameters),
        "supplier": {"name": sbom.supplier},
        "purl": f"pkg:generic/{sbom.model.name}@{sbom.model.parameters}",
        "properties": [
            {"name": "model.architecture", "value": sbom.model.architecture},
            {"name": "model.parameters", "value": str(sbom.model.parameters)},
        ],
    }
    if sbom.model.training_data:
        model_component["properties"].append(
            {
                "name": "model.training_data",
                "value": ",".join(sbom.model.training_data),
            }
        )
    if sbom.model.base_model:
        model_component["properties"].append(
            {"name": "model.base_model", "value": sbom.model.base_model}
        )
    if sbom.model.evaluations:
        model_component["properties"].append(
            {
                "name": "model.evaluations",
                "value": ",".join(sbom.model.evaluations),
            }
        )
    if sbom.model.license:
        model_component["licenses"] = [{"license": {"id": sbom.model.license}}]
    if sbom.model.digest:
        model_component["hashes"] = [{"alg": "SHA-256", "content": sbom.model.digest}]

    dep_components = [
        {
            "type": "library",
            "bom-ref": f"dep:{d.name}:{d.version}",
            "name": d.name,
            "version": d.version,
            "purl": f"pkg:pypi/{d.name}@{d.version}",
            **({"hashes": [{"alg": "SHA-256", "content": d.digest}]} if d.digest else {}),
        }
        for d in sbom.dependencies
    ]

    dependencies = [
        {
            "ref": f"model:{sbom.model.name}",
            "dependsOn": [f"dep:{d.name}:{d.version}" for d in sbom.dependencies],
        }
    ]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [{"vendor": "AumOS", "name": "model-sbom", "version": "1.0.0"}],
            "supplier": {"name": sbom.supplier},
        },
        "components": [model_component, *dep_components],
        "dependencies": dependencies,
    }


def to_spdx(sbom: SbomInput) -> dict[str, Any]:
    """Generate an SPDX 3.0 SBOM with AI extensions per the SPDX AI-BOM working draft."""
    now = _now_or(sbom.created_at)
    document_id = f"spdx-doc-{uuid.uuid4()}"
    packages = []

    model_pkg_spdxid = f"SPDXRef-Package-model-{sbom.model.name.replace('.', '-')}"
    model_pkg: dict[str, Any] = {
        "name": sbom.model.name,
        "SPDXID": model_pkg_spdxid,
        "versionInfo": str(sbom.model.parameters),
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "supplier": f"Organization: {sbom.supplier}",
        "copyrightText": "NOASSERTION",
        # AI extension fields per SPDX AI-BOM draft.
        "builtDate": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "annotations": [
            {
                "annotationType": "REVIEW",
                "annotator": sbom.supplier,
                "annotationDate": _utcnow_iso(),
                "comment": f"model.architecture={sbom.model.architecture}",
            },
            {
                "annotationType": "REVIEW",
                "annotator": sbom.supplier,
                "annotationDate": _utcnow_iso(),
                "comment": f"model.parameters={sbom.model.parameters}",
            },
        ],
    }
    if sbom.model.training_data:
        model_pkg["annotations"].append(
            {
                "annotationType": "REVIEW",
                "annotator": sbom.supplier,
                "annotationDate": _utcnow_iso(),
                "comment": f"model.training_data={','.join(sbom.model.training_data)}",
            }
        )
    if sbom.model.base_model:
        model_pkg["annotations"].append(
            {
                "annotationType": "REVIEW",
                "annotator": sbom.supplier,
                "annotationDate": _utcnow_iso(),
                "comment": f"model.base_model={sbom.model.base_model}",
            }
        )
    if sbom.model.license:
        model_pkg["licenseConcluded"] = sbom.model.license
        model_pkg["licenseDeclared"] = sbom.model.license
    if sbom.model.digest:
        model_pkg["externalRefs"] = [
            {
                "referenceCategory": "SECURITY",
                "referenceType": "cpe23Type",
                "referenceLocator": f"sha256:{sbom.model.digest}",
            }
        ]
    packages.append(model_pkg)

    for d in sbom.dependencies:
        dep_id = f"SPDXRef-Package-dep-{d.name.replace('.', '-')}"
        pkg = {
            "name": d.name,
            "SPDXID": dep_id,
            "versionInfo": d.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "supplier": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        if d.digest:
            pkg["externalRefs"] = [
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": f"sha256:{d.digest}",
                }
            ]
        packages.append(pkg)

    relationships = [
        {
            "spdxElementId": model_pkg_spdxid,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": f"SPDXRef-Package-dep-{d.name.replace('.', '-')}",
        }
        for d in sbom.dependencies
    ]

    return {
        "spdxVersion": "SPDX-3.0",
        "SPDXID": document_id,
        "name": sbom.model.name,
        "dataLicense": "CC0-1.0",
        "documentNamespace": f"https://warrantor.dev/spdx/{uuid.uuid4()}",
        "creationInfo": {
            "created": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: warrantor-model-sbom-1.0.0", f"Organization: {sbom.supplier}"],
        },
        "packages": packages,
        "relationships": relationships,
    }


def generate(sbom: SbomInput, fmt: SbomFormat | str) -> dict[str, Any]:
    """Generate an SBOM in the requested format.

    Args:
        sbom: the model + dependencies + supplier.
        fmt: "cyclonedx" or "spdx" (case-insensitive).

    Returns:
        The SBOM as a JSON-serializable dict.
    """
    fmt_enum = SbomFormat(fmt.lower()) if isinstance(fmt, str) else fmt
    if fmt_enum is SbomFormat.CYCLONEDX:
        return to_cyclonedx(sbom)
    if fmt_enum is SbomFormat.SPDX:
        return to_spdx(sbom)
    raise ValueError(f"unknown SBOM format: {fmt}")


__all__ = [
    "Dependency",
    "ModelInfo",
    "SbomFormat",
    "SbomInput",
    "generate",
    "to_cyclonedx",
    "to_spdx",
]
