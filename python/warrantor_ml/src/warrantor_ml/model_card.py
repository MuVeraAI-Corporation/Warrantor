"""Signed AIBOM generation for a fine-tuned guard model.

A model card in this pipeline is not prose with a metrics table stapled on. It is the only
place several load-bearing facts can live at all, because the structures downstream cannot
hold them:

* ``model_sbom.ModelInfo.license`` is a **single** SPDX string, emitted as both
  ``licenseConcluded`` and ``licenseDeclared``. Base-model licence, per-dataset licence and
  derived-artifact licence are three genuinely different things for a Qwen3Guard fine-tune on
  WildGuardMix plus ExpGuardMix, and they all collapse into that one slot. So the AIBOM carries
  them separately and the SBOM is emitted as a subordinate document.
* ``model_sbom.ModelInfo.training_data`` is a bare ``list[str]`` with no licence, gating or
  redistribution slot. The dataset licence table lives here.
* ``responsible_ai::CarbonFootprint`` is explicitly *per-action inference* energy. There is no
  field anywhere in the substrate for the energy of the training run. Training carbon is a card
  field with no receipt counterpart, and that gap is stated rather than papered over.
* ``ContentScanner::scan`` returns ``ScannerVerdict``, not ``Result``. A scanner that OOMs or
  times out has no way to signal unavailability, so the failure contract exists **only** here.
* ``ModerationConfig.deny_threshold`` cannot raise recall (rule 3 in ``decide()`` requires
  ``is_harmful``, which rule 2 has already denied on). Recall is a property of the model's own
  internal threshold, so the operating threshold is a versioned card field and changing it is a
  model change requiring a new digest.

The module's central promise: **it refuses to emit a card with a missing required field.**
Emitting a card with blanks would produce a document that looks like assurance and is not, and
a blank field in an accountability artifact is worse than a loud failure.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ._canonical import canonical_json, is_wellformed_digest

__all__ = [
    "AIBOM_VERSION",
    "PLACEHOLDER_EXPLANATION",
    "PLATFORM_COMPONENTS",
    "REQUIRED_FIELDS",
    "SELF_CHANGE_PROTECTED_PREFIXES",
    "FieldRule",
    "IncompleteModelCardError",
    "build_aibom",
    "example_card",
    "main",
    "sign_aibom",
    "validate_card",
    "verify_aibom",
]

AIBOM_VERSION = "warrantor-aibom/1.0"

#: Rejected verbatim by ``rust/responsible-ai``'s ``validate_ra_block`` as a MISSING
#: explanation, so a card must never ship it as the deny-path template.
PLACEHOLDER_EXPLANATION = "No explanation provided"

#: Mirrors ``rust/self-governance``'s ``SELF_CHANGE_PROTECTED_PREFIXES`` (I-11).
SELF_CHANGE_PROTECTED_PREFIXES: tuple[str, ...] = (
    "spiffe://warrantor.io/trust-core",
    "spiffe://warrantor.io/authority",
    "spiffe://warrantor.io/policy",
    "spiffe://warrantor.io/self-governance",
    "spiffe://warrantor.io/flight-recorder",
    "spiffe://warrantor.io/evidence",
    "spiffe://warrantor.io/kms",
    "spiffe://warrantor.io/mcp-gateway",
)

#: ``PlatformComponent`` is a CLOSED four-variant enum on the Rust side. There is no variant
#: for a guard/scanner model, and adding one moves a fixed-size array type, the serde wire
#: vocabulary and two tests together. Until that reviewed change lands, a guard model registers
#: as a sub-agent of an existing component and the card says so explicitly.
PLATFORM_COMPONENTS: tuple[str, ...] = (
    "nl_console",
    "policy_compiler",
    "risk_scorer",
    "audit_fleet",
)

_FLOATING_REVISIONS = frozenset({"", "main", "master", "head", "latest", "default"})
_HEX = frozenset("0123456789abcdef")


class IncompleteModelCardError(ValueError):
    """Raised instead of emitting a card that is missing or malforming a required field."""

    def __init__(self, problems: Sequence[str]) -> None:
        self.problems: tuple[str, ...] = tuple(problems)
        listed = "\n".join(f"  - {problem}" for problem in problems)
        super().__init__(
            f"refusing to emit an AIBOM: {len(problems)} required field problem(s)\n{listed}\n"
            "A blank field in an accountability artifact is worse than a loud failure."
        )


# ---------------------------------------------------------------------------
# Declarative field rules
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FieldRule:
    """One required field: where it lives, why it exists, and what makes it valid."""

    path: str
    why: str
    check: Callable[[Any], bool] = lambda value: True
    expectation: str = "must be present and non-empty"


def _nonempty_string(value: Any) -> bool:
    """A present, non-blank string."""

    return isinstance(value, str) and bool(value.strip())


def _nonempty_list(value: Any) -> bool:
    """A present, non-empty list."""

    return isinstance(value, list) and len(value) > 0


def _nonempty_mapping(value: Any) -> bool:
    """A present, non-empty mapping."""

    return isinstance(value, dict) and len(value) > 0


def _is_true(value: Any) -> bool:
    """Literally ``True`` -- not truthy, not the string "true"."""

    return value is True


def _unit_interval(value: Any) -> bool:
    """A real number in [0, 1]."""

    return isinstance(value, int | float) and not isinstance(value, bool) and 0.0 <= value <= 1.0


def _positive_int(value: Any) -> bool:
    """A positive integer."""

    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _nonnegative_number(value: Any) -> bool:
    """A non-negative real number."""

    return isinstance(value, int | float) and not isinstance(value, bool) and value >= 0


def _pinned_revision(value: Any) -> bool:
    """A 40-character lowercase hex commit sha -- not a floating tag."""

    if not isinstance(value, str):
        return False
    normalised = value.strip().lower()
    if normalised in _FLOATING_REVISIONS:
        return False
    return len(normalised) == 40 and set(normalised) <= _HEX


def _real_explanation(value: Any) -> bool:
    """Non-blank prose that is not the placeholder the substrate treats as missing."""

    return _nonempty_string(value) and value.strip() != PLACEHOLDER_EXPLANATION


def _governed_svid(value: Any) -> bool:
    """A SPIFFE id outside every self-change-protected prefix (I-11)."""

    if not _nonempty_string(value):
        return False
    if not value.startswith("spiffe://"):
        return False
    return not any(value.startswith(prefix) for prefix in SELF_CHANGE_PROTECTED_PREFIXES)


def _known_component(value: Any) -> bool:
    """One of the four closed ``PlatformComponent`` variants."""

    return value in PLATFORM_COMPONENTS


def _digest(value: Any) -> bool:
    """A well-formed ``sha256:<64 hex>`` digest."""

    return isinstance(value, str) and is_wellformed_digest(value)


def _iso_date(value: Any) -> bool:
    """A parseable ISO-8601 date."""

    if not isinstance(value, str):
        return False
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return False
    return True


REQUIRED_FIELDS: tuple[FieldRule, ...] = (
    # -- identity -----------------------------------------------------------
    FieldRule("identity.model_name", "the artifact's name", _nonempty_string),
    FieldRule("identity.model_version", "distinguishes retrains", _nonempty_string),
    FieldRule(
        "identity.weights_digest",
        "the value the scanner MUST return in ScannerVerdict.model_digest; if it differs, the "
        "receipt's accountability claim is decorative",
        _digest,
        "must be sha256:<64 lowercase hex>",
    ),
    # -- base model ---------------------------------------------------------
    FieldRule("base_model.repo_id", "which upstream model this derives from", _nonempty_string),
    FieldRule(
        "base_model.revision",
        "a floating tag makes the lineage unreproducible",
        _pinned_revision,
        "must be a pinned 40-character commit sha, not main/latest",
    ),
    FieldRule(
        "base_model.licence",
        "model_sbom.ModelInfo.license has one slot and the derived artifact consumes it, so the "
        "base licence needs its own carrier",
        _nonempty_string,
    ),
    FieldRule("base_model.licence_url", "counsel reads the canonical text", _nonempty_string),
    FieldRule(
        "base_model.acceptable_use_policy",
        "an acceptable-use rider narrows a permissive licence; state 'none' explicitly rather "
        "than leaving it blank",
        _nonempty_string,
    ),
    # -- datasets -----------------------------------------------------------
    FieldRule(
        "datasets",
        "model_sbom.ModelInfo.training_data is a bare list[str] with no licence slot",
        _nonempty_list,
        "must be a non-empty list of dataset licence rows",
    ),
    # -- derived artifact ---------------------------------------------------
    FieldRule("derived_artifact.licence", "what the adapter itself ships under", _nonempty_string),
    FieldRule(
        "derived_artifact.licence_compatibility_argument",
        "the field an acquirer's counsel reads first: why the derived licence is compatible "
        "with the base licence AND every dataset licence",
        _nonempty_string,
    ),
    # -- CSAM ---------------------------------------------------------------
    FieldRule("csam_exclusion.attested", "non-negotiable standing rule", _is_true, "must be true"),
    FieldRule("csam_exclusion.statement", "a named, dated statement", _nonempty_string),
    FieldRule("csam_exclusion.filters", "which filters were applied", _nonempty_list),
    FieldRule("csam_exclusion.attested_by", "a person, not a process", _nonempty_string),
    FieldRule("csam_exclusion.attested_on", "when", _iso_date, "must be an ISO-8601 date"),
    # -- architecture -------------------------------------------------------
    FieldRule("architecture.family", "maps to ModelInfo.architecture", _nonempty_string),
    FieldRule(
        "architecture.parameters", "maps to ModelInfo.parameters", _positive_int, "must be > 0"
    ),
    # -- method -------------------------------------------------------------
    FieldRule("method.technique", "LoRA / QLoRA / full fine-tune", _nonempty_string),
    FieldRule(
        "method.hyperparameters", "the run is not reproducible without them", _nonempty_mapping
    ),
    FieldRule("method.compute_tier", "which free tier ran it", _nonempty_string),
    # -- evaluation ---------------------------------------------------------
    FieldRule(
        "evaluation.recall",
        "THE deny-gate metric: a false negative is silently recorded as a success",
        _unit_interval,
        "must be a number in [0, 1]",
    ),
    FieldRule("evaluation.precision", "reported alongside recall", _unit_interval, "[0, 1]"),
    FieldRule("evaluation.f1", "reported alongside recall", _unit_interval, "[0, 1]"),
    FieldRule(
        "evaluation.false_negative_rate", "1 - recall, stated plainly", _unit_interval, "[0, 1]"
    ),
    FieldRule("evaluation.sample_count", "a recall figure over 12 samples is noise", _positive_int),
    FieldRule("evaluation.eval_set_digest", "pins what was measured", _digest, "sha256:<64 hex>"),
    FieldRule(
        "evaluation.result_digest",
        "binds the card to a specific evaluate.py run",
        _digest,
        "sha256:<64 hex>",
    ),
    FieldRule(
        "evaluation.per_category_recall",
        "aggregate recall hides a category the model misses entirely",
        _nonempty_mapping,
    ),
    FieldRule(
        "evaluation.frontier_context",
        "report the comparison honestly rather than in isolation",
        _nonempty_string,
    ),
    # -- threshold ----------------------------------------------------------
    FieldRule(
        "operating_threshold.value",
        "ModerationConfig.deny_threshold cannot tune recall, so the threshold is a property of "
        "the card and changing it is a model change requiring a new digest",
        _unit_interval,
        "[0, 1]",
    ),
    FieldRule("operating_threshold.calibration_note", "how it was chosen", _nonempty_string),
    # -- taxonomy -----------------------------------------------------------
    FieldRule(
        "harm_category_map",
        "without it ScannerVerdict.flagged_categories is unreadable downstream",
        _nonempty_mapping,
    ),
    # -- failure ------------------------------------------------------------
    FieldRule(
        "failure_semantics.on_timeout",
        "the ContentScanner trait has no error channel; this contract exists only here",
        _nonempty_string,
    ),
    FieldRule("failure_semantics.on_oom", "same", _nonempty_string),
    FieldRule("failure_semantics.on_load_failure", "same", _nonempty_string),
    FieldRule(
        "failure_semantics.registry_owner",
        "somebody must drop a dead scanner from the slice, because decide() only fails closed "
        "on an EMPTY slice",
        _nonempty_string,
    ),
    # -- bias ---------------------------------------------------------------
    FieldRule(
        "bias_audit.checked",
        "BiasAudit.exceeds_threshold requires checked == true, so checked:false is a silent "
        "pass rather than a neutral state",
        _is_true,
        "must be true",
    ),
    FieldRule("bias_audit.score", "the measured score", _unit_interval, "[0, 1]"),
    FieldRule("bias_audit.protected_classes", "which classes were evaluated", _nonempty_list),
    FieldRule(
        "bias_audit.checker_model_digest",
        "reflexivity: for a guard model the artifact under audit and the artifact doing the "
        "auditing are related, so the checker must be a distinct, separately digested model",
        _digest,
        "sha256:<64 hex>",
    ),
    # -- carbon -------------------------------------------------------------
    FieldRule(
        "carbon.training.energy_wh",
        "no field anywhere in the substrate holds training energy; reporting only inference "
        "watt-hours understates the footprint by orders of magnitude",
        _nonnegative_number,
    ),
    FieldRule("carbon.training.co2_grams", "same", _nonnegative_number),
    FieldRule("carbon.training.region", "grid intensity is regional", _nonempty_string),
    FieldRule("carbon.training.hardware", "T4 / P100 / 5080 / A100", _nonempty_string),
    FieldRule(
        "carbon.inference.model_efficiency_wh_per_1k",
        "populates CarbonFootprint.model_efficiency_wh_per_1k at runtime",
        _nonnegative_number,
    ),
    # -- explanation --------------------------------------------------------
    FieldRule(
        "right_to_explanation.explanation",
        "validate_ra_block treats the literal string 'No explanation provided' as MISSING",
        _real_explanation,
        f"must be real prose, not {PLACEHOLDER_EXPLANATION!r}",
    ),
    FieldRule("right_to_explanation.key_factors", "what drove the decision", _nonempty_list),
    FieldRule(
        "right_to_explanation.human_review_available",
        "GDPR Art. 22",
        lambda value: isinstance(value, bool),
        "must be a boolean",
    ),
    # -- SG1 ----------------------------------------------------------------
    FieldRule("sg1.agent_id", "PlatformAgent.agent_id", _nonempty_string),
    FieldRule(
        "sg1.svid",
        "check 5 (I-11): the SVID must sit outside all eight self-change-protected prefixes",
        _governed_svid,
        "must start with spiffe:// and not be under a protected prefix",
    ),
    FieldRule("sg1.capabilities", "check 2: must be non-empty", _nonempty_list),
    FieldRule("sg1.kill_switchable", "check 4", _is_true, "must be true"),
    FieldRule(
        "sg1.consequential_outputs",
        "SG1 loophole: `receipting || consequential_outputs.is_empty()` means an EMPTY list "
        "passes the receipting check with receipting:false",
        _nonempty_list,
    ),
    FieldRule("sg1.receipting", "check 3", _is_true, "must be true"),
    FieldRule(
        "sg1.platform_component",
        "PlatformComponent is a closed four-variant enum with no guard-model slot; state which "
        "one this registers under",
        _known_component,
        f"must be one of {PLATFORM_COMPONENTS}",
    ),
    FieldRule(
        "sg1.registration_note",
        "record whether this is a sub-agent registration or awaits a new enum variant",
        _nonempty_string,
    ),
    # -- provenance ---------------------------------------------------------
    FieldRule("provenance.trained_by", "who ran it", _nonempty_string),
    FieldRule("provenance.run_id", "which run", _nonempty_string),
    FieldRule(
        "provenance.dataset_manifest_digest", "pins the corpus snapshot", _digest, "sha256:<64 hex>"
    ),
    FieldRule("provenance.supplier", "SbomInput.supplier", _nonempty_string),
    # -- advisory -----------------------------------------------------------
    FieldRule(
        "advisory_declaration",
        "the model advises; the deterministic substrate decides. May contribute to Deny, never "
        "to Allow, never wired to a terminating action",
        _nonempty_string,
    ),
)

_DATASET_ROW_RULES: tuple[FieldRule, ...] = (
    FieldRule("dataset_id", "which corpus", _nonempty_string),
    FieldRule("revision", "pins the snapshot", _nonempty_string),
    FieldRule("digest", "pins the bytes", _digest, "sha256:<64 hex>"),
    FieldRule("licence", "SPDX or named licence", _nonempty_string),
    FieldRule("licence_url", "canonical text", _nonempty_string),
    FieldRule(
        "gated",
        "whether a click-through stands between you and the file",
        lambda value: isinstance(value, bool),
        "must be a boolean",
    ),
    FieldRule(
        "redistributable",
        "may the corpus travel with the artifact",
        lambda value: isinstance(value, bool),
        "must be a boolean",
    ),
    FieldRule(
        "commercial_use",
        "the click-through terms can be NARROWER than the licence; ExpGuardMix is CC-BY-4.0 but "
        "the gate form says research-only",
        _nonempty_string,
    ),
    FieldRule("terms_read_on", "when the terms were read", _iso_date, "ISO-8601 date"),
)


def _lookup(card: dict[str, Any], path: str) -> Any:
    """Resolve a dotted path, returning ``None`` for any missing segment."""

    current: Any = card
    for segment in path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return None
        current = current[segment]
    return current


def validate_card(card: dict[str, Any]) -> tuple[str, ...]:
    """Return every required-field problem. Empty tuple means the card may be emitted."""

    problems: list[str] = []
    for rule in REQUIRED_FIELDS:
        value = _lookup(card, rule.path)
        if value is None:
            problems.append(f"{rule.path}: MISSING ({rule.why})")
        elif not rule.check(value):
            problems.append(f"{rule.path}: INVALID -- {rule.expectation} (got {value!r})")

    rows = _lookup(card, "datasets")
    if isinstance(rows, list):
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                problems.append(f"datasets[{index}]: INVALID -- must be an object")
                continue
            for rule in _DATASET_ROW_RULES:
                value = row.get(rule.path)
                label = f"datasets[{index}].{rule.path}"
                if value is None:
                    problems.append(f"{label}: MISSING ({rule.why})")
                elif not rule.check(value):
                    problems.append(f"{label}: INVALID -- {rule.expectation} (got {value!r})")

    checker = _lookup(card, "bias_audit.checker_model_digest")
    weights = _lookup(card, "identity.weights_digest")
    if checker is not None and checker == weights:
        problems.append(
            "bias_audit.checker_model_digest: INVALID -- must differ from "
            "identity.weights_digest; a model cannot be its own bias checker"
        )
    return tuple(problems)


# ---------------------------------------------------------------------------
# Emission
# ---------------------------------------------------------------------------


def _sbom_document(card: dict[str, Any]) -> dict[str, Any]:
    """Embed a CycloneDX Model SBOM if ``model_sbom`` is importable, else record why not.

    ``model_sbom`` is a sibling project in this monorepo, not a declared dependency of this
    one. Importing it opportunistically keeps the AIBOM richer where it is installed without
    making the gate depend on cross-project installation order.
    """

    try:
        from model_sbom import Dependency, ModelInfo, SbomFormat, SbomInput, generate
    except ImportError:
        return {
            "embedded": False,
            "reason": "model_sbom is not importable in this environment",
            "note": "Generate separately with python/model_sbom; the model digest in that "
            "document MUST equal identity.weights_digest.",
        }
    model = ModelInfo(
        name=str(_lookup(card, "identity.model_name")),
        architecture=str(_lookup(card, "architecture.family")),
        parameters=int(_lookup(card, "architecture.parameters")),
        training_data=[str(row.get("digest")) for row in _lookup(card, "datasets") or []],
        base_model=f"{_lookup(card, 'base_model.repo_id')}@{_lookup(card, 'base_model.revision')}",
        evaluations=[str(_lookup(card, "evaluation.result_digest"))],
        license=str(_lookup(card, "derived_artifact.licence")),
        digest=str(_lookup(card, "identity.weights_digest")),
    )
    dependencies = [
        Dependency(name=item["name"], version=item["version"], digest=item.get("digest"))
        for item in card.get("runtime_dependencies", [])
        if isinstance(item, dict) and "name" in item and "version" in item
    ]
    supplier = str(_lookup(card, "provenance.supplier"))
    document = generate(
        SbomInput(model=model, dependencies=dependencies, supplier=supplier),
        SbomFormat.CYCLONEDX,
    )
    return {
        "embedded": True,
        "format": "cyclonedx-1.5",
        "document": document,
        "known_limitation": "ModelInfo.license carries the DERIVED licence only. Base-model and "
        "per-dataset licensing cannot be expressed in the SBOM schema and live in this AIBOM's "
        "base_model and datasets sections. Fix requires an S4 schema extension.",
    }


def build_aibom(card: dict[str, Any], generated_at: datetime | None = None) -> dict[str, Any]:
    """Validate a card and build the AIBOM body, or refuse.

    Raises:
        IncompleteModelCardError: if any required field is missing or malformed. Every problem
            is reported at once so the caller fixes the card in one pass instead of discovering
            them one failure at a time.
    """

    problems = validate_card(card)
    if problems:
        raise IncompleteModelCardError(problems)
    timestamp = (generated_at or datetime.now(UTC)).astimezone(UTC)
    return {
        "aibom_version": AIBOM_VERSION,
        "generated_at": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "card": card,
        "model_sbom": _sbom_document(card),
        "schema_gaps": [
            "model_sbom.ModelInfo.license is a single SPDX string; base / dataset / derived "
            "licences cannot all be expressed there.",
            "model_sbom.ModelInfo.training_data has no licence, gating or redistribution slot.",
            "responsible_ai::CarbonFootprint is per-action inference only; training energy has "
            "no receipt counterpart anywhere in the substrate.",
            "ContentScanner::scan has no error channel; failure semantics are contractual, not "
            "type-enforced.",
            "PlatformComponent is a closed four-variant enum with no guard-model variant.",
        ],
    }


def sign_aibom(body: dict[str, Any], private_key_bytes: bytes) -> dict[str, Any]:
    """Sign an AIBOM body with Ed25519 over its canonical JSON.

    Same canonicalisation as the W10 moderation receipt verify path: recursively sorted keys,
    no whitespace. A signed AIBOM therefore verifies under the same discipline as the receipts
    that will cite its model digest.
    """

    if len(private_key_bytes) != 32:
        raise ValueError(f"Ed25519 private key must be 32 bytes, got {len(private_key_bytes)}")
    key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    canonical = canonical_json(body).encode("utf-8")
    signature = key.sign(canonical)
    public = key.public_key().public_bytes_raw()
    return {
        "body": body,
        "signature_algorithm": "Ed25519",
        "signature_public_key": public.hex(),
        "signature_value": signature.hex(),
    }


def verify_aibom(envelope: dict[str, Any]) -> None:
    """Verify a signed AIBOM, raising :class:`ValueError` on any failure."""

    body = envelope.get("body")
    if not isinstance(body, dict):
        raise ValueError("signed AIBOM is missing its body")
    try:
        public_bytes = bytes.fromhex(envelope.get("signature_public_key", ""))
        signature = bytes.fromhex(envelope.get("signature_value", ""))
    except ValueError as error:
        raise ValueError(f"malformed signature envelope: {error}") from error
    if len(public_bytes) != 32:
        raise ValueError(f"public key must be 32 bytes, got {len(public_bytes)}")
    if len(signature) != 64:
        raise ValueError(f"signature must be 64 bytes, got {len(signature)}")
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            signature, canonical_json(body).encode("utf-8")
        )
    except InvalidSignature as error:
        raise ValueError("Ed25519 signature does not verify") from error


# ---------------------------------------------------------------------------
# Example card
# ---------------------------------------------------------------------------


def _registry_dataset_entry(
    dataset_id: str,
    *,
    digest: str,
    commercial_use: str,
    note: str,
) -> dict[str, Any]:
    """One AIBOM datasets entry, with every factual field read FROM the dataset registry.

    These fields used to be retyped here, and they drifted: this block declared ExpGuardMix at
    58,928 rows for a corpus whose train split holds 46,005 -- a 23% overstatement inside a
    provenance document, in a repository whose subject is provenance. The registry corrected the
    figure and this copy did not, because nothing connected them.

    ``digest``, ``commercial_use`` and ``note`` stay arguments: the digest is per-artifact, and
    the other two are the card's own prose about a conflict the registry records in its own
    words. The row count, licence, gating and terms date are facts with exactly one home.
    """

    from .datasets import get_dataset

    spec = get_dataset(dataset_id)
    return {
        "dataset_id": spec.dataset_id,
        "revision": spec.revision,
        "digest": digest,
        "licence": spec.licence,
        "licence_url": spec.licence_url,
        "gated": spec.gated,
        "redistributable": spec.redistributable,
        "commercial_use": commercial_use,
        "terms_read_on": spec.terms_read_on.isoformat(),
        "rows": spec.total_rows,
        "note": (
            f"{spec.total_rows:,} rows total ("
            + " + ".join(f"{split.rows:,} {split.name}" for split in spec.splits)
            + f"), read from the dataset registry. {note}"
        ),
    }


def example_card() -> dict[str, Any]:
    """A fully-populated card used as the CLI's ``--template`` and as a test fixture.

    The metric values are placeholders marked as such. It is a *shape*, not a claim.
    """

    return {
        "identity": {
            "model_name": "warrantor-guard-qwen3guard-gen-4b-lora",
            "model_version": "0.1.0-PLACEHOLDER",
            "weights_digest": "sha256:" + "0" * 64,
        },
        "base_model": {
            "repo_id": "Qwen/Qwen3Guard-Gen-4B",
            "revision": "0" * 40,
            "licence": "Apache-2.0",
            "licence_url": "https://huggingface.co/Qwen/Qwen3Guard-Gen-4B/blob/main/LICENSE",
            "acceptable_use_policy": "none -- the LICENSE file is verbatim 201-line Apache 2.0 "
            "('Copyright 2024 Alibaba Cloud') with no acceptable-use rider, no addendum and no "
            "NOTICE file. Apache-2.0 s.3 terminates the patent grant on patent litigation over "
            "the Work, and s.6 forbids use of Alibaba/Qwen trademarks in downstream branding.",
        },
        "datasets": [
            _registry_dataset_entry(
                "wildguardmix",
                digest="sha256:" + "1" * 64,
                commercial_use="restricted-by-click-through (AI2 responsible-use terms)",
                note="Not the 92K figure that circulated in early planning.",
            ),
            _registry_dataset_entry(
                "expguardmix",
                digest="sha256:" + "2" * 64,
                commercial_use="UNRESOLVED -- licence permits it, click-through says "
                "'solely for research purposes'. Awaiting written counsel read.",
                note="GPT-4o-generated corpus; records a closed-frontier-model dependency in "
                "the data lineage. arXiv:2603.02588, ICLR 2026 conference track.",
            ),
        ],
        "derived_artifact": {
            "licence": "Apache-2.0",
            "licence_compatibility_argument": "PLACEHOLDER -- the adapter is a derivative work "
            "of an Apache-2.0 base, which permits sublicensing under Apache-2.0 provided the "
            "licence copy, notices and modification markers travel with it. Dataset licences "
            "(ODC-By-1.0, CC-BY-4.0) impose attribution but do not attach to model weights on "
            "any settled reading; the ExpGuardMix click-through restriction is the open "
            "question and must be resolved by counsel before this argument is relied on.",
        },
        "csam_exclusion": {
            "attested": True,
            "statement": "PLACEHOLDER -- no CSAM was present in any training corpus.",
            "filters": ["hash-matching against known-CSAM hash sets", "corpus provenance review"],
            "attested_by": "PLACEHOLDER -- named human",
            "attested_on": "2026-08-12",
            "retention": "Any suspected material is deleted, not retained, and reported.",
        },
        "architecture": {
            "family": "transformer-decoder (Qwen3ForCausalLM)",
            "parameters": 4_000_000_000,
        },
        "method": {
            "technique": "QLoRA (NF4 base, r=16 adapters, paged AdamW, gradient checkpointing)",
            "compute_tier": "Kaggle free tier (2x T4) -- zero marginal spend",
            "hyperparameters": {
                "lora_r": 16,
                "lora_alpha": 32,
                "lora_dropout": 0.05,
                "learning_rate": 1e-4,
                "sequence_length": 2048,
                "epochs": 1,
                "seed": 20260812,
            },
        },
        "evaluation": {
            "recall": 0.0,
            "precision": 0.0,
            "f1": 0.0,
            "false_negative_rate": 1.0,
            "sample_count": 1,
            "eval_set_digest": "sha256:" + "3" * 64,
            "result_digest": "sha256:" + "4" * 64,
            "per_category_recall": {"PLACEHOLDER": 0.0},
            "frontier_context": "ICLR 2026 workshop benchmark (arXiv:2605.28830, 14 guard "
            "models, 79,331 samples, 8 NIST AI RMF categories): Qwen Guard 4B leads on recall "
            "at 83.97%; ShieldGemma leads on precision at 82.20% while missing 54.51% of unsafe "
            "content; GPT-OSS Safeguard 20B misses 75.14%. No correlation between size and "
            "recall. That eval set aggregates HarmBench, StrongREJECT, RealToxicityPrompts and "
            "BeaverTails -- it measures those distributions, not ours.",
        },
        "operating_threshold": {
            "value": 0.5,
            "calibration_note": "PLACEHOLDER. ModerationConfig.deny_threshold cannot raise "
            "recall (decide() rule 3 requires is_harmful, which rule 2 already denied on), so "
            "this threshold is internal to the model. Changing it is a model change and "
            "requires a new weights digest.",
        },
        "harm_category_map": {
            "violent": "HarmCategory::Violence",
            "hate_speech": "HarmCategory::HateSpeech",
            "sexual_content": "HarmCategory::SexualContent",
            "self_harm": "HarmCategory::SelfHarm",
            "harassment": "HarmCategory::Harassment",
            "dangerous_content": "HarmCategory::DangerousContent",
            "privacy_violation": "HarmCategory::PrivacyViolation",
            "deception": "HarmCategory::Deception",
            "jailbreak": 'HarmCategory::Custom("jailbreak")',
            "finance": 'HarmCategory::Custom("domain:finance")',
            "healthcare": 'HarmCategory::Custom("domain:healthcare")',
            "law": 'HarmCategory::Custom("domain:law")',
        },
        "failure_semantics": {
            "on_timeout": "return is_harmful=true, confidence=1.0, detail='scanner timeout'. "
            "Deny-biased because ContentScanner::scan has no error channel.",
            "on_oom": "return is_harmful=true and signal the registry to drop this scanner.",
            "on_load_failure": "the scanner is never added to the slice; if the slice ends up "
            "empty, decide() denies with AllScannersUnavailable, which is the only fail-closed "
            "path the substrate actually enforces.",
            "registry_owner": "PLACEHOLDER -- the component that builds the &[Box<dyn "
            "ContentScanner>] slice owns removal of dead scanners.",
        },
        "bias_audit": {
            "checked": True,
            "score": 0.0,
            "protected_classes": ["gender", "race", "age", "religion", "nationality"],
            "checker_model_digest": "sha256:" + "5" * 64,
            "reflexivity_note": "The checker must be a distinct, separately digested model. A "
            "guard model cannot audit its own bias.",
        },
        "carbon": {
            "training": {
                "energy_wh": 0.0,
                "co2_grams": 0.0,
                "region": "PLACEHOLDER",
                "hardware": "Kaggle 2x NVIDIA T4",
                "note": "No field in responsible_ai::CarbonFootprint or model_sbom.ModelInfo "
                "holds training energy. This number has no receipt counterpart by design gap.",
            },
            "inference": {"model_efficiency_wh_per_1k": 0.0},
        },
        "right_to_explanation": {
            "explanation": "This response was withheld because an advisory content scanner "
            "flagged it against a published harm taxonomy. The scanner's finding contributed to "
            "a deny decision made by the policy substrate, not by the model.",
            "key_factors": [
                "flagged harm categories",
                "scanner confidence relative to the model's operating threshold",
                "the substrate's advisory asymmetry: a flag may deny, never allow",
            ],
            "human_review_available": True,
        },
        "sg1": {
            "agent_id": "warrantor-guard-content-scanner",
            "svid": "spiffe://warrantor.io/ai/content-scanner",
            "capabilities": ["read", "scan"],
            "kill_switchable": True,
            "consequential_outputs": ["moderation_verdict"],
            "receipting": True,
            "platform_component": "audit_fleet",
            "registration_note": "Registered as a SUB-AGENT of audit_fleet. PlatformComponent "
            "is a closed four-variant enum with no guard-model slot; adding one moves "
            "all() -> [PlatformComponent; 4], missing_components(), a discriminant-order sort "
            "and two tests together, so it is a deliberate reviewed change, not a side effect "
            "of landing this model.",
        },
        "provenance": {
            "trained_by": "PLACEHOLDER -- named human",
            "run_id": "PLACEHOLDER",
            "dataset_manifest_digest": "sha256:" + "6" * 64,
            "supplier": "did:web:muveraai.com",
        },
        "runtime_dependencies": [
            {"name": "transformers", "version": "4.51.0"},
            {"name": "peft", "version": "0.11.0"},
        ],
        "advisory_declaration": "This model's output is ADVISORY. It may contribute to a Deny "
        "and never to an Allow, and it is never wired to a terminating action. The "
        "deterministic substrate decides; the model advises.",
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """CLI for ``warrantor-ml-model-card``."""

    parser = argparse.ArgumentParser(
        prog="warrantor-ml-model-card",
        description="Validate, build and sign an AIBOM. Refuses to emit an incomplete card.",
    )
    parser.add_argument("--card", type=Path, help="path to a JSON card draft")
    parser.add_argument("--out", type=Path, help="write the AIBOM here")
    parser.add_argument(
        "--template",
        type=Path,
        help="write a fully-populated example card to this path and exit",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="report required-field problems and exit non-zero if any",
    )
    parser.add_argument(
        "--signing-key",
        type=Path,
        help="path to a 32-byte raw Ed25519 private key (hex or binary)",
    )
    parser.add_argument(
        "--fields",
        action="store_true",
        help="list every required field and why it exists, then exit",
    )
    return parser


def _read_key(path: Path) -> bytes:
    """Read a raw or hex-encoded 32-byte Ed25519 private key."""

    raw = path.read_bytes()
    if len(raw) == 32:
        return raw
    text = raw.decode("utf-8", errors="ignore").strip()
    try:
        decoded = bytes.fromhex(text)
    except ValueError as error:
        raise ValueError(f"{path}: not a 32-byte raw key nor valid hex") from error
    if len(decoded) != 32:
        raise ValueError(f"{path}: decoded key is {len(decoded)} bytes, expected 32")
    return decoded


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``warrantor-ml-model-card``."""

    arguments = build_parser().parse_args(argv)

    if arguments.fields:
        for rule in REQUIRED_FIELDS:
            print(f"{rule.path}\n    {rule.expectation}\n    why: {rule.why}")
        return 0

    if arguments.template is not None:
        arguments.template.parent.mkdir(parents=True, exist_ok=True)
        arguments.template.write_text(
            json.dumps(example_card(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"wrote card template to {arguments.template}")
        print("Every PLACEHOLDER value must be replaced before this card means anything.")
        return 0

    if arguments.card is None:
        build_parser().error("--card is required (or use --template / --fields)")

    card = json.loads(arguments.card.read_text(encoding="utf-8"))
    problems = validate_card(card)
    if arguments.validate_only:
        if problems:
            print(f"{len(problems)} required-field problem(s):", file=sys.stderr)
            for problem in problems:
                print(f"  - {problem}", file=sys.stderr)
            return 1
        print("card is complete")
        return 0

    try:
        body = build_aibom(card)
    except IncompleteModelCardError as error:
        print(str(error), file=sys.stderr)
        return 1

    document: dict[str, Any] = body
    if arguments.signing_key is not None:
        document = sign_aibom(body, _read_key(arguments.signing_key))
        verify_aibom(document)

    rendered = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    if arguments.out is not None:
        arguments.out.parent.mkdir(parents=True, exist_ok=True)
        arguments.out.write_text(rendered, encoding="utf-8")
        signed = "signed " if arguments.signing_key else ""
        print(f"wrote {signed}AIBOM to {arguments.out}")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
