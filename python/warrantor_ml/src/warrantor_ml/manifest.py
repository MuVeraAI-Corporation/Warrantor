"""Dataset provenance manifests, and the five things a manifest is refused for.

"Every dataset needs a manifest" is only worth stating if it is enforceable, so this module is
built as a validator that refuses rather than a schema that records. The refusals are named
after the failures they prevent, not after the fields they check.

The structural commitment is the **teacher / judge separation**. Open-weight teachers may
generate training rows. Frontier models may score rows and may never write them. That rule
survives a late-night rejection-sampling loop only if it is carried by a type and checked by a
validator: see :class:`SourceRole`, :func:`validate_manifest` rule (a), and the companion
constraint in :mod:`warrantor_ml.teachers` where a judge's output is not a type any corpus
builder accepts.

The second structural commitment is **inherited lineage**. ExpGuardMix's corpus was generated
with GPT-4o and its gate form says research-only while its licence says CC-BY-4.0. Both facts
are already recorded in :mod:`warrantor_ml.datasets` as prose in ``notes`` and ``terms_note``.
Here they become machine-readable inherited facts that an AIBOM can carry and that
:mod:`warrantor_ml.parity` can refuse a commercial-clearance claim on.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from ._canonical import canonical_json, is_wellformed_digest, sha256_text
from .datasets import REGISTRY

__all__ = [
    "MANIFEST_FORMAT",
    "DatasetManifest",
    "ManifestRefused",
    "SourceKind",
    "SourceRole",
    "SourceRow",
    "TeacherProvenance",
    "corpus_source",
    "validate_manifest",
]

MANIFEST_FORMAT = "warrantor.dataset-manifest/1"

#: Where a block of rows came from. ``repo-artifact`` covers rows derived from warrants,
#: refusal logs and report bundles inside this repository -- the substrate models' only real
#: supervision.
SourceKind = Literal["corpus", "repo-artifact", "teacher-generated"]

#: What a model was allowed to do. The whole data doctrine is this one distinction.
SourceRole = Literal["teacher", "judge"]


class ManifestRefused(ValueError):
    """Raised when a manifest describes a corpus that must not be built or trained on."""


@dataclass(frozen=True)
class TeacherProvenance:
    """Everything needed to reproduce a block of generated rows, or to disown them.

    A generated row whose prompt template is not digested is a row nobody can regenerate, which
    makes the manifest a claim rather than a record. The seed and decoding options are here for
    the same reason the evaluator pins ``temperature`` and ``num_ctx``: changing any of them
    changes the data, and a corpus that does not say what produced it cannot be compared with
    the next one.
    """

    model_id: str
    role: SourceRole
    weights_digest: str
    prompt_template_digest: str
    seed: int
    decoding: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the manifest body."""

        return {
            "model_id": self.model_id,
            "role": self.role,
            "weights_digest": self.weights_digest,
            "prompt_template_digest": self.prompt_template_digest,
            "seed": self.seed,
            "decoding": dict(self.decoding),
        }


@dataclass(frozen=True)
class SourceRow:
    """One block of rows in a corpus, with where it came from and what it inherits.

    ``row_count`` is declared here and checked against the counted rows behind ``content_digest``
    by :func:`validate_manifest`. A declared count that nobody reconciles is the field that
    quietly drifts once a filter is added upstream, and then every per-class denominator in
    every downstream report is wrong by an amount nobody can recover.
    """

    source_id: str
    kind: SourceKind
    split: str
    row_count: int
    content_digest: str
    licence: str
    commercial_use: str
    repo_id: str = ""
    revision: str = ""
    #: Closed-frontier models anywhere in this block's ancestry. Inherited, never recomputed:
    #: ExpGuardMix's rows were GPT-4o-generated upstream, so anything derived from them carries
    #: that dependency even though no frontier API is called at training time.
    frontier_lineage: tuple[str, ...] = ()
    #: Present only for ``teacher-generated`` rows.
    generator: TeacherProvenance | None = None
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the manifest body."""

        return {
            "source_id": self.source_id,
            "kind": self.kind,
            "split": self.split,
            "row_count": self.row_count,
            "content_digest": self.content_digest,
            "licence": self.licence,
            "commercial_use": self.commercial_use,
            "repo_id": self.repo_id,
            "revision": self.revision,
            "frontier_lineage": list(self.frontier_lineage),
            "generator": self.generator.to_dict() if self.generator else None,
            "notes": list(self.notes),
        }


def corpus_source(
    dataset_id: str,
    split: str,
    row_count: int,
    content_digest: str,
    *,
    notes: Sequence[str] = (),
) -> SourceRow:
    """Build a corpus :class:`SourceRow` with licence facts pulled FROM the registry.

    Licence, commercial-use status and revision are read from :data:`warrantor_ml.datasets.REGISTRY`
    rather than passed in. Retyping a licence at the call site is how a manifest ends up saying
    CC-BY-4.0 about a corpus whose click-through says research-only, which is precisely the
    conflict ``datasets.py`` already went to the trouble of recording separately.

    ``frontier_lineage`` is derived, not asked for: a corpus whose registry notes say it was
    generated with a frontier model inherits that dependency automatically, so a caller cannot
    forget to declare it.
    """

    try:
        spec = REGISTRY[dataset_id]
    except KeyError as error:
        known = ", ".join(sorted(REGISTRY))
        raise ManifestRefused(f"unknown dataset {dataset_id!r}; registered: {known}") from error
    spec.split(split)  # raises for a split the registry does not declare

    lineage: list[str] = []
    haystack = " ".join(spec.notes).lower()
    if "gpt-4o" in haystack:
        lineage.append("openai/gpt-4o (upstream corpus generation, per the dataset card)")

    return SourceRow(
        source_id=f"{dataset_id}:{split}",
        kind="corpus",
        split=split,
        row_count=row_count,
        content_digest=content_digest,
        licence=spec.licence,
        commercial_use=spec.commercial_use,
        repo_id=spec.homepage.rsplit("/datasets/", 1)[-1],
        revision=spec.revision,
        frontier_lineage=tuple(lineage),
        notes=(*notes, spec.terms_note),
    )


@dataclass(frozen=True)
class DatasetManifest:
    """The provenance record for one built corpus.

    ``csam_exclusion`` is a required attestation and not a boolean flag, matching
    :mod:`warrantor_ml.model_card`'s treatment: it has to name the filters applied and the date,
    because "true" attests to nothing and a blank field in an accountability artifact is worse
    than a loud failure.
    """

    corpus_id: str
    task: str
    built_for_split: str
    sources: tuple[SourceRow, ...]
    csam_exclusion: Mapping[str, Any] | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def declared_rows(self) -> int:
        """Total rows this manifest claims to describe."""

        return sum(source.row_count for source in self.sources)

    @property
    def frontier_lineage(self) -> tuple[str, ...]:
        """Every closed-frontier dependency inherited from any source, deduplicated."""

        seen: set[str] = set()
        for source in self.sources:
            seen.update(source.frontier_lineage)
        return tuple(sorted(seen))

    @property
    def commercially_cleared(self) -> bool:
        """Whether every source permits commercial use outright.

        ``restricted-by-click-through`` and ``unverified`` both read as NOT cleared. The licence
        is not the agreement that was signed; the gate form is, and it is narrower.
        """

        return all(source.commercial_use == "permitted" for source in self.sources)

    def to_dict(self) -> dict[str, Any]:
        """The canonical manifest body, without its own digest."""

        return {
            "format": MANIFEST_FORMAT,
            "corpus_id": self.corpus_id,
            "task": self.task,
            "built_for_split": self.built_for_split,
            "declared_rows": self.declared_rows,
            "frontier_lineage": list(self.frontier_lineage),
            "commercially_cleared": self.commercially_cleared,
            "csam_exclusion": dict(self.csam_exclusion) if self.csam_exclusion else None,
            "sources": [source.to_dict() for source in self.sources],
            "notes": list(self.notes),
        }

    @property
    def manifest_digest(self) -> str:
        """Digest over the canonical body, for ``model_card`` and the parity decision record."""

        return sha256_text(canonical_json(self.to_dict()))


#: Splits whose rows are used to MEASURE. A teacher-generated row here turns the eval into a
#: measurement of agreement with the teacher, which is not the quantity anyone wants.
EVAL_SPLITS = frozenset({"eval", "test", "validation", "holdout"})


def validate_manifest(
    manifest: DatasetManifest,
    counted_rows: Mapping[str, int] | None = None,
) -> None:
    """Refuse a manifest that describes a corpus that must not exist. Raises, never warns.

    Every refusal below is named after a real way a corpus goes wrong, and all of them are
    reported together so a manifest gets fixed in one pass rather than five.

    Args:
        manifest: the manifest to check.
        counted_rows: ``source_id -> rows actually counted behind the content digest``. Omitting
            it skips rule (d) only; the declared count is then unreconciled and the caller has
            said so by not passing the numbers.

    Raises:
        ManifestRefused: with every problem listed.
    """

    problems: list[str] = []

    if not manifest.sources:
        problems.append("no sources: a manifest that describes nothing attests to nothing")

    for source in manifest.sources:
        # (a) A judge that wrote training rows. The doctrine breach that actually happens is not
        # calling a frontier model to author a corpus; it is a rejection-sampling loop where the
        # scorer's correction text is copied into the pair it just rejected.
        if source.kind == "teacher-generated":
            if source.generator is None:
                problems.append(
                    f"{source.source_id}: teacher-generated rows with no generator recorded; "
                    "rows nobody can attribute are rows nobody can withdraw"
                )
            elif source.generator.role != "teacher":
                problems.append(
                    f"{source.source_id}: generated by {source.generator.model_id!r}, which is "
                    "registered with role='judge'. A frontier model may SCORE training data and "
                    "may never WRITE it -- this is the data doctrine, not a preference"
                )
            elif not is_wellformed_digest(source.generator.weights_digest):
                problems.append(
                    f"{source.source_id}: generator weights_digest is not sha256:<64 hex>; "
                    "an open-weight teacher that is not pinned is not an open-weight teacher"
                )

            # (b) Generated rows in a measured split.
            if source.split in EVAL_SPLITS or manifest.built_for_split in EVAL_SPLITS:
                problems.append(
                    f"{source.source_id}: teacher-generated rows assigned to the "
                    f"{source.split!r} split of a corpus built for {manifest.built_for_split!r}. "
                    "An eval containing teacher output measures agreement with the teacher, not "
                    "capability -- and the gate would then promote on it"
                )

        # (c) A corpus row with no licence. The SBOM has one licence slot and the AIBOM copies
        # its dataset table from here; an unlicensed row makes both documents unfounded.
        if source.kind == "corpus" and not source.licence.strip():
            problems.append(
                f"{source.source_id}: corpus rows with no licence recorded. "
                "model_sbom.ModelInfo.training_data has no licence slot, so if it is not here "
                "it is nowhere"
            )

        if not is_wellformed_digest(source.content_digest):
            problems.append(
                f"{source.source_id}: content_digest {source.content_digest!r} is not "
                "sha256:<64 lowercase hex>"
            )

        if source.row_count < 0:
            problems.append(f"{source.source_id}: negative row_count {source.row_count}")

        # (d) A declared count nobody reconciled against the bytes.
        if counted_rows is not None:
            actual = counted_rows.get(source.source_id)
            if actual is None:
                problems.append(
                    f"{source.source_id}: declared {source.row_count} rows but no counted total "
                    "was supplied for reconciliation"
                )
            elif actual != source.row_count:
                problems.append(
                    f"{source.source_id}: declares {source.row_count} rows, counted {actual}. "
                    "Every downstream denominator is computed from the declared figure"
                )

    # (e) No CSAM exclusion attestation. Standing rule, mirrored from `model_card`, which refuses
    # to emit an AIBOM without it for the same reason.
    attestation = manifest.csam_exclusion
    if not attestation or not attestation.get("attested"):
        problems.append(
            "csam_exclusion: MISSING. Non-negotiable standing rule -- a corpus built from "
            "web-derived text ships with an attestation naming the filters applied and the "
            "date, or it does not ship"
        )
    elif not str(attestation.get("filters") or "").strip():
        problems.append(
            "csam_exclusion.filters: MISSING. 'attested: true' with no named filter attests to "
            "nothing at all"
        )

    if problems:
        listing = "\n".join(f"  - {problem}" for problem in problems)
        raise ManifestRefused(
            f"refusing the corpus manifest {manifest.corpus_id!r}: "
            f"{len(problems)} problem(s)\n{listing}"
        )
