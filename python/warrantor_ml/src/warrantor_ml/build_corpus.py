"""Build a training corpus for one of the eight models, with its provenance manifest.

``--describe-only`` exists to be run first and is not a convenience. ``benchmark_expguard``'s
own history is the argument: the plan said the legal vertical was spelled ``legal`` and that a
general band existed, and the corpus disagreed on both counts. Only inspecting the split showed
it, and nothing about a selector written against the wrong spelling looks broken -- it just
selects nothing, which is indistinguishable from a corpus that has none.

Nothing here trains anything and nothing dispatches a job. It reads a split, selects rows,
renders pairs, writes JSONL, and emits a manifest that :func:`warrantor_ml.manifest.validate_manifest`
has already refused or accepted.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .leakage import content_fingerprint
from .manifest import DatasetManifest, ManifestRefused, corpus_source, validate_manifest
from .tasks import guard

__all__ = ["ExcessiveLeakageError", "build_guard_corpus", "build_parser", "main"]

TASKS = ("guard", "bounds", "triage", "effects", "summary")

#: The attestation every built corpus carries. Named filters and a date, because "attested:
#: true" with nothing behind it attests to nothing -- the same standard `model_card` holds.
CSAM_ATTESTATION: dict[str, Any] = {
    "attested": True,
    "filters": "Upstream corpus filtering by the dataset publishers (AI2 responsible-use terms "
    "for WildGuardMix; expert validation for ExpGuardMix) plus no image or binary content in "
    "any row -- these corpora are text-only. No new web crawl is performed by this pipeline.",
    "attested_on": "2026-08-13",
    "limitation": "This attests to the pipeline's own inputs and to the publishers' stated "
    "process. It is not an independent audit of either upstream corpus.",
}


class ExcessiveLeakageError(ValueError):
    """The training split overlaps the eval split by more than a repairable margin.

    Dropping a handful of colliding rows repairs an upstream duplicate. Dropping thousands
    conceals a corpus that is wrong, and the repair would be indistinguishable from the fix
    in the manifest -- both read as "n rows excluded". So there is a ceiling, and crossing it
    is an error rather than a larger number in a summary.
    """


#: Above this fraction of the eval split, an overlap stops being an upstream duplicate and
#: starts being evidence the two splits are not what they claim to be. Deliberately a hard
#: constant and not a CLI flag: :mod:`warrantor_ml.leakage` makes the argument that a
#: threshold exposed as a knob is a threshold that gets turned until the corpus passes.
MAX_REPAIRABLE_LEAKAGE = 0.01


def _exclude_leaked_rows(
    rows: tuple[guard.GuardCorpusRow, ...],
    eval_prompts: Sequence[str],
) -> tuple[tuple[guard.GuardCorpusRow, ...], dict[str, Any]]:
    """Drop training rows whose normalised content appears in the eval split.

    The check belongs here rather than only in the parity gate. The gate runs after training,
    so a leaked corpus costs a full run before anything says so -- and the operator's only
    remaining repair at that point is to hand-edit a JSONL the manifest has already digested.

    Raises:
        ExcessiveLeakageError: the overlap exceeds :data:`MAX_REPAIRABLE_LEAKAGE`.
    """

    eval_fingerprints = {content_fingerprint(text) for text in eval_prompts}
    kept: list[guard.GuardCorpusRow] = []
    excluded: list[str] = []
    for row in rows:
        if content_fingerprint(row.prompt) in eval_fingerprints:
            excluded.append(row.row_id)
        else:
            kept.append(row)

    overlap_fraction = len(excluded) / len(eval_fingerprints) if eval_fingerprints else 0.0
    if overlap_fraction > MAX_REPAIRABLE_LEAKAGE:
        raise ExcessiveLeakageError(
            f"{len(excluded)} training row(s) match {len(eval_fingerprints)} eval fingerprint(s) "
            f"-- {overlap_fraction:.2%} of the eval split, above the {MAX_REPAIRABLE_LEAKAGE:.0%} "
            "ceiling. At this size the overlap is not an upstream duplicate to be repaired: the "
            "two splits are not the held-out pair they are being treated as. Excluding the rows "
            "would leave a corpus that passes the gate and an eval set that measures "
            "memorisation. Check that --eval-rows is the split the recipe's baseline was "
            "measured on."
        )

    report = {
        "eval_rows_fingerprinted": len(eval_fingerprints),
        "excluded_row_count": len(excluded),
        "overlap_fraction_of_eval": overlap_fraction,
        # Bounded: the count is the finding, the ids are for whoever has to look one up.
        "excluded_row_ids": sorted(excluded)[:20],
    }
    return tuple(kept), report


def build_guard_corpus(
    rows: tuple[guard.GuardCorpusRow, ...],
    selector: str,
    benign_ratio: float,
    output: Path,
    dataset_id: str,
    split: str,
    eval_prompts: Sequence[str] | None = None,
) -> tuple[DatasetManifest, dict[str, Any]]:
    """Select, render and write a guard corpus, returning its manifest and a summary.

    Args:
        eval_prompts: the held-out split the parity gate will score against. When given, rows
            colliding with it are excluded before selection and the exclusion is recorded in
            the manifest. When ``None``, no claim about hold-out is made or recorded.

    Raises:
        ManifestRefused: the manifest describes a corpus that must not be trained on.
        guard.MissingCorpusFieldError: the selector needs a column this split does not carry.
        ExcessiveLeakageError: the overlap with ``eval_prompts`` is too large to repair.
    """

    leakage_note: str
    leakage_report_body: dict[str, Any] | None = None
    if eval_prompts is None:
        # Recorded as absent rather than omitted. A manifest that is silent about hold-out
        # reads the same as one that checked and found nothing, and they are different facts.
        leakage_note = (
            "hold-out NOT verified at build time: no eval split was supplied to the builder. "
            "The parity gate performs its own leakage check and will refuse the candidate if "
            "this corpus overlaps the eval set."
        )
    else:
        rows, leakage_report_body = _exclude_leaked_rows(rows, eval_prompts)
        leakage_note = (
            f"hold-out verified at build time against {leakage_report_body['eval_rows_fingerprinted']}"
            f" eval fingerprint(s); {leakage_report_body['excluded_row_count']} training row(s) "
            f"excluded for collision ({leakage_report_body['overlap_fraction_of_eval']:.4%} of the "
            "eval split). Comparison is over NFKC-folded content, not row ids."
        )

    if selector == "weak-category":
        selected = guard.weak_category_subset(rows, benign_ratio)
    elif selector == "adversarial":
        selected = guard.adversarial_subset(rows, benign_ratio)
    else:
        raise ValueError(f"unknown guard selector {selector!r}; use weak-category or adversarial")

    pairs, dropped = guard.build_guard_pairs(selected, selector)
    digest = guard.write_pairs_jsonl(pairs, output)

    manifest = DatasetManifest(
        corpus_id=f"guard-{selector}-{dataset_id}-{split}",
        task="guard",
        built_for_split="train",
        sources=(
            corpus_source(
                dataset_id,
                split,
                row_count=len(pairs),
                content_digest=digest,
                notes=(
                    f"selector={selector}, benign_ratio={benign_ratio}, "
                    f"{len(dropped)} row(s) dropped for an absent or unrecognised label",
                    leakage_note,
                ),
            ),
        ),
        csam_exclusion=CSAM_ATTESTATION,
        notes=(
            "Targets rendered in the exact two-line Safety:/Categories: shape that "
            "evaluate.parse_guard_response consumes, so the existing benchmarks can score the "
            "adapter without a second harness.",
        ),
    )
    validate_manifest(manifest, counted_rows={f"{dataset_id}:{split}": len(pairs)})
    summary = {
        "selected_rows": len(selected),
        "pairs_written": len(pairs),
        "dropped_unlabelled": len(dropped),
        "positives": sum(1 for pair in pairs if pair.unsafe),
        "benign_counterweight": sum(1 for pair in pairs if not pair.unsafe),
        "content_digest": digest,
        "output": str(output),
        "leakage": leakage_report_body,
    }
    return manifest, summary


def build_parser() -> argparse.ArgumentParser:
    """CLI for ``warrantor-ml-build-corpus``."""

    parser = argparse.ArgumentParser(
        prog="warrantor-ml-build-corpus",
        description="Build a training corpus and its provenance manifest. Describes first.",
    )
    parser.add_argument("--task", choices=TASKS, required=True)
    parser.add_argument(
        "--rows",
        type=Path,
        help="JSONL or parquet split to read (parquet needs the [parquet] extra)",
    )
    parser.add_argument(
        "--describe-only",
        action="store_true",
        help="print the corpus schema and exit WITHOUT selecting or writing anything",
    )
    parser.add_argument(
        "--selector",
        choices=("weak-category", "adversarial"),
        help="guard task only: which axis to build",
    )
    parser.add_argument(
        "--benign-ratio",
        type=float,
        help="guard task only: benign rows per selected positive. REQUIRED -- there is no "
        "default, because an adapter trained on positives alone buys recall with the "
        "false-positive rate the parity gate then refuses it for",
    )
    parser.add_argument(
        "--eval-rows",
        type=Path,
        help="the held-out split the parity gate will score against. Colliding training rows "
        "are excluded before selection and the exclusion is recorded in the manifest. Omit it "
        "and the manifest says hold-out was not verified -- the gate will still check, but "
        "only after a full training run has already been spent",
    )
    parser.add_argument("--dataset-id", default="wildguardmix")
    parser.add_argument("--split", default="train")
    parser.add_argument("--out", type=Path, help="write the JSONL corpus here")
    parser.add_argument("--manifest", type=Path, help="write the provenance manifest here")
    return parser


def _load_rows(path: Path) -> tuple[guard.GuardCorpusRow, ...]:
    """Read a split from whichever format it is in."""

    if path.suffix == ".parquet":
        return guard.load_rows_parquet(path)
    return guard.load_rows_jsonl(path)


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``warrantor-ml-build-corpus``."""

    arguments = build_parser().parse_args(argv)

    if arguments.task != "guard":
        # The four substrate corpora are built from warrant artifacts, and there are none in
        # this repository yet. Saying so is more useful than emitting an empty file that looks
        # like a corpus.
        print(
            f"task {arguments.task!r}: the builder, label vocabulary and metric are implemented "
            f"in warrantor_ml.tasks.{arguments.task}, but there is no corpus of real warrants "
            "in this repository to build from -- a handful of fixtures, nothing like a training "
            "set. Supply warrant artifacts and call the builder directly; the parity gate will "
            "return insufficient_evidence until the positive counts clear its floor.",
        )
        return 0

    if arguments.rows is None:
        build_parser().error("--rows is required for the guard task")
    rows = _load_rows(arguments.rows)

    if arguments.describe_only:
        print(json.dumps(guard.describe_split(rows), indent=2, ensure_ascii=False))
        return 0

    if arguments.selector is None or arguments.benign_ratio is None:
        build_parser().error(
            "--selector and --benign-ratio are both required. --benign-ratio has no default on "
            "purpose: zero is a legitimate choice and it has to be written down"
        )
    if arguments.out is None:
        build_parser().error("--out is required unless --describe-only")

    eval_prompts: Sequence[str] | None = None
    if arguments.eval_rows is not None:
        eval_prompts = tuple(row.prompt for row in _load_rows(arguments.eval_rows))

    try:
        manifest, summary = build_guard_corpus(
            rows,
            arguments.selector,
            arguments.benign_ratio,
            arguments.out,
            arguments.dataset_id,
            arguments.split,
            eval_prompts=eval_prompts,
        )
    except (ManifestRefused, guard.MissingCorpusFieldError, ExcessiveLeakageError) as error:
        print(f"\nCORPUS NOT BUILT\n{error}")
        return 2

    summary["manifest_digest"] = manifest.manifest_digest
    summary["commercially_cleared"] = manifest.commercially_cleared
    summary["frontier_lineage"] = list(manifest.frontier_lineage)
    print(json.dumps(summary, indent=2, ensure_ascii=False))

    if arguments.manifest is not None:
        body = manifest.to_dict()
        body["manifest_digest"] = manifest.manifest_digest
        body["generated_at"] = datetime.now(UTC).isoformat()
        arguments.manifest.parent.mkdir(parents=True, exist_ok=True)
        arguments.manifest.write_text(
            json.dumps(body, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"manifest: {arguments.manifest}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
