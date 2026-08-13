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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .manifest import DatasetManifest, ManifestRefused, corpus_source, validate_manifest
from .tasks import guard

__all__ = ["build_guard_corpus", "build_parser", "main"]

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


def build_guard_corpus(
    rows: tuple[guard.GuardCorpusRow, ...],
    selector: str,
    benign_ratio: float,
    output: Path,
    dataset_id: str,
    split: str,
) -> tuple[DatasetManifest, dict[str, Any]]:
    """Select, render and write a guard corpus, returning its manifest and a summary.

    Raises:
        ManifestRefused: the manifest describes a corpus that must not be trained on.
        guard.MissingCorpusFieldError: the selector needs a column this split does not carry.
    """

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

    try:
        manifest, summary = build_guard_corpus(
            rows,
            arguments.selector,
            arguments.benign_ratio,
            arguments.out,
            arguments.dataset_id,
            arguments.split,
        )
    except (ManifestRefused, guard.MissingCorpusFieldError) as error:
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
