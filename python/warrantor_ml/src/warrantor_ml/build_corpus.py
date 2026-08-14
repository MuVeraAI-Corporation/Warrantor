"""Build a training corpus for one of the nine recipes, with its provenance manifest.

``--describe-only`` exists to be run first and is not a convenience. ``benchmark_expguard``'s
own history is the argument: the plan said the legal vertical was spelled ``legal`` and that a
general band existed, and the corpus disagreed on both counts. Only inspecting the split showed
it, and nothing about a selector written against the wrong spelling looks broken -- it just
selects nothing, which is indistinguishable from a corpus that has none.

Nothing here trains anything and nothing dispatches a job. It reads a split, selects rows,
renders pairs, writes JSONL, and emits a manifest that :func:`warrantor_ml.manifest.validate_manifest`
has already refused or accepted.

``--recipe`` is the flag that makes the declaration true
--------------------------------------------------------
:class:`warrantor_ml.recipes.Recipe` has always carried ``corpus_task``, ``corpus_selector`` and
``corpus_arguments``, and its digest has always covered them -- but nothing read them. This
module did not import ``recipes`` at all, so an operator hand-typed ``--selector`` and
``--benign-ratio`` and nothing ever compared the corpus that got built to the recipe that
claimed to specify it. A recipe's stated ``benign_ratio`` of 1.0 and a corpus built at 0.0 were
indistinguishable downstream: ``--manifest-digest`` is a free-form string the parity gate copies
into its evidence and never validates against anything.

``--recipe <id>`` closes that by building FROM the declaration: task, selector, benign ratio,
target categories, dataset id and split all come off the recipe, and the manifest records the
recipe id and digest that produced the corpus. Passing a flag that contradicts the recipe is a
refusal, not an override -- an override would restore exactly the gap this closes.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .leakage import content_fingerprint
from .manifest import DatasetManifest, ManifestRefused, corpus_source, validate_manifest
from .recipes import Recipe, get_recipe
from .tasks import guard

__all__ = [
    "SELECTOR_ARGUMENTS",
    "SELECTOR_FUNCTIONS",
    "CorpusPlan",
    "CorpusSpecificationError",
    "ExcessiveLeakageError",
    "RecipeUnbuildableError",
    "build_guard_corpus",
    "build_parser",
    "main",
    "plan_from_recipe",
]

TASKS = ("guard", "bounds", "triage", "effects", "summary")

#: The CLI's selector names, mapped to the ``module:function`` strings recipes record. Two
#: spellings of one choice, so the mapping is data and the reverse lookup can refuse rather than
#: fall through to a default.
SELECTOR_FUNCTIONS: dict[str, str] = {
    "weak-category": "warrantor_ml.tasks.guard:weak_category_subset",
    "adversarial": "warrantor_ml.tasks.guard:adversarial_subset",
}

#: Exactly which ``corpus_arguments`` keys each selector consumes. Checked rather than assumed:
#: ``adversarial_subset`` takes no ``categories``, so a recipe that declared some would be making
#: a targeting claim the builder silently drops -- and a dropped declaration reads, in the
#: manifest and the recipe digest alike, exactly like an honoured one.
SELECTOR_ARGUMENTS: dict[str, frozenset[str]] = {
    "weak-category": frozenset({"benign_ratio", "categories"}),
    "adversarial": frozenset({"benign_ratio"}),
}


class CorpusSpecificationError(ValueError):
    """The requested selection cannot be honoured exactly as asked for.

    Distinct from :class:`~warrantor_ml.tasks.guard.MissingCorpusFieldError`, which says the
    corpus lacks something. This says the *request* is incoherent -- an unknown selector, or a
    category list handed to a selector that does not read one. Both would otherwise be absorbed:
    an unknown selector by a fall-through, a dropped category list by a manifest that records the
    targeting claim anyway.
    """


class RecipeUnbuildableError(ValueError):
    """The named recipe does not describe a corpus this builder can construct.

    Raised rather than falling back to CLI defaults. A recipe whose declaration cannot be
    executed is a recipe whose declaration is decoration, and quietly substituting the flag
    defaults for it would rebuild the very gap ``--recipe`` exists to close.
    """


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


@dataclass(frozen=True)
class CorpusPlan:
    """A fully resolved corpus build: every input the builder needs, and where each came from.

    Produced either from a recipe (:func:`plan_from_recipe`) or from explicit flags. Having one
    type for both is what lets the CLI refuse a flag that contradicts a recipe instead of
    silently letting one win.
    """

    selector: str
    benign_ratio: float
    categories: tuple[str, ...]
    dataset_id: str
    split: str
    recipe_id: str = ""
    recipe_digest: str = ""


def plan_from_recipe(recipe: Recipe) -> CorpusPlan:
    """Resolve a recipe's declared corpus specification into a buildable plan.

    Raises:
        RecipeUnbuildableError: the recipe is not a guard recipe, names a selector this builder
            has no implementation for, or carries ``corpus_arguments`` keys the selector does not
            consume (or is missing ones it requires).
    """

    if recipe.corpus_task != "guard":
        raise RecipeUnbuildableError(
            f"{recipe.recipe_id}: corpus_task is {recipe.corpus_task!r}, and the substrate "
            "corpora are built from warrant artifacts, of which this repository has a handful of "
            "fixtures and nothing like a training set. There is nothing for --recipe to build"
        )

    matches = [key for key, value in SELECTOR_FUNCTIONS.items() if value == recipe.corpus_selector]
    if not matches:
        known = ", ".join(f"{key} -> {value}" for key, value in sorted(SELECTOR_FUNCTIONS.items()))
        raise RecipeUnbuildableError(
            f"{recipe.recipe_id}: corpus_selector {recipe.corpus_selector!r} has no "
            f"implementation in this builder. Declared selectors: {known}"
        )
    selector = matches[0]

    declared = set(recipe.corpus_arguments)
    expected = SELECTOR_ARGUMENTS[selector]
    if declared != expected:
        raise RecipeUnbuildableError(
            f"{recipe.recipe_id}: corpus_arguments {sorted(declared)} do not match what the "
            f"{selector!r} selector consumes ({sorted(expected)}). An unread argument is a "
            "declaration nothing honours, and an absent one is a default the recipe digest does "
            "not cover -- both of them let the recipe and the corpus disagree in silence"
        )

    ratio = recipe.corpus_arguments["benign_ratio"]
    if not isinstance(ratio, int | float) or isinstance(ratio, bool):
        raise RecipeUnbuildableError(
            f"{recipe.recipe_id}: corpus_arguments['benign_ratio'] is {ratio!r}, not a number"
        )

    categories = tuple(str(name) for name in recipe.corpus_arguments.get("categories", ()))
    return CorpusPlan(
        selector=selector,
        benign_ratio=float(ratio),
        categories=categories,
        dataset_id=recipe.config.dataset_id,
        split=recipe.config.dataset_split,
        recipe_id=recipe.recipe_id,
        recipe_digest=recipe.recipe_digest,
    )


def build_guard_corpus(
    rows: tuple[guard.GuardCorpusRow, ...],
    selector: str,
    benign_ratio: float,
    output: Path,
    dataset_id: str,
    split: str,
    eval_prompts: Sequence[str] | None = None,
    categories: Sequence[str] | None = None,
    recipe_id: str = "",
    recipe_digest: str = "",
) -> tuple[DatasetManifest, dict[str, Any]]:
    """Select, render and write a guard corpus, returning its manifest and a summary.

    Args:
        eval_prompts: the held-out split the parity gate will score against. When given, rows
            colliding with it are excluded before selection and the exclusion is recorded in
            the manifest. When ``None``, no claim about hold-out is made or recorded.
        categories: which harm classes the weak-category selector targets. ``None`` falls back to
            :data:`warrantor_ml.tasks.guard.WEAK_CATEGORIES`, and the resolved list is written
            into the manifest either way. That last part is the point: on ExpGuardTrain the
            fallback selects exactly one class, not because anyone chose one but because the
            other three entries are WildGuard spellings that happen not to match. A corpus that
            is correct by luck is not a corpus that is specified, so the manifest records what
            was actually targeted rather than the name of a default.
        recipe_id: the recipe this corpus was built from, recorded in the manifest so the
            declaration and the artifact can be checked against each other after the fact.
        recipe_digest: that recipe's digest at build time.

    Raises:
        CorpusSpecificationError: the selector is unknown, or ``categories`` was given for a
            selector that does not read them.
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
        resolved_categories = (
            tuple(guard.WEAK_CATEGORIES) if categories is None else tuple(categories)
        )
        selected = guard.weak_category_subset(rows, benign_ratio, categories=resolved_categories)
    elif selector == "adversarial":
        if categories:
            raise CorpusSpecificationError(
                f"the adversarial selector does not read categories, so {list(categories)} would "
                "be dropped. The manifest would then record a targeting claim the corpus does "
                "not honour"
            )
        resolved_categories = ()
        selected = guard.adversarial_subset(rows, benign_ratio)
    else:
        raise CorpusSpecificationError(
            f"unknown guard selector {selector!r}; use weak-category or adversarial"
        )

    pairs, dropped = guard.build_guard_pairs(selected, selector)
    digest = guard.write_pairs_jsonl(pairs, output)

    provenance_note = (
        f"built from recipe {recipe_id} ({recipe_digest})"
        if recipe_id
        else "built from CLI flags, not from a recipe: no declared corpus specification stands "
        "behind these arguments. Pass --recipe to bind the corpus to a digested declaration"
    )
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
                    # Verbatim and always, including the fallback. The category list is the
                    # single fact that decides what the corpus is FOR, and it used to live
                    # nowhere but a module-level default the recipe digest did not cover.
                    "categories targeted: "
                    + (", ".join(resolved_categories) if resolved_categories else "n/a"),
                    provenance_note,
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
        "categories": list(resolved_categories),
        "recipe_id": recipe_id,
        "recipe_digest": recipe_digest,
    }
    return manifest, summary


def build_parser() -> argparse.ArgumentParser:
    """CLI for ``warrantor-ml-build-corpus``."""

    parser = argparse.ArgumentParser(
        prog="warrantor-ml-build-corpus",
        description="Build a training corpus and its provenance manifest. Describes first.",
    )
    parser.add_argument(
        "--recipe",
        help="build from a recipe's DECLARED corpus specification: task, selector, benign ratio, "
        "target categories, dataset id and split all come off the recipe and the manifest records "
        "its digest. Any of those flags passed alongside --recipe is a refusal, never an "
        "override: an override would restore the gap where the recipe says benign_ratio=1.0 and "
        "the corpus was built at 0.0 with nothing downstream able to tell",
    )
    parser.add_argument(
        "--task",
        choices=TASKS,
        help="required unless --recipe is given, which carries the task",
    )
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
    parser.add_argument(
        "--category",
        action="append",
        dest="categories",
        help="guard weak-category selector only, repeatable: which harm class to target. "
        "Defaults to guard.WEAK_CATEGORIES, which is four names in TWO vocabularies -- on "
        "ExpGuardTrain three of them match nothing and the default therefore selects one class "
        "by accident. Name them, or pass --recipe and let the digested declaration name them",
    )
    parser.add_argument(
        "--dataset-id",
        # No default. It used to be `wildguardmix`, and `manifest.corpus_source` reads licence,
        # attribution and frontier lineage purely from this id -- so `--rows expguardtrain.parquet`
        # without overriding it produced a manifest that PASSED validation while declaring ODC-By
        # instead of CC-BY-4.0, attributing AI2 instead of the ExpGuard authors, and omitting the
        # GPT-4o lineage. Nothing cross-checks the loaded file against the declared id, so the
        # only defence is that the id must be written down.
        help="the registry id of the corpus --rows came from. REQUIRED on the build path: the "
        "manifest's licence, attribution and frontier lineage are all derived from it and "
        "nothing reconciles them against the file actually loaded",
    )
    parser.add_argument("--split", default=None, help="registry split name (default: train)")
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

    plan: CorpusPlan | None = None
    if arguments.recipe is not None:
        conflicting = [
            flag
            for flag, value in (
                ("--selector", arguments.selector),
                ("--benign-ratio", arguments.benign_ratio),
                ("--category", arguments.categories),
                ("--dataset-id", arguments.dataset_id),
                ("--split", arguments.split),
            )
            if value is not None
        ]
        if arguments.task is not None and arguments.task != "guard":
            conflicting.append("--task")
        if conflicting:
            build_parser().error(
                f"{', '.join(conflicting)} cannot be combined with --recipe. The recipe carries "
                "the corpus specification and its digest covers it; a flag that silently won "
                "over the declaration is exactly the disagreement --recipe exists to prevent. "
                "Drop the flag, or edit the recipe and accept the new digest"
            )
        try:
            plan = plan_from_recipe(get_recipe(arguments.recipe))
        except (KeyError, RecipeUnbuildableError) as error:
            print(f"\nCORPUS NOT BUILT\n{error.args[0] if error.args else error}")
            return 2
        arguments.task = "guard"

    if arguments.task is None:
        build_parser().error("one of --task or --recipe is required")

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

    if plan is None:
        if arguments.selector is None or arguments.benign_ratio is None:
            build_parser().error(
                "--selector and --benign-ratio are both required. --benign-ratio has no default "
                "on purpose: zero is a legitimate choice and it has to be written down"
            )
        if arguments.dataset_id is None:
            build_parser().error(
                "--dataset-id is required. It used to default to 'wildguardmix', which meant "
                "building from expguardtrain.parquet produced a manifest that validated cleanly "
                "while declaring the wrong licence, the wrong attribution and no GPT-4o lineage "
                "-- because manifest.corpus_source derives all three from this id and nothing "
                "reconciles them against the file. Pass --recipe to have it come off a "
                "declaration instead"
            )
        plan = CorpusPlan(
            selector=arguments.selector,
            benign_ratio=arguments.benign_ratio,
            categories=tuple(arguments.categories or ()),
            dataset_id=arguments.dataset_id,
            split=arguments.split or "train",
        )

    if arguments.out is None:
        build_parser().error("--out is required unless --describe-only")

    eval_prompts: Sequence[str] | None = None
    if arguments.eval_rows is not None:
        eval_prompts = tuple(row.prompt for row in _load_rows(arguments.eval_rows))

    try:
        manifest, summary = build_guard_corpus(
            rows,
            plan.selector,
            plan.benign_ratio,
            arguments.out,
            plan.dataset_id,
            plan.split,
            eval_prompts=eval_prompts,
            categories=plan.categories or None,
            recipe_id=plan.recipe_id,
            recipe_digest=plan.recipe_digest,
        )
    except (
        ManifestRefused,
        guard.MissingCorpusFieldError,
        ExcessiveLeakageError,
        CorpusSpecificationError,
    ) as error:
        # Four named ways a corpus can be wrong, one exit code. Named rather than a bare
        # ValueError so a genuine bug in this module still surfaces as a traceback instead of
        # being printed as a corpus refusal -- which would read as the pipeline working.
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
