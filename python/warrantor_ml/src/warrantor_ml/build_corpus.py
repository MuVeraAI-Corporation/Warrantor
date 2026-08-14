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

A declaration is not provenance until the file is checked against it
-------------------------------------------------------------------
``--recipe`` alone made the gap worse rather than better in one specific way:
``--recipe guard-4b-weak-category --rows expguardtrain.parquet`` took the dataset id off a
WildGuard recipe, read ExpGuard rows, and stamped the manifest with the recipe's digest -- a
document declaring ODC-By-1.0, attributing AI2, carrying no GPT-4o lineage, and *reading as
verified*. :func:`reconcile_rows_with_declared_split` compares the file handed to ``--rows``
against :attr:`warrantor_ml.datasets.SplitSpec.remote_path` and refuses on a mismatch, and the
same check runs on ``--eval-rows`` because "hold-out verified" about an unnamed file is the same
kind of sentence. It is a filename check, and the manifest says so rather than implying more.

Likewise the category list: a four-class request that matches one class is refused, and the
manifest records the classes that MATCHED with the count of rows behind each. What was asked for
and what the split answered are two facts, and they used to be written down as one.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from .datasets import UnknownDatasetError, get_dataset
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
    "RowsNotTheDeclaredSplitError",
    "build_guard_corpus",
    "build_parser",
    "main",
    "plan_from_recipe",
    "reconcile_rows_with_declared_split",
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


class RowsNotTheDeclaredSplitError(ValueError):
    """``--rows`` is not the file the declared dataset and split name.

    The manifest's licence, attribution and frontier lineage are derived entirely from the
    dataset id -- so ``--recipe guard-4b-weak-category --rows expguardtrain.parquet`` produced a
    manifest that PASSED :func:`~warrantor_ml.manifest.validate_manifest` while declaring
    ODC-By-1.0, attributing AI2 and omitting the GPT-4o lineage of the corpus actually read.
    Making the id come off a digested recipe rather than a flag did not close that: it removed
    the flag that could have contradicted the file and stamped the manifest with a recipe digest,
    which reads as provenance nobody checked.

    The registry already knows which file each split is: :attr:`~warrantor_ml.datasets.SplitSpec.
    remote_path`. So compare, and refuse.
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


def _split_owning_file(file_name: str) -> str:
    """Which registered ``dataset:split`` publishes a file of this name, if any.

    Named in the refusal because "wrong file" is much less useful than "that is the file
    expguardmix:train publishes", which names both the mistake and the fix.
    """

    from .datasets import REGISTRY

    stem = PurePosixPath(file_name).stem
    for spec in REGISTRY.values():
        for candidate in spec.splits:
            if PurePosixPath(candidate.remote_path).stem == stem:
                return f"{spec.dataset_id}:{candidate.name}"
    return ""


def reconcile_rows_with_declared_split(rows_path: Path, dataset_id: str, split: str) -> str:
    """Check the loaded file against the split the manifest is about to claim it came from.

    Returns the note recorded verbatim in the manifest, so the strength of the claim travels
    with it: this is a filename comparison against
    :attr:`warrantor_ml.datasets.SplitSpec.remote_path`, not a content check. No published
    digest of either upstream parquet exists in this repository to compare bytes against, so it
    catches the wrong file and cannot catch a renamed one. Saying which it is beats a manifest
    line that reads as verification.

    A different container for the same split (``expguardtrain.jsonl`` for
    ``expguardtrain.parquet``) is accepted, because both loaders normalise onto
    :func:`warrantor_ml.tasks.guard.rows_from_columns` and the conversion is a real workflow. A
    different *stem* is refused.

    Raises:
        RowsNotTheDeclaredSplitError: the file is not the declared split's file.
        warrantor_ml.datasets.UnknownDatasetError: the dataset id or split is not registered --
            which ``manifest.corpus_source`` would refuse a few lines later anyway, since it
            reads the licence from the same registry.
    """

    spec = get_dataset(dataset_id)
    declared = spec.split(split)
    expected = PurePosixPath(declared.remote_path).name
    actual = rows_path.name
    verified = (
        f"source file reconciled against the registry: --rows {actual} matches the file "
        f"{dataset_id}:{split} declares ({declared.remote_path}). FILENAME check only -- no "
        "published content digest exists to compare the bytes against, so this catches the "
        "wrong file and cannot catch a renamed one."
    )
    if actual == expected:
        return verified
    if PurePosixPath(actual).stem == PurePosixPath(expected).stem:
        return (
            f"{verified} Loaded as {actual}, a {rows_path.suffix or 'suffixless'} rendering of "
            f"the declared {expected}; both loaders normalise onto the same row type."
        )

    owner = _split_owning_file(actual)
    belongs = f" That filename is what {owner} publishes." if owner else ""
    raise RowsNotTheDeclaredSplitError(
        f"--rows {actual} is not the file {dataset_id}:{split} declares ({expected})."
        f"{belongs} The manifest's licence, attribution and frontier lineage are derived from "
        f"the dataset id alone, so building this would produce a document that validates and is "
        f"false -- {spec.licence} and the {spec.dataset_id} attribution stamped on rows from "
        "somewhere else. Point --rows at the declared split, or build under the recipe/id that "
        "names the corpus you actually have"
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
    rows_path: Path | None = None,
    eval_rows_path: Path | None = None,
) -> tuple[DatasetManifest, dict[str, Any]]:
    """Select, render and write a guard corpus, returning its manifest and a summary.

    Args:
        eval_prompts: the held-out split the parity gate will score against. When given, rows
            colliding with it are excluded before selection and the exclusion is recorded in
            the manifest. When ``None``, no claim about hold-out is made or recorded.
        categories: which harm classes the weak-category selector targets, as an explicit
            request. Every named class must match rows in this split: a request that matches
            three of four is refused, because ``weak_category_subset`` refuses only when NONE
            match and the corpus it returns for a partial match is indistinguishable from one
            that honoured the whole request. ``None`` falls back to
            :data:`warrantor_ml.tasks.guard.WEAK_CATEGORIES`, which is a measured table spanning
            two corpus vocabularies rather than a request, so absent classes there are recorded
            by name with their zero counts instead of refused.
        recipe_id: the recipe this corpus was built from, recorded in the manifest so the
            declaration and the artifact can be checked against each other after the fact.
        recipe_digest: that recipe's digest at build time.
        rows_path: where ``rows`` were loaded from, reconciled against the file
            ``dataset_id``/``split`` declares. ``None`` records that no such check was possible
            -- rows handed over in memory cannot be traced to a file -- rather than leaving the
            manifest silent, which would read the same as a check that passed.
        eval_rows_path: where ``eval_prompts`` came from, reconciled against the ``test`` split
            of the same dataset. The hold-out sentence names a file or says it cannot.

    Raises:
        CorpusSpecificationError: the selector is unknown, ``categories`` was given for a
            selector that does not read them, or a requested class matches no rows.
        RowsNotTheDeclaredSplitError: ``rows_path`` or ``eval_rows_path`` is not the declared
            split's file.
        ManifestRefused: the manifest describes a corpus that must not be trained on.
        guard.MissingCorpusFieldError: the selector needs a column this split does not carry.
        ExcessiveLeakageError: the overlap with ``eval_prompts`` is too large to repair.
    """

    if rows_path is None:
        source_file_note = (
            "source file NOT reconciled: rows were supplied in memory, so there is no filename "
            "to compare against the split this manifest names. The licence, attribution and "
            "frontier lineage below are derived from the dataset id and nothing has checked "
            "them against the rows"
        )
    else:
        source_file_note = reconcile_rows_with_declared_split(rows_path, dataset_id, split)

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
        # Which file the hold-out claim is about. "Verified against 2,275 fingerprints" is a
        # reassuring sentence about an unnamed file, and an unrelated file produces the same
        # sentence with zero collisions.
        if eval_rows_path is None:
            eval_source_note = (
                " The eval rows were supplied in memory and are NOT reconciled to a registered "
                "split, so this states non-overlap with whatever was handed in."
            )
        else:
            eval_source_note = " Eval split: " + reconcile_rows_with_declared_split(
                eval_rows_path, dataset_id, "test"
            )
        rows, leakage_report_body = _exclude_leaked_rows(rows, eval_prompts)
        leakage_note = (
            f"hold-out verified at build time against {leakage_report_body['eval_rows_fingerprinted']}"
            f" eval fingerprint(s); {leakage_report_body['excluded_row_count']} training row(s) "
            f"excluded for collision ({leakage_report_body['overlap_fraction_of_eval']:.4%} of the "
            "eval split). Comparison is over NFKC-folded content, not row ids." + eval_source_note
        )

    matched_counts: dict[str, int] = {}
    absent: tuple[str, ...] = ()
    if selector == "weak-category":
        requested = categories is not None
        resolved_categories = (
            tuple(guard.WEAK_CATEGORIES) if categories is None else tuple(categories)
        )
        matched_counts = guard.category_positive_counts(rows, resolved_categories)
        absent = tuple(name for name, count in matched_counts.items() if count == 0)
        if absent and requested:
            vocabulary = sorted({row.subcategory for row in rows if row.subcategory})[:20]
            raise CorpusSpecificationError(
                f"{len(absent)} of {len(resolved_categories)} requested categories match no "
                f"unsafe row in this split: {list(absent)}. Matched: "
                f"{ {name: count for name, count in matched_counts.items() if count} }. "
                "weak_category_subset refuses only when NONE match, so this would have built a "
                "corpus covering "
                f"{len(resolved_categories) - len(absent)} class(es) under a declaration naming "
                f"{len(resolved_categories)} -- and a dropped target reads in the manifest, and "
                "in the recipe digest, exactly like an honoured one. The split's vocabulary "
                f"begins: {vocabulary}. Name the classes this corpus carries, or build the "
                "declared classes from the corpus that has them"
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
    # MATCHED, with the count that proves each match -- not the list that was asked for. The
    # request and the result used to be recorded as one string, so a four-class declaration that
    # matched one class was written down as four.
    matched = ", ".join(f"{name}={count}" for name, count in matched_counts.items() if count)
    matched_note = f"categories targeted: {matched or 'n/a'}" + (
        " -- each name with the number of unsafe rows it matched" if matched else ""
    )
    category_notes: tuple[str, ...] = (matched_note,)
    if absent:
        category_notes += (
            "categories in the default list that this split does NOT carry (0 unsafe rows "
            f"matched, nothing was selected for them): {', '.join(absent)}. The default is "
            "guard.WEAK_CATEGORIES, a measured table spanning both corpus vocabularies rather "
            "than a request; an explicitly requested class that matched nothing is a refusal, "
            "not a note",
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
                    # Verbatim and always, including the fallback. What the corpus is FOR is the
                    # single fact that used to live nowhere but a module-level default the recipe
                    # digest did not cover.
                    *category_notes,
                    provenance_note,
                    source_file_note,
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
        # The result beside the request, always. `categories` is what was asked for and
        # `categories_matched` is what the split answered with; reporting only the first is how
        # a one-class corpus was recorded as a four-class one.
        "categories_matched": dict(matched_counts),
        "categories_absent": list(absent),
        "recipe_id": recipe_id,
        "recipe_digest": recipe_digest,
        "source_file": str(rows_path) if rows_path is not None else None,
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
        help="JSONL or parquet split to read (parquet needs the [parquet] extra). Its filename "
        "must be the one the registry declares for the dataset/split being built -- a different "
        "container for the same split is fine, a different split is a refusal, because the "
        "manifest's licence and attribution come off the id and nothing else compares them to "
        "the file",
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
        help="the held-out split the parity gate will score against, reconciled against the "
        "registry's TEST split for the same dataset. Colliding training rows are excluded before "
        "selection and the exclusion is recorded in the manifest. Omit it and the manifest says "
        "hold-out was not verified -- the gate will still check, but only after a full training "
        "run has already been spent",
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

    if arguments.describe_only:
        print(
            json.dumps(
                guard.describe_split(_load_rows(arguments.rows)), indent=2, ensure_ascii=False
            )
        )
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

    # Before reading a 54 MB parquet, not after: the file either is the split the manifest will
    # name or it is not, and that is answerable from the registry and a filename. Repeated
    # inside build_guard_corpus, which is where the note comes from -- the function has to be
    # safe for a library caller too, and the check is pure.
    try:
        reconcile_rows_with_declared_split(arguments.rows, plan.dataset_id, plan.split)
        if arguments.eval_rows is not None:
            reconcile_rows_with_declared_split(arguments.eval_rows, plan.dataset_id, "test")
    except (RowsNotTheDeclaredSplitError, UnknownDatasetError) as error:
        print(f"\nCORPUS NOT BUILT\n{error.args[0] if error.args else error}")
        return 2

    rows = _load_rows(arguments.rows)

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
            rows_path=arguments.rows,
            eval_rows_path=arguments.eval_rows,
        )
    except (
        ManifestRefused,
        guard.MissingCorpusFieldError,
        ExcessiveLeakageError,
        CorpusSpecificationError,
        RowsNotTheDeclaredSplitError,
        UnknownDatasetError,
    ) as error:
        # Six named ways a corpus can be wrong, one exit code. Named rather than a bare
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
