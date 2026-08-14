"""Read-only CLIs over the training programme: recipes, lanes, parity and script export.

Four entry points, none of which trains anything, downloads anything, or dispatches a job. They
answer the questions that have to be answerable before any of that happens:

* ``warrantor-ml-recipes`` -- what are the eight, and what is each one's digest?
* ``warrantor-ml-lanes`` -- will this recipe fit and finish on that lane?
* ``warrantor-ml-export`` -- render the standalone runner the orchestrator will upload.
* ``warrantor-ml-parity`` -- given a benchmark result document, promote or refuse.

They live in one module because they are one surface over the same declarative data, and four
near-identical argument parsers in four files is how three of them drift.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .lane_export import render_kaggle_script, render_modal_entrypoint
from .lanes import LANES, LaneUnsuitableError, resolve
from .leakage import LeakageReport, leakage_report
from .parity import load_candidate_result, parity_gate
from .recipes import get_recipe, list_recipes
from .tasks import guard

__all__ = [
    "export_main",
    "lanes_main",
    "parity_main",
    "recipes_main",
]


# ---------------------------------------------------------------------------
# recipes
# ---------------------------------------------------------------------------


def recipes_main(argv: list[str] | None = None) -> int:
    """Entry point for ``warrantor-ml-recipes``."""

    parser = argparse.ArgumentParser(
        prog="warrantor-ml-recipes",
        description="The eight training recipes, as data with a stable digest.",
    )
    parser.add_argument("--recipe", help="restrict to one recipe id")
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args(argv)

    selected = (get_recipe(arguments.recipe),) if arguments.recipe else list_recipes()
    if arguments.json:
        print(
            json.dumps(
                [
                    {**recipe.to_dict(), "recipe_digest": recipe.recipe_digest}
                    for recipe in selected
                ],
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0
    for recipe in selected:
        print(f"{recipe.recipe_id:26} {recipe.config.profile_key:22} {recipe.model_role}")
        print(f"  digest    {recipe.recipe_digest}")
        print(f"  corpus    {recipe.corpus_task} via {recipe.corpus_selector}")
        print(
            f"  gate      {recipe.baseline_id or '(no measured baseline yet)'}"
            + (f" [{recipe.gate_slice}]" if recipe.gate_slice else "")
        )
        for note in recipe.notes:
            print(f"  - {note}")
        print()
    return 0


# ---------------------------------------------------------------------------
# lanes
# ---------------------------------------------------------------------------


def lanes_main(argv: list[str] | None = None) -> int:
    """Entry point for ``warrantor-ml-lanes``. Refuses a recipe that cannot run on a lane."""

    parser = argparse.ArgumentParser(
        prog="warrantor-ml-lanes",
        description="Resolve a recipe against a compute lane. Pure arithmetic, no GPU touched.",
    )
    parser.add_argument("--recipe", help="recipe id; omit to list the lanes")
    parser.add_argument("--lane", choices=sorted(LANES), help="lane to resolve against")
    parser.add_argument(
        "--corpus-rows",
        type=int,
        help="rows the run will train on. REQUIRED -- there is no default, for the same reason "
        "--benign-ratio has none. This number drives the wall-clock estimate, the save_steps "
        "cadence AND the session-cap refusal, so a substituted one lets the router approve a "
        "lane for a corpus it was never shown. The cap exists to be discovered before the run, "
        "not at hour eleven",
    )
    parser.add_argument("--resume-from", help="a checkpoint, which permits a run over the cap")
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args(argv)

    if arguments.recipe is None:
        for lane in (LANES[key] for key in sorted(LANES)):
            precision, reason = lane.precision
            print(
                f"{lane.key:16} {lane.usable_vram_gib:>5.1f} GiB  {precision:5}  {lane.description}"
            )
            print(f"  session cap {lane.session_cap_hours}  weekly {lane.weekly_budget_hours}")
            print(f"  {reason}")
            for note in lane.notes:
                print(f"  - {note}")
            print()
        return 0

    if arguments.lane is None:
        parser.error("--lane is required when --recipe is given")
    if arguments.corpus_rows is None:
        parser.error(
            "--corpus-rows is required when --recipe is given. Build the corpus first and pass "
            "its pairs_written count; the session-cap refusal is only as true as this number"
        )

    recipe = get_recipe(arguments.recipe)
    try:
        resolution = resolve(
            recipe.config, arguments.lane, arguments.corpus_rows, arguments.resume_from
        )
    except LaneUnsuitableError as error:
        print(f"\nLANE REFUSED\n{error}")
        return 2

    if arguments.json:
        print(json.dumps({**resolution.to_dict(), "recipe_digest": recipe.recipe_digest}, indent=2))
        return 0
    print(f"recipe    {recipe.recipe_id}  ({recipe.recipe_digest})")
    print(f"lane      {resolution.lane.key}  precision={resolution.precision}")
    print(
        f"VRAM      {resolution.estimated_vram_gib:.2f} GiB of {resolution.lane.usable_vram_gib:.2f}"
    )
    print(f"wall      {resolution.estimated_hours:.2f} h  save_steps={resolution.save_steps}")
    print(f"          {resolution.precision_reason}")
    for warning in resolution.warnings:
        print(f"WARNING: {warning}")
    return 0


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------


def export_main(argv: list[str] | None = None) -> int:
    """Entry point for ``warrantor-ml-export``. Renders a runner; dispatches nothing."""

    parser = argparse.ArgumentParser(
        prog="warrantor-ml-export",
        description="Render a standalone lane runner from a recipe. Writes a file, runs nothing.",
    )
    parser.add_argument("--recipe", required=True)
    parser.add_argument("--lane", required=True, choices=sorted(LANES))
    parser.add_argument(
        "--corpus-rows",
        type=int,
        required=True,
        help="rows the run will train on. Required: it is embedded in the generated script's "
        "RUN_MANIFEST as the wall-clock estimate and sets save_steps, so a default writes a "
        "provenance record describing a run that was never planned",
    )
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args(argv)

    recipe = get_recipe(arguments.recipe)
    try:
        resolution = resolve(recipe.config, arguments.lane, arguments.corpus_rows, "checkpoint")
    except LaneUnsuitableError as error:
        print(f"\nLANE REFUSED\n{error}")
        return 2

    if arguments.lane.startswith("kaggle"):
        text = render_kaggle_script(recipe, resolution)
    elif arguments.lane == "modal-a100":
        text = render_modal_entrypoint(recipe, resolution)
    else:
        print(
            f"lane {arguments.lane!r} runs in-repo -- use `warrantor-ml-fine-tune` directly. "
            "Export exists for lanes that do not have this repository checked out."
        )
        return 2

    arguments.out.parent.mkdir(parents=True, exist_ok=True)
    arguments.out.write_text(text, encoding="utf-8")
    print(f"wrote {arguments.out} ({len(text)} bytes) for recipe {recipe.recipe_digest}")
    print("GENERATED FILE -- edit the recipe and regenerate, never the output.")
    return 0


# ---------------------------------------------------------------------------
# parity
# ---------------------------------------------------------------------------


def parity_main(argv: list[str] | None = None) -> int:
    """Entry point for ``warrantor-ml-parity``. Reads a result document, returns a verdict.

    Exit codes: 0 promote, 1 reject, 3 insufficient_evidence. The third is deliberately not 1 --
    "we could not tell" and "it did not work" call for different next actions, and a CI job that
    treats them the same will retry the wrong one.
    """

    parser = argparse.ArgumentParser(
        prog="warrantor-ml-parity",
        description="The blind parity gate. Promotes only on a two-sided significance test.",
    )
    parser.add_argument("--result", type=Path, required=True, help="benchmark result document")
    parser.add_argument("--recipe", required=True)
    parser.add_argument("--lane", required=True, choices=sorted(LANES))
    parser.add_argument("--precision", required=True)
    parser.add_argument("--manifest-digest", required=True)
    parser.add_argument(
        "--training-corpus",
        type=Path,
        help="the JSONL corpus the candidate trained on; required for the leakage check",
    )
    parser.add_argument(
        "--eval-corpus",
        type=Path,
        help="the eval split, parquet or JSONL. Prefer the parquet: it is what the splits "
        "actually are, and it removes the hand-export step where the text ends up under a key "
        "the leakage comparison does not read",
    )
    parser.add_argument(
        "--breakdown-key",
        default="wildguard_breakdowns",
        choices=("wildguard_breakdowns", "expguard_breakdowns"),
        help="which benchmark module produced the result document. Naming the wrong one does "
        "not silently compare across corpora: the gate binds the document's eval_set.source to "
        "the baseline's corpus by digest and returns insufficient_evidence when they differ",
    )
    parser.add_argument("--out", type=Path, help="write the decision document here")
    arguments = parser.parse_args(argv)

    recipe = get_recipe(arguments.recipe)
    try:
        candidate = load_candidate_result(
            arguments.result,
            candidate_id=recipe.recipe_id,
            baseline_id=recipe.baseline_id,
            lane=arguments.lane,
            precision=arguments.precision,
            manifest_digest=arguments.manifest_digest,
            breakdown_key=arguments.breakdown_key,
        )
    except ValueError as error:
        # A document the gate cannot read is evidence it could not evaluate, not a candidate it
        # rejected. Exit 3, because 1 is reserved for `reject` and a CI job that conflates them
        # retries the wrong one. The usual cause is --breakdown-key naming the other benchmark.
        print(f"INSUFFICIENT EVIDENCE\n{error}")
        return 3

    if arguments.training_corpus and arguments.eval_corpus:
        leakage = leakage_report(
            _read_corpus(arguments.training_corpus), _read_corpus(arguments.eval_corpus)
        )
    else:
        # Not checking is not the same as checking and finding nothing. An unchecked corpus is
        # reported as a blocking precondition, so the gate cannot silently skip it.
        leakage = LeakageReport(
            {
                "training_rows_fingerprinted": 0,
                "eval_rows_fingerprinted": 0,
                "distinct_collisions": 0,
                "overlapping_eval_rows": 1,
                "overlap_fraction_of_eval": 0.0,
                "examples": [],
                "note": "LEAKAGE WAS NOT CHECKED: --training-corpus and --eval-corpus were not "
                "both supplied. Recorded as an overlap so the gate refuses rather than "
                "promoting on an unverified held-out claim.",
            }
        )

    decision = parity_gate(candidate, recipe.gate_slice or "overall", leakage)
    body = decision.to_dict()
    body["decision_digest"] = decision.decision_digest
    body["recipe_digest"] = recipe.recipe_digest
    print(json.dumps(body, indent=2, ensure_ascii=False))

    if arguments.out is not None:
        arguments.out.parent.mkdir(parents=True, exist_ok=True)
        arguments.out.write_text(
            json.dumps(body, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"decision: {arguments.out}")

    return {"promote": 0, "reject": 1, "insufficient_evidence": 3}[decision.verdict]


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    """Read a JSONL corpus for the leakage comparison."""

    rows: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                rows.append(json.loads(stripped))
    return rows


def _read_corpus(path: Path) -> list[dict[str, object]]:
    """Read a corpus for the leakage comparison, in whichever format it is in.

    Parquet is accepted because the eval splits ARE parquet and nothing in this repository
    produced the JSONL the flag used to demand. That left every operator hand-exporting it and
    choosing their own key, which is precisely how an eval arm ends up carrying `text` where
    the comparison looks for `prompt` -- fingerprinting nothing and reporting a held-out set.
    `leakage_report` refuses that now, but not needing the export at all removes the step where
    it goes wrong.

    The parquet path reuses the same loader the corpus builder uses, so the field the gate
    compares is the field the corpus was built from, by construction rather than by agreement.
    """

    if path.suffix == ".parquet":
        return [
            {"row_id": row.row_id, "prompt": row.prompt} for row in guard.load_rows_parquet(path)
        ]
    return _read_jsonl(path)
