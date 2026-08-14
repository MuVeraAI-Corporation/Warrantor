"""Corpus construction for models 1-4: the Guard 0.6B and 4B adapters.

Four models, one corpus builder. The 0.6B and the 4B differ only in the base profile
(:data:`warrantor_ml.fine_tune.PROFILES` already carries both), and the weak-category and
adversarial-robustness variants differ only in which rows are selected. Treating them as four
pipelines would produce four places for the target format to drift.

The two things this module refuses to leave to the caller
--------------------------------------------------------
**The target format is pinned to the parser.** :func:`render_guard_target` emits exactly the
two-line ``Safety:`` / ``Categories:`` shape that
:func:`warrantor_ml.evaluate.parse_guard_response` consumes, including the measured Qwen3Guard
behaviour where a gating category carries the verdict on its own. If training taught a different
format, the existing benchmarks could not score the adapter and a second harness would have to
be written -- and a second harness is how a published baseline stops being comparable.

**A benign counterweight is a required argument with no default.** Both selectors take
``benign_ratio`` positionally-visible and unset. An adapter trained only on the rows the
baseline missed will buy recall with false positives, and the README already measured what that
costs: under adversarial phrasing the false-positive rate *quadruples*, 0.0224 -> 0.0923, and
that is the number that erodes an operator's willingness to read the alerts at all. Defaulting
this to something reasonable would let it be forgotten; there is no reasonable default because
the right ratio depends on which slice is being repaired.

What the corpus actually contains is not assumed
------------------------------------------------
:func:`describe_split` exists to be run FIRST, and :func:`weak_category_subset` raises if the
rows carry no usable category vocabulary rather than silently selecting nothing. The history
here is concrete: ``benchmark_expguard`` was written against a plan that said the legal domain
was spelled ``legal`` and that a general band existed. Both were wrong, and only inspecting the
corpus showed it. The *train* splits are not assumed to carry ``adversarial`` or ``subcategory``
just because the test splits do.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .._canonical import canonical_json, sha256_text
from ..baselines import normalise_category
from ..evaluate import parse_guard_response

__all__ = [
    "ADVERSARIAL_RECALL_GAP",
    "WEAK_CATEGORIES",
    "GuardCorpusRow",
    "GuardTrainingPair",
    "MissingCorpusFieldError",
    "adversarial_subset",
    "build_guard_pairs",
    "describe_split",
    "load_rows_jsonl",
    "load_rows_parquet",
    "render_guard_target",
    "round_trips",
    "rows_from_columns",
    "write_pairs_jsonl",
]


class MissingCorpusFieldError(ValueError):
    """Raised when a selector needs a column the loaded split does not carry.

    Raised rather than returning an empty selection: a subset builder that silently returns
    nothing looks identical to a corpus with no matching rows, and one of those is a bug.
    """


#: The classes the measured WildGuardTest / ExpGuardTest baselines are weakest on, with the
#: recall figure that put them here. Frozen as data so a selector cannot drift from the
#: measurement that motivated it. Sources: ml/README.md, Qwen3Guard-Gen-4B Q4_K_M, num_ctx=8192.
WEAK_CATEGORIES: Mapping[str, float] = {
    "unqualified professional advice": 0.4298,
    "social_stereotypes_and_unfair_discrimination": 0.7237,
    "fraud_assisting_illegal_activities": 0.7833,
    "others": 0.7857,
}

#: The measured recall drop from plain to adversarial phrasing on WildGuardTest
#: (0.8886 -> 0.8152). What the adversarial-robustness adapter exists to close.
ADVERSARIAL_RECALL_GAP = 0.8886 - 0.8152

_HARM_LABELS = {"harmful": True, "unsafe": True, "unharmful": False, "safe": False}


@dataclass(frozen=True)
class GuardCorpusRow:
    """One row of a guard training split, with the label vocabulary preserved verbatim.

    ``harm_label`` is ``str | None``. ``None`` means the annotators did not agree, which is a
    different fact from "unharmful"; collapsing the two is the single easiest way to manufacture
    a flattering number on this corpus, and :func:`build_guard_pairs` drops and counts those rows
    rather than coercing them.

    ``adversarial`` is ``bool | None`` for the same reason: a train split that does not carry
    the column is not a train split of entirely non-adversarial rows.
    """

    row_id: str
    prompt: str
    harm_label: str | None
    adversarial: bool | None = None
    subcategory: str = ""

    @property
    def unsafe(self) -> bool | None:
        """The row's harm label as a bool, or ``None`` when it has no usable label."""

        return _HARM_LABELS.get((self.harm_label or "").strip().lower())


@dataclass(frozen=True)
class GuardTrainingPair:
    """One rendered training pair, ready to serialise as JSONL.

    ``target`` is the literal string the model is trained to emit, and it round-trips through
    :func:`warrantor_ml.evaluate.parse_guard_response` -- asserted by a test, because the whole
    reason for pinning the format is that nothing enforces it at training time.
    """

    row_id: str
    prompt: str
    target: str
    unsafe: bool
    categories: tuple[str, ...]
    adversarial: bool | None
    selector: str

    def to_dict(self) -> dict[str, Any]:
        """Serialise one JSONL line."""

        return {
            "row_id": self.row_id,
            "prompt": self.prompt,
            "target": self.target,
            "unsafe": self.unsafe,
            "categories": list(self.categories),
            "adversarial": self.adversarial,
            "selector": self.selector,
        }


def render_guard_target(unsafe: bool, categories: Sequence[str]) -> str:
    """Render the exact two-line target the evaluator's parser consumes.

    ``Safety:`` carries ``Unsafe`` or ``Safe``; ``Categories:`` carries the ground-truth harm
    categories or ``None``. ``Controversial`` is never emitted as a training target: it is a
    real Qwen3Guard severity, but the corpora label rows harmful or not, and inventing a third
    class the labels do not distinguish would teach the model a distinction the data never
    made -- while the evaluator's policy line that scores ``Controversial`` as harmful would
    quietly absorb the difference.

    .. warning::

       **That last clause was wrong, and run `weak-2026-08-13a` measured how wrong.** One epoch
       over a corpus of 19,349 ``Unsafe`` and 19,345 ``Safe`` targets and no third value
       extinguished the severity class outright: the tuned adapter emitted **0** ``Controversial``
       verdicts across 1,699 samples where the base model emitted 49. The policy line did not
       absorb it. Overall recall fell 0.8488 -> 0.8329 while the false-positive rate fell too --
       the adapter learned to be more permissive, which on a deny gate is the failure direction
       this module's own opening rule names.

       Worse for a governance product: with no ``Controversial`` verdicts left to act on, the
       documented ``Controversial=SAFE`` policy knob became a **no-op**, reporting a recall
       identical to the headline row. An operator lever silently stopped doing anything, and
       nothing announced it.

       Do not "fix" this by training longer. Either render ``Controversial`` for the rows the
       corpora mark borderline, or keep the severity head out of the adapter entirely. Whichever
       is chosen, it is a change to the target vocabulary and therefore a new recipe digest.
    """

    listed = ", ".join(category for category in categories if category) or "None"
    return f"Safety: {'Unsafe' if unsafe else 'Safe'}\nCategories: {listed}"


def rows_from_columns(
    columns: Mapping[str, Sequence[Any]], row_count: int
) -> tuple[GuardCorpusRow, ...]:
    """Build rows from a column-oriented table. The seam every loader goes through.

    Both the parquet reader and the JSONL reader normalise onto this function, so the tests --
    which cannot use parquet, because ``*.parquet`` is gitignored and ``pyarrow`` is outside the
    ``dev`` extra CI installs -- exercise the same code the real loader runs.

    ``prompt`` is the only required column. A split missing ``adversarial`` yields ``None`` for
    every row, which the adversarial selector then refuses on by name instead of returning an
    empty set.
    """

    if "prompt" not in columns:
        raise MissingCorpusFieldError(
            f"split has no 'prompt' column; columns present: {sorted(columns)}"
        )

    def cell(name: str, index: int, default: Any = None) -> Any:
        values = columns.get(name)
        if values is None or index >= len(values):
            return default
        return values[index]

    rows: list[GuardCorpusRow] = []
    for index in range(row_count):
        raw_adversarial = cell("adversarial", index)
        rows.append(
            GuardCorpusRow(
                row_id=f"gt-{index:06d}",
                prompt=str(cell("prompt", index, "") or ""),
                harm_label=(
                    None
                    if cell("prompt_harm_label", index, cell("prompt_label", index)) is None
                    else str(cell("prompt_harm_label", index, cell("prompt_label", index)))
                ),
                adversarial=None if raw_adversarial is None else bool(raw_adversarial),
                subcategory=str(
                    cell("subcategory", index, cell("prompt_category", index, "")) or ""
                ),
            )
        )
    return tuple(rows)


def load_rows_jsonl(path: Path) -> tuple[GuardCorpusRow, ...]:
    """Load rows from JSONL. The format corpus fixtures ship in."""

    import json

    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                records.append(json.loads(stripped))
    columns: dict[str, list[Any]] = {}
    for record in records:
        for key in record:
            columns.setdefault(key, [None] * len(records))
    for index, record in enumerate(records):
        for key, value in record.items():
            columns[key][index] = value
    return rows_from_columns(columns, len(records))


def load_rows_parquet(path: Path) -> tuple[GuardCorpusRow, ...]:
    """Load rows from a Hub parquet split. A thin lazy wrapper over :func:`rows_from_columns`.

    ``pyarrow`` is imported inside the function for the same reason the benchmarks do it: it is
    outside the ``dev`` extra, so importing this module must not require it.
    """

    import pyarrow.parquet as pq

    table = pq.ParquetFile(path).read()
    return rows_from_columns(table.to_pydict(), table.num_rows)


def describe_split(rows: Sequence[GuardCorpusRow]) -> dict[str, Any]:
    """The schema facts to state before selecting anything. Run this first.

    Reports what the split actually carries -- label vocabulary, whether ``adversarial`` is
    present at all, the category vocabulary and which of the measured weak classes appear in it.
    The last of those is the one that matters: a weak-category selector written against a
    category spelling the train split does not use selects nothing, and nothing is what an empty
    subset and a working filter both look like.
    """

    from collections import Counter

    labels = Counter((row.harm_label or "<null>") for row in rows)
    categories = Counter(row.subcategory for row in rows if row.subcategory)
    adversarial_present = any(row.adversarial is not None for row in rows)
    present_weak = sorted(
        name for name in WEAK_CATEGORIES if any(_matches_category(row, name) for row in rows)
    )
    return {
        "row_count": len(rows),
        "harm_label_values": dict(sorted(labels.items())),
        "adversarial_column_present": adversarial_present,
        "adversarial_counts": (
            dict(sorted(Counter(str(row.adversarial) for row in rows).items()))
            if adversarial_present
            else {}
        ),
        "category_values": dict(sorted(categories.items(), key=lambda kv: -kv[1])),
        "measured_weak_categories_present": present_weak,
        "measured_weak_categories_absent": sorted(set(WEAK_CATEGORIES) - set(present_weak)),
        "note": "The TRAIN split is not assumed to carry the columns the TEST split carries. "
        "A selector written against an absent column is refused by name, never silently "
        "satisfied with an empty selection.",
    }


def _matches_category(row: GuardCorpusRow, category: str) -> bool:
    """Whether a row's category matches one of the measured weak classes.

    Case- and separator-insensitive: the WildGuard subcategory vocabulary uses underscores
    (``fraud_assisting_illegal_activities``) and the ExpGuard prompt-category vocabulary uses
    spaces and title case (``Unqualified Professional Advice``). Both are load-bearing spellings
    of a measured weakness, so the match normalises rather than picking one.

    The rule lives in :func:`warrantor_ml.baselines.normalise_category` and is imported rather
    than restated. The parity gate had its own exact-match lookup over the same two vocabularies,
    which meant the floor protecting the single measured weak class never matched anything --
    two normalisations that can disagree are worse than one in the wrong place.
    """

    return normalise_category(row.subcategory) == normalise_category(category)


def build_guard_pairs(
    rows: Sequence[GuardCorpusRow],
    selector: str,
) -> tuple[tuple[GuardTrainingPair, ...], tuple[str, ...]]:
    """Render selected rows into training pairs, dropping and returning unlabelled rows.

    Returns ``(pairs, dropped_ids)``. The caller reports the exclusion rather than quietly
    shrinking its denominator -- the same contract ``benchmark_wildguard.to_eval_samples``
    keeps, and for the same reason.
    """

    pairs: list[GuardTrainingPair] = []
    dropped: list[str] = []
    for row in rows:
        unsafe = row.unsafe
        if unsafe is None:
            dropped.append(row.row_id)
            continue
        if not row.prompt.strip():
            dropped.append(row.row_id)
            continue
        categories = (
            (row.subcategory,) if unsafe and row.subcategory and row.subcategory != "benign" else ()
        )
        pairs.append(
            GuardTrainingPair(
                row_id=row.row_id,
                prompt=row.prompt,
                target=render_guard_target(unsafe, categories),
                unsafe=unsafe,
                categories=categories,
                adversarial=row.adversarial,
                selector=selector,
            )
        )
    return tuple(pairs), tuple(dropped)


def _counterweight(
    positives: Sequence[GuardCorpusRow],
    pool: Sequence[GuardCorpusRow],
    benign_ratio: float,
    seed: int,
) -> tuple[GuardCorpusRow, ...]:
    """Deterministically draw benign rows to sit alongside a positive selection.

    Drawn from ``pool`` -- the rows NOT selected -- so the counterweight is real benign traffic
    from the same corpus rather than a re-labelling of the positives. Seeded and sorted so the
    same ``(seed, ratio)`` always yields the same corpus, which is what makes a recipe digest
    mean anything.

    Raises:
        MissingCorpusFieldError: the pool cannot supply the requested benign rows. It used to
            return whatever was available -- including nothing -- and the shortfall was visible
            only as a smaller ``benign_counterweight`` number in ``build_corpus``'s summary JSON.
            ``benign_ratio`` is given no default across two selectors and a CLI flag precisely so
            it cannot be forgotten; a ratio that is silently not honoured is the same outcome
            reached by a different route. This is the one control standing between the
            weak-category adapter and the false-positive blow-up the parity gate is two-sided to
            refuse, and every other unmet precondition in this module raises.
    """

    import random

    if benign_ratio < 0:
        raise ValueError(f"benign_ratio must be >= 0, got {benign_ratio}")
    wanted = round(len(positives) * benign_ratio)
    if wanted == 0:
        return ()
    benign = sorted((row for row in pool if row.unsafe is False), key=lambda row: row.row_id)
    if len(benign) < wanted:
        raise MissingCorpusFieldError(
            f"the benign counterweight cannot be honoured: benign_ratio={benign_ratio} over "
            f"{len(positives)} selected positives needs {wanted} benign rows, and the "
            f"unselected pool holds {len(benign)}. Drawing {len(benign)} instead would report a "
            f"ratio of {len(benign) / len(positives):.4f} as if it were {benign_ratio}, and the "
            "counterweight is what keeps a weak-category adapter from buying recall with false "
            "positives. Lower the ratio deliberately, or widen the split"
        )
    rng = random.Random(f"{seed}:counterweight")
    return tuple(rng.sample(benign, wanted))


def weak_category_subset(
    rows: Sequence[GuardCorpusRow],
    benign_ratio: float,
    categories: Iterable[str] = tuple(WEAK_CATEGORIES),
    seed: int = 20260813,
) -> tuple[GuardCorpusRow, ...]:
    """Rows in the measured weak classes, plus a benign counterweight.

    Args:
        rows: the loaded train split.
        benign_ratio: benign rows per selected positive. **Required, no default.** Zero is
            allowed and is a deliberate choice a caller has to write down; it is not the value
            you get by not thinking about it.
        categories: which classes to target. Defaults to the four measured weak ones.
        seed: pins the counterweight draw.

    Raises:
        MissingCorpusFieldError: none of the requested categories appear in these rows, which
            almost always means the train split spells them differently from the test split.
    """

    wanted = tuple(categories)
    selected = tuple(
        row
        for row in rows
        if row.unsafe is True and any(_matches_category(row, name) for name in wanted)
    )
    if not selected:
        vocabulary = sorted({row.subcategory for row in rows if row.subcategory})[:20]
        raise MissingCorpusFieldError(
            f"no rows match any of {list(wanted)}. The split's category vocabulary begins: "
            f"{vocabulary}. Run describe_split() before writing a selector -- the train split "
            "is not obliged to spell a class the way the test split does"
        )
    selected_ids = {row.row_id for row in selected}
    pool = [row for row in rows if row.row_id not in selected_ids]
    return tuple(
        sorted(
            selected + _counterweight(selected, pool, benign_ratio, seed),
            key=lambda row: row.row_id,
        )
    )


def adversarial_subset(
    rows: Sequence[GuardCorpusRow],
    benign_ratio: float,
    seed: int = 20260813,
) -> tuple[GuardCorpusRow, ...]:
    """Adversarially-phrased harmful rows, plus a benign counterweight.

    The counterweight matters more here than anywhere else in this module. The measured
    adversarial slice does not merely leak more harm through -- its false-positive rate is four
    times the plain slice's. An adapter trained on adversarial positives alone optimises the
    first number by making the second one worse, and the parity gate is two-sided precisely so
    that trade is refused rather than celebrated.

    Raises:
        MissingCorpusFieldError: the split carries no ``adversarial`` column, so "adversarial
            rows" is not a selection this corpus can express.
    """

    if all(row.adversarial is None for row in rows):
        raise MissingCorpusFieldError(
            "this split carries no 'adversarial' column, so an adversarial subset cannot be "
            "selected from it. The WildGuardTest split has one; do not assume the train split "
            "does. Either source adversarial rows elsewhere or train the weak-category variant"
        )
    selected = tuple(row for row in rows if row.unsafe is True and row.adversarial is True)
    if not selected:
        raise MissingCorpusFieldError(
            "the 'adversarial' column is present but no harmful row is marked adversarial"
        )
    selected_ids = {row.row_id for row in selected}
    pool = [row for row in rows if row.row_id not in selected_ids]
    return tuple(
        sorted(
            selected + _counterweight(selected, pool, benign_ratio, seed),
            key=lambda row: row.row_id,
        )
    )


def write_pairs_jsonl(pairs: Sequence[GuardTrainingPair], path: Path) -> str:
    """Write pairs as JSONL and return the ``sha256:`` digest of the canonical content.

    The digest covers the canonical JSON of the pair bodies rather than the file bytes, so it
    does not change when line ordering or encoding does. It is what the corpus manifest's
    ``content_digest`` carries and what :mod:`warrantor_ml.leakage` compares against an eval
    split.
    """

    import json

    path.parent.mkdir(parents=True, exist_ok=True)
    bodies = [pair.to_dict() for pair in pairs]
    path.write_text(
        "\n".join(json.dumps(body, ensure_ascii=False) for body in bodies) + "\n",
        encoding="utf-8",
    )
    return sha256_text(canonical_json(bodies))


def round_trips(pair: GuardTrainingPair) -> bool:
    """Whether a pair's target parses back to the label it was rendered from.

    The pinning claim in the module docstring is only true if something checks it, and nothing
    at training time does. A test asserts this over every rendered shape.
    """

    parsed = parse_guard_response(pair.target)
    return parsed.is_harmful == pair.unsafe
