"""Detect an eval set that stopped being held out.

The published train/test boundary is not the leak path anyone should worry about. AI2 and the
ExpGuard authors already separated their splits. The real leak is **teacher augmentation over a
train split**: a teacher paraphrases a training row, the paraphrase is near-identical to a test
row that was itself a paraphrase of the same seed prompt, and a held-out set quietly becomes a
memorisation check. Nothing about that shows up in a split name.

So the comparison here is over normalised *content*, not identifiers. Two rows that differ only
in whitespace, case, punctuation or a wrapper phrase are the same row for this purpose, and the
report says how many of them there are and which they were.

This module computes digests over text. That is not verification, and it never touches a bundle
or a signature -- see :mod:`warrantor_ml.tasks.summary` for the rule about where verification
happens. These are content fingerprints for a set-overlap question.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

__all__ = [
    "LeakageReport",
    "content_fingerprint",
    "leakage_report",
    "normalise_text",
]

_WHITESPACE = re.compile(r"\s+")
_PUNCTUATION = re.compile(r"[^\w\s]", re.UNICODE)


def normalise_text(text: str) -> str:
    """Fold a row to the form two near-duplicates share.

    NFKC first so a full-width or combining variant folds onto its plain form -- a paraphrase
    pipeline that round-trips through a tokenizer emits those routinely and they would otherwise
    read as distinct rows. Then case, punctuation and whitespace go, because an augmented row
    that differs from its source only by a trailing question mark is not a new example.

    Deliberately NOT stemmed or embedded. A fuzzy similarity threshold turns leakage into a
    judgement call with a knob, and the knob is always turned until the corpus passes.
    """

    folded = unicodedata.normalize("NFKC", text).casefold()
    folded = _PUNCTUATION.sub(" ", folded)
    return _WHITESPACE.sub(" ", folded).strip()


def content_fingerprint(text: str) -> str:
    """A short hex fingerprint of a row's normalised content.

    Truncated to 32 hex characters: this is a set-membership key for an overlap count, not an
    integrity claim, and calling it a full digest would invite it being read as one.
    """

    return hashlib.sha256(normalise_text(text).encode("utf-8")).hexdigest()[:32]


class LeakageReport(dict[str, Any]):
    """The overlap finding. A dict subclass so it serialises straight into a decision record."""

    @property
    def clean(self) -> bool:
        """True when the check ran over both arms and found no eval row in the training corpus.

        Zero overlap is not sufficient. If either arm fingerprinted nothing while rows were
        supplied, the comparison did not happen -- the usual cause is an eval export whose text
        lives under a different key, and the symptom is a report that says CLEAN over an empty
        set while every eval row is verbatim in the training corpus. That is a false pass on
        the one check standing between a memorised adapter and promotion, so it is reported as
        not clean.
        """

        if self.get("unusable_arms"):
            return False
        return int(self["overlapping_eval_rows"]) == 0


def _fingerprints(rows: Iterable[Mapping[str, Any] | str], field: str) -> dict[str, list[str]]:
    """Fingerprint -> the row ids that produced it."""

    index: dict[str, list[str]] = {}
    for position, row in enumerate(rows):
        if isinstance(row, str):
            text, row_id = row, f"row-{position:06d}"
        else:
            text = str(row.get(field, ""))
            row_id = str(row.get("row_id") or row.get("id") or f"row-{position:06d}")
        if not text.strip():
            continue
        index.setdefault(content_fingerprint(text), []).append(row_id)
    return index


def leakage_report(
    training_rows: Sequence[Mapping[str, Any] | str],
    eval_rows: Sequence[Mapping[str, Any] | str],
    field: str = "prompt",
    sample_limit: int = 20,
) -> LeakageReport:
    """Report how much of an eval split appears in a training corpus.

    Args:
        training_rows: the built corpus, INCLUDING every augmented row. Checking only the
            original corpus is how augmentation-driven leakage passes a leakage check.
        eval_rows: the held-out split the parity gate will score against.
        field: which key carries the text. ``prompt`` for guard corpora.
        sample_limit: how many colliding ids to list. The count is the finding; the sample is
            for whoever has to fix it.

    Returns:
        A :class:`LeakageReport`. ``clean`` is the only thing the gate reads, and it is true
        only at zero overlap -- there is no acceptable-leakage threshold, because an eval set is
        held out or it is not.
    """

    training_index = _fingerprints(training_rows, field)
    eval_index = _fingerprints(eval_rows, field)
    shared = sorted(set(training_index) & set(eval_index))

    overlapping_eval_rows = sum(len(eval_index[key]) for key in shared)
    examples = [
        {
            "fingerprint": key,
            "eval_row_ids": eval_index[key][:5],
            "training_row_ids": training_index[key][:5],
        }
        for key in shared[:sample_limit]
    ]
    eval_total = sum(len(ids) for ids in eval_index.values())
    training_total = sum(len(ids) for ids in training_index.values())

    # Rows were supplied and none of them carried usable text under `field`. Almost always a
    # key mismatch -- an eval split exported with `text` rather than `prompt` fingerprints to
    # nothing, collides with nothing, and reports CLEAN while being identical to the training
    # corpus. Named per arm because the fix differs: the wrong export, or the wrong corpus.
    unusable_arms = [
        name
        for name, supplied, fingerprinted in (
            ("training", len(training_rows), training_total),
            ("eval", len(eval_rows), eval_total),
        )
        if supplied and not fingerprinted
    ]

    return LeakageReport(
        {
            "training_rows_fingerprinted": training_total,
            "eval_rows_fingerprinted": eval_total,
            "unusable_arms": unusable_arms,
            "field": field,
            "distinct_collisions": len(shared),
            "overlapping_eval_rows": overlapping_eval_rows,
            "overlap_fraction_of_eval": (overlapping_eval_rows / eval_total if eval_total else 0.0),
            "examples": examples,
            "normalisation": "NFKC, casefold, punctuation stripped, whitespace collapsed. "
            "Exact match after normalisation -- no fuzzy threshold, because a threshold is a "
            "knob and the knob gets turned until the corpus passes.",
            "note": "The published train/test boundary is not the risk. Teacher augmentation "
            "over a train split is: it can reproduce a held-out row closely enough that the "
            "eval measures memorisation, and no split name records that.",
        }
    )
