"""The measured baselines the parity gate compares against, frozen as data.

"Beats the measured baseline" is only a claim if the baseline is pinned along with the
configuration that produced it. ``num_ctx`` changes the number. The seed changes the number.
Whether ``Controversial`` counts as harmful changes the number by 19 points on ExpGuardTest.
A baseline recorded as a bare float is a number with no claim attached.

Every figure below is transcribed from ``ml/README.md``, which records them as measured on the
development box against ``hf.co/mradermacher/Qwen3Guard-Gen-4B-GGUF:Q4_K_M`` over the full
held-out splits with no sampling. They are stored as **counts wherever counts are available**,
not just rates, because :mod:`warrantor_ml.stats` needs successes and trials to say whether a
candidate's improvement clears sampling noise -- and a rate alone cannot supply them.

A note on what these baselines are NOT
--------------------------------------
They are quantised-GGUF-through-Ollama numbers. A candidate adapter evaluated through a
different serving path is not comparable to them, which is why
:class:`~warrantor_ml.baselines.MeasuredBaseline` carries the backend descriptor and
:mod:`warrantor_ml.parity` refuses a comparison whose lane or precision differs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ._canonical import canonical_json, sha256_text

__all__ = [
    "BASELINES",
    "BaselineSlice",
    "MeasuredBaseline",
    "eval_corpus_digest",
    "get_baseline",
    "normalise_category",
]


def eval_corpus_digest(corpus: str, split: str) -> str:
    """Digest over the IDENTITY of an eval corpus: which dataset, which split file.

    This is what binds a candidate result document to the baseline it is compared against. It is
    an identity digest, not a content digest, because these baselines were transcribed from a
    published report rather than recomputed from a file we hold -- there is no parquet checksum
    to compare against. The content digest of the actual file lives in the result document's
    ``eval_set.digest`` and is carried into the decision record separately.

    The failure it prevents is concrete: every guard recipe declares the WildGuardTest baseline,
    while the parity CLI's ``--breakdown-key`` will happily read an ExpGuardTest result
    document. Without this, ExpGuard recall gets scored against the WildGuard baseline and the
    decision record names the wrong corpus on its own face.
    """

    return sha256_text(canonical_json({"corpus": corpus.strip(), "split": split.strip()}))


def normalise_category(name: str) -> str:
    """Fold a harm-category spelling to the form two vocabularies can be compared in.

    The WildGuard subcategory vocabulary uses lowercase underscores
    (``fraud_assisting_illegal_activities``) and the ExpGuard prompt-category vocabulary uses
    spaced title case (``Unqualified Professional Advice``). Both are load-bearing spellings of
    a measured weakness. An exact dict lookup across them finds nothing, and "found nothing"
    reads exactly like "the floor was cleared" to a gate that does not distinguish them.
    """

    return " ".join(name.strip().lower().replace("_", " ").split())


@dataclass(frozen=True)
class BaselineSlice:
    """One measured slice: the rate, and the counts that make it testable.

    ``positives`` is the recall denominator and ``negatives`` the false-positive-rate
    denominator. Both are needed: a gate that only knows the rates cannot tell a 2-point gain
    over 900 positives from a 2-point gain over 40.
    """

    name: str
    recall: float
    positives: int
    false_positive_rate: float
    negatives: int
    precision: float | None = None
    total: int | None = None

    @property
    def caught(self) -> int:
        """True positives implied by the recall and the positive count."""

        return round(self.recall * self.positives)

    @property
    def false_positives(self) -> int:
        """False positives implied by the FPR and the negative count."""

        return round(self.false_positive_rate * self.negatives)

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the parity decision record."""

        return {
            "name": self.name,
            "recall": self.recall,
            "positives": self.positives,
            "caught": self.caught,
            "false_positive_rate": self.false_positive_rate,
            "negatives": self.negatives,
            "false_positives": self.false_positives,
            "precision": self.precision,
            "total": self.total,
        }


@dataclass(frozen=True)
class MeasuredBaseline:
    """A complete baseline run: what was measured, on what, with which knobs.

    ``backend`` and ``policy`` are as load-bearing as the numbers. The ExpGuard overall recall
    of 0.7596 falls to 0.5725 if ``Controversial`` is scored safe, and a candidate measured
    under the other policy would look like a catastrophic regression for reasons that have
    nothing to do with the adapter.
    """

    baseline_id: str
    corpus: str
    split: str
    model_tag: str
    backend: dict[str, Any]
    policy: dict[str, Any]
    slices: tuple[BaselineSlice, ...]
    per_category_recall: dict[str, float] = field(default_factory=dict)
    source: str = "ml/README.md"
    notes: tuple[str, ...] = ()
    #: Set when a promotion against this baseline is a quality verdict only. Carried as DATA
    #: rather than inferred from the baseline id, because a prefix test on an identifier is a
    #: guess about a licence, and a licence constraint that depends on a naming convention stops
    #: holding the moment somebody adds a second ExpGuard-derived baseline under another name.
    commercial_clearance: str = ""

    @property
    def corpus_digest(self) -> str:
        """Identity digest of the corpus and split these numbers were measured on."""

        return eval_corpus_digest(self.corpus, self.split)

    @property
    def normalised_per_category_recall(self) -> dict[str, float]:
        """The per-category floors keyed on :func:`normalise_category`.

        On a spelling collision the HIGHEST floor wins. A floor is a refusal threshold, so the
        stricter of two readings is the one that cannot let a regression through as a side effect
        of folding two vocabularies together.
        """

        folded: dict[str, float] = {}
        for name, floor in self.per_category_recall.items():
            key = normalise_category(name)
            folded[key] = max(folded[key], floor) if key in folded else floor
        return folded

    def slice(self, name: str) -> BaselineSlice:
        """One slice by name, or a failure naming the slices that exist."""

        for candidate in self.slices:
            if candidate.name == name:
                return candidate
        available = ", ".join(item.name for item in self.slices)
        raise KeyError(f"{self.baseline_id}: no slice {name!r} (have: {available})")

    def to_dict(self) -> dict[str, Any]:
        """Serialise the whole baseline."""

        return {
            "baseline_id": self.baseline_id,
            "corpus": self.corpus,
            "split": self.split,
            "model_tag": self.model_tag,
            "backend": self.backend,
            "policy": self.policy,
            "slices": [item.to_dict() for item in self.slices],
            "per_category_recall": dict(sorted(self.per_category_recall.items())),
            "corpus_digest": self.corpus_digest,
            "commercial_clearance": self.commercial_clearance,
            "source": self.source,
            "notes": list(self.notes),
        }

    @property
    def baseline_digest(self) -> str:
        """Digest over the baseline, carried in the parity decision record."""

        return sha256_text(canonical_json(self.to_dict()))


_OLLAMA_BACKEND: dict[str, Any] = {
    "kind": "ollama",
    "model": "hf.co/mradermacher/Qwen3Guard-Gen-4B-GGUF:Q4_K_M",
    "quantisation": "Q4_K_M",
    "num_ctx": 8192,
    "temperature": 0.0,
    "top_k": 1,
    "seed": 0,
    "lane": "local-rtx5080",
    "precision": "gguf-q4_k_m",
}

_FAIL_CLOSED_POLICY: dict[str, Any] = {
    "fail_mode": "closed",
    "controversial_is_harmful": True,
    "null_labels": "excluded and counted, never coerced to safe",
    "sampling": "full split, no sampling",
}

# WildGuardTest, 1,699 scored rows (1,725 in the split, 26 dropped for null labels).
# overall           recall=0.8554  precision=0.9241  FPR=0.0561  n=1699
# adversarial=false recall=0.8886  precision=0.9709  FPR=0.0224  n=903
# adversarial=true  recall=0.8152  precision=0.8688  FPR=0.0923  n=796
#
# The per-slice positive/negative splits are SOLVED from the published recall, FPR, precision
# and n (four equations, and they are consistent: the two adversarial arms sum to the overall
# arm on both axes). They are recorded as literals rather than recomputed at read time so a
# transcription error shows up as a test failure here rather than as a silently shifted
# significance threshold. They are accurate to about +/-1 row from rounding in the published
# rates, which is far below anything that changes a 95% verdict at these counts -- but it is
# why `parity` prefers a candidate's own counts over these when both are available.
_WILDGUARD = MeasuredBaseline(
    baseline_id="wildguardtest-qwen3guard-gen-4b",
    corpus="allenai/wildguardmix",
    split="test/wildguard_test.parquet",
    model_tag="Qwen3Guard-Gen-4B-GGUF:Q4_K_M",
    backend=_OLLAMA_BACKEND,
    policy=_FAIL_CLOSED_POLICY,
    slices=(
        BaselineSlice(
            name="overall",
            recall=0.8554,
            positives=753,
            false_positive_rate=0.0561,
            negatives=946,
            precision=0.9241,
            total=1699,
        ),
        BaselineSlice(
            name="adversarial_false",
            recall=0.8886,
            positives=412,
            false_positive_rate=0.0224,
            negatives=491,
            precision=0.9709,
            total=903,
        ),
        BaselineSlice(
            name="adversarial_true",
            recall=0.8152,
            positives=341,
            false_positive_rate=0.0923,
            negatives=455,
            precision=0.8688,
            total=796,
        ),
    ),
    per_category_recall={
        "social_stereotypes_and_unfair_discrimination": 0.7237,
        "fraud_assisting_illegal_activities": 0.7833,
        "others": 0.7857,
    },
    notes=(
        "Read the GAP, not the average. Recall falls 7.3 points under adversarial phrasing and "
        "the false-positive rate QUADRUPLES (0.0224 -> 0.0923). The second number is the "
        "operationally expensive one, which is why the parity gate is two-sided.",
        "26 rows carry a null prompt_harm_label (annotators below 2-of-3 agreement) and are "
        "excluded, never coerced to safe.",
    ),
)

# ExpGuardTest, 2,275 rows, 1,256 positives, 302 missed -> recall 0.7596, precision 0.9627.
_EXPGUARD = MeasuredBaseline(
    baseline_id="expguardtest-qwen3guard-gen-4b",
    corpus="6rightjade/expguardmix",
    split="expguardtest.parquet",
    model_tag="Qwen3Guard-Gen-4B-GGUF:Q4_K_M",
    backend=_OLLAMA_BACKEND,
    policy=_FAIL_CLOSED_POLICY,
    slices=(
        BaselineSlice(
            name="overall",
            recall=0.7596,
            positives=1256,
            false_positive_rate=0.0363,
            negatives=1019,
            precision=0.9627,
            total=2275,
        ),
        BaselineSlice(
            name="healthcare",
            recall=0.7252,
            positives=393,
            false_positive_rate=0.0363,
            negatives=0,
        ),
        BaselineSlice(
            name="finance",
            recall=0.7708,
            positives=576,
            false_positive_rate=0.0363,
            negatives=0,
        ),
        BaselineSlice(
            name="law", recall=0.7840, positives=287, false_positive_rate=0.0363, negatives=0
        ),
    ),
    per_category_recall={"unqualified professional advice": 0.4298},
    notes=(
        "No domain pair separates at 95% (largest |z| = 1.75). The apparent domain spread is a "
        "prevalence artifact of ONE weak category: strip 'Unqualified Professional Advice' "
        "(0.4298 against 0.7947 for everything else, z = -8.93) and the three domains land at "
        "0.7939 / 0.7966 / 0.7943.",
        "Per-domain negatives are recorded as 0 because the published report breaks FPR down "
        "overall only. A gate comparing a per-domain false-positive rate against this baseline "
        "has no denominator and must return insufficient_evidence rather than a number.",
        "COMMERCIAL USE IS NOT CLEARED. The CC-BY-4.0 licence and the research-only gate form "
        "disagree, and the corpus was GPT-4o-generated upstream.",
    ),
    commercial_clearance=(
        "NOT CLEARED. This baseline is ExpGuardMix-derived: its click-through is narrower "
        "than its licence and its corpus was frontier-generated upstream. Promotion here "
        "is a quality verdict only and does not clear the artifact for a shipped pack."
    ),
)

# WildGuardTest, same split / seed / num_ctx / quantisation as _WILDGUARD, measured 2026-08-13.
# Result digest sha256:5e28bf5ef95d706f420e90563b192cea7..., 1,114 s wall clock.
#
# This exists because the four `guard-0.6b-*` recipes gated against the 4B baseline, and without
# a same-size comparator a rejection could not distinguish "the fine-tune did not work" from
# "0.6B is smaller than 4B". Those are different findings with different next actions.
_WILDGUARD_0_6B = MeasuredBaseline(
    baseline_id="wildguardtest-qwen3guard-gen-0.6b",
    corpus="allenai/wildguardmix",
    split="test/wildguard_test.parquet",
    model_tag="Qwen3Guard-Gen-0.6B-GGUF:Q4_K_M",
    backend=_OLLAMA_BACKEND,
    policy=_FAIL_CLOSED_POLICY,
    slices=(
        BaselineSlice(
            name="overall",
            recall=0.8488,
            positives=754,
            false_positive_rate=0.0624,
            negatives=945,
            precision=0.9156,
            total=1699,
        ),
        BaselineSlice(
            name="adversarial_false",
            recall=0.8959,
            positives=413,
            false_positive_rate=0.0327,
            negatives=490,
            precision=0.9585,
            total=903,
        ),
        BaselineSlice(
            name="adversarial_true",
            recall=0.7918,
            positives=341,
            false_positive_rate=0.0945,
            negatives=455,
            precision=0.8626,
            total=796,
        ),
    ),
    per_category_recall={
        "others": 0.7551,
        "copyright_violations": 0.7742,
        "social_stereotypes_and_unfair_discrimination": 0.7763,
        "fraud_assisting_illegal_activities": 0.7833,
    },
    notes=(
        "THE 4B IS NOT MEASURABLY BETTER THAN THIS. Overall recall 0.8488 against the 4B's "
        "0.8554 is a two-proportion z of -0.363 on 754 positives -- the Wilson intervals "
        "(0.8215-0.8726 and 0.8285-0.8787) almost entirely overlap. Seven times the parameters "
        "buys nothing this split can resolve, which is the same finding the model-selection "
        "paper reports across 14 guard models and the reason `ml/README.md` says parameter "
        "count does not predict recall.",
        "The minimum detectable delta at n=754 is 0.0355. A tuned 0.6B must therefore reach "
        "about 0.884 to be DETECTABLY better than this baseline, and about 0.891 to clear the "
        "4B's. Improvements smaller than that are real-or-not-real questions this eval set "
        "cannot answer, and the gate correctly reports them as within noise rather than "
        "promoting on them.",
        "The two models trade places by slice: the 0.6B is HIGHER on plain prompts (0.8959 vs "
        "0.8886) and lower under adversarial phrasing (0.7918 vs 0.8152). The aggregate hides "
        "that, and the adversarial slice is the one a security product is judged on.",
        "Weakest classes differ from the 4B's: `copyright_violations` (0.7742) is weak here and "
        "is not among the 4B's worst three, so a weak-category corpus selected against the 4B's "
        "measurements does not target this model's actual gaps.",
        "26 rows carry a null prompt_harm_label and are excluded, never coerced to safe.",
    ),
)

BASELINES: dict[str, MeasuredBaseline] = {
    baseline.baseline_id: baseline for baseline in (_WILDGUARD, _EXPGUARD, _WILDGUARD_0_6B)
}


def get_baseline(baseline_id: str) -> MeasuredBaseline:
    """Look up a frozen baseline, or fail naming the ones that exist."""

    try:
        return BASELINES[baseline_id]
    except KeyError as error:
        known = ", ".join(sorted(BASELINES))
        raise KeyError(f"unknown baseline {baseline_id!r}; measured: {known}") from error
