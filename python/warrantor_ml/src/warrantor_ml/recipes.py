"""The eight recipes, as data with a stable digest.

A recipe is a :class:`~warrantor_ml.fine_tune.FineTuneConfig` plus the things a config does not
carry: which corpus selector built the data, which baseline the result is measured against, and
which slice of that baseline the promotion decision reads. All of it is declarative, so a
Kaggle run and a Modal run of "the same recipe" are **provably** the same recipe rather than two
scripts that were edited in parallel.

That is what :attr:`Recipe.recipe_digest` is for. It covers the config, the selector and the
gate target, and it is recorded in the run record next to the lane and the precision. Two run
records with the same recipe digest and different lanes are the confounded comparison
:mod:`warrantor_ml.lanes` warns about and :mod:`warrantor_ml.parity` refuses.

Four of the eight are one recipe shape
--------------------------------------
Guard 0.6B and 4B, each in a weak-category and an adversarial-robustness variant, differ only in
``profile_key`` and the row selector. They are enumerated rather than generated so each one has
a stable id and digest that a run record can name, but they are built from one function so the
hyperparameters cannot drift between them.

The four substrate recipes carry a cold-start warning in their notes, and it is not decoration:
there is no corpus of real warrants in this repository. Those recipes are built and cannot yet
be exercised at a size that would support a promotion, which is why the gate's
``insufficient_evidence`` verdict exists.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

from ._canonical import canonical_json, sha256_text
from .fine_tune import PROFILES, FineTuneConfig

__all__ = [
    "RECIPES",
    "Recipe",
    "get_recipe",
    "list_recipes",
]


@dataclass(frozen=True)
class Recipe:
    """One named training recipe: the config, the data selector, and how it will be judged."""

    recipe_id: str
    model_role: str
    config: FineTuneConfig
    #: The corpus builder and selector, as ``"module:function"`` plus its keyword arguments.
    #: Recorded rather than called here so a recipe stays inert data.
    corpus_task: str
    corpus_selector: str
    corpus_arguments: dict[str, Any]
    #: Which frozen baseline the candidate is compared against, and which slice carries the
    #: promotion decision. Empty for the substrate models, which have no measured baseline yet.
    baseline_id: str
    gate_slice: str
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        """The canonical recipe body."""

        config = asdict(self.config)
        config["output_dir"] = str(self.config.output_dir)
        return {
            "recipe_id": self.recipe_id,
            "model_role": self.model_role,
            "config": config,
            "corpus_task": self.corpus_task,
            "corpus_selector": self.corpus_selector,
            "corpus_arguments": dict(self.corpus_arguments),
            "baseline_id": self.baseline_id,
            "gate_slice": self.gate_slice,
            "notes": list(self.notes),
        }

    @property
    def recipe_digest(self) -> str:
        """Stable digest over the recipe body.

        Excludes nothing, deliberately -- including ``output_dir``, because two runs writing to
        different directories are two runs and a digest that ignored it would let a rerun
        masquerade as a reproduction. Callers that want a path-independent identity should
        normalise the path before digesting.
        """

        return sha256_text(canonical_json(self.to_dict()))

    def for_lane(self, lane_key: str) -> Recipe:
        """A copy tagged for a lane, so the run record names the lane in the recipe too."""

        return replace(
            self,
            recipe_id=f"{self.recipe_id}@{lane_key}",
            config=replace(self.config, output_dir=self.config.output_dir / lane_key),
        )


def _guard_recipe(
    profile_key: str,
    variant: str,
    selector: str,
    benign_ratio: float,
    gate_slice: str,
    notes: tuple[str, ...],
) -> Recipe:
    """Build one of the four guard adapter recipes.

    All four share these hyperparameters on purpose. A weak-category adapter and an adversarial
    adapter that also differed in learning rate would make the comparison between them a
    comparison of two things at once, and the whole point of splitting the axes was to be able
    to attribute the result to the data.
    """

    parameters = PROFILES[profile_key].parameters
    return Recipe(
        recipe_id=f"guard-{profile_key.replace('qwen3guard-gen-', '')}-{variant}",
        model_role=f"Qwen3Guard-Gen {profile_key.split('-')[-1].upper()} {variant} adapter",
        config=FineTuneConfig(
            profile_key=profile_key,
            technique="qlora" if parameters > 1_000_000_000 else "lora",
            base_dtype="nf4" if parameters > 1_000_000_000 else "bf16",
            dataset_id="wildguardmix",
            dataset_split="train",
            lora_rank=16,
            lora_alpha=32,
            sequence_length=2048,
            batch_size=2,
            gradient_accumulation_steps=8,
            learning_rate=1e-4,
            epochs=1.0,
            seed=20260813,
            # BOTH SETTINGS WERE MEASURED, AND BOTH LOSE. Run `weak-2026-08-13a` supervised
            # severity: `Controversial` went 49 verdicts -> 0, recall 0.8488 -> 0.8329, and the
            # documented Controversial=SAFE knob became a no-op. So run `catonly-2026-08-13b`
            # masked it instead -- and did far worse: 0.6804 overall, 0.5572 adversarial, with
            # the model emitting its own CATEGORY words in the severity slot. Masking a field's
            # loss does not isolate it when LoRA adapts the weights both fields share.
            #
            # Back to True, which is the less-bad of two measured losses and keeps the severity
            # line at least well-formed. This is NOT a fix; see the warning on
            # FineTuneConfig.supervise_severity. The next attempt needs separate parameters or a
            # corpus that can supervise all three severity values, not a third setting here.
            supervise_severity=True,
            output_dir=Path("artifacts") / f"guard-{profile_key}-{variant}",
        ),
        corpus_task="guard",
        corpus_selector=selector,
        corpus_arguments={"benign_ratio": benign_ratio},
        baseline_id="wildguardtest-qwen3guard-gen-4b",
        gate_slice=gate_slice,
        notes=notes,
    )


_WEAK_NOTES = (
    "Targets the measured weak classes: Unqualified Professional Advice 0.4298, "
    "social_stereotypes_and_unfair_discrimination 0.7237, fraud_assisting_illegal_activities "
    "0.7833, others 0.7857.",
    "benign_ratio is 1.0 rather than 0: training on the missed positives alone buys recall with "
    "false positives, and the gate refuses a candidate whose FPR regresses.",
    "Run describe_split on the TRAIN split first. The measured class names come from the TEST "
    "splits and the train split is not obliged to spell them the same way.",
    "REVISED after run weak-2026-08-13a, which this recipe's previous digest "
    "(sha256:7509dd11...) produced and the gate REJECTED. Severity is no longer supervised. "
    "Supervising it taught the adapter a binary Unsafe/Safe vocabulary and extinguished "
    "Qwen3Guard's third severity Controversial -- 49 verdicts to 0 over 1,699 samples -- which "
    "took recall from 0.8488 to 0.8329 WITH the false-positive rate falling, i.e. a more "
    "permissive gate, and silently made the Controversial=SAFE policy knob a no-op.",
    "Unqualified Professional Advice is unreachable from this corpus: it is an ExpGuardMix "
    "category and the WildGuardMix train split has no such class. Neither train split carries a "
    "borderline/agreement signal either -- WildGuard's prompt_harm_agreement exists only in its "
    "TEST split -- so rendering Controversial as a third target class is not available here, "
    "which is why the fix is to stop supervising severity rather than to label it better.",
)

_ADVERSARIAL_NOTES = (
    "Targets the measured 0.8886 -> 0.8152 recall drop under adversarial phrasing.",
    "benign_ratio is 1.5, higher than the weak-category recipe, because the adversarial slice's "
    "false-positive rate is already four times the plain slice's (0.0224 -> 0.0923). That is "
    "the number this recipe is most likely to make worse.",
    "The WildGuard TRAIN split may not carry the `adversarial` column the TEST split carries. "
    "adversarial_subset refuses by name rather than selecting nothing.",
)


def _substrate_recipe(
    recipe_id: str,
    model_role: str,
    corpus_task: str,
    selector: str,
    notes: tuple[str, ...],
) -> Recipe:
    """Build one of the four substrate recipes: bounds, triage, effects, summary.

    All four use the 0.6B base. They are structured-output tasks over short inputs, not safety
    classification, and the argument that put the 4B in front of the deny gate -- highest recall
    of fourteen guard models -- says nothing about them. Starting small also means the cold-start
    problem is visible as a bad result rather than hidden under capacity.
    """

    return Recipe(
        recipe_id=recipe_id,
        model_role=model_role,
        config=FineTuneConfig(
            profile_key="qwen3guard-gen-0.6b",
            technique="lora",
            base_dtype="bf16",
            dataset_id="local-smoke",
            dataset_split="train",
            lora_rank=16,
            lora_alpha=32,
            sequence_length=1024,
            batch_size=4,
            gradient_accumulation_steps=4,
            learning_rate=1e-4,
            epochs=2.0,
            seed=20260813,
            output_dir=Path("artifacts") / recipe_id,
        ),
        corpus_task=corpus_task,
        corpus_selector=selector,
        corpus_arguments={},
        baseline_id="",
        gate_slice="",
        notes=(
            *notes,
            "COLD START: there is no corpus of real warrants in this repository -- a handful of "
            "fixtures, nothing like a training set. Teacher augmentation would carry nearly all "
            "the weight, and no teacher-generated row may enter an eval split. Expect the gate "
            "to return insufficient_evidence until real warrant history accumulates. That is "
            "the honest state, not a defect in the pipeline.",
        ),
    )


RECIPES: dict[str, Recipe] = {
    recipe.recipe_id: recipe
    for recipe in (
        _guard_recipe(
            "qwen3guard-gen-0.6b",
            "weak-category",
            "warrantor_ml.tasks.guard:weak_category_subset",
            1.0,
            "overall",
            _WEAK_NOTES,
        ),
        _guard_recipe(
            "qwen3guard-gen-0.6b",
            "adversarial",
            "warrantor_ml.tasks.guard:adversarial_subset",
            1.5,
            "adversarial_true",
            _ADVERSARIAL_NOTES,
        ),
        _guard_recipe(
            "qwen3guard-gen-4b",
            "weak-category",
            "warrantor_ml.tasks.guard:weak_category_subset",
            1.0,
            "overall",
            _WEAK_NOTES,
        ),
        _guard_recipe(
            "qwen3guard-gen-4b",
            "adversarial",
            "warrantor_ml.tasks.guard:adversarial_subset",
            1.5,
            "adversarial_true",
            _ADVERSARIAL_NOTES,
        ),
        _substrate_recipe(
            "bound-proposer",
            "task description -> proposed warrant bounds",
            "bounds",
            "warrantor_ml.tasks.bounds:parse_proposal",
            (
                "Scored by OVER-GRANT RATE, never accuracy: an under-broad proposal costs a "
                "refusal, an over-broad one grants authority nobody chose.",
                "Every field of BoundProposal is required. A model that omits the budget is "
                "PROPOSAL_INCOMPLETE and is counted separately -- never defaulted, because an "
                "absent budget in the substrate is a ceiling of zero.",
            ),
        ),
        _substrate_recipe(
            "refusal-triage",
            "refusal -> the bound was wrong | the agent was wrong",
            "triage",
            "warrantor_ml.tasks.triage:build_triage_examples",
            (
                "Labels come from what the operator did NEXT, never from RefusalSignal or "
                "RefusalGroup.guidance: those are a comparison against two constants, and a "
                "model distilled from them has an `if` statement as its ceiling.",
                "Output is a TriageEstimate with source='model'. It never populates "
                "RefusalGroup.signal. Wiring it into /v1/summary/refusals is a Rust change "
                "outside this workstream.",
            ),
        ),
        _substrate_recipe(
            "effect-risk",
            "proposed action -> SideEffectClass",
            "effects",
            "warrantor_ml.tasks.effects:effect_risk_report",
            (
                "Supervised by construction -- the five labels already exist in the schema. The "
                "design work is entirely in the cost model.",
                "Headline is recall on the consequential set. A downgrade ACROSS that boundary "
                "removes the human approval invariant I-08 requires and is counted separately. "
                "An unknown class is an abstention and never a fall-back to 'read'.",
            ),
        ),
        _substrate_recipe(
            "report-summariser",
            "verified report bundle -> prose for a decision-maker",
            "summary",
            "warrantor_ml.tasks.summary:render_source_facts",
            (
                "HAZARD, handled structurally: the summariser accepts VerifiedBundleView and "
                "nothing else, and that type has one constructor which refuses unless the "
                "Rust-produced envelope says integrity == 'ok'. There is no code path from a "
                "tampered bundle to prose.",
                "The model is never shown the verification verdict, so it cannot describe one. "
                "Eval is a faithfulness check -- every number traceable to a bundle field -- "
                "not a similarity score against a reference summary.",
            ),
        ),
    )
}


def list_recipes() -> tuple[Recipe, ...]:
    """Every recipe in stable id order."""

    return tuple(RECIPES[key] for key in sorted(RECIPES))


def get_recipe(recipe_id: str) -> Recipe:
    """Look up one recipe, or fail naming the eight."""

    try:
        return RECIPES[recipe_id]
    except KeyError as error:
        known = ", ".join(sorted(RECIPES))
        raise KeyError(f"unknown recipe {recipe_id!r}; declared: {known}") from error
