"""The nine recipes, as data with a stable digest.

A recipe is a :class:`~warrantor_ml.fine_tune.FineTuneConfig` plus the things a config does not
carry: which corpus selector built the data, which baseline the result is measured against, and
which slice of that baseline the promotion decision reads. All of it is declarative, so a
Kaggle run and a Modal run of "the same recipe" are **provably** the same recipe rather than two
scripts that were edited in parallel.

That is what :attr:`Recipe.recipe_digest` is for. It covers the config, the selector and the
gate target, and it is recorded in the run record next to the lane and the precision. Two run
records with the same recipe digest and different lanes are the confounded comparison
:mod:`warrantor_ml.lanes` warns about and :mod:`warrantor_ml.parity` refuses.

Five of the nine are one recipe shape
------------------------------------
Guard 0.6B and 4B in a weak-category and an adversarial-robustness variant, plus the 0.6B
ExpGuard weak-category variant, differ only in ``profile_key``, the corpus and the row
selector. They are enumerated rather than generated so each one has a stable id and digest that
a run record can name, but they are built from one function so the hyperparameters cannot drift
between them.

The four substrate recipes carry a cold-start warning in their notes, and it is not decoration:
there is no corpus of real warrants in this repository. Those recipes are built and cannot yet
be exercised at a size that would support a promotion, which is why the gate's
``insufficient_evidence`` verdict exists.

Every registered baseline must be bound by a recipe
---------------------------------------------------
``baselines.BASELINES`` holds four measured baselines and, until this module was corrected,
``_guard_recipe`` hardcoded exactly one of them for all four guard recipes. Three baselines
were therefore unreachable: ``wildguardtest-qwen3guard-gen-0.6b`` -- whose own docstring says it
exists *because* the ``guard-0.6b-*`` recipes gated against the 4B -- and both ExpGuard
baselines. ``parity_main`` reads ``recipe.baseline_id`` and exposes no override, so an
unreferenced baseline is not "available", it is dead. :mod:`warrantor_ml.parity` could measure
Unqualified Professional Advice, the weakest class on both models, and no CLI path could ask it
to. A test in ``test_recipes.py`` now asserts the binding is total.

``corpus_arguments`` is the corpus specification, and it is executed
-------------------------------------------------------------------
It carries ``benign_ratio`` and, for the weak-category selector, the explicit ``categories``
tuple. Both are covered by :attr:`Recipe.recipe_digest`, and
``warrantor-ml-build-corpus --recipe <id>`` builds from them rather than from hand-typed flags.
Before that, ``categories`` was an implicit dependency on the module-level
``guard.WEAK_CATEGORIES``: adding an ExpGuard class to it would have changed what the WildGuard
weak-category recipes select while their digests stayed identical.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

from ._canonical import canonical_json, sha256_text
from .fine_tune import PROFILES, FineTuneConfig
from .tasks.guard import WEAK_CATEGORIES

__all__ = [
    "DEFERRED_BASELINES",
    "EXPGUARD_ONLY_CATEGORIES",
    "EXPGUARD_WEAK_CATEGORIES",
    "RECIPES",
    "WILDGUARD_WEAK_CATEGORIES",
    "Recipe",
    "get_recipe",
    "list_recipes",
    "unbound_baselines",
]

#: The one measured weak class that WildGuardMix does not contain. ``guard.WEAK_CATEGORIES`` is
#: the measured table across BOTH corpora and is frozen against the published measurement, so the
#: exclusion is expressed here rather than by editing the table.
EXPGUARD_ONLY_CATEGORIES: tuple[str, ...] = ("unqualified professional advice",)

#: The WildGuard-spelled weak classes, resolved from the measured table rather than retyped, with
#: the classes WildGuardMix does not carry removed. Baked into ``corpus_arguments`` at import so
#: the recipe digest covers the selection: a change to ``guard.WEAK_CATEGORIES`` still changes
#: the digest of every recipe that selects on it.
#:
#: Unqualified Professional Advice used to be in here and is an ExpGuardMix category -- the
#: WildGuardMix train split has no such class (ml/README.md, verified with ``--describe-only``).
#: Declaring it made these two recipes name a target they could not reach, which is the same
#: "targeting claim nothing acts on" that ``_guard_recipe`` raises ValueError over, and it made
#: them unbuildable once ``build_corpus`` started refusing a request that matches only part of a
#: split. UPA is trained for by ``guard-0.6b-expguard-weak``, on the corpus that has it.
WILDGUARD_WEAK_CATEGORIES: tuple[str, ...] = tuple(
    name for name in WEAK_CATEGORIES if name not in EXPGUARD_ONLY_CATEGORIES
)

#: The four ExpGuard classes the 0.6B ExpGuard recipe targets, in the ExpGuardTest spelling.
#:
#: Chosen by arithmetic, not by which name reads worst. The gate slice is ``overall`` and
#: promotion needs +44 caught rows out of 1,256 (see ``_EXPGUARD_WEAK_NOTES``). Unqualified
#: Professional Advice alone has only 76 missed positives in the whole test split, so a UPA-only
#: adapter would have to roughly double its recall before the aggregate moved at all -- and the
#: honest reject that produced would say nothing about UPA. These four carry 127 recoverable
#: misses between them (UPA 76, Privacy Violation 13, Violence & Incitement 19, Self-Harm 19), so
#: recovering about a third of them clears the bar.
#:
#: Their ExpGuardTrain positive counts, read from the cached split: UPA 1,173, Privacy Violation
#: 1,584, Violence & Incitement 2,284, Self-Harm & Suicide Promotion 595.
EXPGUARD_WEAK_CATEGORIES: tuple[str, ...] = (
    "Unqualified Professional Advice",
    "Privacy Violation",
    "Violence & Incitement",
    "Self-Harm & Suicide Promotion",
)


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
    *,
    dataset_id: str,
    baseline_id: str,
    categories: tuple[str, ...] = (),
) -> Recipe:
    """Build one of the five guard adapter recipes.

    All five share these hyperparameters on purpose. A weak-category adapter and an adversarial
    adapter that also differed in learning rate would make the comparison between them a
    comparison of two things at once, and the whole point of splitting the axes was to be able
    to attribute the result to the data.

    ``dataset_id``, ``baseline_id`` and ``categories`` are keyword-only parameters rather than
    the constants they used to be. The baseline in particular: all four original recipes named
    ``wildguardtest-qwen3guard-gen-4b``, which orphaned the other three measured baselines and
    asked every 0.6B candidate to beat a model seven times its size.

    Raises:
        ValueError: ``categories`` is given for a selector that does not read it, or omitted for
            one that does. A category list silently ignored by ``adversarial_subset`` would be a
            recipe whose declaration says one thing and whose corpus builder does another, and
            ``build_corpus --recipe`` executes this dict verbatim.
    """

    wants_categories = selector.endswith(":weak_category_subset")
    if wants_categories and not categories:
        raise ValueError(
            f"{profile_key}/{variant}: selector {selector!r} selects on categories and none were "
            "declared. The default would come from guard.WEAK_CATEGORIES, which the recipe "
            "digest does not cover -- on ExpGuardTrain that default happens to select one class, "
            "and a corpus that is correct by luck is not a corpus that is specified"
        )
    if categories and not wants_categories:
        raise ValueError(
            f"{profile_key}/{variant}: selector {selector!r} does not read categories, so "
            f"declaring {list(categories)} would record a targeting claim nothing acts on"
        )

    corpus_arguments: dict[str, Any] = {"benign_ratio": benign_ratio}
    if wants_categories:
        corpus_arguments["categories"] = list(categories)

    parameters = PROFILES[profile_key].parameters
    return Recipe(
        recipe_id=f"guard-{profile_key.replace('qwen3guard-gen-', '')}-{variant}",
        model_role=f"Qwen3Guard-Gen {profile_key.split('-')[-1].upper()} {variant} adapter",
        config=FineTuneConfig(
            profile_key=profile_key,
            technique="qlora" if parameters > 1_000_000_000 else "lora",
            base_dtype="nf4" if parameters > 1_000_000_000 else "bf16",
            dataset_id=dataset_id,
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
        corpus_arguments=corpus_arguments,
        baseline_id=baseline_id,
        gate_slice=gate_slice,
        notes=notes,
    )


_WEAK_NOTES = (
    "Targets the measured weak classes THIS corpus carries: "
    "social_stereotypes_and_unfair_discrimination 0.7237, fraud_assisting_illegal_activities "
    "0.7833, others 0.7857. Three, not four -- see the Unqualified Professional Advice note.",
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
    "category and the WildGuardMix train split has no such class. It is therefore NO LONGER "
    "DECLARED here (it was, and the declaration was decoration): corpus_arguments['categories'] "
    "names the three reachable classes, and build_corpus refuses a request that matches only "
    "part of a split rather than recording the whole request as honoured. Neither train split "
    "carries a "
    "borderline/agreement signal either -- WildGuard's prompt_harm_agreement exists only in its "
    "TEST split -- so rendering Controversial as a third target class is not available here, "
    "which is why the fix is to stop supervising severity rather than to label it better.",
    "For UPA, use `guard-0.6b-expguard-weak`. It trains from ExpGuardTrain and gates against the "
    "ExpGuardTest baseline the UPA figure was measured on -- a corpus this recipe cannot reach "
    "and a baseline this recipe must not be scored against.",
)

_EXPGUARD_WEAK_NOTES = (
    "The ONLY recipe that can train for Unqualified Professional Advice. UPA is the weakest "
    "measured class on both guard sizes (0.3719 on the 0.6B, 0.4298 on the 4B) and it exists "
    "only in ExpGuardMix -- the WildGuardMix train split has no such category, which is why the "
    "two WildGuard weak-category recipes no longer declare it and target three classes each.",
    "Gated against expguardtest-qwen3guard-gen-0.6b, the same-size baseline measured on the same "
    "split, seed, num_ctx and quantisation. THE BAR, computed with this repo's own `stats` "
    "against that baseline's overall slice (898/1256 caught, 89/1019 false positives): promotion "
    "needs at least 942 caught (recall >= 0.7500, i.e. +44 rows) AND fewer than 116 false "
    "positives (FPR below 0.1138). The minimum detectable delta is 0.0353; anything smaller is "
    "`within_noise` and is a reject, correctly.",
    "Four classes, not one, and the reason is arithmetic. UPA has only 76 missed positives in "
    "the whole 2,275-row test split, so a UPA-only adapter would have to nearly double its "
    "recall before the `overall` slice moved at all. The four together carry 127 recoverable "
    "misses (UPA 76, Privacy Violation 13, Violence & Incitement 19, Self-Harm 19), so about a "
    "third of them clears the bar.",
    "MEASURE THE 0.6B's SEVERITY EXPOSURE BEFORE TRAINING, and budget for it as the most likely "
    "failure mode. Run weak-2026-08-13a took Qwen3Guard's `Controversial` verdicts from 49 to 0 "
    "over 1,699 WildGuard samples. On ExpGuardTest the 4B's `Controversial` verdicts carry 235 "
    "of 954 true positives -- losing them drops recall 0.7596 -> 0.5725, four times what "
    "flattening cost on WildGuard. The 0.6B's exposure is recorded NOWHERE: no ExpGuard result "
    "document is committed in this repository. Without that number a reject cannot be attributed "
    "between 'the adapter did not learn' and 'the adapter flattened severity'. "
    "supervise_severity=False is the mitigation and it has never been run.",
    "Two of the six per-category floors -- Fraud, Scams & Deception (603 positives) and Criminal "
    "Planning (356) -- are NOT trained for by this recipe and can only fall. That is the gate "
    "working, not a flaw: an aggregate that improves while a class collapses is exactly what the "
    "floors exist to refuse.",
    "Do NOT pass --sample-size when scoring. `stratified_sample` stratifies on (domain, "
    "prompt_label), not category, and Privacy Violation has 25 test positives -- a subsample can "
    "drop a floor-bearing class entirely, which the gate reports as insufficient_evidence.",
    "COMMERCIAL USE IS NOT CLEARED. ExpGuardMix's licence is CC-BY-4.0 and its gate form says "
    "research-only; the click-through is the agreement that was signed and it is the narrower "
    "one. Its corpus was GPT-4o-generated upstream. A promotion here is a quality verdict and "
    "never a clearance for a shipped vertical pack -- the baseline carries that string and the "
    "decision record prints it.",
    "Run describe_split on the TRAIN split first. Verified 2026-08-13 against the cached file: "
    "46,005 rows, prompt_label {unsafe 25877, safe 20128}, no `adversarial` column (so the "
    "adversarial variant is not available on this corpus), and these four categories select "
    "5,636 positives + 5,636 benign with 0 rows dropped and 0 train/test leakage.",
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
        # The two 0.6B WildGuard recipes gate against the 0.6B baseline, not the 4B one. That
        # baseline was measured on 2026-08-13 for exactly this purpose and then left unbound, so
        # every 0.6B candidate was still being asked to beat a model seven times its size -- a
        # legitimate product question ("can we ship the small one") standing in for the question
        # a training run actually asks ("did tuning help"). Re-pointing changes both digests,
        # which is correct and has precedent in the supervise_severity revision.
        _guard_recipe(
            "qwen3guard-gen-0.6b",
            "weak-category",
            "warrantor_ml.tasks.guard:weak_category_subset",
            1.0,
            "overall",
            _WEAK_NOTES,
            dataset_id="wildguardmix",
            baseline_id="wildguardtest-qwen3guard-gen-0.6b",
            categories=WILDGUARD_WEAK_CATEGORIES,
        ),
        _guard_recipe(
            "qwen3guard-gen-0.6b",
            "adversarial",
            "warrantor_ml.tasks.guard:adversarial_subset",
            1.5,
            "adversarial_true",
            _ADVERSARIAL_NOTES,
            dataset_id="wildguardmix",
            baseline_id="wildguardtest-qwen3guard-gen-0.6b",
        ),
        _guard_recipe(
            "qwen3guard-gen-0.6b",
            "expguard-weak",
            "warrantor_ml.tasks.guard:weak_category_subset",
            1.0,
            "overall",
            _EXPGUARD_WEAK_NOTES,
            dataset_id="expguardmix",
            baseline_id="expguardtest-qwen3guard-gen-0.6b",
            categories=EXPGUARD_WEAK_CATEGORIES,
        ),
        _guard_recipe(
            "qwen3guard-gen-4b",
            "weak-category",
            "warrantor_ml.tasks.guard:weak_category_subset",
            1.0,
            "overall",
            _WEAK_NOTES,
            dataset_id="wildguardmix",
            baseline_id="wildguardtest-qwen3guard-gen-4b",
            categories=WILDGUARD_WEAK_CATEGORIES,
        ),
        _guard_recipe(
            "qwen3guard-gen-4b",
            "adversarial",
            "warrantor_ml.tasks.guard:adversarial_subset",
            1.5,
            "adversarial_true",
            _ADVERSARIAL_NOTES,
            dataset_id="wildguardmix",
            baseline_id="wildguardtest-qwen3guard-gen-4b",
        ),
        # DELIBERATELY ABSENT: a 4B ExpGuard recipe. `expguardtest-qwen3guard-gen-4b` carries ONE
        # per-category floor (UPA 0.4298) where the 0.6B baseline carries six, because that is
        # all ml/README.md transcribed -- everything else is aggregated as "0.7947 for every
        # other class". Binding it now would gate the better-instrumented-looking model with five
        # ExpGuard classes unprotected. It needs a re-run of `benchmark_expguard` against the 4B,
        # and those numbers must not be invented.
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


#: Measured baselines that no recipe binds, each with the reason it is not bound YET.
#:
#: An entry here is a deferral on the record, not an exemption. :func:`unbound_baselines` returns
#: any registered baseline missing from both this table and the recipes, and
#: ``warrantor-ml-recipes`` prints the result -- so the next baseline that is measured, committed
#: and then forgotten shows up as UNEXPLAINED on a command a human runs, rather than as three
#: silently unreachable entries in ``baselines.BASELINES``, which is what was there before.
DEFERRED_BASELINES: dict[str, str] = {
    "expguardtest-qwen3guard-gen-4b": (
        "DEFERRED pending re-measurement. This baseline carries ONE per-category floor "
        "(unqualified professional advice 0.4298) where the 0.6B ExpGuard baseline carries six, "
        "because ml/README.md aggregated everything else as '0.7947 for every other class'. A 4B "
        "ExpGuard recipe bound to it would be gated with five ExpGuard classes unprotected while "
        "looking better instrumented than the 0.6B. Unblock by re-running benchmark_expguard "
        "against the 4B and transcribing the full by_prompt_category table; do not invent it."
    ),
}


def unbound_baselines() -> dict[str, str]:
    """Every measured baseline no recipe names, mapped to why -- or to a refusal to guess.

    A baseline nothing binds is not "available", it is dead: ``programme.parity_main`` reads
    ``recipe.baseline_id`` and exposes no override, so there is no CLI path to gate against it.
    Three of the four registered baselines were in that state, including one whose own docstring
    said it existed for recipes that were never re-pointed at it.
    """

    from .baselines import BASELINES

    bound = {recipe.baseline_id for recipe in RECIPES.values() if recipe.baseline_id}
    return {
        baseline_id: DEFERRED_BASELINES.get(
            baseline_id,
            "UNEXPLAINED: no recipe binds this baseline and no deferral reason is recorded in "
            "recipes.DEFERRED_BASELINES. Nothing can be gated against it. Bind it to a recipe or "
            "write down why it is not bound yet.",
        )
        for baseline_id in sorted(BASELINES)
        if baseline_id not in bound
    }


def list_recipes() -> tuple[Recipe, ...]:
    """Every recipe in stable id order."""

    return tuple(RECIPES[key] for key in sorted(RECIPES))


def get_recipe(recipe_id: str) -> Recipe:
    """Look up one recipe, or fail naming the nine."""

    try:
        return RECIPES[recipe_id]
    except KeyError as error:
        known = ", ".join(sorted(RECIPES))
        raise KeyError(f"unknown recipe {recipe_id!r}; declared: {known}") from error
