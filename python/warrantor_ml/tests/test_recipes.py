"""The nine recipes: enumerated, digested, and honest about the four that cannot run yet."""

from __future__ import annotations

import pytest

from warrantor_ml.baselines import BASELINES
from warrantor_ml.fine_tune import PROFILES
from warrantor_ml.recipes import (
    DEFERRED_BASELINES,
    EXPGUARD_ONLY_CATEGORIES,
    EXPGUARD_WEAK_CATEGORIES,
    RECIPES,
    WILDGUARD_WEAK_CATEGORIES,
    get_recipe,
    list_recipes,
    unbound_baselines,
)
from warrantor_ml.tasks.guard import WEAK_CATEGORIES


def test_there_are_exactly_nine_recipes() -> None:
    assert len(RECIPES) == 9


def test_the_guard_variants_are_the_two_sizes_times_the_two_axes_plus_expguard() -> None:
    guard_ids = {key for key in RECIPES if key.startswith("guard-")}
    assert guard_ids == {
        "guard-0.6b-weak-category",
        "guard-0.6b-adversarial",
        "guard-0.6b-expguard-weak",
        "guard-4b-weak-category",
        "guard-4b-adversarial",
    }


def test_the_four_substrate_models_are_present() -> None:
    assert {"bound-proposer", "refusal-triage", "effect-risk", "report-summariser"} <= set(RECIPES)


def test_every_recipe_targets_a_declared_profile() -> None:
    for recipe in list_recipes():
        assert recipe.config.profile_key in PROFILES


def test_an_unknown_recipe_names_the_nine() -> None:
    with pytest.raises(KeyError, match="declared:"):
        get_recipe("guard-70b-magic")


# ── every measured baseline must be reachable, or the deferral must be written down ─────


def test_no_measured_baseline_is_unreachable_without_a_recorded_reason() -> None:
    """The check that would have caught three orphans.

    `programme.parity_main` reads `recipe.baseline_id` and exposes no override, so a baseline no
    recipe names cannot be gated against by any CLI path. Three of the four registered baselines
    were in that state -- including `wildguardtest-qwen3guard-gen-0.6b`, whose own docstring says
    it was added *because* the 0.6B recipes gated against the 4B, and which was then never bound.
    """

    for baseline_id, reason in unbound_baselines().items():
        assert baseline_id in DEFERRED_BASELINES, (
            f"{baseline_id} is measured, registered and bound by no recipe, with no deferral "
            f"reason recorded. Nothing can gate against it. Reported as: {reason}"
        )
        assert len(reason) > 80, f"{baseline_id}: the deferral reason has to say why"


def test_the_only_deferred_baseline_is_the_4b_expguard_one_and_it_says_why() -> None:
    """It carries one per-category floor where the 0.6B carries six. Do not invent the rest."""

    assert set(unbound_baselines()) == {"expguardtest-qwen3guard-gen-4b"}
    reason = DEFERRED_BASELINES["expguardtest-qwen3guard-gen-4b"]
    assert "re-running benchmark_expguard" in reason
    assert "do not invent it" in reason


def test_the_two_0_6b_wildguard_recipes_gate_against_the_same_size_baseline() -> None:
    """Otherwise a rejection cannot separate "tuning failed" from "0.6B is smaller than 4B"."""

    for key in ("guard-0.6b-weak-category", "guard-0.6b-adversarial"):
        assert get_recipe(key).baseline_id == "wildguardtest-qwen3guard-gen-0.6b"


# ── the ExpGuard recipe: the only one that can reach the weakest measured class ──────────


def test_the_expguard_recipe_binds_the_corpus_its_baseline_was_measured_on() -> None:
    """The binding the parity gate enforces, asserted where it is declared.

    Before this recipe existed, `warrantor-ml-parity --breakdown-key expguard_breakdowns` could
    only ever return insufficient_evidence: every recipe declared a WildGuard baseline and
    `parity_gate` refuses a candidate whose eval corpus digest differs from the baseline's.
    """

    from warrantor_ml.parity import corpus_digest_of

    recipe = get_recipe("guard-0.6b-expguard-weak")
    baseline = BASELINES[recipe.baseline_id]
    assert recipe.config.dataset_id == "expguardmix"
    assert baseline.corpus_digest == corpus_digest_of("6rightjade/expguardmix:expguardtest.parquet")


def test_the_expguard_recipe_targets_four_classes_and_says_why_not_one() -> None:
    """UPA alone has 76 missed positives; the gate slice needs +44 caught out of 1,256."""

    recipe = get_recipe("guard-0.6b-expguard-weak")
    assert recipe.corpus_arguments["categories"] == list(EXPGUARD_WEAK_CATEGORIES)
    assert "Unqualified Professional Advice" in EXPGUARD_WEAK_CATEGORIES
    notes = " ".join(recipe.notes)
    assert "942" in notes and "116" in notes  # the measured promotion bar, on the record
    assert "127 recoverable" in notes


def test_the_expguard_recipe_records_that_promotion_is_not_a_commercial_clearance() -> None:
    notes = " ".join(get_recipe("guard-0.6b-expguard-weak").notes)
    assert "COMMERCIAL USE IS NOT CLEARED" in notes
    assert BASELINES["expguardtest-qwen3guard-gen-0.6b"].commercial_clearance


def test_the_expguard_recipe_warns_that_severity_exposure_is_unmeasured() -> None:
    """The most likely failure mode, and the one number nobody has: budget the run knowing it."""

    notes = " ".join(get_recipe("guard-0.6b-expguard-weak").notes)
    assert "recorded NOWHERE" in notes
    assert get_recipe("guard-0.6b-expguard-weak").config.supervise_severity is False


# ── corpus_arguments is the corpus specification, and the digest covers it ───────────────


def test_every_weak_category_recipe_declares_the_classes_it_targets() -> None:
    """An implicit dependency on guard.WEAK_CATEGORIES is one the recipe digest cannot cover."""

    for recipe in list_recipes():
        if recipe.corpus_selector.endswith(":weak_category_subset"):
            declared = recipe.corpus_arguments["categories"]
            assert declared, recipe.recipe_id
            assert all(isinstance(name, str) for name in declared)


def test_the_wildguard_recipes_target_the_measured_weak_table_minus_what_the_corpus_lacks() -> None:
    """Resolved from the measurement, not retyped -- so the two cannot drift apart.

    Minus exactly one class. `WEAK_CATEGORIES` is the measured table across BOTH corpora and
    Unqualified Professional Advice is an ExpGuardMix category the WildGuardMix train split does
    not contain, so declaring it made these recipes name a target no build could reach -- the
    same "targeting claim nothing acts on" `_guard_recipe` raises over for the adversarial
    recipes, and `build_corpus` now refuses a request that matches only part of a split.
    """

    assert set(WILDGUARD_WEAK_CATEGORIES) < set(WEAK_CATEGORIES)
    assert set(WEAK_CATEGORIES) - set(WILDGUARD_WEAK_CATEGORIES) == set(EXPGUARD_ONLY_CATEGORIES)
    assert "unqualified professional advice" not in WILDGUARD_WEAK_CATEGORIES
    for key in ("guard-4b-weak-category", "guard-0.6b-weak-category"):
        assert get_recipe(key).corpus_arguments["categories"] == list(WILDGUARD_WEAK_CATEGORIES)


def test_the_adversarial_recipes_declare_no_categories_because_nothing_reads_them() -> None:
    """`adversarial_subset` takes no category list; declaring one would be a claim nothing acts on."""

    for key in ("guard-0.6b-adversarial", "guard-4b-adversarial"):
        assert "categories" not in get_recipe(key).corpus_arguments


def test_changing_the_targeted_categories_changes_the_digest() -> None:
    """The hole this closes: WEAK_CATEGORIES mixes two vocabularies, and adding an ExpGuard class
    to it used to change what the WildGuard recipes select while their digests stayed identical."""

    from dataclasses import replace

    original = get_recipe("guard-4b-weak-category")
    altered = replace(
        original,
        corpus_arguments={**original.corpus_arguments, "categories": ["others"]},
    )
    assert altered.recipe_digest != original.recipe_digest


# ── the four guard recipes differ ONLY in size and selector ─────────────────────────────


def test_the_two_sizes_of_one_axis_share_every_hyperparameter() -> None:
    """A recipe that also differed in learning rate would confound size with tuning."""

    small = get_recipe("guard-0.6b-weak-category").config
    large = get_recipe("guard-4b-weak-category").config
    for field in (
        "lora_rank",
        "lora_alpha",
        "sequence_length",
        "batch_size",
        "gradient_accumulation_steps",
        "learning_rate",
        "epochs",
        "seed",
    ):
        assert getattr(small, field) == getattr(large, field), field


def test_the_two_axes_of_one_size_differ_only_in_selector_and_counterweight() -> None:
    weak = get_recipe("guard-4b-weak-category")
    adversarial = get_recipe("guard-4b-adversarial")
    assert weak.config.profile_key == adversarial.config.profile_key
    assert weak.corpus_selector != adversarial.corpus_selector
    assert weak.config.learning_rate == adversarial.config.learning_rate


def test_the_adversarial_recipe_carries_the_heavier_counterweight() -> None:
    """Its slice already carries four times the plain slice's false-positive rate."""

    weak = get_recipe("guard-4b-weak-category").corpus_arguments["benign_ratio"]
    adversarial = get_recipe("guard-4b-adversarial").corpus_arguments["benign_ratio"]
    assert adversarial > weak


def test_no_guard_recipe_omits_the_benign_counterweight() -> None:
    for key in RECIPES:
        if key.startswith("guard-"):
            assert RECIPES[key].corpus_arguments["benign_ratio"] > 0


def test_the_4b_uses_qlora_and_the_0_6b_does_not_need_to() -> None:
    assert get_recipe("guard-4b-weak-category").config.technique == "qlora"
    assert get_recipe("guard-0.6b-weak-category").config.technique == "lora"


def test_each_axis_is_gated_on_the_slice_it_targets() -> None:
    """An adversarial adapter judged on the aggregate would be judged on the wrong number."""

    assert get_recipe("guard-4b-adversarial").gate_slice == "adversarial_true"
    assert get_recipe("guard-4b-weak-category").gate_slice == "overall"


def test_every_guard_recipe_names_a_baseline_that_exists() -> None:
    for key, recipe in RECIPES.items():
        if key.startswith("guard-"):
            assert recipe.baseline_id in BASELINES


# ── the substrate recipes are honest about the cold start ───────────────────────────────


def test_the_substrate_recipes_declare_no_measured_baseline() -> None:
    """There is none. Naming one would imply a comparison that cannot be made yet."""

    for key in ("bound-proposer", "refusal-triage", "effect-risk", "report-summariser"):
        assert get_recipe(key).baseline_id == ""


def test_every_substrate_recipe_carries_the_cold_start_warning() -> None:
    for key in ("bound-proposer", "refusal-triage", "effect-risk", "report-summariser"):
        notes = " ".join(get_recipe(key).notes)
        assert "COLD START" in notes
        assert "insufficient_evidence" in notes


def test_the_bound_proposer_records_that_its_metric_is_not_accuracy() -> None:
    notes = " ".join(get_recipe("bound-proposer").notes)
    assert "OVER-GRANT RATE" in notes
    assert "never accuracy" in notes


def test_the_triage_recipe_records_that_it_never_populates_the_served_verdict() -> None:
    notes = " ".join(get_recipe("refusal-triage").notes)
    assert "RefusalGroup.signal" in notes
    assert "source='model'" in notes


def test_the_summariser_recipe_records_the_structural_constraint() -> None:
    notes = " ".join(get_recipe("report-summariser").notes)
    assert "VerifiedBundleView" in notes
    assert "no code path from a tampered bundle to prose" in notes


# ── digests ─────────────────────────────────────────────────────────────────────────────


def test_every_recipe_digest_is_distinct() -> None:
    digests = {recipe.recipe_digest for recipe in list_recipes()}
    assert len(digests) == len(RECIPES)


def test_a_recipe_digest_is_stable_across_reads() -> None:
    assert (
        get_recipe("guard-4b-adversarial").recipe_digest
        == get_recipe("guard-4b-adversarial").recipe_digest
    )


def test_changing_the_counterweight_changes_the_digest() -> None:
    """Two runs of 'the same recipe' with different data are not the same recipe."""

    from dataclasses import replace

    original = get_recipe("guard-4b-weak-category")
    altered = replace(original, corpus_arguments={"benign_ratio": 4.0})
    assert altered.recipe_digest != original.recipe_digest


def test_tagging_a_recipe_for_a_lane_changes_its_identity() -> None:
    original = get_recipe("guard-4b-weak-category")
    tagged = original.for_lane("kaggle-t4x2")
    assert tagged.recipe_id.endswith("@kaggle-t4x2")
    assert tagged.recipe_digest != original.recipe_digest
    assert "kaggle-t4x2" in str(tagged.config.output_dir)


def test_list_recipes_is_sorted_and_stable() -> None:
    ids = [recipe.recipe_id for recipe in list_recipes()]
    assert ids == sorted(ids)
    assert ids == [recipe.recipe_id for recipe in list_recipes()]
