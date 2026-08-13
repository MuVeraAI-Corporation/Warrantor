"""The eight recipes: enumerated, digested, and honest about the four that cannot run yet."""

from __future__ import annotations

import pytest

from warrantor_ml.baselines import BASELINES
from warrantor_ml.fine_tune import PROFILES
from warrantor_ml.recipes import RECIPES, get_recipe, list_recipes


def test_there_are_exactly_eight_recipes() -> None:
    assert len(RECIPES) == 8


def test_the_four_guard_variants_are_the_two_sizes_times_the_two_axes() -> None:
    guard_ids = {key for key in RECIPES if key.startswith("guard-")}
    assert guard_ids == {
        "guard-0.6b-weak-category",
        "guard-0.6b-adversarial",
        "guard-4b-weak-category",
        "guard-4b-adversarial",
    }


def test_the_four_substrate_models_are_present() -> None:
    assert {"bound-proposer", "refusal-triage", "effect-risk", "report-summariser"} <= set(RECIPES)


def test_every_recipe_targets_a_declared_profile() -> None:
    for recipe in list_recipes():
        assert recipe.config.profile_key in PROFILES


def test_an_unknown_recipe_names_the_eight() -> None:
    with pytest.raises(KeyError, match="declared:"):
        get_recipe("guard-70b-magic")


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
