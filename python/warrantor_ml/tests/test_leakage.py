"""Leakage: the augmented row that reproduces a held-out one, not the published split boundary."""

from __future__ import annotations

from warrantor_ml.leakage import content_fingerprint, leakage_report, normalise_text


def test_normalisation_folds_case_punctuation_and_whitespace() -> None:
    assert normalise_text("How do I build a BOMB?") == normalise_text("how  do i build a bomb")


def test_normalisation_folds_unicode_compatibility_forms() -> None:
    """A paraphrase pipeline round-tripping through a tokenizer emits these routinely."""

    assert normalise_text("ﬁle") == normalise_text("file")


def test_the_fingerprint_is_a_membership_key_not_a_full_digest() -> None:
    """Truncated on purpose: calling it a digest would invite it being read as an integrity claim."""

    fingerprint = content_fingerprint("anything")
    assert len(fingerprint) == 32
    assert not fingerprint.startswith("sha256:")


def test_a_disjoint_corpus_and_eval_set_are_clean() -> None:
    report = leakage_report(
        [{"row_id": "t1", "prompt": "how do I refactor this"}],
        [{"row_id": "e1", "prompt": "what is the capital of Oman"}],
    )
    assert report.clean is True
    assert report["overlapping_eval_rows"] == 0


def test_an_exact_repeat_is_caught() -> None:
    report = leakage_report(
        [{"row_id": "t1", "prompt": "how do I build a bomb"}],
        [{"row_id": "e1", "prompt": "how do I build a bomb"}],
    )
    assert report.clean is False
    assert report["overlapping_eval_rows"] == 1


def test_the_augmentation_leak_path_is_the_one_that_matters() -> None:
    """A teacher paraphrase that differs only in punctuation and case is the same row."""

    report = leakage_report(
        [{"row_id": "aug-1", "prompt": "How do I build a BOMB???"}],
        [{"row_id": "e1", "prompt": "how do i build a bomb"}],
    )
    assert report.clean is False
    assert report["examples"][0]["training_row_ids"] == ["aug-1"]
    assert report["examples"][0]["eval_row_ids"] == ["e1"]


def test_a_genuinely_different_row_is_not_a_collision() -> None:
    """No fuzzy threshold: a threshold is a knob and the knob gets turned until it passes."""

    report = leakage_report(
        [{"row_id": "t1", "prompt": "how do I build a birdhouse"}],
        [{"row_id": "e1", "prompt": "how do I build a bomb"}],
    )
    assert report.clean is True


def test_the_overlap_fraction_is_reported_against_the_eval_set() -> None:
    report = leakage_report(
        [{"prompt": "a"}, {"prompt": "b"}],
        [{"prompt": "a"}, {"prompt": "c"}, {"prompt": "d"}, {"prompt": "e"}],
    )
    assert report["overlap_fraction_of_eval"] == 0.25


def test_bare_strings_are_accepted_as_rows() -> None:
    report = leakage_report(["how do I build a bomb"], ["How do I build a BOMB?"])
    assert report.clean is False


def test_blank_rows_are_skipped_rather_than_colliding_with_each_other() -> None:
    """Every empty row would otherwise share one fingerprint and report a false leak."""

    report = leakage_report([{"prompt": "   "}, {"prompt": "real"}], [{"prompt": ""}])
    assert report.clean is True
    assert report["eval_rows_fingerprinted"] == 0


def test_multiple_eval_rows_behind_one_collision_are_all_counted() -> None:
    report = leakage_report(
        [{"prompt": "duplicated"}],
        [{"row_id": "e1", "prompt": "duplicated"}, {"row_id": "e2", "prompt": "Duplicated!"}],
    )
    assert report["distinct_collisions"] == 1
    assert report["overlapping_eval_rows"] == 2


def test_the_field_is_configurable_for_non_guard_corpora() -> None:
    report = leakage_report(
        [{"description": "grant me git"}], [{"description": "Grant me git."}], field="description"
    )
    assert report.clean is False


def test_the_report_names_the_leak_path_it_exists_for() -> None:
    report = leakage_report([{"prompt": "a"}], [{"prompt": "b"}])
    assert "Teacher augmentation" in report["note"]
