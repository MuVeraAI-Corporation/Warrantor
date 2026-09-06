"""Tests for tools/ci/check_claims.py — the public claim ledger checker.

Every refusal test below is paired with an allowed control. A checker that refuses every entry
passes a one-sided test and proves nothing, which is why the controls are not decoration: each one
names, in its docstring, the refusal it keeps honest.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

from check_claims import (
    LEDGER_FORMAT,
    LEDGER_RELATIVE_PATH,
    LOCALES_RELATIVE_PATH,
    REPOSITORY_ROOT,
    ClaimIssue,
    check_append_only,
    check_bound_statement,
    check_claim,
    check_ledger,
    check_views,
    head_digest,
    history_digest,
    load_ledger,
    load_locales,
    render_view,
    state_digest,
    wiring_reachability,
)


def a_fact(**overrides: object) -> dict[str, object]:
    """A minimal well-formed `fact` entry; overrides break exactly one thing."""

    claim: dict[str, object] = {
        "id": "CL-001",
        "status": "fact",
        "version": 1,
        "text": "9 of 39 crates reachable",
        "falsifier": {
            "who": "anyone with a clone",
            "how": "python tools/ci/wiring_census.py disagrees with the rendered number",
        },
        "derived_from": {
            "record": "evidence/wiring-coverage.json",
            "pointers": ["/reachable", "/total"],
        },
        "template": "{0} of {1} crates reachable",
        "surfaces": ["docs/public-claims.md"],
        "corrections": [],
    }
    claim.update(overrides)
    return claim


def test_a_claim_with_no_falsifier_is_refused(tmp_path: Path) -> None:
    issues = check_claim(tmp_path, a_fact(falsifier={}))
    assert (
        ClaimIssue("CL-001", "no falsifier: an entry must name who could show it false and how")
        in issues
    ), issues


def test_a_claim_with_an_empty_how_is_refused(tmp_path: Path) -> None:
    broken = a_fact(falsifier={"who": "a reviewer", "how": "   "})
    assert any("falsifier.how" in issue.message for issue in check_claim(tmp_path, broken))


def test_the_allowed_control_a_well_formed_claim_raises_no_falsifier_issue(tmp_path: Path) -> None:
    """The control. Without this, a checker that refuses everything passes the two above."""

    issues = check_claim(tmp_path, a_fact())
    assert not [issue for issue in issues if "falsifier" in issue.message], issues


RECORD = '{"format": "warrantor.wiring-coverage/1", "reachable": 9, "total": 39, "edges": 17}'


def fake_tree(tmp_path: Path, surface_text: str) -> Path:
    """A tree holding one record and one surface, so `check_claim` has something to read."""

    (tmp_path / "evidence").mkdir(exist_ok=True)
    (tmp_path / "evidence" / "wiring-coverage.json").write_text(RECORD, encoding="utf-8")
    (tmp_path / "docs").mkdir(exist_ok=True)
    (tmp_path / "docs" / "public-claims.md").write_text(surface_text, encoding="utf-8")
    return tmp_path


def test_a_stale_rendering_is_refused(tmp_path: Path) -> None:
    tree = fake_tree(tmp_path, "the census says 8 of 39 crates reachable\n")
    issues = check_claim(tree, a_fact())
    assert any("does not render" in issue.message for issue in issues), issues
    assert any("docs/public-claims.md" in issue.message for issue in issues), issues


def test_the_allowed_control_a_current_rendering_passes(tmp_path: Path) -> None:
    """The control: the same claim against a surface that does show the number."""

    tree = fake_tree(tmp_path, "the census says 9 of 39 crates reachable\n")
    assert check_claim(tree, a_fact()) == []


def test_a_number_changed_in_the_record_alone_is_refused(tmp_path: Path) -> None:
    """The direction that matters: the record moves, the prose does not."""

    tree = fake_tree(tmp_path, "the census says 9 of 39 crates reachable\n")
    (tree / "evidence" / "wiring-coverage.json").write_text(
        RECORD.replace('"reachable": 9', '"reachable": 10'), encoding="utf-8"
    )
    assert any("does not render" in issue.message for issue in check_claim(tree, a_fact()))


def test_a_fact_whose_own_text_omits_its_derived_rendering_is_refused(tmp_path: Path) -> None:
    """A `fact` is bound to its record through its own text, not only through its surfaces."""

    tree = fake_tree(tmp_path, "the census says 9 of 39 crates reachable\n")
    drifted = a_fact(text="lots of crates are reachable")
    messages = [issue.message for issue in check_claim(tree, drifted)]
    assert any("text does not contain" in message for message in messages), messages


def test_a_fact_with_no_record_is_refused(tmp_path: Path) -> None:
    """`fact` means recomputed from a named record. Without one it is a slogan."""

    tree = fake_tree(tmp_path, "9 of 39 crates reachable\n")
    messages = [issue.message for issue in check_claim(tree, a_fact(derived_from={}))]
    assert any("fact needs derived_from" in message for message in messages), messages


def test_the_allowed_control_a_claim_status_entry_needs_no_record(tmp_path: Path) -> None:
    """The control for the rule above: only `fact` is held to a recomputable record."""

    tree = fake_tree(tmp_path, "a thing that cannot be recomputed here\n")
    entry = a_fact(
        status="claim",
        derived_from={},
        template="",
        text="a thing that cannot be recomputed here",
    )
    assert check_claim(tree, entry) == []


def test_a_claim_status_entry_with_a_surface_is_still_quoted_accurately(tmp_path: Path) -> None:
    """A `claim` is not exempt from being quoted correctly just because it is not a `fact`."""

    tree = fake_tree(tmp_path, "something else entirely\n")
    entry = a_fact(status="claim", derived_from={}, template="", text="the quoted sentence")
    assert any("does not render" in issue.message for issue in check_claim(tree, entry))


# --- corrections -------------------------------------------------------------------------------


def a_corrected(**overrides: object) -> dict[str, object]:
    """An entry at version 2 whose one correction retains version 1 verbatim."""

    prior_text = "I-07 (evidence precedes commitment) is orphaned."
    claim = a_fact(
        id="CL-004",
        version=2,
        text="I-07 (evidence precedes commitment) is partial.",
        template="I-07 (evidence precedes commitment) is partial.",
        derived_from={"record": "evidence/wiring-coverage.json", "pointers": []},
        corrections=[
            {
                "version": 1,
                "date": "2026-09-05",
                "reason": (
                    "the ledger and the gaps table disagreed; evidence/invariants.json is "
                    "the record"
                ),
                "superseded_status": "fact",
                "superseded_text": prior_text,
                "supersedes_digest": state_digest("CL-004", 1, "fact", prior_text),
            }
        ],
    )
    claim.update(overrides)
    return claim


def test_a_silent_rewrite_is_refused(tmp_path: Path) -> None:
    """Text changed, version bumped, nothing retained. This is the defect."""

    silent = a_corrected(corrections=[])
    messages = [issue.message for issue in check_claim(tmp_path, silent)]
    assert any("version 2 with 0 corrections" in message for message in messages), messages


def test_a_correction_that_misquotes_the_superseded_text_is_refused(tmp_path: Path) -> None:
    """A retained text that does not hash to its own digest is a rewritten history."""

    tampered = a_corrected()
    cast(list[dict[str, object]], tampered["corrections"])[0]["superseded_text"] = "I-07 is fine."
    assert any("supersedes_digest" in issue.message for issue in check_claim(tmp_path, tampered))


def test_a_correction_with_no_date_is_refused(tmp_path: Path) -> None:
    undated = a_corrected()
    del cast(list[dict[str, object]], undated["corrections"])[0]["date"]
    assert any("date" in issue.message for issue in check_claim(tmp_path, undated))


def test_a_correction_with_no_reason_is_refused(tmp_path: Path) -> None:
    unexplained = a_corrected()
    cast(list[dict[str, object]], unexplained["corrections"])[0]["reason"] = ""
    assert any("reason" in issue.message for issue in check_claim(tmp_path, unexplained))


def test_corrections_dated_backward_are_refused(tmp_path: Path) -> None:
    """Two corrections whose dates move backward cannot both be honest."""

    first = cast(list[dict[str, object]], a_corrected()["corrections"])[0]
    older_text = "I-07 was something else."
    second = {
        "version": 2,
        "date": "2026-01-01",
        "reason": "backdated",
        "superseded_status": "fact",
        "superseded_text": older_text,
        "supersedes_digest": state_digest("CL-004", 2, "fact", older_text),
    }
    claim = a_corrected(version=3, corrections=[first, second])
    assert any("date moves backward" in issue.message for issue in check_claim(tmp_path, claim))


def test_the_allowed_control_a_properly_versioned_correction_passes(tmp_path: Path) -> None:
    """The control: a correction done right is accepted, so the refusals above are not universal."""

    tree = fake_tree(tmp_path, "I-07 (evidence precedes commitment) is partial.\n")
    assert check_claim(tree, a_corrected()) == []


# --- append-only, against the parent commit ----------------------------------------------------


def test_removing_a_correction_is_refused() -> None:
    before = {"claims": [a_corrected()]}
    after = {
        "claims": [
            a_corrected(
                version=1,
                corrections=[],
                text="I-07 (evidence precedes commitment) is orphaned.",
            )
        ]
    }
    messages = [issue.message for issue in check_append_only(before, after)]
    assert any("was removed or altered" in message for message in messages), messages
    assert any("version fell" in message for message in messages), messages


def test_deleting_a_whole_claim_is_refused() -> None:
    issues = check_append_only({"claims": [a_corrected()]}, {"claims": []})
    assert [issue.message for issue in issues] == [
        "removed from the ledger; entries are append-only"
    ]


def test_rewriting_a_retained_reason_is_refused() -> None:
    """The flattering rewrite: the correction stays, its reason is softened."""

    after = a_corrected()
    cast(list[dict[str, object]], after["corrections"])[0]["reason"] = "a minor clarification"
    messages = [
        issue.message
        for issue in check_append_only({"claims": [a_corrected()]}, {"claims": [after]})
    ]
    assert any("was removed or altered" in message for message in messages), messages


def test_the_allowed_control_appending_a_correction_passes() -> None:
    """The control: growth is allowed, which is the whole point of an append-only ledger.

    The parent's `text` is set to what `a_corrected`'s one correction retains. Before the
    published-state comparison below existed this fixture did not have to be consistent, because
    nothing read the parent's text -- which is precisely the hole the comparison closes. The
    assertion is unchanged; only the fixture was made honest.
    """

    published = "I-07 (evidence precedes commitment) is orphaned."
    before = {"claims": [a_fact(id="CL-004", text=published)]}
    assert check_append_only(before, {"claims": [a_corrected()]}) == []


def test_the_allowed_control_adding_a_new_claim_passes() -> None:
    """The control: a ledger that could never gain an entry would be a freeze, not a ratchet."""

    before = {"claims": [a_fact()]}
    after = {"claims": [a_fact(), a_corrected()]}
    assert check_append_only(before, after) == []


def test_dropping_the_last_correction_changes_the_history_digest() -> None:
    """Detection by comparison: an offline holder of the earlier copy sees the digest move."""

    full = a_corrected()
    shortened = a_corrected(version=1, corrections=[], text="I-07 ... is orphaned.")
    assert history_digest(full) != history_digest(shortened)


def test_the_head_digest_moves_when_any_claim_history_moves() -> None:
    before = {"format": LEDGER_FORMAT, "claims": [a_fact(), a_corrected()]}
    after = {"format": LEDGER_FORMAT, "claims": [a_fact(), a_corrected(corrections=[], version=1)]}
    assert head_digest(before) != head_digest(after)


def test_the_allowed_control_an_unchanged_ledger_keeps_its_head_digest() -> None:
    """The control: the digest is a function of content, not of the moment it was computed."""

    ledger = {"format": LEDGER_FORMAT, "claims": [a_fact(), a_corrected()]}
    assert head_digest(ledger) == head_digest(ledger)


# --- the published state itself, compared across revisions --------------------------------------
#
# The block above compares versions and retained corrections. It does not compare the one thing a
# reader actually reads: the entry's current text. Both tests below passed against a checker that
# permitted the rewrite, which is how they were found -- by running the gate on a hand-built
# rewrite rather than by reading the code.


def test_rewriting_a_published_text_at_the_same_version_is_refused() -> None:
    """The defect this checker was built to refuse, performed on the checker's own ledger.

    Version left at 1, corrections left empty, text replaced. Every earlier assertion in this file
    is satisfied by that edit: the version did not fall, no correction was dropped, and the new
    text hashes to a new head that `--write` will happily record.
    """

    before = {"claims": [a_fact()]}
    after = {"claims": [a_fact(text="41 of 41 crates reachable")]}
    messages = [issue.message for issue in check_append_only(before, after)]
    assert any("with no correction appended" in message for message in messages), messages
    assert any("9 of 39 crates reachable" in message for message in messages), messages


def test_rewriting_a_published_status_at_the_same_version_is_refused() -> None:
    """`claim` promoted to `fact` is a strengthening, and it is still a rewrite."""

    before = {"claims": [a_fact(status="claim")]}
    after = {"claims": [a_fact(status="fact")]}
    assert any(
        "with no correction appended" in issue.message for issue in check_append_only(before, after)
    ), check_append_only(before, after)


def test_weakening_a_falsifier_at_the_same_version_is_refused() -> None:
    """A falsifier nobody could act on turns a claim back into a slogan without touching its text."""

    before = {"claims": [a_fact()]}
    after = {"claims": [a_fact(falsifier={"who": "the maintainers", "how": "they disagree"})]}
    assert any(
        "with no correction appended" in issue.message for issue in check_append_only(before, after)
    ), check_append_only(before, after)


def test_a_correction_that_retains_a_text_the_parent_never_published_is_refused() -> None:
    """The second hole: the retained text hashes to itself and to nothing that was ever published.

    `check_claim` verifies `supersedes_digest` against the text sitting beside it, so a fabricated
    pair is internally consistent. Only the parent revision knows what version 1 actually said.
    """

    published = "I-07 (evidence precedes commitment) is orphaned."
    before = {"claims": [a_fact(id="CL-004", text=published)]}
    fabricated = "I-07 (evidence precedes commitment) was always described as partial."
    after = a_corrected()
    retained = cast(list[dict[str, object]], after["corrections"])[0]
    retained["superseded_text"] = fabricated
    retained["supersedes_digest"] = state_digest("CL-004", 1, "fact", fabricated)
    messages = [issue.message for issue in check_append_only(before, {"claims": [after]})]
    assert any("does not retain what the parent revision published" in m for m in messages), (
        messages
    )
    assert any(published in m for m in messages), messages


def test_a_version_that_rises_with_no_correction_for_the_parent_is_refused() -> None:
    """Version 1 to version 3 with one correction: no entry retains what version 1 said."""

    before = {
        "claims": [a_fact(id="CL-004", text="I-07 (evidence precedes commitment) is orphaned.")]
    }
    only_second = cast(list[dict[str, object]], a_corrected()["corrections"])[0]
    only_second["version"] = 2
    only_second["supersedes_digest"] = state_digest(
        "CL-004", 2, "fact", str(only_second["superseded_text"])
    )
    after = a_corrected(version=3, corrections=[only_second])
    messages = [issue.message for issue in check_append_only(before, {"claims": [after]})]
    assert any("no correction retains version 1" in message for message in messages), messages


def test_changing_a_falsifier_with_no_retained_falsifier_is_refused() -> None:
    """Raising the version is not enough: the superseded falsifier has to be retained too.

    `state_digest` covers the id, version, status and text of a version -- not its falsifier -- and
    extending it would change every `supersedes_digest` already retained in `evidence/claims.json`,
    which is a rewrite of history to close a hole about rewriting history. So the retained falsifier
    is compared against the parent revision instead of hashed, and this test is what makes that
    comparison load-bearing.
    """

    published = "I-07 (evidence precedes commitment) is orphaned."
    before = {"claims": [a_fact(id="CL-004", text=published)]}
    after = a_corrected(falsifier={"who": "the maintainers", "how": "they disagree"})
    messages = [issue.message for issue in check_append_only(before, {"claims": [after]})]
    assert any("superseded_falsifier" in message for message in messages), messages


def test_retaining_a_falsifier_the_parent_never_published_is_refused() -> None:
    published = "I-07 (evidence precedes commitment) is orphaned."
    before = {"claims": [a_fact(id="CL-004", text=published)]}
    after = a_corrected(falsifier={"who": "the maintainers", "how": "they disagree"})
    cast(list[dict[str, object]], after["corrections"])[0]["superseded_falsifier"] = {
        "who": "anyone with a clone",
        "how": "something the parent revision never said",
    }
    messages = [issue.message for issue in check_append_only(before, {"claims": [after]})]
    assert any("does not retain the falsifier" in message for message in messages), messages


def test_the_allowed_control_a_retained_falsifier_passes() -> None:
    """The control: sharpening a falsifier is allowed, and it is allowed exactly one way."""

    published = "I-07 (evidence precedes commitment) is orphaned."
    parent = a_fact(id="CL-004", text=published)
    after = a_corrected(falsifier={"who": "a reviewer", "how": "a sharper check than the old one"})
    cast(list[dict[str, object]], after["corrections"])[0]["superseded_falsifier"] = parent[
        "falsifier"
    ]
    assert check_append_only({"claims": [parent]}, {"claims": [after]}) == []


def test_the_allowed_control_an_unchanged_claim_passes() -> None:
    """The control: a revision that changes nothing is not an edit and must not be refused."""

    assert check_append_only({"claims": [a_fact()]}, {"claims": [a_fact()]}) == []


def test_the_allowed_control_a_correction_retaining_the_parents_text_passes() -> None:
    """The control that makes the two refusals above mean something.

    The same version bump, the same correction shape -- and the retained text is what the parent
    revision actually published. This is the honest path, and it is the only one that passes.
    """

    before = {
        "claims": [a_fact(id="CL-004", text="I-07 (evidence precedes commitment) is orphaned.")]
    }
    assert check_append_only(before, {"claims": [a_corrected()]}) == []


# --- the two rendered views --------------------------------------------------------------------


def two_views(tmp_path: Path) -> tuple[str, str]:
    """Render both locales from one ledger, the way `--write` does."""

    ledger = {
        "format": LEDGER_FORMAT,
        "recorded": "2026-09-05",
        "bound_statement": "The gate refuses a merge, not an edit.",
        "head_digest": "sha256:" + "0" * 64,
        "claims": [a_corrected()],
    }
    locales = load_locales(REPOSITORY_ROOT / LOCALES_RELATIVE_PATH)
    return (
        render_view(ledger, "en", locales["en"]),
        render_view(ledger, "ar", locales["ar"]),
    )


def test_both_views_carry_a_byte_identical_head_digest_line(tmp_path: Path) -> None:
    english, arabic = two_views(tmp_path)
    line = "`head_digest` sha256:" + "0" * 64
    assert line in english and line in arabic


def test_a_view_whose_head_digest_was_edited_is_refused(tmp_path: Path) -> None:
    english, arabic = two_views(tmp_path)
    tampered = arabic.replace("0" * 64, "1" * 64)
    issues = check_views({"en": english, "ar": tampered})
    assert any("head_digest differs between views" in issue.message for issue in issues), issues
    assert any("this is a defect, not a translation note" in issue.message for issue in issues), (
        issues
    )


def test_the_allowed_control_two_views_from_one_ledger_pass(tmp_path: Path) -> None:
    """The control: the refusal above must not fire on an honest pair."""

    english, arabic = two_views(tmp_path)
    assert check_views({"en": english, "ar": arabic}) == []


def test_a_translated_quotation_is_refused(tmp_path: Path) -> None:
    """Translating a claim body manufactures a claim nobody made."""

    english, arabic = two_views(tmp_path)
    tampered = arabic.replace("I-07 (evidence precedes commitment) is partial.", "I-07 is fine.")
    issues = check_views({"en": english, "ar": tampered})
    assert any("quoted text differs between views" in issue.message for issue in issues), issues


def test_a_translated_superseded_text_is_refused(tmp_path: Path) -> None:
    """Translating a retraction rewrites it, which is worse than translating a claim."""

    english, arabic = two_views(tmp_path)
    tampered = arabic.replace("I-07 (evidence precedes commitment) is orphaned.", "I-07 was fine.")
    issues = check_views({"en": english, "ar": tampered})
    assert any("quoted text differs between views" in issue.message for issue in issues), issues


# --- the ledger as a whole ----------------------------------------------------------------------


def test_a_ledger_whose_bound_statement_is_missing_is_refused(tmp_path: Path) -> None:
    """An honest limitation that is not published is not a limitation, it is a note to self."""

    ledger = {"format": LEDGER_FORMAT, "claims": [], "head_digest": "sha256:x"}
    messages = [issue.message for issue in check_ledger(tmp_path, ledger)]
    assert any("bound_statement" in message for message in messages), messages


def test_a_ledger_with_a_stale_head_digest_is_refused(tmp_path: Path) -> None:
    ledger = {
        "format": LEDGER_FORMAT,
        "bound_statement": "x",
        "head_digest": "sha256:" + "0" * 64,
        "claims": [a_fact()],
    }
    messages = [issue.message for issue in check_ledger(tmp_path, ledger)]
    assert any("head_digest is stale" in message for message in messages), messages


def test_the_allowed_control_the_committed_ledger_passes_every_check() -> None:
    """The control that matters most: this repository's real ledger, gated end to end."""

    ledger = load_ledger(REPOSITORY_ROOT / LEDGER_RELATIVE_PATH)
    assert check_ledger(REPOSITORY_ROOT, ledger) == []


def test_a_duplicate_claim_id_is_refused(tmp_path: Path) -> None:
    ledger = {
        "format": LEDGER_FORMAT,
        "bound_statement": "x",
        "head_digest": "sha256:x",
        "claims": [a_fact(), a_fact()],
    }
    messages = [issue.message for issue in check_ledger(tmp_path, ledger)]
    assert any("duplicate id" in message for message in messages), messages


def test_an_unknown_status_is_refused(tmp_path: Path) -> None:
    messages = [issue.message for issue in check_claim(tmp_path, a_fact(status="true"))]
    assert any("status 'true' not in" in message for message in messages), messages


# --- the published limitation --------------------------------------------------------------------

BOUND = "The gate refuses a merge, not an edit."


def bounded_ledger(**overrides: object) -> dict[str, object]:
    ledger: dict[str, object] = {
        "format": LEDGER_FORMAT,
        "bound_statement": BOUND,
        "bound_surfaces": ["docs/public-claims.md"],
        "claims": [],
    }
    ledger.update(overrides)
    return ledger


def test_a_surface_that_does_not_carry_the_limitation_is_refused(tmp_path: Path) -> None:
    fake_tree(tmp_path, "a page that says nothing about what this does not cover\n")
    messages = [i.message for i in check_bound_statement(tmp_path, bounded_ledger())]
    assert any("does not appear verbatim in docs/public-claims.md" in m for m in messages), messages


def test_a_softened_limitation_is_refused(tmp_path: Path) -> None:
    """The tempting edit: the paragraph stays, the escape hatch is dropped from it."""

    fake_tree(tmp_path, "The gate refuses a merge.\n")
    assert check_bound_statement(tmp_path, bounded_ledger()) != []


def test_naming_no_bound_surface_at_all_is_refused(tmp_path: Path) -> None:
    messages = [
        i.message for i in check_bound_statement(tmp_path, bounded_ledger(bound_surfaces=[]))
    ]
    assert any("at least one surface" in m for m in messages), messages


def test_the_allowed_control_a_surface_carrying_the_limitation_passes(tmp_path: Path) -> None:
    """The control: the three refusals above must not fire on a page that does publish it."""

    fake_tree(tmp_path, f"intro\n\n> {BOUND}\n\nmore\n")
    assert check_bound_statement(tmp_path, bounded_ledger()) == []


def test_softening_the_limitation_moves_the_head_digest() -> None:
    """It is folded into the head on purpose, so a quiet improvement is visible to an old copy."""

    assert head_digest(bounded_ledger()) != head_digest(
        bounded_ledger(bound_statement="The gate refuses a merge.")
    )


# --- line wrapping is not a truth claim ----------------------------------------------------------


def test_a_rewrapped_surface_still_renders(tmp_path: Path) -> None:
    """The control for the normalization: re-wrapping a paragraph is not a defect."""

    tree = fake_tree(tmp_path, "the census says 9 of 39\n  crates reachable, and more text\n")
    assert check_claim(tree, a_fact()) == []


def test_normalization_does_not_reach_across_a_table_cell(tmp_path: Path) -> None:
    """`|` is not whitespace, so a sentence cannot be assembled out of two different cells."""

    tree = fake_tree(tmp_path, "| 9 of 39 | crates reachable |\n")
    assert any("does not render" in i.message for i in check_claim(tree, a_fact()))


def test_the_orphan_count_is_recomputed_and_not_carried(tmp_path: Path) -> None:
    """A template cannot subtract, so the orphan count must come from the reduction."""

    (tmp_path / "evidence").mkdir(exist_ok=True)
    record = tmp_path / "evidence" / "wiring-coverage.json"
    record.write_text(RECORD, encoding="utf-8")
    assert wiring_reachability(record) == [9, 39, 30, 17]
