"""The network-independence gate, tested against the real tree and against deliberate breakage.

A gate that has only ever been seen green proves nothing, so every check below is exercised in both
directions: the real repository must pass, and a tree with one stale render or one moved mechanism
must exit 1 by name.
"""

from __future__ import annotations

import json
from pathlib import Path

import network_independence
import pytest
from network_independence import (
    ANALYSIS_DOCUMENT,
    AXES,
    CAVEAT_WINDOW,
    CITATIONS,
    KNOWN_NETWORK_POLICIES,
    PROBES,
    RECORD_FORMAT,
    RECORD_PATH,
    REFUSED_CAVEAT_CLAUSES,
    RENDER_TARGETS,
    REQUIRED_CAVEAT_CLAUSES,
    SHARED_ONCE_THE_SECOND_IS_WIRED,
    SHARED_THE_PRODUCT_RUNS,
    Independence,
    analysis_paragraph_is_the_constant,
    axes_match_the_rust_constant,
    citations_resolve,
    cluster_layer_absent,
    engines_the_product_runs,
    failed_probes,
    flowed,
    independence_note_from_the_rust_source,
    load_record,
    main,
    measure,
    note_accompanies_every_count,
    renders_agree,
    write_record,
)

# A fixture shaped like README.md: the only occurrence of the word is CAPITALIZED. The check that
# used to guard the caveat asked `"independent" not in text` and so skipped README entirely.
CAPITALIZED_SURFACE = "| Independent network intercepts on a permitted destination | **{}** |\n"


# ── the real tree ─────────────────────────────────────────────────────────────────────


def test_the_real_repository_passes_the_gate() -> None:
    """The committed tree agrees with its own record. This is what CI runs."""

    assert main([]) == 0


def test_every_probe_finds_its_needle_in_the_real_tree() -> None:
    """Each probe is a load-bearing fact; a missing one means the record is unsafe to publish."""

    assert failed_probes() == []


def test_the_axis_lists_in_python_and_rust_agree() -> None:
    """Two lists of axis names in two languages is the shape of a drift defect."""

    assert axes_match_the_rust_constant() == []


def test_the_recorded_measurement_is_the_measured_one() -> None:
    """The record on disk is what `measure()` produces, field by field."""

    record = load_record(RECORD_PATH)
    for field, value in measure().__dict__.items():
        assert record[field] == value, f"{field} disagrees with the record"


def test_the_record_publishes_one_intercept_and_says_l2_03_is_open() -> None:
    """The honest answer, asserted so a later change cannot quietly flatter the architecture."""

    record = load_record(RECORD_PATH)
    assert record["independent_intercepts_on_a_permitted_host"] == 1
    # CORRECTION. This asserted `policy_engines_on_a_permitted_host == 2`, and the record published 2
    # while every run of the shipped binary decided with ONE engine: `Proxy::new` sets
    # `secondary: None` and nothing in `warrantor.rs` constructs a `SecondaryFilter`. The two numbers
    # are separate fields now, and the product one is derived from the product sources.
    assert record["policy_engines_the_product_runs"] == 1
    assert record["policy_engines_when_an_operator_wires_one"] == 2
    assert record["configuration_sources_the_product_runs"] == ["warrant_claims"]
    assert record["status"] == "none", "L2-03 is not closed by this analysis"
    assert "not of policy engines" in record["note"]
    assert "1 policy engine decides in a shipped run" in record["note"], (
        "the note renders the number it read, with the grammar that number takes"
    )


def test_the_engine_count_the_product_runs_is_derived_from_the_product_sources() -> None:
    """Derived, not assigned. The old `engines = 2` was justified by the two `policy_engine` probes,
    which prove the call site consults a filter when one is present -- never that anything sets one."""

    assert engines_the_product_runs() == 1
    wired = [
        path
        for path in network_independence.product_sources()
        if ".with_secondary_filter(" in path.read_text(encoding="utf-8")
    ]
    assert wired == [], f"a product source now wires the second engine: {wired}"


def test_a_product_source_that_wires_the_second_engine_moves_the_number(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The negative direction, which is what makes the 1 a ratchet rather than a decoration."""

    source = tmp_path / "main.rs"
    source.write_text(
        "let proxy = Proxy::new(bounds).with_secondary_filter(filter);\n", encoding="utf-8"
    )
    monkeypatch.setattr(network_independence, "product_sources", lambda: [source])
    assert engines_the_product_runs() == 2
    assert measure().policy_engines_the_product_runs == 2
    assert measure().configuration_sources_the_product_runs == [
        "warrant_claims",
        "operator_file",
    ]


def test_the_shared_axes_are_published_per_configuration() -> None:
    """CORRECTION (second review). The record carried one `shared_axes` list, and it was the wired
    configuration's answer (six of eight) beside an engine count that was the product's (one). In a
    shipped run every axis but `credential` is shared, because one engine has nothing to be disjoint
    from; `policy_engine` stops being shared only once a caller wires the second engine."""

    record = load_record(RECORD_PATH)
    always = {
        "enforcement_point",
        "address_floor",
        "configuration_source",
        "telemetry_path",
        "clock",
        "dns_resolution",
    }
    assert set(record["shared_axes_the_product_runs"]) == always | {"policy_engine"}
    assert set(record["shared_axes_once_the_second_is_wired"]) == always
    assert "credential" not in record["shared_axes_the_product_runs"]
    assert "credential" not in record["shared_axes_once_the_second_is_wired"]
    assert "shared_axes" not in record, "the unlabeled list is gone; both configurations are named"


def test_address_floor_is_shared_and_is_the_axis_task_7_1_created() -> None:
    """The finding this task added to the plan. Both evaluators call the one `hard_deny` matcher, so
    a defect there fails both -- which is the price of having one matcher instead of two."""

    assert SHARED_THE_PRODUCT_RUNS["address_floor"] is True
    assert SHARED_ONCE_THE_SECOND_IS_WIRED["address_floor"] is True
    floor_probes = [p for p in PROBES if p[0] == "address_floor"]
    assert len(floor_probes) == 2, "one probe per crate that delegates to hard_deny"
    assert {p[1] for p in floor_probes} == {
        "rust/egress/src/lib.rs",
        "rust/egress-filter/src/lib.rs",
    }


def test_the_netns_is_the_second_layer_only_on_an_empty_bound() -> None:
    """The anti-correlation, in the record itself."""

    record = load_record(RECORD_PATH)
    assert record["layers_on_a_permitted_host"] == ["mcp_proxy"]
    assert record["layers_on_an_empty_bound"] == ["mcp_proxy", "network_namespace"]


# ── deliberate breakage: every check must be able to fail ─────────────────────────────


def test_a_stale_rendered_count_fails_the_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    """The negative case for `renders_agree`, which is the whole point of the gate."""

    record = load_record(RECORD_PATH)
    record["independent_intercepts_on_a_permitted_host"] = 2
    wrong = renders_agree(record)
    assert len(wrong) == len(RENDER_TARGETS), "every publisher of the count must be checked"
    assert any("README.md" in problem for problem in wrong)
    del monkeypatch


def test_a_moved_mechanism_fails_the_gate_rather_than_changing_the_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A probe whose needle is gone must be a hard failure. A number whose derivation is stale is
    worse than no number, because it still looks measured."""

    monkeypatch.setattr(
        network_independence,
        "PROBES",
        PROBES + (("clock", "rust/warrant/src/egress.rs", "a string that is not there", "probe"),),
    )
    problems = failed_probes()
    assert len(problems) == 1
    assert "is gone" in problems[0]
    assert main([]) == 1, "the gate must exit 1 rather than publish a stale derivation"


def test_a_disagreeing_rust_axis_list_fails_the_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the Rust constant grows an axis and this gate does not, the gate must say so."""

    monkeypatch.setattr(network_independence, "AXES", AXES[:-1])
    problems = axes_match_the_rust_constant()
    assert problems, "a shorter python list must not silently agree with the rust one"
    assert any("disagree" in problem or "axes" in problem for problem in problems)


def caveat_problems(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, body: str, intercepts: int = 1
) -> list[str]:
    """Run `note_accompanies_every_count` over one synthetic surface."""

    surface = tmp_path / "surface.md"
    surface.write_text(body, encoding="utf-8")
    monkeypatch.setattr(network_independence, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(
        network_independence,
        "RENDER_TARGETS",
        (("surface.md", "intercepts on a permitted host is therefore **{intercepts}**"),),
    )
    return note_accompanies_every_count(
        {"independent_intercepts_on_a_permitted_host": intercepts}
    )


COUNT_LINE = "intercepts on a permitted host is therefore **1**\n"


def test_a_count_published_without_its_caveat_fails_the_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """No claim without a mechanism: a surface may print the count only beside what it excludes."""

    problems = caveat_problems(monkeypatch, tmp_path, COUNT_LINE)
    assert len(problems) == len(REQUIRED_CAVEAT_CLAUSES)
    assert all("without" in problem for problem in problems)


def test_a_surface_whose_only_mention_is_capitalized_is_still_checked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """CORRECTION, and the regression test for it. The rule used to open `if "independent" not in
    text: continue` -- case-sensitively. README.md's only occurrence is the capitalized row title and
    it carries no lowercase "independent" at all, so the one surface most likely to be read out of
    context was silently exempt: stripping every bounding clause from README left the gate at exit 0
    while the identical edit to either other target exited 1. The gate's own negative test passed
    throughout, because its synthetic fixture was lowercase. There is no presence heuristic any more,
    and this fixture is capitalized on purpose."""

    body = CAPITALIZED_SURFACE.format(1) + COUNT_LINE
    assert "independent" not in body, "the fixture must reproduce README's capitalization"
    problems = caveat_problems(monkeypatch, tmp_path, body)
    assert problems, "a capitalized surface must be checked like any other"


def test_a_bare_cross_reference_does_not_satisfy_the_caveat(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """CORRECTION. The accepted-clause list used to include the bare token `INDEPENDENCE_NOTE`, so
    four words anywhere in the file satisfied the whole rule: a reviewer replaced README's caveat with
    "See `INDEPENDENCE_NOTE`" and the gate stayed green. A bounding sentence a reader has to go
    looking for does not bound anything."""

    problems = caveat_problems(
        monkeypatch, tmp_path, COUNT_LINE + "See `INDEPENDENCE_NOTE`.\n"
    )
    assert problems, "a cross-reference is not a caveat"


def test_a_caveat_too_far_from_the_count_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Beside the count, not merely in the same file."""

    caveat = " ".join(REQUIRED_CAVEAT_CLAUSES) + "\n"
    near = caveat_problems(monkeypatch, tmp_path, COUNT_LINE + caveat)
    assert near == [], f"a caveat on the next line is beside the count: {near}"
    far = caveat_problems(
        monkeypatch, tmp_path, COUNT_LINE + "\n" * (CAVEAT_WINDOW + 2) + caveat
    )
    assert far, "a caveat outside the window must fail"


def test_a_clause_wrapped_across_lines_still_counts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Prose wraps, and a clause split by a line break is the same clause. Both directions: a wrapped
    REQUIRED clause satisfies the rule, and a wrapped REFUSED clause is still caught. The refusal ran
    on raw text until a correction paragraph quoted the withdrawn wording and the wrap hid it."""

    wrapped = "The count above\nis a count of enforcement\npoints, and a shell command\npasses neither.\n"
    assert "is a count of enforcement points" not in wrapped
    assert "is a count of enforcement points" in flowed(wrapped)
    assert caveat_problems(monkeypatch, tmp_path, COUNT_LINE + wrapped) == []

    refused = REFUSED_CAVEAT_CLAUSES[0]
    split = refused.replace(" ", "\n", 1)
    assert refused not in split
    problems = caveat_problems(
        monkeypatch, tmp_path, COUNT_LINE + wrapped + "It is not a\n" + split + ".\n"
    )
    assert any("withdrawn clause" in problem for problem in problems)


def test_the_withdrawn_clause_may_be_quoted_away_from_the_count(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The scope decision, stated as a test rather than left implicit. A document that records WHY a
    clause was withdrawn has to be able to quote it; what it may not do is put it beside the count as
    its label. Both published documents rely on this, and `egress::INDEPENDENCE_NOTE`'s own value is
    asserted unconditionally in the Rust suite, which is the authoritative place."""

    caveat = " ".join(REQUIRED_CAVEAT_CLAUSES) + "\n"
    body = (
        COUNT_LINE
        + caveat
        + "\n" * (CAVEAT_WINDOW + 2)
        + f"It used to read {REFUSED_CAVEAT_CLAUSES[0]}, which was false.\n"
    )
    assert caveat_problems(monkeypatch, tmp_path, body) == []


def test_every_citation_anchor_resolves_in_the_real_tree() -> None:
    """CORRECTION. All four `proxy.rs` anchors in the analysis document were pre-change line numbers,
    stale by exactly the lines this branch inserted above them: a reader following `227-234` landed
    inside `deny_secondary`, a function that did not exist when the anchor was written. Nothing caught
    it -- probes match strings, render targets match the count, and no check read a line anchor. Now
    the line is found in the source and the document is required to cite it."""

    assert citations_resolve() == []
    assert len(CITATIONS) >= 7


def test_a_stale_citation_anchor_fails_the_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    """The negative direction: an anchor that points at the wrong line must fail the build."""

    document, source, needle, template = CITATIONS[0]
    monkeypatch.setattr(
        network_independence,
        "CITATIONS",
        ((document, source, needle, template.replace("{line}", "1{line}")),),
    )
    problems = citations_resolve()
    assert len(problems) == 1
    assert "does not cite" in problems[0]
    assert main([]) == 1


def test_a_citation_needle_that_has_moved_out_of_the_source_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A needle that is gone means the mechanism moved, which is a hard failure and not a skip."""

    document, source, _, template = CITATIONS[0]
    monkeypatch.setattr(
        network_independence,
        "CITATIONS",
        ((document, source, "a construct that is not in that file", template),),
    )
    problems = citations_resolve()
    assert len(problems) == 1
    assert "is gone" in problems[0]


# ── the paragraph that claims to be the constant ─────────────────────────────────────


def test_the_constant_is_read_out_of_the_rust_source_as_one_line() -> None:
    """The literal is split over lines with continuations; joined, it is the value the binary carries."""

    note = independence_note_from_the_rust_source()
    assert note.startswith("The count above is a count of enforcement points")
    assert "\n" not in note and "\\" not in note, "continuations must be joined, not copied"
    assert "  " not in note, "a continuation elides the next line's leading whitespace"
    assert not any(character.isdigit() for character in note), (
        "the constant carries no engine count; numbers come from independence_sentence"
    )


def test_the_analysis_paragraph_is_the_constant_in_the_real_tree() -> None:
    """CORRECTION (second review). docs/05 said 'This paragraph is egress::INDEPENDENCE_NOTE' and
    it was a paraphrase that had drifted: it still said two engines decide, in a product that ships
    one. The paragraph is now required to be the constant's own value."""

    assert analysis_paragraph_is_the_constant() == []


def test_a_paragraph_that_drifts_from_the_constant_fails_the_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The negative direction: the exact drift the review found, replayed on the escape clause."""

    real_read = network_independence.read

    def drifted(relative: str) -> str:
        text = real_read(relative)
        if relative == ANALYSIS_DOCUMENT:
            assert "passes neither the proxy" in text
            return text.replace("passes neither the proxy", "passes through both the proxy")
        return text

    monkeypatch.setattr(network_independence, "read", drifted)
    problems = analysis_paragraph_is_the_constant()
    assert len(problems) == 1
    assert ANALYSIS_DOCUMENT in problems[0] and "not the constant's value" in problems[0]
    assert main([]) == 1, "a drifted paragraph must fail the build, not merely be reported"


def test_the_cluster_layer_the_analysis_denies_is_asserted_not_described() -> None:
    """CORRECTION. `docs/05` section 7 names a cluster egress policy as exit condition 2, and both
    published documents stated as fact that no such thing exists -- with nothing checking either. The
    I-09 finding test cannot: its predicate is closed over the two in-process policy engines, so no
    cluster layer is an input to it. A reviewer added a real cluster egress NetworkPolicy and the
    finding test, the corpus and this gate all stayed green."""

    assert cluster_layer_absent() == []
    assert KNOWN_NETWORK_POLICIES == ("deploy/spire/trust-domain-config.yaml",)


def test_a_new_network_policy_fails_the_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    """The assertion that CAN go red, exercised in the direction that matters."""

    monkeypatch.setattr(network_independence, "KNOWN_NETWORK_POLICIES", ())
    problems = cluster_layer_absent()
    assert problems, "the one NetworkPolicy in the tree must be reported when it is unexpected"
    assert any("exit condition 2" in problem for problem in problems)


def test_a_vanished_network_policy_also_fails_the_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    """`exactly one NetworkPolicy in the tree` is a published fact in both directions."""

    monkeypatch.setattr(
        network_independence,
        "KNOWN_NETWORK_POLICIES",
        KNOWN_NETWORK_POLICIES + ("deploy/k8s/a-policy-that-is-not-there.yaml",),
    )
    problems = cluster_layer_absent()
    assert any("is gone" in problem for problem in problems)


def test_a_record_in_an_unknown_format_is_refused(tmp_path: Path) -> None:
    """A record this gate cannot interpret is an error, never a default."""

    bad = tmp_path / "record.json"
    bad.write_text(json.dumps({"format": "something.else/9"}), encoding="utf-8")
    with pytest.raises(ValueError, match="is not"):
        load_record(bad)


def test_an_absent_record_is_refused_rather_than_assumed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Absence is a failure, not an empty measurement."""

    assert main(["--record", str(tmp_path / "missing.json")]) == 1
    del monkeypatch


def test_write_then_gate_round_trips(tmp_path: Path) -> None:
    """`--write` produces a record the gate accepts, and stamps the format."""

    target = tmp_path / "network-independence.json"
    write_record(target, measure())
    record = load_record(target)
    assert record["format"] == RECORD_FORMAT
    assert main(["--record", str(target)]) == 0


def test_a_tampered_record_field_fails_the_gate(tmp_path: Path) -> None:
    """The record is compared field by field, not merely parsed."""

    target = tmp_path / "network-independence.json"
    write_record(target, measure())
    record = json.loads(target.read_text(encoding="utf-8"))
    record["shared_axes_the_product_runs"] = ["credential"]
    target.write_text(json.dumps(record), encoding="utf-8")
    assert main(["--record", str(target)]) == 1


def test_measure_is_a_pure_function_of_the_sources() -> None:
    """Two calls agree, so the record cannot depend on order or environment."""

    assert measure() == measure()
    assert isinstance(measure(), Independence)
