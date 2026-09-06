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
    AXES,
    PROBES,
    RECORD_FORMAT,
    RECORD_PATH,
    RENDER_TARGETS,
    SHARED,
    Independence,
    axes_match_the_rust_constant,
    failed_probes,
    load_record,
    main,
    measure,
    note_accompanies_every_count,
    renders_agree,
    write_record,
)


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
    assert record["policy_engines_on_a_permitted_host"] == 2
    assert record["status"] == "none", "L2-03 is not closed by this analysis"
    assert "not of policy engines" in record["note"]


def test_the_shared_axes_are_the_six_the_analysis_names() -> None:
    """`credential` and `policy_engine` are the only two that are not shared, and both for stated
    reasons: the first by absence of any key, the second because a second evaluator is wired."""

    record = load_record(RECORD_PATH)
    assert set(record["shared_axes"]) == {
        "enforcement_point",
        "address_floor",
        "configuration_source",
        "telemetry_path",
        "clock",
        "dns_resolution",
    }
    assert "credential" not in record["shared_axes"]
    assert "policy_engine" not in record["shared_axes"]


def test_address_floor_is_shared_and_is_the_axis_task_7_1_created() -> None:
    """The finding this task added to the plan. Both evaluators call the one `hard_deny` matcher, so
    a defect there fails both -- which is the price of having one matcher instead of two."""

    assert SHARED["address_floor"] is True
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


def test_a_count_published_without_its_caveat_fails_the_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """No claim without a mechanism: a surface may print the count only beside what it excludes."""

    naked = tmp_path / "naked.md"
    naked.write_text("independent intercepts: 1\n", encoding="utf-8")
    monkeypatch.setattr(network_independence, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(network_independence, "RENDER_TARGETS", (("naked.md", "{intercepts}"),))
    problems = note_accompanies_every_count({"independent_intercepts_on_a_permitted_host": 1})
    assert len(problems) == 1
    assert "without the clause that bounds it" in problems[0]


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
    record["shared_axes"] = ["credential"]
    target.write_text(json.dumps(record), encoding="utf-8")
    assert main(["--record", str(target)]) == 1


def test_measure_is_a_pure_function_of_the_sources() -> None:
    """Two calls agree, so the record cannot depend on order or environment."""

    assert measure() == measure()
    assert isinstance(measure(), Independence)
