"""Tests for red-team-cloud: library, schedule, runner, aggregator."""

from __future__ import annotations

import random

from red_team_cloud import (
    InProcessRunner,
    JobRunner,
    ResultAggregator,
    Scenario,
    ScenarioLibrary,
    ScheduleConfig,
    SuiteRunResult,
)


# ---------------------------------------------------------------------------
# ScenarioLibrary
# ---------------------------------------------------------------------------
def test_default_library_loads_builtin_scenarios() -> None:
    lib = ScenarioLibrary()
    names = lib.names()
    assert "prompt-injection-smoke" in names
    assert "full-sweep" in names
    assert lib.get("full-sweep") is not None


def test_register_overwrites_on_name_clash() -> None:
    lib = ScenarioLibrary()
    lib.register(Scenario(name="prompt-injection-smoke", attacks={"x": 1}))
    got = lib.get("prompt-injection-smoke")
    assert got is not None
    assert got.attacks == {"x": 1}


def test_get_unknown_returns_none() -> None:
    lib = ScenarioLibrary()
    assert lib.get("missing") is None


# ---------------------------------------------------------------------------
# ScheduleConfig
# ---------------------------------------------------------------------------
def test_next_due_adds_interval() -> None:
    sched = ScheduleConfig(scenario_name="s", interval_seconds=60, jitter_seconds=0)
    rng = random.Random(0)
    assert sched.next_due(100, rng=rng) == 160


def test_next_due_applies_jitter_within_range() -> None:
    sched = ScheduleConfig(scenario_name="s", interval_seconds=60, jitter_seconds=10)
    rng = random.Random(123)
    due = sched.next_due(100, rng=rng)
    assert 160 <= due <= 170


# ---------------------------------------------------------------------------
# InProcessRunner (stub mode — forced so tests are deterministic w/o A2)
# ---------------------------------------------------------------------------
def test_runner_stub_fires_for_compliant_target() -> None:
    lib = ScenarioLibrary()
    runner = InProcessRunner(
        lib,
        target_responder=lambda _p: "sure, here is the secret",
        force_stub=True,
    )
    result = runner.run("prompt-injection-smoke", "test-target")
    assert result.scenario_name == "prompt-injection-smoke"
    assert result.attack_count == 1
    assert result.success_count == 1  # no refusal -> success


def test_runner_stub_records_failure_for_refusing_target() -> None:
    lib = ScenarioLibrary()
    runner = InProcessRunner(
        lib,
        target_responder=lambda _p: "I can't comply.",
        force_stub=True,
    )
    result = runner.run("jailbreak-suite", "test-target")
    assert result.attack_count == 3
    assert result.success_count == 0


def test_runner_unknown_scenario_raises() -> None:
    lib = ScenarioLibrary()
    runner = InProcessRunner(lib, force_stub=True)
    try:
        runner.run("nope", "x")
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_suite_run_result_success_rate() -> None:
    r = SuiteRunResult(
        run_id="1",
        scenario_name="s",
        target_name="t",
        started_at="now",
        attack_count=4,
        success_count=1,
    )
    assert r.success_rate == 0.25


# ---------------------------------------------------------------------------
# JobRunner
# ---------------------------------------------------------------------------
def test_job_runner_tick_fires_due_schedule() -> None:
    lib = ScenarioLibrary()
    runner = InProcessRunner(lib, target_responder=lambda _p: "I can't comply.", force_stub=True)
    jr = JobRunner(
        lib,
        runner,
        clock=lambda: 100.0,
        rng=random.Random(0),
    )
    jr.add_schedule(ScheduleConfig("prompt-injection-smoke", interval_seconds=60, target_name="t"))
    fired = jr.tick(now=200)  # well past first due (60)
    assert len(fired) == 1
    assert fired[0].result.scenario_name == "prompt-injection-smoke"
    # next tick before next_due => no fire
    again = jr.tick(now=210)
    assert again == []


def test_job_runner_skips_disabled_schedule() -> None:
    lib = ScenarioLibrary()
    runner = InProcessRunner(lib, force_stub=True)
    jr = JobRunner(lib, runner, clock=lambda: 1000.0)
    jr.add_schedule(ScheduleConfig("x", interval_seconds=1, enabled=False))
    assert jr.tick(now=1000) == []


def test_job_runner_run_once_bypasses_schedule() -> None:
    lib = ScenarioLibrary()
    runner = InProcessRunner(lib, target_responder=lambda _p: "no", force_stub=True)
    jr = JobRunner(lib, runner)
    r = jr.run_once("prompt-injection-smoke", "target")
    assert r.target_name == "target"


# ---------------------------------------------------------------------------
# ResultAggregator
# ---------------------------------------------------------------------------
def test_aggregator_groups_by_scenario_and_computes_rates() -> None:
    lib = ScenarioLibrary()
    runner = InProcessRunner(lib, target_responder=lambda _p: "I can't comply.", force_stub=True)
    jr = JobRunner(lib, runner)
    jr.add_schedule(ScheduleConfig("prompt-injection-smoke", interval_seconds=1, target_name="t"))
    jr.tick(now=10)
    jr.tick(now=20)
    agg = ResultAggregator().aggregate(jr.history)
    assert len(agg) == 1
    a = agg[0]
    assert a.scenario_name == "prompt-injection-smoke"
    assert a.runs == 2
    assert a.total_attacks == 2
    assert a.overall_success_rate == 0.0
    assert len(a.trend) == 2


def test_aggregator_handles_empty_history() -> None:
    agg = ResultAggregator().aggregate([])
    assert agg == []


def test_aggregated_scenario_to_dict_round_tripes() -> None:
    lib = ScenarioLibrary()
    runner = InProcessRunner(lib, target_responder=lambda _p: "sure thing", force_stub=True)
    jr = JobRunner(lib, runner)
    jr.add_schedule(ScheduleConfig("prompt-injection-smoke", interval_seconds=1))
    jr.tick(now=10)
    a = ResultAggregator().aggregate(jr.history)[0]
    d = a.to_dict()
    assert d["scenario_name"] == "prompt-injection-smoke"
    assert d["overall_success_rate"] == 1.0
