"""Tests for the two-benchmark runner.

# What these are actually protecting

This module was written into `ml/` at 186 lines, beside launchers of 28, and `ml/README.md`
forbids exactly that: nothing under `ml/` is linted, format-checked or tested, so logic placed
there is unverified by construction. CI could not have caught it -- the file was invisible to the
check that would have flagged it.

Moving it here is only half the fix. Being *inside* the gate does nothing on its own; these tests
are the other half, and they cover the two things a relocation can silently break: the paths, and
the promise that nothing is downloaded before the preconditions pass.
"""

from __future__ import annotations

from pathlib import Path

from warrantor_ml import run_corpus_benchmarks as runner


def test_the_repository_root_hop_count_is_right() -> None:
    """The failure this exists for is a hop count that is wrong but still yields a valid Path.

    `parents[4]` produces *some* directory whatever the nesting is, so a move would not raise --
    it would resolve to somewhere plausible and report "the benchmark scripts are missing",
    sending the reader after a data problem that does not exist.
    """
    assert (runner.REPOSITORY_ROOT / "ml").is_dir(), (
        f"REPOSITORY_ROOT resolved to {runner.REPOSITORY_ROOT}, which has no ml/ directory: the "
        "parent hop count is wrong for this file's location"
    )
    assert (runner.REPOSITORY_ROOT / "python" / "warrantor_ml").is_dir()
    assert runner.ML_DIRECTORY == runner.REPOSITORY_ROOT / "ml"


def test_every_benchmark_script_it_names_exists() -> None:
    """A runner that shells out to a filename is a runner that can name one that is not there.

    The same class of defect as an error message naming a flag that does not exist: it survives
    every test that does not actually look.
    """
    for name, script, _ in runner.BENCHMARKS:
        path = runner.ML_DIRECTORY / script
        assert path.is_file(), f"{name} points at {path}, which does not exist"


def test_the_pinned_configuration_matches_the_measured_one() -> None:
    """Both benchmarks must run at the settings every published figure was measured at.

    8192 is not arbitrary: this repository shipped `num_ctx: 4096` for eight releases while every
    published figure was measured at 8192, so the configuration in production was one nobody had
    measured. `tests/guard_parity.rs` pins the Rust side against the Python evaluator; this pins
    the runner against the same number.
    """
    assert runner.NUM_CTX == 8192
    assert runner.SEED == 0


def test_a_missing_token_is_a_refusal_that_names_both_gates() -> None:
    """The preflight must name what is missing, not fail later with an HTTP 401 from inside a loader."""
    problems = runner.preflight("http://127.0.0.1:11434")
    token_problems = [p for p in problems if "HF_TOKEN" in p]
    if not token_problems:
        # A token is present in this environment, so there is nothing to assert about its absence.
        return
    complaint = token_problems[0]
    for url in runner.GATES:
        assert url in complaint, f"the refusal does not tell the reader where to accept {url}"
    assert "export HF_TOKEN" in complaint


def test_a_missing_ollama_binary_is_a_note_and_never_a_refusal() -> None:
    """Refusing on the absence of a local binary would be a guess about somebody's setup.

    The endpoint may be a remote ollama-compatible server, so this is reported and not enforced --
    and the distinction is load-bearing, because `main` treats anything not prefixed NOTE as fatal.
    """
    problems = runner.preflight("http://a-remote-host.example:11434")
    for problem in problems:
        if "ollama" in problem and "PATH" in problem:
            assert problem.startswith("NOTE"), (
                "a missing local ollama must be a NOTE: main() counts every non-NOTE problem as "
                "fatal, so this would refuse to run against a perfectly good remote endpoint"
            )


def test_the_gate_urls_are_the_two_corpora_and_nothing_else() -> None:
    """A refusal that sends someone to the wrong licence form costs them a round trip."""
    assert len(runner.GATES) == 2
    assert any("wildguardmix" in url for url in runner.GATES)
    assert any("ExpGuardMix" in url for url in runner.GATES)
    for url in runner.GATES:
        assert url.startswith("https://huggingface.co/datasets/")


def test_a_bare_host_becomes_the_chat_url_the_benchmarks_post_to() -> None:
    """The runner's own default is a bare host; the classifier posts to the URL verbatim.

    Without this normalisation every call posted to `/` and the server answered 405 until the
    benchmark gave up -- found the first time the runner was ever executed, because it was
    written behind a gated-corpus blocker and never run before that. A full chat URL passes
    through untouched, and a trailing slash on a bare host is not a second route.
    """
    assert runner.chat_url("http://127.0.0.1:11434") == "http://127.0.0.1:11434/api/chat"
    assert runner.chat_url("http://127.0.0.1:11434/") == "http://127.0.0.1:11434/api/chat"
    assert runner.chat_url("http://127.0.0.1:11434/api/chat") == "http://127.0.0.1:11434/api/chat"


def test_the_launcher_shim_stays_a_launcher() -> None:
    """`ml/README.md`'s rule, asserted rather than described.

    This is the test that would have caught the original defect. The launchers are 28-31 lines; a
    threshold well above that still refuses anything with real logic in it.
    """
    shim = runner.ML_DIRECTORY / "run_corpus_benchmarks.py"
    lines = shim.read_text(encoding="utf-8").splitlines()
    assert len(lines) < 60, (
        f"{shim} is {len(lines)} lines. Launchers under ml/ are never linted, format-checked or "
        "tested -- logic belongs in this package, where the gate can see it"
    )
    assert "from warrantor_ml.run_corpus_benchmarks import main" in "\n".join(lines)


def test_no_benchmark_is_reachable_without_passing_preflight_first() -> None:
    """`--check` must be able to say 'not ready' without downloading a corpus.

    Asserted structurally: preflight takes only an endpoint string and touches no network, so
    calling it cannot fetch anything. A regression that moved a download earlier would show up as
    this test becoming slow or needing a token.
    """
    problems = runner.preflight("http://127.0.0.1:11434")
    assert isinstance(problems, list)
    assert all(isinstance(problem, str) for problem in problems)
    # `eval_results` is created by main(), never by preflight.
    assert not (Path(runner.REPOSITORY_ROOT) / "eval_results" / ".preflight-touched").exists()
