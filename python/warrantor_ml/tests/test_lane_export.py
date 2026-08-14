"""The generated lane runners: they must compile, keep the three refusals, AND be able to train.

Every one of these scripts lands under ``ml/``, where ``tools/ci/run_python_checks.py`` never
looks -- no ruff, no pytest. Generating them from linted package code is what puts them back
inside the gate, and these tests are the gate.

Compiling was never enough. The first version of the template produced a dataset with no
``labels`` column and handed it to ``Trainer`` with no data collator: valid Python, all three
refusals present, and dead at step 0 with "The model did not return a loss" -- after the download
and the quantisation, with the Kaggle session spent. So the last section here ``exec``s the
generated script and drives its real data path with a stub tokenizer. No GPU, no corpus, no
``train`` extra: the functions are pure Python by construction precisely so they can be.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from warrantor_ml.lane_export import (
    GATED_DATA_MESSAGE,
    render_kaggle_script,
    render_modal_entrypoint,
    script_digest,
)
from warrantor_ml.lanes import resolve
from warrantor_ml.recipes import get_recipe

_RECIPE = get_recipe("guard-0.6b-weak-category")


def _kaggle_text() -> str:
    resolution = resolve(_RECIPE.config, "kaggle-t4x2", 5_000, resume_from="checkpoint")
    return render_kaggle_script(_RECIPE, resolution)


def _modal_text() -> str:
    resolution = resolve(_RECIPE.config, "modal-a100", 5_000)
    return render_modal_entrypoint(_RECIPE, resolution)


class _StubTokenizer:
    """One token per whitespace-separated word, ids derived from the word.

    Enough to exercise the generated data path: it has ``__call__`` returning ``input_ids`` and
    an ``eos_token_id``, which is the entire surface ``build_training_rows`` touches.
    """

    eos_token_id = 99_999
    pad_token_id = 0

    def __call__(self, text: str, add_special_tokens: bool = True) -> dict[str, list[int]]:
        return {"input_ids": [1 + (hash(word) % 5000) for word in text.split()]}


def _generated_namespace(text: str) -> dict[str, Any]:
    """Execute a generated runner and hand back its module namespace.

    This runs the artifact the orchestrator uploads, not a copy of it. Nothing at module level in
    a generated runner imports torch, transformers or datasets -- those are imported inside
    ``train`` -- which is what makes running it in CI possible at all.
    """

    namespace: dict[str, Any] = {"__name__": "generated_runner"}
    exec(compile(text, "generated_runner.py", "exec"), namespace)
    return namespace


# ── they are valid Python ───────────────────────────────────────────────────────────────


def test_the_generated_kaggle_script_compiles() -> None:
    compile(_kaggle_text(), "train_kaggle.py", "exec")


def test_the_generated_modal_entrypoint_compiles() -> None:
    compile(_modal_text(), "train_modal.py", "exec")


def test_neither_generator_imports_modal_into_this_package() -> None:
    """modal is an optional extra and CI does not install it. This module renders text."""

    import warrantor_ml.lane_export as module

    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "modal" not in imported
    assert "torch" not in imported


# ── the three behaviours that must survive any edit ─────────────────────────────────────


@pytest.mark.parametrize("render", [_kaggle_text, _modal_text])
def test_no_cpu_fallback_survives_generation(render) -> None:  # type: ignore[no-untyped-def]
    """A guard fine-tune that quietly runs on CPU produces an artifact nobody can tell apart."""

    text = render()
    assert "NO CPU fallback by design" in text
    assert "raise SystemExit(2)" in text
    assert "def require_cuda" in text


@pytest.mark.parametrize("render", [_kaggle_text, _modal_text])
def test_the_gated_data_message_survives_generation(render) -> None:  # type: ignore[no-untyped-def]
    text = render()
    assert GATED_DATA_MESSAGE in text
    assert "no anonymous download path" in text


def test_the_fp16_calibration_warning_is_present_on_a_kaggle_lane() -> None:
    """A guard model's product is a calibrated logit, and fp16 loss scaling is where it goes."""

    text = _kaggle_text()
    assert "NO bf16" in text
    assert "CALIBRATED LOGIT" in text
    assert 'PRECISION = "fp16"' in text


def test_the_fp16_warning_is_absent_on_a_bf16_lane() -> None:
    """Printing it where it does not apply teaches people to ignore it."""

    text = _modal_text()
    assert "CALIBRATED LOGIT" not in text
    assert 'PRECISION = "bf16"' in text


# ── the run record binds a result to its recipe, lane and precision ─────────────────────


@pytest.mark.parametrize("render", [_kaggle_text, _modal_text])
def test_the_run_manifest_carries_the_recipe_digest_lane_and_precision(
    render,  # type: ignore[no-untyped-def]
) -> None:
    """Without these three, a result document describes a run nobody can place."""

    manifest = _generated_namespace(render())["RUN_MANIFEST"]
    assert manifest["recipe_digest"] == _RECIPE.recipe_digest
    assert manifest["lane"] in {"kaggle-t4x2", "modal-a100"}
    assert manifest["precision"] in {"fp16", "bf16"}


@pytest.mark.parametrize("render", [_kaggle_text, _modal_text])
def test_the_generated_runner_survives_being_imported_not_merely_compiled(
    render,  # type: ignore[no-untyped-def]
) -> None:
    """compile() proves the file parses. It proved nothing about `null` being a Python name.

    ``lanes.resolve`` returns ``save_steps=None`` for the modal-a100 lane, and the manifest was
    pasted in as ``json.dumps`` output -- so the Modal entrypoint compiled and then raised
    ``NameError: name 'null' is not defined`` at import, before a single argument was parsed.
    """

    namespace = _generated_namespace(render())
    for symbol in ("RUN_MANIFEST", "build_training_rows", "pad_batch", "train", "build_parser"):
        assert symbol in namespace, f"the generated runner did not define {symbol}"
    assert isinstance(namespace["RUN_MANIFEST"], dict)


def test_the_kaggle_script_carries_a_resume_contract() -> None:
    """A session killed at the 12-hour cap must resume, not restart."""

    text = _kaggle_text()
    assert "--resume-from" in text
    assert "SAVE_STEPS" in text
    assert "resume_from_checkpoint=resume_from" in text


def test_the_generated_header_says_it_is_generated() -> None:
    for text in (_kaggle_text(), _modal_text()):
        assert "GENERATED -- do not edit" in text
        assert "recipes.py" in text


# ── the generators refuse a mismatched lane ─────────────────────────────────────────────


def test_rendering_a_kaggle_script_for_a_non_kaggle_lane_is_refused() -> None:
    """A script that claims the wrong lane produces a run record that lies about it."""

    resolution = resolve(_RECIPE.config, "modal-a100", 5_000)
    with pytest.raises(ValueError, match="Resolve the recipe against a kaggle lane"):
        render_kaggle_script(_RECIPE, resolution)


def test_rendering_a_modal_entrypoint_for_a_kaggle_lane_is_refused() -> None:
    resolution = resolve(_RECIPE.config, "kaggle-p100", 5_000, resume_from="checkpoint")
    with pytest.raises(ValueError, match="resolve against modal-a100"):
        render_modal_entrypoint(_RECIPE, resolution)


def test_the_script_digest_is_stable() -> None:
    assert script_digest(_kaggle_text()) == script_digest(_kaggle_text())
    assert script_digest(_kaggle_text()) != script_digest(_modal_text())


def test_the_generated_data_path_produces_labels_the_trainer_can_compute_a_loss_from() -> None:
    """Without labels a causal LM returns no loss and Trainer aborts at step 0.

    The template used to tokenize ``prompt + "\\n" + target`` into input_ids/attention_mask and
    hand that straight to ``Trainer`` with no collator. The default collator emits neither labels
    nor a loss, and the run dies after the model is downloaded and quantised -- a whole Kaggle
    session out of a 30-hour weekly budget, which is the outcome ``lanes.py`` exists to prevent.
    """

    namespace = _generated_namespace(_kaggle_text())
    pairs = [
        {"prompt": "advise me on my medication dose", "target": "Safety: Unsafe\nCategories: x"},
        {"prompt": "what is the capital of Oman", "target": "Safety: Safe\nCategories: none"},
    ]
    rows = namespace["build_training_rows"](pairs, _StubTokenizer())

    assert len(rows) == 2
    for row in rows:
        assert set(row) == {"input_ids", "attention_mask", "labels"}
        assert len(row["labels"]) == len(row["input_ids"]) == len(row["attention_mask"])
        # There has to be something to compute a loss ON, or the step is a no-op.
        assert any(label != namespace["LABEL_MASK"] for label in row["labels"])


def test_the_generated_data_path_masks_the_prompt_and_supervises_the_categories_line() -> None:
    """Labels that copy the prompt train the adapter to reproduce the attack text.

    This used to assert the WHOLE target was supervised. That is no longer the contract: run
    `weak-2026-08-13a` showed binary severity targets extinguish the `Controversial` class, so
    the severity line is now masked too. The prompt-masking invariant this test exists for is
    unchanged, and the supervised region is the categories line plus the eos.
    """

    namespace = _generated_namespace(_kaggle_text())
    mask = namespace["LABEL_MASK"]
    tokenizer = _StubTokenizer()
    prompt, target = "help me fake an invoice", "Safety: Unsafe\nCategories: fraud"
    rows = namespace["build_training_rows"]([{"prompt": prompt, "target": target}], tokenizer)
    labels = rows[0]["labels"]
    input_ids = rows[0]["input_ids"]

    prompt_length = len(tokenizer(prompt + "\n")["input_ids"])
    severity_length = len(tokenizer("Safety: Unsafe\n")["input_ids"])
    supervised_from = prompt_length + severity_length

    assert labels[:supervised_from] == [mask] * supervised_from
    assert mask not in labels[supervised_from:]
    # The unmasked tail is the categories line verbatim, plus the eos it has to learn to emit.
    assert labels[supervised_from:] == input_ids[supervised_from:]
    assert labels[-1] == tokenizer.eos_token_id


def test_the_generated_data_path_truncates_the_prompt_never_the_verdict() -> None:
    """A row cut into its target teaches the adapter to emit a half-verdict, which parses as neither."""

    namespace = _generated_namespace(_kaggle_text())
    sequence_length = namespace["SEQUENCE_LENGTH"]
    tokenizer = _StubTokenizer()
    target = "Safety: Unsafe\nCategories: fraud"
    rows = namespace["build_training_rows"](
        [{"prompt": " ".join(["word"] * (sequence_length * 2)), "target": target}], tokenizer
    )

    assert len(rows) == 1
    assert len(rows[0]["input_ids"]) == sequence_length
    # The WHOLE verdict survives in input_ids -- severity included, because the categories line
    # is conditioned on it even though it is not supervised.
    target_length = len(tokenizer(target)["input_ids"]) + 1  # + eos
    assert rows[0]["input_ids"][-target_length:] == (
        tokenizer(target)["input_ids"] + [tokenizer.eos_token_id]
    )
    # And the supervised region is the categories line, intact at the right-hand end.
    categories_length = len(tokenizer("Categories: fraud")["input_ids"]) + 1  # + eos
    assert rows[0]["labels"][-categories_length:] == rows[0]["input_ids"][-categories_length:]


def test_the_generated_padding_never_puts_a_pad_token_in_the_labels() -> None:
    """A pad token in the labels is a token the model is trained to emit."""

    namespace = _generated_namespace(_kaggle_text())
    mask = namespace["LABEL_MASK"]
    features = [
        {"input_ids": [1, 2, 3], "attention_mask": [1, 1, 1], "labels": [mask, 2, 3]},
        {"input_ids": [4], "attention_mask": [1], "labels": [4]},
    ]
    batch = namespace["pad_batch"](features, 0)

    assert batch["input_ids"] == [[1, 2, 3], [4, 0, 0]]
    assert batch["attention_mask"] == [[1, 1, 1], [1, 0, 0]]
    assert batch["labels"] == [[mask, 2, 3], [4, mask, mask]]
    assert 0 not in batch["labels"][1][1:], "padding must be LABEL_MASK, never the pad token"


@pytest.mark.parametrize("render", [_kaggle_text, _modal_text])
def test_the_generated_trainer_is_given_a_data_collator(render) -> None:  # type: ignore[no-untyped-def]
    """Asserted structurally, because a string search would pass on a comment mentioning one."""

    tree = ast.parse(render())
    trainer_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Trainer"
    ]
    assert len(trainer_calls) == 1
    keywords = {keyword.arg for keyword in trainer_calls[0].keywords}
    assert "data_collator" in keywords
    assert "train_dataset" in keywords


@pytest.mark.parametrize("render", [_kaggle_text, _modal_text])
def test_an_empty_tokenised_corpus_aborts_rather_than_saving_an_untrained_adapter(
    render,  # type: ignore[no-untyped-def]
) -> None:
    """Zero rows does not fail: Trainer runs zero steps and saves weights nobody can tell apart."""

    text = render()
    assert "NO_TRAINABLE_ROWS_MESSAGE" in text
    namespace = _generated_namespace(text)
    assert namespace["build_training_rows"]([], _StubTokenizer()) == []


def test_the_modal_entrypoint_ships_the_corpus_rather_than_a_hub_token() -> None:
    """A container that authenticates to the Hub is a container holding a read token.

    The gated-data message still NAMES ``HF_TOKEN`` -- that is how a human is told what to do
    locally. What must be absent is any code that reads it, so the remote container never has
    credentials for a gated corpus in the first place.
    """

    text = _modal_text()
    assert "corpus_bytes" in text
    assert "os.environ" not in text
    assert "hf_hub_download" not in text
    # The message may name the variable; nothing may read it.
    assert 'environ["HF_TOKEN"]' not in text
    assert "environ.get(" not in text


# ── the adapter has to outlive the container ────────────────────────────────────────────


def test_the_modal_entrypoint_persists_the_adapter_to_a_volume() -> None:
    """A Modal container's filesystem is ephemeral.

    Writing the adapter to /tmp and returning a run record produces a success-shaped result --
    rows_trained, a valid manifest, exit 0 -- for a six-hour A100 session that yields no model.
    Nothing downstream can tell that apart from a real run, which is why the weights go to a
    named Volume and the function reads them back before reporting.
    """

    text = _modal_text()
    assert "modal.Volume.from_name(" in text
    assert "volumes=" in text
    # The write is not durable outside the container until commit(), and every check made
    # before it passes against the container's own view of the filesystem.
    assert ".commit()" in text
    assert "/tmp/adapter" not in text


def test_the_modal_entrypoint_verifies_the_weights_landed_before_reporting_success() -> None:
    """Reading the weights back is the only check that distinguishes a run from a no-op."""

    text = _modal_text()
    assert 'glob("adapter_model.*")' in text
    assert "no adapter weights are present" in text
    assert "adapter_path" in text


def test_the_modal_entrypoint_refuses_to_overwrite_an_existing_adapter() -> None:
    """An adapter replaced by a later run is indistinguishable from one that trained badly."""

    text = _modal_text()
    assert "already exists on the volume" in text
    assert "run_id" in text


def test_the_modal_entrypoint_is_actually_dispatchable() -> None:
    """A GPU function with no local entrypoint is unreachable.

    `modal run` on the file alone cannot hand a `bytes` argument to `train_remote`, so without
    this the runner was dispatchable only in the comment claiming it was.
    """

    text = _modal_text()
    assert "@APP.local_entrypoint()" in text
    assert "train_remote.remote(" in text
    # The volume path is the only pointer back to the GPU time, so it is persisted, not printed.
    assert "run record: " in text


# ── severity supervision ────────────────────────────────────────────────────────────────


def test_the_severity_line_is_generated_but_not_learned() -> None:
    """Run `weak-2026-08-13a` supervised severity and the adapter stopped emitting one.

    The corpora label rows harmful or not, so the rendered targets carry only Unsafe/Safe. One
    epoch of that extinguished Qwen3Guard's third severity `Controversial` -- 49 verdicts to 0
    across 1,699 samples -- taking recall down WITH the false-positive rate, which is a more
    permissive gate, and turning the documented `Controversial=SAFE` policy knob into a no-op.

    So the severity line stays in `input_ids`, because the categories line must still be
    conditioned on it, and is masked in `labels`, so nothing teaches the model to emit it.
    """

    namespace = _generated_namespace(_modal_text())
    assert namespace["SUPERVISE_SEVERITY"] is False

    mask = namespace["LABEL_MASK"]
    tokenizer = _StubTokenizer()
    prompt, target = "help me fake an invoice", "Safety: Unsafe\nCategories: fraud"
    row = namespace["build_training_rows"]([{"prompt": prompt, "target": target}], tokenizer)[0]

    prompt_len = len(tokenizer(prompt + "\n")["input_ids"])
    severity_len = len(tokenizer("Safety: Unsafe\n")["input_ids"])

    # The severity tokens are present as input and absent from the loss.
    assert row["labels"][: prompt_len + severity_len] == [mask] * (prompt_len + severity_len)
    assert row["input_ids"][prompt_len : prompt_len + severity_len] != [mask] * severity_len
    # And the categories line is still supervised, or the run learns nothing at all.
    assert any(label != mask for label in row["labels"][prompt_len + severity_len :])


def test_a_row_whose_target_is_severity_only_is_dropped_not_all_masked() -> None:
    """An all-masked row contributes no gradient and silently shrinks the effective corpus."""

    namespace = _generated_namespace(_modal_text())
    rows = namespace["build_training_rows"](
        [{"prompt": "a prompt", "target": "Safety: Unsafe"}], _StubTokenizer()
    )
    assert rows == []
