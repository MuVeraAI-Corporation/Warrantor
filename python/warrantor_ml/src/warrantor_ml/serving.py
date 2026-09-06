"""The one place the deployed serving configuration is written down.

Four things read a serving configuration in this repository and, before this module, four things
*declared* one: :class:`warrantor_ml.evaluate.OllamaGuardBackend`'s dataclass defaults,
``warrantor_ml.baselines._ollama_backend``'s literal, ``rust/warrant/src/guard.rs``'s
``GuardKnobs``, and whatever HTTP client a caller hands to the generated ``ContentScanner``
adapter. Three of the four were bound to each other by ``rust/warrant/tests/guard_parity.rs``.
The fourth was bound to nothing, and the promotion gate compared none of them.

Why quantization is the axis this module exists for
---------------------------------------------------
It is the one axis here with a measured effect, and the effect does not point one way.
``docs/content-program/drafts/T-03-measuring-guard-models-paper.md`` records it twice:

* ``R13`` (line 555): ``Q4_K_M``, the deployed default, is **not verdict-neutral** -- 4 and 11
  items per thousand differ from ``f16``.
* ``R32`` (lines 699-710): across five models from three publishers, **between 4 and 18 verdicts
  per thousand change** at the precision most deployments serve; and ``R33`` records that the
  *direction* does not generalize -- one model moves safety-adverse, another usability-adverse.

So a deployer may assume neither that quantization errs safe nor that it errs conservative, which
is why a configuration difference here is a refusal rather than a warning.

``num_ctx`` is in this record for reproducibility, and NOT because it was measured to matter.
``docs/content-program/01-track-technical.md`` line 172 says so in the repository's own voice --
*"num_ctx pinning is NOT a finding -- it is a deployment decision and a config-divergence
incident, with no sensitivity sweep behind it"* -- and the sweep has since run: ``R23``
(``T-03`` line 613) reports a decision-change rate of **0 of 493 at every one of five num_ctx
values, on both models**. It is recorded and compared because a figure whose configuration nobody
can reconstruct is unauditable, not because moving it changes verdicts.

What this module is not
-----------------------
It is a repository-declared record, not an attestation. It is signed by nothing and it observes
no process. It establishes only that this checkout's evaluator, its promotion gate, its generated
adapter and its Rust CLI read one value -- so a divergence between them is a diff rather than an
argument.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Final

from ._canonical import canonical_json, sha256_text

__all__ = [
    "DEPLOYED",
    "NUM_CTX",
    "NUM_PREDICT",
    "QUANTIZATION",
    "REQUIRED_KEYS",
    "SEED",
    "TEMPERATURE",
    "TOP_K",
    "TOP_P",
    "configuration_mismatch",
    "deployed_digest",
    "quantisation_in_tag",
    "recorded_serving_configuration",
]

#: The GGUF quantization the product serves and every published guard figure was measured at.
#: Named ``Q4_K_M`` in the Ollama model tags of both measured baselines. Moving it invalidates
#: every quoted recall until the benchmarks are re-run; see ``R13``/``R32`` above.
QUANTIZATION: Final[str] = "Q4_K_M"

#: Context window. Pinned for reproducibility, measured inert by ``R23`` -- see the module docs.
NUM_CTX: Final[int] = 8192

#: Seed, part of the determinism contract on both sides of the language boundary.
SEED: Final[int] = 0

#: Cap on generated tokens. A guard verdict is two lines; a truncated one is unparseable, which
#: this system records as NO COVERAGE rather than as a miss.
NUM_PREDICT: Final[int] = 64

#: Greedy decoding. Two runs of the same case must be one measurement, not two.
TEMPERATURE: Final[float] = 0.0
TOP_P: Final[float] = 1.0
TOP_K: Final[int] = 1

#: The deployed serving configuration, as one record. Keyed with ``quantisation`` spelled the way
#: ``baselines._ollama_backend`` already spells it, so the two are comparable without a
#: translation layer -- a translation layer is a second place for the two to disagree.
DEPLOYED: Final[Mapping[str, Any]] = {
    "quantisation": QUANTIZATION,
    "num_ctx": NUM_CTX,
    "seed": SEED,
    "num_predict": NUM_PREDICT,
    "temperature": TEMPERATURE,
    "top_p": TOP_P,
    "top_k": TOP_K,
}

#: Absence is a mismatch. A recorded configuration that omits a key is not a configuration that
#: agrees on it, and treating the two the same is how the 4096 release shipped: nothing said
#: 4096 was wrong, because nothing said what right was.
REQUIRED_KEYS: Final[tuple[str, ...]] = (
    "quantisation",
    "num_ctx",
    "seed",
    "num_predict",
    "temperature",
    "top_p",
    "top_k",
)


#: The shape of a GGUF quantization label. Applied with ``fullmatch`` to the whole upper-cased tag
#: suffix, so the segment must be a label and not merely begin with one. ``F16``/``F32``/``BF16``
#: are the float widths; ``Q`` and ``IQ`` take a block count and then any number of block-type
#: parts, which covers ``Q8_0``, ``Q6_K``, ``Q4_K_M`` and ``IQ4_XS``. A whole-shape match rather
#: than a first-letter test because a first-letter test made ``Qwen3`` a quantization.
_QUANTISATION_LABEL: Final[re.Pattern[str]] = re.compile(
    "(?:BF16|F16|F32|(?:I?Q)[0-9]+(?:_[0-9A-Z]+)*)"
)


def deployed_digest() -> str:
    """Digest over :data:`DEPLOYED`, so a decision can be pinned to the configuration it assumed.

    Carried into the parity decision record. A decision that names no configuration digest cannot
    be re-audited after the configuration moves, and the configuration is the thing that moved.
    """

    return sha256_text(canonical_json(dict(DEPLOYED)))


def recorded_serving_configuration(backend: Mapping[str, Any]) -> dict[str, Any]:
    """Flatten a result document's ``backend`` block onto :data:`REQUIRED_KEYS`.

    Two shapes are in circulation and both are read here rather than one being declared wrong.
    :meth:`warrantor_ml.evaluate.OllamaGuardBackend.descriptor` nests the sampling knobs under
    ``options`` and puts ``seed`` at both levels; ``baselines._ollama_backend`` writes what it
    records flat, which is five of the seven compared keys -- ``quantisation``, ``num_ctx``,
    ``seed``, ``temperature``, ``top_k`` -- and neither ``num_predict`` nor ``top_p``. Passed
    through this function and :func:`configuration_mismatch`, that literal is therefore refused on
    the two it omits, exactly as an absent field must be. That is not a hole in the gate: the gate
    reads the evaluator's result documents in ``eval_results/``, and no result document is built
    from that literal. Neither shape is translated into the other, because a translation step is a
    third shape.

    A key absent from every level is **omitted from the result**, never defaulted. Defaulting it
    would make every historical document silently agree with whatever this build happens to
    serve, which is the exact failure this task exists to close: the five 2026-08-22 candidate
    documents record no quantization at all, and a default would have promoted them as matching.

    ``quantisation`` has a third place it can be written and that place is read too: the Ollama
    model tag, which names the quantization after its final colon
    (``hf.co/mradermacher/Qwen3Guard-Gen-4B-GGUF:Q4_K_M``). Recovering it from the tag is not
    defaulting -- it is reading the one place the fact IS recorded in the documents this repository
    already committed, and it is what separates the two baseline documents, whose tags name
    ``Q4_K_M``, from the five candidate documents, whose tags name nothing. Collapsing those two
    cases into a single refusal would lose the distinction this gate exists to draw.
    """

    options = backend.get("options")
    nested: Mapping[str, Any] = options if isinstance(options, Mapping) else {}
    recorded: dict[str, Any] = {}
    for key in REQUIRED_KEYS:
        if key in backend:
            recorded[key] = backend[key]
        elif key in nested:
            recorded[key] = nested[key]
    if "quantisation" not in recorded:
        from_tag = quantisation_in_tag(str(backend.get("model", "")))
        if from_tag is not None:
            recorded["quantisation"] = from_tag
    return recorded


def quantisation_in_tag(model_tag: str) -> str | None:
    """The quantization an Ollama model tag names, or ``None`` when it names none.

    Deliberately narrow, and narrow by SHAPE rather than by first letter. Only the segment after
    the FINAL colon is considered, and only when the whole segment matches
    :data:`_QUANTISATION_LABEL`: a float width (``F16``, ``F32``, ``BF16``) or a ``Q``/``IQ`` block
    count with its optional block-type parts (``Q8_0``, ``Q4_K_M``, ``Q6_K``, ``IQ4_XS``). A tag
    whose suffix is a version (``:latest``, ``:v2``), a model name (``:Qwen3``, ``:Qwen3-4B``), or
    which has no colon at all, returns ``None``, which the gate treats as a refusal.

    The first version of this reader asked whether the suffix started with ``Q``, ``F16``, ``F32``,
    ``BF16`` or ``IQ`` and contained any digit, which made ``:Qwen3`` a quantization named
    ``Qwen3`` -- and the evaluator then wrote that string into a signed result document as
    provenance. Guessing that widely is the failure this function's own next sentence names: a
    provenance field that is wrong and unchecked is worse than an absent one --
    ``baselines._ollama_backend``'s own docstring records that lesson, from a record whose
    ``model_tag`` said 0.6B while its ``backend["model"]`` said 4B.
    """

    _, separator, suffix = model_tag.rpartition(":")
    candidate = suffix.strip()
    if not separator or not candidate:
        return None
    if _QUANTISATION_LABEL.fullmatch(candidate.upper()):
        return candidate
    return None


def configuration_mismatch(recorded: Mapping[str, Any]) -> tuple[str, ...]:
    """Every field on which ``recorded`` differs from :data:`DEPLOYED`, or is absent.

    An empty tuple means parity. Each entry names the field, the recorded value and the deployed
    one, because a refusal an operator cannot act on gets bypassed rather than fixed.

    Numeric comparison is by value across ``int``/``float`` (``0`` and ``0.0`` are one
    temperature) but ``bool`` is never numeric -- ``True == 1`` in Python and a ``top_k`` of
    ``True`` is not a ``top_k`` of 1.
    """

    problems: list[str] = []
    for key in REQUIRED_KEYS:
        expected = DEPLOYED[key]
        if key not in recorded:
            problems.append(
                f"{key} is absent from the recorded configuration (this build serves "
                f"{expected!r}); an absent field is a mismatch, never a match"
            )
            continue
        if not _values_agree(recorded[key], expected):
            problems.append(
                f"{key} was recorded as {recorded[key]!r} and this build serves {expected!r}"
            )
    return tuple(problems)


def _values_agree(recorded: Any, expected: Any) -> bool:
    """Whether a recorded value is the deployed one, without letting ``True`` pass for ``1``."""

    if isinstance(recorded, bool) is not isinstance(expected, bool):
        return False
    if isinstance(recorded, bool):
        return recorded is expected
    if isinstance(recorded, int | float) and isinstance(expected, int | float):
        return float(recorded) == float(expected)
    return recorded == expected
