"""Open-weight teachers may generate. Frontier judges may only score.

The rule is one sentence and it erodes by convenience, not by decision. Nobody sets out to call
a frontier API to author training rows. What happens is a rejection-sampling loop: a frontier
model scores a generated pair, explains what is wrong with it, and somebody -- reasonably, at
2am -- pastes the explanation into the pair and keeps it. The corpus is now frontier-authored
and no field records it.

So the separation here is carried by types, and the enforcement is that they do not meet:

* :func:`generate` returns :class:`GeneratedRow`, which is the only thing corpus builders in
  :mod:`warrantor_ml.tasks` accept.
* :func:`judge` returns :class:`JudgeScore`. It carries numbers and a ``rationale`` string, and
  it is **not** a :class:`GeneratedRow`. There is no constructor, adapter or ``from_score``
  anywhere in this package that turns one into the other, and adding one is the change a
  reviewer is being asked to notice.
* :func:`generate` raises :class:`FrontierGenerationRefused` for any model id that is not in
  :data:`TEACHERS`, which is checked before a backend is touched.

Local generation runs through the same loopback, standard-library, option-pinned shape as
:class:`warrantor_ml.evaluate.OllamaGuardBackend`: temperature 0, seed recorded, no new HTTP
client, no egress. Importing this module performs no I/O.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from ._canonical import canonical_json, sha256_text
from .manifest import TeacherProvenance

__all__ = [
    "JUDGES",
    "TEACHERS",
    "FrontierGenerationRefused",
    "GeneratedRow",
    "JudgeScore",
    "ModelSpec",
    "TeacherBackend",
    "UnknownJudgeError",
    "generate",
    "judge",
    "prompt_template_digest",
]


class FrontierGenerationRefused(PermissionError):
    """Raised when something that is not a registered open-weight teacher was asked to generate.

    ``PermissionError`` rather than ``ValueError``: this is a refusal of authority, not a typo,
    and it should read that way in a traceback.
    """


class UnknownJudgeError(KeyError):
    """Raised when a scoring model is not in the judge allowlist."""


@dataclass(frozen=True)
class ModelSpec:
    """A model this pipeline is permitted to call, and in which role.

    ``weights_digest`` is empty for judges on purpose: a hosted frontier model has no weights
    anyone can digest, which is exactly why it cannot be a teacher. A corpus whose provenance
    bottoms out in "whatever the endpoint returned that week" is not reproducible, and
    :func:`warrantor_ml.manifest.validate_manifest` refuses a generated block whose generator
    digest is not well-formed.
    """

    model_id: str
    repo_id: str
    revision: str
    licence: str
    weights_digest: str
    open_weights: bool
    notes: tuple[str, ...] = field(default_factory=tuple)


#: Models permitted to WRITE training rows. Open weights, pinned revision, digestible.
#:
#: The digests below are placeholders in the shape the validator requires and MUST be replaced
#: with the real file digests before a corpus built with them is trained on -- which is why
#: `validate_manifest` checks the shape and the model card checks the value. Adding a row here
#: is a licence decision and a reproducibility decision, not a convenience.
TEACHERS: dict[str, ModelSpec] = {
    "qwen3-14b-instruct": ModelSpec(
        model_id="qwen3-14b-instruct",
        repo_id="Qwen/Qwen3-14B-Instruct",
        revision="0" * 40,
        licence="Apache-2.0",
        weights_digest="sha256:" + "0" * 64,
        open_weights=True,
        notes=(
            "General augmentation teacher for the substrate tasks (bounds, triage, effects). "
            "Apache-2.0 with no acceptable-use rider, so generated rows inherit no rider.",
            "PLACEHOLDER weights_digest -- replace with the real file digest before any corpus "
            "built with this teacher is used for training.",
        ),
    ),
    "qwen3guard-gen-4b": ModelSpec(
        model_id="qwen3guard-gen-4b",
        repo_id="Qwen/Qwen3Guard-Gen-4B",
        revision="0" * 40,
        licence="Apache-2.0",
        weights_digest="sha256:" + "0" * 64,
        open_weights=True,
        notes=(
            "The guard itself, used as a teacher only for hard-negative MINING on benign text. "
            "Never used to relabel a row whose human label already exists: distilling the "
            "measured baseline reproduces its 0.4298 recall on Unqualified Professional Advice "
            "along with everything else.",
            "PLACEHOLDER weights_digest -- replace before use.",
        ),
    ),
}

#: Models permitted to SCORE and nothing else. Everything here is hosted and closed.
#:
#: A judge's output is a :class:`JudgeScore`. It cannot be assigned to a training-pair field
#: because no training-pair field has its type.
JUDGES: dict[str, ModelSpec] = {
    "frontier-judge": ModelSpec(
        model_id="frontier-judge",
        repo_id="(hosted frontier API -- no weights)",
        revision="",
        licence="proprietary",
        weights_digest="",
        open_weights=False,
        notes=(
            "MAY SCORE, MAY NEVER GENERATE. Blind pairwise judging of candidate outputs only. "
            "Its rationale text is carried on JudgeScore and read by humans reviewing an eval; "
            "no corpus builder accepts a JudgeScore.",
            "A frontier judgement is also never a verdict in the product sense -- it is an "
            "input to a human decision about whether an eval set is measuring the right thing.",
        ),
    ),
}


@dataclass(frozen=True)
class GeneratedRow:
    """One augmented training pair. The ONLY row type corpus builders accept.

    ``teacher_id`` is required and is checked against :data:`TEACHERS` at construction time by
    :func:`generate`, so a row cannot exist without a registered open-weight author.
    """

    row_id: str
    prompt: str
    target: str
    teacher_id: str
    seed: int
    #: Free-form task-specific labels (e.g. the side-effect class, the triage label). Kept as a
    #: mapping rather than typed per task so one generation path serves five corpus builders.
    labels: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class JudgeScore:
    """A frontier model's score for something. Deliberately not a training row.

    There is no path from here into a corpus. ``rationale`` exists because a human reading an
    eval report needs to know *why* the judge scored something low; it is not a correction to
    be pasted into the row that earned it.
    """

    subject_id: str
    judge_id: str
    score: float
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        """Serialise for an eval report. Note the absence of anything shaped like a target."""

        return {
            "subject_id": self.subject_id,
            "judge_id": self.judge_id,
            "score": self.score,
            "rationale": self.rationale,
            "usable_as_training_data": False,
        }


class TeacherBackend(Protocol):
    """The seam :func:`generate` talks to. Implementations must be deterministic given a seed.

    Deliberately narrow: one method, text in, text out. The local implementation is expected to
    be a loopback Ollama call built the way ``evaluate.OllamaGuardBackend`` builds one --
    temperature 0, ``top_k`` 1, explicit seed, pinned ``num_ctx`` -- so a generated corpus can
    be regenerated byte-for-byte from the manifest.
    """

    def descriptor(self) -> dict[str, Any]:
        """Backend identity, recorded in the manifest's generator block."""

    def complete(self, prompt: str) -> str:
        """Produce one completion, or raise."""


def prompt_template_digest(template: str) -> str:
    """Digest a prompt template so the manifest pins the instructions, not just the model.

    Two runs of the same teacher with different prompts produce different corpora. A manifest
    that records only the model id claims a reproducibility it does not have.
    """

    return sha256_text(template)


def generate(
    teacher_id: str,
    prompts: Sequence[tuple[str, str]],
    backend: TeacherBackend,
    *,
    prompt_template: str,
    seed: int,
    decoding: Mapping[str, Any] | None = None,
) -> tuple[tuple[GeneratedRow, ...], TeacherProvenance]:
    """Generate training rows with a registered open-weight teacher.

    Args:
        teacher_id: must be a key of :data:`TEACHERS`. Checked BEFORE the backend is touched, so
            a misrouted call costs nothing and fails identically offline.
        prompts: ``(row_id, rendered_prompt)`` pairs, in the order they should be generated.
        backend: the completion seam. Never constructed here -- the caller supplies it, which
            is what keeps this module import-time silent and testable with no network.
        prompt_template: the template the prompts were rendered from; digested into provenance.
        seed: recorded in every row and in the provenance block.
        decoding: sampling options, recorded verbatim. Defaults to the deterministic set.

    Returns:
        The rows and the :class:`~warrantor_ml.manifest.TeacherProvenance` block that must
        accompany them in the corpus manifest.

    Raises:
        FrontierGenerationRefused: ``teacher_id`` is not a registered open-weight teacher --
            including when it is a registered *judge*, which earns a message that says so.
    """

    if teacher_id in JUDGES:
        raise FrontierGenerationRefused(
            f"{teacher_id!r} is registered as a JUDGE and may not generate training data. "
            "Frontier models may score and may never write. If this corpus needs augmentation, "
            f"route it through an open-weight teacher: {', '.join(sorted(TEACHERS))}"
        )
    if teacher_id not in TEACHERS:
        raise FrontierGenerationRefused(
            f"{teacher_id!r} is not a registered open-weight teacher. Registered teachers: "
            f"{', '.join(sorted(TEACHERS))}. Adding one is a licence and reproducibility "
            "decision -- the model needs open weights, a pinned revision and a file digest, "
            "because a corpus nobody can regenerate is a corpus nobody can withdraw"
        )

    spec = TEACHERS[teacher_id]
    options: Mapping[str, Any] = decoding or {
        "temperature": 0.0,
        "top_p": 1.0,
        "top_k": 1,
        "seed": seed,
    }
    rows = tuple(
        GeneratedRow(
            row_id=row_id,
            prompt=prompt,
            target=backend.complete(prompt),
            teacher_id=teacher_id,
            seed=seed,
        )
        for row_id, prompt in prompts
    )
    provenance = TeacherProvenance(
        model_id=spec.model_id,
        role="teacher",
        weights_digest=spec.weights_digest,
        prompt_template_digest=prompt_template_digest(prompt_template),
        seed=seed,
        # The backend descriptor goes in verbatim: `num_ctx` and the endpoint change the output
        # and a provenance block that omits them overstates what it pins.
        decoding={**options, "backend": backend.descriptor()},
    )
    return rows, provenance


def judge(
    judge_id: str,
    subject_id: str,
    score: float,
    rationale: str,
) -> JudgeScore:
    """Record a frontier model's score for something. Produces no training data.

    Raises:
        UnknownJudgeError: ``judge_id`` is not on the judge allowlist. A teacher id is refused
            here too -- not because scoring with an open model is wrong, but because the roles
            are recorded per call and a row that says "judged by the teacher that wrote it" is
            a measurement of nothing.
    """

    if judge_id not in JUDGES:
        raise UnknownJudgeError(
            f"{judge_id!r} is not a registered judge; registered: {', '.join(sorted(JUDGES))}"
        )
    return JudgeScore(subject_id=subject_id, judge_id=judge_id, score=score, rationale=rationale)


def roster_digest() -> str:
    """Digest of the whole teacher/judge roster, for the parity decision record.

    A promotion decision that does not pin which models were permitted to touch the data is a
    decision that cannot be re-audited after the roster changes.
    """

    body = {
        "teachers": {
            key: {
                "repo_id": spec.repo_id,
                "revision": spec.revision,
                "licence": spec.licence,
                "weights_digest": spec.weights_digest,
            }
            for key, spec in sorted(TEACHERS.items())
        },
        "judges": {
            key: {"repo_id": spec.repo_id, "licence": spec.licence}
            for key, spec in sorted(JUDGES.items())
        },
    }
    return sha256_text(canonical_json(body))
