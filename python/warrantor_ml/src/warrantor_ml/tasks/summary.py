"""Model 8: prose over a report bundle, designed around the hazard rather than warned about it.

A fluent summary of a TAMPERED record is precisely the failure this product exists to prevent.
An operator who reads *"the agent completed the refactor within its bounds and spent 40 cents"*
has been told a story about bytes nobody vouched for, and the story is more persuasive than the
red banner beside it.

Guarding that with a conditional is not enough, because a conditional can be moved. So the
constraint is structural: the summariser accepts :class:`VerifiedBundleView` and nothing else,
and that class has exactly one constructor, :meth:`VerifiedBundleView.from_response`, which
raises unless the Rust-produced envelope says ``integrity == "ok"``. There is no code path from
a tampered bundle to prose because there is no way to build the input type from one.

Verification happens only in Rust
---------------------------------
This module performs **no digest comparison, no signature check, and imports no crypto**. It
reads the verdict the local agent already computed and refuses on it. That is the whole
contract: a second verifier above the Rust line can disagree with the first, and then a human
has to decide which to believe -- which is the situation the product exists to prevent. If this
file ever grows a ``hashlib`` import over bundle bytes or a ``cryptography`` import at all, that
is the change to stop.

``unknown`` is never rendered as ``failed``
-------------------------------------------
Integrity is three-valued. ``failed`` means checked and broken; ``unknown`` means not checked.
An archived bundle from a machine that no longer has the key is ``unknown``, and telling its
owner it was tampered with is a false accusation. :meth:`VerifiedBundleView.from_response`
raises with **distinct messages** for the two, and a test asserts the ``unknown`` message does
not contain the word for the other.

And the prose carries no envelope vocabulary
--------------------------------------------
:func:`check_summary` rejects a summary containing ``verified``, ``integrity``, ``ok``,
``failed`` or ``unknown`` as whole words. A UI that can place model text where a verdict belongs
will eventually do it; the cheapest way to stop that is for the model's output to contain no
string that looks like a verdict.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

__all__ = [
    "ENVELOPE_VOCABULARY",
    "ReportSummary",
    "SummaryFaithfulnessError",
    "UnverifiedBundleRefused",
    "VerifiedBundleView",
    "check_summary",
    "render_source_facts",
]


class UnverifiedBundleRefused(PermissionError):
    """Raised when a bundle was not vouched for by the Rust verifier. Never downgraded.

    ``PermissionError`` because this is a refusal to act, not a malformed input.
    """


class SummaryFaithfulnessError(ValueError):
    """Raised when generated prose says something the bundle does not."""


#: Words that name a verification verdict. A summary containing any of them can be mistaken for
#: one, so the faithfulness check rejects it. Matched on word boundaries -- ``ok`` must not
#: reject ``looked`` or ``broken``.
ENVELOPE_VOCABULARY: tuple[str, ...] = (
    "verified",
    "unverified",
    "integrity",
    "ok",
    "failed",
    "unknown",
    "tampered",
    "signature",
    "attested",
)


@dataclass(frozen=True)
class VerifiedBundleView:
    """A report bundle the Rust verifier vouched for. The summariser's ONLY accepted input.

    Construct it with :meth:`from_response` and no other way. The fields are deliberately a
    narrow projection of ``ReportBundle`` -- everything the prose is allowed to mention, and
    nothing that would let the summariser reason about verification.
    """

    bundle_digest: str
    warrant_id: str
    goal: str
    subject: str
    state: str
    issued_at: int
    expires_at: int
    #: ``ReportBundle.limitations`` is never empty by construction on the Rust side, and a
    #: summary that omits it is a summary that quietly upgrades a caveated record into a clean
    #: one. :func:`check_summary` requires the summary to name that limitations exist.
    limitations: tuple[str, ...]
    staged_count: int | None
    spend_cents_observed: int | None
    bounds: Mapping[str, Any]
    liveness: str

    @classmethod
    def from_response(cls, payload: Mapping[str, Any]) -> VerifiedBundleView:
        """Read a ``/v1/warrants/{id}/report`` response, or refuse it.

        The envelope shape is the one ``Response::json`` produces::

            {"verified": bool, "verification": {"integrity", "liveness", "checked_at", ...},
             "data": {...}}

        Raises:
            UnverifiedBundleRefused: integrity is not ``ok``. The message differs by cause --
                ``failed`` and ``unknown`` are different claims and one of them is an accusation.
        """

        verification = payload.get("verification")
        if not isinstance(verification, Mapping):
            raise UnverifiedBundleRefused(
                "the response carries no verification envelope. Nothing here can supply one: "
                "verification happens in Rust, client-side, and a summariser that computed its "
                "own verdict would be a second verifier that can disagree with the first"
            )
        integrity = str(verification.get("integrity", "")).strip().lower()

        if integrity == "failed":
            raise UnverifiedBundleRefused(
                "refusing to summarise: the local agent CHECKED this record and the check did "
                "not hold. A fluent summary of an altered record is the failure this product "
                f"exists to prevent. Verifier's reason: {verification.get('reason', '')!r}"
            )
        if integrity != "ok":
            # Deliberately does NOT say the record failed, was altered, or was tampered with.
            # `unknown` means nothing was checked, and reporting it as a failure is a false
            # accusation against an archive whose signing key is simply no longer to hand.
            raise UnverifiedBundleRefused(
                "refusing to summarise: nothing was checked for this record, so there is no "
                "verdict to rest prose on. This is NOT a statement that the record is bad -- it "
                "is the absence of a check. Re-request it from a local agent that holds the "
                f"key. Verifier's code: {verification.get('code')!r}"
            )

        data = payload.get("data")
        if not isinstance(data, Mapping):
            raise UnverifiedBundleRefused("the response carries a verdict but no bundle data")

        digest = verification.get("digest")
        if not isinstance(digest, str) or not digest:
            raise UnverifiedBundleRefused(
                "the verdict names no digest, so a summary produced from it could not be bound "
                "to the bundle it describes. A summary that cannot be tied to its subject can "
                "be shown against a different one"
            )

        limitations = tuple(str(item) for item in data.get("limitations", ()) or ())
        if not limitations:
            raise UnverifiedBundleRefused(
                "the bundle declares no limitations. ReportBundle.limitations is never empty by "
                "construction, so an empty list means this is not a bundle this summariser "
                "understands -- and summarising a record whose caveats went missing is how a "
                "reader ends up trusting a guarantee that was never made"
            )

        spend = data.get("spend")
        spend_cents = None
        if isinstance(spend, Mapping):
            raw = spend.get("cents_observed")
            spend_cents = None if raw is None else int(raw)

        return cls(
            bundle_digest=digest,
            warrant_id=str(data.get("warrant_id", "")),
            goal=str(data.get("goal", "")),
            subject=str(data.get("subject", "")),
            state=str(data.get("state", "")),
            issued_at=int(data.get("issued_at", 0)),
            expires_at=int(data.get("expires_at", 0)),
            limitations=limitations,
            staged_count=(None if data.get("staged_count") is None else int(data["staged_count"])),
            spend_cents_observed=spend_cents,
            bounds=dict(data.get("bounds", {}) or {}),
            liveness=str(verification.get("liveness", "")),
        )

    def source_numbers(self) -> frozenset[str]:
        """Every number the prose is permitted to contain, as strings.

        The faithfulness check is a whitelist rather than a similarity score: each numeric token
        in the summary must appear here. A summary that invents a spend figure is not slightly
        less similar to the reference, it is false, and a similarity score prices those the same.
        """

        values: set[str] = {
            str(self.issued_at),
            str(self.expires_at),
            str(len(self.limitations)),
        }
        if self.staged_count is not None:
            values.add(str(self.staged_count))
        if self.spend_cents_observed is not None:
            values.add(str(self.spend_cents_observed))
        for key in ("tools", "write_paths", "egress_hosts", "staged_classes"):
            entry = self.bounds.get(key)
            if isinstance(entry, Sequence) and not isinstance(entry, str):
                values.add(str(len(entry)))
        for entry in self.bounds.values():
            if isinstance(entry, int) and not isinstance(entry, bool):
                values.add(str(entry))
        return frozenset(values)


def render_source_facts(view: VerifiedBundleView) -> dict[str, Any]:
    """The fact sheet handed to the model. The model sees this and never the raw response.

    Notice what is absent: no ``integrity``, no ``verified``, no digest, no signing key. The
    summariser is not given the verification verdict at all, so it cannot describe one even if
    it wanted to, and the prose it produces is about the run rather than about the check.
    """

    return {
        "warrant_id": view.warrant_id,
        "goal": view.goal,
        "subject": view.subject,
        "state": view.state,
        "issued_at": view.issued_at,
        "expires_at": view.expires_at,
        "staged_count": view.staged_count,
        "spend_cents_observed": view.spend_cents_observed,
        "bounds": dict(view.bounds),
        "limitations": list(view.limitations),
        "instruction": "Summarise the run for a decision-maker. Describe only what is above. "
        "Do not describe whether the record was checked -- that is not in your input and it is "
        "not yours to state. You MUST tell the reader the record carries limitations and how "
        "many.",
    }


@dataclass(frozen=True)
class ReportSummary:
    """Generated prose, bound to the digest of the bundle it summarises.

    ``bundle_digest`` travels with the prose so a summary of bundle A cannot be displayed
    against bundle B. Without it, a cached summary outlives the record it describes and there is
    nothing to compare.
    """

    bundle_digest: str
    warrant_id: str
    prose: str
    model_id: str

    def to_dict(self) -> dict[str, Any]:
        """Serialise, with the binding first and the disclaimer attached."""

        return {
            "bundle_digest": self.bundle_digest,
            "warrant_id": self.warrant_id,
            "prose": self.prose,
            "model_id": self.model_id,
            "source": "model",
            "note": "Generated prose about a record the local agent vouched for. It is not "
            "itself a verdict and must never be rendered where one belongs.",
        }


_NUMBER = re.compile(r"\d+")
_LIMITATION_WORDS = ("limitation", "caveat", "does not establish", "not established")


def check_summary(summary: ReportSummary, view: VerifiedBundleView) -> None:
    """Faithfulness check: every claim traceable, no verdict vocabulary, limitations named.

    This is the eval for model 8, and it is deliberately not a similarity score against a
    reference summary. A model that writes fluent prose with one invented number scores well on
    similarity and is unusable; a model that writes plainly and states only what the bundle says
    scores poorly on similarity and is correct.

    Raises:
        SummaryFaithfulnessError: on the first category of problem found, with all instances of
            it listed.
    """

    problems: list[str] = []

    if summary.bundle_digest != view.bundle_digest:
        problems.append(
            f"summary is bound to {summary.bundle_digest!r} but was checked against "
            f"{view.bundle_digest!r}; a summary shown against the wrong bundle is worse than no "
            "summary"
        )

    lowered = summary.prose.lower()
    leaked = [word for word in ENVELOPE_VOCABULARY if re.search(rf"\b{re.escape(word)}\b", lowered)]
    if leaked:
        problems.append(
            f"prose contains verification vocabulary {leaked}. Model text that reads like a "
            "verdict can be placed where a verdict belongs, and integrity is an Ed25519 "
            "question with a three-valued answer that no model gets to opine on"
        )

    permitted = view.source_numbers()
    invented = sorted({token for token in _NUMBER.findall(summary.prose)} - permitted)
    if invented:
        problems.append(
            f"prose contains numbers with no source in the bundle: {invented}. Every figure a "
            "decision-maker reads has to be traceable to a field"
        )

    if not any(word in lowered for word in _LIMITATION_WORDS):
        problems.append(
            "prose never mentions that the bundle carries limitations. ReportBundle.limitations "
            "is never empty by construction, and a summary that drops it silently upgrades a "
            "caveated record into a clean one"
        )

    if problems:
        listing = "\n".join(f"  - {problem}" for problem in problems)
        raise SummaryFaithfulnessError(
            f"summary for {view.warrant_id!r} is not faithful: {len(problems)} problem(s)\n"
            f"{listing}"
        )
