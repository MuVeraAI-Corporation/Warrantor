"""Per-model corpus builders, label vocabularies and asymmetric metrics.

One module per model family. Four of the eight models -- Guard 0.6B and 4B, each in a
weak-category and an adversarial-robustness variant -- share :mod:`~warrantor_ml.tasks.guard`,
because they are two row selectors over one corpus and two base profiles, not four pipelines.
The other four are substrate models whose supervision comes from warrant artifacts, so each
gets its own module, its own label vocabulary mirrored from the Rust type it serves, and its
own metric.

Not one of these tasks is scored with accuracy. Every one of them has two error directions that
cost different amounts, which is the same argument :mod:`warrantor_ml.metrics` already makes for
the deny gate: an over-broad bound proposal grants authority nobody chose, an under-broad one
costs a refusal; a downgrade across the consequential boundary is not the same error as a
confusion within it.
"""

from __future__ import annotations

__all__: list[str] = []
