"""Warrantor model intelligence — the guard-model lane of the content-moderation plane.

Five pieces, each usable on its own:

* :mod:`warrantor_ml.datasets` — declarative corpus registry. Licences, click-through terms and
  gating are data; downloads happen on demand and never at import.
* :mod:`warrantor_ml.metrics` — confusion matrix and the derived rates, recall first.
* :mod:`warrantor_ml.evaluate` — runs a guard model over a labelled set against a local Ollama
  backend, deterministically, and writes a signed-digest JSON result.
* :mod:`warrantor_ml.model_card` — builds and signs an AIBOM, and refuses to emit one that is
  missing a required field.
* :mod:`warrantor_ml.fine_tune` — LoRA/QLoRA planning and training, with no CPU fallback.
* :mod:`warrantor_ml.deploy_model` — registers a fine-tuned adapter behind the
  ``ContentScanner`` trait without touching enforcement code.

Standing constraints these modules encode rather than document:

* **Recall is the metric.** A false negative on a deny gate is silently recorded as a success.
* **Models advise; the deterministic substrate decides.** No model output is ever wired to a
  terminating action.
* **Zero marginal spend.** No paid API, no cloud GPU, no new accounts.
* **Never train on CSAM.** The AIBOM will not emit without a named, dated exclusion attestation.

Importing this package performs no I/O.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "1.0.0"
