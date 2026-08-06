# aumos-bias-sentinel (A3)

Combined bias and copyright auditing for model outputs.

**Bias module** — four simplified detectors:
- **BOLD** — counts identity-group mentions in prompts/responses.
- **HONEST** — flags identity-group + negative-token co-occurrences.
- **CrowS-Pairs** — measures stereotype polarity via counterfactual pairs.
- **WinoBias** — measures gendered pronoun bias in coreference.

**Copyright module** — n-gram overlap detector: flags any contiguous n-gram
(default 13) shared with a reference corpus of copyrighted text.

The detectors are intentionally lightweight (no model weights). They cover the
"signal" each academic metric captures and gate on configurable thresholds;
the full statistical variants (using a language model) are task 03.

See `docs/rfcs/A3-bias-sentinel.md`.
