# aumos-metr-bridge (X6)

Integration with [METR](https://metr.org/) (Model Evaluation & Threat Research)
evaluations. Four components:

- **METREvalAdapter** — translates a METR task spec into an AumOS ``safe_eval``
  pipeline so METR tasks run under the AumOS evaluation harness.
- **TranscriptExporter** — exports an AumOS agent transcript into the METR
  transcript format (JSONL with ``step``, ``role``, ``content`` fields).
- **RiskReportBridge** — translates an AumOS risk report into the METR risk
  schema (severity-ordered findings with CWE/MITRE ATLAS tags).
- **IndependentVerifier** — second-source check that re-runs the eval with a
  different seed and confirms the score is reproducible.

See `docs/rfcs/X6-metr-bridge.md`.
