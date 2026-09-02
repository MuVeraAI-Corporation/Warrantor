# Artifact review — Every Eval Ever

Status: paper, schema and pinned repository reviewed; local suite reproduced with one bounded
presentation failure  
Review date: 2026-08-30  
Repository: `https://github.com/evaleval/every_eval_ever`  
Commit: `687b7a36902c01db8a80f0b719d8861d6494f550` (2026-08-28)  
Paper: arXiv:2606.14516 (2026-06-12)  
Repository version: 0.2.3rc1  
Schema version: 0.3.0  
License: MIT

## Decision

**Adopt the schema semantics; modify the assurance layer; do not fork the general vocabulary.**

EEE is direct prior art for the cross-harness portion of Warrantor evaluation receipts. It is not
direct prior art for Warrantor's proposed authenticated authority-to-evidence chain. The clean design
boundary is:

- EEE describes the evaluation, source, model, generation, dataset, metric, judge and instance
  evidence;
- Warrantor authenticates the accountable authority, issuer, evaluator, grader and exact predicate;
- optional receiver/TEE evidence corroborates or measures execution; and
- independent inventory reconciliation provides a declared completeness bound.

## Reproduction receipt

| Item | Observed result |
|---|---|
| Clone identity | Clean repository at `687b7a36902c01db8a80f0b719d8861d6494f550` before local environment creation |
| Runtime | uv 0.10.4; CPython 3.13.11 selected by uv |
| Environment | Isolated `.venv` created from the pinned repository; 68 packages installed |
| Initial command | Default captured pytest invocation |
| Initial result | No collection result; mounted-environment capture cleanup raised `FileNotFoundError` while truncating pytest's temporary output file |
| Controlled rerun | Explicit `tests` path with output capture disabled |
| Collected outcome | 997 passed; 45 skipped; 1 failed; 1,043 total in 137.01 seconds |
| Sole failure | ANSI-color assertion expected a bold-red escape sequence; capture-disabled output contained correct failure text and counts but no escape sequence |
| Semantic conclusion | No converter, schema, validation, checksum, provenance, duplicate-detection or raw-capture failure was observed |

The initial capture failure and the ANSI assertion are recorded rather than discarded. Neither is
evidence that EEE's data semantics are correct; the positive result is limited to the executed suite.
It also does not reproduce the reported public-datastore scale or every remote adapter against live
third-party services.

## Schema surface reviewed

### Aggregate evaluation record

The aggregate schema can represent:

- schema and evaluation identity, retrieval time and source provenance;
- source organization and evaluator relationship;
- evaluation library/framework and version;
- model identity, developer and access/deployment information;
- generation configuration;
- benchmark/evaluation name and dataset source;
- metric type, direction, bounds and score details;
- uncertainty or confidence information;
- LLM-judge configuration where applicable; and
- a checked reference to detailed instance results.

### Instance-level sidecar

The optional JSONL sidecar adds:

- stable relationship to the aggregate evaluation;
- raw and formatted input;
- reference/target answer;
- model output and reasoning;
- multi-turn messages and tool-call traces;
- answer attribution;
- per-instance evaluation and score; and
- token and performance information.

Its support for single-turn, multi-turn and agentic structures makes it useful for Warrantor beyond
ordinary benchmark scores, but it is still not a complete action-effect or environment-state trace.

## Integrity and provenance mechanisms

The repository uses SHA-256 for downloaded/raw payload snapshots, detailed-result checksums and
duplicate/fingerprint workflows. Aggregate and sidecar validation checks IDs, paths, counts and
cross-file consistency. Cron/conversion paths emit accounting and provenance reports so excluded,
failed and converted records are not silently conflated.

These mechanisms are necessary but do not authenticate a producer. A malicious or compromised
operator can alter content and recompute an unkeyed digest. Repository review history identifies a
maintainer-approved contribution; it is not a portable evaluation signature and cannot prove that
the named evaluator executed the reported run.

No native DSSE, in-toto, Sigstore, Ed25519 or equivalent semantic-record signing profile was located
in the bounded source search. This is a version-bounded negative result, not a claim about every
deployment, extension or future release.

## Important limitations retained from the source

1. Representation is strongest for text and single-model evaluation. Multimodal, human-preference,
   multi-agent and other complex modalities need further evolution.
2. EEE does not run evaluations. It can only preserve provenance that the source supplied or that a
   converter can reliably reconstruct.
3. A shared schema makes nominal comparisons possible but does not make two framework results
   methodologically equivalent.
4. Fresh UUIDs distinguish records but do not create a canonical identity for semantically identical
   runs; deduplication remains an analysis/governance function.
5. Community ingestion can introduce omissions, inconsistent metadata or correction needs.
6. Schema validation is not benchmark-validity review, signer authentication, measured execution,
   complete mediation or population completeness.

## Required Warrantor compatibility profile

The Warrantor predicate should include or losslessly reference an EEE 0.3 record and add:

| Warrantor block | Required property |
|---|---|
| `native_source` | Immutable original bytes, media type, native framework/version and digest |
| `conversion` | Adapter identity/digest, source-to-target field map, transformations and classified loss |
| `authority` | Accountable principal, warrant/delegation chain and verifier-recomputed effective authority |
| `issuer` | Credential/key identity, key history, signature algorithm and claim boundary |
| `evaluator` | Code/source/container digest, invocation, dependencies and runtime identity |
| `grader` | Code or judge-model identity, rubric/prompt digest, calibration and decision rule |
| `target` | Asserted ID plus artifact/runtime measurement when available; adapter/quantization state |
| `corroboration` | Receiver, gateway, trusted-time, transparency or TEE evidence kept as separate claims |
| `completeness` | Declared population/window and reconciliation result against independent inventory |
| `lineage` | Rerun, correction, invalidation, supersession and human acceptance links |

## Adapter order

1. **Inspect AI** — richest native provenance and existing EEE conversion path.
2. **garak** — important red-team attempts/detector evidence and existing result semantics.
3. **PyRIT** — rich component identities, scoring rationale and prompt/conversion lineage.
4. **AgentDojo** — agentic tasks, attacks, messages and utility/security outcomes.
5. **Hawk** — operational runner/import/editor and storage provenance around Inspect.

Each adapter must publish a source-field coverage report. “Converted successfully” is insufficient:
the release gate is no unknown semantic loss and verified binding from original bytes to the signed
predicate.

## Score and standing

EEE scores **91/100 — essential** under the v2 rubric:

| Dimension | Score |
|---|---:|
| Rigor | 17/20 |
| Technical depth | 14/15 |
| Authority | 13/15 |
| Warrantor relevance | 15/15 |
| Reproducibility | 10/10 |
| Independence | 8/10 |
| Originality | 5/5 |
| Durability | 4/5 |
| Recency fitness | 5/5 |

It is essential because ignoring it would cause Warrantor to duplicate a rapidly developing neutral
schema and lose interoperability credibility. It is not evidence that evaluation authenticity or
completeness is solved.

## Immediate actions

- Open an upstream design discussion before adding Warrantor-specific semantic fields.
- Freeze an EEE 0.3 compatibility fixture and create a version-negotiation policy.
- Build the Inspect round-trip and source-field coverage report first.
- Place the resulting EEE predicate inside the existing DSSE/in-toto Warrantor design.
- Add negative vectors for recomputed hashes, signer substitution, omitted instances, edited logs,
  lossy conversion, stale schema, UUID duplication and unverified judge identity.
- Defer any “first,” “only” or “complete” positioning until independent adapters and completeness
  experiments pass.

