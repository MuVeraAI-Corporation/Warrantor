# Native evaluation-artifact integrity and interoperability matrix

Status: pinned code-inspection wave complete  
Snapshot: 2026-08-30  
Claim under test: CLM-0013  
Purpose: distinguish reproducibility metadata, content integrity, storage controls, authenticated claims,
measured execution and history completeness across the evaluation systems named by the repository.

## Executive result

The repository's original sentence—“promptfoo, Inspect, HELM and lm-eval-harness all market
reproducibility and none of them signs anything or pins the grader”—is not defensible as a global
absence claim. Direct academic prior art already signs or hardware-attests material evaluation
inputs and outputs. The narrower native-harness result is version-bounded:

> At the pinned commits inspected on 2026-08-30, no built-in profile was found in garak, PyRIT,
> Inspect AI, AgentDojo or METR/Hawk that key-signs the complete native evaluation artifact and
> enables an independent relying party to authenticate the asserted evaluator, grader, target,
> inputs and results without trusting the artifact operator.

That statement must not be shortened to “the tools provide no integrity or provenance.” They record
substantial evidence:

- garak records run/plugin configuration, attempt-level prompts and outputs, detector results and
  content hashes;
- PyRIT records deterministic component identities, scorer and target identifiers, prompt hashes,
  conversions, objectives and score rationale;
- Inspect records the richest reviewed native run specification, source revision, package versions,
  model roles, scorers, metrics and per-sample evidence;
- AgentDojo records benchmark, task, attack, injection, pipeline, trace, utility and security results;
- Hawk adds authenticated access, cloud isolation, S3 checksums, conditional updates and warehouse
  ingestion around Inspect logs; and
- Every Eval Ever (EEE) supplies a broad cross-source schema, validation, provenance accounting and
  converters.

Hashes, object-store ETags, presigned URLs and access control solve different problems from a signed
evaluation statement. An untrusted operator can usually recompute an unkeyed hash after changing an
artifact. A valid signature establishes who controlled a signing key, not that the signer routed
every evaluation, used the asserted compute or disclosed every record. Those properties require
separate evidence.

## Inspection receipt

| System | Pinned revision | Native/version signal | Inspected evidence paths | Version-bounded result |
|---|---|---|---|---|
| garak | `8ed1543b985a5722adb659584182faf6f7907d4e` (2026-08-25) | `0.16.1.pre1`; latest stable tag observed as v0.16.0 | command/report writers, attempt serialization, detector hit log, reporting documentation | Rich JSONL and attempt hashes; no native DSSE, in-toto, Sigstore, Ed25519 or equivalent report signature found |
| PyRIT | `0899b2144056a41aea22996ed086c8617262e8ea` (2026-08-29) | `1.1.0.dev0`; stable v1.0.x tags present | component identity, memory models, prompt/score records, scenario results and CLI paths | Deterministic component/content hashes and rich identities; no key-authenticated evaluation artifact found |
| Inspect AI | `6b4008552562ab04822e35cbec9eed002b7c1645` (2026-08-30) | setuptools-scm revision; tags through 0.3.260 observed | `EvalSpec`, revision/package/scorer/sample models, `.eval` write/update paths and log docs | Strongest native provenance; logs can be rewritten with edit provenance and conditional ETags; no native evaluation-artifact signature found |
| AgentDojo | `089ed468cf3ed0322acc66b0211f26d9d90dbf60` (2026-06-02) | package version 0.1.35 | trace logger, task results, benchmark command and result contribution flow | Detailed mutable JSON traces; no native content digest or keyed signature found |
| METR/Hawk | `4e36a1455b0be78ff6720ff30129f423aa755ef0` (2026-08-28) | package version 2.5.0 | runner, S3/warehouse import, checksum/URL paths, log identity rewrite and sample editor | Operational storage and access controls around Inspect; no signed semantic evaluation claim found |
| Every Eval Ever | `687b7a36902c01db8a80f0b719d8861d6494f550` (2026-08-28) | package 0.2.3rc1; schema 0.3.0 | paper, schemas, validators, raw capture, duplicate detection and converters | Broad semantic standardization and SHA-256 integrity/deduplication; no native signer-authenticated evaluation profile found |

The two revisions dated after the nominal 2026-08-28 discovery cutoff are current continuously
updated repositories/documentation inspected to avoid reporting already-stale behavior. Every claim
retains its commit identifier. No inference is made about earlier or later versions.

## Capability comparison

Legend: **Strong** = first-class native evidence; **Partial** = recorded indirectly or incompletely;
**No** = not found in the inspected native path; **External** = supplied by infrastructure rather
than the semantic evaluation artifact.

| Property | garak | PyRIT | Inspect AI | AgentDojo | Hawk | EEE |
|---|---|---|---|---|---|---|
| Native artifact | JSONL report + hit log + HTML summary | Memory database and scenario/result views | `.eval` or JSON `EvalLog` | Per-run JSON trace + aggregated results | Inspect logs in S3 + database projection | Aggregate JSON + optional instance JSONL |
| Harness/source identity | **Strong** version/run/plugin setup | **Strong** module/class/version identities | **Strong** task source, revision and packages | **Strong** package and benchmark version | **Strong** runner image/config can be pinned | **Strong** evaluation library and source metadata |
| Invocation/config | **Strong** generator/probe/detector config | **Strong** behavioral component parameters | **Strong** task args, generate config, roles and sandbox | **Partial** encoded by pipeline/attack/suite fields | **Strong** run config plus Inspect | **Strong when source supplies it** |
| Evaluator/scorer identity | **Strong** probe/detector names and results | **Strong** scorer identifiers/config identities | **Strong** scorer specs, options, metrics and metadata | **Partial** utility/security evaluators by benchmark code/version | Inherited from Inspect | **Strong semantic fields; source-dependent** |
| Grader/judge identity | **Partial** detector configuration | **Strong/partial** scorer and child-component identity | **Strong** model roles/scorer specs | **Partial** pipeline and benchmark evaluator | Inherited from Inspect | **Strong schema support; source-dependent** |
| Target model/agent binding | **Partial** generator string/config, not model digest | **Strong asserted identity plus prompt-target records** | **Strong asserted model/config/base URL; artifact digest not universal** | **Partial** pipeline name/model string | Inspect plus deployment config | **Strong semantic identity/access-mode fields; measurement absent** |
| Dataset/corpus | **Partial** probe parameters/prompts | **Partial/strong** prompt and objective records | **Strong** dataset name/location/sample IDs/shuffle | **Strong** suite/task/injection identities | Inherited from Inspect | **Strong schema source and dataset fields; source-dependent** |
| Per-case evidence | **Strong** attempt prompt/output/detector values | **Strong** prompts, conversions and score records | **Strong** input/output/target/events/scores | **Strong** messages, tasks, injection and outcomes | Inherited from Inspect | **Optional strong** instance sidecar |
| Native content digest | **Partial** SHA-256 over attached attempt data | **Strong** deterministic component and prompt hashes | **Partial** revisions and storage ETags; no universal claim digest | **No** | **External** checksums/file hashes/ETags | **Strong** SHA-256 raw capture, sidecars and duplicate fingerprints |
| Keyed artifact signature | **No** | **No** | **No** | **No** | **No semantic signature** | **No** |
| Hardware/runtime attestation | **No** | **No** | **No native profile** | **No** | **No native semantic binding** | **No** |
| Trusted timestamp/transparency | **No** | **No** | **No native profile** | **No** | **External storage/event history only** | **No cryptographic transparency profile** |
| Post-run mutability | Plain files can change | Database/content can change | Explicit read/write, metadata/tag edits, invalidation and rewrites | Trace logger overwrites on update | Header import and sample editing paths rewrite logs with ETag control | PR/database correction and replacement workflows; hashes detect changed bytes |
| Completeness evidence | **No** | **No** | **No** | **No** | **Partial operational inventory**, not independent semantic completeness | **No**; only submitted records are visible |
| Lossless cross-harness normalization | **No native common schema** | **No native common schema** | EEE converter exists | No reviewed EEE converter | Uses Inspect | **Design purpose; loss depends on source fields and adapter** |

## Native evidence that must survive each adapter

### garak

A conforming adapter must preserve the run ID; garak and plugin versions; generator, probe and
detector names/configuration; plugin-cache snapshot; attempt ID/status/goal; complete conversation;
prompt and output; triggers; detector values; evaluation aggregate; confidence information; content
hashes; and failed/unevaluated states. A headline attack-success rate is irreversibly lossy.

The generator string must remain labeled as an asserted implementation/configuration identifier. It
must not be promoted to a model-artifact digest or measured workload identity.

### PyRIT

Preserve the PyRIT and evaluation-component hashes; the exact class/module and behavioral parameters
used to derive them; parent/child component identity; target and converter identities; original and
converted prompt hashes; objective; score value/status/category/rationale/metadata; scorer identity;
timestamps; and database/run lineage. Warrantor must record that these hashes are deterministic
identifiers, not signatures.

### Inspect AI

Inspect should be the first reference adapter because its `EvalSpec` and samples already cover most
Warrantor fields. Preserve eval/run/task IDs; task version/source/registry/arguments; source revision
and dirty state; resolved package/direct-URL revisions; dataset identity/location/sample selection;
sandbox; model, roles, base URL and generation arguments; scorers, options, metrics and metadata;
plan; results; token statistics; errors; samples/events; reductions; tags; metadata; and every
post-run update. Do not flatten edit provenance into the final header value only.

An S3 ETag is a conditional-write token, not an evaluator signature. A log that has been edited can
still be usable evidence if the complete update chain is retained and the final Warrantor envelope
authenticates the precise bytes and semantic predicate.

### AgentDojo

Preserve suite, pipeline, benchmark and package versions; user and injection task IDs; attack and
injection mapping; messages; error; timestamp and duration; utility and security outcomes; model and
defense/attack settings embodied by the pipeline; and trace/result relationship. Because native
updates overwrite a JSON path, ingest should retain the original bytes and create append-only
Warrantor versions rather than overwrite the prior receipt.

### Hawk

Preserve the entire Inspect log plus runner image digest, evaluation-set config, dependency install
resolution, Kubernetes workload/pod identity, sandbox/network-policy configuration, middleman/model
route, storage object version/checksum/ETag, importer identity/version, warehouse projection and every
editor operation. Label S3 authentication, presigned URL, checksum and ETag evidence as storage or
transport controls. Do not display them as proof that the evaluation claim is true.

### Every Eval Ever

EEE is the normalization target rather than another execution harness. Preserve source type,
organization and evaluator relationship; retrieval time; library/version; model identity and access
mode; generation and judge configuration; benchmark/dataset source; metric semantics and bounds;
uncertainty; detailed-result checksum/path/count; and instance-level raw/formatted inputs, references,
outputs, reasoning, message/tool-call sequences, attribution, score, tokens and performance where
available.

Warrantor must add a conversion report containing every native source field, its EEE/Warrantor
destination, transformation, information-loss classification and digest. Unknown semantic fields
fail closed. A field can be discarded only when a reviewed rule classifies it as non-semantic and
records the original source bytes by digest.

## Six layers that must not be collapsed

| Layer | Question answered | Example | Still not proved |
|---|---|---|---|
| Semantic record | What does this field mean? | EEE schema, Inspect `EvalSpec` | Authenticity, execution, completeness |
| Reproducibility provenance | What code/config/data was reported? | Inspect revision/packages; PyRIT component identities | That the report is truthful or immutable |
| Content integrity | Did these bytes change relative to a digest? | SHA-256, ETag | Who created them or whether the original was complete |
| Authenticated assertion | Which credential/key asserted this predicate? | DSSE/in-toto signature | Correct compute, truthful signer or complete routing |
| Measured/corroborated execution | Did an independent system or measured environment observe the event? | Receiver signature, TEE/RATS evidence | Evaluation validity or unobserved events |
| Reconciled completeness | Are omissions/extras detectable within a declared population and window? | Signed evaluator set reconciled with provider/receiver inventory | Colluding inventories or an incorrectly scoped population |

## Strong decisions

| Decision | Classification | Rationale and action |
|---|---|---|
| General cross-harness schema | **Consume** | Adopt EEE 0.3 semantics or a provably lossless mapping. Do not create an incompatible general result vocabulary. |
| First adapter | **Adopt: Inspect** | It provides the richest native log and an EEE converter already exists, minimizing avoidable semantic invention. |
| Red-team adapters | **Build thin adapters** | Add garak and PyRIT next; preserve native hashes and identities but wrap the final predicate with authenticated provenance. |
| Agent-security adapter | **Build thin adapter** | AgentDojo supplies task/attack/trace semantics that are directly relevant to W3/W5 evaluation and should remain append-only after ingest. |
| Cloud operations | **Integrate/compare Hawk** | Use Hawk as the strongest reviewed operational Inspect comparator; bind runner and importer evidence rather than mistaking S3 controls for semantic attestation. |
| Warrantor value layer | **Build and prove** | Own DSSE/in-toto envelope, authority chain, signer/evaluator/grader credentials, optional TEE/receiver corroboration, key history, conversion proof and completeness reconciliation. |
| New proprietary semantic schema | **Reject** | It duplicates EEE, raises adopter switching cost and weakens academic and standards credibility. |
| “Nobody signs evals” marketing | **Reject** | Directly contradicted by reviewed academic designs and too broad to survive feature/version-aware scrutiny. |

## Acceptance gates before freezing Warrantor's evaluation predicate

1. Produce real native logs from pinned garak, PyRIT, Inspect and AgentDojo runs; store their original
   bytes and licenses.
2. Convert each to EEE and Warrantor; emit a machine-readable native-field coverage report.
3. Round-trip every representable field and measure classified loss. Any unknown semantic loss fails.
4. Sign the exact semantic predicate with DSSE/in-toto and verify it in two independent languages.
5. Substitute target, grader, rubric, dataset, per-case result, environment and conversion report;
   every mutation must fail or create a clearly distinct receipt.
6. Edit Inspect metadata/tags, invalidate a sample, overwrite an AgentDojo trace and re-import a Hawk
   log; the evidence graph must retain lineage rather than silently replace history.
7. Reconcile a signed receipt set with at least one independently produced provider, gateway,
   receiver or billing inventory and report omission/extra detection bounds.
8. Publish latency, receipt size, storage amplification, verification cost, batch/crash recovery, key
   rotation and unavailable-log/attestation behavior for each assurance profile.
9. Repeat the inspection at every dependency upgrade. The native-signing finding expires when a
   pinned revision changes.

## Defensible repository wording

Use:

> At the inspected commits, garak, PyRIT, Inspect AI, AgentDojo and Hawk preserve valuable native
> evaluation provenance but do not expose a built-in, key-authenticated complete evaluation artifact.
> Every Eval Ever provides a strong normalization baseline. Warrantor is testing an EEE-compatible
> assurance profile that additionally binds prior authority, authenticated evaluator/grader identity,
> optional measured execution and receipt-set reconciliation.

Do not use:

> Nobody signs evaluations; existing frameworks do not preserve evaluator or grader identity; or
> Warrantor is the first independently verifiable evaluation format.

