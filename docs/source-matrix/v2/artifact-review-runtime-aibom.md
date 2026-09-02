# Runtime AIBOM: evidence review, prior-art adjudication, and Warrantor decision record

**Research status:** promoted evidence wave; architecture decision ready; implementation remediation required  
**Evidence cutoff:** 2026-08-28 for the main collection; indispensable older foundations are separated  
**Last verified:** 2026-09-01  
**Primary scope:** W2 evidence-before-commit envelope and S4 `warrantor-aibom`; supporting scope W1, W3, W4, W5, and W6  
**Audience paths:** executives, product leaders, security architects, implementers, researchers, governance teams, and content teams  

---

## 1. Executive verdict

### 1.1 The decision

**Modify and rebuild S4; reject the current novelty and compliance language.**

Warrantor should not market `warrantor-aibom` as the first system to bind an AI bill of materials, a model, or a runtime measurement to an action. The broad repository statement—“AIBOMs everywhere are build-time and static. Nobody binds them to the runtime-attested weight digest”—is contradicted at several levels:

1. `k8s-aibom` is an open runtime Kubernetes controller that observes deployed AI workloads and emits runtime ML-BOMs. It does not prove exact model weights or bind an inference, but it disproves “all AIBOMs are build-time and static.”
2. KServe V2 inference responses associate a response and request ID with a model name and optional version. OpenTelemetry GenAI conventions similarly associate response telemetry with the model reported as actually used. Neither is cryptographic, but both disprove the absence of action-to-model association.
3. OpenSSF Model Signing and Sigstore Model Transparency calculate and sign model-file digests and verify substitution. They do not prove loading or execution, but they provide the missing artifact-integrity substrate.
4. A patent family with a 2020-10-29 priority date describes attestation statements that bind ML execution results to the model, device setup, and provenance and may cover an inference or a window/hash chain of inferences.
5. A separate 2025-03-21 priority filing describes hardware-assisted runtime model attestation and a signed processing tag intended to let a downstream consumer determine that the correct model version and hardware produced an inference result.

The narrow, defensible opportunity is different:

> Build an open, standards-composed, independently conformable profile that links a current AI/ML-BOM to a cryptographically verified model artifact, a measured loaded-model instance and configuration, and a specific evidence-before-commit action receipt—while representing evidence strength and opaque-provider limits honestly.

That is a valuable product and research program. It is **not yet a defensible first-ever invention claim**, and patent counsel should review the disclosed prior art before any patent, exclusivity, or freedom-to-operate assertion.

### 1.2 Current implementation verdict

The current `python/model_sbom` package is a useful prototype-shaped static metadata emitter, not the runtime-bound AIBOM described by the current Warrantor architecture.

| Repository assertion | Reproduced result | Verdict |
|---|---|---|
| CycloneDX 1.5 AIBOM output | Can pass the official 1.5 JSON Schema only when the caller supplies a syntactically valid SHA-256 value | Narrowly true, but stale and weak |
| Native CycloneDX ML-BOM | Model is encoded as `library`; AI data are custom properties despite native ML-BOM/model-card support in CycloneDX 1.5 | False |
| SPDX 3.0 output | Fails the official SPDX 3.0.1 JSON Schema; lacks JSON-LD `@context` and uses SPDX 2.x document/package structure | False |
| Model integrity | Accepts an arbitrary caller-provided digest; does not read or hash a model artifact | False |
| Runtime binding | Has no runtime observer, loader measurement, attestation, inference hook, request/action binding, or receipt verifier | False |
| Test evidence | Eight unit tests pass; they assert the package's own chosen fields and do not load either official schema | Insufficient |
| EU AI Act Article 55 compliance | An SBOM is at most one supporting input; Article 55 applies to systemic-risk GPAI obligations and requires risk assessment/mitigation, incident reporting, and cybersecurity protections | Materially false/overbroad |

### 1.3 Recommended action classification

| Decision | Action | Why |
|---|---|---|
| Keep S4 as a Warrantor capability | **Modify** | The enterprise need is real, but scope and implementation must change |
| Current Python generator as production implementation | **Reject** | It is neither current-format conformant nor runtime-bound |
| CycloneDX 1.7 / ECMA-424 as default exchange form | **Adopt** | Current, formal, machine-readable ML-BOM and evidence vocabulary |
| SPDX 3.0.1 AI Profile | **Adopt as supported projection** | Strong semantic AI/dataset/provenance model; higher implementation complexity |
| G7 SBOM for AI minimum elements | **Adopt as field-coverage baseline** | Highest-authority current minimum-elements consensus found |
| OpenSSF Model Signing / Sigstore | **Consume** | Strong open artifact hashing, signing, verification, DSSE/in-toto composition |
| Kubernetes runtime discovery | **Consume/extend** | `k8s-aibom` already covers workload discovery and evidence locators |
| KServe and OpenTelemetry identifiers | **Adopt as correlation inputs** | Useful request/model correlation, explicitly not trust proof |
| RATS/EAT/TEE evidence | **Consume through an adapter** | Required for measured runtime evidence where the deployment can support it |
| “Nobody does this” / “first ever” language | **Reject** | Contradicted by tools, protocols, papers, and patent prior art |
| “Article 55 compliance with this SBOM” language | **Reject** | Compliance depends on legal role, model classification, controls, and evidence beyond a BOM |

---

## 2. Research questions and adjudicated answers

### RQ1. Is the existing AIBOM landscape only build-time and static?

**No.** Static and build/post-build generation remains common, including OWASP AIBOM Generator, Cisco AI BOM, SafeDep xBOM, AIBoMGen, and many research prototypes. However, `k8s-aibom` observes Kubernetes workloads at runtime and regenerates BOMs as workload state changes. Peer-reviewed work also explicitly proposes lifecycle and runtime AIBOM operation.

The important distinction is that **runtime observation is not runtime attestation**. A controller can observe a pod, image digest, environment variable, command-line model name, KServe storage URI, or Kubernetes annotation without proving the exact model weights resident in accelerator memory.

### RQ2. Does existing work bind an inference or output to a model?

**Yes, at multiple assurance levels.**

- KServe V2 carries `model_name`, optional `model_version`, and `id` in request/response objects.
- OpenTelemetry GenAI records a response identifier and reported response model.
- Model APIs commonly return a model identifier, version, deployment name, or system fingerprint.
- Patent literature describes attested or signed statements linking an execution result to a model and runtime/device state.

Most widely deployed protocols stop at a provider-asserted name/version. That leaves room for a stronger interoperable profile, but not for a broad nonexistence claim.

### RQ3. Do current standards natively support AI/ML BOMs?

**Yes.**

- CycloneDX 1.5 introduced native ML-BOM and model-card support in 2023.
- CycloneDX 1.7 is standardized as ECMA-424, second edition, December 2025.
- SPDX 3.0.1 contains a native AI Profile, `AIPackage`, datasets, provenance and integrity relationships.
- The G7 minimum-elements document supplies a cross-government field baseline spanning models, datasets, infrastructure, security, and performance.

Custom `model.*` properties are therefore a compatibility escape hatch, not an acceptable substitute for native current constructs.

### RQ4. Can an AIBOM prove which weights actually served an action?

**Not by itself.** A BOM is a claim-bearing inventory. The proof requires an evidence chain:

1. canonicalize and hash the model artifact;
2. verify signature, provenance, and policy before loading;
3. measure the model, adapters, tokenizer, serving engine, and effective configuration at the trusted load boundary;
4. bind the measurement to an instance/epoch and an attested execution environment;
5. correlate the inference request/result with that instance/epoch;
6. sign a receipt that binds the action/result to the AIBOM digest and runtime evidence;
7. let an independent verifier validate freshness, endorsement, reference values, receipt signature, and cross-object equality.

Without those steps, `runtime_aibom` is only a reference attached after the fact.

### RQ5. Is exact weight-level proof always possible?

**No.** Hosted or proprietary APIs may disclose only a model alias, deployment identifier, or version label. Quantized engines, tensor-parallel shards, dynamic adapters, prompt adapters, speculative decoders, routing/mixture-of-experts, and provider-side silent updates complicate “one weight digest.”

Warrantor must encode an evidence tier and never upgrade a provider assertion into a measured digest. A receipt for an opaque hosted API should say `provider_asserted_model`, not `measured_loaded_weights`.

### RQ6. Does an AIBOM demonstrate EU AI Act Article 55 compliance?

**No.** The EU Commission describes Article 55 as additional obligations for providers of general-purpose AI models with systemic risk: notification, systemic-risk assessment and mitigation, serious-incident reporting, and cybersecurity protection. The endorsed GPAI Code of Practice provides a broader voluntary compliance path. AIBOM data can support technical documentation, inventory, version control, risk analysis, incident investigation, and downstream information, but cannot establish the provider role, systemic-risk classification, adequacy of testing, incident process, or cybersecurity controls.

---

## 3. Evidence and assurance ladder

The word “runtime” is too imprecise for architecture or marketing. Warrantor should use this explicit ladder.

| Level | Name | What is known | Typical evidence | What remains unproved |
|---:|---|---|---|---|
| L0 | Declared | A human or deployment manifest names a model | Annotation, environment variable, CLI flag | Existence, integrity, loading, use |
| L1 | Discovered | A controller observes a workload or endpoint attribute | Kubernetes spec/status, KServe CR, image reference | Truth of model name; exact artifact |
| L2 | Content-addressed | Artifact bytes map to a canonical digest | File/tree hash, OCI manifest/index digest | Who supplied it; whether it loaded |
| L3 | Signed and policy-verified | Trusted signer endorsed exact artifact content | OMS/Sigstore/DSSE/in-toto bundle and verification result | Deployment and use |
| L4 | Verified-before-load | Loader checked content and policy before accepting it | Loader event, signature verification receipt, admission decision | Continued resident state; inference use |
| L5 | Measured-loaded | Trusted boundary measured effective loaded model state | Runtime measurement, model instance/epoch, adapter/config digest | Hardware isolation and request association |
| L6 | Attested execution | A verifier accepts evidence about the runtime and measurement | EAT/RATS evidence, TEE/TPM report, nonce, reference values | Per-action association unless included |
| L7 | Action-bound receipt | A signed receipt binds request/result/action to the accepted runtime evidence and AIBOM | W2 receipt, result/action digest, runtime state digest, AIBOM digest, attestation result | Correctness of the model output or policy itself |

**Product rule:** every receipt must carry `evidence_level`, `evidence_source`, and `limitations`. Missing evidence is a state, not an invitation to infer a stronger one.

---

## 4. Current repository implementation audit

### 4.1 Architectural promise

The current Warrantor architecture defines S4 as a Tier-A capability:

> “Runtime-bound AIBOM: binds the ML-BOM to the weight digest that actually served the action.”

W2 describes one signed envelope carrying the runtime AIBOM and optional attestation bundle. The WAR receipt specification states that `artifacts.runtime_aibom` binds the model digest that actually served the action.

This is an assurance claim, not merely a serialization feature. It must be implemented at the model load and inference boundaries.

### 4.2 What `python/model_sbom` actually does

The package:

- accepts a `ModelInfo` object;
- accepts an optional caller-provided digest string;
- formats CycloneDX-like or SPDX-like JSON;
- adds dependency names and versions;
- exposes a CLI;
- does not open, canonicalize, or hash the referenced model;
- does not query a model server or deployment;
- does not verify a signature or provenance statement;
- does not observe model loading;
- does not obtain an attestation;
- does not bind an inference request, response, external effect, or W2 receipt.

### 4.3 CycloneDX findings

The generated object declares CycloneDX 1.5. Its model component uses:

- `type: library` rather than `machine-learning-model`;
- parameter count as `version`;
- `model.architecture`, `model.parameters`, `model.training_data`, `model.base_model`, and `model.evaluations` as custom properties;
- an optional hash whose syntax and provenance are not checked.

This ignores the native ML-BOM `modelCard` structures already present in CycloneDX 1.5. A valid 64-character hexadecimal digest allowed the output to pass the official 1.5 JSON Schema. The repository test fixture uses `abc123`, which the official schema rejects as an invalid SHA-256 content value.

Schema validity would still not prove semantic truth, completeness, artifact identity, signature verification, runtime discovery, or action binding.

### 4.4 SPDX findings

The generated object labels itself `SPDX-3.0` but uses a structure resembling SPDX 2.x:

- `spdxVersion`;
- `SPDXID`;
- `documentNamespace`;
- `creationInfo.creators` string array;
- top-level `packages` and `relationships`;
- annotation comments as the primary AI extension mechanism.

Official SPDX 3.0.1 JSON-LD requires the global `@context`, element-collection structure, valid typed elements, and both structural and semantic validation. The current S4 output failed the official structural schema with three top-level validation failures. It is not an SPDX 3.0 AI Profile document.

### 4.5 Test findings

All eight repository unit tests passed with output capture disabled under the available Python 3.14 environment. Their scope is self-referential:

- expected format labels;
- expected custom properties and annotations;
- dependency-link strings;
- CLI behavior;
- optional-field behavior.

They do not:

- load an official CycloneDX or SPDX schema;
- exercise SPDX semantic validation;
- verify a real artifact hash;
- test tampering/substitution;
- exercise a model loader or inference service;
- validate a W2 receipt;
- test stale evidence, model hot-swap, adapter changes, batching, routing, failover, or opaque APIs.

### 4.6 Compliance finding

The package module claims that a GPAI provider can “demonstrate EU AI Act Article 55 compliance with the SBOM this package emits.” This is not supportable. The statement should be removed immediately and replaced with a bounded description:

> The output may contribute inventory and technical-documentation evidence. Compliance depends on the actor's legal role, the model's classification, applicable obligations, the accuracy and completeness of the data, and the implementation and assessment of required controls.

---

## 5. Reproduction ledger

### 5.1 Warrantor S4 tests

| Item | Result |
|---|---|
| Command | `uv run --project python/model_sbom --extra dev pytest -s -q python/model_sbom/tests/test_sbom.py` |
| Result | 8 passed |
| Bound | Proves internal expectations only |
| Environment note | Pytest capture under the available Python 3.14 environment raised a temporary-file `FileNotFoundError`; `-s` avoided that unrelated capture defect |

### 5.2 CycloneDX structural validation

| Input | Official schema | Result |
|---|---|---|
| S4 output with a genuine 64-hex SHA-256 value | CycloneDX 1.5 JSON Schema | Valid |
| S4 repository test fixture with `abc123` | CycloneDX 1.5 JSON Schema | Invalid at `components/0/hashes/0/content` |
| Semantic ML-BOM review | CycloneDX 1.5 model-card model | Uses a generic library plus custom properties instead of native ML constructs |

### 5.3 SPDX structural validation

| Input | Official schema | Result |
|---|---|---|
| S4 “SPDX-3.0” output | SPDX 3.0.1 JSON Schema | Invalid |
| Required global JSON-LD context | `https://spdx.org/rdf/3.0.1/spdx-context.jsonld` | Missing |
| Semantic OWL/SHACL validation | SPDX 3.0.1 model | Not reachable because structural validation fails |

### 5.4 `k8s-aibom` artifact inspection

| Item | Result |
|---|---|
| Pinned release/commit | v1.4.0, commit `24867bea795062e18ec4df5f5d7e2d85e41e46ef` |
| Release date | 2026-08-25 |
| Output | CycloneDX 1.6 ML-BOM |
| Golden vLLM BOM | Independently schema-valid against the repository's bundled 1.6 schema |
| Runtime evidence | Running container image digest from pod status; workload fields with declared/inferred/unresolved confidence and evidence locators |
| Model integrity | Model component had a name but no model-weight hash in the reviewed golden output |
| Blind spot | Runtime fetch of a model from an arbitrary URL can be invisible |
| Action binding | None |
| Test inventory | 212 Go test functions across 43 test files found in the inspected internal packages |
| Reproduction bound | Go toolchain and Kubernetes cluster were unavailable, so the suite and live controller were not executed |

### 5.5 OpenSSF/Sigstore model signing reproduction

| Item | Result |
|---|---|
| Implementation | `model-signing` 1.1.1 |
| Key path | EC prime256v1 private/public key |
| Signed object | A local model/test artifact |
| Bundle | 1,343 bytes; SHA-256 `f1ef0893ab213c6fb5ec339f56dea494b76791c64db687f657b8510de1e2c66d` |
| Bundle structure | Sigstore bundle → DSSE envelope → in-toto Statement → per-file SHA-256 subject |
| Positive verification | Succeeded |
| Substitution test | Replacing the signed file produced a digest mismatch and exit status 1 |
| Independent schema check | Official OMS validator and `oms_schemas` both returned OK |
| Tool defect observed | RSA-2048 key path failed because an RSA public key has no `curve`; EC P-256 succeeded |
| Assurance bound | Proves signed artifact integrity, not loading, execution, inference, or action binding |

---

## 6. Standards and field crosswalk

### 6.1 Field-family crosswalk

| Field family | G7 SBOM for AI minimum elements | CycloneDX 1.7 | SPDX 3.0.1 AI | Recommended Warrantor profile |
|---|---|---|---|---|
| BOM identity | Author, signature, tool/version, context, timestamp | Metadata, serial number, version, lifecycles, tools | SpdxDocument/ElementCollection, creationInfo, profiles | `bom_uri`, digest, format/version, profile, generator, created time |
| Model identity | Name, identifier, version, timestamp, producer, description | `machine-learning-model`, name/version, purl, hashes, external refs | `AIPackage`, name, packageVersion, suppliedBy, content identifiers | Canonical model-set ID plus artifact-set/tree digest; never parameter count as version |
| Model content integrity | Hash value and algorithm | Component hashes, evidence, signature references, formulation | ContentIdentifier, provenance/integrity relationships | Per-file/shard digests, canonical aggregate digest, signature-verification result |
| Architecture/configuration | Model properties, inputs/outputs | Model parameters, architecture, inputs/outputs, model card | typeOfModel, hyperparameters, application/training information | Architecture, tokenizer, quantization, adapter set, serving configuration digests |
| Data | Training data, dataset identity/hash/provenance/sensitivity | Datasets, model-card data and provenance | Dataset profile and relationships | Dataset references/digests with disclosure and sensitivity policy |
| Software/runtime | Infrastructure software | Components, services, dependencies, formulation, lifecycles | Software/Build/Core profiles and relationships | Serving engine image/binary digest, libraries, driver, compiler, runtime flags |
| Hardware | Infrastructure hardware | Hardware components, cryptographic assets, services | Elements/relationships plus extensions | Accelerator type, firmware/microcode, TEE/TPM identity where available |
| Security | Controls, compliance, vulnerability references | Vulnerabilities, declarations, attestations/evidence | Security profile, relationships, external references | Signature/policy decision, vulnerability snapshot, attestation appraisal, limitations |
| Performance | Performance and security KPIs | Model-card metrics and considerations | Metrics and thresholds | Eval receipt refs, performance envelope, safety/security metrics with dataset/config digests |
| Runtime observation | Generation context and lifecycle are acknowledged | Lifecycles/evidence can represent observed state | Provenance and relationships can represent state | Evidence source, confidence, observation time, deployment/workload identity |
| Loaded-state measurement | Not prescribed | Representable but not prescribed | Representable but not prescribed | Required for L5+; measurement method, measured values, instance epoch |
| Per-action binding | Not prescribed | Attestations/evidence can carry claims but no required inference profile | General relationship/provenance model; no required inference profile | Required at L7; request/result/action digest, instance epoch, accepted attestation, receipt signature |

### 6.2 Format policy

1. **Canonical internal model:** a Warrantor logical AIBOM profile independent of serialization.
2. **Default exchange:** CycloneDX 1.7 JSON / ECMA-424 second edition.
3. **Required projection:** SPDX 3.0.1 JSON-LD AI + Dataset + Software/Build/Security profiles where semantics are available.
4. **Loss accounting:** every projection emits a machine-readable loss report; never silently discard fields.
5. **Version policy:** validate against pinned schemas and semantic models; record exact schema digest and validator version.
6. **Signature policy:** sign the canonical byte representation or a digest-addressed attestation over it; do not sign a mutable URL alone.

---

## 7. Prior-art feature matrix

Legend: **Y** present; **P** partial or provider-asserted; **N** absent; **U** unresolved.

| Source/artifact | AI inventory | Runtime discovery | Artifact digest | Signature verification | Loaded-state measurement | Request/result association | Attested/signed action evidence | Open implementation |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| CycloneDX 1.7 / ECMA-424 | Y | P | Y | P | P | P | P | spec |
| SPDX 3.0.1 AI Profile | Y | P | Y | P | P | P | P | spec/tool ecosystem |
| G7 SBOM for AI minimum elements | Y | P | Y | P | N | N | N | guidance |
| OWASP AIBOM Generator | Y | N | P | N | N | N | N | Y |
| Cisco AI BOM | Y | N | P | N | N | N | N | Y |
| SafeDep xBOM | Y | N | P | N | N | N | N | Y |
| AIBoMGen | Y | N | Y | Y | N | N | N | Y |
| `k8s-aibom` v1.4.0 | Y | Y | container Y / model P | P/roadmap | N | N | N | Y |
| OpenSSF Model Signing / Model Transparency | model manifest | N | Y | Y | N | N | N | Y |
| KServe V2 inference protocol | metadata | service state | N | N | N | Y | N | Y |
| OpenTelemetry GenAI conventions | metadata | telemetry | N | N | N | Y | N | Y |
| RATS + EAT | P | Y | measurement-dependent | endorsement-dependent | P/Y by environment | extension/profile-dependent | Y if claims are bound | standards/tool ecosystem |
| WO2022093241A1 / US20230261857A1 | P | Y | P | P | Y by described attestation | Y | Y | patent disclosure |
| US20250337589A1 | P | Y | Y/P identifiers | Y/P | Y | Y | Y signed processing tag | patent disclosure |
| Current Warrantor S4 code | P | N | caller assertion | N | N | N | N | Y |
| Target Warrantor profile | Y | Y | Y | Y | Y or explicit weaker tier | Y | Y | must be Y |

### 7.1 Novelty adjudication

The compound idea “a signed/attested record proving which model produced an inference result” is prior art. The 2020-priority patent family is especially damaging to the broad claim because it explicitly describes:

- an attestation statement;
- an ML execution output/result;
- information about the model and device setup;
- data provenance/lineage;
- a nonce/public-key request flow;
- per-window or per-number-of-inferences attestations and a hash chain.

The 2025-priority patent is even closer to Warrantor's language:

- runtime attestation of AI models or runtimes;
- identifiers that may include model version, producer, hash, or neuron parameters;
- model registration after attestation;
- inference execution;
- a hardware-produced, optionally signed processing tag;
- downstream verification that the correct model version and hardware produced the result.

This evidence does not prove product deployment, patent validity, infringement, claim scope, or freedom to operate. It is sufficient to reject the repository's nonexistence statement and trigger professional patent analysis.

### 7.2 What may remain differentiable

Potentially differentiable implementation-level work, subject to a deeper patent and product search:

- a vendor-neutral open profile combining CycloneDX/SPDX, OMS/Sigstore, RATS/EAT, KServe/OpenTelemetry, and W2 receipts;
- explicit assurance tiers that prevent claimed metadata from masquerading as measured state;
- expected-set completeness for the effective model set: base, tokenizer, adapters, routing, safety models, speculative decoder, retrieval artifacts, serving engine, and configuration;
- evidence-before-commit enforcement where the external effect is withheld unless the runtime evidence and AIBOM binding validate;
- cross-language positive/negative conformance and independent producer/consumer implementations;
- a translation-loss ledger across CycloneDX and SPDX;
- opaque-provider honesty and downgrade policy;
- formal invariants covering hot-swap, batching, routing, failover, and stale-attestation races.

Use “open conformance profile” and “standards-composed assurance implementation,” not “first” or “nobody,” until this exact feature set is independently searched.

---

## 8. Recommended target architecture

### 8.1 Separate the four objects

Do not overload one “AIBOM” object with four trust functions.

| Object | Purpose | Mutability | Trust decision |
|---|---|---|---|
| Authoring AIBOM | Declared build/training/supply-chain inventory | Versioned | Is it complete and policy-conformant for release? |
| Deployment observation | What the orchestrator/controller can observe | Continuously updated | What appears deployed, and with what confidence? |
| Runtime-state attestation | What a trusted loader/runtime measured and accepted | Per load/epoch | What is actually loaded in this trusted instance? |
| Action receipt | Which accepted runtime state served a request and gated an action | Append-only | May this result/action be accepted or committed? |

### 8.2 Recommended components

1. **AIBOM normalizer**
   - consumes CycloneDX, SPDX, model cards, OCI metadata, training provenance, evaluation receipts, and manifests;
   - validates pinned schemas and semantic rules;
   - produces the canonical logical object and projections;
   - calculates canonical document digest and loss report.

2. **Artifact verifier**
   - calculates a canonical file/tree or OCI artifact-set digest;
   - verifies OMS/Sigstore signature and transparency evidence;
   - evaluates signer, provenance, vulnerability, license, and policy rules;
   - returns a signed verification result with tool/schema/trust-root versions.

3. **Deployment observer**
   - consumes Kubernetes/container/runtime metadata;
   - reuses or contributes to `k8s-aibom` rather than duplicating its controller;
   - retains per-attribute evidence source, locator, observation time, and confidence;
   - never labels a declared model ID as verified.

4. **Trusted model loader / runtime adapter**
   - verifies the artifact before load;
   - records the effective model set after quantization/compilation/adapters;
   - creates a unique `model_instance_id` and monotonic `load_epoch`;
   - derives `effective_model_state_digest` from ordered typed components and configuration;
   - obtains platform evidence or records an explicit non-attested tier.

5. **Inference correlation adapter**
   - binds `request_id`, response/result digest, model instance, load epoch, routing decision, and batch slot;
   - supports KServe V2 and OpenTelemetry correlation fields;
   - handles streaming, retry, speculative decoding, ensembles, routers, and fallback models.

6. **W2 receipt builder/verifier**
   - verifies the runtime evidence before permitting a commit where the deployment claims evidence-before-commit;
   - binds the action intent, authorization result, request/result digest, effective model-state digest, AIBOM digest, and accepted appraisal result;
   - signs the receipt and exposes an offline verifier.

### 8.3 Effective model-state digest

A single “weight digest” is insufficient for modern inference. Define a typed Merkle commitment over at least:

- base model artifact set;
- quantized/compiled engine artifact set;
- tokenizer and vocabulary;
- adapters/LoRA/prompt tuning;
- routing and mixture-of-experts configuration;
- safety/guard model set;
- speculative-decoding draft model;
- system prompt/template and tool schema where policy treats them as executable configuration;
- retrieval index snapshot or reference where it materially affects the action;
- inference engine image/binary;
- relevant runtime flags and precision;
- accelerator/firmware identity where attested.

Each leaf needs a type, canonicalization method, digest algorithm, digest, source, verification result, and absence semantics. Never concatenate ambiguous strings.

### 8.4 Receipt profile

Recommended logical fields:

```text
runtime_aibom:
  profile: warrantor.runtime-aibom/v1
  evidence_level: L0..L7
  bom:
    uri
    digest_algorithm
    digest
    format
    format_version
    schema_digest
    projection_loss_report_digest
  artifact_verification:
    model_artifact_set_digest
    signature_bundle_digest
    signer_identity
    trust_root_digest
    policy_digest
    decision
    verified_at
  runtime_state:
    model_instance_id
    load_epoch
    effective_model_state_digest
    runtime_image_digest
    configuration_digest
    observation_source
    measured_at
  attestation:
    evidence_ref
    evidence_digest
    nonce_or_freshness
    appraisal_policy_digest
    appraisal_result_digest
    verifier_identity
    appraised_at
  inference:
    request_id
    provider_response_id
    result_digest
    route_digest
    batch_member_id
    started_at
    completed_at
  limitations[]
```

The W2 outer receipt must separately bind `runtime_aibom` to the authorized action intent and external-effect result. A verifier must reject cross-field mismatch, stale epochs, unknown assurance levels, missing expected components, unsupported digest algorithms, untrusted appraisal policies, and ambiguous provider aliases.

---

## 9. Threat model and negative conformance corpus

### 9.1 Principal threats

| Threat | Failure | Required negative test |
|---|---|---|
| Caller-supplied fake digest | BOM asserts integrity without hashing bytes | Supply mismatched digest; generation or verification must fail |
| Model substitution after signing | Signed manifest does not match loaded files | Replace one shard; pre-load verification must fail |
| TOCTOU after verification | Verified file is replaced before/mid-load | Swap inode/object between verify and load; loader must use immutable/content-addressed handle |
| Hot-swap without epoch change | Receipt names stale model state | Reload model/adapter; instance or epoch must change before serving |
| Adapter omission | Base digest is correct but LoRA changes behavior | Load undeclared adapter; expected-set or state-digest check must fail |
| Quantization/compiler drift | Source weights match but compiled engine differs | Change quantization/build settings; effective state digest must differ |
| Router/fallback ambiguity | Different model actually serves request | Force fallback; receipt must identify actual route/model set |
| Batch confusion | Evidence for one request is attached to another | Reorder batch members; per-member correlation must remain correct |
| Streaming truncation/retry | Multiple responses share an ID ambiguously | Retry/partial stream; receipt must identify final accepted result |
| Stale attestation replay | Old good evidence covers current bad state | Replay old nonce/epoch; verifier must reject |
| Attester/verifier collusion | Self-asserted evidence is treated as independent | Use untrusted endorsement/appraisal root; verifier must reject |
| Opaque API alias drift | Provider silently changes weights behind same name | Downgrade to provider-asserted tier; never claim exact digest |
| BOM projection loss | SPDX/CycloneDX conversion drops security fields | Round trip; loss ledger must expose every unmapped field |
| Schema-version confusion | Old validator accepts obsolete shape | Pin schema digest/version; unknown versions fail closed |
| Missing expected component | BOM lists base model but omits tokenizer/guard | Expected-set manifest must fail completeness check |
| URL mutability | BOM references mutable hub branch or `latest` tag | Resolve to immutable commit/digest or mark unresolved |
| Receipt splicing | Valid AIBOM from one action is attached to another | Cross-object digest and request binding must fail |
| Evidence stripping | Lower-assurance path omits limitation metadata | Missing assurance/limitations must fail policy |

### 9.2 Formal invariants

Recommended machine-checked properties:

1. **No accepted action without an accepted runtime state** for deployments configured at L5–L7.
2. **One receipt, one inference correlation tuple:** `(request_id, result_digest, model_instance_id, load_epoch)` is immutable.
3. **Epoch freshness:** a receipt cannot refer to an epoch superseded before the recorded inference began.
4. **Expected-set completeness:** every required typed component contributes to the effective state digest.
5. **No assurance inflation:** derived evidence level is the minimum strength of every required link.
6. **Opaque-provider bound:** no evidence path lacking measured artifact identity may emit `measured_loaded_weights`.
7. **Projection accountability:** a projection is accepted only with zero critical unmapped fields or an explicit policy waiver.
8. **Appraisal binding:** accepted attestation evidence is tied to the verifier, appraisal policy, reference values, nonce/freshness, and receipt.
9. **Hot-swap separation:** any effective model-set change creates a new epoch before the next accepted request.
10. **Commit ordering:** where evidence-before-commit is claimed, receipt verification precedes irreversible external effect.

---

## 10. Highest-quality source canon

Scores apply the approved 100-point protocol. A source can be essential for one decision while explicitly bounded elsewhere.

### 10.1 Essential standards and government sources

| Score | Source | Why it is essential | Critical limitation |
|---:|---|---|---|
| 98 | [EU AI Act, Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng) | Primary law for documentation, logging, GPAI and systemic-risk obligations; adjudicates the Article 55 claim | Does not prescribe an AIBOM or certify this implementation |
| 97 | [ECMA-424, 2nd edition: CycloneDX 1.7](https://ecma-international.org/publications-and-standards/standards/ecma-424/) | Current formal BOM standard with ML models, evidence, attestations, formulation, dependencies, vulnerabilities and lifecycle context | General representational standard, not a runtime proof profile |
| 96 | [SPDX 3.0.1 AI Profile](https://spdx.github.io/spdx-spec/v3.0.1/model/AI/AI/) and [serialization rules](https://spdx.github.io/spdx-spec/v3.0.1/serializations/) | Normative AI/dataset/provenance model and exact conformance requirements; directly exposes S4's invalid output | Semantic and JSON-LD complexity; ecosystem maturity varies |
| 95 | [G7 SBOM for AI—Minimum Elements](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/KI/SBOM-for-AI_minimum-elements.pdf?__blob=publicationFile&v=2) | Cross-government minimum field set across metadata, model, data, infrastructure, security, and KPIs | Nonmandatory guidance, explicitly not an implementation or legislation |
| 94 | [RFC 9334: RATS Architecture](https://www.rfc-editor.org/rfc/rfc9334.html) | Durable architecture for attester, verifier, relying party, evidence, endorsements and appraisal | Does not define model-specific measurements or action binding |
| 94 | [RFC 9711: Entity Attestation Token](https://www.rfc-editor.org/rfc/rfc9711.html) | Standard token claims for attestation evidence/results and freshness composition | Trust depends on profile, endorsements, reference values and verifier policy |
| 94 | [in-toto Attestation Framework v1.2](https://github.com/in-toto/attestation/tree/v1.2.0/spec/v1) | Strong statement/resource-descriptor substrate already used by model signing | Attestation syntax does not make a claim true |
| 92 | [EU General-Purpose AI Code of Practice](https://digital-strategy.ec.europa.eu/en/policies/contents-code-gpai) | Commission-endorsed voluntary route for Articles 53 and 55; proves compliance scope is much broader than a BOM | Applicable obligations depend on role/model classification; not AIBOM-specific |

### 10.2 Essential and high-quality direct technical comparators

| Score | Source | Evidence contribution | Decision |
|---:|---|---|---|
| 92 | [`k8s-aibom` v1.4.0](https://github.com/GoogleCloudPlatform/k8s-aibom) | Runtime Kubernetes discovery, CycloneDX ML-BOM, confidence/evidence locators, immutable sink design, schema-valid golden output | Consume/extend; disproves static-only claim; does not prove weights/action |
| 92 | [OpenSSF Model Signing Specification](https://github.com/ossf/model-signing-spec) | Current schema and conformance foundation for model integrity/signing | Adopt for artifact verification |
| 91 | [Sigstore Model Transparency](https://github.com/sigstore/model-transparency) | Reproducible hashing, DSSE/in-toto/Sigstore bundle, substitution detection | Consume; fix/bound key-path defects; no runtime proof |
| 90 | [KServe V2 Inference Protocol](https://kserve.github.io/website/docs/concepts/architecture/data-plane/v2-protocol) | Widely relevant request/response correlation with model name/version and request ID | Adopt as protocol adapter; name/version are not trusted digests |
| 88 | [OpenTelemetry GenAI semantic conventions](https://github.com/open-telemetry/semantic-conventions-genai) | Response ID/model and cross-stack telemetry correlation | Adopt as observability projection; telemetry is not authenticated by default |
| 89 | [CycloneDX Authoritative Guide to AI/ML-BOM](https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-AI-ML-BOM-en.pdf) | Detailed implementation guidance for current ML-BOM concepts | Adopt as implementer guide, subordinate to ECMA-424 normative text |
| 86 | [OWASP AIBOM Generator](https://github.com/GenAI-Security-Project/aibom-generator) | Open CycloneDX 1.6 Hugging Face metadata generator with completeness score | Benchmark static authoring; do not call its hub metadata runtime evidence |
| 84 | [NIST SP 800-218A](https://csrc.nist.gov/pubs/sp/800/218/a/final) | Secure AI model lifecycle profile for producers, integrators and acquirers | Adopt as lifecycle/control baseline, not an AIBOM schema |

### 10.3 Decisive patent and disclosure prior art

| Score | Source | Priority/publication | Why it matters | Bound |
|---:|---|---|---|---|
| 89 | [WO2022093241A1 / US20230261857A1, “Generating statements”](https://patents.google.com/patent/WO2022093241A1/en) | Priority 2020-10-29; published 2022-05-05 | Describes attestation statements binding ML execution results to model/setup/provenance, nonce flows, and inference-window/hash-chain attestations | Patent disclosure; legal status/claim scope and implementations require counsel |
| 88 | [US20250337589A1, “Hardware assisted artificial intelligence model attestation”](https://patents.google.com/patent/US20250337589A1/en) | Priority 2025-03-21; published 2025-10-30 | Describes model/runtime attestation, identifiers including hash/version, inference, and an optionally signed processing tag for downstream validation | Pending patent; disclosure is prior art evidence, not proof of deployment or validity |
| 79 | [US20260135718A1, “Artificial intelligence supply chain integrity and provenance system”](https://patents.google.com/patent/US20260135718A1/en) | Filed 2026-01-08; published 2026-05-14 | Continuously verifies data/model/runtime/inference pathways and emits machine-verifiable certification artifacts | Broad disclosure, later priority, no reproduced artifact |
| 76 | [EP4625295A1, “Method for generating bill-of-material file”](https://patents.google.com/patent/EP4625295A1) | Published 2025 | AI BOM includes model/training/dependency/environment/authentication-code information and running-stage consistency language | Focuses BOM generation and consistency; action binding not established |

### 10.4 Peer-reviewed and preprint research

| Score | Source | Contribution | Limitation |
|---:|---|---|---|
| 86 | [Operationalising AIBOMs for Verifiable AI Provenance and Lifecycle Assurance](https://www.frontiersin.org/journals/computer-science/articles/10.3389/fcomp.2026.1735919/full) | Peer-reviewed design-science work, schema/toolkit, vulnerability and reproducibility claims, lifecycle framing | Author-reported figures require independent replication; runtime/action binding is not Warrantor-equivalent |
| 82 | [Implementing AI BOM with SPDX 3.0](https://arxiv.org/abs/2504.16743) | Written by core SPDX contributors; detailed AI/Dataset profile implementation guidance | Preprint/guide, subordinate to normative SPDX 3.0.1 |
| 81 | [AIBoMGen](https://arxiv.org/abs/2601.05703) and [research artifact](https://github.com/idlab-discover/AIBoMGen) | Signed training-time AIBOM generation with an accessible implementation | Primarily training/build-time; independent conformance and operational scale remain open |
| 77 | [AIGen](https://arxiv.org/abs/2607.26652) | Hybrid MLOps automation for SPDX 3.0 AIBOM generation | New preprint; limited independent reproduction and no per-action binding |
| 75 | [AIBOMs into Agentic AIBOMs](https://arxiv.org/abs/2603.10057) | Extends inventory framing toward agentic systems | Conceptual/new; requires feature-level and artifact verification |
| 73 | [AIRS: AI Risk Scanning and AIBOM work](https://arxiv.org/abs/2511.12668) | Connects inventory to AI risk scanning | Tool maturity, validation and action-level assurance are limited |

### 10.5 Additional open tools worth monitoring

| Band | Source | Value | Why not essential yet |
|---|---|---|---|
| High/support | [Cisco AI BOM](https://github.com/cisco-ai-defense/aibom) | Source/container/cloud discovery; CycloneDX and SPDX output | Vendor-authored; primarily static; full independent conformance pending |
| Supporting | [SafeDep xBOM](https://github.com/safedep/xbom) | Static code analysis for AI/SaaS/crypto dependencies | Discovery does not establish loaded model identity |
| Supporting | [`aibom-toolkit`](https://github.com/radanliev/aibom-toolkit) | Artifact associated with peer-reviewed operationalisation paper | Reproduction and claimed metrics need independent audit |
| Supporting | [OWASP AIBOM Initiative](https://genai.owasp.org/owasp-aibom/) | Community coordination and adoption context | Initiative/vendor/community claims require artifact-level corroboration |
| Supporting | [CoSAI AI supply-chain controls](https://www.coalitionforsecureai.org/the-ai-supply-chain-security-imperative-6-critical-controls-every-executive-must-implement-now/) | Practical executive synthesis: provenance, signing, runtime monitoring, AIBOM, infrastructure | Industry coalition guidance; not a normative schema or independent evaluation |

### 10.6 Regional implementation and governance sources

| Score | Source | Region | Product implication | Bound |
|---:|---|---|---|---|
| 87 | [India AI Governance Guidelines](https://psa.gov.in/CMS/web/sites/default/files/publication/India%20Al%20Governance%20Guidelines%205%C2%A0Nov%C2%A02025.pdf) | India | Auditability, monitoring, standards, compliance-by-design, public procurement and reporting support inventory/evidence demand | Not AIBOM-specific and not itself binding law |
| 84 | [Saudi National AI Risk Management Framework](https://sdaia.gov.sa/en/MediaCenter/KnowledgeCenter/Pages/SDAIAPublications.aspx) | Saudi Arabia | Risk identification, assessment, treatment, monitoring, reliability and compliance mapping create a deployment profile need | Official publication metadata verified; direct English artifact link and field crosswalk remain to be pinned |
| 81 | [UAE “Towards a Future of Responsible AI”](https://ai.gov.ae/wp-content/uploads/2025/01/Towards-a-Future-of-Responsible-AI-EN-White-Paper.pdf) | UAE | Supports governance, transparency, responsibility, traceability and ecosystem positioning | Informational white paper, not legal advice or AIBOM specification |
| 81 | [Qatar Principles and Guidelines for Ethical AI](https://www.mcit.gov.qa/wp-content/uploads/sites/4/2025/04/AI-Guidelines-_-En.pdf) | Qatar | Accountability, monitoring, robustness, auditability and secure adoption support evidence-oriented deployment | Principles/guidelines, not runtime inventory or attestation requirements |

Regional conclusion: no authoritative India, Saudi, UAE, or Qatar source reviewed in this wave mandates an action-bound AIBOM. They do create strong demand for traceability, monitoring, auditability, inventory, security, and procurement evidence. Warrantor should offer jurisdiction overlays without claiming legal compliance from a BOM.

---

## 11. Options with trade-offs

### Option A — Patch the existing static generator

**Scope:** update to CycloneDX 1.7 and SPDX 3.0.1, validate inputs, hash local files.

**Advantages:** fastest path to honest standards-conformant authoring; useful developer tool.

**Disadvantages:** does not meet the current runtime/action-bound architecture; high risk that marketing continues to overstate it.

**Recommendation:** do this only as phase 0 and rename it `aibom-author` or explicitly label output L0–L3.

### Option B — Build a Warrantor runtime-AIBOM stack from scratch

**Scope:** authoring, controller, signing, loader, attestation, inference adapters, receipt verifier.

**Advantages:** unified ownership and precise profile.

**Disadvantages:** duplicates mature work, increases cryptographic and Kubernetes attack surface, delays product proof, and makes independent interoperability harder.

**Recommendation:** reject.

### Option C — Standards-composed profile and thin integration layer

**Scope:** consume CycloneDX/SPDX, G7 fields, OMS/Sigstore, `k8s-aibom`, KServe/OpenTelemetry, RATS/EAT; own the canonical crosswalk, evidence-strength model, effective-state commitment, W2 binding, verifier, and conformance suite.

**Advantages:** strongest time-to-trust, interoperability, defensibility, academic value, and open-source ecosystem influence.

**Disadvantages:** upstream dependencies and version coordination; integration and canonicalization remain difficult.

**Recommendation:** **preferred**.

### Option D — Defer exact runtime proof and support provider assertions only

**Scope:** record provider model/version, response ID and static BOM.

**Advantages:** works with hosted APIs; low integration cost.

**Disadvantages:** cannot support the core “weights actually served” claim.

**Recommendation:** support as an explicit lower-assurance profile, never as the flagship proof.

---

## 12. Implementation roadmap and acceptance gates

### Phase 0 — Stop assurance inflation

- remove the Article 55 compliance statement;
- remove “first,” “nobody,” and “all AIBOMs are static” language;
- label current output experimental/static;
- reject nonconforming digests and mutable references;
- add official schema validation to CI;
- quarantine current SPDX output until rebuilt.

**Exit gate:** no generated object or documentation claims standards conformance, runtime binding, or regulatory compliance beyond reproduced evidence.

### Phase 1 — Current conformant authoring

- implement native CycloneDX 1.7 ML-BOM/model-card fields;
- implement real SPDX 3.0.1 AI/Dataset JSON-LD objects and relationships;
- define canonical logical fields and translation-loss report;
- hash local file sets and OCI artifacts;
- integrate OMS/Sigstore verification;
- use G7 minimum elements as completeness policy.

**Exit gate:** positive and negative validation passes official structural and semantic validators; independent round-trip tests show critical-field preservation.

### Phase 2 — Deployment observation

- adopt/contribute to `k8s-aibom` rather than forking silently;
- add Warrantor observation adapter and evidence-level mapping;
- support workload/container image digest, KServe and model-server metadata;
- retain declared/inferred/unresolved/verified distinction.

**Exit gate:** live cluster tests cover deploy/update/rollback/failure, unresolved model IDs, runtime download blind spots, and immutable archive behavior.

### Phase 3 — Verified loader and effective model state

- implement content-addressed immutable model ingestion;
- verify signature/provenance/policy before load;
- commit the base model, derived engine, adapters, tokenizer, guard models, and configuration;
- emit instance ID and monotonic epoch;
- integrate platform attestation where available.

**Exit gate:** substitution, TOCTOU, hot-swap, adapter omission, quantization drift, rollback, and stale-attestation tests fail closed.

### Phase 4 — Per-inference and per-action binding

- correlate KServe/provider request IDs and response IDs;
- bind result digest to instance/epoch and route/batch state;
- verify evidence before irreversible commit where configured;
- emit W2 receipt and offline verifier;
- add opaque-provider downgrade logic.

**Exit gate:** two independent implementations exchange receipts; all negative corpus vectors are rejected; effect ordering is independently demonstrated.

### Phase 5 — Assurance and publication

- formalize core invariants;
- commission independent security review;
- publish test vectors, schema digests, reproducibility bundle, threat model and benchmark;
- obtain patent/FTO review before renewed novelty language;
- publish jurisdiction-specific procurement and governance overlays.

**Exit gate:** architecture, implementation, security, legal, and claim ledgers agree on exactly what is proven.

---

## 13. Business, procurement, and commercialization implications

### 13.1 Enterprise value

The defensible customer outcome is not “an AI SBOM file.” It is:

- faster incident scoping when a model, adapter, dataset, library, container, or runtime is compromised;
- evidence that a released and approved model was the one used for a controlled action;
- procurement visibility across hosted, self-managed, and edge AI deployments;
- audit evidence whose strength and limitations are machine-readable;
- change detection across model, runtime and configuration epochs;
- reusable integration with existing SBOM, SIEM, governance, Kubernetes and attestation systems.

### 13.2 Buyer questions the product must answer

1. Which exact artifact or provider assertion is represented?
2. Who created each field, and what evidence supports it?
3. Was the artifact signature verified before load?
4. What changed between the approved and served state?
5. Which request and external action used that state?
6. Can an independent verifier reproduce the decision offline?
7. What is unknown because the provider is opaque?
8. Which jurisdictional or control mappings are evidence mappings rather than compliance guarantees?

### 13.3 Packaging recommendation

- **Community:** authoring, validation, format crosswalk, local artifact hashing, verifier, test vectors.
- **Enterprise:** cluster observers, policy integrations, evidence archive, opaque-provider adapters, fleet diffing, incident impact analysis, support and certified deployment profiles.
- **Assurance add-on:** TEE/TPM adapters, reference-value management, independent appraisals, compliance evidence packs.

Avoid charging for an invented format. Monetize operational integration, evidence quality, fleet-scale correlation, policy and assurance.

---

## 14. Academic research program

### 14.1 Research questions

1. What is the minimum trusted computing base needed to prove that an exact effective model state served an inference?
2. How should an effective state digest represent sharding, quantization, compilation, adapters, routing, speculative decoding, and retrieval state?
3. Can evidence strength be composed monotonically without assurance inflation?
4. What completeness guarantees are possible for opaque or remotely hosted models?
5. How frequently must runtime evidence be refreshed to balance cost and stale-state risk?
6. How can an action receipt prove correlation under dynamic batching and streaming without exposing sensitive inputs/outputs?
7. Which fields survive losslessly across CycloneDX 1.7 and SPDX 3.0.1 AI/Dataset profiles?
8. Can an independent verifier detect all state-relevant changes across heterogeneous inference servers?
9. How do runtime AIBOMs change incident-response mean time to scope and procurement assurance effort?
10. What patent-bounded novelty remains in an open standards-composition and conformance architecture?

### 14.2 Evaluation design

Build a benchmark with:

- three serving systems: vLLM, KServe/Triton-compatible, and one hosted API;
- base models, quantized derivatives, LoRA adapters, guard models, router/fallback, and speculative decoder;
- signed and unsigned artifacts;
- Kubernetes and non-Kubernetes deployments;
- TEE-attested and non-attested runtime profiles;
- 30+ attacks from the negative corpus;
- independent producer and verifier implementations in at least two languages.

Measure:

- detection precision/recall for state-relevant changes;
- false assurance rate by evidence level;
- receipt latency and throughput overhead;
- evidence size and verifier time;
- time to incident blast-radius determination;
- schema/profile conformance and projection loss;
- reproducibility across deployment environments.

### 14.3 Candidate venues

- USENIX Security, NDSS, IEEE S&P, ACM CCS for trusted runtime/evidence architecture;
- IEEE Secure Development Conference and ACSAC for implementation/conformance;
- ACM/IEEE ICSE, ASE, EASE, SANER for artifact generation, schema quality and supply-chain engineering;
- MLSys for serving/runtime measurement and overhead;
- FAccT or AIES for transparency, governance and assurance interpretation;
- software supply-chain and AI security workshops for early test-vector releases.

---

## 15. Content authority program

Recommended sequence:

1. **“An AI BOM is an inventory, not proof of execution.”**
2. **“Seven evidence levels from model name to action-bound receipt.”**
3. **“CycloneDX 1.7 versus SPDX 3.0.1 for AI systems.”**
4. **“Why a hash supplied by the caller is not integrity evidence.”**
5. **“The effective model is more than the weights.”**
6. **“What Kubernetes can observe—and what it cannot prove.”**
7. **“Model signing, runtime attestation, and receipts are different layers.”**
8. **“Do not claim EU AI Act compliance from an AIBOM.”**
9. **“Opaque model APIs need honest assurance downgrades.”**
10. **“Prior art killed our first-ever claim—and improved the product.”**

The tenth topic is unusually strong thought leadership if written candidly: it demonstrates evidence discipline, reduces credibility risk, and reframes differentiation around execution quality and openness.

---

## 16. Audience reading paths

### Executives and product leaders

1. Sections 1, 2, 11, and 13.
2. G7 minimum elements.
3. EU GPAI obligations and Code of Practice.
4. `k8s-aibom` compliance disclaimer and assurance limitations.

### Security and platform architects

1. Sections 3, 6, 7, 8, and 9.
2. ECMA-424 / CycloneDX 1.7.
3. SPDX 3.0.1 AI Profile and serialization rules.
4. RATS, EAT, in-toto, OMS/Sigstore.
5. KServe and OpenTelemetry correlation specifications.

### Engineers and implementers

1. Sections 4, 5, 8, 9, and 12.
2. CycloneDX AI/ML-BOM guide.
3. `k8s-aibom`, Model Transparency and OWASP AIBOM artifacts.
4. Official schemas and negative conformance corpus.

### Academic researchers

1. Sections 2, 7, 9, and 14.
2. Frontiers operationalisation paper.
3. SPDX implementation guide, AIBoMGen and AIGen.
4. Patent disclosures as prior-art boundaries.

### Risk, audit, policy, and compliance teams

1. Sections 1, 3, 6, 10.1, 10.6, and 13.
2. EU AI Act and GPAI Code.
3. G7 minimum elements.
4. NIST SP 800-218A and jurisdiction overlays.

### Marketing, partnerships, and content teams

1. Sections 1.1, 7.1–7.2, 13, and 15.
2. Never use “first,” “nobody,” “proves compliance,” or “the exact weights served” without the evidence level and deployment qualification.
3. Lead with interoperable evidence composition, honest assurance tiers, and incident/procurement outcomes.

---

## 17. Open gaps and next searches

### Critical

- professional patent landscape and freedom-to-operate review of model/runtime attestation, inference-result tags, and AI BOM consistency;
- independent live reproduction of `k8s-aibom` on Kubernetes;
- exact loader/serving integration patterns for vLLM, Triton, KServe ModelMesh, Ray Serve, and hosted providers;
- TEE-specific feasibility for measuring large sharded/compiled model states;
- canonical digest design for effective model sets;
- W2 receipt schema revision and verifier test vectors.

### High

- full direct-download and field-level review of Saudi Arabia's 2026 National AI Risk Management Framework;
- India, UAE and Qatar procurement/control mappings tied to exact primary provisions;
- current patent status and family/claim analysis in the United States, Europe, India, Saudi Arabia, UAE, and Qatar;
- independent conformance of Cisco AI BOM, AIBoMGen, AIGen and `aibom-toolkit` outputs;
- artifact-scale performance and failure analysis of OMS/Sigstore model signing on multi-hundred-gigabyte sharded models;
- OCI artifact/referrer and Hugging Face immutable-revision profiles.

### Medium

- AIBOM vulnerability advisory and VEX interoperability;
- privacy leakage from runtime inventory and attestation evidence;
- retention, revocation and deletion semantics for BOMs containing sensitive dataset/model metadata;
- commercial product feature and pricing verification;
- independent interviews with enterprise auditors, model-platform teams and regulators.

---

## 18. Claim-ledger outcomes

| Claim | Status | Confidence | Corrected position |
|---|---|---|---|
| AIBOMs everywhere are build-time/static; nobody binds runtime-attested weights to an action | **Contradicted** | High | Runtime AIBOMs, action/model correlation, signed model artifacts, and result/model attestation prior art exist; a complete widely adopted open composition was not found |
| Current S4 implements current conformant CycloneDX/SPDX runtime AIBOM | **Contradicted** | High | Static CycloneDX-like prototype; CycloneDX semantics are stale/custom; SPDX 3.0.1 output is invalid; no runtime/action binding |
| The emitted S4 SBOM demonstrates EU AI Act Article 55 compliance | **Contradicted** | High | It may support documentation/inventory; Article 55 compliance requires systemic-risk controls and evidence far beyond a BOM |

---

## 19. Strong recommendation

Keep the strategic objective, change the claim, and rebuild the mechanism.

Warrantor should own the **assurance composition and conformance boundary**:

- current AIBOM formats;
- exact artifact verification;
- deployment observation with evidence provenance;
- measured effective model state;
- attestation appraisal;
- inference/action correlation;
- evidence-before-commit receipt binding;
- independent verification and negative test vectors.

Consume the mature standards and open implementations underneath it. Treat hosted-provider model names as lower-tier assertions. Publish what cannot be proven. Use patent counsel before novelty claims. This path produces a more credible product, a better open-source contribution, a stronger academic program, and a more defensible enterprise story than the original “nobody does this” premise.
