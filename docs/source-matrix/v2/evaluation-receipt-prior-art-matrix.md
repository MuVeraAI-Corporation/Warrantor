# Evaluation-receipt prior-art and design-decision matrix

Status: normative substrate, artifact and named-harness waves complete  
Snapshot: 2026-08-30  
Repository target: [`specs/warrantor-v4/09-eval-receipt.md`](../../../specs/warrantor-v4/09-eval-receipt.md) as a profile of the Warrantor Action Receipt  
Claim under test: CLM-0013 — no existing system signs an AI evaluation, pins the evaluator or grader, and produces an independently verifiable artifact

## Executive conclusion

CLM-0013 is contradicted. Attestable Audits implements a TEE protocol that binds the measured model,
audit code, audit data and result and then links later inference to the audited model. The grant-
evaluation preprint independently specifies a signed, timestamped bundle binding original and
canonical input, complete evaluator input, measured model/rubric/runtime and output. Aqta implements
portable, cross-language signed decision records, although its gateway signature does not establish
which provider compute ran. Together these sources remove the basis for a broad absence claim.

The named-harness inspection also rejects the opposite overcorrection. At the pinned commits, garak,
PyRIT, Inspect AI, AgentDojo and Hawk preserve useful native provenance, evaluator/scorer identities,
per-case records, hashes or storage controls. No built-in key-authenticated complete evaluation
artifact was found, but that result is valid only for the inspected versions and native paths. It is
not proof about extensions, private deployments or future releases.

Every Eval Ever (EEE) is decisive semantic prior art. Its aggregate and instance schemas, validation
and converters make a Warrantor-only general cross-harness vocabulary unnecessary. EEE does not sign
records, run evaluations, attest compute or prove receipt-set completeness. The strong decision is to
consume EEE semantics and place them inside Warrantor's authenticated assurance profile.

The normative substrate review is also decisive. DSSE authenticates exact typed bytes but has no
identity, time, revocation or semantic policy. in-toto v1.2 supplies the Statement and predicate model,
but its JSONL Bundle is not authenticated as a complete set. SCITT/RFC 9943 proves accepted
registration and auditable history, yet explicitly permits false statements and selective issuer
submission. RATS/EAT separates Evidence, verifier appraisal and Attestation Results, but the EAT base
permits unsecured profiles and defines no implementation-strength floor. None of these standards
turns a signature, TEE token or log receipt into complete evaluation assurance by itself.

The current Warrantor design still has a defensible contribution, but it is a composition claim:

> A lossless EEE-compatible DSSE/in-toto evaluation profile that binds prior authority, authenticated
> evaluator and grader identity, native artifacts, validity qualifications and per-case results;
> supports optional receiver or TEE corroboration; and makes conversion loss, receipt-set completeness
> and cross-harness conformance independently testable.

That claim remains a target, not an established fact. The current eval-receipt document is a frozen
candidate specification without its own schema, independent implementation, conformance vectors or
production evidence.

## Evidence standing

| Source | Evidence class | What is demonstrated | What must not be inferred | Library standing |
|---|---|---|---|---|
| Warrantor eval receipt | Repository specification | Detailed DSSE/in-toto run-provenance fields and validity rules | No implementation, interoperability, adoption, non-bypassability or novelty proof | Internal design under review |
| Attestable Audits | ICML TAIG 2025 workshop paper | AWS Nitro prototype; model + audit code + audit data + result attestation; later prompt/response binding; three benchmark families and cost/performance evaluation | Benchmark validity, production readiness, vendor independence, completeness or public reproducibility | High-quality, 82/100 |
| Auditable grant evaluation | 2026 single-author preprint | Precise proposed packet: original/canonical/full-input/output hashes, measured model/rubric/runtime, hardware attestation, RFC 3161 time and log | A working system, measured performance, formal canonicalization security or legal sufficiency | Gap-only, 62/100 |
| Aqta ATTESTATION/ACTION | Vendor repository/specification | Stable signed records, Python/TypeScript verifiers, pinned-key verification, negative vectors, differential fuzzing and transparency components | Truthful issuer, named provider compute, evaluator/grader binding, execution, complete traffic or independent managed-service validation | Supporting, 77/100 |
| Every Eval Ever | 2026 preprint plus reproduced repository | Aggregate/instance schemas, source and evaluator relationship, model/framework/generation/judge/dataset/metric semantics, validation and converters | Producer authenticity, measured execution, complete routing, benchmark validity or population completeness | Essential, 91/100 |
| garak, PyRIT, Inspect AI, AgentDojo | Pinned native-code inspection | Substantial framework-specific run, evaluator/scorer, target, case and result evidence | A built-in complete keyed signature at the inspected commits; absence in every extension or future version | Version-bounded implementation evidence |
| METR/Hawk | Pinned cloud-platform inspection | Inspect execution, storage, access control, checksums, conditional updates and warehouse ingestion | That S3 authentication/checksums authenticate the semantic evaluation claim or that imported/edited logs are immutable | Version-bounded operational evidence |
| Sello / Notarized Agents | Preprint plus reference implementation | Receiver-signed confidential action receipts and witnessed-log direction | Receipt-set completeness, independent receiver adoption or production log behavior | Supporting prior-art input |
| AERF v0.2 | Reproduced public draft | Parent/PDP-signed receipt, policy/context hashes, optional log proof, schema, vectors and adversary corpus | Stable standard, principal authority, enforcement, complete mediation, correct upstream context or adoption | Supporting, 78/100 |
| DSSE v1.0.2 | Current open envelope specification | Exact typed-payload authentication, canonicalization avoidance and multi-signature threshold | Key/identity trust, time, revocation, predicate truth, compute or set completeness | Essential, 90/100 |
| in-toto Attestation v1.2 | Stable CNCF/in-toto specification plus reproduced bindings | Subject-bound Statement, typed predicate ecosystem and multi-language implementation | Whole-Bundle authentication, deletion/replay detection, producer truth, complete routing or enforcement | Essential, 94/100 |
| SCITT RFC 9943 + COSE Receipts RFC 9942 | 2026 IETF Proposed Standards | Registered-history inclusion, auditability and non-equivocation in a declared VDS | Statement accuracy, complete issuer submission, issuance order, execution or receipt-set completeness | Essential, 95/94 |
| RATS RFC 9334 + EAT RFC 9711 + CMW RFC 9999 | IETF architecture and current Proposed Standards | Evidence/appraisal/result roles, attestation claims/profiles and typed heterogeneous carriage | Minimum attester strength, automatically trusted execution, verifier correctness, protected collections or authorization | Essential, 93/95/93 |

“Independent verification” is not one property. A relying party may independently verify a
signature while still trusting the signer to have told the truth, routed every event, used the named
provider, and disclosed every receipt. The design must state which dependency is removed at each
profile.

## Semantic interoperability decision

EEE and Warrantor should occupy different layers:

| Layer | Recommended owner | Decision |
|---|---|---|
| Evaluation-result vocabulary | EEE | **Consume** schema 0.3 or maintain a provably lossless mapping |
| Native framework evidence | garak, PyRIT, Inspect, AgentDojo and other harnesses | **Preserve** original bytes and all semantically relevant native fields |
| Conversion proof | Warrantor adapters | **Build** machine-readable field coverage, transformation and classified-loss reports |
| Authenticated statement | DSSE/in-toto Warrantor profile | **Adopt and extend** signer/credential, exact verified bytes, predicate digest, key history and replay semantics |
| Authority and accountability | Warrantor WAR/AAE chain | **Build** verifier-recomputed effective authority and responsible principal binding |
| Measured or corroborated execution | Strict EAT profile carried as protected RATS CMW, receiver, gateway, trusted time or transparency evidence | **Compose** as separately typed claims; bind verifier policy/reference values and never imply more than the evidence observes |
| Receipt-set completeness | Warrantor reconciliation profile | **Build and measure** against independently produced provider/receiver/inventory sets |

The detailed pinned-version evidence and adapter requirements are recorded in
[`evaluation-harness-integrity-matrix.md`](evaluation-harness-integrity-matrix.md). The EEE schema and
test reproduction are recorded in
[`artifact-review-every-eval-ever.md`](artifact-review-every-eval-ever.md).
The envelope/attestation reproductions and cross-standard decision are recorded in
[`artifact-review-aerf-v0-2.md`](artifact-review-aerf-v0-2.md),
[`artifact-review-in-toto-attestation-v1-2.md`](artifact-review-in-toto-attestation-v1-2.md) and
[`attestation-substrate-decision-matrix.md`](attestation-substrate-decision-matrix.md).

## Field-level comparison

Legend: **Direct** = first-class and implemented or normatively specified; **Partial** = adjacent or
signer-asserted only; **Design** = proposed but not implemented; **No** = absent from reviewed scope.

| Evidence requirement | Warrantor candidate | Attestable Audits | Grant design | Aqta | Decision for Warrantor |
|---|---|---|---|---|---|
| Prior warrant / accountable principal | **Direct design** through WAR actor and authority chain | **No** | **No**; agency policy manifest only | **Partial** organization/session; no verified principal authority | Keep as differentiator; verifier must recompute authority and identify who authorized the run |
| Receipt issuer and trusted key | **Direct design** through DSSE signer | **Direct** TEE/vendor attestation root | **Design** CPU root + ephemeral TEE key | **Direct** pinned Ed25519 issuer key | Separate issuer identity, evaluator identity and hardware root; one signature must not imply all three |
| Evaluator/harness identity | **Direct design** name, version, source and invocation digests | **Direct** audit code digest | **Design** runtime, prompt and rubric measurement | **No**; applied policy IDs are not evaluator identity | Require content digest, source, version, resolved plugins and invocation |
| Grader / rubric / judge | **Direct design** judge model in provenance; rubric field should be explicit | **Partial** inside audit-code/data commitment | **Design direct** rubric + prompt in reference measurement | **No** | Add explicit grader type, code/model digest, rubric digest, calibration and decision rule |
| Target model / agent | **Direct design** model/endpoint/agent digests | **Direct measured** model hash; prototype uses quantized model | **Design measured** model hash | **Partial asserted** model string | Distinguish claimed identifier, artifact digest, runtime measurement and quantization/adapter state |
| Evaluation data / corpus | **Direct design** plugin/case/result digests | **Direct measured** audit dataset | **Partial design** original/canonical submission | **No** | Bind corpus manifest, split/holdout status, labels, transformations and access-confidentiality policy |
| Raw and canonical input | **Partial** resolved config and results; no explicit Horig/Hcan split | **Partial** audit dataset hash | **Design direct** Horig, Hcan and complete-input HI | **Partial** request or args hash only | Add distinct raw-artifact, canonical-representation and final evaluator-input commitments |
| Prompt, preprocessing and context policy | **Partial direct** config digest; judge/attacker provenance | **Partial** audit code/data digest | **Design direct** prompt/rubric/runtime measurement and canonicalization | **No** | Make each independently addressable; a single config digest is insufficient for review and migration |
| Seeds / stochasticity / repetition | **Direct design** | **Partial** sampling parameters reported in paper | **No** | **No** | Retain deterministic/stochastic classification and require distribution evidence before rate claims |
| Environment / accelerator / drivers | **Direct design** | **Direct measured base** plus reported deployment | **Design measured** runtime | **No** | Bind container, runtime, driver, accelerator and attestation evidence without equating a digest with measurement |
| Per-case results | **Direct design** stable IDs + result digests | **No in attestation**; aggregate result R, underlying benchmark execution exists | **Design** output O for one submission | **No** | Require per-case addressability or a Merkle commitment; never accept only a headline score |
| Summary and validity qualifications | **Direct design** outcomes, noise floor, elicitation and awareness | **Partial** benchmark metrics; no Warrantor validity block | **Partial** uncertainty and reviewer cues | **No** | Retain validity block; add explicit known limitations and intended-use decision boundary |
| Output/result integrity | **Direct design** DSSE plus per-case digests | **Direct measured** audit result and prompt/response | **Design direct** HO and signed O | **Partial** gateway decision, not evaluator output | Support both full output and privacy-preserving commitment with disclosure policy |
| Human decision / override | **No explicit eval artifact**; can link WAR actions | **No** | **Design direct** human final decision separate | **Draft** ACCEPT-v1 records acceptance but not verified reviewer identity | Define a linked acceptance artifact with verified identity/authority options; do not fold it into evaluator correctness |
| Trusted time and replay resistance | **Direct design** nonce, issued/expiry and tiered anchor | **Partial** attestation/log; production replay lifecycle incomplete | **Design direct** nonce/timestamp + RFC 3161 | **Partial** signer clock; IDs; external anchoring developing | Require nonce, validity, key-history lookup, external time for high assurance and replay/deduplication semantics |
| Workload / compute measurement | **Optional design** platform verdict | **Direct** Nitro remote attestation | **Design direct** TEE measurement | **No** | Make TEE/RATS evidence an optional profile with appraisal policy and multi-vendor adapters |
| Confidential model/data support | **Not defined in eval profile** | **Direct prototype** encrypted upload and TEE data-in-use protection | **Design direct** | **No** | Define detached encrypted subjects/commitments so portability does not require public model or corpus contents |
| Receiver or external witness | **Partial** transparency anchor | **Direct vendor-root attestation; public-log design** | **Design** external verifier and timestamp/log | **No independent signer**; gateway self-signs | Support receiver, independent evaluator, trusted-time, TEE and transparency evidence as distinct corroborators |
| Receipt-set completeness | **No complete model** | **No**; log publication helps only if routing/publication is complete | **Partial design** Merkle log detects later deletion of logged entries, not never-logged events | **Explicitly open** | Add completeness statement plus reconciliation against an independently produced provider, receiver or billing record |
| Cross-harness portability | **Design goal** adapters for five harnesses | **No standard profile** | **Future-work direction** | **Portable envelope, wrong semantics** | Use one predicate with lossless adapters and fail closed when native fields cannot be represented |
| Cross-language conformance | **Planned** | **No public artifact located** | **No artifact** | **Implemented and reproduced** | Treat differential canonicalization and profile-confusion tests as release gates |
| Empirical implementation evidence | **No runnable eval profile** | **Prototype and experiment; no public code located** | **None** | **Open verifiers reproduced; managed gateway closed** | Implement at least two independent producers and verifiers; publish vectors and failure-path results before novelty claims |

## Assurance profiles

These are assurance profiles over one semantic predicate, not competing wire formats.

| Profile | Required evidence | What it can support | Residual trust |
|---|---|---|---|
| **Portable provenance** | DSSE/in-toto receipt; trusted evaluator signing identity; full run, target, grader, data, configuration, result and validity commitments | “This evaluator signed these exact typed bytes.” | Evaluator truthfulness, routing, environment and completeness |
| **Corroborated** | Portable provenance plus receiver/gateway signature, trusted time or monitored SCITT inclusion | “A second system observed or registered the same committed event.” | Collusion, unobserved paths, false statements, selective submission and provider compute unless measured |
| **Measured execution** | Corroborated profile plus fresh protected EAT/CMW evidence and an Attestation Result binding verifier, policy, reference values, endorsements and code/model/data/config/result | “This verifier appraised evidence that the committed result came from this measured environment under stated assumptions.” | Hardware/vendor/design trust, verifier correctness, semantic validity, omitted executions and post-attestation change |
| **Reconciled completeness** | Measured or corroborated evidence plus signed expected-set manifest, independently produced event inventory and reconciliation result | “Within the declared population/window, missing or extra records are detectable to the stated bound.” | Colluding manifests/inventories, scope definition and upstream path completeness |

Profiles must be selected by policy and consequence, not marketing language. A valid portable receipt
must never be displayed as “hardware attested”; a TEE receipt must never be displayed as “complete”
without reconciliation.

## Required Warrantor specification corrections

1. Replace “the documented gap is uncontested” and every “nobody signs/pins” statement with the
   pinned-version wording in the harness matrix. The named native paths have now been inspected; the
   result must retain tool, commit, date, inspected surface and extension/future-version limitations.
2. Keep DSSE + in-toto. Use canonical digests only where a stable content address is required; do
   not make signature verification depend on reparsing or JSON canonicalization. Add digest-bound
   SCITT re-envelopment/registration as a transparency option rather than redefining a producer
   signature as a SCITT receipt.
3. Add explicit `raw_input`, `canonical_input`, `evaluator_input`, `rubric`, `grader`, `evaluator`,
   `manifest`, `acceptance`, `corroboration`, `attestation`, `completeness` and `claim_boundary`
   blocks. Large/private artifacts should be content-addressed, encrypted and referenced, not copied.
4. Separate four identities: accountable principal, receipt issuer, evaluator runtime and grader or
   reviewer. Record whether each is caller-asserted, issuer-observed, credential-verified,
   receiver-attested or hardware-measured.
5. Make the current run-validity controls machine-verifiable where possible. `noise_floor`,
   `elicitation_method`, holdout status and awareness markers need schemas and rejection vectors, not
   only prose.
6. Define losslessness against EEE and each native harness. Every adapter must produce a source-field
   coverage report; an unrepresented native field is either explicitly classified as non-semantic or
   causes adapter failure. Preserve original bytes by digest.
7. Define completeness separately from tamper evidence. Merkle inclusion proves that one entry was
   logged; consistency proves append-only evolution between observed tree heads; neither proves every
   evaluation was submitted.
8. Link, do not conflate, the evaluator result and human decision. The acceptance record should bind
   the exact receipt digest and use verified reviewer identity/authority when the deployment claims
   human accountability.
9. Publish two independent producer implementations and at least two verifiers across Rust, Python,
   Go or TypeScript, then run differential vectors for Unicode, numbers, unknown fields, profile
   confusion, missing cases, ordering, stale manifests, key rotation, replay and privacy modes.
10. Add cost and failure semantics for every profile: signing/verification latency, evidence size,
    storage amplification, log/attestation outage, key loss, partial batch, evaluator crash and
    reconstruction behavior.
11. Define a strict EAT profile and protected RATS CMW collection for measured evaluation. Forbid
    unsecured tokens, bind nonce/freshness, verifier identity, appraisal-policy digest, reference
    values and endorsements, and expose the Attestation Result separately from raw Evidence.
12. Authenticate the expected receipt population. Neither in-toto Bundle nor SCITT inclusion proves
    complete submission; add a signed expected-set manifest, closure rule and reconciliation result.

## Adopt, modify, defer, reject

| Decision | Recommendation | Reason |
|---|---|---|
| DSSE + in-toto base | **Adopt** | Standards-aligned envelope and predicate model; avoids another canonical-signature island |
| SCITT + COSE Receipts | **Adopt as optional transparency profile** | Strong registered-history proof; explicitly not statement truth or submission completeness |
| RATS/EAT/CMW | **Adopt with a strict measured-execution profile** | Correct evidence/appraisal/result model and interoperable carriage; base formats deliberately do not guarantee trustworthiness |
| AERF core wire format | **Reject; interoperate** | Useful reproduced vectors and prior art, but unstable/inconsistent draft duplicates more mature standards |
| Current Warrantor semantic blocks | **Modify** | Strong run-validity fields, but missing raw/canonical/full-input separation, explicit rubric/manifest governance, corroboration and completeness |
| TEE for every evaluation | **Reject** | Cost, capacity, vendor trust and availability are disproportionate for low-impact runs |
| TEE as high-assurance profile | **Adopt with modification** | Direct prior art shows the value; require portable appraisal and explicit residual assumptions |
| Aqta wire format as Warrantor core | **Reject** | Useful engineering comparator but weaker semantics and non-standard envelope for Warrantor's target |
| Aqta vectors and verifier lessons | **Adopt/port** | Reproduced cross-language edge cases are immediately valuable for Warrantor conformance |
| Every Eval Ever semantics | **Adopt/consume** | Directly solves much of cross-harness representation; avoids a proprietary schema island |
| Inspect AI first adapter | **Adopt** | Richest reviewed native provenance and an existing EEE converter make it the fastest losslessness baseline |
| garak, PyRIT and AgentDojo adapters | **Build thin adapters** | Preserve domain-specific native evidence; do not reimplement their evaluation engines |
| Native hashes/ETags as signatures | **Reject** | They support content/storage integrity or concurrency, not key-authenticated semantic claims |
| Grant architecture as implementation | **Defer** | Field design is useful; efficacy, cost and security remain untested |
| “First/only/nobody” messaging | **Reject** | Already contradicted and unnecessary for a stronger feature-bounded product thesis |

## Next evidence gates

- Produce representative native logs from the pinned garak, PyRIT, Inspect and AgentDojo versions;
  convert them through EEE and Warrantor and publish machine-readable field-coverage and round-trip
  loss reports.
- Bind a Hawk-run Inspect log to runner image, resolved dependencies, workload identity, storage
  version and importer/editor lineage, then show exactly which claims remain infrastructure-trusted.
- Reproduce at least one SCITT service/client and two independent EAT/CMW implementation paths;
  current normative review establishes format and guarantee boundaries, not production
  interoperability, key/status operation or cross-vendor assurance equivalence.
- Obtain or reconstruct an Attestable Audits prototype only as a research artifact, then test model,
  rubric, dataset and result substitution plus replay, log outage and direct-path bypass.
- Build Warrantor golden vectors before freezing the eval predicate; include an intentionally lossy
  adapter and require failure.
- Reconcile an evaluator receipt set against an independent provider or gateway event list and report
  the first measured omission-detection bound.
