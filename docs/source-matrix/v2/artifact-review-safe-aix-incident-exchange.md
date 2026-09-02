# SAFE finding and AIX incident exchange — standards, prior art and implementation audit

Status: canonical v2 evidence artifact  
Review date: 2026-08-31  
Main evidence window: 2024-08-28 through 2026-08-28  
Older foundations: explicitly separated  
Repository authority: current Warrantor architecture, with legacy SAFE/AIX material retained for traceability  
Decision scope: SAFE Finding, X9 incident exchange, incident-to-control learning, disclosure, transport, integrity, regional operations and the associated build/consume decision

## Executive decision

The narrow repository observation is correct: the Open Secure AI Alliance SAFE RFC pinned at commit
`4ec7660569f41224c6bb8a1311c053e285a4d53d` is prose. It contains no normative schema, transport,
validation rules or standards crosswalk. That fact does **not** support the broader portfolio assertion that
there is “no existing implementation anywhere,” or that Warrantor should introduce another independent
top-level incident format.

The market and standards state changed materially before the research cutoff:

- OCSF 1.9.0, released on 2026-08-03, provides an `Incident Finding` class, AI-agent identity,
  model attribution, delegation, evidence entries, prompt/response context, notes, resources and a
  domain-neutral record-integrity profile with signatures and tamper-evident chaining.
- ETSI TS 104 158-1 and TS 104 158-2, published in March 2026, define the AI Common Incident
  Expression (AICIE) global resource framework and an AI-specific common incident container.
- The OECD published a 29-criterion, eight-dimension common AI-incident reporting framework in
  February 2025.
- CISA published an operational AI cybersecurity collaboration playbook in January 2025.
- A 2026 AAAI paper supplies a seven-dimension institutional design framework derived from nine
  safety-critical reporting regimes, while the current practice-informed AI-security taxonomy supplies
  incident/vulnerability and control-context fields derived from expert interviews and pilot coding.
- Mature STIX, TAXII, CSAF, TLP and IEP standards already cover adjacent threat-intelligence,
  transport, advisory, redistribution and handling-policy layers.

The strongest recommendation is therefore:

> **Do not ship SAFE Finding v0.1 as a competing top-level schema and do not describe X9 as OCSF
> compatible. Build a strict SAFE interoperability profile over OCSF 1.9 Incident Finding, add an ETSI
> AICIE import/export profile, and use existing transport, handling, advisory and threat-intelligence
> standards at their natural layers. Warrantor should own authenticated authority/evidence binding,
> loss-reporting translations, conformance, and incident-to-control receipts.**

Recommended disposition:

| Repository item | Disposition | Reason |
|---|---|---|
| SAFE mission, reporting compact, review layers and disclosure workflow | **Adopt and refine** | These are governance semantics, not redundant wire-format inventions. |
| `specs/warrantor-v4/04-safe-finding.schema.json` as a standalone exchange schema | **Reject as the canonical wire format** | It duplicates standards, omits essential lifecycle and exchange semantics, and contains an underspecified signature field. |
| OCSF 1.9 `Incident Finding` plus `ai_operation` and `record_integrity` | **Adopt as the internal event foundation** | It already supplies the closest operational and agent-aware schema substrate. |
| ETSI AICIE Part 2 | **Modify/profile; never accept unvalidated** | It is direct AI-incident prior art, but the normative Annex A printed in V1.1.1 is not syntactically valid JSON Schema. |
| OECD 29-criterion framework | **Adopt as policy/report completeness baseline** | It supplies global incident/harm context that security-event formats do not. |
| STIX 2.1 | **Adopt for threat-intelligence projection** | It models incidents, indicators, identities, relationships, sightings and courses of action. |
| TAXII 2.1 | **Adopt where CTI ecosystems require it** | It provides HTTPS collection exchange; it is not an incident-governance or authorization protocol. |
| CSAF 2.1 draft | **Profile for product advisory export** | It supplies product/version/remediation and advisory distribution semantics, not agent-run evidence. |
| FIRST TLP 2.0 and IEP 2.0 | **Adopt for handling and redistribution policy** | TLP alone is deliberately simple; IEP adds machine-readable use, attribution, notification and transport policy. |
| OpenTelemetry GenAI conventions | **Reference only for trace links** | Development-stage telemetry is evidence location/context, not an incident record, signature or completeness proof. |
| X9 `python/incident_exchange` OCSF exporter | **Quarantine and replace before use** | It resolves to the wrong OCSF class/category and repurposes lifecycle activity IDs as incident types. |

## Claim adjudication

### Narrow SAFE RFC gap

Claim: “The SAFE finding RFC has no schema, transport, or standards crosswalk.”

Decision: **supported, high confidence, tightly bounded to the pinned SAFE RFC**.

Evidence:

- The pinned RFC defines mission, scope, reporting conditions, deadlines, evidence preservation, an
  eight-layer review, disclosure stages and incident-to-control expectations.
- The text contains no JSON Schema, protocol endpoint, authentication model, version negotiation,
  validation rules, update/supersession algorithm, TLP/IEP marking, OCSF mapping, AICIE mapping,
  STIX/CSAF projection or conformance suite.
- Its “machine-readable updates” and “machine-readable policies” are desired deliverables, not defined
  artifacts.

Required wording:

> “The current SAFE RFC defines governance and reporting intent but does not yet define a normative
> schema, transport, validation contract or standards crosswalk.”

Prohibited inference:

> “No AI incident schema, exchange or implementation exists.”

### “No existing implementation anywhere”

Decision: **contradicted, high confidence**.

ETSI AICIE Parts 1 and 2 are AI-specific technical specifications with record structures. OCSF 1.9 is an
open, compiled, machine-readable security-event schema with agent and integrity primitives. OECD supplies
an operational reporting baseline. CISA, AIID/OECD AIM, STIX/TAXII and current academic taxonomies add
governance, repositories, transport and classification. No single source supplies Warrantor's entire desired
composition, but that is a composition gap—not absence of implementations.

### X9 OCSF compatibility

Implied claim: `python/incident_exchange` emits OCSF v1.1 Incident events and is an OCSF extension.

Decision: **contradicted, high confidence, mechanically reproduced**.

The current exporter sets:

- `class_uid = 3003`
- `category_uid = 3`
- `activity_id = 1..6`, keyed to Warrantor incident type
- `type_uid = class_uid * 100 + activity_id`

Against an official OCSF 1.9.0 schema compiled from tag commit
`856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba`:

| Emitted value or field | Official resolution | Result |
|---|---|---|
| `class_uid = 3003` | `Authorize Session` | Wrong class. |
| `category_uid = 3` | `Identity & Access Management` | Wrong category; Findings is 2. |
| `activity_id = 1` | Assign Privileges for Authorize Session | Wrong semantics. |
| `activity_id = 2` | Assign Groups for Authorize Session | Wrong semantics. |
| `activity_id = 3` | Assign Roles for Authorize Session | Wrong semantics. |
| `activity_id = 4..6` | No enum member for Authorize Session | Invalid. |
| `Incident Finding` | `class_uid = 2005`, category 2 | Correct incident foundation. |
| Incident Finding `activity_id` | 1 Create, 2 Update, 3 Close, 99 Other | Lifecycle, not incident taxonomy. |
| `incident_id`, `title`, `summary` | Not attributes of resolved Authorize Session | Unknown at the emitted top level. |
| `metadata.atlas_techniques`, `metadata.evidence`, `metadata.extras` | Not OCSF metadata attributes | Misplaced extension content. |
| required metadata | product and schema version | Not emitted. |

The `type_uid` arithmetic is internally consistent with the wrong class. That does not make the record an
incident. For an exfiltration event the exporter emits `300305`, which denotes an undefined activity on
Authorize Session rather than an agent incident.

The repository's 14 X9 tests passed. They are self-referential: they assert that output equals the same
hard-coded constants and never resolve a class against an independent OCSF schema. Passing them therefore
does not establish conformance.

## Reproduction receipt

### Inputs

- Warrantor module: `python/incident_exchange`
- Source state reviewed: repository working tree on 2026-08-31
- OCSF source: tag `1.9.0`
- OCSF tag commit: `856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba`
- OCSF tag date: 2026-08-03
- Compiler: `ocsf-schema-compiler`, invoked against the pinned tag
- Compiled result: OCSF base version 1.9.0, approximately 4.4 MiB
- Test event: fixed exfiltration incident, fixed UUID and timestamp

### Checks performed

1. Ran all repository X9 tests: 14 passed.
2. Generated a fixed `IncidentType.EXFILTRATION` event with `to_ocsf()`.
3. Compiled official OCSF 1.9.0 source definitions.
4. Resolved the emitted `class_uid` in the compiled schema.
5. Compared category, activity enumeration, attributes, metadata object and required fields.
6. Resolved the official Incident Finding class independently.

### Reproduced output summary

```text
resolved_class=authorize_session Authorize Session
resolved_category=3 Identity & Access Management
activity=5 [undefined]
unknown_attributes=incident_id, summary, title
missing_unprofiled_required=user
metadata_required=product, version
metadata_unknown=atlas_techniques, evidence, extras
incident_finding_uid=2005
incident_finding_category=2 Findings
incident_finding_activity=Create, Update, Close, Other
```

### Evidence boundary

The official OCSF Toolkit binary could not be downloaded from the GitHub release object in the bounded run;
the transfer stalled before any bytes arrived. This is not needed for the dispositive class-resolution result:
the official tag compiled successfully with the official compiler, and the compiled schema unambiguously
maps UID 3003 to Authorize Session and UID 2005 to Incident Finding. A release gate should nevertheless run
the official toolkit in CI once the corrected producer exists.

## Repository SAFE Finding v0.1 audit

The proposed schema is materially richer than the SAFE prose RFC. It deserves preservation as a requirements
inventory, but not adoption as an independent public format.

### Useful requirements to preserve

- Coordinated disclosure state.
- Discovery, containment, notification, advisory and remediation timestamps.
- Reporter class and confidentiality tier.
- Four SAFE reporting conditions.
- Eight control-review layers with failed/contained/not-implicated status.
- Blast radius, reversibility, exposure and autonomy impact dimensions.
- Incident-time and expected authority evidence.
- Verification method, failure modes, noise floor and reproducibility.
- Causal graph, receipt references and artifact digests.
- Crosswalk references and incident-derived control outputs.
- Supersession and narrative separation.

### Defects and ambiguity

1. The schema creates a new top-level vocabulary instead of profiling OCSF/AICIE.
2. `disclosure_state` mixes record workflow, information-sharing state and publication status.
3. The lifecycle has timestamps but no normative state-transition or optimistic-concurrency rules.
4. Update, merge, withdrawal, correction, redaction and tombstone semantics are incomplete.
5. Reporter identity and confidentiality are fields but not bound to authentication, authorization or handling policy.
6. `condition` permits only one of four conditions although an incident can satisfy several.
7. Review-layer status omits `unknown`, `not_assessed`, `not_applicable` and confidence/provenance.
8. The custom severity vocabulary has no conversion-loss model to OCSF, OECD, CVSS, SSVC or regulator thresholds.
9. `authority_evidence` contains strings and booleans but no typed credential, issuer, holder, scope or verification result.
10. `causal_graph` allows edges to nonexistent nodes and cannot enforce acyclicity or temporal constraints in JSON Schema alone.
11. Artifact `signed` is a boolean assertion; it does not supply or verify a signature.
12. `controls` enumerates formats but does not bind a control to its reviewed finding, compiler, approval, deployment or measured effect.
13. The `crosswalk` object stores foreign identifiers but not mapping version, direction, confidence, cardinality or loss.
14. `integrity.signature` is described as a DSSE envelope but typed as a string, with no media type, payload type, key identifier, verification policy or detached/enveloped rule.
15. “DSSE over the JCS-canonical finding” combines two signing models without specifying whether the DSSE payload is canonical JSON bytes, which fields are excluded, or how recursion through `integrity` is broken.
16. `additionalProperties: false` provides strictness but no extension registry or negotiation mechanism.
17. There is no transport, discovery, collection, subscription, pagination, retry or idempotency contract.
18. There is no TLP/IEP policy, recipient group, embargo, legal hold, selective disclosure or field-level redaction model.
19. There is no conformance profile or canonical positive/negative fixture set.
20. The `$id` host is `openssecureai.org`; governance, persistence and publication of that namespace are not established in the schema.

### Correct use of the draft

Treat `04-safe-finding.schema.json` as an input requirements catalog. Extract the requirements into a profile
matrix, map each to an existing standard field or a narrowly named SAFE extension, and record unavoidable
loss. Do not expose the current document as the canonical exchange contract.

## External evidence canon

### Current 2024–2026 collection

| Score | Source | What it establishes | Important limitation |
|---:|---|---|---|
| 96 | OCSF Schema 1.9.0 | Agent-aware security events, Incident Finding lifecycle, delegation and record integrity | Event normalization, not exchange governance, confidentiality or transport. |
| 91 | Wei and Heim, *Designing Incident Reporting Systems for Harms from GPAI* | Seven institutional-design dimensions across nine safety-critical regimes | US-centric; safety/rights primary; no wire format. |
| 90 | OECD common AI-incident reporting framework | 29 criteria, eight dimensions and seven mandatory fields | Policy/reporting model, not an authenticated schema or exchange. |
| 86 | CISA JCDC AI Cybersecurity Collaboration Playbook | Operational voluntary sharing process, protections and receiver actions, informed by two tabletop exercises | JCDC context; no normative record schema. |
| 86 | Saudi NCA ECC 2:2024 | National requirements for classification, NCA reporting, notifications, threat intelligence and incident reports | Cybersecurity-wide, not AI-specific and no exchange schema. |
| 85 | Bieringer et al., practice-informed AI-security incident taxonomy | Practitioner-derived vulnerability/incident taxonomy, supply-chain and control context, pilot coding | Preprint; small coder samples; current version excludes agentic/multi-agent incidents. |
| 84 | Qatar NCSA National Incident Management Framework | National/sector/local categorization and five-phase incident lifecycle | Cybersecurity-wide; public framework does not define machine interchange. |
| 84 | FIRST IEP 2.0 | Machine-readable handling, permitted action, notification, attribution and transport policy | 2019 foundation; adoption and enforcement are implementation-dependent. |
| 84 | CSAF 2.1 CSD02 | Machine-readable product advisories, product status, remediation and distribution | Draft and vulnerability-advisory focused. |
| 78 | ETSI TS 104 158-2 AICIE Common Container | Direct AI-specific common record with 29 fields and normative Annex A | Printed normative JSON Schema is syntactically invalid; no transport, integrity or update protocol. |
| 76 | ETSI TS 104 158-1 AICIE Global Framework | Decentralized discovery of AI-incident lists, specs, repositories and enrichment | Resource record is shallow; JSON has TBD identifiers and syntax defects; referenced repository is TBD. |
| 73 | Open Secure AI Alliance SAFE RFC | Governance intent, reporting compact, evidence preservation, disclosure and learning | Draft prose only; no normative implementation artifacts. |

### Indispensable older foundations

| Score | Source | Role | Boundary |
|---:|---|---|---|
| 92 | OASIS STIX 2.1 | Threat-intelligence graph, incident/indicator/identity/relationship objects, markings and versioning | CTI language, not a complete incident case-management model. |
| 91 | OASIS TAXII 2.1 | HTTPS REST exchange through API roots and collections | Does not define governance, trust groups or content semantics beyond supported media. |
| 86 | FIRST TLP 2.0 | Four well-understood redistribution labels | Automated representation is deliberately left to exchange designers; not encryption or licensing policy. |
| 84 | FIRST IEP 2.0 | Richer machine-readable information-use and handling policy | Policy statement, not cryptographic enforcement. |

## Standards-layer architecture

No single format should absorb every concern. The correct system is layered.

```text
SAFE governance compact and institutional policy
  reporting threshold, reporter protection, deadlines, disclosure, review ownership
                              |
                              v
Canonical security event: OCSF 1.9 Incident Finding
  lifecycle + finding list + AI agent/model/delegation + evidence + record integrity
                              |
              +---------------+----------------+
              |               |                |
              v               v                v
       ETSI AICIE export   OECD report      STIX/CSAF projections
       AI public/policy    completeness      CTI/advisory consumers
              |               |                |
              +---------------+----------------+
                              |
                              v
Transport profile: authenticated HTTPS or TAXII Collection
  idempotency + ETag/revision + retry + pagination + receiver acknowledgement
                              |
                              v
Handling policy: TLP 2.0 + IEP 2.0 + recipient group + legal constraints
                              |
                              v
Warrantor assurance extensions
  authority at event + receipt lineage + expected-set reconciliation + translation loss
```

### Layer responsibilities

| Layer | Owns | Must not claim |
|---|---|---|
| SAFE compact | Reportability, deadlines, roles, disclosure, learning | Schema conformance, transport security or cryptographic truth. |
| OCSF profile | Canonical operational event and lifecycle | Confidential exchange governance or legal sufficiency. |
| ETSI AICIE | AI-specific policy/public reporting export | Operational security-event fidelity or integrity. |
| OECD | Report completeness and harm context | Machine authentication or transport. |
| STIX | CTI knowledge graph and relationships | Incident case completeness. |
| CSAF | Product advisory and remediation | Agent execution evidence or near-miss reporting. |
| TAXII/HTTPS | Transfer, discovery and collection retrieval | Authorization semantics above server/collection access. |
| TLP/IEP | Recipient handling and redistribution intent | Encryption, access control or enforcement proof. |
| OTel | Trace and evidence-location correlation | Signed evidence or exhaustive capture. |
| Warrantor | Authority/evidence binding, receipt lineage, loss and completeness conformance | Truth of unverified source assertions or legal compliance by itself. |

## Field-level crosswalk

Legend: **N** native, **P** profile/extension, **X** projection only, **—** no adequate field.

| SAFE requirement | OCSF 1.9 | ETSI AICIE Part 2 | OECD | STIX 2.1 | CSAF 2.1 | Warrantor action |
|---|---|---|---|---|---|---|
| Stable finding identifier | N: finding/incident UID | — | — | N: object ID | N: document tracking ID | Use OCSF UID; maintain translation IDs. |
| Create/update/close lifecycle | N: activity and status | — | — | N: modified/revoked/versioning | N: revision history/status | OCSF canonical; export snapshots with loss. |
| Incident description/title | N | N | N | N | N | Direct mapping. |
| First occurrence and range | N: start/end/time | Optional first date | N | N | N | Preserve precision and source clock. |
| Discovery/containment/report times | P | — | Partial | P | Partial | SAFE extension with typed event-time roles. |
| Reporter identity/class | N: reporter object/actor | N but flattened | N | N: identity/creator | N: publisher/tracking | Bind authenticated reporter separately from public projection. |
| Confidentiality/redistribution | P via markings | — | — | N: object markings | N: distribution/TLP | Require TLP+IEP and recipient group. |
| SAFE four reportability conditions | P | Partial relationship | Partial | X | X | Extension vocabulary, multi-valued and versioned. |
| Eight review layers | P | — | — | X | X | SAFE extension objects with assessment status/evidence. |
| Severity/impact | N | N | N | Partial/open vocabulary | Product severity/scores | Store source scales; never overwrite; publish mapping loss. |
| Harm type and parties affected | P | N | N | P | — | OECD/AICIE projection from extension. |
| Autonomy level | P | N | N | P | — | OCSF extension until native field exists. |
| AI agent identity/version/model | N | Partial product string | N/partial | P | Product-oriented | Use OCSF `ai_agent`; no flattened substitution. |
| Delegated authority/parent | N: delegation | — | — | P | — | Use OCSF plus verified Warrantor authority result. |
| Prompt/response context | N via message context | — | — | P/artifact | — | Redact by policy; link digest when content cannot travel. |
| Evidence list | N | One material URL | Supporting material | N: observed data/artifact | Notes/references | Use typed OCSF evidences and content-addressed references. |
| Verification method/noise floor | P | Reproduction steps only | — | P | — | SAFE extension with producer, method and limitations. |
| Causal graph | P/native graph objects emerging | — | Causal relationship category only | N: relationships | — | Use typed graph extension and validate references. |
| Artifact digests | N via file/hash objects | — | — | N: artifact/hash | N: hashes | Reuse foreign types; bind loaded/runtime evidence. |
| MITRE ATLAS/attack mapping | N: attacks | — | — | N: attack pattern/external ref | — | Use OCSF attack objects and STIX projection. |
| OTel trace/span | P | — | — | P | — | Link only; retain sampling/redaction metadata. |
| Product versions and remediation | Partial resources | AI product string/action | Partial | N via vulnerability/course of action | N, strongest | Project to CSAF when advisory semantics apply. |
| Control recommendation | N/P: resources/remediation | Action taken | Action taken | N: course of action | N: remediation | Content-address control plus approval/deployment receipts. |
| Signature/integrity | N: record_integrity | — | — | External/signing profile | Optional external signing | Adopt OCSF/in-toto/DSSE profile; reject string assertion. |
| Tamper-evident chain | N | — | — | — | Revision history, not cryptographic chain | Use OCSF attestation plus durable log where required. |
| Supersession/withdrawal | N via lifecycle/update profile | — | — | N: revoked/modified | N: revision/status | Define SAFE state machine over OCSF events. |
| Expected-set completeness | — | — | — | — | — | Warrantor-owned manifest, acknowledgement and reconciliation. |
| Translation loss | — | — | — | — | — | Warrantor-owned per-field loss report. |

## Lifecycle model

The record lifecycle, disclosure lifecycle and response lifecycle are distinct and must not be collapsed.

### Record lifecycle

```text
create -> update* -> close
   |         |        |
   +------ correction/reopen ------+
```

OCSF Incident Finding activity represents create/update/close. A profile must define stable incident UID,
event UID, revision, idempotency key, causal predecessor, producer time, receiver time and correction reason.

### SAFE disclosure lifecycle

```text
draft -> confidential -> affected-party-notified -> member-advisory -> public
   |           |                 |                    |
   +------ legal hold -----------+                    +-> corrected/superseded
```

Disclosure state determines audience and redaction, not whether the incident itself is new, in progress or
resolved.

### Operational response lifecycle

```text
detect -> triage -> contain -> investigate -> remediate -> verify -> recover -> learn
```

Qatar's NIMF, Saudi ECC, CISA and NIST-style response guidance map here. One operational incident can
produce many OCSF update events and several disclosure artifacts.

### Required transition properties

1. Stable incident ID; unique event/revision ID.
2. No silent destructive update.
3. Idempotent create/update receipt.
4. Optimistic concurrency or monotonic sequence.
5. Explicit correction and supersession.
6. Reopen semantics after close.
7. Independent response and disclosure states.
8. Per-transition actor and authority result.
9. Original and redacted artifact relationship.
10. Retention/tombstone policy compatible with legal obligations.

## Identity, authority and integrity profile

OCSF 1.9 materially narrows the proposed Warrantor novelty surface:

- `ai_agent.uid` is a stable logical identity.
- `ai_agent.instance_uid` identifies a run/session materialization.
- `ai_agent.ai_model` captures the model backing the agent at event time.
- `ai_agent.charter` can reference a durable role/constraints document.
- `delegation.uid`, `issuer_uid`, `parent_uid` and `created_time` carry authority lineage.
- `record_integrity.attestation_list` can carry multiple independent attestations.
- Each attestation can carry a fingerprint, multiple signatures, authority identity and a previous-event link.
- Digital-signature/fingerprint objects record serialization and encoding, including JCS, JWS, COSE and DSSE choices.

These fields are evidence vocabulary, not proof that:

- the issuer was authorized to delegate the requested scope;
- the holder presenting the delegation is the intended delegate;
- every parent was verified and unrevoked at event time;
- the operation/effect was fully mediated;
- the report is truthful or complete;
- the full expected event set was submitted.

Warrantor's defensible extension is a **verification result**, not another identity string:

```text
authority_result:
  profile_version
  verifier_identity
  verified_at
  subject_agent_uid
  instance_uid
  operation_digest
  delegation_chain_digest
  policy_revision
  authorized_scope
  denied_or_narrowed_scope
  credential_status_time
  holder_binding_result
  decision
  limitations
```

The result must be bound to the exact incident event fingerprint and carried under the record-integrity
profile or a referenced in-toto/DSSE statement.

## Transport, trust groups and handling

### Minimum authenticated HTTPS profile

Required endpoints or equivalent operations:

- service discovery and supported profile versions;
- submit create/update/close event;
- retrieve by stable incident and event IDs;
- query changed events by cursor;
- acknowledge accepted, rejected and quarantined records;
- retrieve validation/loss report;
- publish recipient keys and handling capabilities.

Required protocol properties:

- mutually authenticated organization/workload identity;
- authorization by trust group, collection and operation;
- content type and schema/profile version negotiation;
- idempotency key and replay window;
- immutable event digest and receipt;
- optimistic concurrency/ETag for updates;
- retry/backoff and deterministic duplicate handling;
- pagination/cursor semantics;
- maximum record/artifact size;
- artifact upload by digest with malware/content controls;
- receiver validation status and reason codes;
- data residency, retention and deletion policy;
- audit and expected-set reconciliation.

### TAXII option

Use TAXII collections where partners already operate CTI infrastructure. Do not claim that TAXII supplies:

- SAFE membership governance;
- reporter protection;
- incident lifecycle semantics;
- content truth or signature verification;
- field-level authorization;
- automatic affected-party notification.

### TLP and IEP

Each exchangeable event requires:

- a TLP 2.0 label;
- an IEP policy or reference where use restrictions exceed redistribution alone;
- the exact recipient/trust group;
- embargo and expiry if applicable;
- affected-party-notification permission;
- attribution and permitted-action rules;
- conflict behavior when multiple policies apply.

TLP is a human-readable sharing boundary. It is not encryption, licensing, authentication or access-control
proof. IEP is machine-readable intent; enforcement and legal overrides remain deployment responsibilities.

## AICIE assessment

ETSI AICIE is the most direct disconfirming source and an important interoperability target. It is not yet a
sound canonical implementation substrate.

### Part 1 value

- Creates a decentralized framework for discovering lists, specifications, repositories and enrichment.
- Intentionally permits independently operated directories and closed communities.
- Defines resource type, name, address, contact, access control description and additional attributes.
- Connects AI incident repositories, specifications, AI BOMs and knowledge graphs.

### Part 1 limitations

- The normative JSON uses `$schema: "tbd"` and `$id: "tbd2"`.
- The printed object omits necessary JSON punctuation around several properties.
- The example ETSI resource repository address is marked `[TBD]`.
- Replication and synchronization are described as possibilities, not a protocol.
- Trust, authentication, signatures, handling, discovery freshness and directory poisoning are unspecified.

### Part 2 value

- Defines an AI-specific 29-field record aligned heavily with OECD.
- Covers AI-system causal relationship, submitter, evidence material, harm, affected parties, human rights,
  industry, critical infrastructure, model/data links, multiple systems, autonomy, actions and reproduction.
- Is a published ETSI technical specification and therefore cannot be dismissed as a mere blog proposal.

### Part 2 critical defect

The normative Annex A in ETSI TS 104 158-2 V1.1.1 is not valid JSON or JSON Schema as printed. Examples:

- missing commas between enum strings;
- missing commas between object members;
- `"type": {true, false} "string"` constructs;
- an invalid date object embedded after `"type": "string"`;
- unterminated string literals in enum arrays;
- a misspelled `AAICIECCmultipleSystems` field;
- placeholder `$schema` and `$id` URLs.

No official standalone corrected schema was located in the bounded search. Warrantor must therefore treat
AICIE Part 2 as a semantic export target and validate against an independently reconstructed profile only
after ETSI publishes or confirms machine-readable artifacts. Marketing must not call the printed Annex
machine-executable without qualification.

## Regional implications

### North America

CISA's 2025 JCDC playbook was derived from two 2024 tabletop exercises and defines voluntary sharing among
government, industry and international partners, information-sharing protections/mechanisms and what CISA
does after receipt. It is operational governance evidence, not a schema. Warrantor should support a CISA/JCDC
export and process playbook without claiming official integration.

### India

CERT-In's six-hour cyber-incident reporting directions remain an important older/current operational baseline,
while the 2025 DPDP Rules create breach-notification duties. Neither is an AI-specific interchange format.
Before promoting an India profile, obtain the exact current English legal text, sector overlays, field/timing
requirements and counsel-reviewed role mapping. The exchange must be able to emit jurisdiction-specific
notices without confusing a SAFE member report with a statutory filing.

### Saudi Arabia

NCA ECC 2:2024 requires in-scope entities to identify and implement incident/threat management, classify
incidents, report incidents to NCA, share notifications, threat intelligence, indicators and reports, and manage
threat-intelligence feeds. It also requires event logging and at least 12 months retention for specified logs.
SAFE/AIX should provide a Saudi projection and evidence index, not claim that a generic SAFE record is an NCA
submission.

### Qatar

The 2025 NCSA National Incident Management Framework differentiates nationally coordinated, sectorally
coordinated, locally coordinated and no-national-significance incidents. Its five phases cover detection and
notification, triage/categorization, response-team formation, containment/forensics, remediation/verification,
closure and lessons learned. A Qatar profile needs category, coordination owner, service/sector impact,
forensic handoff and national-report references. The public framework does not define a machine schema.

### UAE

The bounded review confirmed official cyber-incident reporting services and national cybersecurity context,
but did not locate an English, current, field-level national AI/cyber incident interchange specification of
comparable depth. UAE coverage remains an explicit gap; do not derive it from Qatar or Saudi requirements.

## Build, consume, modify, defer and reject

| Capability | Decision | Warrantor-owned delta |
|---|---|---|
| Canonical security-event schema | Consume OCSF 1.9 | Strict SAFE profile and conformance, not a fork. |
| AI policy/public report | Modify/consume AICIE and OECD | Validated reconstruction, loss reports and provenance. |
| CTI projection | Consume STIX 2.1 | Stable mapping and custom-object minimization. |
| Product advisory | Consume/profile CSAF 2.1 | Agent/model product-tree mapping and status conversion. |
| Transport | Consume TAXII or authenticated HTTPS | Idempotency, acknowledgements, receipts and expected-set reconciliation. |
| Handling | Consume TLP/IEP | Trust-group enforcement and legal-override recording. |
| Trace context | Reference OTel | Sampling/redaction provenance and digest links. |
| Identity/delegation vocabulary | Consume OCSF | Verify holder, issuer, chain, scope, status and event binding. |
| Integrity envelope | Consume OCSF record integrity plus DSSE/in-toto where needed | Verification policy, key lifecycle and completeness. |
| SAFE governance | Build/contribute | Membership, thresholds, deadlines, disclosure, reporter protections and review governance. |
| Translation service | Build | Bidirectional mapping, loss report, version registry and fixture suite. |
| Expected-set protocol | Build | Producer manifest, receiver acknowledgement, reconciliation and omission evidence. |
| Incident-to-control receipts | Build narrowly | Finding→candidate→approval→compiled target→deployment→effect→regression lineage. |
| Current standalone SAFE schema | Reject as canonical | Preserve only as requirements input. |
| Current X9 exporter | Reject/quarantine | Replace with a validated producer/consumer. |
| AICIE printed Annex as executable schema | Reject | Wait for corrected artifact or publish a clearly non-normative adapter. |

## Recommended canonical profile

### SAFE Core profile over OCSF 1.9

Required OCSF content:

- Incident Finding class UID 2005.
- Activity ID 1/2/3 for create/update/close.
- Stable incident/finding UID and event UID.
- `finding_info_list` with title, description and source context.
- lifecycle status and times;
- producer metadata with OCSF version and product;
- reporter/actor identity;
- `ai_operation` profile when an AI model/agent is implicated;
- `ai_agent.uid`, `instance_uid`, version/framework and model where known;
- delegation UID/issuer/parent when action occurred under delegation;
- typed evidence list and content digests;
- attacks using MITRE ATT&CK/ATLAS objects;
- resources/notes rather than arbitrary metadata fields;
- `record_integrity` profile for signed exchanged events.

Required SAFE extensions:

- reportability conditions, multi-valued and versioned;
- disclosure state and audience;
- review-layer assessments;
- OECD harm/affected-party and autonomy projection fields not otherwise represented;
- verification method, failure modes and noise floor;
- authority verification result;
- receipt/causal lineage references;
- exchange handling policy and trust group;
- translation loss and source-profile information;
- expected-set manifest/acknowledgement references.

### Extension design rules

1. Prefix and register every extension.
2. Never replace a native OCSF field with a duplicate.
3. Preserve source vocabulary and normalized vocabulary separately.
4. Include mapping profile version and direction.
5. Make unknown/not-assessed distinct from false/not-applicable.
6. Bind security-critical extension content under event integrity.
7. Forbid self-asserted booleans such as `signed: true` as verification evidence.
8. Define data minimization and redaction per disclosure state.
9. Publish machine-readable positive and negative fixtures.
10. Test old readers against new optional extensions.

## Reference producer/consumer acceptance gates

### Producer

- Emits OCSF 1.9 Incident Finding UID 2005.
- Never overloads `activity_id` with incident taxonomy.
- Emits required metadata product/version and declared profiles.
- Uses native AI agent, model and delegation objects.
- Stores ATLAS data in attack objects, not metadata extras.
- Validates before signing.
- Produces a translation-loss report for every export.
- Produces deterministic idempotency and event digests.
- Redacts before signing the disclosed representation; links it to the protected original.
- Emits expected-set manifest entries.

### Consumer

- Resolves exact OCSF/profile version.
- Rejects unknown class/category mismatches.
- Rejects invalid activity/type UID combinations.
- Validates required, enum, object and profile constraints.
- Verifies fingerprints/signatures and authority policy.
- Applies TLP/IEP and recipient/trust-group policy.
- Detects replay, stale revision and conflicting update.
- Quarantines unknown extensions rather than silently dropping security-critical fields.
- Returns structured validation and loss results.
- Reconciles accepted/rejected/quarantined events with the producer manifest.

## Release-blocking conformance corpus

### Schema and identifier vectors

1. Correct Incident Finding create event.
2. Correct update and close events.
3. Reject class UID 3003 labeled as an incident.
4. Reject category 3 paired with Incident Finding 2005.
5. Reject incident taxonomy encoded as lifecycle activity ID.
6. Reject activity 4–6 for Incident Finding.
7. Reject incorrect `type_uid` for class/activity pair.
8. Reject unknown required-field omission.
9. Reject arbitrary top-level `title`, `summary` and `incident_id` substitutions.
10. Reject arbitrary values inside OCSF metadata.
11. Reject absent metadata product/version.
12. Reject undeclared profile fields.
13. Accept registered optional SAFE extensions.
14. Reject unknown security-critical extensions under strict profile.
15. Preserve benign unknown extensions in forward-compatible profile.

### Lifecycle and concurrency vectors

16. Duplicate create with same idempotency key.
17. Duplicate create with same incident ID and different content.
18. Update of nonexistent incident.
19. Close of nonexistent incident.
20. Update after close without reopen reason.
21. Concurrent conflicting updates with same predecessor.
22. Out-of-order delivery.
23. Replay outside allowed window.
24. Correction of a publicly disclosed record.
25. Supersession chain cycle.
26. Deletion request under legal hold.
27. Redacted derivative that does not reference protected original.

### Identity, delegation and integrity vectors

28. Self-asserted agent UID without authenticated producer.
29. Instance UID reused across unrelated logical agents.
30. Delegation with unknown issuer.
31. Delegation parent cycle.
32. Expired or revoked delegation.
33. Valid issuer signature but wrong holder.
34. Authority verification bound to a different operation digest.
35. Event changed after fingerprint.
36. Signature over noncanonical or ambiguous serialization.
37. DSSE string asserted without a valid envelope.
38. Co-signature from an unauthorized witness.
39. Broken previous-event chain.
40. Chain truncation and missing expected event.
41. Valid signature with untrusted/expired credential.
42. Valid record integrity but false evidence assertion.

### Handling, privacy and disclosure vectors

43. TLP:RED delivered to unauthorized recipient.
44. TLP:AMBER+STRICT widened to client sharing.
45. Unknown/missing IEP resolves fail-open.
46. Conflicting IEP policies during overlap.
47. Affected-party notification forbidden by policy but required by law.
48. Reporter PII included in public derivative.
49. Prompt or evidence contains secrets and prompt injection.
50. Artifact URL fetch causes SSRF.
51. Artifact decompression bomb or malware.
52. Cross-region replication violates residency policy.
53. Retention expiry conflicts with investigation/legal hold.

### Translation and interoperability vectors

54. OCSF→AICIE exact field mapping.
55. Multi-valued SAFE condition projected to single-valued target.
56. High-resolution timestamps projected to date only.
57. OCSF agent/delegation lost in AICIE.
58. OECD harm context round trip.
59. OCSF→STIX incident/indicator/identity relationships.
60. OCSF→CSAF product tree and remediation status.
61. TLP/IEP preserved across STIX/TAXII.
62. Unknown AICIE enum/free-form value preserved.
63. Invalid printed AICIE Annex rejected rather than silently repaired.
64. Mapping profile upgrade with deterministic loss comparison.
65. Two independent producers produce semantically equivalent records.
66. Two independent consumers return equivalent validation decisions.

### Incident-to-control vectors

67. Finding maps to a typed candidate, not directly to enforcement.
68. Candidate references immutable evidence and mapping version.
69. Approval binds exact candidate digest, reviewer and expiry.
70. Compiler emits explicit capability/loss report per target.
71. Deployment record binds target, revision, canary and rollback.
72. Independent effect event proves or bounds the response.
73. Regression result references the original incident and control revision.
74. Control expiry fails closed or reverts per declared policy.
75. Contradictory new evidence reopens the recommendation.
76. Expected-set reconciliation detects omitted failed deployments.

## Implementation sequence

### P0 — stop incorrect claims and unsafe reuse

1. Remove or qualify “no existing implementation anywhere.”
2. Mark X9 OCSF output unsupported and prevent external emission.
3. Replace OCSF 1.8 references with 1.9.0 in the research and design baseline.
4. Freeze the current SAFE schema as a requirements input, not the public wire format.
5. Publish this claim correction before content or sales material repeats the old wording.

### P1 — profile and conformance

1. Define SAFE Core as an OCSF 1.9 profile.
2. Write a field-level normative mapping and extension registry.
3. Build one producer and one strict consumer.
4. Run the official OCSF compiler/toolkit in CI.
5. Publish positive/negative fixtures and translation-loss documents.
6. Add TLP/IEP and trust-group policy.

### P2 — interoperability

1. Build AICIE Part 2 export/import with explicit nonconformity handling.
2. Build STIX and CSAF projections.
3. Support TAXII collection exchange where useful.
4. Build OECD completeness reports.
5. Commission a second independent producer/consumer.

### P3 — assurance and learning loop

1. Add record-integrity and verified authority results.
2. Add expected-set manifests and receiver reconciliation.
3. Bind incident evidence to response candidates, approvals, deployments and effects.
4. Measure completeness, latency, translation loss, reviewer agreement and false-report rates.
5. Contribute generic extensions/crosswalks upstream rather than keeping a private island.

## Options and trade-offs

### Option A — OCSF canonical, multi-format projections

Recommended.

Benefits:

- Maximum reuse of current agent-aware security-event work.
- Best compatibility with SIEM/data-lake ecosystems.
- Strong lifecycle and integrity base.
- Narrow, defensible Warrantor contribution.

Costs:

- OCSF is security-event oriented; harm, governance and disclosure need extensions.
- Version/profile discipline and mapping tests are ongoing obligations.

### Option B — ETSI AICIE canonical

Not recommended until corrected machine-readable artifacts and conformance exist.

Benefits:

- Direct AI-incident branding and OECD alignment.
- International standards-body provenance.

Costs:

- Current normative schema is not executable as printed.
- Weak operational lifecycle, integrity, transport and agent authority.
- Greater work to integrate security tooling.

### Option C — standalone SAFE schema

Reject as the canonical public format.

Benefits:

- Full control and direct representation of Warrantor-specific requirements.

Costs:

- Duplicates emerging standards.
- Creates an ecosystem island and permanent mapping burden.
- Makes novelty and adoption claims easier to challenge.
- Requires governance, registries, transport, SDKs and independent implementations from scratch.

### Option D — STIX/TAXII canonical

Use only for the CTI projection.

Benefits:

- Mature threat-intelligence ecosystem and transport.

Costs:

- Awkward operational incident lifecycle and AI-agent context.
- Custom STIX objects would recreate much of the profile problem.

## Product and business consequences

- Position the product as an interoperability and assurance layer, not “the first AI incident schema.”
- Enterprise value is reduced integration cost, evidence continuity, validated translations and regulator-ready
  projections—not ownership of another JSON document.
- Procurement differentiators should include supported profiles, independent conformance, data residency,
  trust-group policy, key lifecycle, mapping-loss SLAs and evidence reconciliation.
- A managed exchange can be commercialized through trust-group operations, validation, regional profiles,
  connectors, retention, incident-to-control workflow and assurance reporting.
- Open-source the core profile, fixtures and validators to reduce buyer lock-in concerns; commercialize hosted
  operations, regulated profiles and integration assurance.
- Do not promise statutory filing or compliance from one command. Export evidence with uncovered duties and
  legal assumptions explicit.

## Academic agenda

High-value paper opportunities:

1. **Loss-aware translation among OCSF, AICIE, OECD, STIX and CSAF.** Measure semantic preservation,
   reviewer agreement and failure modes on a public incident corpus.
2. **Authority-aware AI incident records.** Define and evaluate verified delegation/operation binding beyond
   descriptive agent identity.
3. **Expected-set completeness for cross-organization incident exchange.** Formalize omission, replay,
   acknowledgement and reconciliation under partial trust.
4. **Institutional versus technical incident-schema design.** Test whether reporting incentives, anonymity and
   enforcement choices affect record completeness and truthfulness.
5. **Agentic extension of the practice-informed taxonomy.** Cover agents, multi-agent delegation, tool effects,
   recursive model use and cross-system causal chains.
6. **Signed does not mean true.** Evaluate record-integrity, source reliability and independent evidence
   corroboration in AI incident exchanges.

Minimum evaluation design:

- preregistered field mapping and adjudication rules;
- multiple independent coders;
- public and confidential-synthetic incident samples;
- inter-coder agreement and per-field loss;
- adversarial malformed/ambiguous records;
- two independent implementations;
- blinded review of source and target formats;
- privacy, latency and operational-cost measurements;
- explicit negative and null results.

## Content program

Recommended evidence-led series:

1. “Why another AI incident JSON schema is the wrong product.”
2. “OCSF 1.9 changed the agent-security evidence landscape.”
3. “ETSI AICIE exists—and its published JSON Schema still cannot run.”
4. “Seven different things people mean by AI incident exchange.”
5. “TLP is not access control: handling policy for confidential AI incidents.”
6. “From AI incident to verified control without automating unsafe policy changes.”
7. “What Saudi Arabia and Qatar actually require from incident operations.”
8. “How to prove an AI incident record is complete, not merely signed.”

Content guardrails:

- Cite exact version/date and distinguish stable standards from drafts.
- Say “profile,” “projection” and “verified mapping,” not “universal schema.”
- Disclose the AICIE Annex defect factually and invite correction.
- Do not present conformance findings as a legal opinion.
- Do not call internal tests independent validation.
- Pair every novelty statement with named comparators and a bounded property.

## Audience reading paths

### Executives and product leaders

1. Executive decision in this artifact.
2. OECD common reporting framework.
3. CISA JCDC playbook.
4. Options and product consequences above.
5. Wei and Heim's institutional-design paper.

### Security and platform architects

1. OCSF 1.9 Incident Finding, AI operation and record integrity.
2. Standards-layer architecture and field crosswalk above.
3. STIX/TAXII and TLP/IEP.
4. Reference producer/consumer gates.
5. Conformance corpus.

### Engineers and implementers

1. X9 reproduction receipt.
2. OCSF compiled schema and toolkit validation guidance.
3. SAFE Core requirements and extension rules.
4. Lifecycle/concurrency vectors.
5. Translation and interoperability vectors.

### Academic researchers

1. OECD methodology and criteria.
2. Wei and Heim.
3. Bieringer et al.
4. ETSI AICIE Parts 1 and 2.
5. Academic agenda above.

### Risk, audit, policy and compliance teams

1. SAFE reporting/disclosure compact.
2. OECD framework.
3. CISA playbook.
4. Qatar NIMF and Saudi ECC.
5. TLP/IEP and evidence-boundary sections.

### Marketing, partnerships and content teams

1. Corrected claim language.
2. Product/business consequences.
3. Regional implications.
4. Content program and guardrails.
5. Source canon and scores.

## Remaining gaps and next bounded wave

1. Obtain or confirm an official corrected ETSI AICIE JSON Schema and Part 3 security-container status.
2. Execute the corrected producer with the official OCSF Toolkit in CI.
3. Inspect OCSF 1.9 independent producer adoption and real SIEM compatibility.
4. Complete IODEF, MISP, OpenC2/CACAO and CloudEvents mapping where demanded by partners.
5. Verify current English India and UAE statutory/sector reporting fields and legal status.
6. Define disclosure/anonymity governance with counsel and incident-response practitioners.
7. Test the crosswalk on a representative AI incident corpus, including non-security harms and near misses.
8. Commission a second implementation and blind interoperability event.
9. Threat-model exchange discovery, directory poisoning, trust-group compromise and malicious artifacts.
10. Measure business integration cost versus a standalone schema and versus CTI-only reuse.

The lane is materially stronger but not saturated. The architecture decision is clear; production conformance,
corrected AICIE artifacts, independent interoperability and region-specific legal mappings remain open.

## Primary source links

- [Open Secure AI Alliance SAFE RFC](https://github.com/OpenSecureAIAlliance/RFCs/blob/main/rfc-safe-proposal.md)
- [OCSF Schema 1.9.0 tag](https://github.com/ocsf/ocsf-schema/tree/1.9.0)
- [OCSF Incident Finding 1.9.0](https://schema.ocsf.io/1.9.0/classes/incident_finding)
- [OCSF Toolkit validation guidance](https://github.com/ocsf/ocsf-toolkit/blob/main/docs/validation.md)
- [ETSI TS 104 158-1 AICIE Global Framework](https://www.etsi.org/deliver/etsi_ts/104100_104199/10415801/01.01.01_60/ts_10415801v010101p.pdf)
- [ETSI TS 104 158-2 AICIE Common Container](https://www.etsi.org/deliver/etsi_ts/104100_104199/10415802/01.01.01_60/ts_10415802v010101p.pdf)
- [OECD common reporting framework for AI incidents](https://www.oecd.org/en/publications/towards-a-common-reporting-framework-for-ai-incidents_f326d4ac-en.html)
- [AAAI: Designing Incident Reporting Systems for Harms from General-Purpose AI](https://ojs.aaai.org/index.php/AAAI/article/view/41139)
- [Practice-Informed, Practice-Ready AI security incident taxonomy](https://arxiv.org/abs/2412.14855)
- [CISA JCDC AI Cybersecurity Collaboration Playbook](https://www.cisa.gov/news-events/alerts/2025/01/14/cisa-releases-jcdc-ai-cybersecurity-collaboration-playbook-and-fact-sheet)
- [OASIS STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html)
- [OASIS TAXII 2.1](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html)
- [OASIS CSAF 2.1 CSD02](https://docs.oasis-open.org/csaf/csaf/v2.1/csaf-v2.1.html)
- [FIRST TLP 2.0](https://www.first.org/tlp/)
- [FIRST IEP 2.0](https://www.first.org/iep/iep_framework_2_0)
- [Qatar NCSA National Incident Management Framework](https://ncsa.gov.qa/en/national-incident-management-framework)
- [Saudi NCA Essential Cybersecurity Controls ECC 2:2024](https://nca.gov.sa/en/regulatory-documents/controls-list/ecc/)

