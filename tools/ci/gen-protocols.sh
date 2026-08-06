#!/usr/bin/env bash
# Protocol spec generator — emits the 12 protocol specs (P1..P12) into specs/protocols/.
# Each spec: purpose, schema sketch, mandatory fields, signing, revocation, test vectors.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIR="$REPO_ROOT/specs/protocols"
mkdir -p "$DIR"

# id|name|spelled_out|consumed_by|schema_loc|purpose|mandatory_fields
read -r -d '' PROTOCOLS <<'EOF' || true
P1|aae|Agent Authority Envelope|I1, R3, R4, T1, all trusted-core|proto/aumos/protocols/v1/aae.proto + CDDL|Signed task-specific delegation: who may act, for whom, on what, using which resources, for which purpose, within what limits, until when, with which approvals and obligations. Base: SPIFFE SVID + capability-token semantics.|issuer, subject, purpose, resources, tools, data_classes, side_effect_class, spend_budget, time_budget, token_budget, geography, delegation_depth, approvals, expiry, revocation_handle
P2|aar|Agent Action Receipt|E1, X2, all auditing|proto/aumos/protocols/v1/aar.proto + CDDL|Tamper-evident receipt per material action. The receipt is signed BEFORE the action's effect is visible; the action commits only once the receipt is durable (invariant I-07).|actor, authority_hash, artifact_versions, context_commitment, policy_decision, tool_or_api_op, deterministic_checks, approver, outcome, rollback_pointer
P3|cpe|Context Provenance Envelope|future context components|CDDL|Origin/trust through retrieval + transformation. Records source identity, acquisition time, consent, sensitivity, integrity, confidence, transformations, derived-from graph, taint, expiry, allowed use. Enforces invariant I-03 (purpose-bound data use).|source_identity, acquisition_time, consent, sensitivity, integrity, confidence, transformations, derived_from, taint, expiry, allowed_use
P4|amil|Agent Memory Integrity Ledger|future context/memory components|CDDL|Prevents silent memory poisoning. Signed records with ownership, confidence, contradiction links, provenance, quarantine, supersession, retention, consent revocation.|record_id, owner, confidence, contradiction_links, provenance, quarantine_state, supersession, retention, consent_revocation
P5|ssp|Secure Skill Package|S4, X8|CDDL + JSON-LD|Distribute skills safely. Bundles instructions, code, tools, permissions, publisher identity, OMS signature, AI-SBOM, eval set, benchmark, limitations, revocation.|instructions, code, tools, permissions, publisher_identity, oms_signature, ai_sbom, eval_set, benchmark, limitations, revocation
P6|aatm|AI Artifact Trust Manifest|T1, S1, S4, S5|JSON-LD|Binds model + dataset + tokenizer + prompt + adapter + container + policy + skill + eval into one signed graph. Base: OMS + SPDX/CycloneDX + deployment attestations.|model, dataset, tokenizer, prompt, adapter, container, policy, skill, eval, deployment_attestations
P7|abs|Autonomy Budget Specification|I1, R3|CDDL|Machine-enforceable budgets: steps, wall-clock time, tokens, money, external calls, data volume, privilege, irreversible actions, expected risk.|steps, wall_clock, tokens, money, external_calls, data_volume, privilege, irreversible_actions, expected_risk
P8|veb|Verifiable Evaluation Bundle|A1, A5, A6|CDDL|Reproducible eval evidence: test corpus digest, environment, model/harness/policy versions, seeds, traces, judge versions, deterministic assertions, signed result.|corpus_digest, environment, model_version, harness_version, policy_version, seeds, traces, judge_version, deterministic_assertions, signed_result
P9|aix|Agent Incident Exchange|X9, R3|OCSF extension + JSON|Normalized incidents for goal hijack, memory poisoning, tool abuse, identity compromise, exfiltration, rogue delegation. Base: OCSF extension + MITRE ATLAS mapping.|incident_id, type, severity, agent, authority, evidence_refs, mitre_atlas_id, ocsf_class, detected_at, contained_at
P10|made|Multi-Agent Delegation Exchange|I1 (multi-agent future)|CDDL|Signed, attenuated delegation + result exchange between agents. No privilege amplification; hop count; quorum; evidence requirements; trust-domain federation.|delegation_chain, hop_count, quorum, evidence_requirements, trust_domain, result, signature
P11|prb|Proof-Carrying Remediation Bundle|S9, X9|CDDL + JSON-LD|Vulnerability fix with reproducer, root cause, affected-version graph, patch, tests, regression evidence, build provenance, signed artifacts. Embargo-preserving.|reproducer, root_cause, affected_versions, patch, tests, regression_evidence, build_provenance, signed_artifacts, embargo
P12|cap|Capability Attestation Profile|R1, R2, I1|CDDL|Declare and verify what an agent can actually do in a specific runtime: tools, policy, credentials, network, memory, model, sandbox.|runtime, tools, policy, credentials, network, memory, model, sandbox, attestation_evidence
EOF

count=0
while IFS='|' read -r id name spelled consumed schema purpose fields; do
  [ -z "$id" ] && continue
  [[ "$id" == \#* ]] && continue
  cat > "$DIR/${id}-${name}.md" <<EOF
# ${id} — ${spelled}

> ${purpose}

| Field | Value |
|---|---|
| **Protocol ID** | ${id} |
| **Name** | ${name} (${spelled}) |
| **Spec-only canonical** | Yes — see [\`../../docs/00-reconciliation-matrix.md\`](../../docs/00-reconciliation-matrix.md) §9 |
| **Consumed by** | ${consumed} |
| **Schema location** | \`${schema}\` |
| **Base standards** | SPIFFE, OAuth RAR/DPoP, OCSF, OTel, CycloneDX/SPDX, OMS, MITRE ATLAS (as applicable) |

## Purpose

${purpose}

The protocol is **language-neutral**. It is defined once here and consumed identically by every
language implementation via the contract plane (see
[\`../../docs/cross-cutting/19-inter-component-protocol.md\`](../../docs/cross-cutting/19-inter-component-protocol.md)).

## Schema sketch (CDDL / protobuf)

The normative schema lives at \`${schema}\`. Mandatory fields:

\`\`\`
${fields}
\`\`\`

(Field names are stable; renaming is a breaking change requiring a new protocol version per the
governance rules in \`specs/protocols/README.md\`.)

## Signing

Every instance is signed by the issuer using T1 trust-core (Ed25519 by default; KMS/HSM in
production). The signature covers the canonical-CBOR encoding of the protocol message. The
Sigstore Rekor transparency log entry is returned for non-repudiation.

## Revocation

- **Expiry:** every instance carries an explicit expiry timestamp; expired instances are rejected
  without further checks.
- **Revocation handle:** issuers may revoke by publishing the revocation handle to
  \`aumos.<domain>.revoked.v1\` CloudEvent on Kafka.
- **Propagation:** revocation propagates fleet-wide within the I-05 budget (identity <5s,
  credentials <1s).
- **Partial disclosure:** protocols support selective disclosure where the use case requires it
  (e.g. zero-knowledge proofs for sensitive authority claims — future work).

## Adversarial test vectors

Each protocol ships adversarial test vectors in \`testvectors/${id}/\`:

- **Replay** — expired and re-used instances are rejected.
- **Tampering** — any field modified post-signing fails verification.
- **Confused deputy** — an instance presented to the wrong audience is rejected.
- **Privilege amplification** — a delegation chain whose intersection would expand authority is
  rejected (invariant I-02).
- **Downgrade** — an instance claiming an unsupported protocol version is rejected.
- **Replay across contexts** — a receipt from one task replayed in another is detected by
  \`subject\` + \`jti\` uniqueness.

Conformance is enforced by A6 (the cross-language conformance suite) against every language
implementation that consumes the protocol.

## Cross-references

- Reconciliation: [\`../../docs/00-reconciliation-matrix.md\`](../../docs/00-reconciliation-matrix.md) §9
- Architecture: [\`../../docs/02-architecture.md\`](../../docs/02-architecture.md) (planes consuming this protocol)
- Trust core: [\`../../docs/rfcs/T1-trust-core.md\`](../../docs/rfcs/T1-trust-core.md) (signs/verifies)
- Conformance: [\`../../docs/rfcs/A6-conformance.md\`](../../docs/rfcs/A6-conformance.md)
EOF
  count=$((count + 1))
done <<< "$PROTOCOLS"
echo "Generated $count protocol specs in $DIR"
