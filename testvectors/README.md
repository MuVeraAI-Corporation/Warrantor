# testvectors/ — Golden cross-language behavior vectors

The golden vectors that prove a behavior in one language is identical in every other. The
cross-language conformance suite (`tools/conformance/run.sh`, RFC A6) verifies every vector
in Rust, Python, TypeScript, and Go.

## Layout

```
testvectors/
├── T1/           # trust-core: sign/verify + RFC 6962 Merkle-root vectors
│   ├── sign-ed25519-conformance-001.json  # Ed25519 sign/verify (positive)
│   ├── sign-cbor-canonical-002.json       # canonical-CBOR sign/verify (C1 HashMap-ordering fix)
│   ├── sign-ed25519-tampered-003.json     # Ed25519 sign/verify (negative — expected=invalid)
│   ├── merkle-001.json                    # RFC 6962 Merkle root, 4 leaves (power of two)
│   └── merkle-002.json                    # RFC 6962 Merkle root, 5 leaves (orphan promotion)
├── C1-1/         # nvtrust-bridge: (nonce, mock_attestation_report) pairs
├── C1-2/         # cuda-gram: same shape as C1-1
├── R2/           # eval-guard: pre-flight-check scenarios
├── R3/           # kill-switch: (trigger, policy_decision, expected_outcome)
├── R4/           # credential-vault: (issue_request, expected_credential, revoke_result)
├── I1/           # agent-identity: (aae, expected_svid, delegation_chain)
├── P1/           # AAE protocol: adversarial vectors (replay, tamper, confused-deputy)
└── P2/           # AAR protocol: same
```

The conformance runner (`tools/conformance/run.sh`) runs two T1 lanes: a sign/verify lane
(vectors with `payload_hex` + `signature_hex`) and a Merkle-root lane (vectors with
`leaves_hex` + `expected_root_hex`). Each lane verifies every matching vector in Rust,
Python, and Go.

## Vector format

Each vector is a JSON file:

```json
{
  "id": "T1-sign-ed25519-001",
  "description": "Ed25519 sign/verify round-trip on a canonical-CBOR payload",
  "payload": { "action": "issue-credential" },
  "canonical_cbor_hex": "...",
  "signature_hex": "...",
  "verifying_key_hex": "...",
  "expected": "valid"
}
```

## Status

**Wave-1 (Phase 1) target.** The first vectors (T1 sign/verify, C1-1 mock attestation, R3
kill-switch policy) land as part of each component's MVP task (task 02). The cross-language
conformance suite enforces they verify identically in every present language.
