# testvectors/ — Golden cross-language behavior vectors

The golden vectors that prove a behavior in one language is identical in every other. The
cross-language conformance suite (`tools/conformance/run.sh`, RFC A6) verifies every vector
in Rust, Python, TypeScript, and Go.

## Layout

```
testvectors/
├── T1/           # trust-core: (payload, canonical_cbor, signature) triples
├── C1-1/         # nvtrust-bridge: (nonce, mock_attestation_report) pairs
├── C1-2/         # cuda-gram: same shape as C1-1
├── R2/           # eval-guard: pre-flight-check scenarios
├── R3/           # kill-switch: (trigger, policy_decision, expected_outcome)
├── R4/           # credential-vault: (issue_request, expected_credential, revoke_result)
├── I1/           # agent-identity: (aae, expected_svid, delegation_chain)
├── P1/           # AAE protocol: adversarial vectors (replay, tamper, confused-deputy)
└── P2/           # AAR protocol: same
```

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
