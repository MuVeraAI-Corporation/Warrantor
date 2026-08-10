# testvectors/ — Golden cross-language behavior vectors

The golden vectors that prove a behavior in one language is identical in every other. The
strict cross-language conformance suite (`tools/conformance/run.py`, with
`tools/conformance/run.sh` retained as a POSIX shim) verifies every vector in Rust, Python,
TypeScript, and Go. Missing required toolchains or zero-vector lanes are failures.

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

The conformance runner runs two T1 lanes: a sign/verify lane
(vectors with `payload_hex` + `signature_hex`) and a Merkle-root lane (vectors with
`leaves_hex` + `expected_root_hex`). Each lane verifies every matching vector in Rust,
Python, TypeScript, and Go.

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

**Current implemented scope:** five T1 vectors across signature and RFC 6962 Merkle lanes.
The runner requires identical behavior in all four supported languages. The other directories
shown in the target layout remain pending and must not be inferred from this T1 result.
