# proto/ — Canonical Protobuf contracts

The contract plane's machine-checked wire definitions. Managed by **Buf** (see repo-root
`buf.yaml`); breaking changes here break every language implementation.

## Layout

```
proto/
└── aumos/
    ├── identity/v1/      # I1 agent-identity (mock + real)
    ├── trust/v1/         # T1 trust-core sign/verify
    ├── evidence/v1/      # E1 flight-recorder AAR (P2)
    ├── attestation/v1/   # C1-1/C1-2 attestation reports
    └── protocols/v1/     # P1 AAE, P2 AAR, P3 CPE, ... (the 12 open protocols)
```

## Status

**Wave-1 (Phase 1) target.** The first proto schemas land as part of Phase 1 task 01:
`aumos/identity/v1/agent.proto` (the **mock AgentVault** that Wave-1 components integrate
against), `aumos/trust/v1/signing.proto`, `aumos/protocols/v1/aar.proto`.

## Generating bindings

```bash
buf lint                       # enforce STANDARD ruleset
buf breaking --against '.git#branch=main'   # enforce no breaking changes
buf generate                   # generate Rust (tonic/prost), Python, TS, Go bindings
```

Generated code lives in each language's bindings folder; CI rejects uncommitted generated code.
