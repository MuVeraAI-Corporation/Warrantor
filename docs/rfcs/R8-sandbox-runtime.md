# R8 — `sandbox-runtime` RFC

> Actual sandbox (FORGE sandbox + OpenShell). Capability-scoped FS/network/process; default no process spawning; all syscalls logged.

| Field | Value |
|---|---|
| **Canonical ID** | R8 |
| **Name** | sandbox-runtime |
| **Wave** | 4 |
| **Languages** | Rust + WASM (Wasmtime) |
| **DefStack origin** | (none) |
| **AumSecure origin** | Secure Agent Workspace runtime |
| **Sentinel origin** | OpenShell adapter |
| **Dependencies** | T1 |

## Background

This component is reconciled from the source portfolios per
[`00-reconciliation-matrix.md`](../00-reconciliation-matrix.md). Origin mapping:
DefStack (none); AumSecure Secure Agent Workspace runtime; Sentinel OpenShell adapter. The full strategic rationale
appears in the matrix entry and the originating source document (see
[`source-matrix/README.md`](../source-matrix/README.md)).

## Goals and Non-Goals

**Goals:** Actual sandbox (FORGE sandbox + OpenShell). Capability-scoped FS/network/process; default no process spawning; all syscalls logged.

**Non-Goals:**
- Reinventing mature standards (SPIFFE, OCSF, OTel, CycloneDX) — we extend, not fork.
- A second authoritative implementation of any security invariant owned by T1 trust-core.
- Features outside the scope defined in the reconciliation matrix.

## Detailed Design

The reference implementation is [`rust/sandbox-runtime`](../../rust/sandbox-runtime), pinned to
Wasmtime 45.0.1: the newest patch compatible with the repository's Rust 1.93.1 toolchain. Default
Wasmtime features are disabled; only the compiler, runtime, standard library, and required error
surface are enabled. The next Wasmtime major requires Rust 1.94 and must not enter the lockfile
until the repository toolchain is deliberately upgraded.

`SandboxPolicy` is signed through T1 canonical CBOR and binds subject, expiry, module size, fuel,
linear memory, table elements, readable resources, network origins, and commands. The locked-down
constructor grants no host capability. Admission accepts binary WebAssembly only, verifies the
subject and limits, rejects unknown/WASI imports, and requires a non-empty policy resource list for
each declared AumOS host ABI import.

Wasmtime is configured for fuel consumption, bounded stack, one memory/table/instance, no
multi-memory, no memory64, and canonical NaNs. `StoreLimits` independently enforces guest memory
and table growth. Every execution intent is durably audited before compilation. Every host call is
addressed by a policy index rather than a guest-provided path/origin/command and is durably audited
before the injected backend is called. Out-of-range indices trap after a denied audit event.
Compiler/import rejection and every guest result receive final evidence.

The ABI currently exposes `aumos.fs::read(i32) -> i32`, `aumos.net::connect(i32) -> i32`, and
`aumos.process::spawn(i32) -> i32`. The physical operation is delegated to
`HostCapabilityBackend`; `DenyHostBackend` is the safe zero-authority implementation. WASI is not
linked, so there is no ambient environment, filesystem, network, clock, or process authority.

## Dependencies

- **AumOS internal:** T1 policy verification, E1-compatible audit sink, and optional R1 backend
  integration.
- **External:** `wasmtime = 45.0.1`, pinned for MSRV compatibility. Upstream runtime:
  [Bytecode Alliance Wasmtime](https://github.com/bytecodealliance/wasmtime).

## Threat Model

| Threat | Enforced mitigation |
|---|---|
| Infinite loop | Deterministic fuel exhaustion traps the guest. |
| Memory/table bomb | Module byte bound plus `StoreLimits` for memory/table/instances. |
| Ambient host authority | No WASI and unknown imports are rejected. |
| Capability confusion | Exact module/name ABI and policy-indexed resources. |
| Path/origin injection | Guest never supplies a resource string to a backend. |
| Audit bypass | Intent before compilation and capability audit before backend dispatch. |
| Policy substitution | T1 signature covers all limits and allowlists. |
| Text/parser ambiguity | Runtime accepts only binaries beginning with the WebAssembly magic. |

## API

The library exports signed policy/request/result types, `SandboxRuntime`, T1 and dependency
interfaces, capability/audit types, `DenyHostBackend`, and stable `SandboxError` variants. The
entrypoint contract is `() -> i32`; a component-model/WASI surface is intentionally absent.

## Testing

- Nine tests execute actual WebAssembly and cover pure compute, fuel exhaustion, memory denial,
  authorized/audited host dispatch, denied imports, out-of-range resources, audit outage,
  compiler rejection finalization, request bounds, and T1 policy tampering.
- Local acceptance: focused tests and strict Clippy pass.
- Coverage percentage, untrusted-module fuzzing, escape testing, OpenShell/FORGE backend
  integration, platform hardening, and performance/latency evidence remain release gates. An
  in-process Wasmtime reference is not proof of container, kernel, or physical host isolation.

## Deployment

R8 is an embeddable sandbox. Production callers must provide a durable audit sink and a
least-authority backend, pin the target architecture/runtime, isolate compiler caches, and apply
host process/container controls. This crate alone is not a Kubernetes deployment or an OpenShell
installation.

## Milestones

| Milestone | Target | Deliverable |
|---|---|---|
| Week 2 (MVP) | Wave-start + 2wk | Minimal usable version; 1 golden vector; CI green |
| Week 4 (Alpha) | Wave-start + 4wk | Core features; threat model; external integrations stubbed |
| Week 6 (Beta) | Wave-start + 6wk | All features; conformance green; perf targets measured |
| Week 8 (v1.0) | Wave-end | ≥85% coverage; v1.0 tag; signed release; SBOM; SLSA L3 |

## Cross-references

- Reconciliation: [`../00-reconciliation-matrix.md`](../00-reconciliation-matrix.md)
- Architecture: [`../02-architecture.md`](../02-architecture.md)
- Protocols consumed: see `specs/` and `proto/`
