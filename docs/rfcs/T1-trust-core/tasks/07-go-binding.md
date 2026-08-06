# Task 07-go-binding — T1 trust-core

> **Sprint:** Beta week 6. **Acceptance:** Go binding via cgo; conformance green in Go.

## Objective
Expose trust-core to Go via cgo to a C FFI shim.

## Steps
1. Add a C ABI shim in Rust (`#[no_mangle] pub extern "C" fn aumos_trust_sign(...)`) using `cbindgen`
   to generate the header.
2. `bindings/go/` — cgo wrapper; Go package `aumos.dev/trustcore`.
3. Add Go golden-vector verifier to the conformance suite.

## Acceptance criteria
- [ ] `go test ./...` passes in `bindings/go/`.
- [ ] Go verifier passes all golden vectors.
- [ ] cgo header generated, not hand-written.
