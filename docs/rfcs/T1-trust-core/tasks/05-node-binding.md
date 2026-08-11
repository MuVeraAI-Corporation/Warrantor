# Task 05-node-binding — T1 trust-core

> **Sprint:** Beta week 5–6. **Acceptance:** Node/TypeScript binding publishes; conformance green in TS.

## Objective
Expose trust-core to TypeScript via napi-rs.

## Steps
1. `bindings/node/` — `napi-rs` setup; expose `sign`, `verify`, `canonicalCbor`, `notarize`.
2. Generate TypeScript types; ship as `@warrantor/trust-core` (local during Wave-1).
3. Add TypeScript golden-vector verifier to the conformance suite.
4. Document install + usage in `bindings/node/README.md`.

## Acceptance criteria
- [ ] `npm run build` produces the native addon for linux-x64 + darwin-arm64.
- [ ] TS verifier passes all golden vectors.
- [ ] Coverage reported via the conformance runner (no separate TS coverage gate yet).
