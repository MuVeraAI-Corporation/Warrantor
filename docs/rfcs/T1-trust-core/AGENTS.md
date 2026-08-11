# AGENTS.md — T1 trust-core anti-patterns and gotchas

What **not** to do when building T1 trust-core. Each entry has bitten someone before.

## Cryptography

- ❌ **Don't** add a second crypto implementation in Python/TS/Go "for convenience." The Rust crate is
  the sole authority (stack-test kill criterion). Other languages call it via bindings.
- ❌ **Don't** use `serde_json` for canonical encoding — JSON key ordering is not deterministic
  cross-language. Use canonical CBOR.
- ❌ **Don't** derive signatures over a struct directly. Always canonicalize first, then sign the
  encoding's bytes.
- ❌ **Don't** log private keys, even at trace level. Reject them at ingestion.
- ❌ **Don't** use Rust's `Box<dyn Error>` — use `thiserror` so errors are typed and the wire format
  is stable.

## Testing

- ❌ **Don't** write tests that depend on wall-clock time. Inject a `Clock` trait.
- ❌ **Don't** skip the cross-language golden vectors — they are how we prove a Rust signature
  verifies in Python. Failing vectors = broken contract plane.
- ❌ **Don't** disable the cargo-fuzz targets "to speed up CI." They run in nightly CI for a reason.

## Wire format

- ❌ **Don't** hand-write protobuf messages — generate from `proto/warrantor/trust/v1/*.proto` via `buf
  generate`.
- ❌ **Don't** introduce a fourth protocol tier (only internal gRPC, external REST, async CloudEvents
  are allowed).

## Dependencies

- ❌ **Don't** add a crypto dependency without a security review (`ring`, `aws-lc-rs`,
  `rustls` are pre-approved; anything else needs an ADR).
- ❌ **Don't** pin a git dependency in `Cargo.toml` — use a version from crates.io or document why a
  git pin is unavoidable.

## Process

- ❌ **Don't** commit without `-s` (DCO). The CI bot will reject it.
- ❌ **Don't** merge without two reviewer approvals (one from the component owner).
- ❌ **Don't** cut a release tag without the SBOM attached.
