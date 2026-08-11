# S3 — `gguf-ext` RFC

> A bounded GGUF v3 reader/writer and signed `osaf.safety.*` metadata profile for carrying
> verifiable model-safety, provenance, and admission information without changing tensor values.

| Field | Value |
|---|---|
| **Canonical ID** | S3 |
| **Name** | gguf-ext |
| **Wave** | 3 |
| **Languages** | Rust |
| **DefStack origin** | C2.4 GGUF-Ext |
| **Dependencies** | T1 trust-core, P6 AI Artifact Trust Manifest |
| **Upstream format** | GGUF v3 (`ggml-org/ggml` and `ggml-org/llama.cpp`) |

## Background

GGUF is the deployment format used by GGML-based executors such as llama.cpp. GGUF v3 stores a
typed key/value metadata table before tensor descriptors and aligned tensor bytes. Upstream permits
community metadata when keys use a collision-resistant namespace. AumOS uses the
`osaf.safety.*` namespace to bind a model's immutable tensor content and execution-relevant
metadata to a signed safety manifest.

This component is deliberately an extension, not a fork of GGUF. Files without AumOS metadata stay
valid GGUF files. Unaware runtimes may ignore the namespaced keys. A security-enforcing runtime must
use S3 or an independently conformant implementation to validate the profile before admission.

Authoritative upstream references:

- `https://github.com/ggml-org/ggml/blob/master/docs/gguf.md`
- `https://github.com/ggml-org/llama.cpp/blob/master/ggml/include/gguf.h`

## Goals and Non-Goals

**Goals**

- Parse GGUF v3 metadata and tensor descriptors with explicit bounds and resource limits.
- Preserve all unknown upstream/community metadata and tensor bytes during rewrite.
- Add, replace, inspect, and remove only the `osaf.safety.*` profile as an atomic operation.
- Compute a deterministic model payload digest that excludes the self-referential signature fields
  while binding every non-AumOS metadata value, tensor descriptor, and tensor byte.
- Sign and verify the canonical safety manifest through T1-owned Ed25519 primitives.
- Reject duplicate keys, invalid UTF-8/ASCII metadata keys, unsupported nesting, size overflows,
  malformed alignment, overlapping tensor ranges, digest mismatch, and invalid signatures.
- Provide negative/adversarial vectors and round-trip fixtures consumable by llama.cpp.

**Non-Goals**

- Reimplementing inference, quantization, tokenizer behavior, or architecture-specific validation.
- Defining a second signing implementation outside T1 trust-core.
- Claiming that signed metadata makes an unsafe model safe; it only makes declared evidence and
  artifact identity verifiable.
- Silently repairing malformed GGUF files.

## Detailed Design

### Supported container boundary

The first stable release accepts GGUF version 3 in little-endian form. It validates the `GGUF`
magic, version, tensor count, metadata count, value tags, lengths, alignment, tensor descriptor
bounds, and the start/end of the tensor data region before allocating value buffers. Big-endian
files return a typed `UnsupportedEndianness` error until upstream provides an unambiguous marker.

Default limits are fail-closed and caller-configurable only downward or by an explicit trusted
policy: 65,535-byte metadata keys, 16 MiB strings, 1,000,000 array elements, nesting depth 8,
1,000,000 metadata pairs, 1,000,000 tensors, and checked 64-bit arithmetic throughout.

### Metadata profile

All stable profile keys are lowercase ASCII hierarchical keys:

| Key | GGUF type | Required | Meaning |
|---|---|---|---|
| `osaf.safety.profile` | string | yes | Exact profile identifier `osaf.gguf.safety/1`. |
| `osaf.safety.manifest` | string | yes | RFC 8785 canonical JSON P6 manifest. |
| `osaf.safety.manifest_sha256` | string | yes | Lowercase `sha256:<64 hex>` digest of the canonical manifest bytes. |
| `osaf.safety.payload_sha256` | string | yes | Lowercase digest of the normalized model payload defined below. |
| `osaf.safety.signature_algorithm` | string | yes | `ed25519` in profile version 1. |
| `osaf.safety.verifying_key` | string | yes | Lowercase 32-byte Ed25519 public key encoded as 64 hex characters. |
| `osaf.safety.signature` | string | yes | Lowercase 64-byte Ed25519 signature encoded as 128 hex characters. |
| `osaf.safety.issued_at` | uint64 | yes | Unix epoch seconds copied into the signed manifest. |
| `osaf.safety.expires_at` | uint64 | no | Unix epoch seconds; absence means policy decides maximum age. |

Unknown `osaf.safety.*` keys are rejected for profile version 1 so a verifier cannot ignore a
security-relevant extension. Non-AumOS unknown keys are preserved byte-for-byte at the semantic
value level.

### Normalized payload digest

The payload digest is SHA-256 over a length-delimited canonical stream with domain separator
`AUMOS-GGUF-PAYLOAD-V1\0`. It includes:

1. GGUF structural version and effective alignment.
2. Every non-`osaf.safety.*` metadata entry sorted by raw key bytes, encoded as key length/key,
   value type, and a recursively length-delimited canonical value.
3. Every tensor descriptor in file order: name, dimensions, GGML type, and relative offset.
4. The exact aligned tensor-data byte region in file order.

Integer encodings are fixed-width little-endian; floats are hashed by IEEE-754 bit pattern; booleans
are exactly `0` or `1`; strings are raw UTF-8 bytes with unsigned 64-bit lengths. NaN payload bits
are preserved. The digest therefore remains stable when safety metadata is inserted or replaced,
but changes when ordinary model metadata, tensor layout, or tensor bytes change.

The Ed25519 signature input is the domain separator `AUMOS-GGUF-SAFETY-SIGNATURE-V1\0` followed by
the 32-byte payload digest, the 32-byte manifest digest, and the eight-byte little-endian
`issued_at`. `expires_at` and every other policy-relevant statement must also appear inside the
canonical signed P6 manifest.

### Rewrite behavior

Rewriting builds a new temporary file in the destination directory, writes the validated header,
metadata, and tensor descriptors, emits zero padding to the effective alignment, streams the
original tensor data, flushes and syncs, then atomically renames. The library never mutates a model
in place. It refuses input/output aliasing unless atomic replacement was explicitly requested.

## Dependencies

- **T1 trust-core:** Ed25519 signing/verification and canonical cryptographic policy.
- **P6 AATM:** manifest semantics for model, dataset, prompt, policy, license, provenance, and SBOM
  relationships.
- **Upstream GGUF v3:** binary structure and metadata type registry.
- **Rust standard library:** bounded streaming I/O; no unsafe parser code.

## Threat Model

| Threat | Required mitigation |
|---|---|
| Length/count allocation bomb | Validate configured limits and checked arithmetic before allocation. |
| Duplicate-key ambiguity | Reject duplicate metadata keys, including duplicate safety keys. |
| Pathological nested arrays | Enforce depth and element limits before recursive decode. |
| Tensor overlap/out-of-bounds | Validate aligned relative ranges against the actual tensor data region. |
| Metadata substitution | Payload digest binds every non-safety metadata value and descriptor. |
| Tensor substitution | Stream every tensor-data byte into the payload digest. |
| Signature wrapping/downgrade | Exact profile/algorithm values; unknown safety keys fail; domain separation. |
| Time rollback | Verifier accepts an injected trusted clock and policy-defined skew/maximum age. |
| Partial/corrupt rewrite | Same-directory temporary file, flush/sync, atomic replace, original retained on error. |
| Parser differential | Golden malformed fixtures run against S3 and upstream llama.cpp tooling. |

## API

The Rust API uses explicit dependency injection for cryptographic and time boundaries:

```rust
pub struct GgufLimits { /* bounded parser limits */ }
pub struct SafetyManifest { /* canonical JSON plus issued/expiry metadata */ }
pub struct VerifiedSafetyProfile { /* digests, signer key, time validity */ }

pub trait ManifestSigner {
    fn verifying_key(&self) -> [u8; 32];
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignError>;
}

pub fn inspect<R: Read + Seek>(reader: R, limits: &GgufLimits) -> Result<GgufInfo, GgufError>;
pub fn payload_digest<R: Read + Seek>(reader: R, limits: &GgufLimits) -> Result<[u8; 32], GgufError>;
pub fn verify<R: Read + Seek>(reader: R, policy: &VerifyPolicy) -> Result<VerifiedSafetyProfile, VerifyError>;
pub fn rewrite_with_profile<R: Read + Seek, W: Write + Seek>(
    input: R,
    output: W,
    manifest: &SafetyManifest,
    signer: &dyn ManifestSigner,
    limits: &GgufLimits,
) -> Result<(), GgufError>;
```

The CLI exposes `gguf-ext inspect`, `gguf-ext digest`, `gguf-ext sign`, `gguf-ext verify`, and
`gguf-ext strip-safety`. Machine output is versioned JSON; human output is opt-in.

## Testing

- Unit tests cover every scalar/array type, limit, duplicate, alignment, overflow, digest, time,
  algorithm, and signature branch.
- Golden vectors under `testvectors/S3/` include valid, tampered tensor, tampered metadata,
  duplicate-key, truncated, oversize, overlap, unknown-safety-key, expired, and bad-signature cases.
- Property tests assert parse/write/parse semantic equivalence and unchanged tensor bytes.
- Fuzz targets cover header/metadata parsing and complete-file verification with bounded memory.
- Interoperability tests load rewritten fixtures with upstream llama.cpp/gguf tooling and ensure
  non-AumOS metadata remains unchanged.
- Performance evidence reports streaming throughput and peak memory on multi-gigabyte fixtures;
  implementation must not buffer tensor data in memory.

## Deployment

S3 is a library and CLI, not a network service. Release artifacts include Cargo package/source,
signed platform binaries, CycloneDX SBOM, SLSA provenance, checksums, the full vector corpus, and
offline verification instructions. Runtime admission integrates S3 verification through S3's
typed API; it must reject missing/invalid profiles when policy requires the safety extension.

## Reference implementation status (2026-08-09)

[`rust/gguf-ext`](../../rust/gguf-ext) now provides:

- allocation-budgeted GGUF v3 parsing for every metadata scalar and nested homogeneous arrays;
- exact boolean/UTF-8/key/alignment validation and tensor types documented upstream through type
  39, including quantization block-shape and byte-size checks;
- duplicate metadata/tensor rejection, zero/oversize dimension rejection, checked arithmetic,
  zero padding, aligned offsets, range bounds, and overlap detection;
- a streaming normalized payload digest that excludes only `osaf.safety.*` and binds the exact
  tensor-data region;
- RFC 8785 manifest validation through `serde_jcs` 0.2.0, required P6 binding fields, T1-owned raw
  Ed25519 signing/verification, digest/time/profile/algorithm checks, and unknown safety-key denial;
- bounded stream rewrite, same-directory temporary-file persistence for path mutation, atomic
  profile replacement/removal, and a JSON-first `gguf-ext` CLI whose signing key is read from
  standard input rather than an argument;
- 17 unit/property/adversarial tests, a fixed cross-language seed corpus at
  [`testvectors/S3`](../../testvectors/S3), and two bounded cargo-fuzz targets.

Local unit tests and strict Clippy pass. `cargo-fuzz` is not installed in the current evidence
environment, so the harnesses have not been executed here. Upstream llama.cpp round-trip, live
multi-gigabyte peak-memory/throughput evidence, independent review, coverage percentage, release
SBOM/SLSA artifacts, and published binary compatibility remain open release gates. Source and
local tests must not be reported as those proofs.

## Milestones

| Milestone | Acceptance |
|---|---|
| MVP | Bounded GGUF v3 metadata/tensor parser, normalized payload digest, valid and malformed fixtures. |
| Alpha | Atomic profile rewrite, injected T1 signer, verification policy, CLI, adversarial vectors. |
| Beta | Upstream llama.cpp round trip, fuzz corpus, streaming performance and memory evidence. |
| v1.0 | Independent review, signed release/SBOM/provenance, compatibility policy and retained TCK evidence. |

## Cross-references

- [`../00-reconciliation-matrix.md`](../00-reconciliation-matrix.md)
- [`S1-safe-tensors-pp.md`](S1-safe-tensors-pp.md)
- [`S4-model-sbom.md`](S4-model-sbom.md)
- [`T1-trust-core.md`](T1-trust-core.md)
- [`../../specs/protocols/P6-aatm.md`](../../specs/protocols/P6-aatm.md)
