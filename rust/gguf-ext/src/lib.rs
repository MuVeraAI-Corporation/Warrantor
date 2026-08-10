//! # warrantor-gguf-ext (S3)
//!
//! Bounded GGUF v3 parsing and rewriting plus the signed `osaf.safety.*` profile. Tensor bytes
//! are always streamed; parser-controlled allocation is explicitly budgeted; cryptographic
//! operations delegate to T1 trust-core.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod format;
mod profile;

pub use format::{
    inspect, payload_digest, GgufError, GgufInfo, GgufLimits, GgufType, GgufValue, MetadataEntry,
    TensorInfo, GGUF_VERSION,
};
pub use profile::{
    rewrite_path_with_profile, rewrite_with_profile, strip_safety, strip_safety_path, verify,
    ManifestSigner, ProfileError, SafetyManifest, SafetyManifestError, TrustCoreManifestSigner,
    VerifiedSafetyProfile, VerifyError, VerifyPolicy, SAFETY_PROFILE,
};
