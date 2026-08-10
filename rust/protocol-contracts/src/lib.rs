//! AumOS P1-P12 generated bindings and fail-closed protocol validation.

mod generated;
mod validation;

pub use generated::*;
pub use validation::{canonical_signing_bytes, ErrorCode, ProtocolValidator, ValidationResult};
