//! Provenance labels and peer-proposal admission (L5-11, L5-12).
//!
//! Two halves, one rule: **nothing an agent reads carries authority.** Every result the agent
//! endpoint forwards or stages carries a `warrantor.provenance/1` label — origin, trust (always
//! `none`), expiry, compartment, non-transitive — beside the content, never inside it. A peer
//! proposal is signed data naming work it would like done; admission binds it against the
//! receiver's own warrant through the same `Proxy::decide` every real call faces, refuses any
//! credential handle before scope is read, and receipts the decision as a MSG-syscall,
//! DELEGATE-class record either way. Admission grants nothing, performs nothing, and widens
//! nothing.

/// The label wire format.
pub const PROVENANCE_FORMAT: &str = "warrantor.provenance/1";
/// The proposal payload wire format.
pub const PROPOSAL_FORMAT: &str = "warrantor.peer-proposal/1";
/// The signed-envelope wire format: a channel message plus the exact payload bytes.
pub const PROPOSAL_ENVELOPE_FORMAT: &str = "warrantor.peer-proposal-envelope/1";
/// The receipt wire format.
pub const PROPOSAL_RECEIPT_FORMAT: &str = "warrantor.proposal-receipt/1";
/// The export format `warrantor verify` dispatches on.
pub const PROPOSAL_EXPORT_FORMAT: &str = "warrantor.proposal-export/1";
/// The word the receipt spells the syscall as: a proposal is a message (Task 2.1's registry
/// spells the message syscall `msg`; the constant keeps the format stable until then).
pub const MSG_SYSCALL: &str = "msg";
/// L5-12: accepting a proposal is a DELEGATE-class decision, because it is authority-shaped
/// even though it grants nothing.
pub const DELEGATE_DECISION_CLASS: &str = "delegate";
