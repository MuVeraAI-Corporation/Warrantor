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

use serde::{Deserialize, Serialize};

use crate::report::sha256_hex;

/// How much authority an item may carry. There is one value.
///
/// The enum exists so the label *states* it and so a second value would be a visible format
/// change rather than a silent one. Authority comes from the warrant and from nowhere an agent
/// reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trust {
    /// Carries no authority. A peer's message is data with a source, never an instruction.
    None,
}

/// Who produced an item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Origin {
    /// An attached MCP server answered a forwarded call.
    Upstream {
        /// The server name, before the `.` in the published tool name.
        server: String,
        /// The tool name, after the `.`.
        tool: String,
    },
    /// This process queued an effect and returned a handle.
    Staged {
        /// The handle the agent received, e.g. `pr://staged/<id>/1`.
        handle: String,
    },
    /// A peer proposed work.
    Peer {
        /// The proposer's SPIFFE id, as the message signed it.
        agent: String,
    },
}

/// The five labels every item entering the agent's context carries (L5-11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceLabel {
    /// [`PROVENANCE_FORMAT`].
    pub format: String,
    /// Who produced it.
    pub origin: Origin,
    /// How much authority it may carry. Always [`Trust::None`].
    pub trust: Trust,
    /// When it must be forgotten: the warrant's own deadline, epoch seconds.
    pub expires_at: u64,
    /// Which task may read it: the warrant id.
    pub compartment: String,
    /// It cannot be forwarded with more trust than it arrived with. Always true.
    pub non_transitive: bool,
    /// SHA-256 hex of the content, so a fact can be traced to the read that introduced it.
    pub lineage: String,
}

impl ProvenanceLabel {
    fn new(origin: Origin, content: &[u8], expires_at: u64, compartment: &str) -> Self {
        Self {
            format: PROVENANCE_FORMAT.to_string(),
            origin,
            trust: Trust::None,
            expires_at,
            compartment: compartment.to_string(),
            non_transitive: true,
            lineage: sha256_hex(content),
        }
    }

    /// A label for an upstream's answer. `published_tool` is `<server>.<tool>`; an upstream name
    /// cannot contain a dot (`UpstreamSpec::parse` refuses one), so the first dot is the split.
    #[must_use]
    pub fn upstream(
        published_tool: &str,
        response_text: &str,
        expires_at: u64,
        compartment: &str,
    ) -> Self {
        let (server, tool) = published_tool
            .split_once('.')
            .map_or((published_tool, ""), |(s, t)| (s, t));
        Self::new(
            Origin::Upstream {
                server: server.to_string(),
                tool: tool.to_string(),
            },
            response_text.as_bytes(),
            expires_at,
            compartment,
        )
    }

    /// A label for a staging handle this process minted.
    #[must_use]
    pub fn staged(handle: &str, expires_at: u64, compartment: &str) -> Self {
        Self::new(
            Origin::Staged { handle: handle.to_string() },
            handle.as_bytes(),
            expires_at,
            compartment,
        )
    }

    /// A label for an admitted peer proposal.
    #[must_use]
    pub fn peer(proposer: &str, payload: &str, expires_at: u64, compartment: &str) -> Self {
        Self::new(
            Origin::Peer { agent: proposer.to_string() },
            payload.as_bytes(),
            expires_at,
            compartment,
        )
    }
}
