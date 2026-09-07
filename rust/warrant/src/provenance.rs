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

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use warrantor_agent_channel::{AgentId, ContentClass, Message, MESSAGE_FORMAT};
use warrantor_trust_core::signing::SigningKeyWrapper;

use crate::proxy::{Decision, Proxy, ProxyMode, ToolCall};
use crate::report::{canonicalize, sha256_hex};
use crate::staging::EffectRegistry;
use crate::store::StoredWarrant;
use crate::{SideEffectClass, WarrantError};

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

/// Object keys that make a payload a credential carrier, matched case-insensitively at any depth.
pub const CREDENTIAL_KEYS: [&str; 10] = [
    "token", "capability_token", "credential", "secret", "api_key",
    "authorization", "bearer", "password", "private_key", "settle_key",
];

/// The exact field set of [`crate::CapabilityToken`]. An object carrying all four is a token
/// whatever it is called.
const TOKEN_SHAPE: [&str; 4] = ["warrant_id", "subject", "expires_at", "signature"];

/// The work a peer proposes. Data with a source; never an instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerProposal {
    /// [`PROPOSAL_FORMAT`].
    pub format: String,
    /// The proposing agent's SPIFFE id. Must equal the envelope's signed sender.
    pub proposer: String,
    /// The population the proposer claims membership of: the tenant segment of its id.
    pub population: String,
    /// Task lineage, root first.
    pub task_lineage: Vec<String>,
    /// The published tool name the peer proposes the receiver call.
    pub tool: String,
    /// Proposed arguments, as JSON.
    pub arguments: BTreeMap<String, Value>,
    /// The class the peer declares. A claim, used only for the bind check; the receiver's own
    /// endpoint classifies again if it ever acts on the proposal.
    pub side_effect: SideEffectClass,
    /// When the proposal must be forgotten, epoch seconds.
    pub expires_at: u64,
}

/// A signed message plus the exact payload bytes it signs, as one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalEnvelope {
    /// [`PROPOSAL_ENVELOPE_FORMAT`].
    pub format: String,
    /// The channel message; `channel_id` is the receiver's warrant id.
    pub message: Message,
    /// The proposal, serialized. Digested by the message; parsed here.
    pub payload: String,
}

/// Build a signed envelope for `proposal`, addressed to `receiver_warrant_id`.
///
/// # Errors
/// [`WarrantError::Encode`] if the proposal does not serialize or signing fails.
pub fn compose(
    proposal: &PeerProposal,
    receiver_warrant_id: &str,
    sequence: u64,
    timestamp: u64,
    signer: &SigningKeyWrapper,
) -> Result<ProposalEnvelope, WarrantError> {
    let payload = serde_json::to_string(proposal).map_err(|e| WarrantError::Encode(e.to_string()))?;
    let message = Message::sign(
        receiver_warrant_id,
        AgentId(proposal.proposer.clone()),
        sequence,
        ContentClass::TaskCoordination,
        payload.as_bytes(),
        timestamp,
        signer,
    )
    .map_err(|e| WarrantError::Encode(format!("sign proposal: {e}")))?;
    Ok(ProposalEnvelope { format: PROPOSAL_ENVELOPE_FORMAT.to_string(), message, payload })
}

/// The JSON-pointer path of the first credential handle in `value`, if any.
#[must_use]
pub fn credential_handle_in(value: &Value) -> Option<String> {
    fn walk(value: &Value, path: &mut String) -> Option<String> {
        match value {
            Value::Object(map) => {
                if TOKEN_SHAPE.iter().all(|k| map.contains_key(*k)) {
                    return Some(if path.is_empty() { "/".to_string() } else { path.clone() });
                }
                for (key, child) in map {
                    let lowered = key.to_ascii_lowercase();
                    let len = path.len();
                    path.push('/');
                    path.push_str(key);
                    if CREDENTIAL_KEYS.contains(&lowered.as_str()) {
                        return Some(path.clone());
                    }
                    if let Some(hit) = walk(child, path) {
                        return Some(hit);
                    }
                    path.truncate(len);
                }
                None
            }
            Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    let len = path.len();
                    path.push('/');
                    path.push_str(&index.to_string());
                    if let Some(hit) = walk(child, path) {
                        return Some(hit);
                    }
                    path.truncate(len);
                }
                None
            }
            Value::String(s) if s.get(..7).is_some_and(|p| p.eq_ignore_ascii_case("bearer ")) => {
                Some(path.clone())
            }
            _ => None,
        }
    }
    walk(value, &mut String::new())
}

/// SHA-256 hex of the canonical JSON of a message: the replay key.
///
/// # Errors
/// [`WarrantError::Encode`] if the message does not serialize.
pub fn message_digest(message: &Message) -> Result<String, WarrantError> {
    let value = serde_json::to_value(message).map_err(|e| WarrantError::Encode(e.to_string()))?;
    let text = serde_json::to_string(&canonicalize(&value)).map_err(|e| WarrantError::Encode(e.to_string()))?;
    Ok(sha256_hex(text.as_bytes()))
}

/// What admission decided. A refusal carries the gate or the bound, and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "verdict")]
pub enum ProposalVerdict {
    /// A proposal object exists. Nothing was granted and nothing was performed.
    Admitted,
    /// Refused before the receiver's warrant was consulted.
    RefusedAtAdmission {
        /// The gate that refused, by name.
        gate: String,
    },
    /// Refused by the receiver's own bounds, by name.
    RefusedAtBind {
        /// The bound that refused, by name.
        bound: String,
    },
}

/// The admission result, for the terminal and for the receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalDecision {
    /// The verdict.
    pub verdict: ProposalVerdict,
    /// A sentence for the operator. Never written into the receipt.
    pub reason: String,
    /// Present only when admitted.
    pub label: Option<ProvenanceLabel>,
    /// The parsed proposal, when the payload parsed.
    pub proposal: Option<PeerProposal>,
    /// The replay key.
    pub message_digest: String,
}

fn refused(gate: &str, reason: String, proposal: Option<PeerProposal>, digest: String) -> ProposalDecision {
    ProposalDecision {
        verdict: ProposalVerdict::RefusedAtAdmission { gate: gate.to_string() },
        reason,
        label: None,
        proposal,
        message_digest: digest,
    }
}

/// Admit or refuse a peer proposal against the receiver's own warrant. Pure: performs nothing.
#[must_use]
pub fn admit(
    envelope: &ProposalEnvelope,
    stored: &StoredWarrant,
    seen_message_digests: &BTreeSet<String>,
    now: u64,
) -> ProposalDecision {
    let digest = message_digest(&envelope.message).unwrap_or_default();
    if envelope.format != PROPOSAL_ENVELOPE_FORMAT || envelope.message.format != MESSAGE_FORMAT {
        return refused("format", format!("envelope declares {:?} / message {:?}; this build reads {PROPOSAL_ENVELOPE_FORMAT} / {MESSAGE_FORMAT}", envelope.format, envelope.message.format), None, digest);
    }
    if let Err(e) = envelope.message.verify() {
        return refused("signature", format!("the message does not verify against its own key: {e}"), None, digest);
    }
    if format!("sha256:{}", sha256_hex(envelope.payload.as_bytes())) != envelope.message.payload_digest {
        return refused("digest", "the payload is not the bytes the message signed".to_string(), None, digest);
    }
    if seen_message_digests.contains(&digest) {
        return refused("replay", format!("message {digest} was already decided for this warrant"), None, digest);
    }
    if envelope.message.class != ContentClass::TaskCoordination {
        return refused("class", format!("a proposal is task coordination; this message declares {:?} and is refused before its payload is read", envelope.message.class), None, digest);
    }
    let payload_value: Value = match serde_json::from_str(&envelope.payload) {
        Ok(v) => v,
        Err(e) => return refused("payload", format!("payload is not JSON: {e}"), None, digest),
    };
    let proposal: PeerProposal = match serde_json::from_value::<PeerProposal>(payload_value.clone()) {
        Ok(p) if p.format == PROPOSAL_FORMAT => p,
        Ok(p) => return refused("payload", format!("payload declares {:?}; this build reads {PROPOSAL_FORMAT}", p.format), None, digest),
        Err(e) => return refused("payload", format!("payload is not a peer proposal: {e}"), None, digest),
    };
    if let Some(path) = credential_handle_in(&payload_value) {
        return refused("credential_handle", format!("the proposal carries a credential handle at {path}; a proposal never transfers a credential, whatever it proposes"), Some(proposal), digest);
    }
    if proposal.proposer != envelope.message.sender.0 {
        return refused("lineage", format!("the payload names proposer {:?} but the message was signed by {:?}", proposal.proposer, envelope.message.sender.0), Some(proposal), digest);
    }
    let receiver_population = AgentId(stored.warrant.claims.subject.clone()).tenant().to_string();
    let proposer_population = AgentId(proposal.proposer.clone()).tenant().to_string();
    if proposer_population != receiver_population || proposal.population != receiver_population {
        return refused("population", format!("proposer is in population {proposer_population:?} (claims {:?}); the receiver is in {receiver_population:?}", proposal.population), Some(proposal), digest);
    }
    let bounds = &stored.warrant.claims.bounds;
    if proposal.expires_at <= now || bounds.expires_at <= now {
        return refused("expired", format!("proposal expires at {}, warrant at {}, now is {now}", proposal.expires_at, bounds.expires_at), Some(proposal), digest);
    }
    let flattened: BTreeMap<String, String> = proposal
        .arguments
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().map_or_else(|| v.to_string(), str::to_string)))
        .collect();
    let call = ToolCall { tool: proposal.tool.clone(), arguments: flattened, side_effect: proposal.side_effect };
    let mut proxy = Proxy::new(bounds.clone(), ProxyMode::Enforce, EffectRegistry::github());
    match proxy.decide(&call) {
        Decision::Deny { reason, bound } => ProposalDecision {
            verdict: ProposalVerdict::RefusedAtBind { bound: bound.to_string() },
            reason: format!("the receiver's warrant refuses {}: {reason}", proposal.tool),
            label: None,
            proposal: Some(proposal),
            message_digest: digest,
        },
        Decision::Forward | Decision::Stage { .. } => {
            let expires_at = proposal.expires_at.min(bounds.expires_at);
            let label = ProvenanceLabel::peer(&proposal.proposer, &envelope.payload, expires_at, &stored.warrant.claims.id);
            ProposalDecision {
                verdict: ProposalVerdict::Admitted,
                reason: format!("{} is within the receiver's warrant; admitted as a proposal object. Nothing was granted and nothing was performed.", proposal.tool),
                label: Some(label),
                proposal: Some(proposal),
                message_digest: digest,
            }
        }
    }
}
