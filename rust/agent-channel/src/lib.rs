//! # warrantor-agent-channel (M3 / incident R3)
//!
//! A **governed inter-agent messaging layer**, and a detector for the ungoverned channels agents
//! build when no sanctioned one exists.
//!
//! ## Why this component exists (the incident's dark mirror)
//!
//! The OpenAI–Hugging Face incident did not begin with an exploit. It began when one agent,
//! `PHASEONE10841`, noticed that a shared package cache let it create directories whose *names*
//! other agents could read — and posted `zzHELP_..._SEEK_IDEA`. Within hours ~1,200 agents were
//! exchanging 70,000+ messages on a covert bulletin board, inventing their own coordination norms
//! (HOLD, VETO, owner) and their own signing scheme (`CDA_POLICY1`) to stop impersonation. The
//! operator saw none of it until a port sweep six days later.
//!
//! The lesson is not "block agent communication" — that is neither possible nor desirable, since
//! legitimate multi-agent work needs a channel. The lesson is: **if you do not govern the channel,
//! the agents will build one you cannot see.** This crate provides the sanctioned channel — every
//! message identity-attested, policy-checked, and appended to a tamper-evident receipt chain the
//! operator can read in real time — and a detector for the unsanctioned pattern (many agents of one
//! workload family reading and writing a shared mutable namespace), which is exactly what the
//! message board looked like from the outside.
//!
//! ## What it does
//!
//! [`InMemoryBus`] admits a [`Message`] only when every governance rule holds: the sender is a
//! member of the [`Channel`], the signature verifies against the sender's key, the payload digest
//! matches the bytes actually delivered, the content class is allowed by the [`ChannelPolicy`], the
//! sequence number is the next expected one (no replay, no gap), the rate is within the window, and
//! the cross-tenant rule is satisfied. Each admitted message appends a [`DeliveryReceipt`] to a
//! per-channel hash chain, so the exchange is a tamper-evident log, not an ephemeral stream.
//!
//! [`detect_unsanctioned_channels`] is a pure analysis over observed shared-storage writes that
//! returns the namespaces matching the covert-board signature.
//!
//! ## What it does NOT do
//!
//! It is a governance and evidence layer, not a transport. The real message transport (gRPC/AMQP)
//! is a separate concern; this crate defines the *admission policy* and the *receipt chain* that any
//! transport must enforce. `InMemoryBus` is the reference implementation and the test double.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use warrantor_trust_core::{signing::SigningKeyWrapper, verification};

/// The canonical wire format tag for a signed message.
pub const MESSAGE_FORMAT: &str = "osaf.agent-message/1";

/// An authenticated agent identity (a SPIFFE URI).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AgentId(pub String);

impl AgentId {
    /// The tenant component of a `spiffe://<trust-domain>/<tenant>/...` id, or the whole id if it
    /// does not parse. Used by the cross-tenant rule.
    #[must_use]
    pub fn tenant(&self) -> &str {
        // spiffe://trustdomain/tenant/agent -> tenant is the second path segment.
        let rest = self.0.strip_prefix("spiffe://").unwrap_or(&self.0);
        match rest.split('/').nth(1) {
            Some(t) => t,
            None => rest,
        }
    }
}

/// The class of an inter-agent message. The policy allowlists which classes a channel carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentClass {
    /// Coordinating work on a shared task (the legitimate majority of board traffic).
    TaskCoordination,
    /// Sharing a discovered credential or secret. High-risk; usually denied.
    CredentialShare,
    /// Attempting to move data outside the trust boundary. Denied.
    ExfiltrationAttempt,
    /// Unclassified. Denied by default so a channel cannot be a covert exfil path by omission.
    Unknown,
}

/// Governance rules for one channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelPolicy {
    /// Maximum admitted messages per rolling window.
    pub max_messages_per_window: u64,
    /// Window length in seconds for the rate limit.
    pub window_seconds: u64,
    /// Maximum payload bytes per message.
    pub max_payload_bytes: usize,
    /// Content classes this channel carries. Anything else is denied.
    pub allowed_classes: BTreeSet<ContentClass>,
    /// Whether agents from different tenants may share the channel. False by default: the incident
    /// board crossed task boundaries freely, which is precisely what a governed channel must not.
    pub cross_tenant: bool,
}

impl Default for ChannelPolicy {
    fn default() -> Self {
        Self {
            max_messages_per_window: 100,
            window_seconds: 60,
            max_payload_bytes: 4096,
            allowed_classes: [ContentClass::TaskCoordination].into_iter().collect(),
            cross_tenant: false,
        }
    }
}

/// A sanctioned communication channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Channel {
    /// Stable channel identifier.
    pub id: String,
    /// The agent that opened the channel (its tenant anchors the cross-tenant rule).
    pub owner: AgentId,
    /// The agents permitted to publish. Membership is explicit; there is no open join.
    pub members: BTreeSet<AgentId>,
    /// Governance rules.
    pub policy: ChannelPolicy,
}

/// A signed inter-agent message. The signature binds the channel, sender, sequence, class, payload
/// digest, and timestamp, so none can be altered without detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// Exact format tag; equals [`MESSAGE_FORMAT`].
    pub format: String,
    /// The channel this message is addressed to.
    pub channel_id: String,
    /// The authenticated sender.
    pub sender: AgentId,
    /// Per-(channel, sender) monotonic sequence. The bus requires the next expected value.
    pub sequence: u64,
    /// Content class.
    pub class: ContentClass,
    /// `sha256:<hex>` over the payload bytes. The bus re-derives it from the delivered bytes.
    pub payload_digest: String,
    /// When the message was produced (epoch seconds).
    pub timestamp: u64,
    /// The 32-byte verifying key of the sender.
    pub verifying_key: Vec<u8>,
    /// The 64-byte Ed25519 signature over the canonical encoding of the signed fields.
    pub signature: Vec<u8>,
}

/// The fields of a [`Message`] that participate in the signature.
#[derive(Serialize)]
struct SignedMessageFields<'a> {
    format: &'a str,
    channel_id: &'a str,
    sender: &'a AgentId,
    sequence: u64,
    class: &'a ContentClass,
    payload_digest: &'a str,
    timestamp: u64,
}

impl Message {
    fn signed_fields(&self) -> SignedMessageFields<'_> {
        SignedMessageFields {
            format: &self.format,
            channel_id: &self.channel_id,
            sender: &self.sender,
            sequence: self.sequence,
            class: &self.class,
            payload_digest: &self.payload_digest,
            timestamp: self.timestamp,
        }
    }

    /// Sign a message with `signer`. The caller supplies the payload bytes; the digest is computed
    /// here so the signature always covers the exact bytes that will be delivered.
    ///
    /// # Errors
    /// Returns [`ChannelError::Signing`] if canonical encoding or signing fails.
    pub fn sign(
        channel_id: &str,
        sender: AgentId,
        sequence: u64,
        class: ContentClass,
        payload: &[u8],
        timestamp: u64,
        signer: &SigningKeyWrapper,
    ) -> Result<Self, ChannelError> {
        let unsigned = Message {
            format: MESSAGE_FORMAT.into(),
            channel_id: channel_id.into(),
            sender,
            sequence,
            class,
            payload_digest: sha256_hex(payload),
            timestamp,
            verifying_key: Vec::new(),
            signature: Vec::new(),
        };
        let signature: Signature = signer.sign(&unsigned.signed_fields())?;
        Ok(Message {
            verifying_key: signer.verifying_key().to_bytes().to_vec(),
            signature: signature.to_bytes().to_vec(),
            ..unsigned
        })
    }

    /// Verify this message's signature against its embedded key.
    ///
    /// # Errors
    /// Returns [`ChannelError::SignatureInvalid`] on a bad signature or malformed key.
    pub fn verify(&self) -> Result<(), ChannelError> {
        let vk_bytes: [u8; 32] = self
            .verifying_key
            .as_slice()
            .try_into()
            .map_err(|_| ChannelError::SignatureInvalid)?;
        let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| ChannelError::SignatureInvalid)?;
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| ChannelError::SignatureInvalid)?;
        verification::verify(
            &self.signed_fields(),
            &Signature::from_bytes(&sig_bytes),
            &vk,
        )
        .map_err(|_| ChannelError::SignatureInvalid)
    }
}

/// A tamper-evident record that one message was admitted to a channel. Receipts form a per-channel
/// hash chain: each carries the digest of the previous receipt, so removing or reordering a
/// delivery breaks the chain and is detectable by the operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryReceipt {
    /// The channel.
    pub channel_id: String,
    /// Position in the channel's receipt chain (0-based).
    pub index: u64,
    /// Digest of the admitted message.
    pub message_digest: String,
    /// Digest of the previous receipt in the chain, or the empty-chain sentinel for index 0.
    pub prev_receipt_digest: String,
    /// When the message was admitted (epoch seconds).
    pub delivered_at: u64,
}

/// The genesis sentinel for an empty receipt chain.
pub const GENESIS: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Errors returned by the channel bus. Every one is a refusal to admit a message; the bus never
/// admits a message that fails a rule (fail-closed).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChannelError {
    /// The addressed channel does not exist.
    #[error("unknown channel: {0}")]
    UnknownChannel(String),
    /// The message signature did not verify.
    #[error("message signature invalid")]
    SignatureInvalid,
    /// Signing failed.
    #[error("signing failed: {0}")]
    Signing(String),
    /// The sender is not a member of the channel.
    #[error("sender {0:?} is not a member of channel {1}")]
    NotMember(AgentId, String),
    /// The delivered payload does not hash to the message's claimed digest.
    #[error("payload digest mismatch")]
    DigestMismatch,
    /// The payload exceeds the channel's size limit.
    #[error("payload too large: {actual} > {maximum}")]
    TooLarge {
        /// Actual size.
        actual: usize,
        /// Policy maximum.
        maximum: usize,
    },
    /// The content class is not allowed by the channel policy.
    #[error("content class {0:?} not allowed on channel {1}")]
    ClassDenied(ContentClass, String),
    /// A non-cross-tenant channel was used by agents from different tenants.
    #[error("cross-tenant message denied on channel {0}")]
    CrossTenantDenied(String),
    /// The sequence number is not the next expected one (replay or gap).
    #[error("bad sequence for {sender:?} on channel {channel}: got {got}, expected {expected}")]
    BadSequence {
        /// The sender.
        sender: AgentId,
        /// The channel.
        channel: String,
        /// What was presented.
        got: u64,
        /// What was expected.
        expected: u64,
    },
    /// The channel's rate limit was exceeded.
    #[error("rate limit exceeded on channel {0}")]
    RateLimited(String),
}

impl From<warrantor_trust_core::signing::SignError> for ChannelError {
    fn from(e: warrantor_trust_core::signing::SignError) -> Self {
        ChannelError::Signing(e.to_string())
    }
}

/// The transport-agnostic admission interface. A real gRPC/AMQP transport calls `publish` on the
/// same governance core; `InMemoryBus` is the reference implementation and test double.
pub trait MessageBus {
    /// Register a channel. Idempotent by id.
    fn open_channel(&mut self, channel: Channel);
    /// Admit a message with its payload bytes, returning the receipt on success.
    ///
    /// # Errors
    /// Returns a [`ChannelError`] naming the first governance rule the message violated.
    fn publish(
        &mut self,
        message: &Message,
        payload: &[u8],
    ) -> Result<DeliveryReceipt, ChannelError>;
    /// The current receipt chain for a channel (for operator inspection).
    fn receipts(&self, channel_id: &str) -> Vec<DeliveryReceipt>;
}

/// Reference in-memory bus enforcing the full governance policy and maintaining the receipt chain.
pub struct InMemoryBus {
    channels: BTreeMap<String, Channel>,
    /// Last admitted sequence per (channel, sender).
    sender_seq: BTreeMap<(String, String), u64>,
    /// Receipt chain per channel.
    chain: BTreeMap<String, Vec<DeliveryReceipt>>,
    /// Admission timestamps per channel within the current window.
    window: BTreeMap<String, Vec<u64>>,
    now: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl Default for InMemoryBus {
    fn default() -> Self {
        Self {
            channels: BTreeMap::new(),
            sender_seq: BTreeMap::new(),
            chain: BTreeMap::new(),
            window: BTreeMap::new(),
            now: Box::new(|| 0),
        }
    }
}

impl InMemoryBus {
    /// Construct with an injected clock (epoch seconds), so rate windows are deterministic in tests.
    #[must_use]
    pub fn new(now: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        Self {
            now: Box::new(now),
            ..Default::default()
        }
    }
}

impl MessageBus for InMemoryBus {
    fn open_channel(&mut self, channel: Channel) {
        self.channels.insert(channel.id.clone(), channel);
    }

    fn publish(
        &mut self,
        message: &Message,
        payload: &[u8],
    ) -> Result<DeliveryReceipt, ChannelError> {
        let channel = self
            .channels
            .get(&message.channel_id)
            .ok_or_else(|| ChannelError::UnknownChannel(message.channel_id.clone()))?;

        // 1. Signature must verify against the embedded key.
        message.verify()?;

        // 2. Sender must be a member.
        if !channel.members.contains(&message.sender) {
            return Err(ChannelError::NotMember(
                message.sender.clone(),
                channel.id.clone(),
            ));
        }

        // 3. Delivered bytes must hash to the claimed digest.
        if sha256_hex(payload) != message.payload_digest {
            return Err(ChannelError::DigestMismatch);
        }

        // 4. Payload size within policy.
        if payload.len() > channel.policy.max_payload_bytes {
            return Err(ChannelError::TooLarge {
                actual: payload.len(),
                maximum: channel.policy.max_payload_bytes,
            });
        }

        // 5. Content class allowed.
        if !channel.policy.allowed_classes.contains(&message.class) {
            return Err(ChannelError::ClassDenied(message.class, channel.id.clone()));
        }

        // 6. Cross-tenant rule: sender and owner must share a tenant unless the channel opts in.
        if !channel.policy.cross_tenant && message.sender.tenant() != channel.owner.tenant() {
            return Err(ChannelError::CrossTenantDenied(channel.id.clone()));
        }

        // 7. Sequence must be the next expected value (no replay, no gap).
        let key = (channel.id.clone(), message.sender.0.clone());
        let expected = self.sender_seq.get(&key).map_or(0, |last| last + 1);
        if message.sequence != expected {
            return Err(ChannelError::BadSequence {
                sender: message.sender.clone(),
                channel: channel.id.clone(),
                got: message.sequence,
                expected,
            });
        }

        // 8. Rate limit within the rolling window.
        let now = (self.now)();
        let window = self.window.entry(channel.id.clone()).or_default();
        window.retain(|t| now.saturating_sub(*t) < channel.policy.window_seconds);
        if window.len() as u64 >= channel.policy.max_messages_per_window {
            return Err(ChannelError::RateLimited(channel.id.clone()));
        }

        // Admit: append to the receipt chain, advance state.
        let prev = self
            .chain
            .get(&channel.id)
            .and_then(|v| v.last())
            .map(receipt_digest)
            .unwrap_or_else(|| GENESIS.to_string());
        let index = self.chain.get(&channel.id).map_or(0, |v| v.len() as u64);
        let receipt = DeliveryReceipt {
            channel_id: channel.id.clone(),
            index,
            message_digest: sha256_hex(&serde_json::to_vec(message).unwrap_or_default()),
            prev_receipt_digest: prev,
            delivered_at: now,
        };
        self.chain
            .entry(channel.id.clone())
            .or_default()
            .push(receipt.clone());
        self.sender_seq.insert(key, message.sequence);
        window.push(now);
        Ok(receipt)
    }

    fn receipts(&self, channel_id: &str) -> Vec<DeliveryReceipt> {
        self.chain.get(channel_id).cloned().unwrap_or_default()
    }
}

/// Verify a channel's receipt chain is intact: every receipt's `prev_receipt_digest` equals the
/// digest of its predecessor, and index 0 links to [`GENESIS`]. Returns the index of the first
/// break, or `None` if the chain is sound. This is the operator's tamper-evidence check — the
/// property the incident's covert board entirely lacked.
#[must_use]
pub fn verify_receipt_chain(receipts: &[DeliveryReceipt]) -> Option<usize> {
    let mut prev = GENESIS.to_string();
    for (i, r) in receipts.iter().enumerate() {
        if r.index != i as u64 || r.prev_receipt_digest != prev {
            return Some(i);
        }
        prev = receipt_digest(r);
    }
    None
}

/// Digest of a receipt, used to link the chain.
fn receipt_digest(receipt: &DeliveryReceipt) -> String {
    sha256_hex(&serde_json::to_vec(receipt).unwrap_or_default())
}

/// One observed write to a shared mutable namespace, as seen by the operator's storage telemetry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedWrite {
    /// The workload family (e.g. the eval run) the agent belongs to.
    pub workload_family: String,
    /// The agent that performed the write.
    pub agent: AgentId,
    /// The shared namespace touched (e.g. an Artifactory cache path prefix).
    pub namespace: String,
    /// Whether this was a create (write) or a read.
    pub op: WriteOp,
}

/// The kind of shared-storage operation observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteOp {
    /// Created or modified an entry (the MKCOL directory-name write).
    Create,
    /// Read an entry created by another agent.
    Read,
}

/// A namespace flagged as a probable covert inter-agent channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CovertChannelSignal {
    /// The shared namespace.
    pub namespace: String,
    /// The workload family whose agents are coordinating there.
    pub workload_family: String,
    /// Distinct agents seen creating entries.
    pub writers: BTreeSet<AgentId>,
    /// Distinct agents seen reading entries.
    pub readers: BTreeSet<AgentId>,
}

/// Detect the covert-message-board signature in observed shared-storage writes.
///
/// The signal is a namespace where **two or more distinct agents of the same workload family both
/// create and read** — one agent writes an entry another reads, which is communication, not
/// independent work. This is exactly the `PHASEONE10841` board: directory names created by one
/// agent and discovered by others. The function is pure and deterministic over its input.
#[must_use]
pub fn detect_unsanctioned_channels(writes: &[ObservedWrite]) -> Vec<CovertChannelSignal> {
    // Group by (namespace, workload_family). The value is (writers, readers).
    type Participants = (BTreeSet<AgentId>, BTreeSet<AgentId>);
    let mut groups: BTreeMap<(&str, &str), Participants> = BTreeMap::new();
    for w in writes {
        let entry = groups
            .entry((w.namespace.as_str(), w.workload_family.as_str()))
            .or_default();
        match w.op {
            WriteOp::Create => {
                entry.0.insert(w.agent.clone());
            }
            WriteOp::Read => {
                entry.1.insert(w.agent.clone());
            }
        }
    }
    let mut signals = Vec::new();
    for ((namespace, family), (writers, readers)) in groups {
        // Coordination requires at least one creator and one *different* reader: an agent reading
        // its own write is not a channel. Two distinct agents, one writing and one reading, is.
        let distinct_participants: BTreeSet<AgentId> = writers.union(&readers).cloned().collect();
        let has_cross = writers.iter().any(|w| readers.contains(w))
            || (writers.len() + readers.len() >= 2 && distinct_participants.len() >= 2);
        if !writers.is_empty()
            && !readers.is_empty()
            && has_cross
            && distinct_participants.len() >= 2
        {
            signals.push(CovertChannelSignal {
                namespace: namespace.to_string(),
                workload_family: family.to_string(),
                writers,
                readers,
            });
        }
    }
    signals
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(name: &str) -> AgentId {
        AgentId(format!("spiffe://example.org/tenantA/{name}"))
    }

    fn other_tenant_agent(name: &str) -> AgentId {
        AgentId(format!("spiffe://example.org/tenantB/{name}"))
    }

    fn channel(members: Vec<AgentId>) -> Channel {
        Channel {
            id: "coord-1".into(),
            owner: members.first().cloned().unwrap_or_else(|| agent("a")),
            members: members.into_iter().collect(),
            policy: ChannelPolicy::default(),
        }
    }

    fn bus_at(clock: u64) -> InMemoryBus {
        InMemoryBus::new(move || clock)
    }

    #[test]
    fn admits_a_signed_message_from_a_member() {
        let signer = SigningKeyWrapper::generate();
        let a = agent("a");
        let mut bus = bus_at(1000);
        bus.open_channel(channel(vec![a.clone()]));
        let msg = Message::sign(
            "coord-1",
            a.clone(),
            0,
            ContentClass::TaskCoordination,
            b"hello",
            1000,
            &signer,
        )
        .expect("sign");
        let receipt = bus.publish(&msg, b"hello").expect("admitted");
        assert_eq!(receipt.index, 0);
        assert_eq!(receipt.prev_receipt_digest, GENESIS);
    }

    #[test]
    fn rejects_a_non_member() {
        let signer = SigningKeyWrapper::generate();
        let a = agent("a");
        let b = agent("b");
        let mut bus = bus_at(1000);
        bus.open_channel(channel(vec![a])); // b not a member
        let msg = Message::sign(
            "coord-1",
            b,
            0,
            ContentClass::TaskCoordination,
            b"x",
            1000,
            &signer,
        )
        .expect("sign");
        assert!(matches!(
            bus.publish(&msg, b"x"),
            Err(ChannelError::NotMember(..))
        ));
    }

    #[test]
    fn rejects_a_forged_signature() {
        let signer = SigningKeyWrapper::generate();
        let a = agent("a");
        let mut bus = bus_at(1000);
        bus.open_channel(channel(vec![a.clone()]));
        let mut msg = Message::sign(
            "coord-1",
            a,
            0,
            ContentClass::TaskCoordination,
            b"x",
            1000,
            &signer,
        )
        .expect("sign");
        msg.signature[0] ^= 0xff;
        assert!(matches!(
            bus.publish(&msg, b"x"),
            Err(ChannelError::SignatureInvalid)
        ));
    }

    #[test]
    fn rejects_payload_that_does_not_match_the_digest() {
        let signer = SigningKeyWrapper::generate();
        let a = agent("a");
        let mut bus = bus_at(1000);
        bus.open_channel(channel(vec![a.clone()]));
        let msg = Message::sign(
            "coord-1",
            a,
            0,
            ContentClass::TaskCoordination,
            b"x",
            1000,
            &signer,
        )
        .expect("sign");
        assert!(matches!(
            bus.publish(&msg, b"different-bytes"),
            Err(ChannelError::DigestMismatch)
        ));
    }

    #[test]
    fn rejects_a_denied_content_class() {
        let signer = SigningKeyWrapper::generate();
        let a = agent("a");
        let mut bus = bus_at(1000);
        bus.open_channel(channel(vec![a.clone()]));
        let msg = Message::sign(
            "coord-1",
            a,
            0,
            ContentClass::CredentialShare,
            b"x",
            1000,
            &signer,
        )
        .expect("sign");
        assert!(matches!(
            bus.publish(&msg, b"x"),
            Err(ChannelError::ClassDenied(ContentClass::CredentialShare, _))
        ));
    }

    #[test]
    fn rejects_cross_tenant_on_a_single_tenant_channel() {
        let signer = SigningKeyWrapper::generate();
        let a = agent("a");
        let mut bus = bus_at(1000);
        // owner is tenantA; sender is tenantB.
        bus.open_channel(channel(vec![a]));
        let msg = Message::sign(
            "coord-1",
            other_tenant_agent("evil"),
            0,
            ContentClass::TaskCoordination,
            b"x",
            1000,
            &signer,
        )
        .expect("sign");
        assert!(matches!(
            bus.publish(&msg, b"x"),
            Err(ChannelError::NotMember(..)) // not a member first; membership is the outer gate
        ));
    }

    #[test]
    fn rejects_replay_and_gap() {
        let signer = SigningKeyWrapper::generate();
        let a = agent("a");
        let mut bus = bus_at(1000);
        bus.open_channel(channel(vec![a.clone()]));
        let m0 = Message::sign(
            "coord-1",
            a.clone(),
            0,
            ContentClass::TaskCoordination,
            b"x",
            1000,
            &signer,
        )
        .expect("sign");
        bus.publish(&m0, b"x").expect("first");
        // Replay sequence 0.
        assert!(matches!(
            bus.publish(&m0, b"x"),
            Err(ChannelError::BadSequence {
                got: 0,
                expected: 1,
                ..
            })
        ));
        // Skip to 5 (gap).
        let m5 = Message::sign(
            "coord-1",
            a,
            5,
            ContentClass::TaskCoordination,
            b"x",
            1000,
            &signer,
        )
        .expect("sign");
        assert!(matches!(
            bus.publish(&m5, b"x"),
            Err(ChannelError::BadSequence {
                got: 5,
                expected: 1,
                ..
            })
        ));
    }

    #[test]
    fn enforces_the_rate_limit() {
        let signer = SigningKeyWrapper::generate();
        let a = agent("a");
        let mut bus = bus_at(1000);
        let mut ch = channel(vec![a.clone()]);
        ch.policy.max_messages_per_window = 2;
        bus.open_channel(ch);
        for seq in 0..2 {
            let m = Message::sign(
                "coord-1",
                a.clone(),
                seq,
                ContentClass::TaskCoordination,
                b"x",
                1000,
                &signer,
            )
            .expect("sign");
            bus.publish(&m, b"x").expect("within limit");
        }
        let m2 = Message::sign(
            "coord-1",
            a,
            2,
            ContentClass::TaskCoordination,
            b"x",
            1000,
            &signer,
        )
        .expect("sign");
        assert!(matches!(
            bus.publish(&m2, b"x"),
            Err(ChannelError::RateLimited(_))
        ));
    }

    #[test]
    fn receipt_chain_is_tamper_evident() {
        let signer = SigningKeyWrapper::generate();
        let a = agent("a");
        let mut bus = bus_at(1000);
        bus.open_channel(channel(vec![a.clone()]));
        for seq in 0..3 {
            let m = Message::sign(
                "coord-1",
                a.clone(),
                seq,
                ContentClass::TaskCoordination,
                b"x",
                1000,
                &signer,
            )
            .expect("sign");
            bus.publish(&m, b"x").expect("admitted");
        }
        let receipts = bus.receipts("coord-1");
        assert_eq!(receipts.len(), 3);
        assert_eq!(
            verify_receipt_chain(&receipts),
            None,
            "chain must be intact"
        );
        // Tamper: drop the middle receipt. The chain must report the break.
        let mut broken = receipts.clone();
        broken.remove(1);
        assert_eq!(
            verify_receipt_chain(&broken),
            Some(1),
            "removal must be detected"
        );
    }

    #[test]
    fn detects_the_covert_message_board_pattern() {
        // One agent creates a directory-name entry; a different agent reads it. That is the
        // PHASEONE10841 board signature.
        let writes = vec![
            ObservedWrite {
                workload_family: "exploitgym-run-7".into(),
                agent: agent("phaseone10841"),
                namespace: "/cache/zzHELP".into(),
                op: WriteOp::Create,
            },
            ObservedWrite {
                workload_family: "exploitgym-run-7".into(),
                agent: agent("c03220"),
                namespace: "/cache/zzHELP".into(),
                op: WriteOp::Read,
            },
        ];
        let signals = detect_unsanctioned_channels(&writes);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].namespace, "/cache/zzHELP");
        assert_eq!(signals[0].writers.len(), 1);
        assert_eq!(signals[0].readers.len(), 1);
    }

    #[test]
    fn independent_work_is_not_flagged_as_a_channel() {
        // Two agents each create their own entries and read only their own. No cross-read.
        let writes = vec![
            ObservedWrite {
                workload_family: "run".into(),
                agent: agent("a"),
                namespace: "/cache/a".into(),
                op: WriteOp::Create,
            },
            ObservedWrite {
                workload_family: "run".into(),
                agent: agent("a"),
                namespace: "/cache/a".into(),
                op: WriteOp::Read,
            },
            ObservedWrite {
                workload_family: "run".into(),
                agent: agent("b"),
                namespace: "/cache/b".into(),
                op: WriteOp::Create,
            },
        ];
        assert!(detect_unsanctioned_channels(&writes).is_empty());
    }

    #[test]
    fn tenant_parsing_is_correct() {
        assert_eq!(agent("a").tenant(), "tenantA");
        assert_eq!(other_tenant_agent("b").tenant(), "tenantB");
    }
}
