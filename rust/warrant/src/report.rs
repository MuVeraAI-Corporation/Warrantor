//! The report bundle: one serialisable object behind every rendering of `warrantor report`, and
//! the thing that gets signed.
//!
//! # Why a bundle exists at all
//!
//! Before this module the report was `println!` straight to stdout, in two divergent
//! implementations (the CLI and the MCP control endpoint). Prose cannot be signed, cannot be
//! diffed, and cannot be handed to a third party who was not standing at the terminal. So the five
//! sections are built once into [`ReportBundle`], the two prose renderings are derived *from* the
//! bundle, and the signatures cover the same bytes the prose describes. The human output is
//! unchanged — this is additive.
//!
//! # What the signatures actually prove
//!
//! Two receipts, from two crates, over the same bundle digest:
//!
//! * [`warrantor_notary`] decides — nine gates, in order, short-circuiting — whether this warrant
//!   still holds the authority its staged effects would need. Its receipt carries that verdict.
//! * [`warrantor_evidence`] wraps the whole thing in a WAR receipt whose predicate names the
//!   actor, the authority chain, the decision (taken *from* the notary, never invented here), the
//!   operation and the outcome.
//!
//! A third party with the exported file and nothing else runs [`verify_export`]: it recomputes the
//! bundle digest, verifies both Ed25519 signatures, recomputes the authority intersection, and
//! checks that every binding between the receipts and the bundle holds.
//!
//! It proves **who signed and that nothing changed since**. It does not prove the signer is
//! trustworthy — that key has to be established out of band, and [`verify_export`] says so rather
//! than implying otherwise.
//!
//! # What it deliberately does not claim
//!
//! Every gate this deployment cannot actually evaluate is listed in [`ReportBundle::limitations`]
//! in plain language, and the enforcement mode on both receipts is the weaker of the two available
//! variants — `advisory` on the evidence receipt, `observed` on the notary receipt. Warrantor's
//! decision does not sit in the execution path of a coding agent that declines to use the proxy,
//! and a receipt that said `mediated` would be claiming it does. See [`report_modes`].
//!
//! # Why both crates export a `WarReceipt` and neither was renamed
//!
//! `warrantor-evidence` and `warrantor-notary` each export `WarReceipt`, `EnforcementMode`,
//! `DelegationLink`, `Verdict`, `Actor`, `Operation`, `ConsequenceTier` and `SignatureEnvelope`.
//! Same names, different shapes — an evidence receipt has a `predicate`, a notary receipt has a
//! `body`. They are two records of two different things: the notary's is the *decision*, the
//! evidence crate's is the *envelope around the whole action*. Both are correct names in their own
//! crate, and both crates are published at 1.0.
//!
//! Nothing here is renamed, because a rename would not remove a hazard that exists. Substituting
//! one for the other is a type error, not a silent bug: the shapes share no field, so every wrong
//! use is a compile failure. This module keeps them straight by importing the crates as
//! `evidence` and `notary` and never bare-importing a type from either, so every use site names
//! which world it is in. That is a legibility rule, not a safety mechanism — the compiler is the
//! safety mechanism.
//!
//! Two real hazards *did* survive the type system, and both are handled in code rather than prose:
//!
//! * The two [`EnforcementMode`](evidence::EnforcementMode)s share the token `mediated` and
//!   disagree about the other variant (`advisory` against `observed`), so JSON alone cannot say
//!   which crate a mode came from. [`notary_mode_for`] pins the correspondence in an exhaustive
//!   `match`, and [`report_modes`] derives one mode from the other rather than stating both.
//! * Both [`DelegationLink`](evidence::DelegationLink)s are built here, from the same warrant, in
//!   two places about eighty lines apart. If one drifts, the notary decides on a window the
//!   evidence receipt does not record. The exported receipt's link is checked against the bundle
//!   by test.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use warrantor_evidence as evidence;
use warrantor_notary as notary;

use crate::revoke::{RevocationLatency, RevocationSource, RevocationStore};
use crate::spend::SpendSection;
use crate::staging::StagingQueue;
use crate::store::StoredWarrant;
use crate::worktree::Worktree;
use crate::{
    bound_strengths, BoundStrength, Warrant, WarrantBounds, WarrantState, IDENTITY_REVOCATION_SLA,
};

/// How many verdicts this process has computed, across every call to [`build_observed`].
///
/// Exists so that `adjudications_between` in [`RevocationLatency`] is a **counted** number rather
/// than an assumed zero. Process-global because that is the true scope of the fact it records: the
/// question is how many actions this process adjudicated between a revocation reaching disk and the
/// first read that saw it, and that has nothing to do with which store the read went through.
static ADJUDICATIONS: AtomicU64 = AtomicU64::new(0);

/// How many verdicts this process has computed so far.
///
/// Monotone, and reset by nothing but process exit. It counts adjudications, not actions: an agent
/// that acts without asking for a verdict is not counted here, and cannot be.
#[must_use]
pub fn adjudications_computed() -> u64 {
    ADJUDICATIONS.load(Ordering::SeqCst)
}

/// Wire format of [`ReportBundle`]. Present from the first release so a later change to the shape
/// is detectable rather than silently misparsed.
pub const REPORT_BUNDLE_FORMAT: &str = "warrantor.report-bundle/1";

/// Wire format of [`SignedReport`], the self-contained file `--export` writes.
pub const REPORT_EXPORT_FORMAT: &str = "warrantor.report-export/1";

/// The operation class recorded in both receipts. A read, not an action.
pub const REPORT_OPERATION_CLASS: &str = "warrant.report";

/// How much clock skew the notary's freshness gate tolerates, in seconds.
///
/// The request timestamp and the context's `now` are the same value here — the report is generated
/// in one process from one clock read — so this window is slack for nothing in particular. It is
/// stated rather than left at zero because a zero window would look like a freshness guarantee this
/// deployment does not provide: there is no replay store, so the gate has nothing to compare
/// against.
pub const FRESHNESS_WINDOW_SECONDS: u64 = 300;

/// The one place the two enforcement-mode vocabularies are mapped onto each other.
///
/// [`warrantor_evidence::EnforcementMode`] is `{Mediated, Advisory}`;
/// [`warrantor_notary::EnforcementMode`] is `{Observed, Mediated}`. They are the same two states
/// under two names: `advisory` and `observed` both mean *the host may ignore the verdict*, and
/// `mediated` means *bypassing warrantor means bypassing execution* in both crates. Neither maps
/// onto [`BoundStrength`] by a cast.
///
/// The mapping is a function rather than a comment so it cannot rot: the `match` is exhaustive, so
/// a variant added to `warrantor-evidence` stops this crate compiling instead of silently falling
/// through to a mode nobody chose. It only ever maps a mode onto its equal — there is no arm that
/// turns a weak mode into a strong one, which is the direction that would matter.
#[must_use]
pub fn notary_mode_for(mode: evidence::EnforcementMode) -> notary::EnforcementMode {
    match mode {
        evidence::EnforcementMode::Mediated => notary::EnforcementMode::Mediated,
        evidence::EnforcementMode::Advisory => notary::EnforcementMode::Observed,
    }
}

/// The enforcement modes a report's receipts carry, and the reason they are the weak variants.
///
/// One mode is chosen, in one vocabulary; the other is *derived* through [`notary_mode_for`] so
/// the two receipts on a single report cannot come to disagree about the same fact.
///
/// Warrantor mediates a tool call that traverses its MCP proxy. It does not mediate an agent that
/// opens a socket, spawns a shell, or calls a model provider directly — there is no network
/// namespace, no seccomp filter and no firewall anywhere in this system. A receipt claiming
/// `mediated` would be asserting non-bypassability that does not exist, so a report claims neither.
#[must_use]
pub fn report_modes() -> (evidence::EnforcementMode, notary::EnforcementMode) {
    let evidence_mode = evidence::EnforcementMode::Advisory;
    (evidence_mode, notary_mode_for(evidence_mode))
}

// ── errors ────────────────────────────────────────────────────────────────────────────

/// Everything that can go wrong building, signing or verifying a report bundle.
#[derive(Debug, Error)]
pub enum ReportError {
    /// Serialisation failed.
    #[error("encode report: {0}")]
    Encode(String),
    /// A format identifier is not one this build understands.
    #[error("unknown format {found:?}; this build speaks {expected}")]
    Format {
        /// What was in the file.
        found: String,
        /// What this build writes.
        expected: &'static str,
    },
    /// The bundle's bytes do not hash to the digest the receipts were issued over.
    #[error("bundle digest mismatch: receipts cover {expected}, the bundle hashes to {actual}")]
    Digest {
        /// The digest the receipts commit to.
        expected: String,
        /// The digest the bundle actually has now.
        actual: String,
    },
    /// The notary receipt failed verification.
    #[error("notary receipt: {0}")]
    Notary(String),
    /// The evidence receipt failed verification.
    #[error("evidence receipt: {0}")]
    Evidence(String),
    /// A receipt verifies on its own but does not describe this bundle.
    #[error("receipt does not bind to this bundle: {0}")]
    Binding(String),
    /// A receipt claims a stronger enforcement mode than warrantor ever issues.
    #[error("enforcement-mode escalation: {0}")]
    Mode(String),
    /// A predicate invariant the evidence crate enforces with `assert!` would have been violated.
    ///
    /// Checked here so a malformed predicate is an error rather than a process abort: the
    /// workspace release profile is `panic = "abort"`.
    #[error("evidence predicate invariant: {0}")]
    Predicate(String),
    /// The report verifies, but the warrant's deadline has passed — so it no longer describes live
    /// authority.
    ///
    /// Separate from [`ReportError::Evidence`] on purpose: "intact but stale" and "corrupt" want
    /// opposite responses from whoever is reading, and collapsing them into one message would make
    /// an ordinary expiry look like tampering.
    #[error("the warrant expired at {expires_at}; this report was verified as of {now}")]
    Expired {
        /// The warrant's deadline, epoch seconds — from the receipt, not the bundle.
        expires_at: u64,
        /// The instant the caller asked about.
        now: u64,
    },
}

// ── the bundle ────────────────────────────────────────────────────────────────────────

/// One bound and how strongly it is actually held.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundLine {
    /// Field name in [`WarrantBounds`].
    pub name: String,
    /// Enforced (the system refuses) or observed (the system only measures).
    pub strength: BoundStrength,
}

/// One staged effect, as the report presents it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedLine {
    /// The typed handle standing for the thing that does not exist yet.
    pub handle: String,
    /// The tool that would perform it at settle time.
    pub tool: String,
    /// Arguments, verbatim as the agent supplied them.
    pub arguments: BTreeMap<String, String>,
}

/// The staged-effect section: either a release order, or the reason there isn't one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum StagedSection {
    /// Effects in release order — dependencies before dependents. Possibly empty.
    Ordered {
        /// The effects, in the order they would be released.
        effects: Vec<StagedLine>,
    },
    /// The queue could not be read, or contains a dependency cycle.
    Unavailable {
        /// Why. Recorded rather than swallowed: an unreadable queue is a fail-closed condition.
        reason: String,
    },
}

/// The changed-files section, present only when the warrant has a worktree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ChangedSection {
    /// Files changed against the base commit, including uncommitted work.
    Files {
        /// Sorted paths, relative to the worktree root.
        paths: Vec<String>,
    },
    /// Git refused.
    Unreadable {
        /// Why.
        reason: String,
    },
}

/// The notary's verdict over this warrant, recorded coarsely.
///
/// Denial names the failing gate and nothing else. That is the notary's rule, not a shortcut: a
/// denial that explained itself would describe the shape of the boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityCheck {
    /// The deciding engine, verbatim from [`warrantor_notary::NOTARY_VERSION`].
    pub engine: String,
    /// Plain-English statement of exactly what was decided, so a reader is not left guessing.
    pub question: String,
    /// Whether the nine gates all passed.
    pub allowed: bool,
    /// The first failing gate, when they did not.
    pub denied_gate: Option<String>,
    /// Capabilities the warrant effectively holds — the intersection, recomputed.
    pub effective_capabilities: Vec<String>,
    /// Capabilities the staged effects would need at settle time.
    pub capabilities_requested: Vec<String>,
}

/// The actor log's position at the moment the report was signed.
///
/// **What crosses into signed evidence is the head digest, not the acts.** The head is what makes a
/// later copy of `actors/<id>.jsonl` checkable against a signature taken now: a log edited or
/// truncated since no longer hashes to it. Copying the acts themselves in would put operator names
/// inside an artifact that gets handed to third parties, which is a disclosure decision nobody
/// asked for and one this bundle could not un-make.
///
/// `None` on the bundle means the log was **not consulted**, which is the true statement about
/// every report exported before this section existed. Absent is never "there were no acts": those
/// are different claims, and the limitations say which is being made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodySection {
    /// How many acts the log held.
    pub acts: usize,
    /// The head entry's digest, or `None` for an empty log.
    pub head: Option<String>,
    /// Whether the chain verified at the moment of signing.
    ///
    /// A report over a warrant whose actor chain is broken is still a valid report — the evidence
    /// is unaffected — and it must say so rather than refusing, because refusing to report on a
    /// warrant is how a broken chain hides.
    pub chain_intact: bool,
    /// Distinct named approvers recorded.
    pub approvers: usize,
    /// The approval requirement in force when the report was taken.
    pub approvals_required: usize,
}

/// What the revocation source held when the report was built (invariant I-05).
///
/// `None` on the bundle means **no source was consulted**, which was the true statement about every
/// report exported before [`crate::revoke`] existed. `Some` with an empty `revoked_svids` means a
/// source *was* read and held nothing. Those are different claims and the limitations say which one
/// is being made — the same distinction `spend` and `custody` already draw, and the same one the
/// containment comment in [`build_observed`] was written to protect.
///
/// **What a present section does not establish.** The set is one machine's journal. A subject revoked
/// on another machine is unrevoked here, because this build links no fan-out. See
/// [`crate::revoke`] for the full tier statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationSection {
    /// The file the set was read from, so a reader can go and look rather than take the set on
    /// trust.
    pub source: String,
    /// The revoked subjects, as handed to the notary's Identity gate.
    pub revoked_svids: Vec<String>,
    /// A propagation measurement, when one was taken. `None` means the report did not measure —
    /// never that the measurement passed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<RevocationLatency>,
    /// Whether the journal was readable at the moment of the read.
    ///
    /// `false` means the set above is empty because the file could not be replayed, **not** because
    /// nothing is revoked. Silence there would render an I/O failure as a clean bill of health.
    pub source_readable: bool,
}

impl RevocationSection {
    /// Read a store's journal into a section.
    ///
    /// `source` is the journal's path, because "a source was consulted" is worth nothing to a reader
    /// who cannot find out which one.
    #[must_use]
    pub fn from_store(store: &RevocationStore) -> Self {
        let source_readable = store.records().is_ok();
        Self {
            source: store.journal_path().display().to_string(),
            revoked_svids: store.revoked_svids(),
            latency: None,
            source_readable,
        }
    }

    /// Attach a propagation measurement taken by the caller that performed the revocation.
    #[must_use]
    pub fn with_latency(mut self, latency: RevocationLatency) -> Self {
        self.latency = Some(latency);
        self
    }
}

/// One staged effect's receipt chain, as the bundle lists it. The receipts themselves ride in
/// [`SignedReport::effect_receipts`]; these ids are what the digest covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectReceiptLine {
    /// The staged handle the receipts are over.
    pub handle: String,
    /// The tool that performed it.
    pub tool: String,
    /// `binding.receipt_id` of the pre-commit receipt.
    pub pre_receipt_id: String,
    /// `binding.receipt_id` of the post-commit receipt, `None` if none was issued.
    ///
    /// Equal to `pre_receipt_id` whenever a post-commit exists: a WAR post-commit is the
    /// pre-commit's predicate with a new phase, a parent pointer and an outcome, so the pair
    /// shares one id and the phase is what tells them apart. Present rather than implied, because
    /// `None` here is the load-bearing case -- it says the log ended between the two.
    pub post_receipt_id: Option<String>,
    /// The post-commit's `outcome.status`, or `"unfinished"` when there is no post-commit.
    pub status: String,
}

/// The per-effect evidence section: which effects were performed under which receipts.
///
/// `None` on the bundle means the receipt log was **not consulted**, which is the true statement
/// about every report exported before this section existed. Absent is never "nothing was
/// performed".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectEvidenceSection {
    /// How many receipts the log held.
    pub receipts_consulted: usize,
    /// One line per pre-commit, in issuance order.
    pub effects: Vec<EffectReceiptLine>,
}

/// The limitation sentence a report carries when no receipt log was read.
pub const NO_EFFECT_RECEIPTS_LIMITATION: &str =
    "No per-effect receipt log was consulted when this report was built, so it does not say which \
     staged effects were performed under a pre-commit receipt. That is not a statement that none \
     was.";

/// Everything `warrantor report` knows, in one signable object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportBundle {
    /// Wire format; see [`REPORT_BUNDLE_FORMAT`].
    pub format: String,
    /// The warrant this report covers.
    pub warrant_id: String,
    /// The stated intent, verbatim from the signed claims.
    pub goal: String,
    /// SPIFFE-shaped identifier of the agent the warrant was granted to.
    pub subject: String,
    /// Parent warrant id, when this is a sub-warrant. Named, not fetched — see `limitations`.
    pub parent: Option<String>,
    /// Lifecycle state at the moment the report was taken.
    pub state: WarrantState,
    /// When the warrant was issued, epoch seconds.
    pub issued_at: u64,
    /// The warrant's deadline, epoch seconds.
    pub expires_at: u64,
    /// When this bundle was built, epoch seconds.
    pub generated_at: u64,
    /// Repository the warrant was granted against.
    pub repo: Option<String>,
    /// The isolated worktree the agent works in.
    pub worktree: Option<String>,
    /// The declared bounds, values included. The prose report prints only their names.
    pub bounds: WarrantBounds,
    /// Which of those bounds the system refuses to exceed, and which it merely measures.
    pub bound_strengths: Vec<BoundLine>,
    /// What the budget bound has actually observed, when a ledger was consulted.
    ///
    /// `None` means no ledger was read — not that nothing was spent. The two are different claims
    /// and the limitations say which one this bundle is making. `#[serde(default)]` so a bundle
    /// exported before ledgers existed still parses; a missing section reads as "not consulted",
    /// which is the true statement about such a file.
    #[serde(default)]
    pub spend: Option<SpendSection>,
    /// Where the actor log stood when this report was signed. See [`CustodySection`].
    ///
    /// `#[serde(default)]` so a bundle exported before this section existed still parses, and
    /// reads as "not consulted".
    ///
    /// **`skip_serializing_if` is the load-bearing half, and `spend` does not have it.**
    /// [`bundle_digest`] hashes a *re-serialisation* of the parsed bundle, not the bytes on disk.
    /// Without the skip, an older export — which has no `custody` key at all — parses as `None`,
    /// re-serialises as `"custody": null`, and hashes to something other than what its receipts
    /// cover. Every report signed before this field existed would stop verifying, on a surface
    /// whose entire purpose is that old evidence keeps checking out.
    ///
    /// With the skip, an absent field stays absent through the round trip and the digest is
    /// unchanged. A present one is inside the signature exactly as much as any other field: editing
    /// it breaks verification, which is the point of putting it here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody: Option<CustodySection>,
    /// What the revocation source held when this report was built. See [`RevocationSection`].
    ///
    /// Same `skip_serializing_if` reasoning as `custody`, and for the same non-negotiable reason: an
    /// absent section must stay absent through the canonical round trip, or every report signed
    /// before this field existed stops verifying.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<RevocationSection>,
    /// Which effects were performed under which receipts. See [`EffectEvidenceSection`]. Same
    /// `skip_serializing_if` reasoning as `custody`: an absent section stays absent through the
    /// digest round trip, so every earlier export keeps verifying.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_evidence: Option<EffectEvidenceSection>,
    /// Staged effects awaiting a settle decision.
    pub staged: StagedSection,
    /// How many effects are staged. `None` when the queue could not be read.
    pub staged_count: Option<usize>,
    /// Head of the staging queue's hash chain. `None` when the queue could not be read.
    pub chain_head: Option<String>,
    /// What changed in the worktree. Absent when the warrant has no worktree.
    pub changed: Option<ChangedSection>,
    /// The notary's verdict over this warrant.
    pub authority_check: AuthorityCheck,
    /// Everything this bundle does **not** establish, in plain language.
    ///
    /// Never empty. A signed artifact whose caveats are implicit is how a reader ends up trusting
    /// a guarantee that was never made.
    pub limitations: Vec<String>,
}

/// A bundle plus the exported, independently verifiable proof over it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedReport {
    /// Wire format; see [`REPORT_EXPORT_FORMAT`].
    pub format: String,
    /// SHA-256 hex of the canonical bundle. Both receipts commit to this value.
    pub bundle_digest: String,
    /// The bundle itself.
    pub bundle: ReportBundle,
    /// The notary's signed verdict.
    pub notary_receipt: notary::WarReceipt,
    /// The WAR evidence receipt over the whole report.
    pub evidence_receipt: evidence::WarReceipt,
    /// The per-effect WAR receipts the bundle's `effect_evidence` lists, verbatim. Outside the
    /// bundle digest on purpose: removing one must fail as a **commit-gate** violation (I-07),
    /// not as a digest mismatch, so a reader learns which effect lost its record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effect_receipts: Vec<evidence::WarReceipt>,
}

/// A built report: the bundle, plus the notary inputs that produced its verdict.
///
/// The inputs are kept so [`Report::sign`] can issue a receipt over the *same* verdict the bundle
/// records, rather than re-deciding and risking a bundle that disagrees with its own proof.
#[derive(Debug, Clone)]
pub struct Report {
    bundle: ReportBundle,
    request: notary::VerdictRequest,
    verdict: notary::Verdict,
    authority: evidence::Authority,
    effect_receipts: Vec<evidence::WarReceipt>,
}

// ── building ──────────────────────────────────────────────────────────────────────────

/// SHA-256 hex of a byte string.
///
/// **The one implementation in this system.** It is public rather than crate-private because
/// `warrantor-archive` delegates its own `sha256_hex` to this function: the artifact digest that
/// names which bytes are which artifact, the enrolment-code digest, and the body digest a device
/// signature covers are all this code. A digest computed a second way — in SQL, in a client, in a
/// helper that re-serialises first — is a second implementation of the rule that decides identity,
/// and the two can come to disagree across a process boundary where nobody is watching.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Recursively sort object keys.
///
/// Warrant-local, and deliberately not shared with the plane crates: `warrantor-evidence`,
/// `warrantor-notary`, `warrantor-spend` and `warrantor-egress` each carry their own, and
/// egress's differs in behaviour. Each receipt is verified by the crate that issued it, so there is
/// no single canonical form to agree on and nothing here assumes one.
pub(crate) fn canonicalize(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::{Map, Value};
    match value {
        Value::Object(map) => {
            let mut sorted: Vec<(&String, &Value)> = map.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            let mut out = Map::new();
            for (key, val) in sorted {
                out.insert(key.clone(), canonicalize(val));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

/// The canonical JSON encoding of a bundle — the exact bytes the digest covers.
///
/// # Errors
/// [`ReportError::Encode`] if the bundle does not serialise.
pub fn canonical_bundle(bundle: &ReportBundle) -> Result<String, ReportError> {
    let value =
        serde_json::to_value(bundle).map_err(|e| ReportError::Encode(format!("bundle: {e}")))?;
    serde_json::to_string(&canonicalize(&value))
        .map_err(|e| ReportError::Encode(format!("canonical bundle: {e}")))
}

/// SHA-256 hex of [`canonical_bundle`].
///
/// # Errors
/// [`ReportError::Encode`] if the bundle does not serialise.
pub fn bundle_digest(bundle: &ReportBundle) -> Result<String, ReportError> {
    Ok(sha256_hex(canonical_bundle(bundle)?.as_bytes()))
}

/// Digest of a warrant's signed claims — the `token_digest` on its delegation link.
pub(crate) fn warrant_claims_digest(warrant: &Warrant) -> String {
    match serde_json::to_value(&warrant.claims) {
        Ok(value) => match serde_json::to_string(&canonicalize(&value)) {
            Ok(text) => format!("sha256:{}", sha256_hex(text.as_bytes())),
            Err(_) => "sha256:unavailable".to_string(),
        },
        Err(_) => "sha256:unavailable".to_string(),
    }
}

/// The one-link authority block for a warrant, built the same way for the report receipt and
/// for every per-effect receipt so the two cannot drift (the module doc's second hazard).
pub(crate) fn warrant_authority(warrant: &Warrant) -> evidence::Authority {
    let claims = &warrant.claims;
    let chain = vec![evidence::DelegationLink {
        issuer: warrant.issuer_key.clone(),
        subject: claims.subject.clone(),
        capabilities: claims.bounds.tools.iter().cloned().collect(),
        not_before: claims.issued_at,
        not_after: claims.bounds.expires_at,
        token_digest: warrant_claims_digest(warrant),
    }];
    evidence::Authority {
        effective_capabilities: evidence::recompute_intersection(&chain),
        intersection_proof: evidence::compute_intersection_proof(&chain),
        chain,
    }
}

/// Digest of the bounds a warrant is evaluated against — its "policy".
pub(crate) fn bounds_policy_digest(bounds: &WarrantBounds) -> String {
    match serde_json::to_value(bounds) {
        Ok(value) => match serde_json::to_string(&canonicalize(&value)) {
            Ok(text) => format!("sha256:{}", sha256_hex(text.as_bytes())),
            Err(_) => "sha256:unavailable".to_string(),
        },
        Err(_) => "sha256:unavailable".to_string(),
    }
}

fn limitations(
    stored: &StoredWarrant,
    contained_scopes: &[String],
    spend: Option<&SpendSection>,
    custody: Option<&CustodySection>,
    revocation: Option<&RevocationSection>,
) -> Vec<String> {
    // Said whether or not a section is present, because the absence is itself a claim a reader
    // would otherwise fill in wrongly.
    let custody_line = match custody {
        None => "This report does not say who acted on this warrant: the actor log was not consulted when it was built. That is not a statement that nobody acted.".to_string(),
        Some(section) if !section.chain_intact => format!(
            "The actor log for this warrant does NOT verify ({} act(s) recorded). Somebody has edited, removed or reordered a line in the record of who settled, voided, stopped or approved it. The evidence in this bundle is unaffected -- signatures are checked separately -- but who acted is now unknown.",
            section.acts
        ),
        Some(section) => format!(
            "Who acted is committed to by the actor log's head digest, not by its contents: {} act(s) and {} distinct approver(s) against a requirement of {}. The head lets a later copy of that log be checked against this signature; it carries no operator names, and it establishes nothing to a reader who has never seen the log itself.",
            section.acts, section.approvers, section.approvals_required
        ),
    };
    // The budget caveat is the one that changes with what was actually read, so it is stated from
    // the input. Before there was a ledger the honest sentence was "no spend figure appears here";
    // now that one can, the sentence has to say where the figure came from -- which is the agent,
    // and only ever the agent.
    let budget = match spend {
        None => "budget_cents_observed is parsed from the agent's own usage reporting and was not \
                 consulted here. No spend figure appears in this bundle, which means none was \
                 read -- not that nothing was spent."
            .to_string(),
        Some(section) if !section.cap_declared => format!(
            "budget_cents_observed was not declared on this warrant, so its ceiling is zero and \
             only zero-cost usage can be recorded. The {} record(s) in the SPEND section are what \
             the agent reported about itself; model API calls do not pass through Warrantor.",
            section.records
        ),
        Some(section) => format!(
            "budget_cents_observed is measured only from usage the agent reported to `warrantor \
             spend`. The {} record(s) in the SPEND section are self-reported: no provider usage \
             record, invoice or billing API was consulted, and an agent that under-reports or \
             never reports is not caught here. The bound stays observed, not enforced.",
            section.records
        ),
    };
    let mut out = vec![
        "Bounds are declared values. `bound_strengths` says which the system refuses to exceed \
         and which it only measures; an observed bound can be exceeded without this report \
         noticing."
            .to_string(),
        "egress_hosts is enforced only for tool calls that traverse the Warrantor MCP proxy. \
         There is no network namespace, seccomp filter or firewall: an agent that opens a socket \
         directly is not bound by it, and nothing in this bundle says otherwise."
            .to_string(),
        "write_paths is not refused at the moment of writing. Nothing intercepts the agent's \
         filesystem access, so an agent under this warrant could have written outside its declared \
         paths and this report would not know. What the warrant does provide is containment after \
         the fact: the agent worked in an isolated worktree, so nothing it wrote touched the \
         developer's working copy, and settle stages only the declared write paths, so \
         out-of-bounds edits are never merged into the base branch -- they are left in the \
         worktree. Read write_paths as a statement of what should have been touched, checkable \
         against the changed-files list in this bundle, not as a boundary that held."
            .to_string(),
        budget,
        "There is no SPIFFE SVID document in this deployment. actor.svid_digest in the evidence \
         receipt is the SHA-256 of the subject identifier string, not of a workload certificate."
            .to_string(),
        "The autonomy budget supplied to the notary's budget gate is the warrant's remaining \
         authorised SECONDS. It is not money and not tokens."
            .to_string(),
        "No replay store exists, so the freshness gate sees an empty seen-nonce set and cannot \
         detect a replayed request."
            .to_string(),
        "No artifact digests are verified here, so the artifacts gate passes over an empty set."
            .to_string(),
        "Verifying a signature proves who signed and that nothing changed since. It does not \
         establish that the signing key is trusted; that has to come from somewhere else."
            .to_string(),
    ];
    out.push(custody_line);
    out.push(NO_EFFECT_RECEIPTS_LIMITATION.to_string());
    // Containment is the one gate whose caveat changes with the input, so it is stated from the
    // input rather than from a fixed sentence. A build that was handed no contained scope has to
    // say the gate passed for want of anything to check, and a build that was handed one has to say
    // where it came from -- a stop record, which attests a supervisor was terminated and does NOT
    // attest that the agent process is gone.
    out.push(if contained_scopes.is_empty() {
        "No containment state was supplied to this report. The containment gate passes because \
         nothing -- no kill switch, no stop record -- was wired to it, not because containment was \
         checked."
            .to_string()
    } else {
        format!(
            "Containment state was supplied: {} scope(s) are contained, so the containment gate \
             denies. That comes from a stop record in this store, which attests that a SUPERVISOR \
             was terminated. It does not attest that the agent process is gone -- see the stop \
             record's own conformance report for what was measured and what was inferred.",
            contained_scopes.len()
        )
    });
    // Revocation (I-05) is the second gate whose caveat is computed from the input, and it is
    // computed for the same reason: "not consulted", "consulted and empty" and "consulted and
    // holding a revoked subject" are three different claims, and collapsing the first two into
    // silence is what let an empty `revoked_svids` read as a clean bill of health -- the defect
    // `i01_active_identity.rs` recorded on 2026-09-02 and this function stopped making on
    // 2026-09-05.
    out.push(match revocation {
        None => "No revocation source was supplied to this report. The Identity gate's \
                 \"unrevoked\" clause passes because nothing was wired to it, not because \
                 revocation was checked."
            .to_string(),
        Some(section) if !section.source_readable => format!(
            "A revocation source was supplied ({}) and it could NOT be read. The revoked set in \
             this bundle is empty because the journal failed to replay, not because nothing is \
             revoked, and the Identity gate was therefore evaluated against an empty set. Treat \
             this report as having checked nothing.",
            section.source,
        ),
        Some(section) if section.revoked_svids.is_empty() => format!(
            "A revocation source WAS consulted ({}) and it holds no revoked subject. That is a \
             statement about this machine's journal, not about any other machine: this build has \
             no fan-out, so a subject revoked elsewhere is unrevoked here.",
            section.source,
        ),
        Some(section) => format!(
            "{} subject(s) are revoked in this machine's journal ({}), so the Identity gate denies \
             every verdict computed after the record reached disk{}. It does not recall a \
             credential already used, does not reach a copy held by a third party, does not close \
             a session already open, and does not propagate to any other machine. The egress \
             broker does not consult the revocation set at all. The subject revoked is the \
             constant this build presents as its principal, not an issued SVID.",
            section.revoked_svids.len(),
            section.source,
            match section.latency {
                Some(l) if !l.propagated =>
                    " -- though the read taken for this report did not find that subject, so \
                     propagation to this reader is UNPROVEN"
                        .to_string(),
                Some(l) if l.within_sla => format!(
                    " -- measured at {:?} across {} adjudication(s), inside the stated {:?}",
                    Duration::from_nanos(l.elapsed_nanos.min(u128::from(u64::MAX)) as u64),
                    l.adjudications_between,
                    IDENTITY_REVOCATION_SLA,
                ),
                Some(l) => format!(
                    " -- measured at {:?} across {} adjudication(s), which BREACHES the stated {:?}",
                    Duration::from_nanos(l.elapsed_nanos.min(u128::from(u64::MAX)) as u64),
                    l.adjudications_between,
                    IDENTITY_REVOCATION_SLA,
                ),
                None => " (propagation was not measured for this report)".to_string(),
            },
        ),
    });
    out.push(match &stored.warrant.claims.parent {
        Some(parent) => format!(
            "The authority chain contains only this warrant. Its parent {parent} is named but was \
             not fetched or verified here, so the chain is a fragment, not a root-to-leaf proof."
        ),
        None => "The authority chain contains only this warrant, which has no parent.".to_string(),
    });
    out
}

/// Build the report for one warrant.
///
/// `queue` is a `Result` rather than an `Option` because an unreadable staging queue is a
/// fail-closed condition that has to reach both the prose and the verdict: the reason is recorded,
/// and the notary's policy gate is denied rather than guessed at.
///
/// `issuer` is the verifying key the warrant's signature is checked against — the real trust
/// anchor from disk, not the key the warrant carries about itself. A warrant signed by some other
/// key fails the notary's chain gate here.
///
/// This form consults **no containment state**, and the bundle's limitations say so. Callers that
/// have a store to look in — the CLI and the MCP control endpoint — use
/// [`build_with_containment`] instead, so a stopped warrant's report denies at gate 1.
#[must_use]
pub fn build(
    stored: &StoredWarrant,
    queue: Result<&StagingQueue, String>,
    issuer: &VerifyingKey,
    now: u64,
) -> Report {
    build_with_containment(stored, queue, issuer, now, &[])
}

/// Build the report for one warrant, honouring the scopes a stop has contained.
///
/// `contained_scopes` is the notary's containment seam — a plain `Vec<String>` of scopes that must
/// not be adjudicated — and a warrant's scope is its id. Supplying it is the whole of the
/// kill-switch wiring: [`crate::stop::StopStore::contained_scopes`] returns the warrant's id once a
/// stop record exists, and gate 1 denies from then on. No kill-switch dependency is involved, and
/// nothing here claims the agent process is gone; that is the stop record's own, separately
/// qualified, claim.
#[must_use]
pub fn build_with_containment(
    stored: &StoredWarrant,
    queue: Result<&StagingQueue, String>,
    issuer: &VerifyingKey,
    now: u64,
    contained_scopes: &[String],
) -> Report {
    // Nothing observed: a caller wanting a section uses `build_observed` with an `Observed`.
    build_observed(
        stored,
        queue,
        issuer,
        now,
        contained_scopes,
        Observed::default(),
    )
}

/// What a caller with a store root looked at, and what it did not.
///
/// Every field is an `Option` and every `None` is a *claim*: "no ledger was consulted" and "a ledger
/// was consulted and it is empty" are different statements, and [`limitations`] says which one the
/// bundle is making. `revocation` is the one whose absence used to be silent — before it existed the
/// Identity gate was handed `Vec::new()` and the bundle said nothing, so a gate that had checked
/// nothing read as a gate that had found nothing.
///
/// A struct rather than three parameters because clippy caps a function at seven arguments and
/// `build_observed` had reached it, and because a caller writing `Observed::default()` says what it
/// means more plainly than three bare `None`s in a row.
#[derive(Debug, Clone, Default)]
pub struct Observed {
    /// What the budget bound has actually observed, when a ledger was read.
    pub spend: Option<SpendSection>,
    /// Where the actor log stood, when it was read.
    pub custody: Option<CustodySection>,
    /// What the revocation source held, when one was read.
    pub revocation: Option<RevocationSection>,
}

/// Build the report, honouring containment and carrying whatever the caller observed.
///
/// The fullest form, used by every caller that has a store root to look in. See [`Observed`] for why
/// each of its fields is an `Option` and what a `None` asserts.
///
/// Supplying a section changes what the bundle *reports*, never what any bound *is*: the budget
/// stays [`crate::BoundStrength::Observed`] and `bound_strengths()` is untouched. What it changes
/// is that a bound labelled "observed" now has something that observed it. Revocation adds no row
/// to `bound_strengths()` either: it is a property of the existing Identity gate, not a new bound on
/// the warrant.
#[must_use]
pub fn build_observed(
    stored: &StoredWarrant,
    queue: Result<&StagingQueue, String>,
    issuer: &VerifyingKey,
    now: u64,
    contained_scopes: &[String],
    observed: Observed,
) -> Report {
    let Observed {
        spend,
        custody,
        revocation,
    } = observed;
    let claims = &stored.warrant.claims;
    let bounds = &claims.bounds;

    // ── staged effects ───────────────────────────────────────────────────────────────
    let (staged, staged_count, chain_head, staged_tools, queue_available) = match queue {
        Ok(queue) => {
            let count = queue.len();
            let head = queue.head_digest().to_string();
            match queue.release_order() {
                Ok(order) => {
                    let mut tools: BTreeSet<String> = BTreeSet::new();
                    let effects = order
                        .into_iter()
                        .map(|effect| {
                            tools.insert(effect.tool.clone());
                            StagedLine {
                                handle: effect.handle.clone(),
                                tool: effect.tool.clone(),
                                arguments: effect.arguments.clone(),
                            }
                        })
                        .collect();
                    (
                        StagedSection::Ordered { effects },
                        Some(count),
                        Some(head),
                        tools.into_iter().collect::<Vec<String>>(),
                        true,
                    )
                }
                Err(e) => (
                    StagedSection::Unavailable {
                        reason: e.to_string(),
                    },
                    Some(count),
                    Some(head),
                    Vec::new(),
                    false,
                ),
            }
        }
        Err(reason) => (
            StagedSection::Unavailable { reason },
            None,
            None,
            Vec::new(),
            false,
        ),
    };

    // ── worktree ─────────────────────────────────────────────────────────────────────
    let changed = stored.worktree.as_ref().map(|path| {
        let tree = Worktree::existing(
            stored.repo.clone().unwrap_or_else(|| path.clone()),
            path.clone(),
            stored
                .branch
                .clone()
                .unwrap_or_else(|| format!("{}{}", crate::worktree::BRANCH_PREFIX, claims.id)),
            stored.base_commit.clone().unwrap_or_default(),
        );
        match tree.changed_files() {
            Ok(paths) => ChangedSection::Files { paths },
            Err(e) => ChangedSection::Unreadable {
                reason: e.to_string(),
            },
        }
    });

    // ── the notary's nine gates ──────────────────────────────────────────────────────
    //
    // Every flag below is COMPUTED. Hardcoding `signature_verified: true` or
    // `policy_decision: true` to make the call compile would turn nine gates into decoration.
    //
    // `Warrant::verify` folds expiry into the same Result, but expiry is gate 2's job
    // (`svid_not_after`), not gate 4's. So the chain gate asks only whether the signature is
    // genuine: verify at t=0, which is before every warrant's deadline because `expires_at == 0`
    // is rejected at grant time. An expired warrant therefore denies at Identity, not at Chain.
    let signature_verified = stored.warrant.verify(issuer, 0).is_ok();

    let own_capabilities: Vec<String> = bounds.tools.iter().cloned().collect();
    let nonce = format!(
        "{}:{now}:{}",
        claims.id,
        chain_head.clone().unwrap_or_default()
    );

    let request = notary::VerdictRequest {
        actor: notary::Actor {
            svid: claims.subject.clone(),
            // The warrant's deadline IS this identity's expiry: past it the subject holds nothing.
            svid_not_after: bounds.expires_at,
            own_capabilities: own_capabilities.clone(),
            delegation_chain: vec![notary::DelegationLink {
                delegatee_svid: claims.subject.clone(),
                capabilities: own_capabilities,
                not_before: claims.issued_at,
                not_after: bounds.expires_at,
                signature_verified,
            }],
        },
        operation: notary::Operation {
            class: REPORT_OPERATION_CLASS.to_string(),
            // What the staged effects would need at settle time. Nothing in `warrantor stage`
            // checks the tool allowlist today, so this gate is the first thing that would notice
            // an effect staged for a tool the warrant does not hold.
            capabilities_requested: staged_tools.clone(),
            consequence_tier: notary::ConsequenceTier::Routine,
            scope: claims.id.clone(),
        },
        artifacts: Vec::new(),
        nonce,
        timestamp: now,
        approval: None,
    };

    let context = notary::VerdictContext {
        now,
        // The kill-switch seam, filled from stop records rather than from a kill-switch crate.
        // Empty means "warrant knows of no contained scope", which is a statement about what was
        // supplied, never a claim that containment was checked and found clear.
        contained_scopes: contained_scopes.to_vec(),
        // The revocation seam (I-05), filled from this machine's append-only journal rather than
        // from an identity provider. Empty means "warrant was handed no revoked subject" — exactly
        // as with `contained_scopes` above, a statement about what was supplied and never a claim
        // that revocation was checked and found clear. `None` for the whole section says even that
        // much was not consulted, and `limitations` distinguishes the two.
        revoked_svids: revocation
            .as_ref()
            .map(|section| section.revoked_svids.clone())
            .unwrap_or_default(),
        seen_nonces: Vec::new(),
        freshness_window_seconds: FRESHNESS_WINDOW_SECONDS,
        verified_artifacts: Vec::new(),
        // Remaining authorised time, in seconds. Zero once the deadline passes.
        budget_remaining: bounds.expires_at.saturating_sub(now),
        // A warrant that is no longer Open authorises nothing, and an unreadable staging queue is
        // indeterminate — which the notary's own doctrine says is denial.
        policy_decision: stored.warrant.state == WarrantState::Open && queue_available,
    };

    let verdict = notary::verdict(&request, &context);
    // Counted here, at the one place in this binary that computes a verdict, so that
    // `RevocationLatency::adjudications_between` is a measured number rather than an assumed zero.
    ADJUDICATIONS.fetch_add(1, Ordering::SeqCst);
    let effective = notary::effective_capabilities(&request.actor);
    let authority_check = AuthorityCheck {
        engine: notary::NOTARY_VERSION.to_string(),
        question: "Does this warrant still hold the authority its staged effects would need at \
                   settle time?"
            .to_string(),
        allowed: verdict.is_allow(),
        denied_gate: match &verdict {
            notary::Verdict::Deny { gate } => Some(gate_name(*gate).to_string()),
            notary::Verdict::Allow { .. } => None,
        },
        effective_capabilities: effective.clone(),
        capabilities_requested: staged_tools,
    };

    // ── the evidence authority block ─────────────────────────────────────────────────
    //
    // One link, and it is a true statement: the issuer delegated exactly `bounds.tools` to
    // `subject` for exactly this validity window, and `token_digest` is a real digest of the
    // signed claims. Built through `compute_intersection_proof` so `verify_authority` recomputes
    // it rather than trusting it.
    let authority = warrant_authority(&stored.warrant);

    let bundle = ReportBundle {
        format: REPORT_BUNDLE_FORMAT.to_string(),
        warrant_id: claims.id.clone(),
        goal: claims.goal.clone(),
        subject: claims.subject.clone(),
        parent: claims.parent.clone(),
        state: stored.warrant.state,
        issued_at: claims.issued_at,
        expires_at: bounds.expires_at,
        generated_at: now,
        repo: stored.repo.as_ref().map(|p| p.display().to_string()),
        worktree: stored.worktree.as_ref().map(|p| p.display().to_string()),
        bounds: bounds.clone(),
        bound_strengths: bound_strengths()
            .into_iter()
            .map(|(name, strength)| BoundLine {
                name: name.to_string(),
                strength,
            })
            .collect(),
        limitations: limitations(
            stored,
            contained_scopes,
            spend.as_ref(),
            custody.as_ref(),
            revocation.as_ref(),
        ),
        spend,
        custody,
        revocation,
        effect_evidence: None,
        staged,
        staged_count,
        chain_head,
        changed,
        authority_check,
    };

    Report {
        bundle,
        request,
        verdict,
        authority,
        effect_receipts: Vec::new(),
    }
}

/// The notary gate names, in the crate's own snake_case vocabulary.
#[must_use]
pub fn gate_name(gate: notary::Gate) -> &'static str {
    match gate {
        notary::Gate::Containment => "containment",
        notary::Gate::Identity => "identity",
        notary::Gate::Freshness => "freshness",
        notary::Gate::Chain => "chain",
        notary::Gate::Authority => "authority",
        notary::Gate::Artifacts => "artifacts",
        notary::Gate::Budget => "budget",
        notary::Gate::Policy => "policy",
        notary::Gate::Approval => "approval",
    }
}

impl Report {
    /// The bundle, for rendering.
    #[must_use]
    pub fn bundle(&self) -> &ReportBundle {
        &self.bundle
    }

    /// Attach the receipt log: the bundle lists every chain, the export carries the receipts.
    ///
    /// Replaces [`NO_EFFECT_RECEIPTS_LIMITATION`] with what was actually read. A log that verifies
    /// nothing is still recorded — an empty section is "consulted, and empty", which differs from
    /// `None`.
    #[must_use]
    pub fn with_effect_receipts(mut self, receipts: Vec<evidence::WarReceipt>) -> Self {
        let effects = crate::receipts::chains(&receipts)
            .into_iter()
            .map(|chain| EffectReceiptLine {
                handle: chain.pre_commit.predicate.operation.target.clone(),
                tool: chain.pre_commit.predicate.operation.class.clone(),
                pre_receipt_id: chain.pre_commit.predicate.binding.receipt_id.clone(),
                post_receipt_id: chain
                    .post_commit
                    .as_ref()
                    .map(|p| p.predicate.binding.receipt_id.clone()),
                status: chain
                    .post_commit
                    .as_ref()
                    .and_then(|p| p.predicate.outcome.as_ref().map(|o| o.status.clone()))
                    .unwrap_or_else(|| "unfinished".to_string()),
            })
            .collect::<Vec<_>>();
        self.bundle
            .limitations
            .retain(|l| l != NO_EFFECT_RECEIPTS_LIMITATION);
        // The mode word is READ from the receipts, never written as a literal. It used to be the
        // string "advisory" hardcoded here, so a bundle carrying a `mediated` receipt still read
        // "each advisory". A rendered word that cannot disagree with the record it describes is not
        // a disclosure; it is decoration -- and this sentence ships inside the signed bundle.
        // `verify_effect_receipts` refuses anything but advisory, so the mixed branch should be
        // unreachable in a bundle that verifies; it exists so a bundle that does NOT verify still
        // says what it actually holds.
        let mut modes: Vec<&str> = receipts
            .iter()
            .map(|r| mode_word_evidence(r.predicate.binding.enforcement_mode))
            .collect();
        modes.sort_unstable();
        modes.dedup();
        let mode_phrase = match modes.as_slice() {
            [single] => format!("each {single}"),
            many => format!("carrying mixed enforcement modes ({})", many.join(", ")),
        };
        self.bundle.limitations.push(format!(
            "{} per-effect receipt chain(s) are attached, {mode_phrase}: the pre-commit was \
             signed before settle performed the effect and the post-commit after, which \
             records what settle did, not that the agent held no other way to do the same \
             thing in the world.",
            effects.len()
        ));
        self.bundle.effect_evidence = Some(EffectEvidenceSection {
            receipts_consulted: receipts.len(),
            effects,
        });
        self.effect_receipts = receipts;
        self
    }

    /// Sign the bundle: a notary receipt over the verdict, a WAR receipt over the whole report.
    ///
    /// # Errors
    /// [`ReportError::Encode`] if the bundle does not serialise, or [`ReportError::Predicate`] if
    /// a predicate invariant would be violated. The second case cannot happen with a bundle this
    /// module built — it is checked anyway because the evidence crate enforces those invariants
    /// with `assert!`, and the release profile is `panic = "abort"`.
    pub fn sign(&self, key: &SigningKey, key_id: &str) -> Result<SignedReport, ReportError> {
        let digest = bundle_digest(&self.bundle)?;
        let (evidence_mode, notary_mode) = report_modes();

        let notary_receipt =
            notary::issue_receipt(&self.verdict, &self.request, notary_mode, key, key_id);

        let predicate = evidence::WarPredicate {
            binding: evidence::Binding {
                receipt_id: digest.clone(),
                phase: evidence::Phase::Atomic,
                parent_receipt: None,
                nonce: self.request.nonce.clone(),
                issued_at: self.bundle.generated_at,
                // The warrant's own deadline, and the receipt's too: past it the subject holds
                // nothing, so a receipt asserting that authority is stale by definition.
                //
                // `verify_export` deliberately does NOT enforce this — an exported report is a
                // record of a past evaluation and has to keep verifying forever. A reader asking
                // whether the authority is still live calls `verify_export_at`, which does.
                expires_at: self.bundle.expires_at,
                enforcement_mode: evidence_mode,
            },
            actor: evidence::Actor {
                principal: self.bundle.subject.clone(),
                workload_id: self.bundle.subject.clone(),
                // Not a certificate digest: there is no SVID document here. Said so in
                // `limitations` rather than left to look like one.
                svid_digest: format!("sha256:{}", sha256_hex(self.bundle.subject.as_bytes())),
            },
            authority: self.authority.clone(),
            decision: evidence::Decision {
                // Taken FROM the notary. Nothing here decides anything itself.
                verdict: if self.verdict.is_allow() {
                    evidence::Verdict::Allow
                } else {
                    evidence::Verdict::Deny
                },
                engine: notary::NOTARY_VERSION.to_string(),
                policy_digest: bounds_policy_digest(&self.bundle.bounds),
                evaluated_at: self.bundle.generated_at,
            },
            operation: evidence::Operation {
                class: REPORT_OPERATION_CLASS.to_string(),
                target: self.bundle.warrant_id.clone(),
                method: "report".to_string(),
                parameters_digest: digest.clone(),
                // A report reads. It changes nothing, so it is reversible and routine — which is
                // exactly what the atomic phase requires.
                reversible: true,
                consequence_tier: evidence::ConsequenceTier::Routine,
            },
            outcome: Some(evidence::Outcome {
                status: "success".to_string(),
                outcome_digest: digest.clone(),
                // A report performs nothing. An empty effects list is the honest value.
                effects: Vec::new(),
                error: None,
                rollback_pointer: None,
            }),
        };

        let evidence_receipt = issue_atomic_checked(predicate, key, key_id)?;

        Ok(SignedReport {
            format: REPORT_EXPORT_FORMAT.to_string(),
            bundle_digest: digest,
            bundle: self.bundle.clone(),
            notary_receipt,
            evidence_receipt,
            effect_receipts: self.effect_receipts.clone(),
        })
    }
}

/// [`warrantor_evidence::issue_atomic`] enforces its invariants with `assert!`. This checks them
/// first and returns an error instead, so a malformed predicate cannot abort the process.
fn issue_atomic_checked(
    predicate: evidence::WarPredicate,
    key: &SigningKey,
    key_id: &str,
) -> Result<evidence::WarReceipt, ReportError> {
    if predicate.binding.phase != evidence::Phase::Atomic {
        return Err(ReportError::Predicate("phase must be atomic".to_string()));
    }
    if predicate.outcome.is_none() {
        return Err(ReportError::Predicate(
            "atomic predicate must carry an outcome".to_string(),
        ));
    }
    if !predicate.operation.reversible
        || predicate.operation.consequence_tier != evidence::ConsequenceTier::Routine
    {
        return Err(ReportError::Predicate(
            "atomic phase requires a reversible, routine operation".to_string(),
        ));
    }
    Ok(evidence::issue_atomic(predicate, key, key_id))
}

// ── verification ──────────────────────────────────────────────────────────────────────

/// Verify an exported report offline, with nothing but the file.
///
/// Checks, in order: both wire formats; that the bundle still hashes to the digest the receipts
/// were issued over; both Ed25519 signatures; the recomputed authority intersection; that both
/// receipts were signed by the same key; that neither receipt claims an enforcement mode stronger
/// than warrantor issues; and that every field binding a receipt to this bundle holds.
///
/// A pass means **nothing has changed since signing**. It does not mean the signer should be
/// believed — the key has to be established out of band. Nor does it mean the warrant is still
/// live: this function takes no clock and checks no deadline, because an exported report is a
/// record of a past evaluation and has to keep verifying after the warrant it describes has
/// lapsed. [`verify_export_at`] is the form that asks whether the authority still holds.
///
/// # Errors
/// The variant of [`ReportError`] naming the first check that failed.
pub fn verify_export(export: &SignedReport) -> Result<(), ReportError> {
    if export.format != REPORT_EXPORT_FORMAT {
        return Err(ReportError::Format {
            found: export.format.clone(),
            expected: REPORT_EXPORT_FORMAT,
        });
    }
    if export.bundle.format != REPORT_BUNDLE_FORMAT {
        return Err(ReportError::Format {
            found: export.bundle.format.clone(),
            expected: REPORT_BUNDLE_FORMAT,
        });
    }

    let actual = bundle_digest(&export.bundle)?;
    if actual != export.bundle_digest {
        return Err(ReportError::Digest {
            expected: export.bundle_digest.clone(),
            actual,
        });
    }

    notary::verify_receipt(&export.notary_receipt)
        .map_err(|e| ReportError::Notary(e.to_string()))?;
    evidence::verify_receipt(&export.evidence_receipt)
        .map_err(|e| ReportError::Evidence(e.to_string()))?;
    evidence::verify_authority(&export.evidence_receipt.predicate.authority)
        .map_err(|e| ReportError::Evidence(e.to_string()))?;

    // One report, one signer. Without this, a receipt lifted from somewhere else and signed by a
    // different key would pass its own verification and ride along.
    if export.notary_receipt.signature.public_key != export.evidence_receipt.signature.public_key {
        return Err(ReportError::Binding(
            "the notary and evidence receipts were signed by different keys".to_string(),
        ));
    }

    let (evidence_mode, notary_mode) = report_modes();
    if export.evidence_receipt.predicate.binding.enforcement_mode != evidence_mode {
        return Err(ReportError::Mode(
            "the evidence receipt claims a mode warrantor never issues for a report; a report is \
             advisory because warrantor does not mediate an agent that bypasses its proxy"
                .to_string(),
        ));
    }
    if export.notary_receipt.body.enforcement_mode != notary_mode {
        return Err(ReportError::Mode(
            "the notary receipt claims a mode warrantor never issues for a report".to_string(),
        ));
    }
    // Belt and braces: an advisory receipt must not be usable to assert non-bypassability.
    if evidence::check_mode_honesty(&export.evidence_receipt, true).is_ok() {
        return Err(ReportError::Mode(
            "an advisory receipt must not be able to assert non-bypassability".to_string(),
        ));
    }

    let predicate = &export.evidence_receipt.predicate;
    let bind = |ok: bool, what: &str| -> Result<(), ReportError> {
        if ok {
            Ok(())
        } else {
            Err(ReportError::Binding(what.to_string()))
        }
    };
    bind(
        predicate.binding.receipt_id == export.bundle_digest,
        "the evidence receipt id is not this bundle's digest",
    )?;
    bind(
        predicate.operation.parameters_digest == export.bundle_digest,
        "the evidence receipt covers different parameters",
    )?;
    bind(
        predicate.operation.target == export.bundle.warrant_id,
        "the evidence receipt names a different warrant",
    )?;
    bind(
        predicate.operation.class == REPORT_OPERATION_CLASS,
        "the evidence receipt is not over a report",
    )?;
    bind(
        predicate.actor.principal == export.bundle.subject,
        "the evidence receipt names a different subject",
    )?;
    match &predicate.outcome {
        Some(outcome) => bind(
            outcome.outcome_digest == export.bundle_digest,
            "the evidence receipt's outcome covers a different bundle",
        )?,
        None => {
            return Err(ReportError::Binding(
                "the evidence receipt carries no outcome".to_string(),
            ))
        }
    }

    let body = &export.notary_receipt.body;
    bind(
        body.actor_svid == export.bundle.subject,
        "the notary receipt names a different subject",
    )?;
    bind(
        body.operation_class == REPORT_OPERATION_CLASS,
        "the notary receipt is not over a report",
    )?;
    bind(
        body.timestamp == export.bundle.generated_at,
        "the notary receipt was issued at a different time than the bundle claims",
    )?;
    bind(
        body.verdict.is_allow() == export.bundle.authority_check.allowed,
        "the bundle's verdict disagrees with the signed notary verdict",
    )?;
    bind(
        matches!(predicate.decision.verdict, evidence::Verdict::Allow)
            == export.bundle.authority_check.allowed,
        "the evidence receipt's decision disagrees with the signed notary verdict",
    )?;

    verify_effect_receipts(export)?;

    Ok(())
}

/// Every chain the bundle lists must be present, verify as a pre->post pair (I-07, I-02), be
/// signed by the report's own key, and describe the handle and status the bundle says it does.
fn verify_effect_receipts(export: &SignedReport) -> Result<(), ReportError> {
    let signer = &export.evidence_receipt.signature.public_key;
    // A per-effect receipt may only ever say `advisory`, and this is the only place that
    // refuses anything else.
    //
    // `settle` mediates the staged path, not the world: an agent holding its own credential
    // opens the same pull request without passing through it. So `mediated` on one of these
    // asserts a non-bypassability this system does not have -- inside a signed bundle, which is
    // the worst place for a bound to be mislabeled.
    //
    // `evidence::check_mode_honesty` does not cover this. It refuses an *advisory* receipt that
    // claims non-bypassability, never a *mediated* one, so `check_mode_honesty(mediated, true)`
    // returns Ok. And the report-level mode checks operate on `export.evidence_receipt` alone.
    // Without this loop, a chain re-signed with the report's OWN key and `Mediated` passed both
    // verify paths clean while the bundle still read `advisory`. Three independent reviews of
    // this branch found that gap and each proved it the same way.
    for receipt in &export.effect_receipts {
        if receipt.predicate.binding.enforcement_mode != evidence::EnforcementMode::Advisory {
            return Err(ReportError::Binding(format!(
                "a per-effect receipt for {} carries enforcement mode {}; settle mediates the \
                 staged path and not the world, so only `advisory` is truthful here and \
                 `mediated` is refused",
                receipt.predicate.operation.target,
                mode_word_evidence(receipt.predicate.binding.enforcement_mode),
            )));
        }
    }
    // Phase as well as id, because `issue_post_commit` clones the pre-commit's predicate and
    // changes only the phase, the parent pointer and the outcome -- so a chain's two receipts
    // carry the SAME `binding.receipt_id`, and a lookup by id alone hands back the pre-commit
    // when asked for the post-commit. That reads as a phase violation two checks later, which is
    // a true error about the wrong thing.
    let find = |id: &str, phase: evidence::Phase| {
        export
            .effect_receipts
            .iter()
            .find(|r| r.predicate.binding.receipt_id == id && r.predicate.binding.phase == phase)
    };
    let missing = |what: &str, handle: &str| {
        ReportError::Evidence(
            evidence::EvidenceError::CommitGate(format!(
                "the {what} receipt for {handle} is missing from the export"
            ))
            .to_string(),
        )
    };
    let Some(section) = &export.bundle.effect_evidence else {
        if export.effect_receipts.is_empty() {
            return Ok(());
        }
        return Err(ReportError::Binding(
            "the export carries effect receipts the bundle does not list".to_string(),
        ));
    };
    let mut expected = 0usize;
    for line in &section.effects {
        expected += 1;
        let pre = find(&line.pre_receipt_id, evidence::Phase::PreCommit)
            .ok_or_else(|| missing("pre-commit", &line.handle))?;
        if pre.signature.public_key != *signer {
            return Err(ReportError::Binding(format!(
                "the pre-commit receipt for {} was signed by a key other than the report's",
                line.handle
            )));
        }
        if pre.predicate.operation.target != line.handle
            || pre.predicate.operation.class != line.tool
        {
            return Err(ReportError::Binding(format!(
                "the pre-commit receipt listed for {} is over a different effect",
                line.handle
            )));
        }
        if pre.predicate.actor.principal != export.bundle.subject {
            return Err(ReportError::Binding(format!(
                "the pre-commit receipt for {} names a different subject",
                line.handle
            )));
        }
        let Some(post_id) = &line.post_receipt_id else {
            evidence::verify_receipt(pre).map_err(|e| ReportError::Evidence(e.to_string()))?;
            evidence::verify_authority(&pre.predicate.authority)
                .map_err(|e| ReportError::Evidence(e.to_string()))?;
            if line.status != "unfinished" {
                return Err(ReportError::Binding(format!(
                    "{} has no post-commit receipt but the bundle records status {:?}",
                    line.handle, line.status
                )));
            }
            continue;
        };
        expected += 1;
        let post = find(post_id, evidence::Phase::PostCommit)
            .ok_or_else(|| missing("post-commit", &line.handle))?;
        evidence::verify_chain(pre, post).map_err(|e| ReportError::Evidence(e.to_string()))?;
        if post.signature.public_key != *signer {
            return Err(ReportError::Binding(format!(
                "the post-commit receipt for {} was signed by a key other than the report's",
                line.handle
            )));
        }
        let status = post
            .predicate
            .outcome
            .as_ref()
            .map(|o| o.status.as_str())
            .unwrap_or_default();
        if status != line.status {
            return Err(ReportError::Binding(format!(
                "the bundle records {} as {:?}; its post-commit receipt says {status:?}",
                line.handle, line.status
            )));
        }
    }
    if export.effect_receipts.len() != expected {
        return Err(ReportError::Binding(format!(
            "the export carries {} effect receipt(s) and the bundle lists {expected}; receipts \
             the bundle does not account for are refused",
            export.effect_receipts.len()
        )));
    }
    Ok(())
}

/// [`verify_export`], plus the question it cannot answer on its own: **whose key was that?**
///
/// # Why this function has to exist
///
/// [`verify_export`] is **anchor-free by construction**. Each receipt carries the public key it was
/// signed with, each is verified against that key, and the only cross-check is that the two receipts
/// agree on one key. Nothing in the file says *which* key should have signed it, so a file signed
/// end to end by a key nobody trusts is fully self-consistent and passes.
///
/// That is correct for what `verify_export` claims — "nothing has changed since signing" — and it is
/// not enough for the question a reader actually has. Anyone holding an Ed25519 keypair can
/// fabricate a bundle, sign both receipts with it, and produce a file that verifies. An evidence
/// archive is precisely a party that holds artifacts it did not produce and could be tempted to
/// improve, so the archive's own design target — *compromise of the server degrades availability,
/// never integrity* — is only true if the reader pins an anchor. This is that pin.
///
/// `anchor` is supplied by the caller and is **never defaulted** to a local key. A caller verifying
/// someone else's evidence against their own issuer key would get a pass or a fail from a key with
/// nothing to do with the case, which is worse than no check: it looks like an answer.
///
/// Where an anchor legitimately comes from is out of scope here and is stage 2 of the backend (the
/// trust directory). Until then it is the operator's `--issuer <hex>`, established out of band —
/// which is what [`verify_export`]'s own limitation sentence has always said has to happen.
///
/// # Errors
/// Everything [`verify_export`] returns, plus [`ReportError::Binding`] when the receipts were signed
/// by a key that is not `anchor`. Integrity is checked first, so a tampered file reads as tampered
/// rather than as merely foreign.
pub fn verify_export_signed_by(
    export: &SignedReport,
    anchor: &VerifyingKey,
) -> Result<(), ReportError> {
    verify_export(export)?;
    // `verify_export` has already established that both receipts carry the same key, so checking
    // one is checking both. Checking the evidence receipt specifically, rather than either, keeps
    // this from silently becoming a one-receipt check if that invariant is ever relaxed.
    let expected = hex::encode(anchor.to_bytes());
    let presented = &export.evidence_receipt.signature.public_key;
    if presented != &expected {
        return Err(ReportError::Binding(format!(
            "this report was signed by {presented}, not by the issuer you pinned ({expected}). \
             The signatures are intact — the file is internally consistent — but it was signed by \
             a different key, so it is not evidence about the issuer you asked about."
        )));
    }
    if export.notary_receipt.signature.public_key != expected {
        return Err(ReportError::Binding(
            "the notary receipt was signed by a key that is not the pinned issuer".to_string(),
        ));
    }
    Ok(())
}

/// [`verify_export`], plus the question it refuses to answer: **is this still true now?**
///
/// Everything `verify_export` checks, and then the evidence receipt's `expires_at` against an
/// explicit `now` — the warrant's own deadline, since past it the subject holds nothing and the
/// report's verdict describes authority that has lapsed.
///
/// `now` is an argument, not a clock read here, for the same reason the notary takes its `now` as
/// an input: a verification that consults the wall clock cannot be replayed by someone checking
/// your work.
///
/// Use this when acting on a report. Use [`verify_export`] when filing one — an archived report
/// must not become unverifiable simply because time passed.
///
/// # Errors
/// Everything [`verify_export`] returns, plus [`ReportError::Expired`] when the deadline has
/// passed. Integrity is checked first, so a tampered file is reported as tampered rather than as
/// merely old.
pub fn verify_export_at(export: &SignedReport, now: u64) -> Result<(), ReportError> {
    verify_export(export)?;
    if evidence::is_expired(&export.evidence_receipt, now) {
        return Err(ReportError::Expired {
            expires_at: export.evidence_receipt.predicate.binding.expires_at,
            now,
        });
    }
    Ok(())
}

// ── rendering ─────────────────────────────────────────────────────────────────────────

/// Render the bundle as the CLI's `warrantor report` has always printed it.
///
/// Byte-for-byte the output that existed before the bundle did. Signing is additive; changing what
/// a developer already reads every morning is not.
#[must_use]
pub fn render_cli(bundle: &ReportBundle) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "WARRANT {}  —  \"{}\"",
        bundle.warrant_id, bundle.goal
    ));
    lines.push(format!("state: {:?}", bundle.state));

    lines.push(String::new());
    lines.push("── AWAITING YOU ──".to_string());
    match &bundle.staged {
        StagedSection::Ordered { effects } if effects.is_empty() => {
            lines.push("  nothing staged".to_string());
        }
        StagedSection::Ordered { effects } => {
            for effect in effects {
                lines.push(format!("  {:<36}  {}", effect.handle, effect.tool));
                for (name, value) in &effect.arguments {
                    lines.push(format!("      {name}: {value}"));
                }
            }
        }
        StagedSection::Unavailable { reason } => {
            lines.push(format!("  release order cannot be computed: {reason}"));
        }
    }

    // The CLI has always required BOTH a repo and a worktree before showing this section.
    if bundle.repo.is_some() && bundle.worktree.is_some() {
        if let Some(changed) = &bundle.changed {
            lines.push(String::new());
            lines.push("── IT CHANGED ──".to_string());
            match changed {
                ChangedSection::Files { paths } if paths.is_empty() => {
                    lines.push("  no files changed".to_string());
                }
                ChangedSection::Files { paths } => {
                    for path in paths.iter().take(20) {
                        lines.push(format!("  {path}"));
                    }
                    if paths.len() > 20 {
                        lines.push(format!("  … and {} more", paths.len() - 20));
                    }
                }
                ChangedSection::Unreadable { reason } => {
                    lines.push(format!("  (worktree unreadable: {reason})"));
                }
            }
        }
    }

    lines.push(String::new());
    lines.push("── BOUNDS ──".to_string());
    for bound in &bundle.bound_strengths {
        lines.push(format!(
            "  {}",
            crate::render_bound(&bound.name, bound.strength)
        ));
    }
    // What each tier does not cover, beneath the column that would otherwise be read as one
    // uniform guarantee. L8-13: a rendering that names a tier without its limit is the defect.
    for legend in crate::render_tier_legend() {
        lines.push(format!("  {legend}"));
    }

    // Additive, and only when a ledger was actually read: with `spend: None` every line above and
    // below is byte for byte what it was before this section existed, which is what makes the
    // "the prose report is exactly what it always was" test a structural guarantee rather than a
    // promise. The block sits under BOUNDS because it is the budget bound's evidence, and it says
    // whose figures they are on its own line so no reader has to reach the limitations to find out.
    if let Some(spend) = &bundle.spend {
        lines.push(String::new());
        lines.push("── SPEND (OBSERVED, SELF-REPORTED) ──".to_string());
        lines.extend(crate::spend::section_lines(spend));
    }

    lines.push(String::new());
    lines.push("── EVIDENCE ──".to_string());
    // `None` means the staging queue could not be read, not that it was empty. Printing
    // `unwrap_or(0)` here would render an unknown count as "0 staged effect(s)" — the fail-open
    // answer, and indistinguishable from a genuinely empty queue. Every other unreadable-queue
    // path in this bundle says so out loud; so does this one.
    match bundle.staged_count {
        Some(count) => lines.push(format!("  {count} staged effect(s)")),
        None => lines.push(
            "  staged effect count UNKNOWN — the staging queue could not be read".to_string(),
        ),
    }
    match &bundle.chain_head {
        Some(head) => lines.push(format!("  chain head {head}")),
        None => {
            lines.push("  chain head UNKNOWN — the staging queue could not be read".to_string());
        }
    }
    if let Some(section) = &bundle.effect_evidence {
        lines.push(format!(
            "  {} effect receipt chain(s) from {} receipt(s): pre-commit before each effect, \
             post-commit after (advisory)",
            section.effects.len(),
            section.receipts_consulted
        ));
        for line in &section.effects {
            lines.push(format!(
                "    {:<36}  {:<10}  {}",
                line.handle,
                line.status,
                &line.pre_receipt_id[..12]
            ));
        }
    }

    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// The additive signed-evidence section, appended after the prose.
///
/// Separate from [`render_cli`] so the guarantee "the existing output is unchanged" is structural
/// rather than a promise: nothing here can alter a line above it.
#[must_use]
pub fn render_signature_section(signed: &SignedReport) -> String {
    let check = &signed.bundle.authority_check;
    let mut lines = vec![
        String::new(),
        "── SIGNED EVIDENCE ──".to_string(),
        format!("  bundle          {}", signed.bundle_digest),
        format!(
            "  authority       {} ({})",
            if check.allowed { "allow" } else { "deny" },
            check
                .denied_gate
                .clone()
                .unwrap_or_else(|| "all nine gates passed".to_string())
        ),
        format!("  decided by      {}", check.engine),
        format!(
            "  signed by       {}",
            signed.evidence_receipt.signature.public_key
        ),
        format!(
            "  receipts        {} (evidence, {}) + {} (notary, {})",
            signed.evidence_receipt.signature.algorithm,
            mode_word_evidence(signed.evidence_receipt.predicate.binding.enforcement_mode),
            signed.notary_receipt.signature.algorithm,
            mode_word_notary(signed.notary_receipt.body.enforcement_mode),
        ),
        format!(
            "  limitations     {} recorded in the bundle",
            signed.bundle.limitations.len()
        ),
    ];
    if let Some(section) = &signed.bundle.effect_evidence {
        // "signed by the same key", not "covered by this signature": the receipts sit outside the
        // bundle digest deliberately, so that removing one fails as a commit-gate violation naming
        // the effect rather than as a digest mismatch naming nothing.
        lines.push(format!(
            "  effects         {} receipt chain(s), each signed by this same key and checked \
             separately from the bundle digest",
            section.effects.len()
        ));
    }
    lines.push("  export it with  warrantor report <id> --export <path>".to_string());
    lines.push(String::new());
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

fn mode_word_evidence(mode: evidence::EnforcementMode) -> &'static str {
    match mode {
        evidence::EnforcementMode::Mediated => "mediated",
        evidence::EnforcementMode::Advisory => "advisory",
    }
}

fn mode_word_notary(mode: notary::EnforcementMode) -> &'static str {
    match mode {
        notary::EnforcementMode::Mediated => "mediated",
        notary::EnforcementMode::Observed => "observed",
    }
}

/// Render the bundle the way the MCP control endpoint has always returned it.
///
/// A second rendering, not a second implementation: the numbers come from the same bundle the CLI
/// prints and the receipts cover.
#[must_use]
pub fn render_mcp(bundle: &ReportBundle) -> String {
    let mut out = vec![
        format!("Warrant {} — {:?}", bundle.warrant_id, bundle.state),
        format!("  goal: {}", bundle.goal),
    ];

    if bundle.worktree.is_some() {
        match &bundle.changed {
            Some(ChangedSection::Files { paths }) if paths.is_empty() => {
                out.push("  changed files: none".to_string());
            }
            Some(ChangedSection::Files { paths }) => {
                out.push(format!("  changed files ({}):", paths.len()));
                for path in paths.iter().take(50) {
                    out.push(format!("    {path}"));
                }
            }
            Some(ChangedSection::Unreadable { reason }) => {
                out.push(format!("  changed files: could not read ({reason})"));
            }
            None => {}
        }
    }

    match &bundle.staged {
        StagedSection::Ordered { effects } if effects.is_empty() => {
            out.push("  staged effects: none".to_string());
        }
        StagedSection::Ordered { effects } => {
            out.push(format!(
                "  staged effects ({}) — NOT yet performed, in release order:",
                effects.len()
            ));
            for effect in effects {
                out.push(format!("    {}  {}", effect.handle, effect.tool));
            }
        }
        StagedSection::Unavailable { reason } => {
            out.push(format!("  staged effects: {reason}"));
        }
    }

    if let Some(section) = &bundle.effect_evidence {
        out.push(format!(
            "  {} effect receipt chain(s) from {} receipt(s): pre-commit before each effect, \
             post-commit after (advisory)",
            section.effects.len(),
            section.receipts_consulted
        ));
    }

    // Bounds were absent from this rendering entirely, so the one reader that most needs the
    // tier — the agent deciding whether a limit is a wall or a note — never saw one.
    out.push("  bounds (tier per bound):".to_string());
    for bound in &bundle.bound_strengths {
        out.push(format!(
            "    {}",
            crate::render_bound(&bound.name, bound.strength)
        ));
    }
    for legend in crate::render_tier_legend() {
        out.push(format!("    {legend}"));
    }

    // Same section, same source, same words as the CLI. The two renderings drifted once already
    // (a 20-file cap here, 50 there) and the fix was to render both from one bundle; rendering the
    // spend block from the same `section_lines` keeps that true for this section too.
    if let Some(spend) = &bundle.spend {
        out.push("  spend (observed, self-reported):".to_string());
        out.extend(crate::spend::section_lines(spend));
    }

    out.join("\n")
}
