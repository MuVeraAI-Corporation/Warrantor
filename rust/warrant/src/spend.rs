//! The budget bound, actually measured.
//!
//! # What was wrong before this module existed
//!
//! `budget_cents_observed` was labelled [`BoundStrength::Observed`], whose documented meaning is
//! "the system measures and reports, but cannot prevent". The system did not measure. The flag was
//! parsed at grant, stored in the signed claims, checked once in the delegation subset test, and
//! then read by nothing for the rest of the warrant's life. No counter existed, no figure was ever
//! printed, and `warrantor report` showed the word "observed" beside a number it had never looked
//! at. So the label was not merely weak — it was false in the one direction that matters, because
//! a developer reading "observed" reasonably concludes something is watching.
//!
//! This module makes the label true. It does not make it stronger.
//!
//! # Why the budget cannot become Enforced, and will not be relabelled here
//!
//! The agent talks to its model provider directly. Not one byte of that conversation passes through
//! Warrantor: there is no inference proxy in this path, no provider webhook, and no billing API
//! read. Every token count this module can ever see is a number the agent chose to hand us. An
//! agent that under-reports, mis-attributes, or simply never calls `warrantor spend` spends
//! whatever it likes and nothing here notices.
//!
//! That is the definition of [`BoundStrength::Observed`], and `bound_strengths()` is left exactly
//! as it was. `budget_cents_observed` is `Observed` before this module and `Observed` after it, and
//! a test in `tests/warrant.rs` fails if that ever changes.
//!
//! # What this module does add
//!
//! * **A durable ledger.** Spend accumulates across processes, in `<root>/spend/<id>.json`, so a
//!   cap means something over a whole run rather than within one invocation.
//! * **A refusal.** A reported usage that would exceed the cap is denied by
//!   [`warrantor_spend`]'s own budget primitive, is not recorded, and exits non-zero. It refuses
//!   the *record*, not the *call* — the call already happened, at the provider, without us.
//! * **Cost-aware routing metadata.** Given the operator's price table and what remains of the cap,
//!   [`quotes`] says what each approved backend would cost for the work in hand and which of them
//!   the remaining allowance still covers. That is advice, priced from the operator's own numbers.
//! * **Evidence.** Each accepted record re-signs the whole ledger through
//!   [`warrantor_spend::issue_receipt`], and `warrantor verify` checks it on a machine that has
//!   never seen this one.
//!
//! # Fail closed: an absent cap is a cap of zero, crate-wide
//!
//! [`WarrantBounds::budget_cents_observed`] is an `Option`, and an absent limit means *none*: a
//! warrant granted without `--budget` has a cap of zero micros, so any usage with a non-zero cost
//! is refused and only free backends can be recorded against it. The refusal names the fix rather
//! than being cryptic.
//!
//! ## The delegation gate reads it the same way
//!
//! [`WarrantBounds::contains`] once read `budget_cents_observed: None` on a *parent* as **no
//! ceiling**, so a budget-less warrant could mint a sub-warrant carrying an arbitrarily large
//! budget: the same `None` meant *zero* to this ledger and *unlimited* to the delegation check.
//! Both readings were defensible alone and they could not both be right, so this was recorded here
//! as a known inconsistency until it was decided. It is decided.
//!
//! The gate now compares `unwrap_or(0)` on both sides. A warrant granted without `--budget` can
//! delegate a ceiling of zero and nothing more — the child it could previously mint with an
//! arbitrarily large budget is refused at issue, so that child never exists.
//!
//! What did **not** change: a child may still not drop a ceiling its parent declared. Zero is the
//! smaller number, but whether a ceiling was *declared* is load-bearing beyond its value — an
//! undeclared budget is never [`SpendLedger::exhausted`], so `warrantor start` can never refuse
//! that warrant on budget grounds. Dropping a declared ceiling trades a start-gated budget for an
//! ungated one, which is an expansion of authority however small the number looks.
//!
//! # Why [`warrantor_spend::decide`] is not called
//!
//! The engine's entry point gates three ceilings at once — tokens, tool calls, and USD — and
//! consumes an `AgentBudget` and a `TaskBudget` together. A warrant declares exactly one of those
//! three: money. It declares no token budget and no tool-call budget, and there is nowhere honest
//! to get them from.
//!
//! Passing wide-open ceilings to satisfy the signature would be worse than not calling it. The
//! verdict `decide` returns is *signed*, and its `remaining_tokens` field would then carry an
//! invented figure into a receipt a third party reads. So this module uses the engine's budget
//! primitive ([`AgentBudget::spend`]) and its pricing ([`ModelBackend::cost_micros`]) directly, and
//! selects a backend with [`choose`] — which deliberately mirrors the engine's own private
//! selector, because selection is only reachable through `decide`. The duplication is stated here
//! rather than hidden; the alternative was a gate that looks like it ran and did not.
//!
//! `remaining_tokens` in an issued receipt is therefore always `0`, and that means "this warrant
//! declares no token allowance", not "the token allowance is exhausted". [`limitations`] says so in
//! the exported artifact, because a receipt read on its own could not tell the difference.
//!
//! [`BoundStrength::Observed`]: crate::BoundStrength::Observed
//! [`WarrantBounds::budget_cents_observed`]: crate::WarrantBounds::budget_cents_observed

use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use warrantor_spend as engine;

use crate::report::{canonicalize, sha256_hex};
use crate::WarrantBounds;

pub use warrantor_spend::{
    AgentBudget, CostReceipt, DenyReason, ModelBackend, SpendRequest, SpendVerdict, ENGINE_VERSION,
    MICROS_PER_DOLLAR,
};

/// Wire format of the persisted ledger.
pub const LEDGER_FORMAT: &str = "warrantor.spend-ledger/1";

/// Wire format of an exported, independently checkable ledger.
pub const LEDGER_EXPORT_FORMAT: &str = "warrantor.spend-export/1";

/// A warrant's budget is expressed in whole cents; the engine works in micros.
pub const MICROS_PER_CENT: u64 = MICROS_PER_DOLLAR / 100;

/// The only provenance any figure in this ledger has ever had.
///
/// A constant rather than a literal at each site so no surface can quietly claim a stronger
/// provenance than the one that exists.
pub const AGENT_REPORTED: &str = "agent-reported";

/// Where the observation stops. Printed wherever a spend figure is shown to a human.
pub const OBSERVATION_NOTE: &str =
    "These figures are what the agent reported about itself. Model API calls do not pass through \
     Warrantor, so nothing here measures a provider: an agent that under-reports, or never \
     reports, spends unobserved. The budget bound is observed, not enforced.";

/// File under the store root that holds the operator's model price table.
pub const BACKENDS_FILE: &str = "backends.json";

// ── errors ────────────────────────────────────────────────────────────────────────────

/// Everything that can go wrong reading, writing or checking a ledger.
#[derive(Debug, Error)]
pub enum SpendError {
    /// Serialisation or I/O failure.
    #[error("spend ledger: {0}")]
    Encode(String),
    /// The artifact declares a format this build does not speak.
    #[error("unknown format {found:?}; this build speaks {expected}")]
    Format {
        /// What the file declared.
        found: String,
        /// What this build reads.
        expected: &'static str,
    },
    /// The ledger does not hash to the digest its receipt signed.
    #[error(
        "ledger digest mismatch: the receipt signed {expected}, the ledger hashes to {actual}"
    )]
    Digest {
        /// The digest bound into the signed receipt.
        expected: String,
        /// What the ledger actually hashes to.
        actual: String,
    },
    /// The cost receipt does not verify.
    #[error("cost receipt: {0}")]
    Receipt(String),
    /// The receipt verifies but does not describe this ledger.
    #[error("{0}")]
    Binding(String),
    /// No usable model price table.
    #[error("{0}")]
    Backends(String),
}

// ── the cap, read from the signed bounds ──────────────────────────────────────────────

/// Did the developer declare a spend ceiling at all?
#[must_use]
pub fn cap_declared(bounds: &WarrantBounds) -> bool {
    bounds.budget_cents_observed.is_some()
}

/// The warrant's spend ceiling in micros, read fresh from the signed claims every time.
///
/// Deliberately not cached in the ledger's own authority: the ledger is mutable, unsigned state
/// between records, and a cap taken from it could be edited upward by anyone who can write the
/// file. The cap comes from [`WarrantBounds`], which lives inside the signed claims.
///
/// An absent ceiling is **zero**, not unlimited. See the module docs.
#[must_use]
pub fn cap_micros(bounds: &WarrantBounds) -> u64 {
    bounds
        .budget_cents_observed
        .map_or(0, |cents| cents.saturating_mul(MICROS_PER_CENT))
}

/// Render micros as dollars, exactly, with no floating point anywhere.
#[must_use]
pub fn usd(micros: u64) -> String {
    format!(
        "${}.{:06}",
        micros / MICROS_PER_DOLLAR,
        micros % MICROS_PER_DOLLAR
    )
}

// ── what an agent claims it used ──────────────────────────────────────────────────────

/// One usage claim, as reported by the agent.
///
/// Named a *claim* rather than a measurement throughout, because that is what it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageClaim {
    /// The backend the agent says it used. `None` asks for the cheapest approved safe one.
    pub backend: Option<String>,
    /// Input tokens claimed.
    pub input_tokens: u64,
    /// Output tokens claimed.
    pub output_tokens: u64,
}

impl UsageClaim {
    /// Total tokens claimed, saturating.
    #[must_use]
    pub fn tokens(&self) -> u64 {
        self.input_tokens.saturating_add(self.output_tokens)
    }
}

// ── the ledger ────────────────────────────────────────────────────────────────────────

/// One accepted usage record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// When it was recorded, epoch seconds.
    pub at: u64,
    /// The backend it was priced against.
    pub backend: String,
    /// Input tokens claimed.
    pub input_tokens: u64,
    /// Output tokens claimed.
    pub output_tokens: u64,
    /// What the operator's price table says that cost, in micros.
    pub cost_micros: u64,
    /// Provenance. Always [`AGENT_REPORTED`]; nothing in this deployment can produce anything else.
    pub source: String,
}

/// A warrant's observed spend, accumulated across processes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendLedger {
    /// Wire format; see [`LEDGER_FORMAT`].
    pub format: String,
    /// The warrant this ledger belongs to.
    pub warrant_id: String,
    /// The subject the warrant was granted to, used as the engine's agent id.
    pub subject: String,
    /// The ceiling as read from the warrant's signed bounds at the last record.
    pub cap_micros: u64,
    /// Whether that ceiling was declared, or is zero because none was.
    pub cap_declared: bool,
    /// Total accepted spend in micros. Equals the sum of the entries' costs, and
    /// [`verify_spend`] refuses a ledger where it does not.
    pub spent_micros: u64,
    /// Every accepted record, oldest first.
    pub entries: Vec<LedgerEntry>,
}

impl SpendLedger {
    /// An empty ledger for a warrant that has recorded nothing.
    #[must_use]
    pub fn new(bounds: &WarrantBounds, warrant_id: &str, subject: &str) -> Self {
        Self {
            format: LEDGER_FORMAT.to_string(),
            warrant_id: warrant_id.to_string(),
            subject: subject.to_string(),
            cap_micros: cap_micros(bounds),
            cap_declared: cap_declared(bounds),
            spent_micros: 0,
            entries: Vec::new(),
        }
    }

    /// What is left of the ceiling, saturating at zero.
    #[must_use]
    pub fn remaining_micros(&self) -> u64 {
        self.cap_micros.saturating_sub(self.spent_micros)
    }

    /// Has the declared ceiling been reached?
    ///
    /// Answers `false` when no ceiling was declared: an undeclared cap refuses *records*, but a
    /// warrant that never had a budget was never budget-exhausted, and refusing to start it on
    /// that basis would be a different bound wearing this one's name.
    #[must_use]
    pub fn exhausted(&self) -> bool {
        self.cap_declared && self.spent_micros >= self.cap_micros
    }

    /// When the last record landed.
    #[must_use]
    pub fn last_at(&self) -> Option<u64> {
        self.entries.last().map(|entry| entry.at)
    }

    /// The canonical JSON encoding — the exact bytes the digest covers.
    ///
    /// # Errors
    /// [`SpendError::Encode`] if the ledger does not serialise.
    pub fn canonical(&self) -> Result<String, SpendError> {
        let value = serde_json::to_value(self)
            .map_err(|e| SpendError::Encode(format!("serialise ledger: {e}")))?;
        serde_json::to_string(&canonicalize(&value))
            .map_err(|e| SpendError::Encode(format!("canonical ledger: {e}")))
    }

    /// SHA-256 hex of [`Self::canonical`].
    ///
    /// # Errors
    /// As [`Self::canonical`].
    pub fn digest(&self) -> Result<String, SpendError> {
        Ok(sha256_hex(self.canonical()?.as_bytes()))
    }

    /// The sum of the entries, computed rather than trusted.
    #[must_use]
    pub fn summed_micros(&self) -> u64 {
        self.entries
            .iter()
            .fold(0u64, |total, entry| total.saturating_add(entry.cost_micros))
    }
}

// ── backend selection and pricing ─────────────────────────────────────────────────────

/// Pick the backend a claim is priced against.
///
/// Mirrors [`warrantor_spend`]'s own private selector — unsafe backends are never eligible, a named
/// backend must be present *and* safe, and an unnamed one takes the cheapest safe entry — because
/// the engine exposes selection only through `decide`, which this module cannot honestly call. See
/// the module docs.
///
/// # Errors
/// [`DenyReason::NoSafeBackend`] when the table offers none, [`DenyReason::BackendNotApproved`]
/// when a named one is absent or is not marked safe.
pub fn choose<'a>(
    requested: Option<&str>,
    backends: &'a [ModelBackend],
) -> Result<&'a ModelBackend, DenyReason> {
    let safe: Vec<&ModelBackend> = backends.iter().filter(|b| b.safe).collect();
    if safe.is_empty() {
        return Err(DenyReason::NoSafeBackend);
    }
    match requested {
        Some(id) => safe
            .into_iter()
            .find(|b| b.id == id)
            .ok_or(DenyReason::BackendNotApproved),
        None => safe
            .into_iter()
            .min_by_key(|b| {
                (
                    b.price_per_1k_input_micros
                        .saturating_add(b.price_per_1k_output_micros),
                    b.id.clone(),
                )
            })
            .ok_or(DenyReason::NoSafeBackend),
    }
}

/// What one backend would cost for the work in hand, and whether the remaining cap covers it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendQuote {
    /// The backend's id.
    pub backend: String,
    /// Whether the operator marked it safe. An unsafe backend is never selectable.
    pub safe: bool,
    /// What the price table says this claim costs there, in micros.
    pub cost_micros: u64,
    /// Whether what remains of the declared cap covers that cost.
    pub affordable: bool,
}

/// Cost-aware routing metadata: every approved backend priced for `claim`, cheapest first.
///
/// This is advice computed from the operator's own price table and the ledger's remaining
/// allowance. It routes nothing — Warrantor is not in the inference path and cannot be. It answers
/// "which model can this warrant still afford for this piece of work", which is the question a
/// developer actually has when a budget is nearly gone.
#[must_use]
pub fn quotes(
    ledger: &SpendLedger,
    claim: &UsageClaim,
    backends: &[ModelBackend],
) -> Vec<BackendQuote> {
    let remaining = ledger.remaining_micros();
    let mut out: Vec<BackendQuote> = backends
        .iter()
        .map(|backend| {
            let cost = backend.cost_micros(claim.input_tokens, claim.output_tokens);
            BackendQuote {
                backend: backend.id.clone(),
                safe: backend.safe,
                cost_micros: cost,
                affordable: backend.safe && cost <= remaining,
            }
        })
        .collect();
    // Safe first, then cheapest, then by id so the order is total and the output is stable.
    out.sort_by(|a, b| {
        b.safe
            .cmp(&a.safe)
            .then(a.cost_micros.cmp(&b.cost_micros))
            .then(a.backend.cmp(&b.backend))
    });
    out
}

// ── recording ─────────────────────────────────────────────────────────────────────────

/// The outcome of offering one usage claim to the ledger.
#[derive(Debug, Clone)]
pub struct SpendDecision {
    /// The engine's verdict. `Allow` means the claim was recorded; `Deny` means nothing changed.
    pub verdict: SpendVerdict,
    /// The request the verdict answers, kept so [`sign`] receipts the same decision rather than
    /// re-deciding and risking a receipt that disagrees with the ledger.
    pub request: SpendRequest,
}

impl SpendDecision {
    /// Was the claim recorded?
    #[must_use]
    pub fn allowed(&self) -> bool {
        matches!(self.verdict, SpendVerdict::Allow { .. })
    }
}

/// Offer one agent-reported usage claim to the ledger.
///
/// On `Allow` the ledger is advanced in place; on `Deny` it is left untouched, matching the
/// engine's own contract. The money gate is [`AgentBudget::spend`] — the engine's, not a
/// reimplementation — so the cap comparison is the one the engine tests cover.
///
/// Recording is **not** permission to spend. The provider call this describes has already happened,
/// somewhere Warrantor cannot see. A denial means the ledger refuses to carry the claim and that
/// the operator should act; it does not mean the money was not spent.
pub fn record(
    bounds: &WarrantBounds,
    ledger: &mut SpendLedger,
    claim: &UsageClaim,
    backends: &[ModelBackend],
    at: u64,
) -> SpendDecision {
    // Re-read the ceiling from the signed claims on every record, so an edited ledger file cannot
    // raise its own cap and a re-granted bound is picked up immediately.
    ledger.cap_micros = cap_micros(bounds);
    ledger.cap_declared = cap_declared(bounds);

    let request = SpendRequest {
        agent_id: ledger.subject.clone(),
        task_id: ledger.warrant_id.clone(),
        estimated_input_tokens: claim.input_tokens,
        estimated_output_tokens: claim.output_tokens,
        requested_backend: claim.backend.clone(),
        // Warrantor declares no tool-call ceiling, and the tool allowlist is a different bound
        // enforced elsewhere. Zero is the honest value: no tool-call allowance is consumed here.
        tool_calls: 0,
    };

    let chosen = match choose(claim.backend.as_deref(), backends) {
        Ok(backend) => backend,
        Err(reason) => {
            return SpendDecision {
                verdict: SpendVerdict::Deny { reason },
                request,
            }
        }
    };
    let cost = chosen.cost_micros(claim.input_tokens, claim.output_tokens);

    let mut budget = AgentBudget {
        agent_id: ledger.subject.clone(),
        usd_cap_micros: ledger.cap_micros,
        usd_spent_micros: ledger.spent_micros,
    };
    match budget.spend(cost) {
        Ok(()) => {
            ledger.spent_micros = budget.usd_spent_micros;
            ledger.entries.push(LedgerEntry {
                at,
                backend: chosen.id.clone(),
                input_tokens: claim.input_tokens,
                output_tokens: claim.output_tokens,
                cost_micros: cost,
                source: AGENT_REPORTED.to_string(),
            });
            SpendDecision {
                verdict: SpendVerdict::Allow {
                    cost_micros: cost,
                    remaining_usd_micros: budget.remaining(),
                    // Zero because this warrant declares no token allowance -- not because one was
                    // exhausted. `limitations` states this in the exported artifact.
                    remaining_tokens: 0,
                    chosen_backend: chosen.id.clone(),
                },
                request,
            }
        }
        Err(reason) => SpendDecision {
            verdict: SpendVerdict::Deny { reason },
            request,
        },
    }
}

// ── evidence ──────────────────────────────────────────────────────────────────────────

/// A ledger plus the proof over it, checkable by someone who has never seen this machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedSpend {
    /// Wire format; see [`LEDGER_EXPORT_FORMAT`].
    pub format: String,
    /// SHA-256 hex of the canonical ledger. Bound into the receipt's `task_id`.
    pub ledger_digest: String,
    /// The ledger itself.
    pub ledger: SpendLedger,
    /// The spend engine's own cost receipt over the decision that produced this ledger state.
    pub receipt: CostReceipt,
    /// Everything this artifact does **not** establish. Never empty.
    pub limitations: Vec<String>,
}

/// What a verified ledger does not prove.
///
/// Never empty, and the first line is the one that matters: every figure is self-reported.
#[must_use]
pub fn limitations() -> Vec<String> {
    vec![
        "Every figure here was reported by the agent about itself. Model API calls do not pass \
         through Warrantor, so no provider usage record, invoice or billing API was consulted. An \
         agent that under-reports or never reports is not caught by this ledger."
            .to_string(),
        "budget_cents_observed is BoundStrength::Observed and remains so. This ledger measures and \
         refuses to record; it cannot refuse a model call, because it is not in the path of one."
            .to_string(),
        "Costs are computed from the operator's own price table in the store's backends.json. They \
         are the operator's prices, not the provider's, and a stale table produces a confident \
         wrong number."
            .to_string(),
        "The cost receipt's remaining_tokens is 0 because this warrant declares no token \
         allowance. It does not mean a token budget was exhausted."
            .to_string(),
        "A warrant granted without --budget has a ceiling of zero, so only zero-cost usage can be \
         recorded against it. An absent limit is none, never unlimited."
            .to_string(),
        "Verifying a signature proves who signed and that nothing changed since. It does not \
         establish that the signing key is trusted; that has to come from somewhere else."
            .to_string(),
    ]
}

/// The `task_id` that binds a receipt to one exact ledger state.
///
/// The engine's receipt body has no field for a ledger digest, and adding one would be a change to
/// a plane crate for one consumer's convenience. Composing the warrant id with the digest into the
/// task identifier binds the whole ledger into the signature with no new machinery: change any
/// entry and the digest changes, so the receipt no longer describes the file it sits in.
#[must_use]
pub fn binding_task_id(warrant_id: &str, ledger_digest: &str) -> String {
    format!("{warrant_id}@{ledger_digest}")
}

/// Sign a ledger and the decision that produced its current state.
///
/// # Errors
/// [`SpendError::Encode`] if the ledger does not serialise.
pub fn sign(
    ledger: &SpendLedger,
    decision: &SpendDecision,
    key: &SigningKey,
    key_id: &str,
    at: u64,
) -> Result<SignedSpend, SpendError> {
    let ledger_digest = ledger.digest()?;
    let mut request = decision.request.clone();
    request.task_id = binding_task_id(&ledger.warrant_id, &ledger_digest);
    let receipt = engine::issue_receipt(&decision.verdict, &request, at, key, key_id);
    Ok(SignedSpend {
        format: LEDGER_EXPORT_FORMAT.to_string(),
        ledger_digest,
        ledger: ledger.clone(),
        receipt,
        limitations: limitations(),
    })
}

/// Check a signed ledger with nothing but the file.
///
/// # Errors
/// [`SpendError`] naming the first check that failed.
pub fn verify_spend(signed: &SignedSpend) -> Result<(), SpendError> {
    if signed.format != LEDGER_EXPORT_FORMAT {
        return Err(SpendError::Format {
            found: signed.format.clone(),
            expected: LEDGER_EXPORT_FORMAT,
        });
    }
    if signed.ledger.format != LEDGER_FORMAT {
        return Err(SpendError::Format {
            found: signed.ledger.format.clone(),
            expected: LEDGER_FORMAT,
        });
    }
    let actual = signed.ledger.digest()?;
    if actual != signed.ledger_digest {
        return Err(SpendError::Digest {
            expected: signed.ledger_digest.clone(),
            actual,
        });
    }
    engine::verify_receipt(&signed.receipt).map_err(|e| SpendError::Receipt(e.to_string()))?;

    // The receipt verifies. Now: does it describe THIS ledger?
    let expected_task = binding_task_id(&signed.ledger.warrant_id, &signed.ledger_digest);
    if signed.receipt.body.task_id != expected_task {
        return Err(SpendError::Binding(format!(
            "the cost receipt is bound to {:?}, not to this ledger ({expected_task})",
            signed.receipt.body.task_id
        )));
    }
    if signed.receipt.body.agent_id != signed.ledger.subject {
        return Err(SpendError::Binding(
            "the cost receipt names a different subject than the ledger".to_string(),
        ));
    }
    if signed.receipt.body.engine_version != ENGINE_VERSION {
        return Err(SpendError::Binding(format!(
            "the cost receipt was issued by {:?}, not {ENGINE_VERSION}",
            signed.receipt.body.engine_version
        )));
    }

    // Internal arithmetic, recomputed rather than trusted: a ledger whose total does not match its
    // own entries is either corrupt or edited, and either way its cap comparison meant nothing.
    let summed = signed.ledger.summed_micros();
    if summed != signed.ledger.spent_micros {
        return Err(SpendError::Binding(format!(
            "the ledger totals {} micros but its entries sum to {summed}",
            signed.ledger.spent_micros
        )));
    }
    if let SpendVerdict::Allow {
        remaining_usd_micros,
        ..
    } = &signed.receipt.body.verdict
    {
        let expected = signed.ledger.remaining_micros();
        if *remaining_usd_micros != expected {
            return Err(SpendError::Binding(format!(
                "the receipt claims {remaining_usd_micros} micros remaining; the ledger and its \
                 cap leave {expected}"
            )));
        }
    }
    if signed.ledger.spent_micros > signed.ledger.cap_micros {
        return Err(SpendError::Binding(format!(
            "the ledger records {} micros spent against a ceiling of {}; a ledger cannot record \
             past its own cap",
            signed.ledger.spent_micros, signed.ledger.cap_micros
        )));
    }
    // A ledger with no caveats would teach its reader to hear more than was said.
    if signed.limitations.is_empty() {
        return Err(SpendError::Binding(
            "the export carries no limitations; every spend figure here is self-reported and an \
             artifact that does not say so is not one this build will accept"
                .to_string(),
        ));
    }
    Ok(())
}

// ── storage ───────────────────────────────────────────────────────────────────────────

/// The per-warrant ledger directory under a store root.
#[derive(Debug, Clone)]
pub struct SpendStore {
    root: PathBuf,
}

impl SpendStore {
    /// Open (or create) `<root>/spend/`.
    ///
    /// # Errors
    /// [`SpendError::Encode`] if the directory cannot be created.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, SpendError> {
        let root = root.as_ref().join("spend");
        std::fs::create_dir_all(&root)
            .map_err(|e| SpendError::Encode(format!("create spend dir: {e}")))?;
        Ok(Self { root })
    }

    /// Path a warrant's ledger occupies.
    #[must_use]
    pub fn path(&self, warrant_id: &str) -> PathBuf {
        self.root.join(format!("{warrant_id}.json"))
    }

    /// Persist a signed ledger, returning where it landed.
    ///
    /// Written to a temporary file and renamed, like [`crate::store::WarrantStore::save`]: a
    /// half-written ledger would understate spend, which is the wrong direction to fail in.
    ///
    /// # Errors
    /// [`SpendError::Encode`] on serialisation or I/O failure.
    pub fn save(&self, signed: &SignedSpend) -> Result<PathBuf, SpendError> {
        let path = self.path(&signed.ledger.warrant_id);
        let temp = path.with_extension("json.tmp");
        let body = serde_json::to_vec_pretty(signed)
            .map_err(|e| SpendError::Encode(format!("serialise ledger: {e}")))?;
        std::fs::write(&temp, &body)
            .map_err(|e| SpendError::Encode(format!("write {}: {e}", temp.display())))?;
        std::fs::rename(&temp, &path)
            .map_err(|e| SpendError::Encode(format!("rename {}: {e}", path.display())))?;
        Ok(path)
    }

    /// Load a warrant's ledger, or an empty one when it has recorded nothing.
    ///
    /// Fail-closed in three ways, all of which matter more than convenience:
    ///
    /// * A file that will not parse is an error, not an empty ledger. Treating an unreadable
    ///   ledger as zero spend would reset the cap for anyone who can corrupt a file.
    /// * A ledger whose proof does not check out is an error.
    /// * A ledger signed by a key other than `issuer` is an error. The trust anchor is the key on
    ///   disk, never the key the artifact carries about itself — the same discipline the report's
    ///   chain gate uses.
    ///
    /// # Errors
    /// [`SpendError`] naming which of those failed.
    pub fn load(
        &self,
        bounds: &WarrantBounds,
        warrant_id: &str,
        subject: &str,
        issuer: &VerifyingKey,
    ) -> Result<SpendLedger, SpendError> {
        let path = self.path(warrant_id);
        let Ok(body) = std::fs::read(&path) else {
            return Ok(SpendLedger::new(bounds, warrant_id, subject));
        };
        let signed: SignedSpend = serde_json::from_slice(&body).map_err(|e| {
            SpendError::Encode(format!(
                "{} exists but does not parse: {e}. Refusing to treat an unreadable ledger as zero \
                 spend.",
                path.display()
            ))
        })?;
        verify_spend(&signed)?;
        let expected_key = hex::encode(issuer.to_bytes());
        if signed.receipt.signature_public_key != expected_key {
            return Err(SpendError::Binding(format!(
                "{} is signed by {}, not by this store's issuer key. A ledger vouching for itself \
                 with its own key proves nothing.",
                path.display(),
                signed.receipt.signature_public_key
            )));
        }
        if signed.ledger.warrant_id != warrant_id {
            return Err(SpendError::Binding(format!(
                "{} holds the ledger for {}, not {warrant_id}",
                path.display(),
                signed.ledger.warrant_id
            )));
        }
        Ok(signed.ledger)
    }
}

/// Read the operator's model price table from `<root>/backends.json`.
///
/// There is no built-in table and no default price. Warrantor does not know what any model costs,
/// and a guessed price would go straight into a signed receipt as though it were a fact. So an
/// absent table is an error whose message says exactly what to write and where — fail closed, and
/// closed loudly enough to be fixable.
///
/// # Errors
/// [`SpendError::Backends`] if the file is missing, unparseable or empty.
pub fn load_backends(root: &Path) -> Result<Vec<ModelBackend>, SpendError> {
    let path = root.join(BACKENDS_FILE);
    let body = std::fs::read(&path).map_err(|_| {
        SpendError::Backends(format!(
            "no model price table at {}. Warrantor does not know what any model costs and will not \
             guess one into a signed receipt. Write the file, for example:\n\
             [\n  {{\"id\": \"gpt-4o\", \"price_per_1k_input_micros\": 2500, \
             \"price_per_1k_output_micros\": 10000, \"safe\": true}},\n  \
             {{\"id\": \"local-llama\", \"price_per_1k_input_micros\": 0, \
             \"price_per_1k_output_micros\": 0, \"safe\": true}}\n]",
            path.display()
        ))
    })?;
    let backends: Vec<ModelBackend> = serde_json::from_slice(&body)
        .map_err(|e| SpendError::Backends(format!("{} does not parse: {e}", path.display())))?;
    if backends.is_empty() {
        return Err(SpendError::Backends(format!(
            "{} declares no backends, so nothing is approved and nothing can be priced",
            path.display()
        )));
    }
    Ok(backends)
}

// ── the report section ────────────────────────────────────────────────────────────────

/// The budget bound as the report carries it: declared ceiling, observed spend, and provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendSection {
    /// The declared ceiling in micros. Zero when none was declared.
    pub cap_micros: u64,
    /// Whether a ceiling was declared at all.
    pub cap_declared: bool,
    /// Observed spend in micros.
    pub spent_micros: u64,
    /// What is left of the ceiling.
    pub remaining_micros: u64,
    /// How many usage claims were recorded.
    pub records: usize,
    /// When the last one landed.
    pub last_at: Option<u64>,
    /// Provenance of every figure above. Always [`AGENT_REPORTED`].
    pub source: String,
}

/// Summarise a ledger for the report bundle.
#[must_use]
pub fn section(ledger: &SpendLedger) -> SpendSection {
    SpendSection {
        cap_micros: ledger.cap_micros,
        cap_declared: ledger.cap_declared,
        spent_micros: ledger.spent_micros,
        remaining_micros: ledger.remaining_micros(),
        records: ledger.entries.len(),
        last_at: ledger.last_at(),
        source: AGENT_REPORTED.to_string(),
    }
}

/// The report's spend block, as lines. Shared by the CLI and MCP renderings so they cannot drift.
#[must_use]
pub fn section_lines(section: &SpendSection) -> Vec<String> {
    let mut lines = Vec::new();
    if section.cap_declared {
        lines.push(format!(
            "  ceiling                 {} (declared)",
            usd(section.cap_micros)
        ));
        lines.push(format!(
            "  observed spend          {} ({} record(s), {})",
            usd(section.spent_micros),
            section.records,
            section.source
        ));
        lines.push(format!(
            "  remaining               {}",
            usd(section.remaining_micros)
        ));
    } else {
        lines.push("  ceiling                 none declared, so none granted".to_string());
        lines.push(format!(
            "  observed spend          {} ({} record(s), {})",
            usd(section.spent_micros),
            section.records,
            section.source
        ));
    }
    lines
}

/// The word for a denial, in terms the operator can act on.
#[must_use]
pub fn reason_word(reason: &DenyReason) -> &'static str {
    match reason {
        DenyReason::UsdCapExceeded => "the warrant's spend ceiling",
        DenyReason::TokenBudgetExhausted => "a token budget",
        DenyReason::ToolCallBudgetExhausted => "a tool-call budget",
        DenyReason::NoSafeBackend => "no approved safe backend",
        DenyReason::BackendNotApproved => "the backend is not approved",
    }
}
