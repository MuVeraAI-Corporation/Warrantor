//! # warrantor-warrant (W1)
//!
//! A **warrant** is bounded authority granted in advance and answerable afterwards. It is the
//! unit that lets a developer walk away from a running agent: everything the agent may do is
//! enumerated before it starts, everything it does is evidenced as it runs, and everything it
//! changes outside its own worktree is atomic at the end.
//!
//! ## Why this is not the Agent Authority Envelope
//!
//! The AAE (P1, validated by [`warrantor_authority_spec`]) authorizes **one action**. A warrant
//! bounds **one task** and has a lifecycle: it opens, accumulates staged effects, and then either
//! settles or voids. The two compose rather than compete — a warrant is the session-scoped bound
//! from which per-action AAEs are issued, and an AAE can never exceed the warrant that produced it.
//!
//! ## The security property that matters most
//!
//! **The acting agent cannot settle its own warrant.** If it could, staging would be decoration:
//! an agent that wanted to open a pull request would simply settle and open it. So settle authority
//! is not a policy check that could be misconfigured — it is a *separate keypair the agent never
//! holds*. The agent receives a [`CapabilityToken`] that is act-scoped by construction; the settle
//! key lives with the developer or the CI identity, and is never loaded into any process the agent
//! shares. See [`Warrant::verify_settle`].
//!
//! This mirrors the approach already taken in the flight recorder, where `commit()` is unreachable
//! without durable evidence because `PendingAction` has no public constructor. Make the wrong thing
//! *impossible* rather than *forbidden*.

// `deny`, not `forbid`. The crate was unsafe-free until the supervisor needed a Windows job object
// and a Unix `pre_exec` -- guarantees that ARE kernel objects and cannot be expressed in safe Rust.
// `deny` still makes any new unsafe a compile error unless it is explicitly annotated, so the two
// exceptions in `supervise` stay visible instead of opening the door crate-wide.
#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod adapters;
pub mod archive_client;
pub mod autofile;
pub mod daemon;
pub mod egress;
pub mod guard;
pub mod harness;
pub mod mcp;
pub mod mcp_endpoints;
pub mod notify;
pub mod operators;
pub mod proxy;
pub mod report;
pub mod retention;
pub mod serve;
pub mod settle;
pub mod spend;
pub mod staging;
pub mod stop;
pub mod store;
pub mod supervise;
pub mod trust;
pub mod upstream;
pub mod worktree;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

pub use warrantor_authority_spec::SideEffectClass;

/// Wire-format identifier. Present in every warrant so a future format change is detectable
/// rather than silently misparsed.
pub const WARRANT_FORMAT: &str = "warrantor.warrant/1";

/// The subject `warrantor grant` records when `--subject` is not given.
///
/// A placeholder, not an identity. Named as a constant because anything answering "what does this
/// machine hold, and for whom" has to be able to say how much of its answer is this one string: a
/// per-person breakdown of warrants that all carry the same default is a fabricated answer.
pub const DEFAULT_CLI_SUBJECT: &str = "spiffe://muveraai.com/agent/local";

/// The subject the MCP `warrant_grant` tool records. That path takes no subject argument at all.
pub const DEFAULT_MCP_SUBJECT: &str = "spiffe://muveraai.com/agent/mcp";

/// Domain separator for warrant signatures.
///
/// Length-prefixed and distinct from every other signature this system produces, so a signature
/// over some other object can never be replayed as a warrant. The agent-identity service learned
/// this the hard way: two token types signed with one key over untagged JSON meant a low-value
/// capability token verified as a high-value SVID.
const WARRANT_DOMAIN: &[u8] = b"warrantor-warrant-v1";

/// Domain separator for capability tokens, distinct from [`WARRANT_DOMAIN`].
const CAPABILITY_DOMAIN: &[u8] = b"warrantor-capability-v1";

/// Errors produced when constructing, validating or settling a warrant.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WarrantError {
    /// The wire format is not one this build understands.
    #[error("unknown warrant format {0:?}; this build speaks {WARRANT_FORMAT}")]
    UnknownFormat(String),
    /// The warrant's own bounds are not self-consistent.
    #[error("invalid warrant: {0}")]
    Invalid(String),
    /// The signature did not verify against the expected key.
    #[error("warrant signature invalid")]
    SignatureInvalid,
    /// The warrant is past its deadline.
    #[error("warrant expired at {expires_at}; now is {now}")]
    Expired {
        /// Deadline, epoch seconds.
        expires_at: u64,
        /// The time it was checked against.
        now: u64,
    },
    /// A settle was attempted with a key that is not the settle authority.
    ///
    /// This is the error that keeps the design honest: an agent presenting its own key here must
    /// be refused, and the refusal is cryptographic rather than advisory.
    #[error("settle refused: the presented key is not this warrant's settle authority")]
    NotSettleAuthority,
    /// A child warrant claimed authority its parent does not hold.
    #[error("sub-warrant would expand authority: {0}")]
    AuthorityExpanded(String),
    /// The operation is not legal from the warrant's current state.
    #[error("warrant is {state:?}; {operation} is not permitted from that state")]
    WrongState {
        /// Current state.
        state: WarrantState,
        /// What was attempted.
        operation: &'static str,
    },
    /// Encoding failed.
    #[error("encode: {0}")]
    Encode(String),
}

/// Where a warrant is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarrantState {
    /// The agent is acting. Local writes land in the worktree; external effects stage.
    Open,
    /// The warrant ended on schedule (deadline or budget) with staged effects awaiting review.
    /// Distinct from [`Self::Void`] on purpose: running out of time is not misbehaviour, so the
    /// work is held rather than destroyed.
    Held,
    /// Staged effects were released and the worktree merged. The only state in which the outside
    /// world changed.
    Settled,
    /// Staged effects were discarded and the worktree deleted. Receipts survive — the record of
    /// what was attempted is evidence, not garbage.
    Void,
}

/// How strongly a bound is actually enforced.
///
/// Presenting an advisory bound as though it were enforced is how a developer ends up trusting
/// something that cannot hold. A token budget parsed from an agent's own self-reporting is not the
/// same kind of promise as a tool allowlist the proxy refuses to forward, and the difference is
/// surfaced rather than hidden.
///
/// # Three tiers, not two
///
/// There were two, and two was one short in a way that mattered. `delegation_depth` is held by an
/// Ed25519 signature and `expires_at` by an OS process link — neither can be bypassed by the agent
/// at all. `tools`, `egress_hosts` and `staged_classes` are held by the MCP proxy, which sees only
/// what the agent routes through it: there is no network namespace, no seccomp filter and no
/// firewall anywhere in this crate, so an agent granted shell access reaches the network without
/// passing the broker.
///
/// Both were labelled `Enforced`. Both are real, and they are not the same promise — the first
/// holds against an agent trying to escape, the second holds against an agent behaving like an
/// agent. Collapsing them meant the strongest claim in the product was made on behalf of the
/// weaker case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundStrength {
    /// The system refuses the action, and the agent cannot route around the thing that refuses.
    ///
    /// Held by cryptography or by the operating system: a signature it cannot forge, a process
    /// link it cannot outlive.
    Enforced,
    /// The system refuses the action at a chokepoint the agent could decline to use.
    ///
    /// Held by the MCP proxy. Real against an agent using its tools — which is what every current
    /// coding agent does, all the time — and not a containment boundary. Warrantor composes with a
    /// sandbox here rather than replacing one.
    Mediated,
    /// The system measures and reports, but cannot prevent. Best-effort.
    Observed,
}

/// Everything a warrant permits. Absent fields mean "not permitted", never "unlimited".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarrantBounds {
    /// Exact tool allowlist. A tool not named here is refused.
    pub tools: BTreeSet<String>,
    /// Path globs the agent may modify, relative to the worktree root.
    pub write_paths: BTreeSet<String>,
    /// Hosts the agent may reach. Empty means no egress at all.
    pub egress_hosts: BTreeSet<String>,
    /// Side-effect classes whose external effects are staged rather than performed.
    pub staged_classes: BTreeSet<SideEffectClass>,
    /// Wall-clock deadline, epoch seconds. Enforced by the supervising process.
    pub expires_at: u64,
    /// Spend ceiling in whole cents. `None` is a ceiling of **zero**, never "unlimited".
    ///
    /// [`BoundStrength::Observed`], not enforced: the agent talks to its model provider directly,
    /// so this is parsed from the agent's own usage reporting and can be defeated by an agent that
    /// does not report. Named `budget_cents_observed` so a caller cannot mistake it for a
    /// guarantee at the point of use.
    ///
    /// The absent-means-zero reading is crate-wide: `spend::cap_micros` gives an undeclared budget
    /// a cap of zero micros, and [`WarrantBounds::contains`] gives it nothing to delegate.
    pub budget_cents_observed: Option<u64>,
    /// Maximum delegation depth remaining for sub-warrants.
    pub delegation_depth: u32,
}

impl WarrantBounds {
    /// Is `other` entirely within these bounds?
    ///
    /// This is the check that makes sub-warrants safe: authority may shrink at every hop and can
    /// never grow. It is evaluated when a child is *issued*, so an out-of-bounds child never
    /// exists rather than being caught later at use time.
    ///
    /// Absent bounds are read as *none* throughout, never as *unlimited* — including
    /// [`WarrantBounds::budget_cents_observed`], where a parent with no declared budget can
    /// delegate a ceiling of zero and nothing more.
    pub fn contains(&self, other: &Self) -> Result<(), WarrantError> {
        fn subset(
            child: &BTreeSet<String>,
            parent: &BTreeSet<String>,
            field: &str,
        ) -> Result<(), WarrantError> {
            if let Some(extra) = child.difference(parent).next() {
                return Err(WarrantError::AuthorityExpanded(format!(
                    "{field}: child claims {extra:?}, which the parent does not hold"
                )));
            }
            Ok(())
        }
        subset(&other.tools, &self.tools, "tools")?;
        subset(&other.write_paths, &self.write_paths, "write_paths")?;
        subset(&other.egress_hosts, &self.egress_hosts, "egress_hosts")?;

        // Staging may only become STRICTER in a child. A child that stages fewer classes than its
        // parent would perform immediately what the parent deferred, which is an expansion of
        // authority even though the set is smaller.
        if let Some(missing) = self.staged_classes.difference(&other.staged_classes).next() {
            return Err(WarrantError::AuthorityExpanded(format!(
                "staged_classes: parent stages {missing:?} but child would perform it immediately"
            )));
        }
        if other.expires_at > self.expires_at {
            return Err(WarrantError::AuthorityExpanded(format!(
                "expires_at: child outlives parent ({} > {})",
                other.expires_at, self.expires_at
            )));
        }
        // An absent budget is a ceiling of ZERO, never "no ceiling". `spend::cap_micros` reads it
        // that way when recording usage, so it is read that way here too: the same `None` cannot
        // mean nothing to the ledger and everything to the gate that mints the warrant. A warrant
        // granted without a budget therefore holds no spend authority and has none to hand on.
        let parent_cents = self.budget_cents_observed.unwrap_or(0);
        let child_cents = other.budget_cents_observed.unwrap_or(0);
        let absent_parent = if self.budget_cents_observed.is_none() {
            " -- the parent declares no budget, which is a ceiling of zero, not an absent one"
        } else {
            ""
        };
        if child_cents > parent_cents {
            return Err(WarrantError::AuthorityExpanded(format!(
                "budget: child {child_cents} exceeds parent {parent_cents}{absent_parent}"
            )));
        }
        // Dropping a DECLARED ceiling is not a narrowing, even though zero is the smaller number.
        // Whether a ceiling was declared is load-bearing beyond its value: a warrant with no
        // declared budget is never `SpendLedger::exhausted`, so `warrantor start` can never refuse
        // it on budget grounds however much the agent reports. A child that dropped its parent's
        // ceiling would trade a start-gated budget for an ungated one -- the same shape as the
        // staged_classes rule above, where a smaller set is an expansion of authority.
        if other.budget_cents_observed.is_none() && self.budget_cents_observed.is_some() {
            return Err(WarrantError::AuthorityExpanded(format!(
                "budget: parent is capped at {parent_cents} but the child declares no ceiling. An \
                 absent budget is a ceiling of zero and is never exhausted, so it is not inherited \
                 -- state the child's ceiling explicitly"
            )));
        }
        if other.delegation_depth >= self.delegation_depth {
            return Err(WarrantError::AuthorityExpanded(format!(
                "delegation_depth: child {} must be below parent {}",
                other.delegation_depth, self.delegation_depth
            )));
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), WarrantError> {
        if self.tools.is_empty() {
            return Err(WarrantError::Invalid(
                "a warrant with no tools can do nothing; state the tools explicitly".into(),
            ));
        }
        if self.expires_at == 0 {
            return Err(WarrantError::Invalid(
                "expires_at is required: a warrant without a deadline never ends".into(),
            ));
        }
        Ok(())
    }
}

/// The claims a warrant asserts. Signed as a unit; the signature lives outside in [`Warrant`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarrantClaims {
    /// Wire format identifier.
    pub format: String,
    /// Unique warrant id (`wrt_…`).
    pub id: String,
    /// Human-readable intent. Recorded in every receipt; not enforced.
    pub goal: String,
    /// SPIFFE ID of the agent this warrant is granted to.
    pub subject: String,
    /// What the warrant permits.
    pub bounds: WarrantBounds,
    /// Issued-at, epoch seconds.
    pub issued_at: u64,
    /// Hex-encoded verifying key of the **settle authority** — the party permitted to settle,
    /// void or renew. Deliberately not the agent's key.
    pub settle_authority: String,
    /// Parent warrant id, when this is a sub-warrant.
    pub parent: Option<String>,
}

/// A signed warrant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Warrant {
    /// The signed claims.
    pub claims: WarrantClaims,
    /// Hex Ed25519 signature over the domain-separated canonical encoding of `claims`.
    pub signature: String,
    /// Hex verifying key of the issuer.
    pub issuer_key: String,
    /// Current lifecycle state. Not signed: it changes over the warrant's life, and every
    /// transition is separately evidenced in the receipt chain.
    pub state: WarrantState,
}

/// An act-scoped token handed to the agent.
///
/// This is what the agent presents to the daemon. It authorises *acting* under a warrant and
/// nothing else — there is no settle scope, and no field that could be set to grant one. An agent
/// that reaches the daemon socket (which it can, running as the same user) still cannot settle,
/// widen its warrant, or touch a sibling's work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// The warrant this token acts under.
    pub warrant_id: String,
    /// The agent it was issued to.
    pub subject: String,
    /// Expiry, epoch seconds. Short by design: an agent that escapes its supervising process
    /// loses its authority within this window even if nothing kills it.
    pub expires_at: u64,
    /// Hex signature over the domain-separated encoding of the fields above.
    pub signature: String,
}

/// Default capability-token lifetime.
///
/// Short deliberately. On platforms with no parent-death signal an agent can outlive a supervisor
/// crash, and this TTL is the bound that still applies when process linkage cannot help — two
/// layers that fail differently.
pub const CAPABILITY_TTL_SECONDS: u64 = 60;

/// Build the exact bytes a signature covers.
///
/// Domain-separated and length-prefixed so that neither the domain nor any field can be re-split.
/// Without length prefixing, `id="ab"` + `subject="c"` and `id="a"` + `subject="bc"` would produce
/// identical bytes and therefore interchangeable signatures.
fn signing_input(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + body.len() + 16);
    out.extend_from_slice(&(domain.len() as u64).to_le_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn canonical(claims: &WarrantClaims) -> Result<Vec<u8>, WarrantError> {
    serde_json::to_vec(claims).map_err(|e| WarrantError::Encode(e.to_string()))
}

impl Warrant {
    /// Grant a warrant, signing it with `issuer`.
    ///
    /// `settle_authority` is the verifying key of the party allowed to settle. **It must not be
    /// the agent's key**; this is the single assumption the whole design rests on, and callers
    /// that get it wrong get a system where staging does nothing.
    ///
    /// # Errors
    /// [`WarrantError::Invalid`] if the bounds are not self-consistent.
    pub fn grant(
        id: impl Into<String>,
        goal: impl Into<String>,
        subject: impl Into<String>,
        bounds: WarrantBounds,
        issued_at: u64,
        settle_authority: &VerifyingKey,
        issuer: &SigningKey,
    ) -> Result<Self, WarrantError> {
        bounds.validate()?;
        let claims = WarrantClaims {
            format: WARRANT_FORMAT.to_string(),
            id: id.into(),
            goal: goal.into(),
            subject: subject.into(),
            bounds,
            issued_at,
            settle_authority: hex::encode(settle_authority.to_bytes()),
            parent: None,
        };
        Ok(Self::sign_claims(claims, issuer))
    }

    fn sign_claims(claims: WarrantClaims, issuer: &SigningKey) -> Self {
        let body = canonical(&claims).expect("claims are always serialisable");
        let signature = issuer.sign(&signing_input(WARRANT_DOMAIN, &body));
        Self {
            claims,
            signature: hex::encode(signature.to_bytes()),
            issuer_key: hex::encode(issuer.verifying_key().to_bytes()),
            state: WarrantState::Open,
        }
    }

    /// Issue a sub-warrant whose authority is a strict subset of this one.
    ///
    /// Intersection is checked here, at issue time, so an over-broad child never exists. An
    /// orchestrator fanning out to sub-agents currently has to hand each one its own full
    /// authority, because there is no way to grant less; this is that way.
    ///
    /// # Errors
    /// [`WarrantError::AuthorityExpanded`] if the child claims anything this warrant does not hold.
    pub fn delegate(
        &self,
        id: impl Into<String>,
        goal: impl Into<String>,
        subject: impl Into<String>,
        bounds: WarrantBounds,
        issued_at: u64,
        issuer: &SigningKey,
    ) -> Result<Self, WarrantError> {
        if self.state != WarrantState::Open {
            return Err(WarrantError::WrongState {
                state: self.state,
                operation: "delegate",
            });
        }
        bounds.validate()?;
        self.claims.bounds.contains(&bounds)?;
        let claims = WarrantClaims {
            format: WARRANT_FORMAT.to_string(),
            id: id.into(),
            goal: goal.into(),
            subject: subject.into(),
            bounds,
            issued_at,
            // A sub-warrant answers to the same authority as its parent: a child that could be
            // settled by someone the parent does not trust would be an escape hatch.
            settle_authority: self.claims.settle_authority.clone(),
            parent: Some(self.claims.id.clone()),
        };
        Ok(Self::sign_claims(claims, issuer))
    }

    /// Verify the warrant's signature and that it has not expired.
    ///
    /// # Errors
    /// [`WarrantError::SignatureInvalid`], [`WarrantError::UnknownFormat`] or
    /// [`WarrantError::Expired`].
    pub fn verify(&self, issuer: &VerifyingKey, now: u64) -> Result<(), WarrantError> {
        if self.claims.format != WARRANT_FORMAT {
            return Err(WarrantError::UnknownFormat(self.claims.format.clone()));
        }
        let body = canonical(&self.claims)?;
        let raw = hex::decode(&self.signature).map_err(|_| WarrantError::SignatureInvalid)?;
        let bytes: [u8; 64] = raw
            .as_slice()
            .try_into()
            .map_err(|_| WarrantError::SignatureInvalid)?;
        issuer
            .verify(
                &signing_input(WARRANT_DOMAIN, &body),
                &Signature::from_bytes(&bytes),
            )
            .map_err(|_| WarrantError::SignatureInvalid)?;
        if now >= self.claims.bounds.expires_at {
            return Err(WarrantError::Expired {
                expires_at: self.claims.bounds.expires_at,
                now,
            });
        }
        Ok(())
    }

    /// Confirm that `presented` is this warrant's settle authority.
    ///
    /// The load-bearing check. An agent holding its own key — or any key other than the one named
    /// in the signed claims — is refused, and because the authority is *inside the signed
    /// claims*, the agent cannot change it either.
    ///
    /// # Errors
    /// [`WarrantError::NotSettleAuthority`] if the key does not match.
    pub fn verify_settle(&self, presented: &VerifyingKey) -> Result<(), WarrantError> {
        if hex::encode(presented.to_bytes()) == self.claims.settle_authority {
            Ok(())
        } else {
            Err(WarrantError::NotSettleAuthority)
        }
    }

    /// Mint the act-scoped token the agent presents to the daemon.
    ///
    /// There is no variant of this that produces settle scope. That is the point: the capability
    /// an agent can hold is a strictly weaker thing than the authority to settle.
    pub fn issue_capability(&self, now: u64, issuer: &SigningKey) -> CapabilityToken {
        let expires_at = (now + CAPABILITY_TTL_SECONDS).min(self.claims.bounds.expires_at);
        let body = format!("{}|{}|{}", self.claims.id, self.claims.subject, expires_at);
        let signature = issuer.sign(&signing_input(CAPABILITY_DOMAIN, body.as_bytes()));
        CapabilityToken {
            warrant_id: self.claims.id.clone(),
            subject: self.claims.subject.clone(),
            expires_at,
            signature: hex::encode(signature.to_bytes()),
        }
    }

    /// Move to a new lifecycle state, rejecting illegal transitions.
    ///
    /// # Errors
    /// [`WarrantError::WrongState`] for any transition out of a terminal state.
    pub fn transition(&mut self, to: WarrantState) -> Result<(), WarrantError> {
        let legal = match (self.state, to) {
            (WarrantState::Open, _) => true,
            // Held is not terminal: the deadline passed, and the settle authority may still
            // release or discard what was staged.
            (WarrantState::Held, WarrantState::Settled | WarrantState::Void) => true,
            _ => false,
        };
        if !legal {
            return Err(WarrantError::WrongState {
                state: self.state,
                operation: "transition",
            });
        }
        self.state = to;
        Ok(())
    }
}

impl CapabilityToken {
    /// Verify the token's signature and that it has not expired.
    ///
    /// # Errors
    /// [`WarrantError::SignatureInvalid`] or [`WarrantError::Expired`].
    pub fn verify(&self, issuer: &VerifyingKey, now: u64) -> Result<(), WarrantError> {
        let body = format!("{}|{}|{}", self.warrant_id, self.subject, self.expires_at);
        let raw = hex::decode(&self.signature).map_err(|_| WarrantError::SignatureInvalid)?;
        let bytes: [u8; 64] = raw
            .as_slice()
            .try_into()
            .map_err(|_| WarrantError::SignatureInvalid)?;
        issuer
            .verify(
                &signing_input(CAPABILITY_DOMAIN, body.as_bytes()),
                &Signature::from_bytes(&bytes),
            )
            .map_err(|_| WarrantError::SignatureInvalid)?;
        if now >= self.expires_at {
            return Err(WarrantError::Expired {
                expires_at: self.expires_at,
                now,
            });
        }
        Ok(())
    }
}

/// Report which bounds are actually enforced and which are merely observed.
///
/// Surfaced so the morning report can say so, rather than presenting a parsed-from-self-reporting
/// budget as though it were the same kind of promise as a tool allowlist.
///
/// # `write_paths` was labelled `Enforced` and is not
///
/// It was, until this list was checked against the code that would have to do the enforcing. There
/// is none. `write_paths` is parsed at grant, compared in the delegation subset test, and read at
/// *settle* by [`worktree::Worktree::commit_all`] — and nowhere else. `proxy.rs`, the one place a
/// bound is actually refused at the moment of action, contains no path logic at all.
///
/// It was caught empirically, not by reading: in the first live dogfood an agent granted
/// `--write 'src/**'` ran its test suite and wrote `tests/__pycache__/`. Nothing refused it, and
/// nothing noticed.
///
/// That made the label the most damaging kind of wrong. [`BoundStrength::Enforced`] promises "the
/// system refuses the action", the report signs a sentence saying so, and a developer who reads it
/// concludes their agent cannot touch anything outside `src/`. Worse than an absent guarantee is
/// one someone relies on.
///
/// What *is* true is written into the limitations of every exported bundle: the worktree keeps the
/// writes off your working copy, and settle stages only in-bounds paths so out-of-bounds edits are
/// never merged. Real containment, at settle rather than at write, and not what `Enforced` means.
#[must_use]
pub fn bound_strengths() -> Vec<(&'static str, BoundStrength)> {
    vec![
        // Refused by the MCP proxy, which sees only what the agent routes through it.
        ("tools", BoundStrength::Mediated),
        // Not refused when the write happens. Contained afterwards: out-of-bounds edits are not
        // staged by settle, so they never reach the base branch. See the note above.
        ("write_paths", BoundStrength::Observed),
        // Proxy again, and the one most often assumed stronger than it is: no netns, no seccomp,
        // no firewall. An agent granted shell access reaches the network without passing here.
        ("egress_hosts", BoundStrength::Mediated),
        ("staged_classes", BoundStrength::Mediated),
        // OS process link: Windows job object, Linux setsid + PR_SET_PDEATHSIG.
        ("expires_at", BoundStrength::Enforced),
        // Ed25519 over the warrant claims. A child cannot hold what its parent did not.
        ("delegation_depth", BoundStrength::Enforced),
        // Parsed from the agent's own usage reporting; defeatable by an agent that does not report.
        ("budget_cents_observed", BoundStrength::Observed),
    ]
}
