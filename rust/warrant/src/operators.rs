//! §2.2 — who did it, and what they were allowed to do.
//!
//! # The gap this closes, stated exactly
//!
//! `serve.rs` has carried this sentence since it was written: *"This bearer token is a single
//! unscoped value, and scoping it the same way is the right next fix."* The consequence for a
//! product whose output is evidence was the sharpest gap in it: **the audit trail could not say
//! which human settled a warrant** — only that someone holding the process's one token did. Two
//! reviewers sharing a console were one principal. A stolen token was indistinguishable from its
//! owner. And `--allow-settle` was all-or-nothing, so an operator who needed to stop a runaway
//! agent had to be given the authority to release its work.
//!
//! # What this is, and the two things it deliberately is not
//!
//! A registry of **named operators**, each holding a token with an explicit set of scopes, stored
//! by digest. Every act that changes a warrant's state through the API is appended to a
//! hash-chained per-warrant log naming the operator who made it.
//!
//! **It is not authentication of a person.** A token authenticates a *token*. The name is bound to
//! it out of band, once, by whoever minted it — the same trust-on-first-use-with-pinning posture
//! [`crate::trust`] takes for issuer keys, and it is recorded as that rather than as an identity
//! claim. Every rendering of an actor says so. A system that printed "settled by ana" from a bearer
//! token, with no further qualification, would be asserting something it cannot check, in the one
//! artifact whose whole value is that its claims are checkable.
//!
//! **It is not in the signed evidence envelope.** Putting an actor inside a signed report means a
//! `WAR` receipt format bump, which is a deliberate, owner-level decision with migration
//! consequences — and the prior handoff records it as an open question rather than a task. So the
//! actor record is a *separate*, store-local, append-only, hash-chained log. That is a weaker
//! guarantee than a signature and it is stated as one: the chain makes tampering detectable to
//! anyone who holds an earlier copy of the head, and it proves nothing to a third party who does
//! not. Routing around the blocker honestly beats either waiting or pretending.
//!
//! # Why tokens are stored by digest
//!
//! The registry is a file on disk that the supervised agent's user can read. Storing tokens in
//! clear would make it a credential store, and one theft of that file would hand over every
//! operator's authority at once — including whichever of them holds `settle`. Digests mean the file
//! can be read and still yields nothing usable. The token is printed exactly once, at mint time, to
//! the terminal of the person who ran the command.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::report::sha256_hex;

/// The wire format of the operator registry.
pub const OPERATORS_FORMAT: &str = "warrantor.operators/1";

/// The wire format of one actor-log line.
pub const ACTOR_FORMAT: &str = "warrantor.actor/1";

/// The longest an operator name may be.
///
/// The same cap and the same reason as [`crate::trust`]'s issuer pins: a name is what makes a
/// principal and a token unconfusable in a log line, and a name long enough to contain a digest, a
/// URL or a sentence stops doing that job.
pub const MAX_NAME: usize = 32;

/// What an operator is allowed to do.
///
/// Deliberately coarse — four scopes, matching the four acts the API can perform that a reader
/// would describe differently. A finer grid would be a permission system nobody configures
/// correctly; these four are the ones an organisation actually distinguishes between.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Read warrants, reports, refusals and summaries. Every operator has this implicitly; naming
    /// it explicitly means a read-only reviewer is a thing you can create.
    Read,
    /// Terminate a running agent. Separated from `Settle` because the person you want able to stop
    /// a runaway at 3am is not necessarily the person you want able to release its work.
    Stop,
    /// Settle or void a warrant: perform every staged effect for real, or discard them.
    Settle,
    /// Record an approval towards a warrant's approval requirement. Held by reviewers who may not
    /// themselves settle, which is the entire point of separating it.
    Approve,
}

impl Scope {
    /// The word it is written as.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Stop => "stop",
            Self::Settle => "settle",
            Self::Approve => "approve",
        }
    }

    /// Parse one scope word.
    ///
    /// # Errors
    /// A sentence naming the four that exist, because a typo in a scope silently grants less than
    /// intended and the operator finds out at the moment they need it.
    pub fn parse(word: &str) -> Result<Self, String> {
        match word.trim() {
            "read" => Ok(Self::Read),
            "stop" => Ok(Self::Stop),
            "settle" => Ok(Self::Settle),
            "approve" => Ok(Self::Approve),
            other => Err(format!(
                "{other:?} is not a scope. The four are: read, stop, settle, approve."
            )),
        }
    }

    /// Parse a comma-separated scope list.
    ///
    /// An empty list is an error rather than an empty set: an operator with no scopes is an entry
    /// that can do nothing, and the reason someone typed it is almost always that they expected a
    /// default. There is no default here — see [`crate::WarrantBounds`]'s own rule that an absent
    /// limit means none, never unlimited, and the corollary that it must therefore be stated.
    ///
    /// # Errors
    /// The first bad word, or a sentence about the empty list.
    pub fn parse_list(raw: &str) -> Result<BTreeSet<Self>, String> {
        let mut scopes = BTreeSet::new();
        for word in raw.split(',').map(str::trim).filter(|w| !w.is_empty()) {
            scopes.insert(Self::parse(word)?);
        }
        if scopes.is_empty() {
            return Err(
                "--scope needs at least one of: read, stop, settle, approve. There is no default: \
                 an operator with no scopes could not even read, and an absent limit means none \
                 here as it does everywhere else in this system."
                    .to_string(),
            );
        }
        // `read` is implied by every other scope, and writing it in makes the rendered line honest
        // rather than making the reader infer it.
        scopes.insert(Self::Read);
        Ok(scopes)
    }
}

/// One named operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operator {
    /// The name a log line will carry.
    pub name: String,
    /// What this operator may do.
    pub scopes: BTreeSet<Scope>,
    /// SHA-256 of the token, hex. The token itself is never stored.
    pub token_digest: String,
    /// When the entry was made.
    pub added_at: u64,
    /// How the name was bound to the person, in the minter's own words. The out-of-band step.
    pub note: String,
}

impl Operator {
    /// Whether this operator holds a scope.
    #[must_use]
    pub fn allows(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
    }

    /// The scopes, as a stable comma-separated string.
    #[must_use]
    pub fn scope_words(&self) -> String {
        self.scopes
            .iter()
            .map(|s| s.word())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// The registry, as stored.
///
/// `Default` is hand-written rather than derived. The derive gives `format: String::default()`,
/// which is `""` — so the first `add` + `save` wrote a registry declaring no format, and the very
/// next `load` refused it as unreadable. Found by running the commands in order, which is the only
/// way that bug is visible: every unit test that built a registry and read it back in memory passed,
/// because nothing in memory ever consults the format field.
///
/// `#[serde(default = "...")]` does not help here: that fills a field absent from the *input*, and
/// this field was present and empty.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorRegistry {
    /// Wire format.
    #[serde(default = "default_format")]
    pub format: String,
    /// The operators, in the order they were added.
    #[serde(default)]
    pub operators: Vec<Operator>,
}

fn default_format() -> String {
    OPERATORS_FORMAT.to_string()
}

impl Default for OperatorRegistry {
    fn default() -> Self {
        Self {
            format: default_format(),
            operators: Vec::new(),
        }
    }
}

/// Where the registry lives.
#[must_use]
pub fn registry_path(root: &Path) -> PathBuf {
    root.join("serve").join("operators.json")
}

/// Where one warrant's actor log lives.
#[must_use]
pub fn actor_log_path(root: &Path, warrant_id: &str) -> PathBuf {
    root.join("actors").join(format!("{warrant_id}.jsonl"))
}

impl OperatorRegistry {
    /// Read the registry, or an empty one when the file does not exist.
    ///
    /// A file that exists and cannot be read is an **error**, never an empty registry. Treating it
    /// as empty would silently fall back to the unscoped session token for every caller — turning a
    /// corrupt permissions file into a quiet removal of every restriction in it, which is the
    /// failure direction a permissions system must never have.
    ///
    /// # Errors
    /// A sentence, if the file exists and will not parse.
    pub fn load(root: &Path) -> Result<Self, String> {
        let path = registry_path(root);
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        let registry: Self = serde_json::from_str(&raw).map_err(|e| {
            format!(
                "{} is not a readable operator registry ({e}). Refusing to treat it as empty: \
                 that would silently drop every restriction it contains and fall back to the \
                 unscoped session token.",
                path.display()
            )
        })?;
        if registry.format != OPERATORS_FORMAT {
            return Err(format!(
                "{} declares format {:?}; this build reads {OPERATORS_FORMAT}. Refusing rather \
                 than guessing at a permissions file.",
                path.display(),
                registry.format
            ));
        }
        Ok(registry)
    }

    /// Write the registry.
    ///
    /// # Errors
    /// A sentence on I/O or serialisation failure.
    pub fn save(&self, root: &Path) -> Result<(), String> {
        let path = registry_path(root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        let body = serde_json::to_vec_pretty(self)
            .map_err(|e| format!("cannot serialise the operator registry: {e}"))?;
        let temp = path.with_extension("json.tmp");
        std::fs::write(&temp, &body)
            .map_err(|e| format!("cannot write {}: {e}", temp.display()))?;
        std::fs::rename(&temp, &path).map_err(|e| format!("cannot replace {}: {e}", path.display()))
    }

    /// Whether any operator is registered.
    ///
    /// The whole compatibility hinge. An empty registry means the server behaves exactly as it did
    /// before this module existed: one unscoped session token, one anonymous principal. Nothing
    /// about a machine that has never run `warrantor operator add` changes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.operators.is_empty()
    }

    /// Find the operator a presented token belongs to.
    ///
    /// The comparison is on the digest and folds every byte with no early return, for the same
    /// reason [`crate::serve::SessionToken::matches`] does: a comparison that returns early leaks
    /// the secret one byte at a time to a caller who can measure it.
    #[must_use]
    pub fn authenticate(&self, presented: &str) -> Option<&Operator> {
        let digest = sha256_hex(presented.as_bytes());
        let mut found: Option<&Operator> = None;
        for operator in &self.operators {
            let mut difference = 0u8;
            let expected = operator.token_digest.as_bytes();
            let actual = digest.as_bytes();
            if expected.len() == actual.len() {
                for (a, b) in expected.iter().zip(actual) {
                    difference |= a ^ b;
                }
                if difference == 0 {
                    found = Some(operator);
                }
            }
        }
        found
    }

    /// Look one up by name.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&Operator> {
        self.operators.iter().find(|o| o.name == name)
    }

    /// Add an operator, minting a token.
    ///
    /// Returns the token in clear **once**. It is not stored and cannot be recovered: a registry
    /// that could reprint a token would be a registry whose theft is equivalent to the theft of
    /// every token in it.
    ///
    /// # Errors
    /// A sentence, for a bad name or a name already taken. A name already taken refuses rather than
    /// replacing, because the existing token is one somebody is currently using and rotating it
    /// silently locks them out with no message either of them would see.
    pub fn add(
        &mut self,
        name: &str,
        scopes: BTreeSet<Scope>,
        note: &str,
        at: u64,
    ) -> Result<String, String> {
        check_name(name)?;
        if self.by_name(name).is_some() {
            return Err(format!(
                "an operator named {name:?} is already registered. Remove it first if you mean to \
                 rotate its token -- replacing it silently would lock out whoever is holding the \
                 old one, with no message either of you would see."
            ));
        }
        if note.trim().is_empty() {
            return Err(
                "--note is required, and it is not paperwork: this token authenticates a TOKEN, \
                 not a person. The note is where you record how you bound this name to a human -- \
                 \"video call 2026-08-16\", \"handed over in person\" -- because that binding is \
                 the only thing making the name in an audit line mean anything."
                    .to_string(),
            );
        }
        let token = mint_token()?;
        self.operators.push(Operator {
            name: name.to_string(),
            scopes,
            token_digest: sha256_hex(token.as_bytes()),
            added_at: at,
            note: note.trim().to_string(),
        });
        Ok(token)
    }

    /// Remove an operator by name.
    ///
    /// # Errors
    /// A sentence when there is no such operator, so a typo in a revocation is not reported as a
    /// successful revocation.
    pub fn remove(&mut self, name: &str) -> Result<Operator, String> {
        let index = self
            .operators
            .iter()
            .position(|o| o.name == name)
            .ok_or_else(|| {
                format!(
                    "no operator named {name:?}. Nothing was revoked -- and a revocation that \
                     reported success for a name that does not exist would be the worst possible \
                     answer to \"did you remove their access\"."
                )
            })?;
        Ok(self.operators.remove(index))
    }
}

/// A name that can appear in an audit line without being confusable with anything else.
fn check_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("an operator needs a name".to_string());
    }
    if name.len() > MAX_NAME {
        return Err(format!(
            "{name:?} is {} characters; an operator name is at most {MAX_NAME}. The cap is what \
             makes a name and a token unconfusable in a log line.",
            name.len()
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(format!(
            "{name:?} must be letters, digits, '-', '_' or '.'. It goes into log lines and command \
             lines, and a name needing quoting is a name that will be typed wrongly."
        ));
    }
    Ok(())
}

/// A fresh 32-byte token, hex.
fn mint_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| format!("cannot draw a token from the system random source: {e}"))?;
    Ok(hex_encode(&bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

// ── the actor log ─────────────────────────────────────────────────────────────────────

/// What kind of act an actor performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Act {
    /// Recorded an approval towards the warrant's requirement.
    Approve,
    /// Released the warrant's staged effects.
    Settle,
    /// Discarded them.
    Void,
    /// Terminated a running agent.
    Stop,
}

impl Act {
    /// The word it is written as.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Settle => "settle",
            Self::Void => "void",
            Self::Stop => "stop",
        }
    }

    /// The scope an act requires.
    #[must_use]
    pub const fn required_scope(self) -> Scope {
        match self {
            Self::Approve => Scope::Approve,
            // Void is a release decision: discarding an agent's work is as irreversible as
            // performing it, and giving one away without the other would be an odd line to draw.
            Self::Settle | Self::Void => Scope::Settle,
            Self::Stop => Scope::Stop,
        }
    }
}

/// One line of the actor log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorRecord {
    /// Wire format.
    pub format: String,
    /// The warrant.
    pub warrant_id: String,
    /// What was done.
    pub act: Act,
    /// The operator's name, or `None` for the unscoped session token.
    ///
    /// `None` is a real and honest value: on a machine with no operator registry the server has one
    /// anonymous principal, and writing a name there would invent one. A reader must be able to
    /// tell "nobody was named" from "ana did it".
    pub actor: Option<String>,
    /// How the caller was authenticated.
    pub via: String,
    /// When.
    pub at: u64,
    /// The digest of the previous line in this warrant's log, or the empty string for the first.
    pub prev: String,
    /// This line's own digest, over every field above.
    pub digest: String,
}

impl ActorRecord {
    /// The digest of this record's content, excluding the digest field itself.
    fn compute_digest(
        warrant_id: &str,
        act: Act,
        actor: Option<&str>,
        via: &str,
        at: u64,
        prev: &str,
    ) -> String {
        // A field-separated pre-image with a separator that cannot appear in any field. Without one,
        // ("ab", "c") and ("a", "bc") hash the same, and two different actors could produce one
        // digest.
        let pre_image = format!(
            "{ACTOR_FORMAT}\u{1f}{warrant_id}\u{1f}{}\u{1f}{}\u{1f}{via}\u{1f}{at}\u{1f}{prev}",
            act.word(),
            actor.unwrap_or("")
        );
        sha256_hex(pre_image.as_bytes())
    }
}

/// Append one act to a warrant's actor log.
///
/// Hash-chained: each line carries the previous line's digest, so a removed or edited line is
/// detectable to anyone holding a later copy of the chain. That is the guarantee, and it is smaller
/// than a signature: it proves nothing to a third party who has never seen an earlier head. The
/// stronger version needs the actor inside the signed report, which needs a receipt format bump.
///
/// # Errors
/// A sentence on I/O failure, or when the existing log cannot be read — an unreadable log is not an
/// empty one, and starting a fresh chain on top of a gap is exactly the silent break the chain
/// exists to prevent.
pub fn record(
    root: &Path,
    warrant_id: &str,
    act: Act,
    actor: Option<&str>,
    via: &str,
    at: u64,
) -> Result<ActorRecord, String> {
    let path = actor_log_path(root, warrant_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    let existing = read_log(root, warrant_id)?;
    let prev = existing
        .last()
        .map(|r| r.digest.clone())
        .unwrap_or_default();
    let digest = ActorRecord::compute_digest(warrant_id, act, actor, via, at, &prev);
    let entry = ActorRecord {
        format: ACTOR_FORMAT.to_string(),
        warrant_id: warrant_id.to_string(),
        act,
        actor: actor.map(str::to_string),
        via: via.to_string(),
        at,
        prev,
        digest,
    };
    let line = serde_json::to_string(&entry)
        .map_err(|e| format!("cannot serialise an actor record: {e}"))?;
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    writeln!(file, "{line}").map_err(|e| format!("cannot append to {}: {e}", path.display()))?;
    // Flushed to disk before returning. An accountability record that is still in a buffer when the
    // process is killed is an act with no record of who performed it.
    file.sync_all()
        .map_err(|e| format!("cannot flush {}: {e}", path.display()))?;
    Ok(entry)
}

/// Read a warrant's actor log.
///
/// # Errors
/// A sentence when the file exists and a line will not parse. A partially-readable accountability
/// log is reported, never silently truncated to the readable prefix.
pub fn read_log(root: &Path, warrant_id: &str) -> Result<Vec<ActorRecord>, String> {
    let path = actor_log_path(root, warrant_id);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let mut records = Vec::new();
    for (index, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: ActorRecord = serde_json::from_str(line).map_err(|e| {
            format!(
                "{}: line {} will not parse ({e}). This is an accountability log; a readable \
                 prefix is not an answer to \"who did this\".",
                path.display(),
                index + 1
            )
        })?;
        records.push(record);
    }
    Ok(records)
}

/// Whether a log's chain is intact, and where it first is not.
///
/// # Errors
/// A sentence naming the first line whose recomputed digest or `prev` link does not hold.
pub fn verify_chain(records: &[ActorRecord]) -> Result<(), String> {
    let mut expected_prev = String::new();
    for (index, record) in records.iter().enumerate() {
        if record.prev != expected_prev {
            return Err(format!(
                "actor log line {} does not follow line {}: it names previous digest {:?}, and the \
                 line before it hashes to {:?}. A line has been removed, reordered or edited.",
                index + 1,
                index,
                record.prev,
                expected_prev
            ));
        }
        let recomputed = ActorRecord::compute_digest(
            &record.warrant_id,
            record.act,
            record.actor.as_deref(),
            &record.via,
            record.at,
            &record.prev,
        );
        if recomputed != record.digest {
            return Err(format!(
                "actor log line {} has been edited: its contents hash to {recomputed}, and it \
                 carries {}.",
                index + 1,
                record.digest
            ));
        }
        expected_prev = record.digest.clone();
    }
    Ok(())
}

// ── approvals ─────────────────────────────────────────────────────────────────────────

/// The wire format of the approval policy.
pub const APPROVALS_FORMAT: &str = "warrantor.approvals/1";

/// How many approvals a settle needs, and whether the settler may be one of them.
///
/// A store-local policy file, like `retention.json` and `notify.json`, for the same reason: it is a
/// decision about this machine's operating posture rather than part of any warrant's granted
/// authority. Putting it inside signed claims would mean re-issuing warrants to change a review
/// policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalPolicy {
    /// Wire format.
    #[serde(default = "default_approvals_format")]
    pub format: String,
    /// How many distinct approvers are required before a settle is permitted.
    ///
    /// Zero means no requirement, which is the shipped default and what every machine with no
    /// policy file behaves as.
    #[serde(default)]
    pub required: usize,
    /// Whether the operator who settles may also count as one of the approvers.
    ///
    /// Defaults to **false**: separation of duties is the entire reason to require approvals, and a
    /// policy where one person approves their own settle requires two acts of one human and calls
    /// it review. Configurable because a one-person team with `required: 1` is a real and
    /// reasonable posture — a deliberate second look at your own work, recorded.
    #[serde(default)]
    pub settler_may_approve: bool,
}

fn default_approvals_format() -> String {
    APPROVALS_FORMAT.to_string()
}

impl Default for ApprovalPolicy {
    fn default() -> Self {
        Self {
            format: APPROVALS_FORMAT.to_string(),
            required: 0,
            settler_may_approve: false,
        }
    }
}

/// Where the approval policy lives.
#[must_use]
pub fn approvals_path(root: &Path) -> PathBuf {
    root.join("approvals.json")
}

impl ApprovalPolicy {
    /// Read the policy, or the default when there is no file.
    ///
    /// # Errors
    /// A sentence when the file exists and will not parse. As with the operator registry, an
    /// unreadable policy is never treated as an absent one: that would turn a corrupt file into the
    /// silent removal of a review requirement.
    pub fn load(root: &Path) -> Result<Self, String> {
        let path = approvals_path(root);
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        let policy: Self = serde_json::from_str(&raw).map_err(|e| {
            format!(
                "{} is not a readable approval policy ({e}). Refusing to treat it as absent: that \
                 would silently remove a review requirement.",
                path.display()
            )
        })?;
        if policy.format != APPROVALS_FORMAT {
            return Err(format!(
                "{} declares format {:?}; this build reads {APPROVALS_FORMAT}.",
                path.display(),
                policy.format
            ));
        }
        Ok(policy)
    }

    /// Whether this policy requires anything at all.
    #[must_use]
    pub fn requires_approval(&self) -> bool {
        self.required > 0
    }
}

/// Who has approved a warrant, from its actor log.
///
/// Distinct *named* approvers. Two approvals from one operator are one approver: the requirement is
/// for independent judgement, and counting a repeat would let one person satisfy a two-person rule
/// by running the command twice.
///
/// Anonymous approvals — the session token on a machine with no operator registry — are counted
/// once in total, under `None`, and [`approval_verdict`] refuses to let them satisfy a requirement
/// above one for exactly that reason: they are indistinguishable from each other.
#[must_use]
pub fn approvers(records: &[ActorRecord]) -> BTreeSet<Option<String>> {
    records
        .iter()
        .filter(|r| r.act == Act::Approve)
        .map(|r| r.actor.clone())
        .collect()
}

/// What a settle attempt is allowed to do, under a policy and a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalVerdict {
    /// No requirement, or it is met.
    Permitted,
    /// Refused, with the sentence explaining what is missing.
    Refused(String),
}

/// Decide whether `settler` may settle this warrant.
///
/// # The three refusals, and why each is separate
///
/// 1. **Not enough distinct approvers.** The plain case.
/// 2. **The settler is the only approver** and the policy does not allow that. Separated because the
///    fix is different: another person has to look, not the same person again.
/// 3. **The requirement exceeds one and the approvals are anonymous.** On a machine with no
///    operator registry every caller is the same unnamed principal, so "two approvers" cannot be
///    established at all — and reporting it as satisfied would be the system asserting a review
///    happened when nothing can show that it did.
#[must_use]
pub fn approval_verdict(
    policy: &ApprovalPolicy,
    records: &[ActorRecord],
    settler: Option<&str>,
) -> ApprovalVerdict {
    if !policy.requires_approval() {
        return ApprovalVerdict::Permitted;
    }
    let all = approvers(records);
    let anonymous = all.contains(&None);
    if anonymous && policy.required > 1 {
        return ApprovalVerdict::Refused(format!(
            "this store requires {} approvals and at least one approval was recorded with no \
             operator name. On a machine with no operator registry every caller is the same \
             unnamed principal, so {} distinct approvers cannot be established. Register operators \
             (`warrantor operator add <name> --scope approve --note \"...\"`) so approvals can be \
             told apart.",
            policy.required, policy.required
        ));
    }
    let counted: BTreeSet<&Option<String>> = if policy.settler_may_approve {
        all.iter().collect()
    } else {
        all.iter()
            .filter(|a| a.as_deref() != settler || settler.is_none() && a.is_some())
            .collect()
    };
    if counted.len() >= policy.required {
        return ApprovalVerdict::Permitted;
    }
    let settler_approved = settler.is_some_and(|s| all.contains(&Some(s.to_string())));
    if settler_approved && !policy.settler_may_approve && counted.len() + 1 >= policy.required {
        return ApprovalVerdict::Refused(format!(
            "this store requires {} approval(s) from someone other than whoever settles. {} has \
             approved and is now settling, which is one person doing both -- set \
             \"settler_may_approve\": true in approvals.json if that is the posture you want, or \
             have somebody else run `warrantor approve`.",
            policy.required,
            settler.unwrap_or("the settler")
        ));
    }
    ApprovalVerdict::Refused(format!(
        "this store requires {} approval(s) before a settle and has {}. Run `warrantor approve \
         <warrant-id>` as an operator holding the approve scope.",
        policy.required,
        counted.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "warrantor-operators-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&path).expect("tempdir");
        path
    }

    #[test]
    fn a_token_is_stored_only_as_a_digest() {
        // The registry is a file the supervised agent's user can read. In clear it would be a
        // credential store whose single theft hands over every operator's authority at once.
        let mut registry = OperatorRegistry::default();
        let token = registry
            .add(
                "ana",
                Scope::parse_list("settle").expect("scopes"),
                "video call",
                1,
            )
            .expect("added");
        let stored = serde_json::to_string(&registry).expect("serialise");
        assert!(
            !stored.contains(&token),
            "the token must not appear anywhere in the stored registry"
        );
        assert!(stored.contains(&sha256_hex(token.as_bytes())));
    }

    #[test]
    fn a_token_authenticates_to_its_operator_and_nothing_else_does() {
        let mut registry = OperatorRegistry::default();
        let ana = registry
            .add(
                "ana",
                Scope::parse_list("settle").expect("s"),
                "in person",
                1,
            )
            .expect("added");
        let bo = registry
            .add("bo", Scope::parse_list("stop").expect("s"), "in person", 2)
            .expect("added");

        assert_eq!(registry.authenticate(&ana).expect("ana").name, "ana");
        assert_eq!(registry.authenticate(&bo).expect("bo").name, "bo");
        assert!(registry.authenticate("deadbeef").is_none());
        assert!(registry.authenticate("").is_none());
    }

    #[test]
    fn scopes_are_separate_so_stopping_a_runaway_does_not_require_releasing_its_work() {
        // The reason `--allow-settle` being all-or-nothing was a real problem: the person you want
        // able to kill a runaway agent at 3am is not necessarily the person you want able to
        // release what it wrote.
        let mut registry = OperatorRegistry::default();
        registry
            .add("oncall", Scope::parse_list("stop").expect("s"), "rota", 1)
            .expect("added");
        let oncall = registry.by_name("oncall").expect("there");
        assert!(oncall.allows(Scope::Stop));
        assert!(!oncall.allows(Scope::Settle));
        assert!(!oncall.allows(Scope::Approve));
        assert!(oncall.allows(Scope::Read), "read is implied by any scope");
    }

    #[test]
    fn an_empty_scope_list_is_refused_rather_than_defaulted() {
        let error = Scope::parse_list("").expect_err("refuses");
        assert!(error.contains("no default"), "{error}");
        let typo = Scope::parse_list("setle").expect_err("refuses");
        assert!(typo.contains("read, stop, settle, approve"), "{typo}");
    }

    #[test]
    fn a_note_is_required_because_the_name_means_nothing_without_one() {
        let mut registry = OperatorRegistry::default();
        let error = registry
            .add("ana", Scope::parse_list("settle").expect("s"), "  ", 1)
            .expect_err("refuses");
        assert!(
            error.contains("authenticates a TOKEN, not a person"),
            "{error}"
        );
    }

    #[test]
    fn a_duplicate_name_refuses_rather_than_rotating_silently() {
        let mut registry = OperatorRegistry::default();
        registry
            .add("ana", Scope::parse_list("settle").expect("s"), "n", 1)
            .expect("added");
        let error = registry
            .add("ana", Scope::parse_list("stop").expect("s"), "n", 2)
            .expect_err("refuses");
        assert!(error.contains("lock out"), "{error}");
    }

    #[test]
    fn revoking_a_name_that_does_not_exist_is_never_reported_as_success() {
        let mut registry = OperatorRegistry::default();
        let error = registry.remove("nobody").expect_err("refuses");
        assert!(error.contains("Nothing was revoked"), "{error}");
    }

    #[test]
    fn an_unreadable_registry_is_an_error_and_never_an_empty_one() {
        // The failure direction a permissions system must not have: a corrupt file silently
        // dropping every restriction in it.
        let dir = tempdir("corrupt");
        std::fs::create_dir_all(dir.join("serve")).expect("mkdir");
        std::fs::write(registry_path(&dir), b"{not json").expect("write");
        let error = OperatorRegistry::load(&dir).expect_err("refuses");
        assert!(error.contains("Refusing to treat it as empty"), "{error}");
    }

    #[test]
    fn a_saved_registry_can_be_loaded_back() {
        // The bug this pins, found by running the commands in order rather than by any unit test:
        // `#[derive(Default)]` gave `format: ""`, so the first `add` + `save` wrote a registry
        // declaring no format and the very next `load` refused it as unreadable. Every in-memory
        // test passed, because nothing in memory consults the format field.
        let dir = tempdir("roundtrip");
        let mut registry = OperatorRegistry::default();
        assert_eq!(
            registry.format, OPERATORS_FORMAT,
            "a fresh registry declares its format"
        );
        let token = registry
            .add("ana", Scope::parse_list("settle").expect("s"), "n", 1)
            .expect("added");
        registry.save(&dir).expect("saved");

        let reloaded = OperatorRegistry::load(&dir).expect("a saved registry must load back");
        assert_eq!(reloaded.authenticate(&token).expect("ana").name, "ana");
    }

    #[test]
    fn an_absent_registry_is_the_behaviour_this_module_replaced() {
        let dir = tempdir("absent");
        let registry = OperatorRegistry::load(&dir).expect("loads");
        assert!(
            registry.is_empty(),
            "no registry means one unscoped principal, as before"
        );
    }

    // ── the actor log ─────────────────────────────────────────────────────────────────

    #[test]
    fn an_actor_log_chains_and_an_edit_is_detectable() {
        let dir = tempdir("chain");
        record(
            &dir,
            "wrt_1",
            Act::Approve,
            Some("ana"),
            "operator-token",
            10,
        )
        .expect("first");
        record(&dir, "wrt_1", Act::Settle, Some("bo"), "operator-token", 20).expect("second");

        let log = read_log(&dir, "wrt_1").expect("read");
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].prev, "", "the first line starts the chain");
        assert_eq!(log[1].prev, log[0].digest);
        verify_chain(&log).expect("intact");

        // Edit the actor on the first line and the chain no longer holds.
        let mut tampered = log.clone();
        tampered[0].actor = Some("mallory".to_string());
        let error = verify_chain(&tampered).expect_err("detected");
        assert!(error.contains("has been edited"), "{error}");
    }

    #[test]
    fn a_removed_line_is_detectable() {
        let dir = tempdir("gap");
        for (n, at) in [(1u8, 10u64), (2, 20), (3, 30)] {
            record(&dir, "wrt_1", Act::Approve, Some(&format!("a{n}")), "t", at).expect("write");
        }
        let mut log = read_log(&dir, "wrt_1").expect("read");
        log.remove(1);
        let error = verify_chain(&log).expect_err("detected");
        assert!(error.contains("does not follow"), "{error}");
    }

    #[test]
    fn an_anonymous_actor_is_none_and_not_an_invented_name() {
        // A reader must be able to tell "nobody was named" from "ana did it". Writing a placeholder
        // name here would be the system inventing a principal.
        let dir = tempdir("anon");
        let entry = record(&dir, "wrt_1", Act::Stop, None, "session-token", 10).expect("write");
        assert_eq!(entry.actor, None);
        let stored = std::fs::read_to_string(actor_log_path(&dir, "wrt_1")).expect("read");
        assert!(stored.contains("\"actor\":null"), "{stored}");
    }

    #[test]
    fn the_digest_pre_image_is_separated_so_two_actors_cannot_collide() {
        // Without a separator ("ab","c") and ("a","bc") hash the same.
        let a = ActorRecord::compute_digest("w", Act::Settle, Some("ab"), "c", 1, "");
        let b = ActorRecord::compute_digest("w", Act::Settle, Some("a"), "bc", 1, "");
        assert_ne!(a, b);
    }

    // ── approvals ─────────────────────────────────────────────────────────────────────

    fn approval(actor: Option<&str>) -> ActorRecord {
        ActorRecord {
            format: ACTOR_FORMAT.to_string(),
            warrant_id: "w".to_string(),
            act: Act::Approve,
            actor: actor.map(str::to_string),
            via: "t".to_string(),
            at: 1,
            prev: String::new(),
            digest: String::new(),
        }
    }

    #[test]
    fn no_policy_permits_everything_which_is_the_shipped_default() {
        let policy = ApprovalPolicy::default();
        assert!(!policy.requires_approval());
        assert_eq!(
            approval_verdict(&policy, &[], Some("ana")),
            ApprovalVerdict::Permitted
        );
    }

    #[test]
    fn two_approvals_from_one_person_are_one_approver() {
        // Otherwise a two-person rule is satisfied by running the command twice.
        let policy = ApprovalPolicy {
            required: 2,
            ..ApprovalPolicy::default()
        };
        let records = vec![approval(Some("ana")), approval(Some("ana"))];
        let verdict = approval_verdict(&policy, &records, Some("cy"));
        assert!(
            matches!(verdict, ApprovalVerdict::Refused(_)),
            "{verdict:?}"
        );
    }

    #[test]
    fn the_settler_does_not_count_as_an_approver_by_default() {
        let policy = ApprovalPolicy {
            required: 1,
            ..ApprovalPolicy::default()
        };
        let records = vec![approval(Some("ana"))];
        match approval_verdict(&policy, &records, Some("ana")) {
            ApprovalVerdict::Refused(why) => {
                assert!(why.contains("one person doing both"), "{why}");
            }
            other => panic!("must refuse: {other:?}"),
        }
        // And someone else settling the same approval is fine.
        assert_eq!(
            approval_verdict(&policy, &records, Some("bo")),
            ApprovalVerdict::Permitted
        );
    }

    #[test]
    fn a_one_person_team_can_opt_into_approving_their_own_settle() {
        let policy = ApprovalPolicy {
            required: 1,
            settler_may_approve: true,
            ..ApprovalPolicy::default()
        };
        assert_eq!(
            approval_verdict(&policy, &[approval(Some("ana"))], Some("ana")),
            ApprovalVerdict::Permitted
        );
    }

    #[test]
    fn anonymous_approvals_cannot_satisfy_a_multi_person_requirement() {
        // With no operator registry every caller is the same unnamed principal. Reporting two
        // anonymous approvals as two approvers would be the system asserting a review happened
        // when nothing can show that it did.
        let policy = ApprovalPolicy {
            required: 2,
            ..ApprovalPolicy::default()
        };
        match approval_verdict(&policy, &[approval(None)], None) {
            ApprovalVerdict::Refused(why) => {
                assert!(why.contains("no operator name"), "{why}");
                assert!(
                    why.contains("operator add"),
                    "the remedy must be named: {why}"
                );
            }
            other => panic!("must refuse: {other:?}"),
        }
        // One anonymous approval CAN satisfy a requirement of one: there is nothing to tell apart.
        let single = ApprovalPolicy {
            required: 1,
            settler_may_approve: true,
            ..ApprovalPolicy::default()
        };
        assert_eq!(
            approval_verdict(&single, &[approval(None)], None),
            ApprovalVerdict::Permitted
        );
    }
}
