//! W5 — the staged-effect queue.
//!
//! An irreversible action becomes safe by never being performed speculatively. You cannot un-send
//! an email; you can decline to send it. So an agent's outward-facing effects are *queued* rather
//! than executed, and the real calls happen only when a human settles the warrant.
//!
//! # Typed handles
//!
//! A staged effect returns a handle standing for a thing that does not exist yet. R1 measured
//! whether frontier models can work with that, and they can — 8/8, including 4/4 with no
//! explanation of the protocol at all. But R1 also found the failure mode that measurement nearly
//! missed: when every effect minted a `pr://` handle from a single counter, `add_label` returned a
//! `pr://` URI that was not a pull request, and an agent threading the most recent handle forward
//! could request review *on the label* and get a successful result. Well-formed, wrong object,
//! silently accepted.
//!
//! Handles are therefore **typed by the effect that mints them** — `pr://`, `comment://`,
//! `review://`, `label://` — and each tool declares which types it accepts as a target. A
//! wrong-type reference is refused as firmly as an invented one.
//!
//! # Ordering
//!
//! Effects form a directed acyclic graph: a comment depends on the PR it is attached to. Release
//! order is a topological sort of that graph, which is what makes partial failure survivable —
//! **every prefix of the order is a coherent state**. The PR can exist without its comment; a
//! comment can never exist without its PR. That property is why the settle engine can stop at a
//! failure and report the exact boundary instead of attempting a compensation that might itself
//! fail halfway.
//!
//! # Durability
//!
//! The queue is an append-only, hash-chained, `fsync`'d JSONL log. A staged effect that silently
//! vanished would be a data-loss bug the developer could not detect — they would settle a warrant
//! and simply not get the pull request they were promised. The chain makes tampering and
//! truncation detectable rather than merely unlikely.
//!
//! The chain cannot, on its own, detect the log being **removed**: an absent file replays as an
//! empty queue at [`GENESIS`], which is exactly what a warrant that staged nothing looks like. That
//! is what [`StagedChainMark`] is for — see its documentation for why the witness has to live
//! outside the file it witnesses.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::WarrantError;

/// Digest that precedes the first entry in a queue.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// What the store last saw of a warrant's staged-effect chain, recorded outside the log itself.
///
/// # Why this exists
///
/// The chain proves that the log was not *edited*. It cannot prove the log still *exists*: the
/// file is created lazily by the first append, so a queue that was never used and a queue somebody
/// deleted are the same absence on disk. [`StagingQueue::open`] reads both as an empty queue at
/// [`GENESIS`], and a report built from that says "0 staged effect(s), chain head 0000…" —
/// success-shaped, and then signed into an evidence bundle.
///
/// So the head and the count are written where the log is not: into the warrant record itself.
/// That is the same reasoning `StoredWarrant::base_commit` already carries — derived state that
/// cannot be re-derived has to be stored.
///
/// # What a mark can and cannot detect
///
/// The chain only grows forward, so a mark is checked by asking whether the digest it recorded is
/// *still where it was*: record number `count` must still carry `head`. Records appended after the
/// mark was taken are ordinary growth and pass. Records missing below it do not — the log was
/// truncated, replaced or deleted, and that is a refusal.
///
/// A mark that lags the log (the process died between the append and the save) weakens detection
/// to everything below the recorded point; it never produces a false alarm. A warrant granted
/// before this field existed carries `None`, and then nothing can be proven about its log either
/// way, which is stated rather than assumed away.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedChainMark {
    /// The chain head at the moment the mark was taken.
    pub head: String,
    /// How many effects the chain held then.
    pub count: u64,
    /// When the mark was taken, epoch seconds.
    pub recorded_at: u64,
}

impl StagedChainMark {
    /// The mark of a warrant that has staged nothing yet.
    ///
    /// Written at grant time rather than at first stage, so a warrant is witnessed from the moment
    /// it exists instead of only from its first staged effect.
    #[must_use]
    pub fn genesis(at: u64) -> Self {
        Self {
            head: GENESIS.to_string(),
            count: 0,
            recorded_at: at,
        }
    }
}

/// A staged effect: an outward-facing action that has been queued but not performed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedEffect {
    /// Position in the queue, from 1.
    pub index: u64,
    /// The handle that stands for this effect, e.g. `pr://staged/wrt_7f3a/1`.
    pub handle: String,
    /// The tool that would perform it.
    pub tool: String,
    /// Arguments, verbatim as the agent supplied them.
    pub arguments: BTreeMap<String, String>,
    /// Handles this effect depends on. Derived from arguments that reference other handles.
    pub depends_on: BTreeSet<String>,
    /// When it was staged, epoch seconds.
    pub staged_at: u64,
}

/// One line of the queue's hash-chained log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct QueueRecord {
    effect: StagedEffect,
    prev_digest: String,
    digest: String,
}

/// The handle scheme a tool mints, and the schemes it accepts as a target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectKind {
    /// Tool name, e.g. `github.create_pr`.
    pub tool: String,
    /// Scheme this tool's handles use, e.g. `pr`.
    pub mints: String,
    /// Handle schemes accepted in the `target` argument. Empty means the tool takes no target.
    pub targets: BTreeSet<String>,
}

/// The registry of known effect kinds.
///
/// A tool absent from the registry cannot be staged: we would not know what its handle means, nor
/// what it may point at. Refusing is the fail-closed answer.
#[derive(Debug, Clone, Default)]
pub struct EffectRegistry {
    kinds: BTreeMap<String, EffectKind>,
}

impl EffectRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The default GitHub effect kinds, typed as R1 showed they must be.
    #[must_use]
    pub fn github() -> Self {
        let mut registry = Self::new();
        registry.register("github.create_pr", "pr", &[]);
        registry.register("github.comment", "comment", &["pr"]);
        registry.register("github.request_review", "review", &["pr"]);
        registry.register("github.add_label", "label", &["pr"]);
        registry
    }

    /// Register an effect kind.
    pub fn register(&mut self, tool: &str, mints: &str, targets: &[&str]) {
        self.kinds.insert(
            tool.to_string(),
            EffectKind {
                tool: tool.to_string(),
                mints: mints.to_string(),
                targets: targets.iter().map(|t| (*t).to_string()).collect(),
            },
        );
    }

    /// Look up an effect kind.
    #[must_use]
    pub fn get(&self, tool: &str) -> Option<&EffectKind> {
        self.kinds.get(tool)
    }
}

/// Extract the scheme from a handle: `pr://staged/w/1` → `pr`.
#[must_use]
pub fn handle_scheme(handle: &str) -> &str {
    handle.split_once("://").map_or("", |(scheme, _)| scheme)
}

/// An append-only, hash-chained queue of staged effects for one warrant.
#[derive(Debug)]
pub struct StagingQueue {
    path: PathBuf,
    warrant_id: String,
    effects: Vec<StagedEffect>,
    /// Every record's digest, in order, so a [`StagedChainMark`] can be checked against the
    /// position it named rather than only against the current head. Kept because a mark taken
    /// mid-run must still verify once more effects have been appended on top of it.
    digests: Vec<String>,
    head: String,
    registry: EffectRegistry,
}

impl StagingQueue {
    /// Open (or create) the queue for `warrant_id` at `path`, replaying and verifying the chain.
    ///
    /// # Errors
    /// [`WarrantError::Invalid`] if the existing log does not form a valid chain — which means it
    /// was truncated or edited, and the queue can no longer be trusted to describe what is pending.
    pub fn open(
        path: impl AsRef<Path>,
        warrant_id: impl Into<String>,
        registry: EffectRegistry,
    ) -> Result<Self, WarrantError> {
        let path = path.as_ref().to_path_buf();
        let warrant_id = warrant_id.into();
        let mut effects = Vec::new();
        let mut digests = Vec::new();
        let mut head = GENESIS.to_string();

        if path.exists() {
            let body = std::fs::read_to_string(&path)
                .map_err(|e| WarrantError::Encode(format!("read queue: {e}")))?;
            for (line_number, line) in body.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let record: QueueRecord = serde_json::from_str(line).map_err(|e| {
                    WarrantError::Invalid(format!("queue line {}: {e}", line_number + 1))
                })?;
                if record.prev_digest != head {
                    return Err(WarrantError::Invalid(format!(
                        "queue chain broken at line {}: expected prev {head}, found {}",
                        line_number + 1,
                        record.prev_digest
                    )));
                }
                let expected = Self::digest(&record.effect, &record.prev_digest)?;
                if expected != record.digest {
                    return Err(WarrantError::Invalid(format!(
                        "queue entry {} has been altered",
                        record.effect.index
                    )));
                }
                head = record.digest.clone();
                digests.push(record.digest.clone());
                effects.push(record.effect);
            }
        }

        Ok(Self {
            path,
            warrant_id,
            effects,
            digests,
            head,
            registry,
        })
    }

    /// Open a queue and check it against what the store last witnessed of its chain.
    ///
    /// This is the call every reader of a stored warrant should make. [`Self::open`] alone cannot
    /// tell a queue that was never written from one that was deleted — see [`StagedChainMark`] —
    /// and answering "0 staged effect(s)" for the second is the fail-open answer.
    ///
    /// # Errors
    /// Everything [`Self::open`] returns, plus [`WarrantError::Invalid`] when the log no longer
    /// contains the chain the mark recorded. `None` for `mark` means no witness exists (a warrant
    /// granted before marks did), and then this is exactly [`Self::open`] — an unwitnessed log is
    /// not evidence that nothing happened, and the caller is told nothing it cannot support.
    pub fn open_witnessed(
        path: impl AsRef<Path>,
        warrant_id: impl Into<String>,
        registry: EffectRegistry,
        mark: Option<&StagedChainMark>,
    ) -> Result<Self, WarrantError> {
        let queue = Self::open(path, warrant_id, registry)?;
        if let Some(mark) = mark {
            queue.verify_against(mark)?;
        }
        Ok(queue)
    }

    /// The chain head and count as they stand, for the store to witness.
    #[must_use]
    pub fn mark(&self, at: u64) -> StagedChainMark {
        StagedChainMark {
            head: self.head.clone(),
            count: self.effects.len() as u64,
            recorded_at: at,
        }
    }

    /// Check that this log still contains the chain a [`StagedChainMark`] recorded.
    ///
    /// # Errors
    /// [`WarrantError::Invalid`] when the record the mark named is gone or now carries a different
    /// digest. Growth past the mark is not an error: the log is append-only, so records staged
    /// after the mark was taken are the expected case.
    pub fn verify_against(&self, mark: &StagedChainMark) -> Result<(), WarrantError> {
        if mark.count == 0 {
            // Nothing was witnessed, so nothing can have been lost below it. A log that is absent
            // here is a log that was never written.
            return Ok(());
        }
        let index = (mark.count - 1) as usize;
        match self.digests.get(index) {
            Some(found) if *found == mark.head => Ok(()),
            Some(found) => Err(WarrantError::Invalid(format!(
                "the staged-effect log for {} no longer matches the chain this store recorded: \
                 effect {} carried {} when it was staged and carries {found} now. The log has been \
                 rewritten. Nothing here can say what the agent actually staged.",
                self.warrant_id, mark.count, mark.head
            ))),
            None => Err(WarrantError::Invalid(format!(
                "the staged-effect log for {} is missing records this store recorded: {} effect(s) \
                 were staged, ending at chain head {}, and the log now holds {}. It was truncated \
                 or deleted. Treating this as an empty queue would report zero staged effects and \
                 sign that into an evidence bundle, so it is refused instead.",
                self.warrant_id,
                mark.count,
                mark.head,
                self.digests.len()
            ))),
        }
    }

    fn digest(effect: &StagedEffect, prev: &str) -> Result<String, WarrantError> {
        let body = serde_json::to_vec(effect)
            .map_err(|e| WarrantError::Encode(format!("digest effect: {e}")))?;
        let mut hasher = Sha256::new();
        hasher.update(prev.as_bytes());
        // Length-prefixed so the previous digest and the body cannot be re-split.
        hasher.update((body.len() as u64).to_le_bytes());
        hasher.update(&body);
        Ok(hex::encode(hasher.finalize()))
    }

    /// Stage an effect and return the handle that stands for it.
    ///
    /// # Errors
    /// [`WarrantError::Invalid`] if the tool is unknown, or a target is unknown or of the wrong
    /// type.
    pub fn stage(
        &mut self,
        tool: &str,
        arguments: BTreeMap<String, String>,
        staged_at: u64,
    ) -> Result<StagedEffect, WarrantError> {
        let kind = self.registry.get(tool).cloned().ok_or_else(|| {
            WarrantError::Invalid(format!(
                "tool {tool:?} is not a known effect kind; it cannot be staged"
            ))
        })?;

        // Resolve and TYPE-CHECK every handle-shaped argument before anything is written.
        let mut depends_on = BTreeSet::new();
        for (name, value) in &arguments {
            if !value.contains("://") {
                continue;
            }
            if !self.knows(value) {
                return Err(WarrantError::Invalid(format!(
                    "{tool}: {name}={value:?} was not issued by this warrant"
                )));
            }
            let scheme = handle_scheme(value);
            if !kind.targets.contains(scheme) {
                // The R1 finding: a well-formed handle pointing at the wrong kind of object.
                return Err(WarrantError::Invalid(format!(
                    "{tool}: {name} is a {scheme:?} handle, but {tool} accepts {:?}",
                    kind.targets
                )));
            }
            depends_on.insert(value.clone());
        }

        let index = self.effects.len() as u64 + 1;
        let effect = StagedEffect {
            index,
            handle: format!("{}://staged/{}/{index}", kind.mints, self.warrant_id),
            tool: tool.to_string(),
            arguments,
            depends_on,
            staged_at,
        };

        let digest = Self::digest(&effect, &self.head)?;
        let record = QueueRecord {
            effect: effect.clone(),
            prev_digest: self.head.clone(),
            digest: digest.clone(),
        };
        self.append(&record)?;
        self.head = digest.clone();
        self.digests.push(digest);
        self.effects.push(effect.clone());
        Ok(effect)
    }

    fn append(&self, record: &QueueRecord) -> Result<(), WarrantError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| WarrantError::Encode(format!("create queue dir: {e}")))?;
        }
        let mut file: File = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| WarrantError::Encode(format!("open queue: {e}")))?;
        let line = serde_json::to_string(record)
            .map_err(|e| WarrantError::Encode(format!("encode queue record: {e}")))?;
        file.write_all(line.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.flush())
            // fsync before returning: an effect the caller believes is queued must actually be on
            // stable storage, or a crash loses work the developer was told was safe.
            .and_then(|()| file.sync_all())
            .map_err(|e| WarrantError::Encode(format!("append queue: {e}")))
    }

    fn knows(&self, handle: &str) -> bool {
        self.effects.iter().any(|e| e.handle == handle)
    }

    /// Every staged effect, in the order they were staged.
    #[must_use]
    pub fn effects(&self) -> &[StagedEffect] {
        &self.effects
    }

    /// Is the queue empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.effects.is_empty()
    }

    /// How many effects are staged.
    #[must_use]
    pub fn len(&self) -> usize {
        self.effects.len()
    }

    /// The chain head, for evidence.
    #[must_use]
    pub fn head_digest(&self) -> &str {
        &self.head
    }

    /// Effects in release order: dependencies before dependents.
    ///
    /// Every prefix of this order is a coherent state, which is what makes a partial release
    /// survivable rather than a mess to untangle.
    ///
    /// # Errors
    /// [`WarrantError::Invalid`] if the graph contains a cycle. It cannot today — an effect can
    /// only depend on handles that existed when it was staged, so dependencies always point
    /// backwards — but a cycle would mean no safe order exists, and silently picking one would be
    /// worse than refusing.
    pub fn release_order(&self) -> Result<Vec<&StagedEffect>, WarrantError> {
        let mut released: BTreeSet<&str> = BTreeSet::new();
        let mut ordered: Vec<&StagedEffect> = Vec::new();
        let mut remaining: Vec<&StagedEffect> = self.effects.iter().collect();

        while !remaining.is_empty() {
            let before = remaining.len();
            remaining.retain(|effect| {
                let ready = effect
                    .depends_on
                    .iter()
                    .all(|handle| released.contains(handle.as_str()));
                if ready {
                    released.insert(effect.handle.as_str());
                    ordered.push(effect);
                }
                !ready
            });
            if remaining.len() == before {
                return Err(WarrantError::Invalid(
                    "staged effects contain a dependency cycle; no safe release order exists"
                        .to_string(),
                ));
            }
        }
        Ok(ordered)
    }
}
