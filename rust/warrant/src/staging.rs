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

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::WarrantError;

/// Digest that precedes the first entry in a queue.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

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
                effects.push(record.effect);
            }
        }

        Ok(Self {
            path,
            warrant_id,
            effects,
            head,
            registry,
        })
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
        self.head = digest;
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
