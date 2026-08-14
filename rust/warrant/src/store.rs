//! Durable warrant storage.
//!
//! Warrants outlive the process that granted them: a developer grants one, closes the terminal,
//! and settles it the next morning. So the store is the boundary between "a warrant exists" and
//! "a warrant is a value in memory that vanishes on exit".
//!
//! # Layout
//!
//! Receipts and warrants live centrally so one tamper-evident chain covers every repository;
//! worktrees live in the repository because git requires it.
//!
//! This block listed two directories, which was true when it was written and wrong by nine by the
//! time anybody asked what the store actually holds. It is the operator-facing description of the
//! root, so it is kept complete — and `warrantor holdings` enumerates the same locations from
//! [`crate::retention::ArtifactClass`] rather than from this prose, so an eleventh directory shows
//! up in the answer whether or not somebody remembers to edit a comment.
//!
//! ```text
//! ~/.warrantor/
//!   warrants/<id>.json         signed warrant + lifecycle state + the staged-chain witness
//!   staged/<id>.jsonl          hash-chained staged-effect queue
//!   stops/<id>.json            signed stop records
//!   spend/<id>.json            signed observed-spend ledger
//!   daemons/<id>[.done].json   supervisor registration and completion
//!   logs/<id>.log              the agent's raw stdout/stderr
//!   refusals/<id>.jsonl        what a bound refused during a session
//!   guard/<id>.jsonl           guard-model session records and signals
//!   keys/{issuer,settle}.key   signing keys
//!   serve/{token,open.html}    the read API's bearer token and its browser shim
//!   backends.json              the local price table for spend routing
//! <repo>/.warrantor/
//!   wrt_<id>/                  the git worktree
//! ```
//!
//! # Why the state is stored outside the signature
//!
//! A warrant's bounds are signed and immutable; its *state* changes as it lives. Storing the state
//! inside the signed claims would mean re-signing on every transition, which would need the issuer
//! key present at settle time — exactly the key we are trying to keep out of the settle path. So
//! state is stored alongside, and every transition is separately evidenced.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::staging::{EffectRegistry, StagedChainMark, StagingQueue};
use crate::{Warrant, WarrantError, WarrantState};

/// Directory name used inside a repository for worktrees.
pub const REPO_DIR: &str = ".warrantor";

/// A warrant as persisted: the signed object plus the mutable lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredWarrant {
    /// The signed warrant.
    pub warrant: Warrant,
    /// Absolute path to the worktree, when one has been created.
    pub worktree: Option<PathBuf>,
    /// Repository the warrant was granted against.
    pub repo: Option<PathBuf>,
    /// Branch the worktree is on.
    #[serde(default)]
    pub branch: Option<String>,
    /// Commit the branch diverged from.
    ///
    /// Persisted because the report needs it to compute what changed, and reconstructing a
    /// worktree handle without it silently produced `git diff <empty>..<branch>`, which fails
    /// with "ambiguous argument". Derived state that cannot be re-derived has to be stored.
    #[serde(default)]
    pub base_commit: Option<String>,
    /// What the store last saw of this warrant's staged-effect chain.
    ///
    /// Stored for the same reason as `base_commit`, one step further: the staged-effect log is
    /// created lazily, so its absence is ambiguous — a warrant that staged nothing and a warrant
    /// whose log was deleted read identically, as an empty queue at genesis. The witness is what
    /// makes the second one detectable, and it has to live outside the file it witnesses.
    ///
    /// `None` on warrants granted before this field existed. That is "cannot say", not "nothing
    /// was staged", and [`StagingQueue::open_witnessed`] checks nothing when it is absent rather
    /// than inventing a verdict.
    #[serde(default)]
    pub staged_chain: Option<StagedChainMark>,
}

/// A filesystem-backed warrant store.
#[derive(Debug, Clone)]
pub struct WarrantStore {
    root: PathBuf,
}

impl WarrantStore {
    /// Open (or create) a store rooted at `root`, conventionally `~/.warrantor`.
    ///
    /// # Errors
    /// [`WarrantError::Encode`] if the directories cannot be created.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, WarrantError> {
        let root = root.as_ref().to_path_buf();
        for sub in ["warrants", "staged"] {
            fs::create_dir_all(root.join(sub))
                .map_err(|e| WarrantError::Encode(format!("create {sub}: {e}")))?;
        }
        Ok(Self { root })
    }

    /// The conventional store location for the current user.
    ///
    /// # Errors
    /// [`WarrantError::Encode`] if no home directory can be determined.
    pub fn default_root() -> Result<PathBuf, WarrantError> {
        // std has no home_dir that is not deprecated, and pulling a crate in for one lookup is
        // not worth the supply-chain surface on a security component.
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .ok_or_else(|| {
                WarrantError::Encode("neither HOME nor USERPROFILE is set".to_string())
            })?;
        Ok(PathBuf::from(home).join(".warrantor"))
    }

    /// The root this store is open on.
    ///
    /// Exposed because enumerating the store from outside used to mean rebuilding the path from
    /// `default_root()` and hoping the two agreed.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn warrant_path(&self, id: &str) -> PathBuf {
        self.root.join("warrants").join(format!("{id}.json"))
    }

    /// Path to a warrant's staged-effect log.
    #[must_use]
    pub fn staged_path(&self, id: &str) -> PathBuf {
        self.root.join("staged").join(format!("{id}.jsonl"))
    }

    /// Persist a warrant, replacing any existing record for the same id.
    ///
    /// The write is atomic: content goes to a temporary file which is then renamed over the
    /// target. A warrant half-written by a process that died mid-save would be worse than one that
    /// was never saved, because the caller would believe bounds exist that do not.
    ///
    /// # Errors
    /// [`WarrantError::Encode`] on serialisation or I/O failure.
    pub fn save(&self, stored: &StoredWarrant) -> Result<(), WarrantError> {
        let path = self.warrant_path(&stored.warrant.claims.id);
        let temp = path.with_extension("json.tmp");
        let body = serde_json::to_vec_pretty(stored)
            .map_err(|e| WarrantError::Encode(format!("serialise warrant: {e}")))?;
        fs::write(&temp, &body).map_err(|e| WarrantError::Encode(format!("write temp: {e}")))?;
        fs::rename(&temp, &path).map_err(|e| WarrantError::Encode(format!("rename: {e}")))?;
        Ok(())
    }

    /// Load a warrant by id.
    ///
    /// # Errors
    /// [`WarrantError::Invalid`] if it does not exist, [`WarrantError::Encode`] if it cannot be
    /// parsed.
    pub fn load(&self, id: &str) -> Result<StoredWarrant, WarrantError> {
        let path = self.warrant_path(id);
        let body = fs::read(&path)
            .map_err(|_| WarrantError::Invalid(format!("no warrant {id} in this store")))?;
        serde_json::from_slice(&body)
            .map_err(|e| WarrantError::Encode(format!("parse warrant {id}: {e}")))
    }

    /// Open a warrant's staged-effect queue, checked against the chain this store witnessed.
    ///
    /// The call every reader should make instead of [`StagingQueue::open`] on a bare path. Opening
    /// by path alone cannot tell a queue that was never written from one that was deleted, and the
    /// difference decides whether a report says "0 staged effect(s)" or refuses to answer.
    ///
    /// # Errors
    /// [`WarrantError::Invalid`] if there is no such warrant, if the chain does not replay, or if
    /// the log no longer holds the chain the witness recorded.
    pub fn open_queue(
        &self,
        id: &str,
        registry: EffectRegistry,
    ) -> Result<StagingQueue, WarrantError> {
        let stored = self.load(id)?;
        StagingQueue::open_witnessed(
            self.staged_path(id),
            id,
            registry,
            stored.staged_chain.as_ref(),
        )
    }

    /// Record where a warrant's staged chain now stands.
    ///
    /// Called after an effect is appended, never before: the witness follows the log so that a
    /// crash between the two leaves a mark that lags (weaker detection) rather than one that runs
    /// ahead (a refusal for a log nobody touched).
    ///
    /// # Errors
    /// [`WarrantError::Invalid`] if there is no such warrant, [`WarrantError::Encode`] on I/O
    /// failure.
    pub fn witness_staged_chain(
        &self,
        id: &str,
        queue: &StagingQueue,
        at: u64,
    ) -> Result<(), WarrantError> {
        let mut stored = self.load(id)?;
        stored.staged_chain = Some(queue.mark(at));
        self.save(&stored)
    }

    /// Every warrant in the store, newest first by issue time.
    ///
    /// # Errors
    /// [`WarrantError::Encode`] if the directory cannot be read.
    pub fn list(&self) -> Result<Vec<StoredWarrant>, WarrantError> {
        Ok(self.list_counting_unreadable()?.0)
    }

    /// Every warrant in the store, and how many files could not be read.
    ///
    /// [`Self::list`] drops what it cannot parse, which is right for a listing — a store that
    /// refuses to list because one file is corrupt is a store you cannot recover from — but it
    /// makes the result look authoritative when it is not. Anything answering "what does this
    /// machine hold" has to be able to say "fourteen, and three I could not read"; a count built on
    /// `list()` alone would report fourteen out of seventeen and look like a complete answer.
    ///
    /// # Errors
    /// [`WarrantError::Encode`] if the directory cannot be read.
    pub fn list_counting_unreadable(&self) -> Result<(Vec<StoredWarrant>, usize), WarrantError> {
        let dir = self.root.join("warrants");
        let mut out = Vec::new();
        let mut unreadable = 0usize;
        let entries =
            fs::read_dir(&dir).map_err(|e| WarrantError::Encode(format!("read warrants: {e}")))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            // A single unreadable warrant must not hide every other one -- a store that refuses to
            // list because one file is corrupt is a store you cannot recover from.
            match fs::read(&path) {
                Ok(body) => match serde_json::from_slice::<StoredWarrant>(&body) {
                    Ok(stored) => out.push(stored),
                    Err(_) => unreadable = unreadable.saturating_add(1),
                },
                Err(_) => unreadable = unreadable.saturating_add(1),
            }
        }
        // Newest first. Expressed with `Reverse` rather than a hand-written comparator so the
        // ordering is stated once instead of depending on argument order being read correctly.
        out.sort_by_key(|s| std::cmp::Reverse(s.warrant.claims.issued_at));
        Ok((out, unreadable))
    }

    /// Warrants that are still open or held — the ones that need a decision.
    ///
    /// # Errors
    /// As [`Self::list`].
    pub fn outstanding(&self) -> Result<Vec<StoredWarrant>, WarrantError> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|s| matches!(s.warrant.state, WarrantState::Open | WarrantState::Held))
            .collect())
    }
}
