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
//! ```text
//! ~/.warrantor/
//!   warrants/wrt_<id>.json     signed warrant + lifecycle state
//!   staged/wrt_<id>.jsonl      hash-chained staged-effect queue
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

    /// Every warrant in the store, newest first by issue time.
    ///
    /// # Errors
    /// [`WarrantError::Encode`] if the directory cannot be read.
    pub fn list(&self) -> Result<Vec<StoredWarrant>, WarrantError> {
        let dir = self.root.join("warrants");
        let mut out = Vec::new();
        let entries =
            fs::read_dir(&dir).map_err(|e| WarrantError::Encode(format!("read warrants: {e}")))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            // A single unreadable warrant must not hide every other one -- a store that refuses to
            // list because one file is corrupt is a store you cannot recover from.
            if let Ok(body) = fs::read(&path) {
                if let Ok(stored) = serde_json::from_slice::<StoredWarrant>(&body) {
                    out.push(stored);
                }
            }
        }
        out.sort_by(|a, b| b.warrant.claims.issued_at.cmp(&a.warrant.claims.issued_at));
        Ok(out)
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
