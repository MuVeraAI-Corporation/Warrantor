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
//! This block listed two directories, which was true when it was written and wrong by ten by the
//! time anybody asked what the store actually holds. It is the operator-facing description of the
//! root, so it is kept complete — and `warrantor holdings` answers from
//! [`crate::retention::ArtifactClass`] rather than from this prose, so there is one list to keep
//! current instead of two. That list is hand-maintained as well, and claiming otherwise would be
//! the same rot in another file: a fourteenth directory has to be added to it by somebody. What is
//! mechanical is the part that can be checked — every directory `open` creates is asserted against
//! `ALL_CLASSES` in `tests/holdings.rs`.
//!
//! ```text
//! ~/.warrantor/
//!   warrants/<id>.json         signed warrant + lifecycle state + the witness taken at grant
//!   staged/<id>.jsonl          hash-chained staged-effect queue
//!   witness/<id>.jsonl         append-only record of how far that chain has advanced
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
//! # Why the chain witness is not kept in the warrant record
//!
//! It was, for one commit, and that was a lost update waiting to happen. The witness advances on
//! the agent's hot path — after every staged effect — while `settle` and `stop` load the same
//! record, spend seconds performing real outward effects, and then save `Settled` or `Held`. A
//! witness write that loaded before that save and stored after it would put `Open` back on disk:
//! a settled warrant that can be settled again (duplicate real-world effects), or a stop whose
//! signed record claims containment over a warrant the store says is still running.
//!
//! So the record keeps only the witness taken at grant, which nothing rewrites, and the advancing
//! witness is appended to `witness/<id>.jsonl` — one [`StagedChainMark`] per line, never rewritten,
//! never read-modify-written. Concurrent appends of a single short line do not interleave, and the
//! reader takes the highest count it finds, so a slow writer cannot lower a fast one's mark either.
//! [`Self::load`] merges the two and every reader sees the stronger of them.
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
    /// **What is persisted here is only the mark taken at grant.** The advancing witness is
    /// appended to `witness/<id>.jsonl` — see the module comment for why keeping it here would be a
    /// lost update on the hot path — and [`WarrantStore::load`] fills this field with whichever of
    /// the two recorded more effects. A save that carries a lagging mark therefore cannot undo an
    /// advance: the higher mark is in a file this record's writer never touches.
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
        for sub in ["warrants", "staged", "witness"] {
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

    /// Path to a warrant's chain-witness log.
    ///
    /// Deliberately not under `staged/`: a witness that a single `rm staged/<id>.*` removes along
    /// with the log it witnesses witnesses nothing.
    #[must_use]
    pub fn witness_path(&self, id: &str) -> PathBuf {
        self.root.join("witness").join(format!("{id}.jsonl"))
    }

    /// Persist a warrant, replacing any existing record for the same id.
    ///
    /// The write is atomic: content goes to a temporary file which is then renamed over the
    /// target. A warrant half-written by a process that died mid-save would be worse than one that
    /// was never saved, because the caller would believe bounds exist that do not.
    ///
    /// It is still a *whole-record* write, so two writers of the same record still race — `settle`
    /// and `stop` on one warrant is the same last-writer-wins it always was. What is no longer in
    /// that race is the chain witness: it advances by append, in its own log, so the frequent
    /// writer cannot clobber the slow one and the slow one cannot rewind the frequent one.
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

    /// Write a warrant that must not already exist.
    ///
    /// [`Self::save`] overwrites, which is right for a state transition — `settle` and `void`
    /// rewrite a record they just read — and catastrophic for a *grant*. A grant that lands on an
    /// existing id replaces that warrant's bounds, its worktree pointer and its staged-chain
    /// witness with a different warrant's, and the record it replaced is the only place the first
    /// warrant's staged effects could be found or checked. Nothing announces it: `fs::rename` over
    /// an existing file succeeds.
    ///
    /// This was reachable. Warrant ids were derived from a **one-second** clock, so two grants in
    /// the same second produced the same id — which is how a test that granted twice in a row
    /// found it, intermittently, depending on where the second boundary fell. The id is now drawn
    /// from the system CSPRNG, and this method exists so that a collision from *any* future
    /// source — a restored backup, a copied store, an id supplied by a caller — is a refusal
    /// rather than a silent overwrite. Two defences, because the first one is a probability
    /// argument and the second one is not.
    ///
    /// # Errors
    /// [`WarrantError::Invalid`] if a warrant with that id is already stored, and
    /// [`WarrantError::Encode`] on serialisation or I/O failure.
    pub fn create(&self, stored: &StoredWarrant) -> Result<(), WarrantError> {
        let path = self.warrant_path(&stored.warrant.claims.id);
        if path.exists() {
            return Err(WarrantError::Invalid(format!(
                "a warrant with id {} is already stored at {}. Refusing to write over it: that \
                 record is the only place its bounds, its worktree and its staged-effect chain \
                 witness are held, and replacing it would leave any effects staged under it \
                 unreachable and uncheckable.",
                stored.warrant.claims.id,
                path.display()
            )));
        }
        self.save(stored)
    }

    /// Load a warrant by id, with its chain witness resolved.
    ///
    /// `staged_chain` comes back as the stronger of what the record carries and what the witness
    /// log holds, so every caller reads the furthest point this store can prove the chain reached.
    ///
    /// # Errors
    /// [`WarrantError::Invalid`] if it does not exist, [`WarrantError::Encode`] if it cannot be
    /// parsed, and either if the witness log exists and cannot be read — an unreadable witness is
    /// not an absent one, and treating it as absent would silently drop the check it exists to make.
    pub fn load(&self, id: &str) -> Result<StoredWarrant, WarrantError> {
        let path = self.warrant_path(id);
        let body = fs::read(&path)
            .map_err(|_| WarrantError::Invalid(format!("no warrant {id} in this store")))?;
        let mut stored: StoredWarrant = serde_json::from_slice(&body)
            .map_err(|e| WarrantError::Encode(format!("parse warrant {id}: {e}")))?;
        self.attach_witness(&mut stored)?;
        Ok(stored)
    }

    /// Fill `stored.staged_chain` with the strongest mark this store holds for it.
    ///
    /// The witness log wins whenever it recorded at least as many effects as the record did, which
    /// is the ordinary case: the record's mark is the one taken at grant and never advances.
    /// Deliberately applied even when the record carries no mark at all — a warrant whose record
    /// says `null` while a witness log sits beside it is not a pre-witness warrant, it is a record
    /// somebody edited, and the log is the evidence that survives that edit.
    fn attach_witness(&self, stored: &mut StoredWarrant) -> Result<(), WarrantError> {
        let logged = self.witnessed_mark(&stored.warrant.claims.id)?;
        if let Some(logged) = logged {
            let advances = stored
                .staged_chain
                .as_ref()
                .is_none_or(|recorded| logged.count >= recorded.count);
            if advances {
                stored.staged_chain = Some(logged);
            }
        }
        Ok(())
    }

    /// The furthest mark in a warrant's witness log, or `None` if it has none.
    ///
    /// Highest count wins rather than last line, because two processes appending concurrently can
    /// land in either order and the lower mark must not be able to hide the higher one.
    ///
    /// # Errors
    /// [`WarrantError::Encode`] if the log exists and cannot be read, [`WarrantError::Invalid`] if
    /// a line will not parse. Both are refusals: a witness nobody can read cannot be quietly
    /// downgraded to "this warrant was never witnessed", because that is the exact answer an
    /// attacker who corrupted it would be after.
    fn witnessed_mark(&self, id: &str) -> Result<Option<StagedChainMark>, WarrantError> {
        let path = self.witness_path(id);
        let body = match fs::read_to_string(&path) {
            Ok(body) => body,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(WarrantError::Encode(format!(
                    "the chain witness for {id} exists and could not be read: {e}. Nothing here \
                     can say how far its staged-effect log should reach."
                )))
            }
        };
        let mut furthest: Option<StagedChainMark> = None;
        for (number, line) in body.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let mark: StagedChainMark = serde_json::from_str(line).map_err(|e| {
                WarrantError::Invalid(format!(
                    "the chain witness for {id} is corrupt at line {}: {e}. It is the record of \
                     how far the staged-effect log reached, so a line nobody can read is refused \
                     rather than skipped.",
                    number + 1
                ))
            })?;
            if furthest.as_ref().is_none_or(|best| mark.count > best.count) {
                furthest = Some(mark);
            }
        }
        Ok(furthest)
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
    /// An append to `witness/<id>.jsonl`, never a rewrite of the warrant record. This runs on the
    /// agent's hot path — once per staged effect, from the CLI and from every MCP `tools/call` that
    /// stages — while `settle` and `stop` hold a copy of the same record across seconds of real
    /// outward work. A load-modify-save here would put their `Settled`/`Held` back to `Open`; see
    /// the module comment.
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
        // `Err` from `try_exists` is "cannot tell", and the cheaper mistake is to record a witness
        // for a warrant that turns out not to exist: an orphan line in a log nobody reads, against
        // losing the detection this call exists to provide.
        if !self.warrant_path(id).try_exists().unwrap_or(true) {
            return Err(WarrantError::Invalid(format!(
                "no warrant {id} in this store"
            )));
        }
        self.append_mark(id, &queue.mark(at))
    }

    /// Append one mark to a warrant's witness log.
    fn append_mark(&self, id: &str, mark: &StagedChainMark) -> Result<(), WarrantError> {
        let path = self.witness_path(id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| WarrantError::Encode(format!("create witness dir: {e}")))?;
        }
        let mut line = serde_json::to_string(mark)
            .map_err(|e| WarrantError::Encode(format!("encode chain witness: {e}")))?;
        line.push('\n');
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| WarrantError::Encode(format!("open witness: {e}")))?;
        // One `write_all` of one short line, in append mode: the unit the filesystem will not
        // interleave with another process's. Two writes here would let a second stage land between
        // them and produce a line that parses as neither mark.
        std::io::Write::write_all(&mut file, line.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| WarrantError::Encode(format!("append witness: {e}")))
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
    /// "Could not be read" includes a warrant whose record parses and whose witness log does not:
    /// the store cannot say how far that warrant's staged chain reached, so it is not one of the
    /// warrants this store can answer for.
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
                    // Witness resolved here too, not only in `load`. A listing whose marks stopped
                    // at the grant-time mark would hand any caller that opened a queue from it a
                    // check that passes on a log deleted after the first staged effect -- the
                    // fail-open answer this whole mechanism exists to remove.
                    Ok(mut stored) => match self.attach_witness(&mut stored) {
                        Ok(()) => out.push(stored),
                        Err(_) => unreadable = unreadable.saturating_add(1),
                    },
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
