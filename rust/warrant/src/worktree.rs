//! W4 — worktree isolation.
//!
//! The "I" in ACID. An agent working under a warrant does so in its own git worktree on its own
//! branch, so nothing it writes is visible to anyone — including a concurrently running warrant —
//! until the warrant settles.
//!
//! # Why a worktree rather than a branch or a copy
//!
//! A branch alone does not isolate: two agents on two branches in one checkout still share a
//! working directory, and the second `git checkout` destroys the first agent's uncommitted work.
//! A full copy isolates but breaks the link to the repository's history, so merging back is a
//! patch-application problem rather than a merge.
//!
//! A worktree gives both: a separate working directory with its own index and HEAD, sharing the
//! object database. Settling is an ordinary merge; voiding is deleting a directory and a branch.
//! This is also the mechanism already used for parallel agent work, so it is a pattern the
//! codebase understands rather than a new one.
//!
//! # What this does NOT isolate
//!
//! Only the filesystem, and only inside the repository. A warrant that permits egress can still
//! reach the network; a tool that writes outside the worktree is bounded by the path allowlist
//! rather than by git. **Isolation is a property of the declared bounds, not of the worktree**,
//! and the docs must not overclaim it.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::WarrantError;

/// Branch prefix for warrant worktrees. Namespaced so a warrant branch is never mistaken for a
/// human's.
pub const BRANCH_PREFIX: &str = "warrantor/";

/// An isolated working directory for one warrant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Worktree {
    /// Repository the worktree was created from.
    pub repo: PathBuf,
    /// Absolute path to the worktree.
    pub path: PathBuf,
    /// Branch the worktree is on.
    pub branch: String,
    /// The commit the branch started from, so a settle knows what to merge into.
    pub base_commit: String,
}

/// Canonicalise a path into a form git will accept.
///
/// On Windows `canonicalize` returns an extended-length path (`\\?\C:\…`). Rust and the Win32 API
/// handle those, but git does not: it tries to create a directory literally named `?` and fails
/// with `could not create leading directories of '//?/C:/…': Invalid argument`. Since every path
/// here is handed to git as an argument, the prefix has to come off.
///
/// Found by running the CLI against a real repository rather than by reading the code — the unit
/// tests passed because they never invoked git with a canonicalised path.
fn canonical_for_git(path: &Path) -> Result<PathBuf, WarrantError> {
    let canonical = path
        .canonicalize()
        .map_err(|e| WarrantError::Invalid(format!("repository path: {e}")))?;
    let text = canonical.to_string_lossy();
    Ok(PathBuf::from(
        text.strip_prefix(r"\\?\").unwrap_or(&text).to_string(),
    ))
}

fn git(repo: &Path, args: &[&str]) -> Result<String, WarrantError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|e| WarrantError::Encode(format!("git not available: {e}")))?;
    if !output.status.success() {
        return Err(WarrantError::Invalid(format!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

impl Worktree {
    /// Create an isolated worktree for `warrant_id` under `<repo>/.warrantor/<warrant_id>`.
    ///
    /// # Errors
    /// [`WarrantError::Invalid`] if the repository is not a git repository, if a worktree for this
    /// warrant already exists, or if git refuses.
    pub fn create(repo: impl AsRef<Path>, warrant_id: &str) -> Result<Self, WarrantError> {
        let repo = canonical_for_git(repo.as_ref())?;

        // Establish it really is a repository before creating anything, so a typo produces a clear
        // error rather than a half-made directory.
        git(&repo, &["rev-parse", "--git-dir"])?;
        let base_commit = git(&repo, &["rev-parse", "HEAD"])?;

        let path = repo.join(crate::store::REPO_DIR).join(warrant_id);
        if path.exists() {
            return Err(WarrantError::Invalid(format!(
                "a worktree for {warrant_id} already exists at {}",
                path.display()
            )));
        }
        let branch = format!("{BRANCH_PREFIX}{warrant_id}");

        git(
            &repo,
            &[
                "worktree",
                "add",
                "-b",
                &branch,
                &path.to_string_lossy(),
                &base_commit,
            ],
        )?;

        Ok(Self {
            repo,
            path,
            branch,
            base_commit,
        })
    }

    /// Reconstruct a handle to an existing worktree without creating one.
    #[must_use]
    pub fn existing(repo: PathBuf, path: PathBuf, branch: String, base_commit: String) -> Self {
        Self {
            repo,
            path,
            branch,
            base_commit,
        }
    }

    /// Commits made on this branch since it diverged from its base.
    ///
    /// # Errors
    /// [`WarrantError::Invalid`] if git refuses.
    pub fn commits(&self) -> Result<Vec<String>, WarrantError> {
        let range = format!("{}..{}", self.base_commit, self.branch);
        let out = git(&self.repo, &["log", "--oneline", &range])?;
        Ok(out.lines().map(str::to_string).collect())
    }

    /// Files changed relative to the base commit, including uncommitted work.
    ///
    /// Uncommitted changes count: an agent that edited files without committing still changed the
    /// worktree, and a report that omitted them would understate what happened.
    ///
    /// # Errors
    /// [`WarrantError::Invalid`] if git refuses.
    pub fn changed_files(&self) -> Result<Vec<String>, WarrantError> {
        let mut files: Vec<String> = git(
            &self.repo,
            &["diff", "--name-only", &self.base_commit, &self.branch],
        )?
        .lines()
        .map(str::to_string)
        .collect();

        // `git -C <repo>` would report the main worktree's status, not this one.
        let uncommitted = Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .args(["status", "--porcelain"])
            .output()
            .map_err(|e| WarrantError::Encode(format!("git status: {e}")))?;
        for line in String::from_utf8_lossy(&uncommitted.stdout).lines() {
            if let Some(name) = line.get(3..) {
                let name = name.trim().to_string();
                if !name.is_empty() && !files.contains(&name) {
                    files.push(name);
                }
            }
        }
        files.sort();
        Ok(files)
    }

    /// Commit whatever the agent left uncommitted, so the work can be settled.
    ///
    /// # Why this is not automatic
    ///
    /// Coding agents edit files; most do not commit. The first dogfood run of this product ended
    /// with a correct fix sitting in the worktree and `settle` refusing it — the documented happy
    /// path did not complete. Committing silently inside `settle` would fix that and introduce a
    /// worse problem: work merged into the base branch under a message nobody chose, with no moment
    /// at which the operator saw what was being committed on their behalf.
    ///
    /// So it stays opt-in. `settle` still refuses a dirty worktree by default and names this as the
    /// way through.
    ///
    /// # It commits only what the warrant permitted
    ///
    /// Not `git add -A`. An agent that runs the test suite leaves `__pycache__`, `target/`, coverage
    /// output and whatever else its tools produced; a repository without an exhaustive `.gitignore`
    /// would have all of it committed and merged. The first dogfood run did exactly that and then
    /// failed the merge on the artifacts it had just committed.
    ///
    /// The warrant already says which paths the agent was allowed to write. Those are precisely the
    /// paths whose changes are legitimate, so those are the only ones staged. Anything the agent
    /// produced outside its write bounds is left in the worktree, where it can be inspected, rather
    /// than merged into the base branch on its behalf.
    ///
    /// Returns the number of paths committed.
    ///
    /// # Errors
    /// [`WarrantError::Encode`] if git cannot be run, [`WarrantError::Invalid`] if the commit fails.
    pub fn commit_all<'a>(
        &self,
        message: &str,
        write_paths: impl IntoIterator<Item = &'a String>,
    ) -> Result<usize, WarrantError> {
        let globs: Vec<&str> = write_paths.into_iter().map(String::as_str).collect();
        if globs.is_empty() {
            return Err(WarrantError::Invalid(
                "this warrant permits no write paths, so there is nothing it could legitimately \
                 have changed; refusing to commit on its behalf"
                    .to_string(),
            ));
        }

        let mut add = vec!["add", "--"];
        add.extend_from_slice(&globs);
        git(&self.path, &add)?;

        // Count what is actually staged, not what is merely present in the worktree: the untracked
        // artifacts left outside the bounds are deliberately not part of this number.
        let staged = Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .args(["diff", "--cached", "--name-only"])
            .output()
            .map_err(|e| WarrantError::Encode(format!("git diff --cached: {e}")))?;
        let listed = String::from_utf8_lossy(&staged.stdout);
        let count = listed.lines().filter(|l| !l.trim().is_empty()).count();
        if count == 0 {
            return Ok(0);
        }
        git(&self.path, &["commit", "-m", message])?;
        Ok(count)
    }

    /// Merge this warrant's branch back into the branch it came from.
    ///
    /// Uses `--no-ff` so the warrant is visible in history as a unit: a reviewer looking at the log
    /// should be able to see that a block of work came from one agent run, not have it flattened
    /// into indistinguishable commits.
    ///
    /// # Errors
    /// [`WarrantError::Invalid`] on merge conflict or if there is uncommitted work — settling a
    /// worktree with unstaged changes would silently drop them.
    pub fn merge_into_base(&self, message: &str) -> Result<(), WarrantError> {
        let dirty = Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .args(["status", "--porcelain"])
            .output()
            .map_err(|e| WarrantError::Encode(format!("git status: {e}")))?;
        if !String::from_utf8_lossy(&dirty.stdout).trim().is_empty() {
            return Err(WarrantError::Invalid(
                "the worktree has uncommitted changes; the merge would silently drop them. \
                 Most agents edit files without committing, so this is the common case rather \
                 than a mistake: re-run with `--commit \"<message>\"` to commit the agent's work \
                 and settle it, or commit it yourself in the worktree first."
                    .to_string(),
            ));
        }
        git(
            &self.repo,
            &["merge", "--no-ff", "-m", message, &self.branch],
        )?;
        Ok(())
    }

    /// Remove the worktree and delete its branch.
    ///
    /// Used by void. `--force` is required because the worktree usually has changes — discarding
    /// them is the entire point of voiding.
    ///
    /// # Errors
    /// [`WarrantError::Invalid`] if git refuses.
    pub fn remove(&self) -> Result<(), WarrantError> {
        git(
            &self.repo,
            &[
                "worktree",
                "remove",
                "--force",
                &self.path.to_string_lossy(),
            ],
        )?;
        // A branch left behind after a void would accumulate as litter and, worse, would let
        // discarded work be resurrected by someone who found the branch later.
        let _ = git(&self.repo, &["branch", "-D", &self.branch]);
        Ok(())
    }
}
