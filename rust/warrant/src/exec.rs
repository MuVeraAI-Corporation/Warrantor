//! EXEC admission by content digest (L4-05).
//!
//! Anything this process executes on a warrant's behalf is identified by the SHA-256 of its
//! bytes, never by its name or path, and the surface it may run on is declared in the warrant.
//! A renamed artifact gets the same verdict; a modified one with the same name is refused. The
//! refusal happens before the process exists, and every attempt -- admitted, unpinned or
//! refused -- is receipted with the digest before anything is spawned.
//!
//! # What this holds and what it does not
//!
//! The gate sits where Warrantor itself spawns: [`crate::daemon::supervise_run`]. It cannot see
//! what the agent then executes from its own shell; that is the mediation ceiling, and the bound
//! is labeled accordingly in [`crate::bound_strengths`]. Digest pinning does not make the pinned
//! artifact safe (blueprint E-04 residual); it makes "which code, exactly" a policy question.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Wire format of an EXEC receipt.
pub const EXEC_RECEIPT_FORMAT: &str = "warrantor.exec-receipt/1";

/// Where admitted code runs. Only surfaces this build has a chokepoint for are nameable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecSurface {
    /// The agent process spawned by `warrantor run` / `warrantor supervise`. Gated here.
    Process,
    /// An MCP server spawned by `--upstream`. Declarable; its gate is tool admission (manifests).
    Upstream,
}

impl ExecSurface {
    /// The word it is written as.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Upstream => "upstream",
        }
    }

    /// Parse one.
    ///
    /// # Errors
    /// A sentence naming the two surfaces this build gates. `shell`, `plugin` and `deserializer`
    /// are real surfaces the blueprint names; refusing them here is the point -- a surface with
    /// no chokepoint must not be declarable as though it had one.
    pub fn parse(word: &str) -> Result<Self, String> {
        match word.trim() {
            "process" => Ok(Self::Process),
            "upstream" => Ok(Self::Upstream),
            other => Err(format!(
                "{other:?} is not an execution surface this build has a chokepoint for. The two \
                 are: process, upstream."
            )),
        }
    }
}

/// One admitted artifact: a surface and the SHA-256 of the bytes that may run on it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ExecAdmission {
    /// Where it may run.
    pub surface: ExecSurface,
    /// Lowercase hex SHA-256 of the whole file. Never a name, never a path.
    pub sha256: String,
}

impl ExecAdmission {
    /// Parse `surface=<64 lowercase hex>`.
    ///
    /// # Errors
    /// A sentence. Uppercase hex is refused rather than lowered: two spellings of one digest
    /// would let the same artifact be admitted twice and revoked once.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let Some((surface, digest)) = raw.split_once('=') else {
            return Err(format!(
                "{raw:?}: an admission is written surface=<sha256>, e.g. process=<64 hex chars>. \
                 Get the digest with `warrantor exec digest <path>`."
            ));
        };
        let surface = ExecSurface::parse(surface)?;
        let digest = digest.trim();
        let is_lower_hex = digest.len() == 64
            && digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !is_lower_hex {
            return Err(format!(
                "{digest:?} is not a 64-character lowercase hex SHA-256. An admission names \
                 bytes, not a file: run `warrantor exec digest <path>` and paste the digest."
            ));
        }
        Ok(Self { surface, sha256: digest.to_string() })
    }
}

/// When in a run the admission was checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecPhase {
    /// `warrantor run`, before the detached supervisor is started. Advisory to the terminal.
    Preflight,
    /// `supervise_run`, immediately before `Supervisor::spawn`. The one that gates.
    Spawn,
}

/// What the gate decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecVerdict {
    /// The `(surface, sha256)` pair is in the warrant's declared set.
    Admitted,
    /// The warrant declares no execution surface. Digested and receipted; nothing refused.
    Unpinned,
    /// Strict mode and the pair is not declared. Nothing was spawned.
    Refused,
}

/// Resolve a command on `PATH`, the way a shell would.
///
/// Moved from the binary's `agents` verb. Written rather than shelled out to `which`/`where`,
/// which differ between platforms, are absent in minimal containers, and on Windows answer about
/// a different search order than the one a spawned process actually gets.
#[must_use]
pub fn resolve_on_path(command: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let extensions: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string())
            .split(';')
            .filter(|e| !e.is_empty())
            .map(str::to_string)
            .collect()
    } else {
        vec![String::new()]
    };
    for directory in std::env::split_paths(&path) {
        for extension in &extensions {
            let candidate = directory.join(format!("{command}{extension}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// The file a program name denotes, before anything is hashed or spawned.
///
/// A bare name is resolved on `PATH` and **never** in `cwd`: a file the agent wrote into its
/// worktree must not shadow a tool of the same name. A name containing a separator is a path;
/// relative paths are joined to `cwd`.
///
/// # Errors
/// A sentence when nothing is found. Nothing that cannot be found can be hashed, and nothing
/// that cannot be hashed can be admitted.
pub fn resolve_program(program: &str, cwd: Option<&Path>) -> Result<PathBuf, String> {
    let has_separator = program.contains('/') || program.contains(char::from(92));
    let candidate = if has_separator {
        let as_path = Path::new(program);
        match (as_path.is_absolute(), cwd) {
            (true, _) | (false, None) => as_path.to_path_buf(),
            (false, Some(dir)) => dir.join(as_path),
        }
    } else {
        return resolve_on_path(program).ok_or_else(|| {
            format!(
                "{program:?} is not on PATH. A bare name is looked up on PATH only, never in the \
                 worktree; give a path if you mean a file there."
            )
        });
    };
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(format!("{} is not a file", candidate.display()))
    }
}

/// SHA-256 of a whole file, streamed, with its length.
///
/// # Errors
/// A sentence on I/O failure.
pub fn sha256_file(path: &Path) -> Result<(String, u64), String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| format!("cannot open {} to digest it: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        total += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), total))
}
