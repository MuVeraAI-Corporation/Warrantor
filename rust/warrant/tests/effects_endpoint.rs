//! L4-01 at the boundary: the agent endpoint classifies by the decomposition registry, and under
//! strict mode an undeclared tool is refused before the proxy decides anything.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use serde_json::Value;
use warrantor_warrant::mcp::Endpoint;
use warrantor_warrant::mcp_endpoints::agent_endpoint_for;
use warrantor_warrant::proxy::ProxyMode;
use warrantor_warrant::store::{StoredWarrant, WarrantStore};
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds};

const NOW: u64 = 1_786_000_000;

fn now() -> u64 {
    NOW
}

fn tempdir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-effects-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn seed(dir: &Path, id: &str) -> StoredWarrant {
    let bounds = WarrantBounds {
        tools: ["files.write_file", "files.read_file"]
            .into_iter()
            .map(str::to_string)
            .collect(),
        write_paths: BTreeSet::new(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        delegation_depth: 1,
    };
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let settle = SigningKey::from_bytes(&[2; 32]);
    let warrant = Warrant::grant(
        id,
        "classify or refuse",
        "spiffe://muveraai.com/agent/a",
        bounds,
        NOW,
        &settle.verifying_key(),
        &issuer,
    )
    .expect("grant");
    let stored = StoredWarrant {
        warrant,
        worktree: None,
        repo: None,
        branch: None,
        base_commit: None,
        staged_chain: None,
    };
    WarrantStore::open(dir)
        .expect("store")
        .save(&stored)
        .expect("save");
    stored
}

fn path_argument() -> BTreeMap<String, Value> {
    // No dot, no scheme: the egress broker must find no destination in it, so the only thing
    // that can refuse these calls is the decomposition gate.
    let mut args = BTreeMap::new();
    args.insert("path".to_string(), Value::String("notes".to_string()));
    args
}

/// The incident, reproduced. A tool nobody declared is forwarded as if it only read, and the only
/// trace is a name in the end-of-session list. This test passes on the code that predates the
/// registry, which is the point: it is what the strict refusal has to change.
#[test]
fn the_shipped_policy_still_guesses_and_still_names_the_guess() {
    let dir = tempdir("permissive");
    let stored = seed(&dir, "wrt_guess");
    let store = WarrantStore::open(&dir).expect("store");
    // No `with_decompositions` at all: the default is the builtin registry and GuessRead, which
    // is byte-for-byte what every session before this task did.
    let mut endpoint = agent_endpoint_for(
        &stored,
        store.staged_path("wrt_guess"),
        ProxyMode::Enforce,
        now,
    )
    .expect("endpoint");
    let guessed = endpoint.call("files.read_file", &path_argument());
    assert!(
        !guessed.text.contains("no declared effect decomposition"),
        "{}",
        guessed.text
    );
    assert!(
        guessed.text.contains("no upstream MCP server is attached"),
        "{}",
        guessed.text
    );
    assert_eq!(
        endpoint.unclassified_tools(),
        vec!["files.read_file".to_string()]
    );
}
