//! L4-01 at the boundary: the agent endpoint classifies by the decomposition registry, and under
//! strict mode an undeclared tool is refused before the proxy decides anything.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use serde_json::Value;
use warrantor_warrant::effects::{Decomposition, DecompositionRegistry, UnclassifiedPolicy};
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
    seed_tools(dir, id, &["files.write_file", "files.read_file"])
}

fn seed_with_tool(dir: &Path, id: &str, tool: &str) -> StoredWarrant {
    seed_tools(dir, id, &[tool])
}

fn seed_tools(dir: &Path, id: &str, tools: &[&str]) -> StoredWarrant {
    let bounds = WarrantBounds {
        tools: tools.iter().map(|t| (*t).to_string()).collect(),
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

#[test]
fn strict_mode_refuses_an_undeclared_tool_before_the_proxy_and_names_it_afterwards() {
    let dir = tempdir("strict");
    let stored = seed(&dir, "wrt_strict");
    let store = WarrantStore::open(&dir).expect("store");
    let mut registry = DecompositionRegistry::builtin();
    registry
        .insert(Decomposition::parse("files.write_file=mutate").expect("parses"))
        .expect("insert");
    let mut endpoint = agent_endpoint_for(
        &stored,
        store.staged_path("wrt_strict"),
        ProxyMode::Enforce,
        now,
    )
    .expect("endpoint")
    .with_decompositions(registry, UnclassifiedPolicy::Refuse);

    let refused = endpoint.call("files.read_file", &path_argument());
    assert!(refused.is_error);
    assert!(
        refused.text.contains("no declared effect decomposition"),
        "{}",
        refused.text
    );
    assert!(
        refused
            .text
            .contains("--upstream-effects 'files.read_file="),
        "{}",
        refused.text
    );

    // Declared: passes the gate, reaches the proxy, and is answered by the one honest thing a
    // session with no upstream can say. Not staged, because EffectRegistry::github() does not
    // know it -- that is Task 2.3's job, not this one's.
    let declared = endpoint.call("files.write_file", &path_argument());
    assert!(
        !declared.text.contains("no declared effect decomposition"),
        "{}",
        declared.text
    );
    assert!(
        declared.text.contains("no upstream MCP server is attached"),
        "{}",
        declared.text
    );

    assert_eq!(
        endpoint.unclassified_tools(),
        vec!["files.read_file".to_string()]
    );
}

/// What the guess actually costs, at the one place in this build where the projected class still
/// changes an outcome by itself: observe mode refuses `Destructive` and `Financial` regardless of
/// the allowlist. Guessed, an actuating tool is `Read` and observe mode lets it through; declared,
/// it projects to `Destructive` and observe mode refuses it.
///
/// This is the assertion that makes the registry load-bearing rather than merely recorded, and it
/// is why `Actuate` may not project to `Physical`: `Physical` is absent from the proxy's
/// `NEVER_IN_OBSERVE`, so projecting there would have left this call forwarded.
#[test]
fn a_declared_actuation_is_refused_in_observe_mode_where_the_guess_was_forwarded() {
    let dir = tempdir("observe");
    let bounds_tool = "k8s.delete_pod";
    let stored = seed_with_tool(&dir, "wrt_observe", bounds_tool);
    let store = WarrantStore::open(&dir).expect("store");

    // Guessed: Read, which observe mode does not block, so the call proceeds.
    let mut guessing = agent_endpoint_for(
        &stored,
        store.staged_path("wrt_observe"),
        ProxyMode::Observe,
        now,
    )
    .expect("endpoint");
    let forwarded = guessing.call(bounds_tool, &path_argument());
    assert!(
        forwarded
            .text
            .contains("no upstream MCP server is attached"),
        "the guess forwards an actuation in observe mode: {}",
        forwarded.text
    );

    // Declared: net+mutate+actuate projects to Destructive, and observe mode refuses it.
    let mut registry = DecompositionRegistry::builtin();
    registry
        .insert(Decomposition::parse("k8s.delete_pod=net+mutate+actuate").expect("parses"))
        .expect("insert");
    let mut declaring = agent_endpoint_for(
        &stored,
        store.staged_path("wrt_observe"),
        ProxyMode::Observe,
        now,
    )
    .expect("endpoint")
    .with_decompositions(registry, UnclassifiedPolicy::GuessRead);
    let blocked = declaring.call(bounds_tool, &path_argument());
    assert!(blocked.is_error, "{}", blocked.text);
    assert!(
        blocked.text.contains("side_effect_class"),
        "the observe-mode block is the bound that refused it: {}",
        blocked.text
    );
    // And the declared tool is not on the guess list, because nothing was guessed about it.
    assert!(declaring.unclassified_tools().is_empty());
}
