//! `warrantor holdings`: the inventory a regulated buyer asks for, and the things it must not fake.
//!
//! Three properties are load-bearing here and each has a test:
//! it reads and never writes; a file it could not read is reported as unknown rather than dropped
//! out of the count; and it never claims a per-person answer the store cannot support.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ed25519_dalek::SigningKey;
use warrantor_warrant::retention::{self, ArtifactClass, DeletionEffect, RETENTION_STATEMENT};
use warrantor_warrant::staging::{EffectRegistry, StagedChainMark};
use warrantor_warrant::store::{StoredWarrant, WarrantStore};
use warrantor_warrant::{
    SideEffectClass, Warrant, WarrantBounds, WarrantState, DEFAULT_CLI_SUBJECT,
};

const NOW: u64 = 1_786_000_000;

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-holdings-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn warrant(id: &str, subject: &str) -> Warrant {
    let settle = SigningKey::from_bytes(&[9u8; 32]);
    let issuer = SigningKey::from_bytes(&[7u8; 32]);
    let bounds = WarrantBounds {
        tools: ["github.create_pr"]
            .into_iter()
            .map(str::to_string)
            .collect(),
        write_paths: BTreeSet::new(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        delegation_depth: 3,
    };
    Warrant::grant(
        id,
        "goal",
        subject,
        bounds,
        NOW,
        &settle.verifying_key(),
        &issuer,
    )
    .expect("grant")
}

fn save(
    store: &WarrantStore,
    id: &str,
    subject: &str,
    state: WarrantState,
    worktree: Option<&Path>,
    witnessed: bool,
) {
    let mut w = warrant(id, subject);
    w.state = state;
    store
        .save(&StoredWarrant {
            warrant: w,
            worktree: worktree.map(Path::to_path_buf),
            repo: None,
            branch: None,
            base_commit: None,
            staged_chain: witnessed.then(|| StagedChainMark::genesis(NOW)),
        })
        .expect("save");
}

fn class(holdings: &retention::Holdings, which: ArtifactClass) -> &retention::ClassHoldings {
    holdings
        .classes
        .iter()
        .find(|c| c.class == which)
        .expect("every class is always reported, present or not")
}

/// A store must never lose a warrant to a name collision, whatever produced one.
///
/// `save` renames over an existing file without complaint, which is right for a state transition —
/// `settle` and `void` rewrite a record they just read — and destroys evidence on a *grant*. The
/// record replaced is the only place that warrant's bounds, its worktree and its staged-effect
/// chain witness live, so a collision leaves anything staged under it unreachable and uncheckable.
///
/// Reached in practice because warrant ids came from a one-second clock. The ids are random now,
/// which is a probability argument; this is the defence that is not one.
#[test]
fn creating_a_warrant_over_an_existing_one_refuses_rather_than_replacing_it() {
    let dir = tempdir("no-clobber");
    let store = WarrantStore::open(&dir).expect("open");
    let record = |subject: &str| StoredWarrant {
        warrant: warrant("wrt_collide", subject),
        worktree: None,
        repo: None,
        branch: None,
        base_commit: None,
        staged_chain: Some(StagedChainMark::genesis(NOW)),
    };

    store
        .create(&record("spiffe://muveraai.com/agent/first"))
        .expect("the first create succeeds");

    let error = store
        .create(&record("spiffe://muveraai.com/agent/second"))
        .expect_err("the second must refuse");
    let rendered = error.to_string();
    assert!(rendered.contains("already stored"), "{rendered}");
    assert!(
        rendered.contains("chain witness"),
        "the refusal must say what would have been lost: {rendered}"
    );

    let held = store.load("wrt_collide").expect("still there");
    assert_eq!(
        held.warrant.claims.subject, "spiffe://muveraai.com/agent/first",
        "the warrant that was already there must be untouched"
    );
}

/// Every class every time, including the ones this machine has never created. A listing that only
/// showed what happened to exist would answer "what do you keep" with "whatever I have used".
#[test]
fn every_class_is_reported_whether_or_not_it_exists_on_disk() {
    let dir = tempdir("all-classes");
    let store = WarrantStore::open(&dir).expect("open");

    let holdings = retention::holdings(&store, NOW).expect("holdings");
    assert_eq!(holdings.classes.len(), retention::ALL_CLASSES.len());

    // `run/` is declared by the daemon record and nothing in this build binds a socket there.
    let run = class(&holdings, ArtifactClass::Run);
    assert!(
        !run.present,
        "a location nothing ever created must not be reported as an empty one"
    );

    let text = retention::render_cli(&holdings);
    assert!(
        text.contains("this location has never been created on this machine"),
        "{text}"
    );
}

/// The absent-limit rule, still true in the state most machines are in: with no `retention.json`
/// there is no window, and every class says so rather than implying one. The prune job exists
/// now, but it refuses to act without a policy, so the statement stays honest until an operator
/// writes one — at which point the per-class lines change to the window and the never-lines
/// (covered in `tests/prune.rs`).
#[test]
fn no_retention_window_is_offered_until_a_policy_exists() {
    let dir = tempdir("no-window");
    let store = WarrantStore::open(&dir).expect("open");
    let text = retention::render_cli(&retention::holdings(&store, NOW).expect("holdings"));

    let stated = text.matches(RETENTION_STATEMENT).count();
    assert!(
        stated >= retention::ALL_CLASSES.len(),
        "every class must carry the statement, not just the header: found {stated}"
    );
}

/// The count must not be built by silently dropping what will not parse. `WarrantStore::list`
/// drops those deliberately, which is right for a listing and wrong for an inventory.
#[test]
fn a_warrant_that_will_not_parse_is_reported_as_unknown_not_dropped() {
    let dir = tempdir("unreadable");
    let store = WarrantStore::open(&dir).expect("open");
    save(
        &store,
        "wrt_ok",
        DEFAULT_CLI_SUBJECT,
        WarrantState::Open,
        None,
        true,
    );
    std::fs::write(dir.join("warrants").join("wrt_broken.json"), b"{not json")
        .expect("write a corrupt record");

    let holdings = retention::holdings(&store, NOW).expect("holdings");
    let warrants = class(&holdings, ArtifactClass::Warrants);
    assert_eq!(warrants.files, 1, "one warrant this store can answer for");
    assert_eq!(warrants.unreadable, 1, "and one it cannot read");

    let text = retention::render_cli(&holdings);
    assert!(
        text.contains("could not be read, and are NOT included in the count above"),
        "{text}"
    );
}

/// `settle` never removes a worktree — only `void` does — so settled worktrees accumulate in every
/// repository a warrant was granted against, and nothing reported them.
#[test]
fn worktrees_left_behind_by_settle_are_counted() {
    let dir = tempdir("worktrees");
    let store = WarrantStore::open(&dir).expect("open");
    let tree = dir.join("repo").join(".warrantor").join("wrt_settled");
    std::fs::create_dir_all(&tree).expect("worktree");

    save(
        &store,
        "wrt_settled",
        DEFAULT_CLI_SUBJECT,
        WarrantState::Settled,
        Some(&tree),
        true,
    );
    save(
        &store,
        "wrt_gone",
        DEFAULT_CLI_SUBJECT,
        WarrantState::Void,
        Some(&dir.join("repo").join(".warrantor").join("wrt_gone")),
        true,
    );

    let holdings = retention::holdings(&store, NOW).expect("holdings");
    assert_eq!(holdings.worktrees.on_disk, 1);
    assert_eq!(holdings.worktrees.settled, 1);
    assert_eq!(holdings.worktrees.missing, 1);
    assert!(retention::render_cli(&holdings).contains("`settle` does not"));
}

/// A per-person answer is only as good as the subject the grant recorded, and the default makes it
/// degenerate. Reporting the grouping and how much of it is the default is the truthful shape;
/// refusing to group at all would under-report a field the store really does hold.
#[test]
fn the_subject_breakdown_says_how_much_of_it_is_the_default() {
    let dir = tempdir("subjects");
    let store = WarrantStore::open(&dir).expect("open");
    save(
        &store,
        "wrt_a",
        DEFAULT_CLI_SUBJECT,
        WarrantState::Open,
        None,
        true,
    );
    save(
        &store,
        "wrt_b",
        DEFAULT_CLI_SUBJECT,
        WarrantState::Open,
        None,
        true,
    );
    save(
        &store,
        "wrt_c",
        "spiffe://example.test/person/vikram",
        WarrantState::Open,
        None,
        true,
    );

    let holdings = retention::holdings(&store, NOW).expect("holdings");
    assert_eq!(holdings.subjects.default_subjects, 2);
    let counts: BTreeMap<&str, usize> = holdings
        .subjects
        .by_subject
        .iter()
        .map(|(s, n)| (s.as_str(), *n))
        .collect();
    assert_eq!(counts.get("spiffe://example.test/person/vikram"), Some(&1));

    let text = retention::render_cli(&holdings);
    assert!(
        text.contains("not a per-person answer and must not be read as one"),
        "{text}"
    );
}

/// The limit the previous commit left behind, surfaced rather than buried: warrants granted before
/// the chain witness existed cannot prove their staged log is intact.
#[test]
fn warrants_with_no_chain_witness_are_counted_as_unprovable() {
    let dir = tempdir("unwitnessed");
    let store = WarrantStore::open(&dir).expect("open");
    save(
        &store,
        "wrt_old",
        DEFAULT_CLI_SUBJECT,
        WarrantState::Open,
        None,
        false,
    );
    save(
        &store,
        "wrt_new",
        DEFAULT_CLI_SUBJECT,
        WarrantState::Open,
        None,
        true,
    );

    let holdings = retention::holdings(&store, NOW).expect("holdings");
    assert_eq!(holdings.unwitnessed_chains, 1);
    assert!(retention::render_cli(&holdings).contains("carry no staged-chain witness"));
}

/// The three locations whose deletion changes an answer rather than losing one must be labelled as
/// such, because they are the ones an operator would otherwise prune first.
#[test]
fn the_classes_that_flip_a_verdict_are_labelled_as_flipping_a_verdict() {
    for which in [
        ArtifactClass::Stops,
        ArtifactClass::Spend,
        ArtifactClass::Daemons,
    ] {
        assert_eq!(
            which.deletion_effect(),
            DeletionEffect::FlipsAVerdict,
            "{} decides a verdict by existing",
            which.name()
        );
    }
    assert_eq!(
        ArtifactClass::Logs.deletion_effect(),
        DeletionEffect::NoIntegrityConsequence,
        "raw agent output is in no evidence bundle -- it is where a window belongs first"
    );
}

/// Doctrine, asserted rather than promised: this command reads. If it ever grows a prune, this test
/// is what makes that a deliberate change instead of a side effect.
#[test]
fn holdings_writes_nothing_and_deletes_nothing() {
    let dir = tempdir("read-only");
    let store = WarrantStore::open(&dir).expect("open");
    save(
        &store,
        "wrt_a",
        DEFAULT_CLI_SUBJECT,
        WarrantState::Open,
        None,
        true,
    );
    std::fs::create_dir_all(dir.join("logs")).expect("logs");
    std::fs::write(dir.join("logs").join("wrt_a.log"), b"output").expect("log");

    let before = walk(&dir);
    let holdings = retention::holdings(&store, NOW).expect("holdings");
    let _ = retention::render_cli(&holdings);
    let after = walk(&dir);

    assert_eq!(before, after, "holdings must not touch the store");
}

fn walk(root: &Path) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(meta) = std::fs::metadata(&path) {
                out.insert(path.display().to_string(), meta.len());
            }
        }
    }
    out
}

/// The inventory is only "enumerated from one place" if the one place covers the store. It is a
/// hand-maintained list, so the part that can be checked mechanically is checked: a directory this
/// store creates and no class names is a location the inventory would silently omit.
#[test]
fn every_directory_this_store_creates_is_a_known_class() {
    let dir = tempdir("classes-cover-the-store");
    let store = WarrantStore::open(&dir).expect("open store");
    // Written through the store's own API, so a new sidecar file lands wherever the store puts it.
    save(
        &store,
        "wrt_cover",
        DEFAULT_CLI_SUBJECT,
        WarrantState::Open,
        None,
        true,
    );
    let mut queue = store
        .open_queue("wrt_cover", EffectRegistry::github())
        .expect("open queue");
    queue
        .stage("github.create_pr", BTreeMap::new(), NOW)
        .expect("stage");
    store
        .witness_staged_chain("wrt_cover", &queue, NOW)
        .expect("witness");

    let known: BTreeSet<std::path::PathBuf> = retention::ALL_CLASSES
        .iter()
        .map(|class| class.path_under(&dir))
        .collect();
    for entry in std::fs::read_dir(&dir).expect("read root").flatten() {
        assert!(
            known.contains(&entry.path()),
            "{} is in the store and in no ArtifactClass, so `warrantor holdings` does not count it",
            entry.path().display()
        );
    }
}
