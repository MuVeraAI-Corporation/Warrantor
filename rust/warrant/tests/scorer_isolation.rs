//! Task 13.7 — what a scored agent can and cannot reach of the machinery that scores it.
//!
//! # What this file asserts, and the word it refuses to use
//!
//! A grader an agent can reach is a grader the agent will optimize. So the questions are: can the
//! scored process write the scorer's inputs, read the scorer's credentials, reach the scorer over
//! the network, or move the thing that becomes its own training label.
//!
//! Every test here asserts a property of a **derived confinement profile** or of a **local
//! registry**, never of a launched sandbox. There is no netns, no seccomp and no firewall anywhere
//! in this repository, and `src/sandbox.rs` says so about itself first: *"a profile that is never
//! launched confines nothing, and this process cannot tell whether the operator launched it."* A
//! test named `the_agent_cannot_write_the_scorer` would be a claim this repository cannot make.
//! Every name below says which of the two it is.
//!
//! # Boundary against the two neighbouring tasks
//!
//! Task 5.3 owns the evidence-integrity adversary: forging, suppressing, replaying and racing the
//! receipt chain. Nothing here attacks the receipt graph, and if the isolation record built here can
//! be forged, that is 5.3's finding to produce in `tests/invariants/adversary/`.
//!
//! Task 14.10 owns the evaluating *organization* and the conformance-receipt envelope. This task
//! stops at one process boundary on one machine and defines no receipt format;
//! `scorer::Escalation` is a plain record, deliberately, until 14.10 lands.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use warrantor_warrant::corpus::{self, LabelSource};
use warrantor_warrant::guard::{
    GuardKnobs, GuardLog, GuardMode, GuardOutcome, GuardProvenance, GuardSignal,
};
use warrantor_warrant::operators::{Operator, OperatorRegistry, Scope};
use warrantor_warrant::sandbox::{self, Confinement, Divergence, Profile};
use warrantor_warrant::scorer::{self, RegisteredThreshold, ScorerError};
use warrantor_warrant::{SideEffectClass, WarrantBounds};

const NOW: u64 = 1_786_000_000;

/// A POSIX worktree path. `sandbox::check_worktree` refuses a Windows path outright, so a fixture
/// that used one would fail for a reason that has nothing to do with this file.
const WORKTREE: &str = "/home/agent/repo/.warrantor/wrt_w1";

fn tempdir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-scorer-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn bounds(write: &[&str], egress: &[&str]) -> WarrantBounds {
    WarrantBounds {
        tools: ["github.create_pr"].into_iter().map(String::from).collect(),
        write_paths: write.iter().map(|s| (*s).to_string()).collect(),
        egress_hosts: egress.iter().map(|s| (*s).to_string()).collect(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: Some(500),
        delegation_depth: 1,
    }
}

fn no_egress_bounds() -> WarrantBounds {
    bounds(&["src/**"], &[])
}

/// Whether a profile opens a read-write hole covering `path`.
///
/// A pure function over `profile.argv`, and deliberately not a filesystem check: nothing here
/// launches a sandbox, so the only thing that can be inspected is the command that would be
/// launched. The three holes a profile can open are `--bind <src> <dst>` (bubblewrap),
/// `--read-write=<path>` (firejail) and the private `/tmp` both of them mount — and the third is
/// the one a derivation-only reading of `src/sandbox.rs` missed until somebody ran it.
fn writable_under(profile: &Profile, path: &Path) -> bool {
    let target = path.to_string_lossy().replace('\\', "/");
    let under = |hole: &str| target == hole || target.starts_with(&format!("{hole}/"));

    let mut arguments = profile.argv.iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            // `--bind <source> <destination>`: the destination is the path inside the sandbox.
            "--bind" => {
                let _source = arguments.next();
                if let Some(destination) = arguments.next() {
                    if under(destination) {
                        return true;
                    }
                }
            }
            "--tmpfs" => {
                if let Some(hole) = arguments.next() {
                    if under(hole) {
                        return true;
                    }
                }
            }
            other => {
                for prefix in ["--read-write=", "--whitelist="] {
                    if let Some(hole) = other.strip_prefix(prefix) {
                        if under(hole) {
                            return true;
                        }
                    }
                }
                if other == "--private-tmp" && under("/tmp") {
                    return true;
                }
            }
        }
    }
    false
}

// ── Step 2: the boundary statement is in the evidence file, not only in this comment ──────────

#[test]
fn the_evidence_file_names_the_two_tasks_this_one_does_not_cover() {
    // Rule 3 applied to a boundary: three statements of one idea drift into each other, so the
    // sentence a reader will actually find is gated rather than trusted. Task 5.3 owns the receipt
    // adversary and Task 14.10 owns the evaluating organization and the receipt envelope; a later
    // reader who cannot find those two numbers in the evidence file will re-derive the boundary
    // wrongly, and the likeliest wrong derivation is that this task covered them.
    let evidence = read_repository_file("docs/task-evidence/task-13.7.md");
    for (task, why) in [
        ("Task 5.3", "the evidence-integrity adversary"),
        ("Task 14.10", "the evaluating organization"),
    ] {
        assert!(
            evidence.contains(task),
            "docs/task-evidence/task-13.7.md must name {task} as the owner of {why}, so a reader \
             does not conclude this task covered it",
        );
    }
    assert!(
        evidence.contains("performs no isolation"),
        "the evidence file must state that eval-guard performs no isolation. The seed for this task \
         said the isolation 'may exist and be unreachable'; the crate's own module doc refutes both \
         halves, and a task that quietly builds on the seed's premise inherits it.",
    );
}

/// Read a repository file by a path relative to the repository root.
///
/// `tests/invariants/harness.rs` has this and is a module of the `invariants` binary, not a shared
/// crate, so it cannot be imported here. Duplicated rather than made public: exporting a test
/// harness from the library would put it in the shipped API surface.
fn read_repository_file(relative: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("rust/warrant has a grandparent")
        .to_path_buf();
    let path = root.join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

// ── Step 5: the scorer's inputs are outside every read-write hole ─────────────────────────────

#[test]
fn a_write_to_the_scorer_s_inputs_is_outside_every_read_write_hole_the_profile_opens() {
    // The scorer's inputs in this product are `~/.warrantor/guard/<id>.jsonl` and
    // `~/.warrantor/runs/<id>.jsonl` (src/store.rs), which live in $HOME and outside the agent's
    // worktree. Under this profile `/` is bound read-only with the worktree as the sole read-write
    // hole, so a write there fails with EROFS at the syscall — held by the operating system.
    //
    // What this test asserts is that the DERIVED PROFILE opens no hole over them. It does not
    // assert that a sandbox was launched, and it cannot: see the module doc.
    let store = tempdir("scorer-inputs");
    let profile = sandbox::profile(&no_egress_bounds(), WORKTREE, Confinement::Bubblewrap);

    // CONTROL: the worktree IS writable, or this test measures nothing at all — a profile that
    // opened no holes would satisfy the assertion below while breaking every agent.
    assert!(
        writable_under(&profile, Path::new(WORKTREE)),
        "control: the worktree must be inside a read-write hole; {}",
        profile.shell_line()
    );
    assert!(
        profile
            .shell_line()
            .contains(&format!("--bind {WORKTREE} {WORKTREE}")),
        "control: {}",
        profile.shell_line()
    );

    for input in ["guard", "runs", "refusals"] {
        let log = store.join(input).join("w1.jsonl");
        assert!(
            !writable_under(&profile, &log),
            "{} is inside a read-write hole this profile opens, so the profile does not hold this \
             property: {}",
            log.display(),
            profile.shell_line()
        );
    }
}

#[test]
fn a_store_the_operator_put_inside_the_worktree_is_writable_and_the_test_says_so() {
    // The other half of the same fact, and the reason `scorer::isolation` checks the store's
    // location rather than assuming it. The Enforced reading of this property needs TWO things
    // true at once: a confinement profile in force, and a store root that is not inside the
    // worktree. An operator who ran with `--root <worktree>/.store` has the second one false, and
    // the profile then binds the scorer's own inputs read-write.
    let profile = sandbox::profile(&no_egress_bounds(), WORKTREE, Confinement::Bubblewrap);
    let inside = Path::new(WORKTREE).join(".store").join("guard");
    assert!(
        writable_under(&profile, &inside),
        "a store under the worktree is inside the read-write hole, and a check that assumed \
         otherwise would report Enforced for a writable grader input: {}",
        profile.shell_line()
    );
}

// ── Step 6: it CAN read the scorer's credentials, and the profile must name that gap ──────────

#[test]
fn the_profile_leaves_the_settle_key_readable_and_must_name_that_gap() {
    // The finding, recorded rather than fixed. `--ro-bind / /` makes $HOME readable, and
    // `~/.warrantor/keys/settle.key` with it. Read-only is not unreadable. Nothing in this
    // repository refuses that read at any tier, and until this test existed `sandbox.rs` emitted a
    // Divergence for every WarrantBounds field and none at all for the store — so the surface whose
    // whole job is enumerating what a profile cannot hold was silent about the one credential a
    // grader must not leak.
    let profile = sandbox::profile(&no_egress_bounds(), WORKTREE, Confinement::Bubblewrap);

    // CONTROL: the profile does hold `write_paths`, so it is not simply an empty derivation whose
    // every property is a gap.
    assert!(
        profile.held().iter().any(|d| matches!(
            d,
            Divergence::Held { bound, .. } if bound == "write_paths"
        )),
        "control: {:?}",
        profile.divergences
    );

    // The mechanism that makes the read possible, read off the command rather than asserted.
    assert!(
        profile
            .argv
            .windows(3)
            .any(|w| w == ["--ro-bind", "/", "/"]),
        "{:?}",
        profile.argv
    );

    let Some(gap) = profile
        .divergences
        .iter()
        .find(|d| d.bound() == "scorer_credentials")
    else {
        panic!(
            "the profile enumerates a divergence per WarrantBounds field and none for the store, \
             so the one credential a grader must not leak is not named anywhere an operator reads: \
             {:?}",
            profile.divergences
        )
    };
    let Divergence::Gap { why, .. } = gap else {
        panic!(
            "scorer_credentials must be a Gap. Held would claim a confinement this profile does not \
             express, and Overreach would claim it denies something the warrant permits: {gap:?}"
        )
    };
    assert!(
        why.contains("read-only is not unreadable"),
        "the sentence has to name why a read-only root does not close this: {why}"
    );
    assert!(
        why.contains("keys/settle.key"),
        "the sentence has to name the file: {why}"
    );
    assert!(
        why.contains("nothing in this repository refuses that read"),
        "the sentence has to say that no tier holds it, rather than implying a weak one does: {why}"
    );
}

#[test]
fn naming_the_store_gap_does_not_move_a_single_bound_strength() {
    // `src/sandbox.rs`'s own rule, extended to the divergence this task adds: a bound does not
    // change tier because a file describing it exists. `scorer_credentials` is not a WarrantBounds
    // field and must not become one — `bound_strengths()` is the list of bounds a WARRANT carries,
    // and adding a non-bound to it would force every profile to speak about it as though a warrant
    // could grant it.
    let names: BTreeSet<&str> = warrantor_warrant::bound_strengths()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert!(
        !names.contains("scorer_credentials"),
        "scorer_credentials is a property of the store's location, not a bound a warrant grants: \
         {names:?}"
    );
    assert_eq!(
        names.len(),
        7,
        "bound_strengths() is the warrant's own bounds and this task adds none: {names:?}"
    );
}

// ── Step 6b: the network property, at the tier the code actually earns ────────────────────────

#[test]
fn a_no_egress_warrant_unshares_the_network_and_a_permitting_one_is_told_it_does_not() {
    // The one property that reaches Enforced without an operator's word for it, and only in one
    // case. `sandbox.rs:318` emits `--unshare-net` ONLY when the warrant grants no egress, because
    // a network namespace has no host allowlist. With any host granted the namespace is
    // deliberately absent and the property falls back to Mediated, held at the MCP proxy — which a
    // shell reaches past.
    let closed = sandbox::profile(&no_egress_bounds(), WORKTREE, Confinement::Bubblewrap);
    assert!(closed.argv.iter().any(|a| a == "--unshare-net"));

    // CONTROL, and the asymmetry: a warrant that permits a host gets no namespace, so the two
    // cases are genuinely different rather than the assertion above being vacuous.
    let open = sandbox::profile(
        &bounds(&["src/**"], &["api.github.com"]),
        WORKTREE,
        Confinement::Bubblewrap,
    );
    assert!(!open.argv.iter().any(|a| a == "--unshare-net"));
    assert_eq!(open.overreaches().len(), 1);
    assert_eq!(open.overreaches()[0].bound(), "egress_hosts");
}

// ── Step 7: the scored party cannot move the thing that becomes its label ─────────────────────

fn registry_with(entries: &[(&str, &[Scope])]) -> OperatorRegistry {
    let mut registry = OperatorRegistry::default();
    for (name, scopes) in entries {
        let mut set: BTreeSet<Scope> = scopes.iter().copied().collect();
        // `read` is implied by every other scope; `Scope::parse_list` inserts it and a
        // hand-built registry has to as well or it is not the shape the product writes.
        set.insert(Scope::Read);
        registry.operators.push(Operator {
            name: (*name).to_string(),
            scopes: set,
            token_digest: format!("digest-of-{name}"),
            added_at: NOW,
            note: "bound out of band, in this test".to_string(),
        });
    }
    registry
}

#[test]
fn a_principal_without_settle_scope_cannot_produce_the_state_that_becomes_a_label() {
    // The gameable surface is not the grader's code — it is the state transition. `corpus.rs:194`
    // derives a training label from `WarrantState`: Void -> Some(true), Settled -> Some(false). So
    // the party who can flip a label is the party who holds `Scope::Settle`, and separating that
    // from `Scope::Approve` is what keeps a reviewer from labelling its own run.
    let registry = registry_with(&[
        ("reviewer", &[Scope::Approve]),
        ("releaser", &[Scope::Settle]),
    ]);

    // CONTROL: the releaser can, or the refusal below proves nothing at all.
    assert!(
        registry
            .by_name("releaser")
            .expect("releaser")
            .allows(Scope::Settle),
        "control: some principal must hold Settle"
    );

    let reviewer = registry.by_name("reviewer").expect("reviewer");
    assert!(
        !reviewer.allows(Scope::Settle),
        "a reviewer holding Approve must not be able to settle, or approving and labelling are the \
         same authority"
    );
    // And the scope it does hold is real, so this is a separation rather than an empty entry.
    assert!(reviewer.allows(Scope::Approve));
}

#[test]
fn a_guard_verdict_never_becomes_a_label_even_when_it_is_the_only_evidence() {
    // This property already holds on main — `corpus.rs` was written to hold it, and its module doc
    // names the trap. It is pinned here because nothing outside the corpus module's own unit tests
    // asserted it, and a "helpful" refactor filling `label` from `guard_said` would train the next
    // guard on this guard's misses with no test going red. Recorded in the evidence file as
    // already-true rather than presented as new.
    let rows = corpus::rows_from(&log_with_one_harmful_signal(), &BTreeMap::new());
    assert_eq!(
        rows.len(),
        1,
        "control: the signal was exported, not dropped"
    );
    assert_eq!(rows[0].label, None);
    assert_eq!(rows[0].guard_said.as_deref(), Some("harmful"));
    assert_eq!(rows[0].label_source, LabelSource::Unlabelled);
    assert!(
        rows[0]
            .why_unlabelled
            .as_deref()
            .is_some_and(|why| !why.is_empty()),
        "an unlabelled row must say why, or it reads as a row nobody looked at"
    );
}

fn log_with_one_harmful_signal() -> GuardLog {
    GuardLog {
        signals: vec![GuardSignal {
            format: warrantor_warrant::guard::GUARD_SIGNAL_FORMAT.to_string(),
            warrant_id: "wrt_scored".to_string(),
            session_id: "s1".to_string(),
            at: NOW,
            tool: "files.write".to_string(),
            argument_names: vec!["text".to_string()],
            content_digest: format!("sha256:{}", "aa".repeat(32)),
            content_bytes: 128,
            truncated: false,
            outcome: GuardOutcome::Harmful,
            mode: GuardMode::Observe,
            severity: "high".to_string(),
            categories: vec!["s1".to_string()],
            gated_by_category: false,
            raw_excerpt: String::new(),
            count: 1,
            provenance: GuardProvenance {
                adapter: "test".to_string(),
                backend_kind: "ollama".to_string(),
                endpoint: "http://127.0.0.1:11434".to_string(),
                model: "m".to_string(),
                model_digest: format!("sha256:{}", "bb".repeat(32)),
                knobs: GuardKnobs::default(),
            },
        }],
        sessions: Vec::new(),
        summaries: Vec::new(),
        unreadable_lines: 0,
    }
}

// ── Step 10: the reward-hacking monitor, its ordering rule, and who it escalates to ───────────

/// Write `runs/<warrant>.jsonl` with one record per timestamp given.
fn record_runs(root: &Path, warrant: &str, at: &[u64]) {
    let directory = root.join("runs");
    std::fs::create_dir_all(&directory).expect("runs directory");
    let mut body = String::new();
    for (index, when) in at.iter().enumerate() {
        let record = serde_json::json!({
            "format": warrantor_warrant::runs::RUN_FORMAT,
            "warrant_id": warrant,
            "run_id": format!("run_{warrant}_{index}"),
            "at": when,
            "mode": "enforce",
            "guard": serde_json::Value::Null,
            "upstreams": 0,
            "note": warrantor_warrant::runs::RUN_NOTE,
        });
        body.push_str(&record.to_string());
        body.push('\n');
    }
    std::fs::write(directory.join(format!("{warrant}.jsonl")), body).expect("write runs");
}

/// Write `refusals/<warrant>.jsonl` with one record carrying `count` occurrences.
fn record_refusals(root: &Path, warrant: &str, at: u64, count: u32) {
    let directory = root.join("refusals");
    std::fs::create_dir_all(&directory).expect("refusals directory");
    let record = serde_json::json!({
        "format": warrantor_warrant::serve::REFUSAL_RECORD_FORMAT,
        "warrant_id": warrant,
        "at": at,
        "kind": "tool",
        "tool": "files.write",
        "bound": "write_paths",
        "destination": serde_json::Value::Null,
        "argument": serde_json::Value::Null,
        "reason": serde_json::Value::Null,
        "count": count,
    });
    std::fs::write(
        directory.join(format!("{warrant}.jsonl")),
        format!("{record}\n"),
    )
    .expect("write refusals");
}

fn threshold(rate: f64, registered_at: u64) -> RegisteredThreshold {
    RegisteredThreshold {
        format: scorer::THRESHOLD_FORMAT.to_string(),
        rate,
        registered_at,
        bom_digest: None,
    }
}

#[test]
fn an_escalation_is_addressed_to_an_operator_who_cannot_settle_the_warrant_being_graded() {
    // The whole mechanism is in the control. `corpus.rs` turns a settle or a void into a training
    // label, so the party holding Settle is the party whose decision BECOMES the label. An
    // escalation that silently fell back to them would be telling the labeller that its own label
    // is the suspect one, which is worse than telling nobody.
    let root = tempdir("escalate");
    record_runs(&root, "wrt_probing", &[NOW, NOW + 10]);
    record_refusals(&root, "wrt_probing", NOW + 20, 9);
    let trend = scorer::trend(&root, &threshold(0.2, NOW - 1));
    assert_eq!(trend.crossed.as_deref(), Some("wrt_probing"), "{trend:?}");

    // The releaser is registered FIRST and holds Stop as well as Settle, which is the realistic
    // dangerous shape: an operator with full authority. An implementation that looked only for
    // `allows(Stop)` would pick it, so this ordering is what gives the assertion teeth.
    let registry = registry_with(&[
        ("releaser", &[Scope::Settle, Scope::Stop]),
        ("env-owner", &[Scope::Stop]),
    ]);
    let escalation = scorer::escalate(&root, &trend, &registry, NOW + 30).expect("crossed");
    assert_eq!(escalation.to, "env-owner");
    assert_eq!(escalation.warrant_id, "wrt_probing");
    assert!(
        escalation.note.contains("does not establish"),
        "{}",
        escalation.note
    );
    assert!(
        escalation.note.contains("ADVISORY"),
        "the escalation is advisory and nothing here quarantines a checkpoint; the record has to \
         say so: {}",
        escalation.note
    );
    // It is durable, or the monitor's output is a print statement.
    assert_eq!(scorer::read_escalations(&root).len(), 1);

    // CONTROL: with only a settling operator registered, escalation REFUSES rather than falling
    // back to the party being graded.
    let only_settler = registry_with(&[("releaser", &[Scope::Settle, Scope::Stop])]);
    assert_eq!(
        scorer::escalate(&root, &trend, &only_settler, NOW + 30),
        Err(ScorerError::NoEnvironmentOwner),
    );
}

#[test]
fn a_trend_that_did_not_cross_produces_no_escalation() {
    // The other control: `escalate` must not manufacture a record. An escalation logged for a run
    // that did not cross trains its reader to ignore the next one.
    let root = tempdir("not-crossed");
    record_runs(&root, "wrt_quiet", &[NOW, NOW + 10]);
    record_refusals(&root, "wrt_quiet", NOW + 20, 0);
    let trend = scorer::trend(&root, &threshold(0.2, NOW - 1));
    assert_eq!(trend.crossed, None, "{trend:?}");
    let registry = registry_with(&[("env-owner", &[Scope::Stop])]);
    assert_eq!(
        scorer::escalate(&root, &trend, &registry, NOW + 30),
        Err(ScorerError::NotCrossed),
    );
    assert!(scorer::read_escalations(&root).is_empty());
}

#[test]
fn a_threshold_registered_after_the_first_run_is_refused() {
    // L11-12: "the threshold is registered before the run, never tuned after". Ordering is the only
    // thing that makes a threshold evidence rather than a rationalisation with a number on it.
    let root = tempdir("late-threshold");
    record_runs(&root, "wrt_probing", &[NOW]);
    record_refusals(&root, "wrt_probing", NOW + 20, 9);

    assert_eq!(
        scorer::trend_checked(&root, &threshold(0.2, NOW + 100)),
        Err(ScorerError::ThresholdRegisteredAfterTheRun {
            run_at: NOW,
            registered_at: NOW + 100,
        }),
    );

    // CONTROL: the same store and the same rate, registered BEFORE the run, is accepted — so the
    // refusal is about the ordering and not about the store or the number.
    let accepted =
        scorer::trend_checked(&root, &threshold(0.2, NOW - 1)).expect("registered first");
    assert_eq!(accepted.crossed.as_deref(), Some("wrt_probing"));
}

#[test]
fn a_registered_threshold_cannot_be_rewritten_once_the_runs_have_happened() {
    let root = tempdir("no-rewrite");
    let first = scorer::register_threshold(&root, 0.2, NOW, None).expect("first registration");
    assert!((first.rate - 0.2).abs() < f64::EPSILON);
    // CONTROL: it can be read back, so the store did take it.
    assert!(
        (read_rate(&root) - 0.2).abs() < f64::EPSILON,
        "control: the first registration is on disk"
    );
    // The bound: a second registration is refused rather than replacing the first.
    let again = scorer::register_threshold(&root, 0.9, NOW + 500, None);
    assert!(
        matches!(
            again,
            Err(ScorerError::ThresholdAlreadyRegistered { rate, .. })
                if (rate - 0.2).abs() < f64::EPSILON
        ),
        "{again:?}"
    );
    assert!(
        (read_rate(&root) - 0.2).abs() < f64::EPSILON,
        "the refusal must leave the original in place, not half-write the replacement"
    );
}

fn read_rate(root: &Path) -> f64 {
    scorer::read_threshold(root)
        .expect("readable")
        .expect("present")
        .rate
}

#[test]
fn an_unreadable_threshold_file_is_an_error_and_never_treated_as_absent() {
    // The same fail-closed rule `OperatorRegistry::load` follows: treating a corrupt file as absent
    // would silently drop the before-the-run ordering, which is the whole content of this number.
    let root = tempdir("corrupt-threshold");
    std::fs::create_dir_all(root.join("scorer")).expect("scorer directory");
    std::fs::write(scorer::threshold_path(&root), "{ not json").expect("write");
    assert!(matches!(
        scorer::read_threshold(&root),
        Err(ScorerError::Io(_))
    ));
    // CONTROL: a well-formed file at the same path reads back, so the error is about the content.
    std::fs::write(
        scorer::threshold_path(&root),
        serde_json::to_string(&threshold(0.4, NOW)).expect("serialise"),
    )
    .expect("write");
    assert!((read_rate(&root) - 0.4).abs() < f64::EPSILON);
}

#[test]
fn the_trend_is_ordered_by_the_runs_own_clock_and_names_the_first_crossing() {
    // "Population-level" here means across the warrants a store holds, ordered by when each one
    // started, so a rising rate is visible as a sequence rather than as a set.
    let root = tempdir("trend-order");
    record_runs(&root, "wrt_early", &[NOW, NOW + 1]);
    record_refusals(&root, "wrt_early", NOW + 5, 1);
    record_runs(&root, "wrt_late", &[NOW + 100]);
    record_refusals(&root, "wrt_late", NOW + 105, 8);

    let trend = scorer::trend(&root, &threshold(2.0, NOW - 1));
    let order: Vec<&str> = trend.per_run.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(order, vec!["wrt_early", "wrt_late"], "{trend:?}");
    // 1 refusal over 2 runs is 0.5, below the threshold; 8 over 1 is 8.0, above it.
    assert_eq!(trend.crossed.as_deref(), Some("wrt_late"));
    // CONTROL: at a threshold below both, the FIRST in time order is the one named — so `crossed`
    // is reading the order rather than picking the maximum.
    let low = scorer::trend(&root, &threshold(0.1, NOW - 1));
    assert_eq!(low.crossed.as_deref(), Some("wrt_early"));
}
