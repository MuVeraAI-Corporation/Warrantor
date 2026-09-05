//! Tier disclosure: every surface that renders a bound renders its tier, and no surface prints
//! "enforced" for a bound `bound_strengths()` calls Observed. L8-13.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use serde_json::Value;
use warrantor_warrant::report::{build, render_cli, render_mcp};
use warrantor_warrant::serve::{no_adapter, route, status, HttpRequest, StoreApi};
use warrantor_warrant::staging::{EffectRegistry, StagingQueue};
use warrantor_warrant::store::{StoredWarrant, WarrantStore};
use warrantor_warrant::{
    bound_strengths, render_bound, render_bounds_table, render_tier_legend, BoundStrength,
    SideEffectClass, Warrant, WarrantBounds,
};

const NOW: u64 = 1_786_000_000;
fn now() -> u64 {
    NOW
}
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TIERS: [BoundStrength; 3] = [
    BoundStrength::Enforced,
    BoundStrength::Mediated,
    BoundStrength::Observed,
];

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-tier-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn issuer() -> SigningKey {
    SigningKey::from_bytes(&[1; 32])
}

fn stored(id: &str, expires_at: u64) -> StoredWarrant {
    let bounds = WarrantBounds {
        tools: ["git".to_string()].into_iter().collect(),
        write_paths: ["src/**".to_string()].into_iter().collect(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at,
        budget_cents_observed: Some(500),
        delegation_depth: 1,
    };
    let warrant = Warrant::grant(
        id,
        "fix the auth bug",
        "spiffe://muveraai.com/agent/a",
        bounds,
        NOW,
        &SigningKey::from_bytes(&[2; 32]).verifying_key(),
        &issuer(),
    )
    .expect("grant");
    StoredWarrant {
        warrant,
        worktree: None,
        repo: None,
        branch: None,
        base_commit: None,
        staged_chain: None,
    }
}

/// The word a surface prints is the word the wire carries. One vocabulary, checked by machine.
#[test]
fn the_tier_word_is_the_serde_name_for_every_variant() {
    for tier in TIERS {
        let wire = serde_json::to_value(tier).expect("serialize");
        assert_eq!(wire, Value::String(tier.word().to_string()), "{tier:?}");
    }
    assert_eq!(BoundStrength::Observed.word(), "observed");
    assert_eq!(BoundStrength::Mediated.word(), "mediated");
    assert_eq!(BoundStrength::Enforced.word(), "enforced");
}

/// The caveat is the half of L8-13 nothing rendered before: what the tier does NOT cover.
#[test]
fn every_tier_states_what_it_does_not_cover_and_the_weaker_two_never_say_enforced() {
    for tier in TIERS {
        assert!(tier.caveat().len() > 20, "{tier:?} has no caveat");
    }
    assert!(BoundStrength::Mediated.caveat().contains("traverse"));
    assert!(BoundStrength::Observed.caveat().contains("nothing refuses"));
    for tier in [BoundStrength::Mediated, BoundStrength::Observed] {
        assert!(
            !tier.caveat().contains("enforced"),
            "{tier:?} must not describe itself with the strongest word"
        );
    }
}

/// `render_bound` is the one formatter. Its output is what the CLI golden has always pinned:
/// the name padded to 24 columns, then the word.
#[test]
fn render_bound_pads_the_name_and_prints_exactly_the_tier_word() {
    assert_eq!(
        render_bound("write_paths", BoundStrength::Observed),
        "write_paths             observed"
    );
    assert_eq!(
        render_bound("expires_at", BoundStrength::Enforced),
        "expires_at              enforced"
    );
    for (name, strength) in bound_strengths() {
        let line = render_bound(name, strength);
        assert!(line.ends_with(strength.word()), "{line}");
        if strength != BoundStrength::Enforced {
            assert!(!line.contains("enforced"), "{line}");
        }
    }
}

/// The legend renders all three tiers, in strength order, each with its caveat.
#[test]
fn the_legend_names_all_three_tiers_and_never_collapses_them() {
    let legend = render_tier_legend();
    assert_eq!(legend.len(), 3);
    for (line, tier) in legend.iter().zip(TIERS) {
        assert!(line.starts_with(tier.word()), "{line}");
        assert!(line.contains(tier.caveat()), "{line}");
    }
    let distinct: BTreeSet<&String> = legend.iter().collect();
    assert_eq!(distinct.len(), 3, "three tiers, three different lines");
}

fn built_bundle(dir: &std::path::Path) -> warrantor_warrant::report::Report {
    let queue = StagingQueue::open(dir.join("q.jsonl"), "wrt_tier", EffectRegistry::github())
        .expect("open queue");
    build(&stored("wrt_tier", NOW + 3600), Ok(&queue), &issuer().verifying_key(), NOW)
}

/// The bundle a signed report carries discloses a tier per bound, and the CLI prints each one
/// through the shared formatter plus the legend.
#[test]
fn the_cli_report_prints_every_bound_with_its_tier_and_the_legend() {
    let dir = tempdir("cli");
    let report = built_bundle(&dir);
    let text = render_cli(report.bundle());
    for bound in &report.bundle().bound_strengths {
        let line = format!("  {}", render_bound(&bound.name, bound.strength));
        assert!(text.contains(&line), "missing {line:?} in:\n{text}");
    }
    for legend in render_tier_legend() {
        assert!(text.contains(&legend), "legend line missing: {legend}");
    }
    let observed_lines: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("write_paths") || l.contains("budget_cents_observed"))
        .collect();
    assert_eq!(observed_lines.len(), 2, "{text}");
    for line in observed_lines {
        assert!(!line.contains("enforced"), "an Observed bound printed as enforced: {line}");
    }
}

/// `render_mcp` rendered no bounds at all, so the report an AGENT reads through the control
/// endpoint disclosed no tier. Same bundle, same formatter, same legend.
#[test]
fn the_mcp_report_discloses_a_tier_per_bound_from_the_same_bundle() {
    let dir = tempdir("mcp");
    let report = built_bundle(&dir);
    let text = render_mcp(report.bundle());
    assert!(text.contains("  bounds (tier per bound):"), "{text}");
    for bound in &report.bundle().bound_strengths {
        let line = format!("    {}", render_bound(&bound.name, bound.strength));
        assert!(text.contains(&line), "missing {line:?} in:\n{text}");
    }
    for legend in render_tier_legend() {
        assert!(text.contains(&legend), "{text}");
    }
    assert!(text.starts_with("Warrant wrt_tier — Open\n  goal: fix the auth bug"));
}

fn api(dir: &std::path::Path) -> StoreApi {
    let store = WarrantStore::open(dir).expect("store");
    StoreApi::new(
        store,
        dir.to_path_buf(),
        issuer(),
        None,
        no_adapter,
        now,
    )
}

/// `GET /v1/warrants/{id}` carries, per bound, the tier word `bound_strengths()` assigns and the
/// caveat for that tier, plus the legend. A client never has to infer a tier from a boolean.
#[test]
fn the_console_json_carries_the_tier_word_and_caveat_per_bound() {
    let dir = tempdir("json");
    WarrantStore::open(&dir)
        .expect("store")
        .save(&stored("wrt_json", NOW + 3600))
        .expect("save");
    let mut api = api(&dir);
    let request = HttpRequest::new("GET", &["v1", "warrants", "wrt_json"], BTreeMap::new())
        .with_bearer(TOKEN);
    let response = route(&mut api, &request);
    assert_eq!(response.status, status::OK);

    let expected: BTreeMap<&str, BoundStrength> = bound_strengths().into_iter().collect();
    let listed = response.body["data"]["bound_strengths"]
        .as_array()
        .expect("bound_strengths is an array");
    assert_eq!(listed.len(), expected.len());
    for entry in listed {
        let name = entry["name"].as_str().expect("name");
        let tier = expected[name];
        assert_eq!(entry["strength"], Value::String(tier.word().to_string()), "{name}");
        assert_eq!(entry["caveat"], Value::String(tier.caveat().to_string()), "{name}");
        if tier == BoundStrength::Observed {
            assert_ne!(entry["strength"], "enforced", "{name}");
        }
    }
    let legend = response.body["data"]["tier_legend"]
        .as_array()
        .expect("tier_legend");
    assert_eq!(legend.len(), 3);
}

/// `warrantor status` is the surface an operator reads every morning, and it printed no tier.
/// Driven through the real binary, because the omission lived in `cmd_status`, not the library.
#[test]
fn warrantor_status_prints_a_tier_per_bound_and_the_legend() {
    let root = tempdir("status");
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // An Open warrant with no daemon record is reported under "attention" (daemon.rs reconcile,
    // `None` arm); what matters here is only that the store is non-empty so the block prints.
    WarrantStore::open(&root)
        .expect("store")
        .save(&stored("wrt_status", at + 3_600))
        .expect("save");

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_warrantor"))
        .args(["status", "--root"])
        .arg(&root)
        .output()
        .expect("run warrantor status");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("bound tiers"), "{stdout}");
    for (name, strength) in bound_strengths() {
        assert!(stdout.contains(&render_bound(name, strength)), "{name} missing:\n{stdout}");
    }
    for legend in render_tier_legend() {
        assert!(stdout.contains(&legend), "{stdout}");
    }
    for line in stdout.lines().filter(|l| l.contains("write_paths")) {
        assert!(!line.contains("enforced"), "{line}");
    }
}
