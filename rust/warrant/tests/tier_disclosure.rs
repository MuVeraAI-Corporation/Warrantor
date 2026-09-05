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
