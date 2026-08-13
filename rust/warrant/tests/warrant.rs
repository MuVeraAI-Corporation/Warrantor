//! W1 tests.
//!
//! The tests that matter here are the ones about *authority*, because the warrant's entire value
//! rests on two claims: an agent cannot settle its own warrant, and a sub-warrant cannot hold
//! more than its parent. Everything else is bookkeeping.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use warrantor_warrant::{
    bound_strengths, BoundStrength, SideEffectClass, Warrant, WarrantBounds, WarrantError,
    WarrantState, CAPABILITY_TTL_SECONDS,
};

const NOW: u64 = 1_786_000_000;
const HOUR: u64 = 3600;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

fn bounds() -> WarrantBounds {
    WarrantBounds {
        tools: set(&["git", "cargo", "rg"]),
        write_paths: set(&["src/**", "tests/**"]),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 8 * HOUR,
        budget_cents_observed: Some(500),
        delegation_depth: 3,
    }
}

fn granted() -> (Warrant, SigningKey, SigningKey) {
    let issuer = key(1);
    let settle = key(2);
    let warrant = Warrant::grant(
        "wrt_test",
        "fix the auth token refresh bug",
        "spiffe://muveraai.com/agent/alpha",
        bounds(),
        NOW,
        &settle.verifying_key(),
        &issuer,
    )
    .expect("grant");
    (warrant, issuer, settle)
}

// ── the load-bearing security property ────────────────────────────────────────────────

/// If the acting agent can settle its own warrant, staging is decoration: an agent that wanted to
/// open a pull request would simply settle and open it.
#[test]
fn the_agent_cannot_settle_its_own_warrant() {
    let (warrant, _issuer, settle) = granted();
    let agent = key(9);

    assert_eq!(
        warrant.verify_settle(&agent.verifying_key()),
        Err(WarrantError::NotSettleAuthority),
        "an agent presenting its own key must be refused"
    );
    warrant
        .verify_settle(&settle.verifying_key())
        .expect("the real settle authority is accepted");
}

/// The settle authority is inside the SIGNED claims, so an agent cannot rewrite it and then
/// present its own key.
#[test]
fn rewriting_the_settle_authority_invalidates_the_warrant() {
    let (mut warrant, issuer, _settle) = granted();
    let agent = key(9);

    warrant.claims.settle_authority = hex::encode(agent.verifying_key().to_bytes());

    assert_eq!(
        warrant.verify(&issuer.verifying_key(), NOW),
        Err(WarrantError::SignatureInvalid),
        "the settle authority is signed; changing it must break the signature"
    );
}

/// The capability token an agent holds has no settle scope, and no field that could be set to
/// grant one.
#[test]
fn the_capability_token_is_act_scoped_only() {
    let (warrant, issuer, _settle) = granted();
    let token = warrant.issue_capability(NOW, &issuer);

    token
        .verify(&issuer.verifying_key(), NOW)
        .expect("a fresh token verifies");
    assert_eq!(token.warrant_id, "wrt_test");
    assert_eq!(token.subject, "spiffe://muveraai.com/agent/alpha");
    // Structurally: the type carries no scope field at all, so there is nothing to escalate.
    assert!(token.expires_at <= NOW + CAPABILITY_TTL_SECONDS);
}

/// Short TTL is the second layer: on a platform with no parent-death signal an agent can outlive
/// its supervisor, and this is the bound that still applies.
#[test]
fn capability_tokens_expire_quickly() {
    let (warrant, issuer, _settle) = granted();
    let token = warrant.issue_capability(NOW, &issuer);

    assert!(matches!(
        token.verify(&issuer.verifying_key(), NOW + CAPABILITY_TTL_SECONDS),
        Err(WarrantError::Expired { .. })
    ));
}

/// A capability token cannot outlive the warrant it acts under, even if the TTL would allow it.
#[test]
fn a_capability_token_never_outlives_its_warrant() {
    let (warrant, issuer, _settle) = granted();
    let almost_expired = warrant.claims.bounds.expires_at - 5;
    let token = warrant.issue_capability(almost_expired, &issuer);
    assert_eq!(token.expires_at, warrant.claims.bounds.expires_at);
}

// ── domain separation ─────────────────────────────────────────────────────────────────

/// Warrants and capability tokens are signed with the same key. Without domain separation a
/// token could be presented as a warrant or vice versa -- the exact confusion that let a
/// 60-second capability token verify as a 15-minute SVID in agent-identity.
#[test]
fn a_capability_signature_does_not_verify_as_a_warrant() {
    let (warrant, issuer, _settle) = granted();
    let token = warrant.issue_capability(NOW, &issuer);

    let mut forged = warrant.clone();
    forged.signature = token.signature.clone();

    assert_eq!(
        forged.verify(&issuer.verifying_key(), NOW),
        Err(WarrantError::SignatureInvalid)
    );
}

// ── sub-warrants: authority shrinks, never grows ──────────────────────────────────────

#[test]
fn a_sub_warrant_within_bounds_is_issued() {
    let (parent, issuer, _settle) = granted();
    let mut child = bounds();
    child.tools = set(&["cargo"]);
    child.write_paths = set(&["src/**"]);
    child.delegation_depth = 2;

    let sub = parent
        .delegate(
            "wrt_child",
            "run the tests",
            "spiffe://muveraai.com/agent/beta",
            child,
            NOW,
            &issuer,
        )
        .expect("a narrower child is legal");

    assert_eq!(sub.claims.parent.as_deref(), Some("wrt_test"));
    // A child answers to the same authority: otherwise it would be an escape hatch.
    assert_eq!(sub.claims.settle_authority, parent.claims.settle_authority);
}

#[test]
fn a_sub_warrant_cannot_claim_a_tool_the_parent_lacks() {
    let (parent, issuer, _settle) = granted();
    let mut child = bounds();
    child.tools = set(&["git", "curl"]); // curl is not in the parent
    child.delegation_depth = 2;

    let result = parent.delegate(
        "wrt_child",
        "g",
        "spiffe://muveraai.com/agent/beta",
        child,
        NOW,
        &issuer,
    );
    assert!(matches!(result, Err(WarrantError::AuthorityExpanded(_))));
}

#[test]
fn a_sub_warrant_cannot_outlive_its_parent() {
    let (parent, issuer, _settle) = granted();
    let mut child = bounds();
    child.expires_at = parent.claims.bounds.expires_at + HOUR;
    child.delegation_depth = 2;

    assert!(matches!(
        parent.delegate(
            "wrt_child",
            "g",
            "spiffe://muveraai.com/agent/beta",
            child,
            NOW,
            &issuer
        ),
        Err(WarrantError::AuthorityExpanded(_))
    ));
}

/// The subtle one. A child that stages FEWER classes performs immediately what its parent
/// deferred -- so a smaller set is an expansion of authority, not a reduction.
#[test]
fn a_sub_warrant_cannot_unstage_what_the_parent_stages() {
    let (parent, issuer, _settle) = granted();
    let mut child = bounds();
    child.staged_classes = BTreeSet::new(); // would perform writes immediately
    child.delegation_depth = 2;

    let result = parent.delegate(
        "wrt_child",
        "g",
        "spiffe://muveraai.com/agent/beta",
        child,
        NOW,
        &issuer,
    );
    assert!(
        matches!(result, Err(WarrantError::AuthorityExpanded(_))),
        "unstaging is an expansion of authority even though the set is smaller"
    );
}

/// Read this one with the reconciled meaning of `None` in mind: the child here is not *uncapped*,
/// it is capped at zero, which is the smaller number. The refusal stands anyway, because whether a
/// ceiling was *declared* does more work than its value — a warrant with no declared budget is
/// never `SpendLedger::exhausted`, so `warrantor start` can never refuse it on budget grounds. A
/// child that dropped its parent's ceiling would trade a start-gated budget for an ungated one.
/// Same shape as the staged_classes rule: the smaller thing can still be the larger authority.
#[test]
fn a_sub_warrant_cannot_be_uncapped_when_the_parent_is_capped() {
    let (parent, issuer, _settle) = granted();
    let mut child = bounds();
    child.budget_cents_observed = None;
    child.delegation_depth = 2;

    assert!(matches!(
        parent.delegate(
            "wrt_child",
            "g",
            "spiffe://muveraai.com/agent/beta",
            child,
            NOW,
            &issuer
        ),
        Err(WarrantError::AuthorityExpanded(_))
    ));
}

/// The reconciled reading, pinned at the delegation gate.
///
/// `budget_cents_observed: None` means a ceiling of ZERO to the spend ledger (`spend::cap_micros`)
/// and it now means the same thing here. Before this was reconciled, `None` on a *parent* read as
/// "no ceiling", so a warrant granted with no `--budget` at all could mint a sub-warrant carrying
/// an arbitrarily large one — the one `None` meaning zero to the ledger and unlimited to the gate.
/// A budget-less parent has no spend authority, so it has none to hand a child.
#[test]
fn a_budget_less_parent_can_delegate_a_ceiling_of_zero_and_nothing_more() {
    let issuer = key(1);
    let settle = key(2);
    let mut uncapped = bounds();
    uncapped.budget_cents_observed = None;
    let parent = Warrant::grant(
        "wrt_no_budget",
        "granted without --budget",
        "spiffe://muveraai.com/agent/alpha",
        uncapped,
        NOW,
        &settle.verifying_key(),
        &issuer,
    )
    .expect("a warrant may be granted without a budget");

    let delegate_with = |cents: Option<u64>| {
        let mut child = bounds();
        child.budget_cents_observed = cents;
        child.delegation_depth = 2;
        parent.delegate(
            "wrt_child",
            "g",
            "spiffe://muveraai.com/agent/beta",
            child,
            NOW,
            &issuer,
        )
    };

    assert!(
        matches!(
            delegate_with(Some(1_000_000)),
            Err(WarrantError::AuthorityExpanded(_))
        ),
        "an absent budget is a ceiling of zero, so there is no budget to delegate"
    );
    assert!(
        matches!(
            delegate_with(Some(1)),
            Err(WarrantError::AuthorityExpanded(_))
        ),
        "one cent is still more than zero; the boundary is exact, not approximate"
    );
    delegate_with(Some(0))
        .expect("a ceiling of zero is what the parent holds, so it may pass it on");
    delegate_with(None).expect("a child with no budget either is within a parent that has none");
}

#[test]
fn delegation_depth_must_strictly_decrease() {
    let (parent, issuer, _settle) = granted();
    let mut child = bounds();
    child.delegation_depth = 3; // equal to the parent's; would allow an infinite chain

    assert!(matches!(
        parent.delegate(
            "wrt_child",
            "g",
            "spiffe://muveraai.com/agent/beta",
            child,
            NOW,
            &issuer
        ),
        Err(WarrantError::AuthorityExpanded(_))
    ));
}

#[test]
fn a_settled_warrant_cannot_delegate() {
    let (mut parent, issuer, _settle) = granted();
    parent.transition(WarrantState::Settled).expect("settle");

    let mut child = bounds();
    child.delegation_depth = 2;
    assert!(matches!(
        parent.delegate(
            "wrt_child",
            "g",
            "spiffe://muveraai.com/agent/beta",
            child,
            NOW,
            &issuer
        ),
        Err(WarrantError::WrongState { .. })
    ));
}

// ── lifecycle ─────────────────────────────────────────────────────────────────────────

#[test]
fn a_warrant_opens_and_verifies() {
    let (warrant, issuer, _settle) = granted();
    assert_eq!(warrant.state, WarrantState::Open);
    warrant
        .verify(&issuer.verifying_key(), NOW)
        .expect("verify");
}

#[test]
fn an_expired_warrant_does_not_verify() {
    let (warrant, issuer, _settle) = granted();
    assert!(matches!(
        warrant.verify(&issuer.verifying_key(), NOW + 9 * HOUR),
        Err(WarrantError::Expired { .. })
    ));
}

/// Held is not terminal: the deadline passing is not misbehaviour, so the settle authority may
/// still release or discard what was staged.
#[test]
fn held_can_still_settle_or_void() {
    for terminal in [WarrantState::Settled, WarrantState::Void] {
        let (mut warrant, _issuer, _settle) = granted();
        warrant.transition(WarrantState::Held).expect("hold");
        warrant.transition(terminal).expect("held is not terminal");
        assert_eq!(warrant.state, terminal);
    }
}

#[test]
fn terminal_states_are_terminal() {
    for terminal in [WarrantState::Settled, WarrantState::Void] {
        let (mut warrant, _issuer, _settle) = granted();
        warrant.transition(terminal).expect("first transition");
        assert!(matches!(
            warrant.transition(WarrantState::Open),
            Err(WarrantError::WrongState { .. })
        ));
    }
}

#[test]
fn a_tampered_bound_invalidates_the_signature() {
    let (mut warrant, issuer, _settle) = granted();
    warrant.claims.bounds.tools.insert("curl".into());
    assert_eq!(
        warrant.verify(&issuer.verifying_key(), NOW),
        Err(WarrantError::SignatureInvalid)
    );
}

#[test]
fn a_warrant_with_no_tools_is_refused() {
    let issuer = key(1);
    let settle = key(2);
    let mut empty = bounds();
    empty.tools = BTreeSet::new();
    assert!(matches!(
        Warrant::grant("w", "g", "s", empty, NOW, &settle.verifying_key(), &issuer),
        Err(WarrantError::Invalid(_))
    ));
}

#[test]
fn a_warrant_without_a_deadline_is_refused() {
    let issuer = key(1);
    let settle = key(2);
    let mut forever = bounds();
    forever.expires_at = 0;
    assert!(matches!(
        Warrant::grant(
            "w",
            "g",
            "s",
            forever,
            NOW,
            &settle.verifying_key(),
            &issuer
        ),
        Err(WarrantError::Invalid(_))
    ));
}

// ── honesty about what is actually enforced ───────────────────────────────────────────

/// Budget is parsed from the agent's own usage reporting, so it can be defeated by an agent that
/// does not report. Presenting it as though it were as strong as the tool allowlist is how a
/// developer ends up trusting something that cannot hold.
///
/// # One assertion was removed from this test, deliberately
///
/// It used to also assert `write_paths == Enforced`. That line was pinning a false claim, not a
/// property: nothing in this codebase ever refused an out-of-bounds write, and a live run proved
/// it by writing outside its declared paths unchallenged. Changing a test to match new behaviour
/// is normally the worst thing you can do to a suite, so it is justified here in place rather than
/// in a commit message someone has to go looking for.
///
/// The property this test exists for -- budget is `Observed` -- is unchanged and still asserted.
/// `write_paths` is now covered explicitly by `write_paths_is_not_advertised_as_enforced`, and the
/// bounds that really are refused by `the_bounds_that_are_enforced_still_say_so`.
#[test]
fn budget_is_reported_as_observed_not_enforced() {
    let strengths: std::collections::HashMap<_, _> = bound_strengths().into_iter().collect();
    assert_eq!(strengths["tools"], BoundStrength::Enforced);
    assert_eq!(strengths["expires_at"], BoundStrength::Enforced);
    assert_eq!(
        strengths["budget_cents_observed"],
        BoundStrength::Observed,
        "budget cannot be enforced: model API calls do not pass through us"
    );
}

/// Deterministic encoding: the same claims must produce the same signature every time, or
/// verification is a coin flip.
#[test]
fn signing_is_deterministic() {
    let issuer = key(1);
    let settle = key(2);
    let a = Warrant::grant(
        "w",
        "g",
        "s",
        bounds(),
        NOW,
        &settle.verifying_key(),
        &issuer,
    )
    .unwrap();
    let b = Warrant::grant(
        "w",
        "g",
        "s",
        bounds(),
        NOW,
        &settle.verifying_key(),
        &issuer,
    )
    .unwrap();
    assert_eq!(a.signature, b.signature);
}

/// `write_paths` must not claim to be enforced, because nothing enforces it.
///
/// Caught empirically in the first live dogfood: an agent granted `--write 'src/**'` ran its test
/// suite and wrote `tests/__pycache__/`. Nothing refused it and nothing noticed. The only consumers
/// of `write_paths` are the grant parser, the delegation subset test, and `commit_all` at settle;
/// `proxy.rs`, where bounds are actually refused at the moment of action, has no path logic at all.
///
/// The label matters more than it looks: `Enforced` is signed into every exported bundle under a
/// sentence saying the system refuses to exceed these bounds. A guarantee someone relies on and
/// that does not hold is worse than no guarantee.
#[test]
fn write_paths_is_not_advertised_as_enforced() {
    let strengths: std::collections::BTreeMap<_, _> = bound_strengths().into_iter().collect();
    assert_eq!(
        strengths.get("write_paths"),
        Some(&BoundStrength::Observed),
        "nothing refuses an out-of-bounds write, so the bundle must not sign a claim that it does"
    );
}

/// The bounds that genuinely are refused keep saying so. This is the other half of the same
/// property: honesty means not overclaiming, and also not quietly giving up a real guarantee.
#[test]
fn the_bounds_that_are_enforced_still_say_so() {
    let strengths: std::collections::BTreeMap<_, _> = bound_strengths().into_iter().collect();
    for name in [
        "tools",
        "egress_hosts",
        "staged_classes",
        "expires_at",
        "delegation_depth",
    ] {
        assert_eq!(
            strengths.get(name),
            Some(&BoundStrength::Enforced),
            "{name} is refused at the moment of action and must keep saying so"
        );
    }
}
