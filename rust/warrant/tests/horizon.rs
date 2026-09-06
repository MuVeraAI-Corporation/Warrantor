//! The horizon governor's refusals, each paired with a control that is allowed.
//!
//! L3-04 asks for "wall-clock and step-count ceilings with automatic escalation to a human as the
//! horizon extends". The wall-clock half already existed as `expires_at`; the count half existed
//! nowhere, and neither did the escalation. These tests are about the halves that did not exist,
//! plus the composition rule that keeps the half that did from being weakened.
//!
//! Every refusal here is paired with an allowed control, because a governor that refuses everything
//! passes a one-sided test and proves nothing.

use std::collections::BTreeSet;
use std::path::Path;

use warrantor_warrant::horizon::{self, HorizonDimension, HorizonUsage, HorizonVerdict};
use warrantor_warrant::proxy::{Decision, Proxy, ProxyMode, ToolCall};
use warrantor_warrant::staging::EffectRegistry;
use warrantor_warrant::{Horizon, SideEffectClass, WarrantBounds};

const ISSUED_AT: u64 = 1_700_000_000;

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|item| (*item).to_string()).collect()
}

/// Bounds with no horizon at all — the state every warrant granted before this field existed is in.
fn bounds_without_horizon() -> WarrantBounds {
    WarrantBounds {
        tools: set(&["git.commit", "git.status"]),
        write_paths: set(&["src/**"]),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Financial].into_iter().collect(),
        expires_at: ISSUED_AT + 86_400,
        budget_cents_observed: Some(100),
        delegation_depth: 2,
        horizon: None,
    }
}

fn usage(elapsed_seconds: u64, effects: u64, unattended_seconds: u64) -> HorizonUsage {
    HorizonUsage {
        elapsed_seconds,
        effects,
        unattended_seconds,
    }
}

fn call(tool: &str) -> ToolCall {
    ToolCall {
        tool: tool.to_string(),
        arguments: std::collections::BTreeMap::new(),
        side_effect: SideEffectClass::Read,
    }
}

// ── an absent horizon is not a satisfied one ─────────────────────────────────────────────

/// An absent horizon is not a bounded one. The report and `warrantor horizon` must say the
/// warrant's only ceiling is its deadline, because that is the true statement about every warrant
/// granted before this field existed. Reading `None` as "within its horizon" would render the
/// unbounded case as a pass.
#[test]
fn an_absent_horizon_is_reported_as_not_declared_and_never_as_within() {
    let bounds = bounds_without_horizon();
    assert!(bounds.horizon.is_none());

    let section = warrantor_warrant::report::horizon_section(&bounds, &usage(10_000, 900, 10_000));
    assert!(
        !section.declared,
        "an absent horizon must not report as declared"
    );
    assert_eq!(section.verdict_word, "not-declared");
    assert!(
        section.dimensions.is_empty(),
        "no dimension may be rendered with a limit nobody granted"
    );
    assert_ne!(
        section.verdict_word, "within",
        "an unbounded warrant must never render as a pass"
    );
    assert!(
        section.breached.is_none(),
        "nothing can be breached when nothing was declared"
    );
}

/// The reverse control: a declared horizon well inside its ceilings reports `within`, so the
/// assertion above measures the absence and not a function that always says `not-declared`.
#[test]
fn a_declared_horizon_inside_its_ceilings_reports_within() {
    let mut bounds = bounds_without_horizon();
    bounds.horizon = Some(Horizon {
        max_wall_seconds: Some(3_600),
        max_effects: Some(50),
        max_unattended_seconds: Some(1_800),
        escalate_at_percent: Some(80),
    });
    let section = warrantor_warrant::report::horizon_section(&bounds, &usage(60, 3, 30));
    assert!(section.declared);
    assert_eq!(section.verdict_word, "within");
    assert_eq!(
        section.dimensions.len(),
        3,
        "three dimensions were declared"
    );
    assert!(section.breached.is_none());

    let verdict = horizon::evaluate(
        bounds.horizon.as_ref().expect("declared"),
        &usage(60, 3, 30),
    );
    assert!(
        matches!(verdict, HorizonVerdict::Within { .. }),
        "got {verdict:?}"
    );
}

// ── the effect ceiling: the dimension that existed nowhere ───────────────────────────────

/// The step-count ceiling L3-04 names and `WarrantBounds` did not have. Refused at
/// `Proxy::decide`, which is the only place in this crate that refuses a call as it arrives.
///
/// The boundary is `admitted < limit`: a ceiling of two admits exactly two effects and refuses the
/// third. The control proves the second is admitted, so the boundary is not off by one.
#[test]
fn the_effect_ceiling_refuses_the_call_that_would_exceed_it() {
    let mut bounds = bounds_without_horizon();
    bounds.horizon = Some(Horizon {
        max_effects: Some(2),
        ..Horizon::none()
    });

    // CONTROL: two effects are within a ceiling of two, and both are admitted. Without this the
    // refusal below would prove only that the proxy refuses.
    let mut proxy = Proxy::new(bounds, ProxyMode::Enforce, EffectRegistry::github());
    let first = proxy.decide(&call("git.commit"));
    let second = proxy.decide(&call("git.commit"));
    assert!(
        !matches!(first, Decision::Deny { .. }) && !matches!(second, Decision::Deny { .. }),
        "the CONTROL was refused, so the attack never reached the boundary: {first:?} {second:?}"
    );
    assert_eq!(proxy.horizon_effects(), 2, "both admissions were counted");

    // ATTACK: the third effect crosses the ceiling and must be refused by name.
    match proxy.decide(&call("git.commit")) {
        Decision::Deny { bound, reason } => {
            assert_eq!(bound, "horizon_effects");
            assert!(
                reason.contains('2') && reason.contains("horizon"),
                "a refusal the agent cannot act on is a crash with better manners: {reason}"
            );
        }
        other => panic!("the third effect was not refused: {other:?}"),
    }
    assert_eq!(
        proxy.horizon_effects(),
        2,
        "a refused call produced no effect and must not consume the ceiling"
    );
}

/// A refused call must not burn the ceiling, and the control is that an *admitted* call does.
/// Without this a warrant could be exhausted by calls it was never allowed to make, which turns an
/// effect ceiling into a rate limit on attempts — Task 8.3's business, not this one's.
#[test]
fn a_call_refused_for_another_reason_does_not_consume_the_effect_ceiling() {
    let mut bounds = bounds_without_horizon();
    bounds.horizon = Some(Horizon {
        max_effects: Some(5),
        ..Horizon::none()
    });
    let mut proxy = Proxy::new(bounds, ProxyMode::Enforce, EffectRegistry::github());

    // ATTACK: a tool outside the allowlist, refused on `tools`, ten times over.
    for _ in 0..10 {
        let decision = proxy.decide(&call("curl.fetch"));
        assert!(matches!(decision, Decision::Deny { bound: "tools", .. }));
    }
    assert_eq!(
        proxy.horizon_effects(),
        0,
        "ten refusals consumed horizon budget, so the ceiling counts attempts and not effects"
    );

    // CONTROL: an allowed call does consume it, so the assertion above is not satisfied by a
    // counter that never moves.
    let allowed = proxy.decide(&call("git.commit"));
    assert!(!matches!(allowed, Decision::Deny { .. }), "{allowed:?}");
    assert_eq!(proxy.horizon_effects(), 1);
}

/// An undeclared effect ceiling refuses nothing. Stated as a test because the crate-wide
/// "absent means none" convention pulls the other way, and this is the one field where it must
/// not apply: the ceiling is a tightening of an already-granted deadline, so absent means the
/// deadline is the only limit — the state `main` was in before this task.
#[test]
fn an_undeclared_effect_ceiling_refuses_nothing() {
    let mut proxy = Proxy::new(
        bounds_without_horizon(),
        ProxyMode::Enforce,
        EffectRegistry::github(),
    );
    for _ in 0..50 {
        let decision = proxy.decide(&call("git.commit"));
        assert!(
            !matches!(decision, Decision::Deny { .. }),
            "an absent horizon refused a call: {decision:?}"
        );
    }
    assert_eq!(proxy.horizon_effects(), 50);
}

/// Seeding is what makes the ceiling mean anything across sessions: the effects a warrant already
/// staged are counted before the new session's first call, because the staging queue persists and
/// a per-session counter starting at zero would hand every restart a fresh allowance.
#[test]
fn a_seeded_count_refuses_the_first_call_of_a_resumed_session() {
    let mut bounds = bounds_without_horizon();
    bounds.horizon = Some(Horizon {
        max_effects: Some(3),
        ..Horizon::none()
    });

    // CONTROL: seeded to two of three, one call is still admitted.
    let mut control = Proxy::new(bounds.clone(), ProxyMode::Enforce, EffectRegistry::github());
    control.seed_horizon_effects(2);
    let decision = control.decide(&call("git.commit"));
    assert!(!matches!(decision, Decision::Deny { .. }), "{decision:?}");

    // ATTACK: seeded to the ceiling, the resumed session's first call is refused.
    let mut attacked = Proxy::new(bounds, ProxyMode::Enforce, EffectRegistry::github());
    attacked.seed_horizon_effects(3);
    match attacked.decide(&call("git.commit")) {
        Decision::Deny { bound, .. } => assert_eq!(bound, "horizon_effects"),
        other => panic!("a resumed session got a fresh allowance: {other:?}"),
    }
}

// ── the wall-clock dimension composes with the deadline, and can only tighten ────────────

/// The horizon supplies a SMALLER number to the deadline the supervisor already enforces. It can
/// never supply a larger one: a horizon that extended a deadline would be an authority expansion
/// wearing a governor's name.
#[test]
fn the_wall_horizon_can_only_tighten_the_deadline_never_extend_it() {
    let mut tight = bounds_without_horizon();
    tight.horizon = Some(Horizon {
        max_wall_seconds: Some(600),
        ..Horizon::none()
    });
    assert_eq!(
        horizon::effective_deadline(&tight, ISSUED_AT),
        ISSUED_AT + 600,
        "a tighter horizon must move the effective deadline in"
    );

    // ATTACK: a horizon far beyond the deadline. The deadline wins.
    let mut loose = bounds_without_horizon();
    loose.horizon = Some(Horizon {
        max_wall_seconds: Some(10_000_000),
        ..Horizon::none()
    });
    assert_eq!(
        horizon::effective_deadline(&loose, ISSUED_AT),
        ISSUED_AT + 86_400,
        "a horizon extended the deadline, which is an authority expansion"
    );

    // CONTROL: no horizon leaves the deadline exactly where it was.
    assert_eq!(
        horizon::effective_deadline(&bounds_without_horizon(), ISSUED_AT),
        ISSUED_AT + 86_400
    );
}

// ── the unattended clock reads NAMED acts only ───────────────────────────────────────────

/// The unattended clock reads the actor log, and only entries with a NAMED operator count.
/// `operators::ActorRecord::actor` documents `None` as the unscoped session token, so counting it
/// would let an agent's own session pass for human contact.
#[test]
fn a_named_operator_act_resets_the_unattended_clock() {
    use warrantor_warrant::operators::{record, Act};
    let root = tempdir("unattended");
    let warrant_id = "wrt_unattended";

    // ATTACK: nothing but anonymous acts, for longer than any plausible ceiling.
    record(&root, warrant_id, Act::Stop, None, "session-token", 1_100).expect("record");
    let breached = horizon::usage_at(&root, warrant_id, ISSUED_AT, None, 0, ISSUED_AT + 4_000);
    assert_eq!(
        breached.unattended_seconds, 4_000,
        "an anonymous act is not human contact"
    );

    // CONTROL: one act by a named operator, and the clock restarts from it.
    record(
        &root,
        warrant_id,
        Act::Approve,
        Some("ana"),
        "operator-token",
        ISSUED_AT + 4_000,
    )
    .expect("record");
    let reset = horizon::usage_at(&root, warrant_id, ISSUED_AT, None, 0, ISSUED_AT + 4_600);
    assert_eq!(
        reset.unattended_seconds, 600,
        "a named act must reset the clock, or the bound refuses every long run regardless of \
         whether anyone was watching"
    );
}

/// A named act in the FUTURE of the clock, or before the warrant was issued, must not produce a
/// nonsense elapsed figure. Saturating arithmetic, asserted rather than assumed.
#[test]
fn an_act_outside_the_runs_window_does_not_produce_a_nonsense_clock() {
    use warrantor_warrant::operators::{record, Act};
    let root = tempdir("window");
    let warrant_id = "wrt_window";
    record(
        &root,
        warrant_id,
        Act::Approve,
        Some("ana"),
        "operator-token",
        ISSUED_AT - 5_000,
    )
    .expect("record");
    // An act BEFORE the warrant existed cannot shorten the unattended clock below the run's own
    // age: the run started at issue, so the clock runs from issue.
    let usage = horizon::usage_at(&root, warrant_id, ISSUED_AT, None, 0, ISSUED_AT + 100);
    assert_eq!(usage.unattended_seconds, 100);

    // CONTROL: an act inside the window does shorten it.
    record(
        &root,
        warrant_id,
        Act::Approve,
        Some("ana"),
        "operator-token",
        ISSUED_AT + 60,
    )
    .expect("record");
    let usage = horizon::usage_at(&root, warrant_id, ISSUED_AT, None, 0, ISSUED_AT + 100);
    assert_eq!(usage.unattended_seconds, 40);
}

// ── evaluate: breach, escalate, within ───────────────────────────────────────────────────

/// Reaching a ceiling is the terminal event, for every dimension. `expires_at` behaves this way
/// already — arriving at the deadline stops the run — and a horizon that reported `within` at
/// exactly its ceiling would let the granted amount be spent and the run continue.
#[test]
fn reaching_any_ceiling_is_a_breach_that_names_its_dimension() {
    let horizon_all = Horizon {
        max_wall_seconds: Some(100),
        max_effects: Some(10),
        max_unattended_seconds: Some(50),
        escalate_at_percent: None,
    };
    for (usage, expected) in [
        (usage(100, 0, 0), HorizonDimension::Wall),
        (usage(0, 10, 0), HorizonDimension::Effects),
        (usage(0, 0, 50), HorizonDimension::Unattended),
    ] {
        match horizon::evaluate(&horizon_all, &usage) {
            HorizonVerdict::Breached { dimension, .. } => assert_eq!(dimension, expected),
            other => panic!("{usage:?} did not breach: {other:?}"),
        }
    }

    // CONTROL: one below every ceiling is not a breach, so the assertions above are not satisfied
    // by a function that always breaches.
    let control = horizon::evaluate(&horizon_all, &usage(99, 9, 49));
    assert!(
        !matches!(control, HorizonVerdict::Breached { .. }),
        "{control:?}"
    );
}

/// The escalation half of L3-04: crossing the escalation percentage is a distinct verdict from
/// both `Within` and `Breached`, because the whole point is that a human is asked BEFORE the
/// horizon ends rather than told after.
#[test]
fn crossing_the_escalation_percentage_escalates_without_breaching() {
    let declared = Horizon {
        max_wall_seconds: Some(1_000),
        max_effects: None,
        max_unattended_seconds: None,
        escalate_at_percent: Some(80),
    };

    // ATTACK: 800 of 1000 seconds is 80%.
    match horizon::evaluate(&declared, &usage(800, 0, 0)) {
        HorizonVerdict::Escalate {
            dimension,
            at_percent,
            limit,
            observed,
        } => {
            assert_eq!(dimension, HorizonDimension::Wall);
            assert_eq!(at_percent, 80);
            assert_eq!(limit, 1_000);
            assert_eq!(observed, 800);
        }
        other => panic!("80% of the wall horizon did not escalate: {other:?}"),
    }

    // CONTROL: 799 is below the threshold and stays `Within`, with the nearest dimension named.
    match horizon::evaluate(&declared, &usage(799, 0, 0)) {
        HorizonVerdict::Within { nearest } => {
            assert_eq!(nearest, Some((HorizonDimension::Wall, 79)));
        }
        other => panic!("799 of 1000 should be within: {other:?}"),
    }

    // And an undeclared escalation percentage escalates nothing, however close the horizon is.
    let no_escalation = Horizon {
        escalate_at_percent: None,
        ..declared
    };
    assert!(matches!(
        horizon::evaluate(&no_escalation, &usage(999, 0, 0)),
        HorizonVerdict::Within { .. }
    ));
}

/// A breach outranks an escalation. A warrant that is over one ceiling and merely near another
/// must halt, not ask.
#[test]
fn a_breach_outranks_an_escalation() {
    let declared = Horizon {
        max_wall_seconds: Some(1_000),
        max_effects: Some(4),
        max_unattended_seconds: None,
        escalate_at_percent: Some(50),
    };
    match horizon::evaluate(&declared, &usage(600, 4, 0)) {
        HorizonVerdict::Breached { dimension, .. } => {
            assert_eq!(dimension, HorizonDimension::Effects);
        }
        other => panic!("a breach was reported as an escalation: {other:?}"),
    }
}

// ── the tier each dimension earns ────────────────────────────────────────────────────────

/// Each dimension declares the tier its own mechanism earns, and the whole bound declares the
/// weakest of them. Mislabeling a bound inside a signed bundle is the worst defect this project
/// can ship, so the mapping is asserted rather than left to a comment.
#[test]
fn each_dimension_declares_the_tier_its_own_mechanism_earns() {
    use warrantor_warrant::BoundStrength;
    assert_eq!(
        HorizonDimension::Wall.strength(),
        BoundStrength::Enforced,
        "the wall horizon terminates through the supervisor's OS process link"
    );
    assert_eq!(
        HorizonDimension::Unattended.strength(),
        BoundStrength::Enforced,
        "the unattended horizon terminates through the same link"
    );
    assert_eq!(
        HorizonDimension::Effects.strength(),
        BoundStrength::Mediated,
        "the effect ceiling is refused at the MCP proxy, which sees only what the agent routes \
         through it"
    );

    // The whole bound takes the weakest word, because a reader takes the first word and moves on.
    let strengths: std::collections::BTreeMap<_, _> =
        warrantor_warrant::bound_strengths().into_iter().collect();
    assert_eq!(
        strengths.get("horizon"),
        Some(&BoundStrength::Mediated),
        "the horizon bound must declare the weakest tier any of its dimensions earns"
    );
}

// ── containment: a child may tighten a horizon and may never loosen or drop one ──────────

/// A child may tighten its horizon and may never loosen one, and dropping a DECLARED horizon is
/// an expansion for the same reason a dropped budget ceiling is: an absent horizon is bounded only
/// by the deadline, so it is never inherited.
#[test]
fn a_child_may_tighten_a_horizon_and_may_never_loosen_or_drop_one() {
    let mut parent = bounds_without_horizon();
    parent.horizon = Some(Horizon {
        max_wall_seconds: Some(3_600),
        max_effects: Some(100),
        max_unattended_seconds: Some(1_800),
        escalate_at_percent: Some(80),
    });

    // CONTROL: every ceiling tightened, and the child is contained.
    let mut tightened = parent.clone();
    tightened.delegation_depth = 1;
    tightened.horizon = Some(Horizon {
        max_wall_seconds: Some(600),
        max_effects: Some(10),
        max_unattended_seconds: Some(300),
        escalate_at_percent: Some(80),
    });
    parent
        .contains(&tightened)
        .expect("a tightened horizon is contained");

    // ATTACK 1: one ceiling loosened.
    let mut loosened = tightened.clone();
    loosened.horizon = Some(Horizon {
        max_effects: Some(101),
        ..parent.horizon.clone().expect("declared")
    });
    let error = parent
        .contains(&loosened)
        .expect_err("a loosened horizon must be refused");
    assert!(
        error.to_string().contains("horizon") && error.to_string().contains("max_effects"),
        "the refusal must name the dimension: {error}"
    );

    // ATTACK 2: the horizon dropped entirely.
    let mut dropped = tightened.clone();
    dropped.horizon = None;
    let error = parent
        .contains(&dropped)
        .expect_err("dropping a declared horizon must be refused");
    assert!(
        error.to_string().contains("horizon"),
        "the refusal must name the bound: {error}"
    );

    // ATTACK 3: a declared dimension dropped while the others tighten. A child that states two of
    // three ceilings has dropped the third, and the third is the one nobody would notice.
    let mut partial = tightened.clone();
    partial.horizon = Some(Horizon {
        max_wall_seconds: Some(600),
        max_effects: None,
        max_unattended_seconds: Some(300),
        escalate_at_percent: Some(80),
    });
    let error = parent
        .contains(&partial)
        .expect_err("dropping one declared dimension must be refused");
    assert!(
        error.to_string().contains("max_effects"),
        "the refusal must name the dropped dimension: {error}"
    );
}

/// A parent with no horizon may hand a child one: that is a tightening, and refusing it would make
/// the governor un-adoptable on every warrant granted before this field existed.
#[test]
fn a_parent_with_no_horizon_may_hand_a_child_one() {
    let parent = bounds_without_horizon();
    let mut child = bounds_without_horizon();
    child.delegation_depth = 1;
    child.horizon = Some(Horizon {
        max_wall_seconds: Some(600),
        ..Horizon::none()
    });
    parent
        .contains(&child)
        .expect("a child may declare a horizon its parent did not");

    // CONTROL: neither side declaring one is contained too, so the assertion above is not
    // satisfied by a rule that accepts everything when the parent is unbounded.
    let mut plain = bounds_without_horizon();
    plain.delegation_depth = 1;
    parent.contains(&plain).expect("no horizon on either side");
}

// ── a declared horizon must bound something ──────────────────────────────────────────────

/// A declared horizon with no dimension bounds nothing, and would render as a governed warrant.
/// Refused at grant, where an invalid warrant never exists rather than being caught at use time.
#[test]
fn a_declared_horizon_with_no_dimension_is_refused_at_grant() {
    use ed25519_dalek::SigningKey;
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let settle = SigningKey::from_bytes(&[2; 32]).verifying_key();

    // ATTACK: a horizon declared with every dimension absent.
    let mut empty = bounds_without_horizon();
    empty.horizon = Some(Horizon::none());
    let error = warrantor_warrant::Warrant::grant(
        "wrt_empty_horizon",
        "goal",
        "spiffe://muveraai.com/agent/test",
        empty,
        ISSUED_AT,
        &settle,
        &issuer,
    )
    .expect_err("an empty horizon must be refused");
    assert!(
        error.to_string().contains("horizon"),
        "the refusal must name the horizon: {error}"
    );

    // CONTROL: one dimension is enough, and the same grant succeeds.
    let mut one = bounds_without_horizon();
    one.horizon = Some(Horizon {
        max_wall_seconds: Some(600),
        ..Horizon::none()
    });
    warrantor_warrant::Warrant::grant(
        "wrt_one_horizon",
        "goal",
        "spiffe://muveraai.com/agent/test",
        one,
        ISSUED_AT,
        &settle,
        &issuer,
    )
    .expect("one declared dimension is a valid horizon");
}

/// An escalation percentage outside 1..=100 is refused, because 0 would escalate at grant and 200
/// would never escalate — both render as a configured escalation that does not work.
#[test]
fn an_out_of_range_escalation_percentage_is_refused_at_grant() {
    use ed25519_dalek::SigningKey;
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let settle = SigningKey::from_bytes(&[2; 32]).verifying_key();
    let grant = |bounds: WarrantBounds| {
        warrantor_warrant::Warrant::grant(
            "wrt_pct",
            "goal",
            "spiffe://muveraai.com/agent/test",
            bounds,
            ISSUED_AT,
            &settle,
            &issuer,
        )
    };
    for bad in [0_u8, 101] {
        let mut bounds = bounds_without_horizon();
        bounds.horizon = Some(Horizon {
            max_wall_seconds: Some(600),
            escalate_at_percent: Some(bad),
            ..Horizon::none()
        });
        let error = grant(bounds).expect_err("an out-of-range percentage must be refused");
        assert!(
            error.to_string().contains("escalate_at_percent"),
            "the refusal must name the field: {error}"
        );
    }
    // CONTROL: the endpoints of the range are accepted.
    for good in [1_u8, 100] {
        let mut bounds = bounds_without_horizon();
        bounds.horizon = Some(Horizon {
            max_wall_seconds: Some(600),
            escalate_at_percent: Some(good),
            ..Horizon::none()
        });
        grant(bounds).expect("1 and 100 are in range");
    }
}

// ── the signature contract ───────────────────────────────────────────────────────────────

/// An absent horizon must stay absent through the canonical round trip, or every warrant signed
/// before this field existed stops verifying — on a surface whose entire purpose is that old
/// evidence keeps checking out.
#[test]
fn an_absent_horizon_does_not_appear_in_the_signed_bytes() {
    let bounds = bounds_without_horizon();
    let json = serde_json::to_string(&bounds).expect("serialise");
    assert!(
        !json.contains("horizon"),
        "an absent horizon reached the signed bytes: {json}"
    );

    // CONTROL: a declared one does appear, so it is inside the signature exactly as much as any
    // other field.
    let mut declared = bounds;
    declared.horizon = Some(Horizon {
        max_wall_seconds: Some(600),
        ..Horizon::none()
    });
    let json = serde_json::to_string(&declared).expect("serialise");
    assert!(json.contains("max_wall_seconds"), "{json}");
    assert!(
        !json.contains("max_effects"),
        "an absent dimension reached the signed bytes: {json}"
    );
}

// ── the breach reason a record can be read from ──────────────────────────────────────────

/// A stop with no reason is indistinguishable from a crash. The breach sentence carries the
/// dimension, the limit and what was observed, in a shape a record can be grepped for.
#[test]
fn the_breach_reason_names_the_dimension_the_limit_and_the_observation() {
    let reason = horizon::breach_reason(HorizonDimension::Effects, 4, 4);
    assert!(reason.starts_with("horizon:effects"), "got {reason}");
    assert!(
        reason.contains("limit 4"),
        "the limit must be there: {reason}"
    );
    assert!(
        reason.contains("observed 4"),
        "so must what was observed: {reason}"
    );
    // Each dimension has its own word, so a record cannot be mistaken for another dimension's.
    assert!(horizon::breach_reason(HorizonDimension::Wall, 1, 1).starts_with("horizon:wall"));
    assert!(horizon::breach_reason(HorizonDimension::Unattended, 1, 1)
        .starts_with("horizon:unattended"));
}

fn tempdir(tag: &str) -> std::path::PathBuf {
    let unique = format!(
        "warrantor-horizon-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&path).expect("create temp root");
    assert!(Path::new(&path).is_dir());
    path
}
