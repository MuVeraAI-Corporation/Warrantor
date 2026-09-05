//! The tool-call ceiling: refused at the proxy before the call, persisted, receipted.

use std::collections::BTreeSet;

use warrantor_warrant::proxy::{Decision, Proxy, ProxyMode, ToolCall};
use warrantor_warrant::spend::{CallCounter, CALLS_BOUND};
use warrantor_warrant::staging::EffectRegistry;
use warrantor_warrant::{SideEffectClass, WarrantBounds};

const NOW: u64 = 1_786_000_000;

fn bounds(max_calls: Option<u64>) -> WarrantBounds {
    WarrantBounds {
        tools: ["selftest.echo".to_string()].into_iter().collect(),
        write_paths: BTreeSet::new(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        max_tool_calls: max_calls,
        delegation_depth: 1,
    }
}

fn read(tool: &str) -> ToolCall {
    ToolCall {
        tool: tool.to_string(),
        arguments: std::collections::BTreeMap::new(),
        side_effect: SideEffectClass::Read,
    }
}

#[test]
fn the_counter_refuses_the_hundred_and_first_and_holds_at_a_hundred() {
    let mut counter = CallCounter::new(&bounds(Some(100)));
    for _ in 0..100 {
        counter.reserve().expect("within the ceiling");
    }
    assert_eq!(counter.remaining(), 0);
    let refused = counter.reserve().expect_err("101st");
    assert_eq!(
        refused.reason,
        warrantor_warrant::spend::DenyReason::ToolCallBudgetExhausted
    );
    assert_eq!(counter.tool_calls_used, 100);
}

#[test]
fn an_undeclared_ceiling_is_zero_calls() {
    let mut counter = CallCounter::new(&bounds(None));
    assert!(
        counter.reserve().is_err(),
        "None is a ceiling of zero, never unlimited"
    );
}

#[test]
fn the_proxy_refuses_the_hundred_and_first_forward_under_the_calls_bound() {
    let mut proxy = Proxy::new(
        bounds(Some(100)),
        ProxyMode::Enforce,
        EffectRegistry::github(),
    );
    for _ in 0..100 {
        assert_eq!(proxy.decide(&read("selftest.echo")), Decision::Forward);
    }
    match proxy.decide(&read("selftest.echo")) {
        Decision::Deny { bound, reason } => {
            assert_eq!(bound, CALLS_BOUND);
            assert!(reason.contains("ceiling"), "{reason}");
        }
        other => panic!("the 101st call must be refused, got {other:?}"),
    }
    assert_eq!(proxy.call_counter().tool_calls_used, 100);
    let recorded = proxy.authority_requests();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].bound, CALLS_BOUND);
}

#[test]
fn a_call_another_bound_refused_does_not_spend_a_slot() {
    let mut proxy = Proxy::new(
        bounds(Some(1)),
        ProxyMode::Enforce,
        EffectRegistry::github(),
    );
    assert!(matches!(
        proxy.decide(&read("not.granted")),
        Decision::Deny { bound: "tools", .. }
    ));
    assert_eq!(
        proxy.call_counter().tool_calls_used,
        0,
        "a tools refusal is not a call"
    );
    assert_eq!(proxy.decide(&read("selftest.echo")), Decision::Forward);
    assert!(
        matches!(proxy.decide(&read("selftest.echo")), Decision::Deny { bound, .. } if bound == CALLS_BOUND)
    );
}

#[test]
fn observe_mode_counts_and_refuses_too() {
    let mut proxy = Proxy::new(
        bounds(Some(2)),
        ProxyMode::Observe,
        EffectRegistry::github(),
    );
    assert_eq!(proxy.decide(&read("anything")), Decision::Forward);
    assert_eq!(proxy.decide(&read("anything.else")), Decision::Forward);
    assert!(
        matches!(proxy.decide(&read("third")), Decision::Deny { bound, .. } if bound == CALLS_BOUND)
    );
}

#[test]
fn a_seeded_counter_starts_where_the_last_session_stopped() {
    let mut carried = CallCounter::new(&bounds(Some(3)));
    carried.tool_calls_used = 3;
    let mut proxy = Proxy::new(
        bounds(Some(3)),
        ProxyMode::Enforce,
        EffectRegistry::github(),
    )
    .with_call_counter(carried);
    assert!(
        matches!(proxy.decide(&read("selftest.echo")), Decision::Deny { bound, .. } if bound == CALLS_BOUND)
    );
}
