//! The tool-call ceiling: refused at the proxy before the call, persisted, receipted.

use std::collections::BTreeSet;

use warrantor_warrant::spend::CallCounter;
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
