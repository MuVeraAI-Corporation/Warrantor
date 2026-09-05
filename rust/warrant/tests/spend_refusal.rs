//! The tool-call ceiling: refused at the proxy before the call, persisted, receipted.

use std::collections::BTreeSet;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use warrantor_notary::{Gate, Verdict};
use warrantor_warrant::proxy::{Decision, Proxy, ProxyMode, ToolCall};
use warrantor_warrant::spend::{
    CallCounter, CallLedger, CallMeter, SpendStore, CALLS_BOUND, CALL_LEDGER_FORMAT,
};
use warrantor_warrant::staging::EffectRegistry;
use warrantor_warrant::store::StoredWarrant;
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds};

const NOW: u64 = 1_786_000_000;

fn tempdir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-calls-{tag}-{}",
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

fn stored(max_calls: Option<u64>) -> StoredWarrant {
    let warrant = Warrant::grant(
        "wrt_calls",
        "echo until refused",
        "spiffe://muveraai.com/agent/local",
        bounds(max_calls),
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

#[test]
fn a_refusal_is_receipted_under_the_budget_gate_and_survives_a_reload() {
    let dir = tempdir("ledger");
    let stored = stored(Some(1));
    let mut meter = CallMeter::open(&dir, &stored, issuer()).expect("open");
    let mut counter = meter.counter();
    counter.reserve().expect("first");
    meter
        .note(&counter, "selftest.echo", false, NOW)
        .expect("admitted");
    assert!(counter.reserve().is_err());
    let path = meter
        .note(&counter, "selftest.echo", true, NOW + 1)
        .expect("refused");
    assert_eq!(
        path,
        SpendStore::open(&dir).unwrap().calls_path("wrt_calls")
    );

    let ledger: CallLedger = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(ledger.format, CALL_LEDGER_FORMAT);
    assert_eq!(ledger.counter.tool_calls_used, 1);
    assert_eq!(ledger.refused, 1);
    let receipt = ledger.receipt.as_ref().expect("a refusal leaves a receipt");
    assert_eq!(receipt.body.verdict, Verdict::Deny { gate: Gate::Budget });
    assert_eq!(
        receipt.body.enforcement_mode,
        warrantor_notary::EnforcementMode::Mediated
    );
    warrantor_notary::verify_receipt(receipt).expect("signed by the issuer");

    let reopened = CallMeter::open(&dir, &stored, issuer()).expect("reopen");
    assert_eq!(
        reopened.counter().tool_calls_used,
        1,
        "the count is durable"
    );
}

#[test]
fn a_ledger_signed_by_a_stranger_is_refused_rather_than_trusted() {
    let dir = tempdir("stranger");
    let stored = stored(Some(1));
    let mut meter = CallMeter::open(&dir, &stored, SigningKey::from_bytes(&[9; 32])).expect("open");
    let mut counter = meter.counter();
    // Ceiling 1: the first call is admitted and the second refused — the refusal must exist for
    // the receipt the stranger-key check is about.
    counter.reserve().expect("first");
    assert!(counter.reserve().is_err());
    meter
        .note(&counter, "selftest.echo", true, NOW)
        .expect("refused");
    let err = CallMeter::open(&dir, &stored, issuer()).expect_err("wrong key");
    assert!(
        err.to_string().contains("not by this store's issuer key"),
        "{err}"
    );
}

#[test]
fn an_unparseable_ledger_is_unknown_spend_not_zero() {
    let dir = tempdir("corrupt");
    let stored = stored(Some(5));
    let path = SpendStore::open(&dir).unwrap().calls_path("wrt_calls");
    std::fs::write(&path, b"{ not json").unwrap();
    assert!(CallMeter::open(&dir, &stored, issuer()).is_err());
}
