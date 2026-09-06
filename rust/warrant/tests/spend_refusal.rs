//! The tool-call ceiling: refused at the proxy before the call, persisted, receipted.

use std::collections::BTreeSet;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use warrantor_notary::{Gate, Verdict};
use warrantor_warrant::mcp::Endpoint;
use warrantor_warrant::mcp_endpoints::agent_endpoint_for;
use warrantor_warrant::proxy::{Decision, Proxy, ProxyMode, ToolCall};
use warrantor_warrant::spend::{
    CallCounter, CallLedger, CallMeter, SpendStore, CALLS_BOUND, CALL_LEDGER_FORMAT,
};
use warrantor_warrant::staging::EffectRegistry;
use warrantor_warrant::store::StoredWarrant;
use warrantor_warrant::upstream::{UpstreamSet, UpstreamSpec};
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds};

const NOW: u64 = 1_786_000_000;
fn now() -> u64 {
    NOW
}

fn selftest() -> UpstreamSet {
    let spec = UpstreamSpec {
        name: "selftest".to_string(),
        program: env!("CARGO_BIN_EXE_warrantor").to_string(),
        args: vec!["selftest-upstream".to_string()],
    };
    UpstreamSet::start(&[spec], std::time::Duration::from_secs(30)).expect("attach")
}

fn echo() -> std::collections::BTreeMap<String, serde_json::Value> {
    [("text".to_string(), serde_json::json!("ping"))]
        .into_iter()
        .collect()
}

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

/// The acceptance test for L3-03 at the tool-call grain: a live upstream, a hundred admitted
/// calls, and the hundred-and-first refused before it is forwarded, receipted, and still refused
/// after the session restarts.
#[test]
fn the_hundred_and_first_call_is_refused_before_the_upstream_sees_it_and_stays_refused() {
    let dir = tempdir("endpoint");
    let stored = stored(Some(100));
    let mut endpoint =
        agent_endpoint_for(&stored, dir.join("staged.jsonl"), ProxyMode::Enforce, now)
            .expect("endpoint")
            .with_upstreams(selftest())
            .metered_by(CallMeter::open(&dir, &stored, issuer()).expect("meter"));
    for i in 0..100 {
        let result = endpoint.call("selftest.echo", &echo());
        assert!(!result.is_error, "call {i}: {}", result.text);
    }
    assert_eq!(endpoint.forwarding_counts(), Some((100, 0)));

    let refused = endpoint.call("selftest.echo", &echo());
    assert!(refused.is_error);
    assert!(refused.text.contains(CALLS_BOUND), "{}", refused.text);
    assert_eq!(
        endpoint.forwarding_counts(),
        Some((100, 0)),
        "the refused call never reached the upstream"
    );
    let ledger = endpoint.call_ledger().expect("metered");
    assert_eq!(ledger.refused, 1);
    assert_eq!(
        ledger.receipt.as_ref().unwrap().body.verdict,
        Verdict::Deny { gate: Gate::Budget }
    );

    drop(endpoint);
    let mut again = agent_endpoint_for(&stored, dir.join("staged.jsonl"), ProxyMode::Enforce, now)
        .expect("endpoint")
        .with_upstreams(selftest())
        .metered_by(CallMeter::open(&dir, &stored, issuer()).expect("meter"));
    let still = again.call("selftest.echo", &echo());
    assert!(
        still.is_error && still.text.contains(CALLS_BOUND),
        "a restart must not reset the ceiling"
    );
}

#[test]
fn an_unmetered_endpoint_still_refuses_but_says_the_count_is_per_session() {
    let dir = tempdir("unmetered");
    let stored = stored(Some(1));
    let mut endpoint =
        agent_endpoint_for(&stored, dir.join("staged.jsonl"), ProxyMode::Enforce, now)
            .expect("endpoint")
            .with_upstreams(selftest());
    assert!(!endpoint.call("selftest.echo", &echo()).is_error);
    assert!(endpoint.call("selftest.echo", &echo()).is_error);
    assert!(endpoint.call_ledger().is_none());
}

#[test]
fn grant_writes_the_ceiling_into_the_claims_and_refuses_a_ceiling_that_does_not_parse() {
    let dir = tempdir("cli");
    let run = |extra: &[&str]| {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_warrantor"));
        // The subcommand comes first; `--root` after it. This binary's parser dispatches on
        // argv[1] before it reads flags, so a leading --root is an unknown command.
        cmd.args(["grant"])
            .arg("--root")
            .arg(&dir)
            .args([
                "--goal",
                "g",
                "--tools",
                "selftest.echo",
                "--write",
                "src/**",
            ])
            .args(extra);
        cmd.output().expect("run")
    };
    let out = run(&["--max-calls", "3"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let store = warrantor_warrant::store::WarrantStore::open(&dir).unwrap();
    let granted = store.list().unwrap();
    assert_eq!(granted.len(), 1);
    assert_eq!(granted[0].warrant.claims.bounds.max_tool_calls, Some(3));

    let bad = run(&["--max-calls", "lots"]);
    assert!(
        !bad.status.success(),
        "an unparseable ceiling is a refusal, never a default"
    );
    assert_eq!(store.list().unwrap().len(), 1);

    let defaulted = run(&[]);
    assert!(defaulted.status.success());
    let all = store.list().unwrap();
    assert!(all.iter().any(|w| w.warrant.claims.bounds.max_tool_calls
        == Some(warrantor_warrant::spend::DEFAULT_MAX_TOOL_CALLS)));
}
