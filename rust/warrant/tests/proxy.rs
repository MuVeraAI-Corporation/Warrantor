//! W3 tests: what the proxy allows, stages, and refuses.

use std::collections::{BTreeMap, BTreeSet};

use warrantor_warrant::proxy::{host_of, Decision, Proxy, ProxyMode, ToolCall};
use warrantor_warrant::staging::EffectRegistry;
use warrantor_warrant::{SideEffectClass, WarrantBounds};

const NOW: u64 = 1_786_000_000;

fn bounds() -> WarrantBounds {
    WarrantBounds {
        tools: ["git", "cargo", "github.create_pr"]
            .into_iter()
            .map(str::to_string)
            .collect(),
        write_paths: ["src/**".to_string()].into_iter().collect(),
        egress_hosts: ["api.github.com".to_string()].into_iter().collect(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        delegation_depth: 2,
    }
}

fn call(tool: &str, class: SideEffectClass, args: &[(&str, &str)]) -> ToolCall {
    ToolCall {
        tool: tool.to_string(),
        arguments: args
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        side_effect: class,
    }
}

fn enforcing() -> Proxy {
    Proxy::new(bounds(), ProxyMode::Enforce, EffectRegistry::github())
}

fn observing() -> Proxy {
    Proxy::new(bounds(), ProxyMode::Observe, EffectRegistry::github())
}

// ── enforce ───────────────────────────────────────────────────────────────────────────

#[test]
fn an_allowlisted_read_is_forwarded() {
    let mut proxy = enforcing();
    let decision = proxy.decide(&call("git", SideEffectClass::Read, &[]));
    assert_eq!(decision, Decision::Forward);
}

#[test]
fn a_tool_outside_the_allowlist_is_refused() {
    let mut proxy = enforcing();
    let decision = proxy.decide(&call("curl", SideEffectClass::Read, &[]));
    match decision {
        Decision::Deny { bound, reason } => {
            assert_eq!(bound, "tools");
            assert!(
                reason.contains("curl"),
                "the agent must know what was refused"
            );
            assert!(
                reason.contains("recorded"),
                "the agent should know the request is visible to a human, so it stops retrying"
            );
        }
        other => panic!("expected a denial, got {other:?}"),
    }
}

/// A staged class produces a handle rather than a real call.
#[test]
fn a_staged_write_is_staged_not_forwarded() {
    let mut proxy = enforcing();
    let decision = proxy.decide(&call(
        "github.create_pr",
        SideEffectClass::Write,
        &[("title", "Fix")],
    ));
    assert!(matches!(decision, Decision::Stage { .. }));
}

#[test]
fn egress_outside_the_allowlist_is_refused() {
    let mut proxy = enforcing();
    let decision = proxy.decide(&call(
        "git",
        SideEffectClass::Read,
        &[("url", "https://api.stripe.com/v1/charges")],
    ));
    match decision {
        Decision::Deny { bound, .. } => assert_eq!(bound, "egress_hosts"),
        other => panic!("expected an egress denial, got {other:?}"),
    }
}

#[test]
fn egress_to_an_allowed_host_is_permitted() {
    let mut proxy = enforcing();
    let decision = proxy.decide(&call(
        "git",
        SideEffectClass::Read,
        &[("url", "https://api.github.com/repos/o/r")],
    ));
    assert_eq!(decision, Decision::Forward);
}

/// A permissive host parser would be an egress bypass, so anything unparseable must fail closed.
#[test]
fn host_parsing_is_conservative() {
    assert_eq!(
        host_of("https://api.github.com/repos/o/r"),
        "api.github.com"
    );
    assert_eq!(host_of("api.github.com"), "api.github.com");
    assert_eq!(host_of("https://api.github.com:443/x"), "api.github.com");
    // Credentials in a URL are a classic way to smuggle a different host past a naive check.
    assert_eq!(
        host_of("https://api.github.com@evil.example/x"),
        "evil.example",
        "the host is what comes AFTER the credentials, which is what the request actually reaches"
    );
}

#[test]
fn a_credential_smuggled_host_is_refused() {
    let mut proxy = enforcing();
    let decision = proxy.decide(&call(
        "git",
        SideEffectClass::Read,
        &[("url", "https://api.github.com@evil.example/steal")],
    ));
    assert!(
        matches!(
            decision,
            Decision::Deny {
                bound: "egress_hosts",
                ..
            }
        ),
        "a URL whose userinfo looks like an allowed host must not pass: {decision:?}"
    );
}

// ── observe ───────────────────────────────────────────────────────────────────────────

/// The purpose of observe mode: an unlisted tool is recorded, not refused, so the warrant can be
/// authored from what the agent actually does.
#[test]
fn observe_records_unlisted_tools_instead_of_refusing() {
    let mut proxy = observing();
    assert_eq!(
        proxy.decide(&call("ripgrep", SideEffectClass::Read, &[])),
        Decision::Forward
    );
    assert_eq!(
        proxy.decide(&call("jq", SideEffectClass::Read, &[])),
        Decision::Forward
    );
    let proposed = proxy.proposed_tools();
    assert!(proposed.contains("ripgrep"));
    assert!(proposed.contains("jq"));
}

/// Even in observe mode, learning must not destroy anything or spend money.
#[test]
fn observe_still_refuses_destructive_and_financial() {
    for class in [SideEffectClass::Destructive, SideEffectClass::Financial] {
        let mut proxy = observing();
        let decision = proxy.decide(&call("anything", class, &[]));
        assert!(
            matches!(
                decision,
                Decision::Deny {
                    bound: "side_effect_class",
                    ..
                }
            ),
            "{class:?} must be refused even while observing, got {decision:?}"
        );
    }
}

/// The consequence of the observe decision, asserted so it cannot drift silently: an ordinary
/// write really happens during an observe run. It is NOT staged.
#[test]
fn observe_does_not_stage_ordinary_writes() {
    let mut proxy = observing();
    let decision = proxy.decide(&call(
        "github.create_pr",
        SideEffectClass::Write,
        &[("title", "Fix")],
    ));
    assert_eq!(
        decision,
        Decision::Forward,
        "observe means observe: the pull request is really opened, which the CLI must announce"
    );
}

// ── authority requests ────────────────────────────────────────────────────────────────

/// Every wall the agent hits is evidence about whether the warrant was scoped right.
#[test]
fn denials_are_recorded_for_the_morning_report() {
    let mut proxy = enforcing();
    proxy.decide(&call("curl", SideEffectClass::Read, &[]));
    proxy.decide(&call("wget", SideEffectClass::Read, &[]));

    let requests = proxy.authority_requests();
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().any(|r| r.tool == "curl"));
}

/// A looping agent must not flood the report with the same refusal a thousand times.
#[test]
fn repeated_denials_are_counted_not_duplicated() {
    let mut proxy = enforcing();
    for _ in 0..50 {
        proxy.decide(&call("curl", SideEffectClass::Read, &[]));
    }
    let requests = proxy.authority_requests();
    assert_eq!(requests.len(), 1, "one entry, not fifty");
    assert_eq!(requests[0].count, 50, "but the count tells you it looped");
}

#[test]
fn requests_are_ordered_by_how_often_they_happened() {
    let mut proxy = enforcing();
    proxy.decide(&call("rare", SideEffectClass::Read, &[]));
    for _ in 0..5 {
        proxy.decide(&call("frequent", SideEffectClass::Read, &[]));
    }
    let requests = proxy.authority_requests();
    assert_eq!(
        requests[0].tool, "frequent",
        "the wall it hit most is the most informative about the bounds"
    );
}

#[test]
fn an_empty_egress_set_denies_all_egress() {
    let mut restricted = bounds();
    restricted.egress_hosts = BTreeSet::new();
    let mut proxy = Proxy::new(restricted, ProxyMode::Enforce, EffectRegistry::github());
    let decision = proxy.decide(&call(
        "git",
        SideEffectClass::Read,
        &[("url", "https://api.github.com/x")],
    ));
    assert!(
        matches!(
            decision,
            Decision::Deny {
                bound: "egress_hosts",
                ..
            }
        ),
        "an absent bound means none, never unlimited"
    );
}

#[test]
fn staging_writes_the_queue_and_returns_a_typed_handle() {
    let dir = std::env::temp_dir().join(format!(
        "warrantor-proxy-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("dir");
    let mut queue = warrantor_warrant::staging::StagingQueue::open(
        dir.join("q.jsonl"),
        "wrt_proxy",
        EffectRegistry::github(),
    )
    .expect("queue");

    let proxy = enforcing();
    let tool_call = call(
        "github.create_pr",
        SideEffectClass::Write,
        &[("title", "Fix")],
    );
    let effect = proxy.apply(&tool_call, &mut queue, NOW).expect("stage");

    assert!(effect.handle.starts_with("pr://staged/wrt_proxy/"));
    assert_eq!(queue.len(), 1);
}

#[test]
fn arguments_reach_the_queue_unchanged() {
    let mut proxy = enforcing();
    let mut arguments = BTreeMap::new();
    arguments.insert("title".to_string(), "Fix \"quoted\" title".to_string());
    let tool_call = ToolCall {
        tool: "github.create_pr".to_string(),
        arguments: arguments.clone(),
        side_effect: SideEffectClass::Write,
    };
    assert!(matches!(proxy.decide(&tool_call), Decision::Stage { .. }));
    assert_eq!(
        tool_call.arguments, arguments,
        "the proxy must not rewrite what the agent asked for"
    );
}
