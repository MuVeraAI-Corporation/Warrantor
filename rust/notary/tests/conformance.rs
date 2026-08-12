//! Conformance test for the W1 Notary verdict function.
//!
//! Loads the shared vectors at `../../testvectors/notary/vectors.json`, applies each vector's
//! overrides to the base request + context, runs `verdict()`, and asserts the expected outcome
//! AND the specific failing gate. This is the contract: every implementation of the verdict
//! function must agree on every vector. (Per spec 11 §1, only Rust implements it; Python
//! Verifies the receipts Rust issues over these vectors — see the Python interop test.)

use serde_json::Value;
use warrantor_notary::{verdict, Gate, Verdict, VerdictContext, VerdictRequest};

const VECTORS_PATH: &str = "../../testvectors/notary/vectors.json";

/// Deep-merge `override_obj` into `base`. For each key in the override: if both base and override
/// have an object at that key, recurse; otherwise the override wins. Arrays are replaced whole
/// (an override of `capabilities_requested` replaces the array, it does not append).
fn deep_merge(base: &mut Value, override_val: &Value) {
    match (base, override_val) {
        (Value::Object(base_map), Value::Object(override_map)) => {
            for (k, v) in override_map {
                deep_merge(base_map.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
        (slot, override_val) => {
            *slot = override_val.clone();
        }
    }
}

fn run_vectors() -> Vec<(String, bool, String)> {
    let raw = std::fs::read_to_string(VECTORS_PATH)
        .unwrap_or_else(|e| panic!("read {VECTORS_PATH}: {e}"));
    let root: Value = serde_json::from_str(&raw).expect("vectors.json is valid JSON");
    let base_req = root.get("base_request").cloned().expect("base_request");
    let base_ctx = root.get("base_context").cloned().expect("base_context");
    let vectors = root
        .get("vectors")
        .and_then(|v| v.as_array())
        .expect("vectors array");

    vectors
        .iter()
        .map(|v| {
            let name = v
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("<unnamed>")
                .to_string();
            let mut req_value = base_req.clone();
            if let Some(o) = v.get("request_overrides") {
                deep_merge(&mut req_value, o);
            }
            let mut ctx_value = base_ctx.clone();
            if let Some(o) = v.get("context_overrides") {
                deep_merge(&mut ctx_value, o);
            }

            let req: VerdictRequest = serde_json::from_value(req_value)
                .unwrap_or_else(|e| panic!("vector {name}: request deserialize: {e}"));
            let ctx: VerdictContext = serde_json::from_value(ctx_value)
                .unwrap_or_else(|e| panic!("vector {name}: context deserialize: {e}"));

            let got = verdict(&req, &ctx);
            let expected = v.get("expected").expect("expected");
            let expected_outcome = expected
                .get("outcome")
                .and_then(|o| o.as_str())
                .unwrap_or("");

            let (passed, detail) = match (&got, expected_outcome) {
                (
                    Verdict::Allow {
                        effective_capabilities,
                    },
                    "allow",
                ) => {
                    let want_caps: Vec<String> = expected
                        .get("effective_capabilities")
                        .and_then(|c| c.as_array())
                        .map(|a| {
                            a.iter()
                                .map(|x| x.as_str().unwrap_or("").to_string())
                                .collect()
                        })
                        .unwrap_or_default();
                    let ok = *effective_capabilities == want_caps;
                    (
                        ok,
                        if ok {
                            "allow with correct effective_capabilities".to_string()
                        } else {
                            format!(
                                "allow but caps want={want_caps:?} got={effective_capabilities:?}"
                            )
                        },
                    )
                }
                (Verdict::Deny { gate }, "deny") => {
                    let want_gate_str = expected.get("gate").and_then(|g| g.as_str()).unwrap_or("");
                    let want_gate = parse_gate(want_gate_str);
                    let ok = *gate == want_gate;
                    (
                        ok,
                        if ok {
                            format!("deny at correct gate {gate:?}")
                        } else {
                            format!("deny but gate want={want_gate:?} got={gate:?}")
                        },
                    )
                }
                (got_v, expected_o) => (false, format!("outcome want={expected_o} got={got_v:?}")),
            };
            (name, passed, detail)
        })
        .collect()
}

fn parse_gate(s: &str) -> Gate {
    match s {
        "containment" => Gate::Containment,
        "identity" => Gate::Identity,
        "freshness" => Gate::Freshness,
        "chain" => Gate::Chain,
        "authority" => Gate::Authority,
        "artifacts" => Gate::Artifacts,
        "budget" => Gate::Budget,
        "policy" => Gate::Policy,
        "approval" => Gate::Approval,
        other => panic!("unknown gate '{other}' in vectors"),
    }
}

#[test]
fn all_conformance_vectors_pass() {
    let results = run_vectors();
    let failed: Vec<&(String, bool, String)> = results.iter().filter(|(_, ok, _)| !ok).collect();
    if !failed.is_empty() {
        let mut msg = format!("{} of {} vectors FAILED:\n", failed.len(), results.len());
        for (name, _, detail) in &failed {
            msg.push_str(&format!("  - {name}: {detail}\n"));
        }
        panic!("{msg}");
    }
    println!("all {} notary conformance vectors passed", results.len());
}

#[test]
fn vector_count_is_expected() {
    let results = run_vectors();
    assert_eq!(
        results.len(),
        16,
        "expected 16 notary vectors; got {}",
        results.len()
    );
}
