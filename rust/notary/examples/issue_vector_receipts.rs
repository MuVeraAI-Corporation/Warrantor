//! Interop producer: run every conformance vector, issue a signed WAR receipt for each, and write
//! a bundle JSON that the Python `warrantor_notary` package then verifies.
//!
//! Usage: `cargo run --example issue_vector_receipts -- <output-path>`
//!
//! This proves the W1 cross-language contract: the verdict is decided once (in Rust) and the
//! receipt is verifiable by any third party (Python) with no privileged access — the README's
//! "test that matters".

use serde_json::Value;
use warrantor_notary::{
    effective_capabilities, generate_keypair, issue_receipt, verdict, EnforcementMode,
    VerdictContext, VerdictRequest,
};

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

fn main() {
    use std::env;
    use std::path::PathBuf;

    // Resolved from the crate manifest, not from the current directory. These were relative paths
    // (`../../testvectors/...`), which only work when you happen to run from inside this crate --
    // `cargo run -p warrantor-notary --example …` from the workspace root panicked with a bare
    // NotFound. That is not cosmetic: this example produces the fixture the Python interop tests
    // need, and those tests `skipif` when it is absent. So the fixture was never produced, the
    // interop tests never ran, and the suite reported green having skipped the one check that
    // proves Rust and Python agree on a signature.
    let repo_root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("crate lives two levels below the repository root")
        .to_path_buf();

    let out = env::args().nth(1).unwrap_or_else(|| {
        repo_root
            .join(".notary_interop_bundle.json")
            .display()
            .to_string()
    });

    let vectors_path = repo_root.join("testvectors/notary/vectors.json");
    let raw = std::fs::read_to_string(&vectors_path)
        .unwrap_or_else(|e| panic!("read vectors at {}: {e}", vectors_path.display()));
    let root: Value = serde_json::from_str(&raw).expect("vectors json");
    let base_req = root.get("base_request").cloned().expect("base_request");
    let base_ctx = root.get("base_context").cloned().expect("base_context");
    let vectors = root
        .get("vectors")
        .and_then(|v| v.as_array())
        .expect("vectors");

    let (signing_key, verifying_key) = generate_keypair();
    let pub_hex = hex::encode(&verifying_key.to_bytes());

    let mut entries: Vec<Value> = Vec::new();

    for v in vectors {
        let name = v.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let mut req_value = base_req.clone();
        if let Some(o) = v.get("request_overrides") {
            deep_merge(&mut req_value, o);
        }
        let mut ctx_value = base_ctx.clone();
        if let Some(o) = v.get("context_overrides") {
            deep_merge(&mut ctx_value, o);
        }
        let req: VerdictRequest = serde_json::from_value(req_value.clone())
            .unwrap_or_else(|e| panic!("vector {name}: request deserialize: {e}"));
        let ctx: VerdictContext = serde_json::from_value(ctx_value)
            .unwrap_or_else(|e| panic!("vector {name}: context deserialize: {e}"));

        let verdict_result = verdict(&req, &ctx);
        let receipt = issue_receipt(
            &verdict_result,
            &req,
            EnforcementMode::Mediated,
            &signing_key,
            "interop-notary",
        );

        entries.push(serde_json::json!({
            "name": name,
            "request": req_value,
            "verdict": verdict_result,
            "effective_capabilities_recomputed": effective_capabilities(&req.actor),
            "receipt": receipt,
        }));
    }

    let bundle = serde_json::json!({
        "schema": "warrantor.notary.interop.v1",
        "notary_public_key": pub_hex,
        "entries": entries,
    });
    let n = bundle.get("entries").unwrap().as_array().unwrap().len();
    std::fs::write(&out, serde_json::to_string_pretty(&bundle).unwrap())
        .unwrap_or_else(|e| panic!("write {out}: {e}"));
    println!("Rust issued {} signed receipts → {}", n, out);
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}
