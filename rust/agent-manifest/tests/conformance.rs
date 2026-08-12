//! Conformance test: load the shared manifest vectors and assert each one.
//!
//! This is the cross-language contract — Python's `warrantor_agent_manifest` runs the same vectors
//! and must agree on every valid/invalid outcome AND the specific error code, mirroring the A6
//! Ed25519 conformance pattern.

use std::collections::HashSet;

use serde_json::Value;
use warrantor_agent_manifest::{parse_and_validate, ManifestError};

const VECTORS_PATH: &str = "../../testvectors/agent-manifest/vectors.json";

#[derive(Debug)]
struct VectorResult {
    name: String,
    passed: bool,
    detail: String,
}

fn run_vectors() -> Vec<VectorResult> {
    let raw = std::fs::read_to_string(VECTORS_PATH)
        .unwrap_or_else(|e| panic!("read vectors {}: {}", VECTORS_PATH, e));
    let root: Value = serde_json::from_str(&raw).expect("vectors.json is valid JSON");
    let vectors = root
        .get("vectors")
        .and_then(|v| v.as_array())
        .expect("vectors.json has a 'vectors' array");

    let mut results = Vec::with_capacity(vectors.len());
    for v in vectors {
        let name = v.get("name").and_then(|n| n.as_str()).unwrap_or("<unnamed>").to_string();
        let manifest_value = v.get("manifest").expect("vector has a manifest");
        let manifest_json = serde_json::to_string(manifest_value).expect("manifest serializes");
        let expected = v.get("expected").expect("vector has an expected");
        let expected_valid = expected.get("valid").and_then(|x| x.as_bool()).unwrap_or(false);

        let result = match parse_and_validate(&manifest_json) {
            Ok(_) => {
                if expected_valid {
                    VectorResult { name, passed: true, detail: "valid as expected".to_string() }
                } else {
                    let want_code = expected.get("error_code").and_then(|c| c.as_str()).unwrap_or("?");
                    VectorResult {
                        name,
                        passed: false,
                        detail: format!("expected INVALID ({}), parsed VALID", want_code),
                    }
                }
            }
            Err(err) => {
                if !expected_valid {
                    let want_code = expected.get("error_code").and_then(|c| c.as_str()).unwrap_or("?");
                    let want_field = expected.get("error_field").and_then(|f| f.as_str());
                    let got_code = error_code(&err);
                    let got_field = error_field(&err);
                    let code_ok = got_code == want_code;
                    let field_ok = match want_field {
                        None => true,
                        Some(wf) => got_field.as_deref() == Some(wf),
                    };
                    VectorResult {
                        name,
                        passed: code_ok && field_ok,
                        detail: format!(
                            "code want={} got={} ({}); field want={:?} got={:?}",
                            want_code, got_code, if code_ok { "OK" } else { "MISMATCH" },
                            want_field, got_field
                        ),
                    }
                } else {
                    VectorResult {
                        name,
                        passed: false,
                        detail: format!("expected VALID, got INVALID: {:?}", err),
                    }
                }
            }
        };
        results.push(result);
    }
    results
}

/// Map an error to its stable error_code string (matches vectors.json + Python implementation).
fn error_code(e: &ManifestError) -> &'static str {
    match e {
        ManifestError::MalformedJson(_) => "MALFORMED_JSON",
        ManifestError::NotAnObject => "NOT_AN_OBJECT",
        ManifestError::MissingRequiredField { .. } => "MISSING_REQUIRED_FIELD",
        ManifestError::UnexpectedField { .. } => "UNEXPECTED_FIELD",
        ManifestError::InvalidApiVersion => "INVALID_API_VERSION",
        ManifestError::InvalidKind => "INVALID_KIND",
        ManifestError::InvalidIdentity { .. } => "INVALID_IDENTITY",
        ManifestError::EmptyCapabilities { .. } => "EMPTY_CAPABILITIES",
        ManifestError::InvalidCapability { .. } => "INVALID_CAPABILITY",
        ManifestError::EmptyPolicyRefs { .. } => "EMPTY_POLICY_REFS",
        ManifestError::InvalidEnforcementMode { .. } => "INVALID_ENFORCEMENT_MODE",
        ManifestError::InvalidVersion { .. } => "INVALID_VERSION",
        ManifestError::InvalidModelDigest { .. } => "INVALID_MODEL_DIGEST",
        _ => "OTHER",
    }
}

fn error_field(e: &ManifestError) -> Option<String> {
    match e {
        ManifestError::MissingRequiredField { field }
        | ManifestError::UnexpectedField { field }
        | ManifestError::InvalidIdentity { field }
        | ManifestError::EmptyCapabilities { field }
        | ManifestError::InvalidCapability { field, .. }
        | ManifestError::EmptyPolicyRefs { field }
        | ManifestError::InvalidEnforcementMode { field, .. }
        | ManifestError::InvalidVersion { field, .. }
        | ManifestError::InvalidModelDigest { field, .. } => Some(field.clone()),
        _ => None,
    }
}

#[test]
fn all_conformance_vectors_pass() {
    let results = run_vectors();
    let failed: Vec<&VectorResult> = results.iter().filter(|r| !r.passed).collect();

    let names: HashSet<&str> = results.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(
        names.len(),
        results.len(),
        "vector names must be unique (silent dedup is a conformance hazard)"
    );

    if !failed.is_empty() {
        let mut msg = format!("{} of {} vectors FAILED:\n", failed.len(), results.len());
        for f in &failed {
            msg.push_str(&format!("  - {}: {}\n", f.name, f.detail));
        }
        panic!("{}", msg);
    }
    println!("all {} conformance vectors passed", results.len());
}

#[test]
fn vector_count_is_expected() {
    // Guards against a silently-shrinking corpus.
    let results = run_vectors();
    assert_eq!(results.len(), 13, "expected 13 manifest vectors; got {}", results.len());
}
