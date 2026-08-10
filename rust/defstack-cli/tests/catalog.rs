//! Tests for the defstack-cli component catalog and compliance-report generator.
//!
//! These are integration tests against the binary's library functions. The CLI argument
//! parsing itself is exercised by the smoke runs in CI.

use std::process::Command;

#[test]
fn list_outputs_all_wave1_components() {
    // The CLI is a binary; invoke it and check the list contains every Wave-1 component id.
    let bin = env!("CARGO_BIN_EXE_defstack");
    let output = Command::new(bin)
        .arg("list")
        .output()
        .expect("run defstack list");
    assert!(output.status.success(), "defstack list should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for id in ["T1", "X1", "C1-1", "C1-2", "R2", "R3", "R4", "I1"] {
        assert!(
            stdout.contains(id),
            "list output must contain component id {id}"
        );
    }
}

#[test]
fn install_unknown_component_exits_nonzero() {
    let bin = env!("CARGO_BIN_EXE_defstack");
    let output = Command::new(bin)
        .args(["install", "does-not-exist"])
        .output()
        .expect("run defstack install");
    assert!(!output.status.success(), "unknown component should fail");
}

#[test]
fn install_known_component_emits_json_plan() {
    let bin = env!("CARGO_BIN_EXE_defstack");
    let output = Command::new(bin)
        .args(["install", "trust-core"])
        .output()
        .expect("run defstack install trust-core");
    assert!(output.status.success(), "install trust-core should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"component\""),
        "output should be a JSON plan"
    );
    assert!(stdout.contains("trust-core"));
}

#[test]
fn compliance_report_includes_all_10_frameworks() {
    let bin = env!("CARGO_BIN_EXE_defstack");
    let output = Command::new(bin)
        .args(["compliance-report"])
        .output()
        .expect("run defstack compliance-report");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for fw in [
        "EU-AI-Act-Article-55",
        "NIST-AI-RMF-1.0",
        "ISO-IEC-42001-2023",
        "FedRAMP-AI",
        "OpenSSF-SLSA-v1.0",
        "EU-DORA",
        "AI-Kill-Switch-Act-HR-2026",
        "EU-NIS2",
        "UK-AI-Safety-Bill",
        "China-Generative-AI",
    ] {
        assert!(
            stdout.contains(fw),
            "compliance-report must include framework {fw}"
        );
    }
}
