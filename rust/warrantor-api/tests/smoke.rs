//! Smoke test for the generated API types — confirms the proto contract plane is consumable.

use warrantor_api::attestation::v1::GpuAttestationReport;
use warrantor_api::identity::v1::AgentAuthorityEnvelope;
use warrantor_api::protocols::v1::AgentActionReceipt;

#[test]
fn generated_types_are_constructible() {
    // Confirms prost generated public types we can name and build.
    let _envelope = AgentAuthorityEnvelope {
        issuer: "spiffe://warrantor.dev/agent-identity".into(),
        subject: "spiffe://warrantor.dev/agent/x".into(),
        purpose: "smoke test".into(),
        ..Default::default()
    };

    let _receipt = AgentActionReceipt {
        id: "receipt-1".into(),
        actor: "spiffe://warrantor.dev/agent/x".into(),
        ..Default::default()
    };
}

#[test]
fn gpu_attestation_report_round_trips() {
    let report = GpuAttestationReport {
        gpu_model: "mock-H100".into(),
        attestation_bytes: b"warrantor-mock".to_vec(),
        nonce: vec![0u8; 16],
        ..Default::default()
    };
    assert_eq!(report.gpu_model, "mock-H100");
    assert_eq!(report.attestation_bytes, b"warrantor-mock");
    assert_eq!(report.nonce.len(), 16);
}
