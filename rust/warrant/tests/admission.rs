//! Admission: what is refused, what is receipted, and what a receipt proves offline.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use warrantor_warrant::admission::{
    manifest_digest, sign_manifest, verify_receipt, AdmissionDecision, AdmissionError,
    AdmissionKind, AdmittedSet, ManifestClaims, SignedManifest, ToolEntry, MANIFEST_FORMAT,
    RECEIPT_FORMAT,
};
use warrantor_warrant::effects::Syscall;
use warrantor_warrant::trust::Directory;

const NOW: u64 = 1_786_000_000;

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn tempdir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-admission-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn entry(effects: &[Syscall]) -> ToolEntry {
    ToolEntry {
        effects: effects.iter().copied().collect(),
        data_classes: ["public".to_string()].into_iter().collect(),
        schema_digest: None,
    }
}

/// The selftest server's manifest: `echo` with the effects given, `now` as a pure attestation.
fn selftest_manifest(echo_effects: &[Syscall]) -> ManifestClaims {
    let mut tools = BTreeMap::new();
    tools.insert("echo".to_string(), entry(echo_effects));
    tools.insert("now".to_string(), entry(&[Syscall::Attest]));
    ManifestClaims {
        format: MANIFEST_FORMAT.to_string(),
        server: "selftest".to_string(),
        kind: AdmissionKind::Tool,
        version: "1.0.0".to_string(),
        issuer: "vendor".to_string(),
        issued_at: NOW,
        expires_at: NOW + 86_400,
        subject_digest: None,
        tools,
    }
}

fn pinned(root: &Path, name: &str, vendor: &SigningKey) -> Directory {
    let mut directory = Directory::load(root).expect("empty");
    directory
        .pin(name, &vendor.verifying_key(), NOW, "test pin")
        .expect("pin");
    directory.save(root).expect("save");
    directory
}

#[test]
fn an_unsigned_manifest_is_refused_and_the_refusal_is_receipted() {
    let root = tempdir("unsigned");
    let vendor = key(7);
    let machine = key(1);
    let directory = pinned(&root, "vendor", &vendor);
    let unsigned = SignedManifest {
        claims: selftest_manifest(&[Syscall::Attest]),
        signature: String::new(),
    };
    let set = AdmittedSet::open(&root);
    let err = set
        .admit(&unsigned, &directory, &machine, NOW + 1)
        .expect_err("unsigned is refused");
    assert_eq!(err, AdmissionError::Unsigned);
    assert!(set.load("selftest").expect("read").is_none(), "nothing was admitted");
    let receipts = set.receipts().expect("ledger");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].claims.decision, AdmissionDecision::Refused);
    assert_eq!(receipts[0].claims.format, RECEIPT_FORMAT);
    verify_receipt(&receipts[0], &machine.verifying_key()).expect("the refusal verifies");
}

#[test]
fn an_unpinned_issuer_is_refused_with_the_pin_command() {
    let root = tempdir("unpinned");
    let vendor = key(7);
    let signed = sign_manifest(selftest_manifest(&[Syscall::Attest]), &vendor);
    let directory = Directory::load(&root).expect("empty");
    let err = AdmittedSet::open(&root)
        .admit(&signed, &directory, &key(1), NOW + 1)
        .expect_err("nobody pinned vendor");
    assert_eq!(err, AdmissionError::UnpinnedIssuer("vendor".to_string()));
    assert!(err.to_string().contains("warrantor issuer add vendor"), "{err}");
}

#[test]
fn a_pinned_signed_manifest_is_admitted_receipted_and_revocable() {
    let root = tempdir("admit");
    let vendor = key(7);
    let machine = key(1);
    let directory = pinned(&root, "vendor", &vendor);
    let signed = sign_manifest(selftest_manifest(&[Syscall::Attest]), &vendor);
    let set = AdmittedSet::open(&root);

    let receipt = set.admit(&signed, &directory, &machine, NOW + 1).expect("admitted");
    assert_eq!(receipt.claims.decision, AdmissionDecision::Admitted);
    assert_eq!(receipt.claims.manifest_digest, manifest_digest(&signed));
    assert_eq!(receipt.claims.issuer_name, "vendor");
    assert_eq!(receipt.claims.issuer_key, hex::encode(vendor.verifying_key().to_bytes()));
    verify_receipt(&receipt, &machine.verifying_key()).expect("verifies");
    assert_eq!(
        verify_receipt(&receipt, &key(2).verifying_key()),
        Err(AdmissionError::Signature)
    );
    assert_eq!(set.load("selftest").expect("read"), Some(signed.clone()));

    let revoked = set
        .revoke("selftest", "operator: vendor advisory", &machine, NOW + 2)
        .expect("revoked");
    assert_eq!(revoked.claims.decision, AdmissionDecision::Revoked);
    assert_eq!(
        set.is_revoked("selftest").expect("read"),
        Some((NOW + 2, "operator: vendor advisory".to_string()))
    );
    assert!(set.load("selftest").expect("read").is_none(), "revoked is not loaded");
    assert!(
        matches!(
            set.admit(&signed, &directory, &machine, NOW + 3),
            Err(AdmissionError::Revoked { .. })
        ),
        "re-presenting the same manifest does not lift a revocation"
    );
    // Three decisions were made (admit, revoke, refused re-admit) and each left exactly one
    // receipt; the plan's draft asserted 4 against its own implementation, which the CLI test's
    // one-refused-admit -> one-receipt invariant rules out.
    assert_eq!(set.receipts().expect("ledger").len(), 3);
}
