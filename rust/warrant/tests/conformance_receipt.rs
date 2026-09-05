use ed25519_dalek::SigningKey;
use warrantor_warrant::conformance::{self, ConformanceStore, CONFORMANCE_RECEIPT_FORMAT};
use warrantor_warrant::stop::{self, EnforcementMode, StopError};

fn issuer() -> SigningKey {
    SigningKey::from_bytes(&[1; 32])
}

fn tempdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("warrantor-conf-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&p).expect("tempdir");
    p
}

#[test]
fn a_drill_on_this_kernel_produces_a_receipt_that_verifies_offline() {
    let dir = tempdir("drill");
    let drill = conformance::drill(&dir).expect("drill");
    assert!(drill.root_gone && drill.descendant_gone, "{drill:?}");
    let signed = conformance::sign_receipt(&drill, &issuer(), 1_786_000_000).expect("sign");
    assert_eq!(signed.format, CONFORMANCE_RECEIPT_FORMAT);
    assert_eq!(signed.receipt.kernel, conformance::kernel_id());
    // The mode is DERIVED from the observation on this kernel. On a machine whose existence
    // checks fit the budget a passing drill earns Enforced; on a slower one it honestly earns
    // Advisory — and the receipt verifies either way, which is the point.
    let expected_mode = conformance::mode_for(&drill);
    assert_eq!(signed.receipt.mode, expected_mode);
    if expected_mode == EnforcementMode::Enforced {
        assert!(drill.within_budget, "{drill:?}");
    }
    conformance::verify_receipt(&signed).expect("verifies");
    // The suite's rule still holds: no elicitation, so no pass-like verdict survives.
    assert!(!signed
        .receipt
        .report
        .report
        .capabilities
        .iter()
        .any(|c| c.verdict.is_pass_like()));
}

#[test]
fn a_receipt_claiming_enforced_without_an_observed_kill_is_refused() {
    let dir = tempdir("forged");
    let mut drill = conformance::drill(&dir).expect("drill");
    drill.descendant_gone = false;
    let signed = conformance::sign_receipt(&drill, &issuer(), 1).expect("sign");
    assert_eq!(
        signed.receipt.mode,
        EnforcementMode::Advisory,
        "sign_receipt derives the mode; it does not accept one"
    );
    let mut forged = signed.clone();
    forged.receipt.mode = EnforcementMode::Enforced;
    assert!(matches!(
        conformance::verify_receipt(&forged),
        Err(StopError::Digest { .. })
    ));
}

#[test]
fn a_stop_is_promoted_only_by_a_verified_receipt_for_this_kernel() {
    let dir = tempdir("promote");
    let store = ConformanceStore::open(&dir).expect("store");
    assert!(store.basis_for_this_kernel().is_none());
    let signed = conformance::sign_receipt(&conformance::drill(&dir).expect("drill"), &issuer(), 7)
        .expect("sign");
    store.save(&signed).expect("save");
    if signed.receipt.mode == EnforcementMode::Enforced {
        let basis = store.basis_for_this_kernel().expect("promoted");
        assert_eq!(basis.receipt_digest, signed.receipt_digest);
    } else {
        // This kernel's drill did not fit the budget (existence-check latency), so nothing is
        // promoted — the honest outcome, not a failure of the drill.
        assert!(store.basis_for_this_kernel().is_none());
    }
    // A receipt for another kernel promotes nothing here.
    let mut elsewhere = signed.clone();
    elsewhere.receipt.kernel = "plan9/none".to_string();
    let other = ConformanceStore::open(tempdir("elsewhere")).expect("store");
    other.save(&elsewhere).expect("save");
    assert!(other.basis_for_this_kernel().is_none());
    let _ = stop::STOP_BUDGET;
}
