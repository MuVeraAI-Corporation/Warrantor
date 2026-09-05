//! Report-bundle tests: what the evidence says, what it refuses to say, and what a third party
//! can check without this machine.
//!
//! The tests that matter here are the honesty ones. A signed bundle is only worth having if a
//! tampered one is refused and an over-claiming one cannot be produced in the first place — so
//! every gate that can deny has a test that makes it deny on real data, every field binding a
//! receipt to the bundle has a test that breaks it, and the enforcement modes are pinned so a
//! later edit cannot quietly upgrade `advisory` to `mediated`.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use warrantor_warrant::report::{
    build, bundle_digest, notary_mode_for, render_cli, render_mcp, report_modes, verify_export,
    verify_export_at, ChangedSection, ReportError, SignedReport, StagedSection,
    REPORT_BUNDLE_FORMAT, REPORT_EXPORT_FORMAT,
};
use warrantor_warrant::staging::{EffectRegistry, StagingQueue};
use warrantor_warrant::store::StoredWarrant;
use warrantor_warrant::{
    bound_strengths, BoundStrength, SideEffectClass, Warrant, WarrantBounds, WarrantState,
};

const NOW: u64 = 1_786_000_000;

fn tempdir(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-report-{tag}-{}",
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

fn settle_key() -> SigningKey {
    SigningKey::from_bytes(&[2; 32])
}

fn bounds(expires_at: u64) -> WarrantBounds {
    WarrantBounds {
        tools: ["github.create_pr".to_string(), "git".to_string()]
            .into_iter()
            .collect(),
        write_paths: ["src/**".to_string()].into_iter().collect(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at,
        budget_cents_observed: Some(500),
        delegation_depth: 3,
    }
}

fn stored_with(expires_at: u64, state: WarrantState) -> StoredWarrant {
    let mut warrant = Warrant::grant(
        "wrt_report",
        "fix the auth token refresh bug",
        "spiffe://muveraai.com/agent/alpha",
        bounds(expires_at),
        NOW,
        &settle_key().verifying_key(),
        &issuer(),
    )
    .expect("grant");
    warrant.state = state;
    StoredWarrant {
        warrant,
        worktree: None,
        repo: None,
        branch: None,
        base_commit: None,
        staged_chain: None,
    }
}

fn stored() -> StoredWarrant {
    stored_with(NOW + 3600, WarrantState::Open)
}

fn queue_at(dir: &std::path::Path) -> StagingQueue {
    StagingQueue::open(dir.join("q.jsonl"), "wrt_report", EffectRegistry::github())
        .expect("open queue")
}

fn args(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn signed_report(dir: &std::path::Path) -> SignedReport {
    let queue = queue_at(dir);
    build(&stored(), Ok(&queue), &issuer().verifying_key(), NOW)
        .sign(&issuer(), "issuer")
        .expect("sign")
}

// ── the format version, from day one ──────────────────────────────────────────────────

/// A signed artifact with no version is a migration you cannot perform: the day the shape changes,
/// every previously exported bundle becomes indistinguishable from a corrupt one.
#[test]
fn the_bundle_and_the_export_both_carry_a_format_version() {
    let dir = tempdir("format");
    let signed = signed_report(&dir);
    assert_eq!(signed.bundle.format, REPORT_BUNDLE_FORMAT);
    assert_eq!(signed.format, REPORT_EXPORT_FORMAT);
}

#[test]
fn an_export_from_an_unknown_format_is_refused_rather_than_guessed_at() {
    let dir = tempdir("badformat");
    let mut signed = signed_report(&dir);
    signed.format = "warrantor.report-export/99".to_string();
    assert!(
        matches!(verify_export(&signed), Err(ReportError::Format { .. })),
        "a future format must be refused, not parsed hopefully"
    );

    let mut signed = signed_report(&dir);
    signed.bundle.format = "warrantor.report-bundle/99".to_string();
    assert!(matches!(
        verify_export(&signed),
        Err(ReportError::Format { .. })
    ));
}

// ── the human output is unchanged ─────────────────────────────────────────────────────

/// Signing is additive. The five sections a developer reads every morning are byte for byte what
/// they were before there was a bundle behind them.
///
/// The one intentional change to this golden output: `write_paths` now renders as `observed`.
/// That is not a relaxation of the report -- it is the report ceasing to state something untrue.
/// Nothing in the codebase refuses an out-of-bounds write, and a live run demonstrated it by
/// writing outside its declared paths unchallenged. Everything else here is byte for byte as it was.
///
/// The second: three legend lines under BOUNDS, so the tier column carries what each tier does
/// not cover (Task 0.4).
#[test]
fn the_prose_report_is_exactly_what_it_always_was() {
    let dir = tempdir("prose");
    let mut queue = queue_at(&dir);
    let pr = queue
        .stage("github.create_pr", args(&[("title", "Fix auth")]), NOW)
        .expect("stage");

    let built = build(&stored(), Ok(&queue), &issuer().verifying_key(), NOW);
    let text = render_cli(built.bundle());

    let expected = format!(
        "WARRANT wrt_report  —  \"fix the auth token refresh bug\"\n\
         state: Open\n\
         \n\
         ── AWAITING YOU ──\n\
         \x20 {:<36}  github.create_pr\n\
         \x20     title: Fix auth\n\
         \n\
         ── BOUNDS ──\n\
         \x20 tools                   mediated\n\
         \x20 write_paths             observed\n\
         \x20 egress_hosts            mediated\n\
         \x20 staged_classes          mediated\n\
         \x20 expires_at              enforced\n\
         \x20 delegation_depth        enforced\n\
         \x20 budget_cents_observed   observed\n\
         \x20 enforced  held by cryptography or the operating system; holds against an agent that tries to route around it\n\
         \x20 mediated  held only for calls that traverse the MCP proxy; a shell or a harness built-in reaches past it, and no netns, seccomp or firewall stands behind it\n\
         \x20 observed  measured and reported after the fact; nothing refuses the action as it happens\n\
         \n\
         ── EVIDENCE ──\n\
         \x20 1 staged effect(s)\n\
         \x20 chain head {}\n",
        pr.handle,
        queue.head_digest()
    );
    assert_eq!(text, expected, "the prose report must not have changed");
}

#[test]
fn an_empty_queue_still_says_nothing_staged() {
    let dir = tempdir("empty");
    let queue = queue_at(&dir);
    let built = build(&stored(), Ok(&queue), &issuer().verifying_key(), NOW);
    let text = render_cli(built.bundle());
    assert!(
        text.contains("── AWAITING YOU ──\n  nothing staged\n"),
        "{text}"
    );
    assert!(text.contains("  0 staged effect(s)\n"), "{text}");
}

/// The MCP control endpoint renders from the same bundle. Before, it was a separate
/// implementation that had already drifted; a divergence now is a test failure, not a surprise.
#[test]
fn the_mcp_rendering_comes_from_the_same_bundle() {
    let dir = tempdir("mcp");
    let mut queue = queue_at(&dir);
    queue
        .stage("github.create_pr", args(&[("title", "Fix auth")]), NOW)
        .expect("stage");
    let built = build(&stored(), Ok(&queue), &issuer().verifying_key(), NOW);
    let text = render_mcp(built.bundle());

    assert!(text.starts_with("Warrant wrt_report — Open\n  goal: fix the auth token refresh bug"));
    assert!(
        text.contains("staged effects (1) — NOT yet performed, in release order:"),
        "{text}"
    );
    assert!(
        !text.contains("changed files"),
        "no worktree means no changed-files section: {text}"
    );
}

// ── round trip: a third party verifies it offline ─────────────────────────────────────

/// The whole point. Serialise the export, throw everything else away, verify from the bytes.
#[test]
fn an_exported_report_verifies_from_its_bytes_alone() {
    let dir = tempdir("roundtrip");
    let signed = signed_report(&dir);
    let json = serde_json::to_vec_pretty(&signed).expect("serialise");

    let parsed: SignedReport = serde_json::from_slice(&json).expect("parse");
    verify_export(&parsed).expect("an untouched export must verify");

    assert_eq!(
        parsed.bundle_digest,
        bundle_digest(&parsed.bundle).expect("digest"),
        "the digest in the file must be the digest of the bundle in the file"
    );
}

#[test]
fn the_bundle_digest_is_stable_across_a_serialisation_round_trip() {
    let dir = tempdir("stable");
    let signed = signed_report(&dir);
    let json = serde_json::to_vec(&signed).expect("serialise");
    let parsed: SignedReport = serde_json::from_slice(&json).expect("parse");
    assert_eq!(
        bundle_digest(&signed.bundle).expect("a"),
        bundle_digest(&parsed.bundle).expect("b"),
    );
}

// ── tampering ─────────────────────────────────────────────────────────────────────────

/// Change the story, and the digest the receipts commit to no longer matches.
#[test]
fn editing_the_bundle_breaks_the_digest() {
    let dir = tempdir("tamper-goal");
    let mut signed = signed_report(&dir);
    signed.bundle.goal = "exfiltrate the credentials".to_string();
    assert!(
        matches!(verify_export(&signed), Err(ReportError::Digest { .. })),
        "an edited bundle must not verify"
    );
}

/// The obvious next move: edit the bundle AND recompute the digest so the two agree. The Ed25519
/// signature over the predicate is what stops that.
#[test]
fn editing_the_bundle_and_re_digesting_it_still_fails() {
    let dir = tempdir("tamper-redigest");
    let mut signed = signed_report(&dir);
    signed.bundle.goal = "exfiltrate the credentials".to_string();
    signed.bundle_digest = bundle_digest(&signed.bundle).expect("digest");

    match verify_export(&signed) {
        Err(ReportError::Binding(_)) => {}
        other => panic!("a re-digested forgery must be refused, got {other:?}"),
    }
}

/// A bound quietly widened after the fact is the tamper that would matter most.
#[test]
fn widening_a_bound_after_signing_is_detected() {
    let dir = tempdir("tamper-bound");
    let mut signed = signed_report(&dir);
    signed
        .bundle
        .bounds
        .egress_hosts
        .insert("evil.example.com".to_string());
    assert!(matches!(
        verify_export(&signed),
        Err(ReportError::Digest { .. })
    ));
}

/// Relabelling an observed bound as enforced would make the report claim a guarantee the system
/// does not provide. It is inside the signed digest, so it cannot be done after the fact.
#[test]
fn upgrading_an_observed_bound_to_enforced_is_detected() {
    let dir = tempdir("tamper-strength");
    let mut signed = signed_report(&dir);
    for bound in &mut signed.bundle.bound_strengths {
        if bound.name == "budget_cents_observed" {
            bound.strength = BoundStrength::Enforced;
        }
    }
    assert!(matches!(
        verify_export(&signed),
        Err(ReportError::Digest { .. })
    ));
}

/// Two receipts, one signer. Otherwise a receipt lifted from another report and signed by another
/// key would pass its own verification and ride along.
#[test]
fn receipts_signed_by_different_keys_are_refused() {
    let dir = tempdir("twokeys");
    let queue = queue_at(&dir);
    let built = build(&stored(), Ok(&queue), &issuer().verifying_key(), NOW);
    let mine = built.sign(&issuer(), "issuer").expect("sign");
    let theirs = built
        .sign(&SigningKey::from_bytes(&[9; 32]), "issuer")
        .expect("sign");

    let mut mixed = mine;
    mixed.notary_receipt = theirs.notary_receipt;
    match verify_export(&mixed) {
        Err(ReportError::Binding(reason)) => {
            assert!(reason.contains("different keys"), "{reason}");
        }
        other => panic!("mixed signers must be refused, got {other:?}"),
    }
}

#[test]
fn a_receipt_naming_a_different_warrant_is_refused() {
    let dir = tempdir("wrong-target");
    let mut signed = signed_report(&dir);
    signed.evidence_receipt.predicate.operation.target = "wrt_someone_else".to_string();
    // Retargeting also invalidates the signature; either refusal is correct, both are refusals.
    assert!(verify_export(&signed).is_err());
}

/// The bundle says allow, the signed verdict says deny. The prose a human reads must never be
/// able to disagree with the proof attached to it.
#[test]
fn a_bundle_that_disagrees_with_its_signed_verdict_is_refused() {
    let dir = tempdir("disagree");
    let mut signed = signed_report(&dir);
    signed.bundle.authority_check.allowed = !signed.bundle.authority_check.allowed;
    assert!(verify_export(&signed).is_err());
}

// ── enforcement-mode honesty ──────────────────────────────────────────────────────────

/// `warrantor-evidence` and `warrantor-notary` disagree on the vocabulary — {Mediated, Advisory}
/// against {Observed, Mediated} — and neither maps onto BoundStrength by a cast. The mapping is
/// pinned here so a later edit cannot quietly upgrade it.
#[test]
fn a_report_claims_the_weaker_enforcement_mode_in_both_vocabularies() {
    use warrantor_evidence::EnforcementMode as EvidenceMode;
    use warrantor_notary::EnforcementMode as NotaryMode;

    let (evidence_mode, notary_mode) = report_modes();
    assert_eq!(
        evidence_mode,
        EvidenceMode::Advisory,
        "warrantor does not mediate an agent that bypasses its proxy; there is no netns, seccomp \
         or firewall anywhere in this system"
    );
    assert_eq!(notary_mode, NotaryMode::Observed);

    let dir = tempdir("modes");
    let signed = signed_report(&dir);
    assert_eq!(
        signed.evidence_receipt.predicate.binding.enforcement_mode,
        EvidenceMode::Advisory
    );
    assert_eq!(
        signed.notary_receipt.body.enforcement_mode,
        NotaryMode::Observed
    );
}

/// The evidence crate's own honesty check, run against our receipt: an advisory receipt must not
/// be able to assert non-bypassability.
#[test]
fn the_report_receipt_cannot_assert_non_bypassability() {
    let dir = tempdir("nonbypass");
    let signed = signed_report(&dir);
    assert!(
        warrantor_evidence::check_mode_honesty(&signed.evidence_receipt, true).is_err(),
        "a report receipt must not be usable to claim the decision cannot be bypassed"
    );
    warrantor_evidence::check_mode_honesty(&signed.evidence_receipt, false)
        .expect("claiming nothing is always fine");
}

/// A receipt that has been edited to claim `mediated` is refused even before the signature check
/// would catch it, so the reason a reader sees names the escalation rather than the byte diff.
#[test]
fn a_receipt_upgraded_to_mediated_is_refused_as_an_escalation() {
    let dir = tempdir("escalate");
    let mut signed = signed_report(&dir);
    signed.evidence_receipt.predicate.binding.enforcement_mode =
        warrantor_evidence::EnforcementMode::Mediated;
    match verify_export(&signed) {
        Err(ReportError::Mode(_)) | Err(ReportError::Evidence(_)) => {}
        other => panic!("a mediated claim must be refused, got {other:?}"),
    }
}

// ── the two vocabularies, mapped once ─────────────────────────────────────────────────

/// `advisory` and `observed` are the same state under two crates' names, and `mediated` is the
/// same in both. The mapping only ever maps a mode onto its equal — a report cannot be made to
/// look stronger by being restated in the other vocabulary.
#[test]
fn the_two_enforcement_vocabularies_map_onto_each_other_without_upgrading() {
    use warrantor_evidence::EnforcementMode as EvidenceMode;
    use warrantor_notary::EnforcementMode as NotaryMode;

    assert_eq!(
        notary_mode_for(EvidenceMode::Advisory),
        NotaryMode::Observed
    );
    assert_eq!(
        notary_mode_for(EvidenceMode::Mediated),
        NotaryMode::Mediated
    );
}

/// The pair `report_modes` returns is derived, not stated twice, so the notary receipt cannot end
/// up claiming a mode the evidence receipt on the same report contradicts.
#[test]
fn the_notary_mode_on_a_report_is_derived_from_the_evidence_mode() {
    let (evidence_mode, notary_mode) = report_modes();
    assert_eq!(notary_mode, notary_mode_for(evidence_mode));

    let dir = tempdir("modepair");
    let signed = signed_report(&dir);
    assert_eq!(
        signed.notary_receipt.body.enforcement_mode,
        notary_mode_for(signed.evidence_receipt.predicate.binding.enforcement_mode),
        "the two receipts on one report must describe the same enforcement fact"
    );
}

// ── the two DelegationLinks, built from one warrant ───────────────────────────────────

/// Both crates export a `DelegationLink` and `build` constructs one of each from the same warrant,
/// about eighty lines apart. Only the evidence link survives into the export, so that is what is
/// pinned: if it drifts from the warrant's real window or tools, the notary is deciding against a
/// delegation the signed receipt does not record.
#[test]
fn the_exported_delegation_link_describes_the_warrant_it_was_built_from() {
    let dir = tempdir("deleglink");
    let signed = signed_report(&dir);
    let chain = &signed.evidence_receipt.predicate.authority.chain;
    assert_eq!(chain.len(), 1, "one warrant, one link");
    let link = &chain[0];

    assert_eq!(link.subject, signed.bundle.subject);
    assert_eq!(link.not_before, signed.bundle.issued_at);
    assert_eq!(
        link.not_after, signed.bundle.expires_at,
        "the link's window is the warrant's deadline — the same value the notary's identity gate \
         is given as svid_not_after"
    );
    let mut delegated = link.capabilities.clone();
    delegated.sort();
    let mut granted: Vec<String> = signed.bundle.bounds.tools.iter().cloned().collect();
    granted.sort();
    assert_eq!(
        delegated, granted,
        "the link must delegate exactly the warrant's tools — no more, and no fewer"
    );
}

// ── expiry: the receipt's own deadline ────────────────────────────────────────────────

/// `warrantor-evidence` declared `EvidenceError::Expired` and never constructed it, so the
/// receipt's `expires_at` was a field nothing read. This is the check that now reads it.
#[test]
fn a_report_whose_warrant_has_expired_is_reported_as_expired() {
    let dir = tempdir("expired");
    let signed = signed_report(&dir);
    let deadline = signed.bundle.expires_at;
    match verify_export_at(&signed, deadline + 1) {
        Err(ReportError::Expired { expires_at, now }) => {
            assert_eq!(expires_at, deadline);
            assert_eq!(now, deadline + 1);
        }
        other => panic!("past the deadline the report is not live, got {other:?}"),
    }
}

#[test]
fn a_report_inside_the_warrants_deadline_is_live() {
    let dir = tempdir("live");
    let signed = signed_report(&dir);
    verify_export_at(&signed, signed.bundle.expires_at - 1).expect("still inside the window");
}

/// The deadline second itself is already past, matching the notary's identity gate, which denies
/// at `svid_not_after <= now`. A boundary second goes to the refusing side in both places.
#[test]
fn the_deadline_second_is_already_expired() {
    let dir = tempdir("deadline");
    let signed = signed_report(&dir);
    assert!(verify_export_at(&signed, signed.bundle.expires_at).is_err());
}

/// The archival path must not rot. An exported report records a decision that was taken; it stays
/// verifiable forever, because "this happened" does not stop being true.
#[test]
fn an_expired_report_still_verifies_as_a_record_of_what_happened() {
    let dir = tempdir("archive");
    let signed = signed_report(&dir);
    verify_export(&signed).expect("integrity has no deadline");
    assert!(
        verify_export_at(&signed, u64::MAX).is_err(),
        "…but liveness does"
    );
}

/// Staleness and tampering want opposite responses from a reader, so they must not arrive as the
/// same error. A tampered file is reported as tampered even when it is also expired.
#[test]
fn a_tampered_expired_report_is_reported_as_tampered_not_as_stale() {
    let dir = tempdir("tampered_expired");
    let mut signed = signed_report(&dir);
    signed.bundle.goal = "something else entirely".to_string();
    match verify_export_at(&signed, u64::MAX) {
        Err(ReportError::Digest { .. }) => {}
        other => panic!("integrity is checked before the clock, got {other:?}"),
    }
}

// ── the nine gates, on real data ──────────────────────────────────────────────────────

#[test]
fn an_open_in_bounds_warrant_is_allowed() {
    let dir = tempdir("allow");
    let mut queue = queue_at(&dir);
    queue
        .stage("github.create_pr", args(&[("title", "Fix")]), NOW)
        .expect("stage");
    let built = build(&stored(), Ok(&queue), &issuer().verifying_key(), NOW);
    let check = &built.bundle().authority_check;
    assert!(check.allowed, "denied at {:?}", check.denied_gate);
    assert_eq!(check.denied_gate, None);
    assert_eq!(
        check.capabilities_requested,
        vec!["github.create_pr".to_string()]
    );
}

/// The gate that earns its keep. `warrantor stage` does not check the tool allowlist, so an effect
/// can be staged for a tool the warrant never held — and until now nothing noticed before settle.
#[test]
fn an_effect_staged_for_a_tool_outside_the_warrant_denies_at_the_authority_gate() {
    let dir = tempdir("deny-authority");
    let mut queue = queue_at(&dir);
    queue
        .stage("github.comment", args(&[("body", "hello")]), NOW)
        .expect("stage");

    // `github.comment` is not in this warrant's tools.
    let built = build(&stored(), Ok(&queue), &issuer().verifying_key(), NOW);
    let check = &built.bundle().authority_check;
    assert!(!check.allowed);
    assert_eq!(check.denied_gate.as_deref(), Some("authority"));
}

#[test]
fn an_expired_warrant_denies_at_the_identity_gate() {
    let dir = tempdir("deny-identity");
    let queue = queue_at(&dir);
    let stored = stored_with(NOW - 1, WarrantState::Open);
    let built = build(&stored, Ok(&queue), &issuer().verifying_key(), NOW);
    let check = &built.bundle().authority_check;
    assert!(!check.allowed);
    assert_eq!(
        check.denied_gate.as_deref(),
        Some("identity"),
        "past its deadline the subject holds nothing"
    );
}

/// The trust anchor is the issuer key on disk, not the key the warrant carries about itself.
#[test]
fn a_warrant_signed_by_another_key_denies_at_the_chain_gate() {
    let dir = tempdir("deny-chain");
    let queue = queue_at(&dir);
    let stranger = SigningKey::from_bytes(&[7; 32]);
    let built = build(&stored(), Ok(&queue), &stranger.verifying_key(), NOW);
    let check = &built.bundle().authority_check;
    assert!(!check.allowed);
    assert_eq!(check.denied_gate.as_deref(), Some("chain"));
}

#[test]
fn a_settled_warrant_denies_at_the_policy_gate() {
    let dir = tempdir("deny-policy");
    let queue = queue_at(&dir);
    let stored = stored_with(NOW + 3600, WarrantState::Settled);
    let built = build(&stored, Ok(&queue), &issuer().verifying_key(), NOW);
    let check = &built.bundle().authority_check;
    assert!(!check.allowed);
    assert_eq!(
        check.denied_gate.as_deref(),
        Some("policy"),
        "a warrant that is no longer open authorises nothing"
    );
}

/// Indeterminate is denial. An unreadable staging queue means we do not know what is pending, and
/// guessing "nothing" would be the fail-open answer.
#[test]
fn an_unreadable_staging_queue_denies_rather_than_assuming_nothing_is_pending() {
    let built = build(
        &stored(),
        Err("queue chain broken at line 3".to_string()),
        &issuer().verifying_key(),
        NOW,
    );
    let bundle = built.bundle();
    assert!(!bundle.authority_check.allowed);
    assert_eq!(
        bundle.authority_check.denied_gate.as_deref(),
        Some("policy")
    );
    assert_eq!(bundle.staged_count, None, "an unknown count is not zero");
    assert_eq!(bundle.chain_head, None);
    assert!(matches!(bundle.staged, StagedSection::Unavailable { .. }));

    // And it still signs and verifies: a denial is evidence too.
    let signed = built.sign(&issuer(), "issuer").expect("sign");
    verify_export(&signed).expect("a deny bundle is still verifiable");
}

/// The EVIDENCE section must not launder an unknown count into a confident zero. `0 staged
/// effect(s)` above an empty chain head is exactly what a clean, empty queue prints, so a reader
/// of the unreadable-queue report would conclude nothing is pending when in fact nobody knows
/// what is pending.
#[test]
fn an_unreadable_queue_renders_an_unknown_count_not_a_zero() {
    let built = build(
        &stored(),
        Err("queue chain broken at line 3".to_string()),
        &issuer().verifying_key(),
        NOW,
    );
    let text = render_cli(built.bundle());

    assert!(
        !text.contains("0 staged effect(s)"),
        "an unreadable queue must not render as a confident zero: {text}"
    );
    assert!(
        text.contains("  staged effect count UNKNOWN — the staging queue could not be read\n"),
        "{text}"
    );
    assert!(
        !text.contains("  chain head \n"),
        "an unknown chain head must not render as a blank one: {text}"
    );
    assert!(
        text.contains("  chain head UNKNOWN — the staging queue could not be read\n"),
        "{text}"
    );
}

// ── what the bundle refuses to claim ──────────────────────────────────────────────────

/// A signed artifact whose caveats are implicit teaches the reader to hear more than was said.
#[test]
fn the_bundle_always_carries_its_limitations() {
    let dir = tempdir("limits");
    let signed = signed_report(&dir);
    let limitations = &signed.bundle.limitations;
    assert!(!limitations.is_empty());

    let all = limitations.join("\n");
    assert!(
        all.contains("MCP proxy") && all.contains("seccomp"),
        "the egress caveat must survive: wiring evidence changed nothing about where egress is \
         enforced. {all}"
    );
    assert!(
        all.contains("budget_cents_observed"),
        "the budget caveat must survive: {all}"
    );
    assert!(
        all.contains("kill switch"),
        "the containment gate passes because nothing is wired to it, and that must be said: {all}"
    );
    assert!(
        all.contains("does not establish that the signing key is trusted"),
        "verification proves who signed, not that they should be believed: {all}"
    );
}

/// Wiring the evidence and notary planes must not relabel a single bound. The report copies
/// `bound_strengths()` verbatim.
#[test]
fn bound_strengths_are_copied_verbatim_and_nothing_is_upgraded() {
    let dir = tempdir("strengths");
    let signed = signed_report(&dir);
    let expected: Vec<(String, BoundStrength)> = bound_strengths()
        .into_iter()
        .map(|(name, strength)| (name.to_string(), strength))
        .collect();
    let actual: Vec<(String, BoundStrength)> = signed
        .bundle
        .bound_strengths
        .iter()
        .map(|b| (b.name.clone(), b.strength))
        .collect();
    assert_eq!(actual, expected);

    let budget = signed
        .bundle
        .bound_strengths
        .iter()
        .find(|b| b.name == "budget_cents_observed")
        .expect("budget bound is listed");
    assert_eq!(
        budget.strength,
        BoundStrength::Observed,
        "the agent talks to its model provider directly; signing a report does not change that"
    );
}

/// The report observes no spend, so it reports none. An unmeasured number in an evidence bundle
/// is worse than a missing one.
#[test]
fn no_spend_figure_is_invented() {
    let dir = tempdir("nospend");
    let signed = signed_report(&dir);
    let json = serde_json::to_string(&signed).expect("serialise");
    assert!(
        !json.contains("usd_spent") && !json.contains("spend_"),
        "nothing here measures spend, so nothing here may report it"
    );
    assert_eq!(
        signed.bundle.bounds.budget_cents_observed,
        Some(500),
        "the declared ceiling is reported as declared, which is all it is"
    );
}

/// A sub-warrant's parent is named, never silently treated as verified.
#[test]
fn an_unverified_parent_chain_is_declared_as_a_fragment() {
    let dir = tempdir("parent");
    let queue = queue_at(&dir);
    let parent = Warrant::grant(
        "wrt_parent",
        "the parent task",
        "spiffe://muveraai.com/agent/parent",
        bounds(NOW + 7200),
        NOW,
        &settle_key().verifying_key(),
        &issuer(),
    )
    .expect("grant parent");
    let mut child_bounds = bounds(NOW + 3600);
    child_bounds.delegation_depth = 2;
    let child = parent
        .delegate(
            "wrt_child",
            "the child task",
            "spiffe://muveraai.com/agent/child",
            child_bounds,
            NOW,
            &issuer(),
        )
        .expect("delegate");
    let stored = StoredWarrant {
        warrant: child,
        worktree: None,
        repo: None,
        branch: None,
        base_commit: None,
        staged_chain: None,
    };

    let built = build(&stored, Ok(&queue), &issuer().verifying_key(), NOW);
    let bundle = built.bundle();
    assert_eq!(bundle.parent.as_deref(), Some("wrt_parent"));
    assert!(
        bundle
            .limitations
            .iter()
            .any(|l| l.contains("wrt_parent") && l.contains("not fetched or verified")),
        "the chain is a fragment and must say so: {:?}",
        bundle.limitations
    );

    let signed = built.sign(&issuer(), "issuer").expect("sign");
    verify_export(&signed).expect("a fragment chain still verifies as what it is");
}

/// The evidence receipt's authority block must recompute — the intersection proof is built from
/// the chain, never asserted alongside it.
#[test]
fn the_authority_intersection_recomputes_from_the_chain() {
    let dir = tempdir("intersect");
    let signed = signed_report(&dir);
    let authority = &signed.evidence_receipt.predicate.authority;
    warrantor_evidence::verify_authority(authority).expect("intersection recomputes");
    assert_eq!(
        authority.effective_capabilities,
        warrantor_evidence::recompute_intersection(&authority.chain)
    );
    assert_eq!(
        authority.effective_capabilities,
        vec!["git".to_string(), "github.create_pr".to_string()],
        "the effective capabilities are the warrant's own tools, sorted"
    );
}

/// A widened capability list in the receipt is authority expansion, and the evidence crate exists
/// to refuse exactly that.
#[test]
fn expanding_the_receipts_capabilities_is_refused() {
    let dir = tempdir("expand");
    let mut signed = signed_report(&dir);
    signed
        .evidence_receipt
        .predicate
        .authority
        .effective_capabilities
        .push("github.merge".to_string());
    assert!(verify_export(&signed).is_err(), "authority may not expand");
}

// ── worktree section shapes ───────────────────────────────────────────────────────────

/// A worktree git cannot read is reported as unreadable rather than as "no files changed".
#[test]
fn an_unreadable_worktree_is_reported_as_unreadable_not_as_clean() {
    let dir = tempdir("worktree");
    let queue = queue_at(&dir);
    let mut stored = stored();
    stored.repo = Some(dir.join("not-a-repo"));
    stored.worktree = Some(dir.join("not-a-worktree"));

    let built = build(&stored, Ok(&queue), &issuer().verifying_key(), NOW);
    let bundle = built.bundle();
    match &bundle.changed {
        Some(ChangedSection::Unreadable { reason }) => assert!(!reason.is_empty()),
        other => panic!("expected an unreadable worktree, got {other:?}"),
    }
    let text = render_cli(bundle);
    assert!(
        text.contains("── IT CHANGED ──\n  (worktree unreadable:"),
        "{text}"
    );
}

// ── the custody section, and the round-trip invariant it rests on ─────────────────────

/// An absent custody section must survive the canonical round trip **as absent**.
///
/// `bundle_digest` hashes a *re-serialisation* of the parsed bundle, not the bytes on disk. So a
/// field that serialises as `"custody": null` when it is `None` changes the digest of every export
/// written before the field existed, and every one of those reports stops verifying — on a surface
/// whose entire purpose is that old evidence keeps checking out.
///
/// `skip_serializing_if` is what prevents it, and this test is what keeps the attribute there: it
/// is one word, it looks decorative beside `default`, and removing it breaks nothing that any other
/// test observes.
#[test]
fn an_absent_custody_section_does_not_appear_in_the_canonical_bundle() {
    let dir = tempdir("custody-absent");
    let queue = queue_at(&dir);
    let built = warrantor_warrant::report::build_observed(
        &stored(),
        Ok(&queue),
        &issuer().verifying_key(),
        NOW,
        &[],
        None,
        None,
    );
    let canonical = warrantor_warrant::report::canonical_bundle(built.bundle()).expect("canonical");
    assert!(
        !canonical.contains("custody"),
        "an absent section must not appear at all, or every pre-existing export changes digest"
    );
}

/// A present custody section is inside the signature, exactly as much as any other field.
#[test]
fn a_custody_section_is_covered_by_the_bundle_digest() {
    let dir = tempdir("custody-signed");
    let queue = queue_at(&dir);
    let section = warrantor_warrant::report::CustodySection {
        acts: 2,
        head: Some("abc".to_string()),
        chain_intact: true,
        approvers: 2,
        approvals_required: 2,
    };
    let built = warrantor_warrant::report::build_observed(
        &stored(),
        Ok(&queue),
        &issuer().verifying_key(),
        NOW,
        &[],
        None,
        Some(section.clone()),
    );
    let before = warrantor_warrant::report::bundle_digest(built.bundle()).expect("digest");

    let mut edited = built.bundle().clone();
    edited.custody = Some(warrantor_warrant::report::CustodySection {
        approvers: 99,
        ..section
    });
    let after = warrantor_warrant::report::bundle_digest(&edited).expect("digest");
    assert_ne!(
        before, after,
        "editing who approved must change the digest, or putting it here bought nothing"
    );

    // And the limitations say what the section does and does not establish.
    assert!(
        built
            .bundle()
            .limitations
            .iter()
            .any(|l| l.contains("head digest") && l.contains("carries no operator names")),
        "{:?}",
        built.bundle().limitations
    );
}

/// A broken actor chain is reported in the limitations, not turned into a refusal.
///
/// Refusing to report on a warrant whose actor log has been edited is how a broken chain hides: the
/// evidence is unaffected — signatures are checked separately — and the reader needs both facts.
#[test]
fn a_broken_actor_chain_is_said_rather_than_refused() {
    let dir = tempdir("custody-broken");
    let queue = queue_at(&dir);
    let built = warrantor_warrant::report::build_observed(
        &stored(),
        Ok(&queue),
        &issuer().verifying_key(),
        NOW,
        &[],
        None,
        Some(warrantor_warrant::report::CustodySection {
            acts: 3,
            head: Some("abc".to_string()),
            chain_intact: false,
            approvers: 1,
            approvals_required: 2,
        }),
    );
    let said = built
        .bundle()
        .limitations
        .iter()
        .find(|l| l.contains("does NOT verify"))
        .expect("the broken chain must be stated");
    assert!(
        said.contains("evidence in this bundle is unaffected"),
        "{said}"
    );
}
