//! I-05 — Revocation latency is bounded.
//!
//! > Identity revocation (I1) propagates to all replicas in <5s; credential revocation (R4) in
//! > <1s.
//!
//! The IDENTITY half is now reachable from the product and does not propagate beyond this process.
//! The credential half is not: its 1-second budget is still compared only inside `Vault::revoke` and
//! `Vault::revoke_all`, which no shipped path calls, so linking the crate bought its journal FORMAT
//! and not its budget. Between 2026-09-05 and the correction later that day this header said "both
//! halves", which overstated the credential side.
//!
//! Until 2026-09-05 this header said the opposite of even that, and it was true: the credential side
//! lived in `rust/credential-vault`, which the `warrantor` binary did not link, and the identity side
//! had no implementation at all — `revoked_svids` is a `Vec<String>` the caller supplies and the one
//! caller supplied an empty one. Task 9.1 linked that crate and wrote `warrantor_warrant::revoke`,
//! which reads its `fsync`'d journal, so the product's own notary call consults a real revocation
//! source.
//!
//! **What that changes, precisely.** The refusal is Tier B, a chokepoint: `notary::verdict` returns
//! `Deny { gate: Identity }` for a revoked subject. The *propagation* claim stays Tier C, observed:
//! there is no fan-out, no broker and no replica set, so "propagates to all replicas in <5s" is
//! measured against one replica, and `rust/warrant/tests/revocation_latency.rs` is where that
//! measurement lives and where a breach fails rather than being logged.
//!
//! Within a single decision the latency is zero, which is what the runtime checks below establish.
//! That is a real property, and on its own it is not the property I-05 states — a revocation nobody
//! delivers propagates in no time to no one. What makes it a property of the product rather than of
//! the corpus is `rust/warrant/tests/revocation.rs`, which drives `report::build_observed` and
//! asserts the refusal against an allowed control.

use crate::{fixture, harness, scenario};
use warrantor_notary as notary;

// -- static ---------------------------------------------------------------------------

#[test]
fn the_credential_revocation_budget_is_declared_as_one_second() {
    assert_eq!(fixture::invariant("I-05").id, "I-05");
    harness::source_contains(
        "rust/credential-vault/src/lib.rs",
        "pub const REVOKE_BUDGET: Duration = Duration::from_secs(1);",
        "I-05's credential half is a number, and this constant is the only place it is written \
         as code rather than as prose.",
    );
    harness::source_contains(
        "rust/credential-vault/src/lib.rs",
        "a revoked credential MUST stay revoked across a restart (I-05)",
        "The durability half of revocation: a vault that forgets on restart has an unbounded \
         effective latency.",
    );
}

// -- runtime --------------------------------------------------------------------------

#[test]
fn a_revocation_is_effective_within_the_decision_that_sees_it() {
    let mut context = scenario::allowed_context();
    context.revoked_svids = vec![scenario::SUBJECT.to_string()];
    let verdict = notary::verdict(&scenario::allowed_request(), &context);
    scenario::assert_denied_at(&verdict, notary::Gate::Identity, "a revoked SVID");
}

// -- adversarial ----------------------------------------------------------------------

#[test]
fn a_revocation_landing_between_the_start_check_and_the_commit_stops_the_commit() {
    // The window I-05 bounds: the agent passed authorization, the operator revoked, and the agent
    // acts. The revocation must win. The identical request is evaluated twice; only the context
    // moves, which is what makes this a latency test rather than a credential test.
    let request = scenario::allowed_request();
    let at_start = notary::verdict(&request, &scenario::allowed_context());

    let mut at_commit_context = scenario::allowed_context();
    at_commit_context.revoked_svids = vec![scenario::SUBJECT.to_string()];
    let at_commit = notary::verdict(&request, &at_commit_context);

    harness::refused_at_the_boundary(
        "a revocation landing between the start check and the commit",
        &at_start,
        &at_commit,
        scenario::notary_allowed,
    );
    scenario::assert_denied_at(
        &at_commit,
        notary::Gate::Identity,
        "a mid-action revocation",
    );
}

/// FINDING (I-05, orphaned) — FIXED BY Task 9.1, 2026-09-05.
///
/// Round zero, hop 5: the incident's agent used a credential shared with another system. A shared
/// credential is the case revocation latency cannot help with, because the unit of revocation is the
/// identity and the credential is not bound to one — and the crate that would bind them,
/// `credential-vault`, was not in the `warrantor` binary's dependency graph. Its 1-second budget and
/// its restart-durability test were real, tested, and unreachable from the product.
///
/// Task 9.1 added the path dependency with `default-features = false`, which costs zero external
/// packages because that crate's CLI and scanner are now feature-gated. `warrantor_warrant::revoke`
/// reads its journal FORMAT.
///
/// **Still not fixed by it, and this doc comment claimed otherwise until 2026-09-05:** the 1-second
/// budget does NOT bind a shipped code path. `REVOKE_BUDGET` is compared in exactly two places,
/// `Vault::revoke` and `Vault::revoke_all` (`rust/credential-vault/src/lib.rs`), and nothing in
/// `rust/warrant/src` constructs a `Vault` or calls either — the binary's whole use of the crate is
/// `JournalOp`, `JournalRecord`, `RevocationJournal`, `CredentialError`, and `REVOKE_BUDGET` read as
/// a number to print. `RevocationStore::revoke` times nothing and refuses nothing on duration. What
/// the dependency edge bought is the journal format; the budget still needs a shipped caller. The
/// credential is also not bound to an issued identity — this test asserts the crate is linked, which
/// is the manifest half, and binding a credential to a per-workload SVID is Task 3.1's.
#[test]
fn hop_05_the_product_links_a_credential_vault_that_can_revoke() {
    let manifest = harness::read_repository_file("rust/warrant/Cargo.toml");
    assert!(
        manifest.contains("warrantor-credential-vault"),
        "I-05's credential half lives in a crate the product does not link, so a shared \
         credential has nothing to revoke it. The 1-second budget binds no shipped code path.",
    );
}

/// FINDING (I-05, unimplemented) — FIXED BY Task 9.1, 2026-09-05, in the narrow sense below.
///
/// The identity half — propagation to all replicas in under five seconds — had no implementation.
/// There was no revocation source, no propagation, and no replica set;
/// `VerdictContext::revoked_svids` is a vector the caller fills, and the product's one caller filled
/// it with nothing.
///
/// Task 9.1 supplied the **source**: `warrantor_warrant::revoke::RevocationStore`, an append-only
/// `fsync`'d journal under the warrant store root, read at adjudication time by
/// `report::build_observed`. `rust/warrant/tests/revocation.rs` drives the product's own path and
/// asserts the refusal against an allowed control, so this string assertion is backed by behavior
/// rather than satisfied by deleting a string.
///
/// **Still not fixed by it, and deliberately not claimed:** propagation. There is no second process,
/// no replica and no broker, so "to all replicas" is measured against one. The subject revoked is
/// `DEFAULT_CLI_SUBJECT`, a constant, until Task 3.1 lands — see the second finding in
/// `i01_active_identity.rs`, which is still `#[ignore]`d for exactly that reason.
#[test]
fn a_revocation_source_exists_for_the_identity_half() {
    let report = harness::read_repository_file("rust/warrant/src/report.rs");
    assert!(
        !report.contains("revoked_svids: Vec::new()"),
        "the only consumer of the Identity gate supplies a revocation set that is empty by \
         construction, so the five-second propagation bound governs nothing.",
    );
}

// -- evidence field -------------------------------------------------------------------

#[test]
fn the_receipt_proves_which_action_the_revocation_stopped() {
    let mut context = scenario::allowed_context();
    context.revoked_svids = vec![scenario::SUBJECT.to_string()];
    let request = scenario::allowed_request();
    let verdict = notary::verdict(&request, &context);

    let (signing_key, _) = notary::generate_keypair();
    let receipt = notary::issue_receipt(
        &verdict,
        &request,
        notary::EnforcementMode::Observed,
        &signing_key,
        "corpus-i05",
    );
    notary::verify_receipt(&receipt).expect("the corpus receipt verifies");
    assert_eq!(receipt.body.timestamp, scenario::NOW);
    assert_eq!(
        receipt.body.actor_svid,
        scenario::SUBJECT,
        "a revocation without an attributable receipt cannot be shown to have taken effect \
         within any latency bound",
    );
}
