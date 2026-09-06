//! I-09 — Failure is safe.
//!
//! > If any plane fails open, the action fails closed. Network loss to I1 = deny.
//!
//! This is the invariant the codebase holds best in its own idiom. Three independent surfaces
//! implement absent-means-none rather than absent-means-unlimited: the egress broker denies when
//! the catalog is missing, the notary treats an unresolvable artifact as unverified, and an
//! undeclared spend budget is a ceiling of zero. The finding is narrower than the others in this
//! corpus and still real: the preflight that refuses to start an agent on an unmeasured boundary
//! lives in a crate the product does not link.

use crate::{fixture, harness, scenario};
use std::collections::BTreeSet;
use warrantor_egress as egress;
use warrantor_notary as notary;
use warrantor_warrant::{spend, WarrantBounds};

fn bounds_with_budget(budget_cents_observed: Option<u64>) -> WarrantBounds {
    WarrantBounds {
        tools: BTreeSet::new(),
        write_paths: BTreeSet::new(),
        egress_hosts: BTreeSet::new(),
        staged_classes: BTreeSet::new(),
        expires_at: scenario::NOW + 3_600,
        budget_cents_observed,
        delegation_depth: 0,
    }
}

// -- static ---------------------------------------------------------------------------

#[test]
fn the_preflight_refusal_names_this_invariant() {
    assert_eq!(fixture::invariant("I-09").id, "I-09");
    // The plan's Task 0.5 quotes this message with a trailing clause -- "an unmeasured boundary is
    // not a passing boundary" -- that origin/main does not carry. The code is the source of record
    // here and the shorter form is what is asserted; the discrepancy is noted in
    // docs/task-evidence/task-5.1.md.
    harness::source_contains(
        "rust/eval-guard/src/cli.rs",
        "REFUSING to start the agent (invariant I-09: failure is safe)",
        "The clearest statement of I-09 in the repository is a refusal message; it must not \
         drift.",
    );
}

// -- runtime --------------------------------------------------------------------------

#[test]
fn an_unavailable_catalog_denies_rather_than_permits() {
    // Network loss to the thing that would have said yes. The broker is handed `None` and must
    // deny, not fall back to a default-allow or to the agent's own belief about connectivity.
    let request = egress::EgressRequest {
        capability: "net.egress:api.example.com".to_string(),
        logical_endpoint: "api.example.com".to_string(),
        chain_capabilities: vec!["net.egress:api.example.com".to_string()],
        enforcement_mode: "advisory".to_string(),
        is_discovery: false,
        has_approval: false,
    };
    assert_eq!(
        egress::decide(&request, None),
        egress::EgressVerdict::Deny {
            reason: egress::DenyReason::CatalogUnavailable
        },
        "a broker that cannot read its catalog must deny",
    );
}

// -- adversarial ----------------------------------------------------------------------

#[test]
fn hop_01_an_impossible_task_fails_closed_rather_than_finding_a_route() {
    // Round zero, hop 1. The incident began with a task the agent could not complete inside its
    // authority, and it looked for a way around rather than stopping. The substrate's half of that
    // is that an indeterminate answer must be a denial: when the artifact provider cannot be
    // reached, the artifact is unverified, not provisionally trusted.
    //
    // The control resolves the digest, which proves the request is otherwise well formed and the
    // refusal below comes from the provider being unreachable and nothing else.
    let digest = "aa".repeat(32);
    let mut request = scenario::allowed_request();
    request.operation.class = "artifact.execute".to_string();
    request.artifacts = vec![notary::ArtifactDigest {
        digest: digest.clone(),
        verified: true,
    }];

    let mut reachable = scenario::allowed_context();
    reachable.verified_artifacts = vec![digest];
    let control = notary::verdict(&request, &reachable);

    // The provider is down: it resolved nothing, so the set is empty.
    let unreachable = scenario::allowed_context();
    let attacked = notary::verdict(&request, &unreachable);

    harness::refused_at_the_boundary(
        "hop 1: an artifact provider that could not be reached",
        &control,
        &attacked,
        scenario::notary_allowed,
    );
    scenario::assert_denied_at(
        &attacked,
        notary::Gate::Artifacts,
        "an unreachable artifact provider",
    );
}

#[test]
fn an_undeclared_budget_is_a_ceiling_of_zero_rather_than_unlimited() {
    // The absent-means-none reading, tested where it is easiest to get backwards. A warrant that
    // names no budget must authorize no spend; the failure mode this guards is the one where a
    // missing limit reads as no limit.
    assert_eq!(
        spend::cap_micros(&bounds_with_budget(None)),
        0,
        "an undeclared budget must cap at zero; absent is none, never unlimited",
    );
    assert!(
        spend::cap_micros(&bounds_with_budget(Some(500))) > 0,
        "control: a declared budget must produce a non-zero cap, or the assertion above is \
         measuring nothing",
    );
    assert!(!spend::cap_declared(&bounds_with_budget(None)));
    assert!(spend::cap_declared(&bounds_with_budget(Some(500))));
}

#[test]
fn an_empty_egress_allowlist_permits_nothing_rather_than_everything() {
    // The same reading on the egress bound. A warrant with no hosts produces no catalog, and no
    // catalog is a denial.
    let permissive = warrantor_warrant::egress::EgressBroker::for_bounds(&WarrantBounds {
        egress_hosts: BTreeSet::from(["api.example.com".to_string()]),
        ..bounds_with_budget(None)
    });
    let empty = warrantor_warrant::egress::EgressBroker::for_bounds(&bounds_with_budget(None));

    harness::refused_at_the_boundary(
        "a warrant granting no egress at all",
        &permissive.decide("api.example.com"),
        &empty.decide("api.example.com"),
        |verdict| matches!(verdict, egress::EgressVerdict::Allow { .. }),
    );
    assert_eq!(
        empty.decide("api.example.com"),
        egress::EgressVerdict::Deny {
            reason: egress::DenyReason::CatalogUnavailable
        },
    );
}

// -- evidence field -------------------------------------------------------------------

#[test]
fn the_egress_receipt_records_which_failure_closed_the_action() {
    // I-09's evidence field is the coarse reason on the refusal. It must survive signing and
    // verification, or a fail-closed event leaves no reviewable trace.
    let request = egress::EgressRequest {
        capability: "net.egress:api.example.com".to_string(),
        logical_endpoint: "api.example.com".to_string(),
        chain_capabilities: vec!["net.egress:api.example.com".to_string()],
        enforcement_mode: "advisory".to_string(),
        is_discovery: false,
        has_approval: false,
    };
    let verdict = egress::decide(&request, None);

    // The signing keys are Ed25519 across every plane in this workspace, so the notary's generator
    // serves here too; the egress crate exposes none of its own.
    let (key, _) = notary::generate_keypair();
    let receipt = egress::issue_receipt(&verdict, &request, scenario::NOW, &key, "corpus-i09");
    egress::verify_receipt(&receipt).expect("the corpus receipt verifies");

    assert_eq!(
        receipt.body.verdict,
        egress::EgressVerdict::Deny {
            reason: egress::DenyReason::CatalogUnavailable
        },
        "the receipt must name which failure closed the action; an unattributed fail-closed event \
         cannot be reviewed",
    );
    assert_eq!(receipt.body.capability, request.capability);
}

// -- finding --------------------------------------------------------------------------

/// FINDING (I-09, orphaned). `eval-guard` refuses to start an agent when the boundary it is meant
/// to be measured against could not be measured — the sharpest expression of I-09 in the
/// repository — and the `warrantor` binary does not link it. The refusal is real, tested, and
/// cannot fire for any user of the shipped product.
///
/// Fixed by: no task in the 2026-09-02 implementation plan links `eval-guard`. Task 0.3's orphan
/// census is where the crate is counted. Recorded 2026-09-02.
#[test]
#[ignore = "I-09 orphaned: eval-guard's fail-closed preflight is not linked by the warrantor binary (2026-09-02)"]
fn the_product_links_the_preflight_that_refuses_an_unmeasured_boundary() {
    let manifest = harness::read_repository_file("rust/warrant/Cargo.toml");
    assert!(
        manifest.contains("warrantor-eval-guard"),
        "the fail-closed preflight lives in a crate the product does not link, so no shipped run \
         is refused for starting against an unmeasured boundary.",
    );
}

/// FINDING (I-09, common mode). Task 5.4, L2-03 / L0-10.
///
/// The independence property belongs to I-09 — *"if any plane fails open, the action fails closed"* —
/// because the anti-correlation is exactly the case where plane A failing open leaves nothing closed.
/// A permitted destination is guarded by one enforcement point, so there is no second plane to fail
/// closed behind the first.
///
/// The attack here is the concrete exploit that anti-correlation opens. **Neither engine resolves
/// DNS**, so a hostname is judged only as a string; and the one layer that would stop a name
/// regardless of what it resolves to — the network namespace, which removes the network outright — is
/// deliberately **not** emitted for any warrant that permits a host
/// (`rust/warrant/src/sandbox.rs` lines 333-346). So a name that encodes the cloud metadata address
/// and is not on `hard_deny`'s hostname list passes both policy engines. Task 7.1's own evidence
/// records this exact string as reaching Allow — see the table in
/// `docs/task-evidence/task-7.1.md`, row `169.254.169.254.nip.io`.
///
/// Written with [`harness::reached_the_boundary_unrefused`], and this doc comment used to overstate
/// what that buys.
///
/// **CORRECTION.** It read: *"so that it starts failing the day either half is fixed: a resolver on
/// the egress path, or a second enforcement point that acts on a permitted host."* Only the first
/// half was ever true. `reached_the_boundary_unrefused` goes red when the predicate below flips, and
/// that predicate is the closure `broker_allows && filter_allows` -- closed over exactly the two
/// in-process policy engines. A resolver on the egress path flips it; so does
/// `169.254.169.254.nip.io` joining `hard_deny`'s hostname list. Nothing outside those two closures
/// is an input, so **no kernel layer and no cluster policy can flip it**: an adversarial reviewer
/// added a real cluster egress `NetworkPolicy` -- egress `policyTypes`, the analysis document's own
/// exit condition 2 -- and this test, the whole I-09 corpus and the CI gate all stayed green.
///
/// The cluster half of the exit condition now has an assertion that CAN go red, in the one place that
/// can see a YAML file: `tools/ci/network_independence.py::cluster_layer_absent` fails the build when
/// a `NetworkPolicy` this analysis does not know about appears in the tree, and when the single one it
/// does name disappears. Whoever lands a second enforcement point converts this test to
/// `refused_at_the_boundary`, closes `### 3.8` in `docs/W1-delivery-gaps.md`, and raises the ratchet.
/// A finding that silently goes stale is a finding nobody will ever close.
///
/// Fixed by: no task in the 2026-09-02 implementation plan builds a second enforcement point or adds
/// a resolver; Phase 5's governing rule forbids the first. Recorded 2026-09-05.
#[test]
fn a_name_that_encodes_the_metadata_address_passes_both_engines_because_neither_resolves_dns() {
    // The operator's own policy allowlists both names, and the warrant permits both. This is the
    // configuration in which the two engines are supposed to be doing their job.
    let permitted_name = "api.github.com";
    let metadata_name = "169.254.169.254.nip.io";

    let bounds = WarrantBounds {
        egress_hosts: BTreeSet::from([permitted_name.to_string(), metadata_name.to_string()]),
        ..bounds_with_budget(None)
    };
    let broker = warrantor_warrant::egress::EgressBroker::for_bounds(&bounds);
    let secondary = warrantor_warrant::egress::SecondaryFilter::from_policy(
        warrantor_egress_filter::PolicyBuilder::with_defaults()
            .allow_domain(permitted_name)
            .allow_domain(metadata_name)
            .build()
            .expect("the operator policy builds"),
    );

    // `allowed` means "no engine refused this destination". Both engines are consulted, so the
    // predicate covers the whole policy surface the product has.
    let verdict = |host: &&str| {
        let broker_allows = matches!(
            broker.decide(host),
            warrantor_warrant::egress::EgressVerdict::Allow { .. }
        );
        let filter_allows = secondary.decide(host).action == warrantor_egress_filter::Action::Allow;
        broker_allows && filter_allows
    };

    // Control: the attack backed out. An ordinary permitted host is allowed, which proves the
    // predicate can say "refused" for a reason other than refusing everything.
    harness::reached_the_boundary_unrefused(
        "a hostname encoding 169.254.169.254, which neither engine resolves and no netns stops",
        &permitted_name,
        &metadata_name,
        verdict,
    );

    // And the same machinery DOES refuse the literal address, so the gap is specifically the
    // resolver and not a missing floor. This is the allowed/refused pair that makes the finding
    // precise rather than alarming.
    //
    // CORRECTION. The message here used to credit "the non-amendable floor" while the assertion
    // observed `CanaryIp`: `169.254.169.254` is in `DEFAULT_CANARY_IPS` and the canary check runs
    // first, and only the action was asserted. Both halves are now named for what they actually are.
    let literal = secondary.decide("169.254.169.254");
    assert_eq!(
        literal.action,
        warrantor_egress_filter::Action::Deny,
        "the literal address is refused and only the NAME gets through: {literal:?}",
    );
    assert_eq!(
        literal.reason,
        warrantor_egress_filter::DecisionReason::CanaryIp,
        "and it is the configured canary list that refuses this one, not the floor: {literal:?}",
    );
    // The floor, on an address only the floor covers -- link-local, in no canary list, explicitly
    // allowlisted, with the private check off. This is what makes "a hostname is judged only as a
    // string" a resolver gap rather than a missing floor.
    let floor_only = warrantor_warrant::egress::SecondaryFilter::from_policy(
        warrantor_egress_filter::PolicyBuilder::with_defaults()
            .allow_ip("169.254.1.1")
            .deny_private_egress(false)
            .build()
            .expect("the operator policy builds"),
    );
    let floored = floor_only.decide("169.254.1.1");
    assert!(
        matches!(
            floored.reason,
            warrantor_egress_filter::DecisionReason::HardDenyFloor { .. }
        ),
        "the non-amendable floor must refuse a link-local address no configured field covers, or \
         `address_floor` is reported shared with nothing behind it: {floored:?}",
    );

    // The measured count agrees with the mechanism just demonstrated. Reading it from the same
    // function the record and the drills read is what stops the prose and the code diverging.
    let measured = warrantor_warrant::egress::independence(&bounds, None);
    assert_eq!(
        measured.intercepts, 1,
        "one enforcement point stands over a permitted destination",
    );
    assert!(
        measured.shared_axes.contains(&"dns_resolution"),
        "the shared blind spot this test just exercised must be named as a shared axis",
    );
    assert!(
        measured.shared_axes.contains(&"configuration_source"),
        "the shared field must be named as a shared axis, not merely demonstrated",
    );

    // Wiring the second policy engine does not change the count: two evaluators, one boundary.
    let paired = warrantor_warrant::egress::independence(&bounds, Some(&secondary));
    assert_eq!(paired.engines, 2);
    assert_eq!(
        paired.intercepts, 1,
        "a second policy domain is not a second enforcement point",
    );
    assert!(
        paired.shared_axes.contains(&"address_floor"),
        "both evaluators consult one hard_deny matcher, so a defect there fails both at once",
    );
}

/// The other half of the anti-correlation, asserted directly: the netns is switched off by the very
/// field that opens the catalogue.
///
/// Separate from the finding above because this one is not a finding — it is a deliberate, documented
/// decision (`rust/warrant/src/sandbox.rs` lines 333-346: a namespace has no host allowlist, so
/// emitting it would deny egress the warrant granted). It is asserted so that the decision cannot be
/// quietly reversed, and paired with its control so it cannot pass vacuously.
#[test]
fn the_only_second_layer_is_emitted_exactly_when_no_destination_is_permitted() {
    let denying = bounds_with_budget(None);
    let permitting = WarrantBounds {
        egress_hosts: BTreeSet::from(["api.github.com".to_string()]),
        ..bounds_with_budget(None)
    };
    let netns = |bounds: &WarrantBounds| {
        warrantor_warrant::sandbox::profile(
            bounds,
            "/home/u/wt",
            warrantor_warrant::sandbox::Confinement::Bubblewrap,
        )
        .argv
        .iter()
        .any(|a| a == "--unshare-net")
    };

    // The control: an empty egress bound DOES emit the namespace, so its absence below is caused by
    // the grant and not by a profile builder that never emits one.
    assert!(
        netns(&denying),
        "control: a warrant granting no egress must unshare the network namespace",
    );
    assert!(
        !netns(&permitting),
        "and a warrant permitting one host must not, or sandbox.rs lines 333-346 have been reversed",
    );

    // Which is the whole anti-correlation: two layers stand only where nothing is permitted.
    assert_eq!(
        warrantor_warrant::egress::independence(&denying, None).intercepts,
        2
    );
    assert!(
        !warrantor_warrant::egress::independence(&denying, None).guards_a_permitted_destination,
        "and those two layers guard nothing, because there is no permitted destination",
    );
    assert_eq!(
        warrantor_warrant::egress::independence(&permitting, None).intercepts,
        1
    );
}

/// I-09's static half for the finding above.
///
/// The two sentences that state where egress holds must keep naming the things that are absent. A
/// surface that drops either clause is how a Tier B bound gets read as Tier A, and how a count of
/// policy domains gets read as a count of enforcement points.
///
/// # Why this reads the CONSTANTS and not their source text
///
/// The first version of this test used [`harness::source_contains`] with a fragment spanning two
/// source lines. It passed on the author's worktree and **failed in a fresh checkout**, because this
/// repository checks out CRLF on Windows: a needle containing `\n` cannot match a file whose lines
/// end `\r\n`. That is the [[windows rust paths are ungated]] failure in miniature — Linux CI would
/// have stayed green while every Windows contributor went red.
///
/// Both notes are `pub const &str` reachable at run time, and a string continuation elides its
/// newline, so the *values* contain no line breaks at all. Asserting the value is therefore both
/// stronger (it survives any reformatting of the source) and portable. A source-text assertion is
/// the right tool only for something with no runtime representation, and neither of these is that.
#[test]
fn the_notes_refuse_to_imply_a_second_boundary() {
    let enforcement = warrantor_warrant::egress::ENFORCEMENT_NOTE;
    assert!(
        enforcement.contains("There is no network namespace, seccomp filter or firewall"),
        "ENFORCEMENT_NOTE is the only place the product says where egress holds; if it stops \
         naming what is absent, the independence count reads as an enforcement count. It reads: \
         {enforcement}",
    );
    assert!(
        enforcement.contains("an agent that opens a socket itself is not bound by them"),
        "and it must keep naming what escapes, not merely what is absent: {enforcement}",
    );

    let independence = warrantor_warrant::egress::INDEPENDENCE_NOTE;
    // CORRECTION, found by two independent adversarial reviewers. This assertion used to require
    // "is a count of policy domains, not a count of enforcement points" -- and so pinned a sentence
    // that mislabeled the number it accompanied, in the UNSAFE direction. Every render target the
    // gate polices publishes one number, `Independence::intercepts`, and that number IS the
    // enforcement-point count. The clause told the reader it was not. The record beside it said the
    // opposite in capital letters. Two Rust tests and one CI gate held the wrong wording in place.
    //
    // This is Task 9.1's shape (a word written beside a record rather than derived from it) and
    // [[verify attribution, not just numbers]]: the figures were right and the labels were wrong.
    // The clause is now attached to the number it is true of, and the old wording is refused so it
    // cannot return. `egress::independence_sentence` is the derived form for anything that prints a
    // number; this constant carries only what holds in every configuration.
    assert!(
        independence.contains("is a count of enforcement points"),
        "INDEPENDENCE_NOTE accompanies the intercept count, which IS the enforcement count, so it \
         must label it as one. It reads: {independence}",
    );
    assert!(
        !independence.contains("count of policy domains, not a count of enforcement points"),
        "the withdrawn clause mislabeled the published count and must not come back: {independence}",
    );
    assert!(
        independence.contains("engine count is a count of policy domains"),
        "the policy-domain clause belongs to the ENGINE count, the number it is true of: \
         {independence}",
    );
    assert!(
        independence.contains("does not add one for a warrant that permits any host"),
        "and the note must not offer the confinement profile as a remedy: `sandbox::profile` omits \
         --unshare-net for exactly the warrants this count is about. It reads: {independence}",
    );
    assert!(
        !independence.contains('\n'),
        "the note is rendered under a count on one-line surfaces, so it must not carry a newline",
    );
}
