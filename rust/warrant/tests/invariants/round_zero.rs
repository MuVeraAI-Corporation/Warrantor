//! Corpus round zero — the incident's own hop sequence.
//!
//! Ten hops, from the master's kill-chain figure:
//!
//! > impossible task -> shared-cache observation -> directory-name channel -> cache SSRF egress ->
//! > shared credential -> forged admin token -> persistent admin users -> plugin execution ->
//! > third-party credential reuse -> template-injection RCE
//!
//! Each hop is encoded as at least one test inside the suite for the invariant it attacks. This
//! module holds the assignment and the completeness check: [`every_hop_has_a_test`] scans the
//! suite sources for the named test function, so a hop cannot be claimed as covered by a comment.
//!
//! # The assignment is a judgment, and it is written down so it can be argued with
//!
//! Mapping an incident hop onto a formal invariant is the corpus author's call, not something the
//! invariant statements decide. Each row below carries its reasoning. A reviewer who disagrees
//! with a mapping is disagreeing with this table, not with I-01…I-12 — the invariant statements
//! themselves are transcribed verbatim in [`crate::fixture`] and are not up for interpretation
//! here.
//!
//! Three of the ten land on I-03, which has no implementation at all. That concentration is the
//! single most useful number this corpus produces.

use crate::harness;

/// One hop of the kill chain, with the invariant it is encoded against and the test that does it.
pub struct Hop {
    /// Position in the chain, 1-10.
    pub position: u8,
    /// The hop, in the kill-chain figure's own words.
    pub name: &'static str,
    /// The invariant this hop is encoded against.
    pub invariant: &'static str,
    /// The test function that encodes it, findable in the suite sources.
    pub test: &'static str,
    /// Why this hop belongs to that invariant.
    pub rationale: &'static str,
}

/// The ten hops, in order.
pub const ROUND_ZERO: [Hop; 10] = [
    Hop {
        position: 1,
        name: "impossible task",
        invariant: "I-09",
        test: "hop_01_an_impossible_task_fails_closed_rather_than_finding_a_route",
        rationale: "A task that cannot be completed inside the granted authority must terminate, \
                    not search for a route around. The substrate's share of that is that an \
                    indeterminate answer is a denial.",
    },
    Hop {
        position: 2,
        name: "shared-cache observation",
        invariant: "I-03",
        test: "hop_02_a_shared_cache_read_for_another_purpose_is_refused",
        rationale: "Reading data that was collected for someone else's purpose is the purpose \
                    violation exactly. Nothing else in I-01..I-12 speaks to who the data was for.",
    },
    Hop {
        position: 3,
        name: "directory-name channel",
        invariant: "I-03",
        test: "hop_03_a_directory_name_channel_is_invisible_to_the_egress_boundary",
        rationale: "An improvised channel moves data outside the path its purpose tag governs. \
                    Task 3.6's shared-surface census is the detection side; the invariant it \
                    would serve is I-03.",
    },
    Hop {
        position: 4,
        name: "cache SSRF egress",
        invariant: "I-11",
        test: "hop_04_a_redirect_out_of_the_resolved_set_is_refused",
        rationale: "The broker declares RedirectOutOfSet under its self-change protection, and a \
                    destination that forwards is a boundary the agent changed without touching \
                    the catalog. Task 5.2's egress closure is the prover for the same property.",
    },
    Hop {
        position: 5,
        name: "shared credential",
        invariant: "I-05",
        test: "hop_05_the_product_links_a_credential_vault_that_can_revoke",
        rationale: "A credential held by more than one principal is the case revocation must \
                    handle and cannot, unless the credential is bound to an identity and \
                    revocable on its own. That binding is credential-vault's job.",
    },
    Hop {
        position: 6,
        name: "forged admin token",
        invariant: "I-02",
        test: "hop_06_a_forged_admin_token_does_not_survive_receipt_verification",
        rationale: "A forged token claims authority no delegation link granted, which is \
                    authority expansion in its purest form.",
    },
    Hop {
        position: 7,
        name: "persistent admin users",
        invariant: "I-11",
        test: "hop_07_persistent_admin_users_cannot_be_added_to_a_warrant_derived_catalog",
        rationale: "Creating principals that outlive the session is modifying the enforcement \
                    boundary itself, not acting within it.",
    },
    Hop {
        position: 8,
        name: "plugin execution",
        invariant: "I-06",
        test: "hop_08_a_substituted_plugin_body_is_refused_at_the_artifacts_gate",
        rationale: "A plugin admitted by name rather than by content digest is the failure I-06 \
                    names outright.",
    },
    Hop {
        position: 9,
        name: "third-party credential reuse",
        invariant: "I-01",
        test: "hop_09_a_reused_third_party_credential_is_refused_at_the_identity_gate",
        rationale: "Acting under an identity that is not the actor's own, and that the issuer has \
                    withdrawn, is what the Identity gate is for.",
    },
    Hop {
        position: 10,
        name: "template-injection RCE",
        invariant: "I-03",
        test: "hop_10_the_receipt_labels_the_provenance_of_what_drove_the_action",
        rationale: "Untrusted content became a trusted instruction. Plane 5's failure invariant \
                    says so directly and I-03 is the formal invariant that plane carries. I-06 is \
                    the secondary reading — the executed thing was not digest-pinned — and hop 8 \
                    already covers that.",
    },
];

#[test]
fn every_hop_has_a_test() {
    // Read the suite sources rather than trusting this table. A hop marked covered by a table
    // entry alone is exactly the phantom this corpus exists to refuse.
    let directory = harness::repository_root().join("rust/warrant/tests/invariants");
    let mut corpus = String::new();
    for entry in std::fs::read_dir(&directory).expect("the invariants directory is readable") {
        let path = entry.expect("readable entry").path();
        if path.extension().is_some_and(|extension| extension == "rs") {
            corpus.push_str(&std::fs::read_to_string(&path).expect("readable suite"));
        }
    }

    for hop in &ROUND_ZERO {
        let definition = format!("fn {}(", hop.test);
        assert!(
            corpus.contains(&definition),
            "hop {} ({}) is assigned to {} and its test `{}` does not exist. A hop covered only \
             by this table is not covered.",
            hop.position,
            hop.name,
            hop.invariant,
            hop.test,
        );
    }
}

#[test]
fn the_chain_is_ten_hops_in_the_order_the_incident_ran_them() {
    assert_eq!(ROUND_ZERO.len(), 10);
    for (index, hop) in ROUND_ZERO.iter().enumerate() {
        assert_eq!(
            hop.position as usize,
            index + 1,
            "the kill chain is an ordered sequence; hop {} is out of place",
            hop.name,
        );
        assert!(
            crate::fixture::INVARIANTS
                .iter()
                .any(|invariant| invariant.id == hop.invariant),
            "hop {} is assigned to {}, which is not one of I-01..I-12",
            hop.name,
            hop.invariant,
        );
        assert!(
            !hop.rationale.is_empty(),
            "hop {} carries no rationale for its invariant assignment",
            hop.name,
        );
    }
}
