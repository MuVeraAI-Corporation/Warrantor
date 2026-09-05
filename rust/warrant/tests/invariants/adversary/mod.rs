//! The evidence-integrity adversary (L0-05), offline half.
//!
//! 9 strategies against the notary, the evidence envelope, the report verifier and the archive.
//! Each is a named test, each runs against a control with the attack backed out, and each declares
//! what it actually reached through [`Reach`] rather than through its own passing status.
//!
//! # Why a strategy declares its reach
//!
//! Not all of them are refused. If those were written as ordinary passing tests the suite would
//! read as N refusals, which is the phantom-scorer shape this corpus exists to refuse: a control
//! believed to exist, steering decisions, while not existing. `Reach` is the same device
//! `warrantor_warrant::harness::Coverage` uses for MCP mediation -- name the escape in the type, so
//! a renderer cannot omit it by forgetting to.
//!
//! # A failing `RefusedAt` strategy is a P0
//!
//! Every `RefusedAt` strategy asserts that a constructed byte sequence is refused by a named check.
//! If one of those tests fails, the failure IS a demonstrated forgery against the shipped verifier
//! and it blocks the release. `tools/ci/check_invariant_ratchet.py` already fails the build on any
//! corpus failure with the message "A failing invariant test is a finding", so no new machinery is
//! needed -- but the reproducing chain belongs in `docs/task-evidence/`, not only in a CI log.

use crate::harness;

mod absence;
mod fixtures;
mod forgery;
mod mislabeling;
mod substitution;

/// What an attack actually reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Refused by a named check, with the control allowed. The string is the check.
    RefusedAt(&'static str),
    /// Reached the boundary and was NOT refused. A recorded finding; the string names the fix.
    Unrefused(&'static str),
    /// The boundary cannot see this attack at all. The string says what could.
    Unrepresentable(&'static str),
}

impl Reach {
    /// One sentence for the operator, in the honest direction.
    #[must_use]
    pub const fn sentence(self) -> &'static str {
        match self {
            Self::RefusedAt(_) => {
                "A reader running the shipped verifier refuses this, and the control proves the \
                 attack reached that refusal rather than dying earlier."
            }
            Self::Unrefused(_) => {
                "This attack is NOT refused today. It is recorded, not fixed, and the named task \
                 is the one that closes it."
            }
            Self::Unrepresentable(_) => {
                "The offline verifier cannot see this attack. Nothing in this suite refuses it and \
                 nothing in this suite should claim to."
            }
        }
    }

    /// True when this strategy is recording a gap rather than a guarantee.
    #[must_use]
    pub const fn is_a_finding(self) -> bool {
        !matches!(self, Self::RefusedAt(_))
    }
}

/// One attack strategy and the test that runs it.
pub struct Strategy {
    /// `A1`..`A9`.
    pub id: &'static str,
    /// What the attack does, in the adversary's own terms.
    pub name: &'static str,
    /// The mechanism under attack, plus any residual that survives the refusal.
    pub target: &'static str,
    /// What the attack actually reached.
    pub reach: Reach,
    /// The test function that runs it, findable in the suite sources.
    pub test: &'static str,
}

/// Every strategy, with what it actually reached.
///
/// A1..A8 are the plan's eight. **A9 is not in the plan**: it was found by attacking commit
/// `a84711b`'s fix as the task brief required, and it is the one genuinely new hole this suite
/// turned up. Recording it as a tenth-hour addition rather than suppressing it is the point of
/// running an adversary at all.
pub const STRATEGIES: [Strategy; 9] = [
    Strategy {
        id: "A1",
        name: "forge a chain end to end with a key the adversary holds",
        target: "evidence::verify_chain, which is anchor-free by construction. Residual: a reader \
                 who pins no key is reading a document that authenticates itself.",
        reach: Reach::RefusedAt(
            "the caller's anchor comparison against the pinned issuer; verify_chain alone does not \
             refuse it",
        ),
        test: "a1_a_chain_forged_end_to_end_verifies_and_is_caught_only_by_the_anchor",
    },
    Strategy {
        id: "A2",
        name: "backdate the evidence receipt by a day",
        target: "report::verify_export's field bindings. The notary receipt's timestamp is bound to \
                 the bundle; the evidence receipt's binding.issued_at is not.",
        reach: Reach::Unrefused(
            "Task 2.3 owns the commit point and the second policy evaluation, which is where an \
             issuance-time binding belongs; Task 3.4's recorder is what could witness it \
             independently",
        ),
        test: "a2_the_evidence_receipts_issuance_time_is_not_bound_to_the_report_it_covers",
    },
    Strategy {
        id: "A3",
        name: "lift a genuine receipt into a false context",
        target: "report::verify_export's receipt-to-bundle bindings",
        reach: Reach::RefusedAt(
            "report::verify_export binding checks: predicate.binding.receipt_id must equal the \
             bundle digest, and the refusal is a Binding rather than a signature failure",
        ),
        test: "a3_a_genuine_receipt_lifted_onto_a_different_report_is_refused_as_a_binding",
    },
    Strategy {
        id: "A4",
        name: "replay the same request and get a second allow",
        target: "notary::Gate::Freshness, asked about an empty nonce set on every call",
        reach: Reach::Unrefused(
            "Task 3.4's flight recorder is the nonce store that survives a restart; nothing on the \
             warrant path remembers a nonce across calls today",
        ),
        test: "a4_the_product_context_allows_a_verbatim_replay",
    },
    Strategy {
        id: "A5",
        name: "smuggle a mediated per-effect receipt past the mode check",
        target: "report::verify_effect_receipts' mode loop and report::verify_export's report-level \
                 mode checks, both added by commit a84711b",
        reach: Reach::RefusedAt(
            "verify_effect_receipts refuses any per-effect receipt whose mode is not Advisory, and \
             the loop runs before the bundle's effect lines are walked, so an unlisted receipt is \
             refused for its mode and not for being unaccounted",
        ),
        test: "a5_a_mediated_per_effect_receipt_is_refused_even_when_the_bundle_does_not_list_it",
    },
    Strategy {
        id: "A6",
        name: "delete a limitation and expand the authority",
        target: "the bundle digest and evidence::verify_authority. Residual: an adversary who \
                 rewrites the delegation chain itself gets an authority that verifies, because the \
                 chain IS the authority -- a receipt proves the chain it carries, never that the \
                 chain was legitimately issued.",
        reach: Reach::RefusedAt(
            "the SHA-256 bundle digest for the removed limitation, and evidence::verify_authority's \
             recomputed intersection, whose error names `authority expansion; I-02`",
        ),
        test: "a6_a_removed_limitation_fails_on_the_digest_and_a_forged_intersection_fails_on_the_proof",
    },
    Strategy {
        id: "A7",
        name: "suppress the evidence entirely",
        target: "the offline verifier, which holds one file and no sequence",
        reach: Reach::Unrepresentable(
            "Task 10.3's evidence-integrity monitors, which must be able to fail loudly about the \
             store they live in; Task 10.6's chain of custody",
        ),
        test: "a7_a_suppressed_receipt_is_indistinguishable_from_a_run_that_never_happened",
    },
    Strategy {
        id: "A8",
        name: "race the archive for attribution, on evidence the adversary manufactured",
        target: "MemoryStore::put_artifact and artifact::ingest. Residual: the door is anchor-free, \
                 so submitted_by_device means `who filed this`, never `who produced this`.",
        reach: Reach::RefusedAt(
            "MemoryStore::put_artifact returns AlreadyHeld and rewrites nothing, so append-only \
             holds even though the attribution goes to the first filer",
        ),
        test: "a8_a_first_filer_owns_the_attribution_and_the_door_never_asked_whose_key_signed_it",
    },
    Strategy {
        id: "A9",
        name: "claim mediated in the bundle's prose while shipping advisory receipts",
        target: "the mode word in the signed bundle's limitation sentence, derived by \
                 with_effect_receipts at BUILD time and never re-derived on the verify path",
        reach: Reach::Unrefused(
            "Task 2.3 is the nearest owner of the report verifier's per-effect checks; the fix is \
             one comparison in verify_effect_receipts -- recompute the mode phrase from \
             export.effect_receipts and refuse a bundle whose sentence disagrees",
        ),
        test: "a9_the_bundles_rendered_mode_word_is_not_gated_against_the_receipts_on_the_verify_path",
    },
];

/// The files the completeness scan reads beyond this directory. Named rather than globbed, because
/// the archive strategy's test lives in another crate: `append_only.rs:355` is the lesson that a
/// hardcoded list stops covering a file silently, so a missing file here is a failure rather than a
/// quietly smaller scan.
const SCANNED: [&str; 1] = ["rust/archive/tests/adversary_custody.rs"];

/// The corpus every completeness check reads: this directory's `.rs` files plus [`SCANNED`].
fn corpus() -> String {
    let directory = harness::repository_root().join("rust/warrant/tests/invariants/adversary");
    let mut corpus = String::new();
    for entry in std::fs::read_dir(&directory).expect("the adversary directory is readable") {
        let path = entry.expect("readable entry").path();
        if path.extension().is_some_and(|extension| extension == "rs") {
            corpus.push_str(&std::fs::read_to_string(&path).expect("readable strategy file"));
        }
    }
    for relative in SCANNED {
        corpus.push_str(&harness::read_repository_file(relative));
    }
    corpus
}

#[test]
fn every_strategy_has_a_test_that_exists() {
    // Scan the sources rather than trusting the table, for the reason round_zero gives: a strategy
    // covered by a table entry alone is not covered.
    let corpus = corpus();
    assert!(
        !STRATEGIES.is_empty(),
        "the adversary registry is empty. An adversary with no strategies is a green result and a \
         false guarantee, which is worse than no adversary."
    );
    for strategy in &STRATEGIES {
        assert!(
            corpus.contains(&format!("fn {}(", strategy.test)),
            "strategy {} ({}) names test `{}`, which does not exist",
            strategy.id,
            strategy.name,
            strategy.test,
        );
    }
}

#[test]
fn the_module_doc_states_the_number_of_strategies_this_suite_actually_has() {
    // Built at run time: a literal count in the needle would be the thing being checked.
    let source = harness::read_repository_file("rust/warrant/tests/invariants/adversary/mod.rs");
    let claimed = format!("{} strategies against the notary", STRATEGIES.len());
    assert!(
        source.contains(&claimed),
        "the module doc claims a different number of strategies than the registry holds ({}). \
         Update both or neither: a documented count nobody checks is how a reviewer reads coverage \
         that does not exist.",
        STRATEGIES.len()
    );
}

#[test]
fn every_finding_names_the_task_that_closes_it_and_no_finding_claims_a_refusal() {
    for strategy in &STRATEGIES {
        match strategy.reach {
            Reach::RefusedAt(check) => assert!(
                !check.is_empty(),
                "strategy {} claims a refusal without naming the check that performs it. A claim \
                 with no mechanism is the defect this whole corpus exists to refuse.",
                strategy.id
            ),
            Reach::Unrefused(fix) | Reach::Unrepresentable(fix) => assert!(
                fix.contains("Task"),
                "strategy {} is a finding and must name the task that closes it, got {fix:?}",
                strategy.id
            ),
        }
        assert!(
            strategy.reach.sentence().len() > 40,
            "strategy {}'s reach must carry a real sentence for the operator",
            strategy.id
        );
        assert!(
            !strategy.target.is_empty(),
            "strategy {} must name the mechanism it attacks",
            strategy.id
        );
    }
    assert_eq!(
        STRATEGIES.iter().filter(|s| s.reach.is_a_finding()).count(),
        4,
        "A2, A4, A7 and A9 are the four attacks this suite does not refuse. If that number changes, \
         the product sentence in docs/W1-delivery-gaps.md changes with it, in the same commit."
    );
}

#[test]
fn the_findings_are_exactly_the_strategies_the_delivery_gaps_document_names() {
    // Rule 6 applied to this suite's own numbers: a rendered count gated against its record. The
    // Tier 5 subsection is where a reader learns which attacks are not refused, so a strategy that
    // becomes a finding without being written down there is a gap nobody was told about.
    let gaps = harness::read_repository_file("docs/W1-delivery-gaps.md");
    for strategy in &STRATEGIES {
        if !strategy.reach.is_a_finding() {
            continue;
        }
        assert!(
            gaps.contains(&format!("strategy {}", strategy.id)),
            "strategy {} is an unrefused finding and docs/W1-delivery-gaps.md does not name it. \
             Every finding this suite records must be readable by someone who never runs the tests.",
            strategy.id
        );
    }
    let claimed = format!(
        "{} of the nine are not refused",
        STRATEGIES.iter().filter(|s| s.reach.is_a_finding()).count()
    );
    assert!(
        gaps.contains(&claimed),
        "docs/W1-delivery-gaps.md must state how many strategies are unrefused, and say {claimed:?}"
    );
}
