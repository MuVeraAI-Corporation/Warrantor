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
    /// Refused by a named check **in shipped code**, with the control allowed. The string is the
    /// check, and the check must be callable by a reader who links this repository's crates.
    RefusedAt(&'static str),
    /// Refused only by a comparison the **reader** has to write, because no shipped symbol offers
    /// it for this envelope. A finding, not a refusal: the mechanism lives in the test, and a
    /// maintainer who deletes shipped code cannot be told about it by this strategy. The string
    /// names the missing symbol and the task that would ship it.
    ///
    /// This variant exists because `RefusedAt` outran its mechanism once. A1 was registered as a
    /// refusal while the refusing comparison was two lines inside its own test, so making
    /// `evidence::verify_chain` a total no-op left A1 green (it turned two pre-existing I-07 tests
    /// red instead). When a label outruns its mechanism the label changes; the mechanism is not
    /// re-described to fit.
    RefusedOnlyByReaderWrittenCode(&'static str),
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
            Self::RefusedOnlyByReaderWrittenCode(_) => {
                "Nothing this repository ships refuses this. The comparison that refuses it is \
                 written inside the test, so the guarantee belongs to code the reader must supply, \
                 and no shipped symbol offers that comparison for this envelope."
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
    ///
    /// Everything that is not a refusal *by shipped code* is a finding, which is why
    /// [`Reach::RefusedOnlyByReaderWrittenCode`] counts here: a reader who does not write the
    /// missing comparison gets no refusal at all.
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
                 who pins no key is reading a document that authenticates itself, and this \
                 repository ships no anchored verifier for a chain to a reader who does.",
        reach: Reach::RefusedOnlyByReaderWrittenCode(
            "no shipped symbol performs the comparison: rust/evidence/src/lib.rs exports \
             verify_receipt, verify_receipt_at, verify_chain, verify_chain_at and verify_authority \
             and no verify_chain_signed_by, while report::verify_export_signed_by, \
             verify_spend_signed_by and verify_stop_signed_by exist for the other envelopes. What \
             refuses A1 is two lines inside a1's own test. Task 1.6 owns the pinned-issuer \
             directory an anchored chain verifier would read from",
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
            "report::verify_export's receipt-to-bundle binding family, refusing as a Binding \
             rather than as a signature failure. Three members of that family bind to the same \
             bundle digest -- binding.receipt_id, operation.parameters_digest and \
             outcome.outcome_digest -- so no ONE of them is individually load-bearing here: \
             replacing binding.receipt_id's comparison with `true` leaves a3 green because \
             parameters_digest refuses the graft with the same variant. What a3 pins is the family \
             and the variant",
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
             refused for its mode and not for being unaccounted. Vector two is refused by the \
             report-level mode family rather than by one line of it: the evidence-receipt mode \
             comparison and the check_mode_honesty belt-and-braces below it both return \
             ReportError::Mode, so neutering either alone leaves a5 green. What a5 pins is the \
             family and the variant",
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
        target: "MemoryStore::put_artifact and artifact::ingest. What IS refused is a DIFFERENT \
                 attack -- rewriting an existing record. put_artifact returns AlreadyHeld and \
                 rewrites nothing, so append-only holds, and a8 asserts that too, because the \
                 refusal to rewrite is what makes the attribution residual tolerable.",
        reach: Reach::Unrefused(
            "the attack A8 declares is not refused, and a8's own assertions say so twice in the \
             words `RECORDED, not fixed`: artifact::ingest calls the anchor-free \
             report::verify_export, so an export signed end to end with a keypair the adversary \
             generated itself enters custody as PutOutcome::Stored, and the first filer owns \
             submitted_by_device on a digest. Task 10.6 owns custody semantics; Task 1.6 owns the \
             pinned-issuer directory the door would have to read to ask whose key signed it",
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
            Reach::Unrefused(fix)
            | Reach::Unrepresentable(fix)
            | Reach::RefusedOnlyByReaderWrittenCode(fix) => assert!(
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
        6,
        "A1, A2, A4, A7, A8 and A9 are the six attacks no code this repository ships refuses. If \
         that number changes, the product sentence in docs/W1-delivery-gaps.md changes with it, in \
         the same commit. It was 4 until an adversarial review showed that two of the five claimed \
         refusals were not refusals: A1's comparison is written inside a1's own test and no \
         shipped symbol offers it, and A8's own assertions record its declared attack succeeding \
         twice in the words `RECORDED, not fixed`."
    );
}

/// The corpus's real `#[ignore]` attributes: lines whose first non-whitespace is `#[ignore`.
///
/// Counted this way rather than by substring, because two doc comments in this corpus *discuss*
/// `#[ignore]` in prose -- `main.rs`'s "Ignored tests are findings" section and `forgery.rs`'s note
/// on A2 -- so a substring count answers 20 where the corpus holds 18. Getting that distinction
/// wrong in a helper would reproduce, inside the gate, exactly the defect the gate exists to catch.
fn ignore_attributes_in_the_corpus() -> usize {
    let directory = harness::repository_root().join("rust/warrant/tests/invariants");
    let mut total = 0;
    let mut stack = vec![directory];
    while let Some(directory) = stack.pop() {
        let entries = std::fs::read_dir(&directory).expect("the invariants directory is readable");
        for entry in entries {
            let path = entry.expect("readable entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let source = std::fs::read_to_string(&path).expect("readable suite file");
                total += source
                    .lines()
                    .filter(|line| line.trim_start().starts_with("#[ignore"))
                    .count();
            }
        }
    }
    total
}

#[test]
fn the_documents_ordinal_for_the_next_ignore_is_read_from_the_ratchet_and_not_from_the_plan() {
    // Rule 2 applied to a number this task got wrong. Both documents originally said "a thirteenth
    // ignore would raise `ignored_ceiling`" one sentence after correctly stating the count is 18,
    // so the next ignore is the nineteenth. Three independent reviews found it, and nothing gated
    // it: the suite gated the strategy count and the finding count and not this ordinal. The
    // ordinal is now spelled with the two numerals it is arithmetic over, so this test can derive
    // the whole sentence from the recorded ceiling instead of trusting a word beside it.
    let ratchet = harness::read_repository_file("tools/ci/invariant-ratchet.json");
    let ratchet: serde_json::Value =
        serde_json::from_str(&ratchet).expect("tools/ci/invariant-ratchet.json is JSON");
    let ceiling = usize::try_from(
        ratchet["ignored_ceiling"]
            .as_u64()
            .expect("the ratchet records an integer ignored_ceiling"),
    )
    .expect("the ceiling fits a usize");

    // The ceiling against the corpus it is a ceiling over. `check_invariant_ratchet.py` fails both
    // when the ignored count rises above the ceiling and when it falls below without the ceiling
    // moving, so on a green tree these are equal -- and a document that describes the ceiling is
    // describing this many attributes.
    assert_eq!(
        ignore_attributes_in_the_corpus(),
        ceiling,
        "tools/ci/invariant-ratchet.json records ignored_ceiling {ceiling}, and the corpus holds a \
         different number of #[ignore] attributes. One of the two is stale, and every sentence in \
         docs/ that renders this number is now wrong."
    );

    let claimed = format!(
        "`ignored_ceiling` is {ceiling}, so ignore number {} would raise it",
        ceiling + 1
    );
    for document in ["docs/W1-delivery-gaps.md", "docs/task-evidence/task-5.3.md"] {
        assert!(
            harness::read_repository_file(document).contains(&claimed),
            "{document} must say {claimed:?}. The ordinal is arithmetic over a recorded number, so \
             it belongs in a sentence a test can rebuild from the record rather than in a word \
             copied from a superseded plan."
        );
    }
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
        "{} of the nine are not refused by code this repository ships",
        STRATEGIES.iter().filter(|s| s.reach.is_a_finding()).count()
    );
    assert!(
        gaps.contains(&claimed),
        "docs/W1-delivery-gaps.md must state how many strategies are unrefused, and say {claimed:?}"
    );
}
