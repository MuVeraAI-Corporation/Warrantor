//! The budget bound: what the ledger now measures, and everything it still cannot.
//!
//! The most important test in this file is `the_budget_bound_is_still_observed_after_wiring`. Every
//! other test exists to make the ledger worth having; that one exists to make sure having it did
//! not turn into a claim nobody can keep. Wiring an engine behind a bound creates exactly one
//! temptation — to promote the bound because it now has machinery behind it — and machinery is not
//! the thing that makes a bound enforceable. Being in the path of the action is, and Warrantor is
//! not in the path of a model API call.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use warrantor_warrant::spend::{
    self, DenyReason, ModelBackend, SpendError, SpendLedger, SpendStore, SpendVerdict, UsageClaim,
    AGENT_REPORTED, LEDGER_EXPORT_FORMAT, LEDGER_FORMAT, MICROS_PER_CENT,
};
use warrantor_warrant::store::StoredWarrant;
use warrantor_warrant::{
    bound_strengths, BoundStrength, SideEffectClass, Warrant, WarrantBounds, WarrantState,
};

const NOW: u64 = 1_786_000_000;

fn tempdir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-spend-{tag}-{}",
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

fn stranger() -> SigningKey {
    SigningKey::from_bytes(&[9; 32])
}

fn bounds(budget_cents: Option<u64>) -> WarrantBounds {
    WarrantBounds {
        tools: ["git".to_string()].into_iter().collect(),
        write_paths: ["src/**".to_string()].into_iter().collect(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: budget_cents,
        delegation_depth: 2,
    }
}

fn stored(budget_cents: Option<u64>) -> StoredWarrant {
    let warrant = Warrant::grant(
        "wrt_spend",
        "fix the auth bug",
        "spiffe://muveraai.com/agent/local",
        bounds(budget_cents),
        NOW,
        &SigningKey::from_bytes(&[2; 32]).verifying_key(),
        &issuer(),
    )
    .expect("grant");
    StoredWarrant {
        warrant,
        worktree: None,
        repo: None,
        branch: None,
        base_commit: None,
        staged_chain: None,
    }
}

fn ledger(budget_cents: Option<u64>) -> SpendLedger {
    SpendLedger::new(
        &bounds(budget_cents),
        "wrt_spend",
        "spiffe://muveraai.com/agent/local",
    )
}

/// gpt-4o at real-ish prices, a free self-hosted model, and one the operator marked unsafe.
fn backends() -> Vec<ModelBackend> {
    vec![
        ModelBackend {
            id: "paid-model".to_string(),
            price_per_1k_input_micros: 2_500,
            price_per_1k_output_micros: 10_000,
            safe: true,
        },
        ModelBackend {
            id: "free-local".to_string(),
            price_per_1k_input_micros: 0,
            price_per_1k_output_micros: 0,
            safe: true,
        },
        ModelBackend {
            id: "unapproved".to_string(),
            price_per_1k_input_micros: 1,
            price_per_1k_output_micros: 1,
            safe: false,
        },
    ]
}

fn claim(input: u64, output: u64, backend: Option<&str>) -> UsageClaim {
    UsageClaim {
        backend: backend.map(str::to_string),
        input_tokens: input,
        output_tokens: output,
    }
}

// ── the honesty boundary ──────────────────────────────────────────────────────────────

/// The one that must never change.
///
/// The spend engine is wired behind this bound now. It observes; it does not intercept. An agent
/// talks to its model provider directly and nothing in this process sees that conversation, so the
/// only figures the ledger can hold are ones the agent volunteered. That is `Observed`, and it is
/// `Observed` whether or not there is an engine behind it.
#[test]
fn the_budget_bound_is_still_observed_after_wiring() {
    let strengths: std::collections::HashMap<_, _> = bound_strengths().into_iter().collect();
    assert_eq!(
        strengths["budget_cents_observed"],
        BoundStrength::Observed,
        "wiring the spend engine measures the budget; it does not put warrantor in the path of a \
         model API call, so the bound cannot become Enforced"
    );
    assert_eq!(
        bound_strengths().len(),
        7,
        "no bound was added or removed by this wiring"
    );
}

/// Every record carries its provenance, and there is only one provenance available.
#[test]
fn every_recorded_figure_says_it_is_self_reported() {
    let mut ledger = ledger(Some(500));
    let decision = spend::record(
        &bounds(Some(500)),
        &mut ledger,
        &claim(1_000, 500, Some("paid-model")),
        &backends(),
        NOW,
    );
    assert!(decision.allowed());
    assert_eq!(ledger.entries.len(), 1);
    assert_eq!(ledger.entries[0].source, AGENT_REPORTED);
    assert_eq!(spend::section(&ledger).source, AGENT_REPORTED);
}

/// Nothing the module renders may imply Warrantor watched the provider.
#[test]
fn no_rendered_line_claims_the_provider_was_measured() {
    let mut ledger = ledger(Some(500));
    spend::record(
        &bounds(Some(500)),
        &mut ledger,
        &claim(1_000, 500, Some("paid-model")),
        &backends(),
        NOW,
    );
    let rendered = spend::section_lines(&spend::section(&ledger)).join("\n");
    let note = spend::OBSERVATION_NOTE.to_lowercase();
    for forbidden in [
        "enforced",
        "measured by warrantor",
        "provider-verified",
        "metered",
    ] {
        assert!(
            !rendered.to_lowercase().contains(forbidden),
            "the spend block must not contain {forbidden:?}: {rendered}"
        );
    }
    assert!(
        note.contains("observed, not enforced"),
        "the note carried to every human surface must say so: {note}"
    );
    assert!(
        rendered.contains(AGENT_REPORTED),
        "the provenance belongs on the line itself, not only in the limitations: {rendered}"
    );
}

// ── the cap, and what absence means ───────────────────────────────────────────────────

/// Whole cents in, micros out, with no floating point anywhere in between.
#[test]
fn cents_become_micros_exactly() {
    assert_eq!(spend::cap_micros(&bounds(Some(500))), 500 * MICROS_PER_CENT);
    assert_eq!(spend::cap_micros(&bounds(Some(500))), 5_000_000);
    assert_eq!(spend::usd(5_000_000), "$5.000000");
    assert_eq!(spend::usd(12_500), "$0.012500");
}

/// An absent limit is none, never unlimited — the rule the rest of this crate lives by, applied
/// to the one bound where "unlimited" was the previous behaviour.
#[test]
fn an_undeclared_budget_is_a_ceiling_of_zero_not_of_infinity() {
    let no_cap = bounds(None);
    assert!(!spend::cap_declared(&no_cap));
    assert_eq!(spend::cap_micros(&no_cap), 0);

    let mut ledger = ledger(None);
    let decision = spend::record(
        &no_cap,
        &mut ledger,
        &claim(1_000, 500, Some("paid-model")),
        &backends(),
        NOW,
    );
    assert!(
        matches!(
            decision.verdict,
            SpendVerdict::Deny {
                reason: DenyReason::UsdCapExceeded
            }
        ),
        "a warrant with no declared budget must not silently absorb a paid call"
    );
    assert_eq!(ledger.spent_micros, 0);
    assert!(ledger.entries.is_empty(), "a denial records nothing");
}

/// The same warrant can still record genuinely free usage: the ceiling is zero, and zero cost
/// fits inside zero.
#[test]
fn an_undeclared_budget_still_admits_zero_cost_usage() {
    let no_cap = bounds(None);
    let mut ledger = ledger(None);
    let decision = spend::record(
        &no_cap,
        &mut ledger,
        &claim(10_000, 10_000, Some("free-local")),
        &backends(),
        NOW,
    );
    assert!(decision.allowed());
    assert_eq!(ledger.spent_micros, 0);
    assert_eq!(ledger.entries.len(), 1);
}

/// A warrant that never had a budget was never budget-exhausted. Treating "no ceiling declared" as
/// "ceiling reached" would silently stop every run that never asked for a budget.
#[test]
fn an_undeclared_budget_is_not_an_exhausted_one() {
    assert!(!ledger(None).exhausted());
    let mut spent = ledger(Some(1));
    assert!(!spent.exhausted());
    spent.spent_micros = MICROS_PER_CENT;
    assert!(spent.exhausted(), "a declared ceiling reached is exhausted");
}

// ── recording ─────────────────────────────────────────────────────────────────────────

/// The engine's own price arithmetic, through the ledger, in micros.
#[test]
fn a_claim_is_priced_by_the_operators_table_and_accumulates() {
    let b = bounds(Some(500));
    let mut ledger = ledger(Some(500));
    // 1000 in @ 2500/1k + 500 out @ 10000/1k = 2500 + 5000 = 7500 micros.
    let first = spend::record(
        &b,
        &mut ledger,
        &claim(1_000, 500, Some("paid-model")),
        &backends(),
        NOW,
    );
    assert!(matches!(
        first.verdict,
        SpendVerdict::Allow {
            cost_micros: 7_500,
            ..
        }
    ));
    assert_eq!(ledger.spent_micros, 7_500);

    spend::record(
        &b,
        &mut ledger,
        &claim(1_000, 500, Some("paid-model")),
        &backends(),
        NOW + 1,
    );
    assert_eq!(
        ledger.spent_micros, 15_000,
        "spend accumulates across calls"
    );
    assert_eq!(ledger.remaining_micros(), 5_000_000 - 15_000);
    assert_eq!(ledger.summed_micros(), ledger.spent_micros);
}

/// The deny path, and the promise that a denial leaves the ledger exactly as it was.
#[test]
fn a_claim_over_the_ceiling_is_refused_and_records_nothing() {
    // One cent of ceiling: 10_000 micros. A 7_500-micro call fits; a second does not.
    let b = bounds(Some(1));
    let mut ledger = ledger(Some(1));
    assert!(spend::record(
        &b,
        &mut ledger,
        &claim(1_000, 500, Some("paid-model")),
        &backends(),
        NOW
    )
    .allowed());
    let before = ledger.clone();

    let second = spend::record(
        &b,
        &mut ledger,
        &claim(1_000, 500, Some("paid-model")),
        &backends(),
        NOW + 1,
    );
    assert!(matches!(
        second.verdict,
        SpendVerdict::Deny {
            reason: DenyReason::UsdCapExceeded
        }
    ));
    assert_eq!(ledger, before, "a denial must not move the ledger at all");
}

/// Backend selection, including the two ways it refuses.
#[test]
fn backend_selection_refuses_the_unapproved_and_defaults_to_the_cheapest_safe() {
    let table = backends();
    let cheapest = spend::choose(None, &table).expect("a safe backend exists");
    assert_eq!(cheapest.id, "free-local");

    let named = spend::choose(Some("paid-model"), &table).expect("named and safe");
    assert_eq!(named.id, "paid-model");

    assert_eq!(
        spend::choose(Some("unapproved"), &backends()),
        Err(DenyReason::BackendNotApproved),
        "a backend the operator did not mark safe is never selectable, even when named"
    );
    assert_eq!(
        spend::choose(Some("never-heard-of-it"), &backends()),
        Err(DenyReason::BackendNotApproved)
    );
    assert_eq!(spend::choose(None, &[]), Err(DenyReason::NoSafeBackend));
}

/// An empty price table denies rather than pricing at zero. A missing price is not a free call.
#[test]
fn no_price_table_means_no_record() {
    let b = bounds(Some(500));
    let mut ledger = ledger(Some(500));
    let decision = spend::record(&b, &mut ledger, &claim(1_000, 500, None), &[], NOW);
    assert!(matches!(
        decision.verdict,
        SpendVerdict::Deny {
            reason: DenyReason::NoSafeBackend
        }
    ));
    assert!(ledger.entries.is_empty());
}

/// An absurd claim must deny, not wrap into an allow. This is the warrant-side half of the
/// saturating-arithmetic fix in the engine: the ledger hands the engine numbers an agent chose,
/// and an agent can choose `u64::MAX`.
#[test]
fn an_absurd_claim_denies_rather_than_overflowing() {
    let b = bounds(Some(500));
    let mut ledger = ledger(Some(500));
    let decision = spend::record(
        &b,
        &mut ledger,
        &claim(u64::MAX, u64::MAX, Some("paid-model")),
        &backends(),
        NOW,
    );
    assert!(
        matches!(
            decision.verdict,
            SpendVerdict::Deny {
                reason: DenyReason::UsdCapExceeded
            }
        ),
        "an overflowing cost must compare LARGE and deny, never wrap small and allow"
    );
    assert_eq!(ledger.spent_micros, 0);
}

/// The ceiling is read from the signed claims on every record, so an edited ledger cannot raise
/// its own cap.
#[test]
fn the_ceiling_is_re_read_from_the_signed_bounds_on_every_record() {
    let b = bounds(Some(1));
    let mut ledger = ledger(Some(1));
    // Forge a generous ceiling into the mutable ledger.
    ledger.cap_micros = 999_999_999;
    ledger.cap_declared = true;

    let decision = spend::record(
        &b,
        &mut ledger,
        &claim(1_000, 500, Some("paid-model")),
        &backends(),
        NOW,
    );
    assert!(decision.allowed());
    assert_eq!(
        ledger.cap_micros, MICROS_PER_CENT,
        "the cap came back from the signed bounds, not from the file"
    );
}

// ── cost-aware routing metadata ───────────────────────────────────────────────────────

/// Quotes price the same work everywhere and say what the remaining ceiling still covers.
#[test]
fn quotes_price_every_backend_and_flag_what_is_still_affordable() {
    let mut ledger = ledger(Some(1)); // 10_000 micros
    let quotes = spend::quotes(&ledger, &claim(1_000, 500, None), &backends());
    assert_eq!(quotes.len(), 3);
    // Safe first, then cheapest.
    assert_eq!(quotes[0].backend, "free-local");
    assert!(quotes[0].affordable);
    assert_eq!(quotes[1].backend, "paid-model");
    assert_eq!(quotes[1].cost_micros, 7_500);
    assert!(quotes[1].affordable, "7500 fits inside a 10000 ceiling");

    let unsafe_quote = quotes.iter().find(|q| q.backend == "unapproved").unwrap();
    assert!(!unsafe_quote.safe);
    assert!(
        !unsafe_quote.affordable,
        "an unapproved backend is never affordable, whatever it costs"
    );

    // Spend most of the ceiling and the paid model stops being reachable.
    ledger.spent_micros = 9_000;
    let after = spend::quotes(&ledger, &claim(1_000, 500, None), &backends());
    let paid = after.iter().find(|q| q.backend == "paid-model").unwrap();
    assert!(
        !paid.affordable,
        "routing advice must follow the remaining ceiling, not the list price"
    );
    assert!(
        after
            .iter()
            .find(|q| q.backend == "free-local")
            .unwrap()
            .affordable
    );
}

// ── evidence ──────────────────────────────────────────────────────────────────────────

fn signed_ledger(cents: Option<u64>) -> spend::SignedSpend {
    let b = bounds(cents);
    let mut ledger = ledger(cents);
    let decision = spend::record(
        &b,
        &mut ledger,
        &claim(1_000, 500, Some("paid-model")),
        &backends(),
        NOW,
    );
    assert!(decision.allowed(), "the fixture must be an allow");
    spend::sign(&ledger, &decision, &issuer(), "issuer", NOW).expect("sign")
}

#[test]
fn a_signed_ledger_verifies_offline() {
    let signed = signed_ledger(Some(500));
    assert_eq!(signed.format, LEDGER_EXPORT_FORMAT);
    assert_eq!(signed.ledger.format, LEDGER_FORMAT);
    spend::verify_spend(&signed).expect("a freshly signed ledger verifies");
    assert!(
        !signed.limitations.is_empty(),
        "an artifact whose caveats are implicit teaches its reader to hear more than was said"
    );
}

/// The receipt binds the whole ledger through its task id. Change one entry and it no longer
/// describes the file it sits in.
#[test]
fn editing_an_entry_breaks_the_receipt_binding() {
    let mut signed = signed_ledger(Some(500));
    signed.ledger.entries[0].cost_micros = 1;
    signed.ledger.spent_micros = 1;
    let err = spend::verify_spend(&signed).expect_err("an edited ledger must not verify");
    assert!(
        matches!(err, SpendError::Digest { .. }),
        "expected a digest mismatch, got {err}"
    );
}

/// Re-signing the edit with a valid key does not save it: the digest is recomputed from the ledger
/// and compared against the one the receipt actually carries.
#[test]
fn re_signing_a_lowered_total_does_not_launder_it() {
    let b = bounds(Some(500));
    let mut ledger = ledger(Some(500));
    let decision = spend::record(
        &b,
        &mut ledger,
        &claim(1_000, 500, Some("paid-model")),
        &backends(),
        NOW,
    );
    // Halve the recorded spend, then sign the LIE with a perfectly good key.
    ledger.spent_micros = 1;
    let signed = spend::sign(&ledger, &decision, &issuer(), "issuer", NOW).expect("sign");
    let err = spend::verify_spend(&signed)
        .expect_err("a total that disagrees with its own entries must be refused");
    assert!(
        matches!(err, SpendError::Binding(_)),
        "expected the entry-sum check to catch it, got {err}"
    );
}

/// A ledger cannot record past its own ceiling, however it was assembled.
#[test]
fn a_ledger_over_its_own_ceiling_is_refused() {
    let b = bounds(Some(1));
    let mut ledger = ledger(Some(1));
    let decision = spend::record(
        &b,
        &mut ledger,
        &claim(1_000, 500, Some("paid-model")),
        &backends(),
        NOW,
    );
    ledger.cap_micros = 100; // below what is already recorded
    let signed = spend::sign(&ledger, &decision, &issuer(), "issuer", NOW).expect("sign");
    assert!(matches!(
        spend::verify_spend(&signed),
        Err(SpendError::Binding(_))
    ));
}

/// Stripping the caveats is itself a failure. A verified spend figure with no statement of where
/// it came from is the artifact this whole module exists to avoid producing.
#[test]
fn an_export_with_no_limitations_is_refused() {
    let b = bounds(Some(500));
    let mut ledger = ledger(Some(500));
    let decision = spend::record(
        &b,
        &mut ledger,
        &claim(1_000, 500, Some("paid-model")),
        &backends(),
        NOW,
    );
    let mut signed = spend::sign(&ledger, &decision, &issuer(), "issuer", NOW).expect("sign");
    signed.limitations.clear();
    // Re-sign so nothing but the missing caveats can be the reason it fails.
    let resigned = spend::sign(&signed.ledger, &decision, &issuer(), "issuer", NOW).expect("sign");
    signed.ledger_digest = resigned.ledger_digest;
    signed.receipt = resigned.receipt;
    assert!(matches!(
        spend::verify_spend(&signed),
        Err(SpendError::Binding(_))
    ));
}

#[test]
fn a_future_format_is_refused_rather_than_parsed_hopefully() {
    let mut signed = signed_ledger(Some(500));
    signed.format = "warrantor.spend-export/99".to_string();
    assert!(matches!(
        spend::verify_spend(&signed),
        Err(SpendError::Format { .. })
    ));
}

/// The limitations must always name the thing a reader would otherwise get wrong.
#[test]
fn the_limitations_name_self_reporting_and_the_zero_token_field() {
    let all = spend::limitations().join("\n");
    assert!(all.contains("reported by the agent about itself"), "{all}");
    assert!(all.contains("BoundStrength::Observed"), "{all}");
    assert!(
        all.contains("remaining_tokens is 0"),
        "a receipt read on its own cannot tell an undeclared allowance from an exhausted one: {all}"
    );
}

/// `remaining_tokens` is zero because no token allowance was declared, and the module says so
/// rather than letting a reader infer exhaustion.
#[test]
fn an_allow_reports_zero_remaining_tokens_because_none_were_ever_granted() {
    let signed = signed_ledger(Some(500));
    match &signed.receipt.body.verdict {
        SpendVerdict::Allow {
            remaining_tokens,
            remaining_usd_micros,
            ..
        } => {
            assert_eq!(*remaining_tokens, 0);
            assert_eq!(*remaining_usd_micros, signed.ledger.remaining_micros());
        }
        other => panic!("expected an allow, got {other:?}"),
    }
}

// ── storage ───────────────────────────────────────────────────────────────────────────

fn store_at(root: &Path) -> SpendStore {
    SpendStore::open(root).expect("open spend store")
}

#[test]
fn an_absent_ledger_reads_as_empty_not_as_an_error() {
    let dir = tempdir("absent");
    let store = store_at(&dir);
    let loaded = store
        .load(
            &bounds(Some(500)),
            "wrt_spend",
            "spiffe://muveraai.com/agent/local",
            &issuer().verifying_key(),
        )
        .expect("a warrant that has recorded nothing has an empty ledger");
    assert_eq!(loaded.spent_micros, 0);
    assert!(loaded.entries.is_empty());
    assert_eq!(loaded.cap_micros, 5_000_000);
}

#[test]
fn a_saved_ledger_round_trips_and_accumulates_across_processes() {
    let dir = tempdir("roundtrip");
    let store = store_at(&dir);
    let signed = signed_ledger(Some(500));
    store.save(&signed).expect("save");

    let loaded = store
        .load(
            &bounds(Some(500)),
            "wrt_spend",
            "spiffe://muveraai.com/agent/local",
            &issuer().verifying_key(),
        )
        .expect("load");
    assert_eq!(loaded.spent_micros, 7_500);
    assert_eq!(loaded.entries.len(), 1);
}

/// Tamper with the file on disk and the next load refuses. Silently resetting the total to zero
/// would hand the cap back to anyone who can write the file.
#[test]
fn a_tampered_ledger_file_refuses_to_load() {
    let dir = tempdir("tampered");
    let store = store_at(&dir);
    let signed = signed_ledger(Some(500));
    let path = store.save(&signed).expect("save");

    let body = std::fs::read_to_string(&path).expect("read");
    std::fs::write(&path, body.replace("7500", "1")).expect("write");

    let err = store
        .load(
            &bounds(Some(500)),
            "wrt_spend",
            "spiffe://muveraai.com/agent/local",
            &issuer().verifying_key(),
        )
        .expect_err("an edited ledger must not load");
    assert!(
        matches!(err, SpendError::Digest { .. } | SpendError::Binding(_)),
        "got {err}"
    );
}

/// Corrupt beyond parsing is still not zero spend.
#[test]
fn an_unparseable_ledger_is_an_error_not_a_fresh_start() {
    let dir = tempdir("corrupt");
    let store = store_at(&dir);
    std::fs::write(store.path("wrt_spend"), b"{ not json").expect("write");
    let err = store
        .load(
            &bounds(Some(500)),
            "wrt_spend",
            "spiffe://muveraai.com/agent/local",
            &issuer().verifying_key(),
        )
        .expect_err("an unreadable ledger must not read as zero spend");
    assert!(matches!(err, SpendError::Encode(_)), "got {err}");
}

/// A ledger that vouches for itself with its own key proves nothing. The trust anchor is the key
/// on disk, the same discipline the report's chain gate uses.
#[test]
fn a_ledger_signed_by_a_stranger_is_refused() {
    let dir = tempdir("stranger");
    let store = store_at(&dir);
    let b = bounds(Some(500));
    let mut led = ledger(Some(500));
    let decision = spend::record(
        &b,
        &mut led,
        &claim(1_000, 500, Some("paid-model")),
        &backends(),
        NOW,
    );
    // Internally valid in every way — it just is not ours.
    let signed = spend::sign(&led, &decision, &stranger(), "issuer", NOW).expect("sign");
    spend::verify_spend(&signed).expect("the stranger's own signature checks out");
    store.save(&signed).expect("save");

    let err = store
        .load(
            &b,
            "wrt_spend",
            "spiffe://muveraai.com/agent/local",
            &issuer().verifying_key(),
        )
        .expect_err("a ledger signed by another key must not be trusted");
    assert!(matches!(err, SpendError::Binding(_)), "got {err}");
}

/// A ledger filed under one warrant must not answer for another.
#[test]
fn a_ledger_for_another_warrant_is_refused() {
    let dir = tempdir("swapped");
    let store = store_at(&dir);
    let signed = signed_ledger(Some(500));
    // Same content, filed under a different id.
    let path = store.path("wrt_other");
    std::fs::write(&path, serde_json::to_vec(&signed).expect("encode")).expect("write");
    let err = store
        .load(
            &bounds(Some(500)),
            "wrt_other",
            "spiffe://muveraai.com/agent/local",
            &issuer().verifying_key(),
        )
        .expect_err("a ledger must answer only for the warrant it names");
    assert!(matches!(err, SpendError::Binding(_)), "got {err}");
}

// ── the price table ───────────────────────────────────────────────────────────────────

/// Warrantor does not know what any model costs, so an absent table denies loudly rather than
/// defaulting. A guessed price would go straight into a signed receipt as though it were a fact.
#[test]
fn a_missing_price_table_denies_and_says_what_to_write() {
    let dir = tempdir("no-backends");
    let err = spend::load_backends(&dir).expect_err("no table means no pricing");
    let message = err.to_string();
    assert!(message.contains("backends.json"), "{message}");
    assert!(
        message.contains("will not guess"),
        "the message has to say why there is no default: {message}"
    );
}

#[test]
fn an_empty_price_table_approves_nothing() {
    let dir = tempdir("empty-backends");
    std::fs::write(dir.join("backends.json"), b"[]").expect("write");
    assert!(matches!(
        spend::load_backends(&dir),
        Err(SpendError::Backends(_))
    ));
}

#[test]
fn a_price_table_round_trips() {
    let dir = tempdir("backends");
    std::fs::write(
        dir.join("backends.json"),
        serde_json::to_vec(&backends()).expect("encode"),
    )
    .expect("write");
    let loaded = spend::load_backends(&dir).expect("load");
    assert_eq!(loaded.len(), 3);
    assert_eq!(loaded[0].id, "paid-model");
}

// ── the report ────────────────────────────────────────────────────────────────────────

/// The report carries the budget bound's VALUE and its observed spend, which it never did before:
/// the BOUNDS block printed the word "observed" beside a number nothing had looked at.
#[test]
fn the_report_carries_the_observed_spend_and_says_whose_figures_they_are() {
    let dir = tempdir("report");
    let queue = warrantor_warrant::staging::StagingQueue::open(
        dir.join("staged.jsonl"),
        "wrt_spend",
        warrantor_warrant::staging::EffectRegistry::github(),
    )
    .expect("queue");

    let b = bounds(Some(500));
    let mut led = ledger(Some(500));
    spend::record(
        &b,
        &mut led,
        &claim(1_000, 500, Some("paid-model")),
        &backends(),
        NOW,
    );

    let built = warrantor_warrant::report::build_observed(
        &stored(Some(500)),
        Ok(&queue),
        &issuer().verifying_key(),
        NOW,
        &[],
        Some(spend::section(&led)),
    );
    let bundle = built.bundle();
    let section = bundle.spend.as_ref().expect("the section is carried");
    assert_eq!(section.spent_micros, 7_500);
    assert_eq!(section.cap_micros, 5_000_000);
    assert!(section.cap_declared);
    assert_eq!(section.records, 1);

    let text = warrantor_warrant::report::render_cli(bundle);
    assert!(
        text.contains("── SPEND (OBSERVED, SELF-REPORTED) ──"),
        "{text}"
    );
    assert!(text.contains("$0.007500"), "{text}");
    assert!(text.contains(AGENT_REPORTED), "{text}");

    let all = bundle.limitations.join("\n");
    assert!(all.contains("budget_cents_observed"), "{all}");
    assert!(
        all.contains("self-reported"),
        "the caveat must say where the figure came from: {all}"
    );
}

/// The five sections a developer reads every morning are untouched when no ledger was consulted.
/// That is what keeps "the prose report is exactly what it always was" a structural guarantee
/// rather than a promise: the block cannot appear unless something asked for it.
#[test]
fn a_report_with_no_ledger_renders_exactly_as_before() {
    let dir = tempdir("no-ledger");
    let queue = warrantor_warrant::staging::StagingQueue::open(
        dir.join("staged.jsonl"),
        "wrt_spend",
        warrantor_warrant::staging::EffectRegistry::github(),
    )
    .expect("queue");
    let built = warrantor_warrant::report::build(
        &stored(Some(500)),
        Ok(&queue),
        &issuer().verifying_key(),
        NOW,
    );
    assert!(built.bundle().spend.is_none());
    let text = warrantor_warrant::report::render_cli(built.bundle());
    assert!(!text.contains("SPEND"), "{text}");
    assert!(
        built
            .bundle()
            .limitations
            .iter()
            .any(|l| l.contains("was not consulted here")),
        "a bundle with no ledger must say it read none, not that nothing was spent: {:?}",
        built.bundle().limitations
    );
}

// ── the MCP surfaces ──────────────────────────────────────────────────────────────────

/// Every MCP-granted warrant used to be uncapped: `budget_cents_observed` was hardcoded `None` and
/// the tool schema had no property for it, so a caller could not have set one if it wanted to.
#[test]
fn the_mcp_grant_tool_can_declare_a_ceiling_and_absent_still_means_none() {
    use serde_json::{json, Value};
    use warrantor_warrant::mcp::Endpoint;
    use warrantor_warrant::mcp_endpoints::ControlEndpoint;
    use warrantor_warrant::store::WarrantStore;

    let dir = tempdir("mcp-grant");
    let store = WarrantStore::open(&dir).expect("store");
    let mut endpoint = ControlEndpoint::new(
        store,
        dir.clone(),
        issuer(),
        SigningKey::from_bytes(&[2; 32]),
        || NOW,
    );

    let schema = endpoint
        .tools()
        .into_iter()
        .find(|tool| tool.name == "warrant_grant")
        .expect("warrant_grant is published")
        .input_schema
        .to_string();
    assert!(
        schema.contains("budget_cents"),
        "a caller cannot set a ceiling it is never offered: {schema}"
    );
    assert!(
        schema.contains("Absent means a ceiling of zero, not unlimited"),
        "the schema has to say what absence means: {schema}"
    );

    // Two stores, because the id is derived from the clock and this endpoint's clock is fixed:
    // granting twice into one store would overwrite rather than produce two warrants.
    let declared = |root: &Path, budget: Option<u64>| -> Option<u64> {
        let store = WarrantStore::open(root).expect("store");
        let mut endpoint = ControlEndpoint::new(
            store,
            root.to_path_buf(),
            issuer(),
            SigningKey::from_bytes(&[2; 32]),
            || NOW,
        );
        let mut arguments = std::collections::BTreeMap::new();
        arguments.insert("goal".to_string(), json!("with a ceiling"));
        arguments.insert("tools".to_string(), json!(["git"]));
        if let Some(cents) = budget {
            arguments.insert("budget_cents".to_string(), json!(cents));
        }
        let result = endpoint.call("warrant_grant", &arguments);
        assert!(!result.is_error, "{:?}", result.text);
        WarrantStore::open(root)
            .expect("store")
            .list()
            .expect("list")[0]
            .warrant
            .claims
            .bounds
            .budget_cents_observed
    };

    assert_eq!(
        declared(&tempdir("mcp-capped"), Some(750)),
        Some(750),
        "the declared ceiling must reach the signed claims"
    );
    assert_eq!(
        declared(&tempdir("mcp-uncapped"), None),
        None,
        "an absent ceiling must stay absent rather than becoming a default"
    );
    let _ = Value::Null;
}

/// The MCP grant tool must never turn a malformed ceiling into no ceiling.
///
/// `budget_cents` was read with `Value::as_u64`, which answers `None` for `"500"`, for `500.0` and
/// for `-1` alike — every one of them a shape an LLM caller emits for an integer field. `None` is
/// not "the caller said nothing" here: `spend::cap_declared` goes false, so the warrant is never
/// `exhausted` and nothing downstream can refuse it on budget grounds. The cap was dropped at the
/// exact moment the caller was setting it, with no error. This is the `--budget 5x` bug that
/// `warrantor grant` already refuses, on the other surface.
///
/// Two properties, and the second is the one that makes the first worth having: a malformed value
/// is a refusal that names the fix, and a refused grant leaves NO warrant behind — a half-granted
/// warrant with a silently absent ceiling would be the same hole wearing an error message.
#[test]
fn the_mcp_grant_tool_refuses_a_budget_it_cannot_parse_rather_than_dropping_the_cap() {
    use serde_json::json;
    use warrantor_warrant::mcp::Endpoint;
    use warrantor_warrant::mcp_endpoints::ControlEndpoint;
    use warrantor_warrant::store::WarrantStore;

    let grant = |tag: &str, budget: serde_json::Value| -> (bool, String, usize, Option<u64>) {
        let root = tempdir(tag);
        let store = WarrantStore::open(&root).expect("store");
        let mut endpoint = ControlEndpoint::new(
            store,
            root.clone(),
            issuer(),
            SigningKey::from_bytes(&[2; 32]),
            || NOW,
        );
        let mut arguments = std::collections::BTreeMap::new();
        arguments.insert("goal".to_string(), json!("cap me"));
        arguments.insert("tools".to_string(), json!(["git"]));
        arguments.insert("budget_cents".to_string(), budget);
        let result = endpoint.call("warrant_grant", &arguments);
        let granted = WarrantStore::open(&root)
            .expect("store")
            .list()
            .expect("list");
        let declared = granted
            .first()
            .and_then(|w| w.warrant.claims.bounds.budget_cents_observed);
        (result.is_error, result.text, granted.len(), declared)
    };

    // The shapes a model actually emits for an integer field. Every one of these used to become a
    // warrant with no declared ceiling, reported to the caller as a success.
    for (tag, budget) in [
        ("mcp-budget-string", json!("500")),
        ("mcp-budget-float", json!(500.5)),
        ("mcp-budget-negative", json!(-1)),
        ("mcp-budget-words", json!("five dollars")),
        ("mcp-budget-array", json!([500])),
        ("mcp-budget-bool", json!(true)),
    ] {
        // The pre-fix read, pinned so the trap cannot quietly come back: `as_u64` answers `None`
        // for every shape in this list, and `None` here is a warrant with no declared ceiling.
        // Whatever the assertions below demand, they demand it of a path that must not be this
        // expression -- if `budget_cents` is ever read this way again, they fail.
        assert_eq!(
            budget.as_u64(),
            None,
            "{budget} is exactly a shape Value::as_u64 drops; the test is pointless if it is not"
        );

        let (is_error, text, count, declared) = grant(tag, budget.clone());
        if tag == "mcp-budget-string" {
            // "500" has exactly one whole-cent reading, so taking it is not a guess.
            assert!(!is_error, "a clean decimal string is unambiguous: {text}");
            assert_eq!(declared, Some(500), "{budget} must reach the signed claims");
            continue;
        }
        assert!(
            is_error,
            "{budget} silently dropped the cap instead of refusing: {text}"
        );
        assert!(
            text.contains("budget_cents") && text.contains("whole"),
            "the refusal has to name the argument and the fix: {text}"
        );
        assert_eq!(
            count, 0,
            "a refused budget must leave NO warrant behind; {budget} minted one anyway"
        );
        assert_eq!(declared, None, "sanity: nothing was stored for {budget}");
    }

    // A float that is exactly a whole count of cents is that count, not a refusal.
    let (is_error, text, _, declared) = grant("mcp-budget-whole-float", json!(500.0));
    assert!(
        !is_error,
        "500.0 is the integer 500 as a model writes it: {text}"
    );
    assert_eq!(
        declared,
        Some(500),
        "an integral float must reach the claims"
    );

    // An explicit null is the caller saying nothing, which already means a ceiling of zero.
    let (is_error, text, _, declared) = grant("mcp-budget-null", json!(null));
    assert!(!is_error, "an explicit null is not a malformed cap: {text}");
    assert_eq!(
        declared, None,
        "null must read as absent, i.e. a cap of zero"
    );
}

/// A stopped, held or settled warrant still reports whatever the ledger holds — spend does not
/// vanish because the lifecycle moved on.
#[test]
fn the_spend_section_survives_a_lifecycle_transition() {
    let dir = tempdir("held");
    let queue = warrantor_warrant::staging::StagingQueue::open(
        dir.join("staged.jsonl"),
        "wrt_spend",
        warrantor_warrant::staging::EffectRegistry::github(),
    )
    .expect("queue");
    let b = bounds(Some(500));
    let mut led = ledger(Some(500));
    spend::record(
        &b,
        &mut led,
        &claim(1_000, 500, Some("paid-model")),
        &backends(),
        NOW,
    );

    let mut held = stored(Some(500));
    held.warrant
        .transition(WarrantState::Held)
        .expect("open -> held");
    let built = warrantor_warrant::report::build_observed(
        &held,
        Ok(&queue),
        &issuer().verifying_key(),
        NOW,
        &[],
        Some(spend::section(&led)),
    );
    assert_eq!(
        built.bundle().spend.as_ref().expect("carried").spent_micros,
        7_500
    );
}

// ── the run precondition ──────────────────────────────────────────────────────────────

/// Wall-clock seconds. The stored warrant a `warrantor run` test loads has to be genuinely live:
/// the deadline precondition is checked before the budget one, so a warrant pinned to [`NOW`]
/// would be refused first and for the wrong reason.
fn wall_clock_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// An Open warrant whose deadline has not passed, saved where the CLI will look for it.
fn live_warrant(root: &Path, id: &str, budget_cents: Option<u64>) {
    let at = wall_clock_now();
    let mut live = bounds(budget_cents);
    live.expires_at = at + 3_600;
    let warrant = Warrant::grant(
        id,
        "fix the auth bug",
        "spiffe://muveraai.com/agent/local",
        live,
        at,
        &SigningKey::from_bytes(&[2; 32]).verifying_key(),
        &issuer(),
    )
    .expect("grant");
    assert_eq!(warrant.state, WarrantState::Open);
    warrantor_warrant::store::WarrantStore::open(root)
        .expect("open warrant store")
        .save(&StoredWarrant {
            warrant,
            worktree: None,
            repo: None,
            branch: None,
            base_commit: None,
            staged_chain: None,
        })
        .expect("save warrant");
}

/// `warrantor run` must not start a run whose budget state it could not read — including when the
/// failure is the ledger STORE rather than a ledger.
///
/// The precondition read `if let Ok(ledgers) = SpendStore::open(root)`, so a store that would not
/// open skipped the whole exhaustion check and the run started: the outer arm failed open while
/// the inner arm, a few lines below it, explicitly refused a warrant whose ledger would not load.
/// Two arms of one check contradicting each other about the same unknown, and the silent one won
/// whenever the thing that was broken happened to be the directory rather than a file in it. The
/// bound is still `Observed` either way — what this restores is that the one place the reported
/// figure has teeth cannot be stepped around by making the ledger directory unavailable.
///
/// Driven through the real binary because the contradiction lived in `cmd_run`, not in the
/// library: a test against `SpendStore` alone would have passed both before and after.
#[test]
fn run_refuses_when_the_spend_ledger_store_will_not_open() {
    let home = tempdir("run-store-unopenable");
    let root = home.join(".warrantor");
    let id = "wrt_run_budget";
    live_warrant(&root, id, Some(500));

    // A regular file where `<root>/spend/` has to be: `create_dir_all` cannot make the directory,
    // so `SpendStore::open` fails and the budget state is unknowable. Nothing else is disturbed.
    std::fs::write(root.join("spend"), b"not a directory").expect("write");
    assert!(
        SpendStore::open(&root).is_err(),
        "the test is pointless unless the store really refuses to open"
    );

    // The agent command is this same binary printing its usage: harmless, present on every
    // platform, and it exits at once. Before the fix the supervisor was spawned to run it.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_warrantor"))
        .args(["run", id, "--", env!("CARGO_BIN_EXE_warrantor"), "--help"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .expect("run warrantor");
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        stderr.contains("budget state is unknown"),
        "an unopenable ledger store has to be refused in the same terms as an unreadable ledger, \
         not skipped: {stderr}"
    );
    assert!(
        !out.status.success(),
        "the run started anyway: {stderr}{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        !root.join("logs").join(format!("{id}.log")).exists(),
        "a refused run must not have spawned a supervisor"
    );
}
