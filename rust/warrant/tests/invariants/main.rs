//! The invariant attack corpus — one suite per formal invariant I-01…I-12.
//!
//! # What this is
//!
//! `docs/02-architecture.md` §3 states twelve invariants and says that every one of them must have
//! "at least one static check, runtime check, adversarial test, and evidence field", and that "a
//! component that breaks an invariant fails CI". This corpus is that. It is a measuring
//! instrument, not a fix: no suite here changes an invariant's implementation, and several of them
//! demonstrate that an invariant the product publishes is not enforced.
//!
//! # How to read a suite
//!
//! Each file carries four kinds of check and says which is which:
//!
//! * a **static** check, over source that the assertion names, for the declaration or refusal text
//!   the invariant depends on;
//! * a **runtime** check, calling the real decision function;
//! * an **adversarial** test, which attempts the violation;
//! * an **evidence-field** assertion, that the record of the refusal carries what a reviewer would
//!   need.
//!
//! # The rule that makes the adversarial tests worth anything
//!
//! Every attack is run against a control with the attack backed out, and the control must be
//! *allowed*. An attack that fails because its payload was malformed produces a green result and a
//! false guarantee — the incident's phantom-scorer dynamic reproduced inside a test suite. See
//! [`harness::refused_at_the_boundary`], which fails loudly on a refused control rather than
//! quietly counting it as a pass.
//!
//! # Ignored tests are findings, not skips
//!
//! An `#[ignore]` here always names the invariant, the task that will fix it, and the date. Each
//! one is a currently-violated invariant recorded in `docs/W1-delivery-gaps.md`. Run them with:
//!
//! ```text
//! cargo test -p warrantor-warrant --test invariants -- --ignored
//! ```
//!
//! They fail. That is the finding, and it is the point. `tools/ci/check_invariant_ratchet.py`
//! holds the line: the passing count may never fall and the ignored count may never rise, so an
//! invariant cannot be quietly demoted by adding an attribute.
//!
//! # Numbering
//!
//! I-01…I-12 are the *formal* invariants from the architecture doc. The master blueprint
//! separately defines four *platform* invariants P1-P4, which map onto I-02, I-07 and I-11+I-12.
//! The two sets are never renumbered into each other and this corpus tests only the first.

mod fixture;
mod harness;
mod round_zero;
mod scenario;

mod i01_active_identity;
mod i02_no_authority_expansion;
mod i03_purpose_bound_data_use;
mod i04_current_policy;
mod i05_bounded_revocation_latency;
mod i06_exact_artifact_identity;
mod i07_evidence_precedes_commitment;
mod i08_non_delegable_human_authority;
mod i09_failure_is_safe;
mod i10_replay_is_detectable;
mod i11_self_change_is_governed;
mod i12_safe_state_is_reachable;
