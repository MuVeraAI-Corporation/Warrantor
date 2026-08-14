//! The evidence archive: durable custody for signed Warrantor evidence, held by a party that
//! cannot forge it.
//!
//! This is stage 1 of the backend RFC W1 bounds — see `docs/rfcs/W2-evidence-archive.md`. It stores
//! the three files `warrantor verify` already reads (`warrantor.report-export/1`,
//! `warrantor.stop-export/1`, `warrantor.ledger-export/1`), content-addressed by SHA-256, in
//! Postgres, behind device-pairing authentication.
//!
//! # The design target, stated first because everything below is shaped by it
//!
//! > **Compromise of this server must degrade availability, never integrity.**
//!
//! An attacker holding this database and this process can withhold an artifact, delay a read, or
//! serve a stale list. They must not be able to make a tampered bundle verify at a client. That is
//! a falsifiable claim and it has a test:
//! `tests/verification_does_not_depend_on_the_archive.rs`.
//!
//! # The four things this crate is not
//!
//! Written in the register [`warrantor_warrant::serve`] uses for the same reason: a crate whose
//! doc does not state what it refuses to do will drift into an authority within two changes.
//!
//! 1. **It is a relay, never an authority.** It stores bytes it was given and returns them
//!    unchanged. It does not decide anything about a warrant, and it has no route that accepts
//!    claims and returns something signed — the moment one exists, warrant-minting authority lives
//!    in a network-reachable process.
//! 2. **Its ingest check is hygiene, and its opinion is never served as a verdict.** Signatures are
//!    verified at the door, and what is refused there is a submission that is not one of the three
//!    evidence files at all — not one whose signatures fail. A file that fails the check is stored
//!    and marked `failed`; a file this build cannot parse is stored and marked `unknown`, because
//!    no verifier ran on it. Refusing to hold either would delete the evidence that it arrived.
//!    That result is recorded and is returned under a field literally named
//!    `not_a_verdict`, because on a remote archive a field called `verified` is exactly what a
//!    viewer would render as one. See [`http`], which deliberately does **not** reuse
//!    [`warrantor_warrant::serve::Response`] for that reason.
//! 3. **It holds no key that can do anything.** No settle key, no issuer key, no grant path. The
//!    only key material it holds is device *public* keys, which authenticate submissions and
//!    authorise nothing else.
//! 4. **Every client re-verifies locally, against an anchor it pinned.** Verification happens only
//!    in Rust, client-side. Nothing above the Rust line ever checks a signature, because a second
//!    verifier can disagree with the first and then a human has to decide which to believe.
//!
//! # Append-only, and what that is worth
//!
//! Nothing here updates or deletes an artifact. That is enforced twice in
//! `migrations/0001_initial.sql` — a `BEFORE UPDATE OR DELETE` trigger and a runtime role with no
//! `UPDATE`/`DELETE` grant — because a grant can be misconfigured by an operator and a trigger
//! cannot. Retention and export knobs exist and are **defaulted off**: an absent retention window
//! grants no deletion authority at all, and is never read as "delete everything older than
//! nothing".
//!
//! It is worth being exact about the limit. Append-only is a property of the *application role*,
//! not of the storage: whoever owns the database can delete rows out of band, and no trigger stops
//! them. What actually carries the custody guarantee is that the artifacts are independently
//! verifiable off this archive, against an anchor the reader pinned — which is why
//! [`warrantor_warrant::report::verify_export_signed_by`] had to exist before this crate could
//! honestly ship.
//!
//! # What a device signature attributes, and what it does not
//!
//! An enrolled device signs each request with an Ed25519 key, so the audit trail names a person
//! rather than "someone holding the token". That closes the *submission* half of W1 delivery gap
//! 2.2 and no more: it attributes who filed an artifact and who read one. It does **not** attribute
//! the settle, which happens on a laptop under the local agent's settle key and may never touch
//! this server. "Who settled this" becomes true only once the local agent binds a device key into
//! the settle record, and that is not this stage.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod artifact;
pub mod device;
pub mod http;
pub mod postgres;
pub mod store;

/// Wire format of an archive success or refusal body.
///
/// Present from the first release for the reason every other format constant in this repository is:
/// the day the shape changes, a client parsing the old one must fail loudly rather than silently
/// read a field that moved.
pub const ARCHIVE_RESPONSE_FORMAT: &str = "warrantor.archive-response/1";

/// SHA-256 hex of a byte string.
///
/// One implementation, used for the artifact digest, the enrolment-code digest and the body digest
/// a device signature covers. A digest computed a second way — in SQL, in a client, in a helper
/// that re-serialises first — is a second implementation of the rule that says which bytes are
/// which artifact.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

// A `digests_match` constant-time comparison used to live here, and it is deliberately gone.
//
// It was never called. Nothing in this crate compares an enrolment-code digest in Rust: `MemoryStore
// ::enrol_device` is a `BTreeMap::get(code_digest)` and `PostgresStore::enrol_device` is a
// `WHERE code_sha256 = $1` decided by a Postgres index — neither is constant-time and neither could
// route through a helper without becoming a full scan of the code table. Keeping the function made
// the RFC's threat-model row read "constant-time comparison" as a shipped mitigation, which is a
// control an auditor checks and this one did not survive `grep`. A dead guard is NO SIGNAL, never
// "all clear", so the guard is removed and the claim is corrected downward in RFC W2 rather than
// left standing over an empty function.
//
// The residual is small and is now stated where the claim was: the compared value is a SHA-256 of
// 32 CSPRNG bytes, so a timing side channel buys an attacker essentially nothing against a secret
// they cannot narrow. The doc-honesty test in `tests/append_only.rs` is what keeps the claim from
// coming back into the RFC without the code coming back with it.
