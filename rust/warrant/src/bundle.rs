//! The trust directory, as a signed file that is carried rather than a service that is queried.
//!
//! # The gap, and why the obvious shape of it is refused
//!
//! [`crate::trust`] pins a name to an issuer key on **one machine**, checked out of band once. That
//! works and it does not scale past one person: a team of five reviewers verifying each other's
//! evidence means twenty pairs of out-of-band key checks, and the fifth person to join does four of
//! them. The roadmap has listed a "trust directory" as unbuilt for every release.
//!
//! It stayed unbuilt because the obvious implementation is a service, and `trust.rs` refuses that
//! in its own words: *"a directory that hands them out over the network is a new trust root, and
//! this design does not add one."* That refusal is right. A server everyone fetches keys from is a
//! server whose compromise silently redefines who everyone trusts, and it would sit **above** the
//! Ed25519 signatures the entire product rests on.
//!
//! # What a bundle is
//!
//! An **export of one machine's pins, signed by that machine's issuer key**. It is a file. It moves
//! by whatever means the team already trusts — a commit in a reviewed repository, an attachment on a
//! signed email, a USB stick — and importing it requires the importer to *already* trust the key
//! that signed it.
//!
//! That last clause is the whole design:
//!
//! * **No new trust root.** A bundle can only be imported against a key the importer had already
//!   pinned out of band. One out-of-band check gets you everything that machine trusts, instead of
//!   one out-of-band check per key. The trust *root* is unchanged — it is still an Ed25519 key a
//!   human checked — and only the *fan-out* improves.
//! * **Nothing is fetched.** There is no URL, no host, no TLS decision and no availability
//!   dependency, so there is nothing whose outage or compromise changes a verdict.
//! * **Provenance survives the import.** Every imported pin records which bundle it came from and
//!   who signed it, so a verdict can say *"pinned as `ana`, imported from a bundle signed by
//!   `security-team` on 2026-08-17"* rather than the flat "trust on first use" that a locally-typed
//!   pin gets. A reader can tell a key they checked themselves from one they inherited, which is a
//!   distinction a directory service erases.
//!
//! # What it deliberately does not do
//!
//! **No transitive import.** A bundle carries pins; it does not carry the *authority to vouch*. If
//! `security-team`'s bundle contains `ana`, importing it pins `ana` — it does not let `ana`'s own
//! bundle be imported without a separate decision. Transitivity is how a web of trust becomes a
//! graph nobody can audit, and one compromised leaf becomes everyone's problem.
//!
//! **No revocation, and this is a real limitation rather than an oversight.** A bundle is a snapshot.
//! If a key is compromised after a bundle ships, nothing in the bundle says so, and an importer who
//! never receives a newer one keeps the stale pin. A revocation channel is a service — the exact
//! thing being refused — so the honest answer is that unpinning is a local act and bundles are dated
//! so an operator can see how old the one they imported is. [`BundleReport`] says so on every
//! import.

use std::collections::BTreeMap;
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::report::sha256_hex;
use crate::trust::{check_name, Directory, PinnedIssuer, TRUST_FORMAT};

/// The wire format of a trust bundle.
pub const BUNDLE_FORMAT: &str = "warrantor.trust-bundle/1";

/// Domain separator for a bundle signature.
///
/// Distinct from every other signature this system produces, and length-prefixed by construction, so
/// a signature over a warrant or a report can never be replayed as a bundle. The agent-identity
/// service learned this the hard way — two token types signed with one key over untagged JSON meant
/// a low-value token verified as a high-value one.
const BUNDLE_DOMAIN: &[u8] = b"warrantor-trust-bundle-v1";

/// The signed contents of a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleClaims {
    /// Always [`BUNDLE_FORMAT`].
    pub format: String,
    /// A name for the machine or team that produced it, chosen by whoever exported it.
    ///
    /// Recorded in every imported pin's provenance, so a verdict can name where a key came from.
    /// It is a *label*, not an authenticated identity: the key that signed the bundle is the
    /// authenticated part, and the label is what a human calls it.
    pub issued_by: String,
    /// When it was exported. Printed on import, because a bundle is a snapshot and its age is the
    /// only signal an importer has that it may be stale.
    pub issued_at: u64,
    /// The pins, name → pin, exactly as the exporting machine held them.
    pub issuers: BTreeMap<String, PinnedIssuer>,
}

/// A bundle: claims, and a signature over them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustBundle {
    /// The signed contents.
    pub claims: BundleClaims,
    /// Hex of the Ed25519 verifying key that signed it.
    pub signed_by: String,
    /// Hex of the signature over the canonical pre-image.
    pub signature: String,
}

/// The canonical bytes a bundle's signature covers.
///
/// Built from a `BTreeMap` and the domain separator rather than from the serialised JSON, so two
/// encoders that differ in whitespace or key order still produce one signature — and so a field
/// added later cannot silently fall outside what was signed.
fn pre_image(claims: &BundleClaims) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(BUNDLE_DOMAIN);
    bytes.push(0x1f);
    bytes.extend_from_slice(claims.format.as_bytes());
    bytes.push(0x1f);
    bytes.extend_from_slice(claims.issued_by.as_bytes());
    bytes.push(0x1f);
    bytes.extend_from_slice(claims.issued_at.to_string().as_bytes());
    for (name, pin) in &claims.issuers {
        bytes.push(0x1e);
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0x1f);
        bytes.extend_from_slice(pin.key.as_bytes());
        bytes.push(0x1f);
        bytes.extend_from_slice(pin.pinned_at.to_string().as_bytes());
        bytes.push(0x1f);
        // The note is signed too. It is where the exporter recorded how they checked the key, and a
        // note that could be edited after signing would be the one field in an evidence artifact
        // that an attacker could rewrite to make a substituted key look checked.
        bytes.extend_from_slice(pin.note.as_bytes());
    }
    bytes
}

/// What went wrong with a bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    /// The file is not a bundle this build reads.
    UnknownFormat(String),
    /// The file will not parse.
    Unreadable(String),
    /// The signature does not verify against the key the bundle names.
    SignatureInvalid,
    /// The bundle was signed by a key the importer does not already trust.
    NotTrusted {
        /// The key that signed it.
        signed_by: String,
    },
    /// A name in the bundle is not one this build will accept.
    BadName {
        /// The name.
        name: String,
        /// Why.
        detail: String,
    },
    /// I/O.
    Io(String),
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownFormat(found) => write!(
                f,
                "that file declares format {found:?}; this build reads {BUNDLE_FORMAT}"
            ),
            Self::Unreadable(detail) => write!(f, "that is not a readable trust bundle: {detail}"),
            Self::SignatureInvalid => write!(
                f,
                "the bundle's signature does not verify against the key it names. Nothing was \
                 imported. Either the file was altered in transit or it was not signed by the key \
                 it claims -- and both mean the pins in it are not evidence of anything."
            ),
            Self::NotTrusted { signed_by } => write!(
                f,
                "this bundle is signed by {signed_by}, which is not a key this machine already \
                 trusts.\n  Importing it would mean accepting a set of keys on the authority of a \
                 key nobody here has checked -- which is the new trust root this design exists to \
                 avoid.\n  Pin the signer first, out of band, and then import:\n    \
                 warrantor issuer add <a-name-you-choose> {signed_by} --note \"how you checked it\"\n\
                 \x20   warrantor issuer import <bundle> --apply\n  \
                 The name you choose is yours; the import finds the signer by KEY, so a \
                 bundle cannot pick which of your pins vouches for it."
            ),
            Self::BadName { name, detail } => {
                write!(f, "the bundle contains a name this build refuses ({name:?}): {detail}")
            }
            Self::Io(detail) => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for BundleError {}

/// Export a machine's pins as a signed bundle.
///
/// Signed with the **issuer** key, which is the key this machine already signs evidence with. A
/// separate bundle-signing key would be a second key to distribute and a second thing to check out
/// of band, for no gain: anyone who accepts this machine's evidence has already checked this key.
#[must_use]
pub fn export(directory: &Directory, issued_by: &str, at: u64, issuer: &SigningKey) -> TrustBundle {
    let claims = BundleClaims {
        format: BUNDLE_FORMAT.to_string(),
        issued_by: issued_by.to_string(),
        issued_at: at,
        issuers: directory.issuers.clone(),
    };
    let signature = issuer.sign(&pre_image(&claims));
    TrustBundle {
        claims,
        signed_by: hex::encode(issuer.verifying_key().to_bytes()),
        signature: hex::encode(signature.to_bytes()),
    }
}

/// Read a bundle from bytes and check its self-consistency.
///
/// This checks the **signature against the key the bundle names**, which establishes only that the
/// file was not altered. Whether that key is one to trust is [`import`]'s question, and keeping the
/// two separate is deliberate: a bundle that verifies against its own key and is signed by a
/// stranger is a perfectly intact file with no authority, and collapsing the two checks would let
/// "the signature is fine" be read as "this is trustworthy".
///
/// # Errors
/// [`BundleError`] for an unreadable file, an unknown format, or a signature that does not verify.
pub fn parse(bytes: &[u8]) -> Result<TrustBundle, BundleError> {
    let bundle: TrustBundle =
        serde_json::from_slice(bytes).map_err(|e| BundleError::Unreadable(e.to_string()))?;
    if bundle.claims.format != BUNDLE_FORMAT {
        return Err(BundleError::UnknownFormat(bundle.claims.format));
    }
    let key_bytes: [u8; 32] = hex::decode(&bundle.signed_by)
        .map_err(|_| BundleError::Unreadable("signed_by is not hex".to_string()))?
        .try_into()
        .map_err(|_| BundleError::Unreadable("signed_by is not 32 bytes".to_string()))?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| BundleError::Unreadable("signed_by is not a valid key".to_string()))?;
    let signature_bytes: [u8; 64] = hex::decode(&bundle.signature)
        .map_err(|_| BundleError::Unreadable("signature is not hex".to_string()))?
        .try_into()
        .map_err(|_| BundleError::Unreadable("signature is not 64 bytes".to_string()))?;
    key.verify(
        &pre_image(&bundle.claims),
        &Signature::from_bytes(&signature_bytes),
    )
    .map_err(|_| BundleError::SignatureInvalid)?;
    // Every name is checked before anything is imported. A bundle carrying a name this build would
    // not let an operator type is a bundle trying to get one in by the side door.
    for name in bundle.claims.issuers.keys() {
        check_name(name).map_err(|detail| BundleError::BadName {
            name: name.clone(),
            detail,
        })?;
    }
    Ok(bundle)
}

/// What an import did, per name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportOutcome {
    /// The name was not held and is now pinned from the bundle.
    Added,
    /// The name was already pinned to the same key. Nothing changed.
    AlreadyAgreed,
    /// The name is already pinned to a **different** key, and was left alone.
    ///
    /// Never overwritten, and there is no `--replace` for this on the bundle path. A local pin is
    /// something a human checked out of band on this machine; a bundle silently redefining it is
    /// precisely the attack a signed bundle otherwise prevents. The conflict is reported with both
    /// keys and the operator resolves it by hand, one name at a time.
    Conflict {
        /// The key this machine holds.
        local: String,
        /// The key the bundle carries.
        incoming: String,
    },
}

/// The result of an import, name by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleReport {
    /// Who the bundle says produced it.
    pub issued_by: String,
    /// The name the importer had pinned the signing key under.
    pub signer_name: String,
    /// When the bundle was exported.
    pub issued_at: u64,
    /// The bundle file's own digest, so an import can be pointed at later.
    pub bundle_digest: String,
    /// Per name, what happened.
    pub outcomes: BTreeMap<String, ImportOutcome>,
}

impl BundleReport {
    /// How many names were newly pinned.
    #[must_use]
    pub fn added(&self) -> usize {
        self.outcomes
            .values()
            .filter(|o| **o == ImportOutcome::Added)
            .count()
    }

    /// The names whose keys disagree with what this machine already holds.
    #[must_use]
    pub fn conflicts(&self) -> Vec<&String> {
        self.outcomes
            .iter()
            .filter(|(_, o)| matches!(o, ImportOutcome::Conflict { .. }))
            .map(|(name, _)| name)
            .collect()
    }

    /// The sentence every import prints. Says what an import is not.
    #[must_use]
    pub fn caveat(&self) -> String {
        format!(
            "These pins are now trusted on the authority of {:?} -- the key you had already checked \
             out of band -- and NOT because anyone checked them here. Every verdict that uses one \
             will say so.\n\nA bundle is a SNAPSHOT, dated {}. There is no revocation channel and \
             there will not be one: a channel is a service, and a service everyone queries is the \
             trust root this design refuses to add. If a key in it is compromised later, nothing \
             here learns that -- unpin it locally with `warrantor issuer remove <name>`.\n\nImports \
             are NOT transitive. Pinning a name from this bundle does not let that name's own \
             bundle be imported; that is a separate decision, deliberately.",
            self.signer_name, self.issued_at
        )
    }
}

/// Merge a bundle into a local directory, on the authority of a key already pinned there.
///
/// The signer must already be in `directory` under some name. That is the whole security argument:
/// one out-of-band check buys everything the signing machine trusts, and the trust root is still an
/// Ed25519 key a human checked rather than a host somebody configured.
///
/// # Errors
/// [`BundleError::NotTrusted`] when the signing key is not already pinned locally.
pub fn import(
    directory: &mut Directory,
    bundle: &TrustBundle,
    bundle_bytes: &[u8],
) -> Result<BundleReport, BundleError> {
    // Resolved by KEY, not by name. Asking "is there a pin named X" would let a bundle choose which
    // local pin vouches for it by choosing its own label.
    let signer_name = directory
        .issuers
        .iter()
        .find(|(_, pin)| pin.key == bundle.signed_by)
        .map(|(name, _)| name.clone())
        .ok_or_else(|| BundleError::NotTrusted {
            signed_by: bundle.signed_by.clone(),
        })?;

    let mut outcomes = BTreeMap::new();
    for (name, incoming) in &bundle.claims.issuers {
        // A bundle that contains the signer's own key under a different name is not an error; the
        // outcome below reports it like any other name.
        match directory.issuers.get(name) {
            Some(local) if local.key == incoming.key => {
                outcomes.insert(name.clone(), ImportOutcome::AlreadyAgreed);
            }
            Some(local) => {
                outcomes.insert(
                    name.clone(),
                    ImportOutcome::Conflict {
                        local: local.key.clone(),
                        incoming: incoming.key.clone(),
                    },
                );
            }
            None => {
                // The note records the provenance, and it replaces rather than appends to the
                // exporter's note: a note claiming "checked on a video call" is true of the
                // exporting machine and false here, and carrying it over unqualified would make an
                // inherited pin read as a locally-checked one.
                let note = format!(
                    "imported from a bundle signed by `{signer_name}` (issued_by {:?}, at {}); \
                     the exporter's own note was: {}",
                    bundle.claims.issued_by,
                    bundle.claims.issued_at,
                    if incoming.note.trim().is_empty() {
                        "(none)"
                    } else {
                        incoming.note.trim()
                    }
                );
                directory.issuers.insert(
                    name.clone(),
                    PinnedIssuer {
                        key: incoming.key.clone(),
                        // The exporter's pin time, not now: when this key was first checked by a
                        // human is the fact a reader wants, and overwriting it with the import time
                        // would make every inherited pin look freshly verified.
                        pinned_at: incoming.pinned_at,
                        note,
                    },
                );
                outcomes.insert(name.clone(), ImportOutcome::Added);
            }
        }
    }

    Ok(BundleReport {
        issued_by: bundle.claims.issued_by.clone(),
        signer_name,
        issued_at: bundle.claims.issued_at,
        bundle_digest: sha256_hex(bundle_bytes),
        outcomes,
    })
}

/// Write a bundle to a path.
///
/// # Errors
/// [`BundleError::Io`] on serialisation or I/O failure.
pub fn write(bundle: &TrustBundle, path: &Path) -> Result<Vec<u8>, BundleError> {
    let body = serde_json::to_vec_pretty(bundle)
        .map_err(|e| BundleError::Io(format!("encode bundle: {e}")))?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| BundleError::Io(format!("create {}: {e}", parent.display())))?;
        }
    }
    std::fs::write(path, &body)
        .map_err(|e| BundleError::Io(format!("write {}: {e}", path.display())))?;
    Ok(body)
}

/// The format string a bundle's embedded directory would carry, for renderings that show it.
#[must_use]
pub fn directory_format() -> &'static str {
    TRUST_FORMAT
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn directory_with(pins: &[(&str, u8)]) -> Directory {
        let mut directory = Directory::empty();
        for (name, seed) in pins {
            directory
                .pin(
                    name,
                    &key(*seed).verifying_key(),
                    1_000,
                    "checked in person",
                )
                .expect("pin");
        }
        directory
    }

    #[test]
    fn a_bundle_round_trips_and_its_signature_covers_every_pin() {
        let signer = key(9);
        let bundle = export(
            &directory_with(&[("ana", 1), ("bo", 2)]),
            "security-team",
            5_000,
            &signer,
        );
        let bytes = serde_json::to_vec(&bundle).expect("serialise");
        let parsed = parse(&bytes).expect("parses");
        assert_eq!(parsed.claims.issuers.len(), 2);

        // Substituting a key breaks the signature: that is the property the whole file rests on.
        let mut tampered = bundle.clone();
        tampered.claims.issuers.get_mut("ana").expect("ana").key =
            hex::encode(key(7).verifying_key().to_bytes());
        let bytes = serde_json::to_vec(&tampered).expect("serialise");
        assert_eq!(
            parse(&bytes).expect_err("must refuse"),
            BundleError::SignatureInvalid
        );
    }

    #[test]
    fn the_note_is_signed_because_it_is_where_the_check_is_recorded() {
        // A note that could be edited after signing would be the one field an attacker could rewrite
        // to make a substituted key look like one somebody verified.
        let signer = key(9);
        let mut bundle = export(&directory_with(&[("ana", 1)]), "team", 5_000, &signer);
        bundle.claims.issuers.get_mut("ana").expect("ana").note =
            "checked by the CEO personally".to_string();
        let bytes = serde_json::to_vec(&bundle).expect("serialise");
        assert_eq!(
            parse(&bytes).expect_err("must refuse"),
            BundleError::SignatureInvalid
        );
    }

    #[test]
    fn a_bundle_signed_by_an_unknown_key_is_refused_and_the_refusal_names_the_way_in() {
        // The no-new-trust-root rule, in the one place it is enforced.
        let signer = key(9);
        let bundle = export(&directory_with(&[("ana", 1)]), "stranger", 5_000, &signer);
        let bytes = serde_json::to_vec(&bundle).expect("serialise");
        let parsed = parse(&bytes).expect("parses");

        let mut mine = Directory::empty();
        let error = import(&mut mine, &parsed, &bytes).expect_err("must refuse");
        let rendered = error.to_string();
        assert!(
            rendered.contains("not a key this machine already trusts"),
            "{rendered}"
        );
        assert!(rendered.contains("new trust root"), "{rendered}");
        assert!(
            rendered.contains("warrantor issuer add"),
            "the refusal must name the way in: {rendered}"
        );
        assert!(mine.issuers.is_empty(), "nothing may be imported");
    }

    #[test]
    fn importing_on_a_pinned_signer_adds_every_new_name() {
        let signer = key(9);
        let bundle = export(
            &directory_with(&[("ana", 1), ("bo", 2)]),
            "security-team",
            5_000,
            &signer,
        );
        let bytes = serde_json::to_vec(&bundle).expect("serialise");
        let parsed = parse(&bytes).expect("parses");

        // One out-of-band check: the signer.
        let mut mine = directory_with(&[("sec", 9)]);
        let report = import(&mut mine, &parsed, &bytes).expect("imports");
        assert_eq!(report.added(), 2);
        assert_eq!(report.signer_name, "sec");
        assert!(mine.resolve("ana").is_some());
        assert!(mine.resolve("bo").is_some());
    }

    #[test]
    fn the_signer_is_resolved_by_key_not_by_the_label_the_bundle_chose() {
        // Otherwise a bundle could pick which local pin vouches for it by choosing its own
        // `issued_by`.
        let signer = key(9);
        let mut bundle = export(
            &directory_with(&[("ana", 1)]),
            "whatever-i-like",
            5_000,
            &signer,
        );
        bundle.claims.issued_by = "sec".to_string();
        // Re-sign, since the label is covered.
        let resigned = export(&directory_with(&[("ana", 1)]), "sec", 5_000, &signer);
        let bytes = serde_json::to_vec(&resigned).expect("serialise");
        let parsed = parse(&bytes).expect("parses");

        // Local pin is under a completely different name; the key is what matters.
        let mut mine = directory_with(&[("the-security-team", 9)]);
        let report = import(&mut mine, &parsed, &bytes).expect("imports");
        assert_eq!(report.signer_name, "the-security-team");
    }

    #[test]
    fn a_local_pin_is_never_overwritten_by_a_bundle() {
        // A local pin is something a human checked out of band on this machine. A bundle silently
        // redefining it is exactly the attack a signed bundle otherwise prevents, and there is no
        // --replace for it: the operator resolves a conflict by hand, one name at a time.
        let signer = key(9);
        let bundle = export(&directory_with(&[("ana", 1)]), "sec", 5_000, &signer);
        let bytes = serde_json::to_vec(&bundle).expect("serialise");
        let parsed = parse(&bytes).expect("parses");

        // Locally, `ana` means a different key.
        let mut mine = directory_with(&[("sec", 9), ("ana", 4)]);
        let before = mine.resolve("ana").expect("ana");
        let report = import(&mut mine, &parsed, &bytes).expect("imports");

        assert_eq!(report.added(), 0);
        assert_eq!(report.conflicts(), vec![&"ana".to_string()]);
        assert_eq!(
            mine.resolve("ana").expect("still ana"),
            before,
            "the local pin must be untouched"
        );
        match report.outcomes.get("ana").expect("outcome") {
            ImportOutcome::Conflict { local, incoming } => assert_ne!(local, incoming),
            other => panic!("expected a conflict: {other:?}"),
        }
    }

    #[test]
    fn a_pin_that_already_agrees_is_reported_as_agreement_and_not_as_new() {
        let signer = key(9);
        let bundle = export(&directory_with(&[("ana", 1)]), "sec", 5_000, &signer);
        let bytes = serde_json::to_vec(&bundle).expect("serialise");
        let parsed = parse(&bytes).expect("parses");
        let mut mine = directory_with(&[("sec", 9), ("ana", 1)]);
        let report = import(&mut mine, &parsed, &bytes).expect("imports");
        assert_eq!(report.added(), 0);
        assert!(report.conflicts().is_empty());
        assert_eq!(
            report.outcomes.get("ana"),
            Some(&ImportOutcome::AlreadyAgreed)
        );
    }

    #[test]
    fn an_imported_pin_says_it_was_inherited_rather_than_checked_here() {
        // A reader has to be able to tell a key they checked from one they inherited. A directory
        // service erases that distinction; this must not.
        let signer = key(9);
        let bundle = export(
            &directory_with(&[("ana", 1)]),
            "security-team",
            5_000,
            &signer,
        );
        let bytes = serde_json::to_vec(&bundle).expect("serialise");
        let parsed = parse(&bytes).expect("parses");
        let mut mine = directory_with(&[("sec", 9)]);
        import(&mut mine, &parsed, &bytes).expect("imports");

        let pin = mine.issuers.get("ana").expect("ana");
        assert!(
            pin.note.contains("imported from a bundle signed by `sec`"),
            "{}",
            pin.note
        );
        assert!(pin.note.contains("security-team"), "{}", pin.note);
        assert_eq!(
            pin.pinned_at, 1_000,
            "the exporter's pin time is kept: when a human first checked it is the fact a reader \
             wants, and stamping the import time would make every inherited pin look fresh"
        );
    }

    #[test]
    fn the_caveat_refuses_to_promise_revocation() {
        let signer = key(9);
        let bundle = export(&directory_with(&[("ana", 1)]), "sec", 5_000, &signer);
        let bytes = serde_json::to_vec(&bundle).expect("serialise");
        let parsed = parse(&bytes).expect("parses");
        let mut mine = directory_with(&[("sec", 9)]);
        let report = import(&mut mine, &parsed, &bytes).expect("imports");
        let caveat = report.caveat();
        assert!(caveat.contains("no revocation channel"), "{caveat}");
        assert!(caveat.contains("NOT transitive"), "{caveat}");
        assert!(caveat.contains("SNAPSHOT"), "{caveat}");
    }

    #[test]
    fn a_bundle_of_another_format_is_refused_rather_than_guessed_at() {
        let signer = key(9);
        let mut bundle = export(&Directory::empty(), "sec", 1, &signer);
        bundle.claims.format = "warrantor.trust-bundle/99".to_string();
        let bytes = serde_json::to_vec(&bundle).expect("serialise");
        assert!(matches!(
            parse(&bytes).expect_err("refuses"),
            BundleError::UnknownFormat(_)
        ));
    }

    #[test]
    fn the_domain_separator_stops_another_signature_being_replayed_as_a_bundle() {
        // Two signature types under one key over untagged bytes is how a low-value token once
        // verified as a high-value one in this codebase's own history.
        let claims = BundleClaims {
            format: BUNDLE_FORMAT.to_string(),
            issued_by: "sec".to_string(),
            issued_at: 1,
            issuers: BTreeMap::new(),
        };
        let image = pre_image(&claims);
        assert!(image.starts_with(BUNDLE_DOMAIN));
        assert_ne!(image, b"warrantor-warrant-v1".to_vec());
    }
}
