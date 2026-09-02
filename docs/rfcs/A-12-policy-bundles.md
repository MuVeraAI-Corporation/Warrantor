# A-12 — `policy-bundles` RFC

> Signed, versioned policy bundles (build-catalogue **A-12**, Domain A, Wave 3, loop L5): a set of policy
> documents pinned by digest into one manifest with a keyed signature envelope, so a distribution of policy
> is a single verifiable artifact rather than a pile of files that drift apart.

| Field | Value |
|---|---|
| **Canonical ID** | A-12 |
| **Name** | policy-bundles |
| **Wave** | 3 (authority plane) |
| **Languages** | Rust |
| **Catalogue item** | A-12 |
| **Dependencies** | A-1 (emits bundles), A-9 (analyzes them); loaded by the notary |

## Background

The policy compiler (A-1) emits policy; the notary loads it. Between those two sits a deployment step that,
if it moves files around by hand, is exactly where integrity quietly dies — one edited document, one stale
copy on a replica, one duplicate rule. A-12 makes the unit of deployment a bundle: every document is
content-addressed, the whole set is digest-sealed, and the seal is signed by a named issuer whose key the
loader already trusts. A bundle either verifies as a unit or the loader refuses it. This is the artifact the
notary's policy load consumes, and it composes — an overlay bundle patches a base without shipping the whole
corpus again.

## Goals and Non-Goals

**Goals:**
- A [`PolicyDoc`](rust/policy-bundles/src/lib.rs) is a versioned document pinned by `sha256:` body digest; a
  [`PolicyBundle`](rust/policy-bundles/src/lib.rs) collects docs under an issuer and a digest over its content.
- [`sign`](rust/policy-bundles/src/lib.rs) produces a [`SignatureEnvelope`](rust/policy-bundles/src/lib.rs);
  [`verify_signature`](rust/policy-bundles/src/lib.rs) checks it against a trusted key, failing closed.
- [`merge`](rust/policy-bundles/src/lib.rs) overlays one bundle on another; [`latest`](rust/policy-bundles/src/lib.rs)
  resolves the newest version of a policy across bundles; [`duplicate_policy_ids`](rust/policy-bundles/src/lib.rs)
  reports a bundle that names a policy twice.

**Non-Goals:**
- Analyzing policy semantics — conflict and dead-policy detection is A-9; A-12 ships documents intact.
- Compiling policy (A-1).
- Real asymmetric crypto — the signature is a keyed content digest, the pure-model stand-in at the same seam.

## Detailed Design

A bundle's digest is computed over its canonical content (id, version, issuer, policies), excluding the
digest field, so [`verify_bundle`](rust/policy-bundles/src/lib.rs) detects any edit. [`sign`](rust/policy-bundles/src/lib.rs)
binds the bundle digest to a key digest via a keyed hash; [`verify_signature`](rust/policy-bundles/src/lib.rs)
returns one of five [`VerifySig`](rust/policy-bundles/src/lib.rs) outcomes — `TamperedBundle` (content digest
broken), `IssuerMismatch`, `UnknownKey` (envelope key ≠ trusted key), `BadSignature`, or `Valid` — checked in
that order so a broken bundle is never mistaken for a signature problem.

[`merge`](rust/policy-bundles/src/lib.rs) is the composition primitive: for each base policy, the patch's
document wins if it names the same id; patch-only ids are appended; the result is a fresh, re-digested bundle
at `base.version + 1`. [`latest`](rust/policy-bundles/src/lib.rs) ranks candidates by `(bundle.version,
doc.version)` so a consumer resolving a policy across a set of bundles gets the newest deterministically.

## Threat Boundary

The adversary is a deployment that ships altered or inconsistent policy: an edited document (bundle digest
breaks), a bundle signed by an untrusted key (`UnknownKey`), a signature replayed onto a different bundle
(`BadSignature`/`IssuerMismatch`), or a bundle that names a policy twice so resolution is ambiguous
(`duplicate_policy_ids`). The loader's contract is simple: verify the signature against a key it already
trusts, and refuse otherwise. The crate trusts the caller's trusted-key digest and body digests as measured.

## API

Library: `warrantor_policy_bundles::{PolicyDoc, PolicyBundle, SignatureEnvelope, VerifySig, bundle_digest,
verify_bundle, sign, verify_signature, duplicate_policy_ids, find, merge, latest}`. `PolicyDoc::new`;
`PolicyBundle::new`.

## Testing

14 unit tests: doc digests are sha256-prefixed; the bundle verifies untouched and fails on tampering; a
signature validates under the trusted key and rejects an untrusted key, a tampered bundle, and an issuer
mismatch; duplicate ids are reported; `find` matches by id; `merge` lets the overlay win on a shared id and
is deterministic and verifiable; `latest` resolves by bundle-then-doc version; the bundle round-trips through
JSON; the empty bundle verifies.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §3 Domain A, A-12.
- Emitted by: the policy compiler (A-1); analyzed by: `rust/policy-analytics` (A-9).
- Loaded by: `rust/notary`; complements `rust/warrant-templates` (A-5, warrant scopes ≠ policy documents).
