# I1 — `root-of-trust` RFC

> Root-of-trust deployment modes (build-catalogue **I-1**, Domain I, Wave 1, loop L2): the Tier-1 gap
> answered as three supported modes rather than one enforced answer — self-custody, threshold signing, and
> escrow continuity — each with a key-ceremony drill and a root-compromise playbook that keeps historical
> receipts verifiable through a re-key.

| Field | Value |
|---|---|
| **Canonical ID** | I1 (catalogue I-1) |
| **Name** | root-of-trust |
| **Wave** | 1 (trust & keys) |
| **Languages** | Rust |
| **Catalogue item** | I-1 |
| **Dependencies** | none (the KMS/HSM and threshold-signing integrations plug into the modes) |

## Background

"Who holds the keys" is the first question every security team asks and the hardest to answer well. The
platform's anti-goals forbid a centralized Warrantor-operated signing service as the default root — that
recreates the single point of failure the platform exists to abolish. But self-custody alone doesn't serve
every buyer: a systemically-important issuer wants t-of-n threshold signing; a regulated deployment needs a
documented recovery path through key loss. I1 turns the hardest question into a **selection matrix with
proofs**: three honest modes, each passing its own ceremony drill, and one compromise playbook (spec 07)
every mode can execute end-to-end.

## Goals and Non-Goals

**Goals:**
- Model the three [`RootMode`](rust/root-of-trust/src/lib.rs)s — [`SelfCustody`](rust/root-of-trust/src/lib.rs), [`ThresholdSigning`](rust/root-of-trust/src/lib.rs) (t-of-n), [`EscrowContinuity`](rust/root-of-trust/src/lib.rs) — as a choice, not an
  enforcement.
- [`ceremony_drill`](rust/root-of-trust/src/lib.rs) / [`ceremony_passes`](rust/root-of-trust/src/lib.rs): each mode's key ceremony has checks, and a malformed threshold
  (0-of-n or t>n) fails its drill.
- A [`RootRegistry`](rust/root-of-trust/src/lib.rs) with [`RootStatus`](rust/root-of-trust/src/lib.rs) (Active / Historical / Revoked); [`verify`](RootRegistry::verify) reports whether an
  [`Issuance`](rust/root-of-trust/src/lib.rs) stands and under which status.
- [`rekey`](RootRegistry::rekey): the compromise playbook — old root → Historical, new root → Active; old issuances still
  verify as `TrustedHistorical` (no trust gap), new issuances as `Current`.

**Non-Goals:**
- Holding keys or talking to a KMS/HSM — the E-14 adapters do; this is the mode model and re-key discipline.
- Real threshold signatures — it models the t-of-n *policy* and ceremony; the scheme is a separate
  integration.
- Real signatures — `sign`/`verify` use a content-binding digest as a stand-in so the lineage logic is
  testable without key material (no credential literals, per the platform's rules).

## Detailed Design

A root carries a `public_key_digest` (a stand-in for key material) and a status. `sign(receipt, root)`
produces `signature = sha256(receipt_digest || public_key_digest)` — a content binding, not a real
signature. `verify` recomputes the binding (a mismatch is `BadSignature`), then maps the root's status:
Active → `Current`, Historical → `TrustedHistorical`, Revoked → `RevokedRoot`; an unknown root is
`UnknownRoot`. `rekey` is the playbook: it flips the old root to Historical (so its past issuances remain
authentic — the whole point of "no trust gap") and installs a new Active root. `revoke` (a different
action) flips to Revoked, voiding the root's issuances — the compromise path when the key is actually lost.

`ceremony_drill` returns the per-mode checklist; `ceremony_passes` is false exactly when the drill is empty,
which happens only for a malformed threshold.

## Threat Boundary

The adversary is a compromised or lost root. The re-key playbook answers *compromise without trust loss*:
past receipts signed by the old root stay verifiable as historical (a verifier can still prove what was
signed and when), while new issuances move to the new root — so rotating a key never erases history or
creates a gap. `revoke` answers *unrecoverable compromise*: the root's issuances stop verifying. The crate
trusts the supplied public-key digests and the host's choice of mode; it does not itself generate or guard
keys (that is the KMS/HSM adapter's job), and its signature stand-in is explicitly not a real signature —
the lineage and status logic is what's under test here.

## API

Library: `warrantor_root_of_trust::{RootMode, RootStatus, RootOfTrust, Issuance, VerifyOutcome,
RootRegistry, sign, ceremony_drill, ceremony_passes}`. `RootRegistry::{new, add_root, get, verify, revoke,
rekey}`.

## Testing

14 unit tests: self-custody, valid-threshold, and escrow ceremonies pass while a malformed threshold fails;
an issuance verifies Current under an active root; a tampered receipt is `BadSignature`; an unknown root is
reported; a revoked root voids its issuances; re-key keeps old receipts `TrustedHistorical` while new ones
are `Current` and marks the old root Historical; the signature binds receipt to root key; a threshold root
carries its parameters; the ceremony drill lists steps; a historical root's signature still verifies.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §11 Domain I, I-1; §17.2 trust chain head (I-1 → B-1 → B-2 → …).
- Complements: `rust/transparency-log` (B-1) and `rust/time-anchoring` (B-2) — the log/anchor verify under a root.
- Key custody adapters: E-14 (Vault/KMS); threshold pairs with A-3 quorum warrants.
- Recovery: I-7 key ceremony/rotation; spec 07 (root compromise).
- Anti-goal honored: no centralized Warrantor signing root as default (self-custody is the default mode).
