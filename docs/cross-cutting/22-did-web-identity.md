# 22 — did:web Publisher Identity

> Status: **design, not implemented.** `did:web:muveraai.com` appears throughout the
> tree as a default signer and SBOM supplier identity, and it does not resolve.
> This document scopes what making it real requires, and why it was not simply
> switched on alongside the Worker that could technically serve it.

## The current state

`did:web:muveraai.com` is the default value of a signer/supplier field in three
places:

| Location | Field |
|----------|-------|
| `python/model_sbom` | `supplier` — who built or provided the model |
| `python/warrantor_hf_plugin` | `signer` — who signed a Hugging Face upload |
| `docs/cross-cutting/13-compliance-frameworks.md` | `signed_by` in a worked example |

Resolution of `did:web:muveraai.com` means fetching
`https://muveraai.com/.well-known/did.json`. That path returns 404, and the
namespace Worker deliberately does not serve it.

## Why it was not switched on

The Worker that serves `/go/*` and `/schemas/*` could serve `/.well-known/did.json`
in a few lines, and `/.well-known/` is unclaimed on the origin. It was left
unserved on purpose.

A DID document is not a description; it **asserts a public key** and states that
the holder of the corresponding private key speaks for that identity. Publishing
one with a placeholder or throwaway key produces an artifact that is
cryptographically well-formed, resolves cleanly, and is worth nothing — while
looking exactly like one that is worth something. A verifier that resolves it and
checks a signature gets a `true` that means nothing.

That is strictly worse than an unresolvable DID, which fails loudly and honestly.
The same reasoning retired the unmonitored `security@` address in
[14-security-disclosure-policy.md](14-security-disclosure-policy.md): a channel
that appears to work and does not is a liability, not a placeholder.

## What making it real requires

The web-serving part is the trivial part. The custody part is not.

### 1. Key generation and custody

Ed25519 signing key, generated on hardware that never exports it. The private key
signs model SBOMs and Hugging Face uploads — the artifacts downstream consumers
verify to decide whether a model is genuinely ours.

Custody must answer, in writing, before a key exists:

- Where does the private key live? A YubiKey or cloud KMS/HSM, not a file.
- Who can invoke it? Signing must be an operation someone performs, not a secret
  a CI job holds.
- What happens when the holder is unavailable? A single-custodian key is an
  availability risk; a shared one is an accountability risk.
- How is a signing event recorded? An unlogged signature is unattributable after
  the fact.

This is the whole cost of the feature. Everything else follows from it.

### 2. The DID document

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
  "id": "did:web:muveraai.com",
  "verificationMethod": [{
    "id": "did:web:muveraai.com#key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:web:muveraai.com",
    "publicKeyMultibase": "<multibase-encoded public key>"
  }],
  "assertionMethod": ["did:web:muveraai.com#key-1"],
  "authentication": ["did:web:muveraai.com#key-1"]
}
```

Note the `#key-1` fragment. Signatures must reference the specific verification
method, not the bare DID, or rotation cannot be expressed: a signature that names
only `did:web:muveraai.com` becomes ambiguous the moment a second key exists.
**The signing code must emit the fragment form from the first signature**, because
retrofitting it invalidates the interpretation of everything signed before.

### 3. Serving it

Add a `muveraai.com/.well-known/*` route to `deploy/muveraai-worker`, serving the
document with `content-type: application/did+json`. Same pass-through-by-default
posture as the existing handlers. `/.well-known/did.json` and
`/.well-known/security.txt` were both verified 404 on the origin, so the route
takes unused territory.

The DID document is public by definition — it contains only public keys. It is the
one part of this with no custody implications.

### 4. Rotation, before first use

Rotation must be designed before the first signature, not after. Required
decisions:

- Adding `#key-2` while `#key-1` remains listed, so old signatures stay verifiable.
- How long a retired key stays published, and how a consumer distinguishes
  "retired normally" from "revoked because compromised" — these must not look the
  same to a verifier.
- Where revocation is announced, given that removing a key from the DID document
  silently invalidates every signature it made.

`did:web` has a known and unavoidable weakness worth stating plainly: it is only
as trustworthy as DNS and TLS for `muveraai.com`. Whoever controls the domain
controls the identity. That is acceptable for publisher attribution, and it is
**not** acceptable for anything requiring a stronger root of trust. Interaction
with P7 revocation semantics needs to be specified rather than assumed.

## Interim position

Until custody exists, `did:web:muveraai.com` stays unresolvable and these defaults
stay as they are. The alternative — swapping them for a non-DID placeholder string
— was considered and rejected: it would remove the visible reminder that a real
identity is owed, and the DID form is what these fields will eventually carry.

Anyone consuming these SBOMs today should treat the supplier field as
**unverified metadata**, because that is what it is.

## Sequence

1. Decide custody (KMS/HSM vs hardware token) and the human process around it.
2. Generate the key; record the public half and its custody terms.
3. Write the rotation and revocation policy — before any signature exists.
4. Publish the DID document via the Worker's `/.well-known/*` route.
5. Change the signing code to emit `did:web:muveraai.com#key-1`, never the bare DID.
6. Add a conformance vector that resolves the DID and verifies a known-good
   signature, so the published document and the signing code cannot drift.
