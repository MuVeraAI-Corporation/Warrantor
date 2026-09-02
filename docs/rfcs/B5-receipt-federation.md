# B5 — `receipt-federation` RFC

> The receipt federation protocol's pure core (build-catalogue **B-5**, Domain B, Wave 3, loop L2):
> peer-to-peer discovery, exchange, third-party verification against a per-node issuer directory with no
> vendor fallback, and privacy tiers — the item that makes Warrantor a protocol instead of a product.

| Field | Value |
|---|---|
| **Canonical ID** | B5 (catalogue B-5) |
| **Name** | receipt-federation |
| **Wave** | 3 (evidence plane) |
| **Languages** | Rust |
| **Catalogue item** | B-5 |
| **Dependencies** | B-1 (common proof surface), A-6 (plane discipline); natural first IETF draft candidate (I-2) |

## Background

Every federated party increases the value of every other party's receipts — the n² network effect — and
federation is the answer to the question every enterprise buyer eventually asks: *"what if the vendor
disappears?"* If verification depends on Warrantor-the-company being online, the receipts are only as
durable as the company. If verification is peer-to-peer against each node's own trust anchors, receipts
keep verifying between remaining peers with no shared vendor infrastructure at all.

B-5 is the item that turns that from a claim into a protocol. This crate pins the *semantics* of the
federation exchange as testable data and pure functions — the message shapes and the verification rules —
while deliberately leaving the wire encoding and transport as a separate concern. Critically, it keeps the
network trust directory open as a deployment choice, not a platform requirement: each node carries its own
[`IssuerDirectory`](rust/receipt-federation/src/lib.rs), and federation works with no central authority.

## Goals and Non-Goals

**Goals:**
- [`discovery`](rust/receipt-federation/src/lib.rs) advertises a node's head digest and trusted pins.
- [`fetch`](rust/receipt-federation/src/lib.rs) returns a [`ReceiptEnvelope`](rust/receipt-federation/src/lib.rs)
  honoring the privacy tier; [`batch_sync`](rust/receipt-federation/src/lib.rs) streams receipts since an index.
- [`verify`](rust/receipt-federation/src/lib.rs) checks a receipt against the directory: the issuer must be
  pinned (no vendor fallback) and, when the payload is disclosed, its content must hash to the claimed digest.
- [`peer_verify`](rust/receipt-federation/src/lib.rs) runs the full exchange-and-verify handshake between two
  nodes, including mutual verification between peers with no shared vendor.

**Non-Goals:**
- Opening sockets or reading a clock — it is the protocol's decision logic over data, deterministic and testable.
- Signing receipts — verification here is issuer-anchor presence plus content-hash integrity, the pure-model
  stand-in for signature checking.
- Mandating a central directory — each node carries its own; the network trust directory stays a deployment choice.

## Detailed Design

A [`FederationNode`](rust/receipt-federation/src/lib.rs) holds an append-only log of
[`Receipt`](rust/receipt-federation/src/lib.rs)s and its own [`IssuerDirectory`](rust/receipt-federation/src/lib.rs)
of [`IssuerPin`](rust/receipt-federation/src/lib.rs)s (issuer id → `sha256:` key digest). A receipt's
`digest` is the `sha256:` of its payload, computed at construction.

Exchange is governed by a [`PrivacyTier`](rust/receipt-federation/src/lib.rs): under `DigestOnly` only the
digest and issuer travel and the payload stays with the holder; under `PayloadByGrant` the payload is
disclosed — permitted only under an explicit bilateral grant. The same tier flows through
[`fetch`](rust/receipt-federation/src/lib.rs) and [`batch_sync`](rust/receipt-federation/src/lib.rs) into the
[`ReceiptEnvelope`](rust/receipt-federation/src/lib.rs), whose `payload` is `Option<String>`.

[`verify`](rust/receipt-federation/src/lib.rs) is fail-closed and returns one of four
[`VerifyOutcome`](rust/receipt-federation/src/lib.rs)s: `UnknownIssuer` when the issuer is not pinned (there
is no vendor fallback to catch it), `Tampered` when a disclosed payload does not hash to the claimed digest,
`DigestOnly` when the issuer is trusted but the payload was withheld, and `Trusted` only when the issuer is
pinned *and* the disclosed payload hashes correctly. [`peer_verify`](rust/receipt-federation/src/lib.rs)
composes fetch-then-verify and returns `UnknownIssuer` — never a silent pass — when the holder has nothing
to serve.

## Threat Boundary

The adversary is a peer that presents an untrusted issuer, a tampered payload, or an empty log hoping for a
default-allow. Each is refused: an unpinned issuer yields `UnknownIssuer` with no fallback path; a payload
that does not hash to its claimed digest yields `Tampered`; an empty holder yields `UnknownIssuer` rather
than `Trusted`. The `mutual_verify` test demonstrates the property that matters for the "vendor disappears"
answer: two peers that each pin the other's issuer verify one another with no shared vendor in the loop.
The crate trusts the caller's directory contents (which issuers are pinned is a governance decision made
out-of-band) and models signature checking as content-hash integrity — the real protocol swaps the hash
check for an issuer signature verification at the same seam.

## API

Library: `warrantor_receipt_federation::{PrivacyTier, IssuerPin, IssuerDirectory, Receipt, ReceiptEnvelope,
DiscoverySnapshot, FederationNode, VerifyOutcome, discovery, fetch, batch_sync, verify, peer_verify}`.
`IssuerDirectory::{new, pin, contains, pins}`; `FederationNode::{new, append, head, directory}`; `Receipt::new`.

## Testing

16 unit tests: discovery advertises head and pins and reports no head for an empty node; fetch withholds the
payload under `DigestOnly`, discloses it under `PayloadByGrant`, and returns `None` for an unknown digest;
verify yields `Trusted`/`DigestOnly`/`UnknownIssuer`/`Tampered` on the four respective conditions, including
the no-vendor-fallback rejection of an unpinned issuer; peer_verify trusts a pinned issuer, fails without a
pin, and treats an empty holder as unknown; batch_sync streams since an index and is empty past the end;
mutual verification between two peers with no shared vendor; the envelope round-trips through JSON.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §5 Domain B, B-5; §17.2 trust
  chain terminal (B-1 → B-2 → B-4 → **B-5** → I-2).
- Builds on: `rust/receipt-graph` (B-1 common proof surface), `rust/authority-algebra` (A-6 plane discipline).
- Protocolization: the natural first IETF draft candidate (I-2); the network trust directory stays a
  deployment choice, not a mandate (anti-goal honored).
