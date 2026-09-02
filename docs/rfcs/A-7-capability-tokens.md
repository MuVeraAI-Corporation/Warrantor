# A7 — `capability-tokens` RFC

> Act-scoped, short-TTL capability tokens (build-catalogue **A-7**, Domain A, Wave 1, loop L3): the
> token that exists as prose in the daemon today becomes a reusable type — minted at grant time, narrowed
> to one act, presented at the moment of action, single-use, receipted, auto-expiring.

| Field | Value |
|---|---|
| **Canonical ID** | A7 (catalogue A-7) |
| **Name** | capability-tokens |
| **Wave** | 1 (authority plane) |
| **Languages** | Rust |
| **Catalogue item** | A-7 |
| **Dependencies** | none (a presentation credential derived from a warrant; the notary remains the authority) |

## Background

The current-state ledger flags it as the first thing any buyer's security review hits: the operator
surface runs on *"one unscoped bearer token per run."* Viewer-narrowing shipped — a token can be narrowed
to a read-only view — but the token is still broad and long-lived: captured once, it authorizes everything
the run could do until it expires. That is a standing credential, and standing credentials are the
incident's "original sin" in miniature.

A-7 completes the §2.4 arc by making the token *act-scoped*: it authorizes exactly one action, is consumed
on first use, and dies on a short TTL. The difference between a bearer token and a capability is that a
capability is only good for the thing it names, once. Small item, disproportionate procurement value.

## Goals and Non-Goals

**Goals:**
- [`mint`](rust/capability-tokens/src/lib.rs) a [`CapabilityToken`](rust/capability-tokens/src/lib.rs) bound to a warrant, a single [`ActScope`](rust/capability-tokens/src/lib.rs) (adapter + operation + resource
  class), and a short expiry.
- [`redeem`](rust/capability-tokens/src/lib.rs) presents the token against the act actually being performed and a [`TokenLedger`](rust/capability-tokens/src/lib.rs), failing closed on expiry, act mismatch, or reuse of a
  single-use token.
- On success, return a [`RedeemReceipt`](rust/capability-tokens/src/lib.rs) binding token id → warrant → action — the settle-record linkage the gate demands.
- Keep it pure and deterministic: every check takes `now_ms` from the caller; no wall clock, no signing.

**Non-Goals:**
- Performing the act or talking to the adapter — the broker redeems, then acts.
- Replacing the notary's warrant check — the token is derived from a warrant; the warrant is still the
  authority.
- Signing the receipt — the digest is a content fingerprint the host records.

## Detailed Design

An [`ActScope`](rust/capability-tokens/src/lib.rs) is the triple `(adapter, operation, resource_class)`;
`matches` is exact equality, so a token minted for `github/create_pr/repo:acme/api` cannot be redeemed for
`github/merge_pr/...` or `slack/...`. `mint` computes the token's `sha256:` digest over its content and
registers the id in the ledger. `redeem` checks, in order: the token is known to the ledger
(`UnknownToken`), `now_ms < expires_at_ms` (`Expired`, with the boundary instant treated as expired), the
presented act matches (`ActMismatch`), and — for single-use tokens — the id is not already consumed
(`AlreadyUsed`). Only after all checks pass does it mark the token consumed and emit the receipt, so a
*failed* redeem never burns a single-use token (a wrong-act attempt leaves the token redeemable for its
correct act).

The ledger is the single-use and unknown-token authority; it is injectable so tests drive issuance and
consumption explicitly. Digests are content fingerprints, not signatures.

## Threat Boundary

The adversary is a captured or replayed token. Short TTL bounds the capture window; act-scoping means a
captured token authorizes one named action, not the run's whole capability; single-use means it is dead
after the first redeem; and the ledger makes replay of a spent token a denial rather than a second
action. The fail-closed ordering (check everything, then consume) prevents an attacker from *burning* a
legitimate token by triggering failed redeems. The crate trusts the caller's `now_ms` (a compromised host
can lie about time) — that is the same trust boundary as the notary's expiry checks — and it does not
verify the warrant behind the token, which the broker does before minting.

## API

Library: `warrantor_capability_tokens::{ActScope, CapabilityToken, TokenDenial, RedeemReceipt,
TokenLedger, mint, redeem}`. `ActScope::matches`; `TokenLedger::{new, is_issued, is_consumed, register}`.

## Testing

14 unit tests: redeem succeeds within TTL and binds token→warrant→act; expired and boundary-instant
redeems are denied; act mismatch (any of the three fields) is denied; a single-use token cannot be
redeemed twice but a multi-use token redeems until expiry; an unknown token is denied; a failed redeem
does not consume a single-use token; the ledger tracks issuance and consumption; the token digest is
deterministic and distinguishes acts; a zero-TTL token is immediately expired; `ActScope::matches` is
exact.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §3 Domain A, A-7; §17.2 authority chain head.
- Authority it derives from: `rust/authority-spec`, `rust/notary` (the warrant), `rust/warrant`.
- Credential substrate it complements: `rust/credential-vault` (M2 handles — the secret stays broker-side;
  A-7 is the act-scoped presentation token on top).
- Consumed by: the effect-adapter brokers (`rust/egress`, `rust/computer-use`, Domain E adapters) and the
  MCP gateway (`rust/warrant`) at the moment of action.
