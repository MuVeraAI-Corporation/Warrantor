# A4 — `escrow-warrants` RFC

> Escrow & conditional warrants (build-catalogue **A-4**, Domain A, loop L5): warrants that activate on a
> condition — a future timestamp, an external event, or a data condition — held escrowed and revocable
> until activation, with activation itself receipted, and sunsetting conditions that expire a grant without
> operator action.

| Field | Value |
|---|---|
| **Canonical ID** | A4 (catalogue A-4) |
| **Name** | escrow-warrants |
| **Wave** | 3 (authority plane) |
| **Languages** | Rust |
| **Catalogue item** | A-4 |
| **Dependencies** | none (the caller supplies the observed time, events, and data predicates) |

## Background

Not every grant should be live the moment it is signed. A successor's authority should begin on a date; an
incident-responder warrant should arm only when the incident ticket is actually filed; a quarterly report's
signing key should activate when the report is finalized. And enterprise warrants should *die* on schedule,
not linger until someone remembers to revoke them. A-4 makes both edges — conditional activation and
automatic sunset — first-class, and receipts each transition so the lifecycle is auditable.

## Goals and Non-Goals

**Goals:**
- A [`Condition`](rust/escrow-warrants/src/lib.rs): `EffectiveAt`, `OnEvent`, or `DataCondition`.
- An [`EscrowWarrant`](rust/escrow-warrants/src/lib.rs) with an activation condition, an optional sunset condition, and a [`WarrantState`](rust/escrow-warrants/src/lib.rs)
  (Escrowed / Active / Expired / Revoked).
- [`try_activate`](rust/escrow-warrants/src/lib.rs) moves Escrowed→Active only when the condition is met (refusing pre-activation); [`try_sunset`](rust/escrow-warrants/src/lib.rs)
  moves Active→Expired when the sunset condition is met; each emits a [`LifecycleReceipt`](rust/escrow-warrants/src/lib.rs).

**Non-Goals:**
- Observing the world — the caller supplies `now_ms`, the event log, and satisfied data predicates.
- Performing the authorized action.

## Detailed Design

`satisfied(cond, now, events, data)` evaluates each condition kind. `try_activate` refuses a Revoked or
Expired warrant, refuses an already-Active one, and otherwise activates only if the activation condition is
met. `try_sunset` requires Active state and a met sunset condition. `revoke` flips to Revoked from either
Escrowed or Active. Every transition emits a digest-bound receipt.

## Threat Boundary

The adversary is a grant that is live too early (used before its moment) or too late (never revoked).
Pre-activation refusal closes the first; sunset conditions close the second by expiring grants without
operator action. The crate trusts the supplied observations (a caller lying about whether an event fired is
outside this boundary — the event log is the substrate's concern); it enforces the state machine and the
receipt trail.

## API

Library: `warrantor_escrow_warrants::{Condition, WarrantState, EscrowWarrant, LifecycleReceipt,
LifecycleError, try_activate, try_sunset, revoke}`.

## Testing

11 unit tests: activation on timestamp, event, and data condition; pre-activation refused; double activation
refused; sunset expires without operator action and requires Active state; a revoked warrant cannot activate;
no sunset condition never expires; receipts are deterministic; revoke emits a receipt.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §3 Domain A, A-4.
- Complements: A-2 delegation (a delegated warrant can itself be conditional); A-3 quorum (activation may
  require a quorum).
