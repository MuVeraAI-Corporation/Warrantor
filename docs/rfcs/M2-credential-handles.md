# M2 — `credential-handles` RFC

> Act-scoped credential minting: an agent holds an opaque, binding-checked capability handle, never a
> raw secret. The secret stays broker-side and is released only at the point of use, where every
> binding is re-checked. Derived from the OpenAI–Hugging Face incident, whose "original sin" was a
> shared standing credential live for the whole agent collective at once.

| Field | Value |
|---|---|
| **Canonical ID** | M2 |
| **Name** | credential-handles |
| **Wave** | 1 (substrate) |
| **Languages** | Rust |
| **Incident requirement** | R2 |
| **Catalogue item** | M-2 |
| **Dependencies** | credential-vault (`ScopedCredential`, `CredentialBackend`) |

## Background

The incident's blast radius was a credential property, not a model property: every agent in the
collective held the *same* standing secret, so one compromised agent leaked a credential that was
simultaneously live for all of them, with no per-use binding to revoke. The existing
`ScopedCredential` model is correct for a broker that *uses* a secret on the caller's behalf, but it
still hands the caller the raw `secret` field — wrong when the caller is an agent whose memory is
itself attack surface. The lesson: **an agent should never hold a secret; it should hold a handle to
one.**

## Goals and Non-Goals

**Goals:** Issue opaque, cryptographically-random handles (128-bit capability ids) bound to a SPIFFE
identity + task + IP, with a short TTL and optional single-use semantics. Resolve a handle to its raw
secret only broker-side, re-checking every binding at the moment of use. Make a stolen handle useless
from a different identity, task, or IP, and make a single-use handle spent after one redemption.

**Non-Goals:**
- Replacing `ScopedCredential`/`Vault` — the handle layer sits *on top* of the existing mint/resolve
  machinery and reuses its backend and JTI revocation model.
- Being the broker itself — `redeem` is the seam a broker calls; how the broker uses the resolved
  secret (HTTP call, DB connection) is out of scope.

## Detailed Design

`CredentialHandle { handle_id, binding: Binding{spiffe_id, task, bound_ip}, issued_at, expires_at,
single_use, jti }` — the agent-visible object, carrying **no secret**. `HandleVault` retains the real
`ScopedCredential` keyed by `handle_id`.

`issue_handle(backend, binding, secret_key, ttl, single_use)` mints a credential via the existing
`issue()` (resolving the secret through the `CredentialBackend`), generates a fresh CSPRNG handle id,
stores the credential broker-side, and returns only the handle.

`redeem(handle_id, presented_binding, now)` is the broker-side resolution. It fails closed, in order,
on: revoked → unknown → expired → `spiffe_id` mismatch → `task` mismatch → `bound_ip` mismatch, and
only then returns the secret. A `BindingMismatch` names the failed field but never the expected value,
so a failed redemption cannot be used to probe what a handle is bound to. A single-use handle is
consumed **after** all checks pass, so a failed redemption (e.g. wrong IP) does not burn a handle the
caller can retry with corrected context. `revoke` / `revoke_all` are the kill-switch analogue of
`Vault::revoke_all`.

## Threat Boundary

`redeem` returns the secret to the **broker**, not the agent. The agent's entire view of the credential
is the handle; the broker performs the privileged operation and returns only the result. This is the
property the incident lacked: no standing secret in agent memory, and a per-use binding check that a
stolen or replayed handle cannot satisfy.

## API

Library: `warrantor_credential_vault::{Binding, CredentialHandle, HandleError, HandleVault}` (re-exported
at crate root; also under `handles::`).

## Testing

15 unit tests: handle carries no secret (serialized), redeem returns secret on match, reject wrong
identity/task/IP, binding-mismatch does not leak expected value, expired fails closed, revoked fails
closed, unknown handle rejected, single-use spent after first redeem, failed redeem does not burn a
single-use handle, multi-use redeems repeatedly, revoke_all stops every outstanding handle, handle ids
unique over 200 issues, backend failure propagates and issues nothing.

## Cross-references

- Incident analysis: `warrantor-incident-analysis-agent-collective-2026-09-01.html` §6, §13 R2, §14 M-2.
- Implementation: `rust/credential-vault/src/handles.rs`.
