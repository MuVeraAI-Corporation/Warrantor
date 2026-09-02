# F6 — `tenancy` RFC

> Tenant isolation as a structural property (build-catalogue **F-6**, Domain F, Wave 2): a nested
> tenant→resource store where every access is scoped by tenant id first, so a cross-tenant read is
> unrepresentable rather than merely forbidden, plus per-tenant quotas enforced fail-closed on write.

| Field | Value |
|---|---|
| **Canonical ID** | F6 (catalogue F-6) |
| **Name** | tenancy |
| **Wave** | 2 (platform plane) |
| **Languages** | Rust |
| **Catalogue item** | F-6 |
| **Dependencies** | none |

## Background

Warrantor is multi-tenant by nature — every deployment issues receipts and invoices across many
organizations, and a leak between tenants is not a bug, it is a breach of the whole premise: the receipt graph
is *evidence*, and evidence that crosses a tenant boundary is contaminated. The usual approach is a
`tenant_id` column plus a `WHERE` clause someone must remember to write — isolation as a *convention* that any
new query can silently violate. F-6 makes isolation *structural*: the store is keyed tenant-first, so there is
no code path that reads "all resources" and filters afterward. A cross-tenant read cannot be expressed, which
is strictly stronger than being forbidden. This is the partition the metering crate (K-2) invoices against and
the receipt plane (B-*) is scoped by.

## Goals and Non-Goals

**Goals:**
- A [`TenantStore`](rust/tenancy/src/lib.rs) holds a `tenant → (path → value)` map;
  [`get`](rust/tenancy/src/lib.rs) and [`list`](rust/tenancy/src/lib.rs) take a tenant id and can only ever
  see that tenant's subtree.
- [`set_quota`](rust/tenancy/src/lib.rs) caps a tenant's resource count;
  [`put`](rust/tenancy/src/lib.rs) refuses a write that would exceed it (fail-closed).
- [`namespace_digest`](rust/tenancy/src/lib.rs) fingerprints one tenant's subtree so two tenants holding the
  same paths with different values are provably distinct.

**Non-Goals:**
- Authenticating the caller — it assumes the caller already carries a resolved tenant scope; mapping principals
  to tenants is the surface layer's job.
- Encrypting at rest — isolation here is logical, not cryptographic.
- Modeling cross-tenant *sharing* — delegation across tenants is the authority plane's concern, not the
  storage partition's.

## Detailed Design

The store is a `BTreeMap<String, BTreeMap<String, String>>` — the outer key is the tenant, the inner map that
tenant's resources. Because every accessor indexes the outer map *first*, a value stored under tenant A is
physically unreachable through a call scoped to tenant B; there is no "scan then filter" path to get wrong.
Quotas are a separate `tenant → limit` map; [`put`](rust/tenancy/src/lib.rs) enforces the limit only on a
*new* path (an overwrite of an existing resource is not a new resource and stays within quota), and returns
[`StoreError::QuotaExceeded`](rust/tenancy/src/lib.rs) without writing when the tenant is at its cap.
[`namespace_digest`](rust/tenancy/src/lib.rs) hashes the canonical JSON of a tenant's inner map, giving an
independent check that two tenants' namespaces differ (or, when they hold identical content, match) without
exposing the contents.

## Threat Boundary

The adversary is a code path that leaks across tenants: a new query that forgets the tenant filter (fixed —
there is no unfiltered query to forget it in), a quota-bypass write that lets one tenant exhaust shared
storage (fixed — `put` fails closed at the cap), or a subtle collision where two tenants' same-named paths
alias (fixed — the tenant is the outer key, so identical paths in different tenants are distinct entries). The
store trusts the caller's tenant scope; it does not authenticate it.

## API

Library: `warrantor_tenancy::{TenantStore, StoreError}`. `TenantStore::{new, set_quota, put, get, delete,
list, resource_count, tenant_count, namespace_digest}`.

## Testing

14 unit tests: put-then-get returns the value; a cross-tenant read returns `None`; the same path under two
tenants is independent; `list` shows only the caller's tenant and is empty for an unknown one; a quota blocks
a new write and reports the limit; a quota allows overwriting an existing path; quotas are per-tenant; delete
removes and reports existence; the namespace digest distinguishes tenants and is stable for empty tenants;
`tenant_count` tracks distinct tenants; clearing a quota makes a tenant unlimited; the store round-trips
through JSON.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §6 Domain F, F-6.
- Partitions the receipts of: the B-plane (transparency-log, receipt-explorer).
- Invoiced against by: `rust/metering` (K-2).
