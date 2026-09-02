# K2 — `metering` RFC

> Usage metering and pricing engine (build-catalogue **K-2**, Domain K, Wave 1): the meter reads the
> receipt graph itself — signed, tenant-scoped counts — and emits invoices where every line item traces to
> receipt digests, so a month's bill reconstructs exactly from the evidence layer and a dispute is
> resolvable by digest.

| Field | Value |
|---|---|
| **Canonical ID** | K2 (catalogue K-2) |
| **Name** | metering |
| **Wave** | 1 (business & GTM) |
| **Languages** | Rust |
| **Catalogue item** | K-2 |
| **Dependencies** | none (counts receipt digests the archive already validated; tenancy is F-6) |

## Background

The gaps analysis recommended usage-based pricing made operational: a per-receipt rate plus a platform
fee, scaled by plan. The reason this is a *trust* feature and not just a billing module is that the
platform already receipts every governed action. A separate metering system is instrumentation that can
drift from reality and be disputed; reading the same signed evidence the product produces gives
invoice-explainability for free — every line points at the receipt digests that justify it, and an
independent script can rebuild the invoice from the receipt graph and confirm it to the microcent. Zero
metering infrastructure to build; the evidence layer does it. This is the head of the money chain
(K-1 licence boundary → K-2 metering → marketplace → funnel → design partners).

## Goals and Non-Goals

**Goals:**
- [`Meter`](rust/metering/src/lib.rs) accumulates [`BillableReceipt`](rust/metering/src/lib.rs)s; [`invoice`](rust/metering/src/lib.rs) produces an [`Invoice`](rust/metering/src/lib.rs) for a tenant and [`Plan`](rust/metering/src/lib.rs) over a period — a
  usage line (deduplicated receipt count × per-receipt rate, carrying the sorted receipt digests) plus a
  monthly platform-fee line.
- **Invoice-explainability**: the usage line's `receipt_digests` are the traceability anchor; [`verify_invoice`](rust/metering/src/lib.rs) recomputes the invoice independently from the receipt graph and confirms the
  total, the lines, and that every billed digest corresponds to a real receipt in the period.
- Integer micro-dollars throughout, so there is no float rounding to dispute.

**Non-Goals:**
- Moving money or integrating a payment provider — it produces the verifiable statement; billing systems
  consume it.
- Verifying receipt signatures — it counts digests the archive validated.
- Managing tenants or plans — those are inputs (multi-tenancy is F-6).

## Detailed Design

[`Plan`](rust/metering/src/lib.rs) carries the rates: Team $0.001/receipt (1000 micros) with no platform
fee; Enterprise and Mission-Critical $0.0005/receipt (500 micros) with $50K/yr and $200K/yr fees, charged
monthly as `annual / 12`. `build_lines` collects the period's receipt digests into a `BTreeSet` (so a
duplicate digest bills once and the digest list is deterministically sorted), emits the usage line only if
there are receipts, and the fee line only if the monthly fee is non-zero. The invoice digest is `sha256:`
over the canonical JSON of `(tenant, plan, period, lines, total)`.

`verify_invoice` is the dispute-resolution primitive: it re-runs `build_lines` against the meter for the
invoice's own tenant/plan/period, requires the recomputed lines and total to match exactly, and checks
every usage-line digest is present in the real receipt set — so an inflated total, a fabricated digest, or
a line that doesn't match the graph all fail.

## Threat Boundary

The adversary is a billing dispute — a customer (or an auditor) claiming the invoice doesn't match the
service actually used. Because the invoice is derived from the same signed receipt graph the product
produces, and `verify_invoice` recomputes it independently, the statement is as verifiable as the product:
the customer can run the same reconstruction and get the same number, and any line is traceable to the
digests that justify it. The meter trusts the receipt stream it is fed (a meter fed a truncated graph
under-bills, which is the archive's integrity concern, not this crate's); it does not re-verify signatures,
and it uses integer arithmetic so totals are exact.

## API

Library: `warrantor_metering::{Plan, BillableReceipt, Meter, InvoiceLine, Invoice, invoice,
verify_invoice}`. `Plan::{per_receipt_micros, annual_platform_fee_micros, monthly_platform_fee_micros}`;
`Meter::{new, record, receipts_for}`.

## Testing

14 unit tests: Team bills per receipt with no fee line; Enterprise adds the monthly platform-fee line; the
usage line traces to receipt digests; billing is tenant-scoped and period-windowed; zero receipts yield an
empty Team invoice; `verify_invoice` accepts an honest invoice and rejects an inflated total or a
fabricated digest; duplicate receipt digests bill once; the invoice digest is deterministic and
distinguishes plans; Mission-Critical's fee exceeds Enterprise's exceeds Team's.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §13 Domain K, K-2; §17.2 money chain head.
- Evidence it meters: `rust/archive` (the receipt graph), `rust/spend` (W9 governed-spend, the value metric).
- Preceded by: K-1 (open-core licence boundary). Followed by: F-4/K-6 marketplace, K-3 funnel, K-4 design
  partners, K-5 SI channel.
- Tenant scoping depends on: F-6 (multi-tenancy & the team boundary).
