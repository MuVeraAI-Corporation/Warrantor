# K1 — `open-core-boundary` RFC

> The BSL 1.1 open-core boundary as code (build-catalogue **K-1**, Domain K, Wave 2): a checked-in licensing
> manifest the CI verifies, where the substrate stays Apache-2.0 forever (enforced by crate layout) and the
> product surface carries BSL 1.1 with a four-year change date — a crate in the wrong family fails the build.

| Field | Value |
|---|---|
| **Canonical ID** | K1 (catalogue K-1) |
| **Name** | open-core-boundary |
| **Wave** | 2 (business plane) |
| **Languages** | Rust |
| **Catalogue item** | K-1 |
| **Dependencies** | none (a CI-time invariant over the crate layout) |

## Background

The sustainable-open-core economics claim rests on a promise buyers and contributors both probe: *the open
authority substrate will never be reliclosed.* A policy slide can break that promise with a single commit —
relicense a crate, move a crate across the boundary, drop the change date. K-1 answers it structurally: the
boundary between the open substrate and the commercial product becomes a machine-checked invariant, not a
statement of intent.

The mechanism is the crate layout itself. A crate belongs to the product family if and only if its name
starts with a product prefix; everything else is substrate and is Apache-2.0 forever. A checked-in
[`LicenceManifest`](rust/open-core-boundary/src/lib.rs) records each crate's family and declared SPDX, and
[`verify`](rust/open-core-boundary/src/lib.rs) fails the build on any drift between the manifest, the layout
rule, and the declared licence. "The open core will be reliclosed" stops being a thing to worry about and
becomes a thing the CI refuses to compile.

## Goals and Non-Goals

**Goals:**
- [`classify_by_name`](rust/open-core-boundary/src/lib.rs) is the layout rule: product family iff the crate
  name starts with a product prefix, otherwise substrate.
- [`verify`](rust/open-core-boundary/src/lib.rs) returns every drift finding — a crate assigned the wrong
  family for its name, or declaring an SPDX its family does not require — so an empty result is the CI gate passing.
- [`effective_spdx`](rust/open-core-boundary/src/lib.rs) resolves a family to its SPDX at a given instant:
  substrate is always Apache-2.0; product is BSL-1.1 until the change date, then Apache-2.0.

**Non-Goals:**
- Enforcing licences at runtime — this is a build/CI-time check over a manifest, not a license server.
- Deciding which crates are product vs substrate — that is the naming convention; the crate only checks consistency.
- Legal advice on BSL terms — it encodes the change-date mechanic, not the full license text.

## Detailed Design

A [`LicenseFamily`](rust/open-core-boundary/src/lib.rs) is `Apache2Substrate` (required SPDX `Apache-2.0`) or
`Bsl11Product` (required SPDX `BSL-1.1`). The `PRODUCT_PREFIXES` list (`n-console`, `n15`, `v1`, `o1`, `o2`,
`portal`, `certification`) defines the product surface; [`classify_by_name`](rust/open-core-boundary/src/lib.rs)
is a pure prefix test.

[`verify`](rust/open-core-boundary/src/lib.rs) walks the manifest's [`CrateLicence`](rust/open-core-boundary/src/lib.rs)
entries and emits two kinds of [`Drift`](rust/open-core-boundary/src/lib.rs): `MisclassifiedFamily` when the
assigned family disagrees with what the name implies, and `WrongLicenceForFamily` when the declared SPDX
disagrees with the family's required SPDX. Either is a build failure. Because the family is *derived from the
name*, a crate cannot silently migrate from substrate to product without also renaming into a product
prefix — and that rename is a visible, reviewable diff.

[`effective_spdx`](rust/open-core-boundary/src/lib.rs) and [`is_converted`](rust/open-core-boundary/src/lib.rs)
model the BSL change-date mechanic: product crates are BSL-1.1 until `change_date_ms`, after which they
become Apache-2.0 automatically. Substrate is Apache-2.0 at every instant — there is no code path that makes
it anything else, which is the structural guarantee.

## Threat Boundary

The adversary is a future commit that quietly relicloses the core: flips a crate's declared licence,
mislabels a substrate crate as product, or removes the change date. Each is caught by
[`verify`](rust/open-core-boundary/src/lib.rs) as drift against the layout rule, failing CI before merge. The
one-way nature of the guarantee is the point: the check makes *widening* the proprietary surface loud and
*relicensing the substrate* impossible without a rename that a reviewer sees. The manifest and clock are
caller-supplied; the crate does not itself read the filesystem or wall clock — the CI harness feeds it the
manifest and `now_ms`.

## API

Library: `warrantor_open_core_boundary::{LicenseFamily, CrateLicence, LicenceManifest, DriftReason, Drift,
classify_by_name, verify, effective_spdx, is_converted}`. `LicenseFamily::required_spdx`.

## Testing

11 unit tests: `classify_by_name` maps product prefixes to BSL-1.1 and everything else to substrate;
`required_spdx` matches each family; `verify` passes a consistent manifest and flags both a misclassified
family and a wrong declared SPDX; `effective_spdx` keeps substrate Apache-2.0 before and after the change
date and flips product from BSL-1.1 to Apache-2.0 at the change-date boundary; `is_converted` is false before
and true at/after the change date; the manifest round-trips through JSON.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §11 Domain K, K-1; §17.2 money
  chain head (**K-1** → K-2 → F-4/K-6 → K-3 → K-4 → K-5).
- Consumed by: CI (the licensing gate runs `verify` over the checked-in manifest each build).
- Pairs with: `rust/metering` (K-2) — the sustainable-open-core economics the boundary makes verifiable.
