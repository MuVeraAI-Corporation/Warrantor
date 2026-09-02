# B3 — `receipt-explorer` RFC

> The receipt explorer (build-catalogue **B-3**, Domain B, Wave 1, loop L4): the human window into the
> receipt graph — a query layer that browses by warrant, agent, time, verdict, plane, and delegation chain
> and independently verifies every receipt it shows, rendering any record that fails verification in a
> distinct untrusted state.

| Field | Value |
|---|---|
| **Canonical ID** | B3 (catalogue B-3) |
| **Name** | receipt-explorer |
| **Wave** | 1 (evidence plane) |
| **Languages** | Rust |
| **Catalogue item** | B-3 |
| **Dependencies** | none (the host supplies the receipt slice from the same store the CLI reads) |

## Background

The receipt graph's value is locked behind CLI queries until a read layer exists. B-3 is that layer, and
it is the prerequisite surface for the executive dashboard (N3), the approval inbox (N5), the audit
workbench (N6), and the regulator portal (N15): build the read layer once, four personas inherit it. The
catalogue's discipline is *no parallel truth* — every view is backed by the same store read the CLI uses,
so the explorer never shows a different picture than the command line.

The gate is a security property, not a UI one: an auditor must trust what they see *without trusting the
explorer*. So each displayed receipt carries the digest and signature the substrate recorded, and the
explorer recomputes the digest from the fields it is about to show — a receipt edited after signing, or
never signed, renders untrusted rather than silently passing.

## Goals and Non-Goals

**Goals:**
- [`explore`](rust/receipt-explorer/src/lib.rs): filter a receipt slice by an [`ExplorerQuery`](rust/receipt-explorer/src/lib.rs) (warrant, agent, plane, verdict, time window, delegation-chain membership — ANDed),
  verify each survivor, and return [`VerifiedReceipt`](rust/receipt-explorer/src/lib.rs)s in time order.
- [`ReceiptView::verify`](rust/receipt-explorer/src/lib.rs): recompute the content digest from the displayed fields and require a
  non-empty signature; a mismatch or an unsigned record is [`VerificationStatus::Untrusted`](rust/receipt-explorer/src/lib.rs).
- [`drill`](rust/receipt-explorer/src/lib.rs): the summary→receipt→evidence→archive-push detail for one receipt.
- Keep it a pure model the front end consumes — no rendering, no fetching, no clock.

**Non-Goals:**
- Rendering HTML or serving a UI — this is the query + verification model.
- Fetching from the archive — the host supplies the slice.
- Cryptographic signature validation — it checks presence and recomputes the digest; full verification is
  the notary's job.

## Detailed Design

A [`ReceiptView`](rust/receipt-explorer/src/lib.rs) is the explorer's projection of a substrate record, carrying the `digest`
and `signature` the substrate recorded. `content_digest` hashes the canonical JSON of the *displayed*
fields (id, warrant, agent, plane, verdict, time, delegation chain, archive flag) — deliberately excluding
`digest` and `signature`. `verify` returns `Trusted` only when a signature is present **and** the stored
digest equals a recomputation; editing any displayed field after signing breaks the equality and yields
`Untrusted`, which is exactly the tamper signal the gate demands.

`explore` applies each optional filter with `is_none_or` (a `None` filter passes everything), sorts by
`(at_ms, receipt_id)` for a stable order, and pairs each survivor with its verification status. `drill`
locates a receipt by id and assembles the detail view, including the archive-push status line and the
evidence reference (the digest the archive anchors).

## Threat Boundary

The adversary is a compromised or edited evidence store presenting a receipt that no longer matches what
was signed. Because verification recomputes the digest from the fields actually shown, a silent edit
changes the displayed content and fails the check — the explorer cannot be tricked into showing a tampered
record as trusted. The crate trusts the host to feed it the same slice the CLI reads (no parallel truth is
a deployment discipline this model supports but cannot itself enforce) and to supply signatures; it checks
presence, not validity, so a forger who can also produce a matching signature is outside this boundary —
that is the notary's / verifier's concern, and the transparency log (B-1) is what makes a rewritten store
third-party-detectable.

## API

Library: `warrantor_receipt_explorer::{Verdict, ReceiptView, VerificationStatus, VerifiedReceipt,
ExplorerQuery, ReceiptDetail, explore, drill}`. `ReceiptView::{content_digest, verify}`.

## Testing

14 unit tests: valid receipts verify trusted; a post-signing content edit and an unsigned record both
render untrusted; filtering by warrant, by agent+plane+verdict, by time window, and by delegation-chain
membership; results are time-ordered; an empty query returns all; drill returns detail with archive status
and evidence ref, flags unarchived records, and returns none for a missing id; the content digest is
deterministic; the verdict shown comes from the same stored field the CLI reads (no parallel truth).

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §5 Domain B, B-3; §17.2 surface chain (D-12 → B-3 → N3/N5/N6/N15).
- Reads: `rust/archive` (the receipt store), `rust/evidence` / `rust/flight-recorder` (the records).
- Verifies against: `rust/transparency-log` (B-1) for third-party detectability of a rewritten store.
- Export target: `rust/incident-replay` (M12) evidence packs — the explorer's filtered set exports as a pack (B-9).
- Inherited by: N3 dashboard, N5 inbox, N6 audit workbench, N15 regulator portal (Domain D).
