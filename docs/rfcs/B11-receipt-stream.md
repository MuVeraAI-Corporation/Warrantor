# B11 — `receipt-stream` RFC

> Streaming receipts (build-catalogue **B-11**, Domain B, loop L4): SDKs and surfaces subscribe to the
> receipt graph as it settles — an event stream filtered by warrant, plane, verdict, or digest prefix, with
> resumable cursors.

| Field | Value |
|---|---|
| **Canonical ID** | B11 (catalogue B-11) |
| **Name** | receipt-stream |
| **Wave** | 2 (evidence plane) |
| **Languages** | Rust |
| **Catalogue item** | B-11 |
| **Dependencies** | none (the transport — SSE/WebSocket — wraps this ordering + cursor + filter model) |

## Background

A governed platform that only exposes receipts to a batch query is a platform whose operators react late.
The incident was detected six days after its precursors were already in the event stream; a live, resumable
subscription is what turns "we can query it eventually" into "a dashboard and a SIEM see it within a second."
The hard part is the delivery contract: in order, no gaps, no duplicates, resumable from any cursor after a
disconnect.

## Goals and Non-Goals

**Goals:**
- [`ReceiptStream`](rust/receipt-stream/src/lib.rs): assign each [`StreamEvent`](rust/receipt-stream/src/lib.rs) a monotonic cursor on [`publish`](ReceiptStream::publish).
- [`subscribe`](ReceiptStream::subscribe): return every event after a cursor that matches a [`StreamFilter`](rust/receipt-stream/src/lib.rs), in cursor order, plus the
  next cursor to resume from.

**Non-Goals:**
- Opening sockets or speaking SSE/WebSocket — the transport wraps this model.
- Persisting across restarts (the archive is the source of truth; the stream is a live view).

## Detailed Design

Cursors are 1-based sequence numbers; cursor 0 means "from the beginning." `publish` assigns `len + 1`.
`subscribe(from, filter)` selects events with `cursor > from` that pass the filter (warrant, plane, verdict,
digest-prefix, ANDed via `is_none_or`), returns them in order, and reports the last cursor as the resume
point — so a client that reconnects with that cursor sees no gap and no duplicate.

## Threat Boundary

The adversary is a missed or duplicated event in a live security feed — a dashboard that silently drops a
deny, or a SIEM that double-counts. The cursor contract makes delivery exactly-once-per-cursor and resumable,
so a disconnect recovers cleanly. The stream trusts the host to publish every settled receipt (a publisher
that skips events is outside this boundary — the archive is the completeness source); it guarantees only the
ordering and cursor semantics over what it is given.

## API

Library: `warrantor_receipt_stream::{StreamVerdict, StreamEvent, StreamFilter, ReceiptStream}`.
`StreamFilter::matches`; `ReceiptStream::{new, len, is_empty, publish, subscribe}`.

## Testing

11 unit tests: cursors are monotonic; subscribing after a cursor skips earlier events; from zero gets
everything; a full read then resume yields no gaps or duplicates; filters by warrant, verdict, digest prefix,
and plane; resume after a partial read picks up only new events; an empty stream subscribes cleanly;
combined filters are ANDed.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §5 Domain B, B-11.
- Notification edge: `rust/archive` webhooks (#57); this is the data edge.
- Powers: D-3 live dashboards, SIEM/SOC integration (with F-5 OTel), agent-to-agent reaction.
