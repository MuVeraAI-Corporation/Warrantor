# B2 — `time-anchoring` RFC

> Time anchoring (build-catalogue **B-2**, Domain B, loop L2): resolves the open §2.1 trust-root decision
> by implementing both leading options behind one interface — RFC 3161 timestamp-authority
> countersignatures and countersigned custody of periodic externally-signed epoch anchors — so "when was
> this actually signed?" becomes a cryptographic answer with externally bounded `[t1, t2]`.

| Field | Value |
|---|---|
| **Canonical ID** | B2 (catalogue B-2) |
| **Name** | time-anchoring |
| **Wave** | 2 (evidence plane) |
| **Languages** | Rust |
| **Catalogue item** | B-2 |
| **Dependencies** | `rust/transparency-log` (B-1) — anchors its epoch heads as well as individual receipts |

## Background

*"When was this actually signed?"* is the first question in every dispute. A receipt whose only timestamp
is the issuer's own clock is a self-asserted claim — the first thing an opposing expert challenges, because
an issuer who can edit history can also set the clock. §2.1 left the trust-root decision open with three
options; B-2 resolves it by implementing the two leading ones behind a single verification interface, so a
deployment chooses by shape rather than by rewriting how auditors check time.

The two options are **(a) RFC 3161 timestamp-authority countersignatures** — a networked TSA countersigns
a receipt or log epoch, giving a window bounded by the TSA's own trusted clock — and **(b) countersigned
custody** — the archive's existing witness chain extended with periodic externally-signed epoch anchors,
which works with no network. Air-gapped sovereigns use (b); cloud deployments use (a); **both verify the
same way**, so an auditor's tooling is identical across regimes.

## Goals and Non-Goals

**Goals:**
- One [`TimeAnchor`](rust/time-anchoring/src/lib.rs) type and one [`verify`](rust/time-anchoring/src/lib.rs) function serving both [`AnchorMode`](rust/time-anchoring/src/lib.rs)s, so verification is mode-agnostic.
- Bind a content digest (a receipt *or* a B-1 log-epoch head) to an `[lower, upper]` window under a named
  authority, with a token that recomputes.
- [`DeploymentShape`](rust/time-anchoring/src/lib.rs) selects the right mode (air-gapped → custody, cloud → TSA).
- Fail loudly: a stripped anchor yields [`AnchorVerdict::NoAnchor`](rust/time-anchoring/src/lib.rs); a tampered window, authority, or
  mismatched content yields [`AnchorVerdict::InvalidAnchor`](rust/time-anchoring/src/lib.rs); an instant outside the window yields [`AnchorVerdict::OutOfWindow`](rust/time-anchoring/src/lib.rs).

**Non-Goals:**
- Contacting a live TSA or holding the authority's key — it verifies the countersignature token the
  authority produced; minting a real RFC 3161 token is the integration's job.
- Replacing the transparency log — it anchors the log, not the other way round.

## Detailed Design

`anchor(mode, authority, content_digest, lower, upper)` computes `token_digest = sha256:` over the
canonical JSON of the binding fields. `verify(content_digest, anchor, observed_ms)` checks, in order: an
anchor is present (else `NoAnchor`); it binds this exact content (else `InvalidAnchor`); its token
recomputes (else `InvalidAnchor` — any post-signing edit to the window or authority breaks this); and the
observed instant falls within `[lower, upper]` inclusive (else `OutOfWindow`). Only then `Trusted` with
the window. The observed instant is supplied by the caller, so the crate keeps no clock and is fully
deterministic.

## Threat Boundary

The adversary is a back-dated or forward-dated claim — an issuer asserting a receipt existed at a time it
did not. External anchoring bounds the signing time to a window the issuer cannot unilaterally set, and the
recomputing token means the window itself cannot be quietly widened after the fact. The crate trusts the
authority's key (a TSA that lies is outside this boundary — that is why the authority is named and the
token is what the host signs/mirrors) and the caller's `observed_ms`. It deliberately does not itself
validate the TSA's signature chain; it proves the anchor is intact and bound to the content, which is the
property the explorer and auditor need to render "anchored in [t1,t2]" versus "self-asserted."

## API

Library: `warrantor_time_anchoring::{AnchorMode, DeploymentShape, TimeAnchor, AnchorVerdict, anchor,
verify}`. `DeploymentShape::anchor_mode`.

## Testing

14 unit tests: a valid anchor within the window is trusted and reports the bounds; window bounds are
inclusive; a missing anchor is a loud `NoAnchor`; a stripped anchor fails where the present one passed; a
tampered window or authority is `InvalidAnchor`; an anchor bound to different content is `InvalidAnchor`;
instants before and after the window are `OutOfWindow`; the token is deterministic and distinguishes mode;
air-gapped selects custody and cloud selects TSA; both modes verify through the same call; a B-1 log-epoch
digest anchors like a receipt.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §5 Domain B, B-2; §17.2 trust chain (B-1 → B-2 → B-4/B-5).
- Anchors: `rust/transparency-log` (B-1) epoch heads; `rust/flight-recorder` / `rust/evidence` receipts.
- Enables: B-4 cross-org chains and B-5 federation (a shared time basis), and the regulator portal's
  "signed in window" claims.
