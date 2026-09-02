# I-5 — `conformance` RFC

> Conformance as public infrastructure (build-catalogue **I-5**, Domain I, Wave 3): a versioned,
> digest-pinned suite of test vectors plus a runner that checks any candidate implementation of a Warrantor
> interface against every vector and returns a pass/fail-per-vector report.

| Field | Value |
|---|---|
| **Canonical ID** | I-5 (catalogue I-5) |
| **Name** | conformance |
| **Wave** | 3 (trust plane) |
| **Languages** | Rust |
| **Catalogue item** | I-5 |
| **Dependencies** | none (implementation-agnostic; the candidate is a callable) |

## Background

Warrantor's authority rests on the claim that its interfaces — the authority algebra (A-6), the receipt
format (B-plane), the federation protocol (B-5) — are *specs*, not products: anyone may implement them and
interoperate. That claim is only real if there is a published, re-runnable way to answer "does this
implementation actually conform?" without asking Warrantor. A conformance suite is that answer, and it is the
same move that made TLS trustworthy: the spec ships with vectors, and a browser's correctness is judged
against the vectors, not against the standards body's opinion. Without public conformance, "open protocol"
quietly degrades into "one implementation that calls itself the reference." I-5 is the general mechanism;
A-6's authority-algebra conformance suite is one instantiation of it.

## Goals and Non-Goals

**Goals:**
- A [`TestVector`](rust/conformance/src/lib.rs) pairs an input with the output every conforming implementation
  must produce; a [`ConformanceSuite`](rust/conformance/src/lib.rs) is a versioned, digest-pinned collection.
- [`run_suite`](rust/conformance/src/lib.rs) drives a candidate — modeled as a pure
  `Fn(&str) -> Result<String, String>` so the suite is implementation-agnostic — over every vector and returns
  a [`ConformanceReport`](rust/conformance/src/lib.rs).
- Conformance is fail-closed: an empty suite, a vector whose candidate errors, or any mismatch yields
  `conforms == false`.

**Non-Goals:**
- Defining the interface semantics — that is the spec the vectors encode; I-5 only checks an implementation
  against them.
- Trusting the candidate's self-report — the runner calls the candidate and compares outputs itself.
- Being a security oracle — conformance to vectors is necessary, not sufficient, for correctness.

## Detailed Design

[`suite_digest`](rust/conformance/src/lib.rs) fingerprints the vector list (order-sensitive, version
independent), so a published suite is tamper-evident and a version bump that changes vectors changes the
digest. [`run_vector`](rust/conformance/src/lib.rs) calls the candidate and records the actual output, or
`None` when the candidate returns an error — an error is a *failure*, never a panic or a silent skip.
[`run_suite`](rust/conformance/src/lib.rs) aggregates: `conforms` is true only when the suite is non-empty and
every vector passed. This makes the empty-suite case fail closed (a suite with no vectors proves nothing), and
makes a candidate that throws on adversarial input fail rather than pass by omission.

## Threat Boundary

The adversary is a vendor claiming conformance it does not have: a self-reported "we pass the suite" (fixed —
the runner calls the candidate), a suite quietly edited to match a buggy implementation (fixed — the digest
pins the vectors, so any change is visible and versioned), or a candidate that passes the happy path but
errors on edge inputs (fixed — an erroring vector is a failure). The suite trusts nothing about the candidate
beyond the callable it is handed.

## API

Library: `warrantor_conformance::{TestVector, ConformanceSuite, VectorResult, ConformanceReport, suite_digest,
verify_suite, run_vector, run_suite}`.

## Testing

14 unit tests: a suite's digest is computed and verifies; tampering is detected; a conforming candidate passes
all vectors; a non-conforming candidate fails; an erroring vector is recorded as a failure with `actual: None`
(not a panic); an empty suite never conforms; a single mismatch breaks conformance; the report records the
suite id and version; `run_vector` matches and mismatches; the digest is order-sensitive; suite and report
round-trip through JSON; the run is deterministic; a version bump changes identity but not the vector digest.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §9 Domain I, I-5.
- Instantiated by: `rust/authority-algebra` (A-6) publishes a conformance suite this runner consumes.
- Generalizes: the vector-checking pattern used across the spec-pinned crates.
