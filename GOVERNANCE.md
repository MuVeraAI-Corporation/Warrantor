# Governance

Warrantor is a small project that intends to grow. This describes how decisions are made today, not
an aspirational structure — an over-specified governance document for a project this size is a way of
looking established rather than being clear.

## Who decides

Maintainers, listed in [MAINTAINERS.md](MAINTAINERS.md), have commit rights and merge authority.
Decisions are made by consensus in the open — a pull request or an issue thread. When consensus is
not reached, the maintainer responsible for that area decides and records why.

## Becoming a maintainer

Sustained, high-quality contribution and demonstrated judgement about what *not* to build. An
existing maintainer proposes; the others agree. There is no fixed contribution count, because the
review that catches a subtle authority bug is worth more than twenty typo fixes.

## What needs more than one reviewer

Two maintainers must approve changes to:

- **Authority semantics** — anything touching warrant bounds, capability tokens, or settle authority.
- **Cryptographic code** — signing, verification, domain separation, key handling.
- **The staging and settle engine** — release ordering, partial-failure behaviour.
- **Process supervision** — the OS lifetime link.

These are the areas where a plausible-looking change can be wrong in a way that tests still pass. A
bug here is not a defect in a feature; it is the removal of the guarantee the project exists to make.

## Changing a security property

Any change that weakens an enforced bound, converts an `Enforced` bound to `Observed`, or adds a path
by which an agent could influence its own authority requires:

1. An issue describing the property being changed and why.
2. Explicit maintainer agreement before implementation, not after.
3. A test that fails without the mechanism — a test that passes when the mechanism is deleted is not
   a test of it.

The last one is enforced by review. Write the test, delete the mechanism, confirm the test goes red,
put the mechanism back. It catches tautological tests, which are common and worse than no test
because they create confidence.

## Roadmap

Direction is set in the open through issues and discussions. Where help is most useful is listed in
the [README](README.md), ranked by what it unblocks.

## Code of conduct

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies to every project space. Reports go to the address
listed there.

## Licence and provenance

Apache-2.0. Every commit carries a [DCO](https://developercertificate.org/) sign-off, enforced in CI.
There is no CLA — the DCO is sufficient and does not ask contributors to assign rights.
