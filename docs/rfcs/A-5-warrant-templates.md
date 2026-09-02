# A5 — `warrant-templates` RFC

> The warrant template library (build-catalogue **A-5**, Domain A, Wave 1, loop L4): a versioned, signed
> library of pre-built warrant scopes per job function and per regulation. Templates are data, not code —
> installable and customizable by narrowing — so onboarding drops from days to minutes and a vertical pack
> becomes a product.

| Field | Value |
|---|---|
| **Canonical ID** | A5 (catalogue A-5) |
| **Name** | warrant-templates |
| **Wave** | 1 (authority plane) |
| **Languages** | Rust |
| **Catalogue item** | A-5 |
| **Dependencies** | none (produces the scope a grant is built from; the notary evaluates it) |

## Background

Authority-setting today is a developer task: hand-edit Cedar. The catalogue's recurring non-dev theme is
that a compliance officer should grant a governed shape in one command. A template library is the
packaging that makes that real — `warrantor template install finance-analyst` yields a working
grant→report→verify cycle with zero hand-written policy, and the officer then customizes bucket names and
dollar caps. Templates are also what make the vertical packs (Domain G) consumable: a pack without
templates is a crate; with templates it is a product. And community templates become an ecosystem surface
(loop L3).

## Goals and Non-Goals

**Goals:**
- Model a [`WarrantTemplate`](rust/warrant-templates/src/lib.rs) as data: a [`TemplateScope`](rust/warrant-templates/src/lib.rs) (capabilities, resource classes, max TTL, max budget, approval-required actions), a
  policy set, and the expected receipt fields — the compliance evidence contract.
- Ship [`builtin_templates`](rust/warrant-templates/src/lib.rs): the job-function shapes (repo-maintainer, read-only-analyst,
  incident-responder) and the finance-family verticals (SR 26-2 underwriter, DORA ops agent, FINRA 2111
  advisor), each carrying its regulatory receipt fields.
- Version and resolve templates through a [`TemplateRegistry`](rust/warrant-templates/src/lib.rs) (latest-version lookup, same-version replace).
- [`instantiate`](rust/warrant-templates/src/lib.rs) a concrete [`GrantScope`](rust/warrant-templates/src/lib.rs) by *narrowing*: an override may only shrink the shape — any capability, resource,
  TTL, or budget widening is a [`NarrowError`](rust/warrant-templates/src/lib.rs), so a customization can never escalate beyond the
  template's governance.

**Non-Goals:**
- Signing templates — the digest is a content fingerprint the host signs on install.
- Evaluating the resulting warrant — the notary does; this produces the scope.
- Running the studio — customization is N2's job; this is the data model and the narrowing rule.

## Detailed Design

A template's identity is `(id, version)`; the registry keeps versions sorted and `latest` returns the
highest. `install` replaces an existing `(id, version)` or appends a new version. The template digest is
`sha256:` over the canonical JSON of its content, so a version bump or a scope edit changes it.

`instantiate(template, override)` enforces narrowing: every override capability must be in the template's
set, every resource class must be a declared class, `override.max_ttl_ms <= template.max_ttl_ms`, and an
override budget must not exceed the template's ceiling (a `None` template ceiling permits any override
budget). The resulting `GrantScope` carries the narrowed capabilities/resources/ttl/budget but **inherits
the template's `requires_approval_for`** — an override cannot drop an approval requirement, which is the
point of the whole exercise. The grant digest binds it to the template id and version.

## Threat Boundary

The adversary is governance drift: a customization that quietly widens a grant beyond the shape the
template encodes, or an override that strips an approval gate. Narrowing-by-intersection makes both
impossible — the override is a subset operation enforced at instantiation, and approval requirements are
inherited, not overridable. The registry trusts installed templates to be signed by the host (the digest
is the fingerprint that signature covers); a tampered template changes its digest. This crate does not
evaluate the grant — a compromised notary is outside its boundary — it guarantees only that what reaches
the notary is no wider than the template.

## API

Library: `warrant_templates::{TemplateScope, WarrantTemplate, TemplateRegistry, GrantScope, NarrowError,
instantiate, builtin_templates}`. `WarrantTemplate::new`; `TemplateRegistry::{new, install, get, latest,
ids}`.

## Testing

14 unit tests: the builtin library ships all six templates; install resolves the latest version and
re-installing a version replaces it; instantiate narrows capabilities and TTL within the template and
inherits its approval requirements; capability, resource, TTL, and budget escalations are each refused; an
unlimited template budget permits any override budget; the template digest is deterministic and
distinguishes versions; the grant digest is deterministic; vertical templates carry their regulatory
receipt fields; registry ids are sorted and unique.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §3 Domain A, A-5; §17.2 authority chain.
- Consumes: `rust/authority-spec` / `rust/notary` (the grant built from the scope), `rust/warrant`.
- Customized by: N2 policy studio (D-2). Makes consumable: Domain G vertical packs (G1–G5).
- Compounds with: A-1 policy compiler (templates are the target shape it compiles toward), A-2 delegation.
