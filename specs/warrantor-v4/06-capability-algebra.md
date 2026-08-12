# The Capability Algebra — `warrantor-intersect-v1`

> The meet operation that makes I-02 ("no authority expansion") a computable property rather than a
> slogan. Effective authority along a delegation chain is the **meet** of every link's capability
> set, computed in a lattice whose ordering *is* attenuation.
>
> **Status:** FROZEN CANDIDATE — closes open question 1 of the v4 contract pack.

---

## 1. Why flat string sets fail

The obvious model — capabilities are opaque strings, meet is set intersection — is provable, fast,
and unusable. Under it, `read:/data/*` and `read:/data/x` are unrelated strings whose intersection
is empty. A root that delegates "read anything under `/data`" to an agent that sub-delegates "read
`/data/x`" produces **no authority at all**, which is not a safe default but a broken one: it makes
legitimate narrowing impossible, so operators route around delegation entirely.

The algebra must therefore understand that `/data/x` is *narrower than* `/data/*`, and it must know
this without appeal to any external resolver, because verification has to work offline.

---

## 2. The capability triple

A capability is a triple:

```
Capability := (Action, Resource, Constraints)
```

| Component | Domain | Meet |
|---|---|---|
| `Action` | Dotted hierarchical name, `*` permitted as a terminal wildcard | Hierarchy meet (§3) |
| `Resource` | Segmented pattern over a scheme-qualified path | Segment-wise meet (§4) |
| `Constraints` | Typed key → predicate map | Conjunction (§5) |

A capability **set** is a finite set of triples. The meet of two sets is defined in §6.

The ordering `a ⊑ b` reads "*a is no broader than b*". The meet `a ∧ b` is the greatest element no
broader than both. **This ordering is the entire security argument:** if the computed effective
authority is always ⊑ every link, authority can never expand.

---

## 3. Action meet

Actions are dotted paths (`tool.read`, `net.egress.http`, `credential.issue`) with `*` permitted
only as the final segment, where it matches any suffix of one or more segments.

```
meet(a, b) = a            if a ⊑ b        (a is equal to, or a suffix-extension of, b)
           = b            if b ⊏ a
           = ⊥            otherwise
```

`tool.read ⊑ tool.*` and `tool.read.file ⊑ tool.read`. `tool.read ∧ tool.write = ⊥`.

**Normative.** `*` **MUST NOT** appear in a non-terminal position. Implementations **MUST** reject a
capability whose action contains an interior wildcard rather than attempt to interpret it — an
un-analyzable action string cannot be proven attenuating.

---

## 4. Resource meet

Resources are scheme-qualified segmented patterns: `fs:/data/reports/q3`, `http://api.example/v1/*`,
`db:prod.customers.**`.

Two wildcard forms, and no others:

| Token | Matches | Position |
|---|---|---|
| `*` | exactly one segment | any |
| `**` | one or more trailing segments | terminal only |

Meet is computed **segment-wise**, left to right, and the language is closed under it — the result
of a meet is always expressible in the same language, which is the property that makes the algebra
decidable:

| left | right | meet |
|---|---|---|
| `x` | `x` | `x` |
| `x` | `y` (x≠y) | `⊥` |
| `x` | `*` | `x` |
| `*` | `*` | `*` |
| any remainder | `**` | the remainder |
| `**` | `**` | `**` |

Schemes must be equal or the meet is `⊥`. If one pattern is exhausted while the other still requires
segments, the meet is `⊥` unless the remaining requirement is exactly `**`.

**Worked:** `fs:/data/**` ∧ `fs:/data/reports/q3` = `fs:/data/reports/q3` — the narrower survives,
which is the behavior flat sets could not express. `fs:/a/*/c` ∧ `fs:/a/b/**` = `fs:/a/b/c`.
`fs:/data/x` ∧ `fs:/logs/x` = `⊥`.

**Normative.** `**` **MUST** appear only as the final token. Percent-encoding, case, and
`.`/`..` segments **MUST** be normalized before the meet (§7); implementations **MUST** reject a
pattern that does not normalize rather than compare raw strings — path-confusion is a standard
escalation route.

---

## 5. Constraint meet

Constraints are a map from a typed key to a predicate. Meet is conjunction, evaluated per key:

| Constraint type | Meet | Example |
|---|---|---|
| Numeric ceiling | `min` | `max_rows: 1000` ∧ `max_rows: 50` → `50` |
| Numeric floor | `max` | `min_approvals: 1` ∧ `min_approvals: 2` → `2` |
| Time interval | interval intersection; empty → `⊥` | disjoint windows → `⊥` |
| Enumerated set | set intersection; empty → `⊥` | `regions:{us,eu}` ∧ `regions:{eu}` → `{eu}` |
| Boolean requirement | logical OR of "required" | `human_approval: false` ∧ `true` → `true` |

A key present in one operand and absent in the other is carried through **unchanged**: absence means
"unconstrained", and constraining an unconstrained dimension is attenuation, never expansion.

> **Normative — the unknown-constraint rule.** If either operand carries a constraint key whose type
> the implementation does not know, the meet **MUST** evaluate to `⊥` and the receipt **MUST** be
> rejected. Implementations **MUST NOT** ignore, drop, or pass through unknown constraints.
>
> This is the single most important rule in this document. Silently dropping an unrecognized
> constraint converts a narrow capability into a broad one — an attacker who can introduce a novel
> constraint key on a link would otherwise widen authority through the very mechanism meant to
> restrict it. Fail closed on the unknown.

---

## 6. Set meet, and the chain

For capability sets `A` and `B`:

```
A ∧ B  =  canonicalize({ a ∧ b : a ∈ A, b ∈ B, a ∧ b ≠ ⊥ })
```

Every pair is met; `⊥` results are discarded; the survivors are canonicalized (§7). The pairwise
product is what allows a broad grant and a narrow grant to combine into the narrow one, rather than
requiring syntactic equality.

Effective authority over a chain of links `L₁ … Lₙ` (root-first) is the left fold:

```
effective(L₁ … Lₙ) = caps(L₁) ∧ caps(L₂) ∧ … ∧ caps(Lₙ)
```

Links whose validity window does not contain the evaluation instant are **excluded before** the
fold — an expired link contributes nothing rather than contributing everything.

**If the fold yields the empty set, the chain grants no authority and the action is denied.**
Empty is a legitimate, common outcome; it is not an error condition to be worked around.

### Properties (the security argument)

Meet is **commutative**, **associative**, and **idempotent**, so the fold is order-independent and
the structure is a meet-semilattice. From `a ∧ b ⊑ a` and `a ∧ b ⊑ b` it follows by induction that:

> **For every link i, `effective(L₁…Lₙ) ⊑ caps(Lᵢ)`.**

That is invariant I-02, stated as a theorem over the algebra rather than as a policy hope. It is the
proposed subject of the machine-checked specification (component `R9`, Tier C) — the property is
small enough to be worth proving mechanically, and proving it is the point.

**What the theorem does not cover:** it assumes every link is authentic. Intersection is sound only
while the identity root is honest; that assumption is addressed separately in
[`07-root-compromise.md`](07-root-compromise.md).

### Verification status

The resource-meet operation defined in §4 has been **mechanically checked** over an exhaustive
sample of the pattern space (all pairs and triples drawn from a set exercising exact segments,
`*`, `**`, mismatched schemes, differing lengths, and disjoint prefixes). It is confirmed
commutative, associative, idempotent, and closed — and the attenuation property `a ∧ b ⊑ a` and
`a ∧ b ⊑ b` holds for every pair, which is invariant I-02 over that sample. The four worked
examples in §4 and §8 reproduce exactly.

This is a check over a sample, not a proof over the domain. Promoting it to a proof — including the
action and constraint dimensions, and the full set-meet of §6 — is the concrete scope of the
machine-checked specification (`R9`, Tier C). The property is now small and precise enough that
proving it is a bounded task rather than an open-ended research programme, which is the main reason
this document was worth writing before any implementation.

---

## 7. Canonical form and the proof digest

`intersection_proof.result_digest` is only meaningful if two implementations canonicalize
identically. Before hashing, an implementation **MUST**:

1. Normalize each resource — lowercase the scheme, resolve `.`/`..`, decode then re-encode
   percent-escapes canonically, collapse duplicate separators.
2. Drop any capability subsumed by another in the same set (if `a ⊑ b`, `a` is redundant and
   removed).
3. Serialize each triple as `action|resource|constraints`, with constraint keys sorted lexically.
4. Sort the triples lexically.
5. Serialize the set as JCS-canonical JSON and digest it.

`links_digest` is computed the same way over the ordered chain, so a verifier can recompute both
values from `authority.chain[]` alone with no issuer cooperation.

**Normative.** A verifier **MUST** recompute `effective_capabilities`, `links_digest`, and
`result_digest`, and **MUST** reject the receipt on any mismatch. The issuer's claimed effective set
is a convenience for readers, never a source of truth.

---

## 8. Conformance vectors

`testvectors/protocols/P2/v2/capability-algebra.json` — every case below **MUST** pass:

| Case | Expected |
|---|---|
| `fs:/data/**` ∧ `fs:/data/reports/q3` | `fs:/data/reports/q3` (narrower wins) |
| `fs:/a/*/c` ∧ `fs:/a/b/**` | `fs:/a/b/c` |
| `fs:/data/x` ∧ `fs:/logs/x` | `⊥` |
| `tool.read` ∧ `tool.*` | `tool.read` |
| `tool.read` ∧ `tool.write` | `⊥` |
| `max_rows:1000` ∧ `max_rows:50` | `50` |
| disjoint time windows | `⊥` |
| **unknown constraint key present** | **`⊥`, receipt rejected** |
| interior wildcard `tool.*.read` | rejected, not interpreted |
| `**` in non-terminal position | rejected |
| unnormalizable path (`fs:/a/../../etc`) | rejected |
| order permutation of the same chain | identical `result_digest` |
| expired link in chain | excluded before fold; fold proceeds |
| all links expired | empty set → deny |
| claimed `effective_capabilities` ⊃ recomputed | rejected (I-02) |
