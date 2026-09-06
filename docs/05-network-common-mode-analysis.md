# Common-mode independence analysis: the double network path

Anchor: **L2-03** *"Independent double network isolation"* and its generalization **L0-10**
*"Common-mode independence analysis"*. Both carry `data-status="none"` in the master blueprint, and
**this document does not change either status.** What it changes is that the absence is now
measured, published, and gated.

L2-03's verification clause is this document's specification, verbatim:

> Disable either layer in a drill; the egress prover (L0-04) still reports closure. Residual: the
> two layers must be shown to share no policy engine, credential or telemetry path, or the drill
> proves nothing. Blueprint proof gate (D-03): Common-mode analysis proving the two layers do not
> share a failure domain.

Two controls that fail together are one control. This document counts the controls, names every
failure domain they share, and concludes that the count of independent intercepts on a permitted
destination is **one**.

Every number below is read from [`evidence/network-independence.json`](../evidence/network-independence.json)
by `tools/ci/network_independence.py`, which derives the record from the sources rather than from
this prose. A sentence here that disagrees with the code fails the build.

---

## 1. The layers that exist

### Layer A — the MCP proxy chokepoint

Real, reachable, and the only layer that decides per host. `rust/warrant/src/proxy.rs` lines
408-442 run every destination a call names through the broker and, only when a caller has wired
one, through the second engine. The shipped binary wires none: `Proxy::new` sets
`secondary: None` and nothing in `warrantor.rs` constructs a `SecondaryFilter`, so a shipped run
decides with **one** engine and the second `if let` below is never entered:

```rust
for destination in crate::egress::destinations_of(call) {
    let verdict = self.egress.decide(&destination.host);
    self.pending.push(PendingDecision {
        tool: call.tool.clone(),
        argument: destination.argument.clone(),
        capability: self
            .resolved_names
            .get(&destination.host)
            .cloned()
            .unwrap_or_else(|| capability_for(&destination.host)),
        destination: destination.host.clone(),
        verdict: verdict.clone(),
    });
    if let EgressVerdict::Deny { reason } = verdict {
        let refusal = EgressRefusal::new(&call.tool, &destination, reason);
        return self.deny_egress(&call.tool, refusal);
    }
    // Second engine, second configuration source, SAME chokepoint.
    //
    // Deny-only, and structurally so: the broker's arm above returns before this runs, so
    // there is no branch here that can turn its `Deny` into a `Forward`. There must never
    // be one -- a warrant bound an operator file could widen is not a bound.
    //
    // This is a second POLICY DOMAIN and not a second boundary. It does not raise
    // `Independence::intercepts`, and no surface may render the engine count as though it
    // were an enforcement count: see `crate::egress::INDEPENDENCE_NOTE`.
    if let Some(secondary) = self.secondary.as_ref() {
        let decision = secondary.decide(&destination.host);
        if decision.action == warrantor_egress_filter::Action::Deny {
            let refusal =
                crate::egress::SecondaryRefusal::new(&call.tool, &destination, &decision);
            return self.deny_secondary(&call.tool, refusal);
        }
    }
}
```

> **Rebase note (2026-09-06).** The block above is the loop as it stands after this branch was
> rebased onto `main` at `92b6018`. Task 2.1's decision log landed on `main` in the meantime and
> inserted the `self.pending.push(...)` at the top of the loop, before either engine can refuse.
> Two consequences, stated so nobody reads the log as a second telemetry path: the pushed record
> is the **broker's** verdict, by the definition of `EgressDecision` (*"One broker decision"*),
> so a call the second engine refuses leaves an `Allow` row in `egress/<warrant>.jsonl` and a row
> in `Proxy::secondary_refusals`, in the same process; and the pushed record is drained by the
> same endpoint that holds both maps. The telemetry-path axis stays **shared**. The four line
> anchors on this page were re-derived by the gate at the rebased tree, not carried forward.

> **Citation correction.** Both adversarial review lenses caught this independently. The block above
> was quoted from the **pre-change** file — missing the very engine this task added — and all four
> `proxy.rs` anchors on this page were pre-change line numbers, stale by exactly the lines this
> branch inserted above them. A reader following the old `227-234` landed inside `deny_secondary`, a
> function that did not exist when the anchor was written. Every non-`proxy.rs` citation on this page
> verified correct, which is the tell: `proxy.rs` is the one file the branch grew. Nothing caught it,
> because the gate's probes matched strings and its render targets matched the count, and no check
> read a line anchor at all. Anchors are now **derived** by
> `tools/ci/network_independence.py::citations_resolve`, which finds each construct's real line in
> the source and fails the build when this document cites a different one.

Two properties of that loop matter for independence and are easy to misread:

- `NEVER_IN_OBSERVE` (`rust/warrant/src/proxy.rs` lines 159-160) holds exactly
  `[SideEffectClass::Destructive, SideEffectClass::Financial]`. It contains nothing egress-shaped,
  so **observe mode records every network call and refuses none.**
- `staged_classes` is consulted *after* the egress loop (lines 444-451), so staging is never a
  substitute for an egress refusal.

### Layer B — the network namespace

`rust/warrant/src/sandbox.rs` lines 316-322. The condition is the whole finding:

```rust
// The asymmetry this module exists to surface. A network namespace is all-or-nothing.
if bounds.egress_hosts.is_empty() {
    match confinement {
        Confinement::Bubblewrap => argv.push("--unshare-net".to_string()),
        Confinement::Firejail => argv.push("--net=none".to_string()),
    }
```

The `else` branch, lines 333-346, states in the code why it is off in every other case: *"a network
namespace has no host allowlist -- it is all or nothing. `--unshare-net` is therefore NOT in the
command above: adding it would deny egress the warrant grants."*

Layer B is also **not an enforcement this process performs**. `sandbox::profile` returns a `Vec<String>`
of argv that the binary *prints*. `PROFILE_CAVEAT` (`rust/warrant/src/sandbox.rs` lines 209-215) says
so in the artifact itself: *"This is a COMMAND, not an enforcement. Nothing is confined until you
launch the agent under it, and Warrantor cannot tell whether you did."*

### The layer the blueprint assumes and the repository does not have

L2-03's `what` places the second layer *"at the cluster infrastructure"*. There is no `deploy/k8s`
directory. There is exactly one `NetworkPolicy` in the tree and it cannot hold an egress bound at
all: `deploy/spire/trust-domain-config.yaml` line 129, with `policyTypes: ["Ingress"]` at line 137.
It restricts who may *reach* trust-core. It says nothing about what any workload may reach, and its
own comment at line 124 concedes the limit: *"NetworkPolicy itself is L3/4; SPIRE enforces the L7
trust."*

**The cluster layer is absent, so L2-03 stays `status=none`.**

---

## 2. The anti-correlation

One warrant field, `WarrantBounds::egress_hosts`, drives both layers — in opposite directions.

Layer A's catalog is empty when the field is empty (`rust/warrant/src/egress.rs` lines 196-201):

```rust
if bounds.egress_hosts.is_empty() {
    return Self {
        catalog: None,
        chain,
    };
}
```

An absent catalog is `DenyReason::CatalogUnavailable`. So:

| `bounds.egress_hosts` | layer A (proxy) | layer B (netns) | independent intercepts on a permitted host |
|---|---|---|---|
| empty | denies everything as `CatalogUnavailable` | `--unshare-net` emitted | 2, but there is no permitted host to intercept |
| non-empty | decides per destination | **not emitted, deliberately** | **1** |

**The two layers are anti-correlated, not independent.** Exactly when layer A has a non-trivial
decision to make, layer B is switched off; exactly when layer B is on, layer A has already denied
everything. There is no configuration in which a permitted destination is guarded twice.

That is a common-mode failure of the strongest kind — a single point of *configuration*, not merely
a single point of failure. It is invisible in every current rendering, because `bound_strengths()`
reports `("egress_hosts", BoundStrength::Mediated)` (`rust/warrant/src/lib.rs` line 695) without
saying that the count of independent intercepts is one.

---

## 3. The four axes, per layer

The anchor's residual makes these the test. Two layers sharing any one of them are not independent.

| axis | layer A (MCP proxy) | layer B (network namespace) | shared? |
|---|---|---|---|
| **enforcement point** | `Proxy::decide`, in the `warrantor` process | the kernel, *if* an operator launched the printed profile | **shared in practice**: layer B is never emitted alongside a permitted host, so only one point ever acts on one |
| **credential** | none — `rust/warrant/src/egress.rs` lines 53-56: *"the process that serves a supervised agent deliberately holds no key"* | none | **not shared** — and independent by *absence*, not by design |
| **configuration source** | `WarrantBounds::egress_hosts`, inside the signed claims | the same field, read with the opposite sense | **shared** |
| **telemetry path** | `Proxy::egress_refusals`, `Proxy::secondary_refusals` and `Proxy::requests` (`rust/warrant/src/proxy.rs` lines 139-152), in-process, no independent sink | **none at all**: a netns refusal is a `connect()` failure inside the agent that never reaches Warrantor | **shared** |

L0-10's own residual names three more that any analysis must concede: *"an unmodeled shared
dependency such as a resolver, a clock or a certificate authority is still common-mode."* Two of the
three are modeled here, and both are shared:

| axis | finding | shared? |
|---|---|---|
| **clock** | `bounds.expires_at` is copied into every `CatalogEntry` (`rust/warrant/src/egress.rs` line 215) and is also the one `BoundStrength::Enforced` time bound | **shared** |
| **DNS resolution** | neither layer resolves. `rust/warrant/src/egress.rs` lines 49-52: *"A hostname that resolves *into* a metadata or private range is therefore not caught by the range check; only a literal address in the bound is."* Layer B removes the resolver entirely | **shared, by absence** — a shared blind spot is a common mode |
| certificate authority | not modeled: no TLS identity is pinned or checked anywhere in this system (`rust/warrant/src/egress.rs`, `tls_identity: None`) | not applicable |

The DNS row is the concrete exploit the anti-correlation opens. A hostname that resolves into
`169.254.169.254` is not caught by layer A's floor unless the name itself is on
`hard_deny::FLOOR_HOSTNAMES`, and layer B — which would catch it, because it removes the network
outright — is off whenever any host is permitted.

**Operator flag.** One `--egress` argument at grant time sets the field that drives both. There is
no second switch.

---

## 4. The shared address floor, which is newer than this analysis

This axis did not exist when this task was specified, and it is the reason a second policy engine
buys less than it looks like it buys.

Task 7.1 placed the non-amendable deny floor in `rust/egress-filter/src/hard_deny.rs` and made
`warrantor-egress` delegate to it (`rust/egress/src/lib.rs` line 18 imports it; line 228 calls
`hard_deny::refuse`). The same two functions are consulted by
`warrantor_egress_filter::Policy::decide_domain` (line 251) and `Policy::decide_ip` (line 314).

So **the moment `Policy` is wired as a second evaluator, the two evaluators share a crate and share
their floor.** A defect in `hard_deny` fails both at once.

That is not an argument against Task 7.1's placement, which was correct for the reason it gives: two
implementations of "is this the metadata service" is the exact shape of the defect that let eight of
nine spellings of `169.254.169.254` reach Allow. One matcher prevents drift. It also couples the
layers. **Both things are true, and the independence analysis has to record the second one even
though the first one is why the code is right.**

The axis is therefore named `address_floor` and it is **shared in every configuration**, wired or
not.

---

## 5. What the second policy engine does and does not buy

`warrantor-egress-filter`'s `Policy` decision surface had no caller in the product. It is now wired
as `SecondaryFilter` in `rust/warrant/src/egress.rs` and consulted inside the existing loop in
`Proxy::decide`, deny-only.

Reachable is not reached. Nothing in the shipped binary constructs a `SecondaryFilter`:
`Proxy::new` sets `secondary: None`, `warrantor.rs` has no caller of `with_secondary_filter` or
`from_operator_config`, and no CLI flag or configuration path leads to either. A shipped run
therefore decides with **one** policy engine, and the record publishes
`policy_engines_the_product_runs: 1`. Two engines decide only once a Rust caller of the library
wires the second, and everything in this section about "both evaluators" describes that wired
configuration.

What that buys, precisely:

- A **second evaluator** with a **different default** (`DecisionReason::DefaultDeny` on an empty
  allowlist) and a **different configuration source** (an operator-authored file, not the signed
  warrant claims). If a destination catalog is over-broad — and Task 1.2 is making catalogs
  machine-generated, which removes the human review step — a second evaluator that never read those
  claims still refuses.
- Deny-only by construction: the broker decides first, so its structured `DenyReason` stays the
  reported reason, and there is no branch in which the filter turns a `Deny` into a `Forward`.

What it does **not** buy, and what no surface may imply:

- It is **not** a second enforcement point. Both evaluators run inside `Proxy::decide`. A shell
  command, a harness built-in, or any socket the agent opens itself passes neither.
- It does **not** raise the intercept count. `engines` goes from 1 to 2; `intercepts` stays at 1.
- It does **not** make the policy-engine axis fully disjoint, because of section 4.

---

## 6. Conclusion

There is no configuration of this system in which a permitted destination is guarded by two
independent controls. When `bounds.egress_hosts` is non-empty the network namespace is
deliberately not emitted (`rust/warrant/src/sandbox.rs` lines 333-346); when it is empty the
proxy denies every destination as `CatalogUnavailable` (`rust/warrant/src/egress.rs` lines
196-201) and there is no permitted destination left to guard. The count of independent
intercepts on a permitted host is therefore **1**, and L2-03 stays `status=none`.

### What the count excludes

The count above is a count of enforcement points acting on a destination this warrant permits.
Every policy engine that decides a destination -- the broker always, and a second engine only once
one is wired -- runs inside the Warrantor MCP proxy at that one point, so the engine count is a
count of policy domains and is not a second boundary: a shell command, a harness built-in, or any
socket the agent opens itself passes neither the proxy nor any engine inside it. There is no network
namespace, seccomp filter or firewall behind this count, and the confinement profile does not add
one for a warrant that permits any host -- it omits --unshare-net precisely then. A hostname that
resolves into a private or metadata range is not caught: no engine at that point resolves DNS.

This paragraph is `egress::INDEPENDENCE_NOTE` in `rust/warrant/src/egress.rs`, verbatim:
`tools/ci/network_independence.py::analysis_paragraph_is_the_constant` reads the constant out of
the Rust source and fails the build if this paragraph is anything else. The same gate requires the
constant's two load-bearing clauses -- what the count is, and what escapes it -- within twelve
lines of the rendered count on each of the three render targets it names (this document,
`README.md`, `docs/W1-delivery-gaps.md`), not merely somewhere in the same file, for the same
reason `ENFORCEMENT_NOTE` exists: a bare count is read as containment. No product code renders the
constant; the three Markdown copies are the only surfaces, and the evidence file for Task 5.4
transcribes the gate's output without being one of them.

L0-10's verification clause asks that *"for each catastrophic effect class an artifact lists at
least two controls with disjoint failure domains."* For network egress, this artifact lists one, and
says so.

> **Correction, found independently by both adversarial review lenses.** This section, the Rust
> constant it quotes and the CI rule that pinned it all used to open *"The count above is a count of
> policy domains, not a count of enforcement points."* That sentence was **false about the number it
> sat beside, in the unsafe direction.** Every surface the gate polices publishes exactly one
> number -- `Independence::intercepts` -- and that number **is** the enforcement-point count. The
> machine record beside it said so in capital letters (`evidence/network-independence.json`: *"The
> count is a count of ENFORCEMENT POINTS ... not of policy engines"*), while the mandated caveat told
> the reader the published `1` did not bound enforcement points. The policy-domain clause now belongs
> to the *engine* count, which is the number it is true of, and
> `tools/ci/network_independence.py` **fails the build on the withdrawn wording** rather than
> requiring it. Two Rust tests refuse it as well, because a clause pinned by CI in three places is a
> clause that comes back. The same paragraph also used to offer a remedy this document disproves
> three sections earlier -- *"unless you launched the confinement profile yourself"* -- which
> `sandbox::profile` withholds for exactly the warrants this count is about.

---

## 7. What would make the count two

Recorded so that this document names its own exit condition rather than leaving the reader to guess.

1. A **second enforcement point** that acts on a *permitted* host. The netns cannot be it: it has no
   host allowlist. A filtering proxy inside the namespace, with the namespace allowing only that
   proxy, would be — `rust/warrant/src/sandbox.rs` line 341 already names this remedy.
2. A **cluster layer** with egress `policyTypes`, which would satisfy L2-03 as written.
3. Either of those must arrive with its **own** configuration source, telemetry sink and clock, or
   the axis table above simply grows a row and the count stays one.

**Which of these the finding test can actually see, and the correction that says so.** This section
used to promise that when *any* of the three lands,
`rust/warrant/tests/invariants/i09_failure_is_safe.rs` starts failing on purpose. That held for exit
condition 1 in its resolver form and for nothing else. `harness::reached_the_boundary_unrefused` goes
red when the predicate handed to it flips, and that predicate is closed over the two in-process
policy engines: a resolver on the egress path flips it, and no kernel layer and no cluster policy is
an input to it at all. A reviewer demonstrated that by landing exit condition 2 -- a real cluster
egress `NetworkPolicy` -- whereupon the finding test stayed green, the I-09 corpus stayed at 85
passed, and the gate went on publishing **1**. The two prose facts in section 3 that carry this
conclusion (*no `deploy/k8s` directory*, *exactly one `NetworkPolicy` in the tree*) were ungated and
false throughout that run.

So the cluster half now has its own assertion, in the one place that can read a YAML file:
`tools/ci/network_independence.py::cluster_layer_absent` fails the build when a `NetworkPolicy` this
analysis does not know about appears, and when the single one it names disappears. Exit condition 1
stays carried by the finding test, and exit condition 3 by the axis table above. Whoever lands any of
them converts the test, moves the count and the record together, and raises the ratchet.
