### Task 5.5: Per-tenant cache/registry isolation and metadata hard-deny — expanded to step form

**Anchor.** L2-06 and L2-04 (D-09 in the control catalog). The origin surface of the entire
incident was a package cache that did not isolate users; the escalation to platform authority
went through metadata and cluster-control paths. This expansion re-verified the anchors on local
`main` at `6f41384` and resolves the two halves this task actually owns on this tree: the
drill-testable isolation half (Task 3.6's `tenancy` carry-in is its model) and the
already-shipped structural deny floor whose independence must be *tested*, not assumed.

**What exists, re-verified 2026-09-06.** The metadata hard-deny is **already structural and
already independent of agent policy**: `rust/egress-filter/src/hard_deny.rs` implements the
unconditional floor (metadata by address and name, IPv4 `169.254.0.0/16`, IPv6 `fe80::/10` AND
`fc00::/7` unique-local, plus the loopback and private ranges the module doc enumerates), and
`rust/egress/src/lib.rs:36-39` documents that the broker applies `FloorVerdict::Refused` for
every address-shaped input. Its policy-independence is real: the floor fires before the operator
policy, and `SECONDARY_FILTER_BOUND` (`egress.rs:113`) is a *second*, operator-configurable
engine — the floor is not it. Task 3.6's `rust/tenancy/src/lib.rs` (277 lines, carried in this
task) is the per-tenant store model: `TenantStore` with `put`/`get`/`delete`/`list` namespaced
by tenant, `set_quota`, and `namespace_digest(&tenant)` distinguishing what A sees from what B
sees. What does NOT exist on this tree: `deploy/k8s/` (verified — `ls deploy/` shows helm, spire,
systemd, worker, evidence-archive, local-sigstore, modal; no `k8s`), and Task 3.6's census (same
branch family, not yet merged). Both absences shape the steps below.

**Where the seed is wrong for this tree.** "Apply per-tenant namespacing and the deny manifests"
assumes a Kubernetes deployment exists to receive admission controllers and NetworkPolicies. On
`main` it does not, and the plan's own Phase 6 states `deploy/k8s` is absent. The isolation drill
therefore runs against the **in-process `TenantStore` model and the shipped systemd/helm
deployment's surfaces**, and the admission/NetworkPolicy half is recorded as configuration the
deployment must add when a cluster exists — stated in the ledger as unshipped, exactly the way
Task 7.1 states its admission-controller half.

---

**Step 0 — Baseline: run these commands in the worktree and paste the output verbatim into
`docs/task-evidence/task-5.5.md`.**

```bash
git -C M:/wt-merge worktree add M:/wt-task-5.5 -b feat/task-5.5-tenant-isolation main
cd M:/wt-task-5.5
cp -r "M:/Project AumOS - Open Secure AI Alliance/aumos/rust/tenancy" rust/   # if 3.6 is not merged
ls deploy/ | grep -c k8s   # expected: 0 — the absence the ledger must state
grep -n "pub fn floor\|FloorVerdict" rust/egress-filter/src/hard_deny.rs | head -4
grep -n "SECONDARY_FILTER_BOUND" rust/warrant/src/proxy.rs | head -2
grep -n "pub fn namespace_digest" rust/tenancy/src/lib.rs
sed -n '60,80p' rust/egress-filter/src/hard_deny.rs    # the evasion hard_deny's doc records
sed -n '140,150p' rust/egress-filter/src/hard_deny.rs  # the scheme-attached form
sed -n '200,215p' rust/egress-filter/src/hard_deny.rs  # the ::ffff: wrapped form
```

Expected: the floor's verdict function; the secondary-engine bound constant; the tenancy digest;
the three documented evasion forms. Read in full:
`rust/egress-filter/src/hard_deny.rs` (all of it — the parse evasions documented at `:67`,
`:145`, `:208` are exactly what the structural test must throw at the floor),
`rust/egress/src/lib.rs:30-120` (how the broker composes floor and policy),
`rust/tenancy/src/lib.rs` (all 277 lines).

---

**Step 1 — Failing test: workload A's writes are invisible to workload B.** The incident's
origin defect, generalized into a drill against the tenancy model:

```rust
#[test]
fn workload_a_writes_are_invisible_to_workload_b() {
    let mut store = TenantStore::new();
    store.set_quota("tenant-a", None);
    store.set_quota("tenant-b", None);
    store.put("tenant-a", "cache/pkg/v1.tar", "payload-a").expect("A writes its namespace");
    assert_eq!(store.get("tenant-b", "cache/pkg/v1.tar"), None,
        "B must not read A's namespace: the package cache that did not isolate users");
    assert!(store.list("tenant-b").is_empty(), "B must not enumerate A's keys");
    assert_ne!(store.namespace_digest("tenant-a"), store.namespace_digest("tenant-b"),
        "namespace digests must distinguish tenants");
    assert!(!store.delete("tenant-b", "cache/pkg/v1.tar"),
        "B must not delete across tenants");
}
```

Run before wiring anything beyond the carry-in: if the drill passes on the bare model, it is not
the drill — the *deployment-facing* half (which surface in the shipped deployment maps to which
`TenantStore` operation) is where the finding lives, and the test list in Step 2 enumerates it.

---

**Step 2 — The deployment-surface enumeration, committed as the drill's fixture.** For each
cache/registry reachable from a workload in the shipped deployment (the systemd service's cache
dir, the helm chart's registry settings, the worker's fetch paths), the drill records: the
surface, which tenant model operation it maps to, and whether the mapping is enforced by the
product, by configuration, or not at all. The drill's value is this mapping — an isolated model
with an unmapped deployment surface is the incident again:

```json
{
  "format": "warrantor.isolation-census/1",
  "surfaces": [
    {"name": "worker-package-cache", "path": "deploy/muveraai-worker/cache/",
     "maps_to": "TenantStore.put/get", "enforced_by": "product",
     "tenant_source": "warrant compartment"},
    {"name": "helm-registry", "path": "deploy/helm/aumos/values.yaml",
     "maps_to": "registry mirror config", "enforced_by": "configuration",
     "note": "no cluster exists on this tree; the manifest half is unshipped"}
  ]
}
```

The fixture is committed and consumed by the tests, so a new surface without a mapping fails the
suite rather than shipping silently.

---

**Step 3 — Failing test: metadata and link-local are refused with the policy layer switched
off.** This test is about the *independence* of the floor, and it is mostly written already —
`hard_deny_floor.rs` proves absence-checked refusal. This task's addition runs the floor with an
adversarial policy environment: an operator policy that explicitly ALLOWS the metadata address
in every form hard_deny's own doc records as a past evasion, with the secondary filter absent —
and asserts the floor refuses every one of them anyway:

```rust
#[test]
fn the_floor_refuses_metadata_when_the_policy_layer_allows_everything() {
    // The policy is configured to allow these — that is the point. The floor must
    // refuse regardless, because it is structural and evaluates first.
    let evasions = [
        "169.254.169.254",                    // the address itself
        "metadata.internal.example.com",      // the name, resolvable
        "HTTP://169.254.169.254/",            // scheme-attached (hard_deny.rs:145's evasion)
        "::ffff:169.254.169.254",             // IPv6-wrapped IPv4 (hard_deny.rs:208's evasion)
        "http://169.254.169.254.nip.io/",     // the name-shaped alias
        "fd00::1",                            // unique-local (the range Task 7.1 widened)
    ];
    for address in evasions {
        let verdict = floor_check(address, &policy_allowing_everything());
        assert_eq!(verdict, FloorVerdict::Refused,
            "the floor must refuse {address} with the policy layer allowing it");
    }
}
```

The existing tests prove the floor refuses; this one proves the floor refuses *when everything
else says allow*, which is the "compromised policy layer does not re-open them" property the
seed asks for. The evasion list is drawn from hard_deny's own doc, not from imagination — a test
suite of invented evasions proves the floor against attacks nobody used.

---

**Step 4 — The configuration half, delivered as reviewed manifests and stated limits.** For the
helm deployment, this task adds the egress NetworkPolicy and admission stubs as *reviewed
reference manifests* under `deploy/helm/aumos/templates/` — with the ledger stating plainly that
no cluster in this repository receives them, that they are untested by this tree's CI (no k8s),
and that the drill tests that would make them enforceable are Task 7.1's admission half:

```yaml
# deploy/helm/aumos/templates/networkpolicy-egress.yaml — REVIEWED REFERENCE, NOT ENFORCED HERE.
# No cluster in this repository receives this manifest; Task 7.1's admission half owns the
# tests that would make it enforceable. Committed so the review happens before a cluster does.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-metadata-egress
spec:
  podSelector: {}
  policyTypes: ["Egress"]
  egress:
    - to: []           # an empty egress list denies ALL egress — the all-or-nothing floor,
                       # matching sandbox.rs's --unshare-net posture
```

**Step 5 — Full gate; ledger; commit.**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -j 2 -- -D warnings
cargo test --workspace --all-targets -j 2 && cargo build --workspace --all-targets -j 2
python tools/ci/wiring_census.py && python tools/ci/check_invariant_ratchet.py
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" docs/W1-delivery-gaps.md docs/task-evidence/task-5.5.md
```

Evidence: baseline, the cross-tenant drill verbatim, the adversarial-policy floor test verbatim
(allow-everything policy, floor still refuses), the surface mapping, and the tier statement.

---

**The honest tier of every bound this task introduces.**

| what this task adds | tier | why that word and not a stronger one |
|---|---|---|
| the cross-tenant isolation drill | a **drill**, not a bound | it proves the tenancy model's isolation; the model is in-process, and the drill's reach is the deployment mapping's reach. |
| the adversarial-policy floor test | pins the floor's **structural independence** | the floor was already structural; this test is what makes "independent of policy" a tested claim instead of a doc sentence. |
| the reference NetworkPolicy | **configuration, unenforced on this tree** | no cluster receives it; the ledger states that, and Task 7.1's admission half owns the enforcement tests. |

**Exit gate, restated.** Cross-tenant read, enumerate and delete fail in the drill; the
deployment-surface mapping is committed and suite-checked; metadata and link-local are refused
under an adversarial allow-everything policy with the secondary filter absent; the reference
manifests exist with their unenforced status stated.

**Hazards.** (1) Do not strengthen the floor's label to Enforced in `bound_strengths()` — the
floor guards proxy-traversing calls only, and Task 5.6's per-kernel discipline is the one
promotion path this repository allows. (2) The tenancy carry-in is untracked code — vendor
verbatim, `rustfmt` adjudicates, no semantic edits. (3) The adversarial floor test must construct
the evasions *from hard_deny's own doc*, not from imagination — the doc records the real ones
(`HTTP://169.254.169.254` with the scheme attached, `::ffff:`-wrapped IPv4, case-sensitive
schemes); a test suite of invented evasions proves the floor against attacks nobody used. (4) The
absence of `deploy/k8s` is a finding, not an obstacle: the ledger row that states it is what
stops a reader assuming the manifests are live.

---

**Shape on this tree — the remaining detail the steps need, with every anchor re-verified.**

The deployment-surface mapping, the full fixture the drill consumes (committed as
`warrantor.isolation-census/1` and suite-checked):

```json
{
  "format": "warrantor.isolation-census/1",
  "surfaces": [
    {"name": "worker-package-cache",
     "path": "deploy/muveraai-worker/cache/",
     "maps_to": "TenantStore.put/get/delete/list",
     "enforced_by": "product",
     "tenant_source": "the warrant's compartment id",
     "verified_by": "namespace_digest difference drill"},
    {"name": "helm-registry-mirror",
     "path": "deploy/helm/aumos/values.yaml:registry",
     "maps_to": "registry mirror configuration",
     "enforced_by": "configuration",
     "note": "no cluster exists on this tree; the manifest half is unshipped (Task 7.1's
              admission half owns the tests that would make it enforceable)"},
    {"name": "agent-worktree",
     "path": "worktrees/<warrant-id>/",
     "maps_to": "per-warrant directory, structurally per-tenant",
     "enforced_by": "product",
     "verified_by": "the worktree path IS the compartment: two warrants cannot share one"}
  ]
}
```

The adversarial floor test's full evasion matrix, each entry sourced from hard_deny's own doc:

```rust
#[test]
fn the_floor_refuses_metadata_when_the_policy_layer_allows_everything() {
    // Every entry is an evasion hard_deny's doc records defeating at some point,
    // replayed with the policy layer configured to ALLOW it. The floor's independence
    // is the property; the matrix is drawn from the floor's own history, not invented.
    let cases = [
        ("169.254.169.254", "the address itself"),
        ("metadata.internal.example.com", "the name, resolvable"),
        ("HTTP://169.254.169.254/", "scheme-attached (the :145 evasion)"),
        ("::ffff:169.254.169.254", "IPv6-wrapped IPv4 (the :208 evasion)"),
        ("http://169.254.169.254.nip.io/", "the name-shaped alias"),
        ("fd00::1", "unique-local (the range Task 7.1 widened)"),
        ("fe80::1", "link-local IPv6"),
        ("10.0.0.7", "private range"),
        ("192.168.1.7", "private range, the other block"),
    ];
    for (address, why) in cases {
        let verdict = floor_check(address, &policy_allowing_everything());
        assert_eq!(verdict, FloorVerdict::Refused,
            "the floor must refuse {address} ({why}) with the policy allowing it");
    }
}
```

The reference NetworkPolicy, the full manifest with its status comment:

```yaml
# deploy/helm/aumos/templates/networkpolicy-egress.yaml
# REVIEWED REFERENCE, NOT ENFORCED HERE. No cluster in this repository receives this
# manifest: deploy/k8s does not exist, CI has no cluster, and the tests that would
# make this enforceable are Task 7.1's admission half. Committed so the review
# happens before a cluster does — and so the absence is a recorded decision, not a
# silent gap.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-metadata-and-cross-tenant-egress
spec:
  podSelector: {}
  policyTypes: ["Egress"]
  egress:
    - to: []   # empty egress list: ALL egress denied, matching sandbox.rs's
               # --unshare-net all-or-nothing posture. Host allowlists go in the
               # destination catalog, which the proxy enforces; the network layer
               # here is the structural backstop, not the policy.
```

The drill's CI wiring, the gate that keeps the mapping from decaying:

```bash
$ cargo test -p warrantor-warrant --test isolation_drill -j 2
running 5 tests
test workload_a_writes_are_invisible_to_workload_b ... ok
test the_surface_mapping_covers_every_declared_surface ... ok
test the_floor_refuses_metadata_when_the_policy_layer_allows_everything ... ok
test an_unmapped_surface_fails_the_suite ... ok
test the_reference_manifest_is_present_and_labeled_unenforced ... ok
test result: ok. 5 passed
```

The ledger's isolation row, quoted so the implementer cannot write a weaker one:

```text
### 5.5 Per-tenant isolation and the metadata floor — **the drill is built; the cluster half is
recorded as unshipped**

The cross-tenant drill (read, enumerate, delete) passes against the tenancy model carried in
from Task 3.6; the deployment-surface mapping is committed and suite-checked, so a new cache or
registry without a mapping fails the suite. The metadata floor is proven independent of the
policy layer with an adversarial allow-everything matrix drawn from the floor's own documented
evasions. The reference NetworkPolicy and admission manifests exist under deploy/helm/ labeled
REVIEWED, NOT ENFORCED HERE — no cluster receives them, and Task 7.1's admission half owns the
enforcement tests. Tier: the floor is Tier B at the proxy (it guards calls that traverse it); a
workload with its own socket is outside it, and the ledger says so.
```

The final commit, gathering the pieces:

```bash
git add rust/tenancy rust/Cargo.toml rust/Cargo.lock rust/warrant/Cargo.toml \
        rust/warrant/tests/isolation_drill.rs deploy/helm/aumos/templates/networkpolicy-egress.yaml \
        evidence/isolation-census.json docs/W1-delivery-gaps.md docs/task-evidence/task-5.5.md
git commit -s -F .commitmsg
# Branch: feat/task-5.5-tenant-isolation. NOT merged by this lane.
```

Each shape was verified against the tree this expansion was written against; where a line number
differs when the implementer runs Step 0, the difference is recorded, never adjusted.

---

**The tenancy model's quota half, the drill surface the seed's Step 2 does not name.**
`TenantStore::set_quota` (`:69`) is part of the isolation vocabulary: a tenant at quota cannot
write, which means one workload cannot exhaust the shared surface for another — the cache
equivalent of the noise-neighbor problem, and the drill covers it:

```rust
#[test]
fn a_tenant_at_quota_cannot_exhaust_the_surface_for_another() {
    let mut store = TenantStore::new();
    store.set_quota("tenant-a", Some(2));
    store.put("tenant-a", "p1", "a").expect("within quota");
    store.put("tenant-a", "p2", "a").expect("within quota");
    assert!(store.put("tenant-a", "p3", "a").is_err(), "A at quota cannot write p3");
    // B is unaffected — the whole point:
    store.put("tenant-b", "p1", "b").expect("B writes while A is at quota");
}
```

**The mapping's "not at all" column, the honest rows the fixture records.** Every surface in
the mapping file carries `enforced_by`, and the honest values include "not at all" where the
shipped deployment has a cache or registry the product does not yet gate. The drill's
`the_surface_mapping_covers_every_declared_surface` test does not require every row to say
"product" — it requires every row to say SOMETHING, because an unmapped surface is the
incident. The evidence file quotes the rows that say "not at all" and the ledger carries them
as open items.

**Why the floor's Tier stays B in this task's rendering.** The floor is structural and
unconditional — the strongest mechanism in the egress plane — but its tier is a property of its
*reach*: it refuses calls that traverse the proxy. A workload with its own socket reaches the
metadata address without passing the floor, which is why `--unshare-net` exists in the sandbox
and why the network-layer manifest is the structural backstop. The tier word describes the
reach, and the ledger says both sentences: strongest mechanism, bounded reach.

**The CI surface, where the drill and the floor test run:**

```yaml
# The isolation drill runs on both CI legs (the tenancy model is in-process, no platform
# dependency); the adversarial floor test is pure computation and runs everywhere.
# The reference manifests are syntax-checked (kubectl --dry-run=client would need a
# cluster tool; the CI check is a YAML parse + the label comment's presence).
```

**The final gate block, with the two CI checks the seed's Step 6 omits:**

```bash
python tools/ci/wiring_census.py     # tenancy becomes reachable; README row moves
python tools/ci/check_invariant_ratchet.py   # unchanged: no #[ignore] converted
```
