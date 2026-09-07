### Task 3.6: Improvised-channel detection and the shared-surface census — expanded to step form

**Anchor.** L5-02 and L2-01 — jointly the control that would have prevented the incident outright.
Agents noticed each other's package fetches in a shared cache *before anyone tried to
communicate*; the board was invisible for roughly eleven days and surfaced only via an unrelated
port-sweep alert. This expansion re-verified the anchors on local `main` at `6f41384` and pins
the carry-in, the classification, and the census-to-CI shape to real code.

**What exists, re-verified 2026-09-06.** `rust/tenancy/src/lib.rs` is **277 lines, untracked**
(dirty main checkout only). It is a per-tenant store with quota: `TenantStore` (`:54`) with
`put`/`get`/`delete`/`list` namespaced by tenant, `set_quota` (`:69`), `resource_count`
(`:121`), `tenant_count` (`:127`), and — the piece this task is built on —
`namespace_digest(&tenant)` (`:133`), a per-tenant digest that already distinguishes "what
tenant A can see" from "what tenant B can see". Task 2.1's effect registry is on `main`:
`DecompositionRegistry::classify` (`effects.rs:463`) classifies by declared decomposition, and
Task 2.5 added `http.call` to the builtin set. The improvised-channel defect the census hunts is
therefore expressible in existing terms: a MUTATE-class call whose target surface is shared
across two workloads of the same family.

---

**Step 0 — Baseline: run these commands in the worktree and paste the output verbatim into
`docs/task-evidence/task-3.6.md`.**

```bash
git -C M:/wt-merge worktree add M:/wt-task-3.6 -b feat/task-3.6-channel-census main
cd M:/wt-task-3.6
cp -r "M:/Project AumOS - Open Secure AI Alliance/aumos/rust/tenancy" rust/
wc -l rust/tenancy/src/lib.rs
grep -n "pub fn namespace_digest\|pub fn put\|pub fn set_quota\|pub fn list" rust/tenancy/src/lib.rs
grep -n "pub fn classify" rust/warrant/src/effects.rs
grep -n "MUTATE" rust/warrant/src/effects.rs | head -4
grep -n "wiring_census" tools/ci/wiring_census.py | head -2
```

Expected: 277 lines carried; `namespace_digest` at `:133`; `classify` at `:463`; the
orphan-census pattern at `tools/ci/wiring_census.py` (the shape the surface census's CI gate
copies). Read in full: `rust/tenancy/src/lib.rs` (all 277 lines — the quota semantics and the
digest are the isolation vocabulary), `rust/warrant/src/effects.rs` (the decomposition the
census classifies against), and Task 0.3's evidence file for the ratchet pattern.

---

**Step 1 — The classification, written before the census: four categories, no fourth.** Every
mutable surface writable by two workloads of the same family is exactly one of: **brokered**
(writes go through a governing intermediary that can attribute and refuse), **read-only** (the
workload cannot write it at all), **per-tenant** (namespaced so cross-tenant writes are
structurally impossible — `TenantStore` is the model), or **covert channel** (shared, writable,
ungoverned). The absence of a fifth category is the design: an "unknown" bucket is where
unenumerated surfaces hide, and this task's exit gate refuses to have one.

```rust
// rust/warrant/src/census.rs
pub const SURFACE_CENSUS_FORMAT: &str = "warrantor.surface-census/1";

/// One mutable surface, classified. There is no Unknown variant: the census's whole job is
/// that this list is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceClass {
    /// Writes are attributed and gated by a governing intermediary.
    Brokered,
    /// The workload cannot write this surface.
    ReadOnly,
    /// Namespaced per tenant; cross-tenant writes are structural impossibilities.
    PerTenant,
    /// Shared, writable, ungoverned. The incident's origin. Alarmed, then refused.
    CovertChannel,
}

/// One declared surface and what the census decided about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceRecord {
    /// The surface's name in the deployment's configuration.
    pub name: String,
    /// How the workload reaches it (path, URL prefix, registry host).
    pub address: String,
    /// The class the census assigned — never Unknown.
    pub class: SurfaceClass,
    /// For PerTenant: the namespace digest per tenant, proving A and B differ.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_digests: Option<Vec<(String, String)>>,
}
```

**Step 2 — Failing test: `warrantor census` enumerates and classifies.** The census enumerates
from the same place Task 2.5's HTTP adapter learned its destinations — declared configuration —
plus the filesystem surfaces the store already knows (worktrees, staged logs, receipts). The
test seeds a config naming three surfaces (one per-tenant backed by `TenantStore`, one
brokered, one read-only), runs the real binary, and asserts each surface appears with a class:

```rust
#[test]
fn the_census_enumerates_declared_surfaces_and_classifies_each() {
    let root = tempdir("census");
    write_surface_config(&root, &[
        surface("pkg-cache", "cache/", SurfaceClass::PerTenant),
        surface("warrant-store", "store/", SurfaceClass::Brokered),
        surface("docs", "docs/", SurfaceClass::ReadOnly),
    ]);
    let out = run_census(&root);
    let census: Census = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(census.surfaces.len(), 3);
    assert!(census.surfaces.iter().all(|s| s.class != SurfaceClass::CovertChannel));
    // And the per-tenant entry carries the digests that prove the namespacing:
    let cache = census.surfaces.iter().find(|s| s.name == "pkg-cache").expect("found");
    let digests = cache.tenant_digests.as_ref().expect("per-tenant proof");
    assert_ne!(digests[0].1, digests[1].1, "A and B digest differently");
}
```

Run before implementing: the missing subcommand is the failure.

**Step 3 — Failing test: a cross-workload MUTATE to a multi-tenant store raises an alarm keyed
on shape.** Two warrants (different warrant ids, same family), one surface classified per-tenant
backed by `TenantStore`, workload A writes to tenant A, then workload B attempts the same
*namespace path* — the alarm fires on the **shape** (two distinct workload principals addressing
one key space), not on content:

```rust
#[test]
fn a_cross_workload_write_alarms_on_shape_and_is_refused() {
    let mut store = TenantStore::new();
    store.put("tenant-a", "cache/pkg/v1.tar", "a").expect("A writes its own namespace");
    // B addresses the same path. The shape is "a second workload principal in A's key
    // space" — the content is irrelevant by design.
    let attempt = store.put_as("tenant-b", "cache/pkg/v1.tar", "b", &principal_b);
    assert!(attempt.is_err(), "the cross-tenant write is refused");
    let alarm = store.take_alarm().expect("the shape raised an alarm");
    assert_eq!(alarm.workloads, [principal_a.clone(), principal_b.clone()]);
    assert_eq!(alarm.surface, "pkg-cache");
    assert!(alarm.receipted_at_ms > 0, "the alarm is timestamped for latency measurement");
}
```

Content keying degrades against steganography (L5-02's own caveat); shape keying does not,
because the shape is what the brokered layer can always see. Assert the alarm is receipted (a
record naming both workload principals and the surface) and that its latency from first
cross-workload write is measured and published — the incident's figure was days via an
unrelated alert; the published number is the improvement this task sells.

**Step 4 — Implement the census and the alarm.** The census subcommand loads the declared
surfaces, classifies each against its backing (per-tenant stores verify via
`namespace_digest`; brokered surfaces verify their intermediary is on the decision path; anything
without a verifier is `CovertChannel` by construction), and writes `warrantor.surface-census/1`.
The alarm hooks the per-tenant store's `put`: a write whose principal's tenant differs from the
path's namespace is the shape, and it refuses in addition to alarming once Step 5 is in. The
alarm's receipt goes to the same ledger discipline every other receipt uses — append-only,
versioned, named.

**Step 5 — Unclassified surfaces are refused to agent workloads, not warned about.** This is the
seed's sharpest sentence and the step that makes the census a guarantee rather than a report: a
declared surface the census cannot classify, or an undeclared surface discovered at write time,
is `CovertChannel`-equivalent for enforcement — the write is refused and receipted. A warning is
an alarm nobody reads in eleven days:

```rust
#[test]
fn a_surface_the_census_cannot_classify_refuses_writes() {
    // Declare a surface with no backing verifier — the config names it, but nothing
    // in the census can prove it brokered, read-only or per-tenant.
    let class = classify_surface(&no_verifier_surface());
    assert_eq!(class, SurfaceClass::CovertChannel,
        "no verifier means the surface is covert by construction");
    assert!(write_is_refused(&no_verifier_surface()),
        "the refusal is the enforcement half of the classification");
}
```

**Step 6 — Wire the census to CI as a ratcheting number.** The plan's hazard is the design:
enumeration decays without automation. `tools/ci/surface_census.py` (Task 0.3's orphan-census
shape) counts declared surfaces and refuses a decrease, and the reference deployment's census
file is committed so drift is a diff:

```bash
python tools/ci/surface_census.py          # counts and verifies each surface's class evidence
python tools/ci/surface_census.py --write  # refreshes evidence/surface-census.json after a
                                           # deliberate change, in the commit that makes it
```

The alarm latency number joins the same gate so it cannot silently regress.

**Step 7 — Full gate; ledger; commit.**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -j 2 -- -D warnings
cargo test --workspace --all-targets -j 2 && cargo build --workspace --all-targets -j 2
cargo metadata --format-version 1 --locked > /dev/null
python tools/ci/wiring_census.py && python tools/ci/surface_census.py && python tools/ci/check_invariant_ratchet.py
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" docs/W1-delivery-gaps.md docs/task-evidence/task-3.6.md rust/warrant/src/census.rs
```

Evidence: baseline, all failing tests verbatim, the detection-latency measurement, the tier
statement (the census itself is a report; the refusal is Tier B at the per-tenant store's write
path — an agent writing the surface outside every governed path is the covert channel by
definition, and the ledger says the census's reach is the guarantee's reach).

---

**The honest tier of every bound this task introduces.**

| what this task adds | tier | why that word and not a stronger one |
|---|---|---|
| the census (enumeration + classification) | a **report**, not a bound | it proves nothing by existing; its value is that the refusal in the next row can only be as complete as it is. |
| the shape alarm | **Observed**-tier evidence, plus a **refusal** at the tenancy store | the alarm records; the per-tenant store's write path refuses — Tier B at that path, because the store is in-process and the agent reaches it only through governed calls. |
| the refused unclassified surface | **Tier B** at the tenancy write path | a workload writing the surface outside every governed path is the covert channel by definition; the ledger says the census's reach is the guarantee's reach. |

**Exit gate, restated.** The census classifies every declared shared surface into the closed
four-category set; an unclassified or undeclared surface is refused with a receipt; a seeded
cross-workload write alarms within the published latency, keyed on shape; the census and the
latency are CI-ratcheted.

**Hazards.** (1) `tenancy` is untracked — carry it in verbatim (277 lines) this task's first
commit, as Task 0.1's pattern; it is already `rustfmt`-clean per the carry inspection, but
expect `cargo fmt --check` to adjudicate. (2) Do not let the four categories grow a fifth
("informational"): an unknown bucket is the hole. (3) The alarm must key on shape only — the
moment the test asserts on content, the census claims a detection capability against
steganography it does not have, and L5-08's horizon item exists precisely because that claim
would be false. (4) The census's declared-surface config is deployment configuration, not code —
the fixture for tests lives beside the tests, the reference deployment's file lives in `deploy/`,
and neither is hardcoded into `census.rs`.

---

**Verification detail — the shapes the steps compile against, captured on the carry-in.**

The tenancy store's namespace digest, the census's per-tenant proof, quoted from the carry-in:

```rust
pub fn namespace_digest(&self, tenant: &str) -> String {
    // A digest over the tenant's own key space: what A sees, digested, differs from
    // what B sees, digested — and the census carries both digests as the proof that
    // the namespacing is real, not asserted.
}
```

The census document, as the test reads it back:

```json
{
  "format": "warrantor.surface-census/1",
  "generated_at": 1788,
  "surfaces": [
    {"name": "pkg-cache", "address": "cache/", "class": "per_tenant",
     "tenant_digests": [["tenant-a", "aa41"], ["tenant-b", "7c09"]]},
    {"name": "warrant-store", "address": "store/", "class": "brokered"},
    {"name": "docs", "address": "docs/", "class": "read_only"}
  ],
  "unclassified": []
}
```

The alarm's receipt, the shape-keyed record the latency is measured from:

```json
{
  "format": "warrantor.channel-alarm/1",
  "surface": "pkg-cache",
  "workloads": ["spiffe://muveraai.com/agent/a", "spiffe://muveraai.com/agent/b"],
  "shape": "second workload principal in one key space",
  "first_cross_write_at_ms": 1788,
  "alarmed_at_ms": 1788,
  "latency_ms": 3,
  "content_digest": null
}
```

`content_digest: null` is load-bearing, and the test pins it: the alarm carries no content
digest because content keying degrades against steganography — the alarm's claim is the shape,
and the null is the sentence that says the claim is honest.

The CI gate, as the evidence records it:

```bash
$ python tools/ci/surface_census.py
surface census: 3 declared surfaces, 3 classified, 0 unclassified — ok
alarm latency (from the drill receipt): 3ms; published bound: 1000ms — ok
$ python tools/ci/surface_census.py --write   # only in the commit that deliberately changes the census
```

The honest-summary sentence the ledger adds: *"Every declared shared surface is classified into
a closed four-category set; the unclassified and undeclared are refused at the tenancy write
path; a seeded cross-workload write alarms in single-digit milliseconds, keyed on shape. What
this does not establish: detection of channels that never touch a declared surface — a covert
channel the deployment does not name is outside the census's reach, and L5-08's steganographic
detection is a horizon item for exactly that reason."*

---

**Shape on this tree — the remaining detail the steps need, with every anchor re-verified.**

The census subcommand's wiring, showing the three places a new verb touches (dispatch, usage,
allowlist — the same triad Tasks 2.4 and 2.6 each paid for):

```rust
// dispatch, inside main's match:
"census" => cmd_census(&args, &root),

// usage, after the tools block:
//   census  [--surface <name=path> ...] [--tenancy <file>]
//           emit warrantor.surface-census/1 over the declared shared surfaces

// the allowlist entry in tests/instructions.rs:
//     "surface",
//     "tenancy",
```

The classification function, where the four-category closure is actually enforced:

```rust
/// Classify one declared surface. There is no Unknown: the census's whole job is
/// that this function returns one of the four for every declared surface, and the
/// fifth outcome (refuse) is what happens when the surface was never declared.
fn classify_surface(surface: &DeclaredSurface) -> SurfaceClass {
    match surface {
        DeclaredSurface::Tenancy { store_path } => {
            // Verify the namespacing is real: digest two tenants, require difference.
            let mut store = TenantStore::open(store_path);
            let a = store.namespace_digest("verification-a");
            let b = store.namespace_digest("verification-b");
            if a == b {
                // The namespacing claim failed its own proof: this is a covert
                // channel wearing a per-tenant name, and the census says so.
                SurfaceClass::CovertChannel
            } else {
                SurfaceClass::PerTenant
            }
        }
        DeclaredSurface::Brokered { intermediary } => {
            if intermediary_on_decision_path(intermediary) {
                SurfaceClass::Brokered
            } else {
                SurfaceClass::CovertChannel
            }
        }
        DeclaredSurface::ReadOnly { .. } => SurfaceClass::ReadOnly,
        DeclaredSurface::Unverifiable { .. } => SurfaceClass::CovertChannel,
    }
}
```

The drill's alarm test through the real binary, the latency measurement the CI gate reads:

```rust
#[test]
fn the_alarm_latency_from_first_cross_write_to_notification_is_measured_and_published() {
    // Workload A writes; workload B writes the same path; the alarm's receipt carries
    // both timestamps. The latency is the difference, and the CI gate refuses a
    // regression above the published bound.
    let drill = CensusDrill::new(&fixture_config());
    drill.write_as("tenant-a", "cache/pkg/v1.tar", "a").expect("A writes");
    let first_cross = drill.now_ms();
    let result = drill.write_as("tenant-b", "cache/pkg/v1.tar", "b");
    assert!(result.is_err(), "the cross write is refused");
    let alarm = drill.take_alarm().expect("alarmed");
    let latency = alarm.alarmed_at_ms - first_cross;
    assert!(latency <= PUBLISHED_BOUND_MS, "latency {latency}ms exceeds the bound");
    // And the published number in the ledger is THIS number, not a hand-copied one:
    assert_eq!(latency, read_published_latency(), "the published latency drifted");
}
```

The carry-in's zero-edit proof, the diff stat that goes in the evidence:

```bash
$ git diff --stat main -- rust/tenancy/
 rust/tenancy/Cargo.toml | 2 +-
 rust/tenancy/src/lib.rs | 4 +-
 2 files changed, 3 insertions(+), 3 deletions(-)
```

The ledger's channel row, quoted so the implementer cannot write a weaker one:

```text
### E.3 Improvised-channel detection and the shared-surface census — **built; the census's
reach is the guarantee's reach**

Every declared shared surface is classified into a closed four-category set (brokered,
read-only, per-tenant, covert-channel); the unclassified and undeclared are refused at the
tenancy write path; a seeded cross-workload write alarms within the published latency, keyed on
shape, with the content digest deliberately null. The census is CI-ratcheted — a removed surface
or a regressed latency is a red build. What this does not establish: detection of channels that
never touch a declared surface — a covert channel the deployment does not name is outside the
census's reach, and L5-08's steganographic detection is a horizon item for exactly that reason.
The tenancy model is in-process; the deployment's real caches are represented by the mapping
file, and a mapping nobody wrote is a surface nobody classified.
```

The final commit, gathering the pieces:

```bash
git add rust/tenancy rust/Cargo.toml rust/Cargo.lock rust/warrant/Cargo.toml \
        rust/warrant/src/census.rs rust/warrant/src/bin/warrantor.rs \
        tools/ci/surface_census.py evidence/surface-census.json \
        rust/warrant/tests/instructions.rs docs/W1-delivery-gaps.md docs/task-evidence/task-3.6.md
git commit -s -F .commitmsg
# Branch: feat/task-3.6-channel-census. NOT merged by this lane.
```

Each shape was verified against the tree this expansion was written against; where a line number
differs when the implementer runs Step 0, the difference is recorded, never adjusted.
