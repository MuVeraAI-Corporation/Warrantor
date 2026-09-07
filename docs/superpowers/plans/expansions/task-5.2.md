### Task 5.2: Egress-closure prover — `warrantor prove-egress` — expanded to step form

**Anchor.** L0-04 and the incident's central failure. "No direct internet access" was true and
irrelevant: three transitive paths existed — a cache SSRF, a proxy on a hosted app, and a rented
third-party sandbox. The report's own conclusion is the specification: restriction proved
insufficient where workloads can reach shared services or other systems providing transitive
paths. This expansion re-verified the anchors on local `main` at `6f41384` and resolves what the
prover enumerates, where it runs, and the one CI shape that makes it continuous.

**What exists, re-verified 2026-09-06.** `rust/egress/` (the broker: `EgressBroker`,
`DestinationCatalog` with `find` and `compute_digest`, `decide`) and `rust/egress-filter/` (the
deny floor: `hard_deny.rs`, whose module doc states the blast radius — cloud metadata, link-local
AND IPv6 unique-local — and records at `:40` that `warrantor-egress` already refused metadata
unconditionally before Task 7.1 shared the matcher). The destination catalog on `main` is
Task 2.5's derived `/2` broker catalog (`EgressBroker::catalog()`), plus Task 1.2's declared
catalog when that branch merges. Sandbox profiles exist: `sandbox.rs:262`
(`pub fn profile(bounds, worktree, confinement) -> Profile`) emits a bubblewrap command line and
documents at `:25` that `--unshare-net` is all-or-nothing — no host allowlist. `deploy/` holds
`helm/aumos/`, `spire/`, `systemd/`, `muveraai-worker/`, `evidence-archive/` — the reference
deployment the prover runs against. `DESTINATION_KEYS` (`egress.rs:706`) is `pub`.

**The seed's blind spot, resolved.** "Enumerates from inside a sandbox profile" cannot mean
network scanning — the non-goal forbids it and the sandbox on this tree is all-or-nothing. What a
closure proof CAN enumerate on this tree is the **graph of declared reachability**: the catalog's
hosts, each host's declared dependencies (from configuration), and the transitive closure of
"what a workload that can reach host X can obtain through X". The SSRF/proxy/rented-sandbox
failures are all instances of one shape: the immediate hop list was checked and the transitive
graph was not. So the prover is a **closure differ over declared configuration plus the deny
floor's verdicts**, seeded with a graph that models relays — and its honest limit, stated in the
ledger, is that it proves the *declared* graph, and its value is exactly the drift it catches.

---

**Step 0 — Baseline: run these commands in the worktree and paste the output verbatim into
`docs/task-evidence/task-5.2.md`.**

```bash
git -C M:/wt-merge worktree add M:/wt-task-5.2 -b feat/task-5.2-prove-egress main
cd M:/wt-task-5.2
grep -n "pub fn decide\|pub struct DestinationCatalog\|pub struct CatalogEntry\|pub fn find" rust/egress/src/lib.rs | head -5
grep -n "metadata_range\|LINK_LOCAL\|UNIQUE_LOCAL\|pub fn " rust/egress-filter/src/hard_deny.rs | head -8
sed -n '25,40p' rust/warrant/src/sandbox.rs
ls deploy/helm/aumos/templates/ | head -6
grep -rn "egress" deploy/helm/aumos/values.yaml | head -4
```

Expected: the broker API; the deny floor's range constants; the all-or-nothing note; the helm
templates the reference deployment manifests. Read in full:
`rust/egress-filter/src/hard_deny.rs` (the floor's exact ranges — the prover's closure must
consult them, because a relay to a metadata address is refused at the floor even when the
catalog names the relay), `rust/egress/src/lib.rs` (the catalog and the verdicts), and
`deploy/helm/aumos/values.yaml` (the declared egress the reference deployment starts from).

---

**Step 1 — The fixture graph and the seeded relay.** The reference-deployment fixture declares
three hosts: `api.example.com` (brokered, in catalog), `cache.internal.example.com` (a shared
cache whose declared configuration permits fetch-by-URL — the SSRF shape), and
`proxy.example.com` (a hosted-app proxy). The dependency edges: workload → api, api → cache,
cache → proxy. The seeded transitive path is workload → api → cache → proxy → metadata (the
cache accepts a `url=` argument; the proxy relays). If the prover cannot find this from declared
configuration alone, the prover is a formality — the seed's own sentence, now testable:

```yaml
# deploy/reference/egress-graph.yaml — the declared reachability the prover reads.
hosts:
  - name: api.example.com
    in_catalog: true
    reaches: [cache.internal.example.com]
  - name: cache.internal.example.com
    in_catalog: false            # reachable THROUGH api, never declared to the workload
    fetch_by_url: true           # the SSRF shape: the cache takes a url= argument
    reaches: [proxy.example.com]
  - name: proxy.example.com
    in_catalog: false
    relays: true                 # the hosted-app proxy
    reaches: ["169.254.169.254"] # and the metadata service is one hop beyond
```

**Step 2 — Failing test: the prover finds the seeded relay and diffs non-empty.**

```rust
#[test]
fn a_relay_reachable_through_a_permitted_host_is_found_and_fails_the_diff() {
    let graph = prove_egress::build_graph(fixture_config_path());
    let closure = graph.closure_from("api.example.com");
    // The catalog names api.example.com only; the closure reaches proxy.example.com
    // and, through it, the deny floor's metadata range.
    let diff = prove_egress::diff_against_catalog(&closure, &fixture_catalog());
    assert!(
        diff.reachable_but_uncataloged.contains(&"proxy.example.com".to_string()),
        "the seeded relay must be found: {diff:?}"
    );
    assert!(diff.violates_deny_floor, "the metadata endpoint through the relay is a floor violation");
    // The path is the remediation: the proof names every hop, not just the endpoint.
    assert_eq!(diff.paths[0].hops, vec!["api.example.com", "cache.internal.example.com",
                                        "proxy.example.com", "169.254.169.254"]);
}
```

Run before implementing: the missing subcommand/module is the failure. Paste the red output
verbatim.

**Step 3 — Implement the closure enumeration over declared configuration.** `prove_egress`
loads the deployment's declared egress (the graph YAML + the catalog), builds the dependency
graph, consults `hard_deny` for each reachable node, and emits `warrantor.egress-proof/1`: the
closure, the diff against the catalog, the floor verdicts, and the coverage statement (Step 5).
Each node's verdict comes from the same `decide`/`hard_deny` functions the proxy uses at
runtime — the prover must not carry a second evaluator, or it proves a different policy than the
one enforcing:

```rust
/// The egress-closure proof. Everything the prover checked, what it found, and what it
/// did NOT check — the coverage block is what makes an empty diff meaningful.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressProof {
    pub format: String,                    // "warrantor.egress-proof/1"
    pub catalog_digest: String,            // which catalog the diff was taken against
    pub closure: Vec<String>,              // every host the declared graph reaches
    pub diff: EgressDiff,                  // reachable-but-uncataloged, floor violations
    pub paths: Vec<ReachPath>,             // the hop chains, for the remediation
    pub coverage: ProofCoverage,           // Step 5's honesty block
}
```

**Step 4 — Any non-empty diff fails, naming the destination.** The subcommand exits non-zero
when the diff is non-empty, prints each offending destination with the path that reaches it
(the three-hop chain, not just the endpoint — the path is the remediation), and refuses nothing
at runtime: this is a proof tool, not a bound. The error text names the violating hop chain so
the operator can close it at the source:

```text
$ warrantor prove-egress --graph deploy/reference/egress-graph.yaml --catalog catalog.json
egress closure FAILED: 2 destination(s) reachable outside the catalog
  proxy.example.com          via api.example.com -> cache.internal.example.com
  169.254.169.254 (metadata) via api.example.com -> cache.internal.example.com -> proxy.example.com
  DENY-FLOOR violation: the metadata range is refused unconditionally at the proxy,
  but the prover's job is the closure, not the runtime refusal.
proof coverage: 3 declared hosts, 3 edges, sources: egress-graph.yaml + destination catalog
  (undeciphered configuration is outside this proof; see the coverage block)
exit 1
```

**Step 5 — Continuous, not periodic, and the prover's own coverage published.** The report's
remediation says continuous explicitly. Two wiring points, both in this task: (a) a CI job that
runs the prover against the fixture graph on every change to `rust/egress*/`,
`rust/warrant/src/sandbox.rs`, or the deployment values — the graph drifts when code or config
drifts, so the proof runs when its inputs move; (b) the reference deployment runs the prover as
a post-apply hook. A nightly-only prover is the eleven-day blind spot again. And the honest
number is what the prover checked, not what exists:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCoverage {
    /// Declared hosts the graph walked.
    pub hosts_walked: usize,
    /// Edges the graph holds.
    pub edges: usize,
    /// Configuration sources read, by path.
    pub sources: Vec<String>,
    /// The sentence that keeps an empty diff honest.
    pub limitation: String,   // "undeciphered configuration is outside this proof"
}
```

**Step 6 — Full gate; ledger; commit.**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -j 2 -- -D warnings
cargo test --workspace --all-targets -j 2 && cargo build --workspace --all-targets -j 2
python tools/ci/wiring_census.py && python tools/ci/check_invariant_ratchet.py
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" docs/W1-delivery-gaps.md docs/task-evidence/task-5.2.md
```

Evidence: baseline, the failing test verbatim, the fixture graph, the proof output over the
reference deployment, and the tier statement (the prover is Tier C, observed — it proves
configuration and refuses nothing at runtime; the runtime bounds stay as they are, and the
ledger says the proof's authority is exactly the drift detection it performs).

---

**The honest tier of every bound this task introduces.**

| what this task adds | tier | why that word and not a stronger one |
|---|---|---|
| the prover itself | **Tier C, observed** | it proves configuration and refuses nothing at runtime; its authority is exactly the drift detection it performs. |
| the CI wiring | a **ratchet**, not a bound | it makes graph drift a red build; it stops nothing at runtime. |
| the coverage block | the **honesty mechanism** | an empty diff without it is a claim about everything; with it, the claim is scoped to what was read. |

**Exit gate, restated.** Empty diff on the reference deployment; the seeded three-hop relay is
detected with its full path named; the proof runs on CI when its inputs move; the prover's own
coverage is published in the proof document.

**Hazards.** (1) No network in CI: the prover reads configuration and calls the deny floor's
functions — it must never open a socket, or the CI job becomes the scan the non-goal forbids and
the flaky test the suite cannot afford. (2) Do not let the fixture graph leak into product code
as a default: the graph is test/deployment configuration, and a hardcoded topology in the binary
is a false proof waiting for a different deployment. (3) The catalog digest changes when the
catalog changes; the proof must record which digest it proved against, or an empty diff from
last week reads as today's. (4) The metadata node in the fixture graph is a *fixture* — the deny
floor refuses it at runtime already; the prover's finding is that the graph makes it REACHABLE,
which is a configuration fact the runtime refusal cannot see.

---

**Shape on this tree — the remaining detail the steps need, with every anchor re-verified.**

The fixture graph's full YAML, the deployment configuration the proof reads (committed beside
the drill):

```yaml
# deploy/reference/egress-graph.yaml — declared reachability, the prover's only input.
# This file is deployment configuration, not product code: a different deployment
# writes its own, and the prover proves what it is given. A hardcoded topology in
# the binary would be a false proof waiting for that deployment.
hosts:
  - name: api.example.com
    in_catalog: true                 # the workload is DECLARED to reach this
    reaches:
      - cache.internal.example.com   # the API fetches packages from the shared cache
  - name: cache.internal.example.com
    in_catalog: false                # reachable THROUGH api — never declared to the workload
    fetch_by_url: true               # the SSRF shape: the cache accepts a url= argument
    reaches:
      - proxy.example.com            # the cache's own egress goes through the proxy
  - name: proxy.example.com
    in_catalog: false
    relays: true                     # the hosted-app proxy: CONNECT + forward
    reaches:
      - "169.254.169.254"            # and the metadata service is one hop beyond
      - "0.0.0.0/8"                  # and the deny floor's other ranges apply
```

The prover's subcommand wiring, the three places a new verb touches (the same triad as before):

```rust
// dispatch:
"prove-egress" => cmd_prove_egress(&args, &root),

// usage, after the census block:
//   prove-egress --graph <egress-graph.yaml> --catalog <catalog.json>
//           prove the declared reachability closes over the destination catalog

// the allowlist entries in tests/instructions.rs:
//     "graph",
//     "catalog",
```

The catalog digest in the proof, why the diff is only meaningful against a named state:

```rust
#[test]
fn the_proof_records_which_catalog_digest_it_diffed_against() {
    let proof = run_prover(&fixture_graph(), &fixture_catalog());
    assert_eq!(proof.catalog_digest, fixture_catalog().digest,
        "the proof is against the catalog's digest at proof time");
    // A stale proof is detectable: re-run the prover, and the digest differs if the
    // catalog moved. An empty diff from last week reads as today's only if nobody
    // can tell which catalog it proved against.
}
```

The CI job, the yaml that makes the proof continuous:

```yaml
# .github/workflows/egress-proof.yml — the proof runs when its inputs move:
# on: [push, pull_request] with paths filters on rust/egress*/, rust/warrant/src/sandbox.rs,
# deploy/**. A nightly-only prover is the eleven-day blind spot again.
jobs:
  egress-closure:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo build -p warrantor-warrant --bin warrantor
      - run: ./target/debug/warrantor prove-egress --graph deploy/reference/egress-graph.yaml
                   --catalog deploy/reference/catalog.json
```

The ledger's egress row, quoted so the implementer cannot write a weaker one:

```text
### E.4 Egress-closure prover — **built; it proves the declared graph, and its reach is the
declared graph's reach**

`warrantor prove-egress` walks the declared reachability graph from the deployment's egress
configuration, consults the same deny floor the proxy uses at runtime, and diffs the transitive
closure against the destination catalog. The seeded three-hop relay (workload -> api -> cache ->
proxy -> metadata) is detected with its full path named, and any non-empty diff is a build
failure. The proof runs in CI when its inputs move, and publishes its own coverage (hosts
walked, edges, sources). What this does not establish: the prover reads declared configuration —
an undeclared surface, an undeclared dependency, or a host that lies about its own egress is
outside the proof. The runtime bounds are unchanged (Tier B at the proxy); the prover is Tier C,
observed, and its authority is exactly the drift detection it performs.
```

The final commit, gathering the pieces:

```bash
git add rust/warrant/src/prove_egress.rs rust/warrant/src/bin/warrantor.rs \
        deploy/reference/egress-graph.yaml deploy/reference/catalog.json \
        .github/workflows/egress-proof.yml tools/ci/instructions.rs \
        rust/warrant/tests/instructions.rs docs/W1-delivery-gaps.md docs/task-evidence/task-5.2.md
git commit -s -F .commitmsg
# Branch: feat/task-5.2-prove-egress. NOT merged by this lane.
```

Each shape was verified against the tree this expansion was written against; where a line number
differs when the implementer runs Step 0, the difference is recorded, never adjusted.

---

**The enumeration's data source, resolved to what this tree actually has.** The prover reads two
configuration sources, and the evidence file names both: the destination catalog (Task 2.5's
derived `/2` broker catalog, digest-stamped, what the workload is declared to reach) and the
deployment's egress graph (the fixture YAML, what each declared host can reach beyond the
workload). The graph's edges come from configuration because no edge can be discovered from
code — a cache that accepts a `url=` argument is a fact about the cache's API, recorded by the
operator who deployed it, and the prover's job is to make that recorded fact contradict-or-confirm
the catalog, loudly.

**The failure mode this task exists to end, stated as the incident states it.** Three transitive
paths existed; each was invisible because the immediate-hop check and the transitive reality
lived in different documents that nobody diffed. The prover is that diff, automated, and its
failure output is the three-hop chain precisely because the remediation for "cache relays
through proxy" is "close the cache's egress", not "remove the proxy from the catalog" — the hop
chain is the instruction.

**Why the prover consults `hard_deny` per node.** A relay to `169.254.169.254` is refused at
runtime by the floor regardless of the catalog. The prover still marks it `violates_deny_floor`
because the finding is configuration-level: the graph says the path exists, the floor says the
endpoint is denied, and the two together mean the configuration is depending on the floor to
keep a declared-reachable path harmless — which is a dependency, not a design. The proof's
`violates_deny_floor` flag is what surfaces that dependency for review; removing it would hide
exactly the class of finding the incident's report named.

**The evidence file's distribution section, quoted as a shape:**

```text
Prover determinism: 10 runs over the fixture graph produced byte-identical proofs
(same closure, same diff, same coverage) — the proof is a pure function of its
inputs, and the evidence records that.
Proof runtime: p50 3ms, max 11ms over the 3-host fixture. The CI budget is 1s;
the fixture is small, and the budget exists to catch accidental graph explosion,
not to measure the prover's speed.
```

**The drift the proof catches, the one-paragraph story for the ledger.** A new host added to
the cache's `reaches:` list without a catalog entry is a non-empty diff on the next CI run —
the failure names the host and the hop chain that reaches it. A host removed from the catalog
while still reachable is the same. A deny-floor range appearing at any closure node flags
`violates_deny_floor`. Every one of these is a change someone could make in a values file on a
Friday afternoon; the proof makes it a red build on Monday.

**The final gate block, restated with the metadata check the seed's Step 7 omits:**

```bash
cargo metadata --format-version 1 --locked > /dev/null   # the proof adds no dependency
python tools/ci/wiring_census.py                          # 14/42 expected; the prover is
                                                          # inside rust/warrant, not a new crate
```
