### Task 5.4: Common-mode independence analysis for double network isolation

**Anchor.** L2-03, quoted verbatim from the master blueprint (`docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html` line 3296): `<article class="item" id="L2-03" data-stratum="L2" data-plane="D" **data-status="none"** data-novelty="compose" data-wave="W1" data-loop="lin">`. The item is titled *"Independent double network isolation"* and its `what` reads: *"Two separate enforcement layers, one at the sandbox and one at the cluster infrastructure, so that a compromise of one leaves the other standing. This is the property whose absence turned a container escape into an internet escape."* Its verification clause is this task's specification and its residual is this task's hazard, both verbatim (line 3303): *"Disable either layer in a drill; the egress prover (L0-04) still reports closure. Residual: the two layers must be shown to share no policy engine, credential or telemetry path, or the drill proves nothing. Blueprint proof gate (D-03): Common-mode analysis proving the two layers do not share a failure domain."* The generalized item is L0-10 *"Common-mode independence analysis"*, also `data-status="none"` (line 3070), whose cross-reference names this one: *"L2-03 double isolation is the canonical instance"*. Neither status is softened here: **status=none for both**, and Step 0 below shows why that is the correct reading of the code and not a stale label.

Two controls that fail together are one control. The product's own vocabulary already knows this — `BoundStrength::Mediated` (`rust/warrant/src/lib.rs` lines 203-208) says the bound is *"held at a chokepoint the agent could decline to use"* — and nothing in this repository measures whether the second thing standing behind that chokepoint is a second failure domain or the same one wearing a different name.

**Step 0 — exact commands, files read in full, and the real output.**

Read in full, with the line counts as measured on `refs/remotes/origin/main` at `e4b5f10`:

```bash
git -C "M:/Project AumOS - Open Secure AI Alliance/aumos" worktree add --detach M:/wt-x-54 refs/remotes/origin/main
cd M:/wt-x-54
wc -l rust/egress/src/lib.rs rust/egress-filter/src/lib.rs rust/warrant/src/proxy.rs \
      rust/warrant/tests/invariants/i09_failure_is_safe.rs
```

```text
  618 rust/egress/src/lib.rs
 1102 rust/egress-filter/src/lib.rs
  311 rust/warrant/src/proxy.rs
  204 rust/warrant/tests/invariants/i09_failure_is_safe.rs
 2235 total
```

Also read in full because the four above are not sufficient to answer the question: `rust/warrant/src/egress.rs` (499 lines — the module that turns a warrant into the broker's catalog), `rust/warrant/src/sandbox.rs` (689 lines — the only netns in the repository), `rust/warrant/tests/sandbox.rs` (106 lines), `deploy/spire/trust-domain-config.yaml` (the only `NetworkPolicy` in the tree), and `tools/ci/wiring_census.py` (205 lines — the orphan gate this task must not regress).

Crate existence, verified rather than assumed:

```bash
git ls-tree --name-only refs/remotes/origin/main rust/ | grep -E 'egress|sandbox-runtime|containment'
```

```text
rust/egress-filter
rust/egress
rust/sandbox-runtime
rust/containment-conformance
```

All four crates this task names are on `origin/main`, so **no carry-in sequence is required** — unlike the thirteen crates Phases 3/5/6 name that are absent. `rust/guard` does not exist and is not named here.

Reachability, from the census that gates it:

```bash
python tools/ci/wiring_census.py
python -c "import json;d=json.load(open('evidence/wiring-coverage.json'));print(d['reachable'],'of',d['total']);print('egress-filter orphaned:', 'warrantor-egress-filter' in d['orphaned']);print('egress orphaned:', 'warrantor-egress' in d['orphaned'])"
```

```text
wiring census: 9 of 39 crates reachable from warrantor-warrant over 17 path edges
9 of 39
egress-filter orphaned: True
egress orphaned: False
```

The nine reachable crates, computed from the manifests: `warrantor-api`, `warrantor-authority-spec`, `warrantor-containment-conformance`, `warrantor-egress`, `warrantor-evidence`, `warrantor-notary`, `warrantor-spend`, `warrantor-trust-core`, `warrantor-warrant`. `warrantor-egress-filter` has **zero** reverse dependencies (`[k for k,v in dependency_graph().items() if 'warrantor-egress-filter' in v]` → `[]`) and **zero** forward path dependencies.

**Finding 1 — the double path does not exist today, and the seed's premise about where the second layer lives is wrong.** The seed's Step 0 says *"Read the sandbox profiles and any `deploy/k8s` manifests."* There is no `deploy/k8s`:

```bash
git ls-tree --name-only refs/remotes/origin/main deploy/
ls deploy/k8s; echo "exit=$?"
```

```text
deploy/evidence-archive
deploy/helm
deploy/local-sigstore
deploy/modal
deploy/muveraai-worker
deploy/spire
deploy/systemd
ls: cannot access 'deploy/k8s': No such file or directory
exit=2
```

There is exactly one `NetworkPolicy` in the entire repository and it cannot hold an egress bound at all:

```bash
grep -rn "kind: NetworkPolicy" --include=*.yaml --include=*.yml .
grep -rn "policyTypes" --include=*.yaml --include=*.yml .
```

```text
./deploy/spire/trust-domain-config.yaml:129:kind: NetworkPolicy
./deploy/spire/trust-domain-config.yaml:137:  policyTypes: ["Ingress"]
```

`policyTypes: ["Ingress"]` on a `podSelector` matching `app.kubernetes.io/name: trust-core` (lines 134-137). It restricts who may *reach* trust-core. It says nothing about what any workload may reach, and its own comment concedes the limit (line 124): *"NetworkPolicy itself is L3/4; SPIRE enforces the L7 trust."* The seed's "cluster infrastructure layer" is not present, so **`data-status="none"` is correct and this task may not close L2-03.** Its honest output is an analysis that says so, a machine-checked record of it, and a drill that starts failing the day the second layer arrives.

**Finding 2 — the two paths that do exist are mutually exclusive, driven by one config field.** This is worse than a shared dependency and it is the finding this task exists to publish.

Path A, the proxy chokepoint, is reachable and real. `rust/warrant/src/proxy.rs` lines 227-234, verbatim:

```rust
        for destination in crate::egress::destinations_of(call) {
            if let crate::egress::EgressVerdict::Deny { reason } =
                self.egress.decide(&destination.host)
            {
                let refusal = EgressRefusal::new(&call.tool, &destination, reason);
                return self.deny_egress(&call.tool, refusal);
            }
        }
```

The chokepoint decisions this task must record with line numbers, both from `rust/warrant/src/proxy.rs`:

```rust
// lines 119-120
const NEVER_IN_OBSERVE: [SideEffectClass; 2] =
    [SideEffectClass::Destructive, SideEffectClass::Financial];

// lines 236-243
        if self.bounds.staged_classes.contains(&call.side_effect)
            && self.registry.get(&call.tool).is_some()
        {
            // Staged: the agent gets a handle, and the effect happens at settle if it happens.
            return Decision::Stage {
                handle: String::new(),
            };
        }
```

`NEVER_IN_OBSERVE` is a two-element array checked at line 188 and it does **not** contain `SideEffectClass::Network` or anything egress-shaped: observe mode records every network call and refuses none. `staged_classes` is a set from the signed claims and is consulted *after* the egress loop, so staging cannot substitute for an egress refusal.

Path B, the network namespace, lives in `rust/warrant/src/sandbox.rs` lines 315-347. The condition is the whole finding:

```rust
    // ── network ───────────────────────────────────────────────────────────────────────
    //
    // The asymmetry this module exists to surface. A network namespace is all-or-nothing.
    if bounds.egress_hosts.is_empty() {
        match confinement {
            Confinement::Bubblewrap => argv.push("--unshare-net".to_string()),
            Confinement::Firejail => argv.push("--net=none".to_string()),
        }
```

and the `else` branch, lines 334-346, states the reason it is off in every other case: *"a network namespace has no host allowlist -- it is all or nothing. `--unshare-net` is therefore NOT in the command above: adding it would deny egress the warrant grants."*

Now read the same field on path A, `rust/warrant/src/egress.rs` lines 191-196:

```rust
        if bounds.egress_hosts.is_empty() {
            return Self {
                catalog: None,
                chain,
            };
        }
```

An empty catalog is `DenyReason::CatalogUnavailable` (`rust/egress/src/lib.rs` lines 173-180). So:

| `bounds.egress_hosts` | path A (proxy) | path B (netns) | independent intercepts on a permitted host |
|---|---|---|---|
| empty | denies everything as `CatalogUnavailable` | `--unshare-net` emitted | 2, but there is no permitted host to intercept |
| non-empty | decides per destination | **not emitted, deliberately** | **1** |

**The two paths are anti-correlated, not independent.** Exactly when path A has a non-trivial decision to make, path B is switched off; exactly when path B is on, path A has already denied everything. One field, `WarrantBounds::egress_hosts`, decides both, in opposite directions. There is no configuration in which a permitted destination is guarded twice. That is a common-mode failure of the strongest kind — a single point of *configuration*, not merely a single point of failure — and it is invisible in every current rendering, because `bound_strengths()` reports `("egress_hosts", BoundStrength::Mediated)` (`rust/warrant/src/lib.rs` line 677) without saying that the count of independent intercepts is one.

**Finding 3 — every shared dependency, named.** Required by the anchor's residual clause, which says a drill that skips this *"proves nothing"*:

- **Same process.** Path A is `Proxy::decide` in the `warrantor` binary. Path B is a `Vec<String>` of argv that the same binary *prints* (`cmd_sandbox`, `rust/warrant/src/bin/warrantor.rs` lines 3938-4011). Nothing launches it.
- **Same configuration struct, same field.** `WarrantBounds::egress_hosts`, as above. A shared config field IS a common mode, and this is not merely shared — it is inverted.
- **Same credential.** Neither path holds one. `rust/warrant/src/egress.rs` lines 48-51 state it: *"It does **not** sign egress receipts... the process that serves a supervised agent deliberately holds no key."* The catalog is unsigned by design (lines 28-31: *"the catalogue is unsigned, and `DestinationCatalog::signature` is left `None`"*). Zero shared credentials is the one axis on which the two are independent, and it is independent by absence, not by design.
- **Same DNS resolver — because neither resolves.** `rust/warrant/src/egress.rs` lines 44-47: *"It does **not** resolve DNS... A hostname that resolves *into* a metadata or private range is therefore not caught by the range check; only a literal address in the bound is."* Path B's netns removes the resolver entirely. So a hostname that resolves into `169.254.169.254` defeats path A's `METADATA_RANGES` check (`rust/egress/src/lib.rs` lines 131-135) and is only stopped by path B, which is off whenever any host is permitted. This is the concrete exploit the anti-correlation opens.
- **Same clock.** `bounds.expires_at` is copied into every `CatalogEntry` (`rust/warrant/src/egress.rs` line 210) and read by the supervisor for `expires_at`, the one `BoundStrength::Enforced` time bound (`rust/warrant/src/lib.rs` line 680). One clock, both layers.
- **Same telemetry path.** Both refusals land in `Proxy::egress_refusals` / `Proxy::requests` (`rust/warrant/src/proxy.rs` lines 109-112), in the same process, with no independent sink. Path B produces no telemetry at all: a netns refusal is a `connect()` failure inside the agent, which never reaches Warrantor.
- **Same operator flag.** One `--egress` argument at grant time sets the field that drives both.

Five of the anchor's four axes are shared. The blueprint's own residual on L0-10 (line 3077) names the ones this analysis must still concede: *"an unmodeled shared dependency such as a resolver, a clock or a certificate authority is still common-mode."* Two of those three are modeled here and shared.

**Finding 4 — path C is an orphan with no kernel behind it.** `rust/egress-filter/src/lib.rs` line 3 describes itself as *"eBPF egress enforcement core. The Rust core that the eBPF programs (task 03) consult on every outbound packet."* Those programs do not exist:

```bash
cat rust/egress-filter/Cargo.toml | sed -n '13,17p'
find . -iname "*.bpf.c" | grep -v target
grep -rn "aya\|libbpf" rust/*/Cargo.toml
```

```text
[dependencies]
thiserror.workspace = true
serde.workspace = true
serde_json = "1"
```

Three dependencies, no eBPF loader crate, no `.bpf.c`, and no reverse dependency. It is a pure decision function that is genuinely good — 26 tests pass, `DecisionReason::DefaultDeny` is the terminal branch at both lines 262 and 309, `Policy::decide_ip` checks canaries and private ranges *before* the allowlist so a break-glass entry cannot punch a hole to the metadata endpoint (lines 276-293) — and it is called by nothing.

```bash
cargo test -p warrantor-egress-filter -j 2 2>&1 | grep "^test result"
```

```text
test result: ok. 26 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

Baselines captured for the exit gate:

```bash
python tools/ci/check_invariant_ratchet.py
```

```text
invariant ratchet: ok (65 passing at floor 65, 19 recorded findings at ceiling 19)
```

```bash
cargo test -p warrantor-warrant --lib sandbox -j 2 2>&1 | tail -4
```

```text
test sandbox::tests::a_warrant_with_egress_does_not_get_a_network_namespace ... ok
test sandbox::tests::firejail_makes_the_same_two_decisions_as_bubblewrap ... ok

test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 124 filtered out; finished in 0.01s
```

`README.md` line 196 currently renders `**9 of 39**`, and `tools/ci/wiring_census.py::readme_renders` (lines 150-155) fails CI if that string stops matching the record. That assertion is the precedent this task copies for its own published number.

**Non-goals.** Each names the adjacent task that owns the excluded work, several of which are being expanded concurrently — do not specify their work here.

1. **The destination catalog's shape and contents are Task 1.2's** (in flight, GLM, branch `feat/egress-capability-catalog`). This task reads `EgressBroker::for_bounds` and asserts a property of it; it does not change how a warrant becomes a catalog, does not add signing to `DestinationCatalog::signature`, and does not add entries. Merge-order hazard: 1.2 edits `rust/warrant/src/egress.rs`, which this task also edits. Rebase on 1.2 and re-run the drills before merging; per [[merging parallel PRs safely]], verify against the *new* main, one at a time.
2. **Semantic egress purpose is Task 7.7's.** The independence question is "how many disjoint failure domains guard this destination", never "should this destination be reachable for this purpose". No purpose field, no intent classification, no `DESTINATION_KEYS` additions.
3. **Enumerating the transitive closure is Task 5.2's** (`warrantor prove-egress`). This task counts intercepts on a destination the closure prover hands it; it does not discover destinations, does not enumerate from inside a profile, and does not build a scanner. The drill uses a fixed destination.
4. **Do not build either isolation layer.** Phase 5's governing rule and Anti-goal 1. No netns is created, no seccomp filter is written, no firewall is configured, no eBPF program is compiled or attached. Task 5.6 owns write-bound promotion per kernel; the kernel-coverage caveat here is quoted from `rust/warrant/src/sandbox.rs`, not re-litigated.
5. **The orphan census's own logic is Task 0.3's** (landed). This task wires one crate and regenerates the record; it does not change `wiring_census.py`.

**Files.**

- Create `docs/05-network-common-mode-analysis.md` — the analysis document, four axes per layer, written before any code.
- Create `evidence/network-independence.json` — the machine-readable record: layers, axes, shared axes, and `independent_intercepts_on_a_permitted_host`.
- Create `tools/ci/network_independence.py` — computes the record from the manifests and sources, and gates every rendered copy of the number against it.
- Create `tools/ci/test_network_independence.py` — unit tests for the gate, following `tools/ci/test_wiring_census.py`.
- Create `rust/warrant/tests/network_independence.rs` — the two drills plus the allowed control.
- Modify `rust/warrant/src/egress.rs` — add the second policy engine as `SecondaryFilter`, config-sourced independently of the warrant claims. No change to `EgressBroker`.
- Modify `rust/warrant/src/proxy.rs` — consult the second engine inside the existing loop at lines 227-234. Deny-only: it can never turn a Deny into a Forward.
- Modify `rust/warrant/Cargo.toml` — add `warrantor-egress-filter` to `[dependencies]`.
- Modify `rust/Cargo.lock` — regenerated by `cargo metadata`, never by hand.
- Modify `rust/warrant/tests/invariants/i09_failure_is_safe.rs` — two tests, one finding-recording and one allowed control.
- Modify `tools/ci/invariant-ratchet.json` — `passing_floor` 65 → 67 in the same commit. `ignored_ceiling` stays 19.
- Modify `evidence/wiring-coverage.json` — regenerated: `reachable` 9 → 10, `warrantor-egress-filter` leaves `orphaned`.
- Modify `README.md` line 196 — `**9 of 39**` → `**10 of 39**`, and `the other 30` → `the other 29`.
- Modify `docs/W1-delivery-gaps.md` — new `### 3.7` under Tier 3, next to `### 3.1` (line 628), which already carries the netns sentence this task qualifies.
- Modify `.github/workflows/ci.yml` — one step in the `rust` job beside the census steps (lines 210-219).
- Create `docs/task-evidence/task-5.4.md` — the exit-gate evidence file, without which `scripts/task_status.py` reports this task UNEVIDENCED rather than DONE.

**Consumes / Produces.**

Consumes (all existing on `origin/main`, quoted with file and line):

- `pub fn profile(bounds: &WarrantBounds, worktree: &str, confinement: Confinement) -> Profile` — `rust/warrant/src/sandbox.rs` line 262.
- `pub enum Divergence { Held { bound: String, how: String }, Overreach { bound: String, why: String }, Gap { bound: String, why: String } }` — `rust/warrant/src/sandbox.rs` line 128; `pub fn held(&self) -> Vec<&Divergence>` line 403, `pub fn overreaches(&self) -> Vec<&Divergence>` line 394.
- `pub fn for_bounds(bounds: &WarrantBounds) -> Self` — `rust/warrant/src/egress.rs` line 185; `pub fn decide(&self, destination: &str) -> broker::EgressVerdict` line 229; `pub fn catalogued(&self) -> usize` line 255.
- `pub const ENFORCEMENT_NOTE: &str` — `rust/warrant/src/egress.rs` line 76.
- `pub fn decide(request: &EgressRequest, catalog: Option<&DestinationCatalog>) -> EgressVerdict` — `rust/egress/src/lib.rs` line 156; `pub enum DenyReason` line 25.
- `pub fn decide_destination(&self, destination: &str) -> Decision` — `rust/egress-filter/src/lib.rs` line 319; `pub fn try_new_default() -> Result<Self, ConfigError>` line 189; `pub struct PolicyBuilder` line 362 with `pub fn build(self) -> Result<Policy, ConfigError>` line 450; `pub fn is_private_or_local(ip: &IpAddr) -> bool` line 624.
- `pub fn refused_at_the_boundary<T, F>(what: &str, control: &T, attacked: &T, allowed: F)` — `rust/warrant/tests/invariants/harness.rs` line 50; `pub fn reached_the_boundary_unrefused<T, F>(...)` line 76; `pub fn source_contains(relative: &str, fragment: &str, why: &str)` line 96.
- `pub fn bound_strengths() -> Vec<(&'static str, BoundStrength)>` — `rust/warrant/src/lib.rs` line 668; `BoundStrength::caveat` line 229.
- `readme_renders(readme: Path, result: WiringCensus) -> bool` — `tools/ci/wiring_census.py` line 150. Not called by this task; copied as the pattern for gating a rendered number.

Produces:

- `pub struct SecondaryFilter` with `pub fn from_operator_config(path: &Path) -> Result<Self, SecondaryConfigError>`, `pub fn default_deny() -> Self`, and `pub fn decide(&self, destination: &str) -> warrantor_egress_filter::Decision` — new, `rust/warrant/src/egress.rs`.
- `pub fn independence(bounds: &WarrantBounds, secondary: Option<&SecondaryFilter>) -> Independence` returning `pub struct Independence { pub intercepts: usize, pub shared_axes: Vec<&'static str>, pub layers: Vec<&'static str> }` — new, `rust/warrant/src/egress.rs`. This is the function the record and the drills both read, so prose and test cannot diverge.
- `evidence/network-independence.json`, format string `warrantor.network-independence/1`.
- `tools/ci/network_independence.py` with `--write` and a default gating mode, exit 1 on any mismatch.

Nothing this task consumes is created by an unlanded task. Task 1.2 is in flight against the same file but is not a prerequisite: `EgressBroker::for_bounds` exists on `origin/main` today.

**Bound strength.**

**Tier B — chokepoint.** Both policy engines decide inside `Proxy::decide`, which sees only calls that traverse the Warrantor MCP proxy. Adding a second engine buys two disjoint *policy* domains (two evaluators, two config sources, two defaults) at **one** enforcement point. It buys nothing at the enforcement-point axis, and this task may not claim otherwise.

The single Tier A case is narrow and is not created here: `--unshare-net`, which the operating system enforces and an agent cannot route around — available only when `bounds.egress_hosts` is empty, and only if the operator actually launched the printed profile, which this process cannot observe (`PROFILE_CAVEAT`, `rust/warrant/src/sandbox.rs` lines 209-215). No netns, seccomp or firewall enforcement is added by this task; containment still composes with an external sandbox.

**What escapes Tier B, verbatim, and this is the sentence that ships in the product** — rendered under the independence count on the CLI, in `warrantor report`, and in every exported bundle:

> Two policy engines decide this destination and one boundary enforces them. The count above is a count of policy domains, not of enforcement points: both engines run inside the Warrantor MCP proxy, so a shell command, a harness built-in, or any socket the agent opens itself passes neither of them. There is no network namespace, seccomp filter or firewall behind this count unless you launched the confinement profile yourself, and this process cannot tell whether you did. A hostname that resolves into a private or metadata range is not caught: neither engine resolves DNS.

**Orphan count.** This task *lowers* the orphan count by one — `warrantor-egress-filter` moves from `orphaned` to reachable, `reachable` 9 → 10 — which is the permitted direction. No new crate is created and no orphan is added.

**No new trust root.** The second engine's configuration is a local file the operator writes, read by the same process, with `Policy::try_new_default()` as the fallback when it is absent. There is no registry, no fetch, and no signature. What that establishes: a corrupted or over-broad destination catalog does not silently widen egress, because a second evaluator with a different default and a different config source still refuses. What it does **not** establish: that the operator's file is authentic, that either engine ran, or that the agent used the proxy at all. Absence of the file is default-deny, not default-allow.

**Invariant conversion.** This task converts **no** recorded `#[ignore]`, and says so rather than inventing one. The two nearest are `rust/warrant/tests/invariants/i09_failure_is_safe.rs` line 196 — `#[ignore = "I-09 orphaned: eval-guard's fail-closed preflight is not linked by the warrantor binary (2026-09-02)"]`, which needs `warrantor-eval-guard` linked and is Task 0.3's census item — and `rust/warrant/tests/invariants/i12_safe_state_is_reachable.rs` line 167 — `#[ignore = "I-12 partial: the kill path is advisory, so it holds only against an agent using its tools (Task 1.3, 2026-09-02)"]`, which is Task 1.3's. `ignored_ceiling` therefore stays 19. What this task does add is two *passing* corpus tests, so `passing_floor` rises 65 → 67 in the same commit, and one of them is written with `harness::reached_the_boundary_unrefused` so that it begins to fail the day a real second enforcement point lands — a finding that retires itself instead of going stale. No assertion is weakened to earn either number.

**Exit gate.** `python tools/ci/network_independence.py && cargo test -p warrantor-warrant --test network_independence -j 2 && python tools/ci/check_invariant_ratchet.py && python tools/ci/wiring_census.py` exits 0, with the ratchet line reading `invariant ratchet: ok (67 passing at floor 67, 19 recorded findings at ceiling 19)` and the census line reading `wiring census: 10 of 39 crates reachable`; any rendered independence count that does not match `evidence/network-independence.json` fails the first command by name.

---

- [ ] **Step 1 — Worktree from `origin/main`, and re-confirm the four Step 0 findings on the branch itself.**

  ```bash
  export PATH="$PATH:/c/Users/MuVeraAICorporation/.cargo/bin"
  git -C "M:/Project AumOS - Open Secure AI Alliance/aumos" fetch origin
  git -C "M:/Project AumOS - Open Secure AI Alliance/aumos" worktree add M:/wt-task-5.4 -b feat/task-5.4-network-common-mode origin/main
  cd M:/wt-task-5.4
  export CARGO_TARGET_DIR=M:/wt-task-5.4-target
  ```

  Then re-run the three commands whose answers this whole task is built on, because a concurrent lane may have landed something since Step 0 (per [[concurrent session hazard]], a second session writes to this checkout):

  ```bash
  ls deploy/k8s; echo "k8s exit=$?"                                   # expected: exit=2, no such directory
  grep -c 'warrantor-egress-filter' rust/warrant/Cargo.toml || true   # expected: 0
  python tools/ci/wiring_census.py                                    # expected: 9 of 39 ... 17 path edges
  grep -n 'if bounds.egress_hosts.is_empty()' rust/warrant/src/sandbox.rs rust/warrant/src/egress.rs
  ```

  The last command must print exactly two hits, `rust/warrant/src/sandbox.rs:318` and `rust/warrant/src/egress.rs:191`. Those two lines are the anti-correlation; if either has moved, re-read both files before continuing, because every line number below is anchored to `e4b5f10`. If `deploy/k8s` now exists, another lane has added a cluster layer: stop and re-scope, because the analysis document's central claim would be stale on the day it lands.

  Test intent: none — this step establishes that the premises are still true.

- [ ] **Step 2 — Write the common-mode analysis as a document first, before any code.**

  `docs/05-network-common-mode-analysis.md`. For each layer, exactly four rows — enforcement point, credential, configuration source, telemetry path — because the anchor's residual makes those four the test. Two layers sharing any one of them are not independent. The document is prose, but every number in it is a number the Step 4 gate will check.

  It must contain the anti-correlation table from Step 0 verbatim, the seven shared dependencies with their file and line, and this sentence, which is the document's conclusion and must not be softened:

  ```markdown
  There is no configuration of this system in which a permitted destination is guarded by two
  independent controls. When `bounds.egress_hosts` is non-empty the network namespace is
  deliberately not emitted (`rust/warrant/src/sandbox.rs` lines 334-346); when it is empty the
  proxy denies every destination as `CatalogUnavailable` (`rust/warrant/src/egress.rs` lines
  191-196) and there is no permitted destination left to guard. The count of independent
  intercepts on a permitted host is therefore **one**, and L2-03 stays `status=none`.
  ```

  Every markdown link in the document must resolve, because `tools/ci/check_docs.py` validates local links fail-closed. Verify before moving on:

  ```bash
  python tools/ci/check_docs.py; echo "exit=$?"     # expected: exit=0
  ```

  Test intent: the document is the artifact L0-10's verification clause demands (*"For each catastrophic effect class an artifact lists at least two controls with disjoint failure domains"*). Here the artifact lists one, and says so.

- [ ] **Step 3 — Failing drill one: disable layer one, assert egress is still refused. It is not.**

  Create `rust/warrant/tests/network_independence.rs`. Drill one removes path A by handing the proxy a warrant whose catalog permits the destination, then asks what stands behind it. Written to fail on `origin/main` and to keep failing until Step 6 lands the second engine — which is the point of writing it first.

  ```rust
  //! Common-mode independence drills for the egress path (Task 5.4, L2-03 / L0-10).
  //!
  //! Each drill removes one layer and asks whether the destination is still refused. A drill that
  //! only ever refuses proves nothing, so every drill is paired with a control in which the same
  //! machinery ALLOWS the destination -- see `harness`-style pairing in the invariant corpus.

  use std::collections::BTreeSet;

  use warrantor_warrant::egress::{EgressBroker, Independence, SecondaryFilter};
  use warrantor_warrant::{sandbox, WarrantBounds};

  const PERMITTED: &str = "api.github.com";

  fn bounds(egress: &[&str]) -> WarrantBounds {
      WarrantBounds {
          tools: BTreeSet::new(),
          write_paths: BTreeSet::new(),
          egress_hosts: egress.iter().map(|s| (*s).to_string()).collect(),
          staged_classes: BTreeSet::new(),
          expires_at: 4_000_000_000,
          budget_cents_observed: None,
          delegation_depth: 0,
      }
  }

  #[test]
  fn drill_one_layer_a_removed_and_something_else_must_still_refuse() {
      let b = bounds(&[PERMITTED]);

      // Control: with layer A in place the broker ALLOWS the permitted host. Without this the
      // refusal below could be a refusal of everything, which measures nothing.
      let broker = EgressBroker::for_bounds(&b);
      assert!(
          matches!(
              broker.decide(PERMITTED),
              warrantor_warrant::egress::EgressVerdict::Allow { .. }
          ),
          "control: a permitted host must be allowed by layer A, or this drill is one-sided",
      );

      // Layer A removed. The only other layer in this repository is the network namespace, and it
      // is NOT emitted for a warrant that permits any host.
      let profile = sandbox::profile(&b, "/home/u/wt", sandbox::Confinement::Bubblewrap);
      let netns_present = profile.argv.iter().any(|a| a == "--unshare-net");
      assert!(
          !netns_present,
          "sandbox.rs lines 334-346 promise no netns for a permitted-egress warrant",
      );

      // The assertion this task must make pass. Refuses on origin/main.
      let filter = SecondaryFilter::default_deny();
      let second = filter.decide(PERMITTED);
      assert_eq!(
          second.action,
          warrantor_egress_filter::Action::Deny,
          "with layer A removed nothing refuses {PERMITTED}: the double path does not exist",
      );
  }
  ```

  Run it and record the failure verbatim in `docs/task-evidence/task-5.4.md` before fixing anything:

  ```bash
  cargo test -p warrantor-warrant --test network_independence -j 2
  ```

  Expected on `origin/main`: a compile error, not an assertion failure — `error[E0432]: unresolved import \`warrantor_warrant::egress::SecondaryFilter\`` plus `error[E0433]: failed to resolve: use of undeclared crate or module \`warrantor_egress_filter\``. That compile error *is* the finding: the second layer is not merely off, it is not addressable from the product's crate at all.

  Test intent: prove there is nothing behind path A. The control assertion is what makes the drill mean something.

- [ ] **Step 4 — Failing drill two: disable layer two, assert egress is still refused — and gate the count.**

  Drill two is the mirror and it *passes* on `origin/main`, which is the asymmetry worth publishing: removing path B changes nothing, because path B was already off.

  ```rust
  #[test]
  fn drill_two_layer_b_removed_and_layer_a_must_still_refuse() {
      // Layer B is already absent for any permitted-egress warrant, so "disabling" it is a no-op.
      // That is the finding: a drill that cannot change the outcome is a drill against a layer
      // that was never standing.
      let b = bounds(&[PERMITTED]);
      let broker = EgressBroker::for_bounds(&b);

      // Layer A alone still refuses a destination outside the bound -- the allowed control above
      // proves it is not refusing everything.
      assert_eq!(
          broker.decide("exfil.example.com"),
          warrantor_warrant::egress::EgressVerdict::Deny {
              reason: warrantor_warrant::egress::DenyReason::NotInCatalog
          },
      );

      // And the count is one, not two. This is the number the record and the product both render.
      let independence = warrantor_warrant::egress::independence(&b, None);
      assert_eq!(
          independence.intercepts, 1,
          "a permitted host is guarded once; L2-03 is status=none until this is 2",
      );
      assert!(
          independence.shared_axes.contains(&"configuration_source"),
          "one field drives both layers in opposite directions; that must be named, not implied",
      );
  }

  #[test]
  fn a_no_egress_warrant_is_the_only_two_layer_case_and_it_guards_nothing() {
      // The one configuration with two layers. Both refuse, and there is no permitted destination
      // for either of them to be independent about.
      let b = bounds(&[]);
      let profile = sandbox::profile(&b, "/home/u/wt", sandbox::Confinement::Bubblewrap);
      assert!(profile.argv.iter().any(|a| a == "--unshare-net"));
      assert_eq!(
          EgressBroker::for_bounds(&b).decide(PERMITTED),
          warrantor_warrant::egress::EgressVerdict::Deny {
              reason: warrantor_warrant::egress::DenyReason::CatalogUnavailable
          },
      );
      assert_eq!(warrantor_warrant::egress::independence(&b, None).intercepts, 2);
      assert_eq!(EgressBroker::for_bounds(&b).catalogued(), 0);
  }
  ```

  Then write `tools/ci/network_independence.py`, which computes the record from the sources rather than trusting the document, and refuses any rendered copy that disagrees with it. It follows `tools/ci/wiring_census.py::readme_renders` exactly, because that assertion has already refused a merge in this program over a stale README row:

  ```python
  RECORD_FORMAT = "warrantor.network-independence/1"
  RENDER_TARGETS = (
      ("docs/05-network-common-mode-analysis.md", "independent intercepts on a permitted host is therefore **{intercepts}**"),
      ("README.md", "| Independent network intercepts on a permitted destination | **{intercepts}**"),
      ("docs/W1-delivery-gaps.md", "one independent intercept, not {two_words}"),
  )

  def renders_agree(root: Path, record: dict) -> list[str]:
      """Every file that publishes the count must publish the recorded one."""
      wrong = []
      for relative, template in RENDER_TARGETS:
          expected = template.format(intercepts=record["independent_intercepts_on_a_permitted_host"],
                                     two_words="two")
          if expected not in (root / relative).read_text(encoding="utf-8"):
              wrong.append(f"{relative}: does not contain {expected!r}")
      return wrong
  ```

  ```bash
  python tools/ci/network_independence.py --write     # writes evidence/network-independence.json
  python tools/ci/network_independence.py; echo "exit=$?"
  python -m pytest tools/ci/test_network_independence.py -q -p no:cacheprovider
  ```

  Test intent: a number that appears in prose is tied to the file it came from, in three places. Deliberately test the negative too — `test_network_independence.py` must include a case that edits the README string in a temporary tree and asserts exit 1, or the gate is untested.

- [ ] **Step 5 — Two corpus tests in `i09_failure_is_safe.rs`, and raise the floor in the same commit.**

  The independence property belongs to I-09 — *"If any plane fails open, the action fails closed"* — because the anti-correlation is exactly the case where plane A failing open leaves nothing closed. Append to `rust/warrant/tests/invariants/i09_failure_is_safe.rs`, under the existing `-- adversarial --` divider:

  ```rust
  #[test]
  fn a_permitted_destination_is_guarded_once_and_the_second_layer_is_switched_off_by_the_same_field() {
      // FINDING, executable. The warrant field that opens the proxy's catalog is the same field
      // that suppresses the network namespace, so the two layers are anti-correlated rather than
      // independent. Written with `reached_the_boundary_unrefused` so that it starts FAILING the
      // day a real second enforcement point lands -- whoever lands it must convert this to
      // `refused_at_the_boundary` and raise the ratchet.
      let permitting = WarrantBounds {
          egress_hosts: BTreeSet::from(["api.github.com".to_string()]),
          ..bounds_with_budget(None)
      };
      let denying = bounds_with_budget(None);

      // Control: with no egress granted, the netns IS emitted -- so the absence below is caused by
      // the grant and by nothing else.
      let control = warrantor_warrant::sandbox::profile(
          &denying, "/home/u/wt", warrantor_warrant::sandbox::Confinement::Bubblewrap);
      let attacked = warrantor_warrant::sandbox::profile(
          &permitting, "/home/u/wt", warrantor_warrant::sandbox::Confinement::Bubblewrap);

      harness::reached_the_boundary_unrefused(
          "a warrant that permits one host, which switches the only second layer off",
          &control,
          &attacked,
          |profile| !profile.argv.iter().any(|a| a == "--unshare-net"),
      );
  }

  #[test]
  fn the_enforcement_note_refuses_to_imply_a_second_boundary() {
      // I-09's static half for this finding: the one sentence that states where egress is enforced
      // must keep naming the three things that are absent. A surface that drops this clause is how
      // a Tier B bound gets read as Tier A.
      harness::source_contains(
          "rust/warrant/src/egress.rs",
          "There is no network \\\n     namespace, seccomp filter or firewall",
          "ENFORCEMENT_NOTE is the only place the product says where egress holds; if it stops \
           naming what is absent, the independence count reads as an enforcement count.",
      );
  }
  ```

  Then, in the same commit, `tools/ci/invariant-ratchet.json`:

  ```json
  {
    "format": "warrantor.invariant-ratchet/1",
    "recorded": "2026-09-05",
    "source": "rust/warrant/tests/invariants/",
    "passing_floor": 67,
    "ignored_ceiling": 19
  }
  ```

  ```bash
  python tools/ci/check_invariant_ratchet.py --show-findings 2>&1 | tail -3
  ```

  Expected: `invariant ratchet: ok (67 passing at floor 67, 19 recorded findings at ceiling 19)`. If the passing count is 66 rather than 67, one of the two tests did not run — count, not reason, is what the ratchet reads, and per [[failure count is not failure reason]] a matching count from the wrong cause is how a half-done step looks finished. Confirm both names appear in the log with `... ok`.

  Test intent: make the finding executable and self-retiring, without weakening any assertion and without adding an `#[ignore]`.

- [ ] **Step 6 — Implement the layer the drills show is missing: a second policy engine, wired, honestly labeled.**

  The drills show that the missing thing is not a second enforcement *point* — building one would be a sandbox, which Phase 5's governing rule forbids. What is missing and buildable is a second *policy domain*: `warrantor-egress-filter` already exists, is tested, defaults to deny at both terminal branches, and checks canaries and private ranges before its own allowlist. Nothing links it. Wire it.

  ```toml
  # rust/warrant/Cargo.toml, [dependencies]
  warrantor-egress-filter = { path = "../egress-filter" }
  ```

  ```rust
  // rust/warrant/src/egress.rs -- new, after EgressBroker.
  //
  // A SECOND POLICY ENGINE AT THE SAME ENFORCEMENT POINT. Read that sentence before the code.
  // This lowers common mode on the policy-engine and configuration-source axes: a different
  // evaluator, a different default, a different config source. It does NOT add an enforcement
  // point. Both engines run inside the MCP proxy; a socket the agent opens itself passes neither.
  pub struct SecondaryFilter {
      policy: warrantor_egress_filter::Policy,
      source: SecondarySource,
  }

  impl SecondaryFilter {
      /// The operator's own file. Absent means default-deny, never default-allow.
      pub fn from_operator_config(path: &Path) -> Result<Self, SecondaryConfigError> { /* ... */ }

      /// The fallback: `Policy::try_new_default()`, whose terminal branch is `DefaultDeny`.
      #[must_use]
      pub fn default_deny() -> Self { /* ... */ }

      /// Deny-only by construction: this returns the filter's decision, and the caller may only
      /// use it to turn Forward into Deny. An `Allow` here can never overturn the broker.
      #[must_use]
      pub fn decide(&self, destination: &str) -> warrantor_egress_filter::Decision { /* ... */ }
  }
  ```

  The call site, replacing `rust/warrant/src/proxy.rs` lines 227-234. Order matters: the broker decides first so its structured `DenyReason` stays the reported reason, and the filter can only add a refusal.

  ```rust
          for destination in crate::egress::destinations_of(call) {
              if let crate::egress::EgressVerdict::Deny { reason } =
                  self.egress.decide(&destination.host)
              {
                  let refusal = EgressRefusal::new(&call.tool, &destination, reason);
                  return self.deny_egress(&call.tool, refusal);
              }
              // Second engine, second config source, same chokepoint. Deny-only: there is no
              // branch here that turns the broker's Deny into a Forward, and there must never be.
              if let Some(secondary) = self.secondary.as_ref() {
                  let decision = secondary.decide(&destination.host);
                  if decision.action == warrantor_egress_filter::Action::Deny {
                      return self.deny_secondary(&call.tool, &destination, decision);
                  }
              }
          }
  ```

  Then the census moves, and the README row must move with it or CI refuses the merge:

  ```bash
  cargo metadata --format-version 1 > /dev/null      # regenerate the lock; never hand-edit
  python tools/ci/wiring_census.py                   # expect the ::notice:: that 10 exceeds floor 9
  python tools/ci/wiring_census.py --write
  python tools/ci/wiring_census.py                   # expect exit 0 after README.md line 196 is edited
  ```

  Expected sequence: first run prints `wiring census: 10 of 39 crates reachable from warrantor-warrant over 18 path edges` and a `::notice::` telling you to `--write`; then, until `README.md` line 196 reads `**10 of 39**` and `the other 29`, it prints `::error::README status table does not show 'reachable from the CLI | **10 of 39**'` and exits 1.

  Test intent: one crate leaves the orphan list. Both counts — 10 of 39, and 18 path edges — are gated against their records.

- [ ] **Step 7 — Assert the four independence properties as tests, not as prose, with the allowed control on each.**

  One test per axis from the anchor's residual clause. Each asserts the *current, honest* answer, so the suite is a measuring instrument and not a wish.

  ```rust
  #[test]
  fn the_four_axes_are_asserted_not_described() {
      let permitting = bounds(&[PERMITTED]);
      let filter = SecondaryFilter::default_deny();
      let with_second = warrantor_warrant::egress::independence(&permitting, Some(&filter));

      // 1. POLICY ENGINE -- now disjoint. Two evaluators, and this is the axis this task fixed.
      assert!(!with_second.shared_axes.contains(&"policy_engine"));
      // 2. CONFIGURATION SOURCE -- now disjoint for the pair of ENGINES, and still shared for the
      //    pair of LAYERS, because one warrant field drives the proxy and the netns both.
      assert!(with_second.shared_axes.contains(&"configuration_source"));
      // 3. CREDENTIAL -- neither holds one. Independent by absence; say so, do not claim design.
      assert!(!with_second.shared_axes.contains(&"credential"));
      // 4. TELEMETRY PATH -- shared. Both refusals land in the same in-process maps.
      assert!(with_second.shared_axes.contains(&"telemetry_path"));

      // ENFORCEMENT POINT -- shared, and unchanged by this task. The fifth axis, added because the
      // blueprint's four do not include it and it is the one a reader assumes.
      assert!(with_second.shared_axes.contains(&"enforcement_point"));

      // And the control, so none of the above is an artifact of a struct that shares everything:
      // with no second engine, `policy_engine` IS shared.
      let alone = warrantor_warrant::egress::independence(&permitting, None);
      assert!(alone.shared_axes.contains(&"policy_engine"));
      assert_eq!(alone.intercepts, 1);
      assert_eq!(with_second.intercepts, 1, "two engines, one enforcement point: still one");
  }
  ```

  Note the last assertion. Wiring a second engine does **not** raise `intercepts`, because `intercepts` counts enforcement points and this task added none. If a later change makes that number 2, the Step 4 gate will fail every rendered copy until each is updated deliberately.

  Test intent: the residual clause becomes four assertions plus a fifth the blueprint omitted, each paired with a control.

- [ ] **Step 8 — The two refusal tests get their allowed controls, and the deny-only property gets a test that tries to break it.**

  A verifier that refuses everything passes a one-sided test. Three pairs:

  ```rust
  #[test]
  fn the_second_engine_allows_what_the_operator_permitted() {
      // The allowed control for every refusal above. Without this, `SecondaryFilter` could be a
      // function that returns Deny unconditionally and the whole suite would still be green.
      let filter = SecondaryFilter::from_policy(
          warrantor_egress_filter::PolicyBuilder::with_defaults()
              .allow_domain(PERMITTED)
              .build()
              .expect("the operator policy builds"),
      );
      assert_eq!(filter.decide(PERMITTED).action, warrantor_egress_filter::Action::Allow);
      assert_eq!(filter.decide("exfil.example.com").action, warrantor_egress_filter::Action::Deny);
      // And the pair that matters most: an allowlist entry must not punch a hole to metadata.
      assert_eq!(
          SecondaryFilter::from_policy(
              warrantor_egress_filter::PolicyBuilder::with_defaults()
                  .allow_ip("169.254.169.254")
                  .build()
                  .expect("builds"),
          )
          .decide("169.254.169.254")
          .action,
          warrantor_egress_filter::Action::Deny,
          "egress-filter checks canaries before its allowlist (lines 276-293); that must survive wiring",
      );
  }

  #[test]
  fn the_second_engine_can_never_overturn_the_broker() {
      // The dangerous direction. An operator file that allows a host the WARRANT does not name
      // must still be refused, or the second engine is a widening mechanism rather than a
      // narrowing one -- and a warrant field the operator can override is not a bound.
      let narrow = bounds(&[PERMITTED]);
      let generous = SecondaryFilter::from_policy(
          warrantor_egress_filter::PolicyBuilder::with_defaults()
              .allow_domain("exfil.example.com")
              .build()
              .expect("builds"),
      );
      let mut proxy = proxy_over(&narrow, Some(generous));
      let decision = proxy.decide(&call_to("exfil.example.com"));
      assert!(
          matches!(decision, warrantor_warrant::proxy::Decision::Deny { bound: "egress_hosts", .. }),
          "the broker refused first and the filter must not be able to un-refuse it: {decision:?}",
      );
  }
  ```

  ```bash
  cargo test -p warrantor-warrant --test network_independence -j 2 2>&1 | grep "^test result"
  ```

  Test intent: prove the suite can say yes, and prove the second engine narrows and never widens.

- [ ] **Step 9 — Publish the sentence, and gate it where it is rendered.**

  The Bound-strength paragraph above ships. Put it in one place and have every surface read it, the way `ENFORCEMENT_NOTE` already works (`rust/warrant/src/egress.rs` line 76) — a second copy is a second thing that can drift.

  ```rust
  /// What the independence count does NOT cover. Printed under the count on every surface.
  ///
  /// One constant, one place, for the same reason as [`ENFORCEMENT_NOTE`]: a count of policy
  /// domains rendered without this paragraph is read as a count of enforcement points, which is
  /// the single most damaging misreading this repository can ship.
  pub const INDEPENDENCE_NOTE: &str =
      "Two policy engines decide this destination and one boundary enforces them. The count above \
       is a count of policy domains, not of enforcement points: both engines run inside the \
       Warrantor MCP proxy, so a shell command, a harness built-in, or any socket the agent opens \
       itself passes neither of them. There is no network namespace, seccomp filter or firewall \
       behind this count unless you launched the confinement profile yourself, and this process \
       cannot tell whether you did. A hostname that resolves into a private or metadata range is \
       not caught: neither engine resolves DNS.";
  ```

  ```rust
  #[test]
  fn every_surface_that_prints_the_count_also_prints_what_it_does_not_cover() {
      for surface in [
          "rust/warrant/src/bin/warrantor.rs",
          "docs/05-network-common-mode-analysis.md",
      ] {
          let text = read_repository_file(surface);
          assert!(
              !text.contains("independent intercept") || text.contains("not a count of enforcement points")
                  || text.contains("INDEPENDENCE_NOTE"),
              "{surface} publishes the count without the clause that bounds it",
          );
      }
  }
  ```

  Test intent: no claim without a mechanism, in prose or in a generated file. A surface may print the count only alongside what the count excludes.

- [ ] **Step 10 — Record the finding in the gaps document and wire the gate into CI.**

  `docs/W1-delivery-gaps.md`, new `### 3.7` immediately after `### 3.6` (line 800), inside Tier 3 where `### 3.1` (line 628) already carries the netns sentence this qualifies. It must name the anti-correlation and must contain the string the Step 4 gate looks for — `one independent intercept, not two`. `### 3.1` gets one added cross-reference sentence and is otherwise untouched: it is Task 5.6's territory.

  `.github/workflows/ci.yml`, in the `rust` job beside the census steps (after line 219), guarded the same way and for the same reason:

  ```yaml
      - name: Test the network-independence gate
        if: runner.os == 'Linux'
        run: python -m pytest ../tools/ci/test_network_independence.py -q -p no:cacheprovider
      # Fails when a rendered independence count disagrees with evidence/network-independence.json.
      # Same shape as the wiring ratchet above: the number lives in one file and every prose copy
      # is checked against it.
      - name: Assert every rendered independence count matches its record
        if: runner.os == 'Linux'
        run: python ../tools/ci/network_independence.py
  ```

  Test intent: the analysis cannot silently go stale. Add the step to the `required` job's `needs` only if a new job is created — this adds steps to an existing job, so `needs` is unchanged; confirm rather than assume:

  ```bash
  git diff .github/workflows/ci.yml | grep -c '^+' ; sed -n '489,510p' .github/workflows/ci.yml
  ```

- [ ] **Step 11 — Full gate for every language touched, evidence file, then commit.**

  Rust and Python were both touched, so both gates run. Per [[repo CI conventions]], run the gate for every language you touched, not only the one you think matters.

  ```bash
  cd M:/wt-task-5.4/rust
  cargo metadata --format-version 1 --locked > /dev/null
  cargo fmt --all -- --check
  cargo clippy --all-targets -j 2 -- -D warnings
  cargo test --workspace --all-targets -j 2 2>&1 | grep -E "^test result|error" | tail -20
  cd M:/wt-task-5.4
  python tools/ci/network_independence.py
  python tools/ci/wiring_census.py
  python tools/ci/check_invariant_ratchet.py --show-findings 2>&1 | tail -3
  python tools/ci/check_docs.py
  python -m pytest tools/ci/test_network_independence.py tools/ci/test_wiring_census.py -q -p no:cacheprovider
  node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" docs/05-network-common-mode-analysis.md docs/task-evidence/task-5.4.md
  ```

  Expected, and each of these is a number a reviewer can check:

  ```text
  wiring census: 10 of 39 crates reachable from warrantor-warrant over 18 path edges
  invariant ratchet: ok (67 passing at floor 67, 19 recorded findings at ceiling 19)
  network independence: 1 independent intercept on a permitted destination; 3 shared axes of 5
  ```

  Write `docs/task-evidence/task-5.4.md` with the verbatim output of every command above, the Step 3 compile error as it was first seen, and the one sentence that is this task's real result: **L2-03 remains `status=none`; what changed is that its absence is now measured, published, and gated, and one previously orphaned crate is wired as a second policy domain behind the same single enforcement point.** Then:

  ```bash
  git add -A && git commit -s
  ```

  Read the roadmap before writing any summary of this task: per [[do not declare done without the roadmap]], the exit gate here is four green commands and one honest status label, not a closed catalog item.

  **Hazards.** Verified on one kernel is not verified on every kernel — `rust/warrant/src/sandbox.rs` lines 68-72 already say WSL2's 6.18 *"is not a hardened distro kernel with `unprivileged_userns_clone` disabled, where `bwrap` will refuse to start at all"* — and that limitation must not be overstated when this task lands. The second hazard is the opposite of understating: a reviewer reading "two policy engines" as "two boundaries" is the exact failure mode `BoundStrength` exists to prevent, which is why `INDEPENDENCE_NOTE` is asserted onto every surface in Step 9 rather than left to a footnote. The third is the merge order: Task 1.2 is editing `rust/warrant/src/egress.rs` right now.
