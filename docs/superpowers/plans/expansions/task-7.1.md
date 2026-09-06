### Task 7.1: Effect-class SDK, conformance kit, and the non-amendable deny floor (L4-20, L4-25)

**Anchor.**

L4-20 is `data-status="none"`, `data-novelty="core"`, `data-wave="W3"`, `data-plane="B"`,
`data-loop="L3"` in `docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html:3829`. Its
`what` reads verbatim: *"Lets a third party write an adapter that inherits every guarantee, with a
conformance test proving it decomposes correctly onto the syscall table and never touches a
credential."* Its `verify` reads verbatim: *"An independently written adapter passes the kit; a
deliberately broken one (credential in agent scope, unclassified effect) fails per vector; an unknown
upstream version downgrades the coverage claim rather than inheriting it (L11-05)."* Status is
`none`: nothing in this repository is an adapter SDK today, and nothing runs a conformance vector.

L4-25 is `data-status="none"`, `data-novelty="compose"`, `data-wave="W1"` — the wave everything else
sits on — `data-plane="D"`, `data-loop="lin"`, at line 3889, tagged `PROPOSED · added`. Its `what`
reads verbatim: *"The cloud metadata service (the link-local address a virtual machine asks for its
own credentials), privileged pods, host mounts, broad service accounts and unrestricted cluster APIs
are denied to agent workloads at the network and admission-controller tier, in a layer no warrant,
policy edit or agent action can amend. This is deliberately not a policy: it is infrastructure,
composed from existing network-policy and admission projects rather than built. … Guarantee class:
OS-bound."* Its `verify` reads verbatim: *"From inside a workload with a deliberately over-broad
warrant, every metadata and link-local request fails at the network tier and every privileged-pod
request fails at admission; the common-mode analysis shows the deny and the policy engine share no
failure domain."*

Do not soften `status=none` on either. Neither number moves because code that looks adjacent
already exists; both move only when the named verification runs.

This task is first in Phase 7 because eight adapter tasks transcribe its contract. Per the Phase 7
scope entry, seeding an adapter before the kit exists produces nine separately-invented
decompositions, which is the defect Task 2.1 is routed to Opus to prevent one layer down. The scope
document states the phase's failure mode as *"breadth read as capability"* and this task's anchor as
*"the floor no agent-amendable policy may reach."*

---

**PREMISE CONTRADICTED. The seed's finding (a) names the wrong mechanism, and the mechanism it names
does not open the metadata endpoint at all.**

The seed says the control is `Policy.deny_private_egress` and that `deny_private_egress(false)` is
the amendable path to `169.254.169.254`. Verified against `refs/remotes/origin/main` by compiling and
running the code: **it is not.** `Policy::decide_ip` evaluates the canary list *before* the private
check, and `169.254.169.254` is a compiled-in default canary, so under `PolicyBuilder::with_defaults()`
the flag is irrelevant — the repository's own test at `rust/egress-filter/src/lib.rs:1027-1043`
already asserts exactly that (*"Even then, canaries stay blocked."*). A step written against the
seed's premise would pass under `with_defaults()`, fail under `new()`, and be diagnosed as the wrong
bug. Line numbers are also off by one to three. What is actually true is worse than the seed, and is
recorded in Findings 1 and 2 below.

The seed's finding (b) is **confirmed in substance and wrong in one number**: `warrantor-egress-filter`
is on the orphan list, but the list holds **30** crates, not 29.

The seed's third structural assumption — that the SDK is *"a new `rust/effect-sdk/` crate"* — is
**contradicted by the census topology**. See Finding 4.

---

**Step 0.** Run every command below and paste the real output into `docs/task-evidence/task-7.1.md`
before writing a line of code. Captured on `refs/remotes/origin/main` at `e4b5f10` on 2026-09-05;
if your capture differs, yours is the truth and this section is stale.

```bash
export PATH="$PATH:/c/Users/MuVeraAICorporation/.cargo/bin"
cd "M:/Project AumOS - Open Secure AI Alliance/aumos"

# 1. Which crates exist. A task that assumes an absent crate dies at its first cargo call.
git ls-tree --name-only -d refs/remotes/origin/main rust/ | wc -l
git ls-tree --name-only refs/remotes/origin/main rust/ | grep -E 'egress|authority-spec|warrant$'

# 2. File sizes, so "read in full" is checkable.
git show refs/remotes/origin/main:rust/egress-filter/src/lib.rs | wc -l
git show refs/remotes/origin/main:rust/egress/src/lib.rs        | wc -l
git show refs/remotes/origin/main:rust/authority-spec/src/lib.rs | wc -l
git show refs/remotes/origin/main:rust/warrant/src/egress.rs     | wc -l

# 3. The census, which is this task's exit gate.
python tools/ci/wiring_census.py
python - <<'PY'
import json; d=json.load(open('evidence/wiring-coverage.json'))
print(d['reachable'],'of',d['total'],'| edges',d['edges'],'| orphans',len(d['orphaned']))
print('egress-filter orphaned:', 'warrantor-egress-filter' in d['orphaned'])
print('egress        orphaned:', 'warrantor-egress' in d['orphaned'])
PY

# 4. The two crates' current test counts, so a regression is visible.
cd rust && cargo test -p warrantor-egress-filter 2>&1 | grep 'test result'
cargo test -p warrantor-egress 2>&1 | grep 'test result'

# 5. The invariant ratchet baseline. It fails on IMPROVEMENT too — read the script's docstring.
cd .. && cat tools/ci/invariant-ratchet.json
grep -n '#\[ignore' rust/warrant/tests/invariants/i11_self_change_is_governed.rs
```

Real output, verbatim:

```
39
rust/authority-spec
rust/egress
rust/egress-filter
rust/warrant
1102
618
510
499
wiring census: 9 of 39 crates reachable from warrantor-warrant over 17 path edges
9 of 39 | edges 17 | orphans 30
egress-filter orphaned: True
egress        orphaned: False
test result: ok. 26 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
{
  "format": "warrantor.invariant-ratchet/1",
  "recorded": "2026-09-02",
  "source": "rust/warrant/tests/invariants/",
  "passing_floor": 65,
  "ignored_ceiling": 19,
  "note": "The invariant attack corpus for I-01..I-12. `passing_floor` may only rise; `ignored_ceiling` may only fall. ..."
}
97:#[ignore = "I-11 unimplemented at the broker: three DenyReason variants are rendered and never constructed (Task 2.5, 2026-09-02)"]
```

Every crate this task touches is **present on `origin/main`**: `rust/egress-filter`, `rust/egress`,
`rust/authority-spec`, `rust/warrant`. **No carry-in sequence is required** — unlike the thirteen
crates Phases 3, 5 and 6 name, none of which this task reaches.

Read in full, no skimming:

- `rust/egress-filter/src/lib.rs` — **1102 lines**, all of it, tests included. The 26 tests are the
  specification of what AX-05 already fixed and what it did not.
- `rust/egress/src/lib.rs` — **618 lines**. This is the crate that is already reachable, so this is
  where the floor has to land.
- `rust/warrant/src/egress.rs` — **499 lines**, added to the seed's list because it is the only
  caller of `warrantor_egress::decide` and therefore the actual shipping path.
- `rust/authority-spec/src/lib.rs` lines **31–125** (the seed says 38–110; `SideEffectClass` opens at
  40 and `ValidateOptions` closes at 125, so the wider window is the honest one).
- `rust/warrant/src/proxy.rs` lines **220–245** and **305–311** — the chokepoint and `host_of`.
- `evidence/wiring-coverage.json`, `tools/ci/wiring_census.py` (206 lines),
  `tools/ci/check_invariant_ratchet.py`, `tools/ci/invariant-ratchet.json`.
- `rust/warrant/tests/invariants/i11_self_change_is_governed.rs` lines **73–130**.
- Task 2.1's section in this plan, in full, for the `Syscall`/`DecompositionRegistry` surface this
  SDK compiles against.
- `README.md` line **196** — the census gate reads it. See Finding 5.

---

**Finding 1 (verified, and worse than the seed). The metadata deny in the crate nobody links is
amendable four ways, and the boolean is the weakest of the four.**

The addresses and the classifier are where the seed says. `rust/egress-filter/src/lib.rs:59-64`:

```rust
pub const DEFAULT_CANARY_IPS: &[&str] = &[
    "127.0.0.1", // loopback (used by exfil proxies); deny by default for non-loopback paths
    "169.254.169.254", // cloud metadata endpoint (AWS/GCP/Azure IMDS)
    "100.100.100.200", // Alibaba cloud metadata
    "fd00:a405::1", // warrantor-internal canary (ULA; was the invalid literal "fd00:aumos::1")
];
```

Link-local classification is at `:615-640`, with the `fe80::/10` mask on line 639:
`(first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80`.

The control the seed names is at `:150-161` — note the field is line **160**, not 159; line 159 is
the serde attribute:

```rust
    /// IP literals that are allowed. Under default-deny this is the only way a bare IP reaches
    /// the network.
    #[serde(default)]
    pub allowlisted_ips: Vec<IpAddr>,
    /// Canary IP literals that are always denied.
    pub canary_ips: Vec<IpAddr>,
    /// True iff RFC-1918 / link-local / loopback egress should be denied.
    ///
    /// **AX-05**: defaults to `true`, and a serialized policy that omits the field also gets
    /// `true` — an older config cannot silently re-enable private egress (SSRF to the cloud
    /// metadata endpoint is the canonical exploit of the old `false` default).
    #[serde(default = "default_true")]
    pub deny_private_egress: bool,
```

The builder's doc comment, quoted verbatim from `:435-436` (the function itself opens at **438**, not
436):

```rust
    /// Toggle the deny-private-egress flag. Defaults to `true`; passing `false` is an explicit,
    /// auditable decision to permit egress to RFC-1918 / loopback / link-local addresses.
    #[must_use]
    pub fn deny_private_egress(mut self, deny: bool) -> Self {
```

But the ordering inside `decide_ip` (`:273-313`) is what decides the outcome, and it puts the canary
list first:

```rust
    pub fn decide_ip(&self, ip: IpAddr) -> Decision {
        let norm = normalize_ip(ip);
        let normalized = norm.to_string();
        // Canary and private checks come FIRST: an allowlist entry must not be able to punch a
        // hole to the metadata endpoint.
        if self.canary_ips.iter().any(|c| normalize_ip(*c) == norm) {
            return Decision { action: Action::Deny, reason: DecisionReason::CanaryIp, /* … */ };
        }
        if self.deny_private_egress && is_private_or_local(&norm) {
            return Decision { action: Action::Deny, reason: DecisionReason::PrivateIp, /* … */ };
        }
```

So the amendable surface is `canary_ips`, not `deny_private_egress`. Verified empirically — a probe
compiled against `refs/remotes/origin/main` and run with `cargo test -p warrantor-egress-filter`,
output verbatim:

```
WITH_DEFAULTS + false + allow_ip -> Deny / CanaryIp      <-- the seed's claimed hole: NOT a hole
NEW + false + allow_ip           -> Allow / Allowlisted
NEW decide_destination           -> Allow / Allowlisted
SERDE adversarial                -> Allow / Allowlisted
SERDE alibaba (100.100.100.200)  -> Allow
SERDE fe80::1                    -> Allow
STRUCT LITERAL                   -> Allow
CONTROL 8.8.8.8                  -> Allow                <-- the allowed control; not one-sided
```

Four independent amendable paths, none of which the boolean alone opens:

1. `PolicyBuilder::new()` (`:394`) sets `use_defaults: false` (`:386`), so `canary_ips` builds
   **empty** and no metadata address is known.
2. `canary_ips` (`:153`) carries **no** `#[serde(default)]`, so a supplied config states the whole
   list — `[]` is accepted.
3. Every `Policy` field is `pub`, so a struct literal bypasses `PolicyBuilder` entirely.
4. `deny_private_egress(false)` — the only one the seed names, and the one that matters least.

The adversarial config that reaches the metadata service, verbatim:

```json
{"blocked_domains":[],"allowlisted_domains":[],"canary_ips":[],
 "allowlisted_ips":["169.254.169.254"],"deny_private_egress":false}
```

**Finding 2 (verified, and the one that actually matters). The crate that IS reachable already has a
metadata deny with no configuration argument — and its matcher is a string prefix, bypassable seven
ways, with a private-range branch that is dead code.**

`rust/egress/src/lib.rs:130-142`:

```rust
/// Metadata ranges that are ALWAYS denied and NEVER catalog-addable (spec §3).
const METADATA_RANGES: &[&str] = &[
    "169.254.", // AWS/GCP/Azure metadata, link-local
    "fd00:",    // IPv6 ULA (private)
    "fe80:",    // IPv6 link-local
];

/// Private ranges denied unless explicitly catalogued (spec §3).
const PRIVATE_RANGES: &[&str] = &[
    "10.", "172.16.", /* … */ "192.168.", "127.", "0.", "::1",
];
```

`:205-218` — the metadata branch returns; the private branch is a comment:

```rust
    for addr in &entry.addresses {
        if is_metadata_range(addr) {
            return EgressVerdict::Deny { reason: DenyReason::MetadataRange };
        }
        if is_private_range(addr) {
            // Private ranges are allowed ONLY if explicitly in the catalog — which it is, since we
            // got here from the catalog. But spec §3 says "Denied unless explicitly catalogued."
            // Since the address IS in a catalog entry, it's explicitly catalogued → allow.
            // However, metadata ranges are NEVER catalog-addable (checked above).
        }
    }
```

`grep -n 'reason: DenyReason::PrivateRange' rust/egress/src/lib.rs` returns **nothing**.
`DenyReason::PrivateRange` is declared at `:35`, rendered as prose at
`rust/warrant/src/egress.rs:454` (*"it is a private-range address this warrant does not name"*) and
as a wire word at `:473`, and **constructed nowhere**. It is a fourth never-constructed variant,
and the I-11 corpus test does not know about it — see Step 10.

The matcher is `addr.starts_with(prefix)` on a `String` (`:230-235`). Probe compiled against
`refs/remotes/origin/main` and run with `cargo test -p warrantor-egress`; each row is one catalog
entry whose sole address is the string shown, decided by `warrantor_egress::decide`. Output verbatim:

```
             169.254.169.254  ->  DENY/MetadataRange
      ::ffff:169.254.169.254  ->  ALLOW
             100.100.100.200  ->  ALLOW
                  2852039166  ->  ALLOW
         0251.0376.0251.0376  ->  ALLOW
                  0xa9fea9fe  ->  ALLOW
    metadata.google.internal  ->  ALLOW
      169.254.169.254.nip.io  ->  DENY/MetadataRange
             169.254.169.254  ->  ALLOW      (one leading space)
                    10.0.0.1  ->  ALLOW
                   127.0.0.1  ->  ALLOW
                 203.0.113.9  ->  ALLOW      (the allowed control)
```

Read that carefully. The dotted-quad form is denied. The IPv4-mapped IPv6 form, the Alibaba address
the *other* crate already knows, the decimal, octal and hexadecimal spellings of the same 32-bit
integer, the well-known hostname, and the dotted-quad with **one leading space** all reach `Allow`.
`169.254.169.254.nip.io` — a name that is not the metadata service — is denied, so the matcher is
over-inclusive as well as under-inclusive. And `10.0.0.1` and `127.0.0.1` are allowed because the
private branch returns nothing.

These are reachable through the shipping path, not synthetic. `EgressBroker::for_bounds`
(`rust/warrant/src/egress.rs:185-224`) builds each catalog entry as
`addresses: vec![host.clone()]` — the literal string from the warrant's `egress_hosts`. The proxy
calls it at `rust/warrant/src/proxy.rs:227-234`, and `host_of` (`:305-311`) does no normalization
beyond stripping scheme, path, credentials and port. A warrant granting `--egress 2852039166` and a
tool call to `http://2852039166/latest/meta-data/` therefore yields host `2852039166`, an exact
catalog match, and `Allow`. Which of the seven spellings survive `host_of` intact is a separate
question the task must assert per spelling rather than assume — `host_of`'s `split_once(':')`
mangles bare IPv6 literals, so the IPv6 rows need the bracketed form or they prove nothing.

**The shape of the work, therefore, is not what the seed says.** `warrantor-egress` has the right
architecture — a `const`, checked unconditionally, no configuration argument, which is most of what
L4-25 asks for — and the wrong matcher. `warrantor-egress-filter` has the right matcher (`normalize_ip`
unwraps mapped forms, `is_private_or_local` is typed on `IpAddr`, and it knows the Alibaba address)
and the wrong architecture, and nothing links it. The task is to put a typed matcher with no
configuration argument into the crate that already ships, reusing the classifier from the crate that
does not.

**Finding 3 (vocabulary mismatch, both lists quoted). Five variants against nine syscalls.**

`rust/authority-spec/src/lib.rs:40-53`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SideEffectClass {
    /// Read-only access.
    Read,
    /// Mutating but non-financial.
    Write,
    /// Spends or moves money.
    Financial,
    /// Destroys data or resources.
    Destructive,
    /// Actuates physical systems.
    Physical,
}
```

Five, at lines 44, 46, 48, 50, 52, with `is_consequential` at `:55-63` selecting
`Financial | Destructive | Physical`.

The blueprint's table has nine.
`docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html:2478`, verbatim:

```
effect syscalls: NET CRED EXEC MUTATE MSG SPEND DELEGATE ACTUATE ATTEST
```

and line 2561 states, verbatim: *"The canonical table has nine entries."* The conformance kit asserts
a decomposition onto **the nine**, which Task 2.1 introduces as
`warrantor_warrant::effects::Syscall` with `pub const ALL: [Self; 9]`. **If Task 2.1 has not landed,
this task cannot assert conformance against anything and must stop at Step 6** — Steps 1 to 5 (the
deny floor) do not depend on it and may land alone.

**Finding 4 (structural, and it changes the Files list). A separate `rust/effect-sdk/` crate cannot
be wired, by construction.**

Task 2.1 places `Syscall` and `DecompositionRegistry` in `rust/warrant/src/effects.rs` — inside
`warrantor-warrant`, the binary crate the census walks *from*. A new `rust/effect-sdk/` crate that
consumes `Syscall` must depend on `warrantor-warrant`, and `warrantor-warrant` cannot then depend on
it without a cycle. The census counts reachability **from** `warrantor-warrant`
(`tools/ci/wiring_census.py:106-119`), so such a crate is an orphan by construction and raises
`total` from 39 to 40 and the orphan count from 30 to 31. **Rule: the orphan count may not rise.**

The SDK therefore ships as `rust/warrant/src/effect_sdk.rs`, a module of the already-reachable
binary crate. `total` stays 39 and no orphan is added.

**Finding 5 (a gate the seed's Files list omits). The census also reads `README.md`.**

`tools/ci/wiring_census.py:150-154` asserts the README status table renders the current number, and
`main` returns 1 when it does not. Verified by making the wiring edge in a scratch worktree:

```
$ python tools/ci/wiring_census.py
wiring census: 10 of 39 crates reachable from warrantor-warrant over 18 path edges
::notice::wiring ratchet: 10 reachable exceeds the floor of 9; run `python tools/ci/wiring_census.py --write` and commit .../evidence/wiring-coverage.json
::error::README status table does not show 'reachable from the CLI | **10 of 39**'
```

`README.md:196` currently reads `| Capabilities reachable from the CLI | **9 of 39** Rust workspace
crates link into the `warrantor` binary; the other 30 compile and pass their tests but nothing a
user runs calls them …`. Both the number **and** the "other 30" clause must change to 29 in the same
commit, or CI fails on a prose mismatch after the code is correct.

The wiring edge itself is verified cheap. `warrantor-egress-filter`'s dependencies are
`{thiserror, serde, serde_json}`, a strict subset of `warrantor-egress`'s
`{thiserror, serde, serde_json, ed25519-dalek, getrandom, sha2}`, so the edge adds **no external
crate** and **no new package** to `Cargo.lock`. `cargo check -p warrantor-egress` passed with the
edge in place, and `git diff rust/Cargo.lock` was exactly one line:

```diff
@@ -2756,6 +2756,7 @@ dependencies = [
   "serde_json",
   "sha2 0.11.0",
   "thiserror",
+  "warrantor-egress-filter",
  ]
```

Critically, the edge goes in **`rust/egress/Cargo.toml`**, not `rust/warrant/Cargo.toml`.
`warrantor-egress` is already reachable (a direct dependency of `warrantor-warrant`), so one edge
below it raises the count without touching the manifest the seed flags as contested by another lane.

---

**Non-goals.** Each names the task that owns the excluded thing.

- **Not writing any adapter.** Tasks 7.3 (messaging, ticketing, email), 7.4 (cloud control plane,
  CI/CD, identity providers), 7.5 (package registries, data platforms, payment rails) and 7.6
  (browser and computer use) do that; 7.2 owns the parser guard. This task ships exactly one
  reference adapter, used only by the conformance tests, so 7.3 has something to transcribe.
- **Not the admission-controller half of L4-25.** Privileged pods, host mounts, broad service
  accounts and unrestricted cluster APIs are Kubernetes admission, a deployment artifact this
  repository does not contain. This task delivers the network-tier floor and the trait an admission
  controller would implement, and Step 11 states plainly that the cluster half is unshipped.
- **Not the destination catalog.** Task 2.5 owns the generic HTTP adapter over a real signed catalog,
  and with it `DenyReason::CatalogInvalidSignature` and `DenyReason::RedirectOutOfSet` — two of the
  three variants `i11_self_change_is_governed.rs:97` names.
- **Not the nine-syscall vocabulary itself.** Task 2.1 owns `Syscall`, `Decomposition` and
  `DecompositionRegistry`. This task consumes them and must not define a parallel local list; a
  second list is the nine-invented-decompositions defect at one remove.
- **Not credential handling.** The kit proves the SDK surface hands an adapter no credential. Task
  3.2 owns the vault. What the kit cannot prove is stated in **Bound strength**.
- **Not purpose or data-class binding.** Task 7.7 owns I-03. A destination floor answers *where*,
  never *what for*.

---

**Files.**

| Path | Change |
|---|---|
| `rust/egress/src/hard_deny.rs` | **new.** The floor. No public item in this module accepts a configuration value of any kind. |
| `rust/egress/src/lib.rs` | modify `:130-142` (`METADATA_RANGES`, `PRIVATE_RANGES` become private to `hard_deny`), `:205-218` (the dead private branch), `:229-243` (`is_metadata_range`, `is_private_range` delegate to `hard_deny`); add `pub mod hard_deny;` |
| `rust/egress/Cargo.toml` | add `warrantor-egress-filter = { path = "../egress-filter", version = "1.0.0" }` — **the wiring edge** |
| `rust/Cargo.lock` | one line, generated; commit it |
| `rust/egress/tests/hard_deny_floor.rs` | **new.** The L4-25 refusal corpus and its allowed controls |
| `rust/egress-filter/src/lib.rs` | modify only to make `normalize_ip` / `is_private_or_local` reusable; **do not weaken any existing assertion** and do not remove `deny_private_egress` — it keeps governing RFC-1918 generally |
| `rust/warrant/src/effect_sdk.rs` | **new.** `EffectAdapter`, `EffectGrant`, `run_conformance` (a module, not a crate — Finding 4) |
| `rust/warrant/src/lib.rs` | add `pub mod effect_sdk;` to the `pub mod` list at `:35-70`, after `pub mod effects;` (Task 2.1) |
| `rust/warrant/src/egress.rs` | modify `:433-484` (`reason_phrase`, `reason_word`) if new `DenyReason` prose is needed; **verify no rendered refusal becomes unreachable** |
| `rust/warrant/tests/effect_sdk_conformance.rs` | **new.** The conformance vectors plus the reference adapter |
| `rust/warrant/tests/invariants/i11_self_change_is_governed.rs` | modify `:83-97` and `:105-130` — move `PrivateRange` into the control list; keep the `#[ignore]`; correct its reason text |
| `tools/ci/invariant-ratchet.json` | raise `passing_floor` in the **same commit** (Step 10) |
| `evidence/wiring-coverage.json` | regenerate via `python tools/ci/wiring_census.py --write` |
| `README.md` | line 196 — `9 of 39` → `10 of 39`, and `other 30` → `other 29` (Finding 5) |
| `docs/W1-delivery-gaps.md` | Step 11 — the unshipped admission half, with the tier it would be |
| `docs/task-evidence/task-7.1.md` | **new.** Step 0 capture plus every gate's real output |

---

**Consumes / Produces.**

Consumes, all quoted from `refs/remotes/origin/main`:

```rust
// rust/authority-spec/src/lib.rs:42
pub enum SideEffectClass { Read, Write, Financial, Destructive, Physical }
// :58
pub const fn is_consequential(self) -> bool;
// :69
pub fn parse(s: &str) -> Result<Self, AaeError>;
// :82
pub const fn as_str(self) -> &'static str;

// rust/egress-filter/src/lib.rs:575
pub fn normalize_ip(ip: IpAddr) -> IpAddr;
// :624
pub fn is_private_or_local(ip: &IpAddr) -> bool;
// :508
pub fn normalize_hostname(host: &str) -> Result<String, ConfigError>;
// :59
pub const DEFAULT_CANARY_IPS: &[&str];   // 169.254.169.254 at :61, 100.100.100.200 at :62

// rust/egress/src/lib.rs:156
pub fn decide(request: &EgressRequest, catalog: Option<&DestinationCatalog>) -> EgressVerdict;
// :25
pub enum DenyReason { NotACapability, NotInCatalog, NotInChainIntersection, MetadataRange,
                      PrivateRange, CatalogUnavailable, CatalogInvalidSignature,
                      DiscoveryRequiresApproval, AgentCannotAmendCatalog, RedirectOutOfSet }
// :72
pub struct CatalogEntry { pub logical_endpoint: String, pub addresses: Vec<String>,
                          pub tls_identity: Option<String>, pub permitted_methods: Vec<String>,
                          pub expires_at: u64 }

// rust/warrant/src/egress.rs:185
pub fn for_bounds(bounds: &WarrantBounds) -> Self;          // on EgressBroker
// :229
pub fn decide(&self, destination: &str) -> broker::EgressVerdict;
// rust/warrant/src/proxy.rs:305
pub fn host_of(value: &str) -> &str;
```

Consumes, **created by Task 2.1** — if these do not resolve, Task 2.1 has not landed and Steps 6 to 9
are blocked:

```rust
// rust/warrant/src/effects.rs
pub enum Syscall { Net, Cred, Exec, Mutate, Msg, Spend, Delegate, Actuate, Attest }
impl Syscall { pub const ALL: [Self; 9]; pub const fn projection(self) -> SideEffectClass; }
pub struct DecompositionRegistry;
impl DecompositionRegistry {
    pub fn get(&self, tool: &str) -> Option<&Decomposition>;
    pub fn classify(&self, tool: &str, policy: UnclassifiedPolicy)
        -> Result<Classified<'_>, Unclassified>;
}
pub enum UnclassifiedPolicy { Refuse, GuessRead }
```

Produces, exact:

```rust
// rust/egress/src/hard_deny.rs
// The mechanism IS the signature: no function here takes a policy, a config, a bool, or &self.
// There is nothing to pass that could change the answer.
pub const FLOOR_FORMAT: &str = "warrantor.egress-hard-deny/1";

pub enum FloorReason { MetadataService, LinkLocal, Loopback, Unspecified, UniqueLocal, Unparseable }

pub enum FloorVerdict { Refused(FloorReason), NotRefused }

/// Parse every spelling of an IPv4 address a resolver or a socket API accepts: dotted quad,
/// bare 32-bit decimal, octal-per-octet, hexadecimal, and both IPv6 forms including the
/// IPv4-mapped one. A literal this cannot parse is `FloorReason::Unparseable`, never allowed.
pub fn parse_address(literal: &str) -> Result<IpAddr, FloorReason>;

/// The floor. One argument: the address. Nothing else exists to supply.
pub fn refuse(literal: &str) -> FloorVerdict;
pub fn refuse_ip(ip: IpAddr) -> FloorVerdict;

/// The addresses no catalog entry, warrant bound, policy field or serialized config can reach.
pub const FLOOR_ADDRESSES: &[&str] = &["169.254.169.254", "100.100.100.200"];

// rust/warrant/src/effect_sdk.rs
pub const CONFORMANCE_FORMAT: &str = "warrantor.adapter-conformance/1";

/// What an adapter is handed. It has no credential accessor, and adding one is a source-gate
/// failure in `rust/warrant/tests/effect_sdk_conformance.rs`.
pub struct EffectGrant<'a> { /* private */ }
impl<'a> EffectGrant<'a> {
    pub fn syscalls(&self) -> &BTreeSet<Syscall>;
    pub fn destination(&self) -> Option<&str>;
    pub fn deadline(&self) -> u64;
    // deliberately absent: credential(), token(), secret(), header(), env()
}

pub enum AdapterOutcome {
    Performed { receipt_fields: BTreeMap<String, String> },
    Refused { reason: String },
    Staged { handle: String },
}

pub trait EffectAdapter {
    fn adapter_name(&self) -> &str;
    fn tools(&self) -> Vec<String>;
    fn declared_syscalls(&self, tool: &str) -> Option<BTreeSet<Syscall>>;
    fn invoke(&mut self, tool: &str, arguments: &BTreeMap<String, Value>,
              grant: &EffectGrant<'_>) -> AdapterOutcome;
}

pub struct VectorResult { pub vector: &'static str, pub passed: bool, pub detail: String }
pub struct ConformanceReport { pub format: &'static str, pub adapter: String,
                               pub vectors: Vec<VectorResult> }
impl ConformanceReport {
    pub fn all_passed(&self) -> bool;
    pub fn to_json(&self) -> Result<String, String>;
}

pub fn run_conformance<A: EffectAdapter>(adapter: &mut A, registry: &DecompositionRegistry)
    -> ConformanceReport;
```

---

**Bound strength.**

The metadata and link-local floor is **Tier B, chokepoint.** A specific line refuses the action at
the moment it is attempted — `hard_deny::refuse` returning `Refused` inside `warrantor_egress::decide`
before any allow path is considered — so it is a refusal, not a settle-time observation. But it binds
only traffic that traverses the broker, and the broker is reached only through the MCP proxy at
`rust/warrant/src/proxy.rs:227`. The crate's own honest word for this is already in the code:
`rust/warrant/src/egress.rs:232` sets `enforcement_mode: "advisory"` with the comment *"Not
'mediated': the proxy mediates only the calls that come through it."*

The sentence that must appear in the product, in these words:

> The metadata and link-local deny is refused at the egress broker and cannot be amended by any
> warrant, policy field or serialized config. It binds the tool calls that reach the broker. It does
> **not** bind a socket the agent opens with its own shell or file tools, it does **not** bind a
> hostname that resolves into the metadata range, and it is **not** an OS or network-tier control:
> nothing outside this process enforces it. L4-25's admission-controller half — privileged pods,
> host mounts, broad service accounts, unrestricted cluster APIs — is not shipped in this
> repository.

The DNS limit is not new and is already stated at `rust/warrant/src/egress.rs:44-47`: *"A hostname
that resolves into a metadata or private range is therefore not caught by the range check; only a
literal address in the bound is."* Do not delete that; extend it. Adding `metadata.google.internal`
and its siblings to a name list narrows the gap by one list and closes nothing, and the step that
adds them must say so.

The conformance kit is **Tier C, observed.** It proves an adapter decomposes correctly and receives
no credential *in a test run against a grant the harness constructs*. It cannot prove a shipped
adapter does either at runtime, and it cannot prove an adapter holds no credential of its own — the
`EffectGrant` surface has no accessor, but an adapter can hold a token in its own struct and the kit
would not see it. State that limit in the kit's own report: `ConformanceReport` renders the sentence
*"this report describes the adapter surface under test vectors, not the adapter's runtime behavior
or its private state."*

**No new trust root.** The kit publishes nothing and calls nothing. A conformance report is a local
JSON document a third party runs and shows; it establishes that the adapter passed the vectors on the
machine that ran them, and nothing about who wrote it, whether the binary shown is the binary run, or
whether an upstream version changed underneath. L4-20's *"an unknown upstream version downgrades the
coverage claim rather than inheriting it"* is L11-05's, not this task's; the report must carry the
upstream version it saw and refuse to claim coverage for any other.

**Orphan count.** Falls from 30 to 29. Nothing is added that nothing links: the SDK is a module of
`warrantor-warrant` (Finding 4), the floor is a module of `warrantor-egress`, and
`warrantor-egress-filter` moves onto the reachable side.

---

**Exit gate.** `cargo test -p warrantor-egress --test hard_deny_floor && cargo test -p warrantor-warrant --test effect_sdk_conformance && cargo test -p warrantor-warrant --test invariants && python tools/ci/check_invariant_ratchet.py && python tools/ci/wiring_census.py` exits 0, with the census line reading exactly `wiring census: 10 of 39 crates reachable from warrantor-warrant over 18 path edges` and **no** `::error::` or `::notice::` line in its output — a `::notice::` means the floor record and README were not updated in this commit, and is a failure.

---

- [ ] **Step 1 — Worktree, then reproduce every number in Step 0 before changing anything.**
      ```bash
      export PATH="$PATH:/c/Users/MuVeraAICorporation/.cargo/bin"
      cd "M:/Project AumOS - Open Secure AI Alliance/aumos"
      git worktree add M:/wt-7.1 -b feat/effect-sdk-and-deny-floor refs/remotes/origin/main
      cd M:/wt-7.1 && export CARGO_TARGET_DIR=M:/wt-7.1-target
      ```
      Then run the whole Step 0 block and paste the output into `docs/task-evidence/task-7.1.md`.
      *Test intent:* if `python tools/ci/wiring_census.py` does not print `9 of 39 … over 17 path
      edges`, or `cargo test -p warrantor-egress-filter` does not print `26 passed`, stop — the
      baseline moved and every figure below needs re-deriving. Never work from the shared checkout:
      it carries ~40 untracked crates `origin/main` does not have.

- [ ] **Step 2 — Failing test: the seven spellings. `rust/egress/tests/hard_deny_floor.rs`.**
      Build one catalog entry per spelling, decide it through `warrantor_egress::decide`, and assert
      `Deny`. Assert the *reason* too, not just the action — `DefaultDeny` would be a false pass,
      because it means the address was refused for not being catalogued rather than for being the
      metadata service, and the same test would pass on a catalog that never listed it.
      ```rust
      const FLOOR_VECTORS: &[(&str, &str)] = &[
          ("dotted quad",          "169.254.169.254"),
          ("ipv4-mapped ipv6",     "::ffff:169.254.169.254"),
          ("alibaba metadata",     "100.100.100.200"),
          ("bare 32-bit decimal",  "2852039166"),
          ("octal per octet",      "0251.0376.0251.0376"),
          ("hexadecimal",          "0xa9fea9fe"),
          ("leading whitespace",   " 169.254.169.254"),
          ("ipv6 link-local",      "fe80::1"),
          ("loopback",             "127.0.0.1"),
          ("rfc-1918",             "10.0.0.1"),
      ];

      #[test]
      fn every_spelling_of_the_metadata_service_is_refused_l4_25() {
          for (name, literal) in FLOOR_VECTORS {
              let verdict = decide(&request(), Some(&catalog_of(literal)));
              match verdict {
                  EgressVerdict::Deny { reason: DenyReason::MetadataRange }
                  | EgressVerdict::Deny { reason: DenyReason::PrivateRange } => {}
                  other => panic!(
                      "{name} ({literal}) must be refused AS the floor, not merely uncatalogued; \
                       got {other:?}"
                  ),
              }
          }
      }
      ```
      *Test intent:* eight of the ten fail today (verified verbatim in Finding 2). Pair it with the
      allowed control in the same file — a verifier that refuses everything proves nothing:
      ```rust
      #[test]
      fn the_floor_does_not_refuse_a_legitimate_public_destination() {
          for ok in ["203.0.113.9", "8.8.8.8", "2606:4700:4700::1111", "api.github.com"] {
              assert!(matches!(decide(&request(), Some(&catalog_of(ok))),
                               EgressVerdict::Allow { .. }),
                      "{ok} is a lawful catalogued destination and must still be allowed");
          }
      }
      ```
      And assert the over-inclusive case is *not* refused by the floor:
      `169.254.169.254.nip.io` is not the metadata service and must not be denied as
      `MetadataRange` — it may be denied as uncatalogued, which is a different sentence.

- [ ] **Step 3 — `rust/egress/src/hard_deny.rs`: a typed matcher with no configuration argument.**
      `parse_address` handles every spelling in Step 2 (`inet_aton` semantics: dotted quad, bare
      decimal, octal per octet, hex, plus both IPv6 forms), then `refuse_ip` classifies the parsed
      `IpAddr` by delegating to `warrantor_egress_filter::normalize_ip` and
      `warrantor_egress_filter::is_private_or_local` plus an exact-match check against
      `FLOOR_ADDRESSES`. Move `METADATA_RANGES` and `PRIVATE_RANGES` into this module and make them
      private; a string-prefix constant that anything else can read is a second matcher waiting to
      disagree with the first. Rewrite the dead branch at `lib.rs:205-218` to
      `return EgressVerdict::Deny { reason: DenyReason::PrivateRange }` — that variant is rendered
      as prose in `warrant/src/egress.rs:454` today and constructed nowhere.
      *Test intent:* Step 2 goes green. `parse_address` gets its own unit tests including the
      failure direction: `"not-an-address"`, `"999.1.1.1"`, `"0x"`, `""` and `"169.254.169.254.5"`
      must all return `Err(FloorReason::Unparseable)` and `refuse` must treat unparseable as
      `Refused`, never as `NotRefused`. Unparseable-is-allowed is the AX-05 lesson
      (`rust/egress-filter/src/lib.rs:92-98`) and repeating it here would be inexcusable.

- [ ] **Step 4 — Failing test: no public surface can amend the floor.**
      Two halves, and both are needed.
      (a) A behavioral half in `hard_deny_floor.rs`: enumerate every path that reaches
      `warrantor_egress::decide` with an attacker-chosen input — a `WarrantBounds` whose
      `egress_hosts` contains each Step-2 spelling, driven through
      `EgressBroker::for_bounds(&bounds).decide(host)`; a `DestinationCatalog` deserialized from
      adversarial JSON; and a catalog built by struct literal — and assert the floor holds through
      all three. This is the L4-25 verification sentence transcribed: *"From inside a workload with a
      deliberately over-broad warrant."*
      (b) A source half, because absence is the mechanism and a behavioral test cannot see a
      parameter that has not been added yet. Assert that `rust/egress/src/hard_deny.rs` contains no
      occurrence of `bool`, `Policy`, `Config`, `deny_private`, or `&self`, with a control asserting
      the probe *does* see `IpAddr` — otherwise a broken probe reads as a pass.
      *Test intent:* the source gate is the only thing that stops a later commit adding
      `refuse(literal, allow_override: bool)` and keeping every behavioral test green. **Put the
      patterns in the Rust file, not in a shell grep**: regexes passed through a heredoc on this box
      lose their backslashes and produce false alarms. The in-file gate is the arbiter.

- [ ] **Step 5 — Wire `warrantor-egress-filter` into the shipping path; record the census rising.**
      Add `warrantor-egress-filter = { path = "../egress-filter", version = "1.0.0" }` to
      **`rust/egress/Cargo.toml`** — not `rust/warrant/Cargo.toml`, which another lane owns.
      Then, in the same commit:
      ```bash
      cd rust && cargo check -p warrantor-egress && cd ..
      python tools/ci/wiring_census.py            # expect the ::notice:: and the README ::error::
      python tools/ci/wiring_census.py --write    # rewrites evidence/wiring-coverage.json
      # README.md:196 — "9 of 39" -> "10 of 39", "the other 30" -> "the other 29"
      python tools/ci/wiring_census.py            # must now be silent and exit 0
      git diff --stat rust/Cargo.lock             # must be exactly "1 insertion"
      ```
      *Test intent:* the census is the exit gate and it reads three files — the manifest graph,
      `evidence/wiring-coverage.json` and `README.md:196`. Verified: the edge yields
      `10 of 39 … over 18 path edges`, adds one `Cargo.lock` line and no new package. If
      `git diff rust/Cargo.lock` shows a new `[[package]]` block, something else drifted — stop.
      Also verified: a concurrent `cargo` in the shared checkout leaves orphaned registry locks on
      this box, so if `cargo check` hangs, check for another lane's build before assuming a bug.

- [ ] **Step 6 — Failing test: an adapter that touches a credential fails conformance.**
      `rust/warrant/tests/effect_sdk_conformance.rs`. Two adapters: `ReferenceAdapter` (correct) and
      `LeakyAdapter` (deliberately broken). Vector V1 asserts `EffectGrant` exposes no credential —
      enforced by the type, so the mechanism is that `LeakyAdapter` *cannot compile* against a grant
      that offers one, and the vector's runtime half asserts the adapter's `receipt_fields` contain
      no value matching a sentinel secret the harness plants in the process environment.
      ```rust
      #[test]
      fn a_leaky_adapter_fails_the_credential_vector() {
          std::env::set_var("WARRANTOR_CONFORMANCE_SENTINEL", "sentinel-3f9c-not-a-real-secret");
          let report = run_conformance(&mut LeakyAdapter::default(), &registry());
          let v1 = report.vectors.iter().find(|v| v.vector == "no-credential-in-grant").unwrap();
          assert!(!v1.passed, "an adapter that reads a credential must fail V1");
          assert!(!report.all_passed());
      }

      #[test]
      fn the_reference_adapter_passes_every_vector() {   // the allowed control
          let report = run_conformance(&mut ReferenceAdapter::default(), &registry());
          assert!(report.all_passed(), "vectors: {:#?}", report.vectors);
      }
      ```
      *Test intent:* both directions in one file. A kit that fails every adapter is not a kit.
      Blocked until Task 2.1 lands `DecompositionRegistry`; if it has not, stop here and report —
      Steps 1 to 5 stand alone and are worth landing.

- [ ] **Step 7 — Failing test: an adapter whose decomposition omits a syscall fails conformance.**
      Vector V2 (`every-tool-declared`) and V3 (`decomposition-matches-registry`). Assert against
      `Syscall::ALL` and the registry Task 2.1 produces — **never** against a list literal in this
      file. `OmittingAdapter` declares `{Net}` for a tool the registry decomposes as
      `{Exec, Net, Mutate}` and must fail V3 naming the missing verbs; `UndeclaredAdapter` offers a
      tool the registry does not know and must fail V2 under `UnclassifiedPolicy::Refuse`.
      *Test intent:* a fourth control — an adapter whose declaration is a strict *superset* of the
      registry's must also fail, with a distinct detail string. Over-declaring is not safe: it
      widens what the kernel authorizes for that tool. Add a static assertion that
      `Syscall::ALL.len() == 9`, so the vocabulary mismatch in Finding 3 becomes a build error if
      anyone reintroduces the five-value list.

- [ ] **Step 8 — The `EffectAdapter` trait, `EffectGrant`, and `run_conformance`.**
      `rust/warrant/src/effect_sdk.rs`, registered in `rust/warrant/src/lib.rs` after
      `pub mod effects;`. `warrantor-warrant` carries `#![deny(missing_docs)]`
      (`rust/warrant/src/lib.rs:32-33`), so every `pub` item needs a doc comment or the build fails.
      Write no claim into a doc comment, log line, error message or the generated
      `ConformanceReport` that a mechanism in this commit does not deliver — the report says which
      vectors ran and what they observed, and never that the adapter is safe.
      *Test intent:* Steps 6 and 7 go green; `cargo doc -p warrantor-warrant` builds clean; and a
      test asserts `ConformanceReport::to_json` round-trips and carries `CONFORMANCE_FORMAT` plus
      the upstream version string, so a report cannot be read as covering a version it never saw.

- [ ] **Step 9 — The reference adapter, kept out of the shipping build.**
      `ReferenceAdapter` lives in `rust/warrant/tests/effect_sdk_conformance.rs`, not in `src/`.
      It is what Task 7.3 transcribes, and shipping it would ship an adapter this task's non-goals
      exclude.
      *Test intent:* `grep -c ReferenceAdapter rust/warrant/src/` returns 0, asserted in the test
      file itself so the constraint survives.

- [ ] **Step 10 — Convert the recorded finding this task actually earns, and raise the ratchet in
      the same commit.**
      `rust/warrant/tests/invariants/i11_self_change_is_governed.rs:97` carries
      `#[ignore = "I-11 unimplemented at the broker: three DenyReason variants are rendered and
      never constructed (Task 2.5, 2026-09-02)"]`. **This task does not flip it** —
      `CatalogInvalidSignature` and `RedirectOutOfSet` are Task 2.5's, and `AgentCannotAmendCatalog`
      is a different condition than an address floor; constructing it here for the wrong reason
      would be a false claim, which is worse than the ignore. What this task does earn:
      `DenyReason::PrivateRange` was a **fourth** never-constructed variant that the test's own list
      omitted, and Step 3 constructs it. So:
      - move `"PrivateRange"` into the `for reachable in [...]` **control** list at `:105-115`,
        beside `NotInCatalog`, `MetadataRange`, `CatalogUnavailable`;
      - correct the doc comment at `:83-95` to record that a fourth variant existed, was found by
        Task 7.1, and is now constructed;
      - keep the `#[ignore]` and keep its text at *three* remaining variants, so
        `ignored_ceiling` stays 19.
      Add one new **passing** case to the same file asserting that a warrant bound naming any
      Step-2 spelling still cannot reach the metadata service — the I-11 self-change boundary at the
      address layer. Then:
      ```bash
      cargo test -p warrantor-warrant --test invariants
      python tools/ci/check_invariant_ratchet.py     # fails on IMPROVEMENT too; read its message
      # edit tools/ci/invariant-ratchet.json: passing_floor 65 -> the number just reported
      python tools/ci/check_invariant_ratchet.py     # must now exit 0
      ```
      *Test intent:* `tools/ci/check_invariant_ratchet.py:159-163` fails when the corpus improves
      without the baseline moving, so the floor must rise in this commit. Never lower an assertion
      to earn a number: if a new case does not pass, it becomes a new `#[ignore]`, which raises
      `ignored_ceiling` and is itself a build failure — which is the correct outcome, not a problem
      to route around.

- [ ] **Step 11 — State the unshipped half, in the product text and in `docs/W1-delivery-gaps.md`.**
      Write the **Bound strength** paragraph verbatim into `docs/W1-delivery-gaps.md` beside the
      Tier 5 section, naming: the admission-controller tier (privileged pods, host mounts, broad
      service accounts, unrestricted cluster APIs) is **not in this repository**; the network-policy
      tier is **not in this repository**; what ships is a broker-tier refusal, Tier B, bounded by the
      mediation ceiling; and the DNS gap, which a name list narrows and does not close. Record that
      L4-25 and L2-04 both remain `status=none` after this task, because
      `docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html:3889` and `:3308` require
      *"every metadata and link-local request fails at the network tier and every privileged-pod
      request fails at admission"*, and this task delivers neither tier. If it were enforced out of
      process by a network policy or an admission controller it would be Tier A; say that, and say
      it is not.
      *Test intent:* `python tools/ci/check_docs.py` passes, and the invariant-corpus source gate
      `harness::source_contains` finds the mediation-ceiling sentence unchanged — no step in this
      task may quietly upgrade an "advisory" or "chokepoint" label to "enforced".

- [ ] **Step 12 — Gates, evidence file, `git commit -s`.**
      Run, in this order, and paste every output into `docs/task-evidence/task-7.1.md`:
      ```bash
      cd rust && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings \
        && cargo test --workspace && cd ..
      python tools/ci/check_invariant_ratchet.py
      python tools/ci/wiring_census.py
      python tools/ci/check_docs.py
      python tools/ci/test_wiring_census.py
      node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" \
        docs/W1-delivery-gaps.md docs/task-evidence/task-7.1.md
      git commit -s        # the DCO gate rejects an unsigned commit
      ```
      *Test intent:* run the gate for **every** language touched, Rust and Python both — a CI
      annotation reports only the jobs that ran, so a green annotation on a partial run is not
      evidence. `cargo test --workspace` runs on Windows here and CI runs it only on ubuntu, so any
      `#[cfg(windows)]` path this touches is otherwise untested. The evidence file must record the
      Step-0 numbers, the Step-2 before/after table with all ten spellings, the census line, the
      one-line `Cargo.lock` diff, the ratchet numbers before and after, and the **Bound strength**
      paragraph exactly as it appears in the product. Do not write "done" in it for anything whose
      output is not pasted beneath the claim.
