# Task 7.1 (partial — Steps 1 to 5 only): the non-amendable deny floor, L4-25

Branch `feat/effect-sdk-and-deny-floor`, based on **local `main` at `f99af94`** — not
`origin/main` at `e4b5f10`. Local `main` carries four unpushed merges, including the egress
metadata-floor fix `c6cb1bb` that this task builds on.

**Scope actually delivered: Steps 1 through 5.** Steps 6 to 9 (the effect-class SDK and the
conformance kit, L4-20) require `rust/warrant/src/effects.rs` from Task 2.1, which has not landed.
Nothing in this branch touches L4-20, and neither L4-20 nor L4-25 may have `status="none"` softened
by it — see *What this task does NOT establish*.

---

## What was already true, and what was left to do

`c6cb1bb` made the metadata floor **correct** in `warrantor-egress`: nine spellings of the metadata
service are refused by name in `rust/egress/tests/metadata_floor.rs`, and `is_metadata_range`
normalizes, parses all four IPv4 radix forms, unwraps IPv4-mapped IPv6 and classifies with real
range checks. This task did **not** rewrite that matcher and did **not** add a second test of those
spellings.

It made the floor correct. It did not make it **unamendable**, and it did not touch
`warrantor-egress-filter` at all. Those two gaps, plus the wiring, are this task's work.

---

## Step 1 — non-amendability: the real count is five, and the plan's list is wrong twice

The plan (Finding 1) names four amendable paths. The count was re-derived by compiling a probe
against this branch's base rather than taking the list on trust. **Two of the plan's four do not
hold, and one real path is absent from the plan.**

Probe output, verbatim, run with `cargo test -p warrantor-egress-filter --test amendability_probe`
before any change (the probe was deleted once recorded; `hard_deny_floor.rs` now carries the same
matrix as assertions):

```
PROBE ROUND 2
A  new()+allow_ip                      Allow  -> no: Deny/PrivateIp
B  new()+false+allow_ip                Allow/Allowlisted
C  with_defaults+false+fe80::1         Allow/Allowlisted
D  with_defaults+alibaba               Deny/CanaryIp
E  serde canary_ips=[]                 Allow/Allowlisted
F  struct literal                      Allow/Allowlisted
G  with_defaults+allow_domain          Allow/Allowlisted
H  with_defaults+mapped ipv6           Deny/CanaryIp
I  Policy::default()                   Deny/CanaryIp
C1 control 8.8.8.8                     Allow/Allowlisted
C2 control api.github.com              Allow/Allowlisted
```

(Row A's raw output was `Deny/PrivateIp`; it is annotated above to make the disproof explicit.)

### The five paths that did reach Allow

| # | path | why it worked |
|---|---|---|
| 1 | `PolicyBuilder::new()` + `deny_private_egress(false)` + `allow_ip` | `PolicyBuilder::default()` sets `use_defaults: false`, so `canary_ips` builds **empty** and no metadata address is known; the boolean then removes the range check |
| 2 | `PolicyBuilder::with_defaults()` + `deny_private_egress(false)`, for `fe80::1` | `DEFAULT_CANARY_IPS` names **no IPv6 link-local address**, so for `fe80::/10` the boolean was the *only* control |
| 3 | a serialized `Policy` stating `"canary_ips": []` | the field carries **no** `#[serde(default)]`, so a supplied config states the whole list and `[]` is accepted. A file on disk, not a code change |
| 4 | a `Policy` struct literal | every `Policy` field is `pub`, so a literal bypasses `PolicyBuilder` entirely |
| 5 | `PolicyBuilder::with_defaults()` + `allow_domain("metadata.google.internal")` | **absent from the plan.** There is no canary *hostname* list, so the metadata service named by DNS was allowlistable by a fully defaulted policy that had weakened nothing at all |

Path 5 is the worst of the five and the plan does not mention it. Paths 1 and 2 also cover the
numeric spellings via the hostname route: `decide_destination("2852039166")` fails
`str::parse::<IpAddr>`, so it went down the *domain* path and `allow_domain("2852039166")` reached
Allow while naming the same 32-bit address as `169.254.169.254`.

### The two the plan asserts that do not hold

- **`PolicyBuilder::new()` alone** is not a hole. `PolicyBuilder::default()` sets
  `deny_private: true`, so `169.254.169.254` is refused as `PrivateIp` (row A). It is a hole only
  in combination with `deny_private_egress(false)`.
- **`deny_private_egress(false)` alone on the defaults** is not a hole for `169.254.169.254`
  (rows D, H, I: `Deny/CanaryIp`) — the plan is right that the boolean matters least for that
  address, and wrong that it matters least overall: for `fe80::/10` it was the whole control
  (row C).

### The fix, and where it lives

`rust/egress-filter/src/hard_deny.rs` — new. **No public item in it accepts a configuration value
of any kind.** The two decision signatures are `refuse(literal: &str) -> FloorVerdict` and
`refuse_ip(ip: IpAddr) -> FloorVerdict`: one argument, the address. There is no receiver, no flag,
no policy, no options struct — nothing an operator, a warrant or an agent could pass that would
change the answer, because there is nothing to pass.

It is consulted in `Policy::decide_ip` immediately after the canary check and before the
private check and the allowlist, and in `Policy::decide_domain` after the IP-literal redirect and
before the blocklist. The canary check is left first deliberately, so an address a config *did*
name still reports `CanaryIp` and no pre-existing assertion changes.

Post-fix probe, verbatim — all five closed, both controls still Allow:

```
A  new()+allow_ip                      Deny/HardDenyFloor { rule: "metadata_service" }
B  new()+false+allow_ip                Deny/HardDenyFloor { rule: "metadata_service" }
C  with_defaults+false+fe80::1         Deny/HardDenyFloor { rule: "link_local" }
D  with_defaults+alibaba               Deny/CanaryIp
E  serde canary_ips=[]                 Deny/HardDenyFloor { rule: "metadata_service" }
F  struct literal                      Deny/HardDenyFloor { rule: "metadata_service" }
G  with_defaults+allow_domain          Deny/HardDenyFloor { rule: "metadata_service" }
H  with_defaults+mapped ipv6           Deny/CanaryIp
I  Policy::default()                   Deny/CanaryIp
C1 control 8.8.8.8                     Allow/Allowlisted
C2 control api.github.com              Allow/Allowlisted
```

### DEVIATION: the floor is in `egress-filter`, not `egress`

The plan puts the floor at `rust/egress/src/hard_deny.rs`. **The code wins: that placement cannot
work.** `warrantor_egress_filter::Policy` is the amendable surface, and `warrantor-egress-filter`
cannot depend on `warrantor-egress` in the direction that would let a floor in `egress` govern
`Policy` — the wiring edge runs `egress -> egress-filter`, and the reverse is a cycle. Putting the
floor in the lower crate means:

- both crates get **one** matcher, which is the point. Two implementations of "is this the metadata
  service" is the exact shape of the defect `c6cb1bb` fixed in one crate and not the other;
- the wiring edge still lands where the plan wants it (`rust/egress/Cargo.toml`), so the census
  still rises;
- the duplicated matcher `c6cb1bb` had written into `rust/egress/src/lib.rs` (`host_only`,
  `parse_ipv4_any_radix`, `canonical_ip`, `METADATA_HOSTNAMES`, `METADATA_ADDRESSES`) is **deleted**
  and delegated, so there is no second copy to drift.

`rust/egress/tests/hard_deny_fail_closed.rs::the_broker_and_the_filter_agree_address_by_address`
asserts the two crates give the same answer over a 17-address corpus containing both polarities.
That test is also what makes the dependency edge load-bearing: delete the edge and it will not
compile.

---

## Step 2 — failing closed: the decision, and exactly what it costs

**The floor fails closed on a literal that could only ever have been an address, and does not fail
closed on a DNS name. That is a decision, not an omission.**

The `addresses` field is documented as *"pre-resolved IPs or explicit hostnames"*, and
`rust/warrant/src/egress.rs:204` (`EgressBroker::for_bounds`) puts a hostname there:
`addresses: vec![host.clone()]`, the literal string from the warrant's `egress_hosts`. So **every
hostname bound a developer writes is an unparseable address by construction.** A floor that refused
everything unparseable would refuse `api.github.com`, `registry.npmjs.org` and every other name a
warrant can carry — it would refuse the entire shipping path rather than harden it. That is what
would break, precisely.

The half that is safe to fail closed on is the half that could only ever have been an address. The
discriminator is the rightmost label: **no registrable top-level domain is entirely numeric**
(RFC 3696 §2), and a `0x` prefix is the other tell. So:

| literal | before | after | why |
|---|---|---|---|
| `999.1.1.1` | Allow | `Deny/UnparseableAddress` | an octet out of range; not a name |
| `0x` | Allow | `Deny/UnparseableAddress` | a hex prefix with no digits |
| `169.254.169.254.5` | Allow | `Deny/UnparseableAddress` | five labels, the last numeric |
| `2852039166000000` | Allow | `Deny/UnparseableAddress` | a decimal too large for 32 bits |
| `""` | Allow | `Deny/UnparseableAddress` | nothing at all |
| `api.github.com` | Allow | **Allow** | a name; the control |
| `169.254.169.254.nip.io` | Allow | **Allow** | a name, refused as uncatalogued elsewhere if at all — refusing it *as the floor* would be a claim about a host the floor knows nothing about |

`DenyReason::UnparseableAddress` is a new variant, **constructed** at
`rust/egress/src/lib.rs` and rendered in `rust/warrant/src/egress.rs` (`reason_phrase` and
`reason_word`). It is not a fourth never-constructed variant.

**What this does not fix:** a DNS name outside `hard_deny::FLOOR_HOSTNAMES` that *resolves* into
the metadata range still reaches `NotRefused`. The floor does not resolve DNS. The hostname list
narrows that gap by exactly the four names on it and **closes nothing**; the module says so in
those words, and the pre-existing statement of the limit at `rust/warrant/src/egress.rs:44-47` is
left intact.

---

## Step 5 — wiring: the census rises, and the orphan count falls

`rust/egress/Cargo.toml` gains
`warrantor-egress-filter = { path = "../egress-filter", version = "1.0.0" }`.
`warrantor-egress` is already a direct dependency of `warrantor-warrant`, so one edge below it puts
the floor on the shipping path.

```
before:  wiring census: 10 of 40 crates reachable from warrantor-warrant over 18 path edges
after:   wiring census: 11 of 40 crates reachable from warrantor-warrant over 19 path edges
orphans: 30 -> 29
```

`rust/Cargo.lock` grew by exactly one line (`warrantor-egress-filter` under
`warrantor-egress`'s dependency list) and **no new `[[package]]` block**: the added crate's
dependency set `{thiserror, serde, serde_json}` is a strict subset of `warrantor-egress`'s.

`README.md:196` was updated in the same change — `**10 of 40**` to `**11 of 40**` and
`the other 30` to `the other 29` — because `tools/ci/wiring_census.py:150-154` asserts that row
against the measured number and returns 1 on a mismatch. Verified: the census emitted
`::error::README status table does not show 'reachable from the CLI | **11 of 40**'` before the
edit and is silent after it.

**The orphan count did not rise.** Nothing new is a crate: the floor is a module of
`warrantor-egress-filter`, which moved *onto* the reachable side.

---

## `DenyReason::PrivateRange` — the pin is left alone, deliberately

`metadata_floor.rs` pins the construction count of `DenyReason::PrivateRange` at **zero**, and it
still reads zero. The variant was **not** given a mechanism, for a stated reason rather than by
omission:

- L4-25 names the metadata service, link-local addresses, privileged pods, host mounts and broad
  service accounts. It does **not** name RFC-1918. Widening the floor to 10/8 is not this task.
- The rule the variant renders — *"private ranges denied unless explicitly catalogued"* — is
  satisfied vacuously at this layer: an address only reaches the check by having been found in the
  catalog, so it is catalogued by arrival. Constructing the variant means deciding that a
  catalogued private address is refused **anyway**, which contradicts
  `test_catalog()`'s `10.0.1.5` and with it `valid_capability_resolves_to_allow`,
  `receipt_round_trip_verifies`, `net_egress_wildcard_allows` in `warrantor-egress`, plus
  `private_egress_can_be_explicitly_opted_out_of` in `warrantor-egress-filter`.
- What **was** removed is the empty `if is_private_range(addr) { }` branch whose comment reasoned
  itself into a no-op. That was a rendered refusal with nothing behind it — a claim without a
  mechanism. The comment is gone, the variant stays declared, the count stays pinned, and the
  decision stays open with the four affected tests named.

**No existing assertion was weakened anywhere in this branch.** One collision occurred and was
resolved the conservative way: a comment I wrote in `rust/egress/src/lib.rs` used the qualified
path `DenyReason::PrivateRange`, which the pin counts as an occurrence and which took the count
from 0 to 1. The pin is a *substring* count, not a construction count, so the honest fix was to
reword my prose rather than loosen the pin. The pin is byte-for-byte unchanged.

---

## Tier table

| bound | word | why not stronger |
|---|---|---|
| metadata service and link-local addresses cannot be reached through `Policy::decide_*` | **Enforced, in-process** | `hard_deny::refuse_ip` returns `Refused` and `decide_ip` returns `Action::Deny` at the moment the decision is asked for, before any allowlist is consulted, and no configuration value can reach it. Confined to callers of this API — it is not an OS bound |
| metadata service and link-local addresses cannot be reached through `warrantor_egress::decide` | **Tier B, chokepoint** | a specific line refuses at decision time, but it binds only tool calls that traverse the broker, which is reached only through the MCP proxy at `rust/warrant/src/proxy.rs:227`. The crate's own honest word is already in the code: `rust/warrant/src/egress.rs:232` sets `enforcement_mode: "advisory"` with the comment *"Not 'mediated': the proxy mediates only the calls that come through it."* **What escapes:** a socket the agent opens with its own shell or file tools; a DNS name that resolves into the range; anything not routed through the proxy |
| the floor is unamendable | **Enforced, by absence** | there is no parameter to pass. The behavioral half proves the five paths are closed; the source half pins both signatures verbatim and forbids `&self`, `: bool`, `Policy`, `Config`, `Options`, `deny_private`, `allowlist`, `canary_ips`, `override` in the module's shipping code, with a control asserting the probe *can* see `IpAddr` and `pub fn refuse` so a broken gate reads as a failure rather than a pass |
| the two crates agree | **Observed** | asserted over a 17-address corpus at test time. It is not a proof that no future address makes them diverge; it is a regression test that fires if a second matcher reappears |
| failing closed on an address-shaped literal | **Enforced, in-process** | `DenyReason::UnparseableAddress` is constructed and returned before the Allow branch |
| L4-25's admission-controller half | **Not shipped** | privileged pods, host mounts, broad service accounts and unrestricted cluster APIs are Kubernetes admission, a deployment artifact this repository does not contain. Nothing in this branch claims otherwise |

No netns, seccomp or firewall enforcement exists in this repository, and nothing in this branch
adds any.

---

## Deviations from the plan

1. **The floor module is `rust/egress-filter/src/hard_deny.rs`, not `rust/egress/src/hard_deny.rs`.**
   The plan's placement cannot govern `Policy` without a dependency cycle. Reasoned above.
2. **The plan's Step 0 baseline is stale.** It records `9 of 39 … over 17 path edges` and
   `26 passed` for `warrantor-egress-filter`, captured on `origin/main` at `e4b5f10`. Local `main`
   at `f99af94` measures `10 of 40 … over 18 path edges` and `26 passed`; after this change,
   `11 of 40 … over 19 path edges`. The plan's Step 1 also branches from
   `refs/remotes/origin/main`, which would have discarded `c6cb1bb`; this branch is off local
   `main`.
3. **Step 2's ten-vector test was not written as specified.** The plan asks for a new test of the
   same ten spellings through `warrantor_egress::decide`. Eight of those are already asserted by
   name in `rust/egress/tests/metadata_floor.rs`, and duplicating them would add a second
   specification of the same rule. The refusal corpus this branch adds is the *amendment paths*
   (`hard_deny_floor.rs`) and the *unparseable* cases (`hard_deny_fail_closed.rs`), which are what
   `c6cb1bb` left open. The plan's expected reason set is also now wrong: it accepts
   `DenyReason::PrivateRange`, which is still never constructed.
4. **Step 3's `parse_address` / `FLOOR_ADDRESSES` surface differs.** The plan specifies
   `parse_address(literal) -> Result<IpAddr, FloorReason>` and a `FloorReason::Unparseable`. This
   branch ships `canonical_ip(literal) -> Option<IpAddr>` plus
   `FloorReason::AddressShapedButUnparseable`, because the plan's `Unparseable` conflates "a name,
   which is legitimate" with "a failed address parse, which is not" — and the plan's own
   instruction to treat all unparseable input as `Refused` would refuse the shipping path (Step 2
   above). `FLOOR_ADDRESSES` is retained as documentation of the two named services; the matching
   is done on typed `Ipv4Addr` values.
5. **Step 4(b)'s source gate does not forbid the literal token `self)`.** `FloorReason::as_str(self)`
   and `FloorVerdict::is_refused(self)` take `self` by value on two `Copy` enums, which is not a
   configuration receiver. The gate forbids `&self` / `&mut self` and, more strongly than the plan
   asks, pins both decision signatures verbatim — a second parameter changes that string and fails
   the gate, which no behavioral test could detect. The gate also trims the module's
   `#[cfg(test)]` block before scanning (with an assertion that the trim actually happened), because
   otherwise the gate reads its own test prose as shipping code; that false positive was hit and
   fixed during this run.
6. **Steps 6 to 9 not attempted.** `rust/warrant/src/effects.rs` does not exist; Task 2.1 has not
   landed. `rust/warrant/src/effect_sdk.rs`, `rust/warrant/tests/effect_sdk_conformance.rs`, the
   `i11` corpus edit and the `passing_floor` raise in `tools/ci/invariant-ratchet.json` are all
   untouched. The ratchet is therefore unchanged rather than raised, which is correct: no invariant
   test moved from ignored to passing.

---

## Gate output, verbatim, with exit codes captured before any pipe

```
$ cargo fmt --check
                                                                    exit 0

$ cargo clippy --all-targets -- -D warnings
                                                                    exit 0

$ cargo test --workspace -j 2 > test.log 2>&1; echo $?
0
  141 suites, 1456 passing, 0 failed, 23 ignored
  (baseline on local main at f99af94: 139 suites, 1435 passing, 0 failed, 23 ignored
   -> +2 suites: rust/egress-filter/tests/hard_deny_floor.rs and
      rust/egress/tests/hard_deny_fail_closed.rs; +21 tests; ignored UNCHANGED at 23,
      which is correct: no invariant test moved from ignored to passing)

$ python tools/ci/wiring_census.py
wiring census: 11 of 40 crates reachable from warrantor-warrant over 19 path edges
                                                                    exit 0
  (no ::error:: and no ::notice:: line — evidence/wiring-coverage.json and README.md:196 were
   regenerated and updated in the same change)

$ python tools/ci/check_invariant_ratchet.py
invariant ratchet: ok (66 passing at floor 66, 18 recorded findings at ceiling 18)
                                                                    exit 0

$ python tools/ci/check_invariants.py
invariant ledger: 12 invariants; enforced=2, orphaned=2, partial=7, unimplemented=1
                                                                    exit 0
```

Baseline on local `main` at `f99af94`, for comparison: census `10 of 40` over 18 edges; ratchet
`66 passing at floor 66, 18 findings at ceiling 18`; ledger identical.

US-English check:

```
$ node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs"     docs/task-evidence/task-7.1.md rust/egress-filter/src/hard_deny.rs     rust/egress-filter/tests/hard_deny_floor.rs rust/egress/tests/hard_deny_fail_closed.rs     rust/egress/tests/metadata_floor.rs rust/egress/src/lib.rs README.md

docs/task-evidence/task-7.1.md                     PASS - 0 Britishisms outside the carve-outs
rust/egress-filter/src/hard_deny.rs                PASS - 0 Britishisms outside the carve-outs
rust/egress-filter/tests/hard_deny_floor.rs        PASS - 0 Britishisms outside the carve-outs
rust/egress/tests/hard_deny_fail_closed.rs         PASS - 0 Britishisms outside the carve-outs
rust/egress/tests/metadata_floor.rs                PASS - 0 Britishisms outside the carve-outs
rust/egress/src/lib.rs                             PASS - 0 Britishisms outside the carve-outs
README.md                                          PASS - 0 Britishisms outside the carve-outs

7 file(s) - 0 finding(s) - 0 protected by carve-outs
                                                                    exit 0

Full output read per file, not the last line.
```

---

## What this task does NOT establish

Specifically, not modestly.

1. **It does not deliver L4-20 at all.** No effect-class SDK, no conformance kit, no reference
   adapter, no `Syscall` decomposition, no `EffectGrant`. `L4-20` stays `status="none"`. Steps 6
   to 9 were not attempted because `rust/warrant/src/effects.rs` does not exist on this branch.
2. **It does not move L4-25 off `status="none"` either.** L4-25's verification sentence requires
   that *"from inside a workload with a deliberately over-broad warrant, every metadata and
   link-local request fails at the network tier and every privileged-pod request fails at
   admission."* This branch delivers neither the network tier nor admission. It delivers a
   refusal inside one process, at an API boundary. A reviewer who reads the census rising as
   L4-25 being satisfied has read it wrong.
3. **It is not an OS or network-tier control.** Nothing outside this process enforces the floor.
   No netns, no seccomp, no iptables/nftables rule, no eBPF program is installed by anything in
   this repository — `warrantor-egress-filter` is named for an eBPF enforcement core that does not
   exist as a loaded program. An agent that opens a socket directly, or that uses a shell tool, is
   not bound by any of this.
4. **It does not close the DNS gap.** `FLOOR_HOSTNAMES` holds four names. Any other name that
   resolves into 169.254.0.0/16, fe80::/10 or 100.100.100.200 reaches `NotRefused`, because the
   floor does not resolve DNS and the broker deliberately does not either. A single CNAME to a
   metadata address defeats the address half entirely.
5. **It does not prove the floor cannot be amended by editing the source.** Nothing can. The
   source gate raises the cost of a quiet amendment from "add a parameter" to "delete an assertion
   and explain it in review". That is a different and weaker claim than *unamendable*, and the
   guarantee class L4-25 asks for (**OS-bound**) is not what this is.
6. **It does not give `DenyReason::PrivateRange` a mechanism**, so *"private ranges denied unless
   explicitly catalogued"* still has none, and a catalogued RFC-1918 address is still allowed.
7. **The 17-address agreement corpus is a regression test, not a proof of equivalence.** The two
   crates now share one matcher, so agreement is structural rather than coincidental — but the test
   would not catch a future divergence introduced outside `hard_deny`.
8. **The five-path count is a count of paths a probe found, not a proof that there are no others.**
   It was derived by enumerating `Policy`'s public constructors and both decision entry points. A
   path through some other public API of `warrantor-egress-filter` that this probe did not
   enumerate would not have appeared.
9. **`enforcement_mode` is still `"advisory"`** at `rust/warrant/src/egress.rs:232`, and this
   branch does not change that word. It is the correct word.
