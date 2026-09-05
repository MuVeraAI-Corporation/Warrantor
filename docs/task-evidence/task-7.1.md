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

## Step 1 — non-amendability: the real count is five, and one real path is absent from the plan

The plan (Finding 1) names four amendable surfaces. The count was re-derived by compiling a probe
against this branch's base rather than taking the list on trust. **A fifth path reached Allow that
the plan does not name**, and the probe also fixed which of the four open a hole on their own.

> **CORRECTION (adversarial review of `5e1b5a5`).** This heading previously read *"the plan's list is
> wrong twice"* and the section below carried a subsection titled *"The two the plan asserts that do
> not hold."* That misrepresented the plan and inflated this task's contribution. The plan's list is
> headed, verbatim, *"Four independent amendable paths, **none of which the boolean alone opens**"*,
> and its own probe output at plan line 19412 already reads `WITH_DEFAULTS + false + allow_ip ->
> Deny / CanaryIp      <-- the seed's claimed hole: NOT a hole`. The plan disproved that claim and
> attributed it to the seed; presenting the disproof as an error *the plan* made was wrong. The first
> of the two was a strained reading for the same reason: plan item 1 asserts a mechanism
> (`use_defaults: false` leaves `canary_ips` empty) that the table below restates and agrees with —
> it never claims `PolicyBuilder::new()` alone reaches Allow, and never probed it on the `allow_ip`
> route. What this task genuinely added is **path 5** and the **`fe80::/10` observation** behind
> path 2, both of which stand on their own without a correction attached.

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

### Which of the four surfaces opens a hole on its own

Neither of these is a correction *of the plan* — the plan's heading already says none of the four is
opened by the boolean alone, and its own probe already recorded the `CanaryIp` result. They are the
probe's measurements, kept because they are what the assertions were written against.

- **`PolicyBuilder::new()` alone** does not reach Allow. `PolicyBuilder::default()` sets
  `deny_private: true`, so `169.254.169.254` is refused as `PrivateIp` (row A). It is a hole only
  in combination with `deny_private_egress(false)`.
- **`deny_private_egress(false)` alone on the defaults** does not reach Allow for `169.254.169.254`
  (rows D, H, I: `Deny/CanaryIp`) — the address is a compiled-in canary. What the probe adds to the
  plan here is the *IPv6* half: for `fe80::/10` the boolean was the **whole** control (row C),
  because `DEFAULT_CANARY_IPS` names no IPv6 link-local address. That observation is path 2 and it is
  new.

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
`rust/warrant/src/egress.rs:209` (`EgressBroker::for_bounds`) puts a hostname there:
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
those words, and the pre-existing statement of the limit at `rust/warrant/src/egress.rs:49-52` is
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
`the other 30` to `the other 29` — because `tools/ci/wiring_census.py:150-154 (`readme_renders`)` asserts that row
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

Every row below was re-examined after an adversarial review. Two labels were **weakened** and one
bound was **widened to name a range it had omitted**; the changes are marked and the reasons are in
*Corrections after adversarial review*, further down.

| bound | word | why not stronger |
|---|---|---|
| the metadata services, IPv4 `169.254.0.0/16`, IPv6 `fe80::/10` **and IPv6 unique-local `fc00::/7`** cannot be reached through `Policy::decide_*` | **Enforced, in-process — over an API with no shipping caller** *(label weakened)* | `hard_deny::refuse_ip` returns `Refused` and `decide_ip` returns `Action::Deny` at the moment the decision is asked for, before any allowlist is consulted, and no configuration value can reach it. But the caller set of `Policy::decide_ip` / `decide_domain` / `decide_destination` **is empty in this workspace** outside the crate's own tests: the only cross-crate import of `warrantor-egress-filter` anywhere is `use warrantor_egress_filter::hard_deny::{…}` in `rust/egress/src/lib.rs:18`. So this row is a real in-process refusal on a decision surface **no shipping code calls yet**. What protects the product today is the Tier B row beneath it. It is also not an OS bound |
| the same set cannot be reached through `warrantor_egress::decide` | **Tier B, chokepoint** | a specific line refuses at decision time, but it binds only tool calls that traverse the broker, which is reached only through the MCP proxy at `rust/warrant/src/proxy.rs:227`. The crate's own honest word is already in the code: `rust/warrant/src/egress.rs:241` sets `enforcement_mode: "advisory"` with the comment *"Not 'mediated': the proxy mediates only the calls that come through it."* **What escapes:** a socket the agent opens with its own shell or file tools; a DNS name that resolves into the range; anything not routed through the proxy |
| the floor cannot be amended by passing something to it | **Enforced, by absence — for parameters only** *(label weakened; the previous row read "the floor is unamendable / Enforced, by absence")* | there is no parameter to pass, and both signatures are pinned verbatim so adding one fails a gate no behavioral test could replace. **What that does not cover:** an amendment that passes nothing. A review inserted a `static AtomicBool` plus a `std::env::var("WARRANTOR_FLOOR_OFF")` read at the head of `refuse_ip` — no parameter, both signatures byte-for-byte, all 64 tests and the source gate green — and setting the variable turned **9** tests red, proving the switch reached the shipping path. Those tokens are enumerated in `forbidden_tokens()` now, and the gate fires on that exact edit. It remains an **enumerated denylist over one file's text**: it catches the channels it names and nothing else |
| the two crates agree | **Observed** | asserted over a 17-address corpus at test time. It is not a proof that no future address makes them diverge; it is a regression test that fires if a second matcher reappears |
| failing closed on an address-shaped literal | **Enforced, in-process** | `DenyReason::UnparseableAddress` is constructed and returned before the Allow branch, and is now asserted through the shipping broker as well as through `warrantor_egress::decide` |
| the refusal word an operator reads names the rule that fired | **Not established** | `warrantor_egress::decide` collapses `MetadataService`, `LinkLocal` and `UniqueLocal` into `DenyReason::MetadataRange` (`rust/egress/src/lib.rs:238-242`), so a `fc00::/7` destination a warrant legitimately names is refused under the word `metadata_range`. Documented in three places and **not fixed**: widening the enum changes the reachable-variant list that `rust/warrant/tests/invariants/i11_self_change_is_governed.rs:110` pins, which is a decision of its own |
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
   above). `FLOOR_ADDRESSES` is a `pub const` of typed `Ipv4Addr` values **and is the list the
   matcher reads.** *(Corrected. `5e1b5a5` shipped it as a `pub` list of strings "retained as
   documentation" beside a private typed `FLOOR_V4` that did the matching. Nothing in the workspace
   read the public list, so an address added to the documented list was not refused, and the whole
   suite stayed green when it was emptied to `&[]` — the exact "two matchers waiting to disagree"
   defect this module's thesis names. There is now one list, and
   `every_address_on_the_public_list_is_actually_refused` fails if emptying it stops mattering.)*
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
7. **`FLOOR_FORMAT` is deleted, not shipped.** `5e1b5a5` added
   `pub const FLOOR_FORMAT: &str = "warrantor.egress-hard-deny/1"` documented as *"the identifier
   this floor's records carry, so a stored verdict names the rule that produced it."* No record
   carries it: `grep -rn FLOOR_FORMAT` over the whole repository returned exactly one hit, its own
   definition. `FloorVerdict` has no format field, `egress-filter`'s `Decision` has none, and
   `EgressVerdict::Deny` carries only a reason. In this repository a `*_FORMAT` const elsewhere **is**
   stamped into the record it names (`"warrantor.wiring-coverage/1"` in
   `evidence/wiring-coverage.json`), so a reviewer reading it would reasonably conclude floor verdicts
   are recorded under that tag. None are recorded at all. The const was never released — `hard_deny.rs`
   is new on this branch — so removing it breaks no published API.
8. **Step 4(b)'s source gate is renamed and its token list extended.** It is now
   `the_floor_module_contains_no_enumerated_amendment_channel`, not
   `the_floor_module_accepts_no_configuration_value_of_any_kind`: the old name asserted more than the
   test can check. Thirteen tokens for *ambient* state were added (`std::env`, `env::var`, `set_var`,
   `static mut`, `AtomicBool`, `AtomicUsize`, `OnceLock`, `OnceCell`, `lazy_static`, `thread_local`,
   `RefCell`, `Mutex`, `RwLock`) after a review shipped a non-parameter amendment past the original
   eleven. `"static "` is deliberately **not** forbidden: `&'static str` contains it, so the token
   would fire on `FloorReason::as_str`. A second control was added that asserts the token list still
   catches the demonstrated amendment, so the denylist cannot be quietly narrowed either.
9. **Step 4(a)'s behavioral half is delivered here, and was missing from `5e1b5a5`.** The plan asked
   for a test driving a deliberately over-broad `WarrantBounds` through
   `EgressBroker::for_bounds(&bounds).decide(host)`. No test `5e1b5a5` added touched that path — both
   new files exercised `warrantor_egress::decide` against a hand-built catalog, and
   `hard_deny_fail_closed.rs` only *mentioned* `for_bounds` in a comment — and the omission was not in
   the disclosed deviations. `rust/warrant/tests/egress.rs` now carries it over 17 spellings, plus the
   unparseable half over 4 and an allowed control over 7.
10. **Every hole test asserts the `DecisionReason`, not just `Action::Deny`.** The plan warned that
    `DefaultDeny` would be a false pass; `5e1b5a5` asserted only the action and did not disclose
    dropping the reason requirement. It was load-bearing, not theoretical — see *Corrections*.

---

## Gate output, verbatim, with exit codes captured before any pipe

```
$ cargo fmt --check
                                                                    exit 0

$ cargo clippy --all-targets -- -D warnings
                                                                    exit 0

$ cargo test --workspace -j 2 > test.log 2>&1; echo $?
0
  141 suites, 1465 passing, 0 failed, 23 ignored
  (baseline on local main at f99af94: 139 suites, 1435 passing, 0 failed, 23 ignored
   -> +2 suites: rust/egress-filter/tests/hard_deny_floor.rs and
      rust/egress/tests/hard_deny_fail_closed.rs; +30 tests; ignored UNCHANGED at 23,
      which is correct: no invariant test moved from ignored to passing)
  (5e1b5a5 measured 1456 passing. The review-fix commit adds 9: five in
   rust/egress-filter/tests/hard_deny_floor.rs -- every_hostname_on_the_public_list_is_refused_by_
   the_floor, every_address_on_the_public_list_is_actually_refused,
   the_rule_word_discriminates_between_the_ranges_it_reports,
   refuse_ip_normalizes_a_mapped_ipv6_address_for_a_third_party_caller,
   the_ipv6_analog_of_rfc_1918_is_in_the_floor_and_the_opt_out_cannot_reach_it -- and four in
   rust/warrant/tests/egress.rs --
   every_spelling_is_refused_through_the_broker_from_an_over_broad_warrant,
   an_address_shaped_bound_that_does_not_parse_fails_closed_through_the_broker,
   the_broker_still_allows_the_ordinary_bounds_a_developer_writes,
   every_refusal_sentence_is_free_of_collapsed_line_continuations. Suite count unchanged: both
   files already existed. No test was deleted, no assertion was removed or weakened, and no
   #[ignore] was added or removed.)

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

### US-English check — the honest scope, and why the earlier block was wrong

`5e1b5a5` recorded this gate over **seven** files and reported `7 file(s) - 0 finding(s)`, exit 0. The
seven omitted two files the commit modified, and **both fail** — one of them on a line the branch
itself added. The reported exit 0 was true only of the subset that excluded the failures. The block
was also labeled *verbatim* while being reformatted: the tool prints a filename, then an indented
result on the next line, with an em-dash and a middot separator; the old block rendered one padded
hyphenated line per file. Below is the tool's own output shape, over **every** modified source file.

The one Britishism this branch introduced — `analogue` at `rust/egress-filter/src/lib.rs:248` — is
fixed to `analog`. The remaining 19 findings are **pre-existing**, verified by running the checker
against `f99af94`, and are not this branch's to sweep up. `forwards` is a known false positive.

```
$ node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" \
    rust/egress-filter/src/hard_deny.rs rust/egress-filter/src/lib.rs \
    rust/egress-filter/tests/hard_deny_floor.rs rust/egress/src/lib.rs \
    rust/egress/tests/hard_deny_fail_closed.rs rust/egress/tests/metadata_floor.rs \
    rust/warrant/src/egress.rs rust/warrant/tests/egress.rs \
    rust/egress/Cargo.toml README.md

rust/egress-filter/src/hard_deny.rs
  PASS — 0 Britishisms outside the carve-outs

rust/egress-filter/src/lib.rs
  FAIL — 15 Britishism(s):
    line   47  defence -> defense
    line  104  normalised -> normalized
    line  108  normalisation -> normalization
    line  123  normalisation -> normalization
    line  124  normalisation -> normalization
    line  134  normalised -> normalized
    line  378  normalised -> normalized
    line  388  normalised -> normalized
    line  490  normalised -> normalized
    line  544  normalisation -> normalization
    line  547  normalises -> normalizes
    line  598  normalisation -> normalization
    line  638  normalised -> normalized
    line  663  defence -> defense
    line  799  normalised -> normalized
  SKIPPED 1 inside carve-outs (quote/proper noun/code) — review, do not auto-fix:
    line  986  unnormalisable

rust/egress-filter/tests/hard_deny_floor.rs
  PASS — 0 Britishisms outside the carve-outs

rust/egress/src/lib.rs
  PASS — 0 Britishisms outside the carve-outs

rust/egress/tests/hard_deny_fail_closed.rs
  PASS — 0 Britishisms outside the carve-outs

rust/egress/tests/metadata_floor.rs
  PASS — 0 Britishisms outside the carve-outs

rust/warrant/src/egress.rs
  FAIL — 2 Britishism(s):
    line  355  backwards -> backward
    line  355  forwards -> forward

rust/warrant/tests/egress.rs
  FAIL — 2 Britishism(s):
    line  670  behaviour -> behavior
    line  716  forwards -> forward

rust/egress/Cargo.toml
  PASS — 0 Britishisms outside the carve-outs

README.md
  PASS — 0 Britishisms outside the carve-outs

10 file(s) · 19 finding(s) · 1 protected by carve-outs
                                                                    exit 1
```

Full output read per file, not the last line. Every one of the 19 is present on `f99af94`:

```
$ git show f99af94:rust/egress-filter/src/lib.rs | node <checker> -   # 15, same lines
$ git show f99af94:rust/warrant/src/egress.rs   | grep -c 'precisely backwards'      -> 1
$ git show f99af94:rust/warrant/tests/egress.rs | grep -cE 'behaviour|it forwards'   -> 2
```

`docs/task-evidence/task-7.1.md` passes the gate; it is checked separately because it is prose rather
than a modified source file.

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
   resolves into `169.254.0.0/16`, `fe80::/10`, **IPv6 unique-local `fc00::/7`** or
   `100.100.100.200` reaches `NotRefused`, because the floor does not resolve DNS and the broker
   deliberately does not either. A single CNAME to a metadata address defeats the address half
   entirely. *(`fc00::/7` was missing from this list, and from every other enumeration in this file,
   until an adversarial review found it. See Correction 1.)*
5. **It does not prove the floor cannot be amended, and the source gate is weaker than this file
   previously claimed.** *(Rewritten.)* The earlier text read: *"The source gate raises the cost of a
   quiet amendment from 'add a parameter' to 'delete an assertion and explain it in review'."* That is
   false. Two amendments pass every assertion with nothing deleted and nothing to explain:
   - inserting `if std::env::var("WARRANTOR_FLOOR_OFF").is_ok() { return FloorVerdict::NotRefused; }`
     as the first statement of `refuse`/`refuse_ip` — no parameter, both pinned signatures byte-for-
     byte, none of the original eleven forbidden tokens present;
   - adding a **new** public entry point `pub fn refuse_with(literal: &str, floor_enabled:
     Option<bool>) -> FloorVerdict`, which the gate cannot see because the verbatim pins cover only
     `refuse` and `refuse_ip`, and `": Option<bool>"` does not contain the substring `": bool"`.

   The first was run: all 64 tests in the two crates stayed green, and `WARRANTOR_FLOOR_OFF=1` then
   turned 9 red, so the switch reached the shipping path. The ambient tokens are enumerated now and
   the gate fires on that edit, but a gate built from a token list can only ever catch the channels on
   the list. The cost of a quiet amendment is **lower** than "delete an assertion", and the guarantee
   class L4-25 asks for (**OS-bound**) is still not what this is.
6. **It does not give `DenyReason::PrivateRange` a mechanism**, so *"private ranges denied unless
   explicitly catalogued"* still has none, and a catalogued RFC-1918 address is still allowed.
7. **The 17-address agreement corpus is a regression test, not a proof of equivalence.** The two
   crates now share one matcher, so agreement is structural rather than coincidental — but the test
   would not catch a future divergence introduced outside `hard_deny`.
8. **The five-path count is a count of paths a probe found, not a proof that there are no others.**
   It was derived by enumerating `Policy`'s public constructors and both decision entry points. A
   path through some other public API of `warrantor-egress-filter` that this probe did not
   enumerate would not have appeared.
9. **`enforcement_mode` is still `"advisory"`** at `rust/warrant/src/egress.rs:241`, and this
   branch does not change that word. It is the correct word. *(The line number read `:232` here and
   in the tier table until a review checked it. On `5e1b5a5` `:232` was
   `logical_endpoint: destination.to_string(),` — four lines above the word the sentence is about, on
   that commit and on `f99af94` alike; the assignment was at `:236`. This commit's own edit to that
   file's module doc moved it again, to `:241`, which is why the number above is `:241` and not the
   `:236` the review reported. Re-derived by grepping for the assignment, not by counting.)*
10. **It does not put `warrantor-egress-filter`'s advertised capability into the product.** The
    census rose from `10 of 40` to `11 of 40` because **the 374 lines of new code `5e1b5a5` added (409 after this
    commit) were placed inside an orphan crate**, not because an orphaned capability was wired up. `Policy`, `PolicyBuilder` and all
    three `decide_*` entry points — what the crate's own manifest description calls the *"R7 — eBPF
    egress enforcement core … policy decision"* — are called by nothing in the product. The only
    cross-crate import of the crate anywhere is `hard_deny`. `README.md:196` now says the census counts
    crates rather than capabilities, and `rust/egress/Cargo.toml` carries the same caveat beside the
    edge.
11. **It does not give an operator the rule word that fired.** `warrantor_egress::decide` maps every
    floor refusal except `AddressShapedButUnparseable` to `DenyReason::MetadataRange`, so a link-local
    or unique-local destination is refused to the operator as a *metadata range*. Recorded in the
    variant's own doc, in the mapping site, and in the tier table; deliberately not fixed here.
12. **It does not make the floor's non-amendability provable, only harder to withdraw silently.**
    The gate reads one file's text with comments stripped. It cannot see a change in
    `rust/egress-filter/src/lib.rs` that stops calling the floor (a separate ordering gate covers the
    `decide_ip` case only), it cannot see a dependency substituted at the workspace level, and it
    cannot see a channel nobody has enumerated.
13. **Two collapsed line continuations remain in `rust/egress/tests/metadata_floor.rs` (lines 158 and
    163) and are not this branch's to fix.** They are inside the `PrivateRange` pin body, which this
    branch asserts is byte-for-byte unchanged, and they are present identically on `f99af94`. Editing
    them would falsify that claim. Named here so a later task picks them up. The
    `reason_phrase` family — the sentences an operator and an agent actually read — is now gated by
    `every_refusal_sentence_is_free_of_collapsed_line_continuations`.

---

## Corrections after adversarial review

Three review lenses — evidence-truth, claim-honesty and test-rigor — each set `refuted=true` on
`5e1b5a5`, with 22 findings between them. Every finding carried a command; every command was rerun
here before anything was changed. Twenty-one reproduced and were fixed; one did not and is disputed
below with counter-evidence.

The mechanism was sound in all three reviews. No live security defect was found, no mutation got past
the floor, and the census, ratchet and ledger numbers all reproduced exactly. What was wrong was what
the branch **said about itself** — which is the failure mode this project has now recorded four times.

### 1. The floor unamendably refuses IPv6 unique-local `fc00::/7`, and this file never said so

**Claimed.** *"Any other name that resolves into 169.254.0.0/16, fe80::/10 or 100.100.100.200 reaches
NotRefused"* (non-establishment 4); the tier table bounded the claim as *"metadata service and
link-local addresses"*; `hard_deny_floor.rs:208` (at `5e1b5a5`) asserted *"the floor covers the metadata service and
link-local ranges, not RFC-1918"*; the `PrivateRange` section said *"L4-25 names the metadata service
and link-local addresses, not RFC-1918. Widening the floor to 10/8 is not this task."*

**True.** `hard_deny.rs` returns `FloorVerdict::Refused(FloorReason::UniqueLocal)` for
`(head & 0xfe00) == 0xfc00`, and the floor is consulted in `decide_ip` **before** the
`deny_private_egress` check, so `deny_private_egress(false)` cannot opt out of it. `fc00::/7` is the
IPv6 analog of RFC-1918. So the branch left the IPv4 half of "private ranges" to a flag an operator
can turn off while making the IPv6 half non-negotiable — and said nothing. A case-insensitive count of
`fc00`, `fd00` and `unique-local` over this file returned **0**.

**It is a behavior change from base, not a restatement.** Measured with a compiled probe on both
commits, in a detached worktree at `f99af94` with its own `CARGO_TARGET_DIR`:

```
f99af94   struct-literal + allowlist + deny_private_egress(false), fd12:3456:789a::1
            -> Allow / Allowlisted
          PolicyBuilder::new() + deny_private_egress(false) + allow_ip, same address
            -> Allow / Allowlisted

5e1b5a5   both of the above
            -> Deny / HardDenyFloor { rule: "unique_local" }
          control, 93.184.216.34 allowlisted on the same policy
            -> Allow / Allowlisted   (both commits)
```

On the shipping path it is worse: `rust/egress/src/lib.rs:238` maps every non-`AddressShaped`
refusal to `DenyReason::MetadataRange`, so a catalogued `fc00::/7` address a warrant legitimately
names is refused to the operator as a *metadata range*.

**Changed.** The range is now named in the module doc (with the before/after verdicts and the
`deny_private_egress` asymmetry stated as a deliberate decision), in the tier-table bound, in
non-establishment 4, in the `PrivateRange` pin's own doc, and in
`PolicyBuilder::deny_private_egress`'s doc, which still described `false` as permitting egress to
link-local addresses and was left stale by `5e1b5a5`. The RFC-1918 control is renamed
`the_floor_leaves_ipv4_private_ranges_to_the_policy_that_already_governs_it`, and a new paired test —
`the_ipv6_analog_of_rfc_1918_is_in_the_floor_and_the_opt_out_cannot_reach_it` — asserts the
`unique_local` refusal against an allowlisted, fully opted-out policy, with the IPv4 opt-out still
reaching Allow as its control. The `MetadataRange` collapse is documented in three places and left
unfixed, with the reason, as non-establishment 11.

### 2. `enforcement_mode` is at line 236, not 232

Cited as `:232` twice — the tier table's Tier B row and non-establishment 9 — on this branch and on
`f99af94` alike, so a wrong number recorded twice rather than a post-edit shift. Line 232 is
`logical_endpoint: destination.to_string(),`. The load-bearing sentence of the whole Tier B claim
pointed four lines above the word it is about. Both citations now read `:241`, re-derived by grepping
for the assignment rather than by counting. `:236` was correct on `5e1b5a5`; this commit's own
five-line addition to that file's module doc moved the assignment down five lines, which is exactly
the drift that produced the original defect and is why the number was re-measured after the last edit
rather than copied from the review.

### 3. The newly shipped operator-facing refusal sentence was mangled

`reason_phrase(DenyReason::UnparseableAddress)` was written as one long line with the line
continuation every neighboring arm uses collapsed into **14 literal spaces**, so the text an operator
reads through `render_decision` and an agent reads through `EgressRefusal::sentence()` was *"…so the
floor cannot              classify it and refuses rather than guess"*. `cargo fmt` does not reformat
string interiors and clippy has no lint for it, so both gates passed at exit 0.

Fixed with a real continuation, and the **class** is now gated:
`every_refusal_sentence_is_free_of_collapsed_line_continuations` asserts no `reason_phrase` output
contains a run of consecutive spaces, over all eleven variants, with a control proving the check can
see one. Reintroducing the original literal turns that test red — run and verified, then restored.
The same artifact appeared in five places in `hard_deny_floor.rs`'s own assertion messages (at
`5e1b5a5`: lines 251, 264, 286 twice, 305) — the text that would be read when the gate fires — and all are fixed. Two remain
in `metadata_floor.rs` and are not this branch's; see non-establishment 13.

### 4. `FLOOR_ADDRESSES` and `FLOOR_FORMAT` were both inert while documented as the mechanism

This is the Task-1.1 shape from earlier this week, shipped twice in one module whose stated thesis is
*"Two matchers are two rules waiting to disagree."*

- `FLOOR_ADDRESSES` was a `pub` list of **strings** documented as the thing that catches
  `100.100.100.200`, beside a private `FLOOR_V4` of typed values that did the matching. Setting it to
  `&[]` left all 64 tests in the two crates green — run and verified. A maintainer adding a newly
  discovered metadata address to the only public list would have changed nothing. **Fixed by deleting
  the duplicate:** there is now one `pub const FLOOR_ADDRESSES: &[Ipv4Addr]`, it *is* the matcher, and
  `every_address_on_the_public_list_is_actually_refused` iterates it with a `NotRefused` control.
  Emptying it now turns **8** tests red across three test binaries — verified. The number was
  recorded as 6 in the first draft of this file, which is the last `test result: FAILED` line
  read instead of the whole output. The per-binary tallies are `1 failed`, `1 failed` and
  `6 failed`; only the sum is the blast radius. The same mistake is recorded in this project as
  `failure-count-is-not-failure-reason`, and this file's own US-English section had already been
  rewritten to say "full output read per file, not the last line" — so the correction is the
  rule this document states, applied to this document.
- `FLOOR_FORMAT` claimed *"the identifier this floor's records carry."* A repository-wide search
  returned exactly one hit: its own definition. No verdict, `Decision`, receipt or evidence file
  carries it. **Deleted** — see deviation 7.

### 5. The gate that exists to stop a quiet amendment could not see the channel that would make one

**Claimed.** *"Enforced, by absence — there is no parameter to pass"*, and *"the source gate raises
the cost of a quiet amendment from 'add a parameter' to 'delete an assertion and explain it in
review'."*

**True.** An amendment that adds **no parameter** defeated both halves with nothing turning red. A
process-global `static AtomicBool` plus a `std::env::var("WARRANTOR_FLOOR_OFF")` read at the head of
`refuse_ip`: both pinned signatures stayed byte-for-byte, none of the original eleven forbidden tokens
appeared, and all 64 tests in the two crates passed — including
`the_floor_module_accepts_no_configuration_value_of_any_kind`. Rerun with `WARRANTOR_FLOOR_OFF=1`, **9
tests failed** (`metadata_range_always_denied`, `every_metadata_spelling_is_refused`,
`hard_deny::tests::every_spelling_of_a_metadata_service_is_refused`,
`hard_deny::tests::link_local_and_unique_local_ranges_are_refused`, `hole_1`, `hole_2`, `hole_3`,
`hole_4`, `the_numeric_spellings_…`), proving the switch reached the shipping path. A second channel
needs no run to see: `pub fn refuse_with(literal: &str, floor_enabled: Option<bool>)` is a brand-new
public entry point taking a configuration value, and `": Option<bool>"` does not contain the forbidden
substring `": bool"` while the verbatim pins cover only `refuse` and `refuse_ip`.

**Changed, and the label with it.** Thirteen ambient tokens added (deviation 8); the test renamed to
`the_floor_module_contains_no_enumerated_amendment_channel`, because the old name asserted more than
any token list can check; a second control added that asserts the list still catches the demonstrated
amendment, so it cannot be narrowed back. Applying the mutation now fails with
`hard_deny.rs contains "std::env"` — verified. The tier row is downgraded to *"Enforced, by absence —
for parameters only"* and states what escapes; non-establishment 5 is rewritten to say the cost of a
quiet amendment is **lower** than the branch claimed, not higher.

### 6. The strongest tier label sat on an API with no shipping caller

`Policy::decide_ip` / `decide_domain` / `decide_destination` have an **empty** caller set in the whole
Rust workspace outside `warrantor-egress-filter`'s own tests. The only cross-crate import of the crate
anywhere is `hard_deny`, from `rust/egress/src/lib.rs:18`. So the census rose because the 374 lines of new code
`5e1b5a5` added (409 after this commit) were placed inside an orphan crate, not because an orphaned capability was wired up — and
*"Confined to callers of this API"* reads as a scope limit rather than as *"the set of callers is
empty."* The nine-item non-establishment list, which went as far as naming an off-by-one in the plan's
own Step 0 baseline, did not say it.

Changed: the tier row now says the caller set is empty and points at the Tier B row as what actually
protects the product; `README.md:196` says the census counts crates rather than capabilities;
`rust/egress/Cargo.toml` carries the same caveat beside the edge; new non-establishment 10. **The edge
itself is untouched and the census is unchanged at `11 of 40` over 19 path edges — the orphan count
did not rise.**

### 7. Every hole test accepted a denial that was not the floor's

The plan's Step 2 warned in advance that `DefaultDeny` would be a false pass and required asserting
the reason. `hard_deny_floor.rs` never imported `DecisionReason` and asserted only
`decision.action == Action::Deny`. The disclosed deviations admitted Step 2's ten-vector test was not
written but **not** that the reason requirement was dropped.

Load-bearing, not hypothetical. Mutating the metadata address list to a no-op left **all 11** tests
green, `hole_4` included, even though its corpus contains `100.100.100.200` — the address the module's
own doc says is caught by nothing else. A probe confirmed why: on that policy `100.100.100.200`
returns `Deny / DefaultDeny`, because `weakest_possible` allowlists only `169.254.169.254`, so two of
`hole_4`'s four spellings were decoration.

Changed: every refusal test asserts `DecisionReason::HardDenyFloor { rule }` with the expected word,
`hole_4` carries a rule per spelling, and the same mutation now turns **6** tests red — verified. The
allowed controls are unchanged and still pass in both polarities.

### 8. Four smaller items, all reproduced and fixed

- **A doc paragraph pasted twice.** `metadata_floor.rs` lines 11-22 at `5e1b5a5` carried the same five-line
  `UPDATE (Task 7.1, L4-25)` paragraph twice, differing only in *"still run through"* versus *"still
  pass through"* — in the file that carries the branch's central "one matcher, not two" argument.
  Removed, with the removal named rather than silent.
- **`FloorReason::as_str` and `HardDenyFloor { rule }` were unasserted in every direction.**
  Collapsing all four arms to `"metadata_service"` left the suite green; so did swapping the
  `LinkLocal` and `UniqueLocal` constructions. `the_rule_word_discriminates_between_the_ranges_it_reports`
  now pins all four words and the two ranges that are easiest to confuse, with a `NotRefused` control.
  Both mutations now turn 4 tests red — verified.
- **`hard_deny::normalize` was dead in every call path and untested.** Making it return its argument
  unchanged left the suite green: `Policy::decide_ip` normalizes first, and `refuse` reaches
  `refuse_ip` through `canonical_ip`, which unwraps too. A third-party caller of the `pub` API gets
  neither. `refuse_ip_normalizes_a_mapped_ipv6_address_for_a_third_party_caller` asserts the guarantee
  at the boundary that offers it, with a mapped-ordinary-address control; the mutation now turns it
  red — verified.
- **`FLOOR_HOSTNAMES`' fourth entry had no test.** Deleting `"instance-data"` left the suite green.
  `every_hostname_on_the_public_list_is_refused_by_the_floor` iterates the const rather than a copied
  corpus, so the list cannot grow a member nothing exercises; deleting the entry now turns it red —
  verified.

### Disputed: `reason_phrase` is not uncalled

**The finding.** test-rigor 7(1): *"The rendering function `egress::reason_phrase` is called by
nothing in the repository — only `reason_word` is (`warrantor.rs:4954`, `serve.rs:2383`) — and has no
test."*

**Not reproduced.** `reason_phrase` has two callers inside `rust/warrant/src/egress.rs`, and both are
reachable from a binary. Searching for the symbol across the workspace:

```
rust/warrant/src/egress.rs:430      reason_phrase(self.reason.clone()),   <- EgressRefusal::sentence()
rust/warrant/src/egress.rs:438  pub fn reason_phrase(reason: DenyReason) -> &'static str {
rust/warrant/src/egress.rs:506      reason_phrase(reason.clone())         <- render_decision()

rust/warrant/src/bin/warrantor.rs:2168   println!("{}", render_decision(host, &verdict));
rust/warrant/src/proxy.rs:174            let sentence = refusal.sentence();
```

(`reason_phrase` also exists as an unrelated private HTTP-status helper in `rust/archive/src/http.rs`
and `rust/warrant/src/serve.rs`; those are different functions and are not what the finding is about.)

The same review wave's claim-honesty finding 5 states the opposite and is correct: it drove a real
warrant through `EgressBroker::decide` to `render_decision` output. So the two lenses disagree, and
the CLI and proxy paths are real. Part **(2)** of that finding — the 14-space literal — reproduced and
is fixed (Correction 3), and the "no test" half is now also false: the sentence gate covers all eleven
variants.
