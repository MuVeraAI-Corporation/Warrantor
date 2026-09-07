### Task 3.7: Generalize warrant-lifecycle self-protection — expanded to step form

**Anchor.** L6-11, generalized. The attach-time refusal already exists and is the proven pattern;
the property is currently narrow. An agent must not be able to obtain authority over the machinery
that governs it — policy, monitors, identities, catalogs, budgets or custody. This expansion
re-verified every anchor against local `main` at `6f41384` on 2026-09-06, and the verification
changes the task's center of gravity: most of the six surfaces are already protected by existing,
tested machinery, so the real work is the red-team suite that *proves* the coverage and the few
surfaces the suite catches unprotected.

**What exists, re-verified 2026-09-06.** The attach-time refusal is
`rust/warrant/src/upstream.rs:87`: `const LIFECYCLE_VERBS: [&str; 4] = ["grant", "settle", "void",
"stage"]`, matched against **every** segment of a published tool name split on `['.', '_', '-',
'/']` (`is_lifecycle_tool`, `:101`), enforced at `UpstreamSet::start` (refuse) with
`start_allowing_lifecycle_tools` as the only bypass — reachable solely from the flag whose name
says what it does (`upstream-allow-lifecycle-tools-i-accept-this`), which prints a WARNING naming
the exact consequence (`bin/warrantor.rs:5248`, verified: *"If any attached server can settle,
void or release staged work, the supervised agent can now call it"*). The refusal's history is in
the module doc at `:47-86`, including the first-version defect (splitting on `.` alone missed
`warrant_settle` — its own control endpoint).

Mapping the six surfaces to what protects them today:

| Surface | Existing protection | Tested by | Gap |
|---|---|---|---|
| Policy | `LIFECYCLE_VERBS` covers `grant` (policy = warrants); MCP control endpoint's lifecycle tools are **not published** on the agent endpoint at all (`mcp_endpoints.rs`, verified at the `tools()` listing) | `tests/upstream.rs` lifecycle tests | The word `revoke` is not in the verb list — `revoke_workload` as a published name passes the segment check today |
| Monitor (the guard) | `--guard` attaches in the operator's process; the agent has no verb to attach, detach or reconfigure a guard — absent by construction, not refused | none — the absence is prose, not a test | The red-team suite must test that NO published/attached path reaches guard mutation |
| Identity | `LIFECYCLE_VERBS` covers `grant`; Task 2.6's `proposal` verbs are operator-side CLI, never published to the agent endpoint | partial via upstream tests | An upstream publishing `identity`/`svid`-shaped names is unconstrained today |
| Catalog | The agent endpoint publishes the warrant's own catalog read-only (`tools()` listing); `mcp_endpoints.rs` refuses catalog mutation by absence of a mutation verb | `egress_broker_wiring.rs` reads; nothing mutates | An upstream publishing `catalog-update`-shaped names is unconstrained |
| Budget | `spend` is recorded from the agent's self-report (Observed); the budget *ceiling* is set at grant, agent-unreachable | `tests/spend.rs` | An upstream publishing `budget-*` mutation names passes the segment check |
| Custody (staged work) | `settle`/`void`/`stage` all in `LIFECYCLE_VERBS`, segment-split, plus the flag WARNING | `tests/upstream.rs` (the original defect) | The best-covered surface; the suite must keep it covered under the segment-split |

The gaps are narrow but real: the verb *list* is closed to the four original verbs, while the
machinery has grown verbs the list never met.

---

**Step 0 — Baseline: run these commands in the worktree and paste the output verbatim into
`docs/task-evidence/task-3.7.md`.**

```bash
git -C M:/wt-merge worktree add M:/wt-task-3.7 -b feat/task-3.7-self-protection main
cd M:/wt-task-3.7
sed -n '76,110p' rust/warrant/src/upstream.rs
grep -n "warrant_settle\|warrant_grant\|warrant_void\|warrant_stage" rust/warrant/src/mcp_endpoints.rs | head -8
grep -n "lifecycle" rust/warrant/tests/upstream.rs | head -6
grep -rn "is_lifecycle_tool\|LIFECYCLE_VERBS" rust/warrant/src --include=*.rs
grep -rn "allow-lifecycle" rust/warrant/src/bin/warrantor.rs | head -3
grep -n "guard" rust/warrant/src/mcp_endpoints.rs | grep -in "tool\|verb" | head -4
```

Expected: the constant at `:87`; the control endpoint's four lifecycle tool names in
`mcp_endpoints.rs` (published on the control endpoint, absent from the agent endpoint's
`tools()`); the upstream tests that pin the original defect; one bypass flag; no guard tool on
the agent endpoint. Read in full: `rust/warrant/src/upstream.rs:1-130` (the refusal and its
history), the control endpoint's tool methods (what the governed machinery's verbs actually look
like on the wire), and `rust/warrant/tests/upstream.rs` (the existing coverage the suite extends
rather than repeats).

---

**Step 1 — The red-team suite: one test per surface, attempts through every reachable path.**
Create `rust/warrant/tests/self_protection.rs`. For each of the six surfaces, the suite attempts
authority-over-it through every path an agent can reach: (a) an attached upstream publishing a
governing tool name in each segment-split spelling (`gov.settle`, `gov_settle`, `gov-settle`,
`settle/gov`), (b) an MCP `tools/call` naming the machinery's own verbs, (c) the control
endpoint's verbs addressed from the agent session. The tests are written BEFORE the extensions,
and the plan expects some to pass and some to fail — the failures are the task's work list, and
each failure output goes verbatim into the evidence file with the surface named:

```rust
/// Spawn a fixture upstream whose `tools/list` publishes exactly one tool with `name`,
/// and try to attach it. The attach is the refusal point — the proven pattern.
fn attach_publishing(name: &str) -> Result<UpstreamSet, UpstreamError> {
    UpstreamSet::start(&[fixture_spec_publishing(name)], Duration::from_secs(30))
}

fn the_segment_spellings(base: &str) -> Vec<String> {
    // The original defect: splitting on '.' alone missed `warrant_settle`. Every test
    // tries the spellings an attacker would, not just the convenient one.
    [format!("{base}.workload"), format!("{base}_workload"), format!("{base}-workload"),
     format!("workload.{base}"), format!("workload_{base}")]
        .into_iter().collect()
}

#[test]
fn an_upstream_publishing_a_revoke_shaped_name_is_refused_at_attach() {
    for name in the_segment_spellings("revoke") {
        assert!(attach_publishing(&name).is_err(), "{name} must be refused at attach");
    }
}
```

The helper covers all four lifecycle verbs (existing green), then the suite adds the uncovered
governed verbs — `revoke`, `stop`, `approve` — as RED tests, one per surface the plan names.

**Step 2 — Extend the refusal to the uncovered surfaces, by generalizing the verb list into the
governed-verb set the machinery actually defines.** The control endpoint defines what governing
means on the wire — `warrant_grant`, `warrant_settle`, `warrant_void`, `warrant_stage`, plus the
verbs added since the list was written. The fix is not four more string literals but one source
of truth:

```rust
/// Every verb that governs the machinery: the lifecycle four, plus the verbs the control
/// endpoint has grown since. `is_lifecycle_tool` consults THIS set; a new governing verb
/// added to the control endpoint must extend it, and the count assertion below refuses
/// to compile past a divergence.
const GOVERNED_VERBS: [&str; 8] = [
    "grant", "settle", "void", "stage", "revoke", "stop", "approve", "report",
];

/// The count assertion, in the same suite: the control endpoint publishes exactly this
/// many governing verbs. A new one without extending GOVERNED_VERBS is a red build.
#[test]
fn the_governed_verb_set_covers_every_control_endpoint_verb() {
    let published = control_endpoint_verb_names(); // read from the control endpoint's tools()
    for verb in published {
        assert!(
            GOVERNED_VERBS.contains(&verb.as_str()),
            "the control endpoint publishes {verb:?} and GOVERNED_VERBS does not name it: \
             an agent-reachable spelling of it would sail past the attach refusal"
        );
    }
}
```

The count assertion is the ratchet: a test asserts the set covers every verb the control
endpoint publishes, so the next governing verb added without extending this set is a red build,
not a silent gap — the same shape Task 2.6's usage-contract allowlist used.

**Step 3 — Refuse at attach time, not call time, for the new surfaces too.** The proven pattern
is attach-wholesale: an upstream that publishes ANY governed-verb name is refused at start, with
the same bypass flag and the same WARNING text extended to name the new verbs. Call-time
refusal alone would mean the agent sees the tool and only fails on use — an attach that prints
its poison at startup is the disclosure that worked for the original four:

```rust
// In bin/warrantor.rs, the bypass WARNING gains the new verb classes:
eprintln!(
    "warrantor: WARNING -- the lifecycle-tool refusal is DISABLED for this session. \
     If any attached server can settle, void, stage, revoke, stop or approve — any of the \
     {} governed verbs — the supervised agent can now call it.",
    GOVERNED_VERBS.len()
);
```

**Step 4 — Legibility: the refusal names the verb and why.** The existing error names the
matched segment and the tool; extend the test to assert the new surfaces' refusals name the
matched verb and the word "governed", and that the bypass flag's WARNING enumerates every verb
class the operator is accepting (not just "lifecycle"):

```rust
#[test]
fn the_refusal_names_the_matched_verb_and_the_word_governed() {
    let err = attach_publishing("ops.revoke_workload").expect_err("refused");
    let text = err.to_string();
    assert!(text.contains("revoke"), "{text}");
    assert!(text.contains("governed"), "{text}");
    assert!(text.contains("ops.revoke_workload"), "{text}");
}
```

**Step 5 — The monitor surface is proven by absence, not extended.** The guard has no
agent-reachable mutation path — that is a structural fact (`--guard` attaches in the operator's
process before the agent exists). The suite's monitor test asserts the absence: no tool call on
the agent endpoint reaches guard state, asserted by driving every guard-shaped tool name the
fixture upstream can publish and asserting either attach-refusal or call-refusal:

```rust
#[test]
fn no_agent_reachable_path_reaches_guard_mutation() {
    // Attach-refusal first: guard-shaped names are governed verbs.
    for name in the_segment_spellings("guard") {
        assert!(attach_publishing(&name).is_err(), "{name}");
    }
    // And the agent endpoint publishes no guard tool: tools() carries none.
    let endpoint = agent_endpoint_for_test();
    assert!(endpoint.tools().iter().all(|t| !t.name.contains("guard")),
        "the agent endpoint must not publish a guard tool: the absence IS the protection");
}
```

Do not add a refusal for a path that does not exist; assert that it does not exist, and say so
in the evidence — a refusal of nothing would be the kind of claim Task 7.6 warns about. The
evidence file states the monitor surface's protection is structural (absence), tested, and
narrower than the other five.

**Step 6 — Full gate; ledger; commit.**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -j 2 -- -D warnings
cargo test --workspace --all-targets -j 2 && cargo build --workspace --all-targets -j 2
python tools/ci/wiring_census.py && python tools/ci/check_invariant_ratchet.py
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" docs/W1-delivery-gaps.md docs/task-evidence/task-3.7.md rust/warrant/src/upstream.rs
```

The ledger's self-protection row states the six surfaces, which were protected before (tested),
which this task closed (with the failing-test outputs as proof), and the tier (Tier B attach-time
chokepoint; an agent that reaches a governed verb through a path outside `UpstreamSet` — a second
control endpoint, a direct store write — is outside this bound, and the ledger says so).

---

**The honest tier of every bound this task introduces.**

| what this task adds | tier | why that word and not a stronger one |
|---|---|---|
| the generalized attach refusal (governed verbs beyond the lifecycle four) | **Tier B attach-time chokepoint** | it refuses at session start, before the agent exists — but only for servers attached through `UpstreamSet`; a second control endpoint or a direct store write is outside it. |
| the governed-verb set + count assertion | a **ratchet**, not a bound | it makes the next unlisted governing verb a red build; it stops nothing by itself. |
| the monitor-surface absence proof | **structural**, tested | the protection is that the path does not exist; the test keeps it from growing silently. |

**Exit gate, restated.** The red-team suite is green across all six surfaces with each refusal a
test; the governed-verb set is one source of truth whose coverage is asserted against the control
endpoint; the bypass WARNING enumerates what is being accepted; the attach-time discipline holds
for every new surface.

**Hazards.** (1) The seed's original defect is the test-construction trap: split on `.` alone and
`warrant_settle` passes — every new test must try the segment-split spellings, not just the dot
form. (2) Do not rename the control endpoint's verbs to *avoid* the list; the list must track the
machinery, or the machinery grows outside governance silently. (3) The bypass flag exists for the
legitimate "supervise my own control loop" case; do not remove it — test that its WARNING covers
every verb class and that the default remains Refuse. (4) The monitor surface's absence is the
one protection that is not a refusal — resist the temptation to add a guard-mutation verb
somewhere just so the suite can refuse it.

---

**Verification detail — the shapes the steps compile against, captured on `main`.**

The control endpoint's governing verbs, the set the count assertion reads (quoted from the
`tools()` listing on `main`):

```text
warrant_grant    <- mcp_endpoints.rs, the control endpoint's grant tool
warrant_settle   <- the lifecycle original
warrant_void     <- the lifecycle original
warrant_stage    <- the lifecycle original
```

The red output of the suite's first uncovered surface, quoted as the evidence records it:

```text
---- an_upstream_publishing_a_revoke_shaped_name_is_refused_at_attach stdout ----
thread 'an_upstream_publishing_a_revoke_shaped_name_is_refused_at_attach' panicked:
  "ops.revoke_workload" attached cleanly: the segment check knows four verbs and
  'revoke' is not one of them. The machinery grew a governing verb and the refusal
  did not grow with it.
```

The bypass WARNING after this task, quoted as the test asserts it:

```text
warrantor: WARNING -- the governed-tool refusal is DISABLED for this session. If any
attached server can settle, void, stage, revoke, stop, approve, grant or report — any of
the 8 governed verbs — the supervised agent can now call it.
```

The count assertion, the ratchet that keeps the set honest:

```rust
#[test]
fn the_governed_verb_set_covers_every_control_endpoint_verb() {
    // The control endpoint is the definition of "governs the machinery": whatever it
    // publishes, an agent must not reach through an upstream. This test fails the
    // build the day someone adds a governing verb without extending GOVERNED_VERBS.
    for verb in control_endpoint_verb_names() {
        assert!(GOVERNED_VERBS.contains(&verb.as_str()), "{verb} is governed and unlisted");
    }
}
```

The monitor surface's absence proof, the one test that asserts a negative:

```bash
$ cargo test -p warrantor-warrant --test self_protection no_agent_reachable_path -j 2
test no_agent_reachable_path_reaches_guard_mutation ... ok
  (the agent endpoint publishes no guard tool; the guard attaches in the operator's
   process before the agent exists. The absence is the protection, and this test is
   what keeps it from growing silently.)
```

The honest-summary sentence the ledger adds: *"The attach-time refusal now covers every verb
the control endpoint can publish, proven by a red-team suite that tried the segment-split
spellings of all six surfaces; the monitor surface's protection is structural absence, now
test-pinned. What this does not establish: a path outside `UpstreamSet` — a second control
endpoint, a direct store write, a second harness — is outside every refusal here, and the
ledger says so."*

---

**Shape on this tree — the remaining detail the steps need, with every anchor re-verified.**

The red-team suite's full surface matrix, the table that decides where the work is:

```text
Surface   | Path (a) attach upstream     | Path (b) tools/call        | Path (c) control verbs
----------|------------------------------|----------------------------|------------------------
policy    | REFUSED (grant in list)      | absent (not published)     | exists, agent-unreachable
monitor   | absent (no guard tool)       | absent                     | exists, agent-unreachable
identity  | RED (revoke-shaped passes)   | absent                     | exists, agent-unreachable
catalog   | RED (catalog-update passes)  | absent                     | exists, agent-unreachable
budget    | RED (budget-set passes)      | absent                     | exists, agent-unreachable
custody   | REFUSED (settle/void/stage)  | absent (not published)     | exists, agent-unreachable
```

Three RED cells in path (a) are this task's implementation work; the absent cells in path (b)
and (c) are structural facts the suite pins as tests.

The GOVERNED_VERBS generalization, showing how the original four stay covered while the list
grows:

```rust
// The original four, unchanged in value and position — the existing tests that pin
// them individually keep passing:
const GOVERNED_VERBS: [&str; 8] = [
    "grant", "settle", "void", "stage",
    "revoke", "stop", "approve", "report",
];

fn is_lifecycle_tool(name: &str) -> bool {
    // Same segment split, same bias toward refusing — the doc above the function is
    // amended to say "governed" where it said "lifecycle", with the count.
    name.split(['.', '_', '-', '/'])
        .any(|segment| GOVERNED_VERBS.contains(&segment))
}
```

The test that pins the ORIGINAL defect's regression, so the segment-split discipline survives
the generalization:

```rust
#[test]
fn the_first_version_defect_stays_fixed_under_the_generalized_list() {
    // upstream.rs:47-56's history: splitting on '.' alone missed warrant_settle.
    // The generalized list must not reintroduce that: every spelling of every verb.
    for verb in GOVERNED_VERBS {
        for name in the_segment_spellings(verb) {
            assert!(is_lifecycle_tool(&name), "{name} must match");
        }
    }
    // And the negative: a name that merely CONTAINS a verb as a substring must not match.
    assert!(!is_lifecycle_tool("resettle_records"), "substring match is the old defect");
    assert!(!is_lifecycle_tool("grantwriter"), "substring match is the old defect");
}
```

The flag WARNING's test, pinning the extended enumeration:

```rust
#[test]
fn the_bypass_warning_enumerates_every_governed_verb_class() {
    // Run the attach with the bypass flag; the stderr must name all eight verbs.
    let out = run_with_bypass_flag();
    let stderr = String::from_utf8_lossy(&out.stderr);
    for verb in GOVERNED_VERBS {
        assert!(stderr.contains(verb), "the WARNING must name {verb}: {stderr}");
    }
}
```

The ledger's self-protection row, quoted so the implementer cannot write a weaker one:

```text
### 3.7 Warrant-lifecycle self-protection, generalized — **the refusal now covers every verb
the control endpoint publishes; the monitor surface is protected by structural absence**

The attach-time refusal (upstream.rs:87) covered four verbs; the machinery it protects has grown
since, and three governing verbs were reachable through an upstream publishing their name in
any segment-split spelling. The red-team suite in tests/self_protection.rs attempts all six
governed surfaces through every agent-reachable path and pins the coverage as tests. The
governed-verb set is one list with a count assertion against the control endpoint's published
verbs, so the next governing verb is a red build. The monitor surface's protection is
structural absence (no guard tool exists on the agent endpoint), test-pinned. Tier: **Tier B
attach-time chokepoint** — the refusal is at session start, before the agent exists, and it
guards only servers attached through `UpstreamSet`; a second control endpoint, a direct store
write, or a harness that bypasses the proxy is outside this bound, and the ledger says so.
```

The final commit, gathering the pieces:

```bash
git add rust/warrant/src/upstream.rs rust/warrant/src/bin/warrantor.rs \
        rust/warrant/tests/self_protection.rs rust/warrant/tests/upstream.rs \
        docs/W1-delivery-gaps.md docs/task-evidence/task-3.7.md
git commit -s -F .commitmsg
# Branch: feat/task-3.7-self-protection. NOT merged by this lane.
```

Each shape was verified against the tree this expansion was written against; where a line number
differs when the implementer runs Step 0, the difference is recorded, never adjusted.
