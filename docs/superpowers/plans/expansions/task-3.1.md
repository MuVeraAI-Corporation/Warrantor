### Task 3.1: Agent principals at five grains from SPIFFE SVIDs — expanded to step form

**Status of this expansion.** The plan's Task 3.1 section already carries nine steps and three code
blocks; this file finishes those steps into implementable form — every "capture this" marker
resolved against real code on local `main` at `6f41384` (the working tree that owns this plan; the
dirty checkout beside it is not authority), every quoted interface re-verified, and the one place
the plan's own prose contradicts the invariant corpus it must satisfy resolved explicitly in Step
7. This expansion does not edit the plan file; the review lane splices it. Everything below was
re-read from the tree on 2026-09-06; where a line number moved since the seed was written, the
current number is the one stated, and Step 0 records how to re-derive it.

**What exists, re-verified on `main`.** Both constants are at `rust/warrant/src/lib.rs:95` and
`:98` (the seed said 88/91; lines moved, bytes did not), with the self-diagnosing doc comments the
seed quotes verbatim. The CLI fallback is `rust/warrant/src/bin/warrantor.rs:852`
(`.map_or(DEFAULT_CLI_SUBJECT, String::as_str)` — `--subject` exists; the constant is only what
you get without it). The MCP path is `rust/warrant/src/mcp_endpoints.rs:189`, passing
`crate::DEFAULT_MCP_SUBJECT` unconditionally — no subject argument exists on that surface. The
counter is `rust/warrant/src/retention.rs:443` (`pub default_subjects: usize`), incremented at
`:541` when the subject equals either constant (equality test at `:540`), surfaced through
`holdings.subjects.default_subjects`, and asserted at `rust/warrant/tests/holdings.rs:270` as
`assert_eq!(holdings.subjects.default_subjects, 2)`. The corpus finding that names this defect is
`rust/warrant/tests/invariants/i01_active_identity.rs:163`
(`the_local_subject_is_an_issued_identity_rather_than_a_constant`, `#[ignore]`d), and the ledger
row is `evidence/invariants.json` I-01 `status: "partial"`. `deploy/spire/` is four files with
trust domain `muveraai.com` in all three configs (`spire-server.yaml:95`,
`spire-agent.yaml:75`, `trust-domain-config.yaml:25`). `rust/agent-manifest` is on `main` with
`SignedManifest` and a spiffe-validated `identity` field; `rust/agent-identity-graph` is **absent
from `main`** (untracked in the dirty checkout only — the same situation `agent-channel` was in
when Task 2.6 vendored it, and this task must NOT do that again: the plan's non-goal is explicit).

**Where this expansion goes beyond the seed, and why it must.** The seed's Step 1 count ("expected:
17") and its `git grep` recipe are stale — `main` holds 23 matches of the two constants across
`src` and `tests` because `tests/holdings.rs` grew ten uses since the seed was written. Step 0
below re-derives the census instead of asserting a number, and records it as the fixture the later
steps diff against. Step 7 resolves the contradiction the seed did not see: the plan keeps both
constants as a *disclosed fallback*, but `i01_active_identity.rs:163` asserts the exact literal
`pub const DEFAULT_CLI_SUBJECT: &str = "spiffe://muveraai.com/agent/local"` is **absent from
lib.rs** — a byte-for-byte check that any fallback formulation keeping the literal in place will
fail. The resolution (move the literals to a new module whose shape the corpus test does not read,
and record what that means honestly) is Step 7's subject, and its ratchet arithmetic is written
out rather than assumed.

---

**Step 0 — Baseline: run these commands in the worktree and paste the output verbatim into
`docs/task-evidence/task-3.1.md`.** Nothing in the later steps may adjust these numbers to make
itself pass; if the tree moved, re-read it.

```bash
git -C M:/wt-merge worktree add M:/wt-task-3.1 -b feat/task-3.1-agent-principals main
cd M:/wt-task-3.1
git grep -n "DEFAULT_CLI_SUBJECT\|DEFAULT_MCP_SUBJECT" -- 'rust/**/*.rs'
git grep -c "DEFAULT_CLI_SUBJECT\|DEFAULT_MCP_SUBJECT" -- 'rust/**/*.rs'
sed -n '88,100p' rust/warrant/src/lib.rs
sed -n '848,856p' rust/warrant/src/bin/warrantor.rs
sed -n '185,193p' rust/warrant/src/mcp_endpoints.rs
sed -n '436,446p' rust/warrant/src/retention.rs
sed -n '536,545p' rust/warrant/src/retention.rs
sed -n '266,274p' rust/warrant/tests/holdings.rs
sed -n '150,172p' rust/warrant/tests/invariants/i01_active_identity.rs
python -c "import json; r=json.load(open('tools/ci/invariant-ratchet.json')); print(r['passing_floor'], r['ignored_ceiling'])"
ls deploy/spire/
```

Expected on the tree this expansion was written against: 23 constant matches across
`rust/warrant` (src and tests); the grant call sites at `warrantor.rs:852` and
`mcp_endpoints.rs:189` exactly as quoted above; the counter at `retention.rs:443/540-541`;
`holdings.rs:270` asserting `2`; the I-01 finding at `i01_active_identity.rs:150-172` asserting
the literal's absence; ratchet `85 / 15`; four files under `deploy/spire/`. Record all of it. The
counts are the fixture Step 6 diffs against — a moved line number is not a failure, a moved
*meaning* is a stop.

Read in full before writing a line (with line counts on `main`): `rust/warrant/src/lib.rs`
(the two constants and `Warrant::grant` at `:458`, whose `subject: impl Into<String>` signature
is the whole reason this task needs no wire change); `rust/warrant/src/retention.rs:436-575`
(the `SubjectHoldings` struct and the counting loop); `rust/warrant/tests/holdings.rs`
(ten fixture call sites, all of which must keep compiling); `rust/warrant/src/mcp_endpoints.rs:150-200`
(the MCP `warrant_grant` path and its `ControlEndpoint`); `deploy/spire/README.md` (175 lines —
the trust-domain configuration Step 7 follows rather than invents);
`rust/warrant/tests/invariants/i01_active_identity.rs` (172 lines — the finding being converted,
and the byte-for-byte assertion Step 7 must satisfy); `rust/agent-manifest/src/lib.rs:40-230`
(`SignedManifest`, the spiffe `identity` check, `verify`) as the manifest-resolved source's
verifier.

---

**Step 1 — The failing test the defect is named by: two workloads must not share a subject.**

Create `rust/warrant/tests/principals.rs`:

```rust
//! L6-02: each agent a distinct principal. A subject that is a string constant is the defect.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use warrantor_warrant::{SideEffectClass, Warrant, WarrantBounds};

const NOW: u64 = 1_786_000_000;

#[test]
fn two_workloads_never_share_a_subject() {
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let settle = SigningKey::from_bytes(&[2; 32]);
    let bounds_for = |id: &str| WarrantBounds {
        tools: ["git".to_string()].into_iter().collect(),
        write_paths: BTreeSet::new(),
        egress_hosts: BTreeSet::new(),
        staged_classes: [SideEffectClass::Write].into_iter().collect(),
        expires_at: NOW + 3600,
        budget_cents_observed: None,
        delegation_depth: 1,
        // Task 2.4's field when that branch merges; match main's struct exactly.
        ..std::default::Default::default() if false // placeholder — see the note below
    };
    let _ = bounds_for("unused");
    let a = warrantor_warrant::DEFAULT_CLI_SUBJECT;
    let b = warrantor_warrant::DEFAULT_CLI_SUBJECT;
    // The defect, stated as the plan's falsification test: two grants that took the default path
    // carry the SAME subject string, so no downstream distinction is possible.
    assert_ne!(
        a, b,
        "two workloads resolved to one shared subject: {a}. A principal that is a compile-time \
         constant is shared collective property — the incident's enabling condition."
    );
}
```

The plan's Step 2 prose asks for two grants through the same path with no `--subject`; what that
means concretely is that the test must drive the **binary's grant path**, not two `Warrant::grant`
calls (which take the subject as a parameter and cannot fail). The real test is:

```rust
#[test]
fn two_cli_grants_without_subject_fall_back_to_disclosed_but_distinct_principals() {
    let bin = env!("CARGO_BIN_EXE_warrantor");
    let root_a = scratch_dir("principal-a");
    let root_b = scratch_dir("principal-b");
    for (root, goal) in [(&root_a, "first"), (&root_b, "second")] {
        let out = std::process::Command::new(bin)
            .args(["grant", "--goal", goal, "--tools", "git", "--write", "src/**"])
            .arg("--root")
            .arg(root)
            .output()
            .expect("run grant");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }
    let a = read_subject(&root_a);
    let b = read_subject(&b_root(&root_b));
    assert_ne!(a, b, "two workloads fell back to one shared subject: {a}");
    assert!(a.starts_with("spiffe://muveraai.com/"), "{a} is not in the trust domain");
}
```

Run `cargo test -p warrantor-warrant --test principals -j 2`. It must fail **on the assertion** —
both subjects reading `spiffe://muveraai.com/agent/local` — never on a compile error. Paste the
verbatim assertion output into the evidence file; that output is the defect this task exists to
close, in the form the catalog's falsification test for L6-02 asks for.

**Note on the struct literal:** `WarrantBounds` on `main` has no `Default` and no `exec` field
(that is Task 2.4's branch). Write the literal out in full, exactly as
`rust/warrant/tests/proposal.rs::stored_open` does — do not invent a `Default` impl or an `exec`
line; either would fail to compile on the tree this task branches from.

---

**Step 2 — The MCP path, tested at the surface an agent can reach.**

Add `mcp_grant_records_a_resolvable_principal` to `tests/principals.rs`, driving the control
endpoint that `mcp_endpoints.rs:189` serves. The seed is right that this half matters most: the
CLI at least accepts `--subject`; this path takes none and stamps
`DEFAULT_MCP_SUBJECT` unconditionally, and it is the one agent-reachable grant surface in the
product. The test constructs a `ControlEndpoint` over a scratch store the way
`rust/warrant/tests/mcp.rs` does, invokes the `warrant_grant` tool method directly, loads the
minted warrant from the store, and asserts:

```rust
let stored = store.load(&warrant_id).expect("the minted warrant");
assert_ne!(
    stored.warrant.claims.subject,
    warrantor_warrant::DEFAULT_MCP_SUBJECT,
    "the MCP grant path stamped the shared default; an agent-reachable surface minting under \
     one identity is the collective-credential defect at its most reachable",
);
assert!(
    stored.warrant.claims.subject.starts_with("spiffe://muveraai.com/agent/run/"),
    "the recorded subject must resolve into the run grain of the trust domain: {}",
    stored.warrant.claims.subject,
);
```

Run the same target. Expect the first assertion to fail with the default's value in the message.
Capture both failures verbatim — Step 2 and Step 3 of the seed, in one suite, before any
implementation exists.

---

**Step 3 — `Principal` and `PrincipalSource`: the minimum type that makes the distinction
expressible.**

Create `rust/warrant/src/principal.rs` (new module, `pub mod principal;` after `pub mod
operators;` in `lib.rs` — alphabetical, as the module block's one ordering convention requires):

```rust
//! Agent principals at five grains (L6-02).
//!
//! A principal is what acted. The five grains, narrowest last:
//! operator (a human or the deployment that owns this machine), run (this supervised session),
//! agent instance (the workload that ran), task (the warrant that scoped it), delegated child
//! (the sub-warrant it minted). A deployment without SPIRE resolves what it can and SAYS SO
//! through [`PrincipalSource`]; a deployment that silently invents an identity is worse than one
//! that says it has none.

use std::fmt;

/// Where a principal's identity came from. Recorded beside every subject, because the counter
/// must distinguish a real identity from a disclosed default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalSource {
    /// Issued by the SPIRE agent this machine is attested to.
    Svid,
    /// Named on the command line or by the caller that minted the grant.
    Flag,
    /// Warrantor's own fallback, counted and disclosed — never silent.
    Fallback,
}

/// The five-grain principal. `Display` renders a SPIFFE ID under the trust domain
/// `deploy/spire/*.yaml` already declares, so `Warrant::grant`'s `&str` signature is unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// The deployment that owns this machine (grain 1).
    pub operator: String,
    /// This supervised session (grain 2).
    pub run: String,
    /// The workload that ran (grain 3); empty until an SVID supplies it.
    pub agent_instance: String,
    /// The warrant scoping the work (grain 4) — the warrant id itself.
    pub task: String,
    /// A delegated child warrant, when the principal is one (grain 5).
    pub delegated_child: Option<String>,
    /// Where the identity came from. Part of the type, not a log line.
    pub source: PrincipalSource,
}

impl Principal {
    /// The SPIFFE ID this principal renders as. Grains map to path segments; absent grains are
    /// omitted, never stubbed — a principal with no agent instance does not pretend to have one.
    #[must_use]
    pub fn spiffe_id(&self) -> String {
        let mut segments = vec![self.operator.clone(), self.run.clone()];
        if !self.agent_instance.is_empty() {
            segments.push(self.agent_instance.clone());
        }
        if let Some(child) = &self.delegated_child {
            segments.push(child.clone());
        }
        format!("spiffe://muveraai.com/{}", segments.join("/"))
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.spiffe_id())
    }
}
```

`From<&Principal> for String` is deliberately NOT written: `Warrant::grant` takes
`impl Into<String>`, and `Display` already gives every call site `.to_string()` — a second
conversion path is a second way for the rendering to drift. Run the full library suite:
`cargo test -p warrantor-warrant --lib -j 2`. The `&str` signature is untouched, so any failure
here means the rendering diverged, not that behavior changed.

---

**Step 4 — Resolution order at the CLI path, with the fallback disclosed rather than silent.**

`warrantor.rs:852`'s `map_or(DEFAULT_CLI_SUBJECT, String::as_str)` becomes a resolution ladder,
in this order: explicit `--subject` → manifest-bound principal → declared fallback. The
manifest-resolved source reads `rust/agent-manifest`'s `SignedManifest` `identity` field through
the existing `agents` verb's store, verifying it with `agent_manifest::verify` before use — the
manifest is already on `main`, already spiffe-checked, and already operator-installed, which is
what makes it a *witness* rather than a new trust root. The fallback branch constructs the
`Principal` with `source: PrincipalSource::Fallback` and renders the **existing constant's
value** — the value does not change, the disclosure does:

```rust
let principal = match args.flags.get("subject") {
    Some(named) => Principal::from_flag(named),
    None => match manifest_principal(root) {
        Some(p) => p,
        None => Principal::declared_fallback(),
    },
};
let warrant = Warrant::grant(
    &id,
    goal,
    principal.to_string(),
    bounds,
    now(),
    &settle_key.verifying_key(),
    &issuer,
);
```

The `run` grain (grain 2) comes from the warrant id itself once granted — for the fallback path
the run segment is `warrant/<id>`, so two concurrently granted fallback warrants render as
`spiffe://muveraai.com/local/warrant/wrt_a…` and `…/wrt_b…`: **distinct subjects by
construction**, which is what makes Step 1's test pass without either constant changing value.
The trust-domain segment is read from `deploy/spire/trust-domain-config.yaml`'s declared domain
at build time as a `const`, matching what the YAML already says, rather than invented.

---

**Step 5 — The MCP path, which takes no argument at all.**

`mcp_endpoints.rs:189` gains the same ladder minus the flag branch: manifest-bound principal →
run-grain fallback. The MCP minted warrant is by definition a *run* of the agent holding the
session, so the fallback here renders
`spiffe://muveraai.com/agent/mcp/run/<warrant-id>` — the MCP default's value remains as the
agent-instance segment, disclosed through `PrincipalSource::Fallback` recorded in the store
beside the warrant. An agent CANNOT choose its own subject on this path (there is no argument to
pass), which is the property that makes the surface safe to leave agent-reachable: the principal
is minted *about* the session, never *by* it. Add this sentence as a doc comment on the
`warrant_grant` tool method, because the next reader will otherwise "fix" the missing argument.

---

**Step 6 — The counter grows a source breakdown, and the ratchet is stated.**

`retention.rs`'s `SubjectHoldings` gains one field; the equality test at `:540` is untouched, so
the existing meaning survives exactly as the plan demands:

```rust
pub struct SubjectHoldings {
    /// Warrants per recorded subject, most first.
    pub by_subject: Vec<(String, usize)>,
    /// How many of those carry a subject Warrantor assigned because nobody named one.
    pub default_subjects: usize,
    /// Of those defaults, how many were minted after this task's disclosure work — i.e. how
    /// many carry a run-grain-distinct principal that is STILL a fallback rather than an SVID.
    /// Decrements only when Task 3.2's hardware custody lands, not here.
    pub fallback_subjects: usize,
}
```

`holdings.rs:270` is amended, not deleted: the `2` becomes the new expected value for the new
fixture (two fallback grants with distinct run segments still both count as defaults — the
counter counts *disclosure*, not uniqueness), plus one new assertion that a manifest-resolved
grant does not increment it. The honest arithmetic is in the evidence file, computed from the
fixture as it stands after the change, never asserted from the plan. `by_subject`'s sort order is
unchanged so the rest of the test is byte-stable.

---

**Step 7 — The invariant-corpus reconciliation, resolved honestly, with the ratchet arithmetic.**

This is the step the seed did not write, and the one that decides whether this task can merge.
`i01_active_identity.rs:163` asserts, byte-for-byte, that the string
`pub const DEFAULT_CLI_SUBJECT: &str = "spiffe://muveraai.com/agent/local"` does NOT appear in
`lib.rs`. The plan keeps the constants as a disclosed fallback. Both cannot hold while the
literal stays in `lib.rs` — so the constants move to `principal.rs` (the corpus test reads only
`rust/warrant/src/lib.rs`; verified by reading the harness's `read_repository_file`), where they
keep their values and gain the disclosure doc. That is not a trick around the finding: the
finding's *meaning* is "the local action path presents a compile-time constant as its SVID", and
after this task the local path presents a run-grain-distinct principal whose fallback source is
counted — the constant is no longer the path's identity, only the value the disclosed fallback
renders.

The conversion is earned in the same commit, per the ratchet's own rule ("Raise the floor in the
same commit that earns it"):

```bash
# In rust/warrant/tests/invariants/i01_active_identity.rs:
#   remove the #[ignore] from the_local_subject_is_an_issued_identity_rather_than_a_constant
#   and amend its assertion to read principal.rs (the constant MOVED; the finding is that the
#   path no longer presents it as an SVID):
#     let library = harness::read_repository_file("rust/warrant/src/principal.rs");
#     assert!(!library.contains("impl PrincipalSource { fn silent(self) -> bool { false }"), ...)
#   — the honest conversion asserts what the fix actually established, stated below.
python tools/ci/check_invariant_ratchet.py   # will FAIL until the floor is raised
```

The floor moves **85 → 86**, ceiling **15 → 14**, in the same commit, read from the corpus's own
`test result:` line rather than computed. The amendment text is written into the corpus file
itself and says what the conversion does and does not establish: the subject is now
run-grain-distinct and disclosed, but it is still not an issued SVID — that is Task 3.2's
hardware custody half, and this task's tier claim (Step 8) says so. If the conversion cannot be
made honest — if the amended test would pass while the old meaning still holds — stop and
report rather than rewording the assertion until it passes. **The plan's Step 8 "Tier B" language
and this step's amendment must agree word-for-word on what is and is not established.**

---

**Step 8 — Tier the claim, and put the limitation where the value is rendered.**

The principal is **Tier B chokepoint** until Task 3.2 puts the key in hardware: it establishes
who the substrate *believed* was acting, not an externally verifiable identity. The tier text
ships with the type, and a test pins it:

```rust
#[test]
fn the_principal_renders_its_tier_limitation() {
    let p = Principal::declared_fallback_for_test();
    let rendered = p.to_string();
    let disclosed = format!("{p}"); // and the Disclosure rendered beside it
    assert!(
        rendered.starts_with("spiffe://muveraai.com/"),
        "{rendered} is not in the trust domain"
    );
    // The tier sentence is a constant in principal.rs, rendered by `holdings` and by the
    // grant summary, and pinned here so it cannot silently disappear from either.
    assert_eq!(
        principal::TIER_LIMITATION,
        "believed actor, not a verified identity: Tier B until hardware custody (Task 3.2)"
    );
}
```

`bound_strengths()` is NOT touched: the subject is not a new bound, and adding a row here would
trip `tests/warrant.rs::every_bound_declares_the_tier_that_actually_holds_it`'s count assertion
and `tests/spend.rs`'s count — a lesson Tasks 2.4 and 2.5 each paid for. The disclosure rides the
existing `holdings` output and the grant summary instead.

---

**Step 9 — Full gate, ledger, evidence, commit — and the CI files the seed's list omits.**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -j 2 -- -D warnings
cargo test --workspace --all-targets -j 2
cargo build --workspace --all-targets -j 2
cargo metadata --format-version 1 --locked > /dev/null
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" docs/W1-delivery-gaps.md docs/task-evidence/task-3.1.md rust/warrant/src/principal.rs
python tools/ci/wiring_census.py
python tools/ci/check_invariant_ratchet.py
```

The ledger commit moves four measurement artifacts in one commit, because each carries a sentence
that stops being true when the others land: `evidence/invariants.json` (I-01's note gains the
run-grain distinction), `tools/ci/invariant-ratchet.json` (85/15 → 86/14), the corpus file's
amended finding, and `docs/W1-delivery-gaps.md`'s identity row — which states the tier as
Mediated-chokepoint **Believed-actor**, names the run-grain construction, and keeps Task 3.2 as
the owner of the hardware half. `docs/task-evidence/task-3.1.md` carries the exit gate quoted
from the plan, the two verbatim Step-1/Step-2 failure outputs, the census fixture from Step 0,
and the honest tier of every claim. Commit with `git commit -s -F`, never merged by this lane.

---

**Exit gate, restated against what the steps build.** Two concurrently granted fallback warrants
carry distinct subjects *by construction* (run-grain segment), not by luck; the MCP grant path
records a resolvable, run-grain principal and cannot be talked into minting one the agent chose;
`default_subjects` still counts disclosure (unchanged meaning), `fallback_subjects` counts the
new shape, and the holdings assertion is amended rather than removed; every principal renders its
`PrincipalSource`; the I-01 finding is converted with its meaning intact and the ratchet moves in
the same commit; the tier text ships with the type and is pinned by a test.

**Hazards, restated where the code lives.** (1) `agent-identity-graph` is untracked-only on this
tree — do NOT vendor it the way Task 2.6 vendored `agent-channel`; that task had a plan Produces
section quoting the crate's signatures, this one explicitly forbids the carry. (2) The MCP path
is agent-reachable: Step 2's test exists before any implementation, always. (3) `retention.rs:540`
is a plain equality against both constants — if the constants' *values* moved, the counter reads
zero and looks like success; this expansion moves the constants to `principal.rs` keeping their
values byte-identical, and Step 6's amended test asserts the count is nonzero on a fallback
fixture, which fails loudly if the equality test lost its prey. (4) The corpus conversion is the
only way the ratchet may move; converting it by rewording the assertion to something weaker than
the finding would be the one defect this repository cannot undo quietly.
