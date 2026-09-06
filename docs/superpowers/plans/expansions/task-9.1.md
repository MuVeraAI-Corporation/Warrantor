### Task 9.1: Bounded revocation with a stated SLA (L6-04)

**Anchor.** The master blueprint's entry for this item carries, verbatim,
`data-status="none" data-novelty="novel" data-wave="W2"`
(`docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html:4162`), and its body states the
requirement in a form that rules out the easy version of this task:

> Revocation propagates to every enforcement point within a bounded interval measured in **execution
> counts and release consistency rather than time-to-live, because a TTL is formally inadequate at
> agent speed**. […] Non-revocation is provable at any past epoch from an append-only revocation log.
> — `master-2026-09-01.html:4166`

Its verification clause is equally specific — *"Revocation latency distributions measured per
enforcement point and published; a verifier demonstrates non-revocation at a past epoch with only log
heads"* (`:4169`) — and its own residual is the sentence this task must not contradict: *"A revoked
credential already used is not recalled; revocation bounds future use only"* (`:4170`).

**This is invariant I-05**, and the Task 5.1 corpus records two distinct reasons it fails. Neither is
a guess; both are executable and both fail today. `status=none` in the blueprint is not softened
here: after this task the item is `partial`, because propagation to a second machine still does not
exist and this task does not build it.

---

**Step 0.** Run these, in this order, in a read-only scratch worktree cut from `origin/main`:

```bash
export PATH="$PATH:/c/Users/MuVeraAICorporation/.cargo/bin"
cd "M:/Project AumOS - Open Secure AI Alliance/aumos"
git worktree add --detach M:/wt-read-9.1 refs/remotes/origin/main
cd M:/wt-read-9.1
export CARGO_TARGET_DIR=M:/wt-read-9.1-target

# 1. the specification: the two recorded findings, in full
cat -n rust/warrant/tests/invariants/i05_bounded_revocation_latency.rs   # 137 lines
cat -n rust/warrant/tests/invariants/harness.rs                          # 128 lines
cat -n rust/warrant/tests/invariants/scenario.rs                         # 184 lines
sed -n '117,161p' rust/warrant/tests/invariants/i01_active_identity.rs   # the THIRD ignore

# 2. the crate this task wires in, in full — 2,050 lines across four files
cat -n rust/credential-vault/Cargo.toml                                  #    27 lines
cat -n rust/credential-vault/src/lib.rs                                  # 1,392 lines
cat -n rust/credential-vault/src/persist.rs                              #   224 lines
cat -n rust/credential-vault/src/cli.rs                                  #   222 lines
cat -n rust/credential-vault/tests/vault_http_policy.rs                  #   185 lines

# 3. the two evidence records this task moves
cat evidence/wiring-coverage.json                                        #  1,121 bytes
cat evidence/invariants.json                                             # 11,834 bytes

# 4. the seam, and the precedent for filling it
sed -n '160,230p' rust/notary/src/lib.rs          # VerdictContext + the Identity gate
sed -n '700,800p' rust/warrant/src/report.rs      # the ONLY notary::verdict call in the binary
sed -n '463,582p' rust/warrant/src/report.rs      # limitations(): the absence-is-a-claim doctrine
sed -n '880,919p' rust/warrant/src/stop.rs        # StopStore::contained_scopes — copy this shape

# 5. the gates that decide pass or fail
cat tools/ci/invariant-ratchet.json
sed -n '24,43p'   tools/ci/check_invariants.py    # WARRANT_REACHABLE_CRATES
sed -n '140,155p' tools/ci/check_invariants.py    # the orphaned/partial status rule
sed -n '145,202p' tools/ci/wiring_census.py       # load_floor, readme_renders, main
grep -n "reachable from the CLI" README.md
sed -n '1107p' docs/W1-delivery-gaps.md
grep -n 'id="L6-04"' -A 10 docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html

# 6. measure the starting state
python tools/ci/wiring_census.py
python tools/ci/check_invariants.py
cd rust
cargo tree -p warrantor-warrant -e normal --depth 1
cargo tree -p warrantor-credential-vault -e normal --depth 1
cargo tree -p warrantor-warrant -e normal -i clap
cargo test -p warrantor-credential-vault 2>&1 | grep "test result:"
cargo test -p warrantor-warrant --test invariants -j 2 2>&1 | tail -1
cargo test -p warrantor-warrant --test invariants -j 2 -- --ignored i05
```

**The output, captured 2026-09-05 at `origin/main` = `e4b5f10`.**

`rust/credential-vault/` is present on `origin/main` — `git ls-tree --name-only refs/remotes/origin/main rust/`
lists it — so this task needs **no carry-in sequence**. It is one of 47 entries there and one of the
39 workspace members the census counts.

The two `#[ignore]` reasons, verbatim, at
`rust/warrant/tests/invariants/i05_bounded_revocation_latency.rs:84` and `:102`. They are the
specification and this task's success is defined as making both assertions true without touching
either assertion:

```rust
// i05_bounded_revocation_latency.rs:83-92
#[test]
#[ignore = "I-05 orphaned: credential-vault is not linked by the warrantor binary, so hop 5 has no boundary (2026-09-02)"]
fn hop_05_the_product_links_a_credential_vault_that_can_revoke() {
    let manifest = harness::read_repository_file("rust/warrant/Cargo.toml");
    assert!(
        manifest.contains("warrantor-credential-vault"),
        "I-05's credential half lives in a crate the product does not link, so a shared \
         credential has nothing to revoke it. The 1-second budget binds no shipped code path.",
    );
}

// i05_bounded_revocation_latency.rs:101-110
#[test]
#[ignore = "I-05 unimplemented: no revocation source exists for the identity half (Task 3.1, 2026-09-02)"]
fn a_revocation_source_exists_for_the_identity_half() {
    let report = harness::read_repository_file("rust/warrant/src/report.rs");
    assert!(
        !report.contains("revoked_svids: Vec::new()"),
        "the only consumer of the Identity gate supplies a revocation set that is empty by \
         construction, so the five-second propagation bound governs nothing.",
    );
}
```

Both fail today, and the failure text is the finding:

```text
running 2 tests
test i05_bounded_revocation_latency::hop_05_the_product_links_a_credential_vault_that_can_revoke ... FAILED
test i05_bounded_revocation_latency::a_revocation_source_exists_for_the_identity_half ... FAILED

---- hop_05_the_product_links_a_credential_vault_that_can_revoke stdout ----
panicked at warrant\tests\invariants\i05_bounded_revocation_latency.rs:87:5:
I-05's credential half lives in a crate the product does not link, so a shared credential has
nothing to revoke it. The 1-second budget binds no shipped code path.

---- a_revocation_source_exists_for_the_identity_half stdout ----
panicked at warrant\tests\invariants\i05_bounded_revocation_latency.rs:105:5:
the only consumer of the Identity gate supplies a revocation set that is empty by construction,
so the five-second propagation bound governs nothing.

test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 82 filtered out; finished in 0.01s
```

Baselines:

```text
$ python tools/ci/wiring_census.py
wiring census: 9 of 39 crates reachable from warrantor-warrant over 17 path edges

$ python tools/ci/check_invariants.py
invariant ledger: 12 invariants; enforced=2, orphaned=2, partial=7, unimplemented=1

$ cargo test -p warrantor-warrant --test invariants -j 2
test result: ok. 65 passed; 0 failed; 19 ignored; 0 measured; 0 filtered out; finished in 0.21s

$ cargo test -p warrantor-credential-vault 2>&1 | grep "test result:"
test result: ok. 30 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.22s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.28s
```

`evidence/wiring-coverage.json` confirms the orphan claim — `warrantor-credential-vault` is the
seventh name in the `orphaned` array of 30, against `"reachable": 9`, `"total": 39`, `"edges": 17`.
`evidence/invariants.json` (from Task 0.5, already on `origin/main`) says of I-05:

```json
{
  "id": "I-05",
  "statement": "Revocation latency is bounded. Identity revocation (I1) propagates to all replicas in <5s; credential revocation (R4) in <1s.",
  "status": "orphaned",
  "enforced_by": [
    { "crate": "credential-vault", "symbol": "warrantor_credential_vault::REVOKE_BUDGET",
      "test": "rust/credential-vault/src/lib.rs::revoke_all_meets_budget",
      "note": "1 s budget; over-budget revocation is an error" },
    { "crate": "credential-vault", "symbol": "warrantor_credential_vault::Vault",
      "test": "rust/credential-vault/src/lib.rs::revocation_survives_an_actual_restart_ax40",
      "note": "asserts 'a revoked credential MUST stay revoked across a restart (I-05)'" }
  ],
  "gap": "warrantor-credential-vault is not linked by the warrantor binary; identity revocation (<5s) has no implementation at all. Phase 3 custody (L1-07)."
}
```

**Six places the seed is wrong or incomplete. The code wins; each of these is verified above.**

1. **The seed's Step 6 asks for a test that already exists and already passes.**
   `i05_bounded_revocation_latency.rs:114-137` is
   `fn the_receipt_proves_which_action_the_revocation_stopped()`, it is not `#[ignore]`d, and it is
   one of the 65 passing. Writing it again is duplicate work. What does *not* exist is a receipt on
   the **product's** path that carries a revocation source or a measured latency — the existing test
   signs a synthetic verdict inside the corpus with `notary::EnforcementMode::Observed` and asserts
   `receipt.body.actor_svid == scenario::SUBJECT`. Step 8 below does the missing half.

2. **Converting the identity-half `#[ignore]` also converts a third one, in `i01`.**
   `i01_active_identity.rs:135` `fn the_products_own_notary_call_consults_a_revocation_source()`
   asserts, byte-for-byte, the same thing: `!report.contains("revoked_svids: Vec::new()")`. So the
   ratchet moves **65 → 68 passing and 19 → 16 ignored**, not 67/17. Raising the floor to 67 fails
   `check_invariant_ratchet.py:159-165` with *"the corpus improved (68 passing, 16 ignored) and
   tools/ci/invariant-ratchet.json still says 67/17"* — an improvement is a failure there by design.

3. **The seed's Files list omits five files whose CI gates this task will otherwise trip.**
   `tools/ci/check_invariants.py:149` reads `if status == "orphaned" and any(linked)` → *"orphaned
   but cites a crate the warrantor binary links"*. The moment `credential-vault` joins
   `WARRANT_REACHABLE_CRATES` (`:28-39`) while I-05 still says `"orphaned"`, the docs job fails.
   `wiring_census.py:196` fails when `README.md:196` no longer shows the current number. And
   `docs/W1-delivery-gaps.md:1107` ends with the words **"no task links `credential-vault`"**, which
   this task falsifies.

4. **The seed says "Read Task 3.1 … record whether it has landed." It has not.**
   `rust/warrant/src/lib.rs:88` still declares
   `pub const DEFAULT_CLI_SUBJECT: &str = "spiffe://muveraai.com/agent/local";`, and
   `i01_active_identity.rs:151`'s `#[ignore]` on that constant is still live. **This task therefore
   does not consume Task 3.1's output.** It supplies the revocation *source* for whatever principal
   the product presents, and the principal remains a constant until 3.1 lands. Say so in the
   product; do not imply an issued identity is being revoked.

5. **Wiring `credential-vault` in as written costs four external crates, not zero — and `clap` is
   not one of them.** `cargo tree -p warrantor-warrant -e normal -i clap` returns
   `clap v4.6.6 └── warrantor-trust-core └── warrantor-warrant`: it is already in the graph. The set
   difference over the two normal-dependency trees (155 packages vs 77) is exactly
   `aho-corasick, regex, regex-automata, regex-syntax` plus `warrantor-credential-vault` itself, all
   four from `regex = "1"` at `credential-vault/Cargo.toml:22`, used in only one place —
   `scan_for_exposed_credentials` at `lib.rs:806-822`. Step 2 feature-gates it to zero.

6. **"Distributions per enforcement point" has exactly one notary enforcement point to distribute
   over.** `grep -rn "notary::verdict" rust/warrant/src/` returns a single hit,
   `report.rs:764`. `warrantor-egress`'s decision function, `egress::decide(request, catalog)` at
   `rust/egress/src/lib.rs:156`, takes no revocation input at all and this task does not give it one.
   The evidence file must say "2 enforcement points, 1 of which consults the revocation set", not
   "distributions per enforcement point".

`premise_contradicted = true`.

---

**Non-goals.**

- **Not an identity provider, and not per-workload SVIDs.** The subject stays
  `DEFAULT_CLI_SUBJECT` / `DEFAULT_MCP_SUBJECT` until **Task 3.1** (agent principals at five grains
  from SPIFFE SVIDs) narrows them; `retention.rs:443`'s `pub default_subjects: usize` counter is
  3.1's gate, not this task's, and nothing here touches it.
- **Not fan-out, replicas, or a revocation directory.** `credential-vault/src/lib.rs:463` already
  promises *"revocation fans out to every replica in <1s via Kafka CloudEvents (task 04)"*. No broker
  is introduced. Cross-machine authority is **Task 9.5** (cross-organization authority and agent
  naming), which is where "no new trust root" stops being a preference.
- **Not quorum on the revoke act.** One operator can revoke here. Making the *authority to revoke*
  itself k-of-n is **Task 9.2** (quorum authority for high-consequence classes).
- **Not the SLA as a buyer-facing artifact.** No latency chart, no published SLA page, no
  `bound_strengths()` row. `rust/warrant/src/lib.rs:668`'s table and its README rendering
  (`render_bounds_table`, pinned by `tests/tier_disclosure.rs`) are untouched; rendering the number
  for an operator is **Task 11.10**.
- **Not purpose on the revocation.** "Revoked for what" is a purpose field, which is **Task 9.3**
  (I-03) and **Task 7.7**. A revocation here is unconditional for the named subject.
- **Not egress-path revocation.** Making `egress::decide` consult the revocation set belongs with
  the destination-catalog work in **Task 7.7**; this task states in the product that it does not.

---

**Files.**

Modified:
- `rust/credential-vault/Cargo.toml` — `[features]`; `regex` and `clap` become optional; `[[bin]]`
  gains `required-features = ["cli"]`.
- `rust/credential-vault/src/lib.rs` — `#[cfg(feature = "scan")]` on the scanner and its five tests;
  a `RevocationJournal` re-export note. **No change to `REVOKE_BUDGET` (`:35`), `Vault` (`:466`) or
  `persist`** — the two strings `i05`'s static test greps for at `:25` and `:31` must survive
  byte-identical.
- `rust/warrant/Cargo.toml` — the wiring edge (**contended**: five other Phase-9 tasks add path
  deps to this table; rebase before pushing).
- `rust/warrant/src/lib.rs` — `pub mod revoke;`, `pub const IDENTITY_REVOCATION_SLA`.
- `rust/warrant/src/report.rs` — `RevocationSection`; `build_observed` gains an eighth parameter;
  `:753` `revoked_svids: Vec::new(),` is replaced; `limitations()` (`:463`) gains the disclosure.
- `rust/warrant/src/bin/warrantor.rs` — `"revoke" => cmd_revoke(...)` in the dispatch at `:6405`;
  `USAGE`; the two `build_observed` call sites at `:1055` and `:5992`.
- `rust/warrant/src/mcp_endpoints.rs:323`, `rust/warrant/src/serve.rs:2910` — the other two
  `build_observed` call sites.
- `rust/warrant/tests/report.rs` (3 sites), `tests/spend.rs` (2), `tests/staged_chain.rs` (1) — the
  new parameter. Eleven call sites in total, five in `src` including the forwarder at `report.rs:609`.
- `rust/warrant/tests/invariants/i05_bounded_revocation_latency.rs` — `#[ignore]` removal only, at
  `:84` and `:102`, plus the module doc at `:1-13` which currently states the crate is unreachable.
- `rust/warrant/tests/invariants/i01_active_identity.rs` — `#[ignore]` removal only, at `:134`.
- `tools/ci/invariant-ratchet.json` — `passing_floor` 65 → 68, `ignored_ceiling` 19 → 16.
- `tools/ci/check_invariants.py:28-39` — `"credential-vault"` into `WARRANT_REACHABLE_CRATES`.
- `evidence/invariants.json` — I-05 `"orphaned"` → `"partial"`, new `enforced_by` entries, new `gap`.
  The `"statement"` string is checked against `docs/02-architecture.md:84` by
  `check_invariants.py:130` and must not be edited.
- `evidence/wiring-coverage.json` — regenerated (`--write`): `reachable` 9 → 10, `edges` 17 → 18,
  `orphaned` loses one name.
- `README.md:196` — `**9 of 39**` → `**10 of 39**`, and "the other 30" → "the other 29".
- `docs/W1-delivery-gaps.md:1107` — the I-05 row.

Created:
- `rust/warrant/src/revoke.rs` — `RevocationStore`, `RevocationRecord`, `RevocationLatency`.
- `rust/warrant/tests/revocation.rs` — the refusal test and its allowed control.
- `rust/warrant/tests/revocation_latency.rs` — the measurement, and the SLA-breach refusal.
- `evidence/revocation-latency.json` — format `warrantor.revocation-latency/1`.
- `docs/task-evidence/task-9.1.md`.

---

**Consumes / Produces.**

Consumes (existing, quoted with file and line):

- `rust/notary/src/lib.rs:176` `pub revoked_svids: Vec<String>,` — the seam. Its gate is
  `rust/notary/src/lib.rs:209-217`:
  ```rust
  // Gate 2 — Identity (I-01). No active identity, no action.
  if req.actor.svid.is_empty()
      || ctx.revoked_svids.contains(&req.actor.svid)
      || req.actor.svid_not_after <= ctx.now
  {
      return Verdict::Deny { gate: Gate::Identity };
  }
  ```
- `rust/notary/src/lib.rs:201` `pub fn verdict(req: &VerdictRequest, ctx: &VerdictContext) -> Verdict`
  — pure, reads no clock, called from exactly one place in the binary.
- `rust/warrant/src/report.rs:753` `revoked_svids: Vec::new(),` inside the `VerdictContext` literal
  at `:747-762`, and `:764` `let verdict = notary::verdict(&request, &context);`.
- `rust/warrant/src/report.rs:622` `pub fn build_observed(stored: &StoredWarrant, queue: Result<&StagingQueue, String>, issuer: &VerifyingKey, now: u64, contained_scopes: &[String], spend: Option<SpendSection>, custody: Option<CustodySection>) -> Report`.
- `rust/warrant/src/report.rs:463` `fn limitations(stored: &StoredWarrant, contained_scopes: &[String], spend: Option<&SpendSection>, custody: Option<&CustodySection>) -> Vec<String>` — and its doctrine at `:469-470`,
  *"Said whether or not a section is present, because the absence is itself a claim a reader would
  otherwise fill in wrongly."*
- `rust/warrant/src/stop.rs:912` `pub fn contained_scopes(&self, warrant_id: &str) -> Vec<String>` —
  **the shape to copy.** Its doc comment at `:908-910` is the whole design of this task in one
  sentence: *"This is the whole of the kill-switch wiring, and it needs no kill-switch dependency:
  the notary's `contained_scopes` is a `Vec<String>` and a warrant's scope is its id."*
- `rust/warrant/src/store.rs:113` `pub struct WarrantStore`, `:151` `pub fn root(&self) -> &Path`,
  `:70` `pub const REPO_DIR: &str = ".warrantor";` — where the journal lives.
- `rust/credential-vault/src/persist.rs:87` `pub fn open<P: AsRef<Path>>(path: P) -> Result<(Self, Vec<JournalRecord>), CredentialError>`;
  `:146` `pub fn append(&mut self, record: &JournalRecord) -> Result<(), CredentialError>` (write →
  `flush` → `sync_all` before returning, `:153-155`); `:163` `pub fn read_all<P: AsRef<Path>>(path: P) -> Result<Vec<JournalRecord>, CredentialError>`;
  `:34` `pub enum JournalOp { Issued, Revoked, RevokedAll }`; `:45` `pub struct JournalRecord { pub op: JournalOp, pub jti: String, pub at: u64 }`.
- `rust/credential-vault/src/lib.rs:35` `pub const REVOKE_BUDGET: Duration = Duration::from_secs(1);`
  — the credential half's number, reused, not re-declared. `:588` `pub fn revoke(&mut self, jti: &str) -> Result<(), CredentialError>`
  and `:597-602`, the precedent for failing on a blown budget rather than logging it:
  ```rust
  let elapsed = start.elapsed();
  if elapsed > REVOKE_BUDGET {
      return Err(CredentialError::RevocationBudgetExceeded { elapsed, budget: REVOKE_BUDGET });
  }
  ```
  `:651` `pub fn verify(&self, cred: &ScopedCredential) -> Result<(), CredentialError>`; `:500`
  `pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, CredentialError>`; `:538`
  `pub fn is_durable(&self) -> bool`.
- `rust/warrant/tests/invariants/harness.rs:50` `pub fn refused_at_the_boundary<T, F>(what: &str, control: &T, attacked: &T, allowed: F)`
  — the paired-control machinery; `:96` `pub fn source_contains(relative: &str, fragment: &str, why: &str)`;
  `:32` `pub fn read_repository_file(relative: &str) -> String`.
- `tools/ci/wiring_census.py:32` `SHIPPING_TABLE = "dependencies"`, `:106` `def reachable_crates(...)`,
  `:150` `def readme_renders(readme: Path, result: WiringCensus) -> bool`.
- `tools/ci/check_invariants.py:28` `WARRANT_REACHABLE_CRATES = frozenset({...})`, `:149` the
  orphaned rule.
- `tools/ci/check_invariant_ratchet.py:37` `RESULT_PATTERN`, `:138` `def check(result, baseline) -> list[str]`.

Produces (new):

- `rust/warrant/src/revoke.rs`:
  - `pub struct RevocationRecord { pub svid: String, pub recorded_at: u64, pub sequence: u64 }`
  - `pub struct RevocationStore { path: PathBuf }`
  - `pub fn open(root: &Path) -> Result<Self, WarrantError>` — `<root>/revocations.jsonl`
  - `pub fn revoked_svids(&self) -> Vec<String>` — the seam filler, mirroring `stop.rs:912`
  - `pub fn revoke(&mut self, svid: &str) -> Result<RevocationRecord, WarrantError>`
  - `pub fn was_revoked_at(&self, svid: &str, epoch: u64) -> bool` — the blueprint's past-epoch
    non-revocation proof, answered from the journal alone
  - `pub fn latency(&self, record: &RevocationRecord) -> RevocationLatency`
  - `pub struct RevocationLatency { pub elapsed_nanos: u128, pub adjudications_between: u64, pub sla_nanos: u128, pub within_sla: bool }`
  - `pub trait RevocationSource { fn revoked_svids(&self) -> Vec<String>; }` — implemented by
    `RevocationStore` and by the slow fault injector in the test, which is how the breach case gets
    exercised without a real slow disk
- `rust/warrant/src/lib.rs`: `pub const IDENTITY_REVOCATION_SLA: Duration = Duration::from_secs(5);`
  — the identity half's 5 s from `docs/02-architecture.md:84`, written as code for the first time,
  exactly as `REVOKE_BUDGET` is the credential half.
- `rust/warrant/src/report.rs`: `pub struct RevocationSection { pub source: String, pub revoked_svids: Vec<String>, pub latency: Option<RevocationLatency> }`,
  and `build_observed(..., revocation: Option<RevocationSection>)`.
- `evidence/revocation-latency.json`, format `warrantor.revocation-latency/1`.

Nothing here is created by another task. `RevocationJournal` and `REVOKE_BUDGET` both exist today
and are unreachable; that is the entire finding.

---

**Bound strength.**

**Tier B — chokepoint (`BoundStrength::Mediated`, `rust/warrant/src/lib.rs:208`)** for the refusal:
`rust/notary/src/lib.rs:211` refuses the action at the moment it is adjudicated, and the refusal is
a specific line of code returning `Verdict::Deny { gate: Gate::Identity }`. It is a chokepoint, not
an OS bound: an agent that never asks for a verdict is never refused, and nothing in this task
terminates a process, closes a socket, or invalidates a bearer token held elsewhere.

**Tier C — observed (`BoundStrength::Observed`, `:210`)** for the *propagation* claim. Nothing in
this build delivers a revocation record to a second process, so the measured latency is this
machine's own.

**No new trust root.** The revocation list is a local append-only JSONL file under the warrant store
root, appended by `warrantor revoke` on this machine and read by this machine's adjudications. It
establishes: every verdict this process computes after the `sync_all` at `persist.rs:155` returns
denies at gate Identity for that subject; and non-revocation at any past epoch is provable from the
journal alone, because revocation is monotone (`persist.rs:15`) and each record carries `at`. It
establishes nothing about any other machine, and it is not a directory, a CA, or an authority anyone
else consults.

**The orphan count does not rise.** This task *lowers* it: `reachable` 9 → 10, orphan list 30 → 29.

**The sentence that will appear in the product**, in `limitations()` and in `warrantor revoke`'s own
output, and which nothing in this task may soften:

> Revocation is refused at the adjudication chokepoint: every verdict this machine computes after the
> revocation is on disk denies at gate Identity for that subject. It does not recall a credential
> already used, does not reach a copy held by a third party, does not close a session already open,
> and does not propagate to any other machine — this build has no fan-out, so the measured latency is
> this process's, not the fleet's. The egress broker does not consult the revocation set at all. The
> subject revoked is the constant this build presents as its principal, not an issued SVID.

---

**Exit gate.** `python tools/ci/check_invariant_ratchet.py --show-findings && python tools/ci/wiring_census.py && python tools/ci/check_invariants.py && cargo test -p warrantor-warrant -p warrantor-credential-vault`
must print `invariant ratchet: ok (68 passing at floor 68, 16 recorded findings at ceiling 16)` and
`wiring census: 10 of 39 crates reachable from warrantor-warrant over 18 path edges`, with
`cargo test --test revocation_latency` green — a run in which the SLA-breach case is the one test
that refuses and the in-budget case is the one that passes.

---

- [ ] **Step 1 — Worktree, and the measurement test that cannot yet compile.**

```bash
export PATH="$PATH:/c/Users/MuVeraAICorporation/.cargo/bin"
git -C "M:/Project AumOS - Open Secure AI Alliance/aumos" \
  worktree add M:/wt-9.1-revocation -b feat/bounded-revocation origin/main
cd M:/wt-9.1-revocation
export CARGO_TARGET_DIR=M:/wt-9.1-revocation-target
```

Write the test first, so the interface is decided by a caller rather than by the implementation.
`rust/warrant/tests/revocation_latency.rs`:

```rust
//! I-05's identity half, measured. An SLA nobody measures is a sentence.
//!
//! The bound this asserts is `IDENTITY_REVOCATION_SLA` (5 s, from docs/02-architecture.md:84).
//! Two numbers are recorded, because wall-clock alone is gameable by a fast disk: the elapsed
//! nanoseconds, and `adjudications_between` — how many verdicts this process computed between the
//! revocation reaching disk and the first refusal. The blueprint asks for "execution counts", and
//! zero is the only defensible value for a single-process store.

use std::time::Duration;
use warrantor_warrant::revoke::{RevocationSource, RevocationStore};
use warrantor_warrant::IDENTITY_REVOCATION_SLA;

#[test]
fn the_measured_propagation_latency_is_inside_the_stated_sla() {
    let scratch = scratch_root("within-sla");
    let mut store = RevocationStore::open(scratch.path()).expect("a fresh store opens");

    let record = store.revoke("spiffe://muveraai.com/agent/local").expect("revoke succeeds");
    let latency = store.latency(&record);

    assert!(
        latency.within_sla,
        "measured propagation was {:?}, over the stated SLA of {IDENTITY_REVOCATION_SLA:?}. \
         Do not raise the SLA to make this pass.",
        Duration::from_nanos(latency.elapsed_nanos as u64),
    );
    assert_eq!(
        latency.adjudications_between, 0,
        "a verdict was computed between the revocation reaching disk and the first refusal, so \
         an action was adjudicated against a stale revocation set",
    );
    assert_eq!(latency.sla_nanos, IDENTITY_REVOCATION_SLA.as_nanos());
}
```

Run: `cargo test -p warrantor-warrant --test revocation_latency`.
Expected: `error[E0432]: unresolved import warrantor_warrant::revoke`. That is the correct starting
failure — the module does not exist.

- [ ] **Step 2 — Feature-gate `credential-vault` so the wiring edge costs zero external crates.**

The finding from Step 0: linking the crate as written adds `aho-corasick, regex, regex-automata,
regex-syntax`, all four reachable only from `scan_for_exposed_credentials` (`lib.rs:806-822`), which
`warrant` does not call. `clap` is already in the graph via `trust-core`, so it costs nothing, but
gate it anyway: nothing but the `[[bin]]` uses it (`grep -n clap rust/credential-vault/src/` returns
one line, `cli.rs:3`).

`rust/credential-vault/Cargo.toml`:

```toml
[dependencies]
thiserror.workspace = true
serde.workspace = true
serde_json = "1"
# `clap` is used by src/cli.rs and nowhere else; `regex` by scan_for_exposed_credentials and nowhere
# else. Both are optional so that a library consumer — warrantor-warrant, which needs only the
# revocation journal — links neither. Measured: with default-features = false this edge adds ZERO
# packages to warrant's normal-dependency tree, which without the gate gains four (aho-corasick,
# regex, regex-automata, regex-syntax). clap was already there via trust-core.
clap = { workspace = true, optional = true }
regex = { version = "1", optional = true }
ureq = { version = "2", default-features = false, features = ["tls", "json"] }

[features]
default = ["cli", "scan"]
# The `credential-vault` binary. Nothing but src/cli.rs needs it.
cli = ["dep:clap", "scan"]
# The credential-exposure scanner. Pattern matching, not brokering.
scan = ["dep:regex"]

[[bin]]
name = "credential-vault"
path = "src/cli.rs"
required-features = ["cli"]
```

In `lib.rs`, put `#[cfg(feature = "scan")]` on `use regex::Regex;` (`:25`), on `CREDENTIAL_PATTERNS`
(`:783`), on `CredentialExposure` (`:793`), on `scan_for_exposed_credentials` (`:806`), and on the
three scanner tests (`scan_detects_aws_key` `:940`, `scan_detects_multiple_types_at_once` `:949`,
`scan_returns_empty_on_clean_text` `:966`). **Do not touch `:35` `REVOKE_BUDGET` or the doc comment
at `:11-16`** — `i05_bounded_revocation_latency.rs:23-34` greps this file for
`"pub const REVOKE_BUDGET: Duration = Duration::from_secs(1);"` and for
`"a revoked credential MUST stay revoked across a restart (I-05)"`, and those two static assertions
are among the 65 currently passing.

Verify both builds and the default:

```text
$ cargo test -p warrantor-credential-vault                    # default: 30 + 3, unchanged
$ cargo test -p warrantor-credential-vault --no-default-features
   → the three scanner tests are gone; the 27 others plus the vault_http_policy 3 still pass
$ cargo build -p warrantor-credential-vault --no-default-features --bins
   → builds nothing; `required-features = ["cli"]` skips the binary rather than failing
```

*Test intent:* that the gate is a real partition and not a rename — the default feature set behaves
exactly as before, and the no-default set compiles without `regex` in the graph at all.

- [ ] **Step 3 — Add the wiring edge, and watch the census rise.**

`rust/warrant/Cargo.toml`, after `warrantor-spend` (`:56`), in the style of the comments already
there:

```toml
# The credential vault, behind invariant I-05's revocation bound. `default-features = false`
# deliberately: the vault's CLI and its credential scanner are gated (see that crate's [features]),
# so this edge adds ZERO packages to this crate's normal-dependency tree and no line to Cargo.lock.
# The 7-external-dep, tokio-free posture is unchanged.
#
# What this buys is that I-05 stops being orphaned. The vault's 1-second REVOKE_BUDGET and its
# fsync'd revocation journal were real, tested and unreachable from the product; `revoke.rs` now
# reads that journal, so the number binds a shipped code path.
#
# What it does NOT buy: fan-out. That crate's own comment (lib.rs:463) promises replica propagation
# via Kafka CloudEvents; no broker is linked here and none is claimed. Propagation stays Observed.
warrantor-credential-vault = { path = "../credential-vault", version = "1.0.0", default-features = false }
```

Then measure, regenerate, and fix the README in the same step so the census gate cannot be left red:

```bash
python tools/ci/wiring_census.py
# ::notice::wiring ratchet: 10 reachable exceeds the floor of 9; run
#   `python tools/ci/wiring_census.py --write` and commit evidence/wiring-coverage.json
# ::error::README status table does not show 'reachable from the CLI | **10 of 39**'
python tools/ci/wiring_census.py --write
python -m pytest tools/ci/test_wiring_census.py -q -p no:cacheprovider
cargo tree -p warrantor-warrant -e normal --prefix none | awk '{print $1}' | sort -u | wc -l
# 156 — exactly one more than the 155 at origin/main, and the one is warrantor-credential-vault
```

`README.md:196` becomes `**10 of 39**` and "the other 29". At this point
`cargo test -p warrantor-warrant --test invariants -- --ignored i05` reports **1 failed, 1 passed**:
`hop_05_the_product_links_a_credential_vault_that_can_revoke` now passes on the manifest grep, and
the identity half still fails. Leave the `#[ignore]` on until Step 9 — the ratchet is raised once,
in one commit.

*Test intent:* the census is a manifest-level claim, so it must be checked against the dependency
tree as well. A crate reachable in the census but contributing no code would be an edge that buys
nothing; the package count rising by exactly one, and Step 5's runtime refusal, are what make the
edge honest.

- [ ] **Step 4 — `RevocationStore`: the local source, and the past-epoch proof.**

`rust/warrant/src/revoke.rs`. The store reuses `credential-vault`'s journal format rather than
inventing a second one, which is the point of the edge: the JSONL file is readable with `cat`,
`fsync`'d before a revocation is acknowledged, and monotone.

```rust
//! The local revocation source for the notary's Identity gate (invariant I-05).
//!
//! # What this is, and what it is not
//!
//! `notary::VerdictContext::revoked_svids` is a `Vec<String>` the caller supplies, and until now the
//! product's one caller (`report.rs:764`) supplied an empty one — so gate 2 asked whether an SVID
//! appeared in an empty set. This module supplies it, in exactly the shape
//! [`crate::stop::StopStore::contained_scopes`] supplies the containment gate: a local file, read at
//! adjudication time, needing no service.
//!
//! **No new trust root.** The journal is a file under this store's root, appended by an operator on
//! this machine. It establishes that every verdict THIS process computes after the record is
//! `sync_all`'d denies at gate Identity for that subject, and that non-revocation at a past epoch is
//! provable from the log alone. It establishes nothing about any other machine, nothing about a
//! credential a third party already holds, and nothing about a session already open.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use warrantor_credential_vault::{JournalOp, JournalRecord, RevocationJournal};

use crate::{WarrantError, IDENTITY_REVOCATION_SLA};

/// The file, under the warrant store root. Named for what it holds, not for who writes it.
pub const REVOCATION_JOURNAL: &str = "revocations.jsonl";

/// A revocation, as recorded. `sequence` is the record's index in the journal — the "release
/// consistency" half of the blueprint's bound, which a wall clock cannot express.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationRecord {
    /// The subject revoked.
    pub svid: String,
    /// Epoch seconds at which the record became durable.
    pub recorded_at: u64,
    /// The record's position in the append-only journal, from zero.
    pub sequence: u64,
    /// Monotonic instant at which `sync_all` returned. Not serialized: it is only meaningful
    /// against this process's clock, and pretending otherwise is how a local measurement gets
    /// reported as a fleet one.
    durable_at: Instant,
}

/// Anything that can answer "which subjects are revoked". A trait so the latency test can inject a
/// deliberately slow source and prove the SLA breach is detected, rather than waiting for a slow
/// disk that may never arrive in CI.
pub trait RevocationSource {
    /// The revoked subjects, as the notary's context wants them.
    fn revoked_svids(&self) -> Vec<String>;
}

/// The append-only, `fsync`-per-write revocation list for one warrant store.
#[derive(Debug)]
pub struct RevocationStore {
    path: PathBuf,
    adjudications: u64,
}

impl RevocationStore {
    /// Open (or create) the store's revocation journal.
    ///
    /// # Errors
    /// Returns [`WarrantError`] if the journal cannot be opened or replayed. **Fail-closed**: an
    /// unreadable journal is never treated as an empty one. `stop.rs:903` makes the same call for
    /// the same reason — unknown resolves to contained, and here unknown resolves to error rather
    /// than to "nothing is revoked".
    pub fn open(root: &Path) -> Result<Self, WarrantError> { /* … */ }

    /// Record a revocation, durably, and return what was recorded.
    ///
    /// The `Instant` in the returned record is taken **after** `RevocationJournal::append` returns,
    /// which is after its `sync_all` (`persist.rs:155`). Measuring from before the write would
    /// charge the SLA for the disk and then claim the disk was fast.
    pub fn revoke(&mut self, svid: &str) -> Result<RevocationRecord, WarrantError> { /* … */ }

    /// Was this subject revoked at or before `epoch`?
    ///
    /// The blueprint's past-epoch clause: answerable from the log alone, because revocation is
    /// monotone (`persist.rs:15`) and every record carries `at`. A reader with only this file can
    /// therefore demonstrate NON-revocation at a past epoch, which is the harder direction.
    #[must_use]
    pub fn was_revoked_at(&self, svid: &str, epoch: u64) -> bool { /* … */ }

    /// Measure the propagation of a revocation to this process's adjudication point.
    #[must_use]
    pub fn latency(&self, record: &RevocationRecord) -> RevocationLatency { /* … */ }

    /// Count one adjudication. Called by the report path, so `adjudications_between` is a real
    /// count and not an assumption.
    pub fn note_adjudication(&mut self) { self.adjudications += 1; }
}

impl RevocationSource for RevocationStore {
    fn revoked_svids(&self) -> Vec<String> {
        // Replay, keep the Revoked ops, dedupe. Monotone, so no un-revoke case exists.
        RevocationJournal::read_all(&self.path)
            .map(|records| { /* … */ })
            // Fail-closed on a corrupt journal would mean revoking everything, which is worse than
            // the alternative here: the caller already got an error from `open`, so reaching this
            // arm means the file changed underneath us. Return the empty set AND let the report's
            // limitation say the source was unreadable — never silently.
            .unwrap_or_default()
    }
}

/// One measurement, in the two units the blueprint names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RevocationLatency {
    /// Wall-clock nanoseconds from durability to first refusal.
    pub elapsed_nanos: u128,
    /// How many verdicts this process computed in that window. Zero is the only defensible value
    /// for a single-process store; a positive number means an action was adjudicated against a
    /// revocation set that was already stale.
    pub adjudications_between: u64,
    /// The stated bound, from [`IDENTITY_REVOCATION_SLA`].
    pub sla_nanos: u128,
    /// Whether the measurement is inside the bound. Computed, never supplied.
    pub within_sla: bool,
}
```

Unit tests in the same file: a revoke-then-read round trip; a restart (drop and re-`open`) proving
the revocation survives, mirroring `credential-vault`'s `revocation_survives_an_actual_restart_ax40`
(`lib.rs:1171`); `was_revoked_at` true after and **false before** the record's `at`; and an
unreadable-journal case asserting `open` returns `Err` rather than an empty store.

*Test intent:* the past-epoch pair is the one that matters. A store that answers "revoked" for every
epoch is useless as a proof of non-revocation, so the negative direction is asserted explicitly.

- [ ] **Step 5 — Failing test: a revoked subject is refused on the product's own path, with an allowed control.**

`rust/warrant/tests/revocation.rs`. This is the test that makes the `#[ignore]` removal in Step 9
mean something: without it, deleting the string `revoked_svids: Vec::new()` would satisfy the
assertion and change no behavior, which is exactly the gaming the corpus doc at
`tests/invariants/main.rs:30-41` warns about.

```rust
#[test]
fn a_revoked_subject_is_refused_at_the_identity_gate_on_the_products_own_path() {
    // CONTROL: the same warrant, the same store, nothing revoked. Must be ALLOWED — otherwise the
    // refusal below proves only that the fixture was broken.
    let fixture = fixture::open_warrant_store("revocation-control");
    let store = RevocationStore::open(fixture.root()).unwrap();
    let control = report::build_observed(
        &fixture.stored, Ok(&fixture.queue), &fixture.issuer, fixture::NOW,
        &[], None, None, Some(report::RevocationSection::from_source(&store)),
    );
    assert!(
        control.bundle.authority_check.allowed,
        "the CONTROL was refused, so the attack never reached the Identity gate. Fix the fixture; \
         never weaken the assertion. denied_gate = {:?}",
        control.bundle.authority_check.denied_gate,
    );

    // ATTACK: revoke the subject the warrant names, rebuild through the same function.
    let mut store = RevocationStore::open(fixture.root()).unwrap();
    store.revoke(&fixture.stored.warrant.claims.subject).unwrap();
    let attacked = report::build_observed(
        &fixture.stored, Ok(&fixture.queue), &fixture.issuer, fixture::NOW,
        &[], None, None, Some(report::RevocationSection::from_source(&store)),
    );

    assert!(!attacked.bundle.authority_check.allowed);
    assert_eq!(
        attacked.bundle.authority_check.denied_gate.as_deref(),
        Some("identity"),
        "a revoked subject must deny at Identity specifically. A denial at some earlier gate would \
         let this test pass for the wrong reason.",
    );
}

#[test]
fn a_report_built_without_a_revocation_source_says_so_rather_than_implying_none() {
    let fixture = fixture::open_warrant_store("revocation-absent");
    let built = report::build_observed(
        &fixture.stored, Ok(&fixture.queue), &fixture.issuer, fixture::NOW,
        &[], None, None, None,          // no source consulted
    );
    assert!(
        built.bundle.limitations.iter().any(|line| line.contains(
            "No revocation source was supplied to this report"
        )),
        "an absent revocation source must be disclosed. Silence reads as \"checked and clear\", \
         which is the claim report.rs:749-751 already refuses to make for containment.",
    );
}
```

Then make them pass. In `report.rs`, replace `:753`:

```rust
        // The revocation seam, filled from this store's journal rather than from an identity
        // provider. Empty means "warrant was handed no revoked subject", which — exactly as with
        // `contained_scopes` above — is a statement about what was supplied, never a claim that
        // revocation was checked and found clear. `None` for the whole section says even that much
        // was not consulted, and `limitations()` distinguishes the two.
        revoked_svids: revocation.as_ref().map(|s| s.revoked_svids.clone()).unwrap_or_default(),
```

*Test intent:* the pair. `refused_at_the_boundary`'s discipline (`harness.rs:50-66`) applied outside
the corpus — a verifier that refuses everything would pass the attack half and fail the control half,
and the control half is written first for that reason.

- [ ] **Step 6 — `warrantor revoke`, and the operator act that produced it.**

Add `"revoke" => cmd_revoke(&args, &store, &root),` to the dispatch at `bin/warrantor.rs:6405`, plus
a `USAGE` entry. Three forms:

```text
warrantor revoke --svid <SVID>     record a revocation; prints the record and the measured latency
warrantor revoke --list            the current revoked set, with each record's sequence and epoch
warrantor revoke --at <EPOCH> --svid <SVID>
                                   was this subject revoked at that epoch? the past-epoch proof
```

`cmd_revoke` writes through `RevocationStore::revoke`, appends the act to the actor log the way
`cmd_stop` does (so `CustodySection` covers who revoked), and prints the Bound-strength sentence from
above under the record. A revocation that does not say what it fails to reach is the "intention" the
seed's anchor names.

*Test intent:* one CLI test that `--list` reflects a `--svid` in a fresh store, and one that
`--at <epoch before the record>` prints the non-revoked answer. The second is the only surface
through which the blueprint's past-epoch clause is reachable by a person.

- [ ] **Step 7 — Failing test: the SLA is measured, and a breach refuses.**

Declare the number in `rust/warrant/src/lib.rs`, beside the bound vocabulary:

```rust
/// The identity half of invariant I-05: revocation reaches this process's adjudication point within
/// five seconds. From `docs/02-architecture.md:84` — "Identity revocation (I1) propagates to all
/// replicas in <5s" — with the honest narrowing that this build has exactly one replica.
///
/// The credential half's number is not restated here: it is
/// `warrantor_credential_vault::REVOKE_BUDGET` (1 s), and one number in two places is how the two
/// halves drift apart.
pub const IDENTITY_REVOCATION_SLA: Duration = Duration::from_secs(5);
```

Complete `rust/warrant/tests/revocation_latency.rs` from Step 1 with the breach case, paired against
the in-budget control:

```rust
/// A source that takes longer than the SLA to answer. The point is not that a real disk would: it is
/// that if one did, the measurement must FAIL rather than round the number down. An SLA that cannot
/// be seen to break is not measured.
struct SlowSource { delay: Duration }

impl RevocationSource for SlowSource {
    fn revoked_svids(&self) -> Vec<String> {
        std::thread::sleep(self.delay);
        vec!["spiffe://muveraai.com/agent/local".to_string()]
    }
}

#[test]
fn a_propagation_slower_than_the_sla_fails_the_measurement() {
    // CONTROL: a source inside the budget measures within_sla == true.
    let fast = measure(&SlowSource { delay: Duration::from_millis(10) });
    assert!(
        fast.within_sla,
        "the CONTROL breached the SLA, so this test proves nothing about the breach case. \
         Measured {:?} against {IDENTITY_REVOCATION_SLA:?}.",
        Duration::from_nanos(fast.elapsed_nanos as u64),
    );

    // BREACH: over the budget. `within_sla` must be false, and the value must be the real one.
    let slow = measure(&SlowSource { delay: IDENTITY_REVOCATION_SLA + Duration::from_millis(250) });
    assert!(!slow.within_sla, "a source slower than the SLA was reported as inside it");
    assert!(
        slow.elapsed_nanos > IDENTITY_REVOCATION_SLA.as_nanos(),
        "the breach must be recorded at its real magnitude, not clamped to the bound",
    );
}

#[test]
fn the_evidence_file_records_the_measurement_and_names_what_it_does_not_cover() {
    let record = warrantor_warrant::revoke::latency_evidence();
    assert_eq!(record.format, "warrantor.revocation-latency/1");
    assert_eq!(record.enforcement_points, 2);
    assert_eq!(record.enforcement_points_consulting_revocation, 1);
    assert!(record.not_covered.iter().any(|line| line.contains("does not propagate")));
}
```

`evidence/revocation-latency.json`, written by `warrantor revoke --write-evidence` and asserted by
the test above:

```json
{
  "format": "warrantor.revocation-latency/1",
  "recorded": "2026-09-05",
  "sla": { "identity_seconds": 5, "credential_seconds": 1,
           "identity_source": "docs/02-architecture.md:84",
           "credential_source": "rust/credential-vault/src/lib.rs:35" },
  "enforcement_points": 2,
  "enforcement_points_consulting_revocation": 1,
  "points": [
    { "name": "notary identity gate",
      "call_site": "rust/warrant/src/report.rs:764",
      "consults_revocation": true,
      "p50_nanos": 0, "p99_nanos": 0, "max_adjudications_between": 0, "samples": 0 },
    { "name": "egress broker",
      "call_site": "rust/egress/src/lib.rs:156",
      "consults_revocation": false,
      "note": "egress::decide takes no revocation input; this task does not give it one (Task 7.7)" }
  ],
  "not_covered": [
    "does not propagate to any other machine: no fan-out is linked",
    "does not recall a credential already used, per the blueprint's own residual for B-06",
    "does not reach a copy of the credential held by a third party",
    "does not close a session already open",
    "the subject revoked is DEFAULT_CLI_SUBJECT, not an issued SVID, until Task 3.1 lands"
  ]
}
```

The `p50/p99/samples` zeros are placeholders the writer fills; committing them as literals with
`"samples": 0` is the honest starting state, and a reviewer can tell a measured zero from an
unmeasured one.

*Test intent:* the breach case is the whole step. A measurement that can only report success is a
constant.

- [ ] **Step 8 — The report says what the revocation did and did not reach.**

`RevocationSection` into the bundle, and three arms in `limitations()` (`report.rs:463`), following
the containment precedent at `:545-557` — which is the only limitation in that function computed from
its input rather than fixed, for exactly this reason:

```rust
    out.push(match revocation {
        None => "No revocation source was supplied to this report. The Identity gate's \
                 \"unrevoked\" clause passes because nothing was wired to it, not because \
                 revocation was checked.".to_string(),
        Some(section) if section.revoked_svids.is_empty() => format!(
            "A revocation source WAS consulted ({}) and it holds no revoked subject. That is a \
             statement about this machine's journal, not about any other machine: this build has \
             no fan-out, so a subject revoked elsewhere is unrevoked here.",
            section.source,
        ),
        Some(section) => format!(
            "{} subject(s) are revoked in this machine's journal ({}), so the Identity gate denies \
             every verdict computed after the record reached disk{}. It does not recall a \
             credential already used, does not reach a copy held by a third party, does not close a \
             session already open, and does not propagate to any other machine. The egress broker \
             does not consult the revocation set at all. The subject revoked is the constant this \
             build presents as its principal, not an issued SVID.",
            section.revoked_svids.len(),
            section.source,
            match section.latency {
                Some(l) if l.within_sla => format!(
                    " — measured at {:?}, inside the stated {IDENTITY_REVOCATION_SLA:?}",
                    Duration::from_nanos(l.elapsed_nanos as u64)),
                Some(l) => format!(
                    " — measured at {:?}, which BREACHES the stated {IDENTITY_REVOCATION_SLA:?}",
                    Duration::from_nanos(l.elapsed_nanos as u64)),
                None => " (propagation was not measured for this build)".to_string(),
            },
        ),
    });
```

Update the eleven `build_observed` call sites: `report.rs:609` (pass `None`), `bin/warrantor.rs:1055`
and `:5992` (pass a real section from the store), `mcp_endpoints.rs:323` and `serve.rs:2910` (same),
and the six in `tests/report.rs`, `tests/spend.rs`, `tests/staged_chain.rs` (pass `None`, so those
tests keep asserting what they assert).

**No new `bound_strengths()` row.** The revocation bound is a property of the existing Identity gate,
not a new bound on the warrant, and adding a row would change the README bounds table and
`tests/tier_disclosure.rs` for no gain. Rendering the SLA to an operator is Task 11.10.

*Test intent:* three assertions, one per arm, so the "consulted and empty" case cannot silently
collapse into the "not consulted" case. That collapse is the defect the containment comment at
`report.rs:749-751` was written to prevent, and it would be a bound reported as stronger than it is.

- [ ] **Step 9 — Convert the three `#[ignore]`s, and raise the ratchet in this commit.**

Remove, and change nothing else in these files:

- `i05_bounded_revocation_latency.rs:84` — `#[ignore = "I-05 orphaned: credential-vault is not linked by the warrantor binary, so hop 5 has no boundary (2026-09-02)"]`
- `i05_bounded_revocation_latency.rs:102` — `#[ignore = "I-05 unimplemented: no revocation source exists for the identity half (Task 3.1, 2026-09-02)"]`
- `i01_active_identity.rs:134` — `#[ignore = "I-01 currently violated: revoked_svids is hardcoded empty in report.rs (Task 1.1 / Task 3.1, 2026-09-02)"]`

Rewrite the `FINDING` doc comment above each into a `FIXED BY` note naming this task and this
commit, and correct the module header at `i05_bounded_revocation_latency.rs:6-13`, which currently
says *"Both halves exist in the repository and neither is reachable from the product"* — true on
2026-09-02, false after Step 3. **`i01_active_identity.rs:151`'s second `#[ignore]` stays**: the CLI
subject is still a constant, and that is Task 3.1's.

`tools/ci/invariant-ratchet.json`:

```json
{
  "format": "warrantor.invariant-ratchet/1",
  "recorded": "2026-09-05",
  "source": "rust/warrant/tests/invariants/",
  "passing_floor": 68,
  "ignored_ceiling": 16,
  "note": "The invariant attack corpus for I-01..I-12. `passing_floor` may only rise; `ignored_ceiling` may only fall. Raised 65/19 -> 68/16 by Task 9.1: credential-vault is linked and report.rs consults a revocation source, which converts both I-05 findings and the shared I-01 finding on `revoked_svids: Vec::new()`."
}
```

`tools/ci/check_invariants.py:28-39` gains `"credential-vault"`, and its comment at `:26-27` is
updated. `evidence/invariants.json`'s I-05 entry moves to `"status": "partial"` — required, because
`:149` fails a build in which an `orphaned` invariant cites a linked crate — with the `statement`
untouched (`:130` compares it to `docs/02-architecture.md:84`) and:

```json
  "status": "partial",
  "enforced_by": [
    { "crate": "credential-vault", "symbol": "warrantor_credential_vault::REVOKE_BUDGET",
      "test": "rust/credential-vault/src/lib.rs::revoke_all_meets_budget",
      "note": "1 s budget; over-budget revocation is an error" },
    { "crate": "credential-vault", "symbol": "warrantor_credential_vault::Vault",
      "test": "rust/credential-vault/src/lib.rs::revocation_survives_an_actual_restart_ax40",
      "note": "asserts 'a revoked credential MUST stay revoked across a restart (I-05)'" },
    { "crate": "warrant", "symbol": "warrantor_warrant::revoke::RevocationStore",
      "test": "rust/warrant/tests/revocation.rs::a_revoked_subject_is_refused_at_the_identity_gate_on_the_products_own_path",
      "note": "the product's one notary call now consults a durable local revocation journal" },
    { "crate": "warrant", "symbol": "warrantor_warrant::IDENTITY_REVOCATION_SLA",
      "test": "rust/warrant/tests/revocation_latency.rs::a_propagation_slower_than_the_sla_fails_the_measurement",
      "note": "5 s identity bound, measured; a breach fails the test rather than being logged" }
  ],
  "gap": "partial, not enforced: propagation is measured for one process and one enforcement point. There is no fan-out, no replica set, and the egress broker does not consult the revocation set (Task 7.7). The subject revoked is a constant until Task 3.1. Cross-machine revocation is Task 9.5."
```

`docs/W1-delivery-gaps.md:1107` becomes:

```text
| **I-05** Revocation latency is bounded | partial | The credential half is linked and reachable: `warrant` reads `credential-vault`'s fsync'd revocation journal, so the 1-second budget binds a shipped path. The identity half now has a source and a measured 5-second bound at one enforcement point, and no propagation beyond this process: no fan-out, no replica set, and `egress::decide` does not consult it. `invariant-corpus:I-05` | Tier 2 | Task 9.1 wired it; Task 3.1 for an issued subject, Task 7.7 for the egress point, Task 9.5 for cross-machine |
```

*Test intent:* `python tools/ci/check_invariant_ratchet.py --show-findings` must print
`invariant ratchet: ok (68 passing at floor 68, 16 recorded findings at ceiling 16)`. Any other
number — including a better one — is a failure by design (`check_invariant_ratchet.py:159-165`),
which is what stops a floor from drifting away from reality.

- [ ] **Step 10 — Every gate for every language touched, the evidence file, and `git commit -s`.**

```bash
cd M:/wt-9.1-revocation
# Rust — the language this task touched
cd rust
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p warrantor-credential-vault --no-default-features
cargo test -p warrantor-warrant --test invariants -j 2
cargo test -p warrantor-warrant --test revocation --test revocation_latency
cd ..
# Python — the three CI scripts this task edited or moved
python tools/ci/wiring_census.py
python -m pytest tools/ci/test_wiring_census.py -q -p no:cacheprovider
python tools/ci/check_invariants.py
python -m pytest tools/ci/test_check_invariants.py -q -p no:cacheprovider
python tools/ci/check_invariant_ratchet.py --show-findings
python tools/ci/check_docs.py
# Markdown — the two docs this task edited
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" \
  docs/task-evidence/task-9.1.md docs/W1-delivery-gaps.md README.md
git commit -s -m "feat: bound revocation latency and measure it (I-05, L6-04)"
```

Expected, and the numbers the exit gate reads:

```text
wiring census: 10 of 39 crates reachable from warrantor-warrant over 18 path edges
invariant ledger: 12 invariants; enforced=2, orphaned=1, partial=8, unimplemented=1
test result: ok. 68 passed; 0 failed; 16 ignored; 0 measured; 0 filtered out
invariant ratchet: ok (68 passing at floor 68, 16 recorded findings at ceiling 16)
```

`docs/task-evidence/task-9.1.md` records: the two `#[ignore]` strings that were removed and the third
in `i01` that came with them; the census before and after with the package-count delta of exactly
one; the four `regex` crates the feature gate kept out and the `cargo tree -i clap` output proving
`clap` was already present; the measured latency and `adjudications_between` from a real run; the
verbatim Bound-strength sentence as it appears in `limitations()`; and the three things this task
leaves for 3.1, 7.7 and 9.5. `cargo test --workspace` must remain at or above the 133 suites and
1,385 tests recorded at `e4b5f10`, plus the new suites.

**Windows note.** CI runs the workspace on ubuntu only, so every `#[cfg(windows)]` path in this task
is untested there. `RevocationStore::open` and `RevocationJournal::append` both touch the filesystem;
run `cargo test -p warrantor-warrant --test revocation --test revocation_latency` on this box before
pushing, and put the scratch journal under `std::env::temp_dir()` rather than the repository, so a
concurrent lane's `cargo` cannot race the file.

*Test intent:* the last gate is that no number in this task is asserted anywhere without a command
in this step that produces it.
