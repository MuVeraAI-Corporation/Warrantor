### Task 3.3: Operator device-key binding in settle records — expanded to step form

**Anchor.** L1-07. A two-person rule is only as strong as the evidence that the second person was
actually there. This expansion verifies every anchor against local `main` at `6f41384` and turns
the seed's six prose steps into implementable steps with the exact code shape, the real line
numbers, and the one place the seed's file list is wrong about this tree.

**What exists on `main`, re-verified 2026-09-06.** The approval path is
`rust/warrant/src/operators.rs`: `ActorRecord` (struct at `:492`) carries `act`, `warrant_id`,
`actor: Option<String>` and `via: String` — the approver is a NAME, authenticated by a session
token whose comparison is documented at `:315` as early-exit-free. The distinct-approver count
lives at `operators.rs:677` (`How many distinct approvers are required before a settle is
permitted`), and `operators.rs:761` (`pub fn approvers(records: &[ActorRecord]) ->
BTreeSet<Option<String>>`) is where "distinct" is computed — on `Option<String>`, so an unscoped
token counts as its own approver. The settle gate that reads it is `cmd_settle`'s approval-policy
block in `bin/warrantor.rs` and the HTTP route's in `serve.rs`. `rust/warrant/src/review.rs`
exists (notification side of approvals). **No device key exists anywhere**: `keys/` holds
`issuer.key` and `settle.key` only, and `grep -rn "device" rust/warrant/src/operators.rs` returns
zero hits. The gap ledger row this task closes is the multi-user row (`§3.3 No multi-machine or
multi-repo view`) — its approval half, not the machine half.

**Where the seed's file list is wrong.** It names `rust/warrant/src/review.rs` as a primary file;
on this tree review.rs is the *notification* side and has no authority role. The real second file
is `rust/warrant/src/operators.rs` plus the settle call sites (`bin/warrantor.rs` `cmd_settle`,
`serve.rs`'s settle route, `mcp_endpoints.rs:470` `settle_warrant`). The schema to extend is
`ActorRecord`, not a separate settle-record schema — the settle path already reads the approval
verdict through `operators::approval_verdict`, so binding the device key at approval time and
carrying it through `ActorRecord` is the whole data path.

---

**Step 0 — Baseline: run these commands in the worktree and paste the output verbatim into
`docs/task-evidence/task-3.3.md`.**

```bash
git -C M:/wt-merge worktree add M:/wt-task-3.3 -b feat/task-3.3-device-key-approval main
cd M:/wt-task-3.3
sed -n '492,530p' rust/warrant/src/operators.rs      # ActorRecord, the schema to extend
sed -n '670,700p' rust/warrant/src/operators.rs      # distinct-approver count
sed -n '755,775p' rust/warrant/src/operators.rs      # approvers() — Option<String> semantics
grep -n "approval_verdict\|requires_approval" rust/warrant/src/bin/warrantor.rs | head -6
grep -n "approval_verdict\|requires_approval" rust/warrant/src/serve.rs | head -6
grep -n "via:" rust/warrant/src/operators.rs | head -8   # what 'via' holds today
grep -rn "device" rust/warrant/src/operators.rs | wc -l  # expected: 0 — no device key exists
grep -n "keys/" rust/warrant/src/bin/warrantor.rs | head -4  # what keys/ holds today
```

Expected: `ActorRecord.via` carries strings like `"session-token"` / `"cli"`; zero device-key
references in operators.rs; `approvers()` dedupes on the actor name; `keys/` holds issuer and
settle keys only. Read in full: `rust/warrant/src/operators.rs:190-330` (token minting and the
timing-safe comparison), `:460-560` (records and log append), `:660-780` (the verdict function),
and the settle call sites above. If `via` has grown a device variant, stop and re-read — the tree
moved.

The Step 0 output IS the finding the task closes, stated in the evidence file's own words:

```
via: "session-token"   <- the approver is whoever held the token, on any machine
via: "cli"             <- the approver is whoever ran the command, on this machine
device references: 0   <- no hardware, no key, no binding: the second person is a name
```

---

**Step 1 — The key type: reuse what exists, add nothing new.** The device key is an Ed25519
signing key minted by `operator device add <name>` (new verb under `operator`), written to
`keys/devices/<name>.key` with the hex verifying key appended to the operator's registry entry —
NOT a new trust store. The registry entry gains `device_key: Option<String>` (hex verifying key).
Reusing `load_or_create_key`'s shape is wrong: device keys are per-operator and numerous, not
per-machine singletons. What is reused: the timing-safe comparison at `:315` for the challenge,
and the ledger discipline (every record format gets a version constant):

```rust
/// One operator's registered device. The verifying key is what a second machine checks
/// against; the private half never touches the store this registry lives in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// The operator this device belongs to — matches the registry entry's name.
    pub operator: String,
    /// The device's own name, chosen by the operator.
    pub name: String,
    /// Hex Ed25519 verifying key. The signing half lives on the operator's device.
    pub verifying_key_hex: String,
    /// When the device was registered, epoch seconds.
    pub registered_at: u64,
}
```

The registry file is `operators/devices.json`, versioned `warrantor.operator-devices/1`, written
through the same atomic-write discipline `issuers.json` uses (temporary file, rename). A device
can be removed, and removal is effective for the NEXT approval — a binding recorded while the
device was registered verifies forever after (the key is in the record), which is the honest
semantics: revocation changes what can be approved next, not what was approved before. That
sentence goes in the verb's output and the ledger.

---

**Step 2 — Failing test: approval binds a device key, and the binding verifies offline.**

```rust
// rust/warrant/tests/device_approval.rs
use std::process::Command;

fn warrantor(root: &std::path::Path, args: &[&str]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_warrantor");
    let mut all = args.iter().map(|a| a.to_string()).collect::<Vec<_>>();
    all.push("--root".to_string());
    all.push(root.to_string_lossy().to_string());
    Command::new(bin).args(&all).output().expect("run warrantor")
}

#[test]
fn an_approval_records_a_device_key_that_a_second_machine_can_check() {
    let operator_root = tempdir("device-op");
    let store_root = tempdir("device-store");

    // 1. The operator registers a device. The PRIVATE half is written to the operator's
    //    own root; the store learns only the verifying key.
    let reg = warrantor(&operator_root, &["operator", "device", "add", "ana-laptop",
        "--operator", "ana", "--out-device-key"]);
    assert!(reg.status.success(), "{}", String::from_utf8_lossy(&reg.stderr));

    // 2. A warrant is granted and an approval recorded WITH --device-key ana-laptop.
    let grant = warrantor(&store_root, &["grant", "--goal", "two-person", "--tools", "git"]);
    assert!(grant.status.success());
    let id = warrant_id_from(&grant);

    // The approval is signed ON the operator's device: the challenge is read from the
    // approve verb's output, signed by the device key file, and the signature passed in.
    let approve = warrantor(&store_root, &["approve", &id, "--operator", "ana",
        "--device", "ana-laptop", "--device-signature", &device_signature]);
    assert!(approve.status.success(), "{}", String::from_utf8_lossy(&approve.stderr));

    // 3. From the store root alone (no device key present), the record must carry the
    //    verifying key and the challenge must verify under it.
    let log = read_actor_log(&store_root, &id);
    let binding = log.records[0].device.as_ref().expect("the approval is device-bound");
    let key = decode_verifying_key(&binding.verifying_key_hex).expect("hex key");
    key.verify(binding.challenge.as_bytes(),
               &decode_signature(&binding.signature_hex).expect("hex signature"))
        .expect("the device binding verifies from the store alone");
}
```

Run `cargo test -p warrantor-warrant --test device_approval -j 2` before implementing: it must
fail on the missing verb (`unknown command "operator"` surfaced with the sub-verb named, or the
registry write failing), not on a compile error. Paste the refusal and the assertion output.

The challenge construction, exactly:

```rust
/// What the device key signs at approval time: the warrant, the act, the operator, the
/// position in the actor log and the clock — the five things that make this approval
/// THIS approval, joined with the unit separator the pre-commit predicate uses.
pub fn approval_challenge(warrant_id: &str, operator: &str, at: u64, log_position: usize) -> String {
    format!("{warrant_id}\u{1f}approve\u{1f}{operator}\u{1f}{at}\u{1f}{log_position}")
}
```

---

**Step 3 — Bind at approval time; carry into the record.** `cmd_approve` takes
`--device <name> --device-signature <hex>`; when present it writes the signed challenge and the
device's verifying key into the new `ActorRecord.device: Option<DeviceBinding>` field:

```rust
/// A device-key binding on one approval. The verifying key travels IN the record, so a
/// second machine verifies the binding with no access to the operator's registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceBinding {
    /// The device's registered name.
    pub device_name: String,
    /// Hex verifying key — copied into the record at approval time.
    pub verifying_key_hex: String,
    /// The challenge that was signed.
    pub challenge: String,
    /// Hex signature over the challenge.
    pub signature_hex: String,
}
```

`ActorRecord` gains the field with
`#[serde(default, skip_serializing_if = "Option::is_none")]` so every existing actor log replays
byte-identically — the same absent-is-skipped discipline Task 2.4's `exec` field used, for the
same reason: the actor log is append-only and replayed, and a shape change for old readers is a
corrupt-log refusal on every machine that ever used this build. A test pins that: an actor log
written before this task deserializes unchanged, and the new field is absent on its records.

---

**Step 4 — Negative test: a device key that does not verify is refused, not warned.** The settle
gate's verdict function gains one clause: an approval whose `DeviceBinding` fails signature
verification is treated as **no approval at all** — the policy verdict is recomputed without it,
which for a two-approver policy means the settle is refused. Never a warning: a warning-grade
failure is an approval an attacker can attach and an operator ignores.

```rust
#[test]
fn a_settle_with_a_tampered_device_binding_is_refused_and_the_control_settles() {
    // approve with a device binding; flip one hex character of the signature;
    // settle must be refused (the binding counts as no approval, so a two-approver
    // policy is unmet). Then the un-tampered control settles through the identical path.
}
```

The refusal sentence names the operator and the reason ("device binding for ana does not
verify; the approval is not counted"), never the key bytes. The paired control is in the same
test: an approval whose binding verifies, through the identical code path, permits the settle —
a refusal that refuses everything proves nothing.

---

**Step 5 — Disclosure: unbound means unbound.** Where no device key is available (the unscoped
session token path), `device` stays `None` and the settle report's approval line renders:

```
approval  ana (unbound: name only, no device key checked)
approval  bob (device ana-laptop, verified)
```

A test pins the `unbound` sentence so it cannot silently disappear, and the gaps ledger's
multi-user row states what an unbound approval does not establish: the second person may have
been a second token on the same machine. The `approvers()` dedupe is also pinned: two
device-bound approvals from one operator count as ONE approver — the distinct-approver rule is
about people, and a device is not a person.

---

**Step 6 — Full gate; ledger; commit.**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -j 2 -- -D warnings
cargo test --workspace --all-targets -j 2 && cargo build --workspace --all-targets -j 2
cargo metadata --format-version 1 --locked > /dev/null
python tools/ci/wiring_census.py && python tools/ci/check_invariant_ratchet.py
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" docs/W1-delivery-gaps.md docs/task-evidence/task-3.3.md rust/warrant/src/operators.rs
```

The ledger's multi-user row gains the device-binding sentence and its honest limit; the evidence
file carries Step 0's baseline, the Step 2 verbatim failure, and the tier statement.

---

**Step 7 — The tier statement, written into the row and pinned by a test.** The device binding
is **Tier B chokepoint at the approval act**: it establishes that whoever approved held a key
registered to a named operator, on whatever machine that key lives on. It does not establish the
operator is a human (a held key is a held key), does not bind the machine (the key travels), and
does not survive a compromised operator device. The row says all three; a test pins the
`DeviceBinding` doc comment's tier sentence so a future edit cannot soften it silently.

**Exit gate, restated.** A two-person approval produces an actor log whose device bindings
verify on a second machine with no access to the first store's private keys; a tampered binding
is a refusal at settle, not a warning; the unbound path is disclosed in exactly those words, the
dedupe rule survives the new field, and the tier sentence is test-pinned.

**Hazards.** (1) `approvers()` dedupes on `Option<String>` — two device-bound approvals from one
operator must still count as one approver, and a test proves the dedupe survives the new field.
(2) The actor log is append-only and replayed; adding a non-skipped field breaks every existing
log's deserialization — the `skip_serializing_if` discipline is load-bearing, not style. (3) Do
not mint device keys with `KeyKind`; the enum's variants are the machine's three identities and a
fourth would change `load_or_create_key`'s contract for every caller. (4) The signature input is
the challenge string only — do not fold the record's other fields into it; a binding that signs
more than the challenge cannot be verified from the store alone, which defeats Step 2's whole
point.

---

**Verification detail — the shapes the steps compile against, captured on `main`.**

The registry write, using the atomic discipline the issuer registry already follows:

```rust
impl OperatorRegistry {
    /// Register one device under `operator`, atomically. The registry file is
    /// operators/devices.json, versioned warrantor.operator-devices/1; the write is
    /// a temporary file renamed over the target, the same discipline the issuer
    /// registry uses, because a half-written registry would read as "no devices",
    /// which is the silent downgrade this verb must never produce.
    pub fn add_device(&mut self, operator: &str, device: &str, verifying_key_hex: &str, at: u64) -> Result<(), String> {
        let existing = self.devices.iter().find(|d| d.operator == operator && d.name == device);
        if existing.is_some() {
            return Err(format!("device {device:?} is already registered for {operator:?}; \
                 remove it first with `operator device remove`"));
        }
        self.devices.push(DeviceRecord {
            operator: operator.to_string(),
            name: device.to_string(),
            verifying_key_hex: verifying_key_hex.to_string(),
            registered_at: at,
        });
        Ok(())
    }
}
```

The challenge verification on the second machine — the whole reason the verifying key travels
in the record:

```rust
impl DeviceBinding {
    /// Verify the binding from the record alone: no operator registry, no device key
    /// file, no network. This is what makes the binding evidence rather than a claim.
    ///
    /// # Errors
    /// A sentence when the key hex, the signature hex or the verification fails.
    pub fn verify(&self) -> Result<(), String> {
        let key = decode_verifying_key(&self.verifying_key_hex)?;
        let sig = decode_signature(&self.signature_hex)?;
        key.verify(self.challenge.as_bytes(), &sig)
            .map_err(|_| "the device binding does not verify".to_string())
    }
}
```

The verdict function's new clause, in context:

```rust
// operators.rs, in the approval-verdict computation — after the name-based distinct
// count, before the return:
for record in records.iter().filter(|r| r.act == Act::Approve) {
    if let Some(binding) = &record.device {
        if let Err(e) = binding.verify() {
            // The binding does not verify: this approval is NOT counted. The sentence
            // names the operator and the reason, never the key bytes.
            return (ApprovalVerdict::Refused(format!(
                "device binding for {} does not verify ({}); the approval is not counted",
                record.actor.as_deref().unwrap_or("(unnamed)"), e
            )), counted_without(record));
        }
    }
}
```

The gate and ledger block, restated with the two CI files the seed omits:

```bash
python tools/ci/wiring_census.py    # unchanged: no new crate, no new edge
python tools/ci/check_invariant_ratchet.py   # unchanged: this task converts no #[ignore]
cargo metadata --format-version 1 --locked > /dev/null
```

And the honest-summary sentence the ledger adds, quoted here so the implementer does not
invent a weaker one: *"Approvals can now carry a device-key binding that a second machine
verifies offline; an unbound approval says so on every rendering, and the two-person rule is
still only as strong as the weakest binding — an operator who approves without a device key
is a name, not a proven second person."*

---

**Shape on this tree — the remaining detail the steps need, with every anchor re-verified.**

The `DeviceBinding`'s place in the actor log replay, and why the absent-is-skipped discipline is
load-bearing rather than stylistic. `ActorRecord`s are appended to `actors/<warrant-id>.jsonl`
and replayed by every later reader — the approval verdict, the holdings inventory, and the
morning report all read the same log. A field added without
`#[serde(default, skip_serializing_if = "Option::is_none")]` would change the serialization of
every record written before this task, and the replay on any store with history would fail with
an unknown-field or missing-field error — which is the corrupt-log refusal firing for a reason
that has nothing to do with corruption. The pin test:

```rust
#[test]
fn an_actor_log_written_before_device_binding_replays_unchanged() {
    // A fixture actor log in the old shape (no device field), deserialized,
    // re-serialized, and compared byte-for-byte: the new field must not appear.
    let old = r#"{"format":"warrantor.actor-record/1","warrant_id":"w1","act":"approve",
                  "actor":"ana","via":"session-token"}"#;
    let record: ActorRecord = serde_json::from_str(old).expect("the old shape parses");
    assert!(record.device.is_none());
    let round_trip = serde_json::to_string(&record).expect("serializes");
    assert!(!round_trip.contains("device"), "the absent field must stay absent: {round_trip}");
}
```

The verb registration in `cmd_operator`, dispatch, and usage — the three places a new
sub-verb touches:

```rust
// dispatch, inside cmd_operator's match:
match args.positional.first().map(String::as_str) {
    Some("list") => cmd_operator_list(&root),
    Some("add") => cmd_operator_add(args, &root),
    Some("remove") => cmd_operator_remove(args, &root),
    Some("session-scope") => cmd_operator_session_scope(args, &root),
    Some("device") => cmd_operator_device(args, &root),        // <- this task
    ...
}

// usage, the operator block gains one line:
//   operator device add <name> --operator <op> [--out-device-key]
//           | remove <name> --operator <op>
```

The CLI verb's body, including the private-half discipline — the signing key is written to the
operator's own root, never to the store:

```rust
fn cmd_operator_device(args: &Args, root: &Path) -> ExitCode {
    let Some(name) = args.positional.get(1) else {
        return fail("usage: warrantor operator device add <name> --operator <op> \
                     [--out-device-key <path>]");
    };
    let Some(operator) = args.flags.get("operator") else {
        return fail("--operator is required: a device belongs to a named operator");
    };
    // The device's keypair: generated HERE, the private half written only where the
    // --out-device-key flag names (the operator's own root), the public half into
    // the store's registry. A device key in the store root would be a credential
    // the machine holds for the operator — the exact collective-property shape
    // this task exists to end.
    let mut private = [0u8; 32];
    getrandom::fill(&mut private).map_err(|e| format!("entropy: {e}"))?;
    let signing = SigningKey::from_bytes(&private);
    let verifying_hex = hex::encode(signing.verifying_key().to_bytes());
    // ... registry write, then the private half if --out-device-key was named ...
}
```

The evidence file's "what this does NOT establish" section, quoted in full so the implementer
cannot write a weaker one:

```text
- The device binding proves whoever approved held a key registered to a named
  operator. It does not prove the operator is a human: a held key is a held key,
  and Task 3.2's hardware custody is the item that changes that.
- It does not bind the machine: the key travels with the operator, by design.
- A binding recorded while the device was registered verifies forever after;
  device removal changes what can be approved NEXT, not what was approved before.
  Revocation is prospective in this system, and this task does not change that.
- An unbound approval (the session-token path) is disclosed as such on every
  rendering; the two-person rule is only as strong as the weakest binding.
```

The final commit, gathering the pieces the gate list names:

```bash
git add rust/warrant/src/operators.rs rust/warrant/tests/device_approval.rs \
        rust/warrant/src/bin/warrantor.rs docs/W1-delivery-gaps.md docs/task-evidence/task-3.3.md
git commit -s -F .commitmsg
# Branch: feat/task-3.3-device-key-approval. NOT merged by this lane; the review
# lane splices. The evidence file is in the same commit as the code it evidences.
```

Each of these shapes was verified against the tree this expansion was written against; where a
line number differs when the implementer runs Step 0, the difference is recorded, never
adjusted.
