### Task 5.6: Write-bound promotion, per kernel, only where refusal is observed — expanded to step form

**Anchor.** L4-04 and the three-tier taxonomy. `write_paths` was once *signed as Enforced with
nothing enforcing it* — the single most instructive defect in this repository's history.
Containment happened at settle, not at write. This expansion re-verified the anchors on local
`main` at `6f41384`, and the tree already contains the machinery the seed only gestures at: a
sandbox whose module doc records the one verified kernel in its own words, and a conformance
drill whose shape the promotion receipt extends.

**What exists, re-verified 2026-09-06.** `rust/warrant/src/sandbox.rs` emits bubblewrap profiles
(`profile` at `:262`) and documents, in its module doc, exactly what the seed asks for and more:
verified on Linux 6.18 with unprivileged user namespaces against `$HOME` and `/etc` (both refuse)
(`:37`), the honest caveat that bubblewrap's correctness is bubblewrap's claim (`:67`), and the
negative kernel named — WSL2's 6.18 without `unprivileged_userns_clone`, where `bwrap` refuses to
start at all (`:68-69`). The rendering test at `:299` already prints "verified against bubblewrap
on Linux 6.18, where $HOME and /etc both refuse" in the profile's divergence output.
`bound_strengths()` pins `("write_paths", BoundStrength::Observed)` at `lib.rs:694`, and
`tests/warrant.rs::every_bound_declares_the_tier_that_actually_holds_it` plus `tests/spend.rs`'s
count assertion (now 8) pin the table. The conformance drill is
`rust/warrant/tests/conformance_receipt.rs::a_drill_on_this_kernel_produces_a_receipt_that_verifies_offline`
— and its documented Windows load-flake (`docs/task-evidence/finding-kill-drill-confirmation-under-load.md`)
is exactly the per-kernel problem this task generalizes: the drill's verdict is a property of the
kernel it ran on, which is why the receipt carries `kernel_id()`.

**The promotion rule, made mechanical.** `write_paths` moves to `Mediated` **only on a kernel
where a refusal outside the declared paths was observed executing at the moment of write** — the
drill receipt carries that observation, keyed by `conformance::kernel_id()`, and the rendering
reads the receipt. Every other kernel keeps Observed *and says so*. There is no global promotion.

---

**Step 0 — Baseline: run these commands in the worktree and paste the output verbatim into
`docs/task-evidence/task-5.6.md`.**

```bash
git -C M:/wt-merge worktree add M:/wt-task-5.6 -b feat/task-5.6-write-bound-promotion main
cd M:/wt-task-5.6
grep -n "6.18\|one kernel\|WSL2" rust/warrant/src/sandbox.rs | head -6
sed -n '262,300p' rust/warrant/src/sandbox.rs
grep -n '"write_paths"' rust/warrant/src/lib.rs
grep -rn "kernel_id" rust/warrant/src rust/containment-conformance/src --include=*.rs | head -4
cargo test -p warrantor-warrant --test conformance_receipt -j 2   # the drill's verdict on THIS kernel
```

Expected: the sandbox doc's verified/negative kernel sentences; the Observed row at
`lib.rs:694`; `kernel_id()` in the conformance path; the drill's verdict on the development
kernel (Linux 6.18-class if present, else the documented Windows refusal). Read in full:
`rust/warrant/src/sandbox.rs` (module doc and `profile`), the conformance receipt schema, and
`docs/task-evidence/finding-kill-drill-confirmation-under-load.md` (the finding that already
proves one kernel's verdict does not transfer).

---

**Step 1 — The per-kernel drill for the write bound.** The kill drill proved containment; the
write drill proves *refusal at the moment of write*. Inside the bubblewrap profile (or the
profile the platform provides), the drill attempts a write outside the declared paths and
captures: whether the write was refused by the kernel (exit code and errno from the write
itself, not from a settle-time filter), the latency, and `kernel_id()`. The receipt schema gains
a `write_bound` observation:

```rust
/// One kernel's observed write-bound behavior. The promotion reads THIS, not prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteBoundObservation {
    /// `conformance::kernel_id()` — the same id the kill drill pins.
    pub kernel: String,
    /// Whether the out-of-bounds write was refused by the OS at write time.
    pub refused_at_write: bool,
    /// The captured errno / exit status of the refused write.
    pub refusal_detail: String,
    /// Milliseconds for the refusal to surface, for the latency column.
    pub latency_ms: u64,
    /// The declared paths the in-bounds control write used successfully — the paired control
    /// without which a refusal proves only that the filesystem was broken.
    pub in_bounds_control_ok: bool,
    /// The receipt digest this observation was recorded under, so the rendering can cite it.
    pub receipt_digest: String,
}
```

**Step 2 — Failing test: the out-of-bounds write is refused at the moment of write, not
filtered at settle.** On the verified kernel (guarded by the platform the sandbox doc names —
Linux + bubblewrap + unprivileged userns, skipped with the named reason elsewhere, exactly as
Task 1.3's platform tests skip): run the emitted profile around a child that attempts
`$HOME/outside.txt`, capture the write's own failure, and assert the drill receipt records
`refused_at_write: true` with the paired in-bounds control succeeding:

```rust
#[cfg(target_os = "linux")]
#[test]
fn an_out_of_bounds_write_is_refused_at_the_write_on_the_verified_kernel() {
    if !bubblewrap_available() {
        eprintln!("skipped: bubblewrap is not available on this kernel (the sandbox doc \
                   names WSL2's 6.18 without unprivileged_userns_clone as the negative case)");
        return;
    }
    let bounds = bounds_with_write_paths(&["src/**"]);
    let profile = sandbox::profile(&bounds, worktree_path(), Confinement::default());
    let attempt = run_inside_profile(&profile, &["touch", "/HOME-IS-NOT-WRITABLE"]);
    assert!(!attempt.status.success(), "the out-of-bounds write must fail");
    assert!(attempt.refused_by_os(), "the refusal must be the kernel's, not a settle filter");

    // The paired control: the SAME profile permits the declared paths.
    let control = run_inside_profile(&profile, &["touch", "src/in-bounds.txt"]);
    assert!(control.status.success(), "the declared paths must still be writable");

    // And the drill receipt records both facts, keyed by kernel:
    let receipt = write_bound_drill_receipt(&profile, &attempt, &control);
    assert!(receipt.write_bound.refused_at_write);
    assert!(receipt.write_bound.in_bounds_control_ok);
    assert_eq!(receipt.write_bound.kernel, conformance::kernel_id());
}
```

Run before implementing the promotion: today the receipt has no `write_bound` observation, so
the assertion fails on the missing field — the failure IS the deliverable's gap, named.

**Step 3 — Promotion is per kernel and read from receipts.** `bound_strengths()` stays the
static table (`write_paths` at Observed, untouched — the count assertions in `tests/warrant.rs`
and `tests/spend.rs` must not move). The *rendering* becomes receipt-aware: `sandbox.rs`'s
divergence output and the profile rendering read any committed conformance receipts for this
kernel and render:

```rust
// sandbox.rs, in the divergences for write_paths — where the fixed 6.18 sentence lives today:
let observed = committed_write_observation_for(conformance::kernel_id());
match observed {
    Some(o) if o.refused_at_write && o.in_bounds_control_ok => divergences.push(Divergence::Gap {
        bound: "write_paths".to_string(),
        why: format!(
            "MEDIATED ON THIS KERNEL: an out-of-bounds write was refused at the write \
             (receipt {}). The static table still says Observed — the promotion is per \
             kernel, and other kernels keep the Observed rendering with the named reason.",
            o.receipt_digest
        ),
    }),
    _ => divergences.push(Divergence::Gap {
        bound: "write_paths".to_string(),
        why: "OBSERVED: no observed refusal on this kernel. Containment happens at \
              settle. The promotion is per kernel and requires a receipt-backed refusal."
            .to_string(),
    }),
}
```

The existing fixed sentence ("verified against bubblewrap on Linux 6.18") is *replaced* by this
receipt-driven rendering — the sentence was the manual form of the same fact, and the receipt is
the mechanical form. The rendering test at `:299` is amended to expect the receipt-driven text.

**Step 4 — Negative test: on an unverified kernel the rendering must NOT say Enforced.** This is
the task's real deliverable, per the seed. The test simulates a kernel id with no committed
receipt (and separately, a receipt whose `refused_at_write` is false) and asserts the rendering
says Observed — plus the stronger property: `bound_strengths()`'s static row can be edited to
Mediated by a future hand, and the test refuses that edit unless a receipt-backed observation
for the running kernel exists:

```rust
#[test]
fn a_kernel_without_an_observed_refusal_never_renders_as_promoted() {
    // A fabricated kernel id with no committed receipt:
    let rendering = render_write_bound_for("fabricated-kernel-6.99");
    assert!(!rendering.contains("MEDIATED"),
        "a kernel without a receipt-backed refusal must not render as promoted: {rendering}");
    assert!(rendering.contains("OBSERVED"), "{rendering}");
    // A receipt that exists but records NO refusal (the drill ran, the write succeeded):
    let rendering = render_write_bound_with(&observation(refused_at_write: false));
    assert!(!rendering.contains("MEDIATED"),
        "a drill that did not observe a refusal must not promote the bound: {rendering}");
    // The static table is untouched by all of this:
    assert_eq!(bound_strengths()["write_paths"], BoundStrength::Observed);
}
```

**Step 5 — The CI matrix, within what CI can actually run.** Task 0.2's matrix is
ubuntu + windows; the verified kernel is Linux 6.18. The matrix job runs the write drill on the
ubuntu leg (bubblewrap available), records the receipt, and commits it as an artifact the
rendering can read; the Windows leg records the honest negative (bubblewrap absent — Observed,
with the named reason). A kernel matrix beyond what CI offers is stated in the ledger as
unmeasured, with the drill packaged so an operator runs it on their kernel and keeps the receipt
— the receipt, not the CI leg, is the promotion's evidence.

**Step 6 — Full gate; ledger; commit.**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -j 2 -- -D warnings
cargo test --workspace --all-targets -j 2 && cargo build --workspace --all-targets -j 2
python tools/ci/check_invariant_ratchet.py   # unchanged: this task converts no #[ignore]
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" docs/W1-delivery-gaps.md docs/task-evidence/task-5.6.md rust/warrant/src/sandbox.rs
```

The ledger's write-bound row is rewritten: the one-kernel story gains the receipt mechanism, the
promotion rule, and the named negative kernel. Evidence: the baseline, the drill receipt on the
development kernel, the negative-rendering test output, and the tier statement — which is the
task's product: the bound's tier is now per kernel, and every kernel without an observed refusal
says Observed out loud.

---

**The honest tier of every bound this task introduces.**

| what this task adds | tier | why that word and not a stronger one |
|---|---|---|
| the per-kernel write drill + `WriteBoundObservation` | a **measurement**, not a bound | the observation records; it refuses nothing. |
| the receipt-aware rendering | the **promotion mechanism** | the rendered tier per kernel rises to Mediated only under a receipt-backed refusal; the static table stays Observed. |
| the negative-rendering test | the **guard** | it is what makes the promotion rule a property of the code instead of a sentence in the ledger. |

**Exit gate, restated.** The conformance receipt states the write bound per kernel; no kernel
renders promoted without a captured refusal; the verified kernel's promotion is receipt-backed
and the rendering carries the receipt digest; the paired control write is part of every drill.

**Hazards.** (1) Do not promote `budget` in this task — the seed forbids it and
`budget_cents_observed` is Observed for a structural reason (self-reported) no kernel drill
changes. (2) The Windows drill flake documented in
`finding-kill-drill-confirmation-under-load.md` applies to the write drill too: the drill runs
process-kill and filesystem checks under load, and a flaky refusal must read as "unobserved",
never as a refusal — the observation is only recorded when the run is clean by the finding's
criteria. (3) Do not touch `bound_strengths()`'s static row; the promotion lives in the
rendering, and the count-pinning tests are the tripwire that keeps it there. (4) The drill runs
a child process under bubblewrap — on CI, ensure bubblewrap's presence is checked before the
test, not after its failure, and the skip reason names the sandbox doc's own negative kernel.

---

**Shape on this tree — the remaining detail the steps need, with every anchor re-verified.**

The drill's platform guard, how the test skips on kernels the sandbox doc names as negative
cases — quoting the doc's own words as the skip reason:

```rust
#[cfg(target_os = "linux")]
fn bubblewrap_available() -> bool {
    // The sandbox doc names the negative case: WSL2's 6.18 without
    // unprivileged_userns_clone, where bwrap refuses to start at all. The drill's
    // skip reason IS that sentence — a skip without the named reason is a silent
    // downgrade of the matrix, and the matrix is the point.
    std::process::Command::new("bwrap").arg("--version").output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
```

The write drill's child, the exact out-of-bounds attempt and its capture:

```rust
/// Run one command inside the emitted profile and classify the result. The refusal
/// must be the KERNEL's (the write syscall itself fails), not a settle-time filter —
/// the distinction is the entire task.
fn run_inside_profile(profile: &Profile, cmd: &[&str]) -> ProfileAttempt {
    let output = std::process::Command::new("bwrap")
        .args(&profile.bubblewrap_argv())
        .args(cmd)
        .output()
        .expect("run under the profile");
    ProfileAttempt {
        status: output.status,
        // errno from the write itself: EROFS / EACCES / EPERM are kernel refusals;
        // a clean exit with a filter message is a settle-time filter, which is the
        // OLD defect shape and fails this drill.
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

impl ProfileAttempt {
    /// Was the failure the kernel refusing the write at write time? A settle-time
    /// filter would have let the write succeed and removed it later — the exact
    /// `write_paths was signed Enforced with nothing enforcing it` defect.
    fn refused_by_os(&self) -> bool {
        !self.status.success()
            && (self.stderr.contains("EROFS") || self.stderr.contains("EACCES")
                || self.stderr.contains("EPERM") || self.stderr.contains("Read-only"))
    }
}
```

The receipt's placement in the conformance schema, where the promotion reads it:

```rust
// containment_conformance.rs — the drill receipt gains the observation:
pub struct ConformanceReceipt {
    // ... the existing kill-path fields ...
    /// This kernel's observed write-bound behavior. The write_paths rendering reads
    /// THIS, keyed by kernel id — the promotion is per kernel and receipt-backed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_bound: Option<WriteBoundObservation>,
}
```

The rendering test, pinning both sides of the promotion in one place:

```rust
#[test]
fn the_write_bound_rendering_names_its_evidence_by_kernel() {
    // With a receipt-backed refusal for THIS kernel:
    let with = render_write_bound_with(&observation(kernel_id(), true, true));
    assert!(with.contains("MEDIATED ON THIS KERNEL"), "{with}");
    assert!(with.contains(&observation(kernel_id(), true, true).receipt_digest[..16]), "{with}");
    // Without any receipt for a different kernel:
    let without = render_write_bound_for("some-other-kernel");
    assert!(without.contains("OBSERVED"), "{without}");
    assert!(!without.contains("MEDIATED"), "{without}");
    // The static table, untouched through all of it:
    assert_eq!(bound_strengths()["write_paths"], BoundStrength::Observed);
}
```

The ledger's write-bound row, quoted so the implementer cannot write a weaker one:

```text
### 5.6 Write-bound promotion, per kernel, only where refusal is observed — **the promotion is
receipt-backed, and every kernel without a receipt says Observed out loud**

The write drill records one WriteBoundObservation per kernel, keyed by conformance::kernel_id(),
with the out-of-bounds refusal captured from the write syscall itself and a paired in-bounds
control write. The write_paths rendering is receipt-aware: a kernel with a receipt-backed
refusal renders MEDIATED ON THIS KERNEL with the receipt digest; every other kernel renders
OBSERVED with the named reason. The static bound_strengths table is unchanged (Observed), and
the tests that pin it are the tripwire. The named negative kernel (WSL2's 6.18 without
unprivileged_userns_clone) renders Observed with the sandbox doc's own sentence as the reason.
The CI matrix runs the drill on the ubuntu leg and records the honest negative on Windows.
```

The final commit, gathering the pieces:

```bash
git add rust/warrant/src/sandbox.rs rust/warrant/src/containment_conformance.rs \
        rust/warrant/tests/conformance_receipt.rs rust/warrant/tests/write_drill.rs \
        docs/W1-delivery-gaps.md docs/task-evidence/task-5.6.md
git commit -s -F .commitmsg
# Branch: feat/task-5.6-write-bound-promotion. NOT merged by this lane.
```

Each shape was verified against the tree this expansion was written against; where a line number
differs when the implementer runs Step 0, the difference is recorded, never adjusted.

---

**The negative kernel's drill, what the honest negative actually records.** On WSL2's 6.18
without `unprivileged_userns_clone`, `bwrap` refuses to start — so the drill cannot observe a
refusal OR a success. The observation schema has three outcomes, and the schema is what makes
the honest negative expressible:

```rust
pub enum WriteDrillOutcome {
    /// The out-of-bounds write was refused by the kernel; the in-bounds control succeeded.
    Refused { refusal_detail: String, latency_ms: u64 },
    /// The out-of-bounds write SUCCEEDED. This is the worst outcome — the profile does
    /// not contain — and it must never be silently converted to "unobserved".
    WriteSucceeded { path: String },
    /// The drill could not run (no bubblewrap, no userns). Not a pass, not a failure:
    /// the kernel is unmeasured, and the rendering says so with the named reason.
    Unmeasured { reason: String },
}
```

The `WriteSucceeded` variant is the one this task exists to surface: a profile that does not
contain is a `write_paths` defect live on that kernel, and the drill's job is to record it as
the finding it is, not to render the kernel as Observed-by-default as if nothing had been
tried. The rendering for `WriteSucceeded` says `CONTAINMENT FAILED ON THIS KERNEL` — stronger
than Observed, and honest.

**The rendering's four states, the full table the negative test pins:**

```text
receipt says Refused + control ok  -> "MEDIATED ON THIS KERNEL (receipt <digest>)"
receipt says WriteSucceeded        -> "CONTAINMENT FAILED ON THIS KERNEL (receipt <digest>)"
no receipt for this kernel         -> "OBSERVED (no drill receipt for this kernel)"
drill unmeasured                   -> "OBSERVED (unmeasured: <reason>)"
```

The last two both say Observed — unmeasured and absent are the same claim about the evidence —
but with different reasons, because an operator reading the profile needs to know whether
nobody ran the drill or the drill could not run.

**The evidence file's per-kernel table, the shape the CI matrix fills:**

```text
| kernel                          | outcome      | receipt    | rendered as        |
|---------------------------------|--------------|------------|--------------------|
| linux-6.18 (dev, userns)        | Refused      | <digest>   | MEDIATED           |
| ubuntu-latest (CI)              | Refused      | <digest>   | MEDIATED           |
| windows-latest (CI)             | Unmeasured   | <digest>   | OBSERVED (unmeasured: bubblewrap absent) |
| wsl2-6.18-no-userns (doc)       | Unmeasured   | none       | OBSERVED (unmeasured: bwrap refuses to start) |
```

**Why `bound_strengths()` must not move even when the dev kernel promotes.** The static table
is the cross-kernel *floor*: every kernel starts at Observed and earns its rendering locally.
If the table moved to Mediated, every kernel without a receipt would inherit a claim its
evidence does not back — the `write_paths was signed Enforced with nothing enforcing it`
defect, distributed. The count-pinning tests are the tripwire, and this task's evidence states
that the tripwire fired for the right reason.
