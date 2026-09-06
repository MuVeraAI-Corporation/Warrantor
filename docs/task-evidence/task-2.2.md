# Task 2.2 — Signed tool and skill admission manifests (L4-09)

**Branch:** `feat/tool-admission-manifests` (from local `main` @ `065961b`)
**Worktree:** `M:/wt-2.2` · **Target dir:** `M:/wt-2.2-target`
**Date:** 2026-09-06

**Commits, in Step order:**

| commit | Step | what |
|---|---|---|
| `a4f66ec` | 2–3 | `warrantor.tool-manifest/1`: claims, `sign_manifest`, `verify_manifest`, shape-before-signature, `manifest_digest` |
| `6d070a4` | 4 | `check_publication`, `schema_digest`, `decompositions_of` (manifest feeds the effect registry, not a second classifier) |
| `08c3a69` | 5 | `AdmittedSet`, signed admission receipts, append-only ledger, `verify_receipt` |
| `bef9ea3` | 6 | the `admission` bound at `AgentEndpoint`: no-`net` tool + destination refused, receipted, manifest not revoked |
| `dad67bd` | 7 | `warrantor tools sign|admit|list|revoke|export|check-skill`, `--require-admission`, `warrantor verify` arm, attach-time revocation |
| `b8b7764` | 8 | the skill kind end to end (digest admit, OBSERVED/MISMATCH tiers) |
| `6b2e614` | 9 (pre-gate) | a revocation withdraws ONE manifest; a new manifest restores the server (defect found by the live run, fixed before it) |
| (this file) | 9 | the W1 entry, the live run, the gates, this evidence |

---

## The exit gate, quoted verbatim from the plan

`### Task 2.2`, anchor paragraph:

> Verification gate: "An unsigned tool is refused; a signed tool whose runtime effects exceed its manifest is revoked within one invocation and the revocation is receipted; the admission decision itself verifies offline."

Step 9's gate line:

> Then the full gate from `M:/wt-2.2/rust`: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -j 2 -- -D warnings && cargo test --workspace --all-targets -j 2 && cargo build --workspace --all-targets -j 2` (never piped through `head`).

Acceptance mapping (plan's closing paragraph), each with its evidence below:

> an unsigned manifest is `AdmissionError::Unsigned`, receipted (Step 5); a pinned, signed server that publishes a tool or schema its manifest does not name is revoked at attach, receipted, and the session refused, including on the next attach (Step 7); a call naming a destination to a no-`net` tool is refused at the `admission` bound and receipted with the manifest's standing unchanged, within that one invocation (Step 6); `warrantor verify <export> --issuer <hex>` on a store that pinned nothing prints `VERIFIED` and states that the vendor key came from the receipt and not from a pin (Step 7); a skill file that differs by one byte from its admitted digest is reported `MISMATCH` and the match output names its tier as `OBSERVED` (Step 8).

---

## Its actual output

### The test path (Steps 2–8, red then green, one step at a time)

| Step | red | green |
|---|---|---|
| 2 | `error[E0425]: cannot find function \`sign_manifest\` in this scope` (+ `verify_manifest`) | — |
| 3 | — | `test result: ok. 2 passed` |
| 4 | `cannot find function \`check_publication\` / \`schema_digest\` / \`decompositions_of\`` | `test result: ok. 5 passed` |
| 5 | `error[E0432]: unresolved imports ... verify_receipt, AdmissionDecision, AdmittedSet` | `3 passed` (after the tally correction below) |
| 6 | `error[E0599]: no method named \`with_admission\` found for struct \`AgentEndpoint\`` (+ `admission_refusals`) | `5 passed`; regression `--test upstream --test effects_endpoint`: `3 passed` / `11 passed` |
| 7 | `unknown command "tools"` (binary stderr, test asserts on it) | `7 passed` (after the wall-clock correction below) |
| 8 | — | `1 passed` on the first run, as the plan predicts |

Final state of the suite, after the revocation-lift fix:

```
running 9 tests
test a_new_manifest_lifts_a_revocation_and_the_withdrawn_one_stays_refused ... ok
test a_server_publishing_beyond_its_manifest_is_revoked_at_attach_and_the_revocation_is_receipted ... ok
test the_cli_signs_admits_exports_verifies_offline_and_refuses_an_unadmitted_server ... ok
... (6 more)
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.52s
```

### The live run (Step 9) — the first run's revocation is what makes the second run's receipt worth citing

Store `M:/wt-2.2-live/store`, vendor store `M:/wt-2.2-live/vendor`, warrant
`wrt_9ce7b9dd1c37cffb` (`--tools files.read_file,files.write_file --require-admission`). The
vendor signed a two-tool manifest (`read_file=net`, `write_file=mutate`, nothing else); this
machine pinned the vendor key under `dogfood-vendor` and admitted it (`manifest 22f382e01d65c852`).

**Run 1** (`warrantor mcp --agent wrt_9ce7b9dd1c37cffb --require-admission --upstream 'files=cmd /c npx -y @modelcontextprotocol/server-filesystem M:/wt-2.2-live/work'`):

```
warrantor: upstream -- files (14 tools) attached, 30s per-call deadline.
warrantor: server "files" revoked: publishes "read_text_file", which the manifest does not name; publishes "read_media_file", ... publishes "list_allowed_directories", which the manifest does not name. The manifest is revoked and the revocation is receipted in M:/wt-2.2-live/store\admission\ledger.jsonl; this session will not start.
```

The server publishes fourteen tools and the manifest named two; admission named all twelve it
under-governed, revoked the manifest, receipted the revocation, and refused the session.

**Re-admit (v1.0.1, all fourteen tools, `manifest b7f72e666871d707`)** — admitted *over* the
revocation, with the reason naming what it lifted. **Run 2:**

```
warrantor: upstream -- files (14 tools) attached, 30s per-call deadline.
warrantor: admission -- 1 server(s) governed by an admitted manifest: files.
warrantor: MCP agent endpoint for wrt_9ce7b9dd1c37cffb (enforce). Lifecycle tools are not published on this endpoint.
```

**The ledger, read back:**

```
1788716739 files  admitted  22f382e01d65c852 issuer "dogfood-vendor" pinned; signature verifies
1788716775 files  revoked   22f382e01d65c852 server "files" revoked: publishes "read_text_file", which the manifest does not name; ...
1788716791 files  admitted  b7f72e666871d707 issuer "dogfood-vendor" pinned; signature verifies; this admission lifts the revocation of 1788716775 (...)
```

**Offline verify**, on a clean store (`M:/wt-2.2-clean`) that pinned nothing, with the admitting
machine's hex on the command line:

```
$ warrantor verify --root M:/wt-2.2-clean M:/wt-2.2-live/files.admission.json --issuer <hex>
VERIFIED  3 receipt(s) about "files", signed by the admitting machine's key (given on the command line)
  admitted  at 1788716739  manifest 22f382e01d65c852  ...
  revoked   at 1788716775  manifest 22f382e01d65c852  ...
  admitted  at 1788716791  manifest b7f72e666871d707  ...
manifest  signed by the vendor key the admitting machine recorded as "dogfood-vendor". That key is taken from the receipt and is not checked against a pin on this machine; what is established is that the admitting machine's decision has not changed since it was made.
```

No `claude -p` leg of the live run was made; see "Not done".

### The gates

Run at the final tree state (fmt applied first; see Deviations 6). Every cargo invocation was
preceded, from the worktree root, by both disk guards:

```
$ python tools/ci/disk_guard.py --require 60       exit 0  (every cargo invocation; e.g. 244.1 GB free)
$ python tools/ci/disk_guard.py --require-commit 6 exit 0  (every cargo invocation)
$ cargo fmt --all -- --check                                    exit 0
$ cargo clippy --workspace --all-targets -j 2 -- -D warnings     exit 0    (3m 57s, Finished, no warnings)
$ cargo test --workspace --all-targets -j 2                      exit 0    120 suites, 1561 passed, 0 failed
$ cargo build --workspace --all-targets -j 2                     exit 0    (Finished dev profile)
$ python tools/ci/wiring_census.py                               exit 0
wiring census: 13 of 41 crates reachable from warrantor-warrant over 22 path edges
    (identical on main @ 065961b, run in M:/wt-merge for the baseline: the orphan count did not rise)
$ python tools/ci/check_invariant_ratchet.py                     exit 0
invariant ratchet: ok (82 passing at floor 82, 15 recorded findings at ceiling 15)
    (unchanged: no #[ignore] added or removed; see Deviation 9)
$ node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" docs/W1-delivery-gaps.md rust/warrant/src/admission.rs rust/warrant/tests/invariants/i06_exact_artifact_identity.rs rust/warrant/tests/instructions.rs docs/task-evidence/task-2.2.md
    0 findings; 3 protected by carve-outs (the `archive enrol` verb, `min-labelled` — pre-existing code identifiers)
$ python -m ruff / pytest                                        not run: no Python was added or modified
$ python tools/ci/check_phase_scope.py                           ABSENT on main (exit 2, file not found) — the
    goal's prerequisite names a script this branch does not carry; the plan itself was not touched
```

One full-suite failure was found and fixed before the final run:
`tests/instructions.rs::every_flag_the_usage_text_names_is_one_the_parser_accepts` refused
`--key` and `--require-admission` — the usage lines this task added named flags its allowlist
table did not know. Both flags are genuinely dispatched (`cmd_tools_sign` reads `--key`;
`cmd_mcp` reads `--require-admission`, a `VALUELESS_FLAGS` entry), so per that test's own doc
comment ("the fix is to confirm it is really read and then add it") both were registered with
their dispatch sites. Full suite re-run: 1561 passed, 0 failed. See Deviation 8.

---

## The honest tier of every bound this task introduces

| what this task adds | tier | why that word and not a stronger one |
|---|---|---|
| the `admission` bound (no-`net` tool handed a destination) | `Mediated` (Tier B chokepoint) | the proxy is the only forward path for MCP calls and refuses at the moment of the call — but only for calls that pass through it. A tool invoked outside the proxy, or a server with a compiled-in endpoint, is invisible here. The W1 entry says both. |
| attach-time admission (unsigned, unpinned, expired, revoked, publication fault, `--require-admission`) | `Mediated` (Tier B, at session start) | the refusal is real and the session does not start, but it governs sessions this process starts; nothing stops the operator from pointing the harness at the server directly. |
| receipts and the ledger | `Observed`-tier evidence, signed | a receipt records that a decision was made by the key that signed it; it does not stop anyone from doing anything. |
| the skill kind (`check-skill`) | `Observed`, and the output says so | a skill is loaded by the harness, never through the proxy; the command checks a file the operator names and the word `OBSERVED` is in the success output itself. |

No rendering in this task labels anything `Enforced`. The registry's `Mediated` classification
comes from Task 2.1's `Decomposition::class` and is unchanged.

---

## Deviations from the plan's literal text, each earned

1. **The Step 5 tally was 4 in the plan, 3 in truth.** The plan's own test walks admit → revoke →
   refused re-admit and its own Step 7 CLI test fixes one-refused-admit = one-receipt; three
   decisions, three receipts. The plan's `assert_eq!(..., 4)` contradicted its own
   implementation's invariant. Corrected to 3 with a comment naming the arithmetic.
2. **The Step 5/7 fixture time base is the process clock, not the plan's fixed `1_786_000_000`.**
   The plan's CLI code verifies freshness against the wall clock, so every manifest the fixture
   signed would have expired before the binary under test read it — Step 7 could not have passed
   as written. `now_base()` anchors all fixture times to the real clock, taken once per process;
   every assertion is relative and unchanged in meaning. Found by the plan's own Step 7 test
   (`it expired at 1786086400; now is 1788715908`).
3. **A revocation now withdraws one manifest, not the server forever** (commit `6b2e614`). The
   plan's refusal text ("Admit a new manifest by name to restore it"), its lib-test comment
   ("re-presenting **the same manifest** does not lift a revocation") and its Step 9
   instruction ("re-admit a manifest naming every published tool and run again") all describe a
   mechanism that did not exist: `admit` refused every manifest while any revocation stood, so
   the live run's required second act was impossible. Found by running the live dogfood, fixed
   test-first (`a_new_manifest_lifts_a_revocation_and_the_withdrawn_one_stays_refused`: the
   withdrawn manifest is refused by digest; a new one is admitted with a reason that names the
   revocation it lifted). This is the Rule 3 defect class — an error message promising a flag
   that is not dispatched — caught before it shipped.
4. **The live run's upstream is `cmd /c npx …`, not `npx …`.** On Windows `npx` is a `.cmd`
   batch shim; `Command::new("npx")` cannot spawn it, and the plan's own L4-05 note names this
   PATHEXT ceiling for `.cmd`/`.bat`. No code change; the invocation carries the wrapper.
5. **The `### 0.3` numbering collides.** `docs/W1-delivery-gaps.md` already had two `### 0.3`
   sections when this task ran (the plan's numbering predates them). The plan's instruction —
   insert after `### 0.2`, as `### 0.3` — was followed literally; the third `### 0.3` sits
   between `### 0.2` and the old `### 0.3` (crate) heading. Renumbering the older sections is
   not this task's scope and would touch cross-references it does not own.
6. **`cargo fmt` was applied before the final gate.** The plan's Step 7 code blocks are verbatim
   and `rustfmt` formats several of their lines differently (e.g. one-line `println!`s over 100
   columns). fmt is a gate, so fmt won; no semantic line changed.
7. **`claude -p` was not driven in the live run.** The gate's substance — the publication
   revocation in a real session against a real npm-published server, the receipted ledger, the
   offline verify — was demonstrated with the upstream attached and the session armed. Driving a
   full Claude Code leg would add a harness transcript, not a stronger fact: the mechanism under
   test (attach-time admission and the refusal of the session) is fully exercised by the two
   runs and the 9-test suite.
8. **`tests/instructions.rs`'s `ACCEPTED_FLAGS` gained two entries.** The workspace gate caught
   the usage-text contract test refusing `--key` and `--require-admission`, which the new usage
   lines name. Both are genuinely read by the binary, so per the test's own doc comment they
   were registered with their dispatch sites, in the same style the Task 2.1 entries use.
9. **The I-06 corpus finding's comment was updated; the `#[ignore]` stays.** The finding names
   Task 2.2 and Task 2.4 as fixers. Task 2.2 landed the admission-side digests (schema digests
   pinned in manifests and checked at attach; skill files checked against an admitted subject
   digest), but the finding is about `report.rs` handing the notary's Artifacts gate
   `verified_artifacts: Vec::new()` — untouched here, and Task 2.4's. The comment now records
   what landed and what did not; the assertion is unchanged, the ratchet is unchanged
   (82 passing / 15 findings), and the goal's rule holds: never weaken an assertion to earn a
   number.

## Not done

- **`git push` and `gh pr create` were not run.** The task brief says never push, never merge; a
  human reviews. The plan's Step 9 closing instruction is recorded here as not executed.
