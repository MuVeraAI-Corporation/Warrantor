# Task 2.6 — Provenance labels on tool outputs and peer-proposal admission (L5-11, L5-12)

**Branch:** `feat/provenance-peer-proposals` (from local `main` @ `6f41384`)
**Worktree:** `M:/wt-2.6` · **Target dir:** `M:/wt-2.6-target`
**Date:** 2026-09-06

**Commits, in Step order:**

| commit | Steps | what |
|---|---|---|
| `59f35a1` | 1 | the `warrantor-agent-channel` link — vendored, because the crate existed only untracked |
| `5d5bc3c` | 2–3 | `warrantor.provenance/1`: `Trust` (one value), `Origin`, the label, `ToolResult::labeled`, `_meta` emission |
| `8cd0b20` | 4 | the endpoint labels every forwarded and staged result; `labeled_count` |
| `6c23e96` | 5–6 | `PeerProposal`, the signed envelope, the credential scan, `admit` — the eleven-gate order |
| `6d0115c` | 7 | the MSG/delegate receipt: signed, stored, verifiable offline |
| (Step 8) | 8 | anchor `Proposal` variant, `warrantor proposal compose|admit|list`, the `verify` arm, the end-of-session line |
| (this file) | 9 | W1 §2.5, the live run, the gates, this evidence |

---

## The exit gate, quoted verbatim from the plan

Task 2.6's acceptance paragraph:

> (1) `cargo test -p warrantor-warrant --test upstream` shows a real child process's answer coming back with a `warrantor.provenance/1` label whose compartment is the warrant id and whose expiry is the warrant's deadline. (2) `tests/proposal.rs` shows: a credential-carrying proposal for an *in-scope* tool refused with gate `credential_handle` and no credential bytes in the receipt; an out-of-scope proposal refused at bind naming `tools`; an admitted proposal after which `Proxy::decide` still refuses what it refused before; a replay refused; a tampered signature refused; a forged `Admitted` verdict failing verification. (3) The CLI round trip in the same file runs the real binary against a real store and `warrantor verify` accepts the export offline. (4) `Trust` deserializes only `"none"`. (5) The end-of-session line names the label count. (6) The ledger entry states what is not established.

## Its actual output

### The test path (red then green, one step at a time)

| Step | red | green |
|---|---|---|
| 2 | `E0432: unresolved Origin/ProvenanceLabel/Trust` + `E0599: no method labeled` | — |
| 3 | — | `--test provenance`: `3 passed`; mcp (20) and upstream (11) regressions unchanged |
| 4 | `E0599: no method labeled_count` | `--test upstream`: `12 passed` (the label test runs a real child process) |
| 5 | `E0432: unresolved admit/compose/credential_handle_in/PeerProposal/ProposalVerdict` | — |
| 6 | — | `--test proposal`: `8 passed` |
| 7 | `E0432: unresolved receipt_for/sign_receipt/verify_receipt/verify_receipt_signed_by/ProposalStore` | `10 passed` |
| 8 | — | CLI round-trip test (see the suite count in the final commit) |

### The live run (Step 9) — six transcripts, 2026-09-06

Store `M:/wt-2.6-live`, receiver warrant `wrt_0fcf5d3b3a979aa9` (`--tools selftest.echo --subject spiffe://muveraai.com/agent/receiver`):

1. **Admitted.** `warrantor proposal admit wrt_0fcf5d3b3a979aa9 p1.json --export r1.json`:
   ```
   admitted  25acd392564307ec25f68a60c05c688f59317e3bd0cd2a1fe8ea065ee6082f1c
     warrant     wrt_0fcf5d3b3a979aa9
     proposer    spiffe://muveraai.com/agent/peer  (key 1dcafab406f9e2b5; NOT pinned -- integrity verified, identity not established)
     proposes    selftest.echo
     selftest.echo is within the receiver's warrant; admitted as a proposal object. Nothing was granted and nothing was performed.
     authority   unchanged. Admission grants nothing and performs nothing; ...
     kept at     M:/wt-2.6-live\proposals\wrt_0fcf5d3b3a979aa9\000000.json
   ```
2. **A credential-carrying proposal is refused at admission, exit 1, nothing leaked.** `p2.json` proposed the same in-scope tool carrying `--arg api_key=sk-1`:
   ```
   refused at admission (credential_handle)  b4702466669cea5592eaa16dce4a1cffa0618df9461c45172190515ba9928494
   ```
   exit code `1`; `findstr sk-1 proposals\wrt_0fcf5d3b3a979aa9\*.json` finds nothing — the receipt names the gate, never the credential.
3. **An out-of-scope proposal is refused at bind, exit 1.** `p3.json` proposed `github.create_pr`:
   ```
   refused at bind (tools)  f7a7fcdc39feb514115a6bc09ffaf2ab91d69757749db755181207196105ddda
   ```
4. **`proposal list`** shows the decisions in order (admitted, refused:credential_handle, refused:replay from the re-admit attempts, bind:tools).
5. **Offline verify** on a clean root that pinned nothing (`warrantor verify r1.json --root M:/wt-2.6-clean`): `verified 25acd392…`, `syscall       msg (delegate-class decision)`, `authority     unchanged`, `anchor NONE pinned — self-consistency only`, and the line `the proposer's key is recorded, not pinned: integrity is verified, identity is not established`.
6. **The labeled forward.** A real `warrantor mcp --agent <id> --upstream "selftest=<bin> selftest-upstream"` session answered `tools/call selftest.echo` with `_meta.provenance` carrying `compartment: wrt_0fcf5d3b3a979aa9`, `format: warrantor.provenance/1`, the warrant's `expires_at`, and `trust: none`; stderr ended with `warrantor: provenance -- 1 result(s) left this endpoint carrying a warrantor.provenance/1 label: origin, trust=none, expiry, compartment, non-transitive.`

### The gates

Every cargo invocation was preceded by both disk guards. This task hit the longest commit-charge
outage of the window — the guard refused at 5.0–5.7 GB for roughly an hour mid-task — and the
wait-out procedure was followed to the letter; the Step 9 live run (which needs the binary but no
cargo) was executed during the outage rather than deleting anything or skipping the guard.

```
$ python tools/ci/disk_guard.py --require 60        exit 0 (every cargo invocation)
$ python tools/ci/disk_guard.py --require-commit 6  exit 0 (every cargo invocation; REFUSE episodes waited out)
$ cargo fmt --all -- --check                        exit 0 (at the final tree state)
$ cargo clippy --workspace --all-targets -j 2 -- -D warnings   exit 0
$ cargo test --workspace --all-targets -j 2         (count recorded in the final commit's evidence addendum)
$ cargo build --workspace --all-targets -j 2        exit 0
$ cargo metadata --format-version 1 --locked        exit 0 (the one unlocked refresh was Step 1's new edge)
$ python tools/ci/wiring_census.py                  (Task 0.3 is on main: reachable set recorded at the final state)
$ python tools/ci/check_invariant_ratchet.py        exit 0 (unchanged)
$ node verify-us-english.mjs docs/W1-delivery-gaps.md docs/task-evidence/task-2.6.md rust/warrant/src/provenance.rs
```

---

## The honest tier of every bound this task introduces

| what this task adds | tier | why that word and not a stronger one |
|---|---|---|
| the provenance labels | **Mediated** (the proxy sees only what routes through it) | every forwarded/staged result carries the label; the agent's own reads outside the proxy are beyond it, and the ledger entry says so. |
| the admission gates (signature, digest, replay, class, credential scan, lineage, population, expiry) | **Mediated** at the CLI/HTTP admit act | they refuse the *proposal*, not any action; an admitted proposal still binds nothing until the receiver's own endpoint decides each call. |
| the bind through `Proxy::decide` | Tier B, by construction | it is the same engine the real call faces; admission performs nothing and drops the proxy instance. |
| the receipts | Observed-tier evidence, signed by the issuer key | they record what was decided; nothing is prevented by their existence. |

`authority_widened` is structurally `false`, and `verify_receipt` refuses `true` — a receipt that
claims widening cannot verify, so the claim cannot be laundered through a re-signed export.

---

## Deviations from the plan's literal text, each earned

1. **The channel crate was vendored in Step 1.** The plan says "the survey lists it as orphaned
   from the warrant" — but on this tree `rust/agent-channel/` existed only as an *untracked
   directory* in the main working checkout, absent from `main` (verified: no commit in any ref
   touches it; `git ls-tree main rust/` has no `agent-channel`). Committing the Cargo.toml edge
   without the crate would leave every later commit unbuildable from a clean checkout. So Step 1
   commits `rust/agent-channel/{Cargo.toml,src/lib.rs}` verbatim from that checkout, alongside
   the workspace membership and the dependency line — exactly the resolution Task 1.1's evidence
   records for `delegation-chain` under the same situation ("Now: the delegation-chain crate is
   tracked and is the one algebra").
2. **The verify dispatch carries six formats, not four.** The plan's `Some(other)` sentence
   assumed four readable formats; main has accumulated catalog, conformance and effect-registry
   arms since. The proposal arm was inserted before the fall-through and the sentence lists all
   six plus the new one.
3. **`Proxy::bounds()` already existed on main** (it is the accessor `with_catalog` and the egress
   path use), so the plan's Produces item was a no-op; no second definition was added (a
   duplicate-definition error proved it on the first build).
4. **The plan's test fixture for Task 2.6 assumed Task 2.4's `exec` field**, which is on a
   different unmerged branch; the fixture here matches main's `WarrantBounds` shape.
5. **`serde_json::from_value` needed an explicit turbofish** in `admit` — inference cannot pin
   `T` across a match arm that only reads a field in a guard.
6. **The end-of-session provenance line uses format-args syntax**, not string concatenation (the
   plan's snippet concatenated a `&str` constant onto a literal with `+`, which does not compile
   in Rust).
7. **The peer key is generated via `getrandom::fill`**, not `SigningKey::generate(&mut csprng)` —
   the latter needs a rand feature this crate does not carry, and `getrandom::fill` is the
   entropy source the crate already uses (`archive_client.rs`).
8. **The usage block spells `proposal` with sub-verbs in the anchor-adjacent position** and the
   `--root`-last convention the other verbs' tests use; the round-trip test drives the real
   binary exactly as an operator would.

## Not done

- **`git push` and the PR were not run** (the brief's standing rule). Nothing here is merged.
