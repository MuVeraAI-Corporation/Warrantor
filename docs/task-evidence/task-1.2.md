# Task 1.2 — The egress broker into the `--egress` flag, with capability-derived destinations (L4-02, L4-23)

**Branch:** `feat/egress-capability-catalog` (from `origin/main` @ `dbe653a`)
**Worktree:** `M:/wt-1.2` (target dir `M:/wt-1.2/target`, per the task's own Step line)
**Date:** 2026-09-05
**Commits (in Step order):** `a08bee5` (Steps 1–2), `fa639d2` (Steps 3–4), `eb44d19` (Steps 5–6),
`dedc7c0` (Steps 7–8), `040526e` (Step 9), `a279ad1` (Steps 10–11), `258f714` (Step 12),
`44db505` (Step 13). Evidence file committed as the final commit.

**Why this task started while the board read "BLOCKED on phase 0":** the only unmerged Phase 0
work is this lane's own Task 0.5 (`feat/invariant-ledger`, awaiting a human merge), whose files
(`evidence/invariants.json`, `tools/ci/*.py`, `docs/02-architecture.md`, `.gitignore`, `ci.yml`)
do not overlap Task 1.2's code. The standing instruction for this session is to continue
implementing without stopping for merges; merges remain a human's, and the one shared file
(`docs/W1-delivery-gaps.md`) is edited in different sections (§3.1 here, `## The honest summary`
in 0.5), so the later merge is mechanical.

---

## The exit gate, quoted verbatim from the plan

Step 12:

> Run the full gate (`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -j 2
> -- -D warnings`, `cargo test --workspace --all-targets -j 2`, `cargo build --workspace
> --all-targets -j 2`).

And the live check:

> Live check on a scratch repo: `warrantor grant --goal g --tools http.fetch --write 'src/**'
> --egress api.github.com`, then `warrantor mcp --agent <id>` and send
> `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"http.fetch","arguments":{"url":"https://paste.example/x"}}}`
> on stdin: expect `isError: true` with `egress_hosts`, and `<root>/egress/<id>.jsonl` holding one
> `not_a_capability` line; `warrantor report <id> --export r.json` then `warrantor verify r.json`
> on a second machine with the issuer pinned.

## Its actual output

### The full gate

```
$ cargo fmt --all -- --check
(exit 0)

$ cargo clippy --workspace --all-targets -j 2 -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 4m 34s   (exit 0)

$ cargo test --workspace --all-targets -j 2
TEST-EXIT=0 ; 102 suites `test result: ok`; none FAILED
  (first run caught instructions.rs::every_flag_the_usage_text_names_is_one_the_parser_accepts
   failing on the new --egress-capability flag name — see Deviations)

$ cargo build --workspace --all-targets -j 2
BUILD-EXIT=0
```

### The live check, run for real (scratch root `M:/wt-1.2-live`, warrant `wrt_463f768c12893b3b`)

```
$ warrantor grant --root R --goal "live egress check" --tools http.fetch --write "src/**" --egress api.github.com
warrant  wrt_463f768c12893b3b        (catalog written: catalogs/wrt_463f768c12893b3b.json)

$ printf '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"http.fetch",
  "arguments":{"url":"https://paste.example/x"}}}\n' | warrantor mcp --agent <id> --root R
{"id":1,"jsonrpc":"2.0","result":{"content":[{"text":"refused by the warrant's egress_hosts bound:
egress to paste.example is refused: it was supplied as a raw address rather than as a permitted
destination. ...","type":"text"}],"isError":true}}

$ cat R/egress/wrt_463f768c12893b3b.jsonl
{"format":"warrantor.egress-decision/1","warrant_id":"wrt_463f768c12893b3b","at":1788628684,
 "tool":"http.fetch","argument":"url","capability":"net.egress:paste.example",
 "destination":"paste.example","verdict":{"outcome":"deny","reason":"not_a_capability"},
 "catalog_digest":"cc6eaaa15a11f653ce1698dda7dce3a8496c780a3c2678907e1958c8824d9957"}

$ warrantor report <id> --root R --export R/report.json   → bundle.egress.receipts: 1
$ warrantor verify R/report.json --issuer <evidence_receipt's public key>
   → verified (limitations text printed; exit 0)

$ warrantor verify R/catalogs/<id>.json --root R
warrantor: catalog ... verified.
format    warrantor.destination-catalog/1  warrant wrt_463f768c12893b3b  capabilities 1
  host:api.github.com  -> api.github.com  --egress api.github.com (compiled from the flag)
  (followed by ENFORCEMENT_NOTE verbatim)
```

(The plan's "second machine" is approximated by `--issuer <hex>` on the verify call — the key was
passed on the command line, not read from the store that produced the file.)

### Per-step red-then-green

| Step | Red | Green |
|---|---|---|
| 1 | `error[E0432]: unresolved import warrantor_warrant::catalog` | (Step 2) |
| 2 | clippy: `SIGNING_DOMAIN` never used → trimmed for this commit, re-added in Step 4 | 3 passed → `a08bee5` |
| 3 | `error[E0599]: no method named 'sign'` (+ `save`/`load`/`catalog_path`) | (Step 4) |
| 4 | — | 6 passed → `fa639d2` |
| 5 | `error[E0599]: no method named 'with_vocabulary'` (+ `resolve_destinations`, `read_decisions`) | (Step 6) |
| 6 | — | 9 passed; `--test egress --test proxy` unchanged (34+16); lib 136 → `eb44d19` |
| 7 | `error[E0599]: no method named 'with_catalog'` | (Step 8) |
| 8 | first cut put `flush_egress_log` in the trait impl (`E0407`), moved to `impl AgentEndpoint` | 11 passed; mcp/upstream/guard 31+20+11 → `dedc7c0` |
| 9 | — (a lint that pins existing state) | 13 passed → `040526e` |
| 10 | `E0432 EgressSection` / `cannot find function egress_section` / `no method with_egress` | (Step 11) |
| 11 | — | egress crate 13 unchanged; wiring 14 passed; report 42 → `a279ad1` |
| 12 | workspace suite caught `instructions.rs` (see Deviations) | full gate green → `258f714` |
| 13 | — | ledger entry → `44db505` |

## Honest tier of every bound introduced

**No tier moved.** `bound_strengths()` is untouched; `egress_hosts` stays `Mediated`, and
`tests/egress_broker_wiring.rs::egress_hosts_stays_mediated_and_says_so` pins it inside this
task's own test file. What changed is what an agent can *express*: under a verified catalog in
enforce mode, a destination argument is a capability name or the call is refused before the
broker — the L4-23 property. The decision log (`warrantor.egress-decision/1`) is **unsigned**
(the proxy holds no key) and the report section (`EgressSection`) is the issuer countersigning
that log at report time; its note and the new `limitations` line say both halves out loud: it
covers calls that traversed the proxy and nothing else.

## Deviations from the plan's letter, and why

1. **`tests/instructions.rs::ACCEPTED_FLAGS` gained `"egress-capability"`.** The plan's Step 12
   added the flag to the usage text but did not name this test file. The workspace suite caught
   the consequence on the first run: the usage text named a flag the test's inventory lacked —
   the exact "`--upstream` defect" class that test exists to catch. The flag is genuinely wired
   (cmd_grant reads it; the live run above exercised it), so listing it is recording reality, not
   weakening the test.
2. **Unused-import hygiene per commit.** The plan's Step 2 code carries imports Steps 4–11 use
   and says to trim if the steps land in separate commits; the same applied to the test file's
   helpers (`NOW`, `bounds_with`) and later imports (`BTreeMap`, `json`, `Value`,
   `read_decisions`), which clippy's dead-code and unused-import lints reject per commit. Each
   landed with only what that commit uses; later steps re-added theirs.
3. **`cmd_report` wiring.** The plan's sentence reads as a conditional method chain; implemented
   as `match report::egress_section(...) { Some(section) => built.with_egress(section), None =>
   built }` — the library gained no new method beyond the plan's Produces list.
4. **Line-number drift** (VALUELESS_FLAGS at 255–272, usage at 476, cmd_grant's egress_hosts at
   785, decide's egress loop at ~228): each edit anchored on the named code.

## Gates this task could not run, and why

- `python tools/ci/check_phase_scope.py` — not present on this branch's base; run from the main
  checkout in the Task 0.5 session with exit 0. This task adds no plan tasks, so its scope is
  unchanged.
- `python tools/ci/wiring_census.py` — also not on this base (it landed with Task 0.3, which is
  merged on origin/main *after* this branch's cut). The census counts crates reachable from
  `warrantor-warrant`; this task adds no crate and no workspace member, only modules inside the
  already-linked `warrant` crate, so the count cannot fall. The merged-tree census run in the
  0.5 session printed `9 of 39 ... over 17 path edges` before this branch's changes.
- US-English on `docs/W1-delivery-gaps.md`: the 16 pre-existing findings documented in the 0.5
  evidence file are unchanged; the paragraph this task adds is clean.
