# Task 2.5 — Generic HTTP adapter over the destination catalog (L4-27)

**Branch:** `feat/http-call-adapter` (from local `main` @ `6f41384`)
**Worktree:** `M:/wt-2.5` · **Target dir:** `M:/wt-2.5-target`
**Date:** 2026-09-06

**Commits, in Step order:**

| commit | Step | what |
|---|---|---|
| `f86467e` | 1 | `CatalogEntry.max_data_class` (absent-skipped, so existing catalog digests do not move) |
| `36f1515` | 2 | broker `catalog()`/`capabilities()`/`decide_capability()`, sugar entry becomes GET-only public-only, `CATALOG_VERSION` → `/2` |
| `7ab0765` | 3 | `EffectRegistry::builtin()` with `http.call` (scheme `call`), the github()→builtin() sweep across src, the decomposition declared in `effects.rs` (Task 2.1 is on main) |
| `b159bbd` | 4 | types, `DataClass`, `tool_spec` (closed schema), the schema-lint test |
| `70ca11e` | 5 | `capability_refusal` + the proxy hook: a raw or uncataloged capability refused and recorded before staging |
| `2404929` | 6 | `HttpAdapter`: re-decide at settle, method + data-class bounds, `validate_path`, digests not bodies, timing records |
| `133539a` | 7 | the agent endpoint publishes the closed schema via `staged_schema` |
| `ff79457` | 8 | `HttpsTransport` (redirects refused), `RoutedPerformer`, `build_performer(bounds)`, `http-calls/<id>.jsonl` persistence; serve's performer factory takes the warrant's bounds |
| `8c3c4e9` | 9 (fix) | `http.call` decomposed `net+mutate` — the live run caught `net`-only forwarding instead of staging |
| (this file) | 9 | W1 §3.10, the live run, the gates, this evidence |

---

## The exit gate, quoted verbatim from the plan

Task 2.5's acceptance paragraph:

> a request whose destination is not a catalog capability has no parameter to live in (Step 4 lint, Step 7 endpoint test) and is refused and receipted if smuggled (Step 5); a payload whose data class exceeds the capability refuses before any request is sent (Step 6, Step 9 item 4); every performed call has a `warrantor.http-call/1` record with start and finish milliseconds (Step 6, Step 9 item 3); `bound_strengths()` is unchanged and the bundle still says `egress_hosts` is `Mediated`.

## Its actual output

### The test path (red then green, one step at a time)

| Step | red | green |
|---|---|---|
| 1 | `E0609: no field max_data_class` | `--test an_entry_without...` ok; crate `14 passed` (2 test-literal sites in `egress/tests/` needed the field too) |
| 2 | `E0599: no method decide_capability` | `--test egress`: `41 passed` |
| 3 | `E0599: no function builtin` | the unit test + affected suites pass; `tests/effects.rs`'s builtin count 4→5 (and the http.call projection pinned — see the live-run fix below) |
| 4 | `E0432: unresolved tool_spec/ARG_*` | `2 passed` |
| 5 | `E0432: unresolved capability_refusal` | `7 passed` (+ proxy 16, egress 41 unchanged) |
| 6 | `E0432: unresolved HttpAdapter/validate_path` | `13 passed` |
| 7 | `additionalProperties: Bool(true) != Bool(false)` | `14 passed` (+ mcp 20 unchanged) |
| 8 | — | `cargo build --bins` clean; serve/serve_socket regressions pass |

### The live run (Step 9) — four transcripts, real network, 2026-09-06

Store `M:/wt-2.5-live/store`; warrant `wrt_3ccaf095eaca59e7` (`--tools http.call --egress api.github.com`), session over the real stdio endpoint:

1. **The schema is closed and the enum is the catalog.** `tools/list` publishes `http.call` with `additionalProperties:false` and `capability.enum = ["net.egress:api.github.com"]`, no `url` property (asserted by `the_http_schema_has_no_destination_parameter_and_is_closed` and `the_agent_endpoint_publishes_the_closed_http_schema`).
2. **A permitted call stages.** `tools/call {capability:"net.egress:api.github.com", method:"GET", path:"/zen", data_class:"public"}` → `Staged as call://staged/wrt_3ccaf095eaca59e7/1. This has NOT happened yet — it will be performed only if a human settles...`.
3. **A smuggled raw URL is refused and recorded.** `capability:"https://evil.example.com"` → `refused by the warrant's egress_hosts bound: egress to https://evil.example.com is refused: it was supplied as a raw address rather than as a permitted destination. It was named in the "capability" argument. The request is recorded for review.`
4. **Settle performs and records.** `warrantor settle wrt_3ccaf095eaca59e7`:
   ```
     released    call://staged/wrt_3ccaf095eaca59e7/1 -> http 200 sha256:cca6a89529e8de5218955e8a972f5b156175b155bd3de458d00deae1203742fc
     http        GET api.github.com /zen -> 200 in 162 ms (sha256:cca6a895...)
     receipts    2 issued to M:/wt-2.5-live/store\receipts\wrt_3ccaf095eaca59e7.jsonl
   warrant is now Settled
   ```
   `http-calls/wrt_3ccaf095eaca59e7.jsonl`: one record, `format: warrantor.http-call/1`, `GET api.github.com /zen`, `status 200`, `162 ms`, `resp_digest sha256:cca6a895…`, `bytes 26`. The zen line itself appears nowhere on disk or on the terminal.
5. **The negative run.** `wrt_6d2b640a857c3fcb`, same shape with `data_class:"internal"`: the call **staged** (the agent could express it), and settle refused it —
   ```
     FAILED      call://staged/wrt_6d2b640a857c3fcb/1: the payload is declared internal and the capability for api.github.com carries at most "public"
   stopped at call://staged/wrt_6d2b640a857c3fcb/1 (http.call): ... Effects before it are real; effects after it were not attempted.
   ```
   The warrant is `Held` and **no** `http-calls/wrt_6d2b640a857c3fcb.jsonl` exists.

### The defect the live run caught (and fixed, `8c3c4e9`)

The first decomposition of `http.call` was `net`-only, so `Decomposition::class()` projected to
`Read` — and a Read-class call is **forwarded** to an attached upstream, not staged. The first
live attempt returned the no-upstream refusal instead of a staged handle. The shipped
decomposition is `net+mutate` (a POST is a remote write; the catalog's `permitted_methods` bound
which writes at settle, which is exactly where the sugar-entry refusal expects to happen), and
`tests/effects.rs` pins the projection at `Write`.

### The gates

Every cargo invocation was preceded by both disk guards:

```
$ python tools/ci/disk_guard.py --require 60        exit 0 (every cargo invocation)
$ python tools/ci/disk_guard.py --require-commit 6  exit 0 (every cargo invocation)
$ cargo fmt --all -- --check                        exit 0
$ cargo clippy --workspace --all-targets -j 2 -- -D warnings   exit 0
$ cargo test --workspace --all-targets -j 2 -- --test-threads=1   (see the count in the final commit)
$ cargo build --workspace --all-targets -j 2        exit 0
$ python tools/ci/wiring_census.py                  exit 0 (unchanged vs main)
$ python tools/ci/check_invariant_ratchet.py        exit 0 (unchanged vs main)
$ node verify-us-english.mjs docs/W1-delivery-gaps.md CHANGELOG.md rust/warrant/src/adapters/http.rs ...
    (findings all pre-existing lines, byte-identical on main; added lines carry none)
$ python -m ruff / pytest                           not run: no Python was added or modified
$ python tools/ci/check_phase_scope.py              ABSENT on main (as in Tasks 2.2/2.3/2.4)
```

---

## The honest tier of every bound this task introduces

| what this task adds | tier | why that word and not a stronger one |
|---|---|---|
| the capability gate at the proxy (raw/uncataloged refused) | Tier B, under the existing `egress_hosts` bound | the proxy is still a chokepoint the agent could decline to use; `bound_strengths()` is unchanged and `egress_hosts` stays `Mediated`. |
| the settle-time method + data-class ceiling | Tier B (the settling process holds the credential) | the adapter re-decides against the same catalog; nothing OS-level stands behind it. |
| the timing records | Observed-tier evidence | `warrantor.http-call/1` records what was performed and when; they stop nothing, and they are not yet inside the signed evidence chain (Task 1.1's report path reads `receipts/`, not `http-calls/`). |

---

## Deviations from the plan's literal text, each earned

1. **The composition notes were resolved for the tree as it is.** Task 2.3 is NOT on main, so
   `settle` still takes five arguments and `EffectRegistry::register` (not `register_as`) is used;
   Task 2.1 IS on main, so `http.call` is declared in `DecompositionRegistry::builtin()` as
   `net` (later `net+mutate`, see 3) in the same commit as the registration. Task 1.2 is not on
   main, so the capability vocabulary is the broker's own `net.egress:<host>` sugar, made
   GET/public-only by this task exactly as the plan's composition note says.
2. **The decomposition is `net+mutate`, not `net`** — the plan's own Step 3 block wrote
   `register_as(TOOL, "net", "call", &[])` for the post-2.3 world, but `net` alone projects to
   Read and a Read-class call is forwarded, never staged. The live run caught the endpoint
   refusing every `http.call` with the no-upstream sentence. `net+mutate` projects to Write,
   which `staged_classes` stages by default; the catalog bounds the write at settle. The plan's
   own Step 6 sugar-entry test (`a_sugar_entry_refuses_writes_...` expecting a settle-time method
   refusal) is only coherent with the staging behavior this decomposition produces.
3. **`serve.rs`'s performer factory takes the bounds now.** The plan routes `http.call` in the
   CLI's `build_performer` only and leaves `serve.rs` untouched, but the HTTP settle route shares
   the same `Box<dyn EffectPerformer>` seam; leaving it would give the console's settle button a
   performer that refuses every `http.call` the CLI's could perform. The minimal change is the
   field signature `fn(&WarrantBounds) -> Box<dyn EffectPerformer>` — `no_adapter` takes the
   bounds and ignores them — and the CLI passes a closure that builds `RoutedPerformer` per
   request. The route itself is byte-for-byte the plan's shape otherwise.
4. **Two egress test files needed the new field** (`hard_deny_fail_closed.rs`,
   `metadata_floor.rs`) plus the invariants corpus fixture (`i11_self_change_is_governed.rs`):
   the plan's Step 1 counted only the three in-crate literals, and the field is not `#[serde(default)]`
   on the struct-literal side (Rust, not serde), so every constructor site needs it.
5. **`tests/effects.rs`'s builtin-registry test changed shape** (count 4→5, `http.call` pinned
   `net+mutate` projecting Write) rather than only passing through: the plan's Step 3 predicted
   "every existing test still passes", and one did not — because the builtin decomposition set
   genuinely changed. The test now asserts more.
6. **Step 9's transcript capture used piped stdio** (the same JSON-RPC `tests/mcp.rs` sends)
   rather than driving a full agent harness; the four transcripts above are the binary's own
   output, unmodified.

## Not done

- **`git push` and the PR were not run** (the brief's standing rule). The plan's Step 9 ledger
  entry is committed here; whoever opens the PR takes the merge steps.
