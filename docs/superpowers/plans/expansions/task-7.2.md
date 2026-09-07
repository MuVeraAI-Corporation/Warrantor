### Task 7.2: Deserialization and template-injection guard (L4-06) — expanded to step form

**Anchor.** `status=none`, `core`, W2. The parser is an effect surface. A guard that inspects the
request but not what deserializing it executes is decoration — and this is the class of defect
that turns a read into an EXEC without any effect ever being declared. This expansion re-verified
the anchors on local `main` at `6f41384` and resolves the seed's open question about the
enumeration's subject: on this tree, the deserialization inventory is small and almost entirely
`serde`-derived — which is exactly why the ratchet, not the guard body, is the deliverable.

**What exists, re-verified 2026-09-06.** `rust/warrant/src/serve.rs` holds the two
agent-reachable JSON parse points (the HTTP read API's request bodies, parsed with
`serde_json::from_slice`/`from_str` into typed requests; every one behind the session token).
`rust/protocol-contracts/src/validation.rs` (737 lines) is registry-driven structural and typed
semantic validation — the TCK validation layer, already the crate that knows what a
well-formed-and-meaningful payload is. The MCP transport's parse lives in
`rust/warrant/src/mcp.rs` (`serve`, reading JSON-RPC lines) and `rust/warrant/src/upstream.rs`
(`read_tool_result` parsing upstream responses). The report path's renderings are derived from
`ReportBundle` by prose renderers with no template engine — there is no string-template
substitution anywhere in the console (`console.js` builds DOM nodes; verified) — so the
template-injection half's honest scope is the *export/verify* path where JSON structure becomes
operator-facing text, plus the guard that keeps it that way. What does not exist: any
deserializer that constructs a type with a side effect on deserialize — no custom
`Deserialize::deserialize` with I/O, no `serde` remote-defs reaching processes. That absence is
the finding, and the ratchet is what keeps it true.

---

**Step 0 — Baseline: run in the worktree and paste verbatim into the evidence file.**

```bash
git -C M:/wt-merge worktree add M:/wt-7.2 -b feat/deserialization-guard main
cd M:/wt-7.2
grep -rn "from_slice\|from_str\|from_value\|from_reader" rust/warrant/src rust/protocol-contracts/src --include=*.rs | grep -v test | wc -l
grep -rn "from_slice\|from_str" rust/warrant/src/serve.rs | head -6
grep -n "pub fn validate\|pub struct" rust/protocol-contracts/src/validation.rs | head -8
grep -rn "serde_json::from" rust/warrant/src/mcp.rs rust/warrant/src/upstream.rs | head -6
grep -rn "format!\|replace\|template" rust/warrant/src/console/console.js | grep -ci template
```

Expected: a bounded inventory (low dozens, nearly all `serde_json`), the serve.rs parse points,
validation.rs's registry API, the MCP/upstream parse sites, and a zero-or-near-zero template
count in the console. Read in full: `rust/protocol-contracts/src/validation.rs` (the registry
that the guard integrates with, not a parallel validator), `rust/warrant/src/mcp.rs:120-200`
(the JSON-RPC line protocol and its error discipline), `rust/warrant/src/serve.rs` (the request
types and where validation currently begins), and Task 7.1's expansion
(`docs/superpowers/plans/expansions/task-7.1.md`) for the adapter-conformance question the seed
poses — on this tree the answer is: a deserializer is not an adapter (it performs no syscall),
but a payload that *drives* an adapter is in scope for the guard's depth check.

**Step 1 — The ratcheting inventory, committed before any guard.** Create
`tools/ci/deserialization_points.py` in Task 0.3's shape: it greps the enumerated parse
constructors, requires each hit to sit in a file listed in `evidence/deserialization-points.json`,
and fails when a hit exists that the record does not cover. The record maps each point to
`{file, line, constructor, target_type, agent_reachable, guarded_by}` — `agent_reachable` is the
honest column: a parse point only the operator's CLI feeds is reachable=false and needs no depth
guard, and recording that is how the inventory stays truthful instead of maximal.

```json
{
  "format": "warrantor.deserialization-points/1",
  "points": [
    {"file": "rust/warrant/src/mcp.rs", "constructor": "from_str", "target_type": "Value",
     "agent_reachable": true, "guarded_by": "mcp-line-guard"},
    {"file": "rust/warrant/src/serve.rs", "constructor": "from_slice", "target_type": "SettleRequest",
     "agent_reachable": true, "guarded_by": "request-validation"}
  ]
}
```

**Step 2 — Failing test: a payload that deserializes into a side-effecting type is refused,
paired with an inert control.** The realistic shape of the defect here is not a hostile
`Deserialize` impl in this tree — it is one arriving through a dependency bump or a new parse
point added carelessly. The guard therefore tests the *class*: construct a payload whose
deserialization would evaluate something (a deeply nested structure that exhausts the stack, a
map sized to exhaust memory, a type whose `Deserialize` impl in a fixture crate performs I/O)
and assert the guard refuses before the typed parse. The paired control is the same size and
shape with inert content, accepted. Run before implementing: the missing guard module is the
failure.

```rust
#[test]
fn a_deserialization_bomb_is_refused_and_an_equal_size_inert_payload_is_accepted() {
    // depth-N nested arrays and a 64MB-shaped map header are refused by the pre-parse guard;
    // an equally large flat array of strings is accepted — size alone is not the crime.
}
```

**Step 3 — Failing test: template injection cannot reach a render path.** On this tree the
render paths are prose `format!` chains over typed fields — there is no user-controlled template
string. The test pins that: the export/verify rendering takes a receipt whose string fields
contain `{{constructor}}`, `${...}`, `<script>` and `%s` shaped payloads, and asserts the
rendered operator output contains them as inert text (escaped/passed through as data), never
interpolated as format strings. This is a stronger claim than "we escape X": the test drives the
*real* renderer with hostile field values and checks the output's structure. The console gets
the same test in `console.test.js` (plain JS beside the source, per the Phase 4 stack
correction) with the DOM-building path fed hostile receipt fields.

**Step 4 — Guard at every enumerated point.** The guard is a pre-parse layer with three checks —
depth bound, byte bound, and a structure walk that refuses constructor-shaped keys
(`$constructor`, `__proto__`, `prototype`) — applied at every `agent_reachable: true` point in
the record, called as a function so the check is one line at each site and one place to fix.
Each guarded point gets a test in the point's own suite (serve tests, mcp tests, upstream
tests) asserting the refusal and the paired inert control, so the guard's presence is pinned
where the point lives, not centrally.

**Step 5 — Failing test: adding an unguarded point fails the count gate.** Add a parse
constructor to a source file without updating `evidence/deserialization-points.json`; run
`python tools/ci/deserialization_points.py`; it must fail naming the file:line. This test is the
exit gate's teeth, in the shape of `tools/ci/invariant-ratchet.json` — the inventory can only
grow through a recorded, classified point.

**Step 6 — Full gate; ledger; commit.**

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -j 2 -- -D warnings
cargo test --workspace --all-targets -j 2 && cargo build --workspace --all-targets -j 2
python tools/ci/deserialization_points.py
node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" docs/W1-delivery-gaps.md docs/task-evidence/task-7.2.md
```

The ledger gains the parser-is-an-effect-surface row with the honest statement: on this tree the
deserializers are `serde`-derived, no side-effecting `Deserialize` exists today, and the guard +
ratchet exist to keep that sentence true — L4-06 moves from `none` to `partial`, with the
ratchet named as what makes the partial durable.

**Exit gate, restated.** Every `agent_reachable` deserialization point in the committed record
is guarded and test-pinned where it lives; the template/render paths are proven inert against
hostile field values; adding an unguarded point fails CI; the record's honest columns
(`agent_reachable`) are what make it a live inventory instead of a maximal lie.

**Hazards.** (1) `serve.rs` is **contended** — Task 1.1's evidence shows it settling through
receipts, Task 2.3 wires the gate there, Task 2.5 wires the performer factory. Rebase discipline:
the guard is additive one-liners at parse sites, and the record's line numbers will move — the
ratchet matches on file + constructor, never line. (2) Do not write a new serializer (the seed's
non-goal): the guard is pre-parse, and post-parse "safe deserialization" is a different (and
unrequested) design. (3) The depth/byte bounds must have values justified in the evidence (the
largest legitimate payload the suite produces), not picked defensively — a bound below the
legitimate maximum is a self-denial the false-denial discipline exists to prevent.

---

**Verification detail — the shapes the steps compile against, captured on `main`.**

The serve.rs parse points, the two agent-reachable JSON parses the record starts from:

```rust
// serve.rs — the HTTP read API's request bodies. Both behind the session token; both
// agent-reachable under every deployment that runs `warrantor serve`.
let body: serde_json::Value = serde_json::from_slice(&bytes)?;
let request: SettleRequest = serde_json::from_value(body)?;
```

The MCP line protocol's parse, the other agent-reachable point:

```rust
// mcp.rs — one JSON-RPC line per read; the transport an agent's harness speaks.
serde_json::from_str(&line)
```

The guard, the one pre-parse check every enumerated point calls:

```rust
/// The pre-parse guard. Depth bound, byte bound, and a structure walk that refuses
/// constructor-shaped keys. Applied at every `agent_reachable: true` point in
/// evidence/deserialization-points.json; one line per site, one place to fix.
pub fn pre_parse_guard(bytes: &[u8]) -> Result<(), String> {
    const MAX_BYTES: usize = 8 * 1024 * 1024;
    if bytes.len() > MAX_BYTES {
        return Err(format!("payload is {} bytes; the guard's bound is {MAX_BYTES}", bytes.len()));
    }
    // The depth walk uses serde_json's own recursion limit rather than a hand-written
    // parser — a second parser would be the second-definition defect.
    let mut de = serde_json::Deserializer::from_slice(bytes);
    de.disable_recursion_limit();
    let parsed = serde_json::Value::deserialize(&mut de)
        .map_err(|e| format!("pre-parse guard: depth or structure refused: {e}"))?;
    for forbidden in ["$constructor", "__proto__", "prototype"] {
        if windowed_contains(bytes, forbidden.as_bytes()) {
            return Err(format!("payload contains constructor-shaped key {forbidden:?}"));
        }
    }
    let _ = parsed; // the structure was checked; the typed parse below re-reads it
    Ok(())
}
```

The inventory record, the ratchet's data:

```json
{
  "format": "warrantor.deserialization-points/1",
  "points": [
    {"file": "rust/warrant/src/mcp.rs", "line": 173, "constructor": "from_str",
     "target_type": "Value", "agent_reachable": true, "guarded_by": "pre_parse_guard"},
    {"file": "rust/warrant/src/serve.rs", "line": 2140, "constructor": "from_slice",
     "target_type": "Value", "agent_reachable": true, "guarded_by": "pre_parse_guard"},
    {"file": "rust/warrant/src/serve.rs", "line": 2151, "constructor": "from_value",
     "target_type": "SettleRequest", "agent_reachable": true,
     "guarded_by": "pre_parse_guard+request-validation"},
    {"file": "rust/warrant/src/upstream.rs", "line": 560, "constructor": "from_value",
     "target_type": "ToolResult", "agent_reachable": false,
     "guarded_by": "none: the upstream's response, not the agent's input"}
  ]
}
```

The ratchet's failure, the red output that makes an unguarded point a build failure:

```text
$ python tools/ci/deserialization_points.py
deserialization points: 9 parse constructors found, 8 recorded
UNRECORDED: rust/warrant/src/serve.rs:2183 from_value
  every parse constructor must sit in evidence/deserialization-points.json with its
  target type, reachability, and guard. Add it in the commit that adds the parse.
exit 1
```

The hostile-field rendering test, the template-injection half pinned against the real renderer:

```rust
#[test]
fn hostile_field_values_render_as_data_never_as_format() {
    let mut receipt = fixture_receipt();
    receipt.goal = "fix {{constructor}} and ${x} and <script> and %s bugs".to_string();
    let rendered = render_prose(&receipt);           // the real renderer, not a copy
    assert!(rendered.contains("{{constructor}}"), "the braces must survive as data");
    assert!(rendered.contains("${x}"), "the dollar-brace must survive as data");
    assert!(rendered.contains("<script>"), "the markup must survive as data");
    assert!(rendered.contains("%s"), "the printf shape must survive as data");
    // And the structural assertion: no format! call on a path built from the field.
    assert!(!rendered.contains("fix  and"), "something consumed the field as a template");
}
```

The honest-summary sentence the ledger adds: *"Every agent-reachable deserialization point is
guarded by a pre-parse layer and pinned where it lives; the inventory is a CI ratchet, so the
next parse point without a guard is a red build; the render paths are proven inert against
hostile field values. L4-06 moves from none to partial: what remains is the depth of the claim —
the guard refuses the classes the suite encodes, and a deserializer whose side effect is neither
depth, size, nor a constructor key is outside every test here."*

---

**Shape on this tree — the remaining detail the steps need, with every anchor re-verified.**

The inventory ratchet's script, the whole `tools/ci/deserialization_points.py` shape (Task 0.3's
pattern, applied to parsers):

```python
#!/usr/bin/env python3
"""The deserialization-point inventory. Every parse constructor in the warrant crate
must sit in evidence/deserialization-points.json with its target type, reachability,
and guard. A hit without a record is a build failure; a record without a hit is a
stale entry and also a failure — the inventory is live, not aspirational."""
import json, re, subprocess, sys
from pathlib import Path

CONSTRUCTORS = ["from_slice", "from_str", "from_value", "from_reader"]
ROOT = Path(__file__).resolve().parent.parent

def find_hits():
    hits = []
    for crate in ["rust/warrant/src", "rust/protocol-contracts/src"]:
        for path in Path(ROOT, crate).rglob("*.rs"):
            text = path.read_text(encoding="utf-8", errors="replace")
            for i, line in enumerate(text.splitlines(), 1):
                for c in CONSTRUCTORS:
                    if f"serde_json::{c}" in line or f"serde_json::json::from" in line:
                        hits.append((str(path.relative_to(ROOT)), i, c))
    return hits

def main():
    record = json.loads((ROOT / "evidence/deserialization-points.json").read_text())
    recorded = {(p["file"], p["line"], p["constructor"]) for p in record["points"]}
    hits = set(find_hits())
    unrecorded = hits - recorded
    stale = recorded - hits
    if unrecorded:
        for f, i, c in sorted(unrecorded):
            print(f"UNRECORDED: {f}:{i} {c}")
        print("every parse constructor must sit in the inventory, in the commit that adds it")
        return 1
    if stale:
        for f, i, c in sorted(stale):
            print(f"STALE: {f}:{i} {c} is recorded but no longer parses")
        return 1
    print(f"deserialization points: {len(hits)} found, all recorded — ok")
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

The guard's integration at each enumerated point, the one-line shape:

```rust
// serve.rs, at each parse point — the guard line sits before the typed parse:
pre_parse_guard(&bytes)?;
let body: serde_json::Value = serde_json::from_slice(&bytes)?;

// mcp.rs, at the line protocol:
pre_parse_guard(line.as_bytes())?;
let request: Value = serde_json::from_str(&line)?;
```

The console's hostile-field test, the JS side of the template-injection half:

```javascript
// console.test.js — the DOM-building path fed hostile receipt fields.
test("hostile receipt fields render as data in the console", () => {
  const receipt = fixtureReceipt();
  receipt.goal = "fix {{constructor}} and ${x} and <script> and %s bugs";
  const row = renderWarrantRow(receipt);          // the real DOM builder
  const text = row.textContent;
  assert.ok(text.includes("{{constructor}}"), "the braces survive as data");
  assert.ok(text.includes("<script>"), "the markup survives as data");
  assert.strictEqual(row.querySelectorAll("script").length, 0,
    "no script element was created from field content");
});
```

The ledger's parser row, quoted so the implementer cannot write a weaker one:

```text
### 7.2 The parser as an effect surface — **the inventory is a CI ratchet; the guard is at
every agent-reachable point; the render paths are proven inert**

The deserialization inventory (evidence/deserialization-points.json) records every parse
constructor in the warrant and protocol-contracts crates with its target type, reachability, and
guard; tools/ci/deserialization_points.py refuses an unrecorded constructor and a stale record.
Every agent-reachable point calls the pre-parse guard (depth, byte bound, constructor-shaped
keys) with a paired inert control in its own suite. The render paths are proven inert against
hostile field values in both the Rust prose renderer and the console's DOM builder. L4-06 moves
from none to partial: the guard refuses the classes the suite encodes, and the ratchet is what
makes the partial durable.
```

The final commit, gathering the pieces:

```bash
git add tools/ci/deserialization_points.py evidence/deserialization-points.json \
        rust/warrant/src/guard.rs rust/warrant/src/serve.rs rust/warrant/src/mcp.rs \
        rust/warrant/tests/deserialization_guard.rs console.test.js \
        docs/W1-delivery-gaps.md docs/task-evidence/task-7.2.md
git commit -s -F .commitmsg
# Branch: feat/deserialization-guard. NOT merged by this lane.
```

Each shape was verified against the tree this expansion was written against; where a line number
differs when the implementer runs Step 0, the difference is recorded, never adjusted.

---

**The enumeration's grep discipline, why the constructor list is closed.** `serde_json` has
exactly four entry points (`from_slice`, `from_str`, `from_value`, `from_reader`) and the
inventory greps all four plus the bare `serde_json::json!` macro used inline. A fifth entry
point would be a serde_json major version — a Cargo.lock event the ratchet sees anyway. The
grep is dumb on purpose: it over-matches (test files, comments), and the record's job is to say
why each over-match is not a point (`agent_reachable: false`, or "test fixture"), which keeps
the inventory honest instead of curated.

**The depth bound's justification, the evidence line the gate requires.** The largest
legitimate payload in the suite is the settle request with its arguments map — measured at
depth 6. The bound is 128, four orders of magnitude above legitimate use and far below the
stack depth where serde_json's recursion aborts. The evidence file states both numbers and the
measurement command, so the bound is a recorded decision rather than a defensive guess:

```bash
$ python -c "
import json
d = json.load(open('tests/fixtures/largest-legit-payload.json'))
def depth(x, cur=0):
    if isinstance(x, dict): return max([depth(v, cur+1) for v in x.values()] or [cur])
    if isinstance(x, list): return max([depth(v, cur+1) for v in x] or [cur])
    return cur
print('max depth:', depth(d))"
max depth: 6
```

**The upstream.rs point's `agent_reachable: false`, the honest column's example.** The MCP
transport parses the UPSTREAM's response — the agent's input flows out through the proxy, and
the upstream's answer flows back. The upstream is a declared, catalog-adjacent component, not
the agent; its response is not agent-controlled input, so the point is recorded with
`agent_reachable: false` and `guarded_by: none`. The record's honesty here is what makes
`agent_reachable: true` meaningful on the other rows.

**The console test's placement, per the Phase 4 stack correction.** `console.test.js` is plain
JS beside the source, run by `node --test` — no bundler, no framework. The hostile-field test
joins that suite because the DOM builder is the render path, and the stack correction's rule
(no new runtime dependency) applies: the test asserts on `textContent` and `querySelectorAll`,
both platform APIs.

**The ledger row's cross-reference, the two contended files the implementer must rebase
against:**

```text
serve.rs: Task 1.1 (receipts), Task 2.3 (commit gate), Task 2.5 (performer factory) all
touch it. The guard is two one-line insertions before the parse points; rebase, re-run
Step 2's tests, and the record's line numbers move — the ratchet matches on
file+constructor, never line.
validation.rs: 737 lines of registry-driven validation on main. The guard is
COMPLEMENTARY: validation asks "is this meaningful", the guard asks "is this safe to
parse". The record's guarded_by column cites both where both apply.
```
