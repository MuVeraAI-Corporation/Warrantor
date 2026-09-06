# Task 2.1 — Effect decomposition registry with strict-mode refusal (L4-01; Phase 2 keystone)

Branch `feat/effect-decomposition-registry`, twelve commits, merged to `main` at `371037d` on
2026-09-06. Worktree `M:/wt-w5-2.1` (the plan's Step 1 names `M:/wt-2.1`; wave numbering was added
to keep concurrent lanes apart). Unblocks Tasks 2.2–2.6, all of Phase 3, and Task 7.1 steps 6–9.

| commit | what | plan step |
|---|---|---|
| `39eb548` | the nine effect syscalls as the declaration vocabulary; `tests/effects.rs` | 2–3 |
| `ddff555` | `Decomposition` parsing and the lossy projection to `SideEffectClass` | 4–5 |
| `94869ab` | `DecompositionRegistry`: builtin, insert, merge, versioned document that refuses foreign formats and conflicts | 6–7 |
| `180b817` | the strict-mode refusal sentence pinned; the permissive guess pinned beside it | 8 |
| `bd25984` | the unseen-schema corpus (`fixtures/tool-schemas.jsonl`): the strict gate defaults nothing | 9 |
| `de035b2` | the guess is reproduced at the endpoint before anything is refused | 10 |
| `104dec4` | forwarded tools classified by decomposition; `--upstream-strict` refuses the undeclared | endpoint wiring |
| `84c25c2` | the `mcp` verb's decomposition flags tested at the parser | endpoint wiring |
| `248764a` | the declaration is checked with nothing attached; the five-class `--upstream-class` map retired | endpoint wiring |
| `66ef022` | merge of `main` (the US-English gate fix) | — |
| `04ee509` | three sentences that claimed more than the code does, corrected (claim-honesty lens) | review |
| `6eea354` | the no-upstream check tested through the binary; the disclosure constant repaired (test-rigor lens) | review |

Files: `rust/warrant/src/effects.rs` (new, 476 lines), `src/bin/warrantor.rs` (+332), `src/mcp_endpoints.rs`,
`tests/effects.rs`, `tests/effects_endpoint.rs`, `tests/upstream_no_server.rs` (all new), two fixtures,
`docs/W1-delivery-gaps.md`. 1,496 insertions, 102 deletions.

## The exit gate, quoted verbatim from the plan

> **Acceptance (the Phase 2 exit gate's first clause):** a live `warrantor mcp --agent <id> --upstream
> 'files=npx -y @modelcontextprotocol/server-filesystem .' --upstream-strict` session, with no
> `--upstream-effects`, answers the agent's first `files.read_file` with the strict refusal sentence and
> names `files.read_file` on stderr at session end; the same session started with `--upstream-effects
> 'files.read_file=net'` forwards it. That transcript, not the fixture, is what the ledger entry may
> cite as built.

## Status of that acceptance: RUN, 2026-09-06, transcript below

Binary `M:/wt-merge-target/debug/warrantor.exe` built from main `371037d` (the merged tree). Upstream:
`@modelcontextprotocol/server-filesystem` 2026.8.31, fetched with `npx -y` (27 MB with dependencies),
serving a sandbox directory holding one file, `hello.txt`, containing `hello from the sandbox`. The
agent side is two newline-delimited JSON-RPC lines piped into the binary: `initialize`, then
`tools/call` for `files.read_file` on that file. Warrant `wrt_cefe3e146cd4f99d` granted with `--tools files.read_file`.

**One deviation from the plan's literal command, which is itself a finding.** The plan writes the
upstream as `npx -y ...`. On Windows the binary spawns the program directly (`Command::new`, no
shell), and `npx` is a `.cmd` shim, so the literal command fails before any session starts:

```
$ warrantor mcp --agent wrt_cefe3e146cd4f99d --upstream 'files=npx -y @modelcontextprotocol/server-filesystem .' --upstream-strict
warrantor: could not start the upstream MCP server "npx": program not found
exit 1
```

Both sessions below use `npx.cmd` with the same package and arguments. The defect is recorded in
`finding-upstream-npx-windows.md`; the acceptance clause is about what the session does once the
server is attached, and that is unchanged by the shim.

### Session 1: strict, nothing declared. The first `files.read_file` is refused and named at session end.

```
$ warrantor mcp --agent wrt_cefe3e146cd4f99d --upstream 'files=npx.cmd -y @modelcontextprotocol/server-filesystem .' --upstream-strict
--- stdout (what the agent receives) ---
{"id":1,"jsonrpc":"2.0","result":{"capabilities":{"tools":{"listChanged":false}},"protocolVersion":"2025-06-18","serverInfo":{"name":"warrantor-agent","version":"1.0.0"}}}
{"id":2,"jsonrpc":"2.0","result":{"content":[{"text":"files.read_file has no declared effect decomposition, and this session is strict. This build can only tell what a call DOES for the tools it stages; for everything else the decomposition is what an operator declared, and an undeclared tool would otherwise be forwarded as if it only read. Declare it: --upstream-effects 'files.read_file=mutate' (verbs: net, cred, exec, mutate, msg, spend, delegate, actuate, attest, joined with '+'), or load a warrantor.effect-registry/1 file with --upstream-effects-file <path>.","type":"text"}],"isError":true}}
--- stderr (what the operator sees) ---
Secure MCP Filesystem Server running on stdio
Client does not support MCP Roots, using allowed directories set from server args: [<the sandbox directory>]
warrantor: upstream -- files (14 tools) attached, 30s per-call deadline.
warrantor: upstream -- 0 tool decomposition(s) declared; STRICT: an undeclared tool will be refused.
warrantor: MCP agent endpoint for wrt_cefe3e146cd4f99d (enforce). Lifecycle tools are not published on this endpoint.
warrantor: upstream -- 1 tool(s) had no declared effect decomposition: files.read_file. Under --upstream-strict they were refused; otherwise each was given a GUESSED decomposition (read) -- and then forwarded, or, with no upstream attached, met with the no-upstream refusal. Declare each with --upstream-effects '<tool>=mutate' (or the verbs it really has) so a write is staged rather than performed.
warrantor: upstream -- 0 call(s) forwarded, 0 undeliverable, to files (14 tools).
--- exit 0 ---
```

The refusal is the strict sentence, returned as the tool result with `isError: true`. The session-end
line names `files.read_file` as the one tool with no declared decomposition and states that under
`--upstream-strict` it was refused. `0 call(s) forwarded`.

### Session 2: the same session started with `--upstream-effects 'files.read_file=net'`. The call is forwarded.

```
$ warrantor mcp --agent wrt_cefe3e146cd4f99d --upstream 'files=npx.cmd -y @modelcontextprotocol/server-filesystem .' --upstream-strict --upstream-effects 'files.read_file=net'
--- stdout (what the agent receives) ---
{"id":1,"jsonrpc":"2.0","result":{"capabilities":{"tools":{"listChanged":false}},"protocolVersion":"2025-06-18","serverInfo":{"name":"warrantor-agent","version":"1.0.0"}}}
{"id":2,"jsonrpc":"2.0","result":{"content":[{"text":"hello from the sandbox\n","type":"text"}],"isError":false}}
--- stderr (what the operator sees) ---
Secure MCP Filesystem Server running on stdio
Client does not support MCP Roots, using allowed directories set from server args: [<the sandbox directory>]
warrantor: upstream -- files (14 tools) attached, 30s per-call deadline.
warrantor: upstream -- 1 tool decomposition(s) declared; STRICT: an undeclared tool will be refused.
warrantor: MCP agent endpoint for wrt_cefe3e146cd4f99d (enforce). Lifecycle tools are not published on this endpoint.
warrantor: upstream -- 1 call(s) forwarded, 0 undeliverable, to files (14 tools).
--- exit 0 ---
```

`1 call(s) forwarded`, and the result is the file's content, read by the filesystem server. A first
attempt at this session passed the file path in Windows 8.3 short form; the call was forwarded
(`1 call(s) forwarded`) and the filesystem server itself refused it as outside its allowed directory,
because the server compares path strings. That is the server's check, not this product's, and the
run above with the long-form path is the one the clause is read against.

**What this transcript establishes:** the Phase 2 exit gate's first clause, as the plan words it.
**What it does not establish:** anything about a write. `net` was declared because the plan says
`net`; a `read_file` declared as `net` is forwarded, not staged, and nothing here exercises
`mutate` staging through an upstream. That is Task 2.3's acceptance, not this one's.

## What the tests establish

- **Nine verbs and only nine.** `Syscall` parses `net`, `cred`, `exec`, `mutate`, `msg`, `spend`,
  `delegate`, `actuate`, `attest`; a tenth spelling is an error that names itself
  (`tests/effects.rs`; `upstream_no_server.rs` proves the same refusal through the binary, with a
  paired control so the assertion cannot pass by refusing every value).
- **Declaration only.** Nothing infers a decomposition from `inputSchema`. The corpus of twenty-six
  unseen tool schemas is refused wholesale under `UnclassifiedPolicy::Refuse` — the strict gate
  defaults nothing (`bd25984`).
- **The projection never weakens the block.** A multi-syscall decomposition projects to its
  highest-ranked `SideEffectClass`; `Physical` is not reachable from any syscall, so the observe-mode
  hard block that reads `Physical` is unchanged by this task.
- **The registry refuses foreign formats and conflicts.** A document with the wrong
  `EFFECT_REGISTRY_FORMAT`, or two declarations for one tool that disagree, is an error rather than a
  last-writer-wins.
- **The guess is reproduced before it is refused.** The shipped permissive policy still guesses and
  still names its guess (`de035b2`), so the refusal is measured against a demonstrated wrong answer,
  not an asserted one.
- **With no upstream the flag says so.** `NO_UPSTREAM_DECLARATION_DISCLOSURE` is a single clean
  sentence, tested for both its retraction (the declarations decide nothing here) and its positive
  half (a permitted staged effect is still staged and performed at settle).

## The honest tier of every bound this task introduces

| what this task adds | tier, in the vocabulary Task 0.4 fixed | why that word and not a stronger one |
|---|---|---|
| `--upstream-strict` refusal of an undeclared forwarded tool | **mediated** | it is a decision at the proxy chokepoint, real and before the adapter. What escapes it: an agent holding its own route to the same server, and any session with no `--upstream` attached, where the flag is inert and says so. No netns, no seccomp, no firewall stands behind it. |
| classification by declaration, projection to `SideEffectClass` | not a bound; an input to two existing ones | the observe-mode block and `staged_classes` keep their existing tier. This task changes *what they read*, not how far they reach. |
| refusal of a misspelled syscall at argument parse | not a bound on the agent | it bounds the operator's typo the day it is typed. It is fail-closed, and it is tested, but it constrains nothing the agent does. |

Nothing in this task is **Enforced**. No line here is a kernel, an OS boundary, or a signature check.

## What this task does NOT establish

- The kernel does not authorize, check or receipt a syscall. Authorization is still a tool-NAME
  allowlist (`proxy.rs`, `bounds.tools.contains(&call.tool)`). `receipts.rs`, `bundle.rs`, `report.rs`,
  `settle.rs`, `staging.rs` and `proxy.rs` contain zero occurrences of `Syscall`; `warrantor report`
  still prints a staged effect as `github.create_pr`. Task 2.3 moves staging onto syscalls.
- Declarations are unsigned. A registry document is trusted because the operator passed it. Task 2.2
  is the signed manifest.

## Corrections after adversarial review

**Claim-honesty (`04ee509`), three findings, all in prose, none in a mechanism.** The module header
said "The kernel authorizes, checks and receipts syscalls" in the present tense; its own
`deploy_to_prod` example disproves it (see the first bullet above). The no-upstream disclosure
justified itself with a false clause — "every permitted call is already answered with the
no-upstream refusal" — when `Decision::Stage` is reached before the no-upstream arm, so a permitted
`github.create_pr` is staged and performed at settle. The end-of-session line said undeclared tools
"were forwarded with a guessed decomposition" when, with nothing attached, they meet the refusal and
are counted as `permitted_no_route`. Each sentence now states what the code does.

**Test-rigor (`6eea354`), twelve mutations, two survivors, both in recovered work.** Deleting the
whole no-upstream block left the full gate byte-identical at 152 suites / 1546 passing: the check was
real and untested. It is now driven through the binary with a paired control. The unit test on the
disclosure stayed green while the sentence was mangled, and when hardened it found the shipped
constant already carried twenty runs of six spaces, certified by a substring test. The detector now
splits on single spaces and refuses any empty piece rather than searching for a two-space literal,
because a tool that squeezes whitespace squeezes exactly that literal and silently inverts the test.
Both mutations now go red.

**Evidence-truth held.** No rendered number on the branch disagreed with the artifact it described.

## Deviations from the plan's literal text

- Worktree `M:/wt-w5-2.1`, not `M:/wt-2.1`; branch name as the plan's Step 1 names it.
- `main` was merged into the branch once (`66ef022`) rather than rebased, to pick up the US-English
  gate fix; the merge is empty of conflicts.
- The acceptance was run with `npx.cmd` in place of the plan's `npx`; the literal command cannot be spawned on Windows (see the acceptance section and `finding-upstream-npx-windows.md`).

## Branch gate at `6eea354`

fmt 0, clippy 0, cargo 0 at 153 suites / 1548 passing / 0 failed / 20 ignored (`cargo test
--workspace`, doctests included). Census 13 of 41 over 22 edges; ratchet 82 at floor 82, 15 at
ceiling 15; ledger 12 invariants; `check_us_english.py` ok; `check_docs.py` PASS. Mutation control:
one injected double space in the disclosure turned the hardened test red, and the file was restored
byte-identical afterward.

## Post-merge gate on main `371037d` (2026-09-06)

Run on the merged tree itself, not the branch, with `CARGO_BUILD_JOBS=2` from `rust/` and the
shared `M:/wt-merge-target`. Two earlier attempts on the same tree are recorded because each was a
false result: the first reported `exit=0` with `suites=0` (cargo was not on the background shell's
PATH; the count, not the exit, exposed it), the second died with `os error 1455` and rustc exit
`0xc000012d` (the Windows commit limit, 94 of 111 GB held by other processes) before any suite ran.

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 |
| `cargo test --workspace --all-targets` | 0; 119 suites, 1547 passed, 0 failed, 20 ignored |
| `cargo test --workspace --doc` | 0; 40 suites, 1 passed, 0 failed |
| Total passing | 1548, identical to the branch gate at `6eea354` |
| Wiring census | 13 of 41 crates over 22 edges (unchanged) |
| Invariant ratchet | 82 passing at floor 82; 15 recorded findings at ceiling 15 |
| Invariant ledger | 12 invariants; enforced 2, orphaned 1, partial 8, unimplemented 1 |
| `check_docs.py` | PASS, 268 Markdown files, 58 RFCs, 81 catalogue rows |
| `check_us_english.py 44fc3b8` | ok, 1445 added lines across 9 files |

The branch gate reported 153 suites; the difference is target selection only. `--all-targets`
counts six bench and example suites that contain no tests and does not run doctests, which are the
40 suites above. The passing total is the number that has to agree, and it does.
