# Finding: `--upstream 'name=npx ...'` cannot start on Windows

Found 2026-09-06 while running Task 2.1's acceptance, the first time an `--upstream` was attached
to a real server on this machine. Recorded here rather than fixed, because the fix touches
`upstream.rs` spawning and belongs in its own reviewed change.

## What happens

```
$ warrantor mcp --agent wrt_… --upstream 'files=npx -y @modelcontextprotocol/server-filesystem .' --upstream-strict
warrantor: could not start the upstream MCP server "npx": program not found
exit 1
```

`npx` resolves on this machine from any shell. The binary does not use a shell: `upstream.rs`
splits the spec on whitespace and calls `Command::new(program)` directly, which is deliberate and
documented there (a shell string would be parsed by whatever shell an operator tested in, not by
the parser that runs the command). On Windows, `npx`, `npm`, and most Node-installed tools are
`.cmd` shims, and `CreateProcess` does not run a `.cmd` file given its bare name. `npx.cmd` works:
the acceptance in `task-2.1.md` was run that way.

## Why it matters

Every example in the plan and in the binary's own usage text writes `npx -y …`. On Windows each of
them fails before a session starts, with an error that says the program does not exist when it
does. An operator following the documentation gets a refusal that points them at their PATH.

## What a fix would need to be

On Windows only, when the bare program is not found, retry with `.cmd` and `.exe` appended, and say
in the error which names were tried. Not a shell: the argument-splitting rule in `upstream.rs`
stays. The test is the existing `a_missing_program_is_a_spawn_error_naming_the_program` plus a
Windows-only case that spawns a `.cmd` file by its bare name. CI runs the workspace only on
Ubuntu, so that test runs nowhere until the Windows lane exists; it should be written anyway and
marked, so the gap is visible in the ignored count rather than absent.
