# @warrantor/mcp-server

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes 15 security
operations backed by the canonical AumOS component catalog to MCP-compatible coding agents.

Works with **Claude Code**, **OpenAI Codex**, **Cursor**, **Zed**, the **Claude Desktop** app,
and any client that speaks MCP JSON-RPC over stdio.

## What it gives an agent

An agent that connects to this server gains 15 first-class tools covering the AumOS security
primitives — signing, identity, receipts, attestation, preflight, kill-switch, secret scanning,
compliance, SBOM, and evaluation:

| Tool | Component | Purpose |
|---|---|---|
| `warrantor_sign` | T1 trust-core | Ed25519 sign |
| `warrantor_verify` | T1 trust-core | Ed25519 verify |
| `warrantor_issue_identity` | I1 agent-identity | Issue SPIFFE SVID + capability token |
| `warrantor_verify_identity` | I1 agent-identity | Verify an SVID |
| `warrantor_revoke_identity` | I1 agent-identity | Revoke an identity |
| `warrantor_emit_receipt` | E1 flight-recorder | Emit an Agent Action Receipt (P2 AAR) |
| `warrantor_verify_receipt` | E1 flight-recorder | Verify a receipt signature |
| `warrantor_check_attestation` | C1-1 nvtrust-bridge | Check a GPU attestation |
| `warrantor_run_preflight` | R2 eval-guard | Run sandbox pre-flight checks |
| `warrantor_kill` | R3 kill-switch | Trigger containment |
| `warrantor_scan_secrets` | R4 credential-vault | Scan text for exposed credentials |
| `warrantor_compliance_report` | X1 defstack-cli | Generate a compliance report |
| `warrantor_install` | X1 defstack-cli | Install an AumOS component |
| `warrantor_generate_sbom` | S4 model-sbom | Generate a Model SBOM (CycloneDX) |
| `warrantor_run_eval` | A1 safe-eval | Run an evaluation pipeline |

## Two modes

- **`connected`** (default): tools issue real HTTP calls (I1, E1, C1-1, S4, A1, R2, R3, R4)
  and shell out to CLIs (`trust-core`, `defstack`). Dependency outages, command failures, and
  malformed responses return `isError: true` with a stable `CONTROL_*` code. Connected mode
  never manufactures a security outcome or crosses into the demo implementation.
- **`standalone`** (explicit opt-in): every tool returns a deterministic demo response. Zero
  external dependencies and zero network. Use only for development, demos, and dry-runs.

## Install

```bash
# from the aumos repo root
cd typescript
npm install            # sets up the workspace
npm run build -w @warrantor/mcp-server
```

## Run

```bash
# explicit standalone demo
npx aumos-mcp --standalone

# connected is the default — point at your running services
AUMOS_MODE=connected \
AUMOS_AGENT_IDENTITY_URL=http://localhost:8441 \
AUMOS_FLIGHT_RECORDER_URL=http://localhost:8445 \
npx aumos-mcp
```

## Wire it into an MCP client

### Claude Code (`~/.claude.json` or project `.mcp.json`)

```json
{
  "mcpServers": {
    "aumos": {
      "command": "npx",
      "args": ["-y", "@warrantor/mcp-server"],
      "env": { "AUMOS_MODE": "standalone" }
    }
  }
}
```

### Cursor / generic MCP

```json
{
  "mcpServers": {
    "aumos": {
      "command": "node",
      "args": ["typescript/mcp-server/dist/index.js"],
      "env": { "AUMOS_MODE": "connected", "AUMOS_AGENT_IDENTITY_URL": "http://localhost:8441" }
    }
  }
}
```

## Programmatic use

```ts
import { ListTools, CallTool, Server } from '@warrantor/mcp-server';

// Inspect the catalog
const { tools } = ListTools();

// Call a tool directly (no stdio)
const result = await CallTool('warrantor_scan_secrets', { text: 'token=ghp_…' }, { mode: 'standalone' });
console.log(result.data);        // { findings, count, source }
console.log(result.isError);     // false

// Run the JSON-RPC server over stdio
await new Server({ mode: 'standalone' }).run();
```

## Transport & protocol

- **Transport**: stdio (newline-delimited JSON-RPC 2.0). Requests on stdin, responses on stdout,
  logs on stderr. This is what MCP clients expect.
- **Current protocol version**: `2026-07-28`, with required per-request `_meta`, stateless
  `server/discover`, `resultType`, and list cache metadata.
- **Dual-era compatibility**: legacy `2025-11-25` and `2024-11-05` clients can explicitly use
  the `initialize` handshake; modern requests do not depend on connection state.
- **Methods**: `server/discover`, `ping`, `tools/list`, `tools/call`, cancellation notifications,
  plus the legacy `initialize` compatibility path.
- **Error handling**: a tool failure is returned as `{ isError: true, data: { code,
  dependency, retryable, ... } }` — the server never claims that a control succeeded when its
  dependency failed (AumOS invariant I-09: fail-closed, never silent).

## Configuration reference

| Env var / option | Default | Notes |
|---|---|---|
| `AUMOS_MODE` | `connected` | `connected` or explicit demo-only `standalone` |
| `AUMOS_AGENT_IDENTITY_URL` | `http://localhost:8441` | I1 HTTP gateway base URL |
| `AUMOS_FLIGHT_RECORDER_URL` | `http://localhost:8445` | E1 base URL |
| `AUMOS_NVTRUST_BRIDGE_URL` | `http://localhost:8447` | C1-1 base URL |
| `AUMOS_MODEL_SBOM_URL` | `http://localhost:8451` | S4 base URL |
| `AUMOS_SAFE_EVAL_URL` | `http://localhost:8455` | A1 base URL |
| `AUMOS_EVAL_GUARD_URL` | `http://localhost:8460` | R2 base URL |
| `AUMOS_KILL_SWITCH_URL` | `http://localhost:8461` | R3 base URL |
| `AUMOS_CREDENTIAL_VAULT_URL` | `http://localhost:8465` | R4 base URL |
| `AUMOS_TRUST_CORE_BIN` | `trust-core` | T1 CLI binary |
| `AUMOS_DEFSTACK_BIN` | `defstack` | X1 CLI binary |
| `AUMOS_HTTP_TIMEOUT_MS` | `5000` | HTTP call timeout |

## Test

```bash
npm test -w @warrantor/mcp-server
```

## License

Apache-2.0.
