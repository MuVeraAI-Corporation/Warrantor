# @muveraai/aumos-mcp-server

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes the **49 AumOS
components** as tools any MCP-compatible coding agent can discover and call.

Works with **Claude Code**, **OpenAI Codex**, **Cursor**, **Zed**, the **Claude Desktop** app,
and any client that speaks MCP JSON-RPC over stdio.

## What it gives an agent

An agent that connects to this server gains 15 first-class tools covering the AumOS security
primitives — signing, identity, receipts, attestation, preflight, kill-switch, secret scanning,
compliance, SBOM, and evaluation:

| Tool | Component | Purpose |
|---|---|---|
| `aumos_sign` | T1 trust-core | Ed25519 sign |
| `aumos_verify` | T1 trust-core | Ed25519 verify |
| `aumos_issue_identity` | I1 agent-identity | Issue SPIFFE SVID + capability token |
| `aumos_verify_identity` | I1 agent-identity | Verify an SVID |
| `aumos_revoke_identity` | I1 agent-identity | Revoke an identity |
| `aumos_emit_receipt` | E1 flight-recorder | Emit an Agent Action Receipt (P2 AAR) |
| `aumos_verify_receipt` | E1 flight-recorder | Verify a receipt signature |
| `aumos_check_attestation` | C1-1 nvtrust-bridge | Check a GPU attestation |
| `aumos_run_preflight` | R2 eval-guard | Run sandbox pre-flight checks |
| `aumos_kill` | R3 kill-switch | Trigger containment |
| `aumos_scan_secrets` | R4 credential-vault | Scan text for exposed credentials |
| `aumos_compliance_report` | X1 defstack-cli | Generate a compliance report |
| `aumos_install` | X1 defstack-cli | Install an AumOS component |
| `aumos_generate_sbom` | S4 model-sbom | Generate a Model SBOM (CycloneDX) |
| `aumos_run_eval` | A1 safe-eval | Run an evaluation pipeline |

## Two modes

- **`standalone`** (default): every tool returns a deterministic mock response. Zero external
  dependencies, zero network. Perfect for development, demos, and dry-runs.
- **`connected`**: tools issue real HTTP calls (I1, E1, C1-1, S4, A1, R2, R3, R4) and shell out
  to CLIs (`trust-core`, `defstack`). If a service is unreachable, the tool **degrades gracefully**
  to the standalone mock and sets `degraded: true` on the response — the agent always gets an
  answer.

## Install

```bash
# from the aumos repo root
cd typescript
npm install            # sets up the workspace
npm run build -w @muveraai/aumos-mcp-server
```

## Run

```bash
# standalone (default)
npx aumos-mcp

# connected — point at your running services
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
      "args": ["-y", "@muveraai/aumos-mcp-server"],
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
      "args": ["typescript/aumos-mcp-server/dist/index.js"],
      "env": { "AUMOS_MODE": "connected", "AUMOS_AGENT_IDENTITY_URL": "http://localhost:8441" }
    }
  }
}
```

## Programmatic use

```ts
import { ListTools, CallTool, Server } from '@muveraai/aumos-mcp-server';

// Inspect the catalog
const { tools } = ListTools();

// Call a tool directly (no stdio)
const result = await CallTool('aumos_scan_secrets', { text: 'token=ghp_…' }, { mode: 'standalone' });
console.log(result.data);        // { findings, count, source }
console.log(result.isError);     // false

// Run the JSON-RPC server over stdio
await new Server({ mode: 'standalone' }).run();
```

## Transport & protocol

- **Transport**: stdio (newline-delimited JSON-RPC 2.0). Requests on stdin, responses on stdout,
  logs on stderr. This is what MCP clients expect.
- **Protocol version**: `2024-11-05`.
- **Methods**: `initialize`, `ping`, `tools/list`, `tools/call`, `notifications/initialized`.
- **Error handling**: a tool failure is returned as `{ isError: true, ... }` — the server never
  crashes (AumOS invariant I-09: fail-closed, never silent).

## Configuration reference

| Env var / option | Default | Notes |
|---|---|---|
| `AUMOS_MODE` | `standalone` | `standalone` or `connected` |
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
npm test -w @muveraai/aumos-mcp-server
```

## License

Apache-2.0.
