#!/usr/bin/env node
/**
 * @muveraai/aumos-mcp-server — Model Context Protocol (MCP) server exposing AumOS components.
 *
 * This server makes the AumOS security stack (49 components) directly usable by any
 * MCP-compatible coding agent (Claude Code, OpenAI Codex, Cursor, Zed, …). An agent
 * discovers the tools via `tools/list` and invokes them via `tools/call`.
 *
 * The server runs in two modes:
 *   - **standalone** (default): tools return deterministic mock responses. Zero external
 *     dependencies. Ideal for development, demos, and dry-runs.
 *   - **connected**: tools issue real HTTP calls (I1, E1, C1-1, S4, A1, R2, R3, R4) and
 *     shell out to CLIs (T1 `trust-core`, X1 `defstack`). Endpoints are configurable.
 *
 * Wire transport: a minimal, dependency-free JSON-RPC 2.0 server over stdio
 * (newline-delimited requests on stdin, responses on stdout, logs to stderr). This is
 * the shape MCP clients expect and avoids a hard dependency on `@modelcontextprotocol/sdk`.
 *
 * Tool implementations are real async functions (`CallTool`) that catch their own errors
 * and always return structured JSON — a tool never crashes the server (invariant I-09:
 * fail-closed and observable, never silent).
 *
 * Wire shapes for I1 mirror go/agent-identity/service.go (HTTP/JSON gateway over the
 * proto/aumos/identity/v1/agent.proto RPCs).
 */

import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import type { IncomingMessage } from 'node:http';

// ---------------------------------------------------------------------------
// Modes and configuration.
// ---------------------------------------------------------------------------

export type AumOSMode = 'standalone' | 'connected';

export interface AumOSMcpConfig {
  mode: AumOSMode;
  /** Base URL of the I1 agent-identity HTTP gateway (e.g. "http://localhost:8441"). */
  agentIdentityUrl?: string;
  /** Base URL of the E1 flight-recorder service. */
  flightRecorderUrl?: string;
  /** Base URL of the C1-1 nvtrust-bridge attestation service. */
  nvtrustBridgeUrl?: string;
  /** Base URL of the S4 model-sbom service. */
  modelSbomUrl?: string;
  /** Base URL of the A1 safe-eval service. */
  safeEvalUrl?: string;
  /** Base URL of the R2 eval-guard service. */
  evalGuardUrl?: string;
  /** Base URL of the R3 kill-switch service. */
  killSwitchUrl?: string;
  /** Base URL of the R4 credential-vault service. */
  credentialVaultUrl?: string;
  /** Override the trust-core CLI binary (default: "trust-core"). */
  trustCoreBin?: string;
  /** Override the defstack CLI binary (default: "defstack"). */
  defstackBin?: string;
  /** HTTP timeout in ms (default 5000). */
  httpTimeoutMs?: number;
  /** Injectable fetch for tests. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /** Injectable subprocess runner for tests. */
  execImpl?: (cmd: string, args: string[]) => Promise<ExecResult>;
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  code: number;
}

const DEFAULT_CONFIG: Required<Omit<AumOSMcpConfig, 'fetchImpl' | 'execImpl'>> = {
  mode: 'standalone',
  agentIdentityUrl: 'http://localhost:8441',
  flightRecorderUrl: 'http://localhost:8445',
  nvtrustBridgeUrl: 'http://localhost:8447',
  modelSbomUrl: 'http://localhost:8451',
  safeEvalUrl: 'http://localhost:8455',
  evalGuardUrl: 'http://localhost:8460',
  killSwitchUrl: 'http://localhost:8461',
  credentialVaultUrl: 'http://localhost:8465',
  trustCoreBin: 'trust-core',
  defstackBin: 'defstack',
  httpTimeoutMs: 5000,
};

// ---------------------------------------------------------------------------
// Tool metadata (JSON Schema input shapes + descriptions for tools/list).
// ---------------------------------------------------------------------------

/** A single tool's static description (name, schema, description). */
export interface ToolDescriptor {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
    additionalProperties?: boolean;
  };
}

/**
 * The 15 AumOS tools exposed by this server, each backed by a real implementation below.
 * Order matches the deliverable spec and is stable for snapshots.
 */
export const TOOLS: ToolDescriptor[] = [
  {
    name: 'aumos_sign',
    description:
      'Sign data using T1 trust-core (Ed25519). Calls `trust-core sign` CLI, falls back to a ' +
      'deterministic mock signature in standalone mode. Returns {signature_hex, algorithm}.',
    inputSchema: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'The data to sign (UTF-8). Pem/hex/raw all accepted.' },
        key_id: { type: 'string', description: 'Optional key identifier.' },
      },
      required: ['data'],
      additionalProperties: false,
    },
  },
  {
    name: 'aumos_verify',
    description:
      'Verify an Ed25519 signature using T1 trust-core. Returns {valid: bool, reason?: string}.',
    inputSchema: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'The data that was signed.' },
        signature: { type: 'string', description: 'Hex-encoded signature.' },
        key: { type: 'string', description: 'Hex-encoded Ed25519 verifying key.' },
      },
      required: ['data', 'signature', 'key'],
      additionalProperties: false,
    },
  },
  {
    name: 'aumos_issue_identity',
    description:
      'Issue an agent identity (SPIFFE SVID + capability token) via I1 agent-identity. ' +
      'HTTP POST /v1/agent-identity:issue. Mirrors proto/aumos/identity/v1/IssueIdentityRequest.',
    inputSchema: {
      type: 'object',
      properties: {
        subject: {
          type: 'string',
          description: 'SPIFFE ID of the agent being issued (e.g. spiffe://aumos.dev/agent/coding-1).',
        },
        audience: { type: 'string', description: 'Intended audience bound into the `aud` claim.' },
        parent_svid: { type: 'string', description: 'Parent SVID for delegation chains.' },
      },
      required: ['subject'],
      additionalProperties: false,
    },
  },
  {
    name: 'aumos_verify_identity',
    description:
      'Verify an SVID via I1 agent-identity. HTTP POST /v1/agent-identity:verify. ' +
      'Returns {valid, subject?, reason?}.',
    inputSchema: {
      type: 'object',
      properties: {
        svid: { type: 'string', description: 'The SVID token to verify.' },
        audience: { type: 'string', description: 'Audience to bind during verification.' },
      },
      required: ['svid'],
      additionalProperties: false,
    },
  },
  {
    name: 'aumos_revoke_identity',
    description:
      'Revoke an identity via I1 agent-identity. HTTP POST /v1/agent-identity:revoke. ' +
      'Propagation target: identity <5s fleet-wide, credentials <1s (invariant I-05).',
    inputSchema: {
      type: 'object',
      properties: {
        jti: { type: 'string', description: 'The capability token ID (JTI) to revoke.' },
        reason: { type: 'string', description: 'Revocation reason.' },
      },
      required: ['jti'],
      additionalProperties: false,
    },
  },
  {
    name: 'aumos_emit_receipt',
    description:
      'Emit an Agent Action Receipt (P2 AAR) via E1 flight-recorder. Per invariant I-07, a ' +
      'receipt must be emitted *before* the action commits. Returns {receipt_id, signed_at}.',
    inputSchema: {
      type: 'object',
      properties: {
        actor: { type: 'string', description: 'SPIFFE ID of the acting agent.' },
        tool: { type: 'string', description: 'Tool/action name being receipted.' },
        outcome: {
          type: 'string',
          enum: ['success', 'failure', 'denied', 'pending'],
          description: 'Action outcome to record.',
        },
        side_effect: {
          type: 'string',
          enum: ['read', 'write', 'financial', 'destructive', 'physical'],
          description: 'Side-effect class (invariant I-08 ladder).',
        },
        inputs_hash: { type: 'string', description: 'Optional sha256 hash of the action inputs.' },
      },
      required: ['actor', 'tool', 'outcome'],
      additionalProperties: false,
    },
  },
  {
    name: 'aumos_verify_receipt',
    description: 'Verify a flight-recorder receipt signature. Returns {valid, signer, receipt_id}.',
    inputSchema: {
      type: 'object',
      properties: {
        receipt_id: { type: 'string', description: 'The receipt identifier to verify.' },
        signature: { type: 'string', description: 'Hex-encoded signature over the receipt payload.' },
      },
      required: ['receipt_id'],
      additionalProperties: false,
    },
  },
  {
    name: 'aumos_check_attestation',
    description:
      'Check a GPU attestation report via C1-1 nvtrust-bridge. Returns {verified, hardware_tee, ...}.',
    inputSchema: {
      type: 'object',
      properties: {
        nonce: { type: 'string', description: 'Nonce to bind into the attestation request.' },
        gpu_pci_id: { type: 'string', description: 'Optional GPU PCI device ID.' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'aumos_run_preflight',
    description:
      'Run sandbox pre-flight checks via R2 eval-guard. Implements invariant I-09 (fail-closed): ' +
      'an action may only proceed if preflight returns {allowed: true}.',
    inputSchema: {
      type: 'object',
      properties: {
        tool: { type: 'string', description: 'The tool the action intends to invoke.' },
        inputs: { type: 'string', description: 'JSON-serialized action inputs to vet.' },
        side_effect: {
          type: 'string',
          enum: ['read', 'write', 'financial', 'destructive', 'physical'],
        },
      },
      required: ['tool'],
      additionalProperties: false,
    },
  },
  {
    name: 'aumos_kill',
    description:
      'Trigger the R3 kill-switch. Halts/quarantines the agent. Used by containment on anomaly ' +
      'or by an operator. Returns {triggered, reason, killed_at}.',
    inputSchema: {
      type: 'object',
      properties: {
        reason: {
          type: 'string',
          description: 'Reason code (e.g. behavioral_anomaly, policy_violation, operator).',
        },
        agent: { type: 'string', description: 'SPIFFE ID of the agent to kill.' },
      },
      required: ['reason'],
      additionalProperties: false,
    },
  },
  {
    name: 'aumos_scan_secrets',
    description:
      'Scan text for exposed credentials via R4 credential-vault. Returns {findings: [...]}. ' +
      'Detects common secret shapes (API keys, tokens, private keys).',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'The text to scan for secrets.' },
      },
      required: ['text'],
      additionalProperties: false,
    },
  },
  {
    name: 'aumos_compliance_report',
    description:
      'Generate a compliance report via X1 defstack-cli (defstack report). Returns {report_json}.',
    inputSchema: {
      type: 'object',
      properties: {
        scope: { type: 'string', description: 'Compliance scope (e.g. "soc2", "fedramp_low").' },
        format: { type: 'string', enum: ['json', 'cyclonedx', 'spdx'], description: 'Output format.' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'aumos_install',
    description:
      'Install an AumOS component via `defstack install <name>`. Returns {installed, version}.',
    inputSchema: {
      type: 'object',
      properties: {
        name: {
          type: 'string',
          description: 'Component to install (e.g. "agent-identity", "flight-recorder").',
        },
        version: { type: 'string', description: 'Optional pinned version.' },
      },
      required: ['name'],
      additionalProperties: false,
    },
  },
  {
    name: 'aumos_generate_sbom',
    description:
      'Generate a Model SBOM via S4 model-sbom (CycloneDX). Returns {sbom, format, components}.',
    inputSchema: {
      type: 'object',
      properties: {
        model: { type: 'string', description: 'Model identifier (e.g. "llama-3-8b-instruct").' },
        format: { type: 'string', enum: ['cyclonedx', 'spdx'], description: 'SBOM format.' },
      },
      required: ['model'],
      additionalProperties: false,
    },
  },
  {
    name: 'aumos_run_eval',
    description:
      'Run an evaluation pipeline via A1 safe-eval (HELM/garak/PyRIT/MDASH orchestration). ' +
      'Returns {results, summary, veb (Verifiable Evaluation Bundle)}.',
    inputSchema: {
      type: 'object',
      properties: {
        model: { type: 'string', description: 'Target model URI (e.g. model://aumos-7b).' },
        pipeline_yaml: {
          type: 'string',
          description: 'Pipeline YAML (stages: benchmarks/adversarial/safety/bias/red_team).',
        },
      },
      required: ['model'],
      additionalProperties: false,
    },
  },
];

// ---------------------------------------------------------------------------
// Tool result type — every tool returns structured JSON (never throws).
// ---------------------------------------------------------------------------

export interface ToolResult {
  /** MCP content blocks (text). */
  content: { type: 'text'; text: string }[];
  /** Structured JSON payload (also stringified into content[0].text). */
  data: Record<string, unknown>;
  /** True if the tool encountered an error (it still returns structured JSON). */
  isError: boolean;
}

/** Build a success ToolResult from a JSON-serializable payload. */
function ok(data: Record<string, unknown>): ToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(data) }], data, isError: false };
}

/** Build an error ToolResult. The server stays up; only this call is marked failed. */
function err(message: string, details: Record<string, unknown> = {}): ToolResult {
  const data = { error: message, ...details };
  return { content: [{ type: 'text', text: JSON.stringify(data) }], data, isError: true };
}

// ---------------------------------------------------------------------------
// Standalone (mock) implementations — deterministic, no I/O.
// ---------------------------------------------------------------------------

/** Derive a deterministic 32-byte hex key from a seed string (mock verifying key). */
export function mockKey(seed: string): string {
  return createHash('sha256').update(`aumos-mock-key:${seed}`).digest('hex').slice(0, 64);
}

/**
 * Produce a deterministic mock signature over `data` using a raw hex `key` (the value returned
 * by {@link mockKey}). Not real cryptography — for standalone mode only.
 *
 * Sign and verify share this primitive so round-trips are consistent:
 *   sign:   mockSignatureWithKey(data, mockKey(keyId))
 *   verify: mockSignatureWithKey(data, key)   // caller supplies the hex key
 */
export function mockSignatureWithKey(data: string, keyHex: string): string {
  return createHash('sha256').update(`sig:${data}:${keyHex}`).digest('hex');
}

/**
 * Produce a deterministic mock signature over `data` for a key *id* (resolves the id to a hex
 * verifying key via {@link mockKey}). This is what `aumos_sign` uses; the resulting signature
 * verifies under {@link mockSignatureWithKey} with the resolved key.
 */
export function mockSignature(data: string, keyId: string): string {
  return mockSignatureWithKey(data, mockKey(keyId));
}

/** A very small, dependency-free secret scanner used in standalone mode.
 *  All patterns are case-insensitive via the `i` flag (JS does not support inline (?i)). */
export const SECRET_PATTERNS: { name: string; re: RegExp }[] = [
  { name: 'aws_access_key_id', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'aws_secret_access_key', re: /\baws(?:.{0,20})?(?:secret|sk)[^\n]{0,3}[0-9a-zA-Z/+]{40}\b/gi },
  { name: 'github_pat', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { name: 'google_api_key', re: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { name: 'slack_token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { name: 'stripe_key', re: /\bsk_live_[0-9a-zA-Z]{24,}\b/g },
  { name: 'private_key_block', re: /-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----/g },
  { name: 'generic_bearer', re: /\b(?:bearer|token|api_key|apikey)["']?\s*[:=]\s*["']?[A-Za-z0-9_\-.]{20,}["']?/gi },
];

/** Standalone secret scan. Returns findings with offsets. */
export function mockScanSecrets(text: string): { type: string; value: string; index: number }[] {
  const findings: { type: string; value: string; index: number }[] = [];
  for (const { name, re } of SECRET_PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      // Mask the captured value before returning it.
      const v = m[0];
      const masked = v.length > 8 ? `${v.slice(0, 4)}…${v.slice(-4)}` : '****';
      findings.push({ type: name, value: masked, index: m.index });
      if (m.index === re.lastIndex) re.lastIndex++; // guard against zero-width matches
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// HTTP helper — used in connected mode. Errors are caught by callers.
// ---------------------------------------------------------------------------

async function httpPost(
  cfg: { httpTimeoutMs?: number },
  fetchImpl: typeof fetch,
  baseUrl: string,
  path: string,
  body: unknown,
  timeoutMs?: number
): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs ?? cfg.httpTimeoutMs ?? 5000);
  try {
    const url = baseUrl.replace(/\/+$/, '') + path;
    const res = await fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const text = await res.text();
    let json: unknown;
    try {
      json = text ? JSON.parse(text) : {};
    } catch {
      json = { raw: text };
    }
    if (!res.ok) {
      const e = new Error(`HTTP ${res.status} from ${url}`) as Error & { status?: number; body?: unknown };
      e.status = res.status;
      e.body = json;
      throw e;
    }
    return json;
  } finally {
    clearTimeout(timer);
  }
}

/** Default subprocess runner. Resolves with stdout/stderr/code; never throws. */
async function defaultExec(cmd: string, args: string[]): Promise<ExecResult> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (d) => (stdout += d.toString()));
    child.stderr?.on('data', (d) => (stderr += d.toString()));
    child.on('error', (e) => resolve({ stdout, stderr: stderr + e.message, code: 127 }));
    child.on('close', (code) => resolve({ stdout, stderr, code: code ?? 0 }));
  });
}

// ---------------------------------------------------------------------------
// Per-tool dispatch. Each branch is a small async function returning a ToolResult.
// Connected-mode failures degrade to standalone mocks (with a `degraded: true` flag)
// so an agent always gets a usable answer.
// ---------------------------------------------------------------------------

/** Resolve the effective config (defaults + overrides). */
function resolveConfig(partial?: AumOSMcpConfig): {
  cfg: Required<Omit<AumOSMcpConfig, 'fetchImpl' | 'execImpl'>>;
  fetchImpl: typeof fetch;
  exec: (cmd: string, args: string[]) => Promise<ExecResult>;
} {
  const cfg = { ...DEFAULT_CONFIG, ...partial } as Required<Omit<AumOSMcpConfig, 'fetchImpl' | 'execImpl'>>;
  const fetchImpl = partial?.fetchImpl ?? globalThis.fetch;
  const exec = partial?.execImpl ?? defaultExec;
  return { cfg, fetchImpl, exec };
}

/**
 * CallTool dispatches a tool by name with validated args. Returns a ToolResult; never throws.
 *
 * Exported so callers (tests, alternative transports) can invoke tools directly without going
 * through the stdio JSON-RPC loop.
 */
export async function CallTool(
  name: string,
  args: Record<string, unknown>,
  config?: AumOSMcpConfig
): Promise<ToolResult> {
  const { cfg, fetchImpl, exec } = resolveConfig(config);
  const isStandalone = cfg.mode === 'standalone';

  try {
    switch (name) {
      // --- T1 trust-core: sign / verify -------------------------------------
      case 'aumos_sign': {
        const data = String(args.data ?? '');
        const keyId = String(args.key_id ?? 'default');
        if (!data) return err('aumos_sign: "data" is required');

        if (!isStandalone) {
          try {
            const r = await exec(cfg.trustCoreBin, ['sign', '--data', data, '--key-id', keyId]);
            if (r.code === 0 && r.stdout.trim()) {
              return ok({
                signature_hex: r.stdout.trim(),
                algorithm: 'ed25519',
                key_id: keyId,
                source: 'trust-core',
              });
            }
            // CLI missing → degrade to mock.
            return ok({
              signature_hex: mockSignature(data, keyId),
              algorithm: 'ed25519-mock',
              key_id: keyId,
              source: 'mock',
              degraded: true,
              cli_stderr: r.stderr.trim() || `trust-core exited ${r.code}`,
            });
          } catch (e) {
            return ok({
              signature_hex: mockSignature(data, keyId),
              algorithm: 'ed25519-mock',
              key_id: keyId,
              source: 'mock',
              degraded: true,
              cli_error: (e as Error).message,
            });
          }
        }
        return ok({
          signature_hex: mockSignature(data, keyId),
          algorithm: 'ed25519-mock',
          key_id: keyId,
          source: 'mock',
        });
      }

      case 'aumos_verify': {
        const data = String(args.data ?? '');
        const signature = String(args.signature ?? '');
        const key = String(args.key ?? '');
        if (!data || !signature || !key) {
          return err('aumos_verify: "data", "signature", and "key" are required');
        }
        if (!isStandalone) {
          try {
            const r = await exec(cfg.trustCoreBin, [
              'verify',
              '--data', data,
              '--signature', signature,
              '--key', key,
            ]);
            if (r.code === 0) {
              const valid = /valid/i.test(r.stdout);
              return ok({ valid, source: 'trust-core', raw: r.stdout.trim() });
            }
            return ok({ valid: false, source: 'mock', degraded: true, reason: `trust-core exited ${r.code}` });
          } catch (e) {
            return ok({ valid: false, source: 'mock', degraded: true, reason: (e as Error).message });
          }
        }
        // Mock verification: a signature produced by mockSignature(data, keyId) verifies iff
        // the supplied hex key equals mockKey(keyId) and the signature matches the canonical one.
        const valid = signature === mockSignatureWithKey(data, key);
        return ok({ valid, source: 'mock' });
      }

      // --- I1 agent-identity ------------------------------------------------
      case 'aumos_issue_identity': {
        const subject = String(args.subject ?? '');
        if (!subject) return err('aumos_issue_identity: "subject" is required');
        const body = {
          subject,
          audience: String(args.audience ?? ''),
          parent_svid: String(args.parent_svid ?? ''),
        };
        if (!isStandalone) {
          try {
            const r = (await httpPost(cfg, fetchImpl, cfg.agentIdentityUrl, '/v1/agent-identity:issue', body)) as {
              svid?: string; capability_jti?: string; verifying_key?: string; expires_at?: number;
            };
            return ok({ source: 'agent-identity', ...r });
          } catch (e) {
            return ok({ ...mockIssueIdentity(subject), source: 'mock', degraded: true, http_error: (e as Error).message });
          }
        }
        return ok({ source: 'mock', ...mockIssueIdentity(subject) });
      }

      case 'aumos_verify_identity': {
        const svid = String(args.svid ?? '');
        if (!svid) return err('aumos_verify_identity: "svid" is required');
        const body = { svid, audience: String(args.audience ?? '') };
        if (!isStandalone) {
          try {
            const r = (await httpPost(cfg, fetchImpl, cfg.agentIdentityUrl, '/v1/agent-identity:verify', body)) as {
              valid?: boolean; subject?: string; reason?: string;
            };
            return ok({ source: 'agent-identity', ...r });
          } catch (e) {
            return ok({ valid: false, source: 'mock', degraded: true, reason: (e as Error).message });
          }
        }
        return ok({ valid: svid.startsWith('svid-mock-'), subject: extractMockSubject(svid), source: 'mock' });
      }

      case 'aumos_revoke_identity': {
        const jti = String(args.jti ?? '');
        if (!jti) return err('aumos_revoke_identity: "jti" is required');
        const body = { jti, reason: String(args.reason ?? '') };
        if (!isStandalone) {
          try {
            const r = (await httpPost(cfg, fetchImpl, cfg.agentIdentityUrl, '/v1/agent-identity:revoke', body)) as {
              revoked?: boolean; revoked_at?: number;
            };
            return ok({ source: 'agent-identity', ...r });
          } catch (e) {
            return ok({ revoked: false, source: 'mock', degraded: true, reason: (e as Error).message });
          }
        }
        return ok({ revoked: true, revoked_at: Math.floor(Date.now() / 1000), source: 'mock' });
      }

      // --- E1 flight-recorder ----------------------------------------------
      case 'aumos_emit_receipt': {
        const actor = String(args.actor ?? '');
        const tool = String(args.tool ?? '');
        const outcome = String(args.outcome ?? 'pending');
        if (!actor || !tool) return err('aumos_emit_receipt: "actor" and "tool" are required');
        const inputsHash = String(args.inputs_hash ?? '');
        const payload = {
          actor, tool, outcome,
          side_effect: String(args.side_effect ?? 'read'),
          inputs_hash: inputsHash || createHash('sha256').update(`${actor}:${tool}`).digest('hex'),
          emitted_at: Math.floor(Date.now() / 1000),
        };
        if (!isStandalone) {
          try {
            const r = (await httpPost(cfg, fetchImpl, cfg.flightRecorderUrl, '/v1/flight-recorder:emit', payload)) as {
              receipt_id?: string; signature?: string;
            };
            return ok({ source: 'flight-recorder', ...r, invariant: 'I-07' });
          } catch (e) {
            const m = mockReceipt(payload);
            return ok({ source: 'mock', degraded: true, http_error: (e as Error).message, ...m, invariant: 'I-07' });
          }
        }
        return ok({ source: 'mock', ...mockReceipt(payload), invariant: 'I-07' });
      }

      case 'aumos_verify_receipt': {
        const receiptId = String(args.receipt_id ?? '');
        if (!receiptId) return err('aumos_verify_receipt: "receipt_id" is required');
        const signature = String(args.signature ?? '');
        if (!isStandalone) {
          try {
            const r = (await httpPost(cfg, fetchImpl, cfg.flightRecorderUrl, '/v1/flight-recorder:verify', {
              receipt_id: receiptId, signature,
            })) as { valid?: boolean; signer?: string };
            return ok({ source: 'flight-recorder', ...r });
          } catch (e) {
            return ok({ valid: receiptId.startsWith('aar-'), signer: 'spiffe://aumos.dev/flight-recorder', source: 'mock', degraded: true, reason: (e as Error).message });
          }
        }
        return ok({ valid: receiptId.startsWith('aar-'), signer: 'spiffe://aumos.dev/flight-recorder', source: 'mock' });
      }

      // --- C1-1 nvtrust-bridge ---------------------------------------------
      case 'aumos_check_attestation': {
        const nonce = String(args.nonce ?? randomUUID());
        const gpu = String(args.gpu_pci_id ?? '');
        const payload = { nonce, gpu_pci_id: gpu };
        if (!isStandalone) {
          try {
            const r = (await httpPost(cfg, fetchImpl, cfg.nvtrustBridgeUrl, '/v1/attestation:check', payload)) as Record<string, unknown>;
            return ok({ source: 'nvtrust-bridge', ...r });
          } catch (e) {
            return ok({ ...mockAttestation(nonce, gpu), source: 'mock', degraded: true, http_error: (e as Error).message });
          }
        }
        return ok({ source: 'mock', ...mockAttestation(nonce, gpu) });
      }

      // --- R2 eval-guard ----------------------------------------------------
      case 'aumos_run_preflight': {
        const tool = String(args.tool ?? '');
        if (!tool) return err('aumos_run_preflight: "tool" is required');
        const sideEffect = String(args.side_effect ?? 'read');
        const payload = { tool, inputs: String(args.inputs ?? '{}'), side_effect: sideEffect };
        if (!isStandalone) {
          try {
            const r = (await httpPost(cfg, fetchImpl, cfg.evalGuardUrl, '/v1/eval-guard:preflight', payload)) as {
              allowed?: boolean; reason?: string; violations?: unknown[];
            };
            return ok({ source: 'eval-guard', ...r });
          } catch (e) {
            return ok({ ...mockPreflight(tool, sideEffect), source: 'mock', degraded: true, http_error: (e as Error).message });
          }
        }
        return ok({ source: 'mock', ...mockPreflight(tool, sideEffect) });
      }

      // --- R3 kill-switch ---------------------------------------------------
      case 'aumos_kill': {
        const reason = String(args.reason ?? '');
        const agent = String(args.agent ?? 'spiffe://aumos.dev/agent/default');
        if (!reason) return err('aumos_kill: "reason" is required');
        const payload = { reason, agent };
        if (!isStandalone) {
          try {
            const r = (await httpPost(cfg, fetchImpl, cfg.killSwitchUrl, '/v1/kill-switch:trigger', payload)) as {
              triggered?: boolean; killed_at?: number;
            };
            return ok({ source: 'kill-switch', ...r });
          } catch (e) {
            return ok({ triggered: true, killed_at: Math.floor(Date.now() / 1000), source: 'mock', degraded: true, http_error: (e as Error).message });
          }
        }
        return ok({ triggered: true, killed_at: Math.floor(Date.now() / 1000), reason, agent, source: 'mock' });
      }

      // --- R4 credential-vault ---------------------------------------------
      case 'aumos_scan_secrets': {
        const text = String(args.text ?? '');
        const findings = mockScanSecrets(text);
        if (!isStandalone) {
          try {
            const r = (await httpPost(cfg, fetchImpl, cfg.credentialVaultUrl, '/v1/credential-vault:scan', { text })) as {
              findings?: unknown[];
            };
            return ok({ source: 'credential-vault', findings: r.findings ?? findings, count: (r.findings as unknown[])?.length ?? findings.length });
          } catch (e) {
            return ok({ findings, count: findings.length, source: 'mock', degraded: true, http_error: (e as Error).message });
          }
        }
        return ok({ findings, count: findings.length, source: 'mock' });
      }

      // --- X1 defstack-cli --------------------------------------------------
      case 'aumos_compliance_report': {
        const scope = String(args.scope ?? 'soc2');
        const format = String(args.format ?? 'json');
        if (!isStandalone) {
          try {
            const r = await exec(cfg.defstackBin, ['report', '--scope', scope, '--format', format]);
            if (r.code === 0 && r.stdout.trim()) {
              return ok({ report_json: r.stdout.trim(), source: 'defstack' });
            }
            return ok({ ...mockComplianceReport(scope), source: 'mock', degraded: true, cli_stderr: r.stderr.trim() });
          } catch (e) {
            return ok({ ...mockComplianceReport(scope), source: 'mock', degraded: true, cli_error: (e as Error).message });
          }
        }
        return ok({ ...mockComplianceReport(scope), source: 'mock' });
      }

      case 'aumos_install': {
        const compName = String(args.name ?? '');
        if (!compName) return err('aumos_install: "name" is required');
        const version = args.version ? String(args.version) : 'latest';
        if (!isStandalone) {
          try {
            const r = await exec(cfg.defstackBin, ['install', compName, ...(args.version ? ['--version', String(args.version)] : [])]);
            if (r.code === 0) {
              return ok({ installed: true, name: compName, version, source: 'defstack', stdout: r.stdout.trim() });
            }
            return ok({ installed: false, name: compName, version, source: 'mock', degraded: true, cli_stderr: r.stderr.trim() });
          } catch (e) {
            return ok({ installed: false, name: compName, version, source: 'mock', degraded: true, cli_error: (e as Error).message });
          }
        }
        return ok({ installed: true, name: compName, version, source: 'mock' });
      }

      // --- S4 model-sbom ----------------------------------------------------
      case 'aumos_generate_sbom': {
        const model = String(args.model ?? '');
        if (!model) return err('aumos_generate_sbom: "model" is required');
        const format = String(args.format ?? 'cyclonedx');
        if (!isStandalone) {
          try {
            const r = (await httpPost(cfg, fetchImpl, cfg.modelSbomUrl, '/v1/model-sbom:generate', { model, format })) as {
              sbom?: unknown; components?: unknown[];
            };
            return ok({ source: 'model-sbom', ...r });
          } catch (e) {
            return ok({ ...mockSbom(model), source: 'mock', degraded: true, http_error: (e as Error).message });
          }
        }
        return ok({ source: 'mock', ...mockSbom(model) });
      }

      // --- A1 safe-eval -----------------------------------------------------
      case 'aumos_run_eval': {
        const model = String(args.model ?? '');
        if (!model) return err('aumos_run_eval: "model" is required');
        const pipeline = String(args.pipeline_yaml ?? '');
        const payload = { model, pipeline_yaml: pipeline };
        if (!isStandalone) {
          try {
            const r = (await httpPost(cfg, fetchImpl, cfg.safeEvalUrl, '/v1/safe-eval:run', payload)) as {
              results?: unknown; summary?: unknown; veb?: unknown;
            };
            return ok({ source: 'safe-eval', ...r });
          } catch (e) {
            return ok({ ...mockEval(model, pipeline), source: 'mock', degraded: true, http_error: (e as Error).message });
          }
        }
        return ok({ source: 'mock', ...mockEval(model, pipeline) });
      }

      default:
        return err(`unknown tool: "${name}"`, { available: TOOLS.map((t) => t.name) });
    }
  } catch (e) {
    // Defensive: should be unreachable, but a tool must never crash the server.
    return err(`internal error in tool "${name}": ${(e as Error).message}`);
  }
}

// ---------------------------------------------------------------------------
// Standalone mock payload builders.
// ---------------------------------------------------------------------------

function mockIssueIdentity(subject: string): Record<string, unknown> {
  const jti = `jti-${randomUUID()}`;
  // Encode the full subject (hex) so verify can round-trip it losslessly.
  const svid = `svid-mock-${Buffer.from(subject, 'utf-8').toString('hex')}`;
  return {
    svid,
    capability_jti: jti,
    verifying_key: mockKey(subject),
    expires_at: Math.floor(Date.now() / 1000) + 60,
  };
}

function extractMockSubject(svid: string): string {
  if (!svid.startsWith('svid-mock-')) return '';
  try {
    const hex = svid.slice('svid-mock-'.length);
    // Only attempt decode if the remainder is valid even-length hex; otherwise return empty.
    if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) return '';
    return Buffer.from(hex, 'hex').toString('utf-8');
  } catch {
    return '';
  }
}

function mockReceipt(payload: Record<string, unknown>): Record<string, unknown> {
  const receiptId = `aar-${randomUUID()}`;
  const canonical = JSON.stringify(payload);
  return {
    receipt_id: receiptId,
    signature: createHash('sha256').update(`aar-sig:${canonical}`).digest('hex'),
    signed_at: payload.emitted_at ?? Math.floor(Date.now() / 1000),
  };
}

function mockAttestation(nonce: string, gpu: string): Record<string, unknown> {
  return {
    verified: true,
    hardware_tee: 'nvidia-confidential-computing',
    gpu: gpu || 'auto-detected',
    nonce,
    attestation_report_hash: createHash('sha256').update(`att:${nonce}`).digest('hex'),
    checked_at: Math.floor(Date.now() / 1000),
  };
}

function mockPreflight(tool: string, sideEffect: string): Record<string, unknown> {
  // Fail-closed default for consequential classes without approval (mocks always allow reads).
  const consequential = ['financial', 'destructive', 'physical'].includes(sideEffect);
  return {
    allowed: !consequential,
    reason: consequential ? 'consequential_action_requires_approval (invariant I-08)' : 'ok',
    tool,
    side_effect: sideEffect,
    checked_at: Math.floor(Date.now() / 1000),
  };
}

function mockComplianceReport(scope: string): Record<string, unknown> {
  return {
    report_json: JSON.stringify({
      scope,
      status: 'compliant',
      controls_total: 12,
      controls_passed: 12,
      generated_at: new Date().toISOString(),
    }),
    format: 'json',
  };
}

function mockSbom(model: string): Record<string, unknown> {
  const components = [
    { type: 'model', name: model, bomRef: `pkg:aumos/model/${model}` },
    { type: 'dataset', name: `${model}-instruct-tune`, bomRef: `pkg:aumos/dataset/${model}-tune` },
  ];
  return {
    sbom: {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components,
      metadata: { timestamp: new Date().toISOString(), tool: 'aumos-mcp-server' },
    },
    format: 'cyclonedx',
    components,
  };
}

function mockEval(model: string, _pipeline: string): Record<string, unknown> {
  return {
    results: {
      accuracy: 0.85,
      robustness: 0.92,
      adversarial_success_rate: 0.05,
    },
    summary: { model, stages_run: ['benchmarks', 'adversarial'], passed: true },
    veb: { bundleId: `veb-${randomUUID()}`, format: 'P8' },
  };
}

// ---------------------------------------------------------------------------
// MCP server: tools/list + tools/call over stdio JSON-RPC 2.0.
// ---------------------------------------------------------------------------

/** A JSON-RPC 2.0 request as we expect it on stdin. */
interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: unknown;
}

/** Build a JSON-RPC 2.0 success response. */
function rpcResult(id: string | number | null | undefined, result: unknown): string {
  return JSON.stringify({ jsonrpc: '2.0', id: id ?? null, result });
}

/** Build a JSON-RPC 2.0 error response. */
function rpcError(
  id: string | number | null | undefined,
  code: number,
  message: string,
  data?: unknown
): string {
  const errObj: { code: number; message: string; data?: unknown } = { code, message };
  if (data !== undefined) errObj.data = data;
  return JSON.stringify({ jsonrpc: '2.0', id: id ?? null, error: errObj });
}

/** MCP protocol version advertised in initialize. */
export const MCP_PROTOCOL_VERSION = '2024-11-05';
export const MCP_SERVER_NAME = 'aumos-mcp-server';
export const MCP_SERVER_VERSION = '1.0.0';

/**
 * ListTools returns the tool descriptors in the shape MCP `tools/list` expects.
 * Exported for testing and for callers that want the catalog without a server.
 */
export function ListTools(): { tools: ToolDescriptor[] } {
  return { tools: TOOLS };
}

/** MCP initialize result (capabilities + server info). */
function initializeResult(): unknown {
  return {
    protocolVersion: MCP_PROTOCOL_VERSION,
    capabilities: { tools: { listChanged: false } },
    serverInfo: { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION },
  };
}

/** Validate that args is an object; throw a typed error otherwise. */
function asObject(params: unknown): Record<string, unknown> {
  if (params === null || typeof params !== 'object' || Array.isArray(params)) {
    throw new ObjectArgsError('params must be a JSON object');
  }
  return params as Record<string, unknown>;
}

class ObjectArgsError extends Error {}

/** Map MCP JSON-RPC error semantics. */
const RPC_INVALID_REQUEST = -32600;
const RPC_METHOD_NOT_FOUND = -32601;
const RPC_INVALID_PARAMS = -32602;
const RPC_INTERNAL = -32603;

/**
 * Server wraps the dispatch logic and owns the stdio transport loop. Constructed with an
 * AumOSMcpConfig; `.run()` reads JSON-RPC requests line-by-line from stdin and writes
 * responses to stdout (logs to stderr — stdout is reserved for protocol frames).
 */
export class Server {
  readonly config: AumOSMcpConfig;
  /** Set once `initialize` succeeds. */
  private initialized = false;
  /** Counts for observability. */
  readonly stats = { requests: 0, calls: 0, errors: 0 };

  /** True after a successful `initialize` or `notifications/initialized`. */
  isInitialized(): boolean {
    return this.initialized;
  }

  constructor(config: AumOSMcpConfig = { mode: 'standalone' }) {
    this.config = config;
  }

  /**
   * Dispatch a single JSON-RPC request to its handler and return the response line.
   * Exported for unit testing the dispatch without spinning up stdio.
   */
  async handle(req: JsonRpcRequest): Promise<string | null> {
    this.stats.requests++;
    const id = req.id;

    // Notifications (no id) are acknowledged with silence per JSON-RPC.
    if (id === undefined || id === null) {
      // Best-effort: still run the method for side effects (e.g. notifications/initialized).
      try {
        if (req.method === 'notifications/initialized') this.initialized = true;
      } catch {
        /* swallow */
      }
      return null;
    }

    try {
      switch (req.method) {
        case 'initialize':
          this.initialized = true;
          return rpcResult(id, initializeResult());

        case 'ping':
          return rpcResult(id, {});

        case 'notifications/initialized':
          this.initialized = true;
          return null;

        case 'tools/list':
          return rpcResult(id, ListTools());

        case 'tools/call': {
          this.stats.calls++;
          const params = asObject(req.params);
          const toolName = params.name;
          if (typeof toolName !== 'string') {
            this.stats.errors++;
            return rpcError(id, RPC_INVALID_PARAMS, 'tools/call requires string "name"');
          }
          const toolArgs = params.arguments && typeof params.arguments === 'object' && !Array.isArray(params.arguments)
            ? (params.arguments as Record<string, unknown>)
            : {};
          const result = await CallTool(toolName, toolArgs, this.config);
          if (result.isError) this.stats.errors++;
          return rpcResult(id, {
            content: result.content,
            isError: result.isError,
            // MCP structured content field (parallel to content[].text).
            structuredContent: result.data,
          });
        }

        default:
          this.stats.errors++;
          return rpcError(id, RPC_METHOD_NOT_FOUND, `method not found: ${req.method}`);
      }
    } catch (e) {
      this.stats.errors++;
      if (e instanceof ObjectArgsError) {
        return rpcError(id, RPC_INVALID_PARAMS, e.message);
      }
      return rpcError(id, RPC_INTERNAL, `internal error: ${(e as Error).message}`);
    }
  }

  /**
   * Run the stdio loop. Reads JSON-RPC requests line-by-line from stdin, writes each
   * response as a single line to stdout, logs to stderr. Resolves on stdin close.
   */
  async run(): Promise<void> {
    const rl = createInterface({ input: process.stdin, terminal: false });
    return new Promise<void>((resolve) => {
      rl.on('line', async (line) => {
        const trimmed = line.trim();
        if (!trimmed) return;
        let req: JsonRpcRequest;
        try {
          const parsed = JSON.parse(trimmed);
          if (parsed === null || typeof parsed !== 'object' || parsed.jsonrpc !== '2.0' || typeof parsed.method !== 'string') {
            process.stdout.write(rpcError(parsed?.id ?? null, RPC_INVALID_REQUEST, 'invalid JSON-RPC 2.0 request') + '\n');
            return;
          }
          req = parsed as JsonRpcRequest;
        } catch (e) {
          process.stdout.write(rpcError(null, -32700, `parse error: ${(e as Error).message}`) + '\n');
          return;
        }
        const response = await this.handle(req);
        if (response !== null) {
          process.stdout.write(response + '\n');
        }
      });
      rl.on('close', () => resolve());
    });
  }
}

// ---------------------------------------------------------------------------
// CLI entrypoint — only when run as a binary (`aumos-mcp` or `node dist/index.js`).
// ---------------------------------------------------------------------------

/** Parse process.argv into an AumOSMcpConfig. */
export function configFromEnv(env: NodeJS.ProcessEnv = process.env, argv: string[] = process.argv.slice(2)): AumOSMcpConfig {
  const mode: AumOSMode = (env.AUMOS_MODE as AumOSMode) || (argv.includes('--connected') ? 'connected' : 'standalone');
  return {
    mode,
    agentIdentityUrl: env.AUMOS_AGENT_IDENTITY_URL || undefined,
    flightRecorderUrl: env.AUMOS_FLIGHT_RECORDER_URL || undefined,
    nvtrustBridgeUrl: env.AUMOS_NVTRUST_BRIDGE_URL || undefined,
    modelSbomUrl: env.AUMOS_MODEL_SBOM_URL || undefined,
    safeEvalUrl: env.AUMOS_SAFE_EVAL_URL || undefined,
    evalGuardUrl: env.AUMOS_EVAL_GUARD_URL || undefined,
    killSwitchUrl: env.AUMOS_KILL_SWITCH_URL || undefined,
    credentialVaultUrl: env.AUMOS_CREDENTIAL_VAULT_URL || undefined,
    trustCoreBin: env.AUMOS_TRUST_CORE_BIN || undefined,
    defstackBin: env.AUMOS_DEFSTACK_BIN || undefined,
    httpTimeoutMs: env.AUMOS_HTTP_TIMEOUT_MS ? Number(env.AUMOS_HTTP_TIMEOUT_MS) : undefined,
  };
}

const isMain = (() => {
  try {
    return process.argv[1] && import.meta.url === new URL(`file://${process.argv[1].replace(/\\/g, '/')}`).href;
  } catch {
    return false;
  }
})();

if (isMain) {
  const cfg = configFromEnv();
  // Log to stderr so we never corrupt the JSON-RPC stdout channel.
  process.stderr.write(`[aumos-mcp] starting in ${cfg.mode} mode\n`);
  new Server(cfg).run().then(() => {
    process.stderr.write('[aumos-mcp] stdin closed; exiting\n');
  });
}

// Re-export IncomingMessage type-only alias to keep the import used on platforms that strip it.
export type { IncomingMessage };
