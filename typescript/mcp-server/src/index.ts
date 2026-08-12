#!/usr/bin/env node
/**
 * @warrantor/mcp-server — Model Context Protocol (MCP) server exposing Warrantor components.
 *
 * This server exposes 15 operations backed by the canonical Warrantor security stack to any
 * MCP-compatible coding agent (Claude Code, OpenAI Codex, Cursor, Zed, …). An agent discovers
 * the tools via `tools/list` and invokes them via `tools/call`.
 *
 * The server runs in two modes:
 *   - **connected** (default): tools issue real HTTP calls (I1, E1, C1-1, S4, A1, R2,
 *     R3, R4) and shell out to CLIs (T1 `trust-core`, X1 `defstack`). Any dependency or
 *     response failure is returned as a structured, fail-closed tool error.
 *   - **standalone** (explicit opt-in): tools return deterministic demo responses. Zero
 *     external dependencies. This mode is isolated for development, demos, and dry-runs.
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
 * proto/warrantor/identity/v1/agent.proto RPCs).
 */

import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import type { IncomingMessage } from 'node:http';

// ---------------------------------------------------------------------------
// Modes and configuration.
// ---------------------------------------------------------------------------

export type WarrantorMode = 'standalone' | 'connected';

export interface WarrantorMcpConfig {
  mode: WarrantorMode;
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
  execImpl?: (cmd: string, args: string[], stdin?: string) => Promise<ExecResult>;
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  code: number;
}

const DEFAULT_CONFIG: Required<Omit<WarrantorMcpConfig, 'fetchImpl' | 'execImpl'>> = {
  mode: 'connected',
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
 * The 15 Warrantor tools exposed by this server, each backed by a real implementation below.
 * Order matches the deliverable spec and is stable for snapshots.
 */
export const TOOLS: ToolDescriptor[] = [
  {
    name: 'warrantor_sign',
    description:
      'Sign data using T1 trust-core (Ed25519). Connected mode requires a raw hex signing key; ' +
      'standalone mode uses an explicit deterministic demo key. Returns {signature_hex, algorithm}.',
    inputSchema: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'The data to sign (UTF-8). Pem/hex/raw all accepted.' },
        key: { type: 'string', description: 'Hex-encoded Ed25519 signing key (required in connected mode).' },
        key_id: { type: 'string', description: 'Optional demo key identifier (standalone mode only).' },
      },
      required: ['data'],
      additionalProperties: false,
    },
  },
  {
    name: 'warrantor_verify',
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
    name: 'warrantor_issue_identity',
    description:
      'Issue an agent identity (SPIFFE SVID + capability token) via I1 agent-identity. ' +
      'HTTP POST /v1/agent-identity:issue. Mirrors proto/warrantor/identity/v1/IssueIdentityRequest.',
    inputSchema: {
      type: 'object',
      properties: {
        subject: {
          type: 'string',
          description: 'SPIFFE ID of the agent being issued (e.g. spiffe://muveraai.com/agent/coding-1).',
        },
        audience: { type: 'string', description: 'Intended audience bound into the `aud` claim.' },
        parent_svid: { type: 'string', description: 'Parent SVID for delegation chains.' },
      },
      required: ['subject'],
      additionalProperties: false,
    },
  },
  {
    name: 'warrantor_verify_identity',
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
    name: 'warrantor_revoke_identity',
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
    name: 'warrantor_emit_receipt',
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
    name: 'warrantor_verify_receipt',
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
    name: 'warrantor_check_attestation',
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
    name: 'warrantor_run_preflight',
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
    name: 'warrantor_kill',
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
    name: 'warrantor_scan_secrets',
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
    name: 'warrantor_compliance_report',
    description:
      'Generate a compliance report via X1 defstack-cli (`defstack compliance-report`). Returns {report_json}.',
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
    name: 'warrantor_install',
    description:
      'Install an Warrantor component via `defstack install <name>`. Returns {installed, version}.',
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
    name: 'warrantor_generate_sbom',
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
    name: 'warrantor_run_eval',
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
 * verifying key via {@link mockKey}). This is what `warrantor_sign` uses; the resulting signature
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
  baseUrl: string | undefined,
  path: string,
  body: unknown,
  timeoutMs?: number
): Promise<unknown> {
  // In `connected` mode every service URL is optional, so an unconfigured service used to
  // reach `baseUrl.replace(...)` as `undefined` and surface as
  // `Cannot read properties of undefined (reading 'replace')` -- an internal TypeError that
  // named neither the service nor the setting needed to fix it. Six of the fifteen tools failed
  // this way out of the box. Fail with the env var the operator actually has to set.
  if (!baseUrl) {
    throw new Error(
      `service URL is not configured; set the matching AUMOS_*_URL environment variable ` +
        `(see --help) or run the server with --standalone to use local stubs`
    );
  }
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

/** Default subprocess runner. Payloads are written to stdin, never command-line arguments. */
async function defaultExec(cmd: string, args: string[], stdin?: string): Promise<ExecResult> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (d) => (stdout += d.toString()));
    child.stderr?.on('data', (d) => (stderr += d.toString()));
    child.on('error', (e) => resolve({ stdout, stderr: stderr + e.message, code: 127 }));
    child.on('close', (code) => resolve({ stdout, stderr, code: code ?? 0 }));
    child.stdin?.end(stdin ?? '');
  });
}

// ---------------------------------------------------------------------------
// Per-tool dispatch. Each branch is a small async function returning a ToolResult.
// Connected mode never crosses into the standalone dependency graph: dependency failures
// and malformed responses return structured errors with no synthetic security outcome.
// ---------------------------------------------------------------------------

class InvalidControlResponse extends Error {
  constructor(dependency: string, detail: string) {
    super(`${dependency} returned an invalid response: ${detail}`);
    this.name = 'InvalidControlResponse';
  }
}

function errorMessage(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

function requireRecord(value: unknown, dependency: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new InvalidControlResponse(dependency, 'expected a JSON object');
  }
  return value as Record<string, unknown>;
}

function requireStringField(record: Record<string, unknown>, key: string, dependency: string): string {
  const value = record[key];
  if (typeof value !== 'string' || value.length === 0) {
    throw new InvalidControlResponse(dependency, `field "${key}" must be a non-empty string`);
  }
  return value;
}

function requireBooleanField(record: Record<string, unknown>, key: string, dependency: string): boolean {
  const value = record[key];
  if (typeof value !== 'boolean') {
    throw new InvalidControlResponse(dependency, `field "${key}" must be a boolean`);
  }
  return value;
}

function requireNumberField(record: Record<string, unknown>, key: string, dependency: string): number {
  const value = record[key];
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new InvalidControlResponse(dependency, `field "${key}" must be a finite number`);
  }
  return value;
}

function requireArrayField(record: Record<string, unknown>, key: string, dependency: string): unknown[] {
  const value = record[key];
  if (!Array.isArray(value)) {
    throw new InvalidControlResponse(dependency, `field "${key}" must be an array`);
  }
  return value;
}

function requirePresentField(record: Record<string, unknown>, key: string, dependency: string): unknown {
  if (!Object.prototype.hasOwnProperty.call(record, key) || record[key] === undefined) {
    throw new InvalidControlResponse(dependency, `field "${key}" is required`);
  }
  return record[key];
}

function dependencyFailure(tool: string, dependency: string, cause: unknown): ToolResult {
  const invalidResponse = cause instanceof InvalidControlResponse;
  return err(`${tool}: ${invalidResponse ? 'dependency response validation failed' : 'required dependency unavailable'}`, {
    code: invalidResponse ? 'CONTROL_RESPONSE_INVALID' : 'CONTROL_UNAVAILABLE',
    dependency,
    retryable: !invalidResponse,
    cause: errorMessage(cause),
  });
}

function cliFailure(tool: string, dependency: string, result: ExecResult): ToolResult {
  return err(`${tool}: required dependency command failed`, {
    code: 'CONTROL_UNAVAILABLE',
    dependency,
    retryable: result.code === 127,
    exit_code: result.code,
  });
}

function parseTrustCoreSignOutput(stdout: string): { signatureHex: string; verifyingKeyHex: string } {
  const signatureHex = /^signature_hex=([0-9a-f]{128})$/im.exec(stdout)?.[1];
  const verifyingKeyHex = /^verifying_key_hex=([0-9a-f]{64})$/im.exec(stdout)?.[1];
  if (!signatureHex || !verifyingKeyHex) {
    throw new InvalidControlResponse('trust-core', 'sign output is missing canonical signature/key fields');
  }
  return { signatureHex, verifyingKeyHex };
}

/** Resolve the effective config (defaults + overrides). */
function resolveConfig(partial?: WarrantorMcpConfig): {
  cfg: Required<Omit<WarrantorMcpConfig, 'fetchImpl' | 'execImpl'>>;
  fetchImpl: typeof fetch;
  exec: (cmd: string, args: string[], stdin?: string) => Promise<ExecResult>;
} {
  const cfg = { ...DEFAULT_CONFIG, ...partial } as Required<Omit<WarrantorMcpConfig, 'fetchImpl' | 'execImpl'>>;
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
  config?: WarrantorMcpConfig
): Promise<ToolResult> {
  const { cfg, fetchImpl, exec } = resolveConfig(config);
  const isStandalone = cfg.mode === 'standalone';

  try {
    switch (name) {
      // --- T1 trust-core: sign / verify -------------------------------------
      case 'warrantor_sign': {
        const data = String(args.data ?? '');
        const keyId = String(args.key_id ?? 'default');
        if (!data) return err('warrantor_sign: "data" is required');

        if (!isStandalone) {
          const key = String(args.key ?? '');
          if (!/^[0-9a-fA-F]{64}$/.test(key)) {
            return err('warrantor_sign: connected mode requires a 64-character hex "key"', {
              code: 'INVALID_ARGUMENT',
            });
          }
          try {
            const result = await exec(cfg.trustCoreBin, ['sign', '--key', key], data);
            if (result.code !== 0) return cliFailure('warrantor_sign', 'trust-core', result);
            const parsed = parseTrustCoreSignOutput(result.stdout);
            return ok({
              signature_hex: parsed.signatureHex,
              verifying_key_hex: parsed.verifyingKeyHex,
              algorithm: 'ed25519',
              key_id: keyId,
              source: 'trust-core',
            });
          } catch (cause) {
            return dependencyFailure('warrantor_sign', 'trust-core', cause);
          }
        }
        return ok({
          signature_hex: mockSignature(data, keyId),
          algorithm: 'ed25519-mock',
          key_id: keyId,
          source: 'mock',
        });
      }

      case 'warrantor_verify': {
        const data = String(args.data ?? '');
        const signature = String(args.signature ?? '');
        const key = String(args.key ?? '');
        if (!data || !signature || !key) {
          return err('warrantor_verify: "data", "signature", and "key" are required');
        }
        if (!isStandalone) {
          try {
            const result = await exec(
              cfg.trustCoreBin,
              ['verify', '--key', key, '--signature', signature],
              data
            );
            if (result.code === 0 && /^valid=true$/im.test(result.stdout)) {
              return ok({ valid: true, source: 'trust-core' });
            }
            if (result.code === 1 && /^valid=false(?:\s|$)/im.test(result.stdout)) {
              return ok({ valid: false, source: 'trust-core', reason: 'signature_did_not_verify' });
            }
            if (result.code !== 0) return cliFailure('warrantor_verify', 'trust-core', result);
            throw new InvalidControlResponse('trust-core', 'verify output is missing a canonical valid field');
          } catch (cause) {
            return dependencyFailure('warrantor_verify', 'trust-core', cause);
          }
        }
        // Mock verification: a signature produced by mockSignature(data, keyId) verifies iff
        // the supplied hex key equals mockKey(keyId) and the signature matches the canonical one.
        const valid = signature === mockSignatureWithKey(data, key);
        return ok({ valid, source: 'mock' });
      }

      // --- I1 agent-identity ------------------------------------------------
      case 'warrantor_issue_identity': {
        const subject = String(args.subject ?? '');
        if (!subject) return err('warrantor_issue_identity: "subject" is required');
        const body = {
          subject,
          audience: String(args.audience ?? ''),
          parent_svid: String(args.parent_svid ?? ''),
        };
        if (!isStandalone) {
          try {
            const response = requireRecord(
              await httpPost(cfg, fetchImpl, cfg.agentIdentityUrl, '/v1/agent-identity:issue', body),
              'agent-identity'
            );
            requireStringField(response, 'svid', 'agent-identity');
            requireStringField(response, 'capability_jti', 'agent-identity');
            requireStringField(response, 'verifying_key', 'agent-identity');
            requireNumberField(response, 'expires_at', 'agent-identity');
            return ok({ ...response, source: 'agent-identity' });
          } catch (cause) {
            return dependencyFailure('warrantor_issue_identity', 'agent-identity', cause);
          }
        }
        return ok({ source: 'mock', ...mockIssueIdentity(subject) });
      }

      case 'warrantor_verify_identity': {
        const svid = String(args.svid ?? '');
        if (!svid) return err('warrantor_verify_identity: "svid" is required');
        const body = { svid, audience: String(args.audience ?? '') };
        if (!isStandalone) {
          try {
            const response = requireRecord(
              await httpPost(cfg, fetchImpl, cfg.agentIdentityUrl, '/v1/agent-identity:verify', body),
              'agent-identity'
            );
            requireBooleanField(response, 'valid', 'agent-identity');
            return ok({ ...response, source: 'agent-identity' });
          } catch (cause) {
            return dependencyFailure('warrantor_verify_identity', 'agent-identity', cause);
          }
        }
        return ok({ valid: svid.startsWith('svid-mock-'), subject: extractMockSubject(svid), source: 'mock' });
      }

      case 'warrantor_revoke_identity': {
        const jti = String(args.jti ?? '');
        if (!jti) return err('warrantor_revoke_identity: "jti" is required');
        const body = { jti, reason: String(args.reason ?? '') };
        if (!isStandalone) {
          try {
            const response = requireRecord(
              await httpPost(cfg, fetchImpl, cfg.agentIdentityUrl, '/v1/agent-identity:revoke', body),
              'agent-identity'
            );
            requireBooleanField(response, 'revoked', 'agent-identity');
            return ok({ ...response, source: 'agent-identity' });
          } catch (cause) {
            return dependencyFailure('warrantor_revoke_identity', 'agent-identity', cause);
          }
        }
        return ok({ revoked: true, revoked_at: Math.floor(Date.now() / 1000), source: 'mock' });
      }

      // --- E1 flight-recorder ----------------------------------------------
      case 'warrantor_emit_receipt': {
        const actor = String(args.actor ?? '');
        const tool = String(args.tool ?? '');
        const outcome = String(args.outcome ?? 'pending');
        if (!actor || !tool) return err('warrantor_emit_receipt: "actor" and "tool" are required');
        const inputsHash = String(args.inputs_hash ?? '');
        const payload = {
          actor, tool, outcome,
          side_effect: String(args.side_effect ?? 'read'),
          inputs_hash: inputsHash || createHash('sha256').update(`${actor}:${tool}`).digest('hex'),
          emitted_at: Math.floor(Date.now() / 1000),
        };
        if (!isStandalone) {
          try {
            const response = requireRecord(
              await httpPost(cfg, fetchImpl, cfg.flightRecorderUrl, '/v1/flight-recorder:emit', payload),
              'flight-recorder'
            );
            requireStringField(response, 'receipt_id', 'flight-recorder');
            requireStringField(response, 'signature', 'flight-recorder');
            return ok({ ...response, source: 'flight-recorder', invariant: 'I-07' });
          } catch (cause) {
            return dependencyFailure('warrantor_emit_receipt', 'flight-recorder', cause);
          }
        }
        return ok({ source: 'mock', ...mockReceipt(payload), invariant: 'I-07' });
      }

      case 'warrantor_verify_receipt': {
        const receiptId = String(args.receipt_id ?? '');
        if (!receiptId) return err('warrantor_verify_receipt: "receipt_id" is required');
        const signature = String(args.signature ?? '');
        if (!isStandalone) {
          try {
            const response = requireRecord(
              await httpPost(cfg, fetchImpl, cfg.flightRecorderUrl, '/v1/flight-recorder:verify', {
                receipt_id: receiptId,
                signature,
              }),
              'flight-recorder'
            );
            requireBooleanField(response, 'valid', 'flight-recorder');
            return ok({ ...response, source: 'flight-recorder' });
          } catch (cause) {
            return dependencyFailure('warrantor_verify_receipt', 'flight-recorder', cause);
          }
        }
        return ok({ valid: receiptId.startsWith('aar-'), signer: 'spiffe://muveraai.com/flight-recorder', source: 'mock' });
      }

      // --- C1-1 nvtrust-bridge ---------------------------------------------
      case 'warrantor_check_attestation': {
        const nonce = String(args.nonce ?? randomUUID());
        const gpu = String(args.gpu_pci_id ?? '');
        const payload = { nonce, gpu_pci_id: gpu };
        if (!isStandalone) {
          try {
            const response = requireRecord(
              await httpPost(cfg, fetchImpl, cfg.nvtrustBridgeUrl, '/v1/attestation:check', payload),
              'nvtrust-bridge'
            );
            requireBooleanField(response, 'verified', 'nvtrust-bridge');
            return ok({ ...response, source: 'nvtrust-bridge' });
          } catch (cause) {
            return dependencyFailure('warrantor_check_attestation', 'nvtrust-bridge', cause);
          }
        }
        return ok({ source: 'mock', ...mockAttestation(nonce, gpu) });
      }

      // --- R2 eval-guard ----------------------------------------------------
      case 'warrantor_run_preflight': {
        const tool = String(args.tool ?? '');
        if (!tool) return err('warrantor_run_preflight: "tool" is required');
        const sideEffect = String(args.side_effect ?? 'read');
        const payload = { tool, inputs: String(args.inputs ?? '{}'), side_effect: sideEffect };
        if (!isStandalone) {
          try {
            const response = requireRecord(
              await httpPost(cfg, fetchImpl, cfg.evalGuardUrl, '/v1/eval-guard:preflight', payload),
              'eval-guard'
            );
            requireBooleanField(response, 'allowed', 'eval-guard');
            return ok({ ...response, source: 'eval-guard' });
          } catch (cause) {
            return dependencyFailure('warrantor_run_preflight', 'eval-guard', cause);
          }
        }
        return ok({ source: 'mock', ...mockPreflight(tool, sideEffect) });
      }

      // --- R3 kill-switch ---------------------------------------------------
      case 'warrantor_kill': {
        const reason = String(args.reason ?? '');
        const agent = String(args.agent ?? 'spiffe://muveraai.com/agent/default');
        if (!reason) return err('warrantor_kill: "reason" is required');
        const payload = { reason, agent };
        if (!isStandalone) {
          try {
            const response = requireRecord(
              await httpPost(cfg, fetchImpl, cfg.killSwitchUrl, '/v1/kill-switch:trigger', payload),
              'kill-switch'
            );
            requireBooleanField(response, 'triggered', 'kill-switch');
            return ok({ ...response, source: 'kill-switch' });
          } catch (cause) {
            return dependencyFailure('warrantor_kill', 'kill-switch', cause);
          }
        }
        return ok({ triggered: true, killed_at: Math.floor(Date.now() / 1000), reason, agent, source: 'mock' });
      }

      // --- R4 credential-vault ---------------------------------------------
      case 'warrantor_scan_secrets': {
        const text = String(args.text ?? '');
        if (!isStandalone) {
          try {
            const response = requireRecord(
              await httpPost(cfg, fetchImpl, cfg.credentialVaultUrl, '/v1/credential-vault:scan', { text }),
              'credential-vault'
            );
            const findings = requireArrayField(response, 'findings', 'credential-vault');
            return ok({ ...response, findings, count: findings.length, source: 'credential-vault' });
          } catch (cause) {
            return dependencyFailure('warrantor_scan_secrets', 'credential-vault', cause);
          }
        }
        const findings = mockScanSecrets(text);
        return ok({ findings, count: findings.length, source: 'mock' });
      }

      // --- X1 defstack-cli --------------------------------------------------
      case 'warrantor_compliance_report': {
        const scope = String(args.scope ?? 'soc2');
        const format = String(args.format ?? 'json');
        if (!isStandalone) {
          if (format !== 'json') {
            return err('warrantor_compliance_report: defstack supports JSON output in connected mode', {
              code: 'INVALID_ARGUMENT',
            });
          }
          try {
            const result = await exec(cfg.defstackBin, ['compliance-report', '--model', scope]);
            if (result.code !== 0) return cliFailure('warrantor_compliance_report', 'defstack', result);
            if (!result.stdout.trim()) {
              throw new InvalidControlResponse('defstack', 'compliance-report output is empty');
            }
            try {
              JSON.parse(result.stdout);
            } catch (cause) {
              throw new InvalidControlResponse('defstack', `compliance-report output is not JSON: ${errorMessage(cause)}`);
            }
            return ok({ report_json: result.stdout.trim(), format: 'json', source: 'defstack' });
          } catch (cause) {
            return dependencyFailure('warrantor_compliance_report', 'defstack', cause);
          }
        }
        return ok({ ...mockComplianceReport(scope), source: 'mock' });
      }

      case 'warrantor_install': {
        const compName = String(args.name ?? '');
        if (!compName) return err('warrantor_install: "name" is required');
        const version = args.version ? String(args.version) : 'latest';
        if (!isStandalone) {
          if (args.version) {
            return err('warrantor_install: the connected defstack CLI does not support version pinning', {
              code: 'INVALID_ARGUMENT',
            });
          }
          try {
            const result = await exec(cfg.defstackBin, ['install', compName]);
            if (result.code !== 0) return cliFailure('warrantor_install', 'defstack', result);
            if (!result.stdout.trim()) {
              throw new InvalidControlResponse('defstack', 'install output is empty');
            }
            return ok({ installed: true, name: compName, version, source: 'defstack', stdout: result.stdout.trim() });
          } catch (cause) {
            return dependencyFailure('warrantor_install', 'defstack', cause);
          }
        }
        return ok({ installed: true, name: compName, version, source: 'mock' });
      }

      // --- S4 model-sbom ----------------------------------------------------
      case 'warrantor_generate_sbom': {
        const model = String(args.model ?? '');
        if (!model) return err('warrantor_generate_sbom: "model" is required');
        const format = String(args.format ?? 'cyclonedx');
        if (!isStandalone) {
          try {
            const response = requireRecord(
              await httpPost(cfg, fetchImpl, cfg.modelSbomUrl, '/v1/model-sbom:generate', { model, format }),
              'model-sbom'
            );
            requirePresentField(response, 'sbom', 'model-sbom');
            return ok({ ...response, source: 'model-sbom' });
          } catch (cause) {
            return dependencyFailure('warrantor_generate_sbom', 'model-sbom', cause);
          }
        }
        return ok({ source: 'mock', ...mockSbom(model) });
      }

      // --- A1 safe-eval -----------------------------------------------------
      case 'warrantor_run_eval': {
        const model = String(args.model ?? '');
        if (!model) return err('warrantor_run_eval: "model" is required');
        const pipeline = String(args.pipeline_yaml ?? '');
        const payload = { model, pipeline_yaml: pipeline };
        if (!isStandalone) {
          try {
            const response = requireRecord(
              await httpPost(cfg, fetchImpl, cfg.safeEvalUrl, '/v1/safe-eval:run', payload),
              'safe-eval'
            );
            requirePresentField(response, 'results', 'safe-eval');
            requirePresentField(response, 'summary', 'safe-eval');
            requirePresentField(response, 'veb', 'safe-eval');
            return ok({ ...response, source: 'safe-eval' });
          } catch (cause) {
            return dependencyFailure('warrantor_run_eval', 'safe-eval', cause);
          }
        }
        return ok({ source: 'mock', ...mockEval(model, pipeline) });
      }

      default:
        return err(`unknown tool: "${name}"`, { available: TOOLS.map((t) => t.name) });
    }
  } catch (e) {
    // Defensive: should be unreachable, but a tool must never crash the server.
    return err(`internal error in tool "${name}": ${errorMessage(e)}`, { code: 'INTERNAL_ERROR' });
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
      metadata: { timestamp: new Date().toISOString(), tool: 'mcp-server' },
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

/** Current stateless MCP protocol version supported by this server. */
export const MCP_PROTOCOL_VERSION = '2026-07-28';
/** Legacy handshake versions retained for dual-era client compatibility. */
export const MCP_LEGACY_PROTOCOL_VERSIONS = ['2025-11-25', '2024-11-05'] as const;
export const MCP_SUPPORTED_PROTOCOL_VERSIONS: readonly string[] = [
  MCP_PROTOCOL_VERSION,
  ...MCP_LEGACY_PROTOCOL_VERSIONS,
];
/** Default CLI binary names, resolved from PATH when no env override is given. */
export const DEFAULT_TRUST_CORE_BIN = 'trust-core';
/** @see DEFAULT_TRUST_CORE_BIN */
export const DEFAULT_DEFSTACK_BIN = 'defstack';

export const MCP_SERVER_NAME = 'mcp-server';
export const MCP_SERVER_VERSION = '1.0.0';
const MCP_PROTOCOL_VERSION_META_KEY = 'io.modelcontextprotocol/protocolVersion';
const MCP_CLIENT_INFO_META_KEY = 'io.modelcontextprotocol/clientInfo';
const MCP_CLIENT_CAPABILITIES_META_KEY = 'io.modelcontextprotocol/clientCapabilities';

/**
 * ListTools returns the tool descriptors in the shape MCP `tools/list` expects.
 * Exported for testing and for callers that want the catalog without a server.
 */
export function ListTools(): {
  resultType: 'complete';
  tools: ToolDescriptor[];
  ttlMs: number;
  cacheScope: 'public';
} {
  return { resultType: 'complete', tools: TOOLS, ttlMs: 300_000, cacheScope: 'public' };
}

/** Legacy MCP initialize result (capabilities + server info). */
function initializeResult(protocolVersion: string): unknown {
  return {
    protocolVersion,
    capabilities: { tools: { listChanged: false } },
    serverInfo: { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION },
  };
}

/** Stateless capability discovery required by modern MCP. */
function discoverResult(): unknown {
  return {
    resultType: 'complete',
    supportedVersions: MCP_SUPPORTED_PROTOCOL_VERSIONS,
    capabilities: { tools: { listChanged: false } },
    _meta: {
      'io.modelcontextprotocol/serverInfo': {
        name: MCP_SERVER_NAME,
        version: MCP_SERVER_VERSION,
      },
    },
    instructions:
      'Warrantor security controls. Connected mode is fail-closed; inspect isError before using a result.',
    ttlMs: 300_000,
    cacheScope: 'public',
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

class UnsupportedProtocolVersionError extends Error {
  readonly requested: string;

  constructor(requested: string) {
    super(`unsupported MCP protocol version: ${requested}`);
    this.name = 'UnsupportedProtocolVersionError';
    this.requested = requested;
  }
}

interface RequestMetadata {
  protocolVersion: string;
  clientCapabilities: Record<string, unknown>;
}

function hasModernMetadata(params: unknown): boolean {
  if (params === null || typeof params !== 'object' || Array.isArray(params)) return false;
  const meta = (params as Record<string, unknown>)._meta;
  return meta !== null && typeof meta === 'object' && !Array.isArray(meta);
}

function validateModernMetadata(params: unknown): RequestMetadata {
  const paramsObject = asObject(params);
  const meta = asObject(paramsObject._meta);
  const protocolVersion = meta[MCP_PROTOCOL_VERSION_META_KEY];
  if (typeof protocolVersion !== 'string') {
    throw new ObjectArgsError(`params._meta["${MCP_PROTOCOL_VERSION_META_KEY}"] must be a string`);
  }
  if (protocolVersion !== MCP_PROTOCOL_VERSION) {
    throw new UnsupportedProtocolVersionError(protocolVersion);
  }
  const clientCapabilities = meta[MCP_CLIENT_CAPABILITIES_META_KEY];
  if (clientCapabilities === null || typeof clientCapabilities !== 'object' || Array.isArray(clientCapabilities)) {
    throw new ObjectArgsError(
      `params._meta["${MCP_CLIENT_CAPABILITIES_META_KEY}"] must be an object`
    );
  }
  const clientInfo = meta[MCP_CLIENT_INFO_META_KEY];
  if (clientInfo !== undefined) {
    const info = asObject(clientInfo);
    if (typeof info.name !== 'string' || typeof info.version !== 'string') {
      throw new ObjectArgsError(
        `params._meta["${MCP_CLIENT_INFO_META_KEY}"] must contain string name and version`
      );
    }
  }
  return {
    protocolVersion,
    clientCapabilities: clientCapabilities as Record<string, unknown>,
  };
}

/** Map MCP JSON-RPC error semantics. */
const RPC_INVALID_REQUEST = -32600;
const RPC_METHOD_NOT_FOUND = -32601;
const RPC_INVALID_PARAMS = -32602;
const RPC_INTERNAL = -32603;
const RPC_UNSUPPORTED_PROTOCOL_VERSION = -32022;
const RPC_NOT_INITIALIZED = -32002;

/**
 * Server wraps the dispatch logic and owns the stdio transport loop. Constructed with an
 * WarrantorMcpConfig; `.run()` reads JSON-RPC requests line-by-line from stdin and writes
 * responses to stdout (logs to stderr — stdout is reserved for protocol frames).
 */
export class Server {
  readonly config: WarrantorMcpConfig;
  /** Negotiated legacy version, if a handshake-era client initialized this process. */
  private legacyProtocolVersion: string | undefined;
  /** True once at least one current stateless request passed metadata validation. */
  private modernRequestObserved = false;
  /** Counts for observability. */
  readonly stats = { requests: 0, calls: 0, errors: 0 };

  /** True after a valid modern request or successful legacy initialization. */
  isInitialized(): boolean {
    return this.modernRequestObserved || this.legacyProtocolVersion !== undefined;
  }

  constructor(config: WarrantorMcpConfig = { mode: 'connected' }) {
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
      try {
        if (hasModernMetadata(req.params)) {
          validateModernMetadata(req.params);
          this.modernRequestObserved = true;
        } else if (req.method === 'notifications/initialized' && this.legacyProtocolVersion) {
          // Legacy initialization acknowledgement; the handshake was already selected by initialize.
        }
      } catch {
        this.stats.errors++;
      }
      return null;
    }

    try {
      const modernRequest = hasModernMetadata(req.params);

      if (req.method === 'initialize' && !modernRequest) {
        const params = asObject(req.params);
        const requestedVersion = params.protocolVersion;
        if (
          typeof requestedVersion !== 'string' ||
          !(MCP_LEGACY_PROTOCOL_VERSIONS as readonly string[]).includes(requestedVersion)
        ) {
          this.stats.errors++;
          return rpcError(id, RPC_INVALID_PARAMS, 'unsupported legacy initialize protocol version', {
            supported: MCP_LEGACY_PROTOCOL_VERSIONS,
            requested: requestedVersion ?? null,
          });
        }
        this.legacyProtocolVersion = requestedVersion;
        return rpcResult(id, initializeResult(requestedVersion));
      }

      if (modernRequest) {
        validateModernMetadata(req.params);
        this.modernRequestObserved = true;
      } else if (!this.legacyProtocolVersion) {
        this.stats.errors++;
        return rpcError(
          id,
          RPC_NOT_INITIALIZED,
          'request has no modern MCP metadata and no legacy initialize handshake',
          { supported: MCP_SUPPORTED_PROTOCOL_VERSIONS }
        );
      }

      switch (req.method) {
        case 'server/discover':
          if (!modernRequest) {
            this.stats.errors++;
            return rpcError(id, RPC_METHOD_NOT_FOUND, 'server/discover requires modern request metadata');
          }
          return rpcResult(id, discoverResult());

        case 'initialize':
          this.stats.errors++;
          return rpcError(
            id,
            RPC_METHOD_NOT_FOUND,
            'initialize is a legacy method; use per-request metadata with MCP 2026-07-28',
            { supported: MCP_SUPPORTED_PROTOCOL_VERSIONS }
          );

        case 'ping':
          return rpcResult(id, modernRequest ? { resultType: 'complete' } : {});

        case 'tools/list':
          return rpcResult(
            id,
            modernRequest ? ListTools() : { tools: TOOLS }
          );

        case 'tools/call': {
          this.stats.calls++;
          const params = asObject(req.params);
          const toolName = params.name;
          if (typeof toolName !== 'string') {
            this.stats.errors++;
            return rpcError(id, RPC_INVALID_PARAMS, 'tools/call requires string "name"');
          }
          if (!TOOLS.some((tool) => tool.name === toolName)) {
            this.stats.errors++;
            return rpcError(id, RPC_INVALID_PARAMS, `unknown tool: "${toolName}"`, {
              available: TOOLS.map((tool) => tool.name),
            });
          }
          let toolArgs: Record<string, unknown> = {};
          if (params.arguments !== undefined) toolArgs = asObject(params.arguments);
          const result = await CallTool(toolName, toolArgs, this.config);
          if (result.isError) this.stats.errors++;
          return rpcResult(id, {
            ...(modernRequest ? { resultType: 'complete' } : {}),
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
      if (e instanceof UnsupportedProtocolVersionError) {
        return rpcError(id, RPC_UNSUPPORTED_PROTOCOL_VERSION, 'Unsupported protocol version', {
          supported: MCP_SUPPORTED_PROTOCOL_VERSIONS,
          requested: e.requested,
        });
      }
      if (e instanceof ObjectArgsError) {
        return rpcError(id, RPC_INVALID_PARAMS, e.message);
      }
      return rpcError(id, RPC_INTERNAL, `internal error: ${errorMessage(e)}`);
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

/** Parse process.argv into an WarrantorMcpConfig. */
export function configFromEnv(env: NodeJS.ProcessEnv = process.env, argv: string[] = process.argv.slice(2)): WarrantorMcpConfig {
  const hasStandaloneFlag = argv.includes('--standalone');
  const hasConnectedFlag = argv.includes('--connected');
  if (hasStandaloneFlag && hasConnectedFlag) {
    throw new Error('choose exactly one mode flag: --connected or --standalone');
  }
  const envMode = env.AUMOS_MODE;
  if (envMode !== undefined && envMode !== 'connected' && envMode !== 'standalone') {
    throw new Error('AUMOS_MODE must be "connected" or "standalone"');
  }
  const mode: WarrantorMode = envMode ?? (hasStandaloneFlag ? 'standalone' : 'connected');
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
    // Fall back to the bare command name so the binary resolves from PATH.
    //
    // These previously defaulted to `undefined`, which reached `spawn(undefined, ...)` and threw
    // `The "file" argument must be of type string. Received undefined`. Because `connected` is
    // the DEFAULT mode, every CLI-backed tool -- sign, verify, receipts, SBOM -- failed on first
    // use for anyone who had not set these env vars, with an error naming neither the tool nor
    // the missing binary. The doc comments on WarrantorMcpConfig already promised these defaults;
    // only the code was missing them.
    trustCoreBin: env.AUMOS_TRUST_CORE_BIN || DEFAULT_TRUST_CORE_BIN,
    defstackBin: env.AUMOS_DEFSTACK_BIN || DEFAULT_DEFSTACK_BIN,
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
