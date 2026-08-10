import { createPublicKey, verify as cryptoVerify } from 'node:crypto';

/**
 * @aumos/mcp-gateway (X8) — authority-aware Model Context Protocol (MCP) middleware.
 *
 * The gateway sits between an MCP client (an agent) and one or more MCP tool servers. It
 * intercepts every tool call, checks the caller's AAE (P1 Agent Authority Envelope) for the
 * tool's required scope, and either forwards the call to the real tool server or denies it.
 *
 * Defenses implemented (per RFC X8 / specs/protocols/P1-aae.md):
 *   - Confused-deputy defense: the AAE's `tools` list must explicitly contain the requested
 *     tool's SPIFFE ID. A gateway can never be tricked into calling a tool the principal did
 *     not authorize, even if the agent hands it a crafted tool name.
 *   - Audience check: the AAE must be issued *for this gateway* (its `resources` list must
 *     contain the gateway's SPIFFE ID). An AAE minted for a different gateway must be rejected.
 *   - Side-effect-class enforcement: each tool declares the side-effect class it performs
 *     (read/write/financial/destructive/physical). The AAE's `side_effect_class` must be
 *     sufficient to cover the tool's declared class. Consequential classes (financial,
 *     destructive, physical) additionally require an explicit approval entry (invariant I-08).
 *
 * Forwarding is dependency-injected and fail-closed. The bundled Streamable HTTP transport
 * sends a real MCP JSON-RPC `tools/call` request and validates the remote response before the
 * gateway records a successful forward.
 */

// ---------------------------------------------------------------------------
// Side-effect class — mirrors proto/aumos/identity/v1/agent.proto field 7 and
// the invariant I-08 consequential-action escalation ladder.
// ---------------------------------------------------------------------------

/** Side-effect classes ordered by escalating consequence (matches invariant I-08). */
export type SideEffectClass = 'read' | 'write' | 'financial' | 'destructive' | 'physical';

/** Numeric severity for the consequence ladder; higher = more consequential. */
const SIDE_EFFECT_RANK: Record<SideEffectClass, number> = {
  read: 0,
  write: 1,
  financial: 2,
  destructive: 3,
  physical: 4,
};

/** Consequential classes that require explicit human approval (invariant I-08). */
export const CONSEQUENTIAL_CLASSES: ReadonlySet<SideEffectClass> = new Set([
  'financial',
  'destructive',
  'physical',
]);

/** True if `cls` is consequential (requires human approval per invariant I-08). */
export function isConsequential(cls: SideEffectClass): boolean {
  return CONSEQUENTIAL_CLASSES.has(cls);
}

/**
 * Enforcement surfaces an agent may never write to, per invariant I-11
 * ("self-change is governed"). Matched as a prefix against the tool's SPIFFE ID
 * and, where declared, against the resources the tool mutates.
 *
 * Rationale in docs/cross-cutting/21-threat-model.md §4. The set is deliberately
 * coarse: a false denial here is an operator inconvenience, whereas a false
 * allowance lets an agent rewrite the rules that bind it.
 */
export const SELF_CHANGE_PROTECTED_PREFIXES: readonly string[] = [
  'spiffe://aumos.dev/trust-core',
  'spiffe://aumos.dev/authority',
  'spiffe://aumos.dev/agent-identity',
  'spiffe://aumos.dev/policy',
  'spiffe://aumos.dev/flight-recorder',
  'spiffe://aumos.dev/evidence',
  'spiffe://aumos.dev/trust-bundle',
  'spiffe://aumos.dev/kms',
  'spiffe://aumos.dev/mcp-gateway',
];

/**
 * True if invoking this tool would let the caller mutate the substrate that
 * constrains it. Read-only access to these surfaces is permitted — an agent may
 * inspect the policy that governs it; it may not rewrite it.
 */
export function isSelfChange(scope: ToolScope): boolean {
  if (scope.sideEffectClass === 'read') return false;
  const targets = [scope.toolSvid, ...(scope.mutates ?? [])];
  return targets.some((t) =>
    SELF_CHANGE_PROTECTED_PREFIXES.some((p) => t === p || t.startsWith(`${p}/`))
  );
}

// ---------------------------------------------------------------------------
// Agent Authority Envelope (P1) — mirrors proto/aumos/identity/v1/agent.proto
// message AgentAuthorityEnvelope. The gateway consumes this from the VerifyIdentity
// RPC; it does not sign/verify here (trust-core T1 owns the cryptography).
// ---------------------------------------------------------------------------

/** An Agent Authority Envelope, as resolved by I1 agent-identity's VerifyIdentity. */
export interface AgentAuthorityEnvelope {
  /** SPIFFE ID of the issuer (e.g. "spiffe://aumos.dev/agent-identity"). */
  issuer: string;
  /** SPIFFE ID of the subject agent. */
  subject: string;
  /** Human-readable purpose of this delegation. */
  purpose: string;
  /** Resources the agent may touch (URIs / SPIFFE IDs). Audience check uses this. */
  resources: string[];
  /** Tools the agent may invoke (SPIFFE IDs of tool servers). Confused-deputy check uses this. */
  tools: string[];
  /** Data classification levels the agent may read (L0..L4 per cross-cutting 17). */
  dataClasses: string[];
  /** Side-effect class the agent is permitted to perform. */
  sideEffectClass: SideEffectClass;
  /** Spend budget in minor currency units (cents). */
  spendBudget: number;
  /** Wall-clock time budget in seconds. */
  timeBudgetSeconds: number;
  /** Token-count budget for inference calls. */
  tokenBudget: number;
  /** Geographic constraint (ISO-3166 alpha-2; empty = unrestricted). */
  geography: string;
  /** Maximum delegation depth (0 = no further delegation). */
  delegationDepth: number;
  /** Required approver SPIFFE IDs (for consequential actions; invariant I-08). */
  approvals: string[];
  /** Expiry epoch seconds. Must be > 0; 0 or negative is invalid, never "unlimited". */
  expiry: number;
  /** Revocation handle (opaque). Checked against the injected RevocationChecker. */
  revocationHandle: string;
  /**
   * Detached Ed25519 signature by the issuer over the canonical envelope bytes.
   *
   * AX-02: this field previously did not exist. `authorize()` accepted the envelope
   * as a plain caller-supplied object, so a forged envelope claiming
   * `issuer: "spiffe://evil.example"` authorised a `destructive` tool call. An
   * authority envelope without a verified signature is a suggestion, not authority.
   */
  signature: EnvelopeSignature;
}

/** Detached Ed25519 signature over the canonical envelope encoding. */
export interface EnvelopeSignature {
  algorithm: 'Ed25519';
  /** Key identifier, resolved against the gateway's trust bundle. */
  keyId: string;
  /** 128 lowercase hex characters (64 raw bytes). */
  value: string;
}

/**
 * Maps a key identifier to the raw 32-byte Ed25519 public key that may use it,
 * and to the issuer SPIFFE ID that key is authorised to speak for.
 *
 * Binding keyId → issuer matters: without it any key in the bundle can sign for
 * any agent, which is the same defect recorded as AX-07 in the Rust crates.
 */
export interface TrustBundleEntry {
  keyId: string;
  issuer: string;
  /** Raw Ed25519 public key, 32 bytes, hex-encoded (64 chars). */
  publicKeyHex: string;
}

/** Resolves whether a revocation handle has been revoked. Injected by the deployer. */
export interface RevocationChecker {
  isRevoked(revocationHandle: string): boolean;
}

/** Observed resource consumption for the current authority, used for budget ceilings. */
export interface BudgetUsage {
  spentMinor: number;
  elapsedSeconds: number;
  tokensUsed: number;
}

// ---------------------------------------------------------------------------
// Tool registry — maps tool names → the scope they require.
// ---------------------------------------------------------------------------

/** A tool's required scope: its SPIFFE ID + the side-effect class it performs. */
export interface ToolScope {
  /** The tool server's SPIFFE ID (the value that must appear in the AAE's `tools` list). */
  toolSvid: string;
  /** The side-effect class this tool performs. */
  sideEffectClass: SideEffectClass;
  /** Data classes this tool touches (L0..L4). Must be a subset of the AAE's grant. */
  dataClasses?: string[];
  /** ISO-3166 alpha-2 region this tool executes in, if regionally pinned. */
  geography?: string;
  /** Resources this tool mutates, if broader than its own SVID. Checked against I-11. */
  mutates?: string[];
}

/** A tool registered with the gateway. */
export interface RegisteredTool {
  /** The human-readable tool name the agent calls (e.g. "github.create_pr"). */
  name: string;
  /** The scope required to invoke this tool. */
  scope: ToolScope;
  /** Optional human-readable description. */
  description?: string;
}

/**
 * ToolRegistry maps tool names (what the agent calls) to the scope required to invoke them.
 * In production this is populated from a manifest the tool servers publish on connect.
 */
export class ToolRegistry {
  private readonly tools = new Map<string, RegisteredTool>();

  /** Registers (or replaces) a tool. Returns this for chaining. */
  register(tool: RegisteredTool): this {
    this.tools.set(tool.name, tool);
    return this;
  }

  /** Registers many tools at once. */
  registerAll(tools: RegisteredTool[]): this {
    for (const t of tools) this.register(t);
    return this;
  }

  /** Looks up a tool by name. Returns undefined if unknown. */
  lookup(name: string): RegisteredTool | undefined {
    return this.tools.get(name);
  }

  /** True if a tool with this name is registered. */
  has(name: string): boolean {
    return this.tools.has(name);
  }

  /** Removes a tool. */
  unregister(name: string): boolean {
    return this.tools.delete(name);
  }

  /** Returns a sorted list of all registered tool names. */
  names(): string[] {
    return [...this.tools.keys()].sort();
  }

  /** The number of registered tools. */
  get size(): number {
    return this.tools.size;
  }
}

// ---------------------------------------------------------------------------
// Tool call — what the agent sends through the gateway.
// ---------------------------------------------------------------------------

/** An inbound MCP tool call from an agent. */
export interface ToolCall {
  /** The tool name the agent wants to invoke (looked up in the ToolRegistry). */
  tool: string;
  /** The arguments object the agent passed. */
  args: Record<string, unknown>;
  /** The caller's SVID (SPIFFE ID of the agent). */
  callerSvid: string;
}

// ---------------------------------------------------------------------------
// Authorization result.
// ---------------------------------------------------------------------------

/** Machine-stable reason codes. */
export type Reason =
  | 'allowed'
  | 'unknown_tool'
  | 'tool_not_in_aae' // confused-deputy defense
  | 'audience_mismatch'
  | 'side_effect_class_insufficient'
  | 'consequential_approval_missing' // invariant I-08
  | 'expired'
  | 'subject_mismatch'
  | 'signature_invalid'          // AX-02: envelope authenticity
  | 'revoked'
  | 'data_class_exceeded'
  | 'geography_violation'
  | 'budget_exhausted'
  | 'delegation_depth_invalid'
  | 'self_change_denied';        // invariant I-11

export type DenialReason = Exclude<Reason, 'allowed'>;

/** A successful authorization always carries the exact scope that may be forwarded. */
export interface AllowedAuthorizationResult {
  allowed: true;
  reason: 'allowed';
  detail: string;
  scope: ToolScope;
}

/** A denied authorization can never be passed to the transport. */
export interface DeniedAuthorizationResult {
  allowed: false;
  reason: DenialReason;
  detail: string;
  scope?: ToolScope;
}

/** The discriminated outcome of authorizing a tool call against an AAE. */
export type AuthorizationResult = AllowedAuthorizationResult | DeniedAuthorizationResult;

/** Convenience constructors. */
function allow(scope: ToolScope): AllowedAuthorizationResult {
  return { allowed: true, reason: 'allowed', detail: 'call authorized', scope };
}

function deny(reason: DenialReason, detail: string, scope?: ToolScope): DeniedAuthorizationResult {
  return { allowed: false, reason, detail, scope };
}

// ---------------------------------------------------------------------------
// Forward transport.
// ---------------------------------------------------------------------------

/** The authorized request passed to an outbound transport. */
export interface ForwardRequest {
  call: ToolCall;
  scope: ToolScope;
  gatewaySvid: string;
}

/** Dependency boundary used by the gateway to call an actual tool server. */
export interface ToolTransport {
  call(request: ForwardRequest): Promise<unknown>;
}

export type GatewayForwardErrorCode =
  | 'authorization_denied'
  | 'transport_unavailable'
  | 'transport_timeout'
  | 'http_error'
  | 'unsupported_content_type'
  | 'invalid_response'
  | 'remote_error';

/** A stable, observable failure returned by the forwarding boundary. */
export class GatewayForwardError extends Error {
  readonly code: GatewayForwardErrorCode;
  readonly retryable: boolean;
  readonly details: Readonly<Record<string, unknown>>;

  constructor(
    code: GatewayForwardErrorCode,
    message: string,
    options: { retryable?: boolean; details?: Record<string, unknown>; cause?: unknown } = {}
  ) {
    super(message, { cause: options.cause });
    this.name = 'GatewayForwardError';
    this.code = code;
    this.retryable = options.retryable ?? false;
    this.details = Object.freeze({ ...(options.details ?? {}) });
  }
}

export const MCP_PROTOCOL_VERSION = '2026-07-28';

export interface McpHttpTransportConfig {
  /** Resolves a registered tool identity to its Streamable HTTP endpoint. */
  resolveEndpoint: (toolSvid: string, toolName: string) => string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  clientInfo?: { name: string; version: string };
  capabilities?: Record<string, unknown>;
  requestId?: () => string | number;
}

interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function parseJsonRpcResponse(value: unknown, expectedId: string | number): JsonRpcResponse {
  if (!isRecord(value) || value.jsonrpc !== '2.0' || value.id !== expectedId) {
    throw new GatewayForwardError(
      'invalid_response',
      'tool server returned an invalid or mismatched JSON-RPC response'
    );
  }
  if (value.error !== undefined) {
    if (
      !isRecord(value.error) ||
      typeof value.error.code !== 'number' ||
      typeof value.error.message !== 'string'
    ) {
      throw new GatewayForwardError('invalid_response', 'tool server returned a malformed JSON-RPC error');
    }
    return {
      jsonrpc: '2.0',
      id: value.id as string | number | null,
      error: {
        code: value.error.code,
        message: value.error.message,
        ...(value.error.data === undefined ? {} : { data: value.error.data }),
      },
    };
  }
  if (!Object.prototype.hasOwnProperty.call(value, 'result')) {
    throw new GatewayForwardError('invalid_response', 'tool server response has neither result nor error');
  }
  return { jsonrpc: '2.0', id: value.id as string | number | null, result: value.result };
}

function parseSseResponses(body: string, expectedId: string | number): JsonRpcResponse {
  const dataPayloads: string[] = [];
  let currentDataLines: string[] = [];
  for (const line of body.split(/\r?\n/)) {
    if (line === '') {
      if (currentDataLines.length > 0) dataPayloads.push(currentDataLines.join('\n'));
      currentDataLines = [];
    } else if (line.startsWith('data:')) {
      currentDataLines.push(line.slice(5).trimStart());
    }
  }
  if (currentDataLines.length > 0) dataPayloads.push(currentDataLines.join('\n'));

  for (const payload of dataPayloads.reverse()) {
    if (payload === '[DONE]') continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(payload);
    } catch {
      continue;
    }
    if (isRecord(parsed) && parsed.id === expectedId) return parseJsonRpcResponse(parsed, expectedId);
  }
  throw new GatewayForwardError(
    'invalid_response',
    'tool server event stream did not contain the matching JSON-RPC response'
  );
}

/** Current MCP Streamable HTTP transport for authorized `tools/call` requests. */
export class McpHttpTransport implements ToolTransport {
  private readonly resolveEndpoint: (toolSvid: string, toolName: string) => string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly clientInfo: { name: string; version: string };
  private readonly capabilities: Record<string, unknown>;
  private readonly requestId: () => string | number;
  private sequence = 0;

  constructor(config: McpHttpTransportConfig) {
    if (!config.resolveEndpoint) throw new Error('McpHttpTransport: resolveEndpoint is required');
    if (config.timeoutMs !== undefined && (!Number.isFinite(config.timeoutMs) || config.timeoutMs <= 0)) {
      throw new Error('McpHttpTransport: timeoutMs must be a positive finite number');
    }
    this.resolveEndpoint = config.resolveEndpoint;
    this.fetchImpl = config.fetchImpl ?? globalThis.fetch;
    this.timeoutMs = config.timeoutMs ?? 5_000;
    this.clientInfo = config.clientInfo ?? { name: '@aumos/mcp-gateway', version: '1.0.0' };
    this.capabilities = { ...(config.capabilities ?? {}) };
    this.requestId = config.requestId ?? (() => `aumos-gateway-${++this.sequence}`);
  }

  async call(request: ForwardRequest): Promise<unknown> {
    const endpoint = this.resolveEndpoint(request.scope.toolSvid, request.call.tool);
    let url: URL;
    try {
      url = new URL(endpoint);
    } catch (cause) {
      throw new GatewayForwardError('transport_unavailable', 'tool endpoint resolver returned an invalid URL', {
        details: { tool: request.call.tool, toolSvid: request.scope.toolSvid },
        cause,
      });
    }
    if (url.protocol !== 'https:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
      throw new GatewayForwardError('transport_unavailable', 'remote MCP endpoints must use HTTPS', {
        details: { tool: request.call.tool, scheme: url.protocol },
      });
    }

    const id = this.requestId();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method: 'POST',
        headers: {
          accept: 'application/json, text/event-stream',
          'content-type': 'application/json',
          'MCP-Protocol-Version': MCP_PROTOCOL_VERSION,
          'Mcp-Method': 'tools/call',
          'Mcp-Name': request.call.tool,
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id,
          method: 'tools/call',
          params: {
            name: request.call.tool,
            arguments: request.call.args,
            _meta: {
              'io.modelcontextprotocol/protocolVersion': MCP_PROTOCOL_VERSION,
              'io.modelcontextprotocol/clientInfo': this.clientInfo,
              'io.modelcontextprotocol/clientCapabilities': this.capabilities,
              'dev.aumos/gatewaySvid': request.gatewaySvid,
              'dev.aumos/callerSvid': request.call.callerSvid,
            },
          },
        }),
        signal: controller.signal,
      });
    } catch (cause) {
      const timedOut = controller.signal.aborted;
      throw new GatewayForwardError(
        timedOut ? 'transport_timeout' : 'transport_unavailable',
        timedOut ? `tool request timed out after ${this.timeoutMs}ms` : 'tool transport request failed',
        {
          retryable: true,
          details: { tool: request.call.tool, toolSvid: request.scope.toolSvid },
          cause,
        }
      );
    } finally {
      clearTimeout(timer);
    }

    const body = await response.text();
    if (!response.ok) {
      throw new GatewayForwardError('http_error', `tool server returned HTTP ${response.status}`, {
        retryable: response.status >= 500 || response.status === 429,
        details: { status: response.status, tool: request.call.tool },
      });
    }

    const contentType = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
    let envelope: JsonRpcResponse;
    if (contentType === 'application/json') {
      let parsed: unknown;
      try {
        parsed = JSON.parse(body);
      } catch (cause) {
        throw new GatewayForwardError('invalid_response', 'tool server returned invalid JSON', { cause });
      }
      envelope = parseJsonRpcResponse(parsed, id);
    } else if (contentType === 'text/event-stream') {
      envelope = parseSseResponses(body, id);
    } else {
      throw new GatewayForwardError(
        'unsupported_content_type',
        `tool server returned unsupported content type "${contentType ?? 'missing'}"`
      );
    }

    if (envelope.error) {
      throw new GatewayForwardError('remote_error', `tool server rejected the call: ${envelope.error.message}`, {
        details: { remoteCode: envelope.error.code, tool: request.call.tool },
      });
    }
    return envelope.result;
  }
}

// ---------------------------------------------------------------------------
// The gateway.
// ---------------------------------------------------------------------------

/** Configuration for constructing a gateway. */
export interface McpGatewayConfig {
  /** This gateway's own SPIFFE ID; AAE resources must contain it (audience check). */
  gatewaySvid: string;
  /** The tool registry the gateway enforces. */
  registry: ToolRegistry;
  /** Required outbound transport. Omitting it would make real forwarding impossible. */
  transport: ToolTransport;
  /**
   * Trust bundle: the keys permitted to issue authority for this gateway, each bound
   * to the issuer SPIFFE ID it may speak for. REQUIRED — a gateway with no trust
   * bundle cannot distinguish authority from assertion.
   */
  trustBundle: TrustBundleEntry[];
  /** Approver SPIFFE IDs accepted for consequential actions (invariant I-08). */
  approvers?: string[];
  /** Distinct approvers required for a consequential action. Defaults to 1. */
  approvalQuorum?: number;
  /** Revocation oracle. Defaults to a checker that treats nothing as revoked. */
  revocation?: RevocationChecker;
  /**
   * Optional clock function (epoch seconds). Defaults to Date.now()/1000. Injected for tests.
   */
  now?: () => number;
}

/**
 * McpGateway intercepts MCP tool calls and enforces the caller's AAE before forwarding.
 *
 * Usage:
 *   const gw = new McpGateway({ gatewaySvid, registry, transport });
 *   const result = gw.authorize(call, aae);
 *   if (result.allowed) { await gw.forward(call, result); }
 */
export class McpGateway {
  readonly gatewaySvid: string;
  readonly registry: ToolRegistry;
  private readonly now: () => number;
  private readonly transport: ToolTransport;
  private readonly trustBundle: Map<string, TrustBundleEntry>;
  private readonly approvers: Set<string>;
  private readonly approvalQuorum: number;
  private readonly revocation: RevocationChecker;
  /** Counters for observability; incremented on every authorize() / forward(). */
  private readonly stats = { authorized: 0, denied: 0, forwarded: 0, failed: 0 };

  constructor(config: McpGatewayConfig) {
    if (!config.gatewaySvid) throw new Error('McpGateway: gatewaySvid is required');
    if (!config.registry) throw new Error('McpGateway: registry is required');
    if (!config.transport) throw new Error('McpGateway: transport is required');
    this.gatewaySvid = config.gatewaySvid;
    this.registry = config.registry;
    this.transport = config.transport;
    if (!Array.isArray(config.trustBundle) || config.trustBundle.length === 0) {
      throw new Error(
        'McpGateway: trustBundle is required and must be non-empty. A gateway with no ' +
          'trust anchor cannot verify authority, only assume it (AX-02).'
      );
    }
    this.trustBundle = new Map(config.trustBundle.map((e) => [e.keyId, e]));
    this.approvers = new Set(config.approvers ?? []);
    this.approvalQuorum = config.approvalQuorum ?? 1;
    this.revocation = config.revocation ?? { isRevoked: () => false };
    this.now = config.now ?? (() => Math.floor(Date.now() / 1000));
  }

  /**
   * Authorize a tool call against the caller's AAE. Pure function of (call, aae, time).
   *
   * Checks performed, in order:
   *   1. Tool is registered.
   *   2. AAE is not expired.
   *   3. AAE subject matches the caller SVID (the caller is who the AAE was minted for).
   *   4. Audience: the AAE was issued for this gateway (gatewaySvid ∈ aae.resources).
   *   5. Confused-deputy: the tool's SPIFFE ID is in the AAE's `tools` list.
   *   6. Side-effect class: aae.sideEffectClass rank >= tool's required class rank.
   *   7. Consequential (I-08): if the tool's class is consequential, the AAE must carry an
   *      approval entry naming this tool's SVID (i.e. the approver signed off on this tool).
   */
  /**
   * Canonical byte encoding an issuer signs over. Field order is fixed here and must
   * not depend on object key order, which is why the fields are listed explicitly
   * rather than serialised from the object.
   */
  static canonicalEnvelopeBytes(aae: AgentAuthorityEnvelope): Buffer {
    const canonical = [
      aae.issuer,
      aae.subject,
      aae.purpose,
      aae.resources.join(','),
      aae.tools.join(','),
      aae.dataClasses.join(','),
      aae.sideEffectClass,
      String(aae.spendBudget),
      String(aae.timeBudgetSeconds),
      String(aae.tokenBudget),
      aae.geography,
      String(aae.delegationDepth),
      aae.approvals.join(','),
      String(aae.expiry),
      aae.revocationHandle,
    ].join('');
    return Buffer.from(`aumos-aae-v1${canonical}`, 'utf8');
  }

  /**
   * Verify envelope authenticity against the trust bundle.
   *
   * Three things must hold, and the third is the one usually forgotten: the key that
   * signed must be authorised to speak for the issuer named in the envelope.
   * Otherwise any key in the bundle can mint authority for any agent.
   */
  private verifyEnvelope(
    aae: AgentAuthorityEnvelope
  ): { ok: true } | { ok: false; detail: string } {
    const sig = aae.signature;
    if (!sig || sig.algorithm !== 'Ed25519') {
      return { ok: false, detail: 'envelope carries no Ed25519 signature' };
    }
    if (!/^[0-9a-f]{128}$/.test(sig.value)) {
      return { ok: false, detail: 'signature value must be 128 lowercase hex characters' };
    }
    const entry = this.trustBundle.get(sig.keyId);
    if (!entry) {
      return { ok: false, detail: `key "${sig.keyId}" is not in the gateway trust bundle` };
    }
    if (entry.issuer !== aae.issuer) {
      return {
        ok: false,
        detail:
          `key "${sig.keyId}" is authorised for issuer "${entry.issuer}" but the envelope ` +
          `claims "${aae.issuer}"`,
      };
    }
    const spki = Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      Buffer.from(entry.publicKeyHex, 'hex'),
    ]);
    const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    const verified = cryptoVerify(
      null,
      McpGateway.canonicalEnvelopeBytes(aae),
      key,
      Buffer.from(sig.value, 'hex')
    );
    return verified ? { ok: true } : { ok: false, detail: 'Ed25519 signature does not verify' };
  }

  authorize(
    call: ToolCall,
    aae: AgentAuthorityEnvelope,
    usage: BudgetUsage = { spentMinor: 0, elapsedSeconds: 0, tokensUsed: 0 }
  ): AuthorizationResult {
    const tool = this.registry.lookup(call.tool);
    if (!tool) {
      return deny('unknown_tool', `tool "${call.tool}" is not registered with this gateway`);
    }
    const scope = tool.scope;

    // 1. AUTHENTICITY — before any policy evaluation. An unverified envelope is not
    //    authority. This check did not exist prior to AX-02.
    const authentic = this.verifyEnvelope(aae);
    if (!authentic.ok) {
      return deny('signature_invalid', authentic.detail, scope);
    }

    // 1b. Revocation. `revocationHandle` was previously declared and never read.
    if (this.revocation.isRevoked(aae.revocationHandle)) {
      return deny('revoked', `authority ${aae.revocationHandle} has been revoked`, scope);
    }

    // 2. Expiry. `expiry <= 0` is INVALID, not "unlimited". The previous guard was
    //    `aae.expiry > 0 && now >= aae.expiry`, so an attacker-set `expiry: 0`
    //    disabled the check entirely — and the test fixtures shipped that way.
    if (!Number.isInteger(aae.expiry) || aae.expiry <= 0) {
      return deny('expired', `AAE expiry must be a positive epoch second, got ${aae.expiry}`, scope);
    }
    if (this.now() >= aae.expiry) {
      return deny('expired', `AAE expired at ${aae.expiry}`, scope);
    }

    // 3. Subject binding: the caller must be the AAE's subject.
    if (call.callerSvid !== aae.subject) {
      return deny(
        'subject_mismatch',
        `caller "${call.callerSvid}" does not match AAE subject "${aae.subject}"`,
        scope
      );
    }

    // 4. Audience check (confused-deputy defense, gateway side).
    if (!aae.resources.includes(this.gatewaySvid)) {
      return deny(
        'audience_mismatch',
        `AAE not issued for this gateway; resources must contain "${this.gatewaySvid}"`,
        scope
      );
    }

    // 5. Confused-deputy defense (tool side): the tool's SVID must be in the AAE tools list.
    if (!aae.tools.includes(scope.toolSvid)) {
      return deny(
        'tool_not_in_aae',
        `tool "${scope.toolSvid}" is not in the AAE's tools list; confused-deputy attempt blocked`,
        scope
      );
    }

    // 6. Side-effect-class enforcement (escalation ladder).
    if (SIDE_EFFECT_RANK[aae.sideEffectClass] < SIDE_EFFECT_RANK[scope.sideEffectClass]) {
      return deny(
        'side_effect_class_insufficient',
        `AAE permits "${aae.sideEffectClass}" but tool requires "${scope.sideEffectClass}"`,
        scope
      );
    }

    // 6b. Data-class ceiling. Declared in the envelope and previously never read.
    if (scope.dataClasses !== undefined) {
      const permitted = new Set(aae.dataClasses);
      const excess = scope.dataClasses.filter((c) => !permitted.has(c));
      if (excess.length > 0) {
        return deny(
          'data_class_exceeded',
          `tool requires data classes [${excess.join(', ')}] not granted by the AAE`,
          scope
        );
      }
    }

    // 6c. Geography. Declared and previously never read.
    if (aae.geography && scope.geography && aae.geography !== scope.geography) {
      return deny(
        'geography_violation',
        `AAE is scoped to ${aae.geography}; tool executes in ${scope.geography}`,
        scope
      );
    }

    // 6d. Budget ceilings. All three were declared, typed, documented — and never read.
    if (usage.spentMinor > aae.spendBudget) {
      return deny('budget_exhausted', `spend ${usage.spentMinor} exceeds ${aae.spendBudget}`, scope);
    }
    if (usage.elapsedSeconds > aae.timeBudgetSeconds) {
      return deny(
        'budget_exhausted',
        `elapsed ${usage.elapsedSeconds}s exceeds ${aae.timeBudgetSeconds}s`,
        scope
      );
    }
    if (usage.tokensUsed > aae.tokenBudget) {
      return deny('budget_exhausted', `tokens ${usage.tokensUsed} exceeds ${aae.tokenBudget}`, scope);
    }

    // 6e. Delegation depth. Declared and previously never read.
    if (!Number.isInteger(aae.delegationDepth) || aae.delegationDepth < 0 || aae.delegationDepth > 32) {
      return deny(
        'delegation_depth_invalid',
        `delegationDepth must be an integer in 0..32, got ${aae.delegationDepth}`,
        scope
      );
    }

    // 6f. INVARIANT I-11 — self-change is governed. An agent may not modify the
    //     enforcement boundary, policy, identity or evidence that constrains it.
    //     This is checked BEFORE the approval gate and is deliberately not
    //     overridable by approval: an agent that can obtain sign-off to rewrite the
    //     policy engine can obtain sign-off for everything afterwards.
    //     Documented in docs/cross-cutting/21-threat-model.md §4, including its
    //     limitation -- this is one chokepoint, not an OS-level guarantee.
    if (isSelfChange(scope)) {
      return deny(
        'self_change_denied',
        `tool "${scope.toolSvid}" targets a protected enforcement surface; ` +
          `an agent cannot modify its own boundary, policy, identity or evidence (I-11)`,
        scope
      );
    }

    // 7. Consequential-action approval (invariant I-08).
    if (isConsequential(scope.sideEffectClass)) {
      // `approvals` holds APPROVER SPIFFE IDs. The previous check was
      // `approvals.some(a => a.includes(scope.toolSvid))` — a substring match of an
      // approver string against the TOOL's SVID. Type-confused and collidable: an
      // approval naming `.../payroll-readonly-DIFFERENT-TOOL` authorised a financial
      // tool whose SVID was `.../pay`. Approvers must be exact members of the
      // gateway's configured approver set, and quorum must be met.
      const distinctApprovers = new Set(
        aae.approvals.filter((a) => this.approvers.has(a))
      );
      const hasApproval = distinctApprovers.size >= this.approvalQuorum;
      if (!hasApproval) {
        return deny(
          'consequential_approval_missing',
          `tool "${scope.toolSvid}" is consequential (${scope.sideEffectClass}); ` +
            `AAE approvals must include this tool (invariant I-08)`,
          scope
        );
      }
    }

    this.stats.authorized++;
    return allow(scope);
  }

  /**
   * Forwards an authorized tool call to the real tool server.
   *
   * @throws if `result` is not an allowed AuthorizationResult.
   */
  async forward(call: ToolCall, result: AuthorizationResult): Promise<unknown> {
    if (!result.allowed) {
      this.stats.failed++;
      throw new GatewayForwardError(
        'authorization_denied',
        `McpGateway.forward: refusing to forward a denied call (${result.reason})`,
        { details: { reason: result.reason, tool: call.tool } }
      );
    }
    try {
      const response = await this.transport.call({
        call,
        scope: result.scope,
        gatewaySvid: this.gatewaySvid,
      });
      this.stats.forwarded++;
      return response;
    } catch (cause) {
      this.stats.failed++;
      if (cause instanceof GatewayForwardError) throw cause;
      throw new GatewayForwardError('transport_unavailable', 'tool transport failed', {
        retryable: true,
        details: { tool: call.tool, toolSvid: result.scope.toolSvid },
        cause,
      });
    }
  }

  /** Returns counters for observability (authorized, denied, forwarded, failed). */
  counters(): { authorized: number; denied: number; forwarded: number; failed: number } {
    return { ...this.stats };
  }

  /** Internal: increments the denied counter (used by callers wrapping authorize). */
  noteDenial(): void {
    this.stats.denied++;
  }
}
