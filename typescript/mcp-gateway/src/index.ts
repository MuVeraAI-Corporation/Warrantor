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
 * v1.0 ships the authorization logic + tool registry; `forward()` is a stub that would in
 * production proxy the call over MCP JSON-RPC to the real tool server.
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
  /** Expiry epoch seconds. After this the envelope is invalid. */
  expiry: number;
  /** Revocation handle (opaque). */
  revocationHandle: string;
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

/** The outcome of authorizing a tool call against an AAE. */
export interface AuthorizationResult {
  /** True if the call may be forwarded; false if it must be denied. */
  allowed: boolean;
  /** Machine-stable reason code for telemetry / logging. */
  reason: Reason;
  /** Human-readable explanation. */
  detail: string;
  /** The tool scope that was evaluated (set when the tool is known). */
  scope?: ToolScope;
}

/** Machine-stable reason codes. */
export type Reason =
  | 'allowed'
  | 'unknown_tool'
  | 'tool_not_in_aae' // confused-deputy defense
  | 'audience_mismatch'
  | 'side_effect_class_insufficient'
  | 'consequential_approval_missing' // invariant I-08
  | 'expired'
  | 'subject_mismatch';

/** Convenience constructors. */
function allow(scope: ToolScope): AuthorizationResult {
  return { allowed: true, reason: 'allowed', detail: 'call authorized', scope };
}

function deny(reason: Reason, detail: string, scope?: ToolScope): AuthorizationResult {
  return { allowed: false, reason, detail, scope };
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
  /**
   * Optional clock function (epoch seconds). Defaults to Date.now()/1000. Injected for tests.
   */
  now?: () => number;
}

/**
 * McpGateway intercepts MCP tool calls and enforces the caller's AAE before forwarding.
 *
 * Usage:
 *   const gw = new McpGateway({ gatewaySvid, registry });
 *   const result = gw.authorize(call, aae);
 *   if (result.allowed) { await gw.forward(call); }
 */
export class McpGateway {
  readonly gatewaySvid: string;
  readonly registry: ToolRegistry;
  private readonly now: () => number;
  /** Counters for observability; incremented on every authorize() / forward(). */
  private readonly stats = { authorized: 0, denied: 0, forwarded: 0 };

  constructor(config: McpGatewayConfig) {
    if (!config.gatewaySvid) throw new Error('McpGateway: gatewaySvid is required');
    if (!config.registry) throw new Error('McpGateway: registry is required');
    this.gatewaySvid = config.gatewaySvid;
    this.registry = config.registry;
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
  authorize(call: ToolCall, aae: AgentAuthorityEnvelope): AuthorizationResult {
    const tool = this.registry.lookup(call.tool);
    if (!tool) {
      return deny('unknown_tool', `tool "${call.tool}" is not registered with this gateway`);
    }
    const scope = tool.scope;

    // 2. Expiry.
    if (aae.expiry > 0 && this.now() >= aae.expiry) {
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

    // 7. Consequential-action approval (invariant I-08).
    if (isConsequential(scope.sideEffectClass)) {
      // The AAE must carry an approval entry that names this tool's SVID.
      const hasApproval = aae.approvals.some((a) => a.includes(scope.toolSvid));
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
   * v1.0 STUB: in production this would proxy the call over MCP JSON-RPC to the tool server
   * identified by `scope.toolSvid`. Here it records the forward and returns a synthetic
   * acknowledgement so callers and tests can exercise the happy path end-to-end.
   *
   * @throws if `result` is not an allowed AuthorizationResult.
   */
  async forward(call: ToolCall, result: AuthorizationResult): Promise<ForwardAck> {
    if (!result.allowed || result.reason !== 'allowed') {
      throw new Error(`McpGateway.forward: refusing to forward a denied call (${result.reason})`);
    }
    this.stats.forwarded++;
    return {
      tool: call.tool,
      toolSvid: result.scope?.toolSvid ?? '',
      forwardedTo: result.scope?.toolSvid ?? '',
      args: call.args,
      // Stubbed transport: real tool server response would go here.
      stubbed: true,
    };
  }

  /** Returns counters for observability (authorized, denied, forwarded). */
  counters(): { authorized: number; denied: number; forwarded: number } {
    return { ...this.stats };
  }

  /** Internal: increments the denied counter (used by callers wrapping authorize). */
  noteDenial(): void {
    this.stats.denied++;
  }
}

/** A synthetic acknowledgement from the stubbed forward() transport. */
export interface ForwardAck {
  tool: string;
  toolSvid: string;
  forwardedTo: string;
  args: Record<string, unknown>;
  /** Always true in v1.0 — marks the response as a stub, not a real tool-server reply. */
  stubbed: true;
}
