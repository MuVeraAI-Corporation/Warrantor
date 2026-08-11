import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import {
  McpGateway,
  McpHttpTransport,
  GatewayForwardError,
  MCP_PROTOCOL_VERSION,
  ToolRegistry,
  isConsequential,
  type AgentAuthorityEnvelope,
  type ToolCall,
  type RegisteredTool,
  type ForwardRequest,
  type ToolTransport,
  type TrustBundleEntry,
} from './index.js';

const GATEWAY = 'spiffe://muveraai.com/mcp-gateway/default';
const ISSUER = 'spiffe://muveraai.com/agent-identity';
const KEY_ID = 'urn:aumos:key:test-issuer-1';

// A real Ed25519 keypair. AX-02: envelopes must be signed by a key the gateway
// trusts, so the tests now mint genuine signatures instead of asserting policy
// over an envelope whose authenticity was simply assumed.
const { publicKey: ISSUER_PUB, privateKey: ISSUER_PRIV } = generateKeyPairSync('ed25519');
const ISSUER_PUB_HEX = ISSUER_PUB.export({ format: 'der', type: 'spki' })
  .subarray(12)
  .toString('hex');

const TRUST_BUNDLE: TrustBundleEntry[] = [
  { keyId: KEY_ID, issuer: ISSUER, publicKeyHex: ISSUER_PUB_HEX },
];

/** Sign an envelope with the trusted test key, exactly as a real issuer would. */
function signed(aae: AgentAuthorityEnvelope): AgentAuthorityEnvelope {
  const value = cryptoSign(null, McpGateway.canonicalEnvelopeBytes(aae), ISSUER_PRIV).toString('hex');
  return { ...aae, signature: { algorithm: 'Ed25519', keyId: KEY_ID, value } };
}

// A small registry covering read / write / financial tool classes.
function freshRegistry(): ToolRegistry {
  return new ToolRegistry().registerAll([
    {
      name: 'fs.read',
      scope: { toolSvid: 'spiffe://muveraai.com/tools/fs-read', sideEffectClass: 'read' },
    },
    {
      name: 'github.create_pr',
      scope: { toolSvid: 'spiffe://muveraai.com/tools/github', sideEffectClass: 'write' },
    },
    {
      name: 'payment.send',
      scope: { toolSvid: 'spiffe://muveraai.com/tools/payment', sideEffectClass: 'financial' },
    },
    {
      name: 'db.drop_table',
      scope: { toolSvid: 'spiffe://muveraai.com/tools/db-destr', sideEffectClass: 'destructive' },
    },
  ] satisfies RegisteredTool[]);
}

// AAE builder. Defaults grant the read/write tools to the gateway for the agent subject.
function sampleAae(overrides: Partial<AgentAuthorityEnvelope> = {}): AgentAuthorityEnvelope {
  const base: AgentAuthorityEnvelope = {
    issuer: 'spiffe://muveraai.com/agent-identity',
    subject: 'spiffe://muveraai.com/agent/coding-1',
    purpose: 'open a pull request',
    resources: [GATEWAY],
    tools: [
      'spiffe://muveraai.com/tools/fs-read',
      'spiffe://muveraai.com/tools/github',
    ],
    dataClasses: ['L0', 'L1'],
    sideEffectClass: 'write',
    spendBudget: 0,
    timeBudgetSeconds: 3600,
    tokenBudget: 100000,
    geography: '',
    delegationDepth: 0,
    approvals: [],
    // AX-02: `expiry: 0` used to disable the expiry check entirely. It is now
    // rejected as invalid, so fixtures carry a real far-future expiry.
    expiry: 4_102_444_800, // 2100-01-01
    revocationHandle: 'rh-1',
    signature: { algorithm: 'Ed25519', keyId: KEY_ID, value: '0'.repeat(128) },
    ...overrides,
  };
  return signed(base);
}

function call(tool: string, caller = 'spiffe://muveraai.com/agent/coding-1'): ToolCall {
  return { tool, args: {}, callerSvid: caller };
}

function successfulTransport(response: unknown = { content: [{ type: 'text', text: 'ok' }] }): ToolTransport {
  return { call: async () => response };
}

function gateway(now?: () => number, transport: ToolTransport = successfulTransport()): McpGateway {
  return new McpGateway({
    gatewaySvid: GATEWAY,
    registry: freshRegistry(),
    transport,
    now,
    trustBundle: TRUST_BUNDLE,
    approvers: ['spiffe://muveraai.com/human/alice', 'spiffe://muveraai.com/human/bob'],
  });
}

describe('ToolRegistry', () => {
  it('looks up registered tools and reports unknowns', () => {
    const r = freshRegistry();
    expect(r.has('fs.read')).toBe(true);
    expect(r.lookup('fs.read')?.scope.toolSvid).toBe('spiffe://muveraai.com/tools/fs-read');
    expect(r.has('does.not.exist')).toBe(false);
    expect(r.lookup('nope')).toBeUndefined();
  });

  it('supports unregister and size', () => {
    const r = freshRegistry();
    expect(r.size).toBe(4);
    expect(r.unregister('fs.read')).toBe(true);
    expect(r.size).toBe(3);
    expect(r.unregister('missing')).toBe(false);
  });

  it('lists names sorted', () => {
    const r = new ToolRegistry().registerAll([
      { name: 'zeta', scope: { toolSvid: 't1', sideEffectClass: 'read' } },
      { name: 'alpha', scope: { toolSvid: 't2', sideEffectClass: 'read' } },
    ]);
    expect(r.names()).toEqual(['alpha', 'zeta']);
  });
});

describe('McpGateway.authorize — happy path', () => {
  it('allows when the AAE covers the requested tool', () => {
    const g = gateway();
    const r = g.authorize(call('fs.read'), sampleAae());
    expect(r.allowed).toBe(true);
    expect(r.reason).toBe('allowed');
    expect(r.scope?.toolSvid).toBe('spiffe://muveraai.com/tools/fs-read');
  });

  it('allows a write tool when side-effect class is sufficient', () => {
    const g = gateway();
    const r = g.authorize(call('github.create_pr'), sampleAae({ sideEffectClass: 'write' }));
    expect(r.allowed).toBe(true);
  });
});

describe('McpGateway.authorize — denials', () => {
  it('denies an unregistered tool', () => {
    const g = gateway();
    const r = g.authorize(call('not.a.tool'), sampleAae());
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('unknown_tool');
  });

  it('denies when the tool is missing from the AAE tools list (confused-deputy)', () => {
    const g = gateway();
    // payment tool is registered but NOT in the default AAE tools list.
    const r = g.authorize(call('payment.send'), sampleAae());
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('tool_not_in_aae');
    expect(r.detail).toMatch(/confused-deputy/);
  });

  it('denies on audience mismatch (AAE not issued for this gateway)', () => {
    const g = gateway();
    const aae = sampleAae({ resources: ['spiffe://muveraai.com/some-other-gateway'] });
    const r = g.authorize(call('fs.read'), aae);
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('audience_mismatch');
  });

  it('denies an expired AAE', () => {
    const g = gateway(() => 10_000);
    const aae = sampleAae({ expiry: 5_000 });
    const r = g.authorize(call('fs.read'), aae);
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('expired');
  });

  // AX-02 regression. This test previously asserted the defect: `expiry: 0` was
  // treated as "unbounded", so an attacker-set 0 disabled expiry entirely and most
  // of this suite ran with the control switched off. A non-positive expiry is not
  // an unlimited grant -- it is a malformed envelope.
  it('rejects a non-positive expiry instead of treating it as unbounded', () => {
    const g = gateway(() => 9_999_999);
    for (const expiry of [0, -1]) {
      const r = g.authorize(call('fs.read'), sampleAae({ expiry }));
      expect(r.allowed).toBe(false);
      if (!r.allowed) expect(r.reason).toBe('expired');
    }
  });

  it('denies when caller SVID does not match AAE subject', () => {
    const g = gateway();
    const r = g.authorize(
      call('fs.read', 'spiffe://muveraai.com/agent/impostor'),
      sampleAae()
    );
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('subject_mismatch');
  });
});

describe('McpGateway.authorize — side-effect-class enforcement', () => {
  it('denies a write tool when AAE only permits read', () => {
    const g = gateway();
    const aae = sampleAae({ sideEffectClass: 'read' });
    const r = g.authorize(call('github.create_pr'), aae);
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('side_effect_class_insufficient');
  });

  it('allows a read tool when AAE permits a higher class (escalation ladder)', () => {
    const g = gateway();
    const aae = sampleAae({ sideEffectClass: 'financial' });
    // fs.read is read-class; financial >= read so allowed.
    expect(g.authorize(call('fs.read'), aae).allowed).toBe(true);
    // github.create_pr is write-class; financial >= write so allowed.
    expect(g.authorize(call('github.create_pr'), aae).allowed).toBe(true);
  });

  it('requires an approval entry for consequential tools (invariant I-08)', () => {
    const g = gateway();
    const aae = sampleAae({
      sideEffectClass: 'financial',
      tools: ['spiffe://muveraai.com/tools/payment'],
    });
    // No approval entry → denied even though scope is otherwise sufficient.
    const denied = g.authorize(call('payment.send'), aae);
    expect(denied.allowed).toBe(false);
    expect(denied.reason).toBe('consequential_approval_missing');

    // With an approval entry naming the tool SVID → allowed.
    const ok = g.authorize(
      call('payment.send'),
      sampleAae({
        sideEffectClass: 'financial',
        tools: ['spiffe://muveraai.com/tools/payment'],
        approvals: ['spiffe://muveraai.com/human/alice'],
      })
    );
    expect(ok.allowed).toBe(true);
  });

  it('requires approval for destructive tools and respects class rank', () => {
    const g = gateway();
    // financial AAE is rank 2 < destructive rank 3 → denied on class grounds first.
    const aaeFinancial = sampleAae({
      sideEffectClass: 'financial',
      tools: ['spiffe://muveraai.com/tools/db-destr'],
      approvals: ['spiffe://muveraai.com/human/alice'],
    });
    const r1 = g.authorize(call('db.drop_table'), aaeFinancial);
    expect(r1.allowed).toBe(false);
    expect(r1.reason).toBe('side_effect_class_insufficient');

    // destructive AAE without approval → approval-missing denial.
    const aaeDestructive = sampleAae({
      sideEffectClass: 'destructive',
      tools: ['spiffe://muveraai.com/tools/db-destr'],
      approvals: [],
    });
    const r2 = g.authorize(call('db.drop_table'), aaeDestructive);
    expect(r2.allowed).toBe(false);
    expect(r2.reason).toBe('consequential_approval_missing');

    // destructive AAE with approval → allowed.
    const aaeOk = sampleAae({
      sideEffectClass: 'destructive',
      tools: ['spiffe://muveraai.com/tools/db-destr'],
      approvals: ['spiffe://muveraai.com/human/alice'],
    });
    expect(g.authorize(call('db.drop_table'), aaeOk).allowed).toBe(true);
  });
});

describe('isConsequential', () => {
  it('marks financial/destructive/physical consequential; read/write not', () => {
    expect(isConsequential('read')).toBe(false);
    expect(isConsequential('write')).toBe(false);
    expect(isConsequential('financial')).toBe(true);
    expect(isConsequential('destructive')).toBe(true);
    expect(isConsequential('physical')).toBe(true);
  });
});

describe('McpGateway.forward', () => {
  it('passes an authorized call to the injected transport and returns its real response', async () => {
    const requests: ForwardRequest[] = [];
    const response = { content: [{ type: 'text', text: 'real tool result' }] };
    const g = gateway(undefined, {
      call: async (request) => {
        requests.push(request);
        return response;
      },
    });
    const c = call('fs.read');
    const r = g.authorize(c, sampleAae());
    await expect(g.forward(c, r)).resolves.toBe(response);
    expect(requests).toEqual([
      {
        call: c,
        scope: { toolSvid: 'spiffe://muveraai.com/tools/fs-read', sideEffectClass: 'read' },
        gatewaySvid: GATEWAY,
      },
    ]);
    expect(g.counters().forwarded).toBe(1);
    expect(g.counters().failed).toBe(0);
  });

  it('refuses a denied call without invoking the transport', async () => {
    let calls = 0;
    const g = gateway(undefined, { call: async () => { calls++; return {}; } });
    const r = g.authorize(call('not.a.tool'), sampleAae());
    expect(r.allowed).toBe(false);
    await expect(g.forward(call('not.a.tool'), r)).rejects.toMatchObject({
      code: 'authorization_denied',
      retryable: false,
    });
    expect(calls).toBe(0);
    expect(g.counters().failed).toBe(1);
  });

  it('propagates typed transport failures and never counts them as forwarded', async () => {
    const failure = new GatewayForwardError('transport_timeout', 'timed out', { retryable: true });
    const g = gateway(undefined, { call: async () => { throw failure; } });
    const c = call('fs.read');
    const r = g.authorize(c, sampleAae());
    await expect(g.forward(c, r)).rejects.toBe(failure);
    expect(g.counters()).toMatchObject({ forwarded: 0, failed: 1 });
  });

  it('wraps unknown dependency failures in the stable transport error contract', async () => {
    const g = gateway(undefined, { call: async () => { throw new Error('socket closed'); } });
    const c = call('fs.read');
    const r = g.authorize(c, sampleAae());
    await expect(g.forward(c, r)).rejects.toMatchObject({
      code: 'transport_unavailable',
      retryable: true,
    });
  });

  it('increments authorized counter on allow', () => {
    const g = gateway();
    g.authorize(call('fs.read'), sampleAae());
    g.authorize(call('fs.read'), sampleAae());
    expect(g.counters().authorized).toBe(2);
  });
});

describe('McpHttpTransport', () => {
  const request: ForwardRequest = {
    call: call('fs.read'),
    scope: { toolSvid: 'spiffe://muveraai.com/tools/fs-read', sideEffectClass: 'read' },
    gatewaySvid: GATEWAY,
  };

  it('sends a current MCP tools/call request and returns a validated JSON result', async () => {
    let capturedUrl = '';
    let capturedInit: RequestInit | undefined;
    const transport = new McpHttpTransport({
      resolveEndpoint: () => 'https://tools.muveraai.com/mcp',
      requestId: () => 'request-1',
      fetchImpl: async (url, init) => {
        capturedUrl = String(url);
        capturedInit = init;
        return new Response(
          JSON.stringify({ jsonrpc: '2.0', id: 'request-1', result: { accepted: true } }),
          { status: 200, headers: { 'content-type': 'application/json; charset=utf-8' } }
        );
      },
    });

    await expect(transport.call(request)).resolves.toEqual({ accepted: true });
    expect(capturedUrl).toBe('https://tools.muveraai.com/mcp');
    const headers = new Headers(capturedInit?.headers);
    expect(headers.get('accept')).toBe('application/json, text/event-stream');
    expect(headers.get('mcp-protocol-version')).toBe(MCP_PROTOCOL_VERSION);
    expect(headers.get('mcp-method')).toBe('tools/call');
    expect(headers.get('mcp-name')).toBe('fs.read');
    const parsedBody = JSON.parse(String(capturedInit?.body)) as Record<string, unknown>;
    expect(parsedBody).toMatchObject({ jsonrpc: '2.0', id: 'request-1', method: 'tools/call' });
    expect(parsedBody.params).toMatchObject({
      name: 'fs.read',
      arguments: {},
      _meta: {
        'io.modelcontextprotocol/protocolVersion': MCP_PROTOCOL_VERSION,
        'io.modelcontextprotocol/clientCapabilities': {},
        'com.muveraai/gatewaySvid': GATEWAY,
        'com.muveraai/callerSvid': request.call.callerSvid,
      },
    });
  });

  it('extracts the matching response from an MCP event stream', async () => {
    const transport = new McpHttpTransport({
      resolveEndpoint: () => 'http://localhost:9000/mcp',
      requestId: () => 7,
      fetchImpl: async () => new Response(
        'event: message\ndata: {"jsonrpc":"2.0","method":"notifications/progress"}\n\n' +
          'event: message\ndata: {"jsonrpc":"2.0","id":7,"result":{"done":true}}\n\n',
        { status: 200, headers: { 'content-type': 'text/event-stream' } }
      ),
    });
    await expect(transport.call(request)).resolves.toEqual({ done: true });
  });

  it('turns JSON-RPC errors into typed remote failures without exposing synthetic success', async () => {
    const transport = new McpHttpTransport({
      resolveEndpoint: () => 'https://tools.muveraai.com/mcp',
      requestId: () => 8,
      fetchImpl: async () => new Response(
        JSON.stringify({ jsonrpc: '2.0', id: 8, error: { code: -32001, message: 'policy denied' } }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      ),
    });
    await expect(transport.call(request)).rejects.toMatchObject({
      code: 'remote_error',
      details: { remoteCode: -32001, tool: 'fs.read' },
    });
  });

  it.each([
    ['mismatched response id', new Response('{"jsonrpc":"2.0","id":99,"result":{}}', { headers: { 'content-type': 'application/json' } }), 'invalid_response'],
    ['unsupported response media type', new Response('ok', { headers: { 'content-type': 'text/plain' } }), 'unsupported_content_type'],
    ['HTTP failure', new Response('unavailable', { status: 503, headers: { 'content-type': 'text/plain' } }), 'http_error'],
  ] as const)('fails closed on %s', async (_label, response, expectedCode) => {
    const transport = new McpHttpTransport({
      resolveEndpoint: () => 'https://tools.muveraai.com/mcp',
      requestId: () => 1,
      fetchImpl: async () => response,
    });
    await expect(transport.call(request)).rejects.toMatchObject({ code: expectedCode });
  });

  it('aborts and reports a typed timeout', async () => {
    const transport = new McpHttpTransport({
      resolveEndpoint: () => 'https://tools.muveraai.com/mcp',
      timeoutMs: 5,
      fetchImpl: async (_url, init) => new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
      }),
    });
    await expect(transport.call(request)).rejects.toMatchObject({
      code: 'transport_timeout',
      retryable: true,
    });
  });

  it('rejects cleartext remote endpoints before fetch', async () => {
    let called = false;
    const transport = new McpHttpTransport({
      resolveEndpoint: () => 'http://tools.example/mcp',
      fetchImpl: async () => { called = true; return new Response(); },
    });
    await expect(transport.call(request)).rejects.toMatchObject({ code: 'transport_unavailable' });
    expect(called).toBe(false);
  });
});

describe('McpGateway — confused-deputy end-to-end', () => {
  it('blocks an agent that tries to invoke a tool not in its own AAE', () => {
    const g = gateway();
    // Attacker has an AAE for github only but tries payment.send (registered tool).
    const attackerAae = sampleAae({
      sideEffectClass: 'financial',
      tools: ['spiffe://muveraai.com/tools/github'],
      approvals: ['spiffe://muveraai.com/human/alice'],
    });
    const r = g.authorize(call('payment.send'), attackerAae);
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('tool_not_in_aae');
  });
});

describe('McpGateway constructor validation', () => {
  it('rejects a missing gatewaySvid', () => {
    expect(
      () => new McpGateway({ gatewaySvid: '', registry: freshRegistry(), transport: successfulTransport() })
    ).toThrow(/gatewaySvid/);
  });

  it('rejects a missing registry', () => {
    expect(
      () => new McpGateway({
        gatewaySvid: GATEWAY,
        registry: undefined as unknown as ToolRegistry,
        transport: successfulTransport(),
      })
    ).toThrow(/registry/);
  });

  it('rejects a missing transport instead of permitting fabricated forwarding', () => {
    expect(
      () => new McpGateway({
        gatewaySvid: GATEWAY,
        registry: freshRegistry(),
        transport: undefined as unknown as ToolTransport,
      })
    ).toThrow(/transport/);
  });
});
