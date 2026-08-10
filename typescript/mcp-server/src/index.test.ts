import { describe, it, expect, beforeEach } from 'vitest';
import {
  CallTool,
  ListTools,
  Server,
  TOOLS,
  SECRET_PATTERNS,
  mockScanSecrets,
  mockSignature,
  mockKey,
  configFromEnv,
  MCP_SERVER_NAME,
  MCP_SERVER_VERSION,
  MCP_PROTOCOL_VERSION,
  MCP_SUPPORTED_PROTOCOL_VERSIONS,
  type AumOSMcpConfig,
  type ExecResult,
} from './index.js';

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/** Build an explicit standalone-mode config. Production defaults to connected mode. */
function standalone(overrides: Partial<AumOSMcpConfig> = {}): AumOSMcpConfig {
  return { mode: 'standalone', ...overrides };
}

function requireDefined<T>(value: T | null | undefined, label: string): T {
  if (value === null || value === undefined) {
    throw new Error(`test invariant failed: ${label} must be defined`);
  }
  return value;
}

/** A fake fetch that emulates a connection failure for fail-closed connected-mode tests. */
function unreachableFetch(): typeof fetch {
  return async () => {
    throw new Error('ECONNREFUSED (test fake)');
  };
}

/** A fake fetch that returns a fixed JSON body for any POST. */
function fakeFetch(body: unknown, status = 200): typeof fetch {
  return async (_url: URL | RequestInfo, _init?: RequestInit) => {
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    }) as unknown as globalThis.Response & { _url?: string };
  };
}

/** A fake exec that returns canned stdout for trust-core / defstack. */
function fakeExec(stdoutByCmd: Record<string, string>): (cmd: string, args: string[]) => Promise<ExecResult> {
  return async (cmd: string) => ({
    stdout: stdoutByCmd[cmd] ?? '',
    stderr: '',
    code: stdoutByCmd[cmd] !== undefined ? 0 : 127,
  });
}

const REQUIRED_TOOL_NAMES = [
  'aumos_sign',
  'aumos_verify',
  'aumos_issue_identity',
  'aumos_verify_identity',
  'aumos_revoke_identity',
  'aumos_emit_receipt',
  'aumos_verify_receipt',
  'aumos_check_attestation',
  'aumos_run_preflight',
  'aumos_kill',
  'aumos_scan_secrets',
  'aumos_compliance_report',
  'aumos_install',
  'aumos_generate_sbom',
  'aumos_run_eval',
] as const;

// ---------------------------------------------------------------------------
// Tool catalog.
// ---------------------------------------------------------------------------

describe('tool catalog', () => {
  it('exposes exactly the 15 required tools', () => {
    expect(TOOLS).toHaveLength(15);
    const names = TOOLS.map((t) => t.name);
    for (const n of REQUIRED_TOOL_NAMES) {
      expect(names).toContain(n);
    }
  });

  it('ListTools returns the catalog under the MCP key', () => {
    const listed = ListTools();
    expect(listed.tools).toBe(TOOLS);
    expect(listed.tools.length).toBeGreaterThanOrEqual(15);
  });

  it('every tool has a JSON Schema inputSchema of type object with properties', () => {
    for (const t of TOOLS) {
      expect(t.inputSchema.type).toBe('object');
      expect(t.inputSchema.properties).toBeTypeOf('object');
      expect(Object.keys(t.inputSchema.properties).length).toBeGreaterThan(0);
      expect(t.description.length).toBeGreaterThan(10);
    }
  });
});

// ---------------------------------------------------------------------------
// T1 trust-core: sign / verify.
// ---------------------------------------------------------------------------

describe('aumos_sign / aumos_verify', () => {
  it('standalone sign returns a deterministic hex signature', async () => {
    const r = await CallTool('aumos_sign', { data: 'hello', key_id: 'k1' }, standalone());
    expect(r.isError).toBe(false);
    expect(r.data.signature_hex).toBe(mockSignature('hello', 'k1'));
    expect(r.data.algorithm).toBe('ed25519-mock');
    expect(r.data.source).toBe('mock');
  });

  it('standalone verify round-trips a mock signature', async () => {
    const sig = mockSignature('hello', 'k1');
    const key = mockKey('k1');
    const r = await CallTool('aumos_verify', { data: 'hello', signature: sig, key }, standalone());
    expect(r.data.valid).toBe(true);
  });

  it('standalone verify rejects a tampered signature', async () => {
    const key = mockKey('k1');
    const r = await CallTool('aumos_verify', { data: 'hello', signature: 'deadbeef', key }, standalone());
    expect(r.data.valid).toBe(false);
  });

  it('connected mode uses the trust-core CLI when it succeeds', async () => {
    const signingKey = '11'.repeat(32);
    const signature = 'aa'.repeat(64);
    const verifyingKey = 'bb'.repeat(32);
    let invocation: { command: string; args: string[]; stdin?: string } | undefined;
    const r = await CallTool(
      'aumos_sign',
      { data: 'hello', key: signingKey },
      {
        mode: 'connected',
        trustCoreBin: 'trust-core',
        execImpl: async (command, args, stdin) => {
          invocation = { command, args, stdin };
          return {
            stdout: `signature_hex=${signature}\nverifying_key_hex=${verifyingKey}\n`,
            stderr: '',
            code: 0,
          };
        },
      }
    );
    expect(r.isError).toBe(false);
    expect(r.data.source).toBe('trust-core');
    expect(r.data.signature_hex).toBe(signature);
    expect(r.data.verifying_key_hex).toBe(verifyingKey);
    expect(r.data.algorithm).toBe('ed25519');
    expect(invocation).toEqual({
      command: 'trust-core',
      args: ['sign', '--key', signingKey],
      stdin: 'hello',
    });
  });

  it('connected mode fails closed when the CLI is missing', async () => {
    const r = await CallTool(
      'aumos_sign',
      { data: 'hello', key: '11'.repeat(32) },
      { mode: 'connected', execImpl: fakeExec({}) }
    );
    expect(r.isError).toBe(true);
    expect(r.data.code).toBe('CONTROL_UNAVAILABLE');
    expect(r.data.dependency).toBe('trust-core');
    expect(r.data.signature_hex).toBeUndefined();
    expect(r.data.source).toBeUndefined();
  });

  it('connected sign rejects a missing real key before invoking trust-core', async () => {
    let invoked = false;
    const r = await CallTool('aumos_sign', { data: 'hello' }, {
      mode: 'connected',
      execImpl: async () => { invoked = true; return { stdout: '', stderr: '', code: 0 }; },
    });
    expect(r).toMatchObject({ isError: true, data: { code: 'INVALID_ARGUMENT' } });
    expect(invoked).toBe(false);
  });

  it('connected verify preserves a real invalid-signature result without treating it as an outage', async () => {
    const r = await CallTool(
      'aumos_verify',
      { data: 'hello', signature: 'aa'.repeat(64), key: 'bb'.repeat(32) },
      {
        mode: 'connected',
        execImpl: async (_command, _args, stdin) => ({
          stdout: 'valid=false reason=signature_did_not_verify\n',
          stderr: '',
          code: stdin === 'hello' ? 1 : 2,
        }),
      }
    );
    expect(r).toMatchObject({
      isError: false,
      data: { valid: false, source: 'trust-core', reason: 'signature_did_not_verify' },
    });
  });

  it('sign rejects empty data', async () => {
    const r = await CallTool('aumos_sign', { data: '' }, standalone());
    expect(r.isError).toBe(true);
    expect(r.data.error).toMatch(/data/);
  });
});

// ---------------------------------------------------------------------------
// I1 agent-identity.
// ---------------------------------------------------------------------------

describe('I1 agent-identity tools', () => {
  it('issue returns an SVID prefixed svid-mock- in standalone', async () => {
    const r = await CallTool(
      'aumos_issue_identity',
      { subject: 'spiffe://warrantor.dev/agent/coding-1' },
      standalone()
    );
    expect(r.isError).toBe(false);
    expect(String(r.data.svid)).toMatch(/^svid-mock-/);
    expect(r.data.capability_jti).toMatch(/^jti-/);
    expect(r.data.verifying_key).toBeTypeOf('string');
    expect(r.data.expires_at).toBeTypeOf('number');
  });

  it('issue requires a subject', async () => {
    const r = await CallTool('aumos_issue_identity', {}, standalone());
    expect(r.isError).toBe(true);
  });

  it('verify_identity round-trips an issued SVID', async () => {
    const issued = await CallTool(
      'aumos_issue_identity',
      { subject: 'spiffe://warrantor.dev/agent/coding-1' },
      standalone()
    );
    const svid = String(issued.data.svid);
    const r = await CallTool('aumos_verify_identity', { svid }, standalone());
    expect(r.data.valid).toBe(true);
    expect(r.data.subject).toBe('spiffe://warrantor.dev/agent/coding-1');
  });

  it('verify_identity rejects an unknown SVID', async () => {
    const r = await CallTool('aumos_verify_identity', { svid: 'unknown-token' }, standalone());
    expect(r.data.valid).toBe(false);
  });

  it('revoke returns revoked=true in standalone', async () => {
    const r = await CallTool('aumos_revoke_identity', { jti: 'jti-abc', reason: 'rotation' }, standalone());
    expect(r.data.revoked).toBe(true);
    expect(r.data.revoked_at).toBeTypeOf('number');
  });

  it('connected mode posts to /v1/agent-identity:issue', async () => {
    const r = await CallTool(
      'aumos_issue_identity',
      { subject: 'spiffe://warrantor.dev/agent/coding-1' },
      {
        mode: 'connected',
        agentIdentityUrl: 'http://i1:8441',
        fetchImpl: fakeFetch({ svid: 'svid-real-xyz', capability_jti: 'jti-real', verifying_key: 'pk', expires_at: 100 }),
      }
    );
    expect(r.data.source).toBe('agent-identity');
    expect(r.data.svid).toBe('svid-real-xyz');
  });

  it('connected mode fails closed on connection error', async () => {
    const r = await CallTool(
      'aumos_issue_identity',
      { subject: 'spiffe://warrantor.dev/agent/coding-1' },
      { mode: 'connected', agentIdentityUrl: 'http://i1:8441', fetchImpl: unreachableFetch() }
    );
    expect(r.isError).toBe(true);
    expect(r.data.code).toBe('CONTROL_UNAVAILABLE');
    expect(r.data.dependency).toBe('agent-identity');
    expect(String(r.data.cause)).toMatch(/ECONNREFUSED/);
    expect(r.data.svid).toBeUndefined();
    expect(r.data.source).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// E1 flight-recorder.
// ---------------------------------------------------------------------------

describe('E1 flight-recorder tools', () => {
  it('emit_receipt returns an AAR id and signature (invariant I-07)', async () => {
    const r = await CallTool(
      'aumos_emit_receipt',
      { actor: 'spiffe://warrantor.dev/agent/coding-1', tool: 'github.create_pr', outcome: 'success' },
      standalone()
    );
    expect(r.data.invariant).toBe('I-07');
    expect(String(r.data.receipt_id)).toMatch(/^aar-/);
    expect(r.data.signature).toBeTypeOf('string');
  });

  it('emit_receipt requires actor and tool', async () => {
    const r = await CallTool('aumos_emit_receipt', { actor: 'x' }, standalone());
    expect(r.isError).toBe(true);
  });

  it('verify_receipt validates an aar- prefixed id', async () => {
    const r = await CallTool('aumos_verify_receipt', { receipt_id: 'aar-123' }, standalone());
    expect(r.data.valid).toBe(true);
    expect(String(r.data.signer)).toMatch(/flight-recorder/);
  });

  it('connected emit_receipt posts to /v1/flight-recorder:emit', async () => {
    const r = await CallTool(
      'aumos_emit_receipt',
      { actor: 'a', tool: 't', outcome: 'success' },
      {
        mode: 'connected',
        flightRecorderUrl: 'http://e1:8445',
        fetchImpl: fakeFetch({ receipt_id: 'aar-real', signature: 'sig-real' }),
      }
    );
    expect(r.data.source).toBe('flight-recorder');
    expect(r.data.receipt_id).toBe('aar-real');
  });
});

// ---------------------------------------------------------------------------
// C1-1, R2, R3, R4 tools.
// ---------------------------------------------------------------------------

describe('C1-1 / R2 / R3 / R4 tools', () => {
  it('check_attestation returns a verified report', async () => {
    const r = await CallTool('aumos_check_attestation', { nonce: 'n1', gpu_pci_id: 'GPU-0' }, standalone());
    expect(r.data.verified).toBe(true);
    expect(r.data.hardware_tee).toMatch(/nvidia/);
  });

  it('run_preflight allows reads and blocks destructive by default (I-08)', async () => {
    const read = await CallTool('aumos_run_preflight', { tool: 'fs.read', side_effect: 'read' }, standalone());
    expect(read.data.allowed).toBe(true);
    const destr = await CallTool('aumos_run_preflight', { tool: 'db.drop', side_effect: 'destructive' }, standalone());
    expect(destr.data.allowed).toBe(false);
    expect(String(destr.data.reason)).toMatch(/consequential/);
  });

  it('kill returns triggered=true', async () => {
    const r = await CallTool('aumos_kill', { reason: 'behavioral_anomaly' }, standalone());
    expect(r.data.triggered).toBe(true);
    expect(r.data.reason).toBe('behavioral_anomaly');
  });

  it('kill requires a reason', async () => {
    const r = await CallTool('aumos_kill', {}, standalone());
    expect(r.isError).toBe(true);
  });

  it('scan_secrets detects common secret shapes', async () => {
    const text = 'token=ghp_abcdefghijklmnopqrstuvwxyz0123456789 and AKIAIOSFODNN7EXAMPLE';
    const r = await CallTool('aumos_scan_secrets', { text }, standalone());
    expect(r.data.count).toBeGreaterThanOrEqual(2);
    const types = (r.data.findings as { type: string }[]).map((f) => f.type);
    expect(types).toContain('github_pat');
    expect(types).toContain('aws_access_key_id');
  });

  it('scan_secrets masks the captured value', async () => {
    const text = 'key=sk_live_abcdefghijklmnopqrstuvwxyz0123456789';
    const r = await CallTool('aumos_scan_secrets', { text }, standalone());
    const findings = r.data.findings as { value: string }[];
    for (const f of findings) {
      expect(f.value).not.toContain('sk_live_abcdefghijklmnopqrstuvwxyz');
    }
  });

  it('scan_secrets returns no findings for clean text', async () => {
    const r = await CallTool('aumos_scan_secrets', { text: 'just a normal log line' }, standalone());
    expect(r.data.count).toBe(0);
  });

  it('connected scan_secrets posts to /v1/credential-vault:scan', async () => {
    const r = await CallTool(
      'aumos_scan_secrets',
      { text: 'x' },
      {
        mode: 'connected',
        credentialVaultUrl: 'http://r4:8465',
        fetchImpl: fakeFetch({ findings: [{ type: 'github_pat' }] }),
      }
    );
    expect(r.data.source).toBe('credential-vault');
    expect(r.data.findings).toEqual([{ type: 'github_pat' }]);
  });
});

// ---------------------------------------------------------------------------
// X1 defstack, S4, A1 tools.
// ---------------------------------------------------------------------------

describe('X1 / S4 / A1 tools', () => {
  it('compliance_report returns JSON in standalone', async () => {
    const r = await CallTool('aumos_compliance_report', { scope: 'soc2' }, standalone());
    expect(r.data.format).toBe('json');
    expect(r.data.report_json).toBeTypeOf('string');
  });

  it('compliance_report uses defstack in connected mode', async () => {
    const r = await CallTool(
      'aumos_compliance_report',
      { scope: 'soc2' },
      { mode: 'connected', execImpl: fakeExec({ defstack: '{"scope":"soc2","ok":true}' }) }
    );
    expect(r.data.source).toBe('defstack');
    expect(r.data.report_json).toContain('soc2');
  });

  it('install runs defstack install and returns installed=true', async () => {
    const r = await CallTool(
      'aumos_install',
      { name: 'agent-identity' },
      { mode: 'connected', execImpl: fakeExec({ defstack: 'installed agent-identity' }) }
    );
    expect(r.data.installed).toBe(true);
    expect(r.data.version).toBe('latest');
    expect(r.data.source).toBe('defstack');
  });

  it('connected install rejects unsupported version pinning instead of claiming success', async () => {
    const r = await CallTool(
      'aumos_install',
      { name: 'agent-identity', version: '1.0.0' },
      { mode: 'connected', execImpl: fakeExec({ defstack: 'not invoked' }) }
    );
    expect(r).toMatchObject({ isError: true, data: { code: 'INVALID_ARGUMENT' } });
    expect(r.data.installed).toBeUndefined();
  });

  it('install fails closed when defstack is missing', async () => {
    const r = await CallTool(
      'aumos_install',
      { name: 'flight-recorder' },
      { mode: 'connected', execImpl: fakeExec({}) }
    );
    expect(r.isError).toBe(true);
    expect(r.data.code).toBe('CONTROL_UNAVAILABLE');
    expect(r.data.dependency).toBe('defstack');
    expect(r.data.installed).toBeUndefined();
    expect(r.data.source).toBeUndefined();
  });

  it('generate_sbom returns a CycloneDX bom', async () => {
    const r = await CallTool('aumos_generate_sbom', { model: 'llama-3-8b' }, standalone());
    expect((r.data.sbom as { bomFormat: string }).bomFormat).toBe('CycloneDX');
    expect(r.data.format).toBe('cyclonedx');
  });

  it('run_eval returns results + VEB', async () => {
    const r = await CallTool('aumos_run_eval', { model: 'model://aumos-7b' }, standalone());
    expect((r.data.results as { accuracy: number }).accuracy).toBeTypeOf('number');
    expect(String((r.data.veb as { bundleId: string }).bundleId)).toMatch(/^veb-/);
  });

  it('unknown tool returns an error result (not a crash)', async () => {
    const r = await CallTool('aumos_nonexistent', {}, standalone());
    expect(r.isError).toBe(true);
    expect(String(r.data.error)).toMatch(/unknown tool/);
    expect(r.data.available as string[]).toContain('aumos_sign');
  });
});

// ---------------------------------------------------------------------------
// Connected-mode dependency boundary: never manufacture a security outcome.
// ---------------------------------------------------------------------------

interface HttpDependencyCase {
  tool: string;
  args: Record<string, unknown>;
  dependency: string;
  forbiddenFields: string[];
}

const HTTP_DEPENDENCY_CASES: HttpDependencyCase[] = [
  {
    tool: 'aumos_issue_identity',
    args: { subject: 'spiffe://warrantor.dev/agent/test' },
    dependency: 'agent-identity',
    forbiddenFields: ['svid', 'capability_jti'],
  },
  {
    tool: 'aumos_verify_identity',
    args: { svid: 'svid-real' },
    dependency: 'agent-identity',
    forbiddenFields: ['valid'],
  },
  {
    tool: 'aumos_revoke_identity',
    args: { jti: 'jti-real' },
    dependency: 'agent-identity',
    forbiddenFields: ['revoked'],
  },
  {
    tool: 'aumos_emit_receipt',
    args: { actor: 'spiffe://warrantor.dev/agent/test', tool: 'fs.read' },
    dependency: 'flight-recorder',
    forbiddenFields: ['receipt_id', 'signature'],
  },
  {
    tool: 'aumos_verify_receipt',
    args: { receipt_id: 'aar-real' },
    dependency: 'flight-recorder',
    forbiddenFields: ['valid'],
  },
  {
    tool: 'aumos_check_attestation',
    args: { nonce: 'nonce-1' },
    dependency: 'nvtrust-bridge',
    forbiddenFields: ['verified'],
  },
  {
    tool: 'aumos_run_preflight',
    args: { tool: 'fs.read' },
    dependency: 'eval-guard',
    forbiddenFields: ['allowed'],
  },
  {
    tool: 'aumos_kill',
    args: { reason: 'incident' },
    dependency: 'kill-switch',
    forbiddenFields: ['triggered', 'killed_at'],
  },
  {
    tool: 'aumos_scan_secrets',
    args: { text: 'secret text' },
    dependency: 'credential-vault',
    forbiddenFields: ['findings', 'count'],
  },
  {
    tool: 'aumos_generate_sbom',
    args: { model: 'model://test' },
    dependency: 'model-sbom',
    forbiddenFields: ['sbom'],
  },
  {
    tool: 'aumos_run_eval',
    args: { model: 'model://test' },
    dependency: 'safe-eval',
    forbiddenFields: ['results', 'summary', 'veb'],
  },
];

describe('connected-mode fail-closed boundary', () => {
  it.each(HTTP_DEPENDENCY_CASES)(
    '$tool returns CONTROL_UNAVAILABLE when $dependency is unreachable',
    async ({ tool, args, dependency, forbiddenFields }) => {
      const result = await CallTool(tool, args, { mode: 'connected', fetchImpl: unreachableFetch() });
      expect(result).toMatchObject({
        isError: true,
        data: { code: 'CONTROL_UNAVAILABLE', dependency, retryable: true },
      });
      expect(result.data.source).toBeUndefined();
      expect(result.data.degraded).toBeUndefined();
      for (const field of forbiddenFields) expect(result.data[field]).toBeUndefined();
    }
  );

  it.each(HTTP_DEPENDENCY_CASES)(
    '$tool rejects a success-status response missing required $dependency fields',
    async ({ tool, args, dependency, forbiddenFields }) => {
      const result = await CallTool(tool, args, { mode: 'connected', fetchImpl: fakeFetch({}) });
      expect(result).toMatchObject({
        isError: true,
        data: { code: 'CONTROL_RESPONSE_INVALID', dependency, retryable: false },
      });
      expect(result.data.source).toBeUndefined();
      for (const field of forbiddenFields) expect(result.data[field]).toBeUndefined();
    }
  );

  it.each([
    {
      tool: 'aumos_sign',
      args: { data: 'hello', key: '11'.repeat(32) },
      dependency: 'trust-core',
      forbiddenFields: ['signature_hex'],
    },
    {
      tool: 'aumos_verify',
      args: { data: 'hello', signature: 'aa'.repeat(64), key: 'bb'.repeat(32) },
      dependency: 'trust-core',
      forbiddenFields: ['valid'],
    },
    {
      tool: 'aumos_compliance_report',
      args: { scope: 'soc2' },
      dependency: 'defstack',
      forbiddenFields: ['report_json'],
    },
    {
      tool: 'aumos_install',
      args: { name: 'flight-recorder' },
      dependency: 'defstack',
      forbiddenFields: ['installed'],
    },
  ])('$tool returns CONTROL_UNAVAILABLE when $dependency exits unsuccessfully', async (testCase) => {
    const result = await CallTool(testCase.tool, testCase.args, {
      mode: 'connected',
      execImpl: fakeExec({}),
    });
    expect(result).toMatchObject({
      isError: true,
      data: { code: 'CONTROL_UNAVAILABLE', dependency: testCase.dependency },
    });
    expect(result.data.source).toBeUndefined();
    for (const field of testCase.forbiddenFields) expect(result.data[field]).toBeUndefined();
  });
});

describe('mode selection', () => {
  it('defaults to connected mode so demo behavior requires explicit opt-in', () => {
    expect(configFromEnv({}, [])).toMatchObject({ mode: 'connected' });
  });

  it('accepts explicit standalone mode from either CLI or environment', () => {
    expect(configFromEnv({}, ['--standalone']).mode).toBe('standalone');
    expect(configFromEnv({ AUMOS_MODE: 'standalone' }, []).mode).toBe('standalone');
  });

  it('rejects ambiguous or invalid mode selection', () => {
    expect(() => configFromEnv({}, ['--standalone', '--connected'])).toThrow(/exactly one/);
    expect(() => configFromEnv({ AUMOS_MODE: 'demo' }, [])).toThrow(/AUMOS_MODE/);
  });
});

// ---------------------------------------------------------------------------
// Secret scanner internals.
// ---------------------------------------------------------------------------

describe('SECRET_PATTERNS', () => {
  it('does not use unsupported (?i) inline flags', () => {
    for (const p of SECRET_PATTERNS) {
      expect(p.re.source).not.toContain('(?i)');
    }
  });

  it('detects a private key block', () => {
    const text = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAI...\n-----END RSA PRIVATE KEY-----';
    const f = mockScanSecrets(text);
    expect(f.some((x) => x.type === 'private_key_block')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// MCP server dispatch.
// ---------------------------------------------------------------------------

describe('Server (JSON-RPC dispatch)', () => {
  let server: Server;
  beforeEach(() => {
    server = new Server({ mode: 'standalone' });
  });

  function modernParams(fields: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      ...fields,
      _meta: {
        'io.modelcontextprotocol/protocolVersion': MCP_PROTOCOL_VERSION,
        'io.modelcontextprotocol/clientInfo': { name: 'aumos-test-client', version: '1.0.0' },
        'io.modelcontextprotocol/clientCapabilities': {},
      },
    };
  }

  it('implements modern stateless server/discover', async () => {
    const line = await server.handle({
      jsonrpc: '2.0',
      id: 1,
      method: 'server/discover',
      params: modernParams(),
    });
    const res = JSON.parse(requireDefined(line, 'discover response'));
    expect(res.id).toBe(1);
    expect(res.result.resultType).toBe('complete');
    expect(res.result.supportedVersions).toEqual(MCP_SUPPORTED_PROTOCOL_VERSIONS);
    expect(res.result._meta['io.modelcontextprotocol/serverInfo']).toEqual({
      name: MCP_SERVER_NAME,
      version: MCP_SERVER_VERSION,
    });
    expect(res.result.capabilities.tools).toBeDefined();
    expect(server.isInitialized()).toBe(true);
  });

  it('responds to a modern tools/list with result and cache metadata', async () => {
    const line = await server.handle({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/list',
      params: modernParams(),
    });
    const res = JSON.parse(requireDefined(line, 'tools/list response'));
    expect(res.result.resultType).toBe('complete');
    expect(res.result.ttlMs).toBeGreaterThan(0);
    expect(res.result.cacheScope).toBe('public');
    expect(res.result.tools).toHaveLength(15);
    expect(res.result.tools[0].name).toBe('aumos_sign');
  });

  it('dispatches tools/call and returns structured content', async () => {
    const line = await server.handle({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: modernParams({ name: 'aumos_kill', arguments: { reason: 'test' } }),
    });
    const res = JSON.parse(requireDefined(line, 'tools/call response'));
    expect(res.result.resultType).toBe('complete');
    expect(res.result.isError).toBe(false);
    expect(res.result.structuredContent.triggered).toBe(true);
    expect(res.result.content[0].type).toBe('text');
  });

  it('returns METHOD_NOT_FOUND for unknown methods', async () => {
    const line = await server.handle({
      jsonrpc: '2.0',
      id: 4,
      method: 'no/such',
      params: modernParams(),
    });
    const res = JSON.parse(requireDefined(line, 'unknown-method response'));
    expect(res.error.code).toBe(-32601);
    expect(res.error.message).toMatch(/method not found/);
  });

  it('returns INVALID_PARAMS when tools/call has no name', async () => {
    const line = await server.handle({
      jsonrpc: '2.0',
      id: 5,
      method: 'tools/call',
      params: modernParams({ arguments: {} }),
    });
    const res = JSON.parse(requireDefined(line, 'invalid-params response'));
    expect(res.error.code).toBe(-32602);
  });

  it('modern notifications (no id) validate metadata and return no response', async () => {
    const line = await server.handle({
      jsonrpc: '2.0',
      method: 'notifications/cancelled',
      params: modernParams({ requestId: 99, reason: 'test' }),
    });
    expect(line).toBeNull();
  });

  it('modern ping returns a typed complete result', async () => {
    const line = await server.handle({
      jsonrpc: '2.0',
      id: 6,
      method: 'ping',
      params: modernParams(),
    });
    const res = JSON.parse(requireDefined(line, 'ping response'));
    expect(res.result).toEqual({ resultType: 'complete' });
  });

  it('rejects missing modern metadata before any legacy handshake', async () => {
    const line = await server.handle({ jsonrpc: '2.0', id: 7, method: 'tools/list', params: {} });
    const res = JSON.parse(requireDefined(line, 'missing-metadata response'));
    expect(res.error.code).toBe(-32002);
    expect(res.error.data.supported).toEqual(MCP_SUPPORTED_PROTOCOL_VERSIONS);
  });

  it('returns the standard unsupported-version error with supported versions', async () => {
    const params = modernParams();
    const meta = params._meta as Record<string, unknown>;
    meta['io.modelcontextprotocol/protocolVersion'] = '1900-01-01';
    const line = await server.handle({ jsonrpc: '2.0', id: 8, method: 'tools/list', params });
    const res = JSON.parse(requireDefined(line, 'unsupported-version response'));
    expect(res.error).toMatchObject({
      code: -32022,
      data: { requested: '1900-01-01', supported: MCP_SUPPORTED_PROTOCOL_VERSIONS },
    });
  });

  it('retains an explicit legacy initialize path for handshake-era clients', async () => {
    const initialized = await server.handle({
      jsonrpc: '2.0',
      id: 9,
      method: 'initialize',
      params: {
        protocolVersion: '2025-11-25',
        capabilities: {},
        clientInfo: { name: 'legacy-test', version: '1.0.0' },
      },
    });
    const initializeResponse = JSON.parse(requireDefined(initialized, 'legacy initialize response'));
    expect(initializeResponse.result.protocolVersion).toBe('2025-11-25');
    expect(server.isInitialized()).toBe(true);

    const listed = await server.handle({ jsonrpc: '2.0', id: 10, method: 'tools/list', params: {} });
    const listResponse = JSON.parse(requireDefined(listed, 'legacy tools/list response'));
    expect(listResponse.result.tools).toHaveLength(15);
    expect(listResponse.result.resultType).toBeUndefined();
  });

  it('rejects modern initialize and points clients to supported stateless versions', async () => {
    const line = await server.handle({
      jsonrpc: '2.0',
      id: 11,
      method: 'initialize',
      params: modernParams(),
    });
    const res = JSON.parse(requireDefined(line, 'modern initialize response'));
    expect(res.error.code).toBe(-32601);
    expect(res.error.data.supported).toEqual(MCP_SUPPORTED_PROTOCOL_VERSIONS);
  });

  it('rejects a non-object tools/call arguments value', async () => {
    const line = await server.handle({
      jsonrpc: '2.0',
      id: 12,
      method: 'tools/call',
      params: modernParams({ name: 'aumos_kill', arguments: 'not-an-object' }),
    });
    const res = JSON.parse(requireDefined(line, 'invalid arguments response'));
    expect(res.error.code).toBe(-32602);
  });

  it('counts requests/calls/errors in stats', async () => {
    await server.handle({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: modernParams() });
    await server.handle({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: modernParams({ name: 'aumos_kill', arguments: { reason: 'x' } }),
    });
    await server.handle({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: modernParams({ name: 'aumos_unknown', arguments: {} }),
    });
    expect(server.stats.requests).toBe(3);
    expect(server.stats.calls).toBe(2);
    expect(server.stats.errors).toBe(1);
  });
});
