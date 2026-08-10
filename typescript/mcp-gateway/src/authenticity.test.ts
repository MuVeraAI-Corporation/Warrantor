/**
 * AX-02 regression suite — envelope authenticity and the constraints that were
 * declared, typed, documented, and never read.
 *
 * Before this fix `authorize()` took the AAE as a plain caller-supplied object with
 * no signature field at all: no Ed25519 verification, no issuer trust check, no
 * revocation check. A fabricated envelope claiming
 * `issuer: "spiffe://evil.example/i-made-this-up"` authorised a `destructive`-class
 * tool call, which was then forwarded. Separately, `expiry: 0` disabled the expiry
 * check, and the I-08 approval check was a substring match of an *approver* string
 * against the *tool's* SVID.
 */
import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import {
  McpGateway,
  ToolRegistry,
  type AgentAuthorityEnvelope,
  type ForwardRequest,
  type ToolCall,
  type ToolTransport,
  type TrustBundleEntry,
} from './index.js';

const GATEWAY = 'spiffe://muveraai.com/mcp-gateway/default';
const ISSUER = 'spiffe://muveraai.com/agent-identity';
const KEY_ID = 'urn:aumos:key:test-issuer-1';
const AGENT = 'spiffe://muveraai.com/agent/coding-1';

const { publicKey: PUB, privateKey: PRIV } = generateKeyPairSync('ed25519');
const PUB_HEX = PUB.export({ format: 'der', type: 'spki' }).subarray(12).toString('hex');
const TRUST_BUNDLE: TrustBundleEntry[] = [
  { keyId: KEY_ID, issuer: ISSUER, publicKeyHex: PUB_HEX },
];

function sign(aae: AgentAuthorityEnvelope): AgentAuthorityEnvelope {
  const value = cryptoSign(null, McpGateway.canonicalEnvelopeBytes(aae), PRIV).toString('hex');
  return { ...aae, signature: { algorithm: 'Ed25519', keyId: KEY_ID, value } };
}

function baseAae(overrides: Partial<AgentAuthorityEnvelope> = {}): AgentAuthorityEnvelope {
  const draft: AgentAuthorityEnvelope = {
    issuer: ISSUER,
    subject: AGENT,
    purpose: 'read a file',
    resources: [GATEWAY],
    tools: ['spiffe://muveraai.com/tools/fs-read'],
    dataClasses: ['L0', 'L1'],
    sideEffectClass: 'write',
    spendBudget: 1000,
    timeBudgetSeconds: 3600,
    tokenBudget: 100000,
    geography: '',
    delegationDepth: 0,
    approvals: [],
    expiry: 4_102_444_800, // 2100-01-01
    revocationHandle: 'rh-1',
    signature: { algorithm: 'Ed25519', keyId: KEY_ID, value: '0'.repeat(128) },
    ...overrides,
  };
  return sign(draft);
}

function transport(): ToolTransport {
  return {
    async call(_req: ForwardRequest) {
      return { ok: true };
    },
  };
}

function registry(): ToolRegistry {
  return new ToolRegistry().registerAll([
    { name: 'fs.read', scope: { toolSvid: 'spiffe://muveraai.com/tools/fs-read', sideEffectClass: 'read' } },
    { name: 'db.destroy', scope: { toolSvid: 'spiffe://muveraai.com/tools/db-destr', sideEffectClass: 'destructive' } },
    { name: 'pay.send', scope: { toolSvid: 'spiffe://muveraai.com/tools/payment', sideEffectClass: 'financial' } },
  ]);
}

function gw(extra: Partial<ConstructorParameters<typeof McpGateway>[0]> = {}): McpGateway {
  return new McpGateway({
    gatewaySvid: GATEWAY,
    registry: registry(),
    transport: transport(),
    trustBundle: TRUST_BUNDLE,
    approvers: ['spiffe://muveraai.com/human/alice', 'spiffe://muveraai.com/human/bob'],
    ...extra,
  });
}

const call = (tool: string): ToolCall => ({ tool, args: {}, callerSvid: AGENT });

describe('AX-02 — envelope authenticity', () => {
  it('refuses to construct a gateway with no trust bundle', () => {
    expect(() =>
      new McpGateway({
        gatewaySvid: GATEWAY,
        registry: registry(),
        transport: transport(),
        trustBundle: [],
      })
    ).toThrow(/trustBundle is required/);
  });

  it('denies the original exploit: a forged, never-signed envelope', () => {
    const forged: AgentAuthorityEnvelope = {
      ...baseAae(),
      issuer: 'spiffe://evil.example/i-made-this-up',
      sideEffectClass: 'destructive',
      tools: ['spiffe://muveraai.com/tools/db-destr'],
      signature: { algorithm: 'Ed25519', keyId: KEY_ID, value: '0'.repeat(128) },
    };
    const r = gw().authorize(call('db.destroy'), forged);
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.reason).toBe('signature_invalid');
  });

  it('denies a post-signature escalation of the side-effect class', () => {
    const honest = baseAae({ sideEffectClass: 'read' });
    const tampered = { ...honest, sideEffectClass: 'destructive' as const };
    const r = gw().authorize(call('fs.read'), tampered);
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.reason).toBe('signature_invalid');
  });

  it('denies a key absent from the trust bundle', () => {
    const aae = baseAae();
    const r = gw().authorize(call('fs.read'), {
      ...aae,
      signature: { ...aae.signature, keyId: 'urn:aumos:key:unknown' },
    });
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.reason).toBe('signature_invalid');
  });

  it('denies a trusted key signing for an issuer it may not speak for', () => {
    const aae = sign({ ...baseAae(), issuer: 'spiffe://muveraai.com/some-other-issuer' });
    const r = gw().authorize(call('fs.read'), aae);
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.reason).toBe('signature_invalid');
  });

  it('honours revocation, which was previously declared and never read', () => {
    const g = gw({ revocation: { isRevoked: (h: string) => h === 'rh-1' } });
    const r = g.authorize(call('fs.read'), baseAae());
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.reason).toBe('revoked');
  });

  it('rejects a non-positive expiry rather than treating it as unbounded', () => {
    for (const expiry of [0, -1]) {
      const r = gw().authorize(call('fs.read'), baseAae({ expiry }));
      expect(r.allowed).toBe(false);
      if (!r.allowed) expect(r.reason).toBe('expired');
    }
  });

  it('allows a properly signed, unexpired, unrevoked envelope', () => {
    const r = gw().authorize(call('fs.read'), baseAae());
    expect(r.allowed).toBe(true);
  });
});

describe('AX-02 — constraints that were declared and never enforced', () => {
  it('enforces the spend budget', () => {
    const r = gw().authorize(call('fs.read'), baseAae({ spendBudget: 100 }), {
      spentMinor: 101,
      elapsedSeconds: 0,
      tokensUsed: 0,
    });
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.reason).toBe('budget_exhausted');
  });

  it('enforces the time budget', () => {
    const r = gw().authorize(call('fs.read'), baseAae({ timeBudgetSeconds: 60 }), {
      spentMinor: 0,
      elapsedSeconds: 61,
      tokensUsed: 0,
    });
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.reason).toBe('budget_exhausted');
  });

  it('enforces the token budget', () => {
    const r = gw().authorize(call('fs.read'), baseAae({ tokenBudget: 10 }), {
      spentMinor: 0,
      elapsedSeconds: 0,
      tokensUsed: 11,
    });
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.reason).toBe('budget_exhausted');
  });

  it('rejects an out-of-range delegation depth', () => {
    const r = gw().authorize(call('fs.read'), baseAae({ delegationDepth: 33 }));
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.reason).toBe('delegation_depth_invalid');
  });

  it('enforces the data-class ceiling', () => {
    const reg = new ToolRegistry().register({
      name: 'secrets.read',
      scope: {
        toolSvid: 'spiffe://muveraai.com/tools/fs-read',
        sideEffectClass: 'read',
        dataClasses: ['L4'],
      },
    });
    const g = gw({ registry: reg });
    const r = g.authorize(
      { tool: 'secrets.read', args: {}, callerSvid: AGENT },
      baseAae({ dataClasses: ['L0', 'L1'] })
    );
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.reason).toBe('data_class_exceeded');
  });

  it('enforces geography', () => {
    const reg = new ToolRegistry().register({
      name: 'eu.only',
      scope: {
        toolSvid: 'spiffe://muveraai.com/tools/fs-read',
        sideEffectClass: 'read',
        geography: 'DE',
      },
    });
    const g = gw({ registry: reg });
    const r = g.authorize(
      { tool: 'eu.only', args: {}, callerSvid: AGENT },
      baseAae({ geography: 'IN' })
    );
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.reason).toBe('geography_violation');
  });

  it('rejects an approval naming a non-approver (the substring-match defect)', () => {
    const r = gw().authorize(
      call('pay.send'),
      baseAae({
        sideEffectClass: 'financial',
        tools: ['spiffe://muveraai.com/tools/payment'],
        approvals: ['spiffe://muveraai.com/tools/payment-readonly-DIFFERENT'],
      })
    );
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.reason).toBe('consequential_approval_missing');
  });

  it('accepts an approval from a configured approver', () => {
    const r = gw().authorize(
      call('pay.send'),
      baseAae({
        sideEffectClass: 'financial',
        tools: ['spiffe://muveraai.com/tools/payment'],
        approvals: ['spiffe://muveraai.com/human/alice'],
      })
    );
    expect(r.allowed).toBe(true);
  });

  it('enforces an approval quorum greater than one', () => {
    const g = gw({ approvalQuorum: 2 });
    const one = g.authorize(
      call('pay.send'),
      baseAae({
        sideEffectClass: 'financial',
        tools: ['spiffe://muveraai.com/tools/payment'],
        approvals: ['spiffe://muveraai.com/human/alice'],
      })
    );
    expect(one.allowed).toBe(false);
    const two = g.authorize(
      call('pay.send'),
      baseAae({
        sideEffectClass: 'financial',
        tools: ['spiffe://muveraai.com/tools/payment'],
        approvals: ['spiffe://muveraai.com/human/alice', 'spiffe://muveraai.com/human/bob'],
      })
    );
    expect(two.allowed).toBe(true);
  });
});
