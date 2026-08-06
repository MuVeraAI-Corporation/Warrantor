import { describe, it, expect } from 'vitest';
import {
  McpGateway,
  ToolRegistry,
  isConsequential,
  type AgentAuthorityEnvelope,
  type ToolCall,
  type RegisteredTool,
} from './index.js';

const GATEWAY = 'spiffe://aumos.dev/mcp-gateway/default';

// A small registry covering read / write / financial tool classes.
function freshRegistry(): ToolRegistry {
  return new ToolRegistry().registerAll([
    {
      name: 'fs.read',
      scope: { toolSvid: 'spiffe://aumos.dev/tools/fs-read', sideEffectClass: 'read' },
    },
    {
      name: 'github.create_pr',
      scope: { toolSvid: 'spiffe://aumos.dev/tools/github', sideEffectClass: 'write' },
    },
    {
      name: 'payment.send',
      scope: { toolSvid: 'spiffe://aumos.dev/tools/payment', sideEffectClass: 'financial' },
    },
    {
      name: 'db.drop_table',
      scope: { toolSvid: 'spiffe://aumos.dev/tools/db-destr', sideEffectClass: 'destructive' },
    },
  ] satisfies RegisteredTool[]);
}

// AAE builder. Defaults grant the read/write tools to the gateway for the agent subject.
function sampleAae(overrides: Partial<AgentAuthorityEnvelope> = {}): AgentAuthorityEnvelope {
  return {
    issuer: 'spiffe://aumos.dev/agent-identity',
    subject: 'spiffe://aumos.dev/agent/coding-1',
    purpose: 'open a pull request',
    resources: [GATEWAY],
    tools: [
      'spiffe://aumos.dev/tools/fs-read',
      'spiffe://aumos.dev/tools/github',
    ],
    dataClasses: ['L0', 'L1'],
    sideEffectClass: 'write',
    spendBudget: 0,
    timeBudgetSeconds: 3600,
    tokenBudget: 100000,
    geography: '',
    delegationDepth: 0,
    approvals: [],
    expiry: 0, // 0 = no expiry enforcement
    revocationHandle: 'rh-1',
    ...overrides,
  };
}

function call(tool: string, caller = 'spiffe://aumos.dev/agent/coding-1'): ToolCall {
  return { tool, args: {}, callerSvid: caller };
}

function gateway(now?: () => number): McpGateway {
  return new McpGateway({ gatewaySvid: GATEWAY, registry: freshRegistry(), now });
}

describe('ToolRegistry', () => {
  it('looks up registered tools and reports unknowns', () => {
    const r = freshRegistry();
    expect(r.has('fs.read')).toBe(true);
    expect(r.lookup('fs.read')?.scope.toolSvid).toBe('spiffe://aumos.dev/tools/fs-read');
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
    expect(r.scope?.toolSvid).toBe('spiffe://aumos.dev/tools/fs-read');
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
    const aae = sampleAae({ resources: ['spiffe://aumos.dev/some-other-gateway'] });
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

  it('does NOT treat expiry=0 as expired (0 means unbounded)', () => {
    const g = gateway(() => 9_999_999);
    const r = g.authorize(call('fs.read'), sampleAae({ expiry: 0 }));
    expect(r.allowed).toBe(true);
  });

  it('denies when caller SVID does not match AAE subject', () => {
    const g = gateway();
    const r = g.authorize(
      call('fs.read', 'spiffe://aumos.dev/agent/impostor'),
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
      tools: ['spiffe://aumos.dev/tools/payment'],
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
        tools: ['spiffe://aumos.dev/tools/payment'],
        approvals: ['spiffe://aumos.dev/humans/alice/for/spiffe://aumos.dev/tools/payment'],
      })
    );
    expect(ok.allowed).toBe(true);
  });

  it('requires approval for destructive tools and respects class rank', () => {
    const g = gateway();
    // financial AAE is rank 2 < destructive rank 3 → denied on class grounds first.
    const aaeFinancial = sampleAae({
      sideEffectClass: 'financial',
      tools: ['spiffe://aumos.dev/tools/db-destr'],
      approvals: ['x/spiffe://aumos.dev/tools/db-destr'],
    });
    const r1 = g.authorize(call('db.drop_table'), aaeFinancial);
    expect(r1.allowed).toBe(false);
    expect(r1.reason).toBe('side_effect_class_insufficient');

    // destructive AAE without approval → approval-missing denial.
    const aaeDestructive = sampleAae({
      sideEffectClass: 'destructive',
      tools: ['spiffe://aumos.dev/tools/db-destr'],
      approvals: [],
    });
    const r2 = g.authorize(call('db.drop_table'), aaeDestructive);
    expect(r2.allowed).toBe(false);
    expect(r2.reason).toBe('consequential_approval_missing');

    // destructive AAE with approval → allowed.
    const aaeOk = sampleAae({
      sideEffectClass: 'destructive',
      tools: ['spiffe://aumos.dev/tools/db-destr'],
      approvals: ['approver/for/spiffe://aumos.dev/tools/db-destr'],
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
  it('forwards an authorized call and returns a stubbed ack', async () => {
    const g = gateway();
    const c = call('fs.read');
    const r = g.authorize(c, sampleAae());
    const ack = await g.forward(c, r);
    expect(ack.tool).toBe('fs.read');
    expect(ack.toolSvid).toBe('spiffe://aumos.dev/tools/fs-read');
    expect(ack.stubbed).toBe(true);
    expect(g.counters().forwarded).toBe(1);
  });

  it('refuses to forward a denied call', async () => {
    const g = gateway();
    const r = g.authorize(call('not.a.tool'), sampleAae());
    expect(r.allowed).toBe(false);
    await expect(g.forward(call('not.a.tool'), r)).rejects.toThrow(/denied/);
  });

  it('increments authorized counter on allow', () => {
    const g = gateway();
    g.authorize(call('fs.read'), sampleAae());
    g.authorize(call('fs.read'), sampleAae());
    expect(g.counters().authorized).toBe(2);
  });
});

describe('McpGateway — confused-deputy end-to-end', () => {
  it('blocks an agent that tries to invoke a tool not in its own AAE', () => {
    const g = gateway();
    // Attacker has an AAE for github only but tries payment.send (registered tool).
    const attackerAae = sampleAae({
      sideEffectClass: 'financial',
      tools: ['spiffe://aumos.dev/tools/github'],
      approvals: ['x/spiffe://aumos.dev/tools/payment'],
    });
    const r = g.authorize(call('payment.send'), attackerAae);
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('tool_not_in_aae');
  });
});

describe('McpGateway constructor validation', () => {
  it('rejects a missing gatewaySvid', () => {
    expect(
      () => new McpGateway({ gatewaySvid: '', registry: freshRegistry() })
    ).toThrow(/gatewaySvid/);
  });

  it('rejects a missing registry', () => {
    expect(
      () => new McpGateway({ gatewaySvid: GATEWAY, registry: undefined as unknown as ToolRegistry })
    ).toThrow(/registry/);
  });
});
