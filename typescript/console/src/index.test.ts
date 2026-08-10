import { describe, it, expect } from 'vitest';
import {
  initialState,
  reducer,
  filteredReceipts,
  pendingApprovals,
  consequentialPending,
  selectedReceipt,
  allocationsByTenant,
  type AgentActionReceipt,
  type ApprovalRequest,
  type GpuAllocation,
} from './index.js';

function sampleReceipt(overrides: Partial<AgentActionReceipt> = {}): AgentActionReceipt {
  return {
    id: 'r-1',
    actor: 'spiffe://warrantor.dev/agent/coding-1',
    authorityHashHex: 'abc123',
    toolOrApiOp: 'github.create_pr',
    outcome: 'committed',
    emittedAt: 1000,
    signatureHex: 'sig',
    verifyingKeyHex: 'vk',
    approvers: [],
    ...overrides,
  };
}

function sampleApproval(overrides: Partial<ApprovalRequest> = {}): ApprovalRequest {
  return {
    id: 'a-1',
    receiptId: 'r-1',
    actor: 'spiffe://warrantor.dev/agent/coding-1',
    toolOrApiOp: 'payment.send',
    sideEffectClass: 'financial',
    requestedAt: 1000,
    status: 'pending',
    ...overrides,
  };
}

describe('console reducer', () => {
  it('navigates between views', () => {
    let s = initialState();
    s = reducer(s, { type: 'navigate', view: 'fleet' });
    expect(s.activeView).toBe('fleet');
    s = reducer(s, { type: 'navigate', view: 'compliance' });
    expect(s.activeView).toBe('compliance');
  });

  it('sets and selects receipts', () => {
    let s = initialState();
    s = reducer(s, { type: 'set_receipts', receipts: [sampleReceipt()] });
    expect(s.receipts.length).toBe(1);
    s = reducer(s, { type: 'select_receipt', id: 'r-1' });
    expect(s.selectedReceiptId).toBe('r-1');
  });

  it('merges filters partially', () => {
    let s = initialState();
    s = reducer(s, { type: 'set_filters', filters: { actor: 'agent-x' } });
    expect(s.filters.actor).toBe('agent-x');
    s = reducer(s, { type: 'set_filters', filters: { outcome: 'pending' } });
    expect(s.filters.actor).toBe('agent-x'); // preserved
    expect(s.filters.outcome).toBe('pending'); // added
  });

  it('decides an approval', () => {
    let s = initialState();
    s = reducer(s, { type: 'set_approvals', approvals: [sampleApproval()] });
    s = reducer(s, { type: 'decide_approval', id: 'a-1', decision: 'approved', decidedBy: 'alice' });
    expect(s.approvals[0].status).toBe('approved');
    expect(s.approvals[0].decidedBy).toBe('alice');
    expect(s.approvals[0].decidedAt).toBeGreaterThan(0);
  });
});

describe('selectors', () => {
  it('filters receipts by actor', () => {
    const s = reducer(
      initialState(),
      { type: 'set_receipts', receipts: [sampleReceipt({ actor: 'a', id: '1' }), sampleReceipt({ actor: 'b', id: '2' })] }
    );
    const filtered = filteredReceipts(reducer(s, { type: 'set_filters', filters: { actor: 'a' } }));
    expect(filtered.length).toBe(1);
    expect(filtered[0].actor).toBe('a');
  });

  it('filters receipts by outcome', () => {
    const s = reducer(
      initialState(),
      { type: 'set_receipts', receipts: [sampleReceipt({ outcome: 'committed', id: '1' }), sampleReceipt({ outcome: 'pending', id: '2' })] }
    );
    const filtered = filteredReceipts(reducer(s, { type: 'set_filters', filters: { outcome: 'pending' } }));
    expect(filtered.length).toBe(1);
    expect(filtered[0].outcome).toBe('pending');
  });

  it('filters receipts by tool substring', () => {
    const s = reducer(
      initialState(),
      { type: 'set_receipts', receipts: [sampleReceipt({ toolOrApiOp: 'github.create_pr', id: '1' }), sampleReceipt({ toolOrApiOp: 'slack.send', id: '2' })] }
    );
    const filtered = filteredReceipts(reducer(s, { type: 'set_filters', filters: { tool: 'github' } }));
    expect(filtered.length).toBe(1);
  });

  it('returns pending approvals', () => {
    const s = reducer(
      initialState(),
      { type: 'set_approvals', approvals: [sampleApproval({ status: 'pending', id: '1' }), sampleApproval({ status: 'approved', id: '2' })] }
    );
    expect(pendingApprovals(s).length).toBe(1);
  });

  it('identifies consequential pending approvals (I-08)', () => {
    const s = reducer(
      initialState(),
      {
        type: 'set_approvals',
        approvals: [
          sampleApproval({ sideEffectClass: 'financial', status: 'pending', id: '1' }),
          sampleApproval({ sideEffectClass: 'read', status: 'pending', id: '2' }),
          sampleApproval({ sideEffectClass: 'destructive', status: 'pending', id: '3' }),
        ],
      }
    );
    const c = consequentialPending(s);
    expect(c.length).toBe(2); // financial + destructive, not read
  });

  it('returns the selected receipt', () => {
    let s = reducer(initialState(), { type: 'set_receipts', receipts: [sampleReceipt({ id: 'x' })] });
    s = reducer(s, { type: 'select_receipt', id: 'x' });
    expect(selectedReceipt(s)?.id).toBe('x');
  });

  it('returns null when no receipt selected', () => {
    const s = initialState();
    expect(selectedReceipt(s)).toBeNull();
  });

  it('counts allocations by tenant', () => {
    const allocations: GpuAllocation[] = [
      { tenantId: 't1', gpuId: 'g1', gpuModel: 'H100', mode: 'mig', aaeValidated: true },
      { tenantId: 't1', gpuId: 'g2', gpuModel: 'H100', mode: 'mig', aaeValidated: true },
      { tenantId: 't2', gpuId: 'g3', gpuModel: 'A100', mode: 'mps', aaeValidated: true },
    ];
    const s = reducer(initialState(), { type: 'set_allocations', allocations });
    const counts = allocationsByTenant(s);
    expect(counts.get('t1')).toBe(2);
    expect(counts.get('t2')).toBe(1);
  });
});
