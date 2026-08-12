/**
 * @warrantor/console (X7) — Warrantor enterprise policy/evidence console.
 *
 * The data model, API client, and view logic for the enterprise console. The console provides:
 *   - Evidence viewer (browse AARs from E1 flight-recorder)
 *   - Policy administration (view/edit OPA Rego policies compiled by R5 policy-compiler)
 *   - Approvals queue (for consequential actions requiring invariant I-08 approval)
 *   - Fleet management (view N4 tenant-guard allocations)
 *   - Compliance reports (the 10-framework matrix from cross-cutting 13)
 *
 * v1.0 ships the data model + API client + view reducers (testable without a browser).
 * The React/Next.js component layer is task 03 (it consumes this library).
 */

// ---------------------------------------------------------------------------
// Data model — mirrors the proto wire types and the Go/Python component outputs.
// ---------------------------------------------------------------------------

/** An Agent Action Receipt (P2 AAR) as the console receives it from E1. */
export interface AgentActionReceipt {
  id: string;
  actor: string;
  authorityHashHex: string;
  toolOrApiOp: string;
  outcome: 'pending' | 'committed' | 'rolled_back' | 'failed';
  emittedAt: number; // epoch seconds
  signatureHex: string;
  verifyingKeyHex: string;
  approvers: string[];
}

/** A pending approval request (consequential actions per invariant I-08). */
export interface ApprovalRequest {
  id: string;
  receiptId: string;
  actor: string;
  toolOrApiOp: string;
  sideEffectClass: 'read' | 'write' | 'financial' | 'destructive' | 'physical';
  requestedAt: number;
  status: 'pending' | 'approved' | 'denied';
  decidedBy?: string;
  decidedAt?: number;
}

/** A GPU allocation from N4 tenant-guard. */
export interface GpuAllocation {
  tenantId: string;
  gpuId: string;
  gpuModel: string;
  mode: 'mig' | 'mps' | 'none';
  slice?: string;
  aaeValidated: boolean;
}

/** A compliance framework entry (from the 10-framework matrix). */
export interface ComplianceFrameworkEntry {
  framework: string;
  jurisdiction: string;
  status: string;
  components: string[];
}

/** A policy bundle (OPA Rego compiled by R5 policy-compiler). */
export interface PolicyBundle {
  id: string;
  hashHex: string;
  rules: PolicyRule[];
  version: string;
}

/** One rule in a policy bundle. */
export interface PolicyRule {
  id: string;
  engine: 'opa' | 'cedar' | 'openshell';
  body: string; // the Rego/Cedar source
  description: string;
}

// ---------------------------------------------------------------------------
// View state — the console's UI state machine.
// ---------------------------------------------------------------------------

/** The console's top-level view state. */
export interface ConsoleState {
  activeView: View;
  receipts: AgentActionReceipt[];
  approvals: ApprovalRequest[];
  allocations: GpuAllocation[];
  complianceMatrix: ComplianceFrameworkEntry[];
  policies: PolicyBundle[];
  selectedReceiptId: string | null;
  filters: ConsoleFilters;
}

/** The available top-level views. */
export type View = 'evidence' | 'approvals' | 'fleet' | 'compliance' | 'policies';

/** Filters applied to the evidence view. */
export interface ConsoleFilters {
  actor?: string;
  outcome?: AgentActionReceipt['outcome'];
  tool?: string;
  since?: number; // epoch seconds
}

/** The initial empty state. */
export function initialState(): ConsoleState {
  return {
    activeView: 'evidence',
    receipts: [],
    approvals: [],
    allocations: [],
    complianceMatrix: [],
    policies: [],
    selectedReceiptId: null,
    filters: {},
  };
}

// ---------------------------------------------------------------------------
// Reducers — pure functions the UI calls to transition state.
// ---------------------------------------------------------------------------

/** Action types the console dispatches. */
export type ConsoleAction =
  | { type: 'navigate'; view: View }
  | { type: 'set_receipts'; receipts: AgentActionReceipt[] }
  | { type: 'select_receipt'; id: string | null }
  | { type: 'set_filters'; filters: Partial<ConsoleFilters> }
  | { type: 'set_approvals'; approvals: ApprovalRequest[] }
  | { type: 'decide_approval'; id: string; decision: 'approved' | 'denied'; decidedBy: string }
  | { type: 'set_allocations'; allocations: GpuAllocation[] }
  | { type: 'set_compliance'; matrix: ComplianceFrameworkEntry[] }
  | { type: 'set_policies'; policies: PolicyBundle[] };

/** The reducer — pure function, no side effects. */
export function reducer(state: ConsoleState, action: ConsoleAction): ConsoleState {
  switch (action.type) {
    case 'navigate':
      return { ...state, activeView: action.view };
    case 'set_receipts':
      return { ...state, receipts: action.receipts };
    case 'select_receipt':
      return { ...state, selectedReceiptId: action.id };
    case 'set_filters':
      return { ...state, filters: { ...state.filters, ...action.filters } };
    case 'set_approvals':
      return { ...state, approvals: action.approvals };
    case 'decide_approval':
      return {
        ...state,
        approvals: state.approvals.map((a) =>
          a.id === action.id
            ? { ...a, status: action.decision, decidedBy: action.decidedBy, decidedAt: Math.floor(Date.now() / 1000) }
            : a
        ),
      };
    case 'set_allocations':
      return { ...state, allocations: action.allocations };
    case 'set_compliance':
      return { ...state, complianceMatrix: action.matrix };
    case 'set_policies':
      return { ...state, policies: action.policies };
    default:
      return state;
  }
}

// ---------------------------------------------------------------------------
// Selectors — derived state computed from ConsoleState.
// ---------------------------------------------------------------------------

/** Filter receipts by the active filters. */
export function filteredReceipts(state: ConsoleState): AgentActionReceipt[] {
  const f = state.filters;
  return state.receipts.filter((r) => {
    if (f.actor && r.actor !== f.actor) return false;
    if (f.outcome && r.outcome !== f.outcome) return false;
    if (f.tool && !r.toolOrApiOp.includes(f.tool)) return false;
    if (f.since && r.emittedAt < f.since) return false;
    return true;
  });
}

/** Pending approvals (not yet decided). */
export function pendingApprovals(state: ConsoleState): ApprovalRequest[] {
  return state.approvals.filter((a) => a.status === 'pending');
}

/** Approvals requiring human action for consequential side-effects (invariant I-08). */
export function consequentialPending(state: ConsoleState): ApprovalRequest[] {
  return pendingApprovals(state).filter((a) =>
    ['financial', 'destructive', 'physical'].includes(a.sideEffectClass)
  );
}

/** The currently-selected receipt (or null). */
export function selectedReceipt(state: ConsoleState): AgentActionReceipt | null {
  if (!state.selectedReceiptId) return null;
  return state.receipts.find((r) => r.id === state.selectedReceiptId) ?? null;
}

/** Per-tenant allocation counts. */
export function allocationsByTenant(state: ConsoleState): Map<string, number> {
  const m = new Map<string, number>();
  for (const a of state.allocations) {
    m.set(a.tenantId, (m.get(a.tenantId) ?? 0) + 1);
  }
  return m;
}

// ---------------------------------------------------------------------------
// API client — talks to the Go/Python services over HTTP/JSON.
// ---------------------------------------------------------------------------

/** Configuration for the API client. */
export interface ApiClientConfig {
  baseUrl: string; // e.g. "https://console.muveraai.com"
  token?: string;  // bearer token (from SSO in production)
}

/** Fetches receipts from E1 flight-recorder's HTTP endpoint. */
export async function fetchReceipts(
  config: ApiClientConfig,
  since?: number
): Promise<AgentActionReceipt[]> {
  const url = new URL('/v1/receipts', config.baseUrl);
  if (since) url.searchParams.set('since', String(since));
  const resp = await fetch(url, { headers: authHeaders(config) });
  if (!resp.ok) throw new Error(`fetchReceipts: ${resp.status}`);
  return (await resp.json()) as AgentActionReceipt[];
}

/** Fetches pending approvals from I1 agent-identity. */
export async function fetchApprovals(config: ApiClientConfig): Promise<ApprovalRequest[]> {
  const resp = await fetch(new URL('/v1/approvals', config.baseUrl), {
    headers: authHeaders(config),
  });
  if (!resp.ok) throw new Error(`fetchApprovals: ${resp.status}`);
  return (await resp.json()) as ApprovalRequest[];
}

/** Decides an approval (approve or deny). */
export async function decideApproval(
  config: ApiClientConfig,
  id: string,
  decision: 'approved' | 'denied',
  decidedBy: string
): Promise<ApprovalRequest> {
  const resp = await fetch(new URL(`/v1/approvals/${id}:decide`, config.baseUrl), {
    method: 'POST',
    headers: { ...authHeaders(config), 'content-type': 'application/json' },
    body: JSON.stringify({ decision, decidedBy }),
  });
  if (!resp.ok) throw new Error(`decideApproval: ${resp.status}`);
  return (await resp.json()) as ApprovalRequest;
}

function authHeaders(config: ApiClientConfig): Record<string, string> {
  const h: Record<string, string> = { 'content-type': 'application/json' };
  if (config.token) h['authorization'] = `Bearer ${config.token}`;
  return h;
}
