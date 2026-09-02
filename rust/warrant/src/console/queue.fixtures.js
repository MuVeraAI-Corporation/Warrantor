/**
 * Frozen contract fixtures for the approval queue (L8-01).
 *
 * # Why this file exists
 *
 * Task 4.1 builds the operator-facing approval queue surface from a
 * contract, not from a running backend. The Rust `serve.rs` `/v1/queue`
 * route already returns a payload with the fields the console renders
 * today (warrant_id, state, issued_at, staged_effects, blocker, you_can);
 * L8-01's anti-ceremony rules add fields the existing payload does NOT
 * carry: a per-effect preview, the authority chain behind the warrant, the
 * prior receipts, dependency-aware partial-approval metadata, a latency
 * budget with p50/p99, and a disagreement rate.
 *
 * This file freezes the additive contract. Each fixture is a complete
 * `/v1/queue` body that the console renders with no backend running, and
 * each additive field is shaped to match what the Phase 1/2 Rust work
 * will emit (per `docs/02-architecture.md` §4 and the W1 ledger). When the
 * backend ships, the fixtures become a wire-compatibility check, not a
 * guess.
 *
 * # The fields the backend will add (additive, never required)
 *
 *   `entries[i].proposed_effects: ProposedEffect[]`
 *     Per staged effect: tool, target, what it would change, and whether
 *     the warrant's own bounds say it can run.
 *
 *   `entries[i].authority_chain: ChainLink[]`
 *     Grant tree root -> the warrant, with the parent's grant digest.
 *     An approver who cannot see how the warrant was issued cannot tell
 *     whether the warrant is in scope, and a queue that hides this is
 *     rubber-stamping by design.
 *
 *   `entries[i].prior_receipts: PriorReceipt[]`
 *     The most recent settled or refused receipts on the warrant, in time
 *     order. The exact anti-ceremony field: the approver's last look at
 *     this warrant, signed.
 *
 *   `entries[i].timeout: TimeoutSpec | null`
 *     The deadline after which the entry auto-denies. The plan's L8-01
 *     verification clause: "A staged effect with no decision inside the
 *     budget settles as denied." When the budget has expired, the row
 *     shows so and the act bar is empty.
 *
 *   `entries[i].partial_release: PartialRelease | null`
 *     The set of effects the server would release independently of the
 *     others, with the names of the dependents the server would refuse.
 *     Empty on a warrant with no dependencies.
 *
 *   `policy.latency: LatencyStats`
 *     p50 and p99 of approval latency over the last window, plus the
 *     disagreement rate (the share of decisions the approver's verdict
 *     disagreed with the agent's). The plan: "p50 and p99 approval
 *     latency are published per queue alongside the disagreement rate,
 *     so a queue that gets faster while disagreement falls to zero is
 *     flagged, not celebrated."
 *
 * # The rule that overrides any design instinct
 *
 * No surface in this product collapses observed, advisory, mediated and
 * enforced into one green state. The fixtures and the renderer
 * therefore name a tier per row, per effect, and per receipt, and they
 * name a coverage limit beside every guarantee. Where the contract
 * does not yet have a field, the fixture sets it to `null` and the
 * renderer shows "not stated" — never the strongest tier, never a
 * default to enforced.
 */

// ── the additive contract (single source of truth) ───────────────────────

/**
 * One staged effect the warrant is asking the approver to release.
 * `tier` is the same vocabulary the report uses; it is set by the
 * server from `bound_strengths()` and is never recomputed here.
 */
export const PROPOSED_EFFECT_SHAPE = Object.freeze({
  tool: 'string — the tool name, e.g. "github.create_pr"',
  target: 'string — the recipient or resource, e.g. "owner/repo"',
  summary: 'string — one sentence stating what the effect would change',
  tier: 'one of "enforced" | "mediated" | "observed" — never "unknown"',
  covered_by: 'string — what the tier does NOT cover, in one clause',
});

/**
 * One link in the grant tree behind the warrant. A warrant with no
 * parent is a root; otherwise `parent_digest` is the parent's grant
 * digest and `delegated_by` is the principal who delegated.
 */
export const CHAIN_LINK_SHAPE = Object.freeze({
  warrant_id: 'string',
  subject: 'string — the SPIFFE-style principal',
  goal: 'string',
  granted_at: 'number — epoch seconds',
  parent_digest: 'string | null — null on a root',
  delegated_by: 'string | null — null on a root',
});

/**
 * One prior receipt the approver would benefit from seeing before
 * releasing a new effect. The `verdict` is the server's reading, not
 * a recomputation.
 */
export const PRIOR_RECEIPT_SHAPE = Object.freeze({
  at: 'number — epoch seconds',
  by: 'string — operator name or "(anonymous)"',
  kind: 'one of "settle" | "approve" | "refuse" | "void" | "stop"',
  bound: 'string | null — the bound the receipt acted on, when relevant',
  summary: 'string — one sentence',
  receipt_digest: 'string — the receipt\'s content hash',
});

/**
 * The deadline after which this entry auto-denies. A row whose budget
 * has already expired renders with an empty act bar and a "denied by
 * timeout" line; an unexpired row renders the budget so the approver
 * knows how long they have.
 */
export const TIMEOUT_SHAPE = Object.freeze({
  deadline_at: 'number — epoch seconds',
  remaining_seconds: 'number — what the server currently sees',
  on_expiry: 'string — always "deny"; never "approve" or "escalate"',
});

/**
 * The set of effects the server would release independently, and the
 * dependents the server would refuse if a dependency is unreleased.
 * A warrant with no dependencies carries `null`.
 */
export const PARTIAL_RELEASE_SHAPE = Object.freeze({
  independently_releasable: 'string[] — effect indexes in proposed_effects',
  refused_when_unreleased: 'string[] — effect indexes the server would refuse',
  reason: 'string — one sentence naming the dependency',
});

/**
 * Per-queue latency and disagreement rate, in the form the plan
 * demands. The disagreement rate is the share of recent decisions
 * where the approver's verdict differed from the agent's request —
 * the metric that catches a queue drifting into rubber-stamping.
 */
export const LATENCY_SHAPE = Object.freeze({
  window: 'string — the window these stats were computed over',
  sample_size: 'number — how many decisions are in the window',
  p50_seconds: 'number',
  p99_seconds: 'number',
  disagreement_rate: 'number — in [0, 1]; null means too few samples to publish',
  note: 'string | null — what to do if disagreement is trending to zero',
});

// ── the fixtures ─────────────────────────────────────────────────────────

/**
 * A baseline queue: one warrant awaiting a second approval, full
 * additive fields filled in. The case the plan's verification clause
 * names: "the approver sees the proposed effect, the authority chain
 * and the prior receipts BEFORE the approve control."
 */
export const baselineQueue = Object.freeze({
  data: {
    waiting: [
      {
        warrant_id: 'wrt_a',
        state: 'open',
        issued_at: 1_786_000_000,
        staged_effects: 2,
        blocker: {
          blocker: 'awaiting-approval',
          still_needed: 1,
          could_approve: ['ben'],
          approved_by: ['ana'],
        },
        you_can: ['approve'],
        proposed_effects: [
          {
            tool: 'github.create_pr',
            target: 'muveraai/warrantor',
            summary: 'Open a pull request titled "Fix auth" against main.',
            tier: 'enforced',
            covered_by:
              'Held by the MCP proxy and the staging gate; the PR is created, not merged, and the merge is a separate human act.',
          },
          {
            tool: 'fs.write',
            target: 'src/auth/refresh.rs',
            summary: 'Rewrite the refresh-token rotation to use the new signer.',
            tier: 'mediated',
            covered_by:
              'Held only for calls that traverse the MCP proxy; a shell, a harness built-in, or any process the warrant did not name, reaches past it.',
          },
        ],
        authority_chain: [
          {
            warrant_id: 'wrt_root',
            subject: 'spiffe://muveraai.com/agent/orchestrator',
            goal: 'coordinate a one-week auth refactor across the runtime, the desktop, and the console',
            granted_at: 1_785_900_000,
            parent_digest: null,
            delegated_by: null,
          },
          {
            warrant_id: 'wrt_a',
            subject: 'spiffe://muveraai.com/agent/coder',
            goal: 'fix the auth bug',
            granted_at: 1_786_000_000,
            parent_digest: 'sha256:9a7c…d11e',
            delegated_by: 'orchestrator',
          },
        ],
        prior_receipts: [
          {
            at: 1_786_001_200,
            by: 'ana',
            kind: 'approve',
            bound: null,
            summary: 'First of two required approvals recorded; second still owed.',
            receipt_digest: 'sha256:0e3a…b72c',
          },
          {
            at: 1_785_999_500,
            by: 'orchestrator',
            kind: 'refuse',
            bound: 'write_paths',
            summary:
              'First draft staged a write to tests/__pycache__/ which is outside the declared paths; the agent rewrote and re-staged.',
            receipt_digest: 'sha256:cc41…ee90',
          },
        ],
        timeout: {
          deadline_at: 1_786_000_900,
          remaining_seconds: 900,
          on_expiry: 'deny',
        },
        partial_release: null,
      },
    ],
    waiting_on_you: 1,
    counts: { 'awaiting-approval': 1 },
    undetermined: [],
    unreadable_records: 0,
    policy: {
      required: 2,
      settler_may_approve: false,
      latency: {
        window: 'last 24h',
        sample_size: 17,
        p50_seconds: 42,
        p99_seconds: 312,
        disagreement_rate: 0.12,
        note:
          'A disagreement rate trending to zero while latency improves is rubber-stamping, not improvement.',
      },
    },
    you: { name: 'ben', via: 'operator-token', scopes: ['read', 'approve'] },
  },
});

/**
 * A warrant with three staged effects, two of which depend on the
 * first. Releasing only the first two must NOT release the third.
 * The fixture names the dependency, the independently-releasable
 * set, and the dependent the server would refuse.
 */
export const dependencyQueue = Object.freeze({
  data: {
    waiting: [
      {
        warrant_id: 'wrt_b',
        state: 'open',
        issued_at: 1_786_010_000,
        staged_effects: 3,
        blocker: {
          blocker: 'awaiting-decision',
          approved_by: ['ana', 'ben'],
        },
        you_can: ['approve', 'settle'],
        proposed_effects: [
          {
            tool: 'fs.write',
            target: 'src/runtime.rs',
            summary: 'Add the new signing entry point.',
            tier: 'mediated',
            covered_by:
              'Held only for calls that traverse the MCP proxy; a shell reaches past it.',
          },
          {
            tool: 'fs.write',
            target: 'src/signer.rs',
            summary: 'Add the matching key-parsing path.',
            tier: 'mediated',
            covered_by:
              'Held only for calls that traverse the MCP proxy; a shell reaches past it.',
          },
          {
            tool: 'cargo.test',
            target: 'warrantor-warrant',
            summary: 'Run the new signer tests against a recorded fixture set.',
            tier: 'observed',
            covered_by:
              'Measured and reported after the fact; nothing refuses a test invocation as it happens.',
          },
        ],
        authority_chain: [
          {
            warrant_id: 'wrt_b',
            subject: 'spiffe://muveraai.com/agent/coder',
            goal: 'ship the v2 signer without a one-step fix',
            granted_at: 1_786_010_000,
            parent_digest: null,
            delegated_by: null,
          },
        ],
        prior_receipts: [
          {
            at: 1_786_010_500,
            by: 'ana',
            kind: 'approve',
            bound: null,
            summary: 'First of two required approvals recorded.',
            receipt_digest: 'sha256:11fa…04d0',
          },
          {
            at: 1_786_010_600,
            by: 'ben',
            kind: 'approve',
            bound: null,
            summary: 'Second of two required approvals recorded.',
            receipt_digest: 'sha256:22bc…71e3',
          },
        ],
        timeout: {
          deadline_at: 1_786_010_900,
          remaining_seconds: 900,
          on_expiry: 'deny',
        },
        partial_release: {
          independently_releasable: [0, 1],
          refused_when_unreleased: [2],
          reason:
            'Effect 2 runs cargo.test against the new signer; releasing it without effects 0 and 1 would test code that is not on disk.',
        },
      },
    ],
    waiting_on_you: 1,
    counts: { 'awaiting-decision': 1 },
    undetermined: [],
    unreadable_records: 0,
    policy: {
      required: 2,
      settler_may_approve: true,
      latency: {
        window: 'last 24h',
        sample_size: 17,
        p50_seconds: 42,
        p99_seconds: 312,
        disagreement_rate: 0.12,
        note:
          'A disagreement rate trending to zero while latency improves is rubber-stamping, not improvement.',
      },
    },
    you: { name: 'ben', via: 'operator-token', scopes: ['read', 'approve', 'settle'] },
  },
});

/**
 * A warrant whose response budget has already elapsed. The act bar
 * must be empty and the row must say so in plain language, with the
 * exact resolution ("denied by timeout; never escalated") the plan
 * demands.
 */
export const timedOutQueue = Object.freeze({
  data: {
    waiting: [
      {
        warrant_id: 'wrt_c',
        state: 'open',
        issued_at: 1_785_995_000,
        staged_effects: 1,
        blocker: {
          blocker: 'awaiting-approval',
          still_needed: 1,
          could_approve: ['ben', 'cleo'],
          approved_by: ['ana'],
        },
        you_can: [],
        proposed_effects: [
          {
            tool: 'github.merge_pr',
            target: 'muveraai/warrantor#214',
            summary: 'Merge a dependency bump that has been waiting for a second approver for 9m.',
            tier: 'enforced',
            covered_by:
              'Held by the MCP proxy; the merge is performed, not staged, and a refusal halts the chain.',
          },
        ],
        authority_chain: [
          {
            warrant_id: 'wrt_c',
            subject: 'spiffe://muveraai.com/agent/ops',
            goal: 'land a one-line dependency bump behind a two-person rule',
            granted_at: 1_785_995_000,
            parent_digest: null,
            delegated_by: null,
          },
        ],
        prior_receipts: [
          {
            at: 1_785_995_400,
            by: 'ana',
            kind: 'approve',
            bound: null,
            summary: 'First of two required approvals recorded.',
            receipt_digest: 'sha256:7f01…a2c8',
          },
        ],
        timeout: {
          deadline_at: 1_785_995_900,
          remaining_seconds: -120,
          on_expiry: 'deny',
        },
        partial_release: null,
      },
    ],
    waiting_on_you: 0,
    counts: { 'awaiting-approval': 1 },
    undetermined: [],
    unreadable_records: 0,
    policy: {
      required: 2,
      settler_may_approve: false,
      latency: {
        window: 'last 24h',
        sample_size: 17,
        p50_seconds: 42,
        p99_seconds: 312,
        disagreement_rate: 0.12,
        note:
          'A disagreement rate trending to zero while latency improves is rubber-stamping, not improvement.',
      },
    },
    you: { name: 'ben', via: 'operator-token', scopes: ['read', 'approve'] },
  },
});

/**
 * A queue the server has chosen NOT to extend with the additive L8-01
 * fields (e.g. an older binary, or a server where the work has not
 * landed). The console must render what it can, mark the missing
 * fields as "not stated", and NEVER infer them. A renderer that
 * showed a tier or a chain it was not given would be a second
 * implementation of the server's verdict.
 */
export const minimalQueue = Object.freeze({
  data: {
    waiting: [
      {
        warrant_id: 'wrt_d',
        state: 'open',
        issued_at: 1_786_020_000,
        staged_effects: 1,
        blocker: {
          blocker: 'awaiting-approval',
          still_needed: 1,
          could_approve: ['ben'],
          approved_by: ['ana'],
        },
        you_can: ['approve'],
      },
    ],
    waiting_on_you: 1,
    counts: { 'awaiting-approval': 1 },
    undetermined: [],
    unreadable_records: 0,
    policy: {
      required: 2,
      settler_may_approve: false,
    },
    you: { name: 'ben', via: 'operator-token', scopes: ['read', 'approve'] },
  },
});
