/**
 * Frozen contract fixtures for the fleet console and the agent inventory register (L8-02, L8-08).
 *
 * # Why this file exists
 *
 * Task 11.1 builds the operator-facing agent register on top of a frozen contract:
 * the existing `/v1/warrants` route the console already polls, plus the new
 * `/v1/agents` route the backend will publish. The route returns the same
 * warrant records the existing `/v1/warrants` returns, regrouped under the
 * `subject` field (a spiffe:// URI or a name) that owns them. The console's
 * `listFacts` already reads `payload?.data?.warrants`; the fleet's facts
 * function reads `payload?.data?.agents`, which the server builds by
 * grouping warrants on `subject` and folding the warrant set into one
 * authority, one tier, and one coverage-limit sentence.
 *
 * The fields this file freezes are the ones the row renders. No field here
 * is invented; every field is either read from the existing console's
 * warrant-row render path, or named in
 * `docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md`
 * Task 11.1 Step 0.
 *
 * # The contract this file holds
 *
 *   `pack.format` does not apply. The fleet register is a JSON envelope, not
 *     a `SignedReport`. The fields are:
 *
 *   `payload.data.agents[i].subject` — string. The agent's identity. Either
 *     a spiffe:// URI (the broker-issued identity) or a name the store
 *     recorded. Two warrants for the same subject render as one row.
 *   `payload.data.agents[i].warrant_ids[]` — array of strings. The ids of
 *     the warrants this subject owns. A subject with zero warrants still
 *     renders (the shadow-agent case is the 13.1 lane's job, but the
 *     empty register row is this lane's).
 *   `payload.data.agents[i].authority` — object. The resolved authority
 *     chain root for this subject. Empty when the subject is unresolved.
 *     Three states the chain can carry:
 *       `root`: the URI of the root grant, e.g. "spiffe://muveraai.com/ns/ops/sa/admin".
 *       `delegations`: number of hops from the root grant to the subject.
 *       `state`: "enforced" | "mediated" | "observed" | "unresolved".
 *   `payload.data.agents[i].tier` — string. The strongest tier the agent's
 *     warrants advertise (enforced/mediated/observed), exactly the same
 *     vocabulary the queue and coverage panes render. A subject whose
 *     warrants advertise "observed" never renders as enforced, even if
 *     the operator believes otherwise — the warrant's bound strengths
 *     are the source of truth.
 *   `payload.data.agents[i].coverage_limits[]` — array of strings. The
 *     sentences that name what the agent is NOT covered for, one per
 *     warrant. A subject whose warrants all carry "no coverage" limits
 *     renders the limits beside the row, never collapses them into a
 *     single green tick.
 *   `payload.data.agents[i].unresolved` — boolean. True when the subject
 *     could not be pinned to any authority chain. The renderer surfaces
 *     this as `unresolved`, never as `unrestricted`. An agent that the
 *     console cannot resolve is not the same fact as an agent that the
 *     store permits anything — those are different failures with the same
 *     blast radius.
 *
 * # The rule that overrides any design instinct
 *
 * No surface in this product collapses observed, advisory, mediated and
 * enforced into one green state. The fleet register therefore carries a
 * `tier` per agent and a `coverage_limits` list, and the renderer shows
 * `unresolved` as its own state. A register that showed every agent with a
 * green tick would be a nameplate, not a register — exactly the failure
 * the task anchor names.
 */

// ── the additive contract (single source of truth) ───────────────────────

/**
 * One agent in the register. The renderer reads each field; absent fields
 * render as `unresolved`, never as a default.
 */
export const AGENT_SHAPE = Object.freeze({
  subject: 'string — spiffe:// URI or a name the store recorded',
  warrant_ids: 'array of strings — warrant ids this subject owns',
  authority: 'object — { root, delegations, state } or empty when unresolved',
  tier: 'one of "enforced" | "mediated" | "observed" | "unresolved"',
  coverage_limits: 'array of strings — what this agent is NOT covered for',
  unresolved: 'boolean — true when authority could not be pinned',
});

/**
 * An agent with two warrants, both anchored-and-valid, tier "enforced".
 *
 * The fixture's warrants are the same shape the existing console's
 * `listFacts` reads from `payload.data.warrants`. The fleet's grouping
 * is a server-side fold; the console does not re-group client-side,
 * because a console that recomputed the tier from the warrants would
 * be a second implementation of the warrant tier vocabulary, and the
 * two would drift the first time either changed.
 */
export const resolvedAgent = Object.freeze({
  subject: 'spiffe://muveraai.com/agent/alpha',
  warrant_ids: ['wrt_0000000000000001', 'wrt_0000000000000002'],
  authority: {
    root: 'spiffe://muveraai.com/ns/ops/sa/admin',
    delegations: 1,
    state: 'enforced',
  },
  tier: 'enforced',
  coverage_limits: [
    'wrt_0000000000000001: the budget is observed, not enforced — spend beyond 500 cents is recorded, not refused',
    'wrt_0000000000000002: the egress allowlist is mediated, refused by the broker the tool calls pass through',
  ],
  unresolved: false,
});

/**
 * An agent with one warrant, mediated by the broker. Tier "mediated".
 *
 * The tier word is "mediated" because the warrant's strongest bound
 * strength is mediated (the egress allowlist is broker-mediated), even
 * though the warrant's deadline is enforced. The fleet register surfaces
 * the strongest tier across the agent's warrants, not the strongest
 * single bound.
 */
export const mediatedAgent = Object.freeze({
  subject: 'spiffe://muveraai.com/agent/beta',
  warrant_ids: ['wrt_0000000000000003'],
  authority: {
    root: 'spiffe://muveraai.com/ns/ops/sa/admin',
    delegations: 2,
    state: 'mediated',
  },
  tier: 'mediated',
  coverage_limits: [
    'wrt_0000000000000003: the tool allowlist is broker-mediated; what does not go through the broker is not decided by it',
  ],
  unresolved: false,
});

/**
 * An agent whose authority could not be resolved. Tier "unresolved".
 *
 * The plan is explicit: "an agent whose authority cannot be resolved
 * renders as `unresolved`, not as unrestricted." An unresolved authority
 * is not the same fact as an unrestricted agent — those are different
 * failures with the same blast radius, and the renderer's job is to
 * distinguish them in prose, on the page, every time.
 */
export const unresolvedAgent = Object.freeze({
  subject: 'spiffe://muveraai.com/agent/gamma',
  warrant_ids: ['wrt_0000000000000004'],
  authority: {},
  tier: 'unresolved',
  coverage_limits: [
    'wrt_0000000000000004: authority could not be pinned to a root grant',
  ],
  unresolved: true,
});

/**
 * An agent with observed-only bounds. Tier "observed".
 *
 * The agent's warrants advertise observed-only bounds (e.g. spend
 * tracking). The renderer's job is to surface this as observed, never
 * as enforced, even though the agent has warrants and is therefore
 * "running". The tier word the warrant carries is the tier word the
 * page shows.
 */
export const observedAgent = Object.freeze({
  subject: 'spiffe://muveraai.com/agent/delta',
  warrant_ids: ['wrt_0000000000000005'],
  authority: {
    root: 'spiffe://muveraai.com/ns/ops/sa/admin',
    delegations: 1,
    state: 'observed',
  },
  tier: 'observed',
  coverage_limits: [
    'wrt_0000000000000005: spend is observed, not refused as it happens',
    'wrt_0000000000000005: write paths are observed, not enforced',
  ],
  unresolved: false,
});

/**
 * Every fixture in one list, in the order the register renders them.
 * The order is by tier strength: enforced first, then mediated, then
 * observed, then unresolved last. An ordering the renderer overrides
 * would be a renderer that hides the unresolved row; the rules say it
 * cannot.
 */
export const fleetFixtures = Object.freeze([
  resolvedAgent,
  mediatedAgent,
  observedAgent,
  unresolvedAgent,
]);