/**
 * Frozen fixtures for the executive risk view (L8-07, L8-21) — Task 11.10.
 *
 * # Why this file exists
 *
 * The executive view is the surface where the strongest tier is the most
 * misleading. A "100% enforced" dial computed from controls that are Tier C
 * observed is the failure the plan names verbatim. The view must render the
 * WEAKEST tier among its inputs, never an average, and it must surface
 * unmediated coverage (orphaned crates from `evidence/wiring-coverage.json`)
 * as part of every exposure figure.
 *
 * Three feeds compose the view, and the studio must not recompute any of them:
 *   1. Task 8.2 — the runtime risk dial. Carries a per-bound tier and a
 *      posture; carries an `enforced` number or `advisory` for risk appetite.
 *   2. Task 8.4 — the population budget ledger. Carries the
 *      mediated / observed / unmediated split per coverage class.
 *   3. The wiring census (`evidence/wiring-coverage.json`). Carries the
 *      reachable set and the orphaned set, which the view surfaces as the
 *      "exposure figure" — the operator's eye lands here first.
 *
 * The fixtures freeze the three feeds' shapes, plus a small set of roll-up
 * cases that pin the "weakest input tier wins" discipline. A future change
 * to the roll-up logic that reintroduced averaging would be caught by the
 * iteration test.
 *
 * # What this file freezes
 *
 *   `executiveFixtures.dialFixtures` — three dial readings: enforced
 *     appetite, advisory appetite, and a multi-bound roll-up that must
 *     surface the weakest tier.
 *   `executiveFixtures.budgetFixtures` — three population-budget readings:
 *     all-mediated, mixed (where observed is the weakest), and partial
 *     (where unmediated is the weakest and the figure must say so).
 *   `executiveFixtures.censusFixture` — one wiring census read that
 *     mirrors `evidence/wiring-coverage.json` shape; the studio uses it to
 *     surface orphaned coverage as part of every exposure figure.
 *   `executiveFixtures.rollupCases` — a small set of input-tier tuples
 *     with the expected weakest-tier output. Iterated by the test.
 *
 * # The rule that overrides any design instinct
 *
 * "The strongest tier is the most dangerous word in this view." Every
 * aggregate renders the WEAKEST input tier in BOTH the pill class and a
 * prose sentence. A roll-up whose inputs are [enforced, mediated,
 * observed] never renders as enforced, never as mediated, and never as
 * an average. It renders as `observed`, and the prose sentence names
 * the three inputs so a reader can see why.
 */

const frozen = (value) => {
  Object.freeze(value);
  if (Array.isArray(value)) {
    for (const item of value) {
      if (item && typeof item === 'object') Object.freeze(item);
    }
  }
  return value;
};

/** Dial readings (8.2). The `appetite_enforced` flag is the load-bearing
 *  field: when false, the view renders the budget number as `advisory`,
 *  not as a number the system enforces. */
const dialFixtures = frozen([
  frozen({
    kind: 'fixture',
    label: 'dial with an enforced risk appetite and one bound per posture',
    dial: {
      appetite_enforced: true,
      appetite_ceiling: 0.05,
      posture: 'tighten',
      bounds: [
        { id: 'egress', tier: 'enforced', strength: 0.92 },
        { id: 'tool:net', tier: 'mediated', strength: 0.74 },
        { id: 'spend', tier: 'observed', strength: 0.61 },
      ],
    },
    expected_rollup_tier: 'observed',
    expected_appetite_phrase: 'enforced ceiling 5%',
  }),
  frozen({
    kind: 'fixture',
    label: 'dial with an advisory appetite (no enforced number)',
    dial: {
      appetite_enforced: false,
      appetite_ceiling: null,
      posture: 'observe',
      bounds: [
        { id: 'egress', tier: 'mediated', strength: 0.74 },
      ],
    },
    expected_rollup_tier: 'mediated',
    expected_appetite_phrase: 'advisory',
  }),
  frozen({
    kind: 'fixture',
    label: 'dial with all-enforced bounds (a real strongest word)',
    dial: {
      appetite_enforced: true,
      appetite_ceiling: 0.10,
      posture: 'tighten',
      bounds: [
        { id: 'deadline', tier: 'enforced', strength: 1.0 },
        { id: 'delegation', tier: 'enforced', strength: 1.0 },
      ],
    },
    expected_rollup_tier: 'enforced',
    expected_appetite_phrase: 'enforced ceiling 10%',
  }),
]);

/** Population-budget readings (8.4). Each carries a per-class split between
 *  mediated, observed, and unmediated. The studio does not compute the
 *  split; it renders what 8.4 already said. */
const budgetFixtures = frozen([
  frozen({
    kind: 'fixture',
    label: 'all-mediated population',
    budget: {
      mediated: 1240,
      observed: 0,
      unmediated: 0,
      window: { since: '2026-08-01T00:00:00Z', until: '2026-09-01T00:00:00Z' },
    },
    expected_rollup_tier: 'mediated',
    expected_unmediated_phrase: '0 unmediated',
  }),
  frozen({
    kind: 'fixture',
    label: 'mixed population with observed as the weakest',
    budget: {
      mediated: 1240,
      observed: 312,
      unmediated: 0,
      window: { since: '2026-08-01T00:00:00Z', until: '2026-09-01T00:00:00Z' },
    },
    expected_rollup_tier: 'observed',
    expected_unmediated_phrase: '0 unmediated',
  }),
  frozen({
    kind: 'fixture',
    label: 'partial population with unmediated present',
    budget: {
      mediated: 1240,
      observed: 312,
      unmediated: 47,
      window: { since: '2026-08-01T00:00:00Z', until: '2026-09-01T00:00:00Z' },
    },
    expected_rollup_tier: 'unknown',
    expected_unmediated_phrase: 'unmediated',
  }),
]);

/** Census (wiring-coverage.json). The studio reads `reachable`, `orphaned`,
 *  and the orphaned names so the view can name them by name. The fixture
 *  is a snapshot of the live census at 2026-09-06, frozen for the test. */
const censusFixture = frozen({
  kind: 'fixture',
  total: 41,
  reachable: 13,
  edges: 23,
  orphaned: frozen([
    'defstack-cli',
    'warrantor-agent-manifest',
    'warrantor-archive',
    'warrantor-computer-use',
    'warrantor-confidential-fabric',
    'warrantor-content-moderation',
    'warrantor-csam-defense',
    'warrantor-data-plane',
    'warrantor-eval-guard',
    'warrantor-exfil-guard',
    'warrantor-flight-recorder',
    'warrantor-gguf-ext',
    'warrantor-inference-proxy',
    'warrantor-kill-switch',
    'warrantor-misinformation-defense',
    'warrantor-nvtrust-bridge',
    'warrantor-plugin-api',
    'warrantor-policy-bridge',
    'warrantor-post-quantum',
    'warrantor-protocol-contracts',
    'warrantor-provena-chain',
    'warrantor-reputation',
    'warrantor-responsible-ai',
    'warrantor-retrieval',
    'warrantor-safe-tensors-pp',
    'warrantor-sandbox-runtime',
    'warrantor-secure-workspace',
    'warrantor-self-governance',
  ]),
  expected_unmediated_phrase: '28 orphaned of 41 crates',
});

/** Roll-up cases. Each carries an `inputs` array of tier words and the
 *  expected `weakest` output. The studio must never average these. */
const rollupCases = frozen([
  frozen({ kind: 'fixture', label: 'enforced only', inputs: ['enforced'], weakest: 'enforced' }),
  frozen({ kind: 'fixture', label: 'enforced + mediated', inputs: ['enforced', 'mediated'], weakest: 'mediated' }),
  frozen({ kind: 'fixture', label: 'enforced + observed', inputs: ['enforced', 'observed'], weakest: 'observed' }),
  frozen({ kind: 'fixture', label: 'mediated + observed', inputs: ['mediated', 'observed'], weakest: 'observed' }),
  frozen({ kind: 'fixture', label: 'all three', inputs: ['enforced', 'mediated', 'observed'], weakest: 'observed' }),
  frozen({ kind: 'fixture', label: 'observed only', inputs: ['observed'], weakest: 'observed' }),
  frozen({ kind: 'fixture', label: 'mediated only', inputs: ['mediated'], weakest: 'mediated' }),
  // An unknown tier must NOT be coerced to the strongest; the helper falls
  // through to a "not stated" sentence, which the prose layer renders. The
  // test pins that unknown is treated as weaker-than-observed, because
  // a tier the server did not name is weaker than any tier it did.
  frozen({ kind: 'fixture', label: 'unknown only', inputs: ['unknown'], weakest: 'unknown' }),
  frozen({ kind: 'fixture', label: 'enforced + unknown', inputs: ['enforced', 'unknown'], weakest: 'unknown' }),
]);

/** Tier ordering. The weakest tier has the lowest strength; the studio
 *  uses this to find the minimum. A future tier added to the ladder
 *  (e.g. a new "aspirational" tier) would slot in here and the tests
 *  would catch a regression that demoted an existing tier. */
const TIER_ORDER = frozen(['enforced', 'mediated', 'observed', 'unknown']);

export const executiveFixtures = Object.freeze({
  kind: 'fixture',
  TIER_ORDER,
  dialFixtures,
  budgetFixtures,
  censusFixture,
  rollupCases,
});
