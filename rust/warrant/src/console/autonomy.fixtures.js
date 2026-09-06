/**
 * Frozen fixtures for the safe-autonomy expansion ledger (L8-20, L8-24) —
 * Task 11.11.
 *
 * # Why this file exists
 *
 * The autonomy ledger is the surface that pins the rule "autonomy should
 * widen on evidence and narrow on incident, and both directions must be
 * receipted." A ledger that records widening but not narrowing is a growth
 * chart. The pane reads from `/v1/autonomy-ledger` and renders every
 * event with the same shape, the same color discipline, and the same
 * prominence regardless of direction.
 *
 * The ledger is a RENDERING of the dial's receipts (8.2), not a distinct
 * record. The dial already records both directions; the ledger is the
 * view that surfaces the receipts so a reader can audit each one. The
 * distinction matters because two mechanisms that record the same fact
 * would drift the first time either changed — the failure the queue's
 * `you_can` discipline exists to prevent.
 *
 * # What this file freezes
 *
 *   `autonomyFixtures.ledgers` — three ledger readings:
 *     - balanced: widening and narrowing in roughly equal count.
 *     - widen-only: a growth chart (a widening streak with no narrowing).
 *       A future regression that hid narrowing would render this
 *       without saying so, and the test that pins equal prominence
 *       would catch it.
 *     - narrow-only: a tightening streak with no widening. The same
 *       discipline applies in reverse: a tightening streak is just
 *       as much a chart as a widening one.
 *   `autonomyFixtures.wideningCases` — a set of widening entries that
 *     must be accepted or refused, and a set that must be refused for
 *     missing evidence or missing narrowing path. The test iterates the
 *     set and pins the verdict for every entry.
 *   `autonomyFixtures.directionOrder` — the order the pane renders
 *     widening and narrowing within a single time window. The test
 *     pins the order: chronologically, with widening and narrowing
 *     interleaved by date, NOT grouped by direction. A pane that
 *     grouped widening first would be the growth chart.
 *   `autonomyFixtures.baselineCases` — outcome contracts with and
 *     without a baseline. A contract without a baseline is refused at
 *     creation (the contract is a comparison, and a comparison
 *     without a reference is a number).
 *
 * # The rule that overrides any design instinct
 *
 * "A ledger that records widening but not narrowing is a growth chart."
 * Every entry renders with the same shape: a direction pill, a date, a
 * warrant, evidence, a baseline, an outcome metric, and (for widening) a
 * narrowing path. The two pills (`pill-widen` and `pill-narrow`) carry
 * the same color weight in CSS — neither is green-by-default, neither
 * is hidden-by-default. The headline counts both directions in the same
 * sentence, with the count itself rendered as prose.
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

/** A widening entry: a single event where autonomy was loosened.
 *  Carries the evidence it rests on and the narrowing path the system
 *  has agreed to take if the evidence weakens. */
const WIDEN_RECEIPT_KIND = 'widen';
/** A narrowing entry: a single event where autonomy was tightened.
 *  Carries the trigger incident and the bound it touched. */
const NARROW_RECEIPT_KIND = 'narrow';

const ledgers = frozen([
  frozen({
    kind: 'fixture',
    label: 'balanced ledger with widening and narrowing interleaved',
    ledger: {
      window: { since: '2026-08-01T00:00:00Z', until: '2026-09-01T00:00:00Z' },
      entries: [
        {
          id: 'au_0000000000000001',
          direction: 'widen',
          at: '2026-08-04T12:00:00Z',
          warrant_id: 'wrt_0000000000000001',
          bound: 'tool:read',
          evidence_receipts: ['rcp_aaaa1111', 'rcp_aaaa2222'],
          baseline_metric: 'disagreement_rate',
          baseline_value: 0.082,
          outcome_metric: 'disagreement_rate',
          outcome_value: 0.041,
          narrowing_path: 'if_disagreement_exceeds_0.10',
        },
        {
          id: 'au_0000000000000002',
          direction: 'narrow',
          at: '2026-08-09T18:30:00Z',
          warrant_id: 'wrt_0000000000000001',
          bound: 'tool:read',
          trigger: 'incident_2026_08_09',
          receipts: ['rcp_bbbb1111'],
        },
        {
          id: 'au_0000000000000003',
          direction: 'widen',
          at: '2026-08-15T09:00:00Z',
          warrant_id: 'wrt_0000000000000002',
          bound: 'tool:net',
          evidence_receipts: ['rcp_cccc1111'],
          baseline_metric: 'false_denial_rate',
          baseline_value: 0.014,
          outcome_metric: 'false_denial_rate',
          outcome_value: 0.007,
          narrowing_path: 'if_false_denial_exceeds_0.05',
        },
        {
          id: 'au_0000000000000004',
          direction: 'narrow',
          at: '2026-08-22T14:15:00Z',
          warrant_id: 'wrt_0000000000000002',
          bound: 'tool:net',
          trigger: 'incident_2026_08_22',
          receipts: ['rcp_dddd1111'],
        },
      ],
    },
    expected_widen_count: 2,
    expected_narrow_count: 2,
  }),
  frozen({
    kind: 'fixture',
    label: 'widen-only streak (a growth chart, refused by the pane)',
    ledger: {
      window: { since: '2026-08-01T00:00:00Z', until: '2026-09-01T00:00:00Z' },
      entries: [
        {
          id: 'au_0000000000000011',
          direction: 'widen',
          at: '2026-08-04T12:00:00Z',
          warrant_id: 'wrt_0000000000000001',
          bound: 'tool:read',
          evidence_receipts: ['rcp_eeee1111'],
          baseline_metric: 'disagreement_rate',
          baseline_value: 0.080,
          outcome_metric: 'disagreement_rate',
          outcome_value: 0.040,
          narrowing_path: 'if_disagreement_exceeds_0.10',
        },
        {
          id: 'au_0000000000000012',
          direction: 'widen',
          at: '2026-08-15T09:00:00Z',
          warrant_id: 'wrt_0000000000000002',
          bound: 'tool:net',
          evidence_receipts: ['rcp_ffff1111'],
          baseline_metric: 'false_denial_rate',
          baseline_value: 0.012,
          outcome_metric: 'false_denial_rate',
          outcome_value: 0.006,
          narrowing_path: 'if_false_denial_exceeds_0.05',
        },
      ],
    },
    expected_widen_count: 2,
    expected_narrow_count: 0,
  }),
  frozen({
    kind: 'fixture',
    label: 'narrow-only streak (a tightening chart, rendered with equal prominence)',
    ledger: {
      window: { since: '2026-08-01T00:00:00Z', until: '2026-09-01T00:00:00Z' },
      entries: [
        {
          id: 'au_0000000000000021',
          direction: 'narrow',
          at: '2026-08-04T12:00:00Z',
          warrant_id: 'wrt_0000000000000001',
          bound: 'tool:read',
          trigger: 'incident_2026_08_04',
          receipts: ['rcp_gggg1111'],
        },
        {
          id: 'au_0000000000000022',
          direction: 'narrow',
          at: '2026-08-15T09:00:00Z',
          warrant_id: 'wrt_0000000000000002',
          bound: 'tool:net',
          trigger: 'incident_2026_08_15',
          receipts: ['rcp_hhhh1111'],
        },
      ],
    },
    expected_widen_count: 0,
    expected_narrow_count: 2,
  }),
]);

/** Widening cases. The pane refuses a widening entry that does not
 *  carry evidence or a narrowing path. */
const wideningCases = frozen([
  frozen({
    kind: 'fixture',
    label: 'widening with evidence and narrowing path is accepted',
    entry: {
      id: 'au_0000000000000101',
      direction: 'widen',
      at: '2026-08-04T12:00:00Z',
      warrant_id: 'wrt_0000000000000001',
      bound: 'tool:read',
      evidence_receipts: ['rcp_11112222'],
      baseline_metric: 'disagreement_rate',
      baseline_value: 0.080,
      outcome_metric: 'disagreement_rate',
      outcome_value: 0.040,
      narrowing_path: 'if_disagreement_exceeds_0.10',
    },
    accepted: true,
  }),
  frozen({
    kind: 'fixture',
    label: 'widening without evidence is refused',
    entry: {
      id: 'au_0000000000000102',
      direction: 'widen',
      at: '2026-08-04T12:00:00Z',
      warrant_id: 'wrt_0000000000000001',
      bound: 'tool:read',
      evidence_receipts: [],
      baseline_metric: 'disagreement_rate',
      baseline_value: 0.080,
      outcome_metric: 'disagreement_rate',
      outcome_value: 0.040,
      narrowing_path: 'if_disagreement_exceeds_0.10',
    },
    accepted: false,
    refusal_substring: 'evidence',
  }),
  frozen({
    kind: 'fixture',
    label: 'widening without a narrowing path is refused',
    entry: {
      id: 'au_0000000000000103',
      direction: 'widen',
      at: '2026-08-04T12:00:00Z',
      warrant_id: 'wrt_0000000000000001',
      bound: 'tool:read',
      evidence_receipts: ['rcp_11113333'],
      baseline_metric: 'disagreement_rate',
      baseline_value: 0.080,
      outcome_metric: 'disagreement_rate',
      outcome_value: 0.040,
      narrowing_path: '',
    },
    accepted: false,
    refusal_substring: 'narrowing',
  }),
  frozen({
    kind: 'fixture',
    label: 'widening without a baseline is refused',
    entry: {
      id: 'au_0000000000000104',
      direction: 'widen',
      at: '2026-08-04T12:00:00Z',
      warrant_id: 'wrt_0000000000000001',
      bound: 'tool:read',
      evidence_receipts: ['rcp_11114444'],
      baseline_metric: '',
      baseline_value: null,
      outcome_metric: 'disagreement_rate',
      outcome_value: 0.040,
      narrowing_path: 'if_disagreement_exceeds_0.10',
    },
    accepted: false,
    refusal_substring: 'baseline',
  }),
]);

/** Baseline cases. A contract without a baseline metric or value is
 *  refused at creation: a comparison without a reference is a number. */
const baselineCases = frozen([
  frozen({
    kind: 'fixture',
    label: 'contract with a complete baseline is accepted',
    baseline: {
      metric: 'disagreement_rate',
      value: 0.080,
      window: { since: '2026-07-01T00:00:00Z', until: '2026-08-01T00:00:00Z' },
    },
    accepted: true,
  }),
  frozen({
    kind: 'fixture',
    label: 'contract without a metric is refused',
    baseline: {
      metric: '',
      value: 0.080,
      window: { since: '2026-07-01T00:00:00Z', until: '2026-08-01T00:00:00Z' },
    },
    accepted: false,
    refusal_substring: 'metric',
  }),
  frozen({
    kind: 'fixture',
    label: 'contract without a value is refused',
    baseline: {
      metric: 'disagreement_rate',
      value: null,
      window: { since: '2026-07-01T00:00:00Z', until: '2026-08-01T00:00:00Z' },
    },
    accepted: false,
    refusal_substring: 'value',
  }),
  frozen({
    kind: 'fixture',
    label: 'empty contract is refused',
    baseline: {},
    accepted: false,
    refusal_substring: 'metric',
  }),
]);

export const autonomyFixtures = Object.freeze({
  kind: 'fixture',
  WIDEN_RECEIPT_KIND,
  NARROW_RECEIPT_KIND,
  ledgers,
  wideningCases,
  baselineCases,
});
