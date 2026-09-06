/**
 * Frozen fixtures for notice, rights, appeal, and contestability
 * (L8-19, L8-16) — Task 11.12.
 *
 * # Why this file exists
 *
 * "The affected party is not the operator." The notice pane is the only
 * surface in the estate built for someone outside the buying
 * organization. Every design instinct in the rest of the phase — serve
 * the operator, render the fleet — is wrong here. The pane must:
 *
 *   - render the decision that concerned the affected party;
 *   - render the decision's basis, not just the outcome;
 *   - offer a contest route the affected party can reach without a
 *     terminal;
 *   - render role competency per approver, with `unassessed` as a
 *     visible state, never as "OK";
 *   - refuse cross-party disclosure, so a query for one affected
 *     party never reveals another party's data.
 *
 * # What this file freezes
 *
 *   `noticeFixtures.decisionReadings` — three readings of the
 *     affected-party feed:
 *       - one party with one decision carrying a basis and a contest
 *         route and a fully-assessed approver;
 *       - one party with two decisions, one with a basis and a
 *         contest route, one missing a basis (rendered as
 *         "basis: not stated");
 *       - one party with one decision whose approver is
 *         `unassessed` (rendered visibly as unassessed, not as
 *         "OK").
 *   `noticeFixtures.crossPartyCases` — fixtures that pin the
 *     cross-party disclosure refusal. A query for one affected party
 *     that includes another party's record is refused at the helper
 *     level. The test iterates the cases and pins the verdict.
 *   `noticeFixtures.roleCompetencyCases` — fixtures that pin the
 *     role competency rendering. An approver whose competency is
 *     `unassessed` is rendered as such, not as "OK". An approver
 *     whose competency is `expired` is rendered as such, not as
 *     "assessed".
 *   `noticeFixtures.contestRouteCases` — fixtures that pin the
 *     contest route. A decision without a contest route is
 *     rendered as "no contest route", never as a misleading link.
 *     A decision with a contest route is rendered as a button the
 *     affected party can reach without a terminal.
 *
 * # The rule that overrides any design instinct
 *
 * "The affected party is not the operator." A pane that treated
 * the affected party like an operator — showing them the full
 * receipt graph, the agent inventory, the wiring census — would
 * disclose another party's data. The cross-party disclosure test
 * pins the refusal; a future change that let the pane render a
 * record from another party would surface here.
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

/** Decision status words the pane recognizes. A decision whose
 *  status is anything else is rendered as "unknown". */
const DECISION_STATUS_PENDING = 'pending';
const DECISION_STATUS_DECIDED = 'decided';
const DECISION_STATUS_CONTESTED = 'contested';

/** Role competency status words. An approver whose status is
 *  `unassessed` or `expired` is rendered visibly as such. */
const COMPETENCY_ASSESSED = 'assessed';
const COMPETENCY_UNASSESSED = 'unassessed';
const COMPETENCY_EXPIRED = 'expired';

const decisionReadings = frozen([
  frozen({
    kind: 'fixture',
    label: 'one party, one fully-receipted decision, contest route, assessed approver',
    affected_party_id: 'ap-1',
    feed: {
      data: [
        {
          id: 'd-1',
          affected_party_id: 'ap-1',
          decision: 'warrant denied',
          basis: 'r-7',
          rule: 'rule-3.1',
          status: DECISION_STATUS_DECIDED,
          approver: 'approver-A',
          approver_competency: COMPETENCY_ASSESSED,
          contest_url: 'https://example.test/contest/d-1',
        },
      ],
    },
    expected: {
      decision_count: 1,
      has_unassessed: false,
      has_expired: false,
      has_no_basis: false,
      has_no_contest_route: false,
    },
  }),
  frozen({
    kind: 'fixture',
    label: 'one party, two decisions, one missing a basis (rendered visibly as "basis: not stated")',
    affected_party_id: 'ap-2',
    feed: {
      data: [
        {
          id: 'd-2',
          affected_party_id: 'ap-2',
          decision: 'warrant approved',
          basis: 'r-12',
          rule: 'rule-5.2',
          status: DECISION_STATUS_DECIDED,
          approver: 'approver-B',
          approver_competency: COMPETENCY_ASSESSED,
          contest_url: 'https://example.test/contest/d-2',
        },
        {
          id: 'd-3',
          affected_party_id: 'ap-2',
          decision: 'warrant approved with condition',
          basis: '',
          rule: '',
          status: DECISION_STATUS_DECIDED,
          approver: 'approver-C',
          approver_competency: COMPETENCY_ASSESSED,
          contest_url: 'https://example.test/contest/d-3',
        },
      ],
    },
    expected: {
      decision_count: 2,
      has_unassessed: false,
      has_expired: false,
      has_no_basis: true,
      has_no_contest_route: false,
    },
  }),
  frozen({
    kind: 'fixture',
    label: 'one party, one decision whose approver is unassessed (rendered visibly)',
    affected_party_id: 'ap-3',
    feed: {
      data: [
        {
          id: 'd-4',
          affected_party_id: 'ap-3',
          decision: 'warrant approved',
          basis: 'r-22',
          rule: 'rule-2.1',
          status: DECISION_STATUS_DECIDED,
          approver: 'approver-D',
          approver_competency: COMPETENCY_UNASSESSED,
          contest_url: 'https://example.test/contest/d-4',
        },
      ],
    },
    expected: {
      decision_count: 1,
      has_unassessed: true,
      has_expired: false,
      has_no_basis: false,
      has_no_contest_route: false,
    },
  }),
]);

/** Cross-party disclosure cases. A query for one affected party
 *  that includes another party's record is refused at the helper
 *  level. The test iterates these and pins the verdict. */
const crossPartyCases = frozen([
  frozen({
    kind: 'fixture',
    label: 'a feed that contains a record from another party is refused',
    affected_party_id: 'ap-1',
    feed: {
      data: [
        {
          id: 'd-1',
          affected_party_id: 'ap-1',
          decision: 'warrant denied',
          basis: 'r-7',
          rule: 'rule-3.1',
          status: DECISION_STATUS_DECIDED,
          approver: 'approver-A',
          approver_competency: COMPETENCY_ASSESSED,
          contest_url: 'https://example.test/contest/d-1',
        },
        {
          id: 'd-2',
          affected_party_id: 'ap-9',
          decision: 'warrant approved for someone else',
          basis: 'r-99',
          rule: 'rule-9.9',
          status: DECISION_STATUS_DECIDED,
          approver: 'approver-Z',
          approver_competency: COMPETENCY_ASSESSED,
          contest_url: 'https://example.test/contest/d-2',
        },
      ],
    },
    refused: true,
  }),
  frozen({
    kind: 'fixture',
    label: 'a feed that contains only the queried party is accepted',
    affected_party_id: 'ap-1',
    feed: {
      data: [
        {
          id: 'd-1',
          affected_party_id: 'ap-1',
          decision: 'warrant denied',
          basis: 'r-7',
          rule: 'rule-3.1',
          status: DECISION_STATUS_DECIDED,
          approver: 'approver-A',
          approver_competency: COMPETENCY_ASSESSED,
          contest_url: 'https://example.test/contest/d-1',
        },
      ],
    },
    refused: false,
  }),
]);

/** Role competency cases. An approver whose competency is
 *  `unassessed` is rendered visibly as such, not as "OK". An
 *  approver whose competency is `expired` is rendered visibly as
 *  such, not as "assessed". */
const roleCompetencyCases = frozen([
  frozen({
    kind: 'fixture',
    label: 'an approver whose competency is `assessed` is rendered as assessed',
    competency: COMPETENCY_ASSESSED,
    render: 'assessed',
  }),
  frozen({
    kind: 'fixture',
    label: 'an approver whose competency is `unassessed` is rendered as unassessed, never as OK',
    competency: COMPETENCY_UNASSESSED,
    render: 'unassessed',
  }),
  frozen({
    kind: 'fixture',
    label: 'an approver whose competency is `expired` is rendered as expired, never as assessed',
    competency: COMPETENCY_EXPIRED,
    render: 'expired',
  }),
]);

/** Contest route cases. A decision without a contest route is
 *  rendered as "no contest route", never as a misleading link. A
 *  decision with a contest route is rendered as a button the
 *  affected party can reach without a terminal. */
const contestRouteCases = frozen([
  frozen({
    kind: 'fixture',
    label: 'a decision with a contest route renders the route visibly',
    decision: {
      id: 'd-1',
      contest_url: 'https://example.test/contest/d-1',
    },
    has_contest_route: true,
  }),
  frozen({
    kind: 'fixture',
    label: 'a decision without a contest route renders "no contest route", never a misleading link',
    decision: {
      id: 'd-2',
      contest_url: '',
    },
    has_contest_route: false,
  }),
]);

export const noticeFixtures = Object.freeze({
  kind: 'fixture',
  DECISION_STATUS_PENDING,
  DECISION_STATUS_DECIDED,
  DECISION_STATUS_CONTESTED,
  COMPETENCY_ASSESSED,
  COMPETENCY_UNASSESSED,
  COMPETENCY_EXPIRED,
  decisionReadings,
  crossPartyCases,
  roleCompetencyCases,
  contestRouteCases,
});
