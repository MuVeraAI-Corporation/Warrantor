/**
 * Frozen fixtures for the supervisor/regulator portal and the customer
 * trust center (L8-06, L8-28) — Task 11.9.
 *
 * # Why this file exists
 *
 * "Both are read-only views of the same receipts. If they can disagree,
 * one of them is a marketing surface." Every figure the trust center
 * shows is reachable from the portal with the same value, because both
 * panes consume the same `portalFigures()` helper. A trust center that
 * derived its own numbers — even with a smoothing factor or a "look
 * better" presentation — would be a marketing surface, and the
 * differential test would catch it on the first render.
 *
 * The portal is the supervisor's view. The trust center is the prospect's
 * view. Both render the same figures; what differs is the prose around
 * them. The supervisor sees the figures with the receipts behind them;
 * the prospect sees the figures with the assurance language the
 * supervisor would audit. Same numbers, two renderings, one helper.
 *
 * # What this file freezes
 *
 *   `portalFixtures.feedReadings` — three readings of the underlying
 *     feed graph that the portal and the trust center read from:
 *       - one operator with one fully-receipted warrant and one pack;
 *       - one operator with three warrants and two packs and a gap;
 *       - one operator with zero warrants and zero packs (empty estate).
 *     The portal renders the figures; the trust center renders the same
 *     figures; the differential test asserts both renderers produce the
 *     same number for each figure on each reading.
 *   `portalFigures` — the pure function the fixtures pin. Given a feed
 *     graph, the function returns the figures the portal and the trust
 *     center both render. The trust center never has its own
 *     implementation of the figures; a future change that introduced one
 *     would be caught by the differential test.
 *   `portalFixtures.prospectEligibility` — the rules a prospect must
 *     satisfy to see the trust center at all. A prospect who is not
 *     certified under any of the regulatory anchors sees "not eligible",
 *     not a partial figure.
 *   `portalFixtures.filteredViewCases` — cases that pin the rule that
 *     neither surface can show a filtered view that verifies. A filter
 *     that would surface "all OK" while the underlying graph has gaps is
 *     refused at the helper level.
 *
 * # The rule that overrides any design instinct
 *
 * "Both are read-only views of the same receipts. If they can disagree,
 * one of them is a marketing surface." A trust center that hid a
 * 1-pack-to-0-warrant gap to look more reassuring would be the
 * marketing surface the discipline prevents. The fixture pins the gap
 * and the test asserts the figure is the same in both renderings.
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

/** Status words the portal and trust center recognise for a feed.
 *  A feed whose status is anything else is rendered as "unknown". */
const FEED_STATUS_OK = 'ok';
const FEED_STATUS_GAP = 'gap';
const FEED_STATUS_EMPTY = 'empty';
const FEED_STATUS_UNKNOWN = 'unknown';

/** Anchor eligibility. A prospect's anchor is the regulatory framework
 *  that authorizes them to read the trust center at all. The fixtures
 *  pin three anchors — US, India, Gulf — and the trust center refuses
 *  a prospect whose anchor is not in the list. The EU is a passing
 *  mention only. */
const ANCHOR_US = 'US';
const ANCHOR_INDIA = 'India';
const ANCHOR_GULF = 'Gulf';
const ANCHOR_EU_PASSING = 'EU-passing-mention-only';

const feedReadings = frozen([
  frozen({
    kind: 'fixture',
    label: 'one operator, one fully-receipted warrant, one pack',
    feeds: {
      warrants: { status: FEED_STATUS_OK, data: [{ id: 'w1' }] },
      packs: { status: FEED_STATUS_OK, data: [{ id: 'p1', receipts: [{ id: 'r1' }] }] },
    },
    expected: {
      warrant_count: 1,
      pack_count: 1,
      receipt_count: 1,
      has_gap: false,
      feed_status: FEED_STATUS_OK,
    },
  }),
  frozen({
    kind: 'fixture',
    label: 'one operator, three warrants, two packs, one pack has no receipts',
    feeds: {
      warrants: { status: FEED_STATUS_OK, data: [{ id: 'w1' }, { id: 'w2' }, { id: 'w3' }] },
      packs: {
        status: FEED_STATUS_GAP,
        data: [
          { id: 'p1', receipts: [{ id: 'r1' }] },
          { id: 'p2', receipts: [] },
        ],
      },
    },
    expected: {
      warrant_count: 3,
      pack_count: 2,
      receipt_count: 1,
      has_gap: true,
      feed_status: FEED_STATUS_GAP,
    },
  }),
  frozen({
    kind: 'fixture',
    label: 'one operator, zero warrants, zero packs (empty estate)',
    feeds: {
      warrants: { status: FEED_STATUS_EMPTY, data: [] },
      packs: { status: FEED_STATUS_EMPTY, data: [] },
    },
    expected: {
      warrant_count: 0,
      pack_count: 0,
      receipt_count: 0,
      has_gap: false,
      feed_status: FEED_STATUS_EMPTY,
    },
  }),
]);

/** Prospect eligibility. A prospect whose anchor is in the list is
 *  eligible to see the trust center; a prospect whose anchor is not
 *  is shown "not eligible" and never a partial figure. The fixture
 *  iterates the cases and the test pins every verdict. */
const prospectEligibility = frozen([
  frozen({
    kind: 'fixture',
    label: 'a US prospect is eligible',
    anchor: ANCHOR_US,
    eligible: true,
  }),
  frozen({
    kind: 'fixture',
    label: 'an India prospect is eligible',
    anchor: ANCHOR_INDIA,
    eligible: true,
  }),
  frozen({
    kind: 'fixture',
    label: 'a Gulf prospect is eligible',
    anchor: ANCHOR_GULF,
    eligible: true,
  }),
  frozen({
    kind: 'fixture',
    label: 'an EU-only prospect is not eligible (passing mention only)',
    anchor: ANCHOR_EU_PASSING,
    eligible: false,
  }),
  frozen({
    kind: 'fixture',
    label: 'an unknown anchor is not eligible',
    anchor: 'Atlantis',
    eligible: false,
  }),
]);

/** Filtered-view cases. Neither surface can show a filtered view that
 *  verifies. The test iterates these and pins the refusal: any filter
 *  that would surface "all OK" while the underlying graph has gaps is
 *  refused at the helper level. The filter is applied to every record
 *  the portal would render — warrants and packs — so the predicate
 *  must be type-agnostic. Every fixture here uses a filter that keys
 *  on the record's `id`, which both warrants and packs carry. */
const filteredViewCases = frozen([
  frozen({
    kind: 'fixture',
    label: 'a filter that drops the gap pack is refused',
    feeds: {
      warrants: { status: FEED_STATUS_OK, data: [{ id: 'w1' }] },
      packs: {
        status: FEED_STATUS_GAP,
        data: [
          { id: 'p1', receipts: [{ id: 'r1' }] },
          { id: 'p2', receipts: [] },
        ],
      },
    },
    filter: (r) => r.id !== 'p2',
    refused: true,
  }),
  frozen({
    kind: 'fixture',
    label: 'a filter that drops a warrant is refused',
    feeds: {
      warrants: { status: FEED_STATUS_OK, data: [{ id: 'w1' }, { id: 'w2' }] },
      packs: { status: FEED_STATUS_OK, data: [{ id: 'p1', receipts: [{ id: 'r1' }] }] },
    },
    filter: (r) => r.id === 'w1',
    refused: true,
  }),
  frozen({
    kind: 'fixture',
    label: 'a no-op filter is accepted (the unfiltered view is itself a verification)',
    feeds: {
      warrants: { status: FEED_STATUS_OK, data: [{ id: 'w1' }] },
      packs: { status: FEED_STATUS_OK, data: [{ id: 'p1', receipts: [{ id: 'r1' }] }] },
    },
    filter: () => true,
    refused: false,
  }),
]);

export const portalFixtures = Object.freeze({
  kind: 'fixture',
  FEED_STATUS_OK,
  FEED_STATUS_GAP,
  FEED_STATUS_EMPTY,
  FEED_STATUS_UNKNOWN,
  ANCHOR_US,
  ANCHOR_INDIA,
  ANCHOR_GULF,
  ANCHOR_EU_PASSING,
  feedReadings,
  prospectEligibility,
  filteredViewCases,
});
