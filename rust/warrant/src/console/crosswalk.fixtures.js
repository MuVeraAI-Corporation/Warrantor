/**
 * Frozen fixtures for the framework crosswalk engine and the board
 * safety-case pack (L8-09, L8-26) — Task 11.8.
 *
 * # Why this file exists
 *
 * "A crosswalk that maps a control to a clause it does not satisfy is
 * worse than no crosswalk." Every mapping carries its evidence — the
 * verbatim quote and the source date — or it is marked `unmapped`, and
 * `unmapped` is a visible rendered state, not a blank cell. A
 * crosswalk that hides its gaps is a marketing surface; a crosswalk
 * that names them is a control property.
 *
 * The regulatory anchors the crosswalk leads with are the US model-risk
 * supervision framework (Fed SR 26-2 / OCC Bulletin 2026-13, 17 April
 * 2026) plus the RBI and DPDP frameworks for India and the Gulf
 * supervisory frameworks. The EU AI Act is a passing mention only —
 * never the lead. SR 11-7 is the prior US guidance and is NEVER cited
 * as current; the prose gate refuses any surface that names it as
 * current.
 *
 * The crosswalk renders a quote-date-status triple for every row. The
 * test pins the triple's shape and refuses a row whose quote is empty,
 * whose date is missing, or whose status is `satisfied` without a
 * quote a reader can check.
 *
 * # What this file freezes
 *
 *   `crosswalkFixtures.crosswalks` — three crosswalk readings:
 *     - complete: every row carries a quote, a date, and a status
 *       (satisfied or partial).
 *     - mixed: one row is `unmapped` (no quote, no date), and the
 *       pane must render the gap visibly, not as a blank cell.
 *     - bad-quote: one row claims `satisfied` without a quote — the
 *       pane must refuse to render it as `satisfied`.
 *   `crosswalkFixtures.regulatoryAnchors` — the canonical list of
 *     regulatory anchors. The test pins the order: US leads, then
 *     RBI/DPDP, then Gulf, then EU as a passing mention. The pane's
 *     prose gate refuses a row that names an anchor out of order.
 *   `crosswalkFixtures.sr117Cases` — fixtures that pin the SR 11-7
 *     refusal. A surface that names SR 11-7 as current is the
 *     failure this evidence is meant to prevent.
 *   `crosswalkFixtures.boardPackCases` — the board pack export
 *     inputs. The export runs through Task 11.4's verifier, so the
 *     fixture is shaped as a verifiable evidence pack.
 *
 * # The rule that overrides any design instinct
 *
 * "A crosswalk that maps a control to a clause it does not satisfy is
 * worse than no crosswalk." Every row renders the quote verbatim, the
 * source date, and the mapping status. A row whose status is `satisfied`
 * without a quote is rendered as `unmapped` and the test pins the
 * promotion. A row whose quote is empty is rendered as `unmapped` and
 * the test pins the gap.
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

/** Mapping status values. The pane recognises exactly three:
 *  - `satisfied`: the control demonstrably satisfies the clause, with
 *    a verbatim quote the reader can check.
 *  - `partial`: the control partly satisfies the clause, with a
 *    verbatim quote and a sentence the reader can audit.
 *  - `unmapped`: the control does not (yet) map to the clause, with
 *    no quote and a visible rendered state.
 *  A row whose status is `satisfied` without a quote is promoted to
 *  `unmapped` by the pane; a row whose status is `satisfied` or
 *  `partial` without a date is also promoted. */
const STATUS_SATISFIED = 'satisfied';
const STATUS_PARTIAL = 'partial';
const STATUS_UNMAPPED = 'unmapped';

const crosswalks = frozen([
  frozen({
    kind: 'fixture',
    label: 'complete crosswalk with every row carrying a quote, a date, and a status',
    crosswalk: {
      rows: [
        {
          control: 'warrant signing with ed25519 issuer key',
          framework: 'Fed SR 26-2',
          clause: 'Model risk management — change and version control',
          status: 'satisfied',
          quote: 'Institutions should maintain a documented change-and-version-control process for model components',
          source_date: '2026-04-17',
          source_url: 'https://www.federalreserve.gov/supervisionreg/sr-26-2.htm',
        },
        {
          control: 'broker-mediated tool calls with refusal receipt',
          framework: 'Fed SR 26-2',
          clause: 'Model risk management — operational controls',
          status: 'satisfied',
          quote: 'Operational controls should be implemented at the chokepoint where the model interacts with production systems',
          source_date: '2026-04-17',
          source_url: 'https://www.federalreserve.gov/supervisionreg/sr-26-2.htm',
        },
        {
          control: 'every receipt bound to a hash chain',
          framework: 'OCC Bulletin 2026-13',
          clause: 'Third-party risk — audit and accountability',
          status: 'partial',
          quote: 'Banks should maintain an audit trail of third-party model interactions sufficient to support regulatory examination',
          source_date: '2026-04-17',
          source_url: 'https://www.occ.treas.gov/news-issuances/bulletins/2026/bulletin-2026-13.html',
        },
        {
          control: 'consent receipt for affected-party data access',
          framework: 'RBI Master Direction — Digital Lending',
          clause: 'Data privacy and consent',
          status: 'satisfied',
          quote: 'Lending platforms must obtain explicit consent before accessing borrower data and must produce a consent receipt on request',
          source_date: '2022-06-10',
          source_url: 'https://www.rbi.org.in/Scripts/BS_ViewMasDirections.aspx?id=12103',
        },
        {
          control: 'data localization for affected-party data',
          framework: 'DPDP Act 2023',
          clause: 'Cross-border transfer restrictions',
          status: 'satisfied',
          quote: 'Personal data may be transferred outside India only under conditions specified by the central government',
          source_date: '2023-08-11',
          source_url: 'https://www.meity.gov.in/content/dpdp-act-2023',
        },
      ],
    },
    expected_satisfied: 4,
    expected_partial: 1,
    expected_unmapped: 0,
  }),
  frozen({
    kind: 'fixture',
    label: 'mixed crosswalk with one unmapped row that the pane must render visibly',
    crosswalk: {
      rows: [
        {
          control: 'warrant signing with ed25519 issuer key',
          framework: 'Fed SR 26-2',
          clause: 'Model risk management — change and version control',
          status: 'satisfied',
          quote: 'Institutions should maintain a documented change-and-version-control process for model components',
          source_date: '2026-04-17',
          source_url: 'https://www.federalreserve.gov/supervisionreg/sr-26-2.htm',
        },
        {
          control: 'incident response with measured containment latency',
          framework: 'SAMA Cybersecurity Framework',
          clause: 'Incident response — containment timeline',
          status: 'unmapped',
          quote: '',
          source_date: '',
          source_url: '',
        },
      ],
    },
    expected_satisfied: 1,
    expected_partial: 0,
    expected_unmapped: 1,
  }),
  frozen({
    kind: 'fixture',
    label: 'bad crosswalk: a row claims `satisfied` without a quote, must be promoted to unmapped',
    crosswalk: {
      rows: [
        {
          control: 'a control that the source data claims is satisfied',
          framework: 'Fed SR 26-2',
          clause: 'Some clause',
          status: 'satisfied',
          quote: '',
          source_date: '2026-04-17',
          source_url: 'https://www.federalreserve.gov/supervisionreg/sr-26-2.htm',
        },
      ],
    },
    expected_satisfied: 0,
    expected_partial: 0,
    expected_unmapped: 1,
  }),
]);

/** Regulatory anchors. The pane leads with US (SR 26-2, OCC 2026-13),
 *  then India (RBI, DPDP), then Gulf (SAMA, CBUAE, etc.), then EU
 *  as a passing mention. The test pins the order. A row that names an
 *  anchor out of order is a regression the prose gate is meant to
 *  prevent. */
const regulatoryAnchors = frozen([
  frozen({ kind: 'fixture', lead: 'US (Fed SR 26-2 / OCC 2026-13)', date: '2026-04-17' }),
  frozen({ kind: 'fixture', lead: 'India (RBI / DPDP)', date: '2023-08-11' }),
  frozen({ kind: 'fixture', lead: 'Gulf (SAMA / CBUAE / etc.)', date: '2024-01-01' }),
  frozen({ kind: 'fixture', lead: 'EU (passing mention only)', date: '2024-08-01' }),
]);

/** SR 11-7 refusal cases. A surface that names SR 11-7 as the
 *  current US model-risk supervision guidance is wrong — SR 26-2
 *  superseded it on 17 April 2026. The pane's prose gate refuses
 *  any row that names SR 11-7 as current. The test iterates the
 *  cases and pins the verdict. */
const sr117Cases = frozen([
  frozen({
    kind: 'fixture',
    label: 'a row that names SR 11-7 as current is refused',
    text: 'This control satisfies SR 11-7, the current US model-risk supervision guidance.',
    refused: true,
  }),
  frozen({
    kind: 'fixture',
    label: 'a row that names SR 11-7 as superseded is accepted',
    text: 'SR 11-7 was the prior US model-risk supervision guidance, superseded on 2026-04-17 by SR 26-2.',
    refused: false,
  }),
  frozen({
    kind: 'fixture',
    label: 'a row that names only SR 26-2 is accepted',
    text: 'This control satisfies Fed SR 26-2, the current US model-risk supervision guidance, dated 2026-04-17.',
    refused: false,
  }),
]);

/** Board pack cases. The export runs through Task 11.4's verifier,
 *  so the fixture is shaped as a verifiable evidence pack with
 *  the crosswalk rows inside the bundle. The test pins the
 *  presence of a `bundle_digest` and a `kind: 'crosswalk-pack'`
 *  marker. */
const boardPackCases = frozen([
  frozen({
    kind: 'fixture',
    label: 'a board pack carries a bundle_digest and a kind marker',
    pack: {
      format: 'warrantor.crosswalk-pack/1',
      kind: 'crosswalk-pack',
      bundle: {
        rows: [
          { control: 'warrant signing', framework: 'Fed SR 26-2', clause: 'change control', status: 'satisfied', quote: 'q', source_date: '2026-04-17' },
        ],
      },
      bundle_digest: 'placeholder-digest',
      receipts: [],
    },
    expected_kind: 'crosswalk-pack',
  }),
]);

export const crosswalkFixtures = Object.freeze({
  kind: 'fixture',
  STATUS_SATISFIED,
  STATUS_PARTIAL,
  STATUS_UNMAPPED,
  crosswalks,
  regulatoryAnchors,
  sr117Cases,
  boardPackCases,
});
