// frozen contract fixtures for the action-path coverage map (Task 4.4, L8-22).
//
// The console renders from these, against no backend. The Rust side
// (`rust/warrant/src/harness.rs` plus a future `warrantor coverage`
// subcommand) is the source of truth for the wire shape; this file
// pins what the operator will see and what the tests assert.
//
// The matrix vocabulary comes from the plan, Step 2, verbatim:
//   mediated   — the effect class traverses the boundary; a receipt exists for every effect.
//   observed   — the effect class is measured but not refused as it happens; receipts are
//                recorded for evidence but the boundary does not stop the effect.
//   unsupported — this harness + this effect class has no path to the boundary at all.
//                 The named bypass is what the operator has to compose to get coverage
//                 (e.g. a sandbox, a network namespace).
//   bypassable — the harness DECLARED mediated, but the receipts show some effects left
//                without a receipt. The declaration is a claim, the receipts are the
//                evidence, and a gap between the two is a bypass the operator has to
//                name. This cell is the load-bearing one for the exit gate: a map that
//                showed the declaration as truth would be the same shape as a map that
//                said "every path is mediated".
//
// Every fixture is marked `kind: 'fixture'` at the top so a test can
// refuse to confuse it for a server response.

/**
 * One row of the matrix.
 */
export const MATRIX_ROW_SHAPE = Object.freeze({
  /** The effect class. The vocabulary here comes from the existing per-tool type
   *  names; if the Rust side needs a different grouping it can fill in
   *  anything. The console renders the value verbatim. */
  effect_class: '<string>',
  /** The harness id and version, in `<name>@<version>` form. The version
   *  is the load-bearing part: a harness whose version this build does
   *  not know is downgraded, not assumed to be the same as the previous one. */
  harness: '<string>',
  /** One of 'mediated' | 'observed' | 'unsupported' | 'bypassable'. */
  state: '<string>',
  /** A plain-language sentence naming the bypass for any non-mediated cell.
   *  `null` when `state === 'mediated'`. The console renders the named
   *  bypass verbatim — the same discipline as the notification fabric's
   *  `fabric_decision` sentence. */
  named_bypass: '<string|null>',
  /** How many effects in this row have a receipt. */
  receipts: '<number>',
  /** How many effects the row saw in total. `receipts <= total` for
   *  `mediated` and `observed`; for `bypassable` `receipts < total`
   *  and the gap is the bypass. */
  total: '<number>',
});

/**
 * The top-level shape. One response, one pane; the console never
 * fans out into multiple requests for the same render.
 */
export const COVERAGE_MAP_SHAPE = Object.freeze({
  /** Always 'warrantor.coverage-map/1'. */
  format: '<string>',
  /** When the map was computed, epoch seconds. */
  as_of: '<number>',
  /** The matrix itself, one row per (effect_class, harness) pair. */
  matrix: [MATRIX_ROW_SHAPE],
  /** The aggregate counts. The console uses these to draw the
   *  percentage AND the named remainder; the plan is explicit that
   *  the percentage is never published alone. */
  summary: {
    mediated: '<number>',
    observed: '<number>',
    unsupported: '<number>',
    bypassable: '<number>',
    /** The total of all four. */
    total: '<number>',
  },
});

/** Mark every fixture with this so a test can refuse to confuse it
 *  for a server response. */
const tag = (fixture) => Object.freeze({ ...fixture, kind: 'fixture' });

/**
 * The all-mediated case: every effect class × harness pair has a
 * receipt for every effect. The percentage is 100, the remainder is
 * 0. The console still shows the remainder — "0 effects outside
 * mediated" — so a reader who skims to the bottom line still sees
 * the count, not just the percentage.
 */
export const allMediated = tag({
  format: 'warrantor.coverage-map/1',
  as_of: 1_735_000_000,
  matrix: [
    {
      effect_class: 'fs.write',
      harness: 'claude-code@1.2.0',
      state: 'mediated',
      named_bypass: null,
      receipts: 482,
      total: 482,
    },
    {
      effect_class: 'fs.read',
      harness: 'claude-code@1.2.0',
      state: 'mediated',
      named_bypass: null,
      receipts: 1_204,
      total: 1_204,
    },
    {
      effect_class: 'network.egress',
      harness: 'claude-code@1.2.0',
      state: 'mediated',
      named_bypass: null,
      receipts: 38,
      total: 38,
    },
  ],
  summary: {
    mediated: 1_724,
    observed: 0,
    unsupported: 0,
    bypassable: 0,
    total: 1_724,
  },
});

/**
 * The mixed case: one harness is fully mediated, another is
 * observed (MCP calls mediated, harness builtins not), a third is
 * unsupported (no MCP path for that effect class). The named
 * bypass is what the operator has to compose to get coverage.
 */
export const mixedCoverage = tag({
  format: 'warrantor.coverage-map/1',
  as_of: 1_735_000_000,
  matrix: [
    {
      effect_class: 'fs.write',
      harness: 'claude-code@1.2.0',
      state: 'mediated',
      named_bypass: null,
      receipts: 482,
      total: 482,
    },
    {
      effect_class: 'fs.write',
      harness: 'codex@0.41.0',
      state: 'observed',
      named_bypass: 'codex.builtin_bash and codex.builtin_edit are not MCP calls; they reach the file system without traversing the warrant. Compose a sandbox if you need those refused as they happen.',
      receipts: 31,
      total: 31,
    },
    {
      effect_class: 'network.egress',
      harness: 'aider@0.71.0',
      state: 'unsupported',
      named_bypass: 'aider has no MCP client. Network egress is not refusable by the warrant. Compose a network namespace or an egress proxy.',
      receipts: 0,
      total: 0,
    },
  ],
  summary: {
    mediated: 482,
    observed: 31,
    unsupported: 0,
    bypassable: 0,
    total: 513,
  },
});

/**
 * The bypassable case: a harness DECLARED McpOnly, the receipts
 * show some effects left without a receipt. The named bypass is
 * the gap, and the percentage drops. This is the load-bearing
 * case for the exit gate: a map that showed the declaration as
 * truth would publish "100% mediated" while a fifth of the effects
 * were leaving the machine unwitnessed.
 */
export const bypassableDeclared = tag({
  format: 'warrantor.coverage-map/1',
  as_of: 1_735_000_000,
  matrix: [
    {
      effect_class: 'fs.write',
      harness: 'open-interpreter@0.3.0',
      state: 'bypassable',
      named_bypass: 'open-interpreter declares McpOnly but 12 writes left without a receipt. The declarations and the receipts disagree. Investigate which calls are not reaching the proxy.',
      receipts: 38,
      total: 50,
    },
    {
      effect_class: 'fs.read',
      harness: 'open-interpreter@0.3.0',
      state: 'mediated',
      named_bypass: null,
      receipts: 90,
      total: 90,
    },
  ],
  summary: {
    mediated: 90,
    observed: 0,
    unsupported: 0,
    bypassable: 50,
    total: 140,
  },
});

/**
 * The unknown-harness case: a harness version this build does
 * not know has run and produced receipts. The matrix downgrades
 * the row to 'unsupported' rather than inheriting the previous
 * version's claim — a competitor that swaps the harness for a
 * new one cannot inherit the coverage assertion.
 */
export const unknownHarness = tag({
  format: 'warrantor.coverage-map/1',
  as_of: 1_735_000_000,
  matrix: [
    {
      effect_class: 'fs.write',
      harness: 'claude-code@1.2.0',
      state: 'mediated',
      named_bypass: null,
      receipts: 482,
      total: 482,
    },
    {
      effect_class: 'fs.write',
      harness: 'claude-code@2.0.0-beta',
      state: 'unsupported',
      named_bypass: 'this build does not know claude-code@2.0.0-beta. The previous version was McpOnly; new versions may differ. Until the harness profile is updated, this row cannot make a coverage claim.',
      receipts: 17,
      total: 17,
    },
  ],
  summary: {
    mediated: 482,
    observed: 0,
    unsupported: 17,
    bypassable: 0,
    total: 499,
  },
});

/**
 * The empty case: no receipts in the window, or no harnesses
 * registered. The console renders "the map has nothing to say"
 * rather than "0% mediated" — zero rows is a fact about a window,
 * and the operator should not read it as a clean bill of health.
 */
export const emptyMap = tag({
  format: 'warrantor.coverage-map/1',
  as_of: 1_735_000_000,
  matrix: [],
  summary: {
    mediated: 0,
    observed: 0,
    unsupported: 0,
    bypassable: 0,
    total: 0,
  },
});
