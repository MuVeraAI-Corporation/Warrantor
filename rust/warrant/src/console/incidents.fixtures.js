// ── Task 11.2 — incident console fixtures (L8-03, L8-25) ──────────────────────
//
// "A blast-radius bound that has never been exercised is an estimate." The
// fixtures below carry the distribution shape that the Rust lane's Task 8.8
// (isolation conformance and adaptive escape rehearsal) will produce, plus an
// explicit `null` for the latency distribution of a bound that has never been
// rehearsed. A pane that invented a number for that second case would be the
// rule's opposite.
//
// Every fixture is marked `kind: 'fixture'` so a future test can refuse to
// confuse it for a server response. No fixture invents a field the contract
// does not have.

/** The shape of one row in the pane. Pinned by the test that loads this file. */
export const INCIDENT_BOUND_SHAPE = Object.freeze({
  kind: 'fixture',
  id: '',
  effect_class: '',
  tier: '',
  blast_radius: {
    kind: '',
    exercised_at: null,
    cap_bytes: null,
    allowed: null,
  },
  latency_ms: null,
  absences: [],
});

/** A bound that has been exercised — a real distribution, a real exercise date. */
export const memoryCapBound = Object.freeze({
  kind: 'fixture',
  id: 'memory-cap',
  effect_class: 'egress',
  tier: 'enforced',
  blast_radius: Object.freeze({
    kind: 'cgroup.memory',
    cap_bytes: 268435456,
    exercised_at: '2026-09-04T18:22:07Z',
  }),
  latency_ms: Object.freeze({
    p50: 8,
    p99: 47,
    samples: 312,
    disagreement: 0.012,
    measured_at: '2026-09-04T18:30:00Z',
  }),
  absences: Object.freeze([
    'cpu usage is not contained by this bound — measured and reported, not refused',
    'disk I/O is not contained by this bound — measured and reported, not refused',
  ]),
});

/** A mediated bound that has never been rehearsed — latency distribution is `null`. */
export const egressHostsBound = Object.freeze({
  kind: 'fixture',
  id: 'egress-hosts',
  effect_class: 'network',
  tier: 'mediated',
  blast_radius: Object.freeze({
    kind: 'egress.hosts',
    allowed: Object.freeze(['api.github.com', 'registry.npmjs.org']),
    exercised_at: null,
  }),
  latency_ms: null,
  absences: Object.freeze([
    'no DNS-level enforcement — egress is refused at the broker, not at a network namespace',
    'no measurement of egress that does not traverse the broker — what does not go through the broker is not decided by it',
  ]),
});

/** An observed bound that has been measured but never refused — latency is honest. */
export const writePathsBound = Object.freeze({
  kind: 'fixture',
  id: 'write-paths',
  effect_class: 'filesystem',
  tier: 'observed',
  blast_radius: Object.freeze({
    kind: 'paths.write',
    allowed: Object.freeze(['src/**']),
    exercised_at: '2026-08-30T11:05:42Z',
  }),
  latency_ms: Object.freeze({
    p50: 14,
    p99: 91,
    samples: 58,
    disagreement: 0.034,
    measured_at: '2026-08-30T11:30:00Z',
  }),
  absences: Object.freeze([
    "writes outside src/** are not refused as they happen — they are simply not staged, so they never reach the operator's branch",
    'reads are not measured by this bound — only writes that traverse the warrant',
  ]),
});

/** A bound whose tier is unknown — the server did not say. */
export const unknownTierBound = Object.freeze({
  kind: 'fixture',
  id: 'cpu-quota',
  effect_class: 'process',
  tier: 'unknown',
  blast_radius: Object.freeze({
    kind: 'cgroup.cpu',
    cap_shares: 1024,
    exercised_at: null,
  }),
  latency_ms: null,
  absences: Object.freeze([
    'the server did not state the strength tier for this bound — it does not appear as enforced, mediated or observed on this page',
  ]),
});

/** Every fixture, in display order. The pane renders this by default. */
export const incidentFixtures = Object.freeze([
  memoryCapBound,
  egressHostsBound,
  writePathsBound,
  unknownTierBound,
]);

/**
 * The fixture-set bundle as it would arrive from `/v1/incidents/bounds`.
 * `kind: 'fixture'` carries the marker so a test can refuse to confuse this
 * for a server response.
 */
export const incidentBundle = Object.freeze({
  kind: 'fixture',
  as_of: '2026-09-05T12:00:00Z',
  bounds: incidentFixtures,
});