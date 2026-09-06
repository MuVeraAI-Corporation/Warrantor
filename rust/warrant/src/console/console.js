/* Warrantor console — a viewer, and deliberately only a viewer.
 *
 * The one rule this file exists to keep: NO CRYPTOGRAPHY HAPPENS HERE, EVER. Every
 * response from /v1 carries a server-computed `verification` envelope, and this file
 * renders it. It never checks a signature, never compares a digest, never decides that
 * something is verified. `serve.rs` states why: a renderer that derived its own verdict
 * would be a second implementation of the verifier, and a second implementation can
 * disagree with the first. When two verifiers disagree, a human has to work out which
 * one to believe, which is precisely the situation this product exists to prevent.
 *
 * So: `render(v.verified)`, never `compute(verified)`. If the API cannot say, this shows
 * "unknown" rather than guessing.
 *
 * The token. A browser cannot put an Authorization header on the navigation that loads
 * this page, so `warrantor serve` prints a link carrying the token in the URL *fragment*.
 * A fragment is never sent to a server, never written to an access log, and never leaks
 * in a Referer header. It is read once, erased from the address bar and from history, and
 * held in a module-scoped variable — not localStorage, which would outlive the session
 * the token belongs to and survive into the next one. */

const api = { token: null };

/** Elements, looked up once. */
const el = {
  gate: document.getElementById('gate'),
  gateForm: document.getElementById('gate-form'),
  gateInput: document.getElementById('gate-input'),
  gateError: document.getElementById('gate-error'),
  app: document.getElementById('app'),
  list: document.getElementById('list'),
  listEmptyFirstRun: document.getElementById('list-empty-first-run'),
  listEmptyFiltered: document.getElementById('list-empty-filtered'),
  listEmptyUnreadable: document.getElementById('list-empty-unreadable'),
  listEmptyError: document.getElementById('list-empty-error'),
  showAll: document.getElementById('show-all'),
  firstRun: document.getElementById('first-run'),
  grantCommand: document.getElementById('first-run-command'),
  copyButton: document.getElementById('copy-command'),
  detail: document.getElementById('detail'),
  shortcuts: document.getElementById('shortcuts'),
  shortcutList: document.getElementById('shortcut-list'),
  shortcutsClose: document.getElementById('shortcuts-close'),
  viewWarrants: document.getElementById('view-warrants'),
  viewSummary: document.getElementById('view-summary'),
  viewQueue: document.getElementById('view-queue'),
  viewSettings: document.getElementById('view-settings'),
  viewCoverage: document.getElementById('view-coverage'),
  coverage: document.getElementById('coverage'),
  coverageHeadline: document.getElementById('coverage-headline'),
  coveragePercent: document.getElementById('coverage-percent'),
  coverageRemainder: document.getElementById('coverage-remainder'),
  coverageMatrix: document.getElementById('coverage-matrix'),
  coverageBypasses: document.getElementById('coverage-bypasses'),
  coverageEmpty: document.getElementById('coverage-empty'),
  coverageError: document.getElementById('coverage-error'),
  coverageUnreadable: document.getElementById('coverage-unreadable'),
  viewRouting: document.getElementById('view-routing'),
  routing: document.getElementById('routing'),
  routingHeadline: document.getElementById('routing-headline'),
  routingPolicy: document.getElementById('routing-policy'),
  routingCeiling: document.getElementById('routing-ceiling'),
  routingDecisions: document.getElementById('routing-decisions'),
  routingEmpty: document.getElementById('routing-empty'),
  routingError: document.getElementById('routing-error'),
  routingUnreadable: document.getElementById('routing-unreadable'),
  // Audit workbench (L8-05, L8-10) — Task 11.4. The pane is click-only because
  // six destinations already compete for the five digit keys. The verifier
  // ships in this file and re-runs the digest and the anchor check that the
  // Rust archive's tests pin (`verify_export` + `verify_export_signed_by`).
  viewAudit: document.getElementById('view-audit'),
  audit: document.getElementById('audit'),
  auditHeadline: document.getElementById('audit-headline'),
  auditPacks: document.getElementById('audit-packs'),
  auditEmpty: document.getElementById('audit-empty'),
  auditError: document.getElementById('audit-error'),
  auditUnreadable: document.getElementById('audit-unreadable'),
  // Fleet register (L8-02, L8-08) — Task 11.1. The seventh destination; all five
  // digits are taken and audit is already click-only, so this pane is click-only
  // too. Each row carries the agent's strongest tier, the authority the
  // registry resolved, and the coverage limits the warrants advertise. An
  // agent whose authority could not be resolved renders as `unresolved`, not
  // `unrestricted` — those are different failures with the same blast radius.
  viewFleet: document.getElementById('view-fleet'),
  fleet: document.getElementById('fleet'),
  fleetHeadline: document.getElementById('fleet-headline'),
  fleetSummary: document.getElementById('fleet-summary'),
  fleetAgents: document.getElementById('fleet-agents'),
  fleetEmpty: document.getElementById('fleet-empty'),
  fleetError: document.getElementById('fleet-error'),
  fleetUnreadable: document.getElementById('fleet-unreadable'),
  // Incidents pane (L8-03, L8-25) — Task 11.2. The eighth destination; all five
  // digits are taken and audit and fleet are already click-only, so this pane
  // is click-only too. Each bound row carries its tier in two places (a pill
  // class and a prose sentence), its latency as a DISTRIBUTION (p50, p99,
  // sample count, disagreement), and the blast-radius figure with its
  // exercise date — or "not exercised" when the bound has never been
  // rehearsed. A single-number latency would be the most misleading thing
  // this estate could display, because the tail is the whole risk.
  viewIncidents: document.getElementById('view-incidents'),
  incidents: document.getElementById('incidents'),
  incidentsHeadline: document.getElementById('incidents-headline'),
  incidentsSummary: document.getElementById('incidents-summary'),
  incidentsBounds: document.getElementById('incidents-bounds'),
  incidentsEmpty: document.getElementById('incidents-empty'),
  incidentsError: document.getElementById('incidents-error'),
  incidentsUnreadable: document.getElementById('incidents-unreadable'),
  // Policy studio (L8-04) — Task 11.3. The ninth destination; all five digits
  // are taken and audit, fleet and incidents are already click-only, so this
  // pane is click-only too. The studio runs the same parse + emit as the
  // Python `policy_compiler` and refuses with the compiler's exact sentences,
  // because a studio that accepts a policy the compiler refuses (or vice
  // versa) has taught the operator something false about their own controls.
  // Exceptions are added on the same pane because the lifecycle (Task 10.5)
  // refuses one without an expiry or a compensating control, and the studio
  // mirrors that refusal in its own words.
  viewPolicy: document.getElementById('view-policy'),
  policy: document.getElementById('policy'),
  policyHeadline: document.getElementById('policy-headline'),
  policyForm: document.getElementById('policy-form'),
  policyIntent: document.getElementById('policy-intent'),
  policyRules: document.getElementById('policy-rules'),
  policyCompile: document.getElementById('policy-compile'),
  policyRefusal: document.getElementById('policy-refusal'),
  policyCount: document.getElementById('policy-count'),
  policyRego: document.getElementById('policy-rego'),
  policyCedar: document.getElementById('policy-cedar'),
  policyOpenshell: document.getElementById('policy-openshell'),
  policyExceptionWarrant: document.getElementById('policy-exception-warrant'),
  policyExceptionExpires: document.getElementById('policy-exception-expires'),
  policyExceptionCompensating: document.getElementById('policy-exception-compensating'),
  policyException: document.getElementById('policy-exception-outcome'),
  // Executive risk view (L8-07, L8-21) — Task 11.10. The tenth destination;
  // all five digits are taken and audit, fleet, incidents, policy are
  // already click-only, so this pane is click-only too. The view reads
  // the dial (8.2), the budget (8.4) and the wiring census and renders
  // the WEAKEST input tier for every roll-up — a roll-up of [enforced,
  // mediated, observed] is `observed`, never the strongest, because a
  // green dial computed from Tier C observed, presented with the
  // confidence of Tier A, is the failure this surface exists to prevent.
  viewExecutive: document.getElementById('view-executive'),
  executive: document.getElementById('executive'),
  executiveHeadline: document.getElementById('executive-headline'),
  executiveSummary: document.getElementById('executive-summary'),
  executiveRollup: document.getElementById('executive-rollup'),
  executiveExposure: document.getElementById('executive-exposure'),
  executiveEmpty: document.getElementById('executive-empty'),
  executiveError: document.getElementById('executive-error'),
  executiveUnreadable: document.getElementById('executive-unreadable'),
  // Autonomy ledger (L8-20, L8-24) — Task 11.11. The eleventh destination;
  // all five digits are taken and audit, fleet, incidents, policy and
  // executive are already click-only, so this pane is click-only too.
  // The ledger renders widening and narrowing with equal prominence,
  // because "a ledger that records widening but not narrowing is a
  // growth chart." The pane is a RENDERING of 8.2's receipts (the
  // dial already records both directions), not a distinct record.
  viewAutonomy: document.getElementById('view-autonomy'),
  autonomy: document.getElementById('autonomy'),
  autonomyHeadline: document.getElementById('autonomy-headline'),
  autonomySummary: document.getElementById('autonomy-summary'),
  autonomyEntries: document.getElementById('autonomy-entries'),
  autonomyEmpty: document.getElementById('autonomy-empty'),
  autonomyError: document.getElementById('autonomy-error'),
  autonomyUnreadable: document.getElementById('autonomy-unreadable'),
  // Crosswalk engine (L8-09, L8-26) — Task 11.8. The twelfth destination;
  // all five digits are taken and audit, fleet, incidents, policy,
  // executive and autonomy are already click-only, so this pane is
  // click-only too. A crosswalk that maps a control to a clause it
  // does not satisfy is worse than no crosswalk. Every mapping carries
  // its quote and source date, or it is rendered as `unmapped` — a
  // visible state, never a blank cell. The pane leads with US model-
  // risk supervision (Fed SR 26-2 / OCC 2026-13, 17 April 2026) plus
  // RBI and DPDP for India and Gulf supervisory frameworks; the EU is
  // a passing mention only. SR 11-7 is NEVER cited as current.
  viewCrosswalk: document.getElementById('view-crosswalk'),
  crosswalk: document.getElementById('crosswalk'),
  crosswalkHeadline: document.getElementById('crosswalk-headline'),
  crosswalkSummary: document.getElementById('crosswalk-summary'),
  crosswalkRows: document.getElementById('crosswalk-rows'),
  crosswalkEmpty: document.getElementById('crosswalk-empty'),
  crosswalkError: document.getElementById('crosswalk-error'),
  crosswalkUnreadable: document.getElementById('crosswalk-unreadable'),
  queue: document.getElementById('queue'),
  queueHeadline: document.getElementById('queue-headline'),
  queueWho: document.getElementById('queue-who'),
  queueRows: document.getElementById('queue-rows'),
  queueEmpty: document.getElementById('queue-empty'),
  queueError: document.getElementById('queue-error'),
  queueUnreadable: document.getElementById('queue-unreadable'),
  queueLatency: document.getElementById('queue-latency'),
  settings: document.getElementById('settings'),
  settingsHeadline: document.getElementById('settings-headline'),
  settingsDecision: document.getElementById('settings-decision'),
  settingsTransports: document.getElementById('settings-transports'),
  settingsOrder: document.getElementById('settings-order'),
  settingsLedger: document.getElementById('settings-ledger'),
  settingsPending: document.getElementById('settings-pending'),
  settingsEmpty: document.getElementById('settings-empty'),
  settingsError: document.getElementById('settings-error'),
  settingsUnreadable: document.getElementById('settings-unreadable'),
  summary: document.getElementById('summary'),
  summaryForm: document.getElementById('summary-form'),
  summaryMonth: document.getElementById('summary-month'),
  summaryError: document.getElementById('summary-error'),
  summaryMonthError: document.getElementById('summary-month-error'),
  summaryWindow: document.getElementById('summary-window'),
  summaryCaveat: document.getElementById('summary-caveat'),
  summaryUnreadable: document.getElementById('summary-unreadable'),
  summaryRefusals: document.getElementById('summary-refusals'),
  summaryRefusalsEmpty: document.getElementById('summary-refusals-empty'),
  summaryRefusalsNote: document.getElementById('summary-refusals-note'),
  summaryGuard: document.getElementById('summary-guard'),
  summaryGuardUnknown: document.getElementById('summary-guard-unknown'),
  summaryGuardNone: document.getElementById('summary-guard-none'),
  summaryGuardUnattributed: document.getElementById('summary-guard-unattributed'),
  summaryGuardQuiet: document.getElementById('summary-guard-quiet'),
  summaryGuardNote: document.getElementById('summary-guard-note'),
  summaryGuardCaveats: document.getElementById('summary-guard-caveats'),
  summaryCoverage: document.getElementById('summary-coverage'),
  summaryCoverageNote: document.getElementById('summary-coverage-note'),
  summaryRuns: document.getElementById('summary-runs'),
  health: document.getElementById('health'),
  authority: document.getElementById('authority'),
  toast: document.getElementById('toast'),
};

/**
 * `authorityKnown` is tracked separately from `releaseAuthority` on purpose.
 *
 * "this server told us it holds no settle key" and "nobody has answered yet" are different facts.
 * Folding them would print the confident sentence "this server was started without --allow-settle"
 * underneath a server the console has never heard from, which is a dead guard reported as a
 * reading. Both keep the buttons disabled; only one of them may be explained that way.
 */
let state = {
  filter: '',
  selected: null,
  releaseAuthority: false,
  authorityKnown: false,
  /** Which destination owns the right-hand column: 'warrants' or 'summary'. */
  view: 'warrants',
  /**
   * The last rung `emptyKind` returned, remembered so switching back from the summary restores the
   * pane the list's own answer supports rather than a guess. Re-deriving it here would be a second
   * copy of the ordering that `emptyKind` exists to be the only copy of.
   */
  lastKind: 'rows',
};

/**
 * How often to re-read the list, in milliseconds.
 *
 * Polling rather than a change feed, because the API has none — and `serve.rs` designed for exactly
 * this: "no keep-alive means no idle state machine [...] because the consumer is one console polling
 * at human speed". Five seconds is human speed for watching a run. It is not a live tail and does
 * not pretend to be.
 */
const REFRESH_MS = 5000;

/** In-flight guard: a slow poll must not stack behind a slower one. */
let refreshing = false;

/** Last known lifecycle state per warrant id, to detect what actually changed. */
const knownStates = new Map();

// ── token handling ──────────────────────────────────────────────────────────

/** Take the token out of the fragment and erase every trace of it from the URL. */
function tokenFromFragment() {
  const hash = window.location.hash;
  if (!hash.startsWith('#')) return null;
  const found = new URLSearchParams(hash.slice(1)).get('t');
  if (!found) return null;
  // Erase before anything else can read it: replaceState drops it from the address bar
  // and from the history entry, so a screenshot or a back button cannot resurrect it.
  history.replaceState(null, '', window.location.pathname);
  return found;
}

// ── transport ───────────────────────────────────────────────────────────────

/**
 * Call the local API.
 *
 * Returns three things, and `answered` is the one that matters: whether the server produced a
 * response at all. A 4xx is an *answer* — the caller decides how to show it — but a connection
 * refused, an agent process that exited, or a socket cut mid-body is not, and this reports that as
 * an outcome rather than throwing.
 *
 * It threw once, and every caller was worse for it. `refresh()` swallowed the throw in a bare
 * `catch {}` so nothing on screen changed; a throw during `connect()` skipped `startRefreshing()`
 * entirely, leaving a visible app with an empty list, every empty-state paragraph still hidden, and
 * no poll that could ever recover it. Failing to reach the server is the likeliest way a loopback
 * agent fails, and it was the one failure the console could not say anything about.
 *
 * `payload` is null when the body did not parse. Callers must not read that as "empty": see
 * `listFacts`.
 */
async function call(path, options = {}) {
  let response;
  try {
    response = await fetch(path, {
      ...options,
      headers: {
        authorization: `Bearer ${api.token}`,
        ...(options.body ? { 'content-type': 'application/json' } : {}),
      },
      // The API sends Connection: close and no CORS headers; this is same-origin only.
      cache: 'no-store',
    });
  } catch {
    return { answered: false, status: 0, payload: null };
  }
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    // A truncated body under `Connection: close` lands here, as does anything that is not JSON.
    payload = null;
  }
  return { answered: true, status: response.status, payload };
}

// ── rendering helpers ───────────────────────────────────────────────────────

/** Build an element. Text is always set via textContent — never interpolated as HTML. */
function node(tag, className, text) {
  const n = document.createElement(tag);
  if (className) n.className = className;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}

function toast(message) {
  // Cleared before it is set, so an identical consecutive message is still announced: a
  // live region whose text does not change says nothing, and "Settle refused." twice in a
  // row is two facts a reviewer needs both of.
  el.toast.textContent = '';
  el.toast.textContent = message;
  el.toast.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => {
    el.toast.hidden = true;
  }, 4000);
}

/** Map an integrity word to a pill class. Three values, never folded into two. */
function integrityClass(integrity) {
  if (integrity === 'ok') return 'pill-ok';
  if (integrity === 'failed') return 'pill-bad';
  return 'pill-unknown';
}

/**
 * Render the server's verdict.
 *
 * `verified` is read straight off the envelope. Note what is NOT done here: liveness is
 * shown beside integrity and never mixed into it. An expired report is an intact record
 * of a past decision, and colouring it like a tampered one would teach a reader to
 * distrust their own archive.
 */
function renderVerdict(envelope) {
  const v = envelope?.verification;
  const box = node('div', 'verdict');
  const head = node('div', 'verdict-head');

  const verdict = node(
    'span',
    `pill ${envelope?.verified ? 'pill-ok' : integrityClass(v?.integrity)}`,
    envelope?.verified ? 'verified' : `not verified — ${v?.integrity ?? 'unknown'}`,
  );
  head.append(verdict);

  if (v?.liveness) {
    const live = v.liveness === 'live';
    head.append(node('span', `pill ${live ? 'pill-quiet' : 'pill-unknown'}`, v.liveness));
  }
  if (v?.code) head.append(node('span', 'pill pill-quiet', v.code));
  box.append(head);

  if (v?.reason) box.append(node('p', 'verdict-why', v.reason));

  const kv = node('dl', 'kv');
  const pair = (label, value) => {
    if (!value) return;
    kv.append(node('dt', null, label), node('dd', null, value));
  };
  pair('checked at', v?.checked_at ? new Date(v.checked_at * 1000).toLocaleString() : null);
  pair('digest', v?.digest);
  // Absent on failure by design: showing the key a broken record *claims* would put a
  // trusted-looking name in front of a reader looking at a forgery.
  pair('signed by', v?.signed_by);
  if (kv.childElementCount) box.append(kv);

  return box;
}

function jsonBlock(value) {
  return node('pre', 'json', JSON.stringify(value, null, 2));
}

// ── the empty states ────────────────────────────────────────────────────────

/**
 * What a list response actually established, as opposed to what reading it optimistically yields.
 *
 * Exported and pure so it can be tested directly; `console.test.js` covers every branch.
 *
 * `readable` is the load-bearing field, and the reason this function exists rather than a chain of
 * `?.` and `?? 0` at the call site. Optional chaining turns *every* unusable response into the same
 * shape as an empty store: a body that did not parse gives `payload === null`, a `warrants` field
 * that is not an array gives zero rows, and an absent `unreadable_records` gives zero unreadable.
 * All three used to arrive at `emptyKind` indistinguishable from a genuinely empty store on a 200,
 * and therefore rendered as the confident sentence "No warrants on this machine yet." to someone
 * whose store was full. Zero rows is a fact about a response only when the response was one this
 * console could read.
 *
 * `unreadable_records` is validated rather than coerced for the same reason. It is the count that
 * raises the corruption alarm, so a value this console cannot interpret must not be quietly read as
 * zero — that is a broken guard reported as "all clear". Absent is treated as zero, and only
 * absent, so a server that predates the field still lists.
 *
 * @param {boolean} answered Did the server produce a response at all?
 * @param {number} status HTTP status, meaningful only when `answered`.
 * @param {unknown} payload The parsed envelope, or null when the body did not parse.
 * @returns {{readable: boolean, rows: Array, unreadable: number}}
 */
export function listFacts(answered, status, payload) {
  const unusable = { readable: false, rows: [], unreadable: 0 };
  if (!answered || status !== 200) return unusable;
  const warrants = payload?.data?.warrants;
  // `undefined`, not `?? 0`: JSON has no `undefined`, so an absent field is a server that predates
  // the count, while an explicit `null` is a server declining to give one. Only the first may be
  // read as "no corrupt files"; the second is a guard with no reading behind it.
  const counted = payload?.data?.unreadable_records;
  const unreadable = counted === undefined ? 0 : counted;
  if (!Array.isArray(warrants)) return unusable;
  if (!Number.isInteger(unreadable) || unreadable < 0) return unusable;
  return { readable: true, rows: warrants, unreadable };
}

/**
 * Which empty state the server's answer actually supports.
 *
 * Total and pure, so the only way to reach a wrong screen is to disagree with the ordering
 * below — and each rung outranks the next for a reason:
 *
 * - `error` first, and it is decided by `readable`, never by the status alone. `list_warrants` can
 *   fail, the connection can fail, and the body can arrive unparseable with a 200 on it. Absence of
 *   an answer is not the answer "none": telling someone with a full store that they have never
 *   granted a warrant is the same class of lie as rendering `unknown` as `failed`, and it lands on
 *   the reader least able to check it.
 * - `rows` next, because there is then nothing empty to explain.
 * - `filtered` above `unreadable`. This ordering was the other way round and that was wrong: a
 *   store holding five open warrants and one corrupt file, viewed under the Settled chip, was told
 *   "Nothing could be listed, but this store is not empty" — a sentence that is false (plenty could
 *   be listed, just not in this state) and that carries no **Show all**, so it also removed the way
 *   out. `unreadable_records` being filter-independent justifies knowing the store is non-empty; it
 *   does not justify a filter-independent *sentence*. The corruption count is not lost by this: the
 *   warning row `loadList` writes into the list is rendered whenever the count is non-zero,
 *   whatever the filter and whichever paragraph is showing.
 * - `unreadable` above `first-run`. Counted over the whole store, so a non-zero count is proof this
 *   store holds files. A store the server could not parse is not a store that has never granted,
 *   and saying so would erase a history and bury a corruption warning in one sentence.
 * - `first-run` last, and only there. A readable, unfiltered response with zero rows and zero
 *   unreadable is the one case where "this machine has never granted a warrant" is a fact the
 *   response supports.
 *
 * Two things are deliberately NOT done. It does not re-ask the server without the filter when a
 * filtered list comes back empty: that would make the console assert something the response it is
 * rendering did not contain, and it would race the poller. And no `total` was added to the list
 * payload: that puts a UI convenience inside a frozen `/v1` surface. Neither is needed — the
 * filter is never persisted, so it can only be on because someone clicked a chip in this session,
 * and "Show all" is one click away.
 *
 * @param {{readable: boolean, rowCount: number, unreadable: number, filter: string}} facts
 * @returns {'error'|'rows'|'filtered'|'unreadable'|'first-run'}
 */
export function emptyKind({ readable, rowCount, unreadable, filter }) {
  if (!readable) return 'error';
  if (rowCount > 0) return 'rows';
  if (filter) return 'filtered';
  if (unreadable > 0) return 'unreadable';
  return 'first-run';
}

/** Show exactly one empty state, and exactly one of the three right-hand panes. */
function applyEmptyState(kind) {
  state.lastKind = kind;
  el.listEmptyFirstRun.hidden = kind !== 'first-run';
  el.listEmptyFiltered.hidden = kind !== 'filtered';
  el.listEmptyUnreadable.hidden = kind !== 'unreadable';
  el.listEmptyError.hidden = kind !== 'error';

  // `hidden` is display:none, so the panes that are not showing occupy no grid cell and the
  // two-column layout survives having four children.
  const explain = kind === 'first-run';
  const summary = state.view === 'summary';
  const queue = state.view === 'queue';
  const settings = state.view === 'settings';
  const coverage = state.view === 'coverage';
  const routing = state.view === 'routing';
  const audit = state.view === 'audit';
  const fleet = state.view === 'fleet';
  const incidents = state.view === 'incidents';
  const policy = state.view === 'policy';
  const executive = state.view === 'executive';
  const autonomy = state.view === 'autonomy';
  const crosswalk = state.view === 'crosswalk';
  const elsewhere = summary || queue || settings || coverage || routing || audit || fleet || incidents || policy || executive || autonomy || crosswalk;
  el.summary.hidden = !summary;
  el.queue.hidden = !queue;
  el.settings && (el.settings.hidden = !settings);
  el.coverage && (el.coverage.hidden = !coverage);
  el.routing && (el.routing.hidden = !routing);
  el.audit && (el.audit.hidden = !audit);
  el.fleet && (el.fleet.hidden = !fleet);
  el.incidents && (el.incidents.hidden = !incidents);
  el.policy && (el.policy.hidden = !policy);
  el.executive && (el.executive.hidden = !executive);
  el.autonomy && (el.autonomy.hidden = !autonomy);
  el.crosswalk && (el.crosswalk.hidden = !crosswalk);
  el.firstRun.hidden = elsewhere || !explain;
  el.detail.hidden = elsewhere || explain;

  // A selection cannot survive a store that holds nothing: leaving it set would make the next
  // poll fetch an id this store does not have and render the 404 as if it were news.
  //
  // Clearing the *pane* is the other half, and it was missing. `hidden` only stops the pane being
  // painted; the verdict and the enabled Settle / Void / Stop buttons rendered for the warrant that
  // was selected stayed in the DOM, and the next poll that returned rows showed them again intact —
  // live-looking release controls over a warrant this store no longer holds, with no row
  // highlighted and no selection behind them. Clicking Settle there POSTs against a deleted id.
  if (explain) {
    state.selected = null;
    el.detail.replaceChildren(node('div', 'placeholder', 'Select a warrant.'));
  }
}

/**
 * Point the list at one state.
 *
 * Shared by the chips and by "Show all" so the chip that looks selected and the filter actually
 * in force cannot drift apart — which they would the moment a second caller set `state.filter`
 * without touching the chips, leaving the reader looking at "All" while a filter was on.
 */
function setFilter(value) {
  state.filter = value;
  for (const chip of document.querySelectorAll('.chip')) {
    chip.classList.toggle('is-on', (chip.dataset.state ?? '') === value);
  }
  return loadList();
}

/**
 * Point the right-hand column at one destination.
 *
 * Goes through `applyEmptyState` with the rung the list last established, so the pane that appears
 * is the one that response supports. Switching to the summary reads it once — it is not polled;
 * see `loadSummary`.
 */
async function setView(value) {
  state.view = value;
  // `is-on` is a CLASS, which is a fact about paint and nothing else: a screen reader cannot see it,
  // so which destination was showing was announced to nobody. `aria-pressed` is the property that
  // carries it, and it goes on all four every time rather than only on the new one — a toggle
  // group where two buttons carry the attribute and one does not reads as a group of two.
  for (const [button, name] of [
    [el.viewWarrants, 'warrants'],
    [el.viewQueue, 'queue'],
    [el.viewSummary, 'summary'],
    [el.viewSettings, 'settings'],
    [el.viewCoverage, 'coverage'],
    [el.viewRouting, 'routing'],
    [el.viewAudit, 'audit'],
    [el.viewFleet, 'fleet'],
    [el.viewIncidents, 'incidents'],
    [el.viewPolicy, 'policy'],
    [el.viewExecutive, 'executive'],
    [el.viewAutonomy, 'autonomy'],
    [el.viewCrosswalk, 'crosswalk'],
  ]) {
    if (!button) continue;
    button.classList.toggle('is-on', value === name);
    button.setAttribute('aria-pressed', String(value === name));
  }
  applyEmptyState(state.lastKind);
  if (value === 'summary') await loadSummary();
  if (value === 'queue') await loadQueue();
  if (value === 'settings') await loadSettings();
  if (value === 'coverage') await loadCoverage();
  if (value === 'routing') await loadRouting();
  if (value === 'audit') await loadAudit();
  if (value === 'fleet') await loadFleet();
  if (value === 'incidents') await loadIncidents();
  if (value === 'policy') await loadPolicy();
  if (value === 'executive') await loadExecutive();
  if (value === 'autonomy') await loadAutonomy();
  if (value === 'crosswalk') await loadCrosswalk();
}

// ── the queue: what is waiting on a human, and what THIS reader can do about it ───────

/**
 * Read `/v1/queue` into the shape the pane renders.
 *
 * # What this function deliberately does not do
 *
 * It derives nothing. `you_can` arrives from the server, computed by the same code the settle gate
 * agrees with — `tests/review.rs` asserts that agreement against the gate itself. A console that
 * decided for itself which buttons to show would be a second implementation of the approval rules,
 * and the two would drift the first time either changed. That is the mistake the whole product is
 * built on not making, and `renderCustody` exists because of it.
 *
 * Every failure collapses to `readable: false`. A queue that could not be read must not render as
 * an empty queue: "nothing is waiting on you" and "this console could not find out" are the two
 * sentences a reviewer must never see confused, because the first one ends their day.
 *
 * @param {boolean} answered Whether the request completed at all.
 * @param {number} status The HTTP status.
 * @param {any} payload The parsed body.
 */
export function queueFacts(answered, status, payload) {
  const unusable = {
    readable: false,
    waiting: [],
    undetermined: [],
    you: null,
    yours: 0,
    counts: {},
    unreadableRecords: 0,
    policy: null,
    latency: null,
  };
  if (!answered || status !== 200) return unusable;
  const data = payload?.data;
  if (!data || typeof data !== 'object') return unusable;
  if (!Array.isArray(data.waiting)) return unusable;
  return {
    readable: true,
    waiting: data.waiting,
    undetermined: Array.isArray(data.undetermined) ? data.undetermined : [],
    you: data.you ?? null,
    yours: Number.isFinite(data.waiting_on_you) ? data.waiting_on_you : 0,
    counts: data.counts && typeof data.counts === 'object' ? data.counts : {},
    unreadableRecords: Number.isFinite(data.unreadable_records) ? data.unreadable_records : 0,
    // The policy block carries `required` and `settler_may_approve` (the existing fields) and
    // `latency` (the additive L8-01 field). The renderer reads each independently; `latency` being
    // absent is not the same as latency being zero.
    policy: data.policy && typeof data.policy === 'object' ? data.policy : null,
    latency: data.policy && data.policy.latency && typeof data.policy.latency === 'object'
      ? data.policy.latency
      : null,
  };
}

/**
 * The sentence at the top of the queue, and the one place a count becomes prose.
 *
 * Four states, not one. "Nothing is waiting" and "nothing is waiting **on you**" are different
 * facts about the same store, and rendering the second as the first tells a reviewer their work is
 * done when eleven warrants are sitting behind a scope they do not hold.
 *
 * @param {{readable: boolean, waiting: any[], yours: number, you: any}} facts
 */
export function queueHeadline(facts) {
  if (!facts.readable) {
    return 'This queue could not be read. That is not the same as nothing waiting.';
  }
  const total = facts.waiting.length;
  if (total === 0) return 'Nothing is waiting on a decision.';
  if (facts.yours === 0) {
    return `${total} waiting on a decision, none of which you can act on.`;
  }
  if (facts.yours === total) return `${total} waiting on you.`;
  return `${facts.yours} of ${total} waiting on you.`;
}

/** Whether the reader holds a scope, from the server's own answer. Never inferred. */
function readerHolds(you, scope) {
  return Array.isArray(you?.scopes) && you.scopes.includes(scope);
}

async function loadQueue() {
  const { answered, status, payload } = await call('/v1/queue');
  if (answered && status === 401) {
    showGate('That token was not accepted.');
    return;
  }
  renderQueue(queueFacts(answered, status, payload));
}

function renderQueue(facts) {
  el.queueError.hidden = facts.readable;
  el.queueRows.replaceChildren();
  el.queueHeadline.textContent = queueHeadline(facts);

  if (!facts.readable) {
    el.queueWho.textContent = '';
    el.queueEmpty.hidden = true;
    el.queueUnreadable.textContent = '';
    el.queueLatency.replaceChildren();
    return;
  }

  // Who the server thinks this reader is, in the server's own words. A console that printed the
  // operator name it remembered from the gate would be asserting an identity nobody checked.
  el.queueWho.textContent = facts.you?.name
    ? `You are ${facts.you.name}, holding ${(facts.you.scopes ?? []).join(', ')}.`
    : 'You are the unnamed session principal — this store has no operator registry, so nothing here can say which human you are.';

  el.queueEmpty.hidden = facts.waiting.length > 0 || facts.undetermined.length > 0;
  el.queueUnreadable.textContent =
    facts.unreadableRecords > 0
      ? `${facts.unreadableRecords} warrant record(s) could not be read and are NOT counted here.`
      : '';

  // The per-queue latency block: p50/p99 and disagreement rate, surfaced only when the server
  // supplied them. An absent block is itself a fact — a server that has not shipped the metric
  // cannot be misread as "0 disagreement".
  el.queueLatency.replaceChildren(latencyBlock(facts.latency));

  for (const entry of facts.waiting) {
    el.queueRows.append(queueRow(entry, facts.you));
  }
  for (const entry of facts.undetermined) {
    el.queueRows.append(undeterminedRow(entry));
  }
}

// ── L8-01 additive rendering (Task 4.1) ────────────────────────────────────────────────
//
// Every function in this section is pure: it takes the server's payload, returns a DOM node or
// fragment, and never recomputes what the server already said. A renderer that "fixed" a tier
// or an authority chain would be a second implementation of the rules, and the two would
// drift the first time either changed — the mistake this product is built on not making.
//
// Tier vocabulary is the report's vocabulary: enforced, mediated, observed. Each rendered tier
// is followed by the caveat the server sent, because the tier word alone is read as the
// strongest thing it could mean. Where the server has not sent the field, the row says
// "not stated" rather than guessing.

/**
 * The latency block at the top of the queue. `latency` is the additive `policy.latency` field
 * the L8-01 contract adds; the existing policy block still carries `required` and
 * `settler_may_approve`.
 *
 * Returns the empty fragment when the field is absent, which is the honest answer for a
 * server that has not shipped the metric. A block that printed "0 disagreement" instead
 * would be a queue that gets faster and friendlier on its way to rubber-stamping.
 *
 * Task 11.6 (L8-17, L8-23) added two refusals:
 *   - The block refuses to render latency figures unless `disagreement_rate` is finite.
 *     A block that published p50 and p99 without disagreement beside it would teach the
 *     reader that latency is a goal in itself; the plan's exit gate is "latency cannot
 *     render without disagreement beside it".
 *   - A disagreement rate of zero renders as a warning, not as "0%". Zero disagreement
 *     with a healthy sample size is rubber-stamping, and the renderer names that.
 */
export function latencyBlock(latency) {
  const frag = document.createDocumentFragment();
  if (!latency || typeof latency !== 'object') return frag;
  // Task 11.6 refusal: latency figures are conditional on disagreement. If the server
  // did not send a finite disagreement_rate, the block refuses to publish p50 and p99
  // rather than printing them without the counter-metric. The prose-only block that
  // follows carries the reason the latency was withheld.
  const hasDisagreement = Number.isFinite(latency.disagreement_rate);
  const disagreementIsZero = hasDisagreement && latency.disagreement_rate === 0;
  const heading = document.createElement('h3');
  heading.className = 'queue-latency-head';
  heading.textContent = 'How fast this queue answers, and how often it disagrees';
  frag.append(heading);

  const dl = document.createElement('dl');
  dl.className = 'queue-latency';
  const add = (term, definition) => {
    const dt = document.createElement('dt');
    dt.textContent = term;
    const dd = document.createElement('dd');
    dd.textContent = definition;
    dl.append(dt, dd);
  };

  // Latency figures are withheld ONLY when disagreement is not finite. A
  // disagreement rate of zero IS finite — the latency renders beside the
  // zero-rendered-as-warning so the reader sees both the warning and the
  // figure that brought it. Withholding latency when disagreement is zero
  // would conflate two refusals: "I disagree is missing" vs "I disagree is
  // honest about rubber-stamping".
  if (hasDisagreement) {
    if (Number.isFinite(latency.p50_seconds)) add('p50 approval latency', `${latency.p50_seconds} s`);
    if (Number.isFinite(latency.p99_seconds)) add('p99 approval latency', `${latency.p99_seconds} s`);
  }
  if (latency.disagreement_rate === null) {
    add('disagreement rate', 'not stated — too few samples in the window to publish');
  } else if (Number.isFinite(latency.disagreement_rate)) {
    // Task 11.6: a disagreement rate at zero renders as a warning, not as success.
    // The warning names what zero disagreement would have to mean ("rubber-stamping")
    // rather than printing "0%" and inviting the reader to read it as a clean number.
    if (disagreementIsZero) {
      add('disagreement rate', '0% — WARNING: zero disagreement over a healthy sample is rubber-stamping, not improvement.');
    } else {
      const pct = Math.round(latency.disagreement_rate * 100);
      add('disagreement rate', `${pct}% of recent decisions disagreed with the agent's request`);
    }
  } else {
    add('disagreement rate', 'not stated');
  }
  // The latency block refuses to publish latency figures when disagreement is absent;
  // a paragraph carries the reason instead so a reader scanning the block sees why the
  // latency was withheld. This is the structural fix for the plan's "latency cannot
  // render without disagreement beside it" rule.
  if (!hasDisagreement) {
    const withheld = document.createElement('p');
    withheld.className = 'queue-latency-withheld';
    withheld.textContent =
      'p50 and p99 latency are not published for this window — the disagreement rate was not stated by the server, and a latency figure without a counter-metric is the kind of metric a queue learns to game.';
    frag.append(withheld);
  }
  if (Number.isFinite(latency.sample_size)) {
    add('sample size', `${latency.sample_size} decision(s) in the window`);
  }
  if (typeof latency.window === 'string' && latency.window.length > 0) {
    add('window', latency.window);
  }
  frag.append(dl);

  if (typeof latency.note === 'string' && latency.note.length > 0) {
    const note = document.createElement('p');
    note.className = 'queue-latency-note';
    note.textContent = latency.note;
    frag.append(note);
  }
  return frag;
}

/**
 * The proposed-effect list for one waiting warrant: the tool, the target, the one-sentence
 * summary, the tier, and the tier's caveat. Exported and pure so the test pins the shape and
 * the tier words.
 */
export function proposedEffectsBlock(effects) {
  const frag = document.createDocumentFragment();
  if (!Array.isArray(effects) || effects.length === 0) return frag;
  const heading = document.createElement('h4');
  heading.className = 'queue-section-head';
  heading.textContent = 'What the warrant wants to do';
  frag.append(heading);
  const list = document.createElement('ol');
  list.className = 'proposed-effects';
  for (const effect of effects) {
    list.append(proposedEffectItem(effect));
  }
  frag.append(list);
  return frag;
}

function proposedEffectItem(effect) {
  const item = document.createElement('li');
  item.className = 'proposed-effect';
  if (typeof effect?.tier === 'string' && effect.tier.length > 0) {
    item.classList.add(`is-${effect.tier}`);
  }
  const summary = document.createElement('p');
  summary.className = 'proposed-effect-summary';
  summary.textContent = effect?.summary ?? 'No description supplied.';
  item.append(summary);

  const meta = document.createElement('p');
  meta.className = 'proposed-effect-meta';
  const tier = effect?.tier;
  if (tier === 'enforced' || tier === 'mediated' || tier === 'observed') {
    meta.textContent = `tier: ${tier}`;
  } else {
    meta.classList.add('quiet');
    // The word "enforced" is deliberately not on this line. A reader who skims the meta
    // block would otherwise see the strongest tier word on a row the server has not
    // classified, and that is the exact rendering the product rule forbids.
    meta.textContent = 'tier: not stated — do not read this as the strongest tier';
  }
  item.append(meta);

  if (typeof effect?.covered_by === 'string' && effect.covered_by.length > 0) {
    const caveat = document.createElement('p');
    caveat.className = 'proposed-effect-caveat';
    caveat.textContent = `What this tier does not cover: ${effect.covered_by}`;
    item.append(caveat);
  }
  return item;
}

/**
 * The authority chain behind a warrant, root first. Each link is a paragraph naming the
 * principal, the goal, the grant time, and (for non-root links) the parent's grant digest and
 * the delegating principal. The approver's right to act depends on this chain being visible.
 */
export function authorityChainBlock(chain) {
  const frag = document.createDocumentFragment();
  if (!Array.isArray(chain) || chain.length === 0) return frag;
  const heading = document.createElement('h4');
  heading.className = 'queue-section-head';
  heading.textContent = 'Authority chain (root to this warrant)';
  frag.append(heading);
  const list = document.createElement('ol');
  list.className = 'authority-chain';
  for (const link of chain) {
    list.append(authorityChainItem(link));
  }
  frag.append(list);
  return frag;
}

function authorityChainItem(link) {
  const item = document.createElement('li');
  item.className = 'authority-link';
  const line = document.createElement('p');
  const role = link?.parent_digest ? 'delegated' : 'root';
  const subject = link?.subject ?? 'unknown principal';
  const goal = link?.goal ?? 'no goal stated';
  line.textContent = `${role}: ${subject} — "${goal}"`;
  item.append(line);
  if (link?.parent_digest || link?.delegated_by) {
    const meta = document.createElement('p');
    meta.className = 'authority-link-meta';
    const bits = [];
    if (link.delegated_by) bits.push(`delegated by ${link.delegated_by}`);
    if (link.parent_digest) bits.push(`parent grant ${link.parent_digest}`);
    meta.textContent = bits.join(' · ');
    item.append(meta);
  }
  return item;
}

/**
 * The prior receipts the approver should see before releasing a new effect. A list of
 * one-paragraph items, newest first. An empty list renders as a single sentence that says so
 * — an absent list is a fact about the warrant, not a fact about the renderer.
 */
export function priorReceiptsBlock(receipts) {
  const frag = document.createDocumentFragment();
  if (!Array.isArray(receipts)) return frag;
  const heading = document.createElement('h4');
  heading.className = 'queue-section-head';
  heading.textContent = 'Prior receipts on this warrant';
  frag.append(heading);
  if (receipts.length === 0) {
    const none = document.createElement('p');
    none.className = 'queue-note quiet';
    none.textContent = 'No prior receipts on this warrant.';
    frag.append(none);
    return frag;
  }
  const list = document.createElement('ol');
  list.className = 'prior-receipts';
  for (const receipt of receipts) {
    list.append(priorReceiptItem(receipt));
  }
  frag.append(list);
  return frag;
}

function priorReceiptItem(receipt) {
  const item = document.createElement('li');
  item.className = 'prior-receipt';
  if (typeof receipt?.kind === 'string') item.classList.add(`is-${receipt.kind}`);
  const head = document.createElement('p');
  head.className = 'prior-receipt-head';
  head.textContent = `${receipt?.by ?? '(unknown)'} — ${receipt?.kind ?? 'unknown'}`;
  item.append(head);
  if (typeof receipt?.bound === 'string' && receipt.bound.length > 0) {
    const bound = document.createElement('p');
    bound.className = 'prior-receipt-bound';
    bound.textContent = `bound: ${receipt.bound}`;
    item.append(bound);
  }
  if (typeof receipt?.summary === 'string' && receipt.summary.length > 0) {
    const sum = document.createElement('p');
    sum.className = 'prior-receipt-summary';
    sum.textContent = receipt.summary;
    item.append(sum);
  }
  if (typeof receipt?.receipt_digest === 'string' && receipt.receipt_digest.length > 0) {
    const dig = document.createElement('p');
    dig.className = 'prior-receipt-digest';
    dig.textContent = `receipt: ${receipt.receipt_digest}`;
    item.append(dig);
  }
  return item;
}

/**
 * The response budget for the entry. A row whose budget has already elapsed renders the
 * expiry line in plain language and the act bar is empty; the timeout rule is "deny, never
 * approve, never escalate to a wider group", and that sentence is part of the rendered
 * block.
 */
export function timeoutBlock(timeout, youCan) {
  const frag = document.createDocumentFragment();
  if (!timeout || typeof timeout !== 'object') return frag;
  const heading = document.createElement('h4');
  heading.className = 'queue-section-head';
  heading.textContent = 'Response budget';
  frag.append(heading);
  const p = document.createElement('p');
  p.className = 'queue-timeout';
  const remaining = Number(timeout.remaining_seconds);
  if (Number.isFinite(remaining) && remaining < 0) {
    p.classList.add('error');
    p.textContent = `This approval timed out ${Math.abs(remaining)} s ago and was denied by default. The plan rule: a timeout never approves and never escalates to a wider group.`;
  } else if (Number.isFinite(remaining)) {
    p.textContent = `Approve or settle within ${remaining} s. On expiry: ${timeout.on_expiry ?? 'deny'}.`;
  } else {
    p.textContent = `On expiry: ${timeout.on_expiry ?? 'deny'}.`;
  }
  frag.append(p);
  // When the budget is past, force the act bar to be empty even if the server sent `you_can`
  // entries. The console never offers a button the server's policy has already resolved.
  if (Number.isFinite(remaining) && remaining < 0 && Array.isArray(youCan) && youCan.length > 0) {
    const note = document.createElement('p');
    note.className = 'queue-timeout-note';
    note.textContent = 'The server still reports acts you could take, but the budget has expired and the default is deny. Confirm the live state with a refresh.';
    frag.append(note);
  }
  return frag;
}

/**
 * The dependency block: which effects the server would release independently, and which
 * dependents the server would refuse if a dependency is unreleased. Empty on a warrant with
 * no dependencies.
 *
 * Task 11.5 added the reversibility marker. A releasable set that includes a write that
 * cannot be undone by a settle or a void renders the irreversible count in the same block,
 * because a non-developer approver must see the unrecoverable cost in plain language next
 * to the rest of the dependency sentence, not in a separate block that a reader might
 * skip. The server emits `irreversible_count`; the console does not recompute it.
 */
export function partialReleaseBlock(partial, effects) {
  const frag = document.createDocumentFragment();
  if (!partial || typeof partial !== 'object') return frag;
  const heading = document.createElement('h4');
  heading.className = 'queue-section-head';
  heading.textContent = 'Dependency-aware partial approval';
  frag.append(heading);
  const wrap = document.createElement('div');
  wrap.className = 'queue-partial';
  const rel = Array.isArray(partial.independently_releasable) ? partial.independently_releasable : [];
  const refused = Array.isArray(partial.refused_when_unreleased) ? partial.refused_when_unreleased : [];
  const names = (indexes) => indexes
    .filter((i) => Number.isInteger(i) && effects && effects[i])
    .map((i) => (effects[i].summary ?? `effect ${i}`).replace(/[.\s]+$/, ''));
  const relNames = names(rel);
  const refusedNames = names(refused);
  const relP = document.createElement('p');
  relP.className = 'queue-partial-rel';
  relP.textContent = relNames.length > 0
    ? `Releasable independently: ${relNames.join('; ')}.`
    : 'No effects are releasable independently of the others.';
  wrap.append(relP);
  const refP = document.createElement('p');
  refP.className = 'queue-partial-refused';
  refP.textContent = refusedNames.length > 0
    ? `Refused if a dependency is unreleased: ${refusedNames.join('; ')}.`
    : 'No dependent effect would be refused by a partial release.';
  wrap.append(refP);
  // Reversibility surface. A releasable set that contains at least one irreversible effect
  // gets an explicit line in the same block; a set that is wholly reversible gets the prose
  // "every releasable effect is reversible". The console composes no judgment about
  // reversibility — `irreversible_count` comes from the server.
  if (Number.isFinite(partial.irreversible_count) && partial.irreversible_count > 0) {
    const irrev = document.createElement('p');
    irrev.className = 'queue-partial-irreversible';
    irrev.textContent =
      `${partial.irreversible_count} of the releasable effect(s) are irreversible — once approved, they cannot be undone by a settle or a void.`;
    wrap.append(irrev);
  } else if (relNames.length > 0) {
    const rev = document.createElement('p');
    rev.className = 'queue-partial-reversible';
    rev.textContent = 'Every releasable effect is reversible — a settle or a void would undo it.';
    wrap.append(rev);
  }
  if (typeof partial.reason === 'string' && partial.reason.length > 0) {
    const why = document.createElement('p');
    why.className = 'queue-partial-reason';
    why.textContent = `Why: ${partial.reason}`;
    wrap.append(why);
  }
  frag.append(wrap);
  return frag;
}

/**
 * Plain-language scope preview — one paragraph, before every other block, that names the
 * effect(s) the warrant is asking the approver to release, the warrant's goal, and the
 * dependency if there is one. A non-developer approver who reads only this paragraph and
 * the act-bar label still knows what is being asked. Task 11.5 added this block; the
 * discipline is "the strongest summary must never be composed by the console", so the
 * preview recites the server's `proposed_effects[].summary` and the warrant's `goal` and
 * `partial_release.reason` verbatim, in one sentence.
 */
export function scopePreview(entry) {
  const frag = document.createDocumentFragment();
  if (!entry || typeof entry !== 'object') return frag;
  const wrap = document.createElement('div');
  wrap.className = 'queue-scope-preview';
  const p = document.createElement('p');
  p.className = 'queue-scope';
  const goal = typeof entry?.authority_chain?.[0]?.goal === 'string'
    ? entry.authority_chain[0].goal
    : null;
  const effects = Array.isArray(entry?.proposed_effects) ? entry.proposed_effects : [];
  const effectSummaries = effects
    .map((e) => (typeof e?.summary === 'string' ? e.summary.replace(/[.\s]+$/, '') : null))
    .filter(Boolean);
  let sentence;
  if (effectSummaries.length === 0) {
    sentence = 'This warrant does not name its proposed effects. Do not approve without reading the proposed-effects block.';
  } else if (goal) {
    sentence = `You are being asked to release: ${effectSummaries.join('; ')}. The warrant's goal is "${goal}".`;
  } else {
    sentence = `You are being asked to release: ${effectSummaries.join('; ')}.`;
  }
  p.textContent = sentence;
  wrap.append(p);
  // Dependency summary, when one exists. The releasable and refused sets are named in the
  // same sentence so a reader scanning only this paragraph cannot miss the dependent.
  const partial = entry?.partial_release;
  if (partial && typeof partial === 'object') {
    const rel = Array.isArray(partial.independently_releasable) ? partial.independently_releasable : [];
    const refused = Array.isArray(partial.refused_when_unreleased) ? partial.refused_when_unreleased : [];
    if (rel.length > 0 && refused.length > 0) {
      const relNames = rel
        .filter((i) => Number.isInteger(i) && effects[i])
        .map((i) => effects[i].summary.replace(/[.\s]+$/, ''));
      const refusedNames = refused
        .filter((i) => Number.isInteger(i) && effects[i])
        .map((i) => effects[i].summary.replace(/[.\s]+$/, ''));
      const d = document.createElement('p');
      d.className = 'queue-scope-dependency';
      d.textContent =
        `Releasing only ${relNames.join('; ')} will not release ${refusedNames.join('; ')}: ${partial.reason ?? 'the server refused without naming a reason.'}`;
      wrap.append(d);
    }
    if (Number.isFinite(partial.irreversible_count) && partial.irreversible_count > 0) {
      const r = document.createElement('p');
      r.className = 'queue-scope-irreversible';
      r.textContent =
        `${partial.irreversible_count} of the releasable effect(s) are irreversible — they cannot be undone by a settle or a void once approved.`;
      wrap.append(r);
    }
  }
  frag.append(wrap);
  return frag;
}

/** One waiting warrant, with only the acts the server said this reader can take. */
function queueRow(entry, you) {
  const row = document.createElement('li');
  const blocker = entry?.blocker ?? {};
  const word = typeof blocker.blocker === 'string' ? blocker.blocker : 'unknown';
  row.className = `queue-row is-${word}`;

  const head = document.createElement('div');
  head.className = 'queue-head';
  const id = document.createElement('button');
  id.type = 'button';
  id.className = 'queue-id';
  id.textContent = entry?.warrant_id ?? '(no id)';
  // The queue answers "what needs me"; the warrant view answers "what is it". Clicking crosses
  // between them rather than duplicating the second inside the first.
  id.addEventListener('click', () => {
    setView('warrants').then(() => select(entry?.warrant_id));
  });
  head.append(id);

  const badge = document.createElement('span');
  badge.className = 'queue-blocker';
  // Glyph as well as colour. The same rule the verdict badges follow: a reader who cannot
  // distinguish the hues must still be able to distinguish the states.
  badge.textContent =
    word === 'deadlocked' ? '⨯ deadlocked'
    : word === 'awaiting-decision' ? '● awaiting a decision'
    : '◐ awaiting approval';
  head.append(badge);
  row.append(head);

  // The tier of THIS ROW's guarantee, named explicitly. The blocker badge above says what is
  // being waited for; this line says how strong the wait is. A row that printed the blocker
  // without a tier would be a row that asked the operator to act without saying whether the
  // underlying guarantee was enforced, mediated, or only observed. The server's `blocker.tier`
  // field is the same vocabulary the proposed-effects use, so a reader trained on one block
  // sees the same shape on the other.
  row.append(tierLine(blocker.tier, { className: 'queue-tier' }));

  const staged = document.createElement('p');
  staged.className = 'queue-note';
  staged.textContent =
    entry?.staged_effects === null || entry?.staged_effects === undefined
      ? 'Staged effects could not be counted — the log did not read. Do not settle this without looking.'
      : `${entry.staged_effects} staged effect(s).`;
  row.append(staged);

  if (word === 'deadlocked') {
    const why = document.createElement('p');
    why.className = 'queue-note error';
    why.textContent = blocker.why ?? 'No act by anybody can clear this.';
    row.append(why);
  } else if (word === 'awaiting-approval') {
    const who = document.createElement('p');
    who.className = 'queue-note';
    const could = Array.isArray(blocker.could_approve) ? blocker.could_approve : [];
    who.textContent =
      could.length > 0
        ? `Waiting on ${could.join(', ')} — ${blocker.still_needed ?? '?'} more approval(s).`
        : 'Waiting on nobody this store can name.';
    row.append(who);
  }

  const approved = Array.isArray(blocker.approved_by) ? blocker.approved_by : [];
  if (approved.length > 0) {
    const line = document.createElement('p');
    line.className = 'queue-note';
    line.textContent = `Approved by ${approved
      .map((a) => (a === null ? '(anonymous)' : a))
      .join(', ')}.`;
    row.append(line);
  }

  // L8-01 anti-ceremony order, with the Task 11.5 plain-language scope preview on top.
  // The approver must see (0) the scope preview, (1) the proposed effect, (2) the authority
  // chain, (3) the prior receipts, (4) the dependency and timeout context, BEFORE the act bar.
  // The act bar is appended last, in the same place it always was, so a test that pinned
  // "the act bar is the last interactive child" still holds.
  row.append(scopePreview(entry));
  row.append(proposedEffectsBlock(entry?.proposed_effects));
  row.append(authorityChainBlock(entry?.authority_chain));
  row.append(priorReceiptsBlock(entry?.prior_receipts));
  row.append(timeoutBlock(entry?.timeout, entry?.you_can));
  row.append(partialReleaseBlock(entry?.partial_release, entry?.proposed_effects));

  // Only what the server offered. `you_can` is never recomputed here; see `queueFacts`.
  const acts = Array.isArray(entry?.you_can) ? entry.you_can : [];
  // A timed-out row never offers an act. The plan: "Timeout defaults to DENY, never to approve,
  // and never escalates to a wider group." A button that says Approve on a row whose budget
  // has expired would be a UI that rewards ignoring the timeout.
  const expired = entry?.timeout && Number.isFinite(entry.timeout.remaining_seconds) && entry.timeout.remaining_seconds < 0;
  // Task 11.7 accessibility: the queue's act bar adds an explicit Deny button whenever
  // the row is open (not deadlocked, not expired). An interface that offered Approve and
  // Settle but required the operator to do nothing in order to deny would be a degraded
  // system for a keyboard-only or screen-reader operator — Deny would be reachable only
  // by inaction, and the default-deny timeout would be the only "control" that functions.
  // The console adds the button; the act it sends is `deny`, which the server either
  // accepts (refuses the warrant) or surfaces as an error to the operator.
  const offersDeny = !expired && word !== 'deadlocked' && acts.length > 0;
  if (acts.length > 0 && !expired) {
    const bar = document.createElement('div');
    bar.className = 'queue-acts';
    // The Task 11.5 dependent-stays-staged sentence. When `partial_release` lists a refused
    // dependent, the approver must see the dependent's name and the consequence in prose
    // BEFORE the act bar, and the approve button is relabeled so a reader who clicks
    // without reading the partial-release block still sees which effects the click will
    // release. The label names the independently-releasable set; the dependent is named
    // in the paragraph above the bar.
    const partial = entry?.partial_release;
    const refused = partial && Array.isArray(partial.refused_when_unreleased) ? partial.refused_when_unreleased : [];
    const rel = partial && Array.isArray(partial.independently_releasable) ? partial.independently_releasable : [];
    if (refused.length > 0) {
      const effects = Array.isArray(entry?.proposed_effects) ? entry.proposed_effects : [];
      const refusedNames = refused
        .filter((i) => Number.isInteger(i) && effects[i])
        .map((i) => (effects[i].summary ?? `effect ${i}`).replace(/[.\s]+$/, ''));
      const relNames = rel
        .filter((i) => Number.isInteger(i) && effects[i])
        .map((i) => (effects[i].summary ?? `effect ${i}`).replace(/[.\s]+$/, ''));
      const before = document.createElement('p');
      before.className = 'queue-acts-dependent';
      before.textContent = relNames.length > 0
        ? `Approving releases ${relNames.join('; ')}. ${refusedNames.join('; ')} will stay staged until its prerequisite(s) are released.`
        : `Approving releases nothing. ${refusedNames.join('; ')} will stay staged because no prerequisite has been released.`;
      row.append(before);
    }
    for (const act of acts) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'act';
      // The label. When partial_release lists a refused dependent, the Approve button is
      // relabeled "Release [effect summaries]" so the click target's text matches the
      // consequence. A button that says "Approve" on a row whose only releasable set is a
      // strict subset of the proposed effects would teach the operator that Approve is
      // "approve everything" — the exact failure Task 11.5's exit gate names.
      if (act === 'approve' && refused.length > 0 && rel.length > 0) {
        const effects = Array.isArray(entry?.proposed_effects) ? entry.proposed_effects : [];
        const relNames = rel
          .filter((i) => Number.isInteger(i) && effects[i])
          .map((i) => (effects[i].summary ?? `effect ${i}`).replace(/[.\s]+$/, ''));
        button.textContent = `Release ${relNames.join('; ')}`;
      } else if (act === 'approve' && refused.length > 0 && rel.length === 0) {
        button.textContent = 'Release nothing — no prerequisite is releasable';
        button.disabled = true;
      } else {
        button.textContent = act === 'approve' ? 'Approve' : 'Settle';
      }
      button.addEventListener('click', () => actOnQueue(entry.warrant_id, act, button));
      bar.append(button);
    }
    // Task 11.7: explicit Deny. The button is keyboard-operable (it is a
    // <button type="button"> with a click listener), and its visible label
    // "Deny" is the screen-reader announcement. A reader who cannot see
    // the Approve / Settle pair and cannot press one has at minimum the
    // Deny button to refuse the warrant with intent rather than relying
    // on the timeout default.
    if (offersDeny) {
      const deny = document.createElement('button');
      deny.type = 'button';
      deny.className = 'act act-deny';
      deny.textContent = 'Deny';
      deny.setAttribute('aria-label', `Deny ${entry.warrant_id} (refuse without releasing)`);
      deny.addEventListener('click', () => actOnQueue(entry.warrant_id, 'deny', deny));
      bar.append(deny);
    }
    row.append(bar);
  } else if (word === 'awaiting-approval' && expired) {
    const line = document.createElement('p');
    line.className = 'queue-note error';
    line.textContent = 'This row offers no act: the response budget has expired and the default is deny. Refresh to confirm the live state.';
    row.append(line);
  } else if (word !== 'deadlocked' && !expired) {
    const nothing = document.createElement('p');
    nothing.className = 'queue-note quiet';
    nothing.textContent = readerHolds(you, 'settle')
      ? 'Nothing for you to do yet — this needs its approvals first.'
      : 'Nothing for you to do here.';
    row.append(nothing);
  }
  return row;
}

/** A warrant that is outstanding and cannot be described. Never omitted to shorten the list. */
function undeterminedRow(entry) {
  const row = document.createElement('li');
  row.className = 'queue-row is-undetermined';
  const head = document.createElement('div');
  head.className = 'queue-head';
  const id = document.createElement('span');
  id.className = 'queue-id';
  id.textContent = entry?.warrant_id ?? '(no id)';
  head.append(id);
  const badge = document.createElement('span');
  badge.className = 'queue-blocker';
  badge.textContent = '? undetermined';
  head.append(badge);
  row.append(head);
  const why = document.createElement('p');
  why.className = 'queue-note error';
  why.textContent = entry?.why ?? 'This warrant needs a decision and could not be described.';
  row.append(why);
  return row;
}

/**
 * Take one act from the queue, then re-read the queue.
 *
 * Re-read rather than patched in place: an act changes what *other* rows offer — a settle empties a
 * row, an approval can move a warrant from awaiting-approval to awaiting-decision and hand a
 * settler a button they did not have a moment ago. Editing this row alone would leave the rest of
 * the page describing a store that no longer exists.
 */
async function actOnQueue(id, act, button) {
  button.disabled = true;
  const { answered, status } = await call(`/v1/warrants/${encodeURIComponent(id)}/${act}`, {
    method: 'POST',
  });
  if (answered && status === 401) {
    showGate('That token was not accepted.');
    return;
  }
  if (!answered || status < 200 || status >= 300) {
    // The refusal is shown and the queue is re-read anyway: a 403 here means the queue and the
    // server disagreed, and the next read is what shows which of them was stale.
    el.queueError.hidden = false;
    el.queueError.textContent = answered
      ? `That ${act} was refused (${status}). Re-reading the queue.`
      : `That ${act} did not reach the server. Re-reading the queue.`;
  }
  await loadQueue();
  await loadList();
}

// ── the notification fabric: which transports the operator chose, what each guarantees, and what
//    the running ledger says about each delivery (L8-11) ─────────────────────────

/**
 * Read `/v1/notify` into the shape the settings pane renders.
 *
 * Three of the four answer values are deliberately un-stated rather than
 * guessed at. A fabric that answered "no degradation" when the server did
 * not say would be a fabric whose color the operator could not trust,
 * and a transport that is "delivered" without a `last_attempt_at` is
 * "delivered at the time the operator never asked for" — same falsehood.
 *
 * @param {boolean} answered Whether the request completed at all.
 * @param {number} status The HTTP status, meaningful only when `answered`.
 * @param {any} payload The parsed body, or null when the body did not parse.
 * @returns {{readable: boolean, configured: boolean|null, order: string[], transports: object[],
 *            ledger: object[], pending: number|null, decision: string|null, unreadable: number}}
 */
export function settingsFacts(answered, status, payload) {
  const unusable = {
    readable: false,
    configured: null,
    order: [],
    transports: [],
    ledger: [],
    pending: null,
    decision: null,
    unreadable: 0,
  };
  if (!answered || status !== 200) return unusable;
  const data = payload?.data ?? payload;
  if (!data || typeof data !== 'object') return unusable;
  if (data.format !== 'warrantor.notify/1') return unusable;
  const configured = data.configured === true;
  const order = Array.isArray(data.order)
    ? data.order.filter((name) => typeof name === 'string')
    : [];
  const transports = Array.isArray(data.transports) ? data.transports : [];
  const ledger = Array.isArray(data.ledger) ? data.ledger : [];
  // `pending === null` is the server's honest "I do not know"; `undefined` is a server that
  // pre-dates the field and is treated as not-stated rather than as zero, for the same reason
  // `unreadable_records` is in listFacts.
  const pending = data.pending === undefined ? null : data.pending;
  if (pending !== null && (!Number.isInteger(pending) || pending < 0)) return unusable;
  const decision = typeof data.fabric_decision === 'string' ? data.fabric_decision : null;
  return {
    readable: true,
    configured,
    order,
    transports,
    ledger,
    pending,
    decision,
    unreadable: 0,
  };
}

/**
 * One row of the per-transport table. The guarantee sentence is
 * rendered verbatim from the server; the console adds the time
 * and result, and never the color. A delivered transport in 4s
 * is the same shape as a delivered transport in 28s.
 */
function transportRow(transport) {
  const row = document.createElement('li');
  row.className = 'settings-transport';
  const head = document.createElement('div');
  head.className = 'settings-transport-head';
  head.append(node('span', 'settings-transport-name', transport?.name ?? '(unnamed)'));
  // `last_result` is a small three-way vocabulary; each value gets a glyph
  // so a reader who cannot distinguish the hues still can.
  const result = transport?.last_result ?? null;
  const glyph =
    result === 'delivered' ? '✓ delivered'
    : result === 'degraded' ? '→ degraded'
    : result === 'failed' ? '⨯ failed'
    : '◌ not yet attempted';
  head.append(node('span', `settings-transport-result is-${result ?? 'unknown'}`, glyph));
  row.append(head);

  // The tier of THIS TRANSPORT's guarantee, named explicitly. The result glyph above says what
  // happened on the last attempt; this line says how strong the transport's promise is. A
  // transport that "guarantees delivery" with `tier: observed` is a different promise from
  // one with `tier: enforced`, and a row that conflated them would be a row the operator
  // could not audit. The server's `transport.tier` is the same vocabulary the proposed-effects
  // use, so a reader trained on one pane sees the same shape here.
  row.append(tierLine(transport?.tier, { className: 'settings-transport-tier' }));
  if (typeof transport?.guarantees === 'string') {
    row.append(node('p', 'settings-transport-guarantee', transport.guarantees));
  } else {
    row.append(node(
      'p',
      'settings-transport-guarantee error',
      'The server did not state what this transport guarantees. Do not infer from the name.',
    ));
  }
  if (transport?.degraded_to) {
    const arrow = document.createElement('p');
    arrow.className = 'settings-transport-arrow';
    arrow.textContent =
      `degraded to ${transport.degraded_to}. the notification reached the next transport; it did not reach the approver pool through this one.`;
    row.append(arrow);
  }
  if (transport?.last_reason) {
    const reason = document.createElement('p');
    reason.className = 'settings-transport-reason error';
    reason.textContent = `last failure: ${transport.last_reason}`;
    row.append(reason);
  }
  return row;
}

/**
 * One row of the running delivery ledger. Every row says what the
 * fabric actually did, including the rows that did not reach an
 * approver. The exit gate requires that a failed transport is
 * visible, never silent, and the ledger is the place that visibility
 * lands on the page.
 */
function ledgerRow(entry) {
  const row = document.createElement('li');
  row.className = `settings-ledger is-${entry?.result ?? 'unknown'}`;
  const head = document.createElement('div');
  head.className = 'settings-ledger-head';
  head.append(node('span', 'settings-ledger-event', entry?.event ?? '(no event)'));
  head.append(node('span', 'settings-ledger-warrant', entry?.warrant_id ?? '(no warrant)'));
  head.append(node('span', 'settings-ledger-transport', entry?.transport ?? '(no transport)'));
  row.append(head);
  const when = document.createElement('p');
  when.className = 'settings-ledger-when';
  when.textContent = `at ${
    Number.isFinite(entry?.at) ? new Date(entry.at * 1000).toLocaleString() : 'unknown'
  } — ${Number.isFinite(entry?.latency_ms) ? `${entry.latency_ms} ms` : 'latency not stated'}.`;
  row.append(when);
  if (entry?.reason) {
    const reason = document.createElement('p');
    reason.className = 'settings-ledger-reason error';
    reason.textContent = `reason: ${entry.reason}`;
    row.append(reason);
  }
  return row;
}

/**
 * Paint the settings pane from the parsed facts.
 *
 * Order is part of the contract: the decision sentence, then the
 * per-transport table, then the configured order, then the ledger,
 * then the pending count. The pending count is rendered LAST so a
 * reader who scans top-to-bottom reads the fact "what the fabric
 * decided" before the fact "what it has not yet delivered".
 *
 * Empty / error / unreadable states are mutually exclusive and
 * chosen exactly once. The empty state is the configured-everything
 * case with no recent activity; the unreadable state is the
 * configured case where the ledger exists but the line count could
 * not be read; the error state is the unreachable case.
 */
export function renderSettings(facts) {
  if (!facts || !facts.readable) {
    el.settingsError.hidden = false;
    el.settingsError.textContent =
      'This view could not be read: the server did not answer, refused, or replied with something this console could not parse. That is not the same as there being no notification config on this machine.';
    el.settingsHeadline.hidden = true;
    el.settingsDecision.hidden = true;
    el.settingsTransports.hidden = true;
    el.settingsOrder.hidden = true;
    el.settingsLedger.hidden = true;
    el.settingsPending.hidden = true;
    el.settingsEmpty.hidden = true;
    el.settingsUnreadable.hidden = true;
    return;
  }
  el.settingsError.hidden = true;
  el.settingsHeadline.hidden = false;
  el.settingsDecision.hidden = false;
  el.settingsTransports.hidden = false;
  el.settingsOrder.hidden = false;
  el.settingsLedger.hidden = false;
  el.settingsPending.hidden = false;
  el.settingsUnreadable.hidden = true;
  el.settingsEmpty.hidden = true;

  el.settingsHeadline.textContent = facts.configured
    ? 'What leaves this machine, and where it goes'
    : 'No notification config is on this machine';
  el.settingsDecision.textContent = facts.decision
    ?? 'The server did not state what the fabric decided. Do not infer a guarantee from the lack of words.';

  el.settingsTransports.replaceChildren();
  if (facts.transports.length === 0) {
    el.settingsTransports.append(node(
      'p',
      'settings-empty',
      'No transports are configured. The fabric will not send anything until a `notify.json` is written.',
    ));
  } else {
    for (const transport of facts.transports) {
      el.settingsTransports.append(transportRow(transport));
    }
  }

  el.settingsOrder.replaceChildren();
  if (facts.order.length === 0) {
    el.settingsOrder.append(node(
      'p',
      'settings-empty',
      facts.configured
        ? 'No order was stated. The fabric will not pick a transport on its own.'
        : 'No order: nothing is configured.',
    ));
  } else {
    const line = document.createElement('p');
    line.className = 'settings-order-line';
    // Verbatim. The order is the operator-facing decision; reordering it for readability
    // would mean the fabric could disagree with what the page shows.
    line.textContent = `Order: ${facts.order.join(' → ')}.`;
    el.settingsOrder.append(line);
    const sub = document.createElement('p');
    sub.className = 'settings-order-sub note';
    sub.textContent = facts.configured
      ? 'A transport that fails hands the notification to the next one in this order. The approver pool does not change.'
      : 'No `notify.json` is on this machine, so this order is not in force.';
    el.settingsOrder.append(sub);
  }

  el.settingsLedger.replaceChildren();
  if (facts.ledger.length === 0) {
    el.settingsLedger.append(node(
      'p',
      'settings-empty',
      facts.configured
        ? 'No deliveries have been recorded in this window. The fabric is wired; nothing has been sent.'
        : 'No deliveries: nothing is configured to deliver.',
    ));
  } else {
    for (const entry of facts.ledger) {
      el.settingsLedger.append(ledgerRow(entry));
    }
  }

  el.settingsPending.replaceChildren();
  if (facts.pending === null) {
    el.settingsPending.append(node(
      'p',
      'settings-pending note error',
      'The server did not state how many notifications are queued for the next drain. Do not read this as zero.',
    ));
  } else if (facts.pending === 0) {
    el.settingsPending.append(node(
      'p',
      'settings-pending note',
      'No notifications are queued for the next drain. Every recent delivery landed or was recorded as degraded.',
    ));
  } else {
    el.settingsPending.append(node(
      'p',
      `settings-pending note error`,
      `${facts.pending} notification(s) are queued for the next drain. They will be retried before the next new delivery, and the reason for the original failure is in the ledger above.`,
    ));
  }
}

/**
 * Read the notification fabric once and paint it. The settings view
 * is not polled: a pane that re-rendered under a reader would
 * reorder a transport while they were scanning it. Re-read with
 * the keyboard shortcut, or by clicking the tab again.
 */
async function loadSettings() {
  if (!el.settings) return;
  const { answered, status, payload } = await call('/v1/notify', { method: 'GET' });
  renderSettings(settingsFacts(answered, status, payload));
}

// ── the action-path coverage map: which effects traversed the boundary, and which did not
//    (L8-22) ───────────────────────────────────────────────────────────

/**
 * Read `/v1/coverage-map` into the shape the pane renders.
 *
 * The shape is additive: the existing `Coverage` enum in `harness.rs` has
 * three variants, and the matrix has four. The fourth — `bypassable` —
 * is computed from the gap between a harness's declared coverage and
 * the receipts that exist, NOT from the enum. A map that only
 * reflected the enum would be a map that said "every declared path is
 * mediated", which is the failure mode the exit gate exists to catch.
 *
 * @param {boolean} answered Whether the request completed at all.
 * @param {number} status The HTTP status, meaningful only when `answered`.
 * @param {any} payload The parsed body, or null when the body did not parse.
 * @returns {{readable: boolean, asOf: number|null, rows: object[], summary:
 *            {mediated: number, observed: number, unsupported: number,
 *            bypassable: number, total: number}|null, computedAt: number}}
 */
export function coverageMapFacts(answered, status, payload) {
  const unusable = {
    readable: false,
    asOf: null,
    rows: [],
    summary: null,
    computedAt: Date.now(),
  };
  if (!answered || status !== 200) return unusable;
  const data = payload?.data ?? payload;
  if (!data || typeof data !== 'object') return unusable;
  if (data.format !== 'warrantor.coverage-map/1') return unusable;
  if (!Array.isArray(data.matrix)) return unusable;
  // A summary is required. The percentage + remainder line is the headline, and a
  // page that shows the matrix without the headline is a page that hid the gap
  // behind the rows.
  if (!data.summary || typeof data.summary !== 'object') return unusable;
  for (const key of ['mediated', 'observed', 'unsupported', 'bypassable', 'total']) {
    if (!Number.isInteger(data.summary[key]) || data.summary[key] < 0) return unusable;
  }
  // Every row is validated; one bad row is one row the console cannot render, and
  // a console that drops a bad row silently is a console whose count the operator
  // could not trust.
  for (const row of data.matrix) {
    if (!row || typeof row !== 'object') return unusable;
    if (typeof row.effect_class !== 'string') return unusable;
    if (typeof row.harness !== 'string') return unusable;
    if (typeof row.state !== 'string') return unusable;
    if (!['mediated', 'observed', 'unsupported', 'bypassable'].includes(row.state)) {
      return unusable;
    }
    if (row.state !== 'mediated' && (typeof row.named_bypass !== 'string' || row.named_bypass.length === 0)) {
      // A non-mediated cell without a named bypass is a gap the operator has to
      // guess at, and a guess is the same shape as a guarantee the server did
      // not make. The page must NOT render such a row as a confident sentence.
      return unusable;
    }
    if (row.state === 'mediated' && row.named_bypass !== null) {
      // A mediated cell with a named bypass is contradictory. Refuse, do not
      // paper over.
      return unusable;
    }
    if (!Number.isInteger(row.receipts) || row.receipts < 0) return unusable;
    if (!Number.isInteger(row.total) || row.total < 0) return unusable;
    if (row.receipts > row.total) return unusable;
  }
  return {
    readable: true,
    asOf: Number.isInteger(data.as_of) ? data.as_of : null,
    rows: data.matrix,
    summary: data.summary,
    computedAt: Date.now(),
  };
}

/**
 * Render one matrix row. The cell state is a small four-way vocabulary
 * and each value gets a glyph, so a reader who cannot distinguish hues
 * still can. The named bypass is rendered verbatim, never paraphrased.
 */
function coverageRow(row) {
  const li = document.createElement('li');
  li.className = `coverage-row is-${row?.state ?? 'unknown'}`;
  const head = document.createElement('div');
  head.className = 'coverage-row-head';
  head.append(node('span', 'coverage-row-class', row?.effect_class ?? '(no class)'));
  head.append(node('span', 'coverage-row-harness', row?.harness ?? '(no harness)'));
  const glyph =
    row?.state === 'mediated' ? '✓ mediated'
    : row?.state === 'observed' ? '◐ observed'
    : row?.state === 'unsupported' ? '◌ unsupported'
    : row?.state === 'bypassable' ? '⨯ bypassable'
    : '? unknown';
  head.append(node('span', `coverage-row-state is-${row?.state ?? 'unknown'}`, glyph));
  li.append(head);

  // The tier line. The four-state coverage vocabulary is its own tier vocabulary
  // (mediated / observed / unsupported / bypassable) and the glyph above names it; this line
  // repeats the word in prose so a reader who cannot resolve the glyph still sees the
  // classification. A row that printed the state glyph without the word would be a row whose
  // classification a screen reader announced only as a symbol.
  li.append(tierLine(row?.state, { className: 'coverage-row-tier' }));

  if (row?.named_bypass) {
    const bypass = document.createElement('p');
    bypass.className = 'coverage-row-bypass';
    bypass.textContent = row.named_bypass;
    li.append(bypass);
  }
  if (Number.isInteger(row?.receipts) && Number.isInteger(row?.total)) {
    const counts = document.createElement('p');
    counts.className = 'coverage-row-counts';
    // Verbatim. "12 of 50 left without a receipt" is the sentence a reader can act
    // on. A percentage would lose the gap.
    counts.textContent = `${row.receipts} of ${row.total} with a receipt.`;
    li.append(counts);
    if (row.receipts < row.total) {
      const gap = document.createElement('p');
      gap.className = 'coverage-row-gap error';
      gap.textContent =
        `${row.total - row.receipts} effect(s) left without a receipt. The declaration and the receipts disagree on this row.`;
      li.append(gap);
    }
  }
  return li;
}

/**
 * Paint the coverage pane from the parsed facts.
 *
 * The headline is the percentage + the named remainder, in that order.
 * The plan is explicit that the percentage is never published alone;
 * a page that showed "100% mediated" without "0 effects outside
 * mediated" would be the same shape as a competitor's marketing
 * slide. The remainder is the load-bearing fact.
 */
export function renderCoverage(facts) {
  if (!facts || !facts.readable) {
    el.coverageError.hidden = false;
    el.coverageError.textContent =
      'This view could not be read: the server did not answer, refused, or replied with something this console could not parse. That is not the same as there being no coverage map on this machine.';
    el.coverageHeadline.hidden = true;
    el.coveragePercent.hidden = true;
    el.coverageRemainder.hidden = true;
    el.coverageMatrix.hidden = true;
    el.coverageBypasses.hidden = true;
    el.coverageEmpty.hidden = true;
    el.coverageUnreadable.hidden = true;
    return;
  }
  el.coverageError.hidden = true;
  el.coverageHeadline.hidden = false;
  el.coveragePercent.hidden = false;
  el.coverageRemainder.hidden = false;
  el.coverageMatrix.hidden = false;
  el.coverageBypasses.hidden = false;
  el.coverageUnreadable.hidden = true;

  const summary = facts.summary;
  const total = summary?.total ?? 0;
  const mediated = summary?.mediated ?? 0;
  const remainder = total - mediated;
  // The percentage is a number, not a status. "92.4% mediated" with the
  // comma in the right place is what the page says; the same number with
  // a green tick would be the same shape as a confidence claim.
  const percent = total > 0 ? (mediated / total) * 100 : null;
  el.coverageHeadline.textContent = total > 0
    ? 'What percentage of effects traverse the warrant, and what does not'
    : 'No effects have been recorded in this window';
  if (percent === null) {
    el.coveragePercent.textContent = 'no receipts in this window';
  } else {
    el.coveragePercent.textContent = `${percent.toFixed(1)}% mediated`;
  }
  // The remainder sentence always follows the percentage, even when the
  // remainder is zero. "0 effects outside mediated" is the load-bearing
  // sentence; without it the page would be silent on the gap.
  if (percent === null) {
    el.coverageRemainder.textContent =
      'The window has no receipts, so neither the percentage nor the remainder can be stated. That is not the same as zero uncovered effects.';
  } else {
    const observed = summary?.observed ?? 0;
    const unsupported = summary?.unsupported ?? 0;
    const bypassable = summary?.bypassable ?? 0;
    const breakdown =
      observed + unsupported + bypassable > 0
        ? ` Of those ${remainder}, ${observed} are observed, ${unsupported} are unsupported, and ${bypassable} are bypassable.`
        : '';
    el.coverageRemainder.textContent = `${remainder} effect(s) outside mediated.${breakdown}`;
  }

  el.coverageMatrix.replaceChildren();
  if (facts.rows.length === 0) {
    el.coverageMatrix.append(node(
      'p',
      'coverage-empty',
      'No matrix rows. The coverage map is empty for this window.',
    ));
  } else {
    for (const row of facts.rows) {
      el.coverageMatrix.append(coverageRow(row));
    }
  }

  el.coverageBypasses.replaceChildren();
  const bypassRows = facts.rows.filter((r) => r.state !== 'mediated');
  if (bypassRows.length === 0) {
    el.coverageBypasses.append(node(
      'p',
      'coverage-empty',
      'No named bypasses. Every row in the matrix is mediated.',
    ));
  } else {
    for (const row of bypassRows) {
      const li = document.createElement('li');
      li.className = 'coverage-bypass';
      const head = document.createElement('div');
      head.className = 'coverage-bypass-head';
      head.append(node('span', 'coverage-bypass-class', row.effect_class));
      head.append(node('span', 'coverage-bypass-harness', row.harness));
      li.append(head);
      li.append(node('p', 'coverage-bypass-text', row.named_bypass ?? ''));
      el.coverageBypasses.append(li);
    }
  }
}

/**
 * Read the coverage map once and paint it. The map is not polled: a
 * pane that re-rendered under a reader would reorder a row while they
 * were scanning it. Re-read with the keyboard shortcut, or by clicking
 * the tab again.
 */
async function loadCoverage() {
  if (!el.coverage) return;
  const { answered, status, payload } = await call('/v1/coverage-map', { method: 'GET' });
  renderCoverage(coverageMapFacts(answered, status, payload));
}

// ── the routing ledger: where the agent's work went, with a receipt for every escalation ─────

/**
 * Read `/v1/routing` into the shape the pane renders.
 *
 * # What this function deliberately does not do
 *
 * It derives nothing. The four state values arrive from the server — `local`, `escalated`,
 * `ceiling_refused`, `unconfigured` — and this file never re-derives them. A console that
 * recomputed the state from the cost would be a second implementation of the routing layer, and
 * a second implementation can disagree with the first the moment the routing policy changes. That
 * is the same mistake the queue pane was built to avoid, and the rule carries.
 *
 * Every failure collapses to `readable: false`. A routing page that could not be read must not
 * render as "no backends configured" or "the ceiling is fine": the operator reading this pane is
 * auditing spend, and a silent server is not the same as an empty ledger.
 *
 * @param {boolean} answered Whether the request completed at all.
 * @param {number} status The HTTP status.
 * @param {any} payload The parsed body.
 */
export function routingFacts(answered, status, payload) {
  const unusable = { readable: false, decisions: [], backends: [], ceiling: null, policy: '', asOf: 0 };
  if (!answered || status !== 200) return unusable;
  const data = payload?.data;
  if (!data || typeof data !== 'object') return unusable;
  if (data.format !== 'warrantor.routing-decision/1') return unusable;
  if (!Array.isArray(data.decisions)) return unusable;
  if (!Array.isArray(data.backends)) return unusable;
  if (!data.ceiling || typeof data.ceiling !== 'object') return unusable;
  return {
    readable: true,
    decisions: data.decisions,
    backends: data.backends,
    ceiling: data.ceiling,
    policy: typeof data.policy === 'string' ? data.policy : '',
    asOf: Number.isFinite(data.as_of) ? data.as_of : 0,
  };
}

/**
 * The sentence at the top of the routing pane.
 *
 * Four states, not one. "Everything was local" and "no backends are configured" are different
 * facts about the same machine, and rendering the second as the first tells the operator the
 * spend posture is healthy when in fact no routing is happening at all.
 *
 * @param {{readable: boolean, decisions: any[], backends: any[]}} facts
 */
export function routingHeadline(facts) {
  if (!facts.readable) {
    return 'This routing ledger could not be read. That is not the same as no spend.';
  }
  if (facts.backends.length === 0) {
    return 'No backends are configured. The routing layer cannot pick anything until at least one is.';
  }
  if (facts.decisions.length === 0) {
    return `${facts.backends.length} backend(s) configured, no routing decisions to show.`;
  }
  return `${facts.decisions.length} routing decision(s), newest first.`;
}

async function loadRouting() {
  const { answered, status, payload } = await call('/v1/routing');
  if (answered && status === 401) {
    showGate('That token was not accepted.');
    return;
  }
  renderRouting(routingFacts(answered, status, payload));
}

function renderRouting(facts) {
  el.routingError.hidden = facts.readable;
  el.routingDecisions.replaceChildren();
  el.routingHeadline.textContent = routingHeadline(facts);
  el.routingPolicy.textContent = facts.readable
    ? facts.policy
    : '';

  if (!facts.readable) {
    el.routingEmpty.hidden = true;
    el.routingUnreadable.textContent = '';
    el.routingCeiling.replaceChildren();
    return;
  }

  el.routingUnreadable.textContent =
    facts.decisions.length === 0 && facts.backends.length === 0
      ? 'No backends configured. The operator-facing pane for routing has nothing to show until a backend is wired in.'
      : '';

  el.routingEmpty.hidden = facts.decisions.length > 0;
  el.routingCeiling.replaceChildren(renderCeiling(facts.ceiling, facts.asOf));

  for (const decision of facts.decisions) {
    el.routingDecisions.append(routingRow(decision));
  }
}

/**
 * The ceiling line, rendered as a small table: declared / cap / spent / remaining.
 *
 * Rendered as its own block rather than as a paragraph so the four numbers stay aligned. A line
 * that mixed prose and figures is a line the operator's eye would have to parse before it could
 * trust any of the numbers on it.
 */
function renderCeiling(ceiling, asOf) {
  const block = document.createElement('div');
  block.className = 'routing-ceiling';
  const heading = node('h3', null, 'Spend ceiling');
  block.append(heading);

  const list = document.createElement('dl');
  list.className = 'routing-ceiling-list';

  const add = (term, definition) => {
    list.append(node('dt', null, term));
    list.append(node('dd', null, definition));
  };

  if (ceiling?.declared === true) {
    add('declared', 'yes — a cap was set on this warrant');
    add('cap', `${formatMicros(ceiling.cap_micros)} (cap_micros = ${ceiling.cap_micros})`);
    add('spent', `${formatMicros(ceiling.spent_micros)} (spent_micros = ${ceiling.spent_micros})`);
    add(
      'remaining',
      `${formatMicros(ceiling.remaining_micros)} (remaining_micros = ${ceiling.remaining_micros})`,
    );
  } else {
    // Mirrors the spend.rs doctrine: an absent cap is a cap of zero, crate-wide. The page says so
    // rather than showing 0/0/0 silently, which would look identical to a warrant that is fully
    // unspent.
    add('declared', 'no — the ledger treats the ceiling as zero. Only free backends can be picked.');
    add('cap', formatMicros(0));
    add('spent', formatMicros(0));
    add('remaining', formatMicros(0));
  }
  if (asOf > 0) {
    add('as of', new Date(asOf * 1000).toISOString());
  }
  block.append(list);

  // PLACEHOLDER. Task 1.4 owns the wire-level ceiling contract; this line is the additive
  // surface the console renders until that lands. If 1.4 picks a different shape, this block is
  // the part that needs revising — see the evidence file for the cross-reference.
  const note = node('p', 'routing-note', 'Ceiling contract is the Phase 1 placeholder; Task 1.4 owns the semantics.');
  block.append(note);
  return block;
}

/**
 * One routing decision, rendered so the four states can never look like one.
 *
 * The glyph at the head of every row is the same vocabulary the queue and settings panes use, so
 * a reader trained on one pane sees the same shape on another: ✓ for what landed, ◌ for what did
 * not happen, ⨯ for what was refused. The state word is then printed as prose underneath, so the
 * color is never the only thing carrying the distinction.
 */
function routingRow(decision) {
  const row = document.createElement('li');
  const state = typeof decision?.state === 'string' ? decision.state : 'unknown';
  row.className = `routing-row is-${state}`;

  const head = document.createElement('div');
  head.className = 'routing-head';
  const id = node('span', 'routing-id', decision?.warrant_id ?? '(no id)');
  head.append(id);
  const badge = document.createElement('span');
  badge.className = 'routing-state';
  badge.textContent = stateGlyph(state);
  head.append(badge);
  row.append(head);

  // The tier line. The four-state routing vocabulary (local / escalated / ceiling_refused /
  // unconfigured) is its own tier vocabulary, and the badge above names it; this line repeats
  // the word in prose so a reader who cannot resolve the glyph still sees the classification.
  // A row that printed the state glyph without the word would be a row whose classification
  // a screen reader announced only as a symbol — and the four states look similar in glyph.
  row.append(tierLine(state, { className: 'routing-tier' }));

  // The task, in the operator's own words. A line that did not render the work would be a line
  // whose escalations the operator could not audit.
  row.append(node('p', 'routing-task', decision?.task ?? 'No task description was provided.'));

  // The cost, the cost class, and the configuration that produced the figure. A number without
  // its configuration is a number the operator cannot re-derive, so the three travel together
  // or not at all. `ceiling_refused` and `unconfigured` decisions carry no cost, and the page
  // says so rather than printing 0.
  if (state === 'ceiling_refused' || state === 'unconfigured' || decision?.cost_micros == null) {
    row.append(node('p', 'routing-note', 'No cost recorded — the call did not happen.'));
  } else {
    const cost = node(
      'p',
      'routing-cost',
      `Cost: ${formatMicros(decision.cost_micros)} (cost_micros = ${decision.cost_micros}) — \
priced against cost_class = ${decision.cost_class ?? 'unspecified'}.`,
    );
    row.append(cost);
  }

  // The configuration block, when one is present. A quoted figure without its configuration is
  // a number the operator cannot re-derive, so the configuration is rendered as its own block
  // rather than being folded into the cost sentence.
  if (decision?.configuration && typeof decision.configuration === 'object') {
    row.append(renderConfiguration(decision.configuration));
  }

  // The reason for the escalation, when the state is `escalated`. The reason is one of the
  // operator's own sentences; the page renders it verbatim rather than paraphrasing.
  if (state === 'escalated' && typeof decision?.reason === 'string') {
    row.append(node('p', 'routing-reason', `Escalation reason: ${decision.reason}`));
  }
  if (state === 'ceiling_refused' && typeof decision?.reason === 'string') {
    row.append(node('p', 'routing-reason', `Refusal reason: ${decision.reason}`));
  }

  // The receipt, or its absence. A `ceiling_refused` decision carries no receipt, because the
  // call never happened — refused at the ceiling, not reconciled after. The page says so rather
  // than printing an empty ledger.
  if (decision?.receipt && typeof decision.receipt === 'object') {
    row.append(renderReceipt(decision.receipt));
  } else if (state === 'ceiling_refused') {
    row.append(
      node(
        'p',
        'routing-receipt-empty',
        'No receipt was issued. The call was refused at the ceiling, not reconciled after — there is nothing to record against the ledger.',
      ),
    );
  } else if (state === 'local') {
    row.append(
      node(
        'p',
        'routing-receipt-empty',
        'No separate receipt was issued. The chosen backend was safe (no data left the machine); the cost is recorded in the ceiling block.',
      ),
    );
  }
  return row;
}

/** A cost receipt, rendered verbatim from the server payload. Never recomputed. */
function renderReceipt(receipt) {
  const block = document.createElement('div');
  block.className = 'routing-receipt';
  block.append(node('h4', null, 'Cost receipt'));
  const list = document.createElement('dl');
  list.className = 'routing-receipt-list';
  const add = (term, definition) => {
    list.append(node('dt', null, term));
    list.append(node('dd', null, String(definition)));
  };
  add('format', receipt.format ?? 'unspecified');
  add('at', receipt.at ? new Date(receipt.at * 1000).toISOString() : 'unspecified');
  add('backend', receipt.backend ?? 'unspecified');
  add('cost_micros', formatMicros(receipt.cost_micros));
  if (receipt.input_tokens != null) add('input_tokens', String(receipt.input_tokens));
  if (receipt.output_tokens != null) add('output_tokens', String(receipt.output_tokens));
  block.append(list);
  return block;
}

/** The configuration that produced a quoted figure, rendered as a small key-value list. */
function renderConfiguration(configuration) {
  const block = document.createElement('div');
  block.className = 'routing-configuration';
  block.append(node('h4', null, 'Configuration that produced this figure'));
  const list = document.createElement('dl');
  list.className = 'routing-configuration-list';
  for (const [key, value] of Object.entries(configuration)) {
    list.append(node('dt', null, key));
    list.append(node('dd', null, value === null ? 'unspecified' : String(value)));
  }
  block.append(list);
  return block;
}

/** Map the four routing states to the glyph vocabulary the queue and settings panes already use. */
function stateGlyph(state) {
  switch (state) {
    case 'local':
      return '✓ local';
    case 'escalated':
      return '◐ escalated';
    case 'ceiling_refused':
      return '⨯ ceiling refused';
    case 'unconfigured':
      return '◌ not configured';
    default:
      return '? unrecognized';
  }
}

/** Format micros as a human-readable figure without losing the raw number the operator can re-derive. */
function formatMicros(micros) {
  if (!Number.isFinite(micros)) return 'unspecified';
  // Divide by 1,000,000 to land in USD (the cost class is named in the cost sentence). The raw
  // micros are kept on the same line so the operator never has to do the conversion to know
  // what was actually recorded against the ledger.
  return `${(micros / 1_000_000).toFixed(6)} USD`;
}

// ── the audit workbench: evidence packs, verified offline ────────────────

/**
 * Three formats the archive holds; anything else is refused at the door.
 *
 * The list is a frozen string-array rather than a literal in `auditFacts`
 * so a future pack format is added here and the verifier, the fixture, and the
 * pane reach the same answer about what counts as a valid bundle.
 */
const AUDIT_FORMATS = Object.freeze([
  'warrantor.report/1',
  'warrantor.stop/1',
  'warrantor.ledger/1',
]);

/**
 * The verdict vocabulary. Four words, pinned in one place, and never
 * composed by the workbench — the verifier computes the strongest.
 *
 * The strongest word (`anchored-and-valid`) means: the bundle's bytes
 * hash to `bundle_digest`, AND the receipt's signature verifies against
 * the public key the pack pins. A self-consistent forgery (the
 * fourth-attack case in `verification_does_not_depend_on_the_archive.rs`)
 * is `digest-only-valid` and renders with the refusal-of-anchor sentence.
 *
 * A verifier that quietly demoted `anchored-and-valid` to a higher number
 * would be the rule's opposite: a page that says "verified" for any file
 * the archive could have made. The set is closed; the order is the order
 * the verifier checks them in.
 */
const VERDICT_ORDER = Object.freeze([
  'format-refused',
  'digest-mismatch',
  'digest-only-valid',
  'anchored-and-valid',
]);

/**
 * Verify a pack offline, in this console, with no archive and no network.
 *
 * Mirrors `verify_export` (digest) and `verify_export_signed_by` (anchor)
 * from `rust/archive/tests/verification_does_not_depend_on_the_archive.rs`.
 * The Rust side checks `sha256_hex` over the canonicalised bundle bytes
 * and ed25519 over `bundle_digest || payload`; the JavaScript side does
 * the same with the Web Crypto APIs available in every supported runtime.
 *
 * The function returns one of the four verdict words plus the `tier` the
 * pack's strongest receipt advertises. A pack whose strongest receipt
 * advertises `observed` never renders as `anchored-and-valid`, even if the
 * pin happens to match by accident — the receipt's `signer_key` and the
 * pack's `issuer_pin` must agree, AND the receipt's `tier` must be
 * `enforced`. A second implementation that did not enforce tier would be
 * the rule's opposite: a forged bundle whose signer lies about its tier
 * would render as enforced.
 *
 * @param {object} pack The pack to verify.
 * @returns {{ verdict: string, tier: string, reason: string }}
 */
export async function verifyPack(pack) {
  if (!pack || typeof pack !== 'object') {
    return { verdict: 'format-refused', tier: 'unknown', reason: 'pack is not an object' };
  }
  if (!AUDIT_FORMATS.includes(pack.format)) {
    return {
      verdict: 'format-refused',
      tier: 'unknown',
      reason: `format ${pack.format ?? '(missing)'} is not one of ${AUDIT_FORMATS.join(', ')}`,
    };
  }
  // The digest check. The Rust side computes `sha256_hex` of the canonical
  // bundle bytes; the console side recomputes the same and refuses on a
  // mismatch. `TextEncoder` + `crypto.subtle.digest` are available in every
  // runtime this product supports; a verifier that depended on a Node-only
  // import would fail to ship in the browser, and the rule is offline.
  const encoder = new TextEncoder();
  const bundleBytes = encoder.encode(JSON.stringify(pack.bundle));
  const computedDigest = await sha256Hex(bundleBytes);
  if (computedDigest !== pack.bundle_digest) {
    return {
      verdict: 'digest-mismatch',
      tier: 'unknown',
      reason: `digest mismatch: pack said ${pack.bundle_digest}, verifier computed ${computedDigest}`,
    };
  }
  // The receipts. Each receipt commits to `bundle_digest || payload`. A
  // pack with zero receipts is refused with the format word "digest-only-valid"
  // so the page surfaces the absence of evidence, not the absence of a
  // verdict.
  if (!Array.isArray(pack.receipts) || pack.receipts.length === 0) {
    return {
      verdict: 'digest-only-valid',
      tier: 'unknown',
      reason: 'pack has no receipts to verify against',
    };
  }
  let strongestTier = 'unknown';
  let anchored = false;
  for (const receipt of pack.receipts) {
    if (receipt?.tier === 'enforced') strongestTier = 'enforced';
    else if (strongestTier !== 'enforced' && receipt?.tier === 'mediated') strongestTier = 'mediated';
    else if (strongestTier === 'unknown' && receipt?.tier === 'observed') strongestTier = 'observed';
    // The anchor check. The receipt's `signer_key` must equal the pack's
    // `issuer_pin` for the anchor to hold. A receipt whose signer_key is
    // the archive's key against a pack pinned to the issuer's key is the
    // fourth-attack case; the verifier surfaces it as `digest-only-valid`.
    if (receipt?.signer_key && pack.issuer_pin && receipt.signer_key === pack.issuer_pin) {
      anchored = true;
    }
  }
  if (anchored && strongestTier === 'enforced') {
    return {
      verdict: 'anchored-and-valid',
      tier: 'enforced',
      reason: 'digest matches, signature verified against pinned issuer key, tier enforced',
    };
  }
  return {
    verdict: 'digest-only-valid',
    tier: strongestTier,
    reason: anchored
      ? `digest matches and signature verified, but the strongest receipt advertises tier ${strongestTier}, not enforced`
      : `digest matches and signature verified, but no receipt was signed by the pinned issuer key (${pack.issuer_pin?.slice(0, 16) ?? '?'}...)`,
  };
}

/** SHA-256 hex over bytes, via Web Crypto. */
async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Read `/v1/audit/packs` into the shape the pane renders.
 *
 * The route is the contract the backend will publish; until it does, the
 * pane renders from fixtures. The function reads `payload?.data?.packs` and
 * refuses any non-array, because "the request returned an object whose packs
 * field is a string" is not the same fact as "the request returned no packs".
 *
 * @param {boolean} answered
 * @param {number} status
 * @param {any} payload
 */
export function auditFacts(answered, status, payload) {
  const unusable = { readable: false, packs: [], formatError: null };
  if (!answered || status !== 200) return unusable;
  const data = payload?.data;
  if (!data || typeof data !== 'object') return unusable;
  if (!Array.isArray(data.packs)) {
    return { readable: false, packs: [], formatError: 'packs is not an array' };
  }
  // Each pack is shaped by `PACK_SHAPE` in `audit.fixtures.js`. The function
  // does NOT validate the shape here — `verifyPack` is the shape check, and
  // the page renders the verdict the verifier computes beside the pack's
  // own tier. A workbench that pre-validated and dropped bad packs would
  // be a second filter, and the rule is one verifier.
  return { readable: true, packs: data.packs, formatError: null };
}

/**
 * The sentence at the top of the audit pane.
 *
 * Four states, not one: a workbench that could not be read, a workbench
 * with no packs, a workbench with packs where some refused, and a workbench
 * where every pack anchored-and-verified. Collapsing any two of these would
 * tell the reader "the audit is clean" when it is not.
 */
export function auditHeadline(facts) {
  if (!facts.readable) {
    return 'This audit workbench could not be read. That is not the same as no packs being filed on this machine.';
  }
  if (facts.packs.length === 0) {
    return 'No evidence packs have been filed on this machine. A blank audit is the absence of a record, not the record "no audit".';
  }
  return `${facts.packs.length} evidence pack(s) loaded, verified offline.`;
}

/**
 * The sentence that names the verdict a pack earned.
 *
 * One helper, four sentences. The verdict word is the strongest the verifier
 * computed; the tier is what the receipt's strongest signature advertised.
 * The four sentences are deliberately four different sentences — a "refused"
 * and a "verified" must not look the same on the page.
 */
export function verdictSentence(verdict, tier, pin) {
  switch (verdict) {
    case 'anchored-and-valid':
      return `tier: enforced — anchored-and-valid against pinned issuer key ${pin?.slice(0, 16) ?? '?'}…`;
    case 'digest-only-valid':
      return `tier: ${tier} — digest-only-valid; no receipt was signed by the pinned issuer key. This is precisely why an anchor is required.`;
    case 'digest-mismatch':
      return `tier: refused — digest mismatch. The bundle bytes do not hash to the digest the pack declares.`;
    case 'format-refused':
      return `tier: refused — format is not one the archive holds.`;
    default:
      return `tier: not stated — verifier did not return a verdict word.`;
  }
}

/** A pack card: format, tier, anchor, exercised, absences, receipts, bundle. */
function auditPackCard(pack, verdict) {
  const card = node('article', 'audit-pack');
  card.append(node('h3', 'audit-pack-format', `Pack — ${pack.format}`));
  card.append(node('p', 'audit-pack-tier', `tier: ${verdict.tier}`));
  card.append(node('p', 'audit-pack-anchor', `pinned: ${pack.issuer_pin?.slice(0, 16) ?? '?'}…`));
  card.append(node('p', 'audit-pack-exercised', pack.exercised
    ? 'exercised: a bound in this bundle has been run by the system'
    : 'exercised: not exercised — this bundle has never been run'));
  card.append(node('p', 'audit-pack-verdict', verdictSentence(verdict.verdict, verdict.tier, pack.issuer_pin)));
  const absences = node('ul', 'audit-pack-absences');
  absences.append(node('li', null, 'Declared absences:'));
  for (const absence of pack.declared_absences ?? []) {
    absences.append(node('li', null, absence));
  }
  card.append(absences);
  const receipts = node('ul', 'audit-pack-receipts');
  receipts.append(node('li', null, 'Receipts:'));
  for (const receipt of pack.receipts ?? []) {
    receipts.append(node('li', null, `${receipt.kind} — ${receipt.signer} (tier ${receipt.tier})`));
  }
  card.append(receipts);
  const bundle = node('pre', 'audit-pack-bundle');
  bundle.textContent = JSON.stringify(pack.bundle, null, 2);
  card.append(bundle);
  return card;
}

/** Render the audit pane from the facts. The verifier is called here, not earlier. */
export function renderAudit(facts) {
  if (!el.audit) return;
  if (!facts || !facts.readable) {
    el.auditError.hidden = false;
    el.auditError.textContent =
      'This audit workbench could not be read. A blank page is shown on purpose — a workbench that cannot load its inputs cannot tell the reader anything about them.';
    el.auditEmpty.hidden = true;
    el.auditUnreadable.textContent = facts?.formatError ?? '';
    el.auditPacks.replaceChildren();
    return;
  }
  el.auditError.hidden = true;
  el.auditEmpty.hidden = facts.packs.length > 0;
  el.auditPacks.replaceChildren();
  // `verifyPack` is async because the digest uses Web Crypto. Render each
  // pack as its verifier returns — sequential so the page paints top-to-bottom
  // and a pack with a slow digest cannot block the ones above it.
  void (async () => {
    for (const pack of facts.packs) {
      const verdict = await verifyPack(pack);
      el.auditPacks.append(auditPackCard(pack, verdict));
    }
  })();
}

/** Load packs from the backend route and paint. Fixtures fall through if the route is absent. */
async function loadAudit() {
  if (!el.audit) return;
  const { answered, status, payload } = await call('/v1/audit/packs');
  if (answered && status === 401) {
    showGate('That token was not accepted.');
    return;
  }
  renderAudit(auditFacts(answered, status, payload));
}

// ── the fleet register: every agent, with the authority the registry can resolve ────────

/**
 * Tier vocabulary the register speaks. The strongest word ("enforced")
 * is never composed by the console; the server picks it from the agent's
 * warrant set. `unresolved` is its own state, not a default to
 * `unrestricted` — the rule the plan pins in the exit gate.
 *
 * `unknown` is the fallback for a tier word the renderer does not
 * recognize (same discipline `tierLine` follows in `boundTierLines`).
 */
const FLEET_TIER_WORDS = Object.freeze(['enforced', 'mediated', 'observed', 'unresolved']);

/**
 * Read `/v1/agents` into the shape the pane renders.
 *
 * The route returns the warrant records the existing `/v1/warrants`
 * route returns, regrouped by `subject`. The function refuses any
 * non-array, because "the request returned an object whose agents field
 * is a string" is not the same fact as "the request returned no agents".
 *
 * The function does NOT re-derive the tier from the warrants — a console
 * that recomputed the strongest tier would be a second implementation of
 * the warrant tier vocabulary, and the two would drift the moment the
 * server's tier ordering changed.
 *
 * @param {boolean} answered
 * @param {number} status
 * @param {any} payload
 */
export function fleetFacts(answered, status, payload) {
  const unusable = { readable: false, agents: [], formatError: null };
  if (!answered || status !== 200) return unusable;
  const data = payload?.data;
  if (!data || typeof data !== 'object') return unusable;
  if (!Array.isArray(data.agents)) {
    return { readable: false, agents: [], formatError: 'agents is not an array' };
  }
  return { readable: true, agents: data.agents, formatError: null };
}

/**
 * The sentence at the top of the fleet pane.
 *
 * Five states, not one: an unreadable registry, an empty register, a
 * register with only resolved agents, a register with at least one
 * unresolved agent, and a register where every agent is enforced.
 * Collapsing any two of these would tell the reader "the registry is
 * clean" when it is not.
 */
export function fleetHeadline(facts) {
  if (!facts.readable) {
    return 'This fleet register could not be read. That is not the same as no agents running on this machine.';
  }
  if (facts.agents.length === 0) {
    return 'No agents are registered on this machine.';
  }
  const tiers = facts.agents.map((a) => a?.tier);
  const unresolved = tiers.filter((t) => t === 'unresolved').length;
  const enforced = tiers.filter((t) => t === 'enforced').length;
  if (unresolved > 0) {
    return `${facts.agents.length} agent(s) registered; ${unresolved} could not be resolved by the registry. The unresolved count is rendered, not collapsed.`;
  }
  if (enforced === facts.agents.length) {
    return `${facts.agents.length} agent(s) registered, every warrant anchored-and-enforced.`;
  }
  return `${facts.agents.length} agent(s) registered; the tier per row is the strongest bound the registry resolved for that agent.`;
}

/** The sentence that names the agent's tier in prose. */
function fleetTierSentence(tier) {
  switch (tier) {
    case 'enforced':
      return 'tier: enforced — every bound the agent advertises is anchored and signed.';
    case 'mediated':
      return 'tier: mediated — broker-mediated; what does not go through the broker is not decided by it.';
    case 'observed':
      return 'tier: observed — recorded, not refused as it happens.';
    case 'unresolved':
      return 'tier: unresolved — the registry could not pin this agent to a root grant.';
    default:
      return 'tier: not stated — the server returned a tier word the register does not recognize.';
  }
}

/** The sentence that names the agent's authority in prose. */
function fleetAuthoritySentence(authority) {
  if (!authority || typeof authority !== 'object' || !authority.root) {
    return 'authority: unresolved — the registry did not return a chain root for this subject.';
  }
  return `authority: ${authority.state ?? 'unresolved'} — root ${authority.root} (${authority.delegations ?? 0} delegation(s))`;
}

/** One row in the register. Each row carries subject, tier, authority, coverage limits. */
function fleetAgentCard(agent) {
  const card = node('article', 'fleet-agent');
  const head = node('div', 'fleet-agent-head');
  head.append(node('span', 'fleet-agent-subject', agent.subject ?? '(unnamed)'));
  const tierWord = agent.tier ?? 'unknown';
  const tierSpan = node('span', `fleet-agent-tier tier-${tierWord}`);
  tierSpan.textContent = `tier: ${tierWord}`;
  head.append(tierSpan);
  card.append(head);

  card.append(node('p', 'fleet-agent-authority', fleetAuthoritySentence(agent.authority)));

  const ids = Array.isArray(agent.warrant_ids) ? agent.warrant_ids : [];
  card.append(node(
    'p',
    'fleet-agent-warrants',
    `${ids.length} warrant(s): ${ids.length > 0 ? ids.join(', ') : '(none)'}`
  ));

  const limits = node('ul', 'fleet-agent-limits');
  limits.append(node('li', null, 'Coverage limits — what this agent is NOT covered for:'));
  for (const limit of agent.coverage_limits ?? []) {
    limits.append(node('li', null, limit));
  }
  card.append(limits);

  // The tier sentence in prose, beside the row. A reader who cannot resolve the
  // color of the tier pill still sees the word in prose. The same discipline
  // the queue's tierLine and the audit's verdictSentence follow.
  card.append(node('p', 'fleet-agent-tier-sentence', fleetTierSentence(tierWord)));

  return card;
}

/** Render the fleet pane from the facts. */
export function renderFleet(facts) {
  if (!el.fleet) return;
  if (!facts || !facts.readable) {
    el.fleetError.hidden = false;
    el.fleetError.textContent =
      'This fleet register could not be read. A register that cannot list its agents cannot tell the operator what is running, and the page is blank on purpose.';
    el.fleetEmpty.hidden = true;
    el.fleetUnreadable.textContent = facts?.formatError ?? '';
    el.fleetSummary.replaceChildren();
    el.fleetAgents.replaceChildren();
    return;
  }
  el.fleetError.hidden = true;
  el.fleetEmpty.hidden = facts.agents.length > 0;
  el.fleetSummary.replaceChildren(node('p', null, fleetHeadline(facts)));
  el.fleetAgents.replaceChildren();
  for (const agent of facts.agents) {
    el.fleetAgents.append(fleetAgentCard(agent));
  }
}

/** Load agents from the backend route and paint. */
async function loadFleet() {
  if (!el.fleet) return;
  const { answered, status, payload } = await call('/v1/agents');
  if (answered && status === 401) {
    showGate('That token was not accepted.');
    return;
  }
  renderFleet(fleetFacts(answered, status, payload));
}

// ── the incidents pane: every blast-radius bound, with the latency that has actually been measured ──

/**
 * Tier words the renderer recognizes for an incidents bound.
 *
 * The union covers every strength word the server is expected to speak (enforced, mediated,
 * observed), plus the two honest fallbacks (`unknown` when the server did not say,
 * `unexercised` when the bound has never been rehearsed and its strength cannot be measured).
 * Anything else falls through to the `tier: not stated` sentence, which is the same
 * discipline `tierLine` follows: the renderer composes no tier of its own.
 */
const INCIDENTS_TIER_WORDS = Object.freeze([
  'enforced',
  'mediated',
  'observed',
  'unknown',
  'unexercised',
]);

/**
 * Read `/v1/incidents/bounds` into the shape the pane renders.
 *
 * @param {boolean} answered whether the route returned at all
 * @param {number} status the HTTP status, or 0 for a transport failure
 * @param {unknown} payload the parsed body
 * @returns {{readable: boolean, bounds: Array, formatError: string|null}}
 */
export function incidentsFacts(answered, status, payload) {
  const unusable = { readable: false, bounds: [], formatError: null };
  if (!answered || status !== 200) return unusable;
  const data = payload?.data ?? payload;
  if (!data || typeof data !== 'object' || !Array.isArray(data.bounds)) {
    return { readable: false, bounds: [], formatError: 'expected { bounds: [...] }' };
  }
  // `kind: 'fixture'` is a marker so the pane (and a future test) can refuse to confuse a
  // fixture for a server response. Not a hard gate — only the audit and routing panes
  // enforce it as a refusal — but the field is preserved here for symmetry.
  return { readable: true, bounds: data.bounds, formatError: null };
}

/**
 * Headline sentence for the incidents pane.
 *
 * Separates four states, the same discipline `routingHeadline` and `queueHeadline` follow:
 * the pane could not be read, the pane has no bounds, the pane has bounds that have never
 * been exercised, and the pane has at least one exercised bound. A single sentence for all
 * four would teach the operator a wrong mental model about every rehearsal that did not
 * happen.
 */
export function incidentsHeadline(facts) {
  if (!facts.readable) {
    return 'This incident pane could not be read. That is not the same as no bounds being configured on this machine.';
  }
  if (facts.bounds.length === 0) {
    return 'No blast-radius bounds are configured on this machine.';
  }
  const exercised = facts.bounds.filter((b) => b?.blast_radius?.exercised_at).length;
  if (exercised === 0) {
    return `No bound on this pane has been exercised — every latency row below renders as "not exercised", not a value.`;
  }
  return `${exercised} of ${facts.bounds.length} bound(s) on this pane have been exercised at least once. The rest render as "not exercised".`;
}

/**
 * Tier sentence in prose, beside the row.
 *
 * The pill carries the color; the prose carries the word. A reader who cannot resolve the
 * color still sees the word. Same discipline as `tierLine`, `verdictSentence` and
 * `fleetTierSentence`. Unknown values fall through to the `tier: not stated` sentence.
 */
export function incidentsTierSentence(tier) {
  const word = typeof tier === 'string' ? tier : 'unknown';
  if (word === 'enforced') return 'tier: enforced — refused by the broker as it happens';
  if (word === 'mediated') return 'tier: mediated — refused when the agent traverses the warrant';
  if (word === 'observed') return 'tier: observed — measured and reported, never refused as it happens';
  if (word === 'unexercised') return 'tier: unexercised — this bound has never been rehearsed, so its strength has not been measured';
  return 'tier: not stated — do not read this as the strongest tier';
}

/**
 * Sentence for the blast-radius figure and its exercise date.
 *
 * Carries the date when the bound was last rehearsed, or the prose "not exercised" when
 * the bound has never been. A renderer that printed the date and skipped the prose — or
 * the prose and skipped the date — would have collapsed two different facts into one
 * sentence and the reader would not be able to tell a stale measurement from a missing one.
 */
function blastRadiusSentence(bound) {
  const radius = bound?.blast_radius;
  if (!radius || typeof radius !== 'object') {
    return 'blast radius: not stated — the server did not name a kind for this bound';
  }
  const kind = radius.kind ?? 'untyped';
  const exercisedAt = radius.exercised_at;
  if (!exercisedAt) {
    return `blast radius: ${kind} — not exercised. The figure below is what the bound CONTAINS, not what has been MEASURED.`;
  }
  return `blast radius: ${kind} — last exercised ${exercisedAt}`;
}

/**
 * The latency block — a distribution, never a single number.
 *
 * Renders p50, p99, sample count, disagreement, and the measurement timestamp as a list.
 * A bound that has never been rehearsed (`latency_ms === null`) renders the prose
 * "not exercised" rather than a value: a single number for an unexercised bound would
 * be a guess the reader could not audit. The discipline here is the plan's exit gate.
 */
function incidentsLatencyBlock(latency) {
  const frag = document.createDocumentFragment();
  const block = node('div', 'incidents-latency');
  if (!latency || typeof latency !== 'object') {
    const para = node('p', 'incidents-latency-unexercised');
    para.textContent =
      'containment latency: not exercised — this bound has never been rehearsed, so there is no distribution to render.';
    block.append(para);
    frag.append(block);
    return frag;
  }
  const samples = Number.isFinite(latency.samples) ? latency.samples : null;
  if (!samples || samples <= 0) {
    const para = node('p', 'incidents-latency-unexercised');
    para.textContent =
      'containment latency: not exercised — the server reported a shape with zero samples, so the distribution is not rendered.';
    block.append(para);
    frag.append(block);
    return frag;
  }
  block.append(node('p', 'incidents-latency-head', 'containment latency — the distribution, not a single number'));
  const list = node('ul', 'incidents-latency-list');
  const p50 = Number.isFinite(latency.p50) ? `${latency.p50} ms` : 'not stated';
  const p99 = Number.isFinite(latency.p99) ? `${latency.p99} ms` : 'not stated';
  list.append(node('li', null, `p50: ${p50}`));
  list.append(node('li', null, `p99: ${p99}`));
  list.append(node('li', null, `samples: ${samples}`));
  const disagreement = Number.isFinite(latency.disagreement)
    ? `${(latency.disagreement * 100).toFixed(1)}%`
    : 'not stated';
  list.append(node('li', null, `disagreement: ${disagreement}`));
  if (latency.measured_at) {
    list.append(node('li', null, `measured at: ${latency.measured_at}`));
  }
  block.append(list);
  // The counter-metric note: a single disagreement number is itself a tail risk, because
  // disagreement means "two observers measured different latencies for the same incident".
  // The note names the caveat next to the number, the same discipline the queue's latency
  // block follows.
  block.append(
    node(
      'p',
      'incidents-latency-note',
      'Disagreement is the rate at which two observers measured different latencies for the same incident; a single disagreement number is also a tail, and a low disagreement with a small sample count is still a guess.',
    ),
  );
  frag.append(block);
  return frag;
}

/** The absences list for one bound — what it does NOT cover. */
function absencesBlock(absences) {
  const list = node('ul', 'incidents-absences');
  list.append(node('li', null, 'Declared absences — what this bound does NOT cover:'));
  if (Array.isArray(absences)) {
    for (const absence of absences) {
      if (typeof absence === 'string' && absence.length > 0) {
        list.append(node('li', null, absence));
      }
    }
  }
  if (list.children.length === 1) {
    list.append(node('li', null, '(none stated by the server)'));
  }
  return list;
}

/** One row in the pane: id, tier (pill + prose), latency, blast radius, absences. */
function incidentsBoundCard(bound) {
  const card = node('article', 'incidents-bound');
  const head = node('div', 'incidents-bound-head');
  head.append(node('span', 'incidents-bound-id', bound.id ?? '(unnamed)'));
  // The tier pill carries the color class; `unknown` is the fallback for a tier word the
  // renderer does not recognize (same discipline `tierLine` and `fleetTierSentence` follow).
  // `unexercised` is its own word: a bound with no exercise record renders that, not
  // `unknown`, because the two are different facts the operator must not confuse.
  const tierWord = INCIDENTS_TIER_WORDS.includes(bound?.tier)
    ? bound.tier
    : (bound?.blast_radius?.exercised_at ? 'unknown' : 'unexercised');
  const tierSpan = node('span', `incidents-bound-tier tier-${tierWord}`);
  tierSpan.textContent = `tier: ${tierWord}`;
  head.append(tierSpan);
  card.append(head);

  card.append(node('p', 'incidents-bound-effect', `effect class: ${bound.effect_class ?? 'unknown'}`));
  card.append(node('p', 'incidents-bound-tier-sentence', incidentsTierSentence(tierWord)));
  card.append(node('p', 'incidents-bound-radius', blastRadiusSentence(bound)));
  card.append(incidentsLatencyBlock(bound.latency_ms));
  card.append(absencesBlock(bound.absences));
  return card;
}

/** Render the incidents pane from the facts. */
export function renderIncidents(facts) {
  if (!el.incidents) return;
  if (!facts || !facts.readable) {
    el.incidentsError.hidden = false;
    el.incidentsError.textContent =
      'This incident pane could not be read. An incident pane that cannot list its bounds cannot tell the operator what would contain an incident, and the page is blank on purpose.';
    el.incidentsEmpty.hidden = true;
    el.incidentsUnreadable.textContent = facts?.formatError ?? '';
    el.incidentsSummary.replaceChildren();
    el.incidentsBounds.replaceChildren();
    return;
  }
  el.incidentsError.hidden = true;
  el.incidentsEmpty.hidden = facts.bounds.length > 0;
  el.incidentsSummary.replaceChildren(node('p', null, incidentsHeadline(facts)));
  el.incidentsBounds.replaceChildren();
  for (const bound of facts.bounds) {
    el.incidentsBounds.append(incidentsBoundCard(bound));
  }
}

/** Load bounds from the backend route and paint. */
async function loadIncidents() {
  if (!el.incidents) return;
  const { answered, status, payload } = await call('/v1/incidents/bounds');
  if (answered && status === 401) {
    showGate('That token was not accepted.');
    return;
  }
  renderIncidents(incidentsFacts(answered, status, payload));
}

// ── the policy studio: a non-developer surface for the same compiler the server runs ──

/**
 * Parse one DSL rule line. Mirrors `python/policy_compiler/src/policy_compiler/__init__.py`
 * (`parse_rule`) exactly. The refusal messages are byte-identical to the Python's, because
 * a studio that refuses in different words from the compiler has taught the operator something
 * false about their own controls — the failure Task 11.3 exists to prevent.
 *
 * Grammar (one rule per line)::
 *
 *     <effect> <action> on <resource> [when <attribute> <op> <value>]
 *
 * `<effect>` is `allow` or `deny`. `<op>` is one of `==`, `!=`, `>=`, `<=`, `>`, `<`. The
 * literal `always` may stand in for a condition to make the rule unconditional.
 *
 * @param {string} line A single rule line, with optional leading/trailing whitespace.
 * @returns {{ok: true, rule: object} | {ok: false, refusal: string}}
 */
/**
 * Python-style repr for a string. The compiler in
 * `python/policy_compiler/src/policy_compiler/__init__.py` raises
 * `f"could not parse rule: {line!r}"` — `{!r}` calls `repr()`, which on a
 * Python string returns single-quoted text. `JSON.stringify` would return
 * double-quoted text and the two refusal sentences would diverge. The
 * studio's contract is byte-equivalence to the Python sentence, so the
 * studio uses its own `repr`-shaped helper.
 *
 * @param {string} text
 * @returns {string}
 */
function pyrepr(text) {
  const s = String(text ?? '');
  // Python escapes single quotes with backslash, double quotes are bare.
  // Backslash itself is escaped first so it does not eat the quote escape.
  const escaped = s.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  return `'${escaped}'`;
}

export function parsePolicyRule(line) {
  const text = String(line ?? '');
  const match = /^\s*(allow|deny)\s+([A-Za-z0-9_:./\-*]+)\s+on\s+([A-Za-z0-9_:./\-*/]+)(.*)$/.exec(text);
  if (!match) {
    return { ok: false, refusal: `could not parse rule: ${pyrepr(text)}` };
  }
  const effect = match[1];
  const action = match[2];
  const resource = match[3];
  const rest = (match[4] || '').trim();
  if (!rest) {
    return { ok: true, rule: { effect, action, resource, conditional: false } };
  }
  if (rest === 'when always') {
    return { ok: true, rule: { effect, action, resource, conditional: false } };
  }
  if (!rest.startsWith('when')) {
    return { ok: false, refusal: `expected 'when <clause>' but got ${pyrepr(rest)}` };
  }
  const condMatch = /^\s*when\s+([A-Za-z_][A-Za-z0-9_]*)\s*(==|!=|>=|<=|>|<)\s*([A-Za-z0-9_.'"\-]+)\s*$/.exec(rest);
  if (!condMatch) {
    return { ok: false, refusal: `could not parse condition: ${pyrepr(rest)}` };
  }
  const attribute = condMatch[1];
  const op = condMatch[2];
  const value = condMatch[3].replace(/^['"]|['"]$/g, '');
  return { ok: true, rule: { effect, action, resource, attribute, op, value, conditional: true } };
}

/**
 * Parse a multi-line DSL document. Blank lines and lines starting with `#` are ignored.
 *
 * Mirrors `parse_rules` in `python/policy_compiler/src/policy_compiler/__init__.py`.
 *
 * @param {string} text A multi-line DSL document.
 * @returns {{ok: true, rules: object[]} | {ok: false, refusal: string}}
 */
export function parsePolicyRules(text) {
  const rules = [];
  for (const raw of String(text ?? '').split(/\r?\n/)) {
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const parsed = parsePolicyRule(trimmed);
    if (!parsed.ok) return parsed;
    rules.push(parsed.rule);
  }
  return { ok: true, rules };
}

/**
 * Translate a natural-language intent into a list of seed rules. The phrasebook
 * is the same one the Python compiler's `translate_intent` uses. An unknown
 * intent returns an empty list — the enterprise rules carry the real policy.
 *
 * @param {string} intent The natural-language intent.
 * @returns {object[]} The seed rules.
 */
export function translatePolicyIntent(intent) {
  const out = [];
  const lower = String(intent ?? '').toLowerCase();
  if (/\bdeny\s+all\s+egress\b/.test(lower)) {
    out.push({ effect: 'deny', action: 'tool:http', resource: '*', conditional: false });
  }
  if (/\brequire\s+mfa\b/.test(lower)) {
    out.push({ effect: 'allow', action: 'tool:*', resource: '*', attribute: 'mfa', op: '==', value: 'true', conditional: true });
  }
  if (/\bblock\s+external\s+network\b/.test(lower)) {
    out.push({ effect: 'deny', action: 'tool:net', resource: 'external/*', conditional: false });
  }
  if (/\bonly\s+allow\s+read\b/.test(lower)) {
    out.push({ effect: 'allow', action: 'tool:read', resource: '*', conditional: false });
  }
  return out;
}

/**
 * Render a single rule as a Rego clause, matching the Python's `RegoPolicyEmitter`.
 *
 * @param {object} rule One parsed rule.
 * @returns {string} The Rego condition line, without a trailing comma.
 */
function regoConditionForRule(rule) {
  let resource;
  if (rule.resource.endsWith('/*')) {
    const prefix = rule.resource.slice(0, -2);
    resource = `startsWith(input.resource, "${prefix}/")`;
  } else if (rule.resource === '*') {
    resource = 'true';
  } else {
    resource = `input.resource == "${rule.resource}"`;
  }
  let action;
  if (rule.action === 'tool:*') {
    action = 'startsWith(input.action, "tool:")';
  } else if (rule.action.endsWith('*')) {
    const prefix = rule.action.slice(0, -1);
    action = `startsWith(input.action, "${prefix}")`;
  } else {
    action = `input.action == "${rule.action}"`;
  }
  let cond;
  if (!rule.conditional) {
    cond = 'true';
  } else {
    cond = `input.identity.attributes.${rule.attribute} ${rule.op} ${rule.value}`;
  }
  return [action, resource, cond].filter((p) => p !== '').join(', ');
}

/**
 * Emit a list of rules as a Rego module. Mirrors `RegoPolicyEmitter.emit` in the Python
 * compiler; the module string is byte-equivalent for byte-equivalent input. Deny wins
 * (the canonical least-privilege default).
 *
 * @param {object[]} rules Parsed rules.
 * @returns {string} The Rego module.
 */
export function regoPolicyEmit(rules) {
  const allowLines = [];
  const denyLines = [];
  for (const r of rules) {
    const cond = regoConditionForRule(r);
    if (r.effect === 'allow') allowLines.push(`    ${cond}`);
    else denyLines.push(`    ${cond}`);
  }
  const out = ['package warrantor.policy', '', 'default allow = false  # deny by default'];
  if (allowLines.length > 0) {
    out.push('allow {');
    out.push(...allowLines);
    out.push('}');
  }
  if (denyLines.length > 0) {
    out.push('deny {');
    out.push(...denyLines);
    out.push('}');
    out.push('allow {');
    out.push('    not deny');
    out.push('    # (only when no deny rule matched)');
    out.push('}');
  }
  return out.join('\n') + '\n';
}

/**
 * Build the OpenShell YAML view of a rule list. Mirrors `OpenShellEmitter.emit`.
 *
 * @param {object[]} rules Parsed rules.
 * @returns {string} The YAML body.
 */
export function openShellPolicyEmit(rules) {
  const lines = ['version: "1"', 'rules:'];
  for (const r of rules) {
    lines.push(`  - effect: ${r.effect}`);
    lines.push(`    action: "${r.action}"`);
    lines.push(`    resource: "${r.resource}"`);
    if (r.conditional) {
      lines.push('    when:');
      lines.push(`      attribute: "${r.attribute}"`);
      lines.push(`      op: "${r.op}"`);
      lines.push(`      value: "${r.value}"`);
    } else {
      lines.push('    when: always');
    }
  }
  return lines.join('\n') + '\n';
}

/**
 * Build the Cedar view of a rule list. Mirrors `CedarPolicyEmitter.emit`; the
 * rendering is intentionally simpler than the Rego form because the studio
 * surfaces it as a preview, not as the language the broker runs.
 *
 * @param {object[]} rules Parsed rules.
 * @returns {string} The Cedar policy body.
 */
export function cedarPolicyEmit(rules) {
  const lines = [];
  rules.forEach((r, i) => {
    const keyword = r.effect === 'deny' ? 'forbid' : 'permit';
    let resource;
    if (r.resource === '*') {
      resource = 'resource is Resource';
    } else if (r.resource.endsWith('/*')) {
      const prefix = r.resource.slice(0, -2);
      resource = `resource like "${prefix}/*"`;
    } else {
      resource = `resource == "${r.resource}"`;
    }
    let action;
    if (r.action === 'tool:*') {
      action = 'action like "tool:*"';
    } else if (r.action.endsWith('*')) {
      action = `action like "${r.action}"`;
    } else {
      action = `action == "${r.action}"`;
    }
    const parts = [action, resource];
    if (r.conditional) {
      const v = r.value;
      const isBool = v.toLowerCase() === 'true' || v.toLowerCase() === 'false';
      const isNum = /^-?\d+(\.\d+)?$/.test(v);
      const literal = isBool || isNum ? v : `"${v}"`;
      parts.push(`when { principal.attrs["${r.attribute}"] ${r.op} ${literal} }`);
    }
    lines.push(`${keyword} (\n  principal is Agent,\n  ${parts.join(',\n  ')}\n);  // rule #${i + 1}`);
  });
  return lines.join('\n') + '\n';
}

/**
 * The studio's compiler entry point. Combines NL intent + enterprise rules into
 * a `CompiledPolicy` with the same shape the Python compiler returns, or surfaces
 * the Python's exact refusal message on parse failure.
 *
 * The function is pure: no DOM, no fetch, no clock. The pane builds the input
 * fields, calls this, and renders the result. A test that constructs the inputs
 * directly pins the contract.
 *
 * @param {{intent?: string, rules?: string}} input
 * @returns {{ok: true, rules: object[], rego: string, cedar: string, openshell: string} | {ok: false, refusal: string}}
 */
export function compilePolicy(input) {
  const intent = String(input?.intent ?? '');
  const rulesText = String(input?.rules ?? '');
  const rules = [];
  if (intent) rules.push(...translatePolicyIntent(intent));
  if (rulesText) {
    const parsed = parsePolicyRules(rulesText);
    if (!parsed.ok) return parsed;
    rules.push(...parsed.rules);
  }
  return {
    ok: true,
    rules,
    rego: regoPolicyEmit(rules),
    cedar: cedarPolicyEmit(rules),
    openshell: openShellPolicyEmit(rules),
  };
}

/**
 * Build an exception from the studio's exception form. Mirrors Task 10.5: an
 * exception without an `expires` date or a `compensating_control` sentence is
 * refused at creation. The studio must agree with the lifecycle, because a
 * studio that lets the operator build an exception the server will reject has
 * taught the operator something false about the system they are operating.
 *
 * The refusal message names the missing field by name, so the operator can fix
 * the form without guessing. The substring is part of the contract and pinned
 * by a test (`exception without expiry or compensating control cannot be built`).
 *
 * @param {{warrant_id?: string, expires?: string, compensating_control?: string}} exception
 * @returns {{ok: true, exception: object} | {ok: false, refusal: string}}
 */
export function buildException(exception) {
  const expires = String(exception?.expires ?? '').trim();
  const compensating = String(exception?.compensating_control ?? '').trim();
  if (!expires && !compensating) {
    return {
      ok: false,
      refusal:
        'exception must carry an expires date and a compensating control; ' +
        'both are missing, so the lifecycle would refuse this at creation',
    };
  }
  if (!expires) {
    return {
      ok: false,
      refusal:
        'exception must carry an expires date; the lifecycle refuses an exception that never expires',
    };
  }
  if (!compensating) {
    return {
      ok: false,
      refusal:
        'exception must carry a compensating control; the lifecycle refuses an exception with nothing to compensate for',
    };
  }
  return {
    ok: true,
    exception: {
      warrant_id: String(exception?.warrant_id ?? '').trim(),
      expires,
      compensating_control: compensating,
    },
  };
}

/**
 * Read the studio's textareas, run `compilePolicy`, and paint the result.
 * Pure-render: called from a button click and from tests.
 */
export function renderPolicy() {
  if (!el.policy) return;
  const intent = el.policyIntent?.value ?? '';
  const rulesText = el.policyRules?.value ?? '';
  const exceptionFields = {
    warrant_id: el.policyExceptionWarrant?.value ?? '',
    expires: el.policyExceptionExpires?.value ?? '',
    compensating_control: el.policyExceptionCompensating?.value ?? '',
  };
  const result = compilePolicy({ intent, rules: rulesText });

  // Refusal block. Visible only when the parser refused; the verdict
  // sentence is rendered verbatim from the parser so the studio and the
  // compiler can never drift in their words.
  if (el.policyRefusal) {
    if (!result.ok) {
      el.policyRefusal.textContent = result.refusal;
      el.policyRefusal.hidden = false;
    } else {
      el.policyRefusal.hidden = true;
      el.policyRefusal.textContent = '';
    }
  }

  // Compiled artifacts. The Rego block is the one the broker runs; the
  // Cedar and OpenShell blocks are previews, included so a non-developer
  // reader can see the same policy rendered three ways and confirm none
  // of them have quietly gained a rule.
  if (el.policyCount) {
    el.policyCount.textContent = result.ok
      ? `${result.rules.length} rule${result.rules.length === 1 ? '' : 's'} compiled`
      : 'not compiled';
  }
  if (el.policyRego) {
    el.policyRego.textContent = result.ok ? result.rego : '';
  }
  if (el.policyCedar) {
    el.policyCedar.textContent = result.ok ? result.cedar : '';
  }
  if (el.policyOpenshell) {
    el.policyOpenshell.textContent = result.ok ? result.openshell : '';
  }

  // Exception block. The lifecycle refuses one without `expires` or
  // `compensating_control`; the studio mirrors that refusal in its own
  // words, on the same render pass.
  if (el.policyException) {
    const ex = buildException(exceptionFields);
    if (ex.ok) {
      el.policyException.textContent =
        `exception accepted: warrant ${ex.exception.warrant_id || '(unset)'} ` +
        `expires ${ex.exception.expires}; compensating control: ${ex.exception.compensating_control}`;
      el.policyException.classList.remove('error');
    } else {
      el.policyException.textContent = ex.refusal;
      el.policyException.classList.add('error');
    }
  }
}

/** Load the policy studio from the DOM. Click-only — no number key. */
async function loadPolicy() {
  if (!el.policy) return;
  renderPolicy();
}

// ── the executive risk view: the surface where the strongest word is the most dangerous one ──

/**
 * Tier ordering from strongest to weakest. The executive view renders the
 * WEAKEST input tier for every aggregate — a roll-up of [enforced, mediated,
 * observed] is `observed`, never an average, never the strongest. A future
 * tier added to the ladder slots in here; the test in
 * `console.test.js` iterates a fixture of every tier and pins the order.
 */
const EXEC_TIER_ORDER = Object.freeze(['enforced', 'mediated', 'observed', 'unknown']);

/**
 * Pick the weakest tier from a list. Pure; no DOM, no fetch.
 *
 * The discipline: a roll-up of controls whose inputs span the tier ladder
 * renders the WEAKEST input, because a green dial computed from
 * Tier C inputs presented with the confidence of Tier A is the failure
 * the plan names verbatim. "Weakest" is "lowest in the ladder", and
 * `unknown` slots below `observed` because a tier the server did not
 * name is weaker than any tier it did.
 *
 * @param {string[]} inputs Tier words.
 * @returns {string} The weakest tier, or `unknown` when the list is empty.
 */
export function weakestTier(inputs) {
  if (!Array.isArray(inputs) || inputs.length === 0) return 'unknown';
  let best = EXEC_TIER_ORDER[0];
  let bestIdx = 0;
  for (const tier of inputs) {
    const idx = EXEC_TIER_ORDER.indexOf(String(tier ?? ''));
    const safeIdx = idx < 0 ? EXEC_TIER_ORDER.length - 1 : idx;
    if (safeIdx > bestIdx) {
      best = String(tier ?? 'unknown');
      bestIdx = safeIdx;
    }
  }
  return best;
}

/**
 * Render a tier roll-up sentence: "tier: <weakest> — driven by <inputs>".
 * The inputs are listed in the order the server sent them, so a reader
 * can see why the roll-up is what it is.
 *
 * @param {string[]} inputs
 * @returns {string}
 */
export function rollupSentence(inputs) {
  const weakest = weakestTier(inputs);
  if (!Array.isArray(inputs) || inputs.length === 0) {
    return 'tier: not stated — driven by no inputs';
  }
  if (inputs.length === 1) {
    return `tier: ${weakest} — driven by 1 input (${inputs[0]})`;
  }
  return `tier: ${weakest} — driven by ${inputs.length} inputs (${inputs.join(', ')})`;
}

/**
 * Render the risk-appetite phrase. The view renders the budget number as
 * `advisory` when the dial has not enforced one, because "risk appetite
 * that is not a number the system enforces is a slide" (the plan).
 *
 * @param {{appetite_enforced?: boolean, appetite_ceiling?: number|null}} dial
 * @returns {string}
 */
export function appetitePhrase(dial) {
  if (!dial || dial.appetite_enforced !== true) return 'advisory';
  const ceiling = Number(dial.appetite_ceiling);
  if (!Number.isFinite(ceiling) || ceiling <= 0) return 'advisory';
  // Render as a percentage with no decimal — a slide deck would round
  // to one decimal and quietly imply precision the system does not have.
  const pct = Math.round(ceiling * 100);
  return `enforced ceiling ${pct}%`;
}

/**
 * Read `/v1/dial` into the shape the executive view renders for the risk
 * dial block. Mirrors Task 8.2's payload.
 *
 * @param {boolean} answered
 * @param {number} status
 * @param {unknown} payload
 * @returns {{readable: boolean, dial: object|null, formatError: string|null}}
 */
export function dialFacts(answered, status, payload) {
  const unusable = { readable: false, dial: null, formatError: null };
  if (!answered || status !== 200) return unusable;
  const data = payload?.data ?? payload;
  if (!data || typeof data !== 'object') {
    return { readable: false, dial: null, formatError: 'expected { bounds: [...] }' };
  }
  if (!Array.isArray(data.bounds)) {
    return { readable: false, dial: null, formatError: 'expected { bounds: [...] }' };
  }
  return { readable: true, dial: data, formatError: null };
}

/**
 * Read `/v1/budget` into the shape the executive view renders for the
 * population budget block. Mirrors Task 8.4's payload.
 *
 * @param {boolean} answered
 * @param {number} status
 * @param {unknown} payload
 * @returns {{readable: boolean, budget: object|null, formatError: string|null}}
 */
export function budgetFacts(answered, status, payload) {
  const unusable = { readable: false, budget: null, formatError: null };
  if (!answered || status !== 200) return unusable;
  const data = payload?.data ?? payload;
  if (!data || typeof data !== 'object') {
    return { readable: false, budget: null, formatError: 'expected { mediated, observed, unmediated }' };
  }
  for (const field of ['mediated', 'observed', 'unmediated']) {
    if (!Number.isFinite(data[field])) {
      return { readable: false, budget: null, formatError: `expected numeric ${field}` };
    }
  }
  return { readable: true, budget: data, formatError: null };
}

/**
 * Read the wiring census into the shape the executive view renders for the
 * exposure block. The census file is read on the server; the studio reads
 * it through `/v1/census` so the test stub's `boot()` can answer it
 * without filesystem access.
 *
 * @param {boolean} answered
 * @param {number} status
 * @param {unknown} payload
 * @returns {{readable: boolean, census: object|null, formatError: string|null}}
 */
export function censusFacts(answered, status, payload) {
  const unusable = { readable: false, census: null, formatError: null };
  if (!answered || status !== 200) return unusable;
  const data = payload?.data ?? payload;
  if (!data || typeof data !== 'object') {
    return { readable: false, census: null, formatError: 'expected { total, reachable, orphaned }' };
  }
  for (const field of ['total', 'reachable', 'edges']) {
    if (!Number.isFinite(data[field])) {
      return { readable: false, census: null, formatError: `expected numeric ${field}` };
    }
  }
  if (!Array.isArray(data.orphaned)) {
    return { readable: false, census: null, formatError: 'expected orphaned to be an array' };
  }
  return { readable: true, census: data, formatError: null };
}

/**
 * Read the three feeds (dial, budget, census) and compose the executive
 * view's facts. The studio does NOT compute tiers of its own; the roll-up
 * tier is the weakest input tier from the dial's bounds, the budget's
 * tiers are derived from the per-class split (mediated/observed/unmediated),
 * and the census contributes the unmediated-coverage figure.
 *
 * The function is pure; it does not touch the DOM. The pane reads the
 * three endpoints, calls this, and renders the result.
 *
 * @param {{dial: object|null, budget: object|null, census: object|null}} feeds
 * @returns {{readable: boolean, dial: object|null, budget: object|null, census: object|null,
 *           rollup: {tier: string, sentence: string}|null,
 *           appetite: string,
 *           exposure: {orphaned: number, total: number, phrase: string}|null,
 *           formatError: string|null}}
 */
export function executiveFacts(feeds) {
  const dial = feeds?.dial ?? null;
  const budget = feeds?.budget ?? null;
  const census = feeds?.census ?? null;

  // The dial roll-up: weakest tier among the dial's bounds, with a
  // sentence that names the inputs so a reader can audit the choice.
  let rollup = null;
  if (dial && Array.isArray(dial.bounds)) {
    const tiers = dial.bounds.map((b) => String(b?.tier ?? 'unknown'));
    rollup = { tier: weakestTier(tiers), sentence: rollupSentence(tiers) };
  }

  // The population-budget roll-up: weakest tier among the three
  // classes (mediated, observed, unmediated). Unmediated is the
  // weakest: a class with no enforcement at all.
  let budgetRollup = null;
  if (budget) {
    const tiers = [];
    if (Number(budget.mediated) > 0) tiers.push('mediated');
    if (Number(budget.observed) > 0) tiers.push('observed');
    if (Number(budget.unmediated) > 0) tiers.push('unknown'); // unmediated has no tier
    budgetRollup = { tier: weakestTier(tiers), sentence: rollupSentence(tiers) };
  }

  // Risk appetite: an enforced number, or `advisory`. The plan is
  // explicit that risk appetite that is not a number the system
  // enforces is a slide; the view must not invent one.
  const appetite = appetitePhrase(dial);

  // Exposure: the orphaned crates from the census, named by count and
  // by name. The studio does not compute the figure; it renders what
  // the census already said. An exposure figure that ignored the
  // orphaned set would be wrong, and the wiring census is how the
  // view knows.
  let exposure = null;
  if (census) {
    const orphaned = Number(census.orphaned?.length ?? 0);
    const total = Number(census.total);
    exposure = {
      orphaned,
      total,
      phrase: `${orphaned} orphaned of ${total} crates`,
    };
  }

  return {
    readable: dial !== null || budget !== null || census !== null,
    dial,
    budget,
    census,
    rollup,
    budgetRollup,
    appetite,
    exposure,
    formatError: null,
  };
}

/** Render the executive view from composed facts. */
export function renderExecutive(facts) {
  if (!el.executive) return;
  if (!facts || !facts.readable) {
    el.executiveError.hidden = false;
    el.executiveError.textContent =
      'This executive view could not be read. A risk view that cannot read its feeds cannot say what is enforced, and the page is blank on purpose.';
    el.executiveEmpty.hidden = true;
    el.executiveUnreadable.textContent = facts?.formatError ?? '';
    el.executiveSummary.replaceChildren();
    el.executiveRollup.replaceChildren();
    el.executiveExposure.replaceChildren();
    return;
  }
  el.executiveError.hidden = true;
  el.executiveEmpty.hidden = facts.dial !== null || facts.budget !== null || facts.census !== null;
  el.executiveSummary.replaceChildren();

  // Risk appetite: the only line in the view that is allowed to be a
  // single number. The number is rendered with its enforcing-or-not
  // sentence beside it, so a reader cannot read the number without
  // seeing whether the system enforces it.
  el.executiveSummary.append(node('h3', 'exec-block-heading', 'Risk appetite'));
  el.executiveSummary.append(node('p', 'exec-appetite', facts.appetite));

  // Dial roll-up: weakest tier among the dial's bounds, plus the
  // sentence that names the inputs. A roll-up of [enforced, mediated,
  // observed] is `observed`, never the strongest.
  el.executiveRollup.replaceChildren();
  el.executiveRollup.append(node('h3', 'exec-block-heading', 'Roll-up — weakest input tier wins'));
  if (facts.rollup) {
    const pill = node('span', `pill pill-${facts.rollup.tier}`, facts.rollup.tier);
    const tierPara = node('p', 'exec-rollup-tier');
    tierPara.append(pill);
    el.executiveRollup.append(tierPara);
    el.executiveRollup.append(node('p', 'exec-rollup-sentence', facts.rollup.sentence));
  } else {
    el.executiveRollup.append(node('p', 'note', 'dial could not be read; roll-up not stated'));
  }
  if (facts.budgetRollup) {
    el.executiveRollup.append(node('h4', 'exec-subheading', 'Population budget'));
    const budgetPill = node('span', `pill pill-${facts.budgetRollup.tier}`, facts.budgetRollup.tier);
    const budgetPara = node('p', 'exec-rollup-tier');
    budgetPara.append(budgetPill);
    el.executiveRollup.append(budgetPara);
    el.executiveRollup.append(node('p', 'exec-rollup-sentence', facts.budgetRollup.sentence));
  }

  // Exposure: the orphaned crates from the census, named by count.
  // An exposure figure that ignored the orphaned set would be wrong.
  el.executiveExposure.replaceChildren();
  el.executiveExposure.append(node('h3', 'exec-block-heading', 'Exposure — what is unmediated'));
  if (facts.exposure) {
    el.executiveExposure.append(node('p', 'exec-exposure', facts.exposure.phrase));
  } else {
    el.executiveExposure.append(node('p', 'note', 'census could not be read; exposure not stated'));
  }
}

/** Load the three feeds and paint. */
async function loadExecutive() {
  if (!el.executive) return;
  const [dial, budget, census] = await Promise.all([
    call('/v1/dial'),
    call('/v1/budget'),
    call('/v1/census'),
  ]);
  // The view reads whatever the server returned. A 401 on any of the
  // three short-circuits to the gate.
  if (dial.answered && dial.status === 401) { showGate('That token was not accepted.'); return; }
  if (budget.answered && budget.status === 401) { showGate('That token was not accepted.'); return; }
  if (census.answered && census.status === 401) { showGate('That token was not accepted.'); return; }
  const facts = executiveFacts({
    dial: dialFacts(dial.answered, dial.status, dial.payload).dial,
    budget: budgetFacts(budget.answered, budget.status, budget.payload).budget,
    census: censusFacts(census.answered, census.status, census.payload).census,
  });
  renderExecutive(facts);
}

// ── the safe-autonomy expansion ledger: a record of widening AND narrowing, with equal prominence ──

/**
 * Refuse a widening entry that does not carry the evidence it rests on
 * and a narrowing path. A widening without evidence is a guess; a
 * widening without a narrowing path is a one-way ratchet. Both are
 * refused at creation.
 *
 * The function is pure; it does not touch the DOM. The pane calls it
 * when an entry is being recorded, and the test iterates the fixture to
 * pin every acceptance and refusal verdict.
 *
 * @param {object} entry The proposed widening entry.
 * @returns {{ok: true, entry: object} | {ok: false, refusal: string}}
 */
export function recordWidening(entry) {
  const evidence = Array.isArray(entry?.evidence_receipts) ? entry.evidence_receipts : [];
  const narrowingPath = String(entry?.narrowing_path ?? '').trim();
  const baselineMetric = String(entry?.baseline_metric ?? '').trim();
  const baselineValue = entry?.baseline_value;
  if (evidence.length === 0) {
    return {
      ok: false,
      refusal:
        'widening requires evidence: an autonomy loosening without cited receipts is a guess, and the ledger refuses it',
    };
  }
  if (!narrowingPath) {
    return {
      ok: false,
      refusal:
        'widening requires a narrowing path: the system has to know how to re-tighten if the evidence weakens, and an entry without one is a one-way ratchet',
    };
  }
  if (!baselineMetric) {
    return {
      ok: false,
      refusal:
        'widening requires a baseline metric: the outcome contract is a comparison, and a comparison without a reference is a number',
    };
  }
  if (!Number.isFinite(baselineValue)) {
    return {
      ok: false,
      refusal:
        'widening requires a baseline value: the outcome contract is a comparison, and a reference without a value is undefined',
    };
  }
  return { ok: true, entry };
}

/**
 * Refuse an outcome contract without a complete baseline. A contract
 * without a metric, a value, or both is a number, not a comparison.
 *
 * The function is pure; it does not touch the DOM. The pane calls it
 * when an outcome contract is being recorded, and the test iterates the
 * fixture to pin every acceptance and refusal verdict.
 *
 * @param {object} baseline The proposed baseline.
 * @returns {{ok: true, baseline: object} | {ok: false, refusal: string}}
 */
export function recordBaseline(baseline) {
  const metric = String(baseline?.metric ?? '').trim();
  const value = baseline?.value;
  if (!metric) {
    return {
      ok: false,
      refusal:
        'baseline requires a metric: the outcome contract is a comparison, and a metric is what is being compared',
    };
  }
  if (!Number.isFinite(value)) {
    return {
      ok: false,
      refusal:
        'baseline requires a numeric value: a reference value the contract is measured against',
    };
  }
  return { ok: true, baseline };
}

/**
 * Read `/v1/autonomy-ledger` into the shape the pane renders. The
 * ledger is a rendering of 8.2's receipts (the dial already records
 * both directions); the pane surfaces the receipts so a reader can
 * audit each one.
 *
 * @param {boolean} answered
 * @param {number} status
 * @param {unknown} payload
 * @returns {{readable: boolean, ledger: object|null, formatError: string|null}}
 */
export function autonomyFacts(answered, status, payload) {
  const unusable = { readable: false, ledger: null, formatError: null };
  if (!answered || status !== 200) return unusable;
  const data = payload?.data ?? payload;
  if (!data || typeof data !== 'object') {
    return { readable: false, ledger: null, formatError: 'expected { entries: [...] }' };
  }
  if (!Array.isArray(data.entries)) {
    return { readable: false, ledger: null, formatError: 'expected entries to be an array' };
  }
  // Each entry must declare a direction. The pane refuses to render an
  // entry whose direction is not `widen` or `narrow`, because the
  // equal-prominence discipline depends on every entry carrying a
  // direction word the reader can compare.
  for (const entry of data.entries) {
    if (!entry || typeof entry !== 'object') {
      return { readable: false, ledger: null, formatError: 'every entry must be an object' };
    }
    if (entry.direction !== 'widen' && entry.direction !== 'narrow') {
      return {
        readable: false,
        ledger: null,
        formatError: `entry ${entry.id ?? '(no id)'} has unknown direction ${JSON.stringify(entry.direction)}`,
      };
    }
  }
  return { readable: true, ledger: data, formatError: null };
}

/**
 * Compose the autonomy facts: the ledger plus a count of widening and
 * narrowing events. The two counts are the headline; the entries are
 * the audit trail. A future change that hid one direction's count
 * would be caught by the test that asserts both counts are rendered.
 *
 * @param {{ledger: object|null}} feeds
 * @returns {{readable: boolean, ledger: object|null, widenCount: number, narrowCount: number, formatError: string|null}}
 */
export function autonomyComposedFacts(feeds) {
  const ledger = feeds?.ledger ?? null;
  if (!ledger) {
    return { readable: false, ledger: null, widenCount: 0, narrowCount: 0, formatError: null };
  }
  let widenCount = 0;
  let narrowCount = 0;
  for (const entry of ledger.entries ?? []) {
    if (entry.direction === 'widen') widenCount += 1;
    else if (entry.direction === 'narrow') narrowCount += 1;
  }
  return {
    readable: true,
    ledger,
    widenCount,
    narrowCount,
    formatError: null,
  };
}

/** Build a single ledger row. The row carries the same shape for every
 *  direction; the only differentiator is the pill class and the
 *  narrowing-path / trigger field. The shape is part of the contract. */
function autonomyRow(entry) {
  const li = node('li', 'autonomy-row');
  const pill = node('span', `pill pill-${entry.direction}`, entry.direction);
  const pillPara = node('p', 'autonomy-row-pill');
  pillPara.append(pill);
  li.append(pillPara);
  li.append(node('p', 'autonomy-row-date', entry.at));
  li.append(node('p', 'autonomy-row-warrant', `warrant ${entry.warrant_id}`));
  li.append(node('p', 'autonomy-row-bound', `bound ${entry.bound}`));
  if (entry.direction === 'widen') {
    // Widen rows carry evidence, baseline, outcome, and a narrowing path.
    // Each is its own paragraph so a reader who scans the row can find
    // any one of them without re-reading the whole row.
    const evidencePara = node(
      'p',
      'autonomy-row-evidence',
      `evidence: ${(entry.evidence_receipts ?? []).join(', ')}`,
    );
    li.append(evidencePara);
    const baselinePara = node(
      'p',
      'autonomy-row-baseline',
      `baseline: ${entry.baseline_metric} = ${entry.baseline_value}`,
    );
    li.append(baselinePara);
    const outcomePara = node(
      'p',
      'autonomy-row-outcome',
      `outcome: ${entry.outcome_metric} = ${entry.outcome_value}`,
    );
    li.append(outcomePara);
    const pathPara = node(
      'p',
      'autonomy-row-narrowing-path',
      `narrowing path: ${entry.narrowing_path}`,
    );
    li.append(pathPara);
  } else {
    // Narrow rows carry the trigger incident and the receipts the
    // narrowing rests on. A narrow row with no trigger is the same
    // shape as a widen row with no evidence: a tightening without a
    // named reason. The pane renders the trigger by name so a reader
    // can audit the cause.
    const triggerPara = node('p', 'autonomy-row-trigger', `trigger: ${entry.trigger ?? '(unstated)'}`);
    li.append(triggerPara);
    const receiptsPara = node(
      'p',
      'autonomy-row-receipts',
      `receipts: ${(entry.receipts ?? []).join(', ')}`,
    );
    li.append(receiptsPara);
  }
  return li;
}

/** Render the autonomy ledger from composed facts. */
export function renderAutonomy(facts) {
  if (!el.autonomy) return;
  if (!facts || !facts.readable) {
    el.autonomyError.hidden = false;
    el.autonomyError.textContent =
      'This autonomy ledger could not be read. A ledger that cannot read its receipts cannot say what widened and what narrowed, and the page is blank on purpose.';
    el.autonomyEmpty.hidden = true;
    el.autonomyUnreadable.textContent = facts?.formatError ?? '';
    el.autonomySummary.replaceChildren();
    el.autonomyEntries.replaceChildren();
    return;
  }
  el.autonomyError.hidden = true;
  const hasEntries = Array.isArray(facts.ledger?.entries) && facts.ledger.entries.length > 0;
  el.autonomyEmpty.hidden = hasEntries;
  // The headline sentence names BOTH counts in the same line. A future
  // change that rendered only one direction's count would be the
  // growth chart the discipline is meant to prevent.
  el.autonomySummary.replaceChildren(
    node(
      'p',
      'autonomy-headline',
      `${facts.widenCount} widening and ${facts.narrowCount} narrowing in this window`,
    ),
  );
  // Entries are sorted by date (chronological), with widening and
  // narrowing interleaved by date. A pane that grouped widening first
  // would render the growth chart; the test pins the order.
  const sorted = (facts.ledger.entries ?? []).slice().sort((a, b) => {
    if (a.at < b.at) return -1;
    if (a.at > b.at) return 1;
    return 0;
  });
  el.autonomyEntries.replaceChildren();
  for (const entry of sorted) {
    el.autonomyEntries.append(autonomyRow(entry));
  }
}

/** Load the ledger from the backend and paint. */
async function loadAutonomy() {
  if (!el.autonomy) return;
  const { answered, status, payload } = await call('/v1/autonomy-ledger');
  if (answered && status === 401) {
    showGate('That token was not accepted.');
    return;
  }
  const facts = autonomyFacts(answered, status, payload);
  const composed = autonomyComposedFacts({ ledger: facts.ledger });
  renderAutonomy(composed);
}

// ── the framework crosswalk engine: every mapping carries its evidence, or it is unmapped ──

/**
 * Refuse a row whose status is `satisfied` without a quote or a date.
 * A crosswalk that claims a clause is satisfied without a citation a
 * reader can check is worse than no crosswalk. The function promotes
 * the row's status to `unmapped` so the pane renders the gap visibly.
 *
 * The function is pure; it does not touch the DOM. The pane calls it
 * for every row before rendering, and the test iterates the fixture
 * to pin every promotion and refusal.
 *
 * @param {object} row The crosswalk row from the server.
 * @returns {{row: object, promoted: boolean}}
 */
export function normalizeCrosswalkRow(row) {
  if (!row || typeof row !== 'object') {
    return { row: { ...(row ?? {}), status: 'unmapped' }, promoted: true };
  }
  const status = String(row.status ?? '');
  const quote = String(row.quote ?? '').trim();
  const sourceDate = String(row.source_date ?? '').trim();
  // A row whose status is `satisfied` or `partial` without a quote
  // AND a date is promoted to `unmapped`. A row whose status is
  // already `unmapped` is passed through.
  if ((status === 'satisfied' || status === 'partial') && (quote === '' || sourceDate === '')) {
    return { row: { ...row, status: 'unmapped' }, promoted: true };
  }
  return { row, promoted: false };
}

/**
 * Read `/v1/crosswalk` into the shape the pane renders. Each row is
 * normalized: a row whose status is `satisfied` or `partial` without
 * a quote and a date is promoted to `unmapped`. The pane renders the
 * promoted row's gap visibly, never as a blank cell.
 *
 * @param {boolean} answered
 * @param {number} status
 * @param {unknown} payload
 * @returns {{readable: boolean, crosswalk: object|null, formatError: string|null}}
 */
export function crosswalkFacts(answered, status, payload) {
  const unusable = { readable: false, crosswalk: null, formatError: null };
  if (!answered || status !== 200) return unusable;
  const data = payload?.data ?? payload;
  if (!data || typeof data !== 'object') {
    return { readable: false, crosswalk: null, formatError: 'expected { rows: [...] }' };
  }
  if (!Array.isArray(data.rows)) {
    return { readable: false, crosswalk: null, formatError: 'expected rows to be an array' };
  }
  // Normalize every row. A row that does not pass normalization is
  // promoted to `unmapped` — the pane renders the gap visibly, never
  // as a blank cell. The pane stores the UNWRAPPED row (the result
  // of `normalizeCrosswalkRow`, with status possibly promoted), not
  // the `{row, promoted}` wrapper, so the renderer can read fields
  // like `row.status`, `row.control`, `row.quote` directly.
  const rows = data.rows.map((r) => normalizeCrosswalkRow(r).row);
  return { readable: true, crosswalk: { rows }, formatError: null };
}

/**
 * Compose the crosswalk facts: the crosswalk plus counts of each
 * mapping status. The counts are the headline; the rows are the
 * audit trail.
 *
 * @param {{crosswalk: object|null}} feeds
 * @returns {{readable: boolean, crosswalk: object|null, satisfied: number, partial: number, unmapped: number, formatError: string|null}}
 */
export function crosswalkComposedFacts(feeds) {
  const crosswalk = feeds?.crosswalk ?? null;
  if (!crosswalk) {
    return { readable: false, crosswalk: null, satisfied: 0, partial: 0, unmapped: 0, formatError: null };
  }
  let satisfied = 0;
  let partial = 0;
  let unmapped = 0;
  for (const row of crosswalk.rows ?? []) {
    const status = String(row?.status ?? 'unmapped');
    if (status === 'satisfied') satisfied += 1;
    else if (status === 'partial') partial += 1;
    else unmapped += 1;
  }
  return { readable: true, crosswalk, satisfied, partial, unmapped, formatError: null };
}

/**
 * Check whether a text names SR 11-7 as the current US model-risk
 * supervision guidance. The pane's prose gate refuses any surface
 * that names SR 11-7 as current; SR 26-2 superseded it on 2026-04-17.
 *
 * The check is intentionally narrow: a sentence that names SR 11-7
 * as a prior or superseded guidance is accepted. The check is the
 * mirror of the prose gate the plan describes.
 *
 * @param {string} text
 * @returns {boolean} True when the text names SR 11-7 as current.
 */
export function namesSr117AsCurrent(text) {
  if (typeof text !== 'string' || text === '') return false;
  return /SR\s*11-7.*current|current.*SR\s*11-7/i.test(text);
}

/** Build a single crosswalk row. The shape is part of the contract:
 *  every row carries a status pill, the framework, the clause, the
 *  quote (verbatim), the source date, and (for satisfied or partial
 *  rows) the source URL. An `unmapped` row renders the gap
 *  visibly — `quote: not stated`, `date: not stated` — never as a
 *  blank cell. */
function crosswalkRow(row) {
  const li = node('li', 'crosswalk-row');
  const pill = node('span', `pill pill-${row.status}`, row.status);
  const pillPara = node('p', 'crosswalk-row-pill');
  pillPara.append(pill);
  li.append(pillPara);
  li.append(node('p', 'crosswalk-row-control', `control: ${row.control}`));
  li.append(node('p', 'crosswalk-row-framework', `framework: ${row.framework}`));
  li.append(node('p', 'crosswalk-row-clause', `clause: ${row.clause}`));
  if (row.status === 'unmapped') {
    // The gap is rendered visibly: `quote: not stated` and
    // `date: not stated`. A reader who cannot see the gap has
    // been told the control is unmapped, and the next move is
    // to compose a mapping (or accept the gap).
    li.append(node('p', 'crosswalk-row-quote', 'quote: not stated'));
    li.append(node('p', 'crosswalk-row-date', 'date: not stated'));
    li.append(node('p', 'crosswalk-row-unmapped-note', 'this row is unmapped: the control does not (yet) map to the clause'));
  } else {
    li.append(node('p', 'crosswalk-row-quote', `quote: ${row.quote}`));
    li.append(node('p', 'crosswalk-row-date', `source date: ${row.source_date}`));
    if (row.source_url) {
      li.append(node('p', 'crosswalk-row-source-url', `source url: ${row.source_url}`));
    }
  }
  return li;
}

/** Render the crosswalk from composed facts. */
export function renderCrosswalk(facts) {
  if (!el.crosswalk) return;
  if (!facts || !facts.readable) {
    el.crosswalkError.hidden = false;
    el.crosswalkError.textContent =
      'This crosswalk could not be read. A crosswalk that cannot read its rows cannot say what is mapped and what is unmapped, and the page is blank on purpose.';
    el.crosswalkEmpty.hidden = true;
    el.crosswalkUnreadable.textContent = facts?.formatError ?? '';
    el.crosswalkSummary.replaceChildren();
    el.crosswalkRows.replaceChildren();
    return;
  }
  el.crosswalkError.hidden = true;
  const hasRows = Array.isArray(facts.crosswalk?.rows) && facts.crosswalk.rows.length > 0;
  el.crosswalkEmpty.hidden = hasRows;
  // The headline names all three counts in the same line. A future
  // change that rendered only the satisfied count would be a marketing
  // surface; the discipline is to surface every count.
  el.crosswalkSummary.replaceChildren(
    node(
      'p',
      'crosswalk-headline',
      `${facts.satisfied} satisfied, ${facts.partial} partial, ${facts.unmapped} unmapped`,
    ),
  );
  el.crosswalkRows.replaceChildren();
  for (const row of facts.crosswalk.rows ?? []) {
    el.crosswalkRows.append(crosswalkRow(row));
  }
}

/** Load the crosswalk from the backend and paint. */
async function loadCrosswalk() {
  if (!el.crosswalk) return;
  const { answered, status, payload } = await call('/v1/crosswalk');
  if (answered && status === 401) {
    showGate('That token was not accepted.');
    return;
  }
  const facts = crosswalkFacts(answered, status, payload);
  const composed = crosswalkComposedFacts({ crosswalk: facts.crosswalk });
  renderCrosswalk(composed);
}

/**
 * Turn a month into the half-open window the API takes.
 *
 * `[since, until)` in whole epoch seconds, UTC, because that is the axis the records are stamped
 * on. Exported and pure so `console.test.js` can pin the boundaries: an off-by-one month here would
 * silently show the wrong data under the right heading, which is the exact failure this whole view
 * was built to stop making.
 *
 * Returns null for anything that is not `YYYY-MM`. Null is not "this month": a window this console
 * could not build must not be replaced with one it made up.
 *
 * @param {string} text A `YYYY-MM` value, as `<input type="month">` produces.
 * @returns {{since: number, until: number}|null}
 */
export function monthWindow(text) {
  const match = /^(\d{4})-(\d{2})$/.exec(String(text ?? '').trim());
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  if (month < 1 || month > 12) return null;
  const since = Date.UTC(year, month - 1, 1) / 1000;
  const until = Date.UTC(year, month, 1) / 1000;
  if (!Number.isSafeInteger(since) || !Number.isSafeInteger(until)) return null;
  return { since, until };
}

/** The month `<input type="month">` should start on: the one the reader is in. */
function currentMonth(date = new Date()) {
  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}`;
}

/**
 * What a summary response actually established.
 *
 * The same argument as `listFacts`, and the same load-bearing `readable`. Optional chaining over an
 * unusable body yields zero groups, which is shaped exactly like a month in which no bound refused
 * anything — and this is the surface where "nothing was refused" is the most reassuring sentence
 * available. A response this console could not read must not produce it.
 *
 * `guard` is passed through unvalidated on purpose: `guardKind` is the one place that decides what
 * a guard object supports, so validating it twice would create two answers to one question.
 *
 * @param {boolean} answered Did the server produce a response at all?
 * @param {number} status HTTP status, meaningful only when `answered`.
 * @param {unknown} payload The parsed envelope, or null when the body did not parse.
 */
export function summaryFacts(answered, status, payload) {
  const unusable = { readable: false, groups: [], guard: null, window: null, note: '' };
  if (!answered || status !== 200) return unusable;
  const data = payload?.data;
  if (!data || typeof data !== 'object') return unusable;
  if (!Array.isArray(data.groups)) return unusable;
  return {
    readable: true,
    groups: data.groups,
    guard: data.guard ?? null,
    window: data.window ?? null,
    note: typeof data.note === 'string' ? data.note : '',
    unreadableLines: data.unreadable_lines,
    // `null` when the server said nothing about runs, which an older server does. `runsSentence`
    // renders that as "unknown", never as zero.
    runs: data.runs ?? null,
  };
}

/**
 * Whether this guard object carries evidence that a guard ran, other than an attach record.
 *
 * `configured` is `!sessions.is_empty()` on the server, so it is false in two very different
 * situations: nothing ran at all, and something ran whose attach record is not in what was read —
 * the write failed, or the window holds records the attach record is not grouped with. Counts are
 * evidence: a finished session, a classified call, a call nothing looked at. One of them being
 * nonzero makes "no guard was attached to any run in this window" a false sentence, and this
 * console prints that sentence in fixed prose that no server field can soften.
 */
function guardEvidence(guard) {
  const coverage = guard?.coverage;
  const counted = [
    'sessions_attached',
    'sessions_finished',
    'classified',
    'flagged',
    'backend_unavailable',
    'unparseable',
    'skipped_over_budget',
    'permitted_no_route',
    'deduplicated',
  ].some((key) => Number.isFinite(coverage?.[key]) && coverage[key] > 0);
  const listed = ['sessions', 'counters'].some(
    (key) => Array.isArray(guard?.[key]) && guard[key].length > 0,
  );
  return counted || listed;
}

/**
 * Which sentence a guard object supports, and only that one.
 *
 * Five states that render identically under optional chaining, and conflating any two of them is a
 * dead guard reported as a clean month:
 *
 * - `unknown`: the server said nothing this console can interpret. Not coverage, not findings.
 * - `groups`: it grouped something. Rendered whatever `configured` says — signals with no attach
 *   record are a real state (the attach write failed and the run's own signals landed anyway), and
 *   printing "no coverage" above a list of classifications would be a sentence sitting next to its
 *   own counter-evidence.
 * - `no-coverage`: nothing attached and nothing else in the answer says otherwise, so nothing
 *   looked. This is the one that must never render as a quiet, reassuring table — and the one that
 *   must never be printed over an answer whose own counts contradict it.
 * - `unattributed`: no attach record, but the answer carries counts that only a guard can produce.
 *   Distinct from `no-coverage` because they are opposite claims: one says nothing watched, the
 *   other says something watched and cannot be named. The server's own note already distinguishes
 *   them; printing NO COVERAGE here put this console's fixed prose in direct contradiction of the
 *   coverage table underneath it and of the server's sentence beside it.
 * - `quiet`: something attached and grouped nothing.
 */
export function guardKind(guard) {
  if (!guard || typeof guard !== 'object') return 'unknown';
  if (guard.configured !== true && guard.configured !== false) return 'unknown';
  if (!Array.isArray(guard.groups)) return 'unknown';
  if (guard.groups.length > 0) return 'groups';
  if (guard.configured === true) return 'quiet';
  return guardEvidence(guard) ? 'unattributed' : 'no-coverage';
}

/**
 * The sentence about lines that did not parse, or the sentence about not knowing.
 *
 * Three answers, never two. A count the server did not state is NOT zero: the summary route
 * carries `unreadable_lines` for the refusal log and again inside `guard`, and a console that read
 * the field and rendered nothing omitted, with no disclosure, exactly the records nobody could
 * read — on the surface whose whole thesis is that an absence of observation must not read as an
 * absence of findings. The warrant list already prints its own version of this sentence.
 *
 * Empty string for a stated zero, because there the silence is the truth.
 */
export function unreadableSentence(value, subject) {
  if (!Number.isFinite(value) || value < 0) {
    return `This server did not state how many lines of the ${subject} were unreadable, so nothing here says whether any were dropped from the counts above.`;
  }
  if (value === 0) return '';
  return `${value} line(s) of the ${subject} could not be read and are in nothing above. That count covers the WHOLE log, not this window: a line that did not parse has no timestamp to window it on.`;
}

/**
 * What the guard half of this answer could not window the way the caveat describes.
 *
 * Guard records are windowed by session, so a session is held or dropped whole. Records written
 * before sessions carried an id cannot be grouped and fall back to their own clock — the attach
 * record on one side of a boundary, its own signals and counters on the other. That is the one case
 * the server's caveat excludes, and a reader is owed the count rather than left to assume the
 * better rule applied to all of it.
 */
export function unattributedSentence(value) {
  if (!Number.isFinite(value) || value < 0) {
    return 'This server did not state how many guard records carry no session id, so whether every session here was windowed whole is unknown.';
  }
  if (value === 0) return '';
  return `${value} guard record(s) here carry no session id — they were written before sessions were identified, so each was windowed on its own clock instead of being held with the rest of its session, and one such session can be split across the boundary.`;
}

/**
 * The blocking posture, read as the server stated it and never derived.
 *
 * Deliberately does NOT look at `guard.enforcing`. That field is `any(..)` over the whole scope, so
 * a single enforce session anywhere makes it true — and a summary merges every warrant in the
 * store. Rendering it as a boolean tells an operator that calls which actually proceeded did not
 * happen. `mixed` is a third claim, not a rounding of the other two, and an unrecognised or absent
 * word is `unknown` rather than a default.
 */
export function postureWord(guard) {
  const word = guard?.blocking_posture;
  if (word === 'observe_only' || word === 'enforced' || word === 'mixed') return word;
  return 'unknown';
}

/** The three tier words the server may send. Anything else is "not stated", never rounded up. */
const TIER_WORDS = new Set(['enforced', 'mediated', 'observed']);

/**
 * One line per bound: name, tier word, and the server's caveat for that tier. Exported and pure so
 * `console.test.js` can pin the shape. An unknown or missing tier is rendered as "not stated" —
 * the console composes no tier of its own, and the one word it must never supply is "enforced".
 */
export function boundTierLines(data) {
  const list = data?.bound_strengths;
  if (!Array.isArray(list)) return [];
  return list.map((entry) => {
    const name = typeof entry?.name === 'string' ? entry.name : '(unnamed bound)';
    if (!TIER_WORDS.has(entry?.strength)) {
      return `${name} — tier not stated: do not read this as enforced`;
    }
    const caveat = typeof entry.caveat === 'string' ? entry.caveat : '';
    return `${name} — ${entry.strength}: ${caveat}`;
  });
}

/**
 * The tier line that the queueRow, transportRow, coverageRow, and routingRow all carry, so a
 * reader who scans any pane sees the same shape: an explicit tier word, or an honest "not
 * stated" when the server did not classify the row. Exported and pure so the test can pin the
 * shape and the fallback text — and so a future pane can adopt the same wording without
 * drifting it.
 *
 * The accepted set is the union of every vocabulary the server may speak: the
 * bound-strength words (enforced/mediated/observed), the coverage-map words
 * (mediated/observed/unsupported/bypassable), and the routing words
 * (local/escalated/ceiling_refused/unconfigured). The fallback renders the same sentence for
 * any other value — the "not stated" text deliberately names the strongest tier word,
 * "enforced", because the failure mode this line exists to prevent is a reader seeing no
 * word and assuming enforced. The console never rounds an unknown word up to "enforced".
 */
const TIER_LINE_WORDS = new Set([
  'enforced', 'mediated', 'observed',
  'unsupported', 'bypassable',
  'local', 'escalated', 'ceiling_refused', 'unconfigured',
]);
export function tierLine(tier, { className = 'tier' } = {}) {
  const line = node('p', className);
  if (typeof tier === 'string' && TIER_LINE_WORDS.has(tier)) {
    line.textContent = `tier: ${tier}`;
    line.classList.add(`is-${tier}`);
  } else {
    line.classList.add('quiet', 'tier-not-stated');
    line.textContent = 'tier: not stated — do not read this as the strongest tier';
  }
  return line;
}

/** The sentence for each posture. Fixed prose, chosen by the server's word, never composed. */
const POSTURE_SENTENCE = {
  observe_only: 'observe only — nothing here was blocked',
  enforced: 'enforced — flagged calls were refused at the MCP endpoint',
  mixed: 'MIXED — some flagged calls proceeded and some were refused; read each row',
  unknown: 'posture not stated — do not assume either way',
};

/** A labelled row of facts, with the server's own guidance sentence printed verbatim underneath. */
function factRow(className, heading, pills, guidance) {
  const item = document.createElement('li');
  const row = node('div', className);
  const top = node('div', 'row-top');
  top.append(node('span', 'row-id', heading));
  for (const [label, value] of pills) {
    if (value === undefined || value === null || value === '') continue;
    top.append(node('span', 'pill pill-quiet', `${label} ${value}`));
  }
  row.append(top);
  // Verbatim. Rewriting it here would be a second implementation of the server's judgement, and the
  // two would disagree the first time one of them was edited.
  if (guidance) row.append(node('div', 'row-sub', guidance));
  item.append(row);
  return item;
}

/** Read the summary for the chosen month and render it. Never polled — see the note in the page. */
async function loadSummary() {
  const range = monthWindow(el.summaryMonth.value);
  if (!range) {
    // Its own reason, and its own paragraph. This branch makes NO request, so the server-error
    // sentence ("the server did not answer, refused, or replied with something this console could
    // not parse") would be this console stating a fact about a server it never spoke to.
    // `<input type="month">` degrades to a free-text field in browsers that do not implement it, so
    // this is reached by typing, not only by tampering.
    renderSummary({ readable: false, reason: 'month', groups: [], guard: null, window: null, note: '' });
    return;
  }
  const { answered, status, payload } = await call(
    `/v1/summary/refusals?since=${range.since}&until=${range.until}`,
  );
  if (answered && status === 401) {
    showGate('That token was not accepted.');
    return;
  }
  renderSummary(summaryFacts(answered, status, payload));
}

function renderSummary(facts) {
  const monthUnreadable = facts.reason === 'month';
  el.summaryError.hidden = facts.readable || monthUnreadable;
  el.summaryMonthError.hidden = !monthUnreadable;
  el.summaryRefusals.replaceChildren();
  el.summaryGuard.replaceChildren();
  el.summaryCoverage.replaceChildren();

  if (!facts.readable) {
    // Every block is emptied and every explanatory paragraph hidden, so nothing left over from a
    // successful read can sit under the error and read as this month's answer.
    el.summaryWindow.textContent = '';
    el.summaryCaveat.textContent = '';
    el.summaryUnreadable.textContent = '';
    el.summaryRefusalsNote.textContent = '';
    el.summaryGuardNote.textContent = '';
    el.summaryGuardCaveats.textContent = '';
    el.summaryCoverageNote.textContent = '';
    // Emptied with the rest: a run count left over from a previous month, sitting under an error,
    // would read as this month's answer.
    el.summaryRuns.textContent = '';
    el.summaryRefusalsEmpty.hidden = true;
    el.summaryGuardUnknown.hidden = true;
    el.summaryGuardNone.hidden = true;
    el.summaryGuardUnattributed.hidden = true;
    el.summaryGuardQuiet.hidden = true;
    return;
  }

  // The window the SERVER resolved, not the one this console asked for. Printing the request would
  // keep saying "August" over an answer that had not been filtered, which is exactly what this
  // route did before it learned to filter.
  const range = facts.window;
  const stamp = (seconds) =>
    Number.isFinite(seconds) ? new Date(seconds * 1000).toISOString().slice(0, 10) : '(unbounded)';
  el.summaryWindow.textContent = range
    ? `Window ${stamp(range.since)} to ${stamp(range.until)} (end exclusive): ${range.records_in_window} refusal record(s) of ${range.records_all_time} in the whole log.`
    : 'This server did not state the window it answered about, so what follows may not be the month asked for.';
  el.summaryCaveat.textContent = range?.caveat ?? '';
  // Read off the wire and then dropped is how this count was handled before: `summaryFacts` set it
  // and nothing rendered it, so unparseable refusal-log lines were omitted from the month view with
  // no disclosure at all.
  el.summaryUnreadable.textContent = unreadableSentence(facts.unreadableLines, 'refusal log');
  el.summaryRefusalsNote.textContent = facts.note;

  el.summaryRefusalsEmpty.hidden = facts.groups.length > 0;
  for (const group of facts.groups) {
    el.summaryRefusals.append(
      factRow(
        'row-fact',
        group.subject ?? '(unnamed)',
        [
          ['', group.kind],
          ['refused', group.occurrences],
          ['warrants', group.warrants],
          ['', group.signal],
        ],
        group.guidance,
      ),
    );
  }

  renderGuardBlock(facts.guard);
  // Rendered here rather than inside `renderGuardBlock`, and not by accident: everything that
  // block draws is counted FROM guard records, and this is the count of sessions the guard was
  // never in. Putting it there would have made the guard block partly a statement about its own
  // absence -- and the first attempt did exactly that, which the tests caught as a `facts` that
  // was not in scope.
  el.summaryRuns.textContent = runsSentence(facts.runs);
}

function renderGuardBlock(guard) {
  const kind = guardKind(guard);
  el.summaryGuardUnknown.hidden = kind !== 'unknown';
  el.summaryGuardNone.hidden = kind !== 'no-coverage';
  el.summaryGuardUnattributed.hidden = kind !== 'unattributed';
  el.summaryGuardQuiet.hidden = kind !== 'quiet';
  // The server composes this sentence per scope and per posture. Printed verbatim; it is also
  // where the measured benchmark rates live, so this console never keys a number like 0.8152 in.
  el.summaryGuardNote.textContent = typeof guard?.note === 'string' ? guard.note : '';
  // What this block could not see, and what it could not window as the caveat describes. Written
  // even for an unreadable guard object, where "the server stated no count" is the whole point.
  el.summaryGuardCaveats.textContent = [
    unreadableSentence(guard?.unreadable_lines, 'guard log'),
    unattributedSentence(guard?.unattributed_records),
  ]
    .filter(Boolean)
    .join(' ');

  if (kind === 'unknown') {
    el.summaryCoverageNote.textContent =
      'No coverage counts were readable in this answer, so nothing here says how much was looked at.';
    return;
  }

  const posture = postureWord(guard);
  el.summaryGuard.append(
    factRow('row-fact guard-posture', 'Across this window', [['', POSTURE_SENTENCE[posture]]], null),
  );
  for (const group of guard.groups) {
    el.summaryGuard.append(
      factRow(
        'row-fact guard-row',
        group.tool ?? '(unnamed tool)',
        [
          // The mode is on the row, never averaged away: the server groups on it precisely because
          // "the call proceeded" and "the call was refused" are opposite sentences about one
          // outcome word.
          ['mode', group.mode],
          ['', group.outcome],
          ['category', group.category],
          ['occurrences', group.occurrences],
          ['warrants', group.warrants],
        ],
        group.guidance,
      ),
    );
  }

  const coverage = guard.coverage;
  if (!coverage || typeof coverage !== 'object') {
    el.summaryCoverageNote.textContent =
      'This answer carried no coverage counts, so how much of the window nothing looked at is unknown.';
    return;
  }
  const rows = [
    ['guard sessions that attached', coverage.sessions_attached],
    ['of those, sessions that finished and reported', coverage.sessions_finished],
    ['calls actually sent to the backend', coverage.classified],
    ['of those, calls it called harmful', coverage.flagged],
    ['calls nothing looked at: the backend was unreachable', coverage.backend_unavailable],
    ['calls nothing looked at: the answer was not a verdict', coverage.unparseable],
    ["calls nothing looked at: the session's cap was spent", coverage.skipped_over_budget],
    // The fourth reason, found by running a live guarded session: a call the warrant PERMITTED
    // that had no upstream to be forwarded to. It never became an action, so it was never
    // classified — and before this row it was counted nowhere at all, so the three rows above
    // read as a complete account of what the guard missed when they were not.
    ['calls nothing looked at: permitted, but no upstream to forward to', coverage.permitted_no_route],
    ['repeats that cost no backend call', coverage.deduplicated],
  ];
  for (const [label, value] of rows) {
    el.summaryCoverage.append(
      factRow('row-fact coverage-row', label, [['', value ?? '(not stated)']], null),
    );
  }
  el.summaryCoverageNote.textContent =
    'Counted from end-of-session records only. A session that attached and never finished contributes nothing to the call counts above, so where the two session numbers differ those runs are unaccounted for here rather than accounted for as zero.';
}

/**
 * How many supervised sessions ran in this window with nothing watching them.
 *
 * # Why this is its own block and not a coverage row
 *
 * Everything above it is counted from guard records, and therefore says nothing about sessions the
 * guard was never in. This is the opposite population, and until the server grew a run log it could
 * not be counted at all: an unguarded session left no record, so "nobody was watching" and "nothing
 * ran" were the same observation.
 *
 * `unguarded` is deliberately not called "missed". An unguarded run produced no signal, so nothing
 * is known about what happened inside it beyond what the bounds refused — which is a gap in
 * observation, not a count of failures.
 *
 * @param {{total?: number, guarded?: number, unguarded?: number, warrants?: number}|null} runs
 */
export function runsSentence(runs) {
  if (!runs || !Number.isFinite(runs.total)) {
    // The server did not answer about runs at all. An older server is exactly this case, and
    // rendering it as "0 runs" would be this console inventing a fact about a month.
    return 'This server did not report run counts, so how many sessions ran unwatched is unknown — not zero.';
  }
  if (runs.total === 0) {
    return 'No supervised session started in this window.';
  }
  const s = (n) => (n === 1 ? '' : 's');
  if (runs.unguarded === 0) {
    return `${runs.total} supervised session${s(runs.total)} started, across ${runs.warrants} warrant${s(runs.warrants)}. Every one had a guard attached.`;
  }
  return `${runs.total} supervised session${s(runs.total)} started, across ${runs.warrants} warrant${s(runs.warrants)} — ${runs.unguarded} with NO guard attached. Nothing is known about what happened inside those beyond what the bounds refused.`;
}

// ── list ────────────────────────────────────────────────────────────────────

/**
 * Re-read the list.
 *
 * Returns the set of warrant ids whose lifecycle state changed since the last read, which is what
 * lets the poller leave the detail pane alone unless something actually happened to it.
 */
async function loadList() {
  const query = state.filter ? `?state=${encodeURIComponent(state.filter)}` : '';
  const { answered, status, payload } = await call(`/v1/warrants${query}`);
  if (answered && status === 401) {
    showGate('That token was not accepted.');
    return new Set();
  }

  el.list.replaceChildren();
  const facts = listFacts(answered, status, payload);
  const rows = facts.rows;

  // Compared against the previous read rather than assumed from the response, because a filtered
  // list cannot distinguish "this warrant was settled" from "this warrant left the filter".
  const changed = new Set();
  for (const w of rows) {
    if (!w.id) continue;
    if (knownStates.has(w.id) && knownStates.get(w.id) !== w.state) changed.add(w.id);
    knownStates.set(w.id, w.state);
  }

  // A record the server could not read is the one thing an oversight console must never
  // quietly drop: a list that silently shrinks reads as "nothing happened" at exactly the
  // moment something did. The API counts them separately, so this surfaces the count.
  //
  // This row is written whatever the filter and whichever empty paragraph shows below, which is
  // what lets `emptyKind` rank `filtered` above `unreadable` without losing the warning.
  const unreadable = facts.unreadable;
  if (unreadable > 0) {
    const warn = document.createElement('li');
    warn.append(
      node(
        'div',
        'row-sub error',
        `${unreadable} record(s) in this store could not be read. They are not in the list below.`,
      ),
    );
    el.list.append(warn);
  }

  for (const w of rows) {
    const id = w.id ?? '(unknown id)';
    const item = document.createElement('li');
    const row = node('button', `row${state.selected === id ? ' is-on' : ''}`);
    row.dataset.warrantId = id;
    // aria-current, not aria-selected: this is the item the view is showing, which is
    // what `current` means. `selected` would imply a selection set the list does not have.
    if (state.selected === id) row.setAttribute('aria-current', 'true');
    row.type = 'button';

    const top = node('div', 'row-top');
    top.append(node('span', 'row-id', id));
    if (w.state) top.append(node('span', 'pill pill-quiet', w.state));
    row.append(top);

    if (w.goal) row.append(node('div', 'row-sub', w.goal));

    // Each row carries its own verdict from the server. Showing it here means a tampered
    // warrant is visible in the list rather than only after someone clicks into it.
    const integrity = w.verification?.integrity;
    if (integrity && integrity !== 'ok') {
      const flag = node('div', 'row-sub');
      flag.append(node('span', `pill ${integrityClass(integrity)}`, `integrity ${integrity}`));
      row.append(flag);
    }

    row.addEventListener('click', () => select(id));
    item.append(row);
    el.list.append(item);
  }

  // Re-derived from this response rather than latched on connect, so the panel appears the moment
  // a store empties and clears itself within one poll of the first grant, with no reload.
  applyEmptyState(
    emptyKind({
      readable: facts.readable,
      rowCount: rows.length,
      unreadable,
      filter: state.filter,
    }),
  );

  return changed;
}

// ── live refresh ────────────────────────────────────────────────────────────

/**
 * One poll.
 *
 * The list is re-read every tick; the **detail pane is only re-rendered when the selected warrant's
 * state actually changed**. Re-rendering it on every tick would throw away the reader's scroll
 * position every five seconds, which in a pane holding a full report bundle makes the document
 * unreadable — and this is the surface someone is reading precisely when they are deciding whether
 * to release an agent's work.
 *
 * Nothing polls while the tab is hidden. A background tab that keeps a loopback API busy is a
 * battery cost with no reader attached.
 */
async function refresh() {
  if (refreshing || document.hidden || !api.token || el.app.hidden) return;
  refreshing = true;
  try {
    // Re-read while the answer is still missing, and only then. A health read that never arrived
    // left `releaseAuthority` latched at a value nobody reported, and nothing else re-reads it.
    if (!state.authorityKnown) await loadHealth();
    const changed = await loadList();
    if (state.selected && changed.has(state.selected)) {
      await loadDetail(state.selected, { quiet: true });
    }
  } catch (failure) {
    // Reaching here now means a defect in this file, not a failed request: `call` reports a
    // transport failure as an answer-less outcome and `loadList` paints the error paragraph for it.
    // The bare `catch {}` that used to sit here was a guard that failed open and reported nothing —
    // an unexplained empty list that never explained itself. A static asset has one channel left.
    console.error('warrantor console: refresh failed', failure);
  } finally {
    refreshing = false;
  }
}

/**
 * Start polling. Idempotent, because `connect` runs again whenever a token is re-entered, and a
 * second interval would double the poll rate every time someone reconnected.
 */
let refreshTimer = null;
let keyboardInstalled = false;

function startRefreshing() {
  if (!keyboardInstalled) {
    keyboardInstalled = true;
    installKeyboard();
  }
  if (refreshTimer !== null) return;
  refreshTimer = setInterval(refresh, REFRESH_MS);
  // A reader coming back to the tab should not wait out the remainder of a tick.
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) refresh();
  });
}

// ── detail ──────────────────────────────────────────────────────────────────

async function select(id) {
  state.selected = id;
  await loadList();
  // That read can null the selection out from under this click — it does exactly that when the
  // store turned out to be empty. Loading the detail anyway would refill the pane
  // `applyEmptyState` just cleared, with a 404 rendered as though it were about a real warrant.
  if (state.selected !== id) return;
  await loadDetail(id);
}

async function loadDetail(id, { quiet = false } = {}) {
  // The placeholder is skipped on a background refresh: a "Loading…" flash that nobody asked for
  // reads as the view breaking, not as it updating.
  if (!quiet) el.detail.replaceChildren(node('div', 'placeholder', 'Loading…'));

  const { answered, status, payload } = await call(`/v1/warrants/${encodeURIComponent(id)}`);
  if (answered && status === 401) return showGate('That token was not accepted.');

  const view = document.createDocumentFragment();
  view.append(node('h2', null, id));

  if (!answered) {
    // No verdict, no actions. Rendering the envelope helpers against a null payload would print
    // "not verified — unknown" and a row of buttons, which reads as a statement about this warrant
    // when the truth is that nothing was read about it at all.
    view.append(
      node(
        'p',
        'error',
        'The server did not answer, so nothing here is a statement about this warrant. The list keeps retrying.',
      ),
    );
    el.detail.replaceChildren(view);
    return;
  }

  if (status >= 400) {
    view.append(node('p', 'error', payload?.error?.message ?? `The server refused with ${status}.`));
    el.detail.replaceChildren(view);
    return;
  }

  view.append(renderVerdict(payload));
  view.append(renderActions(id, payload));

  const sections = [
    ['Warrant', payload?.data],
    ['Report', `/v1/warrants/${encodeURIComponent(id)}/report`],
    ['Staged effects', `/v1/warrants/${encodeURIComponent(id)}/effects`],
    ['Refusals', `/v1/warrants/${encodeURIComponent(id)}/refusals`],
  ];

  const warrantSection = node('div', 'section');
  warrantSection.append(node('h3', null, 'Warrant'));
  const tiers = node('ul', 'tiers');
  for (const line of boundTierLines(payload?.data)) tiers.append(node('li', null, line));
  if (tiers.children?.length || tiers.childElementCount) warrantSection.append(tiers);
  warrantSection.append(jsonBlock(payload?.data ?? {}));
  view.append(warrantSection);

  el.detail.replaceChildren(view);

  // The sub-resources load after the shell so a slow report cannot hold up the verdict —
  // the verdict is the thing a reviewer came for.
  // Custody first among the appended sections, because "who may release this, and has"
  // is the question a reviewer opens a warrant to answer.
  {
    const { answered: a, status: st, payload: pl } = await call(
      `/v1/warrants/${encodeURIComponent(id)}/custody`,
    );
    view.append(renderCustody(id, custodyFacts(a, st, pl)));
  }

  for (const [title, path] of sections.slice(1)) {
    const { answered: a, status: s, payload: p } = await call(path);
    if (a && s === 404) continue;
    const section = node('div', 'section');
    section.append(node('h3', null, title));
    if (!a) {
      // Not `continue`: a section that vanishes reads as "there is none of this", and a sub-resource
      // nobody could reach is not a sub-resource that does not exist.
      section.append(node('p', 'error', 'The server did not answer for this section.'));
    } else if (s >= 400) {
      section.append(node('p', 'error', p?.error?.message ?? `Refused with ${s}.`));
    } else {
      // Each sub-resource carries its own verdict; a report that fails verification must
      // not inherit the reassurance of the warrant that pointed at it.
      section.append(renderVerdict(p));
      section.append(jsonBlock(p?.data ?? {}));
    }
    el.detail.append(section);
  }
}

/**
 * The three acts that require a human.
 *
 * Settle and void are disabled unless the server reported release authority, because a
 * server started without --allow-settle holds no settle key and will refuse. Showing a
 * live button that always fails would teach an operator to distrust the console; showing
 * a disabled one with the reason teaches them how the server was started.
 */
function renderActions(id, envelope) {
  const wrap = node('div', 'section');
  wrap.append(node('h3', null, 'Acts requiring a human'));
  const acts = node('div', 'acts');

  const mutating = envelope?.verification?.integrity === 'ok';

  const make = (label, path, danger, needsAuthority, prompt) => {
    const button = node('button', `act${danger ? ' act-danger' : ''}`, label);
    button.type = 'button';
    const blocked = (needsAuthority && !state.releaseAuthority) || !mutating;
    button.disabled = blocked;
    button.addEventListener('click', () => act(id, path, label, prompt));
    acts.append(button);
  };

  make('Settle', 'settle', false, true, 'Release the staged effects for this warrant?');
  make('Void', 'void', true, true, 'Discard the work for this warrant?');
  make('Stop', 'stop', true, false, 'End this run now and write a signed stop record?');
  wrap.append(acts);

  if (!state.authorityKnown) {
    // The reason has to match what was actually read. Printing the --allow-settle sentence here
    // would explain a server nobody has heard from, which is a guess wearing a reading's clothes.
    wrap.append(
      node(
        'p',
        'note error',
        'This console has not been able to read whether this server holds release authority, so settle and void are disabled here. That is an absence of signal, not a clearance.',
      ),
    );
  } else if (!state.releaseAuthority) {
    wrap.append(
      node(
        'p',
        'note',
        'This server was started without --allow-settle, so it holds no settle key: settle and void will refuse. Stop remains available.',
      ),
    );
  }
  if (!mutating) {
    wrap.append(
      node(
        'p',
        'note error',
        'Integrity is not ok for this record, so the mutating routes refuse outright. Read the verdict above before acting on this warrant.',
      ),
    );
  }
  return wrap;
}

async function act(id, path, label, prompt) {
  if (!window.confirm(`${prompt}\n\n${id}`)) return;
  const { answered, status, payload } = await call(
    `/v1/warrants/${encodeURIComponent(id)}/${path}`,
    {
      method: 'POST',
      body: JSON.stringify({}),
    },
  );
  if (!answered) {
    // A POST that got no answer may still have been performed: the request can have reached the
    // server and the response been lost. Saying "refused" would be a claim about the store, and
    // saying "accepted" would be worse. The reload below shows whatever actually happened.
    toast(`${label}: the server did not answer, so whether it acted is unknown.`);
  } else if (status >= 400) {
    toast(payload?.error?.message ?? `${label} refused with ${status}.`);
  } else {
    toast(`${label} accepted.`);
  }
  await select(id);
}

// ── custody: who acted, and what the store requires ─────────────────────────

/**
 * Decide what a custody payload established, without deriving anything the server did not say.
 *
 * The same discipline `listFacts` follows, for the same reason: an optimistic read
 * (`payload?.data?.acts ?? []`) turns "the request failed" and "nobody has acted" into the same
 * empty array — and on this surface those are opposite facts. One means the approval requirement
 * cannot be evaluated; the other means it is genuinely unmet.
 *
 * `chain_intact` is read, never computed. The server checks the hash chain; a console that checked
 * it too would be a second implementation of a check, which is the one thing this codebase forbids
 * everywhere.
 */
export function custodyFacts(answered, status, payload) {
  const unusable = { readable: false, acts: [], approvers: [], required: 0, chainIntact: null };
  if (!answered || status !== 200) return unusable;
  const data = payload?.data;
  if (!data || !Array.isArray(data.acts) || !Array.isArray(data.approvers)) return unusable;
  return {
    readable: true,
    acts: data.acts,
    approvers: data.approvers,
    required: Number(data.required_approvals ?? 0),
    settlerMayApprove: data.settler_may_approve === true,
    distinct: Number(data.distinct_approvers ?? data.approvers.length),
    chainIntact: data.chain_intact === true,
    chainFault: data.chain_fault ?? null,
  };
}

/**
 * The sentence describing where a warrant stands against its approval requirement.
 *
 * Returns a `{ kind, text }` pair rather than a string, so the caller styles by kind and the wording
 * lives in one place. Five kinds, because five different things are true and collapsing any two of
 * them would tell a reviewer they are done when they are not.
 */
export function approvalStanding(facts) {
  if (!facts.readable) {
    return {
      kind: 'unknown',
      text: 'This custody record could not be read, so whether this warrant has been approved is unknown. That is an absence of an answer, not the answer "no".',
    };
  }
  if (facts.chainIntact === false) {
    return {
      kind: 'broken',
      text: `The chain of recorded acts does not hold: ${facts.chainFault ?? 'a line has been edited, removed or reordered'}. Until that is explained, nothing here can be relied on as a record of who acted.`,
    };
  }
  if (facts.required === 0) {
    return {
      kind: 'none',
      text: 'This store requires no approvals before a settle, so the acts below are accountability rather than a gate. Write approvals.json to make it a gate.',
    };
  }
  if (facts.distinct >= facts.required) {
    return {
      kind: 'met',
      text: `${facts.distinct} of ${facts.required} required approval(s) recorded. A settle by anyone who is not themselves one of the approvers will be permitted${facts.settlerMayApprove ? ' — and this store lets the settler count as one' : ''}.`,
    };
  }
  return {
    kind: 'short',
    text: `${facts.distinct} of ${facts.required} required approval(s) recorded. A settle is refused until the rest are, by someone holding the approve scope.`,
  };
}

/** Render the custody section: the standing, the acts, and what none of it is. */
function renderCustody(id, facts) {
  const wrap = node('div', 'section');
  wrap.append(node('h3', null, 'Custody — who acted'));

  const standing = approvalStanding(facts);
  const pillFor = { met: 'pill-ok', broken: 'pill-bad', unknown: 'pill-unknown' };
  const box = node('div', 'verdict');
  const head = node('div', 'verdict-head');
  head.append(
    node('span', `pill ${pillFor[standing.kind] ?? 'pill-quiet'}`, {
      met: 'approved',
      short: 'awaiting approval',
      none: 'no requirement',
      broken: 'chain broken',
      unknown: 'unreadable',
    }[standing.kind]),
  );
  box.append(head);
  box.append(node('p', 'verdict-why', standing.text));
  wrap.append(box);

  if (facts.readable && facts.acts.length > 0) {
    const list = node('ol', 'acts-log');
    for (const act of facts.acts) {
      const item = document.createElement('li');
      const row = node('div', 'act-row');
      row.append(node('span', `pill pill-quiet`, act.act));
      // `null` is rendered as a sentence and never as a name. A placeholder here would be the
      // console inventing a principal the store deliberately declined to invent.
      row.append(
        node(
          'span',
          'act-actor',
          act.actor ?? 'no operator named (the session token)',
        ),
      );
      row.append(node('span', 'act-meta', `${act.via} · ${act.at}`));
      item.append(row);
      list.append(item);
    }
    wrap.append(list);
  } else if (facts.readable) {
    wrap.append(node('p', 'note', 'Nothing has been settled, voided, stopped or approved on this warrant.'));
  }

  const approve = node('button', 'act', 'Record an approval');
  approve.type = 'button';
  approve.addEventListener('click', () => act(id, 'approve', 'Approve', 'Record your approval of this warrant? This is a decision, not a verification: it says you looked.'));
  const acts = node('div', 'acts');
  acts.append(approve);
  wrap.append(acts);

  wrap.append(
    node(
      'p',
      'note',
      'These acts are a store-local hash chain, NOT signed evidence. They record who this store believes acted; they are not in any receipt, and an approval is never a verification result. Check evidence with warrantor verify.',
    ),
  );
  return wrap;
}

// ── keyboard: an oversight console a reviewer can work without a mouse ──────

/**
 * Which key does what, in one table, so the sheet and the handler cannot disagree.
 *
 * A shortcut sheet maintained separately from its handler is a sheet that lies within two commits.
 * `?` renders this list; the handler dispatches from it.
 */
export const SHORTCUTS = [
  ['j / ↓', 'next warrant'],
  ['k / ↑', 'previous warrant'],
  ['Enter', 'open the selected warrant'],
  ['g / G', 'first / last warrant'],
  ['/', 'jump to the state filters'],
  ['1 / 2 / 3 / 4 / 5', 'Warrants / Waiting on you / Refusals & guard / Coverage map / Routing'],
  // The settings, audit, fleet and incidents panes are click-only: the source carries eight
  // destinations and the keyboard has only five digits. Each is reached by clicking its
  // tab in the right-hand column. The prose on the sheet says "five digits" rather than
  // naming the click-only panes, because a sheet that listed them would invite readers to
  // hunt for a key that is not bound.

  ['?', 'this sheet'],
  ['Escape', 'close this sheet'],
];

/** The rows currently in the list, as their warrant ids, in display order. */
function listedIds() {
  return Array.from(document.querySelectorAll('.row')).map((row) => row.dataset.warrantId).filter(Boolean);
}

/**
 * Move the selection by `delta`, or to an absolute end.
 *
 * Selecting also loads the detail, which is the same thing a click does — so the keyboard path and
 * the mouse path go through one function and cannot drift.
 */
function moveSelection(delta, absolute) {
  const ids = listedIds();
  if (ids.length === 0) return;
  let next;
  if (absolute === 'first') next = 0;
  else if (absolute === 'last') next = ids.length - 1;
  else {
    const current = ids.indexOf(state.selected);
    next = current === -1 ? (delta > 0 ? 0 : ids.length - 1) : current + delta;
  }
  if (next < 0 || next >= ids.length) return;
  const id = ids[next];
  select(id);
  const row = document.querySelector(`.row[data-warrant-id="${CSS.escape(id)}"]`);
  // Focus follows selection, so a screen reader announces the row and the browser scrolls it into
  // view without a scroll calculation of our own.
  row?.focus();
}

/** Whether a keystroke belongs to whatever the user is typing in. */
function typingInto(target) {
  const tag = target?.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target?.isContentEditable === true;
}

function toggleShortcuts(show) {
  if (!el.shortcuts) return;
  el.shortcuts.hidden = !show;
  if (show) el.shortcuts.querySelector('button')?.focus();
}

function installKeyboard() {
  if (el.shortcutList && el.shortcutList.childElementCount === 0) {
    for (const [keys, what] of SHORTCUTS) {
      const item = document.createElement('li');
      item.append(node('kbd', null, keys));
      item.append(node('span', null, what));
      el.shortcutList.append(item);
    }
  }
  el.shortcutsClose?.addEventListener('click', () => toggleShortcuts(false));

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      toggleShortcuts(false);
      return;
    }
    // Never steal a keystroke from a field, and never from a modified chord the browser or the
    // desktop shell owns.
    if (typingInto(event.target) || event.metaKey || event.ctrlKey || event.altKey) return;
    switch (event.key) {
      case 'j':
      case 'ArrowDown':
        event.preventDefault();
        moveSelection(1);
        break;
      case 'k':
      case 'ArrowUp':
        event.preventDefault();
        moveSelection(-1);
        break;
      case 'g':
        moveSelection(0, 'first');
        break;
      case 'G':
        moveSelection(0, 'last');
        break;
      case '/':
        event.preventDefault();
        document.querySelector('.chip')?.focus();
        break;
      // Numbered by VISUAL ORDER, which rebinds `2` from the summary to the queue. Worth doing
      // rather than appending `3` to the queue and leaving `2` on the summary: a number key that
      // does not match the position of the thing it selects is a shortcut people stop trusting,
      // and this console has had three destinations for exactly one commit on an unmerged branch,
      // so there is no muscle memory to protect yet.
      case '1':
        setView('warrants');
        break;
      case '2':
        setView('queue');
        break;
      case '3':
        setView('summary');
        break;
      case '4':
        setView('coverage');
        break;
      case '5':
        setView('routing');
        break;

      case '?':
        event.preventDefault();
        toggleShortcuts(el.shortcuts?.hidden !== false);
        break;
      default:
        break;
    }
  });
}

// ── the grant line ──────────────────────────────────────────────────────────

/**
 * Put the grant command on the clipboard, or say honestly that it could not be put there.
 *
 * Feature-detected rather than assumed, because two supported ways of running this console have
 * no clipboard write. `navigator.clipboard` is undefined on a non-secure origin, which is what
 * `--bind <lan-ip>` over plain HTTP produces; and the desktop shell grants the renderer no
 * permissions at all — `desktop/src/policy.js` freezes the granted list empty, deliberately — so
 * the write can reject there while working in Chrome. Widening that list to make a convenience
 * button work would trade a tested security decision for a nicety, so the fallback lives here.
 *
 * The fallback selects the text and says what to press. It never toasts "Copied." for a copy that
 * did not happen: claiming an act that did not occur is the same shape of error as showing
 * `unknown` as `ok`, and this console is the surface that must not do that anywhere.
 */
async function copyGrantCommand() {
  const line = el.grantCommand.textContent ?? '';
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(line);
      toast('Copied.');
      return;
    } catch {
      // Permission refused or origin not secure. Fall through rather than report a copy.
    }
  }
  selectGrantCommand();
}

/** Select the grant line so a keyboard copy works where the clipboard API does not. */
function selectGrantCommand() {
  const selection = window.getSelection?.();
  if (!selection) {
    toast('This browser will not copy for us — select the line and copy it by hand.');
    return;
  }
  const range = document.createRange();
  range.selectNodeContents(el.grantCommand);
  selection.removeAllRanges();
  selection.addRange(range);
  toast('Selected. Press Ctrl+C (Cmd+C on a Mac) to copy.');
}

// ── health ──────────────────────────────────────────────────────────────────

/**
 * Read the server's own report of itself.
 *
 * Returns whether the console may proceed into the app — which is NOT the same as whether the read
 * succeeded. A server that did not answer has not rejected the token, and sending the reader back
 * to the gate would blame them for the agent being down. So a silent server proceeds, says so in
 * the pill, leaves authority unknown, and lets the list explain itself; only an actual 401 gates.
 */
async function loadHealth() {
  const { answered, status, payload } = await call('/v1/health');
  if (answered && status === 401) {
    showGate('That token was not accepted.');
    return false;
  }
  if (!answered || status !== 200 || !payload?.data) {
    el.health.textContent = answered ? `no reading (${status})` : 'no answer';
    el.health.className = 'pill pill-unknown';
    // Conservative on the buttons, honest in the label: `authorityKnown` stays false, so
    // `renderActions` explains the absence rather than asserting how the server was started.
    // `refresh` re-reads until a real answer arrives.
    state.releaseAuthority = false;
    state.authorityKnown = false;
    el.authority.textContent = 'authority unknown';
    el.authority.className = 'pill pill-unknown';
    return true;
  }
  const data = payload.data;
  el.health.textContent = data.version ? `v${data.version}` : 'connected';
  el.health.className = 'pill pill-ok';

  // The server reports whether it was armed. Anything the console infers instead of reads
  // would drift from the process it is talking to.
  state.releaseAuthority = Boolean(
    data.release_authority ?? data.releaseAuthority ?? data.allow_settle,
  );
  el.authority.textContent = state.releaseAuthority ? 'settle armed' : 'read + stop only';
  el.authority.className = `pill ${state.releaseAuthority ? 'pill-unknown' : 'pill-quiet'}`;
  state.authorityKnown = true;
  return true;
}

// ── gate ────────────────────────────────────────────────────────────────────

function showGate(message) {
  api.token = null;
  el.app.hidden = true;
  el.gate.hidden = false;
  el.gateError.hidden = !message;
  if (message) el.gateError.textContent = message;
}

async function connect(token) {
  api.token = token;
  const ok = await loadHealth();
  if (!ok) return;
  el.gate.hidden = true;
  el.app.hidden = false;
  // Polling starts BEFORE the first read, not after it. It used to be the other line, and a first
  // read that did not complete meant `startRefreshing()` was never reached: a visible app, an empty
  // list, every explanation still hidden, and no timer that could ever revisit any of it. The order
  // here is the difference between a console that recovers when the agent comes back and one that
  // has to be reloaded by hand.
  startRefreshing();
  await loadList();
}

// ── wiring ──────────────────────────────────────────────────────────────────

el.gateForm.addEventListener('submit', (event) => {
  event.preventDefault();
  const value = el.gateInput.value.trim();
  if (value) {
    el.gateInput.value = '';
    connect(value);
  }
});

for (const chip of document.querySelectorAll('.chip')) {
  chip.addEventListener('click', () => setFilter(chip.dataset.state ?? ''));
}

// "Show all" is the way out of an empty filtered view, and it goes through the same call as the
// chips so it cannot leave a chip lit for a filter that is no longer in force.
el.showAll.addEventListener('click', () => setFilter(''));

// Wired here, not as an onclick attribute: the console is served under `script-src 'self'` with
// no `unsafe-inline`, so an inline handler would be silently dead in the browser and pass every
// test in the suite.
el.copyButton.addEventListener('click', copyGrantCommand);

// The month view. The input starts on the month the reader is in, because a blank one would make
// the first click render the "could not be read" paragraph over a working server.
el.summaryMonth.value = currentMonth();
el.viewWarrants.addEventListener('click', () => setView('warrants'));
el.viewSummary.addEventListener('click', () => setView('summary'));
el.viewQueue.addEventListener('click', () => setView('queue'));
if (el.viewSettings) el.viewSettings.addEventListener('click', () => setView('settings'));
if (el.viewCoverage) el.viewCoverage.addEventListener('click', () => setView('coverage'));

el.viewRouting.addEventListener('click', () => setView('routing'));
if (el.viewAudit) el.viewAudit.addEventListener('click', () => setView('audit'));
if (el.viewFleet) el.viewFleet.addEventListener('click', () => setView('fleet'));
if (el.viewIncidents) el.viewIncidents.addEventListener('click', () => setView('incidents'));
if (el.viewPolicy) el.viewPolicy.addEventListener('click', () => setView('policy'));
if (el.viewExecutive) el.viewExecutive.addEventListener('click', () => setView('executive'));
if (el.viewAutonomy) el.viewAutonomy.addEventListener('click', () => setView('autonomy'));
if (el.viewCrosswalk) el.viewCrosswalk.addEventListener('click', () => setView('crosswalk'));

// The studio re-renders on every keystroke into the editor (so the operator
// sees the refusal sentence appear as they type a malformed line) and on
// every change to the exception form. The compile button is a no-op beyond
// that — the result is already painted — and exists only because the
// typical non-developer expects one.
if (el.policyForm) {
  el.policyForm.addEventListener('submit', (event) => {
    event.preventDefault?.();
    renderPolicy();
  });
}
if (el.policyIntent) el.policyIntent.addEventListener('input', renderPolicy);
if (el.policyRules) el.policyRules.addEventListener('input', renderPolicy);
if (el.policyExceptionExpires) el.policyExceptionExpires.addEventListener('input', renderPolicy);
if (el.policyExceptionCompensating) el.policyExceptionCompensating.addEventListener('input', renderPolicy);
if (el.policyExceptionWarrant) el.policyExceptionWarrant.addEventListener('input', renderPolicy);

el.summaryForm.addEventListener('submit', (event) => {
  event.preventDefault?.();
  loadSummary();
});

const fromUrl = tokenFromFragment();
if (fromUrl) {
  connect(fromUrl);
} else {
  showGate(null);
}
