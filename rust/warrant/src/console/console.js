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
  viewWarrants: document.getElementById('view-warrants'),
  viewSummary: document.getElementById('view-summary'),
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
  el.summary.hidden = !summary;
  el.firstRun.hidden = summary || !explain;
  el.detail.hidden = summary || explain;

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
  el.viewWarrants.classList.toggle('is-on', value === 'warrants');
  el.viewSummary.classList.toggle('is-on', value === 'summary');
  applyEmptyState(state.lastKind);
  if (value === 'summary') await loadSummary();
}

// ── the summary: bounds that refused, and what a model said about what they allowed ──

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
function startRefreshing() {
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
  warrantSection.append(jsonBlock(payload?.data ?? {}));
  view.append(warrantSection);

  el.detail.replaceChildren(view);

  // The sub-resources load after the shell so a slow report cannot hold up the verdict —
  // the verdict is the thing a reviewer came for.
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
