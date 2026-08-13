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
  listEmpty: document.getElementById('list-empty'),
  detail: document.getElementById('detail'),
  health: document.getElementById('health'),
  authority: document.getElementById('authority'),
  toast: document.getElementById('toast'),
};

let state = { filter: '', selected: null, releaseAuthority: false };

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
 * Returns the parsed envelope for any response the server produced, including a refusal:
 * a 4xx here is an *answer*, and the caller decides how to show it. Only a transport
 * failure throws.
 */
async function call(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      authorization: `Bearer ${api.token}`,
      ...(options.body ? { 'content-type': 'application/json' } : {}),
    },
    // The API sends Connection: close and no CORS headers; this is same-origin only.
    cache: 'no-store',
  });
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  return { status: response.status, payload };
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

// ── list ────────────────────────────────────────────────────────────────────

/**
 * Re-read the list.
 *
 * Returns the set of warrant ids whose lifecycle state changed since the last read, which is what
 * lets the poller leave the detail pane alone unless something actually happened to it.
 */
async function loadList() {
  const query = state.filter ? `?state=${encodeURIComponent(state.filter)}` : '';
  const { status, payload } = await call(`/v1/warrants${query}`);
  if (status === 401) {
    showGate('That token was not accepted.');
    return new Set();
  }

  el.list.replaceChildren();
  const warrants = payload?.data?.warrants ?? [];
  const rows = Array.isArray(warrants) ? warrants : [];
  el.listEmpty.hidden = rows.length > 0;

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
  const unreadable = payload?.data?.unreadable_records ?? 0;
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
    const changed = await loadList();
    if (state.selected && changed.has(state.selected)) {
      await loadDetail(state.selected, { quiet: true });
    }
  } catch {
    // A failed poll is not worth a message: the next one is five seconds away, and a console that
    // shouts about a transient fetch teaches the reader to ignore it.
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
  await loadDetail(id);
}

async function loadDetail(id, { quiet = false } = {}) {
  // The placeholder is skipped on a background refresh: a "Loading…" flash that nobody asked for
  // reads as the view breaking, not as it updating.
  if (!quiet) el.detail.replaceChildren(node('div', 'placeholder', 'Loading…'));

  const { status, payload } = await call(`/v1/warrants/${encodeURIComponent(id)}`);
  if (status === 401) return showGate('That token was not accepted.');

  const view = document.createDocumentFragment();
  view.append(node('h2', null, id));

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
    const { status: s, payload: p } = await call(path);
    if (s === 404) continue;
    const section = node('div', 'section');
    section.append(node('h3', null, title));
    if (s >= 400) {
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

  if (!state.releaseAuthority) {
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
  const { status, payload } = await call(`/v1/warrants/${encodeURIComponent(id)}/${path}`, {
    method: 'POST',
    body: JSON.stringify({}),
  });
  if (status >= 400) {
    toast(payload?.error?.message ?? `${label} refused with ${status}.`);
  } else {
    toast(`${label} accepted.`);
  }
  await select(id);
}

// ── health ──────────────────────────────────────────────────────────────────

async function loadHealth() {
  const { status, payload } = await call('/v1/health');
  if (status === 401) {
    showGate('That token was not accepted.');
    return false;
  }
  const data = payload?.data ?? {};
  el.health.textContent = data.version ? `v${data.version}` : 'connected';
  el.health.className = 'pill pill-ok';

  // The server reports whether it was armed. Anything the console infers instead of reads
  // would drift from the process it is talking to.
  state.releaseAuthority = Boolean(
    data.release_authority ?? data.releaseAuthority ?? data.allow_settle,
  );
  el.authority.textContent = state.releaseAuthority ? 'settle armed' : 'read + stop only';
  el.authority.className = `pill ${state.releaseAuthority ? 'pill-unknown' : 'pill-quiet'}`;
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
  await loadList();
  startRefreshing();
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
  chip.addEventListener('click', () => {
    for (const other of document.querySelectorAll('.chip')) other.classList.remove('is-on');
    chip.classList.add('is-on');
    state.filter = chip.dataset.state ?? '';
    loadList();
  });
}

const fromUrl = tokenFromFragment();
if (fromUrl) {
  connect(fromUrl);
} else {
  showGate(null);
}
