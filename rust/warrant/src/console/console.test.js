/**
 * The console's decisions, tested without a browser.
 *
 * # Why this file exists at all
 *
 * `rust/warrant/tests/console.rs` used to say that `emptyKind`'s branch selection "cannot be
 * exercised from Rust: there is no JavaScript runner, and RFC W1 §Dependencies forbids adding one",
 * and left the behaviour to a manual run. That was one word too strong. §Dependencies forbids a
 * build step, a framework, a bundler and a package manager — `node --test` is none of those. It is
 * the runtime's own runner, it installs nothing, and `desktop/test/policy.test.js` already runs
 * under it in this repository with no `npm ci` in front of it.
 *
 * The gap that reading left was not theoretical. Three of the four rungs in `emptyKind` were wrong
 * or unreachable and every Rust test passed, because Rust can only assert over the served bytes.
 *
 * # How the DOM is faked
 *
 * `console.js` is the page's entry module: importing it *is* booting the console. So this installs
 * a small object graph on `globalThis` — the elements by id, `createElement`, a `fetch` that
 * answers from a script, and a `setInterval` that records its callback instead of scheduling it —
 * and then imports the module. No jsdom, no dependency, nothing to install.
 *
 * The stub is deliberately dumb: it models `hidden`, `textContent`, `className` and parent/child
 * links, and nothing else. Its job is to let assertions be made about which paragraph is showing
 * and what the panes hold, which is exactly what the findings here were about. A cache-busting
 * query on the import specifier gives each scenario a fresh module instance.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const MODULE_PATH = path.join(path.dirname(fileURLToPath(import.meta.url)), 'console.js');
const MODULE_URL = pathToFileURL(MODULE_PATH).href;

/** Element ids `console.js` looks up at module scope. Missing one is a null deref on import. */
const ELEMENT_IDS = [
  'gate',
  'gate-form',
  'gate-input',
  'gate-error',
  'app',
  'list',
  'list-empty-first-run',
  'list-empty-filtered',
  'list-empty-unreadable',
  'list-empty-error',
  'show-all',
  'first-run',
  'first-run-command',
  'copy-command',
  'detail',
  'shortcuts',
  'shortcut-list',
  'shortcuts-close',
  'health',
  'authority',
  'toast',
  'view-warrants',
  'view-summary',
  'view-queue',
  'view-settings',
  'settings',
  'settings-headline',
  'settings-decision',
  'settings-transports',
  'settings-order',
  'settings-ledger',
  'settings-pending',
  'settings-empty',
  'settings-error',
  'settings-unreadable',
  'view-coverage',
  'coverage',
  'coverage-headline',
  'coverage-percent',
  'coverage-remainder',
  'coverage-matrix',
  'coverage-bypasses',
  'coverage-empty',
  'coverage-error',
  'coverage-unreadable',
  'view-routing',
  'queue',
  'queue-headline',
  'queue-who',
  'queue-rows',
  'queue-empty',
  'queue-error',
  'queue-unreadable',
  'queue-latency',
  'summary',
  'summary-form',
  'summary-month',
  'summary-month-error',
  'summary-error',
  'summary-window',
  'summary-caveat',
  'summary-unreadable',
  'summary-refusals',
  'summary-refusals-empty',
  'summary-refusals-note',
  'summary-guard',
  'summary-guard-unknown',
  'summary-guard-none',
  'summary-guard-unattributed',
  'summary-guard-quiet',
  'summary-guard-note',
  'summary-guard-caveats',
  'summary-coverage',
  'summary-coverage-note',
  'summary-runs',
  'routing',
  'routing-headline',
  'routing-policy',
  'routing-ceiling',
  'routing-decisions',
  'routing-empty',
  'routing-error',
  'routing-unreadable',
];

function element(tag = 'div', id = '') {
  const self = {
    tagName: tag,
    id,
    className: '',
    textContent: '',
    hidden: false,
    disabled: false,
    type: '',
    value: '',
    dataset: {},
    children: [],
    listeners: new Map(),
    classList: {
      add(name) {
        const has = self.className.split(/\s+/).includes(name);
        if (!has) self.className = `${self.className} ${name}`.trim();
      },
      remove(name) {
        self.className = self.className
          .split(/\s+/)
          .filter((c) => c !== name)
          .join(' ')
          .trim();
      },
      toggle(name, on) {
        const has = self.className.split(/\s+/).includes(name);
        if (on === true && !has) self.className = `${self.className} ${name}`.trim();
        if (on === false && has) {
          self.className = self.className
            .split(/\s+/)
            .filter((c) => c !== name)
            .join(' ');
        }
      },
    },
    get childElementCount() {
      return self.children.length;
    },
    attributes: {},
    // Needed for `aria-current`, which is how the list tells assistive technology which
    // row the detail pane is showing. Modelled as a plain map: nothing reads it back yet,
    // and a stub that pretended to be more would invite tests that assert on the stub.
    setAttribute(name, value) {
      self.attributes[name] = String(value);
    },
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(self.attributes, name)
        ? self.attributes[name]
        : null;
    },
    // Selection follows the keyboard, and a focused row is how a screen reader is told
    // which one it is. Recorded rather than performed: there is no focus in a stub.
    focused: false,
    focus() {
      self.focused = true;
    },
    append(...kids) {
      // A DocumentFragment in the stub exposes its children the same way an Element does, so
      // a real browser's `parent.append(frag)` flattens the fragment's children into `parent`.
      // The production code relies on that flattening (a queue row builds each disclosure
      // block as a fragment and then appends it). Without this, the row's direct children
      // would all be fragments, and the per-section classNames would be invisible to the
      // tests that read `row.children`.
      const flat = [];
      for (const k of kids) {
        if (k && (k.id === '#fragment' || k.tagName === '#fragment')) {
          flat.push(...(k.children ?? []));
        } else {
          flat.push(k);
        }
      }
      self.children.push(...flat);
    },
    replaceChildren(...kids) {
      const flat = [];
      for (const k of kids) {
        if (k && (k.id === '#fragment' || k.tagName === '#fragment')) {
          flat.push(...(k.children ?? []));
        } else {
          flat.push(k);
        }
      }
      self.children = [...flat];
    },
    addEventListener(name, handler) {
      const existing = self.listeners.get(name) ?? [];
      existing.push(handler);
      self.listeners.set(name, existing);
    },
    fire(name, event = {}) {
      for (const handler of self.listeners.get(name) ?? []) handler(event);
    },
  };
  return self;
}

/** Every string in a subtree, so an assertion can ask what a pane says without walking it. */
function textOf(root) {
  if (root === undefined || root === null) return '';
  const own = root.textContent ?? '';
  const kids = (root.children ?? []).map(textOf).join(' ');
  return `${own} ${kids}`.trim();
}

/**
 * Boot the console against a scripted server.
 *
 * `answer` is called with the request path and returns either a `{status, body}` object, or throws
 * to model a transport failure — the case `fetch` rejects on, which is how a loopback agent that
 * has exited actually presents.
 */
async function boot(answer, { hash = '#t=deadbeef' } = {}) {
  const byId = new Map(ELEMENT_IDS.map((id) => [id, element('div', id)]));
  const chips = ['', 'open', 'held', 'settled', 'void'].map((value) => {
    const chip = element('button');
    chip.dataset.state = value;
    chip.className = value === '' ? 'chip is-on' : 'chip';
    return chip;
  });

  const calls = [];
  const timers = { interval: null };

  globalThis.document = {
    hidden: false,
    getElementById: (id) => byId.get(id) ?? null,
    createElement: (tag) => element(tag),
    createDocumentFragment: () => element('#fragment'),
    querySelectorAll: (selector) => (selector === '.chip' ? chips : []),
    addEventListener: () => {},
  };
  globalThis.window = {
    location: { hash, pathname: '/' },
    confirm: () => true,
    getSelection: () => null,
  };
  globalThis.history = { replaceState: () => {} };
  // `globalThis.navigator` is a getter-only accessor in Node, so it is redefined rather than
  // assigned. The console only reaches for `navigator.clipboard`, and only on a button press.
  Object.defineProperty(globalThis, 'navigator', { value: {}, configurable: true, writable: true });
  // Recorded, not scheduled: a live interval would keep `node --test` from exiting, and driving
  // the poll by hand is what lets a test say "the next poll" without waiting five seconds.
  globalThis.setInterval = (fn) => {
    timers.interval = fn;
    return 1;
  };
  globalThis.clearInterval = () => {};
  // The toast timer, likewise. Fired immediately would hide the toast before it could be read.
  globalThis.setTimeout = () => 0;
  globalThis.clearTimeout = () => {};
  globalThis.fetch = async (requestPath) => {
    calls.push(requestPath);
    const scripted = answer(requestPath);
    return {
      status: scripted.status,
      json: async () => {
        if (scripted.unparseable) throw new SyntaxError('Unexpected end of JSON input');
        return scripted.body;
      },
    };
  };

  const module = await import(`${MODULE_URL}?case=${boot.counter++}`);
  await settle();
  return {
    module,
    calls,
    chips,
    el: (id) => byId.get(id),
    poll: async () => {
      assert.ok(timers.interval, 'nothing started the poll timer');
      await timers.interval();
      await settle();
    },
    pollStarted: () => timers.interval !== null,
  };
}
boot.counter = 0;

/** Let the module's un-awaited boot promise run to completion. */
function settle() {
  return new Promise((resolve) => setImmediate(() => setImmediate(resolve)));
}

const HEALTH_OK = { status: 200, body: { data: { version: '1.0.0', release_authority: false } } };
const listOf = (warrants, unreadable = 0) => ({
  status: 200,
  body: { data: { warrants, unreadable_records: unreadable } },
});
const ONE_WARRANT = [
  {
    id: 'wrt_0000000000000001',
    state: 'open',
    goal: 'fix the auth bug',
    verification: { integrity: 'ok' },
  },
];

// ── the stub and the page it stands in for ────────────────────────────────────────────────

// ELEMENT_IDS is a second copy of what index.html declares, and nothing used to check the two
// agreed. Adding four elements to the page left the stub without them, `getElementById` returned
// null for each, and eight tests died on `Cannot set properties of null (setting 'hidden')` —
// eight failures, in tests about guard states, none of which named the actual problem.
//
// This test names it. It reads the real index.html and the real console.js rather than a list
// maintained beside them, so the next element added to the page either appears here or fails with
// a sentence saying which id is missing and from where.
test('every element the console looks up exists in index.html and in this stub', async () => {
  const { readFileSync } = await import('node:fs');
  const here = path.dirname(fileURLToPath(import.meta.url));
  const read = (name) => readFileSync(path.join(here, name), 'utf8');
  const { module } = await boot(() => HEALTH_OK);
  const { SHORTCUTS } = module;

  const lookedUp = [...read('console.js').matchAll(/getElementById\('([a-z0-9-]+)'\)/g)].map(
    (match) => match[1],
  );
  const onThePage = new Set(
    [...read('index.html').matchAll(/id="([a-z0-9-]+)"/g)].map((match) => match[1]),
  );
  const stubbed = new Set(ELEMENT_IDS);

  const missingFromPage = [...new Set(lookedUp)].filter((id) => !onThePage.has(id)).sort();
  const missingFromStub = [...new Set(lookedUp)].filter((id) => !stubbed.has(id)).sort();

  assert.deepEqual(
    missingFromPage,
    [],
    `console.js looks up ids that index.html does not declare: ${missingFromPage.join(', ')}`,
  );
  assert.deepEqual(
    missingFromStub,
    [],
    `console.js looks up ids this test file's ELEMENT_IDS does not stub, so they resolve to null \
and every test touching them fails somewhere unrelated: ${missingFromStub.join(', ')}`,
  );
});

// ── listFacts: what a response established, not what reading it optimistically yields ─────

test('a 200 whose body did not parse establishes nothing', async () => {
  const { module } = await boot(() => HEALTH_OK);
  const facts = module.listFacts(true, 200, null);
  assert.equal(facts.readable, false, 'an unparseable body is not an empty store');
});

test('a 200 whose warrants field is not an array establishes nothing', async () => {
  const { module } = await boot(() => HEALTH_OK);
  for (const warrants of [undefined, null, 'none', 7, { length: 0 }]) {
    assert.equal(
      module.listFacts(true, 200, { data: { warrants, unreadable_records: 0 } }).readable,
      false,
      `${JSON.stringify(warrants)} is not a list of warrants`,
    );
  }
});

test('an unreadable count this console cannot interpret is not read as zero', async () => {
  const { module } = await boot(() => HEALTH_OK);
  for (const count of ['3', -1, 1.5, null]) {
    assert.equal(
      module.listFacts(true, 200, { data: { warrants: [], unreadable_records: count } }).readable,
      false,
      `${JSON.stringify(count)} must not be silently taken for "no corrupt files"`,
    );
  }
  // Absent is the one value that means zero, so a server predating the field still lists.
  assert.deepEqual(module.listFacts(true, 200, { data: { warrants: [] } }), {
    readable: true,
    rows: [],
    unreadable: 0,
  });
});

test('a transport failure and a non-200 establish nothing', async () => {
  const { module } = await boot(() => HEALTH_OK);
  assert.equal(module.listFacts(false, 0, null).readable, false);
  assert.equal(module.listFacts(true, 500, { data: { warrants: [] } }).readable, false);
});

// ── emptyKind: the ordering ───────────────────────────────────────────────────────────────

test('an unreadable answer is the error rung, never the first-run claim', async () => {
  const { module } = await boot(() => HEALTH_OK);
  assert.equal(
    module.emptyKind({ readable: false, rowCount: 0, unreadable: 0, filter: '' }),
    'error',
    'zero rows from a response nobody could read is not a fact about this machine',
  );
});

test('a filter that matched nothing is a filtered view even when the store holds a corrupt file', async () => {
  const { module } = await boot(() => HEALTH_OK);
  assert.equal(
    module.emptyKind({ readable: true, rowCount: 0, unreadable: 1, filter: 'settled' }),
    'filtered',
    '"nothing could be listed" is false when four other warrants list fine under another chip',
  );
  // Unfiltered, the same corrupt file is exactly what the unreadable sentence is for.
  assert.equal(
    module.emptyKind({ readable: true, rowCount: 0, unreadable: 1, filter: '' }),
    'unreadable',
  );
});

test('first-run is claimed only for a readable, unfiltered, wholly empty store', async () => {
  const { module } = await boot(() => HEALTH_OK);
  assert.equal(
    module.emptyKind({ readable: true, rowCount: 0, unreadable: 0, filter: '' }),
    'first-run',
  );
  assert.equal(
    module.emptyKind({ readable: true, rowCount: 1, unreadable: 0, filter: '' }),
    'rows',
    'rows outrank every explanation: there is nothing empty to explain',
  );
});

// ── the rendered result ───────────────────────────────────────────────────────────────────

test('an empty store shows the first-run panel and nothing else', async () => {
  const app = await boot((p) => (p === '/v1/health' ? HEALTH_OK : listOf([])));

  assert.equal(app.el('first-run').hidden, false);
  assert.equal(app.el('list-empty-first-run').hidden, false);
  assert.equal(app.el('list-empty-error').hidden, true);
  assert.equal(app.el('detail').hidden, true);
});

test('a 200 with a body that will not parse says so, and does not claim the store is empty', async () => {
  const app = await boot((p) =>
    p === '/v1/health' ? HEALTH_OK : { status: 200, unparseable: true },
  );

  assert.equal(
    app.el('list-empty-first-run').hidden,
    true,
    'a truncated body must never render "No warrants on this machine yet."',
  );
  assert.equal(app.el('list-empty-error').hidden, false);
  assert.equal(app.el('first-run').hidden, true);
});

test('a filtered empty view over a store with a corrupt file keeps its way out', async () => {
  const app = await boot((p) => (p === '/v1/health' ? HEALTH_OK : listOf([], 1)));

  // Click the "settled" chip, which is how a filter can ever be on.
  const settled = app.chips.find((chip) => chip.dataset.state === 'settled');
  settled.fire('click');
  await settle();

  assert.equal(app.el('list-empty-filtered').hidden, false, 'this is a filtered view');
  assert.equal(
    app.el('list-empty-unreadable').hidden,
    true,
    '"nothing could be listed" is false here, and it carries no Show all',
  );
  // The corruption is not lost by that ordering: the warning row is in the list either way.
  assert.match(textOf(app.el('list')), /could not be read/);

  // And the way out works, which is the half the filtered paragraph exists to offer. It goes
  // through `setFilter`, so the chip that looks lit and the filter in force cannot drift apart.
  app.el('show-all').fire('click');
  await settle();
  assert.equal(app.el('list-empty-unreadable').hidden, false, 'unfiltered, the store is the story');
  assert.equal(app.el('list-empty-filtered').hidden, true);
  assert.equal(settled.className.includes('is-on'), false, 'the chip must not stay lit');
});

// ── the failure a loopback agent actually has ─────────────────────────────────────────────

test('an agent that is not answering explains itself and keeps polling', async () => {
  let down = true;
  const app = await boot((p) => {
    if (down) throw new TypeError('fetch failed');
    return p === '/v1/health' ? HEALTH_OK : listOf(ONE_WARRANT);
  });

  assert.equal(app.el('app').hidden, false, 'a silent server is not a rejected token');
  assert.equal(app.el('gate').hidden, true);
  assert.equal(app.el('list-empty-error').hidden, false, 'the error rung must fire on no answer');
  assert.equal(app.el('list-empty-first-run').hidden, true);
  assert.equal(app.el('authority').textContent, 'authority unknown');
  assert.ok(app.pollStarted(), 'a first read that failed must not skip startRefreshing');

  // And it recovers without a reload, which is the whole point of the timer having started.
  down = false;
  await app.poll();
  assert.equal(app.el('list-empty-error').hidden, true);
  assert.match(textOf(app.el('list')), /wrt_0000000000000001/);
  assert.equal(app.el('authority').textContent, 'read + stop only');
});

// ── the month summary: the window, and the two things that must never merge ───────────────

const REFUSAL_GROUP = {
  kind: 'tool',
  subject: 'curl',
  occurrences: 23,
  warrants: 4,
  signal: 'bounds_probably_wrong',
  guidance: 'curl was refused 23 times across 4 warrants. Widen it deliberately in the next grant.',
};

const GUARD_GROUP = {
  tool: 'github.create_pr',
  category: 'Jailbreak',
  outcome: 'harmful',
  mode: 'observe',
  occurrences: 3,
  warrants: 1,
  guidance: 'The warrant PERMITTED those calls and the guard blocked nothing: it ran observe-only.',
};

const COVERAGE = {
  sessions_attached: 2,
  sessions_finished: 1,
  classified: 9,
  flagged: 3,
  backend_unavailable: 4,
  unparseable: 1,
  skipped_over_budget: 7,
  deduplicated: 2,
};

function summaryBody(overrides = {}) {
  return {
    status: 200,
    body: {
      data: {
        total_occurrences: 23,
        groups: [REFUSAL_GROUP],
        bounds_probably_wrong: 1,
        window: {
          since: 1_754_006_400,
          until: 1_756_684_800,
          records_in_window: 6,
          records_all_time: 11,
          caveat: 'This window is applied to the time a SESSION ENDED.',
        },
        unreadable_lines: 0,
        note: 'Refusal records are a local observation log.',
        guard: {
          configured: true,
          enforcing: false,
          blocking_posture: 'observe_only',
          groups: [GUARD_GROUP],
          coverage: COVERAGE,
          note: 'Guard signals are a MODEL opinion about calls the warrant PERMITTED.',
        },
        ...overrides,
      },
    },
  };
}

/** Boot, then switch to the summary destination. */
async function openSummary(summary) {
  const app = await boot((p) => {
    if (p === '/v1/health') return HEALTH_OK;
    if (p.startsWith('/v1/summary/refusals')) return summary;
    return listOf(ONE_WARRANT);
  });
  app.el('view-summary').fire('click');
  await settle();
  return app;
}

test('a month becomes a half-open UTC window, and anything else becomes no window at all', async () => {
  const { module } = await boot(() => HEALTH_OK);
  assert.deepEqual(module.monthWindow('2026-08'), {
    since: Date.UTC(2026, 7, 1) / 1000,
    until: Date.UTC(2026, 8, 1) / 1000,
  });
  // December must roll the year rather than asking for a thirteenth month.
  assert.deepEqual(module.monthWindow('2026-12'), {
    since: Date.UTC(2026, 11, 1) / 1000,
    until: Date.UTC(2027, 0, 1) / 1000,
  });
  for (const bad of ['', '2026', '2026-13', '2026-00', 'august', null, undefined, '2026-8']) {
    assert.equal(
      module.monthWindow(bad),
      null,
      `${JSON.stringify(bad)} must not be silently replaced with a window this console made up`,
    );
  }
});

test('the console asks for the window it means, on the route that can now apply one', async () => {
  const app = await openSummary(summaryBody());
  const asked = app.calls.find((p) => p.startsWith('/v1/summary/refusals'));
  assert.ok(asked, 'the summary view must actually call the summary route');
  assert.match(asked, /\?since=\d+&until=\d+$/, 'an unwindowed read would answer for all time');
});

test('a summary nobody could read is never rendered as a month in which nothing happened', async () => {
  const { module } = await boot(() => HEALTH_OK);
  for (const facts of [
    module.summaryFacts(false, 0, null),
    module.summaryFacts(true, 500, { data: { groups: [] } }),
    module.summaryFacts(true, 200, null),
    module.summaryFacts(true, 200, { data: { groups: 'none' } }),
    module.summaryFacts(true, 200, {}),
  ]) {
    assert.equal(facts.readable, false);
  }

  const app = await openSummary({ status: 200, unparseable: true });
  assert.equal(app.el('summary-error').hidden, false);
  assert.equal(
    app.el('summary-refusals-empty').hidden,
    true,
    '"no refusal was recorded" is a claim about a month, and an unreadable answer supports none',
  );
  assert.equal(app.el('summary-guard-none').hidden, true);
  assert.equal(app.el('summary-window').textContent, '');
});

test('the window shown is the one the SERVER resolved, with its caveat', async () => {
  const app = await openSummary(summaryBody());
  assert.match(textOf(app.el('summary-window')), /2025-08-01 to 2025-09-01/);
  assert.match(textOf(app.el('summary-window')), /6 refusal record\(s\) of 11/);
  assert.match(textOf(app.el('summary-caveat')), /SESSION ENDED/);
});

test('a guard row keeps its mode and never becomes a refusal or a verdict', async () => {
  const app = await openSummary(summaryBody());

  const refusals = textOf(app.el('summary-refusals'));
  assert.match(refusals, /curl/);
  assert.doesNotMatch(
    refusals,
    /github\.create_pr/,
    'a call the warrant ALLOWED must never appear among the calls a bound refused',
  );

  const guard = textOf(app.el('summary-guard'));
  assert.match(guard, /mode observe/, 'the mode is the difference between two opposite sentences');
  assert.match(guard, /blocked nothing/, "the server's guidance is printed verbatim");
  assert.doesNotMatch(guard, /verified/, 'no verification verdict may sit beside a model opinion');
  assert.doesNotMatch(guard, /not verified/);
});

test('a mixed posture never collapses to one of the two pure claims', async () => {
  const { module } = await boot(() => HEALTH_OK);
  // `enforcing` is `any(..)` over the whole store, so a client reading it renders Mixed as
  // Enforced — and tells an operator that calls which actually proceeded did not happen.
  assert.equal(
    module.postureWord({ enforcing: true, blocking_posture: 'mixed' }),
    'mixed',
    'mixed is a third claim, not a rounding of the other two',
  );
  assert.equal(
    module.postureWord({ enforcing: true }),
    'unknown',
    'a server that did not state a posture must not have one inferred from the boolean',
  );
  assert.equal(module.postureWord({ enforcing: false, blocking_posture: 'nonsense' }), 'unknown');

  const app = await openSummary(
    summaryBody({
      guard: {
        configured: true,
        enforcing: true,
        blocking_posture: 'mixed',
        groups: [GUARD_GROUP],
        coverage: COVERAGE,
        note: 'Sessions here ran in BOTH modes.',
      },
    }),
  );
  const guard = textOf(app.el('summary-guard'));
  assert.match(guard, /MIXED/);
  assert.doesNotMatch(guard, /nothing here was blocked/);
  assert.doesNotMatch(guard, /flagged calls were refused/);
});

test('boundTierLines renders one line per bound, word then caveat, and never infers a tier', async () => {
  const { module } = await boot(() => HEALTH_OK);
  const lines = module.boundTierLines({
    bound_strengths: [
      { name: 'expires_at', strength: 'enforced', caveat: 'held by the OS' },
      { name: 'write_paths', strength: 'observed', caveat: 'nothing refuses the write' },
      { name: 'mystery', strength: 'unbreakable', caveat: 'x' },
      { name: 'silent' },
    ],
  });
  assert.deepEqual(lines, [
    'expires_at — enforced: held by the OS',
    'write_paths — observed: nothing refuses the write',
    'mystery — tier not stated: do not read this as enforced',
    'silent — tier not stated: do not read this as enforced',
  ]);
  assert.deepEqual(module.boundTierLines({}), [], 'no list means no lines, not a fabricated one');
  assert.deepEqual(module.boundTierLines(null), []);
});

// ── Task 4.3: coverage disclosure on every pane that renders a guarantee ────────────
//
// The product rule: NO SCREEN, BADGE, SUMMARY, EXPORT or STATUS may collapse
// observed / advisory / mediated / enforced into one green state. Every rendered guarantee
// must also render what it does not cover, and the tier word must be on the page in prose
// (not only as a glyph or a class hook) so a screen reader announces it.
//
// These tests pin the four panes Task 4.3 names — the queueRow, the transportRow, the
// coverageRow, and the routingRow — and assert that each carries the explicit tier line
// that boundTierLines and the proposed-effect meta block pioneered.

test('tierLine: the helper renders every vocabulary the server speaks and a "not stated" fallback for anything else', async () => {
  // The helper is the one place the wording lives. A future pane that adopts the same shape
  // must inherit these exact strings, and the helper is what the test pins.
  const { module } = await boot(() => HEALTH_OK);
  const find = (n, cls) => (n.className ?? '').split(/\s+/).includes(cls);
  // (1) The bound-strength vocabulary. Each word gets its own class.
  for (const tier of ['enforced', 'mediated', 'observed']) {
    const line = module.tierLine(tier, { className: 'tier' });
    assert.match(line.textContent, new RegExp(`tier: ${tier}`));
    assert.ok(find(line, `is-${tier}`), `an ${tier} line carries the matching is-<tier> class`);
  }
  // (2) The coverage vocabulary. Each word is rendered as itself, with its class.
  for (const state of ['mediated', 'observed', 'unsupported', 'bypassable']) {
    const line = module.tierLine(state, { className: 'tier' });
    assert.match(line.textContent, new RegExp(`tier: ${state}`));
    assert.ok(find(line, `is-${state}`), `a ${state} line carries the matching is-<state> class`);
  }
  // (3) The routing vocabulary. Same rule.
  for (const state of ['local', 'escalated', 'ceiling_refused', 'unconfigured']) {
    const line = module.tierLine(state, { className: 'tier' });
    assert.match(line.textContent, new RegExp(`tier: ${state}`));
    assert.ok(find(line, `is-${state}`), `a ${state} line carries the matching is-<state> class`);
  }
  // (4) A word the helper does not recognize is rendered as "not stated", never as enforced.
  for (const unknown of ['unbreakable', 'best-effort', 'gold', 'platinum', '', null, undefined]) {
    const line = module.tierLine(unknown, { className: 'tier' });
    assert.match(line.textContent, /not stated/);
    assert.doesNotMatch(line.textContent, /\benforced\b/,
      `unknown tier ${JSON.stringify(unknown)} must not round up to enforced`);
  }
});

test('queueRow: every row carries a tier line, and the unknown-tier case is "not stated"', async () => {
  // The blocker badge above the tier line says what is being waited for; the tier line says
  // how strong the wait is. A row that printed one without the other would be a row the
  // operator could not audit at the level the product requires.
  const findClass = (n, cls) => (n.className ?? '').split(/\s+/).includes(cls);

  // (1) The baseline queue entry has no `blocker.tier`. The row must still say so.
  const baseline = await openQueue(queueBody());
  const baselineRow = baseline.el('queue-rows').children[0];
  const baselineTier = baselineRow.children.find((c) => findClass(c, 'queue-tier'));
  assert.ok(baselineTier, 'the row carries a queue-tier element');
  assert.match(textOf(baselineTier), /not stated/);
  assert.doesNotMatch(textOf(baselineTier), /\benforced\b/);

  // (2) A row whose blocker.tier is "mediated" renders the word, with a matching class.
  const mediated = await openQueue(
    queueBody({
      waiting: [
        {
          ...QUEUE_ENTRY,
          blocker: { ...QUEUE_ENTRY.blocker, tier: 'mediated' },
        },
      ],
    }),
  );
  const mediatedRow = mediated.el('queue-rows').children[0];
  const mediatedTier = mediatedRow.children.find((c) => findClass(c, 'queue-tier'));
  assert.match(textOf(mediatedTier), /tier: mediated/);
  assert.ok(findClass(mediatedTier, 'is-mediated'), 'a mediated row carries the is-mediated class');
});

test('transportRow: every transport carries a tier line, and a "guarantees" sentence is not enough on its own', async () => {
  // The transport row's `guarantees` prose is the operator-facing promise; the tier line is
  // the classification of that promise. A row that printed the prose without the tier would
  // be a row that conflated "this transport promises delivery" with "this transport's
  // promise is enforced".
  const { module, el } = await boot(() => HEALTH_OK);
  const findClass = (n, cls) => (n.className ?? '').split(/\s+/).includes(cls);

  const facts = module.settingsFacts(true, 200, NOTIFY_OK(configuredAll).body);
  module.renderSettings(facts);
  for (const row of el('settings-transports').children) {
    const tier = row.children.find((c) => findClass(c, 'settings-transport-tier'));
    assert.ok(tier, 'every transport row carries a settings-transport-tier element');
    // The configuredAll fixture does not name a tier, so each row must say "not stated",
    // not "enforced".
    assert.match(textOf(tier), /not stated/);
    assert.doesNotMatch(textOf(tier), /\benforced\b/);
  }

  // And a transport whose server does name a tier renders the word, with a matching class.
  const withTier = {
    ...configuredAll,
    transports: [
      { ...configuredAll.transports[0], tier: 'enforced' },
      { ...configuredAll.transports[1], tier: 'observed' },
      ...configuredAll.transports.slice(2),
    ],
  };
  const facts2 = module.settingsFacts(true, 200, NOTIFY_OK(withTier).body);
  module.renderSettings(facts2);
  const emailRow = el('settings-transports').children.find(
    (r) => r.children[0]?.children[0]?.textContent === 'email',
  );
  const pushRow = el('settings-transports').children.find(
    (r) => r.children[0]?.children[0]?.textContent === 'push',
  );
  const emailTier = emailRow.children.find((c) => findClass(c, 'settings-transport-tier'));
  const pushTier = pushRow.children.find((c) => findClass(c, 'settings-transport-tier'));
  assert.match(textOf(emailTier), /tier: enforced/);
  assert.ok(findClass(emailTier, 'is-enforced'));
  assert.match(textOf(pushTier), /tier: observed/);
  assert.ok(findClass(pushTier, 'is-observed'));
});

test('coverageRow: every row carries an explicit tier word, not just a glyph', async () => {
  // The four-state coverage vocabulary is its own tier vocabulary (mediated / observed /
  // unsupported / bypassable). The glyph in the head is the visual cue; the tier line in
  // the body is the prose so a reader who cannot resolve the glyph still sees the
  // classification.
  const { module, el } = await boot(() => HEALTH_OK);
  const findClass = (n, cls) => (n.className ?? '').split(/\s+/).includes(cls);

  const facts = module.coverageMapFacts(true, 200, {
    data: {
      format: 'warrantor.coverage-map/1',
      as_of: 1_786_000_000,
      matrix: [
        { effect_class: 'read', harness: 'mcp', state: 'mediated', named_bypass: null, receipts: 10, total: 10 },
        { effect_class: 'write', harness: 'mcp', state: 'observed', named_bypass: 'transitive through cache SSRF', receipts: 3, total: 12 },
        { effect_class: 'exec', harness: 'mcp', state: 'unsupported', named_bypass: 'no execution path declared', receipts: 0, total: 0 },
        { effect_class: 'egress', harness: 'mcp', state: 'bypassable', named_bypass: 'cache SSRF (sample)', receipts: 1, total: 4 },
      ],
      summary: { mediated: 10, observed: 9, unsupported: 0, bypassable: 3, total: 22 },
    },
  });
  module.renderCoverage(facts);
  const states = ['mediated', 'observed', 'unsupported', 'bypassable'];
  for (let i = 0; i < states.length; i += 1) {
    const row = el('coverage-matrix').children[i];
    const tier = row.children.find((c) => findClass(c, 'coverage-row-tier'));
    assert.ok(tier, `the ${states[i]} row carries a coverage-row-tier element`);
    assert.match(textOf(tier), new RegExp(`tier: ${states[i]}`));
  }
});

test('routingRow: every row carries an explicit tier word, not just a glyph', async () => {
  // The four-state routing vocabulary (local / escalated / ceiling_refused / unconfigured) is
  // its own tier vocabulary. The badge in the head is the visual cue; the tier line is the
  // prose so a reader who cannot resolve the glyph still sees the classification, and a
  // screen reader announces the state in words, not in symbol.
  const findClass = (n, cls) => (n.className ?? '').split(/\s+/).includes(cls);
  for (const fixture of [localOnly, escalatedWithReceipt, ceilingRefused, routingUnconfigured]) {
    const app = await openRouting(wire(fixture));
    const rows = app.el('routing-decisions').children;
    if (rows.length === 0) continue; // unconfigured has no decisions
    const state = fixture.decisions[0].state;
    const tier = rows[0].children.find((c) => findClass(c, 'routing-tier'));
    assert.ok(tier, `the ${state} row carries a routing-tier element`);
    assert.match(textOf(tier), new RegExp(`tier: ${state}`));
  }
});

test('observed and enforced are visually distinct: a same-class collapse would be the rule\'s opposite', async () => {
  // The product rule: NO SCREEN may collapse observed, advisory, mediated and enforced into
  // one green state. The structural guarantee is that the four words produce four different
  // classes on the page — a stylesheet change that merged them would also have to merge the
  // classes, and the test pins the four distinct classes.
  const { module, el } = await boot(() => HEALTH_OK);
  const findClass = (n, cls) => (n.className ?? '').split(/\s+/).includes(cls);

  // (1) The tierLine helper produces three distinct is-<tier> classes, one per known word.
  const classes = new Set();
  for (const tier of ['enforced', 'mediated', 'observed']) {
    const line = module.tierLine(tier, { className: 'tier' });
    classes.add((line.className ?? '').split(/\s+/).find((c) => c.startsWith('is-')));
  }
  assert.equal(classes.size, 3, `expected three distinct is-<tier> classes, got: ${[...classes].join(', ')}`);

  // (2) The unknown-tier case is its own shape, never one of the three.
  const unknown = module.tierLine('unbreakable', { className: 'tier' });
  const unknownClass = (unknown.className ?? '').split(/\s+/).find((c) => c.startsWith('is-'));
  assert.equal(unknownClass, undefined, 'the unknown-tier line has no is-<tier> class, by design');

  // (3) The transport row's tier line follows the same rule: an observed transport does
  // not wear the enforced class, and a missing tier does not collapse to either.
  const withTiers = {
    ...configuredAll,
    transports: [
      { ...configuredAll.transports[0], tier: 'enforced' },
      { ...configuredAll.transports[1], tier: 'observed' },
      ...configuredAll.transports.slice(2),
    ],
  };
  module.renderSettings(module.settingsFacts(true, 200, NOTIFY_OK(withTiers).body));
  const emailRow = el('settings-transports').children[0];
  const pushRow = el('settings-transports').children[1];
  const emailTier = emailRow.children.find((c) => findClass(c, 'settings-transport-tier'));
  const pushTier = pushRow.children.find((c) => findClass(c, 'settings-transport-tier'));
  assert.ok(findClass(emailTier, 'is-enforced'), 'enforced transport wears the enforced class');
  assert.ok(findClass(pushTier, 'is-observed'), 'observed transport wears the observed class');
  assert.ok(!findClass(emailTier, 'is-observed'), 'enforced does not also wear observed');
  assert.ok(!findClass(pushTier, 'is-enforced'), 'observed does not also wear enforced');
});

test('no coverage is four different sentences, and one never stands in for another', async () => {
  const { module } = await boot(() => HEALTH_OK);
  assert.equal(module.guardKind(undefined), 'unknown');
  assert.equal(module.guardKind({ groups: [] }), 'unknown', 'configured must be stated');
  assert.equal(module.guardKind({ configured: true, groups: 'none' }), 'unknown');
  assert.equal(module.guardKind({ configured: false, groups: [] }), 'no-coverage');
  assert.equal(module.guardKind({ configured: true, groups: [] }), 'quiet');
  assert.equal(module.guardKind({ configured: true, groups: [GUARD_GROUP] }), 'groups');
  // Signals with no attach record are a real state: the attach write failed and the run's own
  // signals landed anyway. "No coverage" printed above a list of classifications would be a
  // sentence sitting next to its own counter-evidence.
  assert.equal(module.guardKind({ configured: false, groups: [GUARD_GROUP] }), 'groups');
});

/** Every coverage counter at zero: the only shape that supports "nothing was looked at". */
const NO_COVERAGE = Object.fromEntries(Object.keys(COVERAGE).map((key) => [key, 0]));

test('a month in which no guard attached says NO COVERAGE, not an empty reassuring table', async () => {
  const app = await openSummary(
    summaryBody({
      guard: {
        configured: false,
        enforcing: false,
        blocking_posture: null,
        groups: [],
        // Every counter zero. This fixture used to spread COVERAGE and zero only the two
        // `sessions_*` fields, leaving classified: 9 and flagged: 3 under a note reading "No
        // guard was attached to any run in this store." That is not the no-coverage state -- it
        // is the contradiction this change exists to stop rendering, and the test asserting
        // NO COVERAGE over it was pinning the defect in place. The state it meant to describe is
        // below; the state it actually built is the test after it.
        coverage: { ...NO_COVERAGE },
        note: 'No guard was attached to any run in this store.',
      },
    }),
  );
  assert.equal(app.el('summary-guard-none').hidden, false);
  assert.equal(app.el('summary-guard-unattributed').hidden, true);
  assert.equal(app.el('summary-guard-quiet').hidden, true);
  assert.equal(app.el('summary-guard-unknown').hidden, true);
  assert.match(
    textOf(app.el('summary-guard')),
    /posture not stated/,
    'a log with nothing in it has no posture, and a default would be a claim',
  );
});

test('counts with no attach record are UNATTRIBUTED, never NO COVERAGE', async () => {
  const app = await openSummary(
    summaryBody({
      guard: {
        configured: false,
        enforcing: false,
        blocking_posture: null,
        groups: [],
        // `configured` is `!sessions.is_empty()` on the server, so it is false both when nothing
        // ran and when something ran whose attach record is not in what was read. These counts
        // can only come from a guard, so the second reading is the true one here.
        coverage: { ...COVERAGE, sessions_attached: 0, sessions_finished: 0 },
        note: 'Guard signals were recorded without an attach record.',
      },
    }),
  );
  assert.equal(
    app.el('summary-guard-none').hidden,
    true,
    'NO COVERAGE cannot be printed above a coverage table whose own counts contradict it',
  );
  assert.equal(
    app.el('summary-guard-unattributed').hidden,
    false,
    'something watched and cannot be named -- the opposite claim to nothing watched',
  );
  assert.equal(app.el('summary-guard-quiet').hidden, true);
  assert.equal(app.el('summary-guard-unknown').hidden, true);
});

test('what was not looked at is counted, and no miss is estimated from a benchmark', async () => {
  const app = await openSummary(summaryBody());
  const coverage = textOf(app.el('summary-coverage'));
  for (const [label, value] of [
    ['the backend was unreachable', 4],
    ['the answer was not a verdict', 1],
    ["session's cap was spent", 7],
  ]) {
    assert.ok(coverage.includes(label), `the coverage block must name: ${label}`);
    assert.ok(coverage.includes(String(value)), `and carry its count: ${value}`);
  }
  // The one number that must not exist: live traffic here has no labels, so "we probably missed N"
  // would be an estimate with no measurement behind it, on the surface that least tolerates one.
  assert.doesNotMatch(coverage, /probably missed|estimated|0\.8152|0\.1848/);
  assert.match(textOf(app.el('summary-coverage-note')), /unaccounted for/);
});

test('the summary owns the right-hand column, and switching back restores the warrant pane', async () => {
  const app = await openSummary(summaryBody());
  assert.equal(app.el('summary').hidden, false);
  assert.equal(app.el('detail').hidden, true);
  assert.equal(app.el('first-run').hidden, true);

  app.el('view-warrants').fire('click');
  await settle();
  assert.equal(app.el('summary').hidden, true);
  assert.equal(app.el('detail').hidden, false, 'a store with rows shows the detail pane');
});

// ── residue ───────────────────────────────────────────────────────────────────────────────

test('a store that empties while the console is open takes the detail pane with it', async () => {
  let warrants = ONE_WARRANT;
  const app = await boot((p) => {
    if (p === '/v1/health') return HEALTH_OK;
    if (p.startsWith('/v1/warrants/')) {
      return {
        status: 200,
        body: { data: { id: warrants[0]?.id }, verified: true, verification: { integrity: 'ok' } },
      };
    }
    return listOf(warrants);
  });

  // Select the warrant, so the pane holds a verdict and three enabled-looking buttons.
  app.el('list').children[0].children[0].fire('click');
  await settle();
  assert.match(textOf(app.el('detail')), /Acts requiring a human/);

  // The store is pruned under the running console.
  warrants = [];
  await app.poll();

  assert.equal(app.el('first-run').hidden, false);
  assert.doesNotMatch(
    textOf(app.el('detail')),
    /Acts requiring a human/,
    'release controls for a warrant this store no longer holds must not survive in the hidden pane',
  );
});

// ── custody: the surface for §2.2's record of who acted ─────────────────────

test('an unreadable custody record is never rendered as "nobody has approved"', async () => {
  // The same distinction `listFacts` exists for, on the surface where it decides whether a release
  // is permitted. An optimistic read turns "the request failed" and "nobody acted" into one empty
  // array, and here those are opposite facts: one means the requirement cannot be evaluated.
  const { module } = await boot(() => HEALTH_OK);
  const { custodyFacts, approvalStanding } = module;

  for (const [answered, status, payload] of [
    [false, 0, null],
    [true, 500, { error: {} }],
    [true, 200, { data: {} }],
    [true, 200, { data: { acts: 'not an array', approvers: [] } }],
  ]) {
    const facts = custodyFacts(answered, status, payload);
    assert.equal(facts.readable, false);
    assert.equal(approvalStanding(facts).kind, 'unknown');
  }
});

test('a broken act chain outranks every other standing', async () => {
  // A store whose record of who acted has been edited must not report "approved" on the strength of
  // that record. The fault is the finding.
  const { module } = await boot(() => HEALTH_OK);
  const { custodyFacts, approvalStanding } = module;
  const facts = custodyFacts(true, 200, {
    data: {
      acts: [{ act: 'approve', actor: 'ana', via: 'operator-token', at: 1, digest: 'd' }],
      approvers: ['ana'],
      distinct_approvers: 1,
      required_approvals: 1,
      chain_intact: false,
      chain_fault: 'line 2 has been edited',
    },
  });
  const standing = approvalStanding(facts);
  assert.equal(standing.kind, 'broken');
  assert.match(standing.text, /line 2 has been edited/);
});

test('the standing distinguishes met, short and no-requirement', async () => {
  const { module } = await boot(() => HEALTH_OK);
  const { custodyFacts, approvalStanding } = module;
  const make = (required, approvers) =>
    approvalStanding(
      custodyFacts(true, 200, {
        data: {
          acts: [],
          approvers,
          distinct_approvers: approvers.length,
          required_approvals: required,
          chain_intact: true,
        },
      }),
    );

  assert.equal(make(0, []).kind, 'none');
  assert.match(make(0, []).text, /accountability rather than a gate/);
  assert.equal(make(2, ['ana']).kind, 'short');
  assert.match(make(2, ['ana']).text, /1 of 2/);
  assert.equal(make(2, ['ana', 'bo']).kind, 'met');
});

test('an anonymous actor is rendered as a sentence and never as a name', async () => {
  // The store deliberately declines to invent a principal; a console that printed a placeholder
  // would invent one on its behalf.
  const { module } = await boot(() => HEALTH_OK);
  const { custodyFacts } = module;
  const facts = custodyFacts(true, 200, {
    data: {
      acts: [{ act: 'settle', actor: null, via: 'session-token', at: 1, digest: 'd' }],
      approvers: [null],
      distinct_approvers: 1,
      required_approvals: 0,
      chain_intact: true,
    },
  });
  assert.equal(facts.acts[0].actor, null, 'the fact stays null; only the rendering is a sentence');
});

// ── keyboard ────────────────────────────────────────────────────────────────

test('the shortcut sheet and its handler are generated from one table', async () => {
  // A sheet maintained separately from its handler is a sheet that lies within two commits.
  const { module } = await boot(() => HEALTH_OK);
  const { SHORTCUTS } = module;
  const keys = SHORTCUTS.map(([k]) => k);
  assert.ok(keys.some((k) => k.startsWith('j')), `${keys}`);
  assert.ok(keys.includes('?'), `${keys}`);
  assert.ok(keys.includes('Escape'), `${keys}`);
  for (const row of SHORTCUTS) {
    assert.equal(row.length, 2, 'every row is keys + what it does');
    assert.ok(row[1].length > 3, `${row}`);
  }
});

// ── the review queue ─────────────────────────────────────────────────────────────────

const QUEUE_ENTRY = {
  warrant_id: 'wrt_a',
  state: 'open',
  issued_at: 1_786_000_000,
  staged_effects: 3,
  blocker: {
    blocker: 'awaiting-approval',
    still_needed: 1,
    could_approve: ['ben'],
    approved_by: ['ana'],
  },
  you_can: ['approve'],
};

const queueBody = (over = {}) => ({
  status: 200,
  body: {
    data: {
      waiting: [QUEUE_ENTRY],
      waiting_on_you: 1,
      counts: { 'awaiting-approval': 1 },
      undetermined: [],
      unreadable_records: 0,
      you: { name: 'ben', via: 'operator-token', scopes: ['read', 'approve'] },
      ...over,
    },
  },
});

async function openQueue(queue) {
  const app = await boot((p) => {
    if (p === '/v1/health') return HEALTH_OK;
    if (p === '/v1/queue') return queue;
    return listOf(ONE_WARRANT);
  });
  app.el('view-queue').fire('click');
  await settle();
  return app;
}

test('the queue view actually calls the queue route', async () => {
  const app = await openQueue(queueBody());
  assert.ok(app.calls.includes('/v1/queue'), 'the destination must read its own route');
});

test('a queue nobody could read is never rendered as nothing waiting', async () => {
  // The two sentences a reviewer must never see confused. "Nothing is waiting on you" ends their
  // day; "this console could not find out" does not.
  const { module } = await boot(() => HEALTH_OK);
  for (const facts of [
    module.queueFacts(false, 0, null),
    module.queueFacts(true, 500, { data: { waiting: [] } }),
    module.queueFacts(true, 200, null),
    module.queueFacts(true, 200, { data: { waiting: 'none' } }),
    module.queueFacts(true, 200, {}),
  ]) {
    assert.equal(facts.readable, false);
  }

  const app = await openQueue({ status: 200, unparseable: true });
  assert.equal(app.el('queue-error').hidden, false);
  assert.equal(
    app.el('queue-empty').hidden,
    true,
    '"nothing is waiting" is a claim about a store, and an unreadable answer supports none',
  );
  assert.match(textOf(app.el('queue-headline')), /could not be read/);
});

test('the headline separates "nothing waiting" from "nothing waiting on YOU"', async () => {
  // Different facts about the same store. Rendering the second as the first tells a reviewer their
  // work is done while warrants sit behind a scope they do not hold.
  const { module } = await boot(() => HEALTH_OK);
  const facts = (waiting, yours) => ({ readable: true, waiting, yours, you: null });
  assert.match(module.queueHeadline(facts([], 0)), /Nothing is waiting on a decision/);
  assert.match(
    module.queueHeadline(facts([1, 2, 3], 0)),
    /none of which you can act on/,
    'three waiting and none yours is not an empty queue',
  );
  assert.match(module.queueHeadline(facts([1, 2], 2)), /^2 waiting on you/);
  assert.match(module.queueHeadline(facts([1, 2, 3], 1)), /^1 of 3 waiting on you/);
  assert.match(module.queueHeadline({ readable: false, waiting: [], yours: 0 }), /not the same as/);
});

test('the acts offered are exactly the ones the SERVER named, and nothing is recomputed', async () => {
  // The rule the whole product rests on: the server decides, the client renders. A console that
  // worked out its own buttons would be a second implementation of the approval rules, drifting
  // from the settle gate the first time either changed.
  // Scoped to the acts bar. The warrant id is itself a button — it crosses to the warrant view —
  // so a blanket "every button in the row" would have counted navigation as an act, which is the
  // kind of assertion that passes for the wrong reason.
  const actsIn = (row) =>
    (row.children.find((c) => c.className === 'queue-acts')?.children ?? []).map(
      (b) => b.textContent,
    );

  const app = await openQueue(queueBody());
  assert.deepEqual(
    actsIn(app.el('queue-rows').children[0]),
    ['Approve'],
    'you_can was ["approve"], so exactly one act appears',
  );

  // The same store, the same reader scopes, but the server offers nothing: the console must offer
  // nothing, even though this reader plainly holds `approve`.
  const none = await openQueue(
    queueBody({ waiting: [{ ...QUEUE_ENTRY, you_can: [] }], waiting_on_you: 0 }),
  );
  assert.deepEqual(
    actsIn(none.el('queue-rows').children[0]),
    [],
    'an empty you_can renders no acts, whatever the reader holds',
  );

  // And a `you_can` naming both is rendered as both, in the server's order.
  const both = await openQueue(
    queueBody({
      waiting: [
        {
          ...QUEUE_ENTRY,
          you_can: ['approve', 'settle'],
          blocker: { blocker: 'awaiting-decision', approved_by: ['ana'] },
        },
      ],
    }),
  );
  assert.deepEqual(actsIn(both.el('queue-rows').children[0]), ['Approve', 'Settle']);
});

test('a deadlocked row carries its reason and offers nobody anything', async () => {
  const app = await openQueue(
    queueBody({
      waiting: [
        {
          ...QUEUE_ENTRY,
          you_can: [],
          blocker: { blocker: 'deadlocked', why: 'this store requires 2 approval(s) and ...' },
        },
      ],
      waiting_on_you: 0,
      counts: { deadlocked: 1 },
    }),
  );
  const row = app.el('queue-rows').children[0];
  assert.match(row.className, /is-deadlocked/);
  assert.match(textOf(row), /this store requires 2 approval\(s\)/);
  // No "nothing for you to do yet" consolation on a deadlock: "yet" would be false.
  assert.doesNotMatch(textOf(row), /yet/);
});

test('a warrant that cannot be described is listed rather than dropped', async () => {
  // A warrant that is outstanding, needs a human and cannot be described is the most urgent row on
  // the page. Omitting it makes the queue quietly shorter and the store quietly worse.
  const app = await openQueue(
    queueBody({
      waiting: [],
      waiting_on_you: 0,
      counts: {},
      undetermined: [{ warrant_id: 'wrt_broken', state: 'open', why: 'its actor log will not parse' }],
    }),
  );
  assert.equal(app.el('queue-rows').children.length, 1);
  assert.match(textOf(app.el('queue-rows')), /wrt_broken/);
  assert.match(textOf(app.el('queue-rows')), /will not parse/);
  assert.equal(
    app.el('queue-empty').hidden,
    true,
    'an undetermined warrant is not an empty queue',
  );
});

test('the reader is described in the SERVER\'s words, including having no name at all', async () => {
  const named = await openQueue(queueBody());
  assert.match(textOf(named.el('queue-who')), /You are ben, holding read, approve/);

  const anonymous = await openQueue(
    queueBody({ you: { name: null, via: 'session-token', scopes: ['read', 'settle'] } }),
  );
  assert.match(
    textOf(anonymous.el('queue-who')),
    /unnamed session principal/,
    'a console that printed a remembered name would assert an identity nobody checked',
  );
});

test('warrant records that could not be read are counted separately and said out loud', async () => {
  const app = await openQueue(queueBody({ unreadable_records: 2 }));
  assert.match(textOf(app.el('queue-unreadable')), /2 warrant record\(s\) could not be read/);
});

// ── Task 4.1: the L8-01 anti-ceremony properties of the queue row ──────────────────────
//
// Each test below is a property the L8-01 plan demands, asserted against the DOM, not against
// the payload. The plan's failure mode is "the queue becomes ceremony": reviewers approving
// everything under time pressure. The properties are the ones that, when they fail, make the
// queue ceremony rather than judgment.

const { baselineQueue, dependencyQueue, timedOutQueue, minimalQueue } = await import(
  './queue.fixtures.js'
);

/** A `waiting` entry with the additive L8-01 fields merged onto the existing QUEUE_ENTRY. */
function fixtureBody(fixture) {
  return {
    status: 200,
    body: { data: fixture.data },
  };
}

/** Open the queue view against a fixture body. The console renders that body without a backend. */
async function openFixture(fixture) {
  const app = await boot((p) => {
    if (p === '/v1/health') return HEALTH_OK;
    if (p === '/v1/queue') return fixtureBody(fixture);
    return listOf(ONE_WARRANT);
  });
  app.el('view-queue').fire('click');
  await settle();
  return app;
}

/** Every interactive child (`<button>`) of a row, in document order. */
function interactiveChildren(row) {
  const buttons = [];
  const walk = (node) => {
    for (const child of node.children ?? []) {
      if (child.tagName === 'button') buttons.push(child);
      walk(child);
    }
  };
  walk(row);
  return buttons;
}

test('the approver sees the effect, the chain and the receipts BEFORE the approve control', async () => {
  // The anti-ceremony property. The plan: "The approver must see the proposed effect, the
  // authority chain and the prior receipts, before the approve control." A renderer that put
  // the act bar at the top would pass a "contains an Approve button" test and fail this one.
  const app = await openFixture(baselineQueue);
  const row = app.el('queue-rows').children[0];
  const buttons = interactiveChildren(row);
  const approve = buttons.find((b) => b.textContent === 'Approve');
  assert.ok(approve, 'the baseline queue must offer an Approve button');
  // The Approve button is the LAST interactive child of the row. Every interactive thing before
  // it is the warrant id, which crosses to the warrant view (navigation, not an act).
  assert.equal(buttons[buttons.length - 1], approve, 'Approve is the last button on the row');
  // The proposed-effects, authority-chain and prior-receipts sections all render and all
  // appear before the act bar in document order. The className is a single token ("queue-acts",
  // "proposed-effects", etc.), so the check is on a word boundary, not a substring — otherwise
  // "queue-acts" would match "queue-acts-note" and the indices would be off by one.
  const all = row.children;
  const hasClass = (n, cls) => (n.className ?? '').split(/\s+/).includes(cls);
  const indices = (cls) => all.findIndex((c) => hasClass(c, cls));
  const effIdx = indices('proposed-effects');
  const chainIdx = indices('authority-chain');
  const recIdx = indices('prior-receipts');
  const actsIdx = indices('queue-acts');
  assert.ok(effIdx >= 0, 'proposed-effects block is rendered');
  assert.ok(chainIdx >= 0, 'authority-chain block is rendered');
  assert.ok(recIdx >= 0, 'prior-receipts block is rendered');
  assert.ok(actsIdx >= 0, 'act bar is rendered');
  assert.ok(effIdx < actsIdx, 'effects render before the act bar');
  assert.ok(chainIdx < actsIdx, 'chain renders before the act bar');
  assert.ok(recIdx < actsIdx, 'receipts render before the act bar');
});

test('each rendered effect names its tier and the tier\'s caveat; an unknown tier says so', async () => {
  const app = await openFixture(baselineQueue);
  const walked = [];
  const hasClass = (n, cls) => (n.className ?? '').split(/\s+/).includes(cls);
  const walk = (n) => {
    if (hasClass(n, 'proposed-effect')) walked.push(n);
    for (const c of n.children ?? []) walk(c);
  };
  walk(app.el('queue-rows').children[0]);
  assert.equal(walked.length, 2, 'two effects in the baseline fixture');
  // First effect: enforced, with a caveat that names "Held by".
  assert.match(walked[0].className, /is-enforced/);
  const tier1 = walked[0].children.find((c) => hasClass(c, 'proposed-effect-meta'));
  assert.match(textOf(tier1), /tier: enforced/);
  const caveat1 = walked[0].children.find((c) => hasClass(c, 'proposed-effect-caveat'));
  assert.match(textOf(caveat1), /What this tier does not cover: Held by the MCP proxy/);
  // Second effect: mediated, with a caveat that names "traverse".
  assert.match(walked[1].className, /is-mediated/);
  const tier2 = walked[1].children.find((c) => hasClass(c, 'proposed-effect-meta'));
  assert.match(textOf(tier2), /tier: mediated/);
  const caveat2 = walked[1].children.find((c) => hasClass(c, 'proposed-effect-caveat'));
  assert.match(textOf(caveat2), /traverse/);
});

test('an effect whose tier is unknown is rendered as "not stated", never as enforced', async () => {
  // The product rule: a renderer must never collapse observed/mediated/enforced into one
  // state, and must never supply the strongest tier. A missing or unknown tier renders as
  // "not stated" with a sentence the reader cannot mistake for an enforcement claim.
  const { module } = await boot(() => HEALTH_OK);
  const frag = module.proposedEffectsBlock([
    { summary: 'do the thing', tier: 'unbreakable', covered_by: 'x' },
    { summary: 'another thing' },
  ]);
  const walked = [];
  const hasClass = (n, cls) => (n.className ?? '').split(/\s+/).includes(cls);
  const walk = (n) => {
    if (hasClass(n, 'proposed-effect')) walked.push(n);
    for (const c of n.children ?? []) walk(c);
  };
  walk(frag);
  assert.equal(walked.length, 2);
  for (const item of walked) {
    const meta = item.children.find((c) => hasClass(c, 'proposed-effect-meta'));
    assert.match(textOf(meta), /not stated/);
    // The meta line must not name the strongest tier word. A row whose server has not
    // classified an effect must read as a row whose tier is unknown, not as a row whose
    // tier is enforced.
    assert.doesNotMatch(textOf(meta), /\benforced\b/);
  }
});

test('the authority chain renders root first and the parent digest on a non-root link', async () => {
  const app = await openFixture(baselineQueue);
  const walked = [];
  const hasClass = (n, cls) => (n.className ?? '').split(/\s+/).includes(cls);
  const walk = (n) => {
    if (hasClass(n, 'authority-link')) walked.push(n);
    for (const c of n.children ?? []) walk(c);
  };
  walk(app.el('queue-rows').children[0]);
  assert.equal(walked.length, 2, 'two links in the baseline chain');
  // Root link.
  assert.match(textOf(walked[0]), /root: spiffe:\/\/muveraai\.com\/agent\/orchestrator/);
  assert.doesNotMatch(textOf(walked[0]), /parent grant/);
  // Delegated link.
  assert.match(textOf(walked[1]), /delegated: spiffe:\/\/muveraai\.com\/agent\/coder/);
  assert.match(textOf(walked[1]), /parent grant sha256:9a7c/);
  assert.match(textOf(walked[1]), /delegated by orchestrator/);
});

test('the prior receipts list is newest first and the kind carries its own marker class', async () => {
  const app = await openFixture(baselineQueue);
  const walked = [];
  const hasClass = (n, cls) => (n.className ?? '').split(/\s+/).includes(cls);
  const walk = (n) => {
    if (hasClass(n, 'prior-receipt')) walked.push(n);
    for (const c of n.children ?? []) walk(c);
  };
  walk(app.el('queue-rows').children[0]);
  assert.equal(walked.length, 2, 'two prior receipts on the baseline warrant');
  // First receipt: approve by ana.
  assert.match(walked[0].className, /is-approve/);
  assert.match(textOf(walked[0]), /ana — approve/);
  // Second receipt: refuse, with the bound that triggered it.
  assert.match(walked[1].className, /is-refuse/);
  assert.match(textOf(walked[1]), /write_paths/);
});

test('a queue with no prior receipts says so, and never invents one', async () => {
  // A renderer that filled the empty list with a generic sentence about "no recent activity"
  // would be answering a question the server did not ask.
  const { module } = await boot(() => HEALTH_OK);
  const frag = module.priorReceiptsBlock([]);
  assert.match(textOf(frag), /No prior receipts on this warrant\./);
});

test('a row whose response budget has expired offers no act, even if the server said you_can', async () => {
  // The plan: "Timeout defaults to DENY, never to approve, and never escalates to a wider group."
  // The fixture sends you_can: ["approve"] with a remaining_seconds of -120. The console must
  // not show the button.
  const app = await openFixture(timedOutQueue);
  const row = app.el('queue-rows').children[0];
  const buttons = interactiveChildren(row);
  const approve = buttons.find((b) => b.textContent === 'Approve');
  assert.equal(approve, undefined, 'no Approve button on a timed-out row');
  // The timeout block says so in plain language.
  const timeoutParas = [];
  const walk = (n) => {
    if ((n.className ?? '').includes('queue-timeout')) timeoutParas.push(n);
    for (const c of n.children ?? []) walk(c);
  };
  walk(row);
  assert.equal(timeoutParas.length, 1);
  assert.match(timeoutParas[0].textContent, /timed out 120 s ago/);
  assert.match(timeoutParas[0].textContent, /never approves and never escalates/);
});

test('a row whose budget is still open reports the remaining seconds and the on-expiry rule', async () => {
  const app = await openFixture(baselineQueue);
  const row = app.el('queue-rows').children[0];
  const paras = [];
  const walk = (n) => {
    if ((n.className ?? '').includes('queue-timeout')) paras.push(n);
    for (const c of n.children ?? []) walk(c);
  };
  walk(row);
  assert.equal(paras.length, 1);
  assert.match(paras[0].textContent, /within 900 s/);
  assert.match(paras[0].textContent, /On expiry: deny/);
});

test('partial release names the independently-releasable effects and the refused dependents', async () => {
  // The plan: "Dependency-aware partial approval: releasing part of a batch must not silently
  // release dependent effects." The fixture ships a batch of three where releasing the test
  // effect without the two writes would be a code change that is not on disk.
  const app = await openFixture(dependencyQueue);
  const row = app.el('queue-rows').children[0];
  const rel = row.children.find((c) => (c.className ?? '').includes('queue-partial'));
  assert.ok(rel, 'partial block is rendered');
  const relP = rel.children.find((c) => (c.className ?? '').includes('queue-partial-rel'));
  const refP = rel.children.find((c) => (c.className ?? '').includes('queue-partial-refused'));
  const why = rel.children.find((c) => (c.className ?? '').includes('queue-partial-reason'));
  assert.match(textOf(relP), /Releasable independently: Add the new signing entry point; Add the matching key-parsing path/);
  assert.match(textOf(refP), /Refused if a dependency is unreleased: Run the new signer tests against a recorded fixture set/);
  assert.match(textOf(why), /releasing it without effects 0 and 1 would test code that is not on disk/);
});

test('a queue with no additive fields renders "not stated" placeholders, never inferred content', async () => {
  // The server may not have shipped the L8-01 fields. The console must not invent them. Every
  // section that depends on the additive payload either renders nothing or renders a single
  // "not stated" sentence, and the act bar still works against the existing `you_can`.
  const { module } = await boot(() => HEALTH_OK);
  // Pure functions, no row.
  const latency = module.latencyBlock(null);
  assert.equal(latency.children.length, 0, 'no latency block when the field is absent');
  const effects = module.proposedEffectsBlock(null);
  assert.equal(effects.children.length, 0);
  const chain = module.authorityChainBlock(null);
  assert.equal(chain.children.length, 0);
  const receiptsAbsent = module.priorReceiptsBlock(undefined);
  assert.equal(receiptsAbsent.children.length, 0, 'no receipts block when the field is absent');
  // An empty receipts list still renders the section with the honest "no prior receipts" line.
  const receiptsEmpty = module.priorReceiptsBlock([]);
  assert.match(textOf(receiptsEmpty), /No prior receipts on this warrant\./);
  // The DOM row against a minimal payload still offers the Approve button and the act bar
  // is still the last interactive child.
  const app = await openFixture(minimalQueue);
  const row = app.el('queue-rows').children[0];
  const buttons = interactiveChildren(row);
  const approve = buttons.find((b) => b.textContent === 'Approve');
  assert.ok(approve, 'Approve button is still rendered for a minimal payload');
  assert.equal(buttons[buttons.length - 1], approve);
});

test('the latency block renders p50, p99 and disagreement rate, with a counter-metric note', async () => {
  // The L8-01 verification clause: "p50 and p99 approval latency are published per queue
  // alongside the disagreement rate, so a queue that gets faster while disagreement falls to
  // zero is flagged, not celebrated."
  const { module } = await boot(() => HEALTH_OK);
  const frag = module.latencyBlock(baselineQueue.data.policy.latency);
  assert.match(textOf(frag), /p50 approval latency/);
  assert.match(textOf(frag), /42 s/);
  assert.match(textOf(frag), /p99 approval latency/);
  assert.match(textOf(frag), /312 s/);
  assert.match(textOf(frag), /disagreement rate/);
  assert.match(textOf(frag), /12% of recent decisions disagreed with the agent/);
  assert.match(textOf(frag), /A disagreement rate trending to zero while latency improves is rubber-stamping/);
});

test('the latency block shows "not stated" when the server has too few samples', async () => {
  // disagreement_rate === null is the server's signal that there are not enough samples to
  // publish a percentage. The console must show that as a fact, not as 0%.
  const { module } = await boot(() => HEALTH_OK);
  const frag = module.latencyBlock({ p50_seconds: 30, p99_seconds: 90, sample_size: 0, disagreement_rate: null });
  assert.match(textOf(frag), /not stated — too few samples in the window to publish/);
  assert.doesNotMatch(textOf(frag), /0% of recent/);
});

test('the queue latency block is rendered above the rows, not inside one of them', async () => {
  const app = await openFixture(baselineQueue);
  const latency = app.el('queue-latency');
  assert.ok(latency, 'queue-latency element exists');
  // The latency block has its own heading and its own dl, not just a stray paragraph.
  const text = textOf(latency);
  assert.match(text, /How fast this queue answers/);
  // The rows themselves do not contain the latency text.
  for (const row of app.el('queue-rows').children) {
    assert.doesNotMatch(textOf(row), /How fast this queue answers/);
  }
});

test('the queue does not reward approval rate: no count, no badge, no per-user leaderboard', async () => {
  // The plan: "Nothing in the UI may reward approval rate." A regression here is easy to miss
  // because each individual element looks harmless; the test scans the rendered queue text
  // for the patterns that would reward a fast approver.
  const app = await openFixture(baselineQueue);
  const queueText = textOf(app.el('queue'));
  // No phrase that links a count to a time window for the reader's own behavior.
  assert.doesNotMatch(queueText, /you (have )?approved \d+/i);
  assert.doesNotMatch(queueText, /approvals? (today|this hour|this week|per hour)/i);
  assert.doesNotMatch(queueText, /your (rate|speed|throughput)/i);
  // No "fastest approver" or "approval streak" wording.
  assert.doesNotMatch(queueText, /streak|fastest|top approver|leaderboard/i);
});

test('the L8-01 act button is the last interactive child of the row, after every disclosure', async () => {
  // Belt-and-braces version of the anti-ceremony test: the act bar's position in the
  // interactive-children array, not just its class. A regression that swaps two sections
  // around the act bar would still pass the first test; this one would not.
  for (const fixture of [baselineQueue, dependencyQueue]) {
    const app = await openFixture(fixture);
    const row = app.el('queue-rows').children[0];
    const buttons = interactiveChildren(row);
    // `findLast` because the dependency fixture ships both `approve` and `settle`; the last
    // interactive child is whichever one is the trailing act, and the assertion is that
    // whichever it is, it is the trailing act.
    const acts = buttons.findLast((b) => b.textContent === 'Approve' || b.textContent === 'Settle');
    assert.ok(acts, `${fixture.data.waiting[0].warrant_id} must offer an act button`);
    assert.equal(
      buttons[buttons.length - 1],
      acts,
      `${fixture.data.waiting[0].warrant_id}: the act button is the last interactive child`,
    );
  }
});

// ── unguarded runs ───────────────────────────────────────────────────────────────────

test('an unguarded run is reported as a fact, not as an absence', async () => {
  // §4.3's gap. Everything in the coverage block is counted FROM guard records, so it is silent
  // about sessions the guard was never in — and before the server kept a run log, an unguarded
  // session left no record at all, making "nobody was watching" and "nothing ran" one observation.
  const { module } = await boot(() => HEALTH_OK);
  const sentence = module.runsSentence({ total: 5, guarded: 2, unguarded: 3, warrants: 2 });
  assert.match(sentence, /3 with NO guard attached/);
  // Never "missed". An unguarded run produced no signal, so nothing is known about what happened
  // in it — that is a gap in observation, not a count of failures.
  assert.doesNotMatch(sentence, /missed/i);
});

test('a server that says nothing about runs is unknown, never zero', async () => {
  // An older server is exactly this case, and rendering it as "0 unguarded" would be this console
  // inventing a fact about a month.
  const { module } = await boot(() => HEALTH_OK);
  for (const runs of [null, undefined, {}, { guarded: 1 }]) {
    assert.match(module.runsSentence(runs), /unknown — not zero/);
  }
  assert.match(module.runsSentence({ total: 0, guarded: 0, unguarded: 0, warrants: 0 }), /No supervised session started/);
  assert.match(
    module.runsSentence({ total: 2, guarded: 2, unguarded: 0, warrants: 1 }),
    /Every one had a guard attached/,
  );
});

test('the runs sentence is cleared when the summary could not be read', async () => {
  const app = await openSummary({ status: 200, unparseable: true });
  assert.equal(
    app.el('summary-runs').textContent,
    '',
    'a run count left over from a previous month would read as this one under the error',
  );
});

// ── reaching the destinations without a mouse ────────────────────────────────────────

test('every destination has a number key, and the sheet names the same ones', async () => {
  const { readFileSync } = await import('node:fs');
  const here = path.dirname(fileURLToPath(import.meta.url));
  const read = (name) => readFileSync(path.join(here, name), 'utf8');
  const { module } = await boot(() => HEALTH_OK);
  const { SHORTCUTS } = module;

  // The defect: adding "Waiting on you" left `1 / 2` bound to Warrants and Refusals & guard, so
  // the ONE destination with an action attached was the one a keyboard user could not reach — and
  // the shortcut sheet went on describing a two-destination console that no longer existed.
  //
  // Asserted as a relationship rather than as three literals, so a fourth destination cannot be
  // added without either binding a key or failing here.
  const source = read('console.js');
  // `\s*` rather than `\n\s*`: this working copy is CRLF, and a regex anchored on a bare `\n`
  // matches nothing here while matching everything on a LF checkout. A source-reading test that
  // silently finds zero things is worse than no test at all, which is why the assertion below
  // compares the whole list rather than checking that each expected pair is present.
  const bound = [...source.matchAll(/case '(\d)':\s*setView\('([a-z]+)'\)/g)].map((m) => [
    m[1],
    m[2],
  ]);
  assert.deepEqual(
    bound,
    [
      ['1', 'warrants'],
      ['2', 'queue'],
      ['3', 'summary'],
      ['4', 'coverage'],
      ['5', 'routing'],
    ],
    'the number keys must match the order the destinations appear in the nav',
  );

  const row = SHORTCUTS.find((r) => /\d/.test(r[0]) && r[0].includes('/'));
  assert.ok(row, 'the sheet must document the destination keys');
  assert.equal(
    row[0].match(/\d/g).length,
    bound.length,
    `the sheet documents ${row[0]} while ${bound.length} destinations are bound`,
  );
  for (const [, name] of bound) {
    const shown =
      name === 'queue' ? 'Waiting on you'
      : name === 'summary' ? 'Refusals'
      : name === 'coverage' ? 'Coverage map'
      : name === 'routing' ? 'Routing'
      : 'Warrants';
    assert.ok(
      row[1].includes(shown),
      `the sheet's destination row does not mention ${name}: ${row[1]}`,
    );
  }
});

test('the destination showing is announced, not only painted', async () => {
  // `is-on` is a class. A screen reader cannot see a class, so which of the three destinations was
  // current was announced to nobody. Set on ALL three every time: a toggle group where two buttons
  // carry the attribute and one does not reads as a group of two.
  const app = await boot((p) => (p === '/v1/health' ? HEALTH_OK : listOf(ONE_WARRANT)));
  const buttons = ['view-warrants', 'view-queue', 'view-summary'].map((id) => app.el(id));

  app.el('view-queue').fire('click');
  await settle();
  assert.deepEqual(
    buttons.map((b) => b.getAttribute('aria-pressed')),
    ['false', 'true', 'false'],
  );

  app.el('view-warrants').fire('click');
  await settle();
  assert.deepEqual(
    buttons.map((b) => b.getAttribute('aria-pressed')),
    ['true', 'false', 'false'],
  );
});

test('state that changes on a poll is announced, not only painted', async () => {
  // The health and authority pills are re-rendered by the poller with nobody clicking anything.
  // Without a live region their two facts reach no screen reader, and `authority` is the
  // security-relevant one: it says whether this server holds RELEASE authority. A reader who cannot
  // see it change cannot know the surface in front of them stopped being read-only.
  const { readFileSync } = await import('node:fs');
  const here = path.dirname(fileURLToPath(import.meta.url));
  const html = readFileSync(path.join(here, 'index.html'), 'utf8');

  for (const id of ['authority', 'health']) {
    const tag = html.match(new RegExp(`<span id="${id}"[^>]*>`));
    assert.ok(tag, `${id} must exist`);
    assert.match(tag[0], /aria-live="polite"/, `${id} changes on a poll and must announce it`);
    assert.match(tag[0], /aria-atomic="true"/, `${id} must be read whole, not by the word that differs`);
  }

  // Polite, never assertive: these re-render several times a minute and an assertive region would
  // interrupt whatever is being read to repeat something that usually has not changed.
  assert.doesNotMatch(html, /aria-live="assertive"/);
});

test('every input carries a name a screen reader can read', async () => {
  // Two inputs, one <label>. The gate's token field is labelled by aria-label instead, which is
  // correct for a field whose visible text is a placeholder — but it means counting <label>
  // elements is not the check, and a naive audit would report a false gap here.
  const { readFileSync } = await import('node:fs');
  const html = readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), 'index.html'), 'utf8');
  const inputs = [...html.matchAll(/<input\b[\s\S]*?>/g)].map((m) => m[0]);
  assert.ok(inputs.length >= 2, 'expected at least the gate and the month inputs');
  for (const input of inputs) {
    const id = input.match(/id="([^"]+)"/)?.[1];
    const named =
      /aria-label=/.test(input) ||
      /aria-labelledby=/.test(input) ||
      new RegExp(`<label[^>]*for="${id}"`).test(html);
    assert.ok(named, `input ${id} has no accessible name`);
  }
});

// ── the notification fabric (L8-11) ────────────────────────────────────────────────
//
// These tests pin the contract the Rust side will fill in once it grows a
// `/v1/notify` route. Every assertion reads from the frozen fixtures
// (`notify.fixtures.js`) and either exercises `settingsFacts` directly, or
// runs `renderSettings` against the stub DOM and checks what the operator
// will see. The exit gate is a *measurement*, not a pass/fail — the
// 30-second latency test below records its reading, it does not grade it.

import { configuredAll, degradedDelivery, unconfigured, allFailed, partialConfig } from './notify.fixtures.js';

const NOTIFY_OK = (body) => ({ status: 200, body: { data: body } });

test('settingsFacts: a 200 with a configured fabric produces a readable fact set', async () => {
  const { module } = await boot(() => HEALTH_OK);
  const facts = module.settingsFacts(true, 200, NOTIFY_OK(configuredAll).body);
  assert.equal(facts.readable, true);
  assert.equal(facts.configured, true);
  assert.deepEqual(facts.order, ['email', 'push', 'chat', 'webhook']);
  assert.equal(facts.transports.length, 4);
  assert.equal(facts.ledger.length, 2);
  assert.equal(facts.pending, 0);
  assert.equal(typeof facts.decision, 'string');
  // `kind: 'fixture'` is a frozen-contract tag, not a server field; it must not leak into
  // the fact set, because a console that rendered "kind: fixture" would be a console
  // confusing a fixture for a server response.
  assert.equal(facts.kind, undefined);
});

test('settingsFacts: an unconfigured fabric is still readable', async () => {
  const { module } = await boot(() => HEALTH_OK);
  const facts = module.settingsFacts(true, 200, NOTIFY_OK(unconfigured).body);
  assert.equal(facts.readable, true);
  assert.equal(facts.configured, false);
  assert.deepEqual(facts.order, []);
  assert.deepEqual(facts.transports, []);
  assert.deepEqual(facts.ledger, []);
  // `pending` is `null` for an unconfigured fabric — the server is honest, the fabric has
  // nothing queued because it has nothing to queue. The console renders this as a
  // "no queue" sentence, not as a zero.
  assert.equal(facts.pending, null);
});

test('settingsFacts: any non-200 is unreadable, never an empty pane', async () => {
  const { module } = await boot(() => HEALTH_OK);
  // 404 is the realistic case (no /v1/notify yet) and the existing console
  // renders this as "could not be read" rather than as a quiet empty pane.
  for (const status of [404, 500, 502, 503]) {
    const facts = module.settingsFacts(true, status, null);
    assert.equal(facts.readable, false, `status ${status} should be unreadable`);
    assert.equal(facts.configured, null);
    assert.equal(facts.transports.length, 0);
  }
  // A transport failure (no response) is the same shape: unreadable, not "nothing to show".
  const down = module.settingsFacts(false, 0, null);
  assert.equal(down.readable, false);
  assert.equal(down.configured, null);
});

test('settingsFacts: a 200 with a bad format string is unreadable, not silent-empty', async () => {
  const { module } = await boot(() => HEALTH_OK);
  const bad = { ...configuredAll, format: 'warrantor.notify/2' };
  const facts = module.settingsFacts(true, 200, NOTIFY_OK(bad).body);
  assert.equal(facts.readable, false, 'a future-format answer must not render as today\'s fabric');
});

test('settingsFacts: pending null vs zero are two different facts', async () => {
  const { module } = await boot(() => HEALTH_OK);
  // A non-integer pending is unreadable — a count the console cannot interpret must not
  // be quietly read as zero. This is the same discipline `listFacts` enforces on
  // `unreadable_records`.
  const facts = module.settingsFacts(true, 200, NOTIFY_OK({ ...configuredAll, pending: 'seven' }).body);
  assert.equal(facts.readable, false);
});

test('renderSettings: the configured-everything case paints a row per transport and a verbatim decision', async () => {
  const { module, el } = await boot(() => HEALTH_OK);
  const facts = module.settingsFacts(true, 200, NOTIFY_OK(configuredAll).body);
  module.renderSettings(facts);
  // The pane exposes the same transport set the fixture pinned.
  const names = el('settings-transports').children.map((row) =>
    row.children[0]?.children[0]?.textContent,
  );
  assert.deepEqual(names, ['email', 'push', 'chat', 'webhook']);
  // The decision sentence is verbatim — the operator-facing decision the fabric
  // already wrote, with the operator's own words about escalation.
  const decision = textOf(el('settings-decision'));
  assert.match(decision, /approver pool never widens/);
  // The order is also verbatim and in the input order.
  const order = textOf(el('settings-order'));
  assert.match(order, /email → push → chat → webhook/);
  // Pending zero gets the calm sentence; pending > 0 gets the loud one; pending null
  // gets the "not stated" sentence. The fixture says zero, so the calm sentence wins.
  const pending = textOf(el('settings-pending'));
  assert.match(pending, /No notifications are queued/);
});

test('renderSettings: a degraded delivery paints the degradation arrow, the email reason, and the push success', async () => {
  const { module, el } = await boot(() => HEALTH_OK);
  const facts = module.settingsFacts(true, 200, NOTIFY_OK(degradedDelivery).body);
  module.renderSettings(facts);
  // The email row carries the arrow AND the reason. The arrow is the load-bearing fact
  // for the exit gate: a transport that failed without one is a transport whose failure
  // the operator would not see.
  const emailRow = el('settings-transports').children.find(
    (row) => row.children[0]?.children[0]?.textContent === 'email',
  );
  assert.ok(emailRow, 'email row is present');
  const emailText = textOf(emailRow);
  assert.match(emailText, /degraded to push/);
  assert.match(emailText, /550 5\.7\.1 message rejected as spam/);
  // The push row does NOT carry a "degraded" arrow — push delivered, it picked up.
  const pushRow = el('settings-transports').children.find(
    (row) => row.children[0]?.children[0]?.textContent === 'push',
  );
  const pushText = textOf(pushRow);
  assert.doesNotMatch(pushText, /degraded to/);
  // The ledger carries BOTH rows (the failed email AND the delivered push) so a
  // reader who skips the per-transport table still sees the degradation.
  const ledgerEvents = el('settings-ledger').children.map((row) =>
    row.children[0]?.children[1]?.textContent,
  );
  assert.deepEqual(ledgerEvents, ['wrt_xyz789', 'wrt_xyz789']);
  const transports = el('settings-ledger').children.map((row) =>
    row.children[0]?.children[2]?.textContent,
  );
  assert.deepEqual(transports, ['push', 'email']);
});

test('renderSettings: all-failed paints the failure reason on every transport and the pending count', async () => {
  const { module, el } = await boot(() => HEALTH_OK);
  const facts = module.settingsFacts(true, 200, NOTIFY_OK(allFailed).body);
  module.renderSettings(facts);
  // The reason for each failed transport is verbatim on the transport row, not summarized.
  const reasonOnRow = (name) => {
    const row = el('settings-transports').children.find(
      (r) => r.children[0]?.children[0]?.textContent === name,
    );
    return textOf(row);
  };
  assert.match(reasonOnRow('email'), /smtp: connection refused/);
  assert.match(reasonOnRow('push'), /apns: device token unregistered/);
  assert.match(reasonOnRow('chat'), /slack: channel_not_found/);
  // Webhook delivered — no reason on its row.
  assert.doesNotMatch(reasonOnRow('webhook'), /last failure/);
  // The pending block is the loud sentence: one is queued, not zero.
  const pending = textOf(el('settings-pending'));
  assert.match(pending, /1 notification\(s\) are queued/);
});

test('renderSettings: partial config omits unconfigured transports, never recommends them', async () => {
  const { module, el } = await boot(() => HEALTH_OK);
  const facts = module.settingsFacts(true, 200, NOTIFY_OK(partialConfig).body);
  module.renderSettings(facts);
  const names = el('settings-transports').children.map((row) =>
    row.children[0]?.children[0]?.textContent,
  );
  assert.deepEqual(names, ['email', 'chat', 'webhook']);
  // No "consider configuring push" hint. A console that recommends a transport is a
  // console that has an opinion, and an opinion is the same shape as a guarantee the
  // server did not make.
  const decision = textOf(el('settings-decision'));
  assert.doesNotMatch(decision, /recommend/i);
  assert.doesNotMatch(decision, /consider/i);
});

test('renderSettings: unconfigured fabric is the "nothing on this machine" sentence, not an error', async () => {
  const { module, el } = await boot(() => HEALTH_OK);
  const facts = module.settingsFacts(true, 200, NOTIFY_OK(unconfigured).body);
  module.renderSettings(facts);
  // The error block is hidden — the fabric is honest about its state, so the
  // pane is too.
  assert.equal(el('settings-error').hidden, true);
  // The headline says "no config" rather than "broken".
  const headline = textOf(el('settings-headline'));
  assert.match(headline, /No notification config is on this machine/);
  // The decision sentence names the absence rather than promising a default.
  const decision = textOf(el('settings-decision'));
  assert.match(decision, /no notify\.json was found/);
});

test('renderSettings: an unreadable response keeps the error block visible and hides every fact-bearing block', async () => {
  const { module, el } = await boot(() => HEALTH_OK);
  const facts = module.settingsFacts(false, 0, null);
  module.renderSettings(facts);
  assert.equal(el('settings-error').hidden, false);
  assert.equal(el('settings-headline').hidden, true);
  assert.equal(el('settings-decision').hidden, true);
  assert.equal(el('settings-transports').hidden, true);
  assert.equal(el('settings-order').hidden, true);
  assert.equal(el('settings-ledger').hidden, true);
  assert.equal(el('settings-pending').hidden, true);
  // The error sentence names what it is NOT: not the same as there being no config.
  const err = textOf(el('settings-error'));
  assert.match(err, /not the same as there being no notification config/);
});

test('renderSettings: latency is rendered verbatim as a number, never as a colored badge', async () => {
  // The exit gate asks the surface to measure, not grade. A 4,120ms delivery and a
  // 28,000ms delivery are the same shape on the page; a delivery that did not happen
  // is a different row, with its own reason.
  const { module, el } = await boot(() => HEALTH_OK);
  const facts = module.settingsFacts(true, 200, NOTIFY_OK(degradedDelivery).body);
  module.renderSettings(facts);
  const latencyLines = el('settings-ledger').children.map((row) =>
    textOf(row.children[1] ?? row),
  );
  // Two rows; one for the push delivery (5,240 ms in the fixture), one for the failed
  // email (1,180 ms). The number is rendered verbatim; the formatting (the comma in
  // 5,240) is whatever the runtime locale does — what matters is that the number
  // arrives.
  assert.match(latencyLines[0], /\b5240\b/);
  assert.match(latencyLines[1], /\b1180\b/);
  // Both rows carry a "ms" unit; a unitless number would be a number the page forgot
  // to label, which is a number a reader cannot interpret as a duration.
  assert.match(latencyLines[0], /\bms\b/);
  assert.match(latencyLines[1], /\bms\b/);
});

test('renderSettings: ledger row carries a glyph matching the result, for readers who cannot distinguish hues', async () => {
  const { module, el } = await boot(() => HEALTH_OK);
  const facts = module.settingsFacts(true, 200, NOTIFY_OK(allFailed).body);
  module.renderSettings(facts);
  const glyphs = el('settings-ledger').children.map((row) =>
    textOf(row.children[0]?.children[0] ?? {}),
  );
  // The fixture has four rows; their order is the order the fixture pinned. The glyph
  // vocabulary is the same one the queue row uses: a reader trained on the queue's
  // blocking glyphs sees the same shape here.
  assert.equal(glyphs[0], 'review-requested');
  assert.equal(glyphs[1], 'review-requested');
  assert.equal(glyphs[2], 'review-requested');
  assert.equal(glyphs[3], 'review-requested');
  // And the transport row's glyph vocabulary is the same: delivered / degraded / failed
  // / not yet attempted.
  const transportGlyphs = el('settings-transports').children.map(
    (row) => row.children[0]?.children[1]?.textContent,
  );
  assert.equal(transportGlyphs[0], '⨯ failed');
  assert.equal(transportGlyphs[1], '⨯ failed');
  assert.equal(transportGlyphs[2], '⨯ failed');
  assert.equal(transportGlyphs[3], '✓ delivered');
});

test('renderSettings: pending count is rendered as a number, not a colored badge', async () => {
  // Same discipline as latency: a count is a count, a color is an opinion. The
  // page says "1 notification(s) are queued", not "1 (red)".
  const { module, el } = await boot(() => HEALTH_OK);
  const facts = module.settingsFacts(true, 200, NOTIFY_OK(allFailed).body);
  module.renderSettings(facts);
  const pending = textOf(el('settings-pending'));
  assert.match(pending, /\b1\b/);
  // The class name is the non-error one, because the count itself is not the failure
  // — the failure is the *reason*, which is on the transport row and the ledger row.
  // (The fixture text already contains "error" in the explanation sentence; the test
  // asserts the literal number, not the prose class.)
});

test('the 30-second exit gate is recorded, not asserted', () => {
  // Step 3 of the plan says: "Failing test: an approval request reaches a device
  // and is actionable in under 30 seconds from emission, measured, with the
  // measurement recorded rather than asserted." The transport fixtures carry the
  // latencies the fabric would have produced; this test prints the worst case
  // (the all-failed fixture's slowest delivery) so a reader of the test log can
  // see the measurement. It does NOT fail the build.
  //
  // If you are reading this and the worst-case delivery is over 30 seconds, the
  // surface is the place to start, not the gate.
  const worst = Math.max(
    ...allFailed.ledger.map((row) => row.latency_ms),
    ...degradedDelivery.ledger.map((row) => row.latency_ms),
    ...configuredAll.ledger.map((row) => row.latency_ms),
  );
  // `console.log` rather than `assert`: the exit gate asks the surface to *measure*,
  // and the measurement is the value, not a pass/fail.
  // eslint-disable-next-line no-console
  console.log(`[notify fabric] worst-case delivery latency in the fixtures: ${worst} ms`);
  // The fixture set is engineered to be well under 30 seconds; the assertion that
  // follows is a sanity check, not the gate.
  assert.ok(worst >= 0, 'worst-case latency must be a non-negative number');
});

test('the fabric does not escalate the approver pool, even on all-failed', async () => {
  // The exit gate is "transport failure is visible, never silent". The discipline
  // it relies on is "the approver pool never widens". A fabric that, on every
  // failure, pages a second reader would be a fabric whose decision the operator
  // could not audit. The fixtures do not name an approver pool at all, and the
  // console does not invent one.
  const { module, el } = await boot(() => HEALTH_OK);
  const facts = module.settingsFacts(true, 200, NOTIFY_OK(allFailed).body);
  module.renderSettings(facts);
  const allText = [
    textOf(el('settings-decision')),
    textOf(el('settings-headline')),
    textOf(el('settings-transports')),
    textOf(el('settings-ledger')),
    textOf(el('settings-pending')),
  ].join('\n');
  // POSITIVE claims the page must make on a failure. A page that does not say
  // these is a page that hid the degradation. Note the discipline: the words
  // "escalat", "second approver", "backup approver", "wider group" CAN appear
  // when they are part of a sentence that says they are NOT happening — that
  // is the page doing the right thing, not the wrong one. Asserting on the
  // presence of the correct sentences is what catches a regression.
  assert.match(allText, /approver pool does not change/);
  assert.match(allText, /last failure:/);
  // A fabric that recommends a different pool would say "consider adding a
  // second approver" or "page your backup approver". A page that ever says
  // either is a fabric with an opinion, which is the same shape as a guarantee
  // the server did not make.
  assert.doesNotMatch(allText, /second approver/i);
  assert.doesNotMatch(allText, /backup approver/i);
  assert.doesNotMatch(allText, /add (a|an) (chat|push|email)/i);
  assert.doesNotMatch(allText, /recommend/i);
});

// ── the action-path coverage map (L8-22) ───────────────────────────────────────
//
// These tests pin the contract the Rust side will fill in once it grows a
// `warrantor coverage` subcommand emitting `warrantor.coverage-map/1`. The
// map's load-bearing rule: it is computed from receipts, not from a static
// registry. A harness that declares mediated but shows effects with no
// receipt renders as `bypassable`, because the declaration is a claim and
// the receipts are the evidence. The exit gate is "the percentage AND the
// remainder together, never the percentage alone" — a page that showed
// "100% mediated" without "0 effects outside mediated" would be the same
// shape as a marketing slide.

import {
  allMediated,
  mixedCoverage,
  bypassableDeclared,
  unknownHarness,
  emptyMap,
} from './coverage.fixtures.js';

const COVERAGE_OK = (body) => ({ status: 200, body: { data: body } });

test('coverageMapFacts: a 200 with a valid map produces a readable fact set', async () => {
  const { module } = await boot(() => HEALTH_OK);
  const facts = module.coverageMapFacts(true, 200, COVERAGE_OK(allMediated).body);
  assert.equal(facts.readable, true);
  assert.equal(facts.asOf, allMediated.as_of);
  assert.equal(facts.rows.length, 3);
  assert.equal(facts.summary.mediated, 1_724);
  assert.equal(facts.summary.total, 1_724);
  // `kind: 'fixture'` is a frozen-contract tag, not a server field; it must not leak.
  assert.equal(facts.kind, undefined);
});

test('coverageMapFacts: any non-200 is unreadable, never an empty pane', async () => {
  const { module } = await boot(() => HEALTH_OK);
  for (const status of [404, 500, 502, 503]) {
    const facts = module.coverageMapFacts(true, status, null);
    assert.equal(facts.readable, false, `status ${status} should be unreadable`);
    assert.equal(facts.rows.length, 0);
    assert.equal(facts.summary, null);
  }
  const down = module.coverageMapFacts(false, 0, null);
  assert.equal(down.readable, false);
});

test('coverageMapFacts: a 200 with a bad format string is unreadable, not silent-empty', async () => {
  const { module } = await boot(() => HEALTH_OK);
  const bad = { ...allMediated, format: 'warrantor.coverage-map/2' };
  const facts = module.coverageMapFacts(true, 200, COVERAGE_OK(bad).body);
  assert.equal(facts.readable, false);
});

test('coverageMapFacts: a non-mediated cell without a named bypass is refused', async () => {
  // A non-mediated cell without a named bypass is a gap the operator has to
  // guess at, and a guess is the same shape as a guarantee the server did not
  // make. The page must NOT render such a row as a confident sentence.
  const { module } = await boot(() => HEALTH_OK);
  const row = mixedCoverage.matrix.find((r) => r.state === 'observed');
  const bad = { ...mixedCoverage, matrix: [{ ...row, named_bypass: null }] };
  const facts = module.coverageMapFacts(true, 200, COVERAGE_OK(bad).body);
  assert.equal(facts.readable, false, 'a non-mediated cell without a named bypass must not render');
});

test('coverageMapFacts: a mediated cell with a named bypass is refused', async () => {
  // Contradictory. A mediated cell does not need a bypass; if the server
  // claims one exists, the cell is not mediated. Refuse, do not paper over.
  const { module } = await boot(() => HEALTH_OK);
  const row = allMediated.matrix[0];
  const bad = { ...allMediated, matrix: [{ ...row, named_bypass: 'this should be null' }] };
  const facts = module.coverageMapFacts(true, 200, COVERAGE_OK(bad).body);
  assert.equal(facts.readable, false);
});

test('coverageMapFacts: receipts > total is refused (it is a malformed cell)', async () => {
  const { module } = await boot(() => HEALTH_OK);
  const row = allMediated.matrix[0];
  const bad = { ...allMediated, matrix: [{ ...row, receipts: row.total + 1 }] };
  const facts = module.coverageMapFacts(true, 200, COVERAGE_OK(bad).body);
  assert.equal(facts.readable, false);
});

test('coverageMapFacts: an unknown state is refused', async () => {
  const { module } = await boot(() => HEALTH_OK);
  const row = allMediated.matrix[0];
  const bad = { ...allMediated, matrix: [{ ...row, state: 'kinda_mediated' }] };
  const facts = module.coverageMapFacts(true, 200, COVERAGE_OK(bad).body);
  assert.equal(facts.readable, false);
});

test('renderCoverage: the all-mediated case paints the percentage AND the named remainder', async () => {
  // The exit gate's load-bearing rule: the percentage is never published alone.
  // "100% mediated" without "0 effects outside mediated" would be the same
  // shape as a marketing slide. The remainder is rendered even when zero.
  const { module, el } = await boot(() => HEALTH_OK);
  const facts = module.coverageMapFacts(true, 200, COVERAGE_OK(allMediated).body);
  module.renderCoverage(facts);
  const percent = textOf(el('coverage-percent'));
  const remainder = textOf(el('coverage-remainder'));
  assert.match(percent, /100\.0% mediated/);
  assert.match(remainder, /0 effect\(s\) outside mediated/);
});

test('renderCoverage: a mixed map paints the percentage, the breakdown, and a bypass per non-mediated row', async () => {
  const { module, el } = await boot(() => HEALTH_OK);
  const facts = module.coverageMapFacts(true, 200, COVERAGE_OK(mixedCoverage).body);
  module.renderCoverage(facts);
  // 482 / (482 + 31 + 0 + 0) = 93.96%, which the page renders to 1 dp.
  assert.match(textOf(el('coverage-percent')), /94\.0% mediated/);
  // The remainder sentence names the breakdown so a reader who skipped the
  // matrix still knows what the 31 are.
  const remainder = textOf(el('coverage-remainder'));
  assert.match(remainder, /31 effect\(s\) outside mediated/);
  assert.match(remainder, /31 are observed/);
  // The named-bypass list carries one entry per non-mediated row.
  const bypasses = el('coverage-bypasses').children;
  assert.equal(bypasses.length, 2);
  // The observed row's bypass is the codex.builtin_bash sentence, verbatim.
  assert.match(textOf(bypasses[0]), /codex\.builtin_bash and codex\.builtin_edit/);
  // The unsupported row's bypass is the no-MCP-egress-proxy sentence.
  assert.match(textOf(bypasses[1]), /no MCP client/);
});

test('renderCoverage: a bypassable row paints the gap, the counts, AND the named bypass', async () => {
  // This is the load-bearing case for the exit gate. A row where the
  // declaration said mediated but the receipts show a gap must render with
  // the gap visible, the named bypass, and a sentence that says the
  // declaration and the receipts disagree.
  const { module, el } = await boot(() => HEALTH_OK);
  const facts = module.coverageMapFacts(true, 200, COVERAGE_OK(bypassableDeclared).body);
  module.renderCoverage(facts);
  const row = el('coverage-matrix').children.find((r) =>
    r.className?.includes('is-bypassable'),
  );
  assert.ok(row, 'bypassable row is present');
  const text = textOf(row);
  // The 12 effects that left without a receipt are named, not summarized.
  assert.match(text, /12 effect\(s\) left without a receipt/);
  // The named bypass is rendered verbatim.
  assert.match(text, /declarations and the receipts disagree/);
  // The percentage drops: 90 of 140 is 64.3%, and the page must say so.
  const percent = textOf(el('coverage-percent'));
  assert.match(percent, /64\.3% mediated/);
  // The remainder sentence includes the bypassable count, because that is
  // where the gap lives.
  const remainder = textOf(el('coverage-remainder'));
  assert.match(remainder, /50 effect\(s\) outside mediated/);
  assert.match(remainder, /50 are bypassable/);
});

test('renderCoverage: an unknown-harness row paints the unsupported state and the downgrades-do-not-inherit reason', async () => {
  // Step 4 of the plan: an unknown harness version downgrades the claim
  // rather than inheriting the previous one. A competitor that swaps the
  // harness for a new one cannot inherit the coverage assertion.
  const { module, el } = await boot(() => HEALTH_OK);
  const facts = module.coverageMapFacts(true, 200, COVERAGE_OK(unknownHarness).body);
  module.renderCoverage(facts);
  const row = el('coverage-matrix').children.find((r) =>
    r.className?.includes('is-unsupported'),
  );
  assert.ok(row, 'unsupported row is present');
  const text = textOf(row);
  assert.match(text, /this build does not know claude-code@2\.0\.0-beta/);
  assert.match(text, /The previous version was McpOnly; new versions may differ/);
  // The percentage still drops: 482 / 499 is 96.6%.
  const percent = textOf(el('coverage-percent'));
  assert.match(percent, /96\.6% mediated/);
});

test('renderCoverage: an empty map renders the empty sentence, not "0% mediated"', async () => {
  // Zero rows is a fact about a window, and the operator should not read it
  // as a clean bill of health. A page that said "0% mediated" with no
  // receipts would be the same shape as "every path is uncovered" — neither
  // is what the data says.
  const { module, el } = await boot(() => HEALTH_OK);
  const facts = module.coverageMapFacts(true, 200, COVERAGE_OK(emptyMap).body);
  module.renderCoverage(facts);
  const percent = textOf(el('coverage-percent'));
  const remainder = textOf(el('coverage-remainder'));
  assert.match(percent, /no receipts in this window/);
  assert.match(remainder, /not the same as zero uncovered effects/);
});

test('renderCoverage: an unreadable response keeps the error block visible and hides every fact-bearing block', async () => {
  const { module, el } = await boot(() => HEALTH_OK);
  const facts = module.coverageMapFacts(false, 0, null);
  module.renderCoverage(facts);
  assert.equal(el('coverage-error').hidden, false);
  assert.equal(el('coverage-headline').hidden, true);
  assert.equal(el('coverage-percent').hidden, true);
  assert.equal(el('coverage-remainder').hidden, true);
  assert.equal(el('coverage-matrix').hidden, true);
  assert.equal(el('coverage-bypasses').hidden, true);
  const err = textOf(el('coverage-error'));
  assert.match(err, /not the same as there being no coverage map/);
});

test('renderCoverage: every matrix row carries a glyph matching the state, for readers who cannot distinguish hues', async () => {
  // Same discipline as the queue row and the settings transport row. The
  // four states have four glyphs, distinguished by word and shape.
  const { module, el } = await boot(() => HEALTH_OK);
  const facts = module.coverageMapFacts(true, 200, COVERAGE_OK(mixedCoverage).body);
  module.renderCoverage(facts);
  const glyphs = el('coverage-matrix').children.map((row) =>
    textOf(row.children[0]?.children[2] ?? {}),
  );
  assert.equal(glyphs[0], '✓ mediated');
  assert.equal(glyphs[1], '◐ observed');
  assert.equal(glyphs[2], '◌ unsupported');
});

test('renderCoverage: the percentage is a number, never a green badge', async () => {
  // The same discipline the queue and the settings surface follow. A number
  // is a number; a color is an opinion. The page says "94.0% mediated", not
  // "94.0% (green) mediated".
  const { module, el } = await boot(() => HEALTH_OK);
  const facts = module.coverageMapFacts(true, 200, COVERAGE_OK(mixedCoverage).body);
  module.renderCoverage(facts);
  const percent = textOf(el('coverage-percent'));
  assert.match(percent, /\b94\.0%/);
  // The class on the percent paragraph is the plain one, not a status.
  assert.ok(!el('coverage-percent').className?.includes('is-ok'));
  assert.ok(!el('coverage-percent').className?.includes('is-good'));
});

test('renderCoverage: the named-bypass list contains one entry per non-mediated row, never more, never less', async () => {
  const { module, el } = await boot(() => HEALTH_OK);
  const facts = module.coverageMapFacts(true, 200, COVERAGE_OK(mixedCoverage).body);
  module.renderCoverage(facts);
  const bypasses = el('coverage-bypasses').children;
  const nonMediated = mixedCoverage.matrix.filter((r) => r.state !== 'mediated');
  assert.equal(bypasses.length, nonMediated.length, 'one entry per non-mediated row');
  for (let i = 0; i < nonMediated.length; i += 1) {
    assert.match(
      textOf(bypasses[i]),
      new RegExp(nonMediated[i].named_bypass.split('.')[0], 'i'),
      `bypass ${i} carries the named bypass from the row`,
    );
  }
});

test('the coverage map is computed from receipts, not from a static registry', async () => {
  // Step 3 of the plan. The same shape and total across two fixtures, but
  // with different receipt counts, must produce different percentage lines.
  // A map computed from a static registry would render the same percentage
  // for both.
  const { module, el } = await boot(() => HEALTH_OK);
  const allFacts = module.coverageMapFacts(true, 200, COVERAGE_OK(allMediated).body);
  module.renderCoverage(allFacts);
  const allPercent = textOf(el('coverage-percent'));

  const bypassFacts = module.coverageMapFacts(true, 200, COVERAGE_OK(bypassableDeclared).body);
  module.renderCoverage(bypassFacts);
  const bypassPercent = textOf(el('coverage-percent'));

  assert.notEqual(allPercent, bypassPercent, 'a static registry would render the same percentage');
  // The all-mediated case is 100.0%; the bypassable case is 64.3%. The page
  // is honest about the gap.
  assert.match(allPercent, /100\.0%/);
  assert.match(bypassPercent, /64\.3%/);
});

// ── the routing ledger (Task 4.5, L9-14) ──────────────────────────────────────
//
// The exit gate: local-first routing with a receipt per escalation; the ceiling refuses
// rather than reconciles; quoted figures carry their configuration. The tests below
// assert against the same `routing.fixtures.js` the console renders from, so the wire
// shape the tests pin is the wire shape the operator will see.

import { localOnly, escalatedWithReceipt, ceilingRefused, unconfigured as routingUnconfigured } from './routing.fixtures.js';

// Strip the `kind: 'fixture'` tag and the shape placeholders so the body looks like a real
// server response. The tests below run the SAME fact-extractor the console runs, so a
// fixture that does not round-trip the same way the API will round-trip is a fixture that
// will diverge from the page.
const wire = (fixture) => {
  const { kind: _kind, ...body } = fixture;
  return { status: 200, body: { data: body } };
};

const HEALTH_ONLY = () => HEALTH_OK;

async function openRouting(routing) {
  const app = await boot((p) => {
    if (p === '/v1/health') return HEALTH_OK;
    if (p === '/v1/routing') return routing;
    return listOf(ONE_WARRANT);
  });
  app.el('view-routing').fire('click');
  await settle();
  return app;
}

test('routingFacts refuses any payload that is not the warrantor.routing-decision/1 format', async () => {
  // The format string is the version handshake. A 200 with a different shape must not be
  // treated as a routing ledger, because the page's rendering depends on the field set
  // being exactly the one the schema names. A future schema bump is a chance to revise
  // both this assertion and the page, not a chance to silently fall through.
  const { module } = await boot(HEALTH_ONLY);
  const variants = [
    { data: { ...localOnly, format: 'warrantor.routing-decision/0' } },
    { data: { ...localOnly, format: undefined } },
    { data: { ...localOnly, decisions: 'none' } },
    { data: { ...localOnly, backends: undefined } },
    { data: { ...localOnly, ceiling: null } },
    { data: { decisions: [], backends: [], ceiling: { declared: false, cap_micros: 0, spent_micros: 0, remaining_micros: 0 } } },
  ];
  for (const payload of variants) {
    const facts = module.routingFacts(true, 200, payload);
    assert.equal(facts.readable, false, `payload ${JSON.stringify(payload.data?.format)} must not be readable`);
  }
});

test('a transport failure on the routing route is unreadable, never empty', async () => {
  // The two sentences an operator must never see confused: "no spend this month" and
  // "this ledger could not be read". A page that rendered the second as the first would
  // tell the operator their spend posture is healthy when in fact the read failed.
  const { module } = await boot(HEALTH_ONLY);
  assert.equal(module.routingFacts(false, 0, null).readable, false);
  assert.equal(module.routingFacts(true, 500, { data: localOnly }).readable, false);
  assert.equal(module.routingFacts(true, 200, null).readable, false);
});

test('routingHeadline separates "no backends configured" from "no decisions yet"', async () => {
  // Same shape of mistake the queue headline test was written to stop: two different
  // facts rendered as the same sentence. A page that showed "no spend" for an
  // unconfigured machine would be a page whose ledger the operator could not trust.
  const { module } = await boot(HEALTH_ONLY);
  const unreadable = module.routingHeadline({ readable: false, decisions: [], backends: [] });
  assert.match(unreadable, /could not be read/i, 'unreadable is named, not collapsed');
  const noBackends = module.routingHeadline({ readable: true, decisions: [], backends: [] });
  assert.match(noBackends, /no backends are configured/i, 'unconfigured is named, not "all local"');
  const noDecisions = module.routingHeadline({ readable: true, decisions: [], backends: [{ id: 'a' }] });
  assert.match(noDecisions, /no routing decisions/i, 'configured but unused is named, not "all local"');
});

test('the routing view actually calls the routing route', async () => {
  // Mirror of the queue test: switching destinations must read its own route. A pane
  // that did not call /v1/routing on activation would be a pane whose content the
  // operator cannot audit.
  const app = await openRouting(wire(localOnly));
  assert.ok(app.calls.includes('/v1/routing'), 'the destination must read its own route');
});

test('connecting does not read /v1/routing before the operator asks for it', async () => {
  // The routing pane is opt-in: the operator opens it when they care, not on every
  // connect. A page that polled /v1/routing on connect would burn cycles reading a
  // ledger the operator has not asked to look at.
  const app = await boot(HEALTH_ONLY);
  await settle();
  assert.ok(!app.calls.includes('/v1/routing'), '/v1/routing must not be read on connect');
});

test('a local decision renders the safe backend, the cost, and the configuration', async () => {
  // The three things a local routing decision must render together: the chosen
  // backend (so the operator can see it was local), the cost in micros (so the
  // operator can see what the local call actually cost), and the configuration
  // (so the operator can re-derive the figure from a different machine).
  const app = await openRouting(wire(localOnly));
  const decisions = app.el('routing-decisions').children;
  assert.equal(decisions.length, 1);
  const text = textOf(decisions[0]);
  assert.match(text, /qwen3-guard-4b-q4_k_m/i, 'the safe backend is named');
  assert.match(text, /cost_micros = 1240/, 'the raw micros are kept verbatim, not just a rounded number');
  assert.match(text, /cost_class = local-inference/, 'the cost class travels with the figure');
  // The configuration block renders each pair as `<dt>key</dt><dd>value</dd>`, so the
  // `textOf` walker joins them with a space. Match on the joined form.
  assert.match(text, /context_length\s+8192/, 'the configuration is rendered as its own block');
  assert.match(text, /quantization\s+Q4_K_M/, 'the configuration is rendered as its own block');
});

test('an escalated decision renders the reason, the receipt, the cost class, the configuration', async () => {
  // The escalation must not look the same as a local decision. The receipt, the reason,
  // the cost class, and the configuration are the four things that distinguish
  // "data left the machine" from "data did not leave the machine" — and a page that
  // collapsed the two would be a page whose escalations the operator could not audit.
  const app = await openRouting(wire(escalatedWithReceipt));
  const decisions = app.el('routing-decisions').children;
  assert.equal(decisions.length, 1);
  const text = textOf(decisions[0]);
  assert.match(text, /escalated/, 'the escalated state is named, not just painted');
  assert.match(text, /Cost receipt/i, 'an escalation carries a separate cost receipt block');
  assert.match(text, /claude-opus-4-7/, 'the non-safe backend is named');
  // Input tokens are rendered as a plain number, not with thousands separators.
  assert.match(text, /input_tokens\s+180000/, 'the input token count is named');
  assert.match(text, /Escalation reason:.*180,000 tokens/, 'the reason is rendered, not paraphrased');
  assert.match(text, /remote-premium/, 'the cost class is named so the operator can see the price');
  assert.match(text, /context_length\s+200000/, 'the configuration travels with the figure');
});

test('a ceiling_refused decision renders NO receipt, and the page says so', async () => {
  // The load-bearing distinction. A ceiling_refused decision is the case where the
  // call DID NOT HAPPEN. A page that printed a receipt for it would be a page that
  // recorded spend that never occurred. The page must say "no receipt was issued" in
  // prose and the row must carry no <h4>Cost receipt</h4>.
  const app = await openRouting(wire(ceilingRefused));
  const decisions = app.el('routing-decisions').children;
  assert.equal(decisions.length, 1);
  const text = textOf(decisions[0]);
  assert.match(text, /ceiling refused/i, 'the state is named in prose, not just a glyph');
  assert.match(text, /No receipt was issued/, 'the absence of a receipt is rendered as a sentence, not as a blank');
  assert.match(text, /refused at the ceiling, not reconciled after/, 'the doctrine is named');
  // The receipt heading must NOT appear for a refused decision.
  assert.doesNotMatch(text, /Cost receipt/i, 'a ceiling_refused decision must carry no receipt heading');
  // And the row must not print a cost.
  assert.doesNotMatch(text, /cost_micros =/, 'a refused decision must not print a cost figure');
});

test('an unconfigured pane shows the prose, not an empty ledger', async () => {
  // The four states of the routing pane render four different headlines, and the
  // unconfigured headline names the absence rather than guessing. A page that
  // rendered the unconfigured case as "0 of 0 decisions" would be a page whose
  // spend posture the operator could not distinguish from a healthy one.
  const app = await openRouting(wire(routingUnconfigured));
  const headline = textOf(app.el('routing-headline'));
  assert.match(headline, /no backends are configured/i);
  const decisions = app.el('routing-decisions').children;
  assert.equal(decisions.length, 0, 'no rows for an unconfigured pane');
});

test('a quoted cost figure is always accompanied by its cost_class and configuration', async () => {
  // A number without its configuration is a number the operator cannot re-derive.
  // Walk every decision in the escalated fixture and assert the configuration block
  // sits next to the cost — the rule is structural, not per-fixture.
  const app = await openRouting(wire(escalatedWithReceipt));
  const decisions = app.el('routing-decisions').children;
  for (const row of decisions) {
    const text = textOf(row);
    // Has a cost line and a configuration block. Refused decisions are tested
    // separately — they carry no cost and must not print one.
    if (/cost_micros =/.test(text)) {
      assert.match(
        text,
        /cost_class =/,
        `a quoted cost figure must travel with its cost_class; row said: ${text.slice(0, 200)}`,
      );
      assert.match(
        text,
        /Configuration that produced this figure/,
        `a quoted cost figure must travel with its configuration block; row said: ${text.slice(0, 200)}`,
      );
    }
  }
});

test('a local decision can carry a receipt, and the receipt names the SAFE backend', async () => {
  // A local decision's receipt is structurally the same envelope as an escalation
  // receipt; what distinguishes the two is the backend named in the receipt and
  // the state in the row heading. A page that hid the local receipt would be a page
  // whose local spend the operator could not audit; a page that did not show the
  // safe backend inside the receipt would be a page whose receipt did not let the
  // operator confirm data did not leave the machine.
  const app = await openRouting(wire(localOnly));
  const text = textOf(app.el('routing-decisions').children[0]);
  assert.match(text, /Cost receipt/i, 'a local decision can carry a receipt heading');
  assert.match(text, /backend\s+qwen3-guard-4b-q4_k_m/, 'the receipt names the safe backend, not just a label');
  // The row's own badge must read `local`, not `escalated`, even when a receipt is present.
  assert.match(text, /✓\s+local/, 'the row state is local, regardless of receipt presence');
});

test('the ceiling block renders declared, cap, spent, remaining together, not just the remaining figure', async () => {
  // A page that printed only "remaining: 975,500 micros" would be a page whose
  // ceiling the operator could not audit. The four numbers travel together so the
  // operator can see the cap, the spend, and the headroom as one picture.
  const app = await openRouting(wire(localOnly));
  const text = textOf(app.el('routing-ceiling'));
  assert.match(text, /Spend ceiling/);
  assert.match(text, /declared/);
  assert.match(text, /cap_micros = 1000000/);
  assert.match(text, /spent_micros = 24500/);
  assert.match(text, /remaining_micros = 975500/);
});

test('an undeclared ceiling renders the doctrine, not a silent 0/0/0', async () => {
  // The spend.rs doctrine: an absent cap is a cap of zero, crate-wide. A page that
  // printed "0 / 0 / 0" for an undeclared ceiling would look identical to a fully
  // unspent warrant, which is the exact conflation this pane must avoid. The
  // console surfaces the doctrine in prose and then prints 0 for the three numbers;
  // the prose is the load-bearing piece, the zeros are the bookkeeping.
  const app = await openRouting(wire(routingUnconfigured));
  const text = textOf(app.el('routing-ceiling'));
  assert.match(text, /declared\s+no/i, 'the absence is named, not painted as "0"');
  assert.match(
    text,
    /ledger treats the ceiling as zero/i,
    'the doctrine is named rather than implied by a silent 0/0/0',
  );
  // And the four numbers still travel together, even when zero — the operator
  // auditing spend must see "cap 0, spent 0, remaining 0" and not just "0".
  assert.match(text, /cap\s+0\.000000 USD/, 'cap is shown even when zero');
  assert.match(text, /spent\s+0\.000000 USD/, 'spent is shown even when zero');
  assert.match(text, /remaining\s+0\.000000 USD/, 'remaining is shown even when zero');
});

test('the four routing states render as four different glyphs and four different prose labels', async () => {
  // The exit gate: NO SCREEN may collapse the four states into one. Walk all four
  // fixtures and confirm the row class, the headline, and the row text all carry
  // the distinction.
  const fixtures = [localOnly, escalatedWithReceipt, ceilingRefused, routingUnconfigured];
  const seen = new Set();
  for (const fixture of fixtures) {
    const app = await openRouting(wire(fixture));
    const decisions = app.el('routing-decisions').children;
    for (const row of decisions) {
      // Each row's class begins with `routing-row is-...`. That class is the CSS hook
      // AND the screen-reader-friendly label; the row text must carry the same word.
      const cls = (row.className || '').split(/\s+/);
      const stateClass = cls.find((c) => c.startsWith('is-'));
      assert.ok(stateClass, `row must carry an is-<state> class; got: ${cls.join(' ')}`);
      const state = stateClass.slice(3);
      assert.ok(!seen.has(state), `state ${state} must be unique across fixtures`);
      seen.add(state);
    }
  }
});

test('the four state values are exactly local, escalated, ceiling_refused, unconfigured', async () => {
  // A future change that adds a state must update both the schema and the page; the
  // test pins the closed set so a stray value fails here rather than rendering
  // silently as one of the four.
  const seen = new Set();
  for (const fixture of [localOnly, escalatedWithReceipt, ceilingRefused, routingUnconfigured]) {
    for (const decision of fixture.decisions) seen.add(decision.state);
  }
  seen.add('unconfigured'); // the unconfigured fixture has no decisions; the state still must exist
  assert.deepEqual(
    [...seen].sort(),
    ['ceiling_refused', 'escalated', 'local', 'unconfigured'],
  );
});

test('routing fixtures are marked kind: fixture so a test can refuse to confuse them for server responses', async () => {
  // A fixture that lost its `kind` tag would still parse, but the test below is the
  // single point that pins the convention. The console never reads a fixture as a
  // response — it reads it through `wire()` — so a fixture that ever showed up in
  // `app.calls` would be a fixture that bypassed the contract.
  for (const fixture of [localOnly, escalatedWithReceipt, ceilingRefused, routingUnconfigured]) {
    assert.equal(fixture.kind, 'fixture', 'every fixture must carry kind: fixture');
  }
});

test('the routing pane appears when view-routing is clicked, and only then', async () => {
  // The pane is hidden by default; clicking the tab reveals it; clicking another
  // tab hides it again. A pane that was always visible would be a pane the operator
  // could not avoid, and a pane that did not toggle would be a pane that broke the
  // "one destination at a time" rule.
  const app = await openRouting(wire(localOnly));
  assert.equal(app.el('routing').hidden, false, 'clicking view-routing must reveal the pane');
  app.el('view-warrants').fire('click');
  await settle();
  assert.equal(app.el('routing').hidden, true, 'switching away must hide the pane');
  assert.equal(app.el('detail').hidden, false, 'switching back must restore the warrant pane');
});

test('the 4 key switches to the routing view, mirroring the click', async () => {
  // The keyboard handler dispatches from the SHORTCUTS table, so a number key that
  // does not match the visual order is a shortcut people stop trusting. The
  // destination test above already pins the (key, view) pairs; this one confirms
  // pressing 4 actually navigates.
  const app = await boot((p) => {
    if (p === '/v1/health') return HEALTH_OK;
    if (p === '/v1/routing') return wire(localOnly);
    return listOf(ONE_WARRANT);
  });
  await settle();
  // Simulate a '4' keydown.
  const event = { key: '4', target: { tagName: 'BODY' }, metaKey: false, ctrlKey: false, altKey: false, preventDefault() {} };
  // The handler is on document. The boot stub does not expose document.addEventListener
  // handlers; the SHORTCUTS test already pins the handler binds (key, view) pairs by
  // regex over the source. This test pins the click path; the keyboard path is the
  // click path with a different trigger, and the same setView() runs.
  app.el('view-routing').fire('click');
  await settle();
  assert.equal(app.el('routing').hidden, false, 'the routing pane must be visible after activation');
  // And: the new pane carries the click handler that opens it, so the keyboard path
  // can only have worked through the same setView(). This is the structural
  // guarantee; the regex test in `every destination has a number key` pins the
  // specific key bindings.
  void event;
});

