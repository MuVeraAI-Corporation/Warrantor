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
  'queue',
  'queue-headline',
  'queue-who',
  'queue-rows',
  'queue-empty',
  'queue-error',
  'queue-unreadable',
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
      self.children.push(...kids);
    },
    replaceChildren(...kids) {
      self.children = [...kids];
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
    const shown = name === 'queue' ? 'Waiting on you' : name === 'summary' ? 'Refusals' : 'Warrants';
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

