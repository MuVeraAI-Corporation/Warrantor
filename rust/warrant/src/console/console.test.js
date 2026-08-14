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
  'health',
  'authority',
  'toast',
  'view-warrants',
  'view-summary',
  'summary',
  'summary-form',
  'summary-month',
  'summary-error',
  'summary-window',
  'summary-caveat',
  'summary-refusals',
  'summary-refusals-empty',
  'summary-refusals-note',
  'summary-guard',
  'summary-guard-unknown',
  'summary-guard-none',
  'summary-guard-quiet',
  'summary-guard-note',
  'summary-coverage',
  'summary-coverage-note',
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

test('a month in which no guard attached says NO COVERAGE, not an empty reassuring table', async () => {
  const app = await openSummary(
    summaryBody({
      guard: {
        configured: false,
        enforcing: false,
        blocking_posture: null,
        groups: [],
        coverage: { ...COVERAGE, sessions_attached: 0, sessions_finished: 0 },
        note: 'No guard was attached to any run in this store.',
      },
    }),
  );
  assert.equal(app.el('summary-guard-none').hidden, false);
  assert.equal(app.el('summary-guard-quiet').hidden, true);
  assert.equal(app.el('summary-guard-unknown').hidden, true);
  assert.match(
    textOf(app.el('summary-guard')),
    /posture not stated/,
    'a log with nothing in it has no posture, and a default would be a claim',
  );
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
