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
