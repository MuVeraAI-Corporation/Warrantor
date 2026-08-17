/**
 * The shell's non-security policy: the menu, remembered geometry, and what a dying agent says.
 *
 * Separate from `policy.test.js` because these are usability decisions rather than security ones —
 * but two of them are the kind of usability defect that is indistinguishable from a broken product,
 * and both shipped: a macOS window that cannot paste, and an agent that dies behind a window which
 * goes on rendering as if it had not.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  DEFAULT_WINDOW_STATE,
  agentExitMessage,
  menuTemplate,
  newlyWaiting,
  sanitiseWindowState,
  traySummary,
  waitingNotification,
} from '../src/policy.js';

const handlers = { reload: () => {}, about: () => {} };

/** Every role in a template, flattened, so a submenu's contents can be asserted at any depth. */
function roles(template) {
  return template.flatMap((menu) => (menu.submenu ?? []).map((item) => item.role));
}

// ── the menu ──────────────────────────────────────────────────────────────────────────

test('macOS gets an Edit menu containing paste, because ⌘V has nowhere else to go', () => {
  // Not a preference. On macOS the standard editing shortcuts are delivered through the menu, so a
  // window whose menu has no `paste` role cannot paste at all. The first version of this menu had
  // copy and selectAll and neither paste nor cut nor undo.
  const template = menuTemplate({ platform: 'darwin', appName: 'Warrantor', handlers });
  for (const required of ['paste', 'cut', 'copy', 'undo', 'redo', 'selectAll']) {
    assert.ok(roles(template).includes(required), `the Edit menu must offer ${required}`);
  }
});

test('every platform gets the Edit menu, not only the one that needs it most', () => {
  for (const platform of ['darwin', 'win32', 'linux']) {
    const template = menuTemplate({ platform, appName: 'Warrantor', handlers });
    assert.ok(roles(template).includes('paste'), `${platform} must offer paste`);
  }
});

test('macOS gets an application menu first, with quit and hide in it', () => {
  const template = menuTemplate({ platform: 'darwin', appName: 'Warrantor', handlers });
  assert.equal(template[0].label, 'Warrantor', 'the app menu is first on macOS');
  const appRoles = template[0].submenu.map((item) => item.role);
  for (const required of ['quit', 'hide', 'services']) {
    assert.ok(appRoles.includes(required), `the app menu must offer ${required}`);
  }
});

test('non-macOS platforms do not get a macOS-only application menu', () => {
  const template = menuTemplate({ platform: 'win32', appName: 'Warrantor', handlers });
  assert.ok(!roles(template).includes('services'), 'services is a macOS concept');
  assert.ok(!roles(template).includes('hideOthers'), 'hideOthers is a macOS concept');
});

test('Reload is a handler this process owns rather than the built-in role', () => {
  // The built-in reload re-loads the document's own URL. The console takes its token from the URL
  // fragment and erases it, so that URL lands on the token gate — in a window whose whole purpose
  // is that nobody has to paste a token.
  const template = menuTemplate({ platform: 'darwin', appName: 'Warrantor', handlers });
  const view = template.find((menu) => menu.label === 'View');
  const reload = view.submenu.find((item) => item.label === 'Reload');
  assert.equal(typeof reload.click, 'function');
  assert.ok(!('role' in reload), 'the built-in reload role would strand the session');
});

test('About is reachable on every platform', () => {
  for (const platform of ['darwin', 'win32', 'linux']) {
    const template = menuTemplate({ platform, appName: 'Warrantor', handlers });
    const found = template
      .flatMap((menu) => menu.submenu ?? [])
      .some((item) => typeof item.label === 'string' && item.label.startsWith('About'));
    assert.ok(found, `${platform} must be able to answer "which binary is this"`);
  }
});

// ── remembered geometry ───────────────────────────────────────────────────────────────

const ONE_SCREEN = [{ x: 0, y: 0, width: 1920, height: 1040 }];

test('nothing remembered gives the default size and no position', () => {
  const state = sanitiseWindowState(null, ONE_SCREEN);
  assert.equal(state.width, DEFAULT_WINDOW_STATE.width);
  assert.equal(state.height, DEFAULT_WINDOW_STATE.height);
  assert.equal(state.x, undefined, 'absent coordinates let the platform centre the window');
});

test('a position on a monitor that is gone is discarded, not restored', () => {
  // The standard way an application becomes unopenable: a window remembered on a second monitor,
  // restored after that monitor is unplugged, opens where no display is — visible nowhere,
  // focusable by nothing, recoverable only by deleting a file the user does not know exists.
  const state = sanitiseWindowState({ x: 3000, y: 200, width: 1000, height: 700 }, ONE_SCREEN);
  assert.equal(state.x, undefined);
  assert.equal(state.width, 1000, 'the size is still worth keeping');
});

test('a position that is still on a screen is kept', () => {
  const state = sanitiseWindowState({ x: 120, y: 90, width: 1000, height: 700 }, ONE_SCREEN);
  assert.equal(state.x, 120);
  assert.equal(state.y, 90);
});

test('a window remembered larger than the screen is clamped rather than refused', () => {
  const state = sanitiseWindowState({ width: 5000, height: 5000 }, ONE_SCREEN);
  assert.equal(state.width, 1920);
  assert.equal(state.height, 1040);
});

test('a window remembered smaller than usable is raised to the minimum', () => {
  const state = sanitiseWindowState({ width: 10, height: 10 }, ONE_SCREEN);
  assert.equal(state.width, 720);
  assert.equal(state.height, 480);
});

test('a corrupt state file is never a reason the application will not open', () => {
  for (const rubbish of [undefined, 'not an object', 42, [], { width: NaN, height: 'tall' }]) {
    const state = sanitiseWindowState(rubbish, ONE_SCREEN);
    assert.ok(Number.isFinite(state.width) && state.width >= 720, `failed on ${String(rubbish)}`);
    assert.ok(Number.isFinite(state.height) && state.height >= 480);
  }
});

test('no displays at all still yields something openable', () => {
  const state = sanitiseWindowState({ x: 10, y: 10, width: 900, height: 600 }, []);
  assert.equal(state.width, 900);
  assert.equal(state.x, undefined, 'nothing can be shown to be on-screen, so nothing is asserted');
});

test('maximised is remembered as a flag, not as a size equal to the screen', () => {
  const state = sanitiseWindowState(
    { x: 0, y: 0, width: 1100, height: 800, maximized: true },
    ONE_SCREEN,
  );
  assert.equal(state.maximized, true);
  assert.equal(state.width, 1100, 'the un-maximised size is what a restore returns to');
});

// ── the agent dying ───────────────────────────────────────────────────────────────────

test('a dead agent is explained, and says the store survived it', () => {
  // The console recovers silently when an agent comes back, which is right for a hiccup and wrong
  // for a death — so the death is the shell's to report, and it is the only party that knows.
  const message = agentExitMessage(1, null);
  assert.match(message, /exited with code 1/);
  assert.match(message, /Nothing has been lost/);
  assert.match(message, /store on disk/);
});

test('a killed agent names the signal rather than a misleading exit code', () => {
  const message = agentExitMessage(null, 'SIGTERM');
  assert.match(message, /terminated by SIGTERM/);
});

test('an agent that exited cleanly is still reported as gone', () => {
  // Exit 0 is not "fine" here: the window is still open and still showing a console with nothing
  // behind it. Treating a clean exit as unremarkable is how the silent case shipped.
  const message = agentExitMessage(0, null);
  assert.match(message, /exited normally/);
  assert.match(message, /cannot reach anything/);
});

// ── the tray and the notification ───────────────────────────────────────────

test('an unreachable agent is never counted as zero open warrants', () => {
  // "No agent running" is the sentence somebody closes their laptop on. A failed read must not
  // produce it: unknown and zero are opposite facts here.
  for (const response of [
    { answered: false, status: 0, payload: null },
    { answered: true, status: 500, payload: null },
    { answered: true, status: 200, payload: { data: {} } },
  ]) {
    const summary = traySummary(response);
    assert.equal(summary.open, null, JSON.stringify(response));
    assert.doesNotMatch(summary.label, /no agent running/i);
  }
});

test('the tray counts only open warrants and says so in words', () => {
  const summary = traySummary({
    answered: true,
    status: 200,
    payload: {
      data: {
        warrants: [
          { id: 'a', state: 'open' },
          { id: 'b', state: 'settled' },
          { id: 'c', state: 'open' },
        ],
      },
    },
  });
  assert.equal(summary.open, 2);
  assert.match(summary.label, /2 warrants open/);

  const one = traySummary({
    answered: true,
    status: 200,
    payload: { data: { warrants: [{ id: 'a', state: 'open' }] } },
  });
  assert.match(one.label, /1 warrant open/, 'singular, because a tooltip is read as a sentence');
});

test('a waiting warrant notifies once, not every poll', () => {
  // Notifying on a level rather than a transition is how somebody learns to dismiss notifications
  // without reading them, and the one that mattered goes with the rest.
  const seen = new Set();
  const held = {
    answered: true,
    status: 200,
    payload: { data: { warrants: [{ id: 'w1', state: 'held', goal: 'fix the parser' }] } },
  };
  assert.equal(newlyWaiting(held, seen).length, 1);
  assert.equal(newlyWaiting(held, seen).length, 0, 'the second poll is silent');
  assert.equal(newlyWaiting(held, seen).length, 0);
});

test('a failed read neither notifies nor forgets what is waiting', () => {
  // Treating an unreadable answer as "nothing is waiting any more" would re-notify for every
  // warrant the moment the agent came back.
  const seen = new Set();
  const held = {
    answered: true,
    status: 200,
    payload: { data: { warrants: [{ id: 'w1', state: 'held', goal: 'g' }] } },
  };
  assert.equal(newlyWaiting(held, seen).length, 1);
  assert.equal(newlyWaiting({ answered: false, status: 0, payload: null }, seen).length, 0);
  assert.ok(seen.has('w1'), 'the failed read must not clear what is known');
  assert.equal(newlyWaiting(held, seen).length, 0, 'and must not cause a re-notify');
});

test('a warrant that is decided and held again notifies again, because that is two decisions', () => {
  const seen = new Set();
  const held = {
    answered: true,
    status: 200,
    payload: { data: { warrants: [{ id: 'w1', state: 'held', goal: 'g' }] } },
  };
  const settled = {
    answered: true,
    status: 200,
    payload: { data: { warrants: [{ id: 'w1', state: 'settled', goal: 'g' }] } },
  };
  assert.equal(newlyWaiting(held, seen).length, 1);
  assert.equal(newlyWaiting(settled, seen).length, 0);
  assert.ok(!seen.has('w1'), 'leaving the waiting state forgets it');
  assert.equal(newlyWaiting(held, seen).length, 1);
});

test('only held warrants are treated as waiting for a decision', () => {
  // `open` is still running and settled/void are decided. Notifying on any of those would make the
  // notification mean "something happened", which is not actionable.
  const seen = new Set();
  const response = {
    answered: true,
    status: 200,
    payload: {
      data: {
        warrants: [
          { id: 'a', state: 'open' },
          { id: 'b', state: 'settled' },
          { id: 'c', state: 'void' },
        ],
      },
    },
  };
  assert.deepEqual(newlyWaiting(response, seen), []);
});

test('the notification leads with the goal, because a hex id is not recognisable in a second', () => {
  const { title, body } = waitingNotification({ id: 'wrt_abc', goal: 'fix the parser' });
  assert.match(title, /waiting for a decision/);
  assert.ok(body.startsWith('fix the parser'), body);
  assert.match(body, /wrt_abc/);
  // A warrant with no goal still names itself rather than showing an empty line.
  assert.equal(waitingNotification({ id: 'wrt_abc', goal: '' }).body, 'wrt_abc');
});
