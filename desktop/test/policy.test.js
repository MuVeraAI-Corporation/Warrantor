/**
 * The desktop shell's policy, tested without Electron.
 *
 * These run under `node --test` with no display, no Chromium and no binary download, which is the
 * reason the policy is a separate module in the first place. The security-critical decisions in an
 * Electron app are usually three lines inside a callback that no test ever reaches; here they are
 * functions, and a wrong one fails a test rather than shipping.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  agentBinaryCandidates,
  agentExecutableName,
  consoleUrl,
  firstRunRemedy,
  isNavigationAllowed,
  isPermissionGranted,
  originFromLine,
  redactToken,
  resolveAgentBinary,
  tokenFromLine,
} from '../src/policy.js';

const AGENT = 'http://127.0.0.1:8787';

// ── navigation ────────────────────────────────────────────────────────────────

test('the agent origin is allowed, with and without a path or fragment', () => {
  assert.equal(isNavigationAllowed('http://127.0.0.1:8787/', AGENT), true);
  assert.equal(isNavigationAllowed('http://127.0.0.1:8787/#t=abc', AGENT), true);
  assert.equal(isNavigationAllowed('http://127.0.0.1:8787/v1/health', AGENT), true);
});

/**
 * The test this module exists for.
 *
 * Every entry here starts with the expected text and is a different origin. A prefix comparison —
 * the obvious implementation — admits all of them.
 */
test('a lookalike origin is refused however closely it resembles the agent', () => {
  for (const hostile of [
    'http://127.0.0.1:8787.evil.com/',
    'http://127.0.0.1:8787@evil.com/',
    'http://127.0.0.1:8788/',
    'https://127.0.0.1:8787/',
    'http://127.0.0.1.evil.com:8787/',
    'http://localhost:8787/',
  ]) {
    assert.equal(
      isNavigationAllowed(hostile, AGENT),
      false,
      `${hostile} must not be treated as the agent`,
    );
  }
});

test('non-http schemes are refused', () => {
  for (const hostile of [
    'file:///etc/passwd',
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'chrome://settings',
  ]) {
    assert.equal(isNavigationAllowed(hostile, AGENT), false, `${hostile} must be refused`);
  }
});

test('garbage in is refused rather than thrown on', () => {
  assert.equal(isNavigationAllowed('not a url', AGENT), false);
  assert.equal(isNavigationAllowed('', AGENT), false);
  assert.equal(isNavigationAllowed(null, AGENT), false);
  assert.equal(isNavigationAllowed(undefined, AGENT), false);
  assert.equal(isNavigationAllowed('http://127.0.0.1:8787/', 'not a url'), false);
});

// ── permissions ───────────────────────────────────────────────────────────────

test('every permission is denied', () => {
  for (const permission of [
    'media',
    'geolocation',
    'notifications',
    'midi',
    'pointerLock',
    'fullscreen',
    'openExternal',
    'clipboard-read',
    'display-capture',
    'anything-added-in-a-future-electron',
  ]) {
    assert.equal(isPermissionGranted(permission), false, `${permission} must be denied`);
  }
});

// ── reading the agent's output ────────────────────────────────────────────────

test('the token is read from the line that carries it alone', () => {
  const token = 'a'.repeat(64);
  assert.equal(tokenFromLine(`  token         ${token}`), token);
  assert.equal(tokenFromLine(`token ${token}`), token);
});

/**
 * `warrantor serve` prints the token three times: on its own line, inside the console URL, and
 * inside the suggested curl. Only the first is the token line, and matching the others would still
 * "work" today while breaking the moment the surrounding text changes.
 */
test('the token is not read out of the console or curl lines', () => {
  const token = 'b'.repeat(64);
  assert.equal(tokenFromLine(`  console       http://127.0.0.1:8787/#t=${token}`), null);
  assert.equal(
    tokenFromLine(`  try           curl -H "authorization: Bearer ${token}" http://x/v1/health`),
    null,
  );
});

test('a token of the wrong shape is not accepted', () => {
  assert.equal(tokenFromLine('  token         short'), null);
  assert.equal(tokenFromLine(`  token         ${'a'.repeat(63)}`), null);
  assert.equal(tokenFromLine(`  token         ${'A'.repeat(64)}`), null, 'uppercase is not minted');
  assert.equal(tokenFromLine(`  token         ${'z'.repeat(64)}`), null, 'z is not hex');
  assert.equal(tokenFromLine('  token file    C:/x/token'), null);
  assert.equal(tokenFromLine(null), null);
});

test('the origin is read from the end of the serving line', () => {
  assert.equal(
    originFromLine('warrantor: serving /home/x/.warrantor on http://127.0.0.1:8787'),
    'http://127.0.0.1:8787',
  );
});

/**
 * The store path is operator-controlled and can contain anything, including the word this line
 * would otherwise be split on.
 */
test('a store path containing "on" does not confuse the origin', () => {
  assert.equal(
    originFromLine('warrantor: serving /home/on/on some on path on http://127.0.0.1:9999'),
    'http://127.0.0.1:9999',
  );
});

test('a line with no origin yields null', () => {
  assert.equal(originFromLine('  token file    /home/x/.warrantor/serve/token'), null);
  assert.equal(originFromLine(''), null);
  assert.equal(originFromLine(null), null);
});

// ── the URL that gets loaded ──────────────────────────────────────────────────

test('the token is placed in the fragment, never the query', () => {
  const url = new URL(consoleUrl('http://127.0.0.1:8787', 'c'.repeat(64)));
  assert.equal(url.hash, `#t=${'c'.repeat(64)}`);
  assert.equal(url.search, '', 'a query string would be sent to the server and logged');
  assert.equal(url.pathname, '/');
});

// ── redaction ─────────────────────────────────────────────────────────────────

test('every occurrence of the token is redacted from forwarded output', () => {
  const token = 'd'.repeat(64);
  const line = `console http://x/#t=${token} and curl -H "Bearer ${token}"`;
  const safe = redactToken(line, token);
  assert.equal(safe.includes(token), false, 'no occurrence may survive');
  assert.equal(safe, 'console http://x/#t=<redacted> and curl -H "Bearer <redacted>"');
});

test('redaction is a no-op before a token is known', () => {
  assert.equal(redactToken('warrantor: cannot bind', null), 'warrantor: cannot bind');
  assert.equal(redactToken(null, 'x'), '');
});

// ── binary resolution ─────────────────────────────────────────────────────────
//
// Which binary the shell spawns selects the verifier, because verification happens only in Rust and
// only in that binary. The ordering below is therefore a security property, and an untested
// ordering is an asserted one.

const sources = (candidates) => candidates.map((candidate) => candidate.source);

test('the bundled agent outranks everything else in a packaged app', () => {
  const candidates = agentBinaryCandidates({
    isPackaged: true,
    resourcesPath: '/Applications/Warrantor.app/Contents/Resources',
    warrantorBin: '/home/x/other/warrantor',
    platform: 'darwin',
  });
  assert.deepEqual(sources(candidates), ['bundled', 'env', 'path']);
  assert.equal(candidates[0].path, '/Applications/Warrantor.app/Contents/Resources/warrantor');
});

/**
 * The mistake this catches: in development `process.resourcesPath` points inside
 * `node_modules/electron/dist/resources`. A stale binary left there by an earlier experiment would
 * be picked up as though it had been shipped, and it would outrank the one the developer meant.
 */
test('no bundled candidate exists outside a packaged app, resourcesPath or not', () => {
  const candidates = agentBinaryCandidates({
    isPackaged: false,
    resourcesPath: '/repo/desktop/node_modules/electron/dist/resources',
    warrantorBin: undefined,
    platform: 'linux',
  });
  assert.deepEqual(sources(candidates), ['path']);
});

test('the executable name carries .exe only on Windows', () => {
  assert.equal(agentExecutableName('win32'), 'warrantor.exe');
  assert.equal(agentExecutableName('darwin'), 'warrantor');
  assert.equal(agentExecutableName('linux'), 'warrantor');
  const windows = agentBinaryCandidates({
    isPackaged: true,
    resourcesPath: 'C:\\Users\\x\\AppData\\Local\\Programs\\Warrantor\\resources',
    warrantorBin: undefined,
    platform: 'win32',
  });
  assert.equal(
    windows[0].path,
    'C:\\Users\\x\\AppData\\Local\\Programs\\Warrantor\\resources\\warrantor.exe',
  );
});

test('a resourcesPath that already ends in a separator does not gain a second one', () => {
  const [bundled] = agentBinaryCandidates({
    isPackaged: true,
    resourcesPath: '/opt/Warrantor/resources/',
    warrantorBin: undefined,
    platform: 'linux',
  });
  assert.equal(bundled.path, '/opt/Warrantor/resources/warrantor');
});

test('WARRANTOR_BIN ranks below the bundled agent and above PATH', () => {
  const withEnv = agentBinaryCandidates({
    isPackaged: false,
    resourcesPath: '',
    warrantorBin: '/home/x/rust/target/release/warrantor',
    platform: 'linux',
  });
  assert.deepEqual(sources(withEnv), ['env', 'path']);
  assert.equal(withEnv[0].path, '/home/x/rust/target/release/warrantor');
});

/**
 * An unset, empty or whitespace value is *no instruction*, not an instruction to run "". Unchecked
 * it becomes a candidate for the empty path, and `spawn('')` fails with a message about nothing —
 * on Windows, in a GUI-subsystem binary, where that message is the only diagnosis available.
 */
test('an empty or non-string WARRANTOR_BIN produces no candidate at all', () => {
  for (const value of ['', '   ', undefined, null, 0, {}]) {
    const candidates = agentBinaryCandidates({
      isPackaged: false,
      resourcesPath: '',
      warrantorBin: value,
      platform: 'linux',
    });
    assert.deepEqual(sources(candidates), ['path'], `WARRANTOR_BIN=${String(value)}`);
  }
});

test('the last candidate is always the bare name, for PATH resolution', () => {
  for (const platform of ['win32', 'darwin', 'linux']) {
    const candidates = agentBinaryCandidates({
      isPackaged: true,
      resourcesPath: '/r',
      warrantorBin: '/e/warrantor',
      platform,
    });
    const last = candidates[candidates.length - 1];
    assert.equal(last.source, 'path');
    assert.equal(last.path, agentExecutableName(platform));
  }
});

// ── choosing from the candidates: there is no fallthrough ─────────────────────

test('the bundled agent is chosen when it is there', () => {
  const candidates = agentBinaryCandidates({
    isPackaged: true,
    resourcesPath: '/r',
    warrantorBin: undefined,
    platform: 'linux',
  });
  const { binary, error } = resolveAgentBinary(candidates, (path) => path === '/r/warrantor');
  assert.equal(error, null);
  assert.deepEqual(binary, { path: '/r/warrantor', source: 'bundled' });
});

/**
 * The property this whole ordering exists for. A packaged app whose bundled agent is missing has a
 * damaged install; running whatever `warrantor` happens to be on `PATH` instead would start
 * normally and look correct while using a verifier nobody chose. It fails loudly instead.
 */
test('a missing bundled agent is fatal rather than a reason to try PATH', () => {
  const candidates = agentBinaryCandidates({
    isPackaged: true,
    resourcesPath: '/r',
    warrantorBin: '/e/warrantor',
    platform: 'linux',
  });
  const { binary, error } = resolveAgentBinary(candidates, () => false);
  assert.equal(binary, null);
  assert.match(error, /\/r\/warrantor/);
  assert.match(error, /bundled/);
});

/** An explicit instruction that is silently ignored substitutes a verifier the operator did not ask for. */
test('a WARRANTOR_BIN that does not exist is fatal rather than a reason to try PATH', () => {
  const candidates = agentBinaryCandidates({
    isPackaged: false,
    resourcesPath: '',
    warrantorBin: '/typo/warrantor',
    platform: 'linux',
  });
  const { binary, error } = resolveAgentBinary(candidates, () => false);
  assert.equal(binary, null);
  assert.match(error, /WARRANTOR_BIN/);
  assert.match(error, /\/typo\/warrantor/);
});

/** `PATH` cannot be probed from here — resolving it is `spawn`'s job — so it is handed over as-is. */
test('the PATH candidate is used without being probed', () => {
  const candidates = agentBinaryCandidates({
    isPackaged: false,
    resourcesPath: '',
    warrantorBin: undefined,
    platform: 'win32',
  });
  const { binary, error } = resolveAgentBinary(candidates, () => {
    throw new Error('the PATH candidate must never be probed');
  });
  assert.equal(error, null);
  assert.deepEqual(binary, { path: 'warrantor.exe', source: 'path' });
});

// ── the first run on a machine with no identity ──────────────────────────────────────

/**
 * Found by launching the packaged Linux app against a home directory that had never run
 * `warrantor`: the bundled agent resolved, started, and exited 1 for want of an issuer key. That
 * refusal is deliberate and correct — a server that minted an identity on first use would sign
 * evidence with a key nobody chose — and it is also the reviewer's exact path. Install,
 * double-click, dead, with the cause in a log nobody opens.
 */
test('a missing issuer key becomes a route out, not a generic error', () => {
  const remedy = firstRunRemedy(
    'warrantor: no issuer key was found. `warrantor serve` loads keys and never creates them.',
  );
  assert.ok(remedy, 'the known refusal must be recognised');
  assert.match(remedy.command, /^warrantor grant /, 'only `grant` creates the issuer key');
  // The command must commit the holder to nothing: read-only tools, and a deadline short enough
  // that a warrant created to mint a key is not the first thing waiting in the reviewer's queue.
  assert.match(remedy.command, /--tools read_file\b/);
  assert.match(remedy.command, /--deadline 1h\b/);
  assert.doesNotMatch(remedy.command, /write_file|--allow-settle/);
  // And it must say WHY the agent refused, or it reads as a bug rather than a design.
  assert.match(remedy.detail, /nobody chose/);
});

test('an unrelated failure gets no first-run screen', () => {
  // A first-run screen shown for something else sends somebody to create a key they already have,
  // and hides the real cause behind a confident wrong answer.
  for (const other of [
    'EADDRINUSE: address already in use 127.0.0.1:8787',
    'could not start /opt/Warrantor/resources/warrantor: ENOENT',
    'did not announce a token within 20 seconds',
    '',
    null,
    undefined,
  ]) {
    assert.equal(firstRunRemedy(other), null, `${other} must fall through to the generic error`);
  }
});
