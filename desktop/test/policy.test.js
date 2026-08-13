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
  consoleUrl,
  isNavigationAllowed,
  isPermissionGranted,
  originFromLine,
  redactToken,
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
