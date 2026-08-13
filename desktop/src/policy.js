/**
 * The desktop shell's security policy, as pure functions.
 *
 * This file imports nothing. That is the point: the decisions that matter — which URL the window
 * may navigate to, which permissions are granted, which token line to believe — are the ones most
 * worth testing, and they are exactly the ones that become untestable when written inline in an
 * Electron callback. Everything here runs under `node --test` with no Electron and no display.
 *
 * The shell is a *viewer around a viewer*. It renders the console that `warrantor serve` serves,
 * and the console renders a verdict computed in Rust. Neither layer verifies anything, and neither
 * may be allowed to start. So the policy below is written to keep the window pointed at exactly one
 * origin — the local agent this process started — and nowhere else, ever.
 */

/** Permissions the renderer is allowed to request. Deliberately empty. */
const GRANTED_PERMISSIONS = Object.freeze([]);

/**
 * Is this a URL the window may navigate to?
 *
 * An allowlist of one origin, compared after parsing rather than by string prefix. A prefix test is
 * how `http://127.0.0.1:8787.evil.com/` gets through: it starts with the expected text and is a
 * different host. Parsing and comparing `origin` makes that class impossible rather than guarded
 * against.
 *
 * @param {string} candidate - the URL Electron is about to navigate to
 * @param {string} agentOrigin - e.g. "http://127.0.0.1:8787"
 * @returns {boolean}
 */
export function isNavigationAllowed(candidate, agentOrigin) {
  if (typeof candidate !== 'string' || typeof agentOrigin !== 'string') return false;
  let target;
  let allowed;
  try {
    target = new URL(candidate);
    allowed = new URL(agentOrigin);
  } catch {
    return false;
  }
  // `origin` folds scheme, host and port together, so a match cannot be produced by a lookalike
  // host or by the same host on another port.
  return target.origin === allowed.origin;
}

/**
 * Should this permission request be granted?
 *
 * Always no. The console reads a local store and renders JSON; it has no use for a camera, a
 * microphone, a location, a notification or the clipboard, and a shell that grants what it does not
 * need is a shell whose compromise is worth more than it should be.
 *
 * @param {string} _permission
 * @returns {boolean}
 */
export function isPermissionGranted(_permission) {
  return GRANTED_PERMISSIONS.length > 0;
}

/**
 * Pull the session token out of a line of `warrantor serve` output.
 *
 * The server prints `  token         <64 hex>`. Matching the shape rather than the label alone
 * means a future change to the surrounding text cannot silently produce a token of the wrong thing,
 * and an anchored 64-hex pattern cannot match the `console` or `try` lines, which contain the token
 * embedded in a URL.
 *
 * @param {string} line
 * @returns {string|null}
 */
export function tokenFromLine(line) {
  if (typeof line !== 'string') return null;
  const match = /^\s*token\s+([0-9a-f]{64})\s*$/.exec(line);
  return match ? match[1] : null;
}

/**
 * Pull the origin the server bound to out of its output.
 *
 * The server prints `warrantor: serving <path> on http://127.0.0.1:8787`. The path can contain
 * anything, including the word "on", so the URL is taken from the end of the line rather than by
 * splitting on a word.
 *
 * @param {string} line
 * @returns {string|null}
 */
export function originFromLine(line) {
  if (typeof line !== 'string') return null;
  const match = /(http:\/\/[0-9a-zA-Z.:[\]-]+)\s*$/.exec(line);
  if (!match) return null;
  try {
    return new URL(match[1]).origin;
  } catch {
    return null;
  }
}

/**
 * Build the URL that opens an authenticated console.
 *
 * The token goes in the fragment for the same reason `warrantor console` puts it there: a fragment
 * is never sent to a server, so it cannot reach an access log or a `Referer`. Here it additionally
 * never reaches a command line, because the shell hands it to `loadURL` in-process.
 *
 * @param {string} origin
 * @param {string} token
 * @returns {string}
 */
export function consoleUrl(origin, token) {
  return `${new URL(origin).origin}/#t=${token}`;
}

/**
 * Redact a token wherever it appears in text bound for a log.
 *
 * `warrantor serve` prints the token three times — on its own line, in the console URL and in the
 * suggested curl. The shell forwards the child's output so an operator can see a bind failure, and
 * forwarding it verbatim would write the session secret into every log that captures stdout.
 *
 * @param {string} text
 * @param {string|null} token
 * @returns {string}
 */
export function redactToken(text, token) {
  if (typeof text !== 'string') return '';
  if (!token) return text;
  return text.split(token).join('<redacted>');
}
