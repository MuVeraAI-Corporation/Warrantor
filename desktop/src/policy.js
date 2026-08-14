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
 * The name the agent executable carries on this platform.
 *
 * @param {string} platform - a `process.platform` value
 * @returns {string}
 */
export function agentExecutableName(platform) {
  return platform === 'win32' ? 'warrantor.exe' : 'warrantor';
}

/**
 * Where to look for the agent, in descending order of authority.
 *
 * This is a security decision, not a convenience one. Verification happens only in Rust and only in
 * this binary, so substituting the binary substitutes the verifier — and a verifier chosen by
 * something other than the person who installed the app is a verifier nobody audited. An installed
 * application must therefore not be re-pointed at a different agent by an environment variable that
 * any parent process can set.
 *
 * Hence the order: the copy shipped inside the installer wins outright; `WARRANTOR_BIN` is for the
 * development case where there is no bundled copy; the bare name handed to `spawn` for `PATH`
 * resolution is the last resort and is what `npm start` uses today.
 *
 * The bundled candidate is emitted only when the app is packaged. In development
 * `process.resourcesPath` points inside `node_modules/electron/dist/resources`, and a stale file
 * left there by an earlier experiment would be picked up as if it had been shipped.
 *
 * Joins with a literal separator rather than `node:path` so this module keeps importing nothing,
 * which is what lets CI gate it with no Electron and no display.
 *
 * @param {{isPackaged: boolean, resourcesPath: string, warrantorBin: string|undefined,
 *          platform: string}} environment
 * @returns {Array<{path: string, source: 'bundled'|'env'|'path'}>} ordered, never empty
 */
export function agentBinaryCandidates({ isPackaged, resourcesPath, warrantorBin, platform }) {
  const name = agentExecutableName(platform);
  const candidates = [];

  if (isPackaged === true && typeof resourcesPath === 'string' && resourcesPath !== '') {
    const separator = platform === 'win32' ? '\\' : '/';
    const alreadyEnds = resourcesPath.endsWith('/') || resourcesPath.endsWith('\\');
    candidates.push({
      path: `${resourcesPath}${alreadyEnds ? '' : separator}${name}`,
      source: 'bundled',
    });
  }

  // An empty or non-string value is *no instruction*, not an instruction to run "". Left unchecked
  // it becomes a candidate for the empty path, which fails at spawn with a message about nothing.
  if (typeof warrantorBin === 'string' && warrantorBin.trim() !== '') {
    candidates.push({ path: warrantorBin, source: 'env' });
  }

  candidates.push({ path: name, source: 'path' });
  return candidates;
}

/** Human wording for a candidate's source, for the one place a person reads it: an error dialog. */
export function describeBinarySource(source) {
  if (source === 'bundled') return 'bundled with the app';
  if (source === 'env') return 'WARRANTOR_BIN';
  return 'PATH';
}

/**
 * Choose the agent binary from an ordered candidate list.
 *
 * **There is no fallthrough, deliberately.** The list is ordered by authority and the head wins; a
 * head that does not exist is a fatal error rather than a reason to try the next entry. Falling
 * through would mean a packaged app with a damaged install, or an operator whose `WARRANTOR_BIN`
 * has a typo in it, silently runs a *different verifier* than the one that was chosen — which is
 * the whole failure this ordering exists to prevent, and it would be invisible because the app
 * would start and look correct.
 *
 * The consequence, stated so it is a decision rather than an accident: in a packaged build
 * `WARRANTOR_BIN` cannot override the bundled agent. Anyone who needs a different agent should run
 * `warrantor console`, or the shell from source.
 *
 * The `path` candidate cannot be probed — resolving it is `spawn`'s job — so it is handed over
 * as-is and a missing `PATH` entry surfaces as a spawn error naming it.
 *
 * @param {Array<{path: string, source: string}>} candidates
 * @param {(path: string) => boolean} exists
 * @returns {{binary: {path: string, source: string}|null, error: string|null}}
 */
export function resolveAgentBinary(candidates, exists) {
  const [chosen] = candidates;
  if (!chosen) return { binary: null, error: 'no agent binary was configured' };
  if (chosen.source === 'path' || exists(chosen.path)) return { binary: chosen, error: null };
  return {
    binary: null,
    error:
      `the agent binary (${describeBinarySource(chosen.source)}) is not at ${chosen.path}. ` +
      (chosen.source === 'bundled'
        ? 'This install is incomplete; reinstall rather than running a different agent.'
        : 'Correct WARRANTOR_BIN or unset it.'),
  };
}

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
