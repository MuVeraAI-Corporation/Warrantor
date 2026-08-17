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
 * The application menu, per platform.
 *
 * Written here rather than inline because two of its items are correctness rather than decoration,
 * and both were missing:
 *
 * **Paste.** On macOS the standard editing shortcuts are delivered *through the menu*. A window
 * with no Edit menu containing `role: 'paste'` cannot paste, at all, with ⌘V — the keystroke has
 * nowhere to go. The first version of this menu had `copy` and `selectAll` and neither `paste` nor
 * `cut` nor `undo`, so the console's token field could be typed into and not pasted into, on the
 * one platform where that is the difference between working and not.
 *
 * **The application menu.** On macOS the first submenu is the app menu whatever it is called, and
 * it is where `about`, `hide`, `services` and `quit` live. Replacing the whole menu without one
 * removes Hide, Services and the standard Quit item from an application that has no other route to
 * them.
 *
 * Reload survives from the first version and keeps its reason: the console takes its token from the
 * URL fragment and erases it, so reloading the document's own URL lands on the token gate in a
 * window whose entire purpose is that nobody has to paste a token. The handler re-loads the
 * *authenticated* URL, which the shell can do and the page cannot, because the token lives in this
 * process.
 *
 * The rest of Electron's default menu is still dropped. This window shows a verdict; File and
 * Window items that do nothing here are worse than absent.
 *
 * @param {{platform: string, appName: string,
 *          handlers: {reload: () => void, about: () => void}}} options
 * @returns {Array<object>} an Electron menu template
 */
export function menuTemplate({ platform, appName, handlers }) {
  const isMac = platform === 'darwin';
  const template = [];

  if (isMac) {
    template.push({
      label: appName,
      submenu: [
        { label: `About ${appName}`, click: handlers.about },
        { type: 'separator' },
        { role: 'services' },
        { type: 'separator' },
        { role: 'hide' },
        { role: 'hideOthers' },
        { role: 'unhide' },
        { type: 'separator' },
        { role: 'quit' },
      ],
    });
  }

  template.push({
    label: 'View',
    submenu: [
      { label: 'Reload', accelerator: 'CmdOrCtrl+R', click: handlers.reload },
      { type: 'separator' },
      { role: 'resetZoom' },
      { role: 'zoomIn' },
      { role: 'zoomOut' },
      { type: 'separator' },
      { role: 'togglefullscreen' },
      // Kept for support: "what does the console actually say" is answered here, and the renderer
      // has no privileges for it to expose.
      { role: 'toggleDevTools' },
    ],
  });

  template.push({
    label: 'Edit',
    submenu: [
      { role: 'undo' },
      { role: 'redo' },
      { type: 'separator' },
      { role: 'cut' },
      { role: 'copy' },
      { role: 'paste' },
      { role: 'selectAll' },
    ],
  });

  template.push({
    label: 'Window',
    submenu: isMac
      ? [{ role: 'minimize' }, { role: 'zoom' }, { type: 'separator' }, { role: 'front' }]
      : [{ role: 'minimize' }, { role: 'close' }],
  });

  if (!isMac) {
    template.push({
      label: 'Help',
      submenu: [{ label: `About ${appName}`, click: handlers.about }],
    });
  }

  return template;
}

/** The window geometry used when nothing has been remembered. */
export const DEFAULT_WINDOW_STATE = Object.freeze({ width: 1280, height: 860 });

/**
 * Turn a remembered window position into one that is safe to open.
 *
 * Restoring geometry verbatim is the standard way an application becomes unopenable: a window
 * remembered on a second monitor, restored after that monitor is gone, opens at coordinates no
 * display contains — visible nowhere, focusable by nothing, and with no way for the user to get it
 * back other than deleting a file they do not know exists.
 *
 * So a remembered position is kept only when it lands inside some display's work area, with enough
 * of the title bar reachable to drag. Anything else falls back to centring, which every platform
 * does correctly on its own when `x`/`y` are absent.
 *
 * Size is clamped rather than discarded: a window larger than the current display is a nuisance, a
 * window at the wrong place is a support ticket.
 *
 * @param {unknown} saved - whatever was in the state file, which may be anything at all
 * @param {Array<{x: number, y: number, width: number, height: number}>} workAreas
 * @returns {{width: number, height: number, x?: number, y?: number, maximized: boolean}}
 */
export function sanitiseWindowState(saved, workAreas) {
  const state = saved && typeof saved === 'object' ? saved : {};
  const number = (value, fallback) =>
    typeof value === 'number' && Number.isFinite(value) ? value : fallback;

  const areas = Array.isArray(workAreas) ? workAreas : [];
  const widest = areas.reduce((max, a) => Math.max(max, number(a?.width, 0)), 0);
  const tallest = areas.reduce((max, a) => Math.max(max, number(a?.height, 0)), 0);

  let width = Math.max(720, Math.round(number(state.width, DEFAULT_WINDOW_STATE.width)));
  let height = Math.max(480, Math.round(number(state.height, DEFAULT_WINDOW_STATE.height)));
  if (widest > 0) width = Math.min(width, widest);
  if (tallest > 0) height = Math.min(height, tallest);

  const result = { width, height, maximized: state.maximized === true };

  const x = number(state.x, null);
  const y = number(state.y, null);
  if (x === null || y === null) return result;

  // "Enough of it is reachable": the top-left corner plus a strip of title bar has to be inside
  // some work area. Requiring the whole window to fit would refuse a window the user had
  // deliberately hung off the edge of their screen, which is theirs to do.
  const REACHABLE = 80;
  const landsSomewhere = areas.some((area) => {
    const ax = number(area?.x, 0);
    const ay = number(area?.y, 0);
    const aw = number(area?.width, 0);
    const ah = number(area?.height, 0);
    return (
      x + REACHABLE > ax && x < ax + aw && y + 24 > ay && y < ay + ah - 24
    );
  });
  if (!landsSomewhere) return result;

  return { ...result, x: Math.round(x), y: Math.round(y) };
}

/**
 * The sentence shown when the agent dies *after* the window has opened.
 *
 * Previously nothing was shown at all. The child's `exit` handler returned early once startup had
 * settled, so an agent that crashed or was killed left a window rendering a console that could not
 * reach anything — and because the console recovers silently when the agent comes back, its
 * "no answer" state is deliberately quiet. Quiet is right for a hiccup and wrong for a death.
 *
 * @param {number|null} code
 * @param {string|null} signal
 * @returns {string}
 */
export function agentExitMessage(code, signal) {
  const how = signal
    ? `was terminated by ${signal}`
    : code === 0
      ? 'exited normally'
      : `exited with code ${code}`;
  return (
    `The Warrantor agent ${how}.\n\n` +
    'This window is now showing a console that cannot reach anything. Nothing has been lost: ' +
    'warrants, evidence and staged effects live in the store on disk, not in this process. ' +
    'Relaunching starts a new agent and a new session.'
  );
}

/**
 * What the tray should say, from a list response.
 *
 * A pure function over the payload, so the one thing that could be wrong here — deciding a run is
 * finished when the read merely failed — is testable without an Electron process.
 *
 * `null` means **the count is unknown**, and it is a distinct return from zero. A read that failed
 * and a store with nothing open are opposite facts: the first must not quietly render as "no agents
 * running", because that is the sentence somebody closes their laptop on.
 *
 * @param {{answered: boolean, status: number, payload: unknown}} response
 * @returns {{open: number|null, label: string}}
 */
export function traySummary({ answered, status, payload }) {
  if (!answered || status !== 200) {
    return { open: null, label: 'Warrantor — cannot reach the agent' };
  }
  const warrants = payload?.data?.warrants;
  if (!Array.isArray(warrants)) {
    return { open: null, label: 'Warrantor — the agent answered unreadably' };
  }
  const open = warrants.filter((w) => w?.state === 'open').length;
  if (open === 0) return { open: 0, label: 'Warrantor — no agent running' };
  return {
    open,
    label: `Warrantor — ${open} warrant${open === 1 ? '' : 's'} open`,
  };
}

/**
 * Which warrants have newly become "waiting for a decision" since the last look.
 *
 * Transitions, not levels. Notifying on a level means one held warrant produces a notification every
 * poll until somebody acts on it, which is how a person learns to dismiss them without reading — and
 * the one that mattered goes with the rest.
 *
 * A read that failed yields **no** transitions and does not clear what is known. Treating an
 * unreadable answer as "nothing is waiting any more" would re-notify for every warrant the moment
 * the agent came back.
 *
 * @param {{answered: boolean, status: number, payload: unknown}} response
 * @param {Set<string>} alreadyNotified - mutated: ids that have already produced a notification
 * @returns {Array<{id: string, goal: string}>}
 */
export function newlyWaiting({ answered, status, payload }, alreadyNotified) {
  if (!answered || status !== 200) return [];
  const warrants = payload?.data?.warrants;
  if (!Array.isArray(warrants)) return [];

  // `held` is the state a warrant reaches when its deadline or budget ended the run with staged
  // effects waiting for a human. That is precisely "a decision is waiting", and it is the only
  // state that means it: `open` is still running, and settled/void are decided.
  const waiting = warrants.filter((w) => w?.state === 'held' && typeof w?.id === 'string');
  const fresh = waiting.filter((w) => !alreadyNotified.has(w.id));

  // Ids that have left the waiting state are forgotten, so a warrant that is held, decided, and
  // somehow held again notifies twice — which is correct, because it is two decisions.
  const stillWaiting = new Set(waiting.map((w) => w.id));
  for (const id of [...alreadyNotified]) {
    if (!stillWaiting.has(id)) alreadyNotified.delete(id);
  }
  for (const w of fresh) alreadyNotified.add(w.id);

  return fresh.map((w) => ({
    id: w.id,
    goal: typeof w.goal === 'string' ? w.goal : '',
  }));
}

/** The body of the notification raised for a warrant that is waiting on a human. */
export function waitingNotification({ id, goal }) {
  return {
    title: 'A warrant is waiting for a decision',
    // The goal, then the id. A reviewer recognises their own task before they recognise a hex id,
    // and a notification is read in about a second.
    body: goal ? `${goal}\n${id}` : id,
  };
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
