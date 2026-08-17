/**
 * Warrantor desktop — an Electron shell around the console the agent already serves.
 *
 * # What this is, and what it deliberately is not
 *
 * It is a window, a child process, and a policy. It starts `warrantor serve` on a loopback port,
 * reads the session token from that process's stdout, and points a locked-down window at the
 * console. That is the whole job.
 *
 * It is **not** a second implementation of the console, and must never become one. The console
 * renders a verdict computed in Rust and never derives one; a shell that re-rendered any of that
 * would be a second viewer, and a second viewer is a second thing that can misrender a verdict at
 * the exact moment a human is deciding whether to release an agent's work. Everything visible in
 * this window is served by the agent.
 *
 * # Why the shell exists at all, given `warrantor console`
 *
 * `warrantor console` already opens a browser. It requires a terminal to start it. This removes
 * the terminal, which is the difference between a surface an engineer can use and one a reviewer,
 * a risk function or an auditor can. That is the entire delta, and it is worth one small program.
 *
 * # The security posture
 *
 * The renderer runs sandboxed, with context isolation on and Node integration off, so the page has
 * no route to the filesystem or to a child process even if it were somehow replaced. There is no
 * preload script, because the console needs nothing from this process — it talks to the agent over
 * HTTP like any other client, which is what keeps the shell substitutable for a browser.
 *
 * Navigation is pinned to the agent's origin, new windows are refused outright, and every
 * permission request is denied. The decisions themselves live in `policy.js` as pure functions, so
 * they are tested rather than asserted.
 */

import { spawn } from 'node:child_process';
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  Menu,
  Notification,
  Tray,
  app,
  BrowserWindow,
  clipboard,
  dialog,
  nativeImage,
  nativeTheme,
  screen,
  session,
  shell,
} from 'electron';

import {
  agentBinaryCandidates,
  agentExitMessage,
  consoleUrl,
  describeBinarySource,
  firstRunRemedy,
  isNavigationAllowed,
  isPermissionGranted,
  menuTemplate,
  newlyWaiting,
  originFromLine,
  redactToken,
  resolveAgentBinary,
  sanitiseWindowState,
  tokenFromLine,
  traySummary,
  waitingNotification,
} from './policy.js';

/** How much of the agent's stderr to keep for a failure message. A dialog is not a log. */
const AGENT_STDERR_TAIL = 900;

/** How long to wait for the agent to announce itself before giving up, in milliseconds. */
const AGENT_STARTUP_TIMEOUT_MS = 20_000;

/**
 * Trace startup to a file when `WARRANTOR_DESKTOP_TRACE` is set.
 *
 * Kept because the failure it was written for is invisible by default: a GUI-subsystem binary on
 * Windows has no console, so a shell that exits during startup does so with no window, no message
 * and status 0. "It does nothing when I double-click it" is the bug report this answers.
 */
function trace(message) {
  const path = process.env.WARRANTOR_DESKTOP_TRACE;
  if (!path) return;
  try {
    appendFileSync(path, `${new Date().toISOString()} ${message}\n`);
  } catch {
    // Tracing must never be the reason startup fails.
  }
}

// Set before anything reads a path. Electron derives userData from the package name, and this
// package is `@warrantor/desktop`: the slash makes a *nested* directory, and on Windows the
// single-instance lock keyed on that path never succeeds — `requestSingleInstanceLock()` returned
// false on a machine with no other instance running, so the app quit immediately, with no window
// and no error. Naming the app explicitly is the fix, and it also puts the profile somewhere a
// person can find.
app.setName('Warrantor');

trace('module evaluated');

/** The running agent, so it can be stopped when the window closes. */
let agent = null;
/** The session token, held only to redact it from forwarded output. */
let sessionToken = null;
/** True from the first deliberate quit, so a dying agent does not raise a dialog on the way out. */
let quitting = false;
/**
 * Where a post-startup agent death is routed.
 *
 * A mutable indirection rather than a parameter, because the `exit` handler is attached inside
 * `startAgent` — before the window it would report to exists.
 */
let onAgentExit = () => {};

/** Where the remembered window geometry lives. */
function windowStatePath() {
  return join(app.getPath('userData'), 'window-state.json');
}

/**
 * Read the remembered geometry, sanitised against the displays that exist *now*.
 *
 * Every failure path returns the default rather than throwing. A corrupt state file must never be
 * the reason an application will not open — that is a support problem with no user-visible cause,
 * created entirely by a convenience feature.
 */
function readWindowState() {
  let saved = null;
  try {
    saved = JSON.parse(readFileSync(windowStatePath(), 'utf8'));
  } catch {
    saved = null;
  }
  const workAreas = screen.getAllDisplays().map((display) => display.workArea);
  return sanitiseWindowState(saved, workAreas);
}

/**
 * Remember where the window is.
 *
 * `getNormalBounds` rather than `getBounds`, so a window that was maximised when it closed
 * remembers the size it will return to when it is un-maximised, instead of remembering the size of
 * the screen and reopening at that size un-maximised on a smaller one.
 */
function saveWindowState(window) {
  if (!window || window.isDestroyed()) return;
  try {
    const bounds = window.getNormalBounds();
    writeFileSync(
      windowStatePath(),
      JSON.stringify({ ...bounds, maximized: window.isMaximized() }),
    );
  } catch {
    // Losing a remembered position costs a person one drag. Nothing here may be a reason to fail.
  }
}

/**
 * Start `warrantor serve` and resolve once it has announced an origin and a token.
 *
 * Port 0 asks the OS for a free port, so two shells can run side by side and neither has to guess
 * whether 8787 is taken. The origin is read back from the child's own output rather than assumed,
 * which means the window follows whatever the agent actually bound.
 *
 * Release authority is **not** requested. The shell starts a viewer; arming settle is a thing an
 * operator does deliberately, at a terminal, having read what it means. A desktop icon that
 * silently held release authority would make the safest surface the most dangerous one. Nothing may
 * be added to these spawn arguments; `--allow-settle` in particular is the flag that would undo it.
 *
 * Which binary gets spawned is decided in `policy.js`. Do **not** add an integrity check on it
 * here — no hash, no checksum, no signature comparison. Verification happens only in Rust, and a
 * check above that line would be a second verifier that can disagree with the first, leaving a
 * human to decide which to believe. Integrity of this file is the installer's job, the operating
 * system's, and later the code signature's.
 */
function startAgent() {
  return new Promise((resolve, reject) => {
    const { binary, error: resolutionError } = resolveAgentBinary(
      agentBinaryCandidates({
        isPackaged: app.isPackaged,
        resourcesPath: process.resourcesPath,
        warrantorBin: process.env.WARRANTOR_BIN,
        platform: process.platform,
      }),
      existsSync,
    );
    if (!binary) {
      reject(new Error(resolutionError));
      return;
    }

    // Named in the trace and in both rejection messages below, because without it a broken install
    // and an empty PATH produce the identical sentence — and on Windows this is a GUI-subsystem
    // binary with no console, so that sentence is the only diagnosis a reviewer ever gets.
    const binarySource = describeBinarySource(binary.source);
    trace(`agent binary: ${binary.path} (${binarySource})`);

    const child = spawn(binary.path, ['serve', '--port', '0'], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let origin = null;
    let token = null;
    let buffered = '';
    let settled = false;
    // A bounded tail of the agent's own stderr, kept so a startup failure can SAY WHY.
    //
    // Found by launching the Linux AppImage on a machine that had never run `warrantor`: the agent
    // exited 1 with "no issuer key was found ... Run a `warrantor` command that creates it first" --
    // an actionable sentence, written to a log the user never opens -- and the dialog said only
    // "exited with code 1 before it was ready". The cause was already in hand and thrown away.
    //
    // Bounded because a dialog is not a log: the last 900 characters carry the refusal that killed
    // it, and the earlier output is still on stderr for anyone who wants it.
    let stderrTail = '';

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill();
      reject(
        new Error(
          `${binary.path} (${binarySource}) did not announce a token within 20 seconds` +
            (stderrTail.trim() ? `

The agent said:
${stderrTail.trim()}` : ''),
        ),
      );
    }, AGENT_STARTUP_TIMEOUT_MS);

    const finish = () => {
      if (settled || !origin || !token) return;
      settled = true;
      clearTimeout(timer);
      resolve({ child, origin, token, binaryPath: binary.path });
    };

    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      buffered += chunk;
      const lines = buffered.split('\n');
      // Keep the last fragment: a token can be split across two reads, and half a token matches
      // nothing, so a naive per-chunk parse would silently never start.
      buffered = lines.pop() ?? '';
      for (const line of lines) {
        origin ??= originFromLine(line);
        token ??= tokenFromLine(line);
        // Forwarded so a bind failure is visible, redacted so the session secret is not written
        // into whatever captures this process's stdout.
        process.stdout.write(`${redactToken(line, token)}\n`);
      }
      finish();
    });

    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk) => {
      const redacted = redactToken(chunk, token);
      process.stderr.write(redacted);
      // Retained in redacted form, never raw: this string can reach a dialog and a clipboard.
      stderrTail = (stderrTail + redacted).slice(-AGENT_STDERR_TAIL);
    });

    child.on('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new Error(`could not start ${binary.path} (${binarySource}): ${error.message}`));
    });

    child.on('exit', (code, signal) => {
      if (settled) {
        // The window is already open, so this is a death rather than a failed start, and it is
        // reported rather than swallowed. The handler is attached here rather than after the
        // promise resolves because a child can die in the gap between the two.
        onAgentExit(code, signal);
        return;
      }
      settled = true;
      clearTimeout(timer);
      const why = stderrTail.trim();
      reject(
        new Error(
          `${binary.path} (${binarySource}) exited with code ${code} before it was ready` +
            (why ? `

The agent said:
${why}` : ''),
        ),
      );
    });
  });
}

/**
 * Report a failure that prevents the window from opening.
 *
 * Three destinations, because on the platform where this is most likely to be double-clicked there
 * is only one that works. An Electron app on Windows is a GUI-subsystem binary: it has no attached
 * console, so anything written to stderr goes nowhere at all. An earlier version of this function
 * wrote only to stderr, and the app died in complete silence — no window, no message, exit 0 — which
 * is the worst failure mode a desktop application can have.
 *
 * So: a dialog, because that is the only one a person who double-clicked an icon will see; a log
 * file, because a dialog cannot be copied out of and this is the text someone will need to paste;
 * and stderr, which costs nothing and is the one that works when launched from a terminal.
 */
function reportFatal(message) {
  const text = `warrantor-desktop: ${message}`;
  process.stderr.write(`${text}\n`);
  try {
    appendFileSync(join(app.getPath('userData'), 'startup.log'), `${new Date().toISOString()} ${text}\n`);
  } catch {
    // A log that cannot be written must not replace the dialog with a crash.
  }
  // One failure has a known remedy, and showing it as a generic error is what made a clean machine
  // a dead end: the agent refuses to start without an issuer key — correctly — and a reviewer who
  // has just double-clicked an installer has no way to know that means "grant a warrant first".
  const remedy = firstRunRemedy(message);
  if (remedy) {
    try {
      const choice = dialog.showMessageBoxSync({
        type: 'info',
        title: remedy.title,
        message: remedy.title,
        detail: `${remedy.detail}\n\n    ${remedy.command}`,
        buttons: ['Copy the command', 'Quit'],
        defaultId: 0,
        cancelId: 1,
        noLink: true,
      });
      if (choice === 0) {
        clipboard.writeText(remedy.command);
      }
      return;
    } catch {
      // No display, or too early for a dialog. Falls through to the plain error path below rather
      // than swallowing the failure: a first-run screen that cannot render must not silence it.
    }
  }

  try {
    dialog.showErrorBox('Warrantor could not start', message);
  } catch {
    // No display, or too early for a dialog. stderr and the log still carry it.
  }
}


/**
 * Replace the default menu.
 *
 * Electron's default menu ships a Reload item, and Reload strands the reviewer. The console takes
 * its token from the URL fragment and then erases it from the address bar and history, so the
 * document's own URL no longer carries it: reloading that URL lands on the token gate, in a window
 * whose whole purpose was that nobody has to paste a token. The session is still perfectly valid —
 * it just became unreachable through the front door.
 *
 * So Reload is kept, because a stuck view is a real thing that happens, and rewired to re-load the
 * authenticated URL. The token is held in this process, never in the page, which is precisely what
 * makes re-authenticating on reload something the shell can do and the page cannot.
 *
 * The rest of the default menu is dropped. This window shows a verdict; it is not a document
 * editor, and File/Window items that do nothing here are worse than absent.
 */
function installMenu(window, origin, token, binaryPath) {
  Menu.setApplicationMenu(
    Menu.buildFromTemplate(
      menuTemplate({
        platform: process.platform,
        appName: 'Warrantor',
        handlers: {
          reload: () => window.loadURL(consoleUrl(origin, token)),
          about: () => showAbout(window, origin, binaryPath),
        },
      }),
    ),
  );
}

/**
 * What this window is showing, and which agent is showing it.
 *
 * Not decoration. The one question support cannot answer about a desktop install is *which binary
 * is this actually running* — the resolution order in `policy.js` has three possible answers and
 * the window looks identical under all of them. The version reported is the shell's; the agent's
 * own version is on the console's status line, served by the agent itself, because a shell that
 * printed a version it had derived would be a second source of truth about the thing that
 * verifies.
 */
function showAbout(window, origin, binaryPath) {
  dialog.showMessageBox(window, {
    type: 'info',
    title: 'About Warrantor',
    message: `Warrantor ${app.getVersion()}`,
    detail:
      `This window is a shell around the console served by a local agent. Verification happens ` +
      `only in that agent, never here.\n\n` +
      `Agent binary: ${binaryPath}\n` +
      `Serving: ${origin}\n` +
      `Profile: ${app.getPath('userData')}`,
    buttons: ['OK'],
  });
}

/**
 * The agent died after the window opened.
 *
 * Previously nothing happened at all: the `exit` handler returned once startup had settled, so a
 * crashed or killed agent left a window rendering a console that could reach nothing. The console
 * recovers *silently* when an agent comes back, which is right for a hiccup and wrong for a death —
 * so the death is the shell's to report, and it is the only party that knows the child is gone.
 *
 * Relaunching starts a **new agent with a new session token**, which is why it re-enters
 * `createWindow` rather than reloading the page: the old URL carries a token no longer valid for
 * anything.
 */
function reportAgentDeath(window, code, signal) {
  if (quitting) return;
  agent = null;
  const choice = dialog.showMessageBoxSync(window, {
    type: 'error',
    title: 'The agent stopped',
    message: 'Warrantor is not running',
    detail: agentExitMessage(code, signal),
    buttons: ['Relaunch', 'Quit'],
    defaultId: 0,
    cancelId: 1,
  });
  if (choice === 0) {
    if (window && !window.isDestroyed()) window.destroy();
    createWindow().catch((error) => {
      reportFatal(`relaunch failed: ${error?.stack ?? error}`);
      app.exit(1);
    });
    return;
  }
  quitting = true;
  app.quit();
}

/** Apply the policy to a window, and to the session it uses. */
function lockDown(window, origin) {
  const contents = window.webContents;

  // Navigation is pinned to the agent. An external link — there are none in the console today, and
  // this is what keeps that true — is handed to the system browser rather than followed here, so a
  // hostile page can never occupy the window that holds the token.
  contents.on('will-navigate', (event, url) => {
    if (!isNavigationAllowed(url, origin)) {
      event.preventDefault();
    }
  });

  contents.setWindowOpenHandler(({ url }) => {
    if (!isNavigationAllowed(url, origin)) {
      // Opened in the user's browser, where it is subject to that browser's sandbox and has no
      // access to this session.
      shell.openExternal(url).catch(() => {});
    }
    return { action: 'deny' };
  });

  // Attaching a webview would create a frame this policy does not cover.
  contents.on('will-attach-webview', (event) => event.preventDefault());

  session.defaultSession.setPermissionRequestHandler((_contents, permission, callback) => {
    callback(isPermissionGranted(permission));
  });
  session.defaultSession.setPermissionCheckHandler((_contents, permission) =>
    isPermissionGranted(permission),
  );
}

async function createWindow() {
  trace('createWindow entered');
  let started;
  try {
    started = await startAgent();
  } catch (error) {
    reportFatal(error.message);
    app.exit(1);
    return;
  }

  trace(`agent ready on ${started.origin}`);
  agent = started.child;
  sessionToken = started.token;

  const remembered = readWindowState();
  const window = new BrowserWindow({
    width: remembered.width,
    height: remembered.height,
    ...(remembered.x === undefined ? {} : { x: remembered.x, y: remembered.y }),
    minWidth: 720,
    minHeight: 480,
    title: 'Warrantor',
    // Follows the OS, and matches the console's own `color-scheme: light dark`. A window painted
    // dark under a light console flashes white on first paint, which is the one moment a user is
    // deciding whether this application is finished.
    backgroundColor: nativeTheme.shouldUseDarkColors ? '#0f1115' : '#fbfbfd',
    show: false,
    // The standard frame on every platform, including macOS. An inset title bar would look better
    // and cannot be done correctly from here: the console is served by the agent and rendered with
    // no preload, so it has no way to know it is inside this shell — it could neither reserve the
    // space the traffic lights occupy nor mark its top bar as a drag region. The result would be a
    // window with its brand under the close button and no way to move it. Deferred to whenever the
    // shell can tell the page what chrome it is in, which is a change to the page.
    webPreferences: {
      // The three that matter, stated explicitly rather than relied on as defaults: a default that
      // changes between Electron majors is not a security property.
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      webviewTag: false,
      // No preload. The console talks to the agent over HTTP like any other client, which is what
      // keeps this shell substitutable for a browser and keeps the renderer's reach at zero.
    },
  });

  trace('window constructed');
  lockDown(window, started.origin);
  installMenu(window, started.origin, started.token, started.binaryPath);
  onAgentExit = (code, signal) => reportAgentDeath(window, code, signal);

  // Geometry is written on every move and resize rather than only on close, because the close a
  // user cares about remembering is often the one where the machine went to sleep or the process
  // was killed — neither of which fires a close event.
  const remember = () => saveWindowState(window);
  window.on('resize', remember);
  window.on('move', remember);
  window.on('close', remember);

  // Shown on first paint rather than immediately, so the first thing a reviewer sees is the
  // console and not a white rectangle.
  window.once('ready-to-show', () => {
    if (remembered.maximized) window.maximize();
    window.show();
  });
  await window.loadURL(consoleUrl(started.origin, started.token));
  trace('console loaded');

  // After the window exists, so a notification has something to raise itself over,
  // and after the console has loaded, so the first poll does not race the first render.
  installTray(window);
  startWatching(window, started.origin, started.token);
}

// ── the tray, and telling somebody a decision is waiting ────────────────────

/** The tray icon, held so it is not garbage-collected — Electron requires the reference. */
let tray = null;
/** Warrant ids that have already produced a "waiting" notification. */
const notified = new Set();
/** The polling handle, cleared when the agent goes. */
let watcher = null;

/**
 * Read the warrant list as an ordinary client.
 *
 * The same origin and the same token the console uses. Nothing is derived here beyond counting, and
 * counting is arithmetic rather than a judgement — the rule this shell is built on is that it
 * renders nothing the agent did not compute, and a count of rows is not a verdict about any of them.
 */
async function readWarrants(origin, token) {
  try {
    const response = await fetch(`${origin}/v1/warrants`, {
      headers: { authorization: `Bearer ${token}` },
    });
    let payload = null;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }
    return { answered: true, status: response.status, payload };
  } catch {
    // A refused connection is the likeliest way a loopback agent fails, and it is an outcome
    // rather than an exception: `traySummary` renders it as "cannot reach", never as zero.
    return { answered: false, status: 0, payload: null };
  }
}

/**
 * Watch the store, keep the tray honest, and notify once per decision.
 *
 * Five seconds, matching the console's own poll: two clients at the same cadence against a loopback
 * server whose documented consumer is "one console polling at human speed".
 */
function startWatching(window, origin, token) {
  const tick = async () => {
    const response = await readWarrants(origin, token);
    const summary = traySummary(response);
    if (tray && !tray.isDestroyed()) tray.setToolTip(summary.label);

    for (const waiting of newlyWaiting(response, notified)) {
      if (!Notification.isSupported()) break;
      const { title, body } = waitingNotification(waiting);
      const note = new Notification({ title, body });
      note.on('click', () => {
        if (window && !window.isDestroyed()) {
          if (window.isMinimized()) window.restore();
          window.show();
          window.focus();
        }
      });
      note.show();
    }
  };
  void tick();
  watcher = setInterval(() => void tick(), 5000);
}

/**
 * A tray presence, so a run that is minimised is still visible.
 *
 * A supervised agent runs for hours; the window gets minimised and the run becomes invisible, which
 * is the state in which somebody forgets an agent is running at all. This is the smallest fix, and
 * it is a thing a browser tab cannot do — which is the only reason it belongs in this shell.
 *
 * The icon is the app's own, resolved through Electron rather than shipped separately: a second
 * image to keep in step with the first is a second image that goes stale.
 */
function installTray(window) {
  try {
    const image = nativeImage.createFromPath(
      join(app.getAppPath(), 'build', process.platform === 'darwin' ? 'icon.png' : 'icon.png'),
    );
    // An empty image is not an error on every platform, but a tray with no icon is a tray nobody
    // can find. Skipping is better than an invisible control.
    if (image.isEmpty()) {
      trace('tray skipped: no icon');
      return;
    }
    tray = new Tray(image.resize({ width: 18, height: 18 }));
    tray.setToolTip('Warrantor');
    tray.setContextMenu(
      Menu.buildFromTemplate([
        {
          label: 'Show Warrantor',
          click: () => {
            if (window.isMinimized()) window.restore();
            window.show();
            window.focus();
          },
        },
        { type: 'separator' },
        // Quit, not hide. This shell owns a child process holding an open port and a session
        // token; a tray that only hid the window would leave that running behind an icon most
        // people read as "closed".
        { label: 'Quit', click: () => app.quit() },
      ]),
    );
    tray.on('click', () => {
      if (window.isMinimized()) window.restore();
      window.show();
      window.focus();
    });
  } catch (error) {
    // A missing tray costs visibility, never startup.
    trace(`tray failed: ${error?.message ?? error}`);
  }
}

function stopWatching() {
  if (watcher) {
    clearInterval(watcher);
    watcher = null;
  }
  notified.clear();
  if (tray && !tray.isDestroyed()) {
    tray.destroy();
    tray = null;
  }
}

/** Stop the agent. Called on every path that ends the process. */
function stopAgent() {
  // Set before the kill, so the child's own `exit` does not raise "the agent stopped" over an
  // application that is already closing — which is what it would look like to a user who had just
  // pressed Quit.
  quitting = true;
  onAgentExit = () => {};
  stopWatching();
  if (agent && !agent.killed) {
    agent.kill();
    agent = null;
  }
  sessionToken = null;
}

// Everything is wired inside `whenReady`. Electron's ESM main process evaluates this module
// asynchronously relative to app startup, and doing app-level work at module scope is timing that
// is not specified anywhere: `requestSingleInstanceLock()` returned false here on a machine with no
// other instance running, and because the documented response to false is to quit, the app exited
// silently before it had done anything. Inside `whenReady` the ordering is defined.
trace('reached lifecycle wiring');
process.on('uncaughtException', (e) => { trace('UNCAUGHT: ' + (e?.stack ?? e)); });

app.whenReady().then(() => {
  trace('app ready');
  // A second instance would start a second agent against the same store. The store tolerates it,
  // but two windows showing two different sessions is a confusing thing to hand someone who is
  // deciding whether to release an agent's work.
  if (!app.requestSingleInstanceLock()) {
    trace('another instance holds the lock; quitting');
    app.quit();
    return undefined;
  }

  app.on('second-instance', () => {
    const [existing] = BrowserWindow.getAllWindows();
    if (existing) {
      if (existing.isMinimized()) existing.restore();
      existing.focus();
    }
  });

  return createWindow();
}).catch((error) => {
  reportFatal(`startup failed: ${error?.stack ?? error}`);
  app.exit(1);
});

app.on('window-all-closed', () => {
  trace('window-all-closed');
  // Quitting on the last window closing, on every platform including macOS. The macOS convention
  // is the opposite, and it is the wrong one here: this application owns a *child process* holding
  // an open port and a session token, and an app that stayed resident in the Dock with a live
  // agent behind no window would leave an oversight surface running that its operator believes
  // they closed. Reopening from the Dock starts a fresh agent in a second or two; a token nobody
  // can see does not expire on its own.
  stopAgent();
  app.quit();
});

// macOS: clicking the Dock icon with no window open. Unreachable in practice given the quit above,
// and wired anyway, because the two behaviours have to agree — if `window-all-closed` is ever
// relaxed, this is what the Dock icon must already do.
app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length > 0) return;
  createWindow().catch((error) => {
    reportFatal(`could not reopen: ${error?.stack ?? error}`);
  });
});

// `before-quit` and `will-quit` both fire on paths the other does not, and killing an already dead
// child is a no-op, so both are wired rather than one being reasoned about.
app.on('before-quit', stopAgent);
app.on('will-quit', stopAgent);
process.on('exit', stopAgent);

export { sessionToken };
