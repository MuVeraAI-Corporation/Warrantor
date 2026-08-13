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
import { appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { Menu, app, BrowserWindow, dialog, session, shell } from 'electron';

import {
  consoleUrl,
  isNavigationAllowed,
  isPermissionGranted,
  originFromLine,
  redactToken,
  tokenFromLine,
} from './policy.js';

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

/**
 * Start `warrantor serve` and resolve once it has announced an origin and a token.
 *
 * Port 0 asks the OS for a free port, so two shells can run side by side and neither has to guess
 * whether 8787 is taken. The origin is read back from the child's own output rather than assumed,
 * which means the window follows whatever the agent actually bound.
 *
 * Release authority is **not** requested. The shell starts a viewer; arming settle is a thing an
 * operator does deliberately, at a terminal, having read what it means. A desktop icon that
 * silently held release authority would make the safest surface the most dangerous one.
 */
function startAgent() {
  return new Promise((resolve, reject) => {
    const binary = process.env.WARRANTOR_BIN || 'warrantor';
    const child = spawn(binary, ['serve', '--port', '0'], { stdio: ['ignore', 'pipe', 'pipe'] });

    let origin = null;
    let token = null;
    let buffered = '';
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill();
      reject(new Error('the agent did not announce a token within 20 seconds'));
    }, AGENT_STARTUP_TIMEOUT_MS);

    const finish = () => {
      if (settled || !origin || !token) return;
      settled = true;
      clearTimeout(timer);
      resolve({ child, origin, token });
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
      process.stderr.write(redactToken(chunk, token));
    });

    child.on('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new Error(`could not start ${binary}: ${error.message}`));
    });

    child.on('exit', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new Error(`the agent exited with code ${code} before it was ready`));
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
function installMenu(window, origin, token) {
  const reload = () => window.loadURL(consoleUrl(origin, token));
  Menu.setApplicationMenu(
    Menu.buildFromTemplate([
      {
        label: 'Warrantor',
        submenu: [
          { label: 'Reload', accelerator: 'CmdOrCtrl+R', click: reload },
          { type: 'separator' },
          { role: 'zoomIn' },
          { role: 'zoomOut' },
          { role: 'resetZoom' },
          { type: 'separator' },
          { role: 'copy' },
          { role: 'selectAll' },
          { type: 'separator' },
          // Kept for support: "what does the console actually say" is answered here, and the
          // renderer has no privileges for it to expose.
          { role: 'toggleDevTools' },
          { type: 'separator' },
          { role: 'quit' },
        ],
      },
    ]),
  );
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

  const window = new BrowserWindow({
    width: 1280,
    height: 860,
    minWidth: 720,
    minHeight: 480,
    title: 'Warrantor',
    backgroundColor: '#0f1115',
    show: false,
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
  installMenu(window, started.origin, started.token);

  // Shown on first paint rather than immediately, so the first thing a reviewer sees is the
  // console and not a white rectangle.
  window.once('ready-to-show', () => window.show());
  await window.loadURL(consoleUrl(started.origin, started.token));
  trace('console loaded');
}

/** Stop the agent. Called on every path that ends the process. */
function stopAgent() {
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
  stopAgent();
  app.quit();
});

// `before-quit` and `will-quit` both fire on paths the other does not, and killing an already dead
// child is a no-op, so both are wired rather than one being reasoned about.
app.on('before-quit', stopAgent);
app.on('will-quit', stopAgent);
process.on('exit', stopAgent);

export { sessionToken };
