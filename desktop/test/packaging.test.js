/**
 * The packaging contract, tested without Electron and without building anything.
 *
 * These run in the same dependency-free `node --test` gate as the policy tests, and they exist
 * because every failure below is silent: nothing errors, the build succeeds, and the symptom only
 * appears on the machine of the reviewer this whole workstream is for.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { agentExecutableName } from '../src/policy.js';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

const builderConfig = require('../electron-builder.config.cjs');
const manifest = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8'));
const lockfile = JSON.parse(readFileSync(join(here, '..', 'package-lock.json'), 'utf8'));

// ── the builder and the resolver must agree ───────────────────────────────────

/**
 * The highest-value test here.
 *
 * `agentBinaryCandidates()` looks for `<resourcesPath>/warrantor[.exe]`, and `extraResources.to` is
 * what decides the name that file actually lands under. Rename one without the other and bundled
 * resolution silently stops working: the app falls back to nothing, and the only symptom is the
 * error dialog on a fresh machine after a hand-install — which is precisely the failure the bundled
 * agent exists to remove.
 */
test('the bundled agent lands under the name the resolver looks for', () => {
  for (const [platformKey, processPlatform] of [
    ['win', 'win32'],
    ['mac', 'darwin'],
    ['linux', 'linux'],
  ]) {
    const resources = builderConfig[platformKey].extraResources;
    assert.equal(resources.length, 1, `${platformKey} must ship exactly one extra resource`);
    assert.equal(
      resources[0].to,
      agentExecutableName(processPlatform),
      `${platformKey}: extraResources.to must match agentExecutableName('${processPlatform}')`,
    );
  }
});

/**
 * The source path is what the release workflow writes to. `${arch}` is an electron-builder macro,
 * not a shell variable, and a build for one architecture must never pick up a binary compiled for
 * another — a mismatched agent would fail to spawn at all, on a reviewer's machine, silently
 * enough that it reads as "the app is broken".
 */
test('the bundled agent is taken from an architecture-specific directory', () => {
  for (const platformKey of ['win', 'mac', 'linux']) {
    const from = builderConfig[platformKey].extraResources[0].from;
    assert.ok(
      from.startsWith('vendor/${arch}/'),
      `${platformKey}: extraResources.from must be architecture-scoped, got ${from}`,
    );
  }
});

// ── what may be inside the app ────────────────────────────────────────────────

/**
 * No runtime dependencies, ever. The console is served by the agent over HTTP, which is what keeps
 * this shell substitutable for a browser and the renderer's reach at zero. The first dependency
 * that would be added here is `electron-updater`, and an update channel over an unsigned artifact
 * is an unauthenticated code-execution channel.
 */
test('the shell has no runtime dependencies', () => {
  const dependencies = manifest.dependencies ?? {};
  assert.deepEqual(Object.keys(dependencies), []);
});

test('the packaged file list does not reach into node_modules', () => {
  for (const pattern of builderConfig.files) {
    assert.ok(
      !pattern.includes('node_modules'),
      `${pattern} would put a dependency tree inside the asar`,
    );
  }
});

/**
 * `publish: null` is the line that stops `latest.yml` being generated and `electron-updater` being
 * a two-line change away. It must stay null until the artifacts are signed.
 */
test('no publish channel is configured', () => {
  assert.equal(builderConfig.publish, null);
});

/**
 * A per-machine install asks for administrator, and an elevated install invites an elevated launch
 * — which would run the supervised agent as administrator and weaken the containment the warrant
 * claims on the one machine where enforcement actually lives.
 */
test('the Windows installer is per-user and never elevates', () => {
  assert.equal(builderConfig.nsis.perMachine, false);
  assert.equal(builderConfig.win.forceCodeSigning, false);
});

/**
 * `identity: null` and `identity: '-'` are not synonyms, and reading them as synonyms produces a
 * dmg that installs and then will not start.
 *
 * electron-builder 26 routes `null` to `handleNullIdentity()` — "skipped macOS code signing" — and
 * only the literal `'-'` builds an ad-hoc identity. Packaging invalidates the signature the
 * prebuilt Electron arrives with (renamed bundle, renamed Mach-O, rewritten Info.plist, injected
 * extraResources), and Apple Silicon refuses to execute an invalidly-signed Mach-O. Nothing else
 * catches it: the build succeeds, the workflow's "agent is inside the app" assertion passes, and
 * the symptom is an app that does not launch on the reviewer's machine.
 *
 * `hardenedRuntime: false` is asserted with it because the two are one decision. The default for a
 * non-MAS build is ON, and ad-hoc signing under the hardened runtime requires the
 * disable-library-validation entitlement — which `build/entitlements.mac.plist` deliberately does
 * not grant, and which a security product should not grant to route around a missing certificate.
 */
test('the macOS build is ad-hoc signed rather than signing-skipped', () => {
  assert.equal(
    builderConfig.mac.identity,
    '-',
    "mac.identity must be '-' (ad-hoc); null means skip signing entirely",
  );
  assert.equal(
    builderConfig.mac.hardenedRuntime,
    false,
    'ad-hoc signing under the hardened runtime needs an entitlement we do not grant',
  );
});

// ── the Electron pin ──────────────────────────────────────────────────────────

/**
 * A dependency-free `^major.minor.patch` check.
 *
 * `node --test` here runs with no `node_modules` at all — that is the property that keeps the CI
 * gate free of a 150 MB Chromium download — so `semver` is not available and this is the whole of
 * the range logic the pin test needs. Only the caret form is accepted: if the manifest range ever
 * stops being a caret this throws rather than silently admitting everything, because a range check
 * that quietly degrades to "anything" is worse than no check.
 *
 * A prerelease is never satisfying. `43.5.0-beta.1` is not the artifact anybody audited, and
 * reading it as "within 43.x" is exactly the loose comparison this function replaces.
 */
function satisfiesCaretRange(range, version) {
  if (!range.startsWith('^')) {
    throw new Error(`only caret ranges are understood here, got ${range}`);
  }
  if (version.includes('-')) {
    return false; // a prerelease is not the audited version
  }
  const parse = (value) => {
    const parts = value.split('.');
    if (parts.length !== 3 || parts.some((part) => !/^\d+$/.test(part))) {
      throw new Error(`not a plain major.minor.patch version: ${value}`);
    }
    return parts.map(Number);
  };
  const [floorMajor, floorMinor, floorPatch] = parse(range.slice(1));
  const [major, minor, patch] = parse(version);
  if (major !== floorMajor) {
    return false; // a caret never crosses a major
  }
  if (minor !== floorMinor) {
    return minor > floorMinor;
  }
  return patch >= floorPatch;
}

/**
 * The range check is itself tested, because the previous version of the pin test asserted only
 * `version.startsWith('43.')` — which admits `43.0.0`: inside the major, outside `^43.4.0`, and not
 * the release that was audited. A test whose name claims more than its assertion is the failure
 * mode being repaired here, so the boundary cases are pinned rather than assumed.
 */
test('the audited-pin check rejects what the pin does not admit', () => {
  assert.equal(satisfiesCaretRange('^43.4.0', '43.0.0'), false);
  assert.equal(satisfiesCaretRange('^43.4.0', '43.3.9'), false);
  assert.equal(satisfiesCaretRange('^43.4.0', '42.9.9'), false);
  assert.equal(satisfiesCaretRange('^43.4.0', '44.0.0'), false);
  assert.equal(satisfiesCaretRange('^43.4.0', '43.5.0-beta.1'), false);
  assert.equal(satisfiesCaretRange('^43.4.0', '43.4.0'), true);
  assert.equal(satisfiesCaretRange('^43.4.0', '43.4.1'), true);
  assert.equal(satisfiesCaretRange('^43.4.0', '43.5.1'), true);
  assert.throws(() => satisfiesCaretRange('43.4.0', '43.4.0'), /caret/);
});

/**
 * RFC W1 states the pin and says `npm audit` in `desktop/` is a release gate. A pin stated in prose
 * is a sentence; asserted here it is a gate, and `npm audit fix --force` — the reflex fix for an
 * advisory in electron-builder's tree — moves Electron off the audited version and fails this.
 *
 * The lockfile is checked against the manifest range rather than against a hand-copied major, so
 * the assertion means what the test's name says: the resolved Electron is a version the audited
 * range admits, not merely one that shares its major.
 */
test('Electron stays on the audited pin', () => {
  const range = manifest.devDependencies.electron;
  assert.equal(range, '^43.4.0');
  const resolved = lockfile.packages['node_modules/electron'];
  assert.ok(resolved, 'the lockfile must actually contain electron');
  assert.ok(
    satisfiesCaretRange(range, resolved.version),
    `the lockfile resolves electron ${resolved.version}, outside the audited pin ${range}`,
  );
});

// ── the release workflow's own assertion ──────────────────────────────────────

/**
 * A text assertion over the workflow, and the weakest test in this file — no gate here can run a
 * GitHub Actions job. It is worth its line anyway: the workflow's header states that the agent is
 * compiled in-job because `actions/upload-artifact` drops the executable bit and an agent without
 * `+x` fails at spawn with EACCES on the reviewer's first launch. That reasoning is only real if
 * the step that confirms the bundled agent actually tests the bit; a presence-only `find` leaves
 * open the exact failure the comment names, and nothing downstream would notice — the installer
 * builds, uploads and installs, and dies at spawn.
 */
test('the release workflow asserts the bundled agent is executable, not merely present', () => {
  const workflow = readFileSync(
    join(here, '..', '..', '.github', 'workflows', 'desktop-release.yml'),
    'utf8',
  );
  const step = workflow.split('- name: Confirm the agent is inside the app')[1];
  assert.ok(step, 'the "Confirm the agent is inside the app" step must exist');
  const untilNextStep = step.split('\n      - name:')[0];
  assert.match(
    untilNextStep,
    /-x "\$agent"|test -x|-perm -u\+x/,
    'the confirmation step must test the executable bit, not only the file’s presence',
  );
});

// ── the boundary with the typescript workspace ────────────────────────────────

/**
 * Adding `desktop` to the typescript workspace would make `npm ci` there download a ~150 MB
 * Chromium on every CI run, and would make `desktop` a directory `generate_tracker.py`'s
 * `discover_source_directories()` finds, flipping `catalog_integrity.passed` to false. Both are
 * one line of someone's convenience away, so the boundary is asserted rather than remembered.
 */
test('desktop is not a member of the typescript npm workspace', () => {
  const typescriptManifest = JSON.parse(
    readFileSync(join(here, '..', '..', 'typescript', 'package.json'), 'utf8'),
  );
  for (const workspace of typescriptManifest.workspaces ?? []) {
    assert.ok(
      !workspace.includes('desktop'),
      `typescript/package.json workspaces must not reach desktop/, found ${workspace}`,
    );
  }
});

/**
 * electron-builder derives `executableName` from package.json `name` on Linux, and this package is
 * scoped: `@warrantor/desktop` collapses to `@warrantordesktop`, whose `@` is not legal in a file
 * path. The AppImage target refuses outright — "executableName contains characters that cannot be
 * safely used in file paths" — and it does so AFTER downloading Electron and packaging the app, so
 * it costs a whole platform leg to find out.
 *
 * That is what killed the first-ever run of desktop-release. Windows and macOS derive theirs from
 * `productName` and were unaffected, which is precisely why a config that reads fine could sit
 * unexecuted with this in it.
 */
test('executableName is set explicitly and is path-safe', () => {
  assert.ok(builderConfig.executableName, 'executableName must be set, not derived from a scoped name');
  assert.match(
    builderConfig.executableName,
    /^[A-Za-z0-9._ -]+$/,
    'executableName must contain only letters, digits, hyphens, underscores, dots and spaces',
  );
});

/**
 * Electron uses the desktop name as app_id / WM_CLASS. Without it a desktop environment cannot link
 * the running window to the installed .desktop entry: generic icon, no launcher grouping.
 *
 * It lives in package.json and is copied in by `linux.syncDesktopName`. `linux.desktopName` is NOT
 * a key in electron-builder 26's schema — setting it fails config validation for EVERY platform,
 * which is how a Linux-only cosmetic fix took down the three legs that were already passing. The
 * name has to match the .desktop file, which electron-builder names after `executableName`.
 */
test('the linux desktop entry is named after the executable', () => {
  assert.equal(builderConfig.linux.syncDesktopName, true);
  assert.equal(manifest.desktopName, `${builderConfig.executableName}.desktop`);
  assert.equal(
    builderConfig.linux.desktopName,
    undefined,
    'linux.desktopName is not in the v26 schema and fails validation for all platforms',
  );
});

/**
 * Every produced artifact must have a name that is a legal path, and none may be derived from the
 * scoped package name. `@warrantor/desktop` broke packaging twice: once through `executableName`
 * (AppImage refused it outright) and once through the deb target's default artifact name, which is
 * `${name}_${version}_${arch}.${ext}` — putting a SLASH in the output path, so fpm was handed a
 * directory that does not exist and failed with a bare "fpm process failed 1" naming neither.
 */
test('artifact names never derive from the scoped package name', () => {
  // Wherever one is set — per platform or per target, `nsis.artifactName` being the existing case.
  const named = Object.entries(builderConfig)
    .filter(([, value]) => value && typeof value === 'object' && 'artifactName' in value)
    .map(([key, value]) => [key, value.artifactName]);

  assert.ok(named.length > 0, 'no artifactName is configured anywhere');

  for (const [key, artifactName] of named) {
    assert.ok(
      !artifactName.includes('${name}'),
      `${key}: artifactName must not interpolate the scoped package name`,
    );
    // Macros aside, what remains has to be a legal path segment.
    assert.match(
      artifactName.replace(/\$\{[a-zA-Z]+\}/g, 'X'),
      /^[A-Za-z0-9._-]+$/,
      `${key}: artifactName resolves to an unsafe path: ${artifactName}`,
    );
  }

  // Linux specifically MUST set one. Its deb default is `${name}_${version}_${arch}.${ext}`, which
  // is the form that put a slash in the path; AppImage's default comes from productName and is why
  // only half of the Linux leg failed the first time.
  assert.ok(builderConfig.linux.artifactName, 'linux must set artifactName; the deb default is unsafe');
});
