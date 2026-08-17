/**
 * The packaging contract, tested without Electron and without building anything.
 *
 * These run in the same dependency-free `node --test` gate as the policy tests, and they exist
 * because every failure below is silent: nothing errors, the build succeeds, and the symptom only
 * appears on the machine of the reviewer this whole workstream is for.
 */

import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
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
 * That is what killed the first-ever run of desktop-release.
 *
 * The fix belongs to LINUX ONLY, and for one release it was not scoped. A top-level
 * `executableName` applies to every platform, so Windows took it as well and the app installed to
 * `%LOCALAPPDATA%\Programs\warrantor-desktop\warrantor-desktop.exe` with an
 * `Uninstall warrantor-desktop.exe` beside it, while Add/Remove Programs listed `Warrantor 1.0.0`
 * and pointed at a directory named something else.
 *
 * Nothing broke. The app launched, resolved its bundled agent ahead of an empty PATH and loaded the
 * console — which is exactly why it survived a comment asserting Windows was unaffected. Only
 * RUNNING the installer showed it, on 2026-08-17.
 */
test('executableName is scoped to linux, so Windows keeps productName', () => {
  assert.equal(
    builderConfig.executableName,
    undefined,
    'a top-level executableName renames the Windows install directory and executable too: it must ' +
      'live under `linux`, which is the only platform that needs it',
  );
  assert.ok(
    builderConfig.linux.executableName,
    'linux still needs it explicitly — the scoped package name @warrantor/desktop is not path-safe',
  );
  assert.match(
    builderConfig.linux.executableName,
    /^[A-Za-z0-9._ -]+$/,
    'executableName must contain only letters, digits, hyphens, underscores, dots and spaces',
  );
  // Windows and macOS must have nothing overriding productName, or the install directory and the
  // Add/Remove entry go back to disagreeing.
  for (const platform of ['win', 'mac']) {
    assert.equal(
      builderConfig[platform].executableName,
      undefined,
      `${platform} must derive its executable name from productName (${builderConfig.productName})`,
    );
  }
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
  // `linux.executableName` now, not the top-level one. This assertion is what makes the scoping
  // safe: the desktop entry must keep matching whatever Linux's executable is called, wherever
  // that name is configured.
  assert.equal(manifest.desktopName, `${builderConfig.linux.executableName}.desktop`);
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

/**
 * The tray icon has to be inside the app bundle, not only in the build resources.
 *
 * `build/` is electron-builder's own resources directory: it is read at build time to make the
 * window and installer icons, and it is NOT copied into the app. So the path `installTray` resolves
 * — `join(app.getAppPath(), 'build', 'icon.png')` — exists in development and does not exist in a
 * packaged build, and `installTray` skips silently when the image is empty.
 *
 * That is exactly what the first launch of a packaged app traced: `tray skipped: no icon`. No unit
 * test could have caught it, because every one of them asserts against the config, and the config
 * was correct for the build and wrong for the runtime. This one asserts the overlap: the file the
 * runtime opens has to be in the list the packager copies.
 */
test('the tray icon is in the packaged file list, not only in the build resources', () => {
  const listed = builderConfig.files ?? [];
  assert.ok(
    listed.some((pattern) => pattern.includes('build/icon.png')),
    `the icon installTray opens must be packaged, or the tray silently never appears: ${listed}`,
  );
  // And it has to actually be there to be packaged.
  assert.ok(
    existsSync(join(here, '..', 'build', 'icon.png')),
    'build/icon.png is missing from the repository',
  );
});

// ── SIGNING.md's one checkable promise ───────────────────────────────────────────────

test('every certificate extension SIGNING.md promises is ignored', () => {
  // The document told the operator "the root .gitignore already excludes a .p12, a .pfx, or a
  // private key". It excluded `*.key` and `*.pem` and NEITHER of the first two — so the two file
  // types a purchased code-signing certificate actually arrives as were exactly the two the
  // sentence covered and the file did not.
  //
  // That claim is load-bearing at one moment: when somebody acts on the document, drops the
  // certificate they just paid for next to the thing it signs, and runs `git add -A`. A signing
  // key in history is not revocable by deleting the commit.
  //
  // Asserted against the file rather than against the prose, so the two cannot drift apart again.
  const root = join(here, '..', '..', '.gitignore');
  const ignore = readFileSync(root, 'utf8');
  for (const pattern of ['*.p12', '*.pfx', '*.cer', '*.crt', '*.key', '*.pem']) {
    assert.ok(
      ignore.split(/\r?\n/).some((line) => line.trim() === pattern),
      `.gitignore must carry ${pattern}: SIGNING.md promises a certificate cannot be committed`,
    );
  }
});

/**
 * electron-builder 26 does not run on Node 18, and nothing in this repository said so.
 *
 * `app-builder-lib` does `require('@noble/hashes/blake2.js')`, which is ESM — legal only where
 * `require(esm)` is supported, i.e. Node 20.19+. On Node 18 the build dies with `ERR_REQUIRE_ESM`
 * from inside a transitive dependency, naming neither Node nor a version. Found by building the
 * Linux target in WSL2 on Node 18.19, which is still an active LTS a contributor may well have.
 *
 * CI pinned `node-version: 22.x` and therefore never saw it. That pin was the only thing enforcing
 * the requirement, and a pin is not a declaration: it protects CI and tells a human nothing.
 */
test('the Node requirement is declared, and CI satisfies it', () => {
  const engines = manifest.engines;
  assert.ok(engines?.node, 'package.json must declare engines.node — electron-builder 26 needs 20.19+');

  // The range is compound, and it has to be: `require(esm)` landed in 20.19 and in 22.12, but NOT
  // in 22.0-22.11 — every one of which satisfies a naive `>=20.19` and then fails with exactly the
  // error the declaration exists to prevent. Node 22.11 disproved that first draft before this
  // test did.
  assert.match(
    engines.node,
    /20\.19/,
    'the 20.x line needs an explicit 20.19 floor: require(esm) landed there',
  );
  assert.match(
    engines.node,
    /22\.12/,
    'a bare >=20.19 admits Node 22.0-22.11, which do NOT have require(esm) and fail the build',
  );

  // The workflow's pin and the declaration must not disagree: a declaration CI violates is worse
  // than none, because it would fail for contributors and pass for the only build that matters.
  const workflow = readFileSync(
    join(here, '..', '..', '.github', 'workflows', 'desktop-release.yml'),
    'utf8',
  );
  const pinned = workflow.match(/node-version:\s*"?(\d+)/);
  assert.ok(pinned, 'desktop-release.yml must pin a node-version');
  assert.ok(
    Number(pinned[1]) >= 22,
    `CI pins Node ${pinned[1]}; the declared range needs 20.19+ or 22.12+, and the 22.x line is ` +
      'the one CI is on',
  );
});
