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

// ── the Electron pin ──────────────────────────────────────────────────────────

/**
 * RFC W1 states the pin and says `npm audit` in `desktop/` is a release gate. A pin stated in prose
 * is a sentence; asserted here it is a gate, and `npm audit fix --force` — the reflex fix for an
 * advisory in electron-builder's tree — moves Electron off the audited version and fails this.
 */
test('Electron stays on the audited pin', () => {
  assert.equal(manifest.devDependencies.electron, '^43.4.0');
  const resolved = lockfile.packages['node_modules/electron'];
  assert.ok(resolved, 'the lockfile must actually contain electron');
  assert.ok(
    resolved.version.startsWith('43.'),
    `the lockfile resolves electron ${resolved.version}, off the 43.x pin`,
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
