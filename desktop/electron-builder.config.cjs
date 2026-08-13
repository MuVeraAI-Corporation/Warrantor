/**
 * How the shell becomes something a reviewer can install.
 *
 * A `.cjs` config rather than YAML or JSON for two reasons that both matter here: this repository
 * requires comments that explain WHY, and JSON cannot carry them; and `test/packaging.test.js`
 * imports this file directly, so the assertion that the builder and `src/policy.js` agree on where
 * the bundled agent lands is a real test rather than a hope. `package.json` is `type: module`, so
 * the extension must be `.cjs` for `module.exports` to work.
 *
 * ── The bundled agent ────────────────────────────────────────────────────────
 *
 * `extraResources` puts the compiled `warrantor` binary at `process.resourcesPath`, which is what
 * `agentBinaryCandidates()` looks at first. That single line is the difference between a reviewer
 * seeing the console and a reviewer seeing an error dialog on first launch: they have no
 * `warrantor` on `PATH` and no reason to.
 *
 * `${arch}` expands per build, and the release workflow writes the freshly compiled binary to
 * `vendor/<arch>/` in the same job that packages it — so the shipped agent always matches the
 * architecture of the app that spawns it. The workflow then asserts the binary is actually inside
 * the produced app, because a pattern that matches nothing is the kind of failure that only shows
 * up on a reviewer's machine.
 */

module.exports = {
  appId: 'com.muveraai.warrantor',
  productName: 'Warrantor',
  copyright: 'Copyright © MuVeraAI Corporation. Licensed under Apache-2.0.',

  directories: {
    output: 'dist',
    buildResources: 'build',
  },

  // An allowlist, not an exclude list. There are no runtime dependencies and none may be added:
  // everything the window shows is served by the agent over HTTP, which is what keeps this shell
  // substitutable for a browser. A `node_modules` entry appearing here would mean that stopped
  // being true, so `test/packaging.test.js` fails if one does.
  files: ['src/**/*', 'package.json'],

  asar: true,

  // No publish configuration, deliberately.
  //
  // A `publish` block is what generates `latest.yml` and makes adding `electron-updater` a two-line
  // change. An update channel over an unsigned artifact is an unauthenticated code-execution
  // channel pointed at a machine that runs a supervised agent — strictly worse than having no
  // updates at all. The updater comes after signing, never before. See SIGNING.md.
  publish: null,

  win: {
    extraResources: [{ from: 'vendor/${arch}/warrantor.exe', to: 'warrantor.exe' }],
    target: [{ target: 'nsis', arch: ['x64'] }],
    // Explicit rather than relied on: the build must produce an installer without a certificate,
    // and it must be a decision recorded here rather than an accident of a default.
    forceCodeSigning: false,
  },

  nsis: {
    // A per-user install into %LOCALAPPDATA% needs no elevation. Two reasons, both security ones.
    // An unsigned installer asking for administrator is the worst possible first prompt from a
    // security product. And an elevated install path invites an elevated launch, which would run
    // the supervised agent as administrator — weakening the containment the warrant claims, on the
    // machine where enforcement actually lives.
    oneClick: false,
    perMachine: false,
    allowToChangeInstallationDirectory: true,
    artifactName: 'Warrantor-${version}-${arch}-setup.${ext}',
  },

  mac: {
    extraResources: [{ from: 'vendor/${arch}/warrantor', to: 'warrantor' }],
    target: [{ target: 'dmg', arch: ['arm64', 'x64'] }],
    category: 'public.app-category.developer-tools',
    // `null` means ad-hoc: no Developer ID is required, and on Apple Silicon an ad-hoc signature is
    // the difference between an app that launches and a Mach-O the kernel refuses to execute at
    // all. It is not a trust signal — Gatekeeper still refuses the download. See SIGNING.md for
    // the one-line change once a certificate exists.
    identity: null,
  },

  linux: {
    extraResources: [{ from: 'vendor/${arch}/warrantor', to: 'warrantor' }],
    target: [
      { target: 'AppImage', arch: ['x64'] },
      { target: 'deb', arch: ['x64'] },
    ],
    category: 'Development',
    // The deb target fails outright without a maintainer. Read from package.json `author`.
    maintainer: 'MuVeraAI Corporation <opensource@muveraai.com>',
  },
};
