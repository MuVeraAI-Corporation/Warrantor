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

  // Set explicitly because the Linux default is package.json `name`, and this package is scoped:
  // `@warrantor/desktop` becomes `@warrantordesktop`, whose `@` is not legal in a file path.
  // electron-builder refuses at the AppImage step with "executableName contains characters that
  // cannot be safely used in file paths", which is where the first-ever run of desktop-release
  // died — after the Electron download and the packaging, so it costs a full leg to discover.
  //
  // Windows and macOS derive theirs from productName and were unaffected, which is exactly why
  // this could sit in a config that reads fine and had never been executed.
  executableName: 'warrantor-desktop',

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
    // `'-'` is ad-hoc. `null` is NOT, and the difference is the whole macOS leg.
    //
    // In electron-builder 26, `identity: null` reaches `handleNullIdentity()`, which logs
    // "skipped macOS code signing" and signs nothing at all; only the literal `'-'` constructs an
    // ad-hoc `Identity` (app-builder-lib/out/macPackager.js, out/mac/MacTargetHelper.js).
    // Packaging renames Electron.app and its Mach-O, rewrites Info.plist and injects
    // `extraResources`, all of which invalidate the ad-hoc signature the prebuilt Electron ships
    // with — so "skip signing" leaves an invalidly-signed bundle, and on Apple Silicon the kernel
    // refuses to execute one. That failure passes every gate in the release workflow and appears
    // only as an app that will not start on the reviewer's machine.
    //
    // It is not a trust signal: Gatekeeper still refuses the download. See SIGNING.md for the
    // change once a certificate exists.
    identity: '-',
    // Explicit `false`, not a default. electron-builder turns the hardened runtime ON for every
    // non-MAS macOS build unless it is switched off (`hardenedRuntime !== false`), and ad-hoc
    // signing under the hardened runtime requires `com.apple.security.cs.disable-library-validation`
    // — an entitlement that lets arbitrary unsigned libraries load into the process. Granting that
    // to a security product to work around a certificate we have not bought is a worse trade than
    // not enabling the hardened runtime at all, which buys nothing without notarisation anyway.
    // It is switched on together with the Developer ID and notarisation; see SIGNING.md §4.
    hardenedRuntime: false,
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
    // Without this, desktop environments cannot associate the running window with this .desktop
    // entry: the window shows a generic icon and does not group under the launcher. Electron uses
    // it as app_id / WM_CLASS. It must match the .desktop filename, which is `executableName`.
    desktopName: 'warrantor-desktop.desktop',
    synopsis: 'Supervise an AI agent under a warrant you granted.',
  },
};
