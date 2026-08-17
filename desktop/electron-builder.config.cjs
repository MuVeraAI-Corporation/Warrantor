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
  // The sentence that used to sit here — "Windows and macOS derive theirs from productName and were
  // unaffected" — was FALSE, and running the installer is what showed it. A top-level
  // `executableName` applies to every platform, so Windows took it too: the app installed to
  // `%LOCALAPPDATA%\Programs\warrantor-desktop\warrantor-desktop.exe`, the uninstaller was named
  // `Uninstall warrantor-desktop.exe`, and Add/Remove Programs listed `Warrantor 1.0.0` pointing at
  // a directory called something else.
  //
  // Nothing was broken by it — the app launched, found its bundled agent and loaded the console —
  // which is precisely why it survived: a packaging defect that produces a working install is one
  // only an install reveals. It is now scoped to `linux`, the platform that needed it, and Windows
  // and macOS genuinely do derive theirs from productName.

  directories: {
    output: 'dist',
    buildResources: 'build',
  },

  // An allowlist, not an exclude list. There are no runtime dependencies and none may be added:
  // everything the window shows is served by the agent over HTTP, which is what keeps this shell
  // substitutable for a browser. A `node_modules` entry appearing here would mean that stopped
  // being true, so `test/packaging.test.js` fails if one does.
  // `build/icon.png` is in here for the TRAY, and it took a packaged launch to find out why it
  // had to be. `build/` is electron-builder's own resources directory: it is read at BUILD time to
  // make the window and installer icons, and it is not copied into the app. So
  // `join(app.getAppPath(), 'build', 'icon.png')` exists in development and does not exist in a
  // packaged build — and `installTray` skips silently when the image is empty, which is the right
  // behaviour for a missing icon and the wrong outcome here. The first launch of a packaged app
  // traced `tray skipped: no icon`, and nothing else would have said so: every unit test asserts
  // against the config, and the config was correct for the build and wrong for the runtime.
  files: ['src/**/*', 'package.json', 'build/icon.png'],

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
    // The SECOND thing the scoped package name breaks. AppImage names itself from productName and
    // was fine once `executableName` was set; deb defaults to `${name}_${version}_${arch}.${ext}`,
    // and `@warrantor/desktop` puts a SLASH in the output path — fpm is handed
    // `dist/@warrantor/desktop_0.0.0_amd64.deb`, a directory that does not exist, and dies with a
    // bare "fpm process failed 1" that names neither the path nor the cause.
    //
    // Named to match the Windows artifact rather than left to a default, because a default that
    // depends on the package name is the thing that broke twice.
    artifactName: 'Warrantor-${version}-${arch}.${ext}',
    category: 'Development',
    // The deb target fails outright without a maintainer. Read from package.json `author`.
    maintainer: 'MuVeraAI Corporation <opensource@muveraai.com>',
    // Without a desktop name, Electron has no app_id / WM_CLASS and a desktop environment cannot
    // associate the running window with the installed .desktop entry: generic icon, no launcher
    // grouping. electron-builder 26 takes it from package.json `desktopName` and copies it in when
    // this is set — `linux.desktopName` is NOT a key in this version's schema, and setting it
    // fails validation for EVERY platform, not just Linux.
    syncDesktopName: true,
    // Scoped here rather than at the top level, where it silently renamed the Windows install
    // directory and executable as well. See the note above `directories` for what running the
    // installer showed.
    executableName: 'warrantor-desktop',
  },
};
