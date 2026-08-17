# Signing the desktop installers

The installers this repository produces are **unsigned**. This document says what that costs, what
to buy to stop paying it, and exactly which lines change once the certificates exist.

Signing is procurement, not engineering. The engineering is a handful of config lines and a secrets
table, both written out below. The part that takes weeks is the identity verification a certificate
authority and Apple each run against a legal entity.

## 1. What unsigned means, per platform

**Windows.** SmartScreen intercepts the download and the first run. The user sees *"Windows
protected your PC"* with **Unknown publisher**, and the Run button is hidden behind a **More info**
link. Enterprise-managed machines frequently block it outright with no override available to the
person trying to install.

**macOS.** Gatekeeper refuses the app with *"…cannot be opened because the developer cannot be
verified"*, and the download carries a quarantine attribute the app cannot clear for itself.
Separately from Gatekeeper, on Apple Silicon an *entirely* unsigned or invalidly-signed Mach-O will
not execute at all — the kernel requires at least a valid ad-hoc signature, and packaging
invalidates the one the prebuilt Electron ships with (renamed bundle, renamed Mach-O, rewritten
`Info.plist`, injected `extraResources`). That is why `electron-builder.config.cjs` sets
`mac.identity: '-'`, which is what makes electron-builder re-sign the packaged bundle ad-hoc —
launchable, carrying no publisher identity whatsoever.

**`identity: null` is not a synonym for this and must not be used.** In electron-builder 26 `null`
routes to `handleNullIdentity()`, which logs *"skipped macOS code signing"* and signs nothing;
only the literal `'-'` constructs an ad-hoc identity. The config carried `null` until this was
caught, so any macOS build produced before that fix should be assumed unlaunchable on arm64.

`mac.hardenedRuntime` is set to `false` explicitly for the same reason. electron-builder turns the
hardened runtime on by default for non-MAS builds, and ad-hoc signing under it requires
`com.apple.security.cs.disable-library-validation` — an entitlement that admits arbitrary unsigned
libraries into the process, which is not a trade this product should make to work around a
certificate it has not bought. The hardened runtime buys nothing without notarisation; §4 turns
both on together.

**None of this has been observed on a macOS runner: no macOS build has been executed.** The first
dispatch must verify that the produced `.app` actually launches on arm64. If it does not, the fix
is an `afterPack` hook that runs `codesign --force --sign - <helpers>` and then the app bundle,
before the dmg is assembled.

**Linux.** No equivalent check. AppImage and deb carry no publisher trust to lose, which is why the
Linux legs are the only ones where unsigned costs nothing beyond the missing repository signature a
deb in an apt repo would need.

**Both bundled agents.** The `warrantor` binary shipped in the app's resources is a second
executable inside the bundle. See §5 — it is the part of this that will not be obvious later.

## 2. Why this matters more here than for most products

Warrantor's entire thesis is that a human should **read a verdict** rather than click past a
warning. An installer that opens with an operating-system warning the user is told to click through
teaches the opposite lesson at the first moment of contact, before the product has said anything at
all. Every later argument this product makes about not waving things through is undercut by how it
was installed.

That is the reason to buy the certificates. It is not a polish item.

## 3. What to buy

Prices and eligibility rules change, and both vendors revise them without notice — **re-check
before purchase**. The figures below are indicative only.

### A code-signing certificate for Windows

- **EV (Extended Validation)** — carries SmartScreen reputation **immediately**. Roughly $300–600
  per year. This is what removes the "Unknown publisher" screen on day one.
- **OV (Organization Validation)** — cheaper, but SmartScreen reputation has to *accrue* over
  downloads and time, so early users still see the warning. For a product whose first contact is
  the argument, OV buys most of the cost and little of the benefit.

Note the CA/Browser Forum key-storage change: **all** code-signing private keys must now live on
FIPS-140 validated hardware or in a qualified cloud HSM. Even OV therefore requires a hardware token
or a signing service — a `.p12` on a laptop is no longer an option for anyone. Practical routes:

- **Azure Trusted Signing** — subscription-based, no token to mail, integrates with
  electron-builder's `win.azureSignOptions`. Requires a verified organisation.
- **DigiCert KeyLocker** or **SSL.com eSigner** — cloud HSM plus a signing client.
- A physical USB token — cheapest, and the worst fit for CI, because a token cannot be plugged into
  a GitHub-hosted runner.

Choose the cloud option unless signing will only ever happen on one physical machine.

### An Apple Developer Program membership

$99 per year. Yields a **Developer ID Application** certificate (the one for apps distributed
outside the App Store) and access to `notarytool`. Notarisation is a separate step from signing:
Apple scans the signed app and issues a ticket that is stapled to it, and Gatekeeper checks for that
ticket. Signing without notarising still leaves the app blocked.

## 4. The change that enables it

### macOS

In `electron-builder.config.cjs`, the `mac` block becomes:

```js
  mac: {
    extraResources: [{ from: 'vendor/${arch}/warrantor', to: 'warrantor' }],
    target: [{ target: 'dmg', arch: ['arm64', 'x64'] }],
    category: 'public.app-category.developer-tools',
    hardenedRuntime: true,                                   // required for notarisation
    entitlements: 'build/entitlements.mac.plist',            // already committed, currently inert
    entitlementsInherit: 'build/entitlements.mac.plist',
    notarize: true,
    // `identity: '-'` is REMOVED — leaving it in silently keeps the build ad-hoc, and
    // `hardenedRuntime: false` is replaced by the `true` above rather than deleted, so the
    // change is one edit and not two half-edits.
  },
```

`build/entitlements.mac.plist` already exists and grants only `allow-jit` and
`allow-unsigned-executable-memory`, both of which Electron needs under the hardened runtime. That
file was committed now precisely so this really is a config change and not a config change plus a
file nobody remembered.

### Windows

Add to the `win` block, depending on the route chosen in §3:

```js
    // Certificate file or hardware/cloud token, via CSC_LINK / CSC_KEY_PASSWORD:
    signtoolOptions: { publisherName: 'MuVeraAI Corporation', signingHashAlgorithms: ['sha256'] },
    // or, for Azure Trusted Signing:
    azureSignOptions: { endpoint: '...', certificateProfileName: '...', codeSigningAccountName: '...' },
    forceCodeSigning: true,   // flip this so an unsigned build FAILS rather than shipping quietly
```

`forceCodeSigning: true` is the important half. Once a certificate exists, a build that silently
falls back to unsigned is worse than one that fails.

### Repository secrets

| Secret | Platform | What it is |
| --- | --- | --- |
| `CSC_LINK` | Windows/macOS | Base64 of the certificate, or a path/URL to it |
| `CSC_KEY_PASSWORD` | Windows/macOS | Password for that certificate |
| `APPLE_ID` | macOS | Apple ID used for notarisation |
| `APPLE_APP_SPECIFIC_PASSWORD` | macOS | App-specific password, not the account password |
| `APPLE_TEAM_ID` | macOS | Team identifier from the developer account |
| `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` | Windows | Only for Azure Trusted Signing |

electron-builder reads all of these from the environment. The `package` job in
`.github/workflows/desktop-release.yml` needs them passed as `env:` on the build step, and only on
that step — a secret in the job-level `env` is visible to every step including third-party actions.

## 5. The bundled agent is a second binary, and notarisation knows

This is the constraint that follows directly from shipping the agent inside the app, and it will not
be obvious six months from now.

`Warrantor.app/Contents/Resources/warrantor` is a Mach-O executable inside the bundle. **Apple
rejects notarisation of an app that contains an unsigned executable.** So the agent must be signed
with the same Developer ID and the hardened runtime, and it must be signed *before* the app bundle
that contains it — signing an outer bundle does not sign what is inside it.

electron-builder signs binaries it finds under `Contents/Resources` in recent versions, but do not
assume it: run `codesign -dv --verbose=4` against the bundled agent and `spctl -a -vv` against the
app, and read the output. If the agent is missed, sign it in an `afterPack` hook before the app is
signed.

The Windows side has no equivalent hard requirement — an unsigned `warrantor.exe` inside a signed
installer will still run — but sign it anyway. A signed installer that drops an unsigned executable
which then starts a supervised agent is a distinction no security review will accept, and it is one
extra line.

## 6. What not to do

- **Never commit a `.p12`, a `.pfx`, or a private key.** The root `.gitignore` excludes them — as
  of 2026-08-17. It did **not** when this line was written: it carried `*.key` and `*.pem` and
  neither `*.p12` nor `*.pfx`, so the two file types a purchased certificate actually arrives as
  were the two this document promised were covered and were not. Verified now with
  `git check-ignore` for `.p12`, `.pfx`, `.cer`, `.crt`, `.key` and `.pem`. The claim mattered
  exactly at the moment somebody acted on this document, and a signing key in git history is not
  revocable by deleting the commit. Certificates belong in repository secrets regardless: an ignore
  rule stops an accident, not a decision.
- **Never document "right-click → Open", `xattr -dr com.apple.quarantine`, or "More info → Run
  anyway" as the recommended install path.** That is the click-through habit this product exists to
  break, and putting it in our own README makes it ours. Point reviewers at the published
  `SHA256SUMS` and the build-provenance attestation instead: those verify *where the file came
  from*, which is the honest claim available before signing exists. `gh attestation verify
  <file> --repo <owner>/<repo>` checks it.
- **Do not add `electron-updater` while unsigned.** An update channel over an unsigned artifact is
  an unauthenticated code-execution channel pointed at a machine that runs a supervised agent —
  strictly worse than shipping no updates at all. `publish: null` in the builder config and
  `--publish never` in the workflow are what keep it out; a packaging test asserts the first.
- **Do not raise `--audit-level` or run `npm audit fix --force`** to make a release-blocking
  advisory go away. `--force` moves Electron off the audited pin, which fails a packaging test on
  purpose. The correct responses are a newer `electron-builder`, a scoped `overrides` entry, or
  holding the release.

## 7. Current status

`desktop-release.yml` has **never run**: `workflow_dispatch` is unavailable until the workflow file
is on the default branch, so nothing below had been produced by CI when it was written. The only
build performed by hand was a Windows `electron-builder --dir` run against a dummy stand-in for the
agent — an unpacked directory, not an installer.

**That premise is stale, and correcting it is the point of the two updates below.** CI *has* run:
`docs/W1-delivery-gaps.md` §1.1 records dispatch 2026-08-15, run `31875701622`, with all four
packaging jobs green — mac x64, mac arm64, linux x64, win x64 — each carrying one installer
artifact (win 101 MB, mac ~243 MB per arch, linux ~230 MB). This document went on saying nothing had
been built by CI for two days after that, which is the same failure it exists to catch, pointed the
other way: a status table that understates is still a status table nobody can trust.

**Updated 2026-08-17.** That paragraph was true when written and is no longer. A full Windows NSIS
installer has been produced locally: `Warrantor-1.0.0-x64-setup.exe`, 101,239,598 bytes, sha256
`f7f6cd68517de7d01929579c6bdee5bcb938e3bd0c1cd99bd8a170d0d3b151d2`. The packaged app was also
*launched* from `dist/win-unpacked`, twice — which is how the tray defect in `135df7a` was found,
since `build/` is electron-builder's own resources directory and is not copied into the app, so
`installTray` skipped silently in every packaged build while every config assertion passed.

**Updated again 2026-08-17, after the install.** The installer was run. It completed, created its
Start Menu and Desktop shortcuts and its Add/Remove entry, and the installed app launched, resolved
its bundled agent ahead of an empty `PATH` and loaded the console. The tray — the defect
`135df7a` fixed, and one only a packaged launch can find — installed without a `tray skipped` or
`tray failed` line.

It also found a packaging defect that no configuration test could: a **top-level `executableName`**
applies to every platform, so Windows took the Linux fix too and the app installed to
`%LOCALAPPDATA%\Programs\warrantor-desktop\` with an `Uninstall warrantor-desktop.exe`, while
Add/Remove Programs listed `Warrantor 1.0.0`. Nothing broke, which is why it survived a config
comment asserting Windows was unaffected. It is now scoped to `linux`.

What has still never happened: **no installer has been run on macOS or Linux.** Producing an
artifact, installing it and executing it are three different claims and this document keeps them
apart — all four platforms are built, exactly one is installed, and the macOS ad-hoc signature
that Apple Silicon requires has never been observed executing.

| Item | State |
| --- | --- |
| Windows NSIS installer, per-user, no elevation | **built by CI** (run `31875701622`), **built locally**, **installed and launched** 2026-08-17 (sha256 `f7f6cd68…`) |
| macOS dmg, arm64 and x64 | **built by CI** (run `31875701622`, both arches). Never installed and never launched, so the `identity: '-'` fix in §1 is still unobserved on Apple Silicon |
| Linux AppImage and deb, x64 | **built by CI** (run `31875701622`). Never installed and never launched |
| `warrantor` agent bundled inside the app | **observed in an INSTALLED app**: the trace reads `agent binary: …\resources\warrantor.exe (bundled with the app)`, resolved ahead of an empty `PATH`, agent ready, console loaded |
| SHA256SUMS published per platform | in the workflow; the 2026-08-15 run was a dry run, so this step is still unexecuted |
| Build provenance attestation | in the workflow, never executed — tagged releases only |
| Code signature / notarisation | no — needs the certificates in §3 |
| Update channel | none, and none until signing exists |
