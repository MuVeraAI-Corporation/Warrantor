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
Separately from Gatekeeper, on Apple Silicon an *entirely* unsigned Mach-O will not execute at all —
the kernel requires at least an ad-hoc signature. That is why `electron-builder.config.cjs` sets
`mac.identity: null` rather than disabling signing: `null` means ad-hoc, which makes the app
launchable while carrying no publisher identity whatsoever. **Verify on the macOS runner that the
produced `.app` actually launches on arm64.** If it does not, the fix is an `afterPack` hook that
runs `codesign --force --sign - <helpers>` and then the app bundle, before the dmg is assembled.

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
    // `identity: null` is REMOVED — leaving it in silently keeps the build ad-hoc.
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

- **Never commit a `.p12`, a `.pfx`, or a private key.** The root `.gitignore` already excludes
  `*.key` and `*.pem`; neither pattern catches `.p12`. Certificates go in repository secrets.
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

| Item | State |
| --- | --- |
| Windows NSIS installer, per-user, no elevation | built, unsigned |
| macOS dmg, arm64 and x64 | built, ad-hoc signed only |
| Linux AppImage and deb, x64 | built, unsigned |
| `warrantor` agent bundled inside the app | yes, and preferred over `PATH` |
| SHA256SUMS published per platform | yes |
| Build provenance attestation | yes, on tagged releases |
| Code signature / notarisation | no — needs the certificates in §3 |
| Update channel | none, and none until signing exists |
