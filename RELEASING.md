# Releasing to npm, PyPI and crates.io

Written against the repository as it actually is, not as a generic guide. Every
blocker below was verified by running the check, and each one stops a publish
outright.

## Read this first

**Nothing here is currently publishable, and that is the correct state.** The
2026-08-09 audit left 33 findings open — 19 High, 12 Medium, 2 Low — and several
describe features that do not exist rather than defects (`AX-06` attestation is
entirely simulated, `AX-32` the policy plane is an empty directory, `AX-41`
governance is unimplemented). Publishing puts a name on a registry permanently:
crates.io **cannot** delete a version, PyPI deletion is discouraged and the
version number is burned forever, and npm unpublish is limited to 72 hours.

The names are reserved by nobody else — all three registries returned 404 for
`@warrantor/*`, `warrantor-agent` and `warrantor-trust-core` at the time of
writing — so there is no land-grab urgency forcing an early release.

If the goal is to *hold the names* rather than ship, say so explicitly and
publish a single deliberate placeholder per registry. That is a different
operation from this runbook and should not be confused with it.

---

## Blockers, in the order you will hit them

### 1. Every crate is marked unpublishable

`rust/Cargo.toml` line 37:

```toml
publish = false  # Local dev releases only during Wave-1 (per scope boundary)
```

Inherited by all 22 crates. `cargo publish` refuses immediately. This is a
deliberate guard from Wave-1, so removing it is a decision, not a chore — it is
the line that has been preventing an accidental release.

### 2. Path dependencies carry no version

```toml
warrantor-api = { path = "../warrantor-api" }        # current
warrantor-api = { path = "../warrantor-api", version = "1.0.0" }   # required
```

crates.io rejects any crate whose dependency has a `path` but no `version` — the
registry cannot resolve a path that only exists in your working tree. Eight
crates are affected.

### 3. Publish order is not free choice

A crate cannot be published before its dependencies exist on the registry. The
dependency graph gives three tiers:

```
tier 1  defstack-cli, warrantor-api, warrantor-confidential-fabric,
        warrantor-credential-vault, warrantor-egress-filter, warrantor-exfil-guard,
        warrantor-inference-proxy, warrantor-kill-switch, warrantor-policy-bridge,
        warrantor-protocol-contracts, warrantor-provena-chain, warrantor-safe-tensors-pp
tier 2  warrantor-authority-spec, warrantor-eval-guard, warrantor-flight-recorder,
        warrantor-trust-core, warrantor-nvtrust-bridge
tier 3  warrantor-gguf-ext, warrantor-sandbox-runtime, warrantor-secure-workspace
```

Publish tier 1 completely, wait for the index to update, then tier 2, then tier 3.

**Do not publish the two `-fuzz` crates.** `warrantor-trust-core-fuzz` and
`warrantor-gguf-ext-fuzz` are fuzzing harnesses with no `description` and no
`license`; they already set `publish = false` in their own manifests and should
keep it.

### 4. No credentials are configured

```
npm whoami   -> E401 (not logged in)
cargo        -> no ~/.cargo/credentials.toml
```

### 5. Python build tooling is absent

`build` and `twine` are not installed locally.

### 6. The repository is private

This does not block registry publishing — but every published package points its
`repository` field at `github.com/MuVeraAI-Corporation/Warrantor`, which returns
404 to anyone who is not a member. A package whose source link is dead invites
exactly the "is this abandoned or malicious?" question you do not want.

Decide the repo's visibility **before** publishing, not after.

---

## npm — 5 packages

Publishable today: `@warrantor/arena`, `@warrantor/console`,
`@warrantor/mcp-gateway`, `@warrantor/mcp-server`, `@warrantor/protocol-contracts`.
None sets `private: true`.

```bash
# 1. Create the scope. It does not exist yet; publishing to an unclaimed scope fails.
npm login                                  # or: npm login --scope=@warrantor
npm org create warrantor                   # only if you want an org rather than a user scope

# 2. Enforce 2FA on the account before the first publish, not after.

# 3. Verify what would ship, per package.
cd typescript/mcp-server
npm publish --dry-run --access public      # --access public is REQUIRED for a scoped package
```

`--access public` is not optional: scoped packages default to **restricted**,
which fails on a free account and silently produces a private package on a paid
one.

```bash
# 4. Publish, once per package.
npm publish --access public
```

Use a **granular access token** in CI rather than a classic automation token, and
scope it to the `@warrantor` packages only.

## PyPI — 35 projects

```bash
python -m pip install --upgrade build twine

# 1. Build one project.
cd python/warrantor_agent
python -m build                            # produces dist/*.whl and dist/*.tar.gz

# 2. Check the metadata renders. twine check catches a broken long_description,
#    which PyPI rejects AFTER upload consumes the version number.
python -m twine check dist/*

# 3. Upload to TestPyPI FIRST. This is the only registry of the three that gives
#    you a real rehearsal.
python -m twine upload --repository testpypi dist/*
python -m pip install --index-url https://test.pypi.org/simple/ warrantor-agent

# 4. Real upload.
python -m twine upload dist/*
```

Use a **PyPI API token**, never a password, and prefer **Trusted Publishing**
(OIDC from GitHub Actions) so no long-lived token exists at all. Trusted
Publishing requires configuring the publisher on PyPI against this repository and
workflow before the first release.

35 projects is a lot of uploads. Do not loop over them until at least one has
completed the TestPyPI round trip.

## crates.io — 20 crates (22 minus the two fuzz harnesses)

```bash
# 1. Remove the workspace guard (a deliberate decision — see blocker 1).
#    rust/Cargo.toml: delete `publish = false`

# 2. Add versions to every path dependency (blocker 2).

# 3. Authenticate.
cargo login                                # token from crates.io/settings/tokens

# 4. Verify each crate packages cleanly, WITHOUT uploading.
cargo publish --dry-run -p warrantor-api

# 5. Publish tier by tier, in the order above.
cargo publish -p warrantor-api
# ... wait for the index, then tier 2, then tier 3
```

`cargo publish` is **irreversible**. There is no unpublish; `cargo yank` only
stops *new* dependency resolution and leaves the version downloadable forever.

Scope the crates.io token to `publish-new` + `publish-update` and nothing else.

## Desktop installers

A different artifact from the three registries above: `.github/workflows/desktop-release.yml`
produces a Windows NSIS installer, a macOS dmg for arm64 and x64, and a Linux AppImage and deb, all
**unsigned**. Nothing here is irreversible the way a registry publish is, but a tag burns a version
number in the artifact names, so rehearse first.

1. **Run the workflow by `workflow_dispatch` with `dry_run` left true, on the branch, before
   tagging.** This is the only place `npm ci` in `desktop/` ever runs, and neither the workflow YAML
   nor the regenerated lockfile is exercised anywhere else — CI's `desktop` job deliberately
   installs nothing. Confirm all four legs upload artifacts.
2. **Confirm `npm audit` was clean in every leg.** RFC W1 makes it a release gate and it is a step
   in the job. If an advisory appears, the fixes are a newer `electron-builder` or a scoped
   `overrides` entry — never `npm audit fix --force`, which moves Electron off the audited pin, and
   never raising `--audit-level`. If neither clears it, record the advisory in `desktop/SIGNING.md`
   and hold the release.
3. **Install one artifact per platform on a machine with no `warrantor` on `PATH`, and confirm the
   window opens.** This is the whole point of bundling the agent and it is the one thing no gate can
   check. The workflow asserts the binary is inside the app; it cannot assert that the app then
   starts it.
4. **Publish `SHA256SUMS-*` alongside the installers.** The release job already attaches them and
   attaches a build-provenance attestation. Together they are the only integrity signal an unsigned
   installer has.
5. **Say in the release notes that the installers are unsigned**, that SmartScreen and Gatekeeper
   will warn, and link `desktop/SIGNING.md`. Do **not** write instructions for bypassing the
   warning — no "More info → Run anyway", no `xattr -dr com.apple.quarantine`. Teaching users to
   click through a security warning is the exact habit this product exists to break, and doing it in
   our own release notes makes it ours. Point at the checksums and the attestation instead.

---

## The order I would actually do this in

1. **Decide repository visibility.** Everything else assumes readers can see the source.
2. **Close or explicitly accept the 19 open High findings.** Publishing does not
   make them worse, but it does make them public and permanent.
3. **Reserve nothing early.** All three names are free and unclaimed.
4. **Rehearse on TestPyPI.** It is the only free rehearsal available.
5. **Publish one package end to end** — `@warrantor/mcp-server` is the smallest
   real surface — and install it from the registry in a clean directory before
   publishing anything else.
6. **Automate only after a manual release has succeeded once.** A release
   workflow that has never been exercised by hand is a way to make an
   irreversible mistake quickly.

## A gap worth naming

No test in this repository installs anything from a registry or from a clean
clone. That is precisely why `@warrantor/aumos-mcp-server` — a package name that
never existed — sat in the primary integration document, and why the deployment
plan told operators to `go install` a crate that is written in Rust. Both were
found by hand.

Until a smoke test does `npm install`/`pip install`/`cargo add` against a
published artifact in a clean environment, the first person to discover a broken
install command will be a user.
