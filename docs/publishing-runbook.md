# Publishing runbook

Everything that can be prepared without credentials is done. What remains is a short sequence of
clicks in three web UIs, and one decision only you can make.

## Do not create API tokens

The instinct is to generate a PyPI/npm/crates.io token and put it in a repository secret. Don't.
All three registries now support **Trusted Publishing**, where GitHub Actions proves its identity
with a short-lived OIDC token and the registry hands back credentials that expire in minutes.

That matters here more than for most projects:

- **Nothing long-lived exists to leak.** No token in a secret, a `.env`, a shell history, or a
  screenshot. A compromised build-time dependency has nothing to exfiltrate.
- **The grant is scoped to a workflow, not a person.** Only `publish.yml`, in this repository, in
  the named environment, can publish. A token is scoped to whoever holds it.
- **npm adds provenance for free.** Publishing over OIDC attaches an attestation binding the
  tarball to the commit and workflow that produced it — verifiable by anyone.
- **Tokens are being actively phased out.** npm began restricting bypass-2FA granular access tokens
  in 2026 and now directs automated publishing to trusted publishing or staged publishing.

It is also, frankly, the consistent thing to do. This project's whole argument is that authority
should be bounded, scoped in advance, and answerable afterwards. Publishing it with a permanent
credential pasted into a secret would undercut the thesis on the first line of the release process.

---

## Correction — the repository DOES exist

An earlier version of this runbook stated as its first blocker that the repository did not exist.
**That was wrong.** `MuVeraAI-Corporation/Warrantor` exists, is **private**, has `main` as its default
branch, and was pushed to today. The error came from checking with unauthenticated `curl`: GitHub
returns 404 for a private repository to anonymous requests, precisely so it does not leak the
existence of private repos. An authenticated `gh repo view` shows it immediately.

The consequence is good news — **trusted publishing can be configured right now.** OIDC works fine
from a private repository, and PyPI pending publishers can be registered for projects that do not
exist yet.

Two real prerequisites remain, and neither is a blocker so much as a step:

- **`publish.yml` is not yet on remote `main`.** Only the seven older workflows are there. Tag-triggered
  publishing needs it reachable on the repo.
- **The three GitHub environments do not exist.** `pypi`, `crates-io` and `npm` must be created in
  repo Settings → Environments. They need no secrets; they exist so the trusted-publisher config has
  an environment name to bind to.

The canonical org question is also settled: the git remote is already
`https://github.com/MuVeraAI-Corporation/Warrantor.git`, so `MuVeraAI-Corporation` is the answer and
the package metadata already points at it. What remains is that the repo is private, so those URLs
404 for anyone who installs a package until it is made public.

## Blocker 1 — the names are unclaimed, and that is a live risk

Verified against the registries:

| Registry | Names | Status |
|---|---|---|
| PyPI | all 12 `warrantor-*` | **404 — unclaimed** |
| crates.io | `warrantor-warrant` | **does not exist** |
| npm | `@warrantor` scope | **zero packages** |

Your documentation tells developers to install names that nobody owns. Anyone can register
`warrantor-agent` on PyPI right now and ship whatever they like to people following your README.

One thing to be clear about, because it is a common misunderstanding: **a PyPI "pending publisher"
does not reserve the name.** PyPI's own documentation is explicit — the project is not created
until a publish actually happens, and if someone else registers the name first, your pending
publisher is invalidated. Configuring trusted publishing is necessary but not sufficient; only an
actual first publish claims the name.

So the sequence that closes the window is: configure trusted publishing → get `publish.yml` onto
`main` → tag a release. Not: configure and come back to it later.

---

## What is already done

- **PyPI metadata complete on all 12 packages** — `classifiers`, `[project.urls]`, license,
  `requires-python`, authors. They were missing classifiers and URLs, which PyPI renders in the
  sidebar and uses for search facets.
- **crates.io path-dependency versions.** `warrantor-warrant` declared its workspace dependencies
  by path only. `cargo publish` refuses that — correctly, since a published crate cannot depend on
  a local directory. Both now carry `version = "1.0.0"` alongside the path.
- **`.github/workflows/publish.yml`** — tag-triggered, token-free, with crates.io publishing
  ordered so dependencies land before `warrantor-warrant`.
- **`twine check --strict`** runs before any upload, so a malformed README fails the build rather
  than half a 12-package release.

---

## The part only you can do

### 1. PyPI — twelve pending publishers

At <https://pypi.org/manage/account/publishing/>, add a **pending publisher** for each package:

| Field | Value |
|---|---|
| PyPI Project Name | `warrantor-agent` (then repeat for the other 11) |
| Owner | `MuVeraAI-Corporation` *(or whichever org you chose)* |
| Repository name | `Warrantor` |
| Workflow name | `publish.yml` |
| Environment name | `pypi` |

The twelve names: `warrantor-admission`, `warrantor-agent`, `warrantor-backup`,
`warrantor-harness`, `warrantor-hf-plugin`, `warrantor-jira`, `warrantor-langchain`,
`warrantor-ocsf`, `warrantor-rbac`, `warrantor-retention`, `warrantor-sla`, `warrantor-vllm`.

### 2. crates.io — four crates, in dependency order

crates.io requires a crate to exist before trusted publishing can be attached to it, so the first
version of each is published manually from your terminal. You hold the token; it never passes
through anything else.

The dependency chain is **four crates deep, not two** — an earlier version of this runbook said two,
which would have failed on the third command. `warrantor-api` is a path dependency of both
`trust-core` and `authority-spec`, and all three had to be given explicit versions alongside their
paths before `cargo publish` would accept them:

```bash
cd rust
cargo login            # paste your crates.io token at the prompt
cargo publish -p warrantor-api
cargo publish -p warrantor-trust-core        # depends on warrantor-api
cargo publish -p warrantor-authority-spec    # depends on warrantor-api
cargo publish -p warrantor-warrant           # depends on both of the above
```

Wait for each to appear on the registry before running the next — crates.io indexes asynchronously,
and the following command will fail if its dependency is not yet visible. `cargo publish --dry-run`
first if you want to rehearse without committing; a published version can be yanked but never
replaced.

Then, per crate, under Settings → Trusted Publishing: repository `MuVeraAI-Corporation/Warrantor`,
workflow `publish.yml`, environment `crates-io`.

### 3. npm — create the scope, publish once, then attach

npm also requires the package to exist before a trusted publisher can be attached, so the first
release is manual here too.

1. Create the org/scope at <https://www.npmjs.com/org/create> — name it `warrantor`.
2. Publish each package once from your terminal:

```bash
npm login              # browser-based; no token to paste
for pkg in mcp-server mcp-gateway protocol-contracts; do
  ( cd typescript/$pkg && npm install --no-audit --no-fund && npm run build && npm publish --access public )
done
```

`--access public` is required: scoped packages default to private, and the publish fails without a
paid account.

3. Then attach trusted publishing per package — `npm trust` can now do this in bulk rather than one
   at a time: repository `MuVeraAI-Corporation/Warrantor`, workflow `publish.yml`, environment `npm`.

All five TypeScript packages were missing `repository` metadata, which npm provenance verifies
against; that has been added along with `homepage` and `bugs`.

### 4. GitHub environments

Create three environments in repo Settings → Environments: `pypi`, `crates-io`, `npm`. They need no
secrets. Adding required reviewers to them is worth considering — it makes a publish a thing
somebody approves, which is the same shape as settling a warrant.

---

## Then

```bash
git tag v1.0.0
git push origin v1.0.0
```

Watch the run. `workflow_dispatch` with `dry_run` is there for rehearsing the build and metadata
validation without publishing anything.

---

## A note on what I did not do

I did not create any of these tokens or accounts, and won't. Entering credentials into login forms
and handling API tokens is yours to do — not because of a process rule, but because a credential
that passes through an agent is a credential you can no longer reason about the blast radius of.
The trusted-publishing path above exists partly so that this stops being a limitation: once it is
configured, there is no token for anyone to hold, including you.
