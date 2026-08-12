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

## Blocker 0 — the repository does not exist

This has to be settled before anything else, because trusted publishing binds to a repository.

The codebase currently disagrees with itself about its own identity:

| Reference | Where | Status |
|---|---|---|
| `MuVeraAI-Corporation/Warrantor` | Rust workspace `repository`, 8 references | org exists (200), **repo 404** |
| `MuVeraAI/aumos` | GitHub Action README, reusable workflow | org exists (200), **repo 404** |
| `registry.terraform.io/MuVeraAI/warrantor` | Terraform provider README | — |

Both orgs are real. Neither repo is. So today:

- The published GitHub Action instructions (`uses: MuVeraAI/aumos/...`) resolve to nothing.
- Every `Homepage`/`Repository` URL in the Python metadata I just added points at a 404.
- Trusted publishing cannot be configured at all, since there is no repository to name.

**Decide which org is canonical**, create the repo there, push, and make the other set of
references agree. I used `MuVeraAI-Corporation/Warrantor` in the package metadata because it is
what the Rust workspace already declared and it has the most references — change it if that is the
wrong one. It is a one-line sweep either way.

---

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

So the sequence that closes the window is: create the repo → configure trusted publishing → tag a
release. Not: configure and come back to it later.

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

### 2. crates.io — trusted publishing on three crates

crates.io requires the crate to exist before you can configure trusted publishing, which is a
chicken-and-egg you resolve by publishing the first version manually from your own machine
(`cargo login` in your terminal, then `cargo publish`), then configuring OIDC for every release
after. Do that for `warrantor-trust-core` and `warrantor-authority-spec` first — `cargo publish`
will reject `warrantor-warrant` until they are on the registry.

Then, per crate, under Settings → Trusted Publishing: repository `MuVeraAI-Corporation/Warrantor`,
workflow `publish.yml`, environment `crates-io`.

### 3. npm — the `@warrantor` scope

Create the org/scope at <https://www.npmjs.com/org/create>, then configure trusted publishing per
package (`npm trust` can now do this in bulk across packages rather than one at a time):
repository, workflow `publish.yml`, environment `npm`.

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
