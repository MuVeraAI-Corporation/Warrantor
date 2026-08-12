# Distribution channels

Three registries carry Warrantor today. This is what else is worth doing, ranked by how much reach
each adds relative to the effort — not by how many logos it puts on a slide.

## Live now

| Channel | What's there |
|---|---|
| **crates.io** | `warrantor-warrant`, `warrantor-api`, `warrantor-trust-core`, `warrantor-authority-spec` |
| **npm** | `@warrantor/mcp-server`, `@warrantor/mcp-gateway`, `@warrantor/protocol-contracts` |
| **PyPI** | 4 of 12 (`-admission`, `-agent`, `-backup`, `-harness`); the rest are quota-blocked, not broken |
| **docs.rs** | Live already — it builds automatically from crates.io. Free API documentation, no action taken |

---

## The gap that costs the most users

**`cargo install warrantor-warrant` requires a Rust toolchain.** Someone who wants to try a CLI that
supervises their coding agent is not necessarily a Rust developer, and asking them to install a
compiler first loses most of them before the first command.

Everything in the first tier below is a variation on fixing that.

---

## Tier 1 — do these

### 1. GitHub Releases with prebuilt binaries

The single highest-value addition, and a prerequisite for items 2, 3 and 4. Cross-compile
`warrantor` for `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-apple-darwin` and
`x86_64-pc-windows-msvc`, attach them to the release, and `curl | sh` or a download link works for
anyone.

The existing `release.yml` builds only Linux x86_64 and names artifacts `aumos-*`, which is both
incomplete and the old name. `cargo-dist` generates the whole matrix plus installer scripts and a
Homebrew formula from one config.

### 2. The official MCP Registry ← *manifest is ready*

`registry.modelcontextprotocol.io` is the discovery surface for MCP servers — roughly 2,000 listed —
and every MCP client is starting to read from it. You already qualify, because the prerequisite is a
publicly installable package and `@warrantor/mcp-server` is on npm.

`server.json` is written and validated against the published schema. To publish:

```bash
# one-time: install the publisher CLI (see modelcontextprotocol/registry releases)
mcp-publisher login github          # namespace io.github.MuVeraAI-Corporation/* is proven by this
mcp-publisher publish
```

The namespace is reverse-DNS and tied to the GitHub org, so only that org can publish under it.
If you would rather use the domain, `com.muveraai/warrantor` works via a DNS TXT record instead.

### 3. Homebrew

`brew install warrantor` is what a macOS or Linux developer expects. A personal tap
(`MuVeraAI-Corporation/homebrew-tap`) needs no approval and can ship the same day; homebrew-core has
notability requirements and can wait until there are users. `cargo-dist` emits the formula.

### 4. Container images on ghcr.io

You have **16 Dockerfiles** and no published images. GitHub Container Registry is free for public
images, needs no separate account, and authenticates with the same `GITHUB_TOKEN` the workflows
already have. `docker run ghcr.io/muverai-corporation/warrantor-mcp` is a zero-install trial.

---

## Tier 2 — worth doing once there are users

| Channel | Command | Notes |
|---|---|---|
| **cargo-binstall** | `cargo binstall warrantor-warrant` | Free once Tier 1 item 1 exists — it just reads GitHub Releases with conventional artifact names |
| **Scoop / WinGet** | `scoop install warrantor` | Windows. WinGet needs a PR to microsoft/winget-pkgs; Scoop bucket is self-serve |
| **conda-forge** | `conda install warrantor-agent` | Matters for the data-science audience the vLLM and Hugging Face packages target |
| **Docker Hub** | — | Broader reach than ghcr.io but rate-limits anonymous pulls; ghcr first |
| **Awesome lists** | — | `awesome-mcp-servers` and similar drive real traffic and cost one PR |
| **Nix / AUR** | — | Small but vocal audiences; both are usually contributed by users rather than maintainers |

---

## Tier 3 — situational

- **Smithery, mcp.so, PulseMCP, Glama** — third-party MCP directories. Most index the official
  registry automatically, so item 2 covers them. Check before submitting separately.
- **Hugging Face** — you ship `warrantor-hf-plugin`; a Space demonstrating signed-model verification
  would reach that audience where they already are.
- **Claude Desktop extensions (`.dxt`)** — one-click install for non-developers, which is exactly the
  audience the non-developer platform document is about. Worth revisiting when the console exists.
- **Read the Docs** — only if the docs outgrow the repository. `docs.rs` already covers the Rust API.

---

## Not worth it

- **A second package name on the same registry** for discoverability. It fragments installs and
  invites exactly the squatting confusion the naming work was meant to end.
- **Marketplace listings on cloud vendors** before there is a hosted product to bill for.

---

## Ordering

1. **GitHub Releases with real binaries** — unblocks Homebrew, Scoop, and binstall, and removes the
   toolchain requirement that currently gates every CLI user.
2. **MCP Registry** — the manifest is written and valid; it needs one command.
3. **ghcr.io images** — 16 Dockerfiles already exist.
4. Everything else, once someone is actually installing.

A note on sequencing: none of this matters much while the repository is private, because every
package page links to a 404. Making it public is worth more to adoption than any three of these
channels.
