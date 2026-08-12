# aumos-mcp-server (TypeScript) — MCP server exposing the AumOS components as
# tools to any MCP-compatible coding agent (Claude Code, Cursor, Codex, …).
#
# This is a **stdio** JSON-RPC 2.0 server (not a network service). It reads
# newline-delimited requests on stdin and writes responses on stdout; logs go to
# stderr. Run it interactively: `docker compose run --rm aumos-mcp`.
#
# ── Why this image contains Rust binaries ────────────────────────────────────
#
# The server has two kinds of tool. Some reach HTTP services (agent-identity,
# flight-recorder, kill-switch, credential-vault, …); those only need URLs, and
# compose supplies them. The rest — sign, verify, generate_sbom,
# compliance_report, install — shell out to the `trust-core` and `defstack`
# binaries.
#
# Previously this image was Node-only, so those binaries were absent and the
# only mode that worked end to end was `standalone`, which returns responses
# tagged `source: "mock"`. The result was that `docker compose up` gave you a
# demo while the real services sat healthy in the same compose file.
#
# Carrying the binaries costs a Rust build in this image. That is the honest
# price of the default being real enforcement rather than a mock. BuildKit
# caches the cargo layer, so it is paid once per change to the Rust workspace,
# not once per change to this TypeScript source.
#
# Build context MUST be the repository root (see docker-compose.yml), because
# this Dockerfile reaches into both `rust/` and `typescript/`.

# ── Stage 1: build the Rust binaries the connected-mode tools shell out to ───
FROM rust:1.80-slim AS rust-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /rust

# The whole workspace, so Cargo can resolve path dependencies and the shared
# lockfile — the same reason Dockerfile.trust-core copies it wholesale.
COPY rust/ ./

RUN cargo build --release --bin trust-core --bin defstack

# ── Stage 2: install dev deps + compile TypeScript ───────────────────────────
FROM node:20-bookworm-slim AS builder

WORKDIR /app

# Manifests first so `npm install` is cached when only source changes.
# This module has no runtime npm deps (the server is dependency-free), only
# devDependencies (typescript, vitest, @types/node).
COPY typescript/mcp-server/package.json ./
COPY typescript/mcp-server/package-lock.json* ./
RUN npm install --no-audit --no-fund --ignore-scripts

COPY typescript/mcp-server/tsconfig.json ./
COPY typescript/mcp-server/src/ ./src/
RUN npm run build

# Prune to production deps for the runtime image (here: effectively none).
RUN rm -rf node_modules && npm install --omit=dev --no-audit --no-fund --ignore-scripts

# ── Stage 3: minimal Node runtime, with the binaries alongside ───────────────
FROM node:20-bookworm-slim

# libssl3 is what the OpenSSL-linked Rust crates need at runtime;
# ca-certificates is required for any TLS verification.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/dist         ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json

COPY --from=rust-builder /rust/target/release/trust-core /usr/local/bin/trust-core
COPY --from=rust-builder /rust/target/release/defstack   /usr/local/bin/defstack

# Fail the build rather than ship an image whose connected mode is silently
# degraded. An image that looks fine and mocks at runtime is the failure this
# whole change exists to remove.
RUN trust-core key-gen > /dev/null && defstack --help > /dev/null \
    && echo "trust-core and defstack are present and runnable"

ENV NODE_ENV=production

# The server speaks MCP over stdio. Keep stdin attached (compose sets
# stdin_open: true). Logs go to stderr; the JSON-RPC stream on stdout must stay
# clean, so no banners are added here.
ENTRYPOINT ["node", "dist/index.js"]

# No EXPOSE — stdio service, not a network service.
