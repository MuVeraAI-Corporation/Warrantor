# aumos-mcp-server (TypeScript) — MCP server exposing the AumOS components as
# tools to any MCP-compatible coding agent (Claude Code, Cursor, Codex, …).
#
# This is a **stdio** JSON-RPC 2.0 server (not a network service). It reads
# newline-delimited requests on stdin and writes responses on stdout; logs go to
# stderr. Run it interactively: `docker-compose run --rm aumos-mcp`.
#
# Build context MUST be `typescript/aumos-mcp-server/` (see docker-compose.yml).

# ── Stage 1: install dev deps + compile TypeScript ───────────────────────────
FROM node:20-bookworm-slim AS builder

WORKDIR /app

# Copy only manifests first so `npm install` is cached when source changes.
# This module has no runtime npm deps (the server is dependency-free), only
# devDependencies (typescript, vitest, @types/node).
COPY package.json ./
# If a lockfile is present use it for reproducible installs; otherwise fall back
# to a plain install.
COPY package-lock.json* ./
RUN npm install --no-audit --no-fund --ignore-scripts

# Copy the rest of the source and compile to dist/.
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# Prune to production deps for the runtime image (here: effectively none).
RUN rm -rf node_modules && npm install --omit=dev --no-audit --no-fund --ignore-scripts

# ── Stage 2: minimal Node runtime ────────────────────────────────────────────
FROM node:20-bookworm-slim

WORKDIR /app

# Bring over the compiled output and production node_modules.
COPY --from=builder /app/dist        ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json

# The server speaks MCP over stdio. Keep stdin attached (compose sets
# stdin_open: true). Logs are emitted on stderr; the JSON-RPC stream on stdout
# must stay clean (no banners), so we do not add any here.
ENTRYPOINT ["node", "dist/index.js"]

# AUMOS_MODE=standalone (set by compose) makes every tool return deterministic
# mock responses — zero external dependencies, ideal for demos and dry-runs.
ENV NODE_ENV=production

# No EXPOSE — stdio service, not a network service.
