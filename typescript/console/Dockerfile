# console (TypeScript, X7) — AumOS enterprise policy / evidence console.
#
# v1.0 ships the data model, API client, and view reducers (a testable library,
# `src/index.ts`). The React/Next.js UI layer is task 03 and consumes this
# library. To keep `docker-compose up` functional on port 3000, this image
# compiles the library (proving the source builds) and runs a tiny HTTP server
# that serves `/healthz` and a placeholder landing page describing the console.
#
# Build context MUST be `typescript/console/` (see docker-compose.yml).

# ── Stage 1: install dev deps + compile the library ──────────────────────────
FROM node:20-bookworm-slim AS builder

WORKDIR /app

COPY package.json ./
COPY package-lock.json* ./
RUN npm install --no-audit --no-fund --ignore-scripts

COPY tsconfig.json ./
COPY src/ ./src/
# Compile the console library. A non-zero exit means the source is broken —
# fail the image build rather than shipping a dead service.
RUN npm run build

# Generate the tiny HTTP server that will run in the runtime image.
RUN mkdir -p /srv && \
    printf '%s\n' \
      '// Minimal HTTP server for the v1.0 console placeholder. Replaced by the' \
      '// Next.js app (task 03) which consumes the compiled library.' \
      "import { createServer } from 'node:http';" \
      "const PORT = Number(process.env.PORT ?? 3000);" \
      "const HTML = `<!doctype html><html><head><meta charset=\"utf-8\">" \
      "<title>AumOS Console</title><style>body{font-family:system-ui,sans-serif;background:#0b1020;color:#e6edf3;margin:0;padding:3rem;line-height:1.5}h1{margin-top:0}code{background:#1f2740;padding:.15em .4em;border-radius:4px}</style></head>" \
      "<body><h1>AumOS Console (X7)</h1>" \
      "<p>The enterprise policy &amp; evidence console. v1.0 ships the data model, API client, and view reducers as a TypeScript library.</p>" \
      "<p>The React/Next.js UI layer is <em>task 03</em> and consumes <code>@aumos/console</code>.</p>" \
      "<p>Health: <a href=\"/healthz\">/healthz</a></p></body></html>`;" \
      "const server = createServer((req, res) => {" \
      "  if (req.url === '/healthz') {" \
      "    res.writeHead(200, { 'Content-Type': 'application/json' });" \
      "    res.end(JSON.stringify({ service: 'console', status: 'ok', mode: 'placeholder (X7 library built)' }));" \
      "    return;" \
      "  }" \
      "  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });" \
      "  res.end(HTML);" \
      "});" \
      "server.listen(PORT, () => console.error(`console: listening on :${PORT}`));" \
      > /srv/server.mjs

# ── Stage 2: minimal Node runtime ────────────────────────────────────────────
FROM node:20-bookworm-slim

WORKDIR /app

# Ship the compiled library (for downstream tooling) and the placeholder server.
COPY --from=builder /app/dist          ./dist
COPY --from=builder /app/package.json  ./package.json
COPY --from=builder /srv/server.mjs    ./server.mjs

ENV NODE_ENV=production
ENV PORT=3000

# wget is available in the slim base via apt if needed; the slim image ships
# enough for the compose healthcheck (curl is not present, so the compose file
# does not define one for console — we add a node-based probe instead).
HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD node -e "fetch('http://localhost:3000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["node", "server.mjs"]

EXPOSE 3000
