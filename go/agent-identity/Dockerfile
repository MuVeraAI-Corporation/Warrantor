# agent-identity (Go, I1) — identity and authority service.
# Issues SPIFFE SVIDs, capability tokens, manages revocation.
# HTTP/JSON gateway on :8441 with /healthz and /versionz.
#
# Build context MUST be `go/agent-identity/` (see docker-compose.yml).

# ── Stage 1: build the static binary ─────────────────────────────────────────
FROM golang:1.22 AS builder

# CGO disabled → fully static binary that runs on alpine/musl.
ENV CGO_ENABLED=0 GOOS=linux GOFLAGS=-trimpath

WORKDIR /src
COPY go.mod ./
# This module has no external dependencies, so `go mod download` is a no-op,
# but we keep it so future deps benefit from layer caching.
RUN go mod download

COPY . .

# `go build` from the module root, targeting the cmd package.
RUN go build -o /out/agent-identity -ldflags="-s -w" ./cmd/agent-identity

# ── Stage 2: minimal runtime image ───────────────────────────────────────────
FROM alpine:3.20

# ca-certificates for any outbound TLS; wget ships with alpine (used by the
# compose healthcheck: wget -qO- http://localhost:8441/healthz).
RUN apk add --no-cache ca-certificates

COPY --from=builder /out/agent-identity /usr/local/bin/agent-identity

ENTRYPOINT ["/usr/local/bin/agent-identity"]
# The binary defaults to listening on :8441; pass no args unless overriding.
CMD []

EXPOSE 8441
