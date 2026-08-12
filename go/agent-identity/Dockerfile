# agent-identity (Go, I1) — identity and authority service.
# Issues SPIFFE SVIDs, capability tokens, manages revocation.
# HTTP/JSON gateway on :8441 with /healthz and /versionz.
#
# Build context MUST be `go/agent-identity/` (see docker-compose.yml).

# ── Stage 1: build the static binary ─────────────────────────────────────────
# Must be >= the `go` directive in go.mod. Adding github.com/spiffe/go-spiffe/v2
# (for real SPIFFE ID validation) raised that to 1.24.0, and the base image was
# left at 1.22 -- so `go mod download` failed with
# "go.mod requires go >= 1.24.0 (running go 1.22.12)" and this image could not be
# built at all. Nothing caught it because no CI job builds these images.
FROM golang:1.24 AS builder

# CGO disabled → fully static binary that runs on alpine/musl.
ENV CGO_ENABLED=0 GOOS=linux GOFLAGS=-trimpath

WORKDIR /src
# go.sum is required now that the module has a real dependency: without it
# `go mod download` cannot verify module checksums.
COPY go.mod go.sum ./
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
