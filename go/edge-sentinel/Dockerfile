# edge-sentinel (Go, F3) — edge inference attestation agent (<5MB sidecar).
# Runs next to the inference engine and exposes a tiny HTTP surface on :8451
# (/healthz, /lastgood, /killed).
#
# Build context MUST be `go/edge-sentinel/` (see docker-compose.yml).

# ── Stage 1: build the static binary ─────────────────────────────────────────
FROM golang:1.22 AS builder

ENV CGO_ENABLED=0 GOOS=linux GOFLAGS=-trimpath

WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN go build -o /out/edge-sentinel -ldflags="-s -w" ./cmd/edge-sentinel

# ── Stage 2: minimal runtime image ───────────────────────────────────────────
# edge-sentinel targets a <5MB footprint; alpine + a stripped static binary
# satisfies that budget.
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=builder /out/edge-sentinel /usr/local/bin/edge-sentinel

ENTRYPOINT ["/usr/local/bin/edge-sentinel"]
# Override the HTTP surface port to match the compose mapping (8451:8451).
# The binary's `--http-addr` flag defaults to :8445, which collides with the
# flight-recorder compose port; pin it explicitly here.
CMD ["--http-addr", ":8451"]

EXPOSE 8451
