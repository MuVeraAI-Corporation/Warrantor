# fleet-marshal (Go, F4) — OTA model fleet management (canary / blue-green).
# v1.0 runs the rollout logic via an in-process dry-run executor and exposes a
# control HTTP surface on :8450 with /healthz. Production K8s CRD binding lands
# in task 03.
#
# Build context MUST be `go/fleet-marshal/` (see docker-compose.yml).

# ── Stage 1: build the static binary ─────────────────────────────────────────
FROM golang:1.22 AS builder

ENV CGO_ENABLED=0 GOOS=linux GOFLAGS=-trimpath

WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN go build -o /out/fleet-marshal -ldflags="-s -w" ./cmd/fleet-marshal

# ── Stage 2: minimal runtime image ───────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=builder /out/fleet-marshal /usr/local/bin/fleet-marshal

ENTRYPOINT ["/usr/local/bin/fleet-marshal"]
# Override the HTTP surface port to match the compose mapping (8450:8450).
# The binary's `--http-addr` flag defaults to :8446, which collides with the
# kill-switch compose port; pin it explicitly here.
CMD ["--http-addr", ":8450"]

EXPOSE 8450
