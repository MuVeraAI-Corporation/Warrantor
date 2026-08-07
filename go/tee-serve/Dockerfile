# tee-serve (Go, C1-4) — TEE-backed model serving sidecar.
# Binds a Unix-Domain-Socket upstream to a TLS-terminating HTTP listener. In
# production it runs inside the enclave; in development it runs locally with
# mock attestation. HTTP surface on :8448 with /healthz.
#
# Build context MUST be `go/tee-serve/` (see docker-compose.yml).

# ── Stage 1: build the static binary ─────────────────────────────────────────
FROM golang:1.22 AS builder

ENV CGO_ENABLED=0 GOOS=linux GOFLAGS=-trimpath

WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN go build -o /out/tee-serve -ldflags="-s -w" ./cmd/tee-serve

# ── Stage 2: minimal runtime image ───────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=builder /out/tee-serve /usr/local/bin/tee-serve

ENTRYPOINT ["/usr/local/bin/tee-serve"]
# Dev mode: serve plain HTTP (no TLS certs). The binary falls back to
# ListenAndServe when --cert/--key are absent.
CMD ["--addr", ":8448"]

EXPOSE 8448
