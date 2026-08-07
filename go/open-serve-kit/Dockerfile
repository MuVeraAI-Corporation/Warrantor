# open-serve-kit (Go, N1) — OpenAI-compatible inference proxy.
# Routes to the Mock backend by default; set BACKEND=vllm + BACKEND_URL to
# connect to a real model server. HTTP gateway on :8443 with /healthz.
#
# Build context MUST be `go/open-serve-kit/` (see docker-compose.yml).

# ── Stage 1: build the static binary ─────────────────────────────────────────
FROM golang:1.22 AS builder

ENV CGO_ENABLED=0 GOOS=linux GOFLAGS=-trimpath

WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN go build -o /out/open-serve-kit -ldflags="-s -w" ./cmd/open-serve-kit

# ── Stage 2: minimal runtime image ───────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=builder /out/open-serve-kit /usr/local/bin/open-serve-kit

ENTRYPOINT ["/usr/local/bin/open-serve-kit"]
CMD []

EXPOSE 8443
