# tenant-guard (Go, N4) — multi-tenant GPU scheduling (MIG/MPS).
#
# **Library-only in v1.0** (no cmd/). To keep `docker-compose up` functional this
# image compiles the library (proving the source builds) and runs a tiny HTTP
# health server on the compose-assigned port :8449. Production operator wiring
# (controller-runtime) lands in task 03.
#
# Build context MUST be `go/tenant-guard/` (see docker-compose.yml).

# ── Stage 1: compile the library + a tiny health-server binary ───────────────
FROM golang:1.22 AS builder

ENV CGO_ENABLED=0 GOOS=linux GOFLAGS=-trimpath

WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .

# 1. Build every package in the module (the library). A non-zero exit means the
#    source is broken — fail the image build rather than shipping a dead service.
RUN go build ./...

# 2. Generate a tiny health server from an inline main.go. Listens on :8449,
#    serves {"status":"ok"} at /healthz, and 404s anything else.
RUN mkdir -p /health && \
    printf '%s\n' \
      'package main' \
      '' \
      'import (' \
      '	"fmt"' \
      '	"net/http"' \
      '	"os"' \
      ')' \
      '' \
      'const port = "8449"' \
      '' \
      'func main() {' \
      '	mux := http.NewServeMux()' \
      '	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {' \
      '		w.Header().Set("Content-Type", "application/json")' \
      '		fmt.Fprint(w, `{"service":"tenant-guard","status":"ok","mode":"library-only (N4)"}`)' \
      '	})' \
      '	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {' \
      '		w.Header().Set("Content-Type", "application/json")' \
      '		w.WriteHeader(http.StatusNotFound)' \
      '		fmt.Fprint(w, `{"error":"not found"}`)' \
      '	})' \
      '	fmt.Fprintf(os.Stderr, "tenant-guard health: listening on :%s\n", port)' \
      '	if err := http.ListenAndServe(":"+port, mux); err != nil {' \
      '		fmt.Fprintf(os.Stderr, "tenant-guard health: %v\n", err)' \
      '		os.Exit(1)' \
      '	}' \
      '}' > /health/main.go && \
    cd /health && go build -o /out/health-server .

# ── Stage 2: minimal runtime image ───────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates wget

COPY --from=builder /out/health-server /usr/local/bin/health-server

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost:8449/healthz >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/local/bin/health-server"]

EXPOSE 8449
