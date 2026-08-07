# defstack-cloud (Go) — managed SaaS control plane for tenant management.
#
# **Library-only in v1.0** (no cmd/). To keep `docker-compose up` functional this
# image compiles the library (proving the source builds) and runs a tiny HTTP
# health server on the compose-assigned port :8453.
#
# Build context MUST be `go/defstack-cloud/` (see docker-compose.yml).

# ── Stage 1: compile the library + a tiny health-server binary ───────────────
FROM golang:1.22 AS builder

ENV CGO_ENABLED=0 GOOS=linux GOFLAGS=-trimpath

WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .

RUN go build ./...

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
      'const port = "8453"' \
      '' \
      'func main() {' \
      '	mux := http.NewServeMux()' \
      '	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {' \
      '		w.Header().Set("Content-Type", "application/json")' \
      '		fmt.Fprint(w, `{"service":"defstack-cloud","status":"ok","mode":"library-only"}`)' \
      '	})' \
      '	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {' \
      '		w.Header().Set("Content-Type", "application/json")' \
      '		w.WriteHeader(http.StatusNotFound)' \
      '		fmt.Fprint(w, `{"error":"not found"}`)' \
      '	})' \
      '	fmt.Fprintf(os.Stderr, "defstack-cloud health: listening on :%s\n", port)' \
      '	if err := http.ListenAndServe(":"+port, mux); err != nil {' \
      '		fmt.Fprintf(os.Stderr, "defstack-cloud health: %v\n", err)' \
      '		os.Exit(1)' \
      '	}' \
      '}' > /health/main.go && \
    cd /health && go build -o /out/health-server .

# ── Stage 2: minimal runtime image ───────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates wget

COPY --from=builder /out/health-server /usr/local/bin/health-server

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost:8453/healthz >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/local/bin/health-server"]

EXPOSE 8453
