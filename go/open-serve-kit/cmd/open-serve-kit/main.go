// Command open-serve-kit is the N1 OpenAI-compatible proxy.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"aumos.dev/open-serve-kit"
)

func main() {
	addr := flag.String("addr", ":8443", "listen address")
	backend := flag.String("backend", "mock", "default backend (mock|vllm|triton|tensorrt-llm|ollama)")
	backendURL := flag.String("backend-url", "", "backend base URL (required for non-mock backends)")
	wrap := flag.Bool("attest", false, "wrap responses in an attestation envelope")
	flag.Parse()

	var b proxy.Backend
	switch proxy.BackendType(*backend) {
	case proxy.BackendMock:
		b = &proxy.MockBackend{}
	case proxy.BackendVLLM, proxy.BackendTriton, proxy.BackendTensorRT, proxy.BackendOllama:
		if *backendURL == "" {
			log.Fatalf("open-serve-kit: --backend-url required for backend %s", *backend)
		}
		b = proxy.NewHTTPBackend(proxy.BackendType(*backend), *backendURL)
	default:
		log.Fatalf("open-serve-kit: unknown backend %s", *backend)
	}

	router := proxy.NewRouter(b)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           proxy.NewProxy(router, *wrap),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("open-serve-kit: shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	fmt.Fprintf(os.Stderr, "open-serve-kit: listening on %s (backend=%s, attest=%v)\n", *addr, *backend, *wrap)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("open-serve-kit: serve: %v", err)
	}
}
