// Command agent-identity is the I1 agent-identity service.
//
// Wave-2 v1.0: serves the HTTP/JSON gateway on the configured address. Real SPIRE integration
// (task 03) will add the SPIFFE WorkloadAPI as an alternative SVID source.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"aumos.dev/agent-identity"
)

func main() {
	addr := flag.String("addr", ":8441", "listen address for the HTTP/JSON gateway")
	trustDomain := flag.String("trust-domain", "aumos.dev", "SPIFFE trust domain")
	flag.Parse()

	svc, err := identity.NewService(*trustDomain)
	if err != nil {
		log.Fatalf("agent-identity: construct service: %v", err)
	}
	gw := identity.NewHTTPGateway(svc)
	h := gw.Handler()

	server := &http.Server{
		Addr:              *addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("agent-identity: shutting down...")
		_ = server.Close()
	}()

	fmt.Fprintf(os.Stderr, "agent-identity: listening on %s (trust-domain=%s, verifying-key=%s)\n",
		*addr, *trustDomain, svc.VerifyingKeyHex())
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("agent-identity: serve: %v", err)
	}
}
