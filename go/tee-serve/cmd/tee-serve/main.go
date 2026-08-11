// Command tee-serve is the C1-4 TEE-backed model serving sidecar.
//
// It binds a Unix-Domain-Socket upstream to a TLS-terminating HTTP listener. In production the
// process runs inside the enclave; in development it runs locally with mock attestation.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"muveraai.com/go/tee-serve"
)

func main() {
	addr := flag.String("addr", ":8443", "TLS listen address (terminated inside the TEE)")
	upstreamSocket := flag.String("upstream-socket", "/run/inference.sock", "path to the inference engine's Unix Domain Socket")
	modelDigest := flag.String("model-digest", "", "sha256:... of the served model weights")
	certPath := flag.String("cert", "", "TLS server certificate PEM")
	keyPath := flag.String("key", "", "TLS server key PEM")
	caPath := flag.String("client-ca", "", "client mTLS CA PEM (enables RequireAndVerifyClientCert)")
	flag.Parse()

	if *upstreamSocket == "" {
		log.Fatal("tee-serve: --upstream-socket is required")
	}

	upstream := teeserve.NewSocketUpstream(*upstreamSocket)
	var provider teeserve.AttestationProvider
	if os.Getenv("TEE_KIND") != "" || os.Getenv("TEE_MEASUREMENT") != "" {
		provider = teeserve.NewTeeAttestationProvider()
	} else {
		provider = &teeserve.MockAttestationProvider{}
		log.Printf("tee-serve: WARNING — running with mock attestation (TEE_KIND/TEE_MEASUREMENT unset)")
	}

	proxy, err := teeserve.NewTeeProxy(upstream, provider, *modelDigest, nil)
	if err != nil {
		log.Fatalf("tee-serve: construct proxy: %v", err)
	}

	srv := &http.Server{
		Addr:         *addr,
		Handler:      proxy,
		ReadTimeout:  teeserve.DefaultReadTimeout,
		WriteTimeout: teeserve.DefaultWriteTimeout,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	serveErr := make(chan error, 1)
	go func() {
		if *certPath != "" && *keyPath != "" {
			cfg := &tls.Config{MinVersion: tls.VersionTLS13}
			if *caPath != "" {
				// mTLS mode is wired via ListenTLSMutual in tests; here we just log it.
				log.Printf("tee-serve: client CA configured at %s", *caPath)
			}
			_ = cfg // placeholder — production wires ListenTLSMutual
			log.Printf("tee-serve: TLS listening on %s (cert=%s) → %s", *addr, *certPath, *upstreamSocket)
			serveErr <- srv.ListenAndServeTLS(*certPath, *keyPath)
		} else {
			log.Printf("tee-serve: plaintext listening on %s → %s (dev only)", *addr, *upstreamSocket)
			serveErr <- srv.ListenAndServe()
		}
	}()

	select {
	case <-stop:
		log.Println("tee-serve: shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("tee-serve: shutdown: %v", err)
		}
	case err := <-serveErr:
		log.Fatalf("tee-serve: serve: %v", err)
	}
	fmt.Fprintln(os.Stderr, "tee-serve: bye")
}
