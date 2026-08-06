// Command verify_go is the A6 conformance Go verifier entry point.
//
// Reads a golden vector from stdin (JSON) and verifies the signature against the recorded
// verifying key using crypto/ed25519. Exits 0 on success, 1 on mismatch.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

type vector struct {
	PayloadHex      string `json:"payload_hex"`
	VerifyingKeyHex string `json:"verifying_key_hex"`
	SignatureHex    string `json:"signature_hex"`
	Expected        string `json:"expected"`
}

func main() {
	var buf []byte
	for {
		b := make([]byte, 4096)
		n, err := os.Stdin.Read(b)
		if n > 0 {
			buf = append(buf, b[:n]...)
		}
		if err != nil {
			break
		}
	}
	var v vector
	if err := json.Unmarshal(buf, &v); err != nil {
		fmt.Fprintf(os.Stderr, "go: parse: %v\n", err)
		os.Exit(2)
	}
	payload, err := hex.DecodeString(v.PayloadHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "go: payload hex: %v\n", err)
		os.Exit(2)
	}
	vk, err := hex.DecodeString(v.VerifyingKeyHex)
	if err != nil || len(vk) != ed25519.PublicKeySize {
		fmt.Fprintf(os.Stderr, "go: bad verifying key\n")
		os.Exit(2)
	}
	sig, err := hex.DecodeString(v.SignatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		fmt.Fprintf(os.Stderr, "go: bad signature\n")
		os.Exit(2)
	}
	valid := ed25519.Verify(ed25519.PublicKey(vk), payload, sig)
	expected := v.Expected == "valid"
	if valid == expected {
		fmt.Printf("go: ok (valid=%v, expected=%s)\n", valid, v.Expected)
		os.Exit(0)
	}
	fmt.Fprintf(os.Stderr, "go: MISMATCH (valid=%v, expected=%s)\n", valid, v.Expected)
	os.Exit(1)
}
