// Command verify_merkle_go is the A6 conformance Go Merkle-root verifier.
//
// Reads a Merkle golden vector from stdin (JSON) and recomputes the RFC 6962 root over
// `leaves_hex`, comparing to `expected_root_hex`. Exits 0 on match, 1 on mismatch.
//
// Mirrors the Rust `merkle_vector` example and the Python verifier in this directory.
//
// RFC 6962 ordering: leaf = SHA-256(0x00 || leaf), node = SHA-256(0x01 || left || right),
// orphan-promotion for odd layers (no duplication).
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

type merkleVector struct {
	LeavesHex      []string `json:"leaves_hex"`
	ExpectedRootHex string  `json:"expected_root_hex"`
}

func leafHash(leaf []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(leaf)
	return h.Sum(nil)
}

func nodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

func merkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		z := make([]byte, 32)
		return z
	}
	layer := make([][]byte, len(leaves))
	for i, l := range leaves {
		layer[i] = leafHash(l)
	}
	for len(layer) > 1 {
		var next [][]byte
		i := 0
		for i < len(layer) {
			if i+1 < len(layer) {
				next = append(next, nodeHash(layer[i], layer[i+1]))
			} else {
				next = append(next, layer[i]) // orphan promotion
			}
			i += 2
		}
		layer = next
	}
	return layer[0]
}

func main() {
	var buf []byte
	chunk := make([]byte, 4096)
	for {
		n, err := os.Stdin.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		if err != nil {
			break
		}
	}
	var v merkleVector
	if err := json.Unmarshal(buf, &v); err != nil {
		fmt.Fprintf(os.Stderr, "go: merkle parse: %v\n", err)
		os.Exit(2)
	}
	leaves := make([][]byte, len(v.LeavesHex))
	for i, h := range v.LeavesHex {
		b, err := hex.DecodeString(h)
		if err != nil {
			fmt.Fprintf(os.Stderr, "go: merkle leaf hex: %v\n", err)
			os.Exit(2)
		}
		leaves[i] = b
	}
	computed := hex.EncodeToString(merkleRoot(leaves))
	if computed == v.ExpectedRootHex {
		fmt.Printf("go: merkle ok (computed=%s)\n", computed)
		os.Exit(0)
	}
	fmt.Fprintf(os.Stderr, "go: merkle MISMATCH (computed=%s, expected=%s)\n", computed, v.ExpectedRootHex)
	os.Exit(1)
}
