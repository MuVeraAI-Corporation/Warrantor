// Command protocol-tck is the Go batch verifier for the strict cross-language
// protocol TCK. It reads {"keyring": {...}, "vectors": [...]} from stdin and
// writes one JSON line of per-vector results, matching the wire contract of
// rust/protocol-contracts/src/bin/protocol_tck.rs.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	protocolcontracts "aumos.dev/protocol-contracts"
)

type batchVector struct {
	ID             string          `json:"id"`
	Protocol       string          `json:"protocol"`
	ValidationTime uint64          `json:"validation_time"`
	Document       json.RawMessage `json:"document"`
}

type batch struct {
	Keyring map[string]string `json:"keyring"`
	Vectors []batchVector     `json:"vectors"`
}

type vectorResult struct {
	ID        string  `json:"id"`
	Valid     bool    `json:"valid"`
	ErrorCode *string `json:"error_code"`
	Detail    string  `json:"detail"`
}

type output struct {
	Implementation string         `json:"implementation"`
	Results        []vectorResult `json:"results"`
}

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: protocol-tck <registry.json>")
	}
	registryJSON, err := os.ReadFile(os.Args[1])
	if err != nil {
		return fmt.Errorf("read registry: %w", err)
	}
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	var parsed batch
	if err := json.Unmarshal(input, &parsed); err != nil {
		return fmt.Errorf("parse batch: %w", err)
	}
	keyring := make(map[string][]byte, len(parsed.Keyring))
	for keyID, encoded := range parsed.Keyring {
		keyBytes, err := hex.DecodeString(encoded)
		if err != nil {
			return fmt.Errorf("decode key %s: %w", keyID, err)
		}
		keyring[keyID] = keyBytes
	}
	validator, err := protocolcontracts.NewProtocolValidator(registryJSON, keyring)
	if err != nil {
		return fmt.Errorf("build validator: %w", err)
	}
	results := make([]vectorResult, 0, len(parsed.Vectors))
	for _, vector := range parsed.Vectors {
		document, err := protocolcontracts.DecodeJSON(vector.Document)
		if err != nil {
			results = append(results, vectorResult{
				ID:        vector.ID,
				Valid:     false,
				ErrorCode: stringPointer(string(protocolcontracts.ErrorMalformedDocument)),
				Detail:    err.Error(),
			})
			continue
		}
		result := validator.Validate(document, vector.Protocol, vector.ValidationTime)
		var errorCode *string
		if !result.Valid {
			errorCode = stringPointer(string(result.ErrorCode))
		}
		results = append(results, vectorResult{
			ID:        vector.ID,
			Valid:     result.Valid,
			ErrorCode: errorCode,
			Detail:    result.Detail,
		})
	}
	encoded, err := json.Marshal(output{Implementation: "go", Results: results})
	if err != nil {
		return fmt.Errorf("encode results: %w", err)
	}
	fmt.Println(string(encoded))
	return nil
}

func stringPointer(value string) *string {
	return &value
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "protocol-tck: %v\n", err)
		os.Exit(2)
	}
}
