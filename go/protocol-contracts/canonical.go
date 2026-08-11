// Canonical JSON serialisation for the AumOS P1-P12 signing profile.
//
// The signing form is the RFC 8785-compatible integer-only profile: object keys
// sorted lexicographically by their UTF-8 byte sequence, no insignificant
// whitespace, numbers emitted exactly as they appeared on the wire, and only
// the mandatory JSON string escapes. This reproduces `serde_json::to_vec` over
// a `serde_json::Value` (Rust) and `json.dumps(sort_keys=True,
// separators=(",", ":"), ensure_ascii=False)` (Python) byte for byte.

package protocolcontracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

const lowerHexDigits = "0123456789abcdef"

// DecodeJSON parses JSON into generic Go values while preserving the exact
// numeric literals from the input as json.Number.
func DecodeJSON(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	// Reject trailing content so a truncated or doubled document cannot pass.
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("unexpected trailing JSON content")
	}
	return value, nil
}

// CanonicalJSON renders a decoded JSON value in the canonical signing form.
func CanonicalJSON(value any) ([]byte, error) {
	buffer := &bytes.Buffer{}
	if err := writeCanonical(buffer, value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func writeCanonical(buffer *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		buffer.WriteString("null")
	case bool:
		if typed {
			buffer.WriteString("true")
		} else {
			buffer.WriteString("false")
		}
	case json.Number:
		buffer.WriteString(typed.String())
	case string:
		writeCanonicalString(buffer, typed)
	case []any:
		buffer.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				buffer.WriteByte(',')
			}
			if err := writeCanonical(buffer, item); err != nil {
				return err
			}
		}
		buffer.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buffer.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				buffer.WriteByte(',')
			}
			writeCanonicalString(buffer, key)
			buffer.WriteByte(':')
			if err := writeCanonical(buffer, typed[key]); err != nil {
				return err
			}
		}
		buffer.WriteByte('}')
	default:
		return fmt.Errorf("canonical json: unsupported value of type %T", value)
	}
	return nil
}

// writeCanonicalString emits the mandatory JSON string escapes only, leaving
// every other code point as raw UTF-8.
func writeCanonicalString(buffer *bytes.Buffer, value string) {
	buffer.WriteByte('"')
	for _, codePoint := range value {
		switch codePoint {
		case '"':
			buffer.WriteString(`\"`)
		case '\\':
			buffer.WriteString(`\\`)
		case '\b':
			buffer.WriteString(`\b`)
		case '\f':
			buffer.WriteString(`\f`)
		case '\n':
			buffer.WriteString(`\n`)
		case '\r':
			buffer.WriteString(`\r`)
		case '\t':
			buffer.WriteString(`\t`)
		default:
			if codePoint < 0x20 {
				buffer.WriteString(`\u00`)
				buffer.WriteByte(lowerHexDigits[(codePoint>>4)&0x0f])
				buffer.WriteByte(lowerHexDigits[codePoint&0x0f])
				continue
			}
			buffer.WriteRune(codePoint)
		}
	}
	buffer.WriteByte('"')
}

// CanonicalSigningBytes returns the v1 JSON signing form with signature.value
// blanked, matching the Rust and Python reference implementations.
func CanonicalSigningBytes(document any) ([]byte, error) {
	root, ok := document.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("signature must be an object")
	}
	signature, ok := root["signature"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("signature must be an object")
	}
	signingDocument := make(map[string]any, len(root))
	for key, value := range root {
		signingDocument[key] = value
	}
	signingSignature := make(map[string]any, len(signature))
	for key, value := range signature {
		signingSignature[key] = value
	}
	signingSignature["value"] = ""
	signingDocument["signature"] = signingSignature
	return CanonicalJSON(signingDocument)
}

// canonicalKey renders any decoded JSON value as a stable comparison key.
func canonicalKey(value any) string {
	encoded, err := CanonicalJSON(value)
	if err != nil {
		return "\x00unsupported:" + strings.TrimSpace(fmt.Sprintf("%T", value))
	}
	return string(encoded)
}
