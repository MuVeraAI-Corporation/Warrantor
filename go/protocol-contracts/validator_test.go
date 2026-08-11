package protocolcontracts

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const expectedVectorCount = 40

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	return root
}

type vectorEntry struct {
	ID            string `json:"id"`
	Protocol      string `json:"protocol"`
	Category      string `json:"category"`
	Expected      string `json:"expected"`
	ExpectedError string `json:"expected_error"`
	Path          string `json:"path"`
}

type vectorManifest struct {
	WireVersion string            `json:"wire_version"`
	Keyring     map[string]string `json:"keyring"`
	VectorCount int               `json:"vector_count"`
	Vectors     []vectorEntry     `json:"vectors"`
}

type vectorRecord struct {
	ID             string          `json:"id"`
	Protocol       string          `json:"protocol"`
	Expected       string          `json:"expected"`
	ExpectedError  string          `json:"expected_error"`
	ValidationTime uint64          `json:"validation_time"`
	Document       json.RawMessage `json:"document"`
}

func loadManifest(t *testing.T, root string) vectorManifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "testvectors", "protocols", "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest vectorManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	return manifest
}

func newTestValidator(t *testing.T, root string, keyring map[string]string) *ProtocolValidator {
	t.Helper()
	registryJSON, err := os.ReadFile(filepath.Join(root, "specs", "protocols", "registry.json"))
	if err != nil {
		t.Fatalf("read registry: %v", err)
	}
	decoded := make(map[string][]byte, len(keyring))
	for keyID, encoded := range keyring {
		keyBytes, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatalf("decode key %s: %v", keyID, err)
		}
		decoded[keyID] = keyBytes
	}
	validator, err := NewProtocolValidator(registryJSON, decoded)
	if err != nil {
		t.Fatalf("build validator: %v", err)
	}
	return validator
}

func loadVector(t *testing.T, root string, relativePath string) vectorRecord {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "testvectors", "protocols", filepath.FromSlash(relativePath)))
	if err != nil {
		t.Fatalf("read vector %s: %v", relativePath, err)
	}
	var record vectorRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatalf("parse vector %s: %v", relativePath, err)
	}
	return record
}

func TestEveryProtocolVectorMatchesTheExpectedOutcome(t *testing.T) {
	root := repositoryRoot(t)
	manifest := loadManifest(t, root)
	if len(manifest.Vectors) != expectedVectorCount {
		t.Fatalf("manifest declares %d vectors; expected %d", len(manifest.Vectors), expectedVectorCount)
	}
	if manifest.VectorCount != expectedVectorCount {
		t.Fatalf("manifest vector_count is %d; expected %d", manifest.VectorCount, expectedVectorCount)
	}
	validator := newTestValidator(t, root, manifest.Keyring)

	protocolsSeen := make(map[string]struct{})
	categoriesSeen := make(map[string]struct{})
	for _, entry := range manifest.Vectors {
		protocolsSeen[entry.Protocol] = struct{}{}
		categoriesSeen[entry.Category] = struct{}{}
		record := loadVector(t, root, entry.Path)
		document, err := DecodeJSON(record.Document)
		if err != nil {
			t.Fatalf("%s: decode document: %v", entry.ID, err)
		}
		result := validator.Validate(document, record.Protocol, record.ValidationTime)
		expectedValid := record.Expected == "valid"
		if result.Valid != expectedValid {
			t.Errorf("%s: valid=%v, expected valid=%v (%s: %s)",
				entry.ID, result.Valid, expectedValid, result.ErrorCode, result.Detail)
			continue
		}
		if expectedValid {
			if result.ErrorCode != "" {
				t.Errorf("%s: valid result carried error code %s", entry.ID, result.ErrorCode)
			}
			continue
		}
		if string(result.ErrorCode) != record.ExpectedError {
			t.Errorf("%s: error code %s, expected %s (%s)",
				entry.ID, result.ErrorCode, record.ExpectedError, result.Detail)
		}
		if record.ExpectedError != entry.ExpectedError {
			t.Errorf("%s: manifest expects %s but the vector expects %s",
				entry.ID, entry.ExpectedError, record.ExpectedError)
		}
	}
	if len(protocolsSeen) != 12 {
		t.Errorf("vectors cover %d protocols; expected 12", len(protocolsSeen))
	}
	for _, category := range []string{"positive", "negative", "adversarial"} {
		if _, present := categoriesSeen[category]; !present {
			t.Errorf("no vector in category %s", category)
		}
	}
}

func TestUnknownKeyFailsClosed(t *testing.T) {
	root := repositoryRoot(t)
	manifest := loadManifest(t, root)
	validator := newTestValidator(t, root, map[string]string{})
	record := loadVector(t, root, manifest.Vectors[0].Path)
	document, err := DecodeJSON(record.Document)
	if err != nil {
		t.Fatalf("decode document: %v", err)
	}
	result := validator.Validate(document, record.Protocol, record.ValidationTime)
	if result.Valid {
		t.Fatal("a document signed by an unresolvable key must not validate")
	}
	if result.ErrorCode != ErrorUnknownKey {
		t.Fatalf("error code %s, expected %s", result.ErrorCode, ErrorUnknownKey)
	}
}

func TestProtocolMismatchIsRejected(t *testing.T) {
	root := repositoryRoot(t)
	manifest := loadManifest(t, root)
	validator := newTestValidator(t, root, manifest.Keyring)
	record := loadVector(t, root, manifest.Vectors[0].Path)
	document, err := DecodeJSON(record.Document)
	if err != nil {
		t.Fatalf("decode document: %v", err)
	}
	result := validator.Validate(document, "P12", record.ValidationTime)
	if result.ErrorCode != ErrorProtocolMismatch {
		t.Fatalf("error code %s, expected %s", result.ErrorCode, ErrorProtocolMismatch)
	}
}

func TestUnknownCriticalExtensionFailsClosed(t *testing.T) {
	root := repositoryRoot(t)
	manifest := loadManifest(t, root)
	validator := newTestValidator(t, root, manifest.Keyring)
	record := loadVector(t, root, manifest.Vectors[0].Path)
	document, err := DecodeJSON(record.Document)
	if err != nil {
		t.Fatalf("decode document: %v", err)
	}
	root_, ok := document.(map[string]any)
	if !ok {
		t.Fatal("document must be an object")
	}
	root_["critical_extensions"] = []any{"urn:aumos:extension:not-understood"}
	result := validator.Validate(document, record.Protocol, record.ValidationTime)
	if result.ErrorCode != ErrorUnknownCriticalExtension {
		t.Fatalf("error code %s, expected %s", result.ErrorCode, ErrorUnknownCriticalExtension)
	}
}

// TestCanonicalSigningBytesMatchTheRustProfile pins the byte-exact signing
// form: sorted keys, no insignificant whitespace, verbatim integer literals,
// and a blanked signature value. The empirical proof that this matches Rust's
// `serde_json::to_vec` is that the real Ed25519 signature recorded in the
// vector — produced by the reference implementation — verifies over exactly
// these bytes.
func TestCanonicalSigningBytesMatchTheRustProfile(t *testing.T) {
	root := repositoryRoot(t)
	manifest := loadManifest(t, root)
	record := loadVector(t, root, manifest.Vectors[0].Path)
	document, err := DecodeJSON(record.Document)
	if err != nil {
		t.Fatalf("decode document: %v", err)
	}
	signingBytes, err := CanonicalSigningBytes(document)
	if err != nil {
		t.Fatalf("canonical signing bytes: %v", err)
	}
	text := string(signingBytes)
	if !strings.HasPrefix(text, `{"critical_extensions":`) {
		t.Fatalf("canonical form does not start with the lexicographically first key: %.40q", text)
	}
	if !strings.Contains(text, `"value":""`) {
		t.Fatalf("canonical form must blank the signature value; got %q", text)
	}
	if !strings.Contains(text, `"issued_at":1893456000,"issuer":`) {
		t.Fatalf("canonical form must preserve integer literals with no separator padding; got %q", text)
	}
	if strings.Contains(text, `": `) || strings.Contains(text, `", `) || strings.Contains(text, "\n") {
		t.Fatalf("canonical form must not contain insignificant whitespace")
	}

	documentRoot, ok := document.(map[string]any)
	if !ok {
		t.Fatal("document must be an object")
	}
	signature, ok := documentRoot["signature"].(map[string]any)
	if !ok {
		t.Fatal("signature must be an object")
	}
	signatureBytes, err := hex.DecodeString(signature["value"].(string))
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	publicKeyBytes, err := hex.DecodeString(manifest.Keyring[signature["key_id"].(string)])
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKeyBytes), signingBytes, signatureBytes) {
		t.Fatal("the reference signature does not verify over Go's canonical signing bytes")
	}
}
