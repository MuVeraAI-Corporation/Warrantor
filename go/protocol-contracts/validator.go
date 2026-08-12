// Registry-driven structural, semantic, temporal, extension, and signature
// validation for the Warrantor P1-P12 wire protocols.
//
// The validator is a generic interpreter over specs/protocols/registry.json:
// it never hardcodes per-protocol structure, mirroring
// rust/protocol-contracts/src/validation.rs and
// python/protocol_contracts/src/protocol_contracts/validation.py so that all
// four implementations produce identical outcomes and error codes.

package protocolcontracts

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ErrorCode is a stable validation error identifier from specs/protocols/errors.json.
type ErrorCode string

// The twelve normative validation error codes.
const (
	ErrorMalformedDocument        ErrorCode = "MALFORMED_DOCUMENT"
	ErrorCommonSchema             ErrorCode = "COMMON_SCHEMA"
	ErrorUnsupportedProtocol      ErrorCode = "UNSUPPORTED_PROTOCOL"
	ErrorProtocolMismatch         ErrorCode = "PROTOCOL_MISMATCH"
	ErrorUnsupportedVersion       ErrorCode = "UNSUPPORTED_VERSION"
	ErrorPayloadSchema            ErrorCode = "PAYLOAD_SCHEMA"
	ErrorSemanticRule             ErrorCode = "SEMANTIC_RULE"
	ErrorNotYetValid              ErrorCode = "NOT_YET_VALID"
	ErrorExpired                  ErrorCode = "EXPIRED"
	ErrorUnknownCriticalExtension ErrorCode = "UNKNOWN_CRITICAL_EXTENSION"
	ErrorUnknownKey               ErrorCode = "UNKNOWN_KEY"
	ErrorInvalidSignature         ErrorCode = "INVALID_SIGNATURE"
)

// ValidationResult is one deterministic protocol validation outcome.
type ValidationResult struct {
	Valid     bool      `json:"valid"`
	ErrorCode ErrorCode `json:"error_code,omitempty"`
	Detail    string    `json:"detail"`
}

func validResult() ValidationResult {
	return ValidationResult{Valid: true, Detail: "valid"}
}

func invalidResult(code ErrorCode, detail string) ValidationResult {
	return ValidationResult{Valid: false, ErrorCode: code, Detail: detail}
}

type shape struct {
	Required   []string              `json:"required"`
	Properties map[string]descriptor `json:"properties"`
}

type descriptor struct {
	Reference            string                `json:"$ref"`
	FieldType            string                `json:"type"`
	Const                json.RawMessage       `json:"const"`
	Enum                 []json.RawMessage     `json:"enum"`
	Pattern              string                `json:"pattern"`
	MinLength            *int                  `json:"minLength"`
	Minimum              *uint64               `json:"minimum"`
	Maximum              *uint64               `json:"maximum"`
	MinItems             *int                  `json:"minItems"`
	MaxItems             *int                  `json:"maxItems"`
	UniqueItems          bool                  `json:"uniqueItems"`
	Items                *descriptor           `json:"items"`
	AdditionalProperties *bool                 `json:"additionalProperties"`
	Required             []string              `json:"required"`
	Properties           map[string]descriptor `json:"properties"`
}

type protocolDefinition struct {
	ID      string `json:"id"`
	Payload shape  `json:"payload"`
}

type registry struct {
	WireVersion                 string               `json:"wire_version"`
	SupportedCriticalExtensions []string             `json:"supported_critical_extensions"`
	Common                      shape                `json:"common"`
	Types                       map[string]shape     `json:"types"`
	Protocols                   []protocolDefinition `json:"protocols"`
}

// ProtocolValidator validates P1-P12 documents against the canonical registry
// with a caller-owned Ed25519 verification keyring.
type ProtocolValidator struct {
	registry                    registry
	keyring                     map[string]ed25519.PublicKey
	supportedCriticalExtensions map[string]struct{}
	compiledPatterns            map[string]*regexp.Regexp
}

// NewProtocolValidator parses the canonical registry and binds raw 32-byte
// Ed25519 public keys by key identifier.
func NewProtocolValidator(registryJSON []byte, keyring map[string][]byte) (*ProtocolValidator, error) {
	var parsed registry
	if err := json.Unmarshal(registryJSON, &parsed); err != nil {
		return nil, fmt.Errorf("registry is not valid JSON: %w", err)
	}
	if parsed.WireVersion == "" {
		return nil, fmt.Errorf("registry lacks a wire_version")
	}
	if len(parsed.Protocols) == 0 {
		return nil, fmt.Errorf("registry declares no protocols")
	}
	validator := &ProtocolValidator{
		registry:                    parsed,
		keyring:                     make(map[string]ed25519.PublicKey, len(keyring)),
		supportedCriticalExtensions: make(map[string]struct{}, len(parsed.SupportedCriticalExtensions)),
		compiledPatterns:            make(map[string]*regexp.Regexp),
	}
	for keyID, keyBytes := range keyring {
		if len(keyBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key %q must contain %d bytes", keyID, ed25519.PublicKeySize)
		}
		validator.keyring[keyID] = ed25519.PublicKey(append([]byte(nil), keyBytes...))
	}
	for _, extension := range parsed.SupportedCriticalExtensions {
		validator.supportedCriticalExtensions[extension] = struct{}{}
	}
	return validator, nil
}

// Validate checks structure, cross-field rules, time, critical extensions, and
// the detached Ed25519 signature in a deterministic fail-closed order.
func (v *ProtocolValidator) Validate(document any, expectedProtocol string, validationTime uint64) ValidationResult {
	root, ok := document.(map[string]any)
	if !ok {
		return invalidResult(ErrorMalformedDocument, "document must be a JSON object")
	}
	protocol, ok := root["protocol"].(string)
	if !ok {
		return invalidResult(ErrorUnsupportedProtocol, "protocol must identify P1 through P12")
	}
	var definition *protocolDefinition
	for index := range v.registry.Protocols {
		if v.registry.Protocols[index].ID == protocol {
			definition = &v.registry.Protocols[index]
			break
		}
	}
	if definition == nil {
		return invalidResult(ErrorUnsupportedProtocol, "protocol must identify P1 through P12")
	}
	if protocol != expectedProtocol {
		return invalidResult(ErrorProtocolMismatch,
			fmt.Sprintf("document declares %s; lane requires %s", protocol, expectedProtocol))
	}
	if version, ok := root["version"].(string); !ok || version != v.registry.WireVersion {
		return invalidResult(ErrorUnsupportedVersion,
			fmt.Sprintf("only wire version %s is accepted", v.registry.WireVersion))
	}
	if err := v.validateShape(root, v.registry.Common, "$"); err != nil {
		return invalidResult(ErrorCommonSchema, err.Error())
	}
	payload, ok := root["payload"].(map[string]any)
	if !ok {
		return invalidResult(ErrorPayloadSchema, "payload must be an object")
	}
	if err := v.validateShape(payload, definition.Payload, "payload"); err != nil {
		return invalidResult(ErrorPayloadSchema, err.Error())
	}
	if detail := validateSemantics(protocol, payload, root); detail != "" {
		return invalidResult(ErrorSemanticRule, detail)
	}
	issuedAt, ok := unsignedValue(root["issued_at"])
	if !ok {
		return invalidResult(ErrorCommonSchema, "issued_at must be uint")
	}
	expiresAt, ok := unsignedValue(root["expires_at"])
	if !ok {
		return invalidResult(ErrorCommonSchema, "expires_at must be uint")
	}
	if expiresAt <= issuedAt {
		return invalidResult(ErrorCommonSchema, "expires_at must be greater than issued_at")
	}
	if validationTime < issuedAt {
		return invalidResult(ErrorNotYetValid, "validation time precedes issued_at")
	}
	if validationTime >= expiresAt {
		return invalidResult(ErrorExpired, "validation time is at or after expires_at")
	}
	unsupported := v.unsupportedCriticalExtensions(root["critical_extensions"])
	if len(unsupported) > 0 {
		return invalidResult(ErrorUnknownCriticalExtension,
			"unsupported critical extensions: "+strings.Join(unsupported, ", "))
	}
	return v.verifySignature(root)
}

func (v *ProtocolValidator) unsupportedCriticalExtensions(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	unsupported := make([]string, 0)
	for _, item := range items {
		extension, ok := item.(string)
		if !ok {
			continue
		}
		if _, supported := v.supportedCriticalExtensions[extension]; supported {
			continue
		}
		if _, duplicate := seen[extension]; duplicate {
			continue
		}
		seen[extension] = struct{}{}
		unsupported = append(unsupported, extension)
	}
	sort.Strings(unsupported)
	return unsupported
}

func (v *ProtocolValidator) validateShape(value map[string]any, target shape, path string) error {
	for _, required := range target.Required {
		if _, present := value[required]; !present {
			return fmt.Errorf("%s.%s: required property is missing", path, required)
		}
	}
	presentKeys := make([]string, 0, len(value))
	for key := range value {
		presentKeys = append(presentKeys, key)
	}
	sort.Strings(presentKeys)
	for _, key := range presentKeys {
		if _, declared := target.Properties[key]; !declared {
			return fmt.Errorf("%s.%s: additional property is forbidden", path, key)
		}
	}
	declaredNames := make([]string, 0, len(target.Properties))
	for name := range target.Properties {
		declaredNames = append(declaredNames, name)
	}
	sort.Strings(declaredNames)
	for _, name := range declaredNames {
		fieldValue, present := value[name]
		if !present {
			continue
		}
		fieldDescriptor := target.Properties[name]
		if err := v.validateDescriptor(fieldValue, &fieldDescriptor, path+"."+name); err != nil {
			return err
		}
	}
	return nil
}

func (v *ProtocolValidator) validateDescriptor(value any, target *descriptor, path string) error {
	if target.Reference != "" {
		referenced, known := v.registry.Types[target.Reference]
		if !known {
			return fmt.Errorf("%s: unknown registry reference %s", path, target.Reference)
		}
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: expected object", path)
		}
		return v.validateShape(object, referenced, path)
	}
	if len(target.Const) > 0 {
		matches, err := rawMatches(target.Const, value)
		if err != nil {
			return fmt.Errorf("%s: invalid registry constant: %w", path, err)
		}
		if !matches {
			return fmt.Errorf("%s: value does not match constant", path)
		}
	}
	if len(target.Enum) > 0 {
		allowed := false
		for _, candidate := range target.Enum {
			matches, err := rawMatches(candidate, value)
			if err != nil {
				return fmt.Errorf("%s: invalid registry enum: %w", path, err)
			}
			if matches {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%s: value is outside the allowed enum", path)
		}
	}
	switch target.FieldType {
	case "string":
		return v.validateString(value, target, path)
	case "integer":
		return validateInteger(value, target, path)
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%s: expected boolean", path)
		}
		return nil
	case "array":
		return v.validateArray(value, target, path)
	case "object":
		return v.validateObject(value, target, path)
	case "":
		return fmt.Errorf("%s: descriptor lacks a type", path)
	default:
		return fmt.Errorf("%s: unsupported registry type %s", path, target.FieldType)
	}
}

func (v *ProtocolValidator) validateString(value any, target *descriptor, path string) error {
	text, ok := value.(string)
	if !ok {
		return fmt.Errorf("%s: expected string", path)
	}
	if target.MinLength != nil && len([]rune(text)) < *target.MinLength {
		return fmt.Errorf("%s: string is shorter than minLength", path)
	}
	if target.Pattern != "" {
		expression, err := v.pattern(target.Pattern)
		if err != nil {
			return fmt.Errorf("%s: invalid registry regex: %w", path, err)
		}
		if !expression.MatchString(text) {
			return fmt.Errorf("%s: string does not match pattern", path)
		}
	}
	return nil
}

func validateInteger(value any, target *descriptor, path string) error {
	integer, ok := unsignedValue(value)
	if !ok {
		return fmt.Errorf("%s: expected unsigned integer", path)
	}
	if target.Minimum != nil && integer < *target.Minimum {
		return fmt.Errorf("%s: integer is below minimum", path)
	}
	if target.Maximum != nil && integer > *target.Maximum {
		return fmt.Errorf("%s: integer exceeds maximum", path)
	}
	return nil
}

func (v *ProtocolValidator) validateArray(value any, target *descriptor, path string) error {
	items, ok := value.([]any)
	if !ok {
		return fmt.Errorf("%s: expected array", path)
	}
	if target.MinItems != nil && len(items) < *target.MinItems {
		return fmt.Errorf("%s: array is shorter than minItems", path)
	}
	if target.MaxItems != nil && len(items) > *target.MaxItems {
		return fmt.Errorf("%s: array exceeds maxItems", path)
	}
	if target.UniqueItems {
		unique := make(map[string]struct{}, len(items))
		for _, item := range items {
			unique[canonicalKey(item)] = struct{}{}
		}
		if len(unique) != len(items) {
			return fmt.Errorf("%s: array items must be unique", path)
		}
	}
	if target.Items == nil {
		return fmt.Errorf("%s: registry array lacks items", path)
	}
	for index, item := range items {
		if err := v.validateDescriptor(item, target.Items, fmt.Sprintf("%s[%d]", path, index)); err != nil {
			return err
		}
	}
	return nil
}

func (v *ProtocolValidator) validateObject(value any, target *descriptor, path string) error {
	object, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: expected object", path)
	}
	if target.AdditionalProperties != nil && *target.AdditionalProperties {
		return nil
	}
	nested := shape{Required: target.Required, Properties: target.Properties}
	return v.validateShape(object, nested, path)
}

func (v *ProtocolValidator) pattern(source string) (*regexp.Regexp, error) {
	if compiled, cached := v.compiledPatterns[source]; cached {
		return compiled, nil
	}
	compiled, err := regexp.Compile(source)
	if err != nil {
		return nil, err
	}
	v.compiledPatterns[source] = compiled
	return compiled, nil
}

func (v *ProtocolValidator) verifySignature(root map[string]any) ValidationResult {
	signature, ok := root["signature"].(map[string]any)
	if !ok {
		return invalidResult(ErrorCommonSchema, "signature must be an object")
	}
	keyID, ok := signature["key_id"].(string)
	if !ok {
		return invalidResult(ErrorCommonSchema, "key_id must be a string")
	}
	publicKey, resolvable := v.keyring[keyID]
	if !resolvable {
		return invalidResult(ErrorUnknownKey, "key id is not resolvable: "+keyID)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return invalidResult(ErrorUnknownKey, "resolved key is not a valid Ed25519 key")
	}
	signatureHex, ok := signature["value"].(string)
	if !ok {
		return invalidResult(ErrorCommonSchema, "signature value must be a string")
	}
	signatureBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return invalidResult(ErrorInvalidSignature, "signature is not valid hexadecimal")
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return invalidResult(ErrorInvalidSignature, "signature must contain 64 bytes")
	}
	signingBytes, err := CanonicalSigningBytes(root)
	if err != nil {
		return invalidResult(ErrorCommonSchema, err.Error())
	}
	if !ed25519.Verify(publicKey, signingBytes, signatureBytes) {
		return invalidResult(ErrorInvalidSignature, "Ed25519 verification failed")
	}
	return validResult()
}

// rawMatches reports whether a registry constant or enum member equals a
// decoded document value.
func rawMatches(raw json.RawMessage, value any) (bool, error) {
	decoded, err := DecodeJSON(raw)
	if err != nil {
		return false, err
	}
	return canonicalKey(decoded) == canonicalKey(value), nil
}

func unsignedValue(value any) (uint64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseUint(number.String(), 10, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}
