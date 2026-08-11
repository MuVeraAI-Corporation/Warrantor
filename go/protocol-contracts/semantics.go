// Protocol cross-field safety invariants for P1-P12.
//
// Each function returns an empty string when the invariant holds and a
// non-sensitive diagnostic otherwise. The rule set and the exact diagnostics
// mirror the Rust and Python reference implementations.

package protocolcontracts

import (
	"sort"
	"strings"
)

type semanticRule func(payload map[string]any, document map[string]any) string

func hasPrefix(value string, prefix string) bool {
	return strings.HasPrefix(value, prefix)
}

func sortedKeys(source map[string]any) []string {
	keys := make([]string, 0, len(source))
	for key := range source {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

var semanticRules = map[string]semanticRule{
	"P1":  validateP1,
	"P2":  validateP2,
	"P3":  validateP3,
	"P4":  validateP4,
	"P5":  validateP5,
	"P6":  validateP6,
	"P7":  validateP7,
	"P8":  validateP8,
	"P9":  validateP9,
	"P10": validateP10,
	"P11": validateP11,
	"P12": validateP12,
}

func validateSemantics(protocol string, payload map[string]any, document map[string]any) string {
	rule, known := semanticRules[protocol]
	if !known {
		return "unsupported protocol escaped structural validation"
	}
	return rule(payload, document)
}

func objectField(source map[string]any, key string) map[string]any {
	value, _ := source[key].(map[string]any)
	return value
}

func stringField(source map[string]any, key string) string {
	value, _ := source[key].(string)
	return value
}

func boolField(source map[string]any, key string) bool {
	value, _ := source[key].(bool)
	return value
}

func arrayField(source map[string]any, key string) []any {
	value, _ := source[key].([]any)
	return value
}

func integerField(source map[string]any, key string) uint64 {
	value, _ := unsignedValue(source[key])
	return value
}

func objectItems(source map[string]any, key string) []map[string]any {
	raw := arrayField(source, key)
	items := make([]map[string]any, 0, len(raw))
	for _, entry := range raw {
		object, _ := entry.(map[string]any)
		items = append(items, object)
	}
	return items
}

func stringItems(source map[string]any, key string) []string {
	raw := arrayField(source, key)
	items := make([]string, 0, len(raw))
	for _, entry := range raw {
		text, _ := entry.(string)
		items = append(items, text)
	}
	return items
}

// validateP1 requires approval for consequential authority.
func validateP1(payload map[string]any, _ map[string]any) string {
	switch stringField(payload, "side_effect_class") {
	case "financial", "destructive", "physical":
		if len(arrayField(payload, "approvals")) == 0 {
			return "consequential authority requires at least one approver"
		}
	}
	return ""
}

// validateP2 keeps precommit and final receipt phases unambiguous.
func validateP2(payload map[string]any, _ map[string]any) string {
	phase := stringField(payload, "phase")
	outcome := stringField(payload, "outcome")
	parent := stringField(payload, "parent_receipt")
	if phase == "precommit" && (outcome != "pending" || parent != "") {
		return "precommit receipts must be pending and have no parent"
	}
	if phase == "final" && (outcome == "pending" || parent == "") {
		return "final receipts require a terminal outcome and parent precommit receipt"
	}
	return ""
}

// validateP3 requires consent for sensitive context and a linked transform chain.
func validateP3(payload map[string]any, _ map[string]any) string {
	switch stringField(payload, "sensitivity") {
	case "L2", "L3", "L4":
		if !boolField(payload, "consent") {
			return "L2-L4 context requires affirmative consent"
		}
	}
	transformations := objectItems(payload, "transformations")
	for index := 1; index < len(transformations); index++ {
		previous := transformations[index-1]
		current := transformations[index]
		if stringField(previous, "output_digest") != stringField(current, "input_digest") {
			return "transformation digest chain is discontinuous"
		}
	}
	return ""
}

// validateP4 validates hash-chain genesis and consent quarantine semantics.
func validateP4(payload map[string]any, _ map[string]any) string {
	sequence := integerField(payload, "sequence")
	previous := stringField(payload, "previous_digest")
	if (sequence == 0 && previous != "") || (sequence > 0 && !hasPrefix(previous, "sha256:")) {
		return "previous_digest must be empty only for sequence zero"
	}
	if boolField(payload, "consent_revoked") && stringField(payload, "quarantine_state") != "quarantined" {
		return "consent-revoked memory must be quarantined"
	}
	return ""
}

// validateP5 binds the declared runtime to the exact executable media type.
func validateP5(payload map[string]any, _ map[string]any) string {
	runtime := stringField(payload, "runtime")
	mediaType := stringField(objectField(payload, "code"), "media_type")
	accepted := map[string][]string{
		"wasm":      {"application/wasm"},
		"python":    {"text/x-python", "application/vnd.aumos.python"},
		"node":      {"text/javascript", "application/javascript"},
		"container": {"application/vnd.oci.image.manifest.v1+json"},
	}
	for _, candidate := range accepted[runtime] {
		if mediaType == candidate {
			return ""
		}
	}
	return "runtime does not match the content-addressed code media type"
}

// validateP6 requires unique role/artifact pairs including model and policy.
func validateP6(payload map[string]any, _ map[string]any) string {
	roles := stringItems(payload, "roles")
	artifacts := objectItems(payload, "artifacts")
	uniqueRoles := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		uniqueRoles[role] = struct{}{}
	}
	if len(roles) != len(artifacts) || len(uniqueRoles) != len(roles) {
		return "artifact roles must be unique and align one-to-one with artifacts"
	}
	if _, hasModel := uniqueRoles["model"]; !hasModel {
		return "artifact graph must contain model and policy roles"
	}
	if _, hasPolicy := uniqueRoles["policy"]; !hasPolicy {
		return "artifact graph must contain model and policy roles"
	}
	digests := make(map[string]struct{}, len(artifacts))
	for _, artifact := range artifacts {
		digests[stringField(artifact, "digest")] = struct{}{}
	}
	if len(digests) != len(artifacts) {
		return "artifact digests must be unique"
	}
	return ""
}

// validateP7 requires explicit approval for high-risk or administrative authority.
func validateP7(payload map[string]any, _ map[string]any) string {
	highRisk := integerField(payload, "expected_risk_micros") >= 500000
	administrative := stringField(payload, "privilege") == "admin"
	if (highRisk || administrative) && !boolField(payload, "approval_required") {
		return "high-risk or administrative budgets must require approval"
	}
	return ""
}

// validateP8 binds summary counts to the signed assertion set.
func validateP8(payload map[string]any, _ map[string]any) string {
	assertions := objectItems(payload, "assertions")
	var passed uint64
	for _, assertion := range assertions {
		if boolField(assertion, "passed") {
			passed++
		}
	}
	failed := uint64(len(assertions)) - passed
	if passed != integerField(payload, "passed_count") || failed != integerField(payload, "failed_count") {
		return "assertion summary counts do not match signed assertions"
	}
	return ""
}

// validateP9 rejects impossible incident containment timelines.
func validateP9(payload map[string]any, _ map[string]any) string {
	status := stringField(payload, "containment_status")
	containedAt := integerField(payload, "contained_at")
	detectedAt := integerField(payload, "detected_at")
	if status == "open" && containedAt != 0 {
		return "open incidents cannot declare a containment timestamp"
	}
	if status != "open" && containedAt < detectedAt {
		return "contained incidents cannot predate detection"
	}
	return ""
}

// validateP10 enforces chain identity, quorum, depth, and budget attenuation.
func validateP10(payload map[string]any, _ map[string]any) string {
	chain := stringItems(payload, "delegation_chain")
	if len(chain) == 0 {
		return "delegation chain endpoints must match delegator and delegatee"
	}
	if chain[0] != stringField(payload, "delegator") || chain[len(chain)-1] != stringField(payload, "delegatee") {
		return "delegation chain endpoints must match delegator and delegatee"
	}
	hopCount := integerField(payload, "hop_count")
	if hopCount != uint64(len(chain)-1) || hopCount > integerField(payload, "max_depth") {
		return "hop count must match the chain and remain within max depth"
	}
	if integerField(payload, "quorum") > uint64(len(arrayField(payload, "approvals"))) {
		return "approval quorum is not satisfied"
	}
	parent := objectField(payload, "parent_budget")
	delegated := objectField(payload, "delegated_budget")
	for _, key := range sortedKeys(parent) {
		if integerField(delegated, key) > integerField(parent, key) {
			return "delegated budget expands parent ceiling at " + key
		}
	}
	return ""
}

// validateP11 keeps embargo state consistent with the signed disclosure state.
func validateP11(payload map[string]any, document map[string]any) string {
	embargoUntil := integerField(payload, "embargo_until")
	disclosureStatus := stringField(payload, "disclosure_status")
	issuedAt := integerField(document, "issued_at")
	if disclosureStatus == "embargoed" && embargoUntil <= issuedAt {
		return "embargoed remediation requires a future embargo timestamp"
	}
	if disclosureStatus != "embargoed" && embargoUntil > issuedAt {
		return "non-embargoed remediation cannot carry a future embargo"
	}
	return ""
}

// validateP12 binds capability validity to the envelope and a fail-closed network profile.
func validateP12(payload map[string]any, document map[string]any) string {
	if integerField(payload, "valid_until") > integerField(document, "expires_at") {
		return "capability validity cannot exceed envelope expiry"
	}
	if stringField(objectField(payload, "network"), "egress_default") != "deny" {
		return "capability network policy must default deny"
	}
	sandbox := stringField(payload, "sandbox")
	memoryIsolation := stringField(payload, "memory_isolation")
	if sandbox == "wasm" && memoryIsolation != "wasm" {
		return "Wasm sandbox must attest Wasm memory isolation"
	}
	if sandbox == "tee" && memoryIsolation != "tee" {
		return "TEE sandbox must attest TEE memory isolation"
	}
	return ""
}
