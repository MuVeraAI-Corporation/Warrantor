//! Independent registry-driven structural and typed semantic validation.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use regex::Regex;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::{
    AgentActionReceiptPayload, AgentAuthorityEnvelopePayload, AgentIncidentExchangePayload,
    AgentMemoryIntegrityRecordPayload, AiArtifactTrustManifestPayload,
    AutonomyBudgetSpecificationPayload, Budget, CapabilityAttestationProfilePayload,
    ContextProvenanceEnvelopePayload, MultiAgentDelegationExchangePayload,
    ProofCarryingRemediationBundlePayload, SecureSkillPackagePayload,
    VerifiableEvaluationBundlePayload,
};

/// Stable validation errors shared by all TCK implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    MalformedDocument,
    CommonSchema,
    UnsupportedProtocol,
    ProtocolMismatch,
    UnsupportedVersion,
    PayloadSchema,
    SemanticRule,
    NotYetValid,
    Expired,
    UnknownCriticalExtension,
    UnknownKey,
    InvalidSignature,
}

/// One deterministic protocol validation outcome.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ValidationResult {
    /// Whether all validation layers passed.
    pub valid: bool,
    /// Stable error code, absent only for valid documents.
    pub error_code: Option<ErrorCode>,
    /// Non-sensitive diagnostic suitable for local evidence.
    pub detail: String,
}

impl ValidationResult {
    fn valid() -> Self {
        Self {
            valid: true,
            error_code: None,
            detail: "valid".to_owned(),
        }
    }

    fn invalid(error_code: ErrorCode, detail: impl Into<String>) -> Self {
        Self {
            valid: false,
            error_code: Some(error_code),
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Registry {
    wire_version: String,
    supported_critical_extensions: Vec<String>,
    common: Shape,
    types: BTreeMap<String, Shape>,
    protocols: Vec<ProtocolDefinition>,
}

#[derive(Debug, Deserialize)]
struct ProtocolDefinition {
    id: String,
    payload: Shape,
}

#[derive(Debug, Deserialize)]
struct Shape {
    required: Vec<String>,
    properties: BTreeMap<String, Descriptor>,
}

#[derive(Debug, Deserialize)]
struct Descriptor {
    #[serde(rename = "$ref")]
    reference: Option<String>,
    #[serde(rename = "type")]
    field_type: Option<String>,
    #[serde(rename = "const")]
    constant: Option<Value>,
    #[serde(rename = "enum", default)]
    enum_values: Vec<Value>,
    pattern: Option<String>,
    #[serde(rename = "minLength")]
    min_length: Option<usize>,
    minimum: Option<u64>,
    maximum: Option<u64>,
    #[serde(rename = "minItems")]
    min_items: Option<usize>,
    #[serde(rename = "maxItems")]
    max_items: Option<usize>,
    #[serde(rename = "uniqueItems", default)]
    unique_items: bool,
    items: Option<Box<Descriptor>>,
    #[serde(rename = "additionalProperties")]
    additional_properties: Option<bool>,
    #[serde(default)]
    required: Vec<String>,
    #[serde(default)]
    properties: BTreeMap<String, Descriptor>,
}

/// Registry-bound P1-P12 validator with caller-owned key resolution.
pub struct ProtocolValidator {
    registry: Registry,
    keyring: BTreeMap<String, [u8; 32]>,
    supported_critical_extensions: BTreeSet<String>,
}

impl ProtocolValidator {
    /// Parse the canonical registry and bind raw Ed25519 public keys.
    pub fn new(
        registry_json: &str,
        keyring: BTreeMap<String, [u8; 32]>,
    ) -> Result<Self, serde_json::Error> {
        let registry: Registry = serde_json::from_str(registry_json)?;
        let supported_critical_extensions = registry
            .supported_critical_extensions
            .iter()
            .cloned()
            .collect();
        Ok(Self {
            registry,
            keyring,
            supported_critical_extensions,
        })
    }

    /// Validate structure, cross-field rules, time, extensions, and signature.
    #[must_use]
    pub fn validate(
        &self,
        document: &Value,
        expected_protocol: &str,
        validation_time: u64,
    ) -> ValidationResult {
        let Some(root) = document.as_object() else {
            return ValidationResult::invalid(
                ErrorCode::MalformedDocument,
                "document must be a JSON object",
            );
        };
        let Some(protocol) = root.get("protocol").and_then(Value::as_str) else {
            return ValidationResult::invalid(
                ErrorCode::UnsupportedProtocol,
                "protocol must identify P1 through P12",
            );
        };
        let Some(definition) = self
            .registry
            .protocols
            .iter()
            .find(|candidate| candidate.id == protocol)
        else {
            return ValidationResult::invalid(
                ErrorCode::UnsupportedProtocol,
                "protocol must identify P1 through P12",
            );
        };
        if protocol != expected_protocol {
            return ValidationResult::invalid(
                ErrorCode::ProtocolMismatch,
                format!("document declares {protocol}; lane requires {expected_protocol}"),
            );
        }
        if root.get("version").and_then(Value::as_str) != Some(self.registry.wire_version.as_str())
        {
            return ValidationResult::invalid(
                ErrorCode::UnsupportedVersion,
                "only wire version 1.0.0 is accepted",
            );
        }
        if let Err(detail) = self.validate_shape(root, &self.registry.common, "$") {
            return ValidationResult::invalid(ErrorCode::CommonSchema, detail);
        }
        let Some(payload) = root.get("payload").and_then(Value::as_object) else {
            return ValidationResult::invalid(
                ErrorCode::PayloadSchema,
                "payload must be an object",
            );
        };
        if let Err(detail) = self.validate_shape(payload, &definition.payload, "payload") {
            return ValidationResult::invalid(ErrorCode::PayloadSchema, detail);
        }
        if let Some(detail) = validate_semantics(protocol, payload, root) {
            return ValidationResult::invalid(ErrorCode::SemanticRule, detail);
        }
        let Some(issued_at) = root.get("issued_at").and_then(Value::as_u64) else {
            return ValidationResult::invalid(ErrorCode::CommonSchema, "issued_at must be uint");
        };
        let Some(expires_at) = root.get("expires_at").and_then(Value::as_u64) else {
            return ValidationResult::invalid(ErrorCode::CommonSchema, "expires_at must be uint");
        };
        if expires_at <= issued_at {
            return ValidationResult::invalid(
                ErrorCode::CommonSchema,
                "expires_at must be greater than issued_at",
            );
        }
        if validation_time < issued_at {
            return ValidationResult::invalid(
                ErrorCode::NotYetValid,
                "validation time precedes issued_at",
            );
        }
        if validation_time >= expires_at {
            return ValidationResult::invalid(
                ErrorCode::Expired,
                "validation time is at or after expires_at",
            );
        }
        let unsupported_extensions: Vec<&str> = root
            .get("critical_extensions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|extension| !self.supported_critical_extensions.contains(*extension))
            .collect();
        if !unsupported_extensions.is_empty() {
            return ValidationResult::invalid(
                ErrorCode::UnknownCriticalExtension,
                format!(
                    "unsupported critical extensions: {}",
                    unsupported_extensions.join(", ")
                ),
            );
        }
        self.verify_signature(root)
    }

    fn validate_shape(
        &self,
        value: &Map<String, Value>,
        shape: &Shape,
        path: &str,
    ) -> Result<(), String> {
        for required in &shape.required {
            if !value.contains_key(required) {
                return Err(format!("{path}.{required}: required property is missing"));
            }
        }
        for key in value.keys() {
            if !shape.properties.contains_key(key) {
                return Err(format!("{path}.{key}: additional property is forbidden"));
            }
        }
        for (field_name, descriptor) in &shape.properties {
            if let Some(field_value) = value.get(field_name) {
                self.validate_descriptor(field_value, descriptor, &format!("{path}.{field_name}"))?;
            }
        }
        Ok(())
    }

    fn validate_descriptor(
        &self,
        value: &Value,
        descriptor: &Descriptor,
        path: &str,
    ) -> Result<(), String> {
        if let Some(reference) = &descriptor.reference {
            let referenced = self
                .registry
                .types
                .get(reference)
                .ok_or_else(|| format!("{path}: unknown registry reference {reference}"))?;
            let object = value
                .as_object()
                .ok_or_else(|| format!("{path}: expected object"))?;
            return self.validate_shape(object, referenced, path);
        }
        if let Some(constant) = &descriptor.constant {
            if value != constant {
                return Err(format!("{path}: value does not match constant"));
            }
        }
        if !descriptor.enum_values.is_empty() && !descriptor.enum_values.contains(value) {
            return Err(format!("{path}: value is outside the allowed enum"));
        }
        match descriptor.field_type.as_deref() {
            Some("string") => self.validate_string(value, descriptor, path),
            Some("integer") => self.validate_integer(value, descriptor, path),
            Some("boolean") if value.is_boolean() => Ok(()),
            Some("boolean") => Err(format!("{path}: expected boolean")),
            Some("array") => self.validate_array(value, descriptor, path),
            Some("object") => self.validate_object(value, descriptor, path),
            Some(field_type) => Err(format!("{path}: unsupported registry type {field_type}")),
            None => Err(format!("{path}: descriptor lacks a type")),
        }
    }

    fn validate_string(
        &self,
        value: &Value,
        descriptor: &Descriptor,
        path: &str,
    ) -> Result<(), String> {
        let string = value
            .as_str()
            .ok_or_else(|| format!("{path}: expected string"))?;
        if descriptor
            .min_length
            .is_some_and(|minimum| string.chars().count() < minimum)
        {
            return Err(format!("{path}: string is shorter than minLength"));
        }
        if let Some(pattern) = &descriptor.pattern {
            let expression = Regex::new(pattern)
                .map_err(|error| format!("{path}: invalid registry regex: {error}"))?;
            if !expression.is_match(string) {
                return Err(format!("{path}: string does not match pattern"));
            }
        }
        Ok(())
    }

    fn validate_integer(
        &self,
        value: &Value,
        descriptor: &Descriptor,
        path: &str,
    ) -> Result<(), String> {
        let integer = value
            .as_u64()
            .ok_or_else(|| format!("{path}: expected unsigned integer"))?;
        if descriptor.minimum.is_some_and(|minimum| integer < minimum) {
            return Err(format!("{path}: integer is below minimum"));
        }
        if descriptor.maximum.is_some_and(|maximum| integer > maximum) {
            return Err(format!("{path}: integer exceeds maximum"));
        }
        Ok(())
    }

    fn validate_array(
        &self,
        value: &Value,
        descriptor: &Descriptor,
        path: &str,
    ) -> Result<(), String> {
        let items = value
            .as_array()
            .ok_or_else(|| format!("{path}: expected array"))?;
        if descriptor
            .min_items
            .is_some_and(|minimum| items.len() < minimum)
        {
            return Err(format!("{path}: array is shorter than minItems"));
        }
        if descriptor
            .max_items
            .is_some_and(|maximum| items.len() > maximum)
        {
            return Err(format!("{path}: array exceeds maxItems"));
        }
        if descriptor.unique_items {
            let unique: BTreeSet<String> = items.iter().map(Value::to_string).collect();
            if unique.len() != items.len() {
                return Err(format!("{path}: array items must be unique"));
            }
        }
        let item_descriptor = descriptor
            .items
            .as_ref()
            .ok_or_else(|| format!("{path}: registry array lacks items"))?;
        for (index, item) in items.iter().enumerate() {
            self.validate_descriptor(item, item_descriptor, &format!("{path}[{index}]"))?;
        }
        Ok(())
    }

    fn validate_object(
        &self,
        value: &Value,
        descriptor: &Descriptor,
        path: &str,
    ) -> Result<(), String> {
        let object = value
            .as_object()
            .ok_or_else(|| format!("{path}: expected object"))?;
        if descriptor.additional_properties == Some(true) {
            return Ok(());
        }
        let nested = Shape {
            required: descriptor.required.clone(),
            properties: descriptor.properties.clone(),
        };
        self.validate_shape(object, &nested, path)
    }

    fn verify_signature(&self, root: &Map<String, Value>) -> ValidationResult {
        let Some(signature) = root.get("signature").and_then(Value::as_object) else {
            return ValidationResult::invalid(
                ErrorCode::CommonSchema,
                "signature must be an object",
            );
        };
        let Some(key_id) = signature.get("key_id").and_then(Value::as_str) else {
            return ValidationResult::invalid(ErrorCode::CommonSchema, "key_id must be a string");
        };
        let Some(key_bytes) = self.keyring.get(key_id) else {
            return ValidationResult::invalid(
                ErrorCode::UnknownKey,
                format!("key id is not resolvable: {key_id}"),
            );
        };
        let Some(signature_hex) = signature.get("value").and_then(Value::as_str) else {
            return ValidationResult::invalid(
                ErrorCode::CommonSchema,
                "signature value must be a string",
            );
        };
        let Ok(signature_bytes) = hex::decode(signature_hex) else {
            return ValidationResult::invalid(
                ErrorCode::InvalidSignature,
                "signature is not valid hexadecimal",
            );
        };
        let Ok(signature_bytes) = <[u8; 64]>::try_from(signature_bytes) else {
            return ValidationResult::invalid(
                ErrorCode::InvalidSignature,
                "signature must contain 64 bytes",
            );
        };
        let verifying_key = match VerifyingKey::from_bytes(key_bytes) {
            Ok(key) => key,
            Err(_) => {
                return ValidationResult::invalid(
                    ErrorCode::UnknownKey,
                    "resolved key is not a valid Ed25519 key",
                );
            }
        };
        let document = Value::Object(root.clone());
        let signing_bytes = match canonical_signing_bytes(&document) {
            Ok(bytes) => bytes,
            Err(detail) => {
                return ValidationResult::invalid(ErrorCode::CommonSchema, detail);
            }
        };
        let signature = Ed25519Signature::from_bytes(&signature_bytes);
        if verifying_key.verify(&signing_bytes, &signature).is_err() {
            return ValidationResult::invalid(
                ErrorCode::InvalidSignature,
                "Ed25519 verification failed",
            );
        }
        ValidationResult::valid()
    }
}

/// Return the v1 JSON signing form with the signature value cleared.
pub fn canonical_signing_bytes(document: &Value) -> Result<Vec<u8>, String> {
    let mut signing_document = document.clone();
    let signature = signing_document
        .get_mut("signature")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "signature must be an object".to_owned())?;
    signature.insert("value".to_owned(), Value::String(String::new()));
    serde_json::to_vec(&signing_document).map_err(|error| error.to_string())
}

fn validate_semantics(
    protocol: &str,
    payload: &Map<String, Value>,
    root: &Map<String, Value>,
) -> Option<String> {
    let payload_value = Value::Object(payload.clone());
    match protocol {
        "P1" => parse_semantic::<AgentAuthorityEnvelopePayload>(&payload_value, validate_p1),
        "P2" => parse_semantic::<AgentActionReceiptPayload>(&payload_value, validate_p2),
        "P3" => parse_semantic::<ContextProvenanceEnvelopePayload>(&payload_value, validate_p3),
        "P4" => parse_semantic::<AgentMemoryIntegrityRecordPayload>(&payload_value, validate_p4),
        "P5" => parse_semantic::<SecureSkillPackagePayload>(&payload_value, validate_p5),
        "P6" => parse_semantic::<AiArtifactTrustManifestPayload>(&payload_value, validate_p6),
        "P7" => parse_semantic::<AutonomyBudgetSpecificationPayload>(&payload_value, validate_p7),
        "P8" => parse_semantic::<VerifiableEvaluationBundlePayload>(&payload_value, validate_p8),
        "P9" => parse_semantic::<AgentIncidentExchangePayload>(&payload_value, validate_p9),
        "P10" => {
            parse_semantic::<MultiAgentDelegationExchangePayload>(&payload_value, validate_p10)
        }
        "P11" => serde_json::from_value::<ProofCarryingRemediationBundlePayload>(payload_value)
            .map_or_else(
                |error| Some(format!("typed payload conversion failed: {error}")),
                |typed| validate_p11(&typed, root),
            ),
        "P12" => serde_json::from_value::<CapabilityAttestationProfilePayload>(payload_value)
            .map_or_else(
                |error| Some(format!("typed payload conversion failed: {error}")),
                |typed| validate_p12(&typed, root),
            ),
        _ => Some("unsupported protocol escaped structural validation".to_owned()),
    }
}

fn parse_semantic<Payload>(
    payload: &Value,
    validator: fn(&Payload) -> Option<String>,
) -> Option<String>
where
    Payload: for<'de> Deserialize<'de>,
{
    serde_json::from_value::<Payload>(payload.clone()).map_or_else(
        |error| Some(format!("typed payload conversion failed: {error}")),
        |typed| validator(&typed),
    )
}

fn validate_p1(payload: &AgentAuthorityEnvelopePayload) -> Option<String> {
    if matches!(
        payload.side_effect_class.as_str(),
        "financial" | "destructive" | "physical"
    ) && payload.approvals.is_empty()
    {
        return Some("consequential authority requires at least one approver".to_owned());
    }
    None
}

fn validate_p2(payload: &AgentActionReceiptPayload) -> Option<String> {
    if payload.phase == "precommit"
        && (payload.outcome != "pending" || !payload.parent_receipt.is_empty())
    {
        return Some("precommit receipts must be pending and have no parent".to_owned());
    }
    if payload.phase == "final"
        && (payload.outcome == "pending" || payload.parent_receipt.is_empty())
    {
        return Some(
            "final receipts require a terminal outcome and parent precommit receipt".to_owned(),
        );
    }
    None
}

fn validate_p3(payload: &ContextProvenanceEnvelopePayload) -> Option<String> {
    if matches!(payload.sensitivity.as_str(), "L2" | "L3" | "L4") && !payload.consent {
        return Some("L2-L4 context requires affirmative consent".to_owned());
    }
    if payload
        .transformations
        .windows(2)
        .any(|pair| pair[0].output_digest != pair[1].input_digest)
    {
        return Some("transformation digest chain is discontinuous".to_owned());
    }
    None
}

fn validate_p4(payload: &AgentMemoryIntegrityRecordPayload) -> Option<String> {
    let invalid_previous = (payload.sequence == 0 && !payload.previous_digest.is_empty())
        || (payload.sequence > 0 && !payload.previous_digest.starts_with("sha256:"));
    if invalid_previous {
        return Some("previous_digest must be empty only for sequence zero".to_owned());
    }
    if payload.consent_revoked && payload.quarantine_state != "quarantined" {
        return Some("consent-revoked memory must be quarantined".to_owned());
    }
    None
}

fn validate_p5(payload: &SecureSkillPackagePayload) -> Option<String> {
    let accepted = match payload.runtime.as_str() {
        "wasm" => payload.code.media_type == "application/wasm",
        "python" => matches!(
            payload.code.media_type.as_str(),
            "text/x-python" | "application/vnd.aumos.python"
        ),
        "node" => matches!(
            payload.code.media_type.as_str(),
            "text/javascript" | "application/javascript"
        ),
        "container" => payload.code.media_type == "application/vnd.oci.image.manifest.v1+json",
        _ => false,
    };
    (!accepted).then(|| "runtime does not match the content-addressed code media type".to_owned())
}

fn validate_p6(payload: &AiArtifactTrustManifestPayload) -> Option<String> {
    let roles: BTreeSet<&str> = payload.roles.iter().map(String::as_str).collect();
    if payload.roles.len() != payload.artifacts.len() || roles.len() != payload.roles.len() {
        return Some(
            "artifact roles must be unique and align one-to-one with artifacts".to_owned(),
        );
    }
    if !roles.contains("model") || !roles.contains("policy") {
        return Some("artifact graph must contain model and policy roles".to_owned());
    }
    let digests: BTreeSet<&str> = payload
        .artifacts
        .iter()
        .map(|artifact| artifact.digest.as_str())
        .collect();
    if digests.len() != payload.artifacts.len() {
        return Some("artifact digests must be unique".to_owned());
    }
    None
}

fn validate_p7(payload: &AutonomyBudgetSpecificationPayload) -> Option<String> {
    if (payload.expected_risk_micros >= 500_000 || payload.privilege == "admin")
        && !payload.approval_required
    {
        return Some("high-risk or administrative budgets must require approval".to_owned());
    }
    None
}

fn validate_p8(payload: &VerifiableEvaluationBundlePayload) -> Option<String> {
    let passed = payload
        .assertions
        .iter()
        .filter(|assertion| assertion.passed)
        .count() as u64;
    let failed = payload.assertions.len() as u64 - passed;
    if passed != payload.passed_count || failed != payload.failed_count {
        return Some("assertion summary counts do not match signed assertions".to_owned());
    }
    None
}

fn validate_p9(payload: &AgentIncidentExchangePayload) -> Option<String> {
    if payload.containment_status == "open" && payload.contained_at != 0 {
        return Some("open incidents cannot declare a containment timestamp".to_owned());
    }
    if payload.containment_status != "open" && payload.contained_at < payload.detected_at {
        return Some("contained incidents cannot predate detection".to_owned());
    }
    None
}

fn budget_attenuates(parent: &Budget, delegated: &Budget) -> bool {
    delegated.steps <= parent.steps
        && delegated.wall_clock_seconds <= parent.wall_clock_seconds
        && delegated.tokens <= parent.tokens
        && delegated.money_minor <= parent.money_minor
        && delegated.external_calls <= parent.external_calls
        && delegated.data_bytes <= parent.data_bytes
        && delegated.irreversible_actions <= parent.irreversible_actions
}

fn validate_p10(payload: &MultiAgentDelegationExchangePayload) -> Option<String> {
    if payload.delegation_chain.first() != Some(&payload.delegator)
        || payload.delegation_chain.last() != Some(&payload.delegatee)
    {
        return Some("delegation chain endpoints must match delegator and delegatee".to_owned());
    }
    if payload.hop_count != payload.delegation_chain.len().saturating_sub(1) as u64
        || payload.hop_count > payload.max_depth
    {
        return Some("hop count must match the chain and remain within max depth".to_owned());
    }
    if payload.quorum > payload.approvals.len() as u64 {
        return Some("approval quorum is not satisfied".to_owned());
    }
    if !budget_attenuates(&payload.parent_budget, &payload.delegated_budget) {
        return Some("delegated budget expands parent ceiling".to_owned());
    }
    None
}

fn validate_p11(
    payload: &ProofCarryingRemediationBundlePayload,
    root: &Map<String, Value>,
) -> Option<String> {
    let issued_at = root
        .get("issued_at")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    if payload.disclosure_status == "embargoed" && payload.embargo_until <= issued_at {
        return Some("embargoed remediation requires a future embargo timestamp".to_owned());
    }
    if payload.disclosure_status != "embargoed" && payload.embargo_until > issued_at {
        return Some("non-embargoed remediation cannot carry a future embargo".to_owned());
    }
    None
}

fn validate_p12(
    payload: &CapabilityAttestationProfilePayload,
    root: &Map<String, Value>,
) -> Option<String> {
    let expires_at = root
        .get("expires_at")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    if payload.valid_until > expires_at {
        return Some("capability validity cannot exceed envelope expiry".to_owned());
    }
    if payload.network.egress_default != "deny" {
        return Some("capability network policy must default deny".to_owned());
    }
    if payload.sandbox == "wasm" && payload.memory_isolation != "wasm" {
        return Some("Wasm sandbox must attest Wasm memory isolation".to_owned());
    }
    if payload.sandbox == "tee" && payload.memory_isolation != "tee" {
        return Some("TEE sandbox must attest TEE memory isolation".to_owned());
    }
    None
}

impl Clone for Descriptor {
    fn clone(&self) -> Self {
        Self {
            reference: self.reference.clone(),
            field_type: self.field_type.clone(),
            constant: self.constant.clone(),
            enum_values: self.enum_values.clone(),
            pattern: self.pattern.clone(),
            min_length: self.min_length,
            minimum: self.minimum,
            maximum: self.maximum,
            min_items: self.min_items,
            max_items: self.max_items,
            unique_items: self.unique_items,
            items: self.items.clone(),
            additional_properties: self.additional_properties,
            required: self.required.clone(),
            properties: self.properties.clone(),
        }
    }
}
