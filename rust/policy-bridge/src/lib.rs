//! # warrantor-policy-bridge (R6)
//!
//! A fail-closed canonical policy evaluator and adapter boundary for OPA, Cedar, and OpenShell.
//! The bridge computes one immutable policy digest, sends that same semantic policy to every
//! configured engine, validates the digest in each response, and rejects unavailable, malformed,
//! or divergent decisions.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Canonical policy format understood by the reference evaluator and all adapters.
pub const POLICY_FORMAT: &str = "osaf.policy/1";

/// Rule effect. Deny rules always override allow rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    /// Grant the matching operation.
    Allow,
    /// Reject the matching operation.
    Deny,
}

/// One canonical policy rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Stable rule identifier used in evidence.
    pub id: String,
    /// Rule effect.
    pub effect: Effect,
    /// Allowed principals; `*` matches any principal.
    pub principals: Vec<String>,
    /// Allowed action names; `*` matches any action.
    pub actions: Vec<String>,
    /// Allowed resources; a trailing `*` is a prefix match.
    pub resources: Vec<String>,
    /// Required exact context key/value pairs.
    #[serde(default)]
    pub conditions: BTreeMap<String, String>,
}

/// Canonical policy document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalPolicy {
    /// Exact format identifier.
    pub format: String,
    /// Stable policy identifier.
    pub id: String,
    /// Monotonic policy revision.
    pub revision: u64,
    /// Default decision when no allow rule matches. Must remain deny in v1.
    pub default_effect: Effect,
    /// Policy rules. Deny overrides allow regardless of order.
    pub rules: Vec<Rule>,
}

impl CanonicalPolicy {
    /// Validate the document and return its deterministic SHA-256 digest.
    ///
    /// # Errors
    /// Returns [`BridgeError::InvalidPolicy`] when the policy is ambiguous or unsafe.
    pub fn validate_and_digest(&self) -> Result<String, BridgeError> {
        if self.format != POLICY_FORMAT {
            return Err(BridgeError::InvalidPolicy(format!(
                "format must be {POLICY_FORMAT}"
            )));
        }
        if self.id.is_empty() {
            return Err(BridgeError::InvalidPolicy("policy id is required".into()));
        }
        if self.default_effect != Effect::Deny {
            return Err(BridgeError::InvalidPolicy(
                "v1 policies must default deny".into(),
            ));
        }
        let mut identifiers = BTreeSet::new();
        for rule in &self.rules {
            if rule.id.is_empty() || !identifiers.insert(rule.id.clone()) {
                return Err(BridgeError::InvalidPolicy(
                    "rule ids must be non-empty and unique".into(),
                ));
            }
            if rule.principals.is_empty() || rule.actions.is_empty() || rule.resources.is_empty() {
                return Err(BridgeError::InvalidPolicy(format!(
                    "rule {} must constrain principals, actions, and resources",
                    rule.id
                )));
            }
            for value in rule
                .principals
                .iter()
                .chain(rule.actions.iter())
                .chain(rule.resources.iter())
            {
                if value.is_empty() || value.contains('\0') || value.contains(['\r', '\n']) {
                    return Err(BridgeError::InvalidPolicy(format!(
                        "rule {} contains an invalid matcher",
                        rule.id
                    )));
                }
            }
        }
        let canonical = serde_json::to_vec(self)
            .map_err(|error| BridgeError::InvalidPolicy(error.to_string()))?;
        Ok(format!("sha256:{}", hex::encode(Sha256::digest(canonical))))
    }
}

/// An authorization query evaluated against a canonical policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionRequest {
    /// Authenticated caller identity.
    pub principal: String,
    /// Requested operation.
    pub action: String,
    /// Target resource URI.
    pub resource: String,
    /// Trusted request context.
    #[serde(default)]
    pub context: BTreeMap<String, String>,
}

/// Engine-independent decision and evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// True only when an allow matched and no deny matched.
    pub allowed: bool,
    /// Matching canonical rule identifiers.
    pub matched_rule_ids: Vec<String>,
    /// Digest of the exact canonical policy evaluated.
    pub policy_digest: String,
}

fn exact_or_wildcard_match(patterns: &[String], value: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| pattern == "*" || pattern == value)
}

fn resource_match(patterns: &[String], resource: &str) -> bool {
    patterns.iter().any(|pattern| {
        pattern == "*"
            || pattern == resource
            || pattern
                .strip_suffix('*')
                .is_some_and(|prefix| resource.starts_with(prefix))
    })
}

fn rule_matches(rule: &Rule, request: &DecisionRequest) -> bool {
    exact_or_wildcard_match(&rule.principals, &request.principal)
        && exact_or_wildcard_match(&rule.actions, &request.action)
        && resource_match(&rule.resources, &request.resource)
        && rule
            .conditions
            .iter()
            .all(|(key, value)| request.context.get(key) == Some(value))
}

/// Evaluate the canonical policy with deterministic deny-overrides semantics.
///
/// # Errors
/// Returns [`BridgeError::InvalidPolicy`] before evaluation if validation fails.
pub fn evaluate_reference(
    policy: &CanonicalPolicy,
    request: &DecisionRequest,
) -> Result<Decision, BridgeError> {
    let policy_digest = policy.validate_and_digest()?;
    let mut matched_rule_ids = Vec::new();
    let mut allow_matched = false;
    let mut deny_matched = false;
    for rule in &policy.rules {
        if rule_matches(rule, request) {
            matched_rule_ids.push(rule.id.clone());
            match rule.effect {
                Effect::Allow => allow_matched = true,
                Effect::Deny => deny_matched = true,
            }
        }
    }
    matched_rule_ids.sort();
    Ok(Decision {
        allowed: allow_matched && !deny_matched,
        matched_rule_ids,
        policy_digest,
    })
}

/// Supported policy engine adapter kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineKind {
    /// Built-in Rust reference evaluator.
    Reference,
    /// Open Policy Agent adapter.
    Opa,
    /// Cedar adapter.
    Cedar,
    /// OpenShell policy adapter.
    OpenShell,
}

/// A request sent to an injected external policy-engine client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineRequest {
    /// Target engine.
    pub engine: EngineKind,
    /// Canonical policy document.
    pub policy: CanonicalPolicy,
    /// Expected policy digest.
    pub policy_digest: String,
    /// Authorization query.
    pub request: DecisionRequest,
}

/// Validated response contract required from external engine clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineResponse {
    /// Engine decision.
    pub allowed: bool,
    /// Canonical rule identifiers reported as matches.
    pub matched_rule_ids: Vec<String>,
    /// Digest echoed by the engine after loading the policy.
    pub policy_digest: String,
}

/// Transport boundary implemented by OPA, Cedar, or OpenShell integrations.
pub trait EngineClient: Send + Sync {
    /// Evaluate one engine request.
    fn evaluate(&self, request: &EngineRequest) -> Result<EngineResponse, String>;
}

/// Common interface for the reference and external adapters.
pub trait PolicyEngine: Send + Sync {
    /// Engine identity.
    fn kind(&self) -> EngineKind;
    /// Evaluate one request.
    fn evaluate(
        &self,
        policy: &CanonicalPolicy,
        request: &DecisionRequest,
    ) -> Result<Decision, BridgeError>;
}

/// Built-in reference engine.
#[derive(Debug, Default)]
pub struct ReferenceEngine;

impl PolicyEngine for ReferenceEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::Reference
    }

    fn evaluate(
        &self,
        policy: &CanonicalPolicy,
        request: &DecisionRequest,
    ) -> Result<Decision, BridgeError> {
        evaluate_reference(policy, request)
    }
}

/// Fail-closed adapter around an injected external engine client.
pub struct ExternalEngine<C> {
    kind: EngineKind,
    client: C,
}

impl<C> ExternalEngine<C> {
    /// Construct an external adapter. Reference is rejected because it has no external client.
    ///
    /// # Errors
    /// Returns [`BridgeError::InvalidEngine`] for [`EngineKind::Reference`].
    pub fn new(kind: EngineKind, client: C) -> Result<Self, BridgeError> {
        if kind == EngineKind::Reference {
            return Err(BridgeError::InvalidEngine);
        }
        Ok(Self { kind, client })
    }
}

impl<C: EngineClient> PolicyEngine for ExternalEngine<C> {
    fn kind(&self) -> EngineKind {
        self.kind
    }

    fn evaluate(
        &self,
        policy: &CanonicalPolicy,
        request: &DecisionRequest,
    ) -> Result<Decision, BridgeError> {
        let policy_digest = policy.validate_and_digest()?;
        let response = self
            .client
            .evaluate(&EngineRequest {
                engine: self.kind,
                policy: policy.clone(),
                policy_digest: policy_digest.clone(),
                request: request.clone(),
            })
            .map_err(|message| BridgeError::EngineUnavailable {
                engine: self.kind,
                message,
            })?;
        if response.policy_digest != policy_digest {
            return Err(BridgeError::PolicyDigestMismatch { engine: self.kind });
        }
        let known_ids: BTreeSet<&str> = policy.rules.iter().map(|rule| rule.id.as_str()).collect();
        if response
            .matched_rule_ids
            .iter()
            .any(|identifier| !known_ids.contains(identifier.as_str()))
        {
            return Err(BridgeError::MalformedEngineResponse { engine: self.kind });
        }
        let mut matched_rule_ids = response.matched_rule_ids;
        matched_rule_ids.sort();
        matched_rule_ids.dedup();
        Ok(Decision {
            allowed: response.allowed,
            matched_rule_ids,
            policy_digest,
        })
    }
}

/// A per-engine decision returned after equivalence succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineDecision {
    /// Engine identity.
    pub engine: EngineKind,
    /// Validated decision.
    pub decision: Decision,
}

/// Evaluates all configured engines and rejects any disagreement or outage.
pub struct DecisionBridge {
    engines: Vec<Box<dyn PolicyEngine>>,
}

impl DecisionBridge {
    /// Build a bridge. At least two uniquely named engines are required for equivalence proof.
    ///
    /// # Errors
    /// Returns [`BridgeError::InsufficientEngines`] or [`BridgeError::DuplicateEngine`].
    pub fn new(engines: Vec<Box<dyn PolicyEngine>>) -> Result<Self, BridgeError> {
        if engines.len() < 2 {
            return Err(BridgeError::InsufficientEngines);
        }
        let mut kinds = BTreeSet::new();
        for engine in &engines {
            if !kinds.insert(engine.kind()) {
                return Err(BridgeError::DuplicateEngine(engine.kind()));
            }
        }
        Ok(Self { engines })
    }

    /// Evaluate every engine. No partial decision is returned.
    ///
    /// # Errors
    /// Fails closed on policy errors, engine errors, digest mismatch, or decision disagreement.
    pub fn evaluate_equivalent(
        &self,
        policy: &CanonicalPolicy,
        request: &DecisionRequest,
    ) -> Result<Vec<EngineDecision>, BridgeError> {
        let mut decisions = Vec::with_capacity(self.engines.len());
        for engine in &self.engines {
            decisions.push(EngineDecision {
                engine: engine.kind(),
                decision: engine.evaluate(policy, request)?,
            });
        }
        let expected = &decisions[0].decision;
        if decisions.iter().skip(1).any(|decision| {
            decision.decision.allowed != expected.allowed
                || decision.decision.policy_digest != expected.policy_digest
        }) {
            return Err(BridgeError::DecisionDivergence);
        }
        Ok(decisions)
    }
}

/// Stable OPA Rego module that evaluates an `osaf.policy/1` data document.
pub const OPA_REGO_MODULE: &str = r#"package osaf.policy.v1
default allow := false
matches(patterns, value) if { some pattern in patterns; pattern == "*" }
matches(patterns, value) if { some pattern in patterns; pattern == value }
resource_matches(patterns, value) if { some pattern in patterns; pattern == "*" }
resource_matches(patterns, value) if { some pattern in patterns; pattern == value }
resource_matches(patterns, value) if {
  some pattern in patterns
  pattern != "*"
  endswith(pattern, "*")
  startswith(value, trim_suffix(pattern, "*"))
}
matching_rule contains rule if {
  some rule in data.osaf_policy.rules
  matches(rule.principals, input.principal)
  matches(rule.actions, input.action)
  resource_matches(rule.resources, input.resource)
  every key, value in rule.conditions { input.context[key] == value }
}
allow if {
  some rule in matching_rule
  rule.effect == "allow"
  not some deny in matching_rule { deny.effect == "deny" }
}"#;

/// Serialize a validated OpenShell policy bundle with the canonical digest.
///
/// # Errors
/// Returns a policy validation or serialization error.
pub fn compile_openshell(policy: &CanonicalPolicy) -> Result<Vec<u8>, BridgeError> {
    let digest = policy.validate_and_digest()?;
    serde_json::to_vec(&serde_json::json!({
        "apiVersion": "openshell.dev/v1alpha1",
        "kind": "AgentPolicy",
        "metadata": { "name": policy.id, "revision": policy.revision, "digest": digest },
        "spec": policy,
    }))
    .map_err(|error| BridgeError::InvalidPolicy(error.to_string()))
}

/// Policy bridge failures. All variants deny the requested operation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BridgeError {
    /// Canonical policy validation failed.
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),
    /// Reference cannot be constructed as an external adapter.
    #[error("reference engine cannot use an external adapter")]
    InvalidEngine,
    /// Equivalence requires at least two independent engines.
    #[error("at least two engines are required")]
    InsufficientEngines,
    /// The bridge contained the same engine twice.
    #[error("duplicate engine: {0:?}")]
    DuplicateEngine(EngineKind),
    /// An engine could not produce a decision.
    #[error("engine {engine:?} unavailable: {message}")]
    EngineUnavailable {
        /// Failed engine.
        engine: EngineKind,
        /// Stable transport detail.
        message: String,
    },
    /// The engine did not evaluate the requested canonical policy digest.
    #[error("engine {engine:?} returned a different policy digest")]
    PolicyDigestMismatch {
        /// Engine that returned the mismatch.
        engine: EngineKind,
    },
    /// The engine response referenced unknown rules or otherwise violated the contract.
    #[error("engine {engine:?} returned a malformed response")]
    MalformedEngineResponse {
        /// Engine that returned malformed evidence.
        engine: EngineKind,
    },
    /// Two validated engines disagreed on allow/deny.
    #[error("policy engine decisions diverged")]
    DecisionDivergence,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn policy() -> CanonicalPolicy {
        CanonicalPolicy {
            format: POLICY_FORMAT.into(),
            id: "workspace-policy".into(),
            revision: 7,
            default_effect: Effect::Deny,
            rules: vec![
                Rule {
                    id: "allow-read".into(),
                    effect: Effect::Allow,
                    principals: vec!["spiffe://example.org/agent".into()],
                    actions: vec!["read".into()],
                    resources: vec!["repo://project/*".into()],
                    conditions: BTreeMap::from([("environment".into(), "prod".into())]),
                },
                Rule {
                    id: "deny-secrets".into(),
                    effect: Effect::Deny,
                    principals: vec!["*".into()],
                    actions: vec!["read".into()],
                    resources: vec!["repo://project/secrets/*".into()],
                    conditions: BTreeMap::new(),
                },
            ],
        }
    }

    fn request(resource: &str) -> DecisionRequest {
        DecisionRequest {
            principal: "spiffe://example.org/agent".into(),
            action: "read".into(),
            resource: resource.into(),
            context: BTreeMap::from([("environment".into(), "prod".into())]),
        }
    }

    #[test]
    fn reference_is_default_deny_and_deny_overrides_allow() {
        let allowed = evaluate_reference(&policy(), &request("repo://project/src/lib.rs"))
            .expect("valid policy");
        assert!(allowed.allowed);
        assert_eq!(allowed.matched_rule_ids, vec!["allow-read"]);

        let denied = evaluate_reference(&policy(), &request("repo://project/secrets/key"))
            .expect("valid policy");
        assert!(!denied.allowed);
        assert_eq!(denied.matched_rule_ids, vec!["allow-read", "deny-secrets"]);

        let unmatched =
            evaluate_reference(&policy(), &request("other://resource")).expect("valid policy");
        assert!(!unmatched.allowed);
    }

    #[test]
    fn policy_validation_rejects_ambiguous_or_fail_open_documents() {
        let mut invalid = policy();
        invalid.default_effect = Effect::Allow;
        assert!(matches!(
            invalid.validate_and_digest(),
            Err(BridgeError::InvalidPolicy(_))
        ));
        let mut duplicate = policy();
        duplicate.rules[1].id = duplicate.rules[0].id.clone();
        assert!(matches!(
            duplicate.validate_and_digest(),
            Err(BridgeError::InvalidPolicy(_))
        ));
    }

    struct ReferenceClient {
        requests: Mutex<Vec<EngineRequest>>,
        override_allowed: Option<bool>,
        override_digest: Option<String>,
        failure: Option<String>,
    }

    impl EngineClient for ReferenceClient {
        fn evaluate(&self, request: &EngineRequest) -> Result<EngineResponse, String> {
            self.requests
                .lock()
                .expect("request lock")
                .push(request.clone());
            if let Some(failure) = &self.failure {
                return Err(failure.clone());
            }
            let decision = evaluate_reference(&request.policy, &request.request)
                .map_err(|error| error.to_string())?;
            Ok(EngineResponse {
                allowed: self.override_allowed.unwrap_or(decision.allowed),
                matched_rule_ids: decision.matched_rule_ids,
                policy_digest: self
                    .override_digest
                    .clone()
                    .unwrap_or(decision.policy_digest),
            })
        }
    }

    fn client() -> ReferenceClient {
        ReferenceClient {
            requests: Mutex::new(Vec::new()),
            override_allowed: None,
            override_digest: None,
            failure: None,
        }
    }

    #[test]
    fn bridge_proves_equivalence_across_reference_opa_cedar_and_openshell() {
        let bridge = DecisionBridge::new(vec![
            Box::<ReferenceEngine>::default(),
            Box::new(ExternalEngine::new(EngineKind::Opa, client()).expect("OPA")),
            Box::new(ExternalEngine::new(EngineKind::Cedar, client()).expect("Cedar")),
            Box::new(ExternalEngine::new(EngineKind::OpenShell, client()).expect("OpenShell")),
        ])
        .expect("bridge");
        let decisions = bridge
            .evaluate_equivalent(&policy(), &request("repo://project/src/lib.rs"))
            .expect("equivalent");
        assert_eq!(decisions.len(), 4);
        assert!(decisions.iter().all(|decision| decision.decision.allowed));
    }

    #[test]
    fn bridge_fails_closed_on_outage_digest_substitution_and_divergence() {
        let mut unavailable = client();
        unavailable.failure = Some("connection refused".into());
        let bridge = DecisionBridge::new(vec![
            Box::<ReferenceEngine>::default(),
            Box::new(ExternalEngine::new(EngineKind::Opa, unavailable).expect("OPA")),
        ])
        .expect("bridge");
        assert!(matches!(
            bridge.evaluate_equivalent(&policy(), &request("repo://project/src/lib.rs")),
            Err(BridgeError::EngineUnavailable { .. })
        ));

        let mut substituted = client();
        substituted.override_digest = Some("sha256:attacker".into());
        let bridge = DecisionBridge::new(vec![
            Box::<ReferenceEngine>::default(),
            Box::new(ExternalEngine::new(EngineKind::Cedar, substituted).expect("Cedar")),
        ])
        .expect("bridge");
        assert!(matches!(
            bridge.evaluate_equivalent(&policy(), &request("repo://project/src/lib.rs")),
            Err(BridgeError::PolicyDigestMismatch { .. })
        ));

        let mut divergent = client();
        divergent.override_allowed = Some(false);
        let bridge = DecisionBridge::new(vec![
            Box::<ReferenceEngine>::default(),
            Box::new(ExternalEngine::new(EngineKind::OpenShell, divergent).expect("OpenShell")),
        ])
        .expect("bridge");
        assert_eq!(
            bridge.evaluate_equivalent(&policy(), &request("repo://project/src/lib.rs")),
            Err(BridgeError::DecisionDivergence)
        );
    }

    #[test]
    fn openshell_bundle_is_deterministic_and_digest_bound() {
        let first = compile_openshell(&policy()).expect("compile");
        let second = compile_openshell(&policy()).expect("compile");
        assert_eq!(first, second);
        let document: serde_json::Value = serde_json::from_slice(&first).expect("JSON");
        assert_eq!(document["apiVersion"], "openshell.dev/v1alpha1");
        assert!(document["metadata"]["digest"]
            .as_str()
            .expect("digest")
            .starts_with("sha256:"));
    }
}
