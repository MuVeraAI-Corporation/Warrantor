//! W8 Computer-use broker — the MCP gateway generalized to the GUI (spec gap-analysis §3A.3).
//!
//! Every screen action (click, type, navigate, scrape) goes through an authority-scoped broker:
//! - The action's URL must be within the AAE's allowed URL patterns.
//! - The action's DOM selector must be within the AAE's allowed selectors.
//! - A pre-commit receipt is signed with a hash of the screen state before the action.
//! - Each action is independently kill-switchable.
//! - "No internet" is enforced in the browser, not in the prompt.
//!
//! This is the defense the July 2026 frontier-lab escapes needed and did not have.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const BROKER_VERSION: &str = "warrantor-computer-use/1.0";

// ═══════════════════════════════════════════════════════════════════════════
// Action types
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    Click,
    Type,
    Navigate,
    Scrape,
    Screenshot,
}

/// A screen action the agent wants to perform.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScreenAction {
    pub action_type: ActionType,
    /// The DOM selector the action targets (e.g. "#submit-button", "input[name=email]").
    /// None for Navigate/Screenshot (no specific element).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dom_selector: Option<String>,
    /// The URL the action targets or navigates to.
    pub target_url: String,
    /// Text to type (for ActionType::Type).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_text: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Authority scope — what the AAE permits
// ═══════════════════════════════════════════════════════════════════════════

/// The scope of screen actions an agent is authorized to perform. Derived from the AAE.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ActionScope {
    /// URL patterns the agent may interact with. Supports wildcards (e.g. "https://app.example.com/*").
    pub allowed_url_patterns: Vec<String>,
    /// DOM selectors the agent may interact with (e.g. "#search", "nav a").
    pub allowed_dom_selectors: Vec<String>,
    /// Action types the agent may perform.
    pub allowed_action_types: Vec<ActionType>,
    /// URLs explicitly denied (overrides allowed patterns — e.g. deny private ranges).
    pub denied_url_patterns: Vec<String>,
    /// Whether the agent has any network access at all (false = "no internet" enforced at the broker).
    pub network_allowed: bool,
}

impl ActionScope {
    /// Check whether a URL matches any allowed pattern. Supports trailing `*` wildcard.
    fn url_allowed(&self, url: &str) -> bool {
        // First check deny list (deny overrides allow).
        for pat in &self.denied_url_patterns {
            if url_matches(url, pat) {
                return false;
            }
        }
        // Then check allow list.
        if self.allowed_url_patterns.is_empty() {
            return false; // default-deny when no patterns
        }
        self.allowed_url_patterns
            .iter()
            .any(|pat| url_matches(url, pat))
    }

    /// Check whether a DOM selector is within the allowed set.
    fn dom_allowed(&self, selector: &str) -> bool {
        if self.allowed_dom_selectors.is_empty() {
            return true; // if no selector restrictions, allow all (URL scoping is the primary control)
        }
        // Exact match or prefix match (e.g. "#search" matches "#search-button").
        self.allowed_dom_selectors
            .iter()
            .any(|allowed| selector == allowed || selector.starts_with(allowed))
    }

    fn action_type_allowed(&self, action_type: ActionType) -> bool {
        self.allowed_action_types.contains(&action_type)
    }
}

/// Match a URL against a pattern. Supports trailing `*` wildcard.
fn url_matches(url: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        url.starts_with(prefix)
    } else {
        url == pattern
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Denial reasons + verdict
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// A kill-switch is active for this agent's screen session.
    KillSwitchActive,
    /// The action type is not in the allowed set.
    ActionTypeNotPermitted,
    /// The target URL is not within the allowed URL patterns.
    UrlNotInScope,
    /// The target URL is in the explicit deny list.
    UrlInDenyList,
    /// The DOM selector is not within the allowed set.
    DomSelectorNotInScope,
    /// The agent has no network access (the "no internet" rule, enforced at the broker).
    NetworkNotAllowed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum BrokerVerdict {
    Allow {
        action: ScreenAction,
        screenshot_hash: String,
    },
    Deny {
        reason: DenyReason,
    },
}

// ═══════════════════════════════════════════════════════════════════════════
// The broker — the decision engine
// ═══════════════════════════════════════════════════════════════════════════

/// A kill-switch state for screen sessions. When active, ALL actions are denied.
#[derive(Debug, Clone, Default)]
pub struct KillSwitchState {
    pub active_agents: Vec<String>,
}

impl KillSwitchState {
    pub fn is_active(&self, agent_id: &str) -> bool {
        self.active_agents.contains(&agent_id.to_string())
    }
}

/// The decision request: what the agent wants to do + the context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BrokerRequest {
    pub agent_id: String,
    pub action: ScreenAction,
    /// The SHA-256 hash of the current screenshot (the screen state BEFORE the action).
    pub screenshot_hash: String,
}

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("computer-use broker: {0}")]
    Broker(String),
}

/// Decide whether to allow or deny a screen action. Checks (in order):
/// 1. Kill switch for this agent.
/// 2. Network access (if the action is Navigate/Scrape and network is not allowed).
/// 3. Action type permitted.
/// 4. URL in scope (allowed patterns AND not in deny list).
/// 5. DOM selector in scope.
///
/// All checks are model-belief-independent: the agent's belief about what's on screen is irrelevant.
#[must_use]
pub fn decide(
    request: &BrokerRequest,
    scope: &ActionScope,
    kill_switch: &KillSwitchState,
) -> BrokerVerdict {
    // 1. Kill switch.
    if kill_switch.is_active(&request.agent_id) {
        return BrokerVerdict::Deny {
            reason: DenyReason::KillSwitchActive,
        };
    }

    // 2. Network access.
    if matches!(
        request.action.action_type,
        ActionType::Navigate | ActionType::Scrape
    ) && !scope.network_allowed
    {
        return BrokerVerdict::Deny {
            reason: DenyReason::NetworkNotAllowed,
        };
    }

    // 3. Action type.
    if !scope.action_type_allowed(request.action.action_type) {
        return BrokerVerdict::Deny {
            reason: DenyReason::ActionTypeNotPermitted,
        };
    }

    // 4. URL scope.
    if !scope.url_allowed(&request.action.target_url) {
        // Distinguish deny-list from not-in-allow-list for the receipt.
        if scope
            .denied_url_patterns
            .iter()
            .any(|p| url_matches(&request.action.target_url, p))
        {
            return BrokerVerdict::Deny {
                reason: DenyReason::UrlInDenyList,
            };
        }
        return BrokerVerdict::Deny {
            reason: DenyReason::UrlNotInScope,
        };
    }

    // 5. DOM selector scope.
    if let Some(ref selector) = request.action.dom_selector {
        if !scope.dom_allowed(selector) {
            return BrokerVerdict::Deny {
                reason: DenyReason::DomSelectorNotInScope,
            };
        }
    }

    BrokerVerdict::Allow {
        action: request.action.clone(),
        screenshot_hash: request.screenshot_hash.clone(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Signed screen-action receipt
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScreenReceiptBody {
    pub verdict: BrokerVerdict,
    pub agent_id: String,
    pub timestamp: u64,
    pub broker_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScreenReceipt {
    pub body: ScreenReceiptBody,
    pub signature_algorithm: String,
    pub signature_key_id: String,
    pub signature_public_key: String,
    pub signature_value: String,
}

fn canonical_body(body: &ScreenReceiptBody) -> String {
    let v = serde_json::to_value(body).expect("serializes");
    let v = canonicalize_value(&v);
    serde_json::to_string(&v).expect("canonical serializes")
}

fn canonicalize_value(v: &serde_json::Value) -> serde_json::Value {
    use serde_json::{Map, Value};
    match v {
        Value::Object(map) => {
            let mut sorted: Vec<(&String, &Value)> = map.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            let mut out = Map::new();
            for (k, val) in sorted {
                out.insert(k.clone(), canonicalize_value(val));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize_value).collect()),
        other => other.clone(),
    }
}

pub fn issue_receipt(
    verdict: &BrokerVerdict,
    request: &BrokerRequest,
    timestamp: u64,
    signing_key: &SigningKey,
    key_id: &str,
) -> ScreenReceipt {
    let body = ScreenReceiptBody {
        verdict: verdict.clone(),
        agent_id: request.agent_id.clone(),
        timestamp,
        broker_version: BROKER_VERSION.to_string(),
    };
    let canonical = canonical_body(&body);
    let sig: Signature = signing_key.sign(canonical.as_bytes());
    let verifying = signing_key.verifying_key();
    ScreenReceipt {
        body,
        signature_algorithm: "Ed25519".to_string(),
        signature_key_id: key_id.to_string(),
        signature_public_key: hex::encode(&verifying.to_bytes()),
        signature_value: hex::encode(&sig.to_bytes()),
    }
}

pub fn verify_receipt(receipt: &ScreenReceipt) -> Result<(), BrokerError> {
    let pk_bytes = hex::decode(&receipt.signature_public_key)
        .map_err(|e| BrokerError::Broker(format!("public_key hex: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(BrokerError::Broker("public_key must be 32 bytes".into()));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let vkey = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| BrokerError::Broker(format!("public_key: {e}")))?;
    let sig_bytes = hex::decode(&receipt.signature_value)
        .map_err(|e| BrokerError::Broker(format!("signature hex: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(BrokerError::Broker("signature must be 64 bytes".into()));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    let canonical = canonical_body(&receipt.body);
    vkey.verify(canonical.as_bytes(), &sig)
        .map_err(|_| BrokerError::Broker("Ed25519 signature does not verify".into()))
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

#[must_use]
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = ed25519_dalek::rand_core::UnwrapErr(getrandom::SysRng);
    let signing = SigningKey::generate(&mut csprng);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
    pub fn decode(hex: &str) -> Result<Vec<u8>, String> {
        if !hex.len().is_multiple_of(2) {
            return Err("odd-length hex".into());
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> ActionScope {
        ActionScope {
            allowed_url_patterns: vec!["https://app.example.com/*".to_string()],
            allowed_dom_selectors: vec!["#search".to_string(), "nav".to_string()],
            allowed_action_types: vec![ActionType::Click, ActionType::Type, ActionType::Navigate],
            denied_url_patterns: vec!["https://evil.example.com/*".to_string()],
            network_allowed: true,
        }
    }

    fn req(action_type: ActionType, url: &str, dom: Option<&str>) -> BrokerRequest {
        BrokerRequest {
            agent_id: "bot-1".to_string(),
            action: ScreenAction {
                action_type,
                dom_selector: dom.map(String::from),
                target_url: url.to_string(),
                input_text: None,
            },
            screenshot_hash: "sha256:abc123".to_string(),
        }
    }

    #[test]
    fn allow_click_on_authorized_url_and_dom() {
        let v = decide(
            &req(
                ActionType::Click,
                "https://app.example.com/dashboard",
                Some("#search"),
            ),
            &scope(),
            &KillSwitchState::default(),
        );
        assert!(matches!(v, BrokerVerdict::Allow { .. }));
    }

    #[test]
    fn deny_url_not_in_scope() {
        let v = decide(
            &req(
                ActionType::Click,
                "https://other.example.com/page",
                Some("#search"),
            ),
            &scope(),
            &KillSwitchState::default(),
        );
        assert_eq!(
            v,
            BrokerVerdict::Deny {
                reason: DenyReason::UrlNotInScope
            }
        );
    }

    #[test]
    fn deny_url_in_deny_list() {
        let v = decide(
            &req(
                ActionType::Click,
                "https://evil.example.com/exploit",
                Some("#search"),
            ),
            &scope(),
            &KillSwitchState::default(),
        );
        assert_eq!(
            v,
            BrokerVerdict::Deny {
                reason: DenyReason::UrlInDenyList
            }
        );
    }

    #[test]
    fn deny_kill_switch_active() {
        let ks = KillSwitchState {
            active_agents: vec!["bot-1".to_string()],
        };
        let v = decide(
            &req(
                ActionType::Click,
                "https://app.example.com/dashboard",
                Some("#search"),
            ),
            &scope(),
            &ks,
        );
        assert_eq!(
            v,
            BrokerVerdict::Deny {
                reason: DenyReason::KillSwitchActive
            }
        );
    }

    #[test]
    fn deny_action_type_not_permitted() {
        // Scrape is not in the allowed action types.
        let v = decide(
            &req(ActionType::Scrape, "https://app.example.com/data", None),
            &scope(),
            &KillSwitchState::default(),
        );
        assert_eq!(
            v,
            BrokerVerdict::Deny {
                reason: DenyReason::ActionTypeNotPermitted
            }
        );
    }

    #[test]
    fn deny_network_not_allowed_for_navigate() {
        let mut s = scope();
        s.network_allowed = false;
        let v = decide(
            &req(ActionType::Navigate, "https://app.example.com/page", None),
            &s,
            &KillSwitchState::default(),
        );
        assert_eq!(
            v,
            BrokerVerdict::Deny {
                reason: DenyReason::NetworkNotAllowed
            }
        );
    }

    #[test]
    fn deny_dom_selector_not_in_scope() {
        let v = decide(
            &req(
                ActionType::Click,
                "https://app.example.com/dashboard",
                Some("#admin-panel"),
            ),
            &scope(),
            &KillSwitchState::default(),
        );
        assert_eq!(
            v,
            BrokerVerdict::Deny {
                reason: DenyReason::DomSelectorNotInScope
            }
        );
    }

    #[test]
    fn url_wildcard_matching() {
        assert!(url_matches(
            "https://app.example.com/page",
            "https://app.example.com/*"
        ));
        assert!(url_matches(
            "https://app.example.com/a/b/c",
            "https://app.example.com/*"
        ));
        assert!(!url_matches(
            "https://other.com/page",
            "https://app.example.com/*"
        ));
        assert!(url_matches("https://exact.com", "https://exact.com"));
    }

    #[test]
    fn receipt_round_trip_verifies() {
        let (sk, _) = generate_keypair();
        let v = decide(
            &req(
                ActionType::Click,
                "https://app.example.com/dashboard",
                Some("#search"),
            ),
            &scope(),
            &KillSwitchState::default(),
        );
        let r = req(
            ActionType::Click,
            "https://app.example.com/dashboard",
            Some("#search"),
        );
        let receipt = issue_receipt(&v, &r, 1000, &sk, "cu-1");
        verify_receipt(&receipt).expect("receipt verifies");
    }

    #[test]
    fn tampered_receipt_fails() {
        let (sk, _) = generate_keypair();
        let v = decide(
            &req(
                ActionType::Click,
                "https://app.example.com/dashboard",
                Some("#search"),
            ),
            &scope(),
            &KillSwitchState::default(),
        );
        let r = req(
            ActionType::Click,
            "https://app.example.com/dashboard",
            Some("#search"),
        );
        let mut receipt = issue_receipt(&v, &r, 1000, &sk, "cu-1");
        receipt.body.agent_id = "evil".to_string();
        assert!(verify_receipt(&receipt).is_err());
    }

    #[test]
    fn deny_overrides_allow_when_url_in_both_lists() {
        let mut s = scope();
        s.allowed_url_patterns
            .push("https://dual.example.com/*".to_string());
        s.denied_url_patterns
            .push("https://dual.example.com/*".to_string());
        let v = decide(
            &req(
                ActionType::Click,
                "https://dual.example.com/page",
                Some("#search"),
            ),
            &s,
            &KillSwitchState::default(),
        );
        assert_eq!(
            v,
            BrokerVerdict::Deny {
                reason: DenyReason::UrlInDenyList
            }
        );
    }

    #[test]
    fn kill_switch_for_different_agent_does_not_block() {
        let ks = KillSwitchState {
            active_agents: vec!["other-bot".to_string()],
        };
        let v = decide(
            &req(
                ActionType::Click,
                "https://app.example.com/dashboard",
                Some("#search"),
            ),
            &scope(),
            &ks,
        );
        assert!(matches!(v, BrokerVerdict::Allow { .. }));
    }
}
