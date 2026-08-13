//! W9 Spend/budget engine — per-agent USD caps, per-task token/call budgets, cost-aware model
//! routing, cost receipts.
//!
//! Spend is an authority decision: "does this agent have budget?" The answer is enforced pre-call,
//! with receipted denial. A runaway retry loop that would cost $10k overnight is stopped at the
//! budget gate, not discovered on the invoice.
//!
//! All monetary values are in **micros** (millionths of a USD) as unsigned integers — never floats.
//! This is the standard approach in payment systems and avoids the precision loss that makes float
//! money dangerous in a security-critical context.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const ENGINE_VERSION: &str = "warrantor-spend/1.0";

// Micros = millionths of a USD. All money is u64 micros, never floats.
pub const MICROS_PER_DOLLAR: u64 = 1_000_000;

// ═══════════════════════════════════════════════════════════════════════════
// Denial reasons
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// The agent's USD cap would be exceeded by this action.
    UsdCapExceeded,
    /// The task's token budget is exhausted.
    TokenBudgetExhausted,
    /// The task's tool-call budget is exhausted.
    ToolCallBudgetExhausted,
    /// No safe model backend is available at any price.
    NoSafeBackend,
    /// The requested model backend is not in the approved list.
    BackendNotApproved,
}

// ═══════════════════════════════════════════════════════════════════════════
// Budgets
// ═══════════════════════════════════════════════════════════════════════════

/// Per-agent USD budget. All amounts in micros.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentBudget {
    pub agent_id: String,
    pub usd_cap_micros: u64,
    pub usd_spent_micros: u64,
}

impl AgentBudget {
    pub fn remaining(&self) -> u64 {
        self.usd_cap_micros.saturating_sub(self.usd_spent_micros)
    }

    /// Charge `cost_micros` against the cap.
    ///
    /// The addition saturates rather than wrapping. With a plain `+` an absurd cost — an agent
    /// reporting a nonsense token count, or a corrupted price — overflows u64, which panics in
    /// debug and **wraps in release**; a wrapped sum compares small and the comparison below then
    /// yields `Ok`, i.e. the budget gate fails OPEN on exactly the inputs it exists to catch.
    /// Saturating makes the impossible sum compare large, which denies. No normal input reaches
    /// either bound, so this changes nothing except the direction of the absurd case.
    pub fn spend(&mut self, cost_micros: u64) -> Result<(), DenyReason> {
        if self.usd_spent_micros.saturating_add(cost_micros) > self.usd_cap_micros {
            return Err(DenyReason::UsdCapExceeded);
        }
        self.usd_spent_micros = self.usd_spent_micros.saturating_add(cost_micros);
        Ok(())
    }
}

/// Per-task token + tool-call budget.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskBudget {
    pub task_id: String,
    pub max_tokens: u64,
    pub tokens_used: u64,
    pub max_tool_calls: u64,
    pub tool_calls_used: u64,
}

impl TaskBudget {
    pub fn tokens_remaining(&self) -> u64 {
        self.max_tokens.saturating_sub(self.tokens_used)
    }

    pub fn tool_calls_remaining(&self) -> u64 {
        self.max_tool_calls.saturating_sub(self.tool_calls_used)
    }

    /// Consume tokens and tool calls against the task's ceilings.
    ///
    /// Saturating for the same reason as [`AgentBudget::spend`]: a wrapped sum compares small and
    /// turns an absurd request into an allow.
    pub fn consume(&mut self, tokens: u64, tool_calls: u64) -> Result<(), DenyReason> {
        if self.tokens_used.saturating_add(tokens) > self.max_tokens {
            return Err(DenyReason::TokenBudgetExhausted);
        }
        if self.tool_calls_used.saturating_add(tool_calls) > self.max_tool_calls {
            return Err(DenyReason::ToolCallBudgetExhausted);
        }
        self.tokens_used = self.tokens_used.saturating_add(tokens);
        self.tool_calls_used = self.tool_calls_used.saturating_add(tool_calls);
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Model backends with pricing
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelBackend {
    pub id: String,
    /// Price per 1,000 input tokens, in micros.
    pub price_per_1k_input_micros: u64,
    /// Price per 1,000 output tokens, in micros.
    pub price_per_1k_output_micros: u64,
    /// Whether this backend satisfies the safety constraints (attestation, policy).
    pub safe: bool,
}

impl ModelBackend {
    /// Compute the cost in micros for a given token usage.
    ///
    /// Saturating, like the budget comparisons this feeds. The token counts are caller-supplied
    /// estimates — in Warrantor's case, numbers an agent reported about itself — so an absurd count
    /// is reachable input, not a theoretical one. `(tokens / 1000) * price` overflows u64 for a
    /// large enough count, and a wrapped product is a SMALL cost that then passes the cap check:
    /// the fail-open direction, on the one function whose whole job is to say what something costs.
    /// Saturating turns the impossible number into `u64::MAX`, which every ceiling denies.
    #[must_use]
    pub fn cost_micros(&self, input_tokens: u64, output_tokens: u64) -> u64 {
        let priced = |tokens: u64, per_1k: u64| -> u64 {
            (tokens / 1000)
                .saturating_mul(per_1k)
                .saturating_add((tokens % 1000).saturating_mul(per_1k) / 1000)
        };
        priced(input_tokens, self.price_per_1k_input_micros)
            .saturating_add(priced(output_tokens, self.price_per_1k_output_micros))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Spend request + verdict
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpendRequest {
    pub agent_id: String,
    pub task_id: String,
    pub estimated_input_tokens: u64,
    pub estimated_output_tokens: u64,
    /// If None, the engine picks the cheapest safe backend.
    pub requested_backend: Option<String>,
    pub tool_calls: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SpendVerdict {
    Allow {
        cost_micros: u64,
        remaining_usd_micros: u64,
        remaining_tokens: u64,
        chosen_backend: String,
    },
    Deny {
        reason: DenyReason,
    },
}

// ═══════════════════════════════════════════════════════════════════════════
// The spend engine — the decision
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Error)]
pub enum SpendError {
    #[error("spend engine: {0}")]
    Engine(String),
}

/// Decide whether to allow a spend request. Checks (in order):
/// 1. Token budget on the task.
/// 2. Tool-call budget on the task.
/// 3. Model backend selection (requested or cheapest-safe).
/// 4. USD cap on the agent.
///
/// On Allow, the budgets are consumed (mutated). On Deny, no budgets are touched.
pub fn decide(
    request: &SpendRequest,
    agent_budget: &mut AgentBudget,
    task_budget: &mut TaskBudget,
    backends: &[ModelBackend],
) -> SpendVerdict {
    // 1. Token budget check (before consuming — fail-closed).
    //
    // Saturating throughout: these pre-checks must agree with `TaskBudget::consume` and
    // `AgentBudget::spend` exactly, and a plain `+` here would wrap in release and allow the very
    // request the gate exists to deny.
    if task_budget
        .tokens_used
        .saturating_add(request.estimated_input_tokens)
        .saturating_add(request.estimated_output_tokens)
        > task_budget.max_tokens
    {
        return SpendVerdict::Deny {
            reason: DenyReason::TokenBudgetExhausted,
        };
    }

    // 2. Tool-call budget.
    if task_budget
        .tool_calls_used
        .saturating_add(request.tool_calls)
        > task_budget.max_tool_calls
    {
        return SpendVerdict::Deny {
            reason: DenyReason::ToolCallBudgetExhausted,
        };
    }

    // 3. Model backend selection.
    let chosen = match select_backend(&request.requested_backend, backends) {
        Ok(b) => b,
        Err(reason) => return SpendVerdict::Deny { reason },
    };

    // 4. Cost computation + USD cap.
    let cost = chosen.cost_micros(
        request.estimated_input_tokens,
        request.estimated_output_tokens,
    );
    if agent_budget.usd_spent_micros.saturating_add(cost) > agent_budget.usd_cap_micros {
        return SpendVerdict::Deny {
            reason: DenyReason::UsdCapExceeded,
        };
    }

    // All checks pass — consume budgets and allow.
    let _ = task_budget.consume(
        request.estimated_input_tokens + request.estimated_output_tokens,
        request.tool_calls,
    );
    let _ = agent_budget.spend(cost);

    SpendVerdict::Allow {
        cost_micros: cost,
        remaining_usd_micros: agent_budget.remaining(),
        remaining_tokens: task_budget.tokens_remaining(),
        chosen_backend: chosen.id.clone(),
    }
}

/// Select a backend: if the agent specified one, verify it's approved + safe. If None, pick the
/// cheapest safe backend.
fn select_backend<'a>(
    requested: &Option<String>,
    backends: &'a [ModelBackend],
) -> Result<&'a ModelBackend, DenyReason> {
    let safe: Vec<&ModelBackend> = backends.iter().filter(|b| b.safe).collect();
    if safe.is_empty() {
        return Err(DenyReason::NoSafeBackend);
    }
    match requested {
        Some(id) => safe
            .into_iter()
            .find(|b| &b.id == id)
            .ok_or(DenyReason::BackendNotApproved),
        None => {
            // Cheapest safe backend: minimize cost for 1k input + 1k output (a proxy for overall cheapness).
            safe.into_iter()
                .min_by_key(|b| b.price_per_1k_input_micros + b.price_per_1k_output_micros)
                .ok_or(DenyReason::NoSafeBackend)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Signed cost receipt
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CostReceiptBody {
    pub verdict: SpendVerdict,
    pub agent_id: String,
    pub task_id: String,
    pub timestamp: u64,
    pub engine_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CostReceipt {
    pub body: CostReceiptBody,
    pub signature_algorithm: String,
    pub signature_key_id: String,
    pub signature_public_key: String,
    pub signature_value: String,
}

fn canonical_body(body: &CostReceiptBody) -> String {
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
    verdict: &SpendVerdict,
    request: &SpendRequest,
    timestamp: u64,
    signing_key: &SigningKey,
    key_id: &str,
) -> CostReceipt {
    let body = CostReceiptBody {
        verdict: verdict.clone(),
        agent_id: request.agent_id.clone(),
        task_id: request.task_id.clone(),
        timestamp,
        engine_version: ENGINE_VERSION.to_string(),
    };
    let canonical = canonical_body(&body);
    let sig: Signature = signing_key.sign(canonical.as_bytes());
    let verifying = signing_key.verifying_key();
    CostReceipt {
        body,
        signature_algorithm: "Ed25519".to_string(),
        signature_key_id: key_id.to_string(),
        signature_public_key: hex::encode(&verifying.to_bytes()),
        signature_value: hex::encode(&sig.to_bytes()),
    }
}

pub fn verify_receipt(receipt: &CostReceipt) -> Result<(), SpendError> {
    let pk_bytes = hex::decode(&receipt.signature_public_key)
        .map_err(|e| SpendError::Engine(format!("public_key hex: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(SpendError::Engine("public_key must be 32 bytes".into()));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let vkey = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| SpendError::Engine(format!("public_key: {e}")))?;
    let sig_bytes = hex::decode(&receipt.signature_value)
        .map_err(|e| SpendError::Engine(format!("signature hex: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(SpendError::Engine("signature must be 64 bytes".into()));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    let canonical = canonical_body(&receipt.body);
    vkey.verify(canonical.as_bytes(), &sig)
        .map_err(|_| SpendError::Engine("Ed25519 signature does not verify".into()))
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

    fn backends() -> Vec<ModelBackend> {
        vec![
            ModelBackend {
                id: "gpt-4o".to_string(),
                price_per_1k_input_micros: 2500,   // $0.0025/1k
                price_per_1k_output_micros: 10000, // $0.01/1k
                safe: true,
            },
            ModelBackend {
                id: "llama-3.1-local".to_string(),
                price_per_1k_input_micros: 0, // self-hosted
                price_per_1k_output_micros: 0,
                safe: true,
            },
            ModelBackend {
                id: "evil-model".to_string(),
                price_per_1k_input_micros: 1,
                price_per_1k_output_micros: 1,
                safe: false, // not safe
            },
        ]
    }

    fn agent(cap: u64) -> AgentBudget {
        AgentBudget {
            agent_id: "bot-1".into(),
            usd_cap_micros: cap,
            usd_spent_micros: 0,
        }
    }

    fn task(max_tokens: u64, max_calls: u64) -> TaskBudget {
        TaskBudget {
            task_id: "task-1".into(),
            max_tokens,
            tokens_used: 0,
            max_tool_calls: max_calls,
            tool_calls_used: 0,
        }
    }

    fn req(input: u64, output: u64, tool_calls: u64) -> SpendRequest {
        SpendRequest {
            agent_id: "bot-1".into(),
            task_id: "task-1".into(),
            estimated_input_tokens: input,
            estimated_output_tokens: output,
            requested_backend: None,
            tool_calls,
        }
    }

    #[test]
    fn allow_within_budget() {
        let mut ab = agent(10 * MICROS_PER_DOLLAR);
        let mut tb = task(100_000, 50);
        let v = decide(&req(1000, 500, 1), &mut ab, &mut tb, &backends());
        assert!(matches!(v, SpendVerdict::Allow { .. }));
        // Should pick the cheapest safe backend (llama-3.1-local at $0).
        if let SpendVerdict::Allow { chosen_backend, .. } = v {
            assert_eq!(chosen_backend, "llama-3.1-local");
        }
    }

    #[test]
    fn deny_when_usd_cap_exceeded() {
        let mut ab = agent(100); // $0.0001 cap — very low
        let mut tb = task(1_000_000, 100);
        let mut r = req(1000, 500, 1);
        r.requested_backend = Some("gpt-4o".into()); // force a paid backend → cost exceeds cap
        let v = decide(&r, &mut ab, &mut tb, &backends());
        assert_eq!(
            v,
            SpendVerdict::Deny {
                reason: DenyReason::UsdCapExceeded
            }
        );
    }

    #[test]
    fn deny_when_token_budget_exhausted() {
        let mut ab = agent(10 * MICROS_PER_DOLLAR);
        let mut tb = task(100, 50); // only 100 tokens
        let v = decide(&req(1000, 500, 1), &mut ab, &mut tb, &backends());
        assert_eq!(
            v,
            SpendVerdict::Deny {
                reason: DenyReason::TokenBudgetExhausted
            }
        );
    }

    #[test]
    fn deny_when_tool_call_budget_exhausted() {
        let mut ab = agent(10 * MICROS_PER_DOLLAR);
        let mut tb = task(1_000_000, 0); // no tool calls allowed
        let v = decide(&req(100, 50, 1), &mut ab, &mut tb, &backends());
        assert_eq!(
            v,
            SpendVerdict::Deny {
                reason: DenyReason::ToolCallBudgetExhausted
            }
        );
    }

    #[test]
    fn deny_unsafe_backend() {
        let mut ab = agent(10 * MICROS_PER_DOLLAR);
        let mut tb = task(1_000_000, 100);
        let mut r = req(1000, 500, 1);
        r.requested_backend = Some("evil-model".into());
        let v = decide(&r, &mut ab, &mut tb, &backends());
        assert_eq!(
            v,
            SpendVerdict::Deny {
                reason: DenyReason::BackendNotApproved
            }
        );
    }

    #[test]
    fn requested_safe_backend_selected() {
        let mut ab = agent(10 * MICROS_PER_DOLLAR);
        let mut tb = task(1_000_000, 100);
        let mut r = req(1000, 500, 1);
        r.requested_backend = Some("gpt-4o".into());
        let v = decide(&r, &mut ab, &mut tb, &backends());
        if let SpendVerdict::Allow { chosen_backend, .. } = v {
            assert_eq!(chosen_backend, "gpt-4o");
        } else {
            panic!("should allow");
        }
    }

    #[test]
    fn cheapest_safe_backend_chosen_by_default() {
        let mut ab = agent(10 * MICROS_PER_DOLLAR);
        let mut tb = task(1_000_000, 100);
        let v = decide(&req(1000, 500, 1), &mut ab, &mut tb, &backends());
        if let SpendVerdict::Allow { chosen_backend, .. } = v {
            assert_eq!(chosen_backend, "llama-3.1-local"); // $0, cheapest
        }
    }

    #[test]
    fn deny_when_no_safe_backend() {
        let mut ab = agent(10 * MICROS_PER_DOLLAR);
        let mut tb = task(1_000_000, 100);
        let v = decide(&req(100, 50, 1), &mut ab, &mut tb, &[]); // no backends
        assert_eq!(
            v,
            SpendVerdict::Deny {
                reason: DenyReason::NoSafeBackend
            }
        );
    }

    #[test]
    fn budgets_consumed_on_allow() {
        let mut ab = agent(10 * MICROS_PER_DOLLAR);
        let mut tb = task(10_000, 10);
        let _ = decide(&req(1000, 500, 2), &mut ab, &mut tb, &backends());
        assert_eq!(tb.tokens_used, 1500);
        assert_eq!(tb.tool_calls_used, 2);
        // `>= 0` on a u64 was always true and asserted nothing -- the test would have
        // passed with spend accounting removed entirely. Clippy caught it.
        //
        // Zero IS the right answer here: `backends()` offers a free self-hosted model
        // and the selector takes it, so an allowed request costs nothing. Asserting the
        // exact figure rather than a tautology means the test now fails if a free
        // backend is ever wrongly charged for.
        assert_eq!(
            ab.usd_spent_micros, 0,
            "the free local backend was selected, so nothing should have been charged"
        );
    }

    #[test]
    fn budgets_not_consumed_on_deny() {
        let mut ab = agent(100); // too low for any paid backend
        let mut tb = task(10_000, 10);
        let mut r = req(1000, 500, 2);
        r.requested_backend = Some("gpt-4o".into()); // force a paid backend → cost exceeds cap
        let _ = decide(&r, &mut ab, &mut tb, &backends());
        assert_eq!(tb.tokens_used, 0); // NOT consumed on deny
        assert_eq!(ab.usd_spent_micros, 0); // NOT consumed on deny
    }

    #[test]
    fn cost_computation() {
        let b = &backends()[0]; // gpt-4o: $0.0025/1k in, $0.01/1k out
        let cost = b.cost_micros(1000, 1000);
        assert_eq!(cost, 2500 + 10000); // $0.0125 = 12500 micros
    }

    #[test]
    fn receipt_round_trip_verifies() {
        let (sk, _) = generate_keypair();
        let mut ab = agent(10 * MICROS_PER_DOLLAR);
        let mut tb = task(1_000_000, 100);
        let v = decide(&req(1000, 500, 1), &mut ab, &mut tb, &backends());
        let r = issue_receipt(&v, &req(1000, 500, 1), 1000, &sk, "spend-1");
        verify_receipt(&r).expect("receipt verifies");
    }

    #[test]
    fn tampered_receipt_fails() {
        let (sk, _) = generate_keypair();
        let mut ab = agent(10 * MICROS_PER_DOLLAR);
        let mut tb = task(1_000_000, 100);
        let v = decide(&req(1000, 500, 1), &mut ab, &mut tb, &backends());
        let mut r = issue_receipt(&v, &req(1000, 500, 1), 1000, &sk, "spend-1");
        r.body.agent_id = "evil".into();
        assert!(verify_receipt(&r).is_err());
    }

    #[test]
    fn cumulative_spend_hits_cap() {
        let mut ab = agent(13_000); // $0.013 cap
        let mut tb = task(1_000_000, 100);
        let b = vec![backends()[0].clone()]; // only gpt-4o
                                             // First call: 1000 in + 500 out = 2500 + 5000 = 7500 micros. Remaining: 5500.
        let v1 = decide(&req_with_backend(1000, 500), &mut ab, &mut tb, &b);
        assert!(matches!(v1, SpendVerdict::Allow { .. }));
        // Second call: same cost = 7500. 5500 < 7500 → deny.
        let v2 = decide(&req_with_backend(1000, 500), &mut ab, &mut tb, &b);
        assert_eq!(
            v2,
            SpendVerdict::Deny {
                reason: DenyReason::UsdCapExceeded
            }
        );
    }

    /// An absurd cost must DENY, not wrap into an allow.
    ///
    /// With the plain `usd_spent + cost > cap` this crate used to carry, a cost near `u64::MAX`
    /// overflowed: debug builds panicked, release builds wrapped to a small number that compared
    /// under the cap and returned `Ok`. That is a budget gate failing open on exactly the input it
    /// exists to catch, so the arithmetic saturates and the impossible sum denies.
    #[test]
    fn an_overflowing_cost_denies_rather_than_wrapping() {
        let mut ab = agent(10 * MICROS_PER_DOLLAR);
        ab.usd_spent_micros = 5;
        assert_eq!(ab.spend(u64::MAX), Err(DenyReason::UsdCapExceeded));
        assert_eq!(ab.usd_spent_micros, 5, "a denied spend must change nothing");
    }

    /// Pricing an absurd token count must saturate, not wrap.
    ///
    /// This is the same failure one layer down: `(tokens / 1000) * price` overflows before any
    /// budget comparison happens, and a wrapped product is a small cost that sails through the cap.
    #[test]
    fn an_absurd_token_count_prices_at_the_ceiling_rather_than_wrapping() {
        let paid = &backends()[0];
        assert_eq!(paid.cost_micros(u64::MAX, u64::MAX), u64::MAX);
        // A free backend still costs nothing, however absurd the count.
        assert_eq!(backends()[1].cost_micros(u64::MAX, u64::MAX), 0);
        // And ordinary pricing is untouched.
        assert_eq!(paid.cost_micros(1000, 1000), 12_500);
        assert_eq!(paid.cost_micros(1500, 0), 3_750);
    }

    /// The same, for the task ceilings.
    #[test]
    fn an_overflowing_token_claim_denies_rather_than_wrapping() {
        let mut tb = task(1_000, 10);
        tb.tokens_used = 7;
        assert_eq!(
            tb.consume(u64::MAX, 1),
            Err(DenyReason::TokenBudgetExhausted)
        );
        assert_eq!(
            tb.consume(1, u64::MAX),
            Err(DenyReason::ToolCallBudgetExhausted)
        );
        assert_eq!(tb.tokens_used, 7);
        assert_eq!(tb.tool_calls_used, 0);
    }

    /// `decide` duplicates those comparisons before consuming, so it must saturate too — otherwise
    /// the pre-check and the consume disagree and the engine allows what the budget would refuse.
    #[test]
    fn decide_denies_an_overflowing_estimate() {
        let mut ab = agent(10 * MICROS_PER_DOLLAR);
        let mut tb = task(100_000, 50);
        let v = decide(&req(u64::MAX, u64::MAX, 1), &mut ab, &mut tb, &backends());
        assert_eq!(
            v,
            SpendVerdict::Deny {
                reason: DenyReason::TokenBudgetExhausted
            }
        );
        assert_eq!(tb.tokens_used, 0);
        assert_eq!(ab.usd_spent_micros, 0);
    }

    fn req_with_backend(input: u64, output: u64) -> SpendRequest {
        SpendRequest {
            agent_id: "bot-1".into(),
            task_id: "task-1".into(),
            estimated_input_tokens: input,
            estimated_output_tokens: output,
            requested_backend: Some("gpt-4o".into()),
            tool_calls: 1,
        }
    }
}
