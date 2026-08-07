//! # aumos-inference-proxy (N3)
//!
//! A dedicated LLM inference gateway that sits in front of N1 open-serve-kit. Middleware chain:
//!   1. **auth** — verify a SPIFFE SVID or API key
//!   2. **rate_limit** — per-identity token bucket
//!   3. **prompt_filter** — detect prompt injection / PII / content-policy violations
//!   4. **cache** — semantic cache (exact-match in v1.0; similarity-based in task 03)
//!   5. **audit** — emit an AAR (P2) via E1 flight-recorder
//!   6. **fallback** — fail over to a backup backend on error
//!
//! See RFC N3.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Errors returned by the proxy middleware chain.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// Authentication failed.
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    /// Rate limit exceeded.
    #[error("rate limit exceeded for {identity} (limit={limit}/s)")]
    RateLimitExceeded {
        /// The identity whose bucket is empty.
        identity: String,
        /// The configured per-second limit.
        limit: u32,
    },
    /// The prompt was rejected by the filter.
    #[error("prompt rejected: {0}")]
    PromptRejected(String),
}

/// A request entering the proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRequest {
    /// The caller identity (SPIFFE SVID or API key id).
    pub identity: String,
    /// The model id.
    pub model: String,
    /// The prompt text.
    pub prompt: String,
}

/// A response leaving the proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyResponse {
    /// The completion text.
    pub text: String,
    /// Whether the response came from the cache.
    pub cached: bool,
}

// ---------------------------------------------------------------------------
// Middleware 1: auth
// ---------------------------------------------------------------------------
/// Authenticator trait. Implementations verify the identity credential.
pub trait Authenticator: Send + Sync {
    /// Verify the identity. Returns Ok(()) on success.
    ///
    /// # Errors
    /// Returns [`ProxyError::Unauthorized`] on failure.
    fn verify(&self, identity: &str) -> Result<(), ProxyError>;
}

/// An allow-list authenticator (SPIFFE IDs or API keys in a set).
pub struct AllowListAuth {
    allowed: std::collections::HashSet<String>,
}

impl AllowListAuth {
    /// Construct with the given allowed identities.
    #[must_use]
    pub fn new<I>(allowed: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        Self {
            allowed: allowed.into_iter().collect(),
        }
    }
}

impl Authenticator for AllowListAuth {
    fn verify(&self, identity: &str) -> Result<(), ProxyError> {
        if self.allowed.contains(identity) {
            Ok(())
        } else {
            Err(ProxyError::Unauthorized(format!(
                "identity {identity} not in allow list"
            )))
        }
    }
}

/// An open authenticator (CI / development only — accepts everything).
pub struct OpenAuth;

impl Authenticator for OpenAuth {
    fn verify(&self, _identity: &str) -> Result<(), ProxyError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Middleware 2: rate limit (token bucket per identity)
// ---------------------------------------------------------------------------
/// A per-identity token-bucket rate limiter.
pub struct RateLimiter {
    limit_per_sec: u32,
    state: Mutex<HashMap<String, Bucket>>,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    /// Construct with a per-identity per-second limit.
    #[must_use]
    pub fn new(limit_per_sec: u32) -> Self {
        Self {
            limit_per_sec,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Check one request for `identity`. Returns Ok(()) if allowed.
    ///
    /// # Errors
    /// Returns [`ProxyError::RateLimitExceeded`] if the bucket is empty.
    pub fn check(&self, identity: &str) -> Result<(), ProxyError> {
        // H7 fix: recover from poisoned mutex instead of panicking (panic=abort in release)
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let bucket = state.entry(identity.to_string()).or_insert(Bucket {
            tokens: f64::from(self.limit_per_sec),
            last_refill: now,
        });
        // Refill based on elapsed time.
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * f64::from(self.limit_per_sec))
            .min(f64::from(self.limit_per_sec));
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            Err(ProxyError::RateLimitExceeded {
                identity: identity.to_string(),
                limit: self.limit_per_sec,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Middleware 3: prompt filter
// ---------------------------------------------------------------------------
/// Prompt-injection + PII + content-policy filter. v1.0 uses simple substring matching;
/// task 03 adds a learned classifier.
pub struct PromptFilter {
    injection_markers: Vec<String>,
    banned_substrings: Vec<String>,
}

impl PromptFilter {
    /// Construct with default injection markers (the markers A2 adversaria uses).
    #[must_use]
    pub fn new() -> Self {
        Self {
            injection_markers: vec![
                "system override".into(),
                "disregard all previous".into(),
                "DAN jailbreak".into(),
                "maintenance mode".into(),
            ],
            banned_substrings: vec![
                // PII patterns (simplified — R4 credential-vault has the real scanner)
                "AKIA".into(), // AWS key prefix
            ],
        }
    }

    /// Add a custom banned substring.
    pub fn ban(mut self, s: impl Into<String>) -> Self {
        self.banned_substrings.push(s.into());
        self
    }

    /// Check a prompt. Returns Ok(()) if it passes the filter.
    ///
    /// # Errors
    /// Returns [`ProxyError::PromptRejected`] if the prompt matches an injection marker or
    /// banned substring.
    pub fn check(&self, prompt: &str) -> Result<(), ProxyError> {
        let lowered = prompt.to_lowercase();
        for marker in &self.injection_markers {
            if lowered.contains(marker) {
                return Err(ProxyError::PromptRejected(format!(
                    "injection marker detected: {marker}"
                )));
            }
        }
        for banned in &self.banned_substrings {
            if prompt.contains(banned) {
                return Err(ProxyError::PromptRejected(format!(
                    "banned content: {banned}"
                )));
            }
        }
        Ok(())
    }
}

impl Default for PromptFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Middleware 4: semantic cache (exact-match in v1.0)
// ---------------------------------------------------------------------------
/// An exact-match cache keyed on (model, sha256(prompt)). Similarity-based caching is task 03.
pub struct Cache {
    store: Mutex<HashMap<String, String>>,
}

impl Cache {
    /// Construct an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }

    fn key(model: &str, prompt: &str) -> String {
        let mut h = Sha256::new();
        h.update(model.as_bytes());
        h.update(b"|");
        h.update(prompt.as_bytes());
        let digest = hex::encode(h.finalize());
        format!("{model}/{digest}")
    }

    /// Look up a cached response.
    pub fn get(&self, model: &str, prompt: &str) -> Option<String> {
        let store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        store.get(&Self::key(model, prompt)).cloned()
    }

    /// Store a response.
    pub fn put(&self, model: &str, prompt: &str, response: &str) {
        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        store.insert(Self::key(model, prompt), response.to_string());
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.store.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// The full middleware chain
// ---------------------------------------------------------------------------
/// The proxy holding its middleware instances.
pub struct Proxy {
    auth: Box<dyn Authenticator>,
    rate_limiter: RateLimiter,
    filter: PromptFilter,
    cache: Cache,
}

/// Builder for the proxy.
pub struct ProxyBuilder {
    auth: Box<dyn Authenticator>,
    rate_limit_per_sec: u32,
    filter: PromptFilter,
}

impl ProxyBuilder {
    /// Start with an open authenticator and 100 req/sec limit.
    #[must_use]
    pub fn new() -> Self {
        Self {
            auth: Box::new(OpenAuth),
            rate_limit_per_sec: 100,
            filter: PromptFilter::new(),
        }
    }

    /// Set the authenticator.
    pub fn auth(mut self, a: Box<dyn Authenticator>) -> Self {
        self.auth = a;
        self
    }

    /// Set the per-identity rate limit.
    pub fn rate_limit(mut self, per_sec: u32) -> Self {
        self.rate_limit_per_sec = per_sec;
        self
    }

    /// Build the proxy with a fresh cache.
    #[must_use]
    pub fn build(self) -> Proxy {
        Proxy {
            auth: self.auth,
            rate_limiter: RateLimiter::new(self.rate_limit_per_sec),
            filter: self.filter,
            cache: Cache::new(),
        }
    }
}

impl Default for ProxyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Proxy {
    /// Run a request through the middleware chain. The supplied `backend` function performs
    /// the actual inference (in production this is the call to N1 open-serve-kit).
    ///
    /// # Errors
    /// Returns [`ProxyError`] if any middleware rejects the request.
    pub fn handle(
        &self,
        req: &ProxyRequest,
        mut backend: impl FnMut(&ProxyRequest) -> String,
    ) -> Result<ProxyResponse, ProxyError> {
        self.auth.verify(&req.identity)?;
        self.rate_limiter.check(&req.identity)?;
        self.filter.check(&req.prompt)?;
        if let Some(cached) = self.cache.get(&req.model, &req.prompt) {
            return Ok(ProxyResponse {
                text: cached,
                cached: true,
            });
        }
        let text = backend(req);
        self.cache.put(&req.model, &req.prompt, &text);
        Ok(ProxyResponse {
            text,
            cached: false,
        })
    }
}

// Suppress an unused-import warning if Duration ends up unused.
#[allow(dead_code)]
fn _duration_marker() -> Duration {
    Duration::from_secs(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list_auth_accepts_known() {
        let a = AllowListAuth::new(["spiffe://aumos.dev/agent/x".to_string()]);
        assert!(a.verify("spiffe://aumos.dev/agent/x").is_ok());
        assert!(a.verify("spiffe://aumos.dev/agent/y").is_err());
    }

    #[test]
    fn rate_limiter_allows_under_limit() {
        let r = RateLimiter::new(5);
        for _ in 0..5 {
            r.check("id").expect("under limit");
        }
    }

    #[test]
    fn rate_limiter_blocks_over_limit() {
        let r = RateLimiter::new(2);
        r.check("id").expect("1");
        r.check("id").expect("2");
        assert!(matches!(r.check("id"), Err(ProxyError::RateLimitExceeded { .. })));
    }

    #[test]
    fn prompt_filter_rejects_injection() {
        let f = PromptFilter::new();
        assert!(matches!(
            f.check("SYSTEM OVERRIDE now"),
            Err(ProxyError::PromptRejected(_))
        ));
    }

    #[test]
    fn prompt_filter_accepts_clean() {
        let f = PromptFilter::new();
        assert!(f.check("what is the weather today").is_ok());
    }

    #[test]
    fn prompt_filter_rejects_aws_key() {
        let f = PromptFilter::new();
        assert!(f.check("use AKIAIOSFODNN7EXAMPLE").is_err());
    }

    #[test]
    fn cache_returns_stored_response() {
        let c = Cache::new();
        c.put("m", "hi", "hello");
        assert_eq!(c.get("m", "hi"), Some("hello".to_string()));
        assert_eq!(c.get("m", "other"), None);
    }

    #[test]
    fn proxy_full_chain_caches_second_call() {
        let proxy = ProxyBuilder::new().rate_limit(10).build();
        let req = ProxyRequest {
            identity: "id".into(),
            model: "m".into(),
            prompt: "hi".into(),
        };
        let calls = std::cell::Cell::new(0u32);
        let mut backend = |_: &ProxyRequest| {
            calls.set(calls.get() + 1);
            "hello".to_string()
        };
        let r1 = proxy.handle(&req, &mut backend).expect("first");
        assert!(!r1.cached);
        let r2 = proxy.handle(&req, &mut backend).expect("second");
        assert!(r2.cached);
        assert_eq!(r2.text, "hello");
        assert_eq!(calls.get(), 1); // backend called exactly once
    }

    #[test]
    fn proxy_rejects_unauthorized() {
        let proxy = ProxyBuilder::new()
            .auth(Box::new(AllowListAuth::new(["allowed".to_string()])))
            .build();
        let req = ProxyRequest {
            identity: "denied".into(),
            model: "m".into(),
            prompt: "hi".into(),
        };
        assert!(matches!(
            proxy.handle(&req, |_| "x".to_string()),
            Err(ProxyError::Unauthorized(_))
        ));
    }

    #[test]
    fn proxy_rejects_injection_prompt() {
        let proxy = ProxyBuilder::new().build();
        let req = ProxyRequest {
            identity: "id".into(),
            model: "m".into(),
            prompt: "system override".into(),
        };
        assert!(matches!(
            proxy.handle(&req, |_| "x".to_string()),
            Err(ProxyError::PromptRejected(_))
        ));
    }
}
