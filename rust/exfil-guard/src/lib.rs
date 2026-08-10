//! # warrantor-exfil-guard
//!
//! eBPF exfiltration prevention core. Three detectors run on every outbound
//! buffer (the eBPF upcall hands the Rust core a `(buffer, flow)` pair):
//!
//!   - `PatternMatcher` — regex-free literal patterns matching AWS keys
//!     (`AKIA...`), GitHub PATs (`ghp_...`), OpenAI keys (`sk-...`), US SSNs
//!     (`NNN-NN-NNNN`), and credit cards (13-19 digit runs that pass the
//!     Luhn checksum).
//!   - `EntropyDetector` — Shannon-entropy detector: any contiguous run of
//!     at least `min_length` printable bytes whose byte-level Shannon
//!     entropy exceeds `min_entropy` is flagged (the canonical "this looks
//!     like a secret blob" signal). Defaults: 4.5 bits/byte over at least
//!     32 bytes.
//!   - `VolumeMonitor` — per-flow rate limiter: max `max_per_transfer` bytes
//!     per single buffer and max `max_per_hour` bytes per rolling hour.
//!
//! Plus a domain blocklist (re-uses the canonical R7 default list).
//!
//! The core is `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`; the
//! eBPF plumbing itself lives in task 03.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use thiserror::Error;

/// The default per-transfer byte cap (1 MiB). Larger single transfers are
/// almost always anomalous for an inference-serving agent.
pub const DEFAULT_MAX_PER_TRANSFER: usize = 1024 * 1024;

/// The default rolling-hour byte cap (10 MiB).
pub const DEFAULT_MAX_PER_HOUR: usize = 10 * 1024 * 1024;

/// The default entropy threshold (bits/byte). Values above 4.5 over >= 32
/// bytes are typical of encrypted/encoded secrets and atypical of natural
/// language or structured config.
pub const DEFAULT_MIN_ENTROPY: f64 = 4.5;

/// The default minimum length for an entropy window.
pub const DEFAULT_MIN_LENGTH: usize = 32;

/// The default domain blocklist (mirrors R7).
pub const DEFAULT_BLOCKED_DOMAINS: &[&str] =
    &["pastebin.com", "requestbin.com", "webhook.site", "ngrok.io"];

/// The kind of detector that flagged a sample.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DetectorKind {
    /// The literal-pattern matcher (AWS keys, GitHub PATs, ...).
    PatternMatcher,
    /// The Shannon-entropy detector.
    EntropyDetector,
    /// The per-flow volume monitor.
    VolumeMonitor,
    /// The domain blocklist.
    DomainBlocklist,
}

/// The structured finding returned by any detector.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    /// Which detector produced the finding.
    pub kind: DetectorKind,
    /// The rule id within the detector (e.g. ``"AWS_ACCESS_KEY"``).
    pub rule_id: String,
    /// A human-readable message.
    pub message: String,
    /// The byte offset in the scanned buffer where the match began.
    pub offset: usize,
    /// The length of the matched span.
    pub length: usize,
}

/// The structured verdict for a buffer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Verdict {
    /// True iff no detector produced a finding.
    pub allowed: bool,
    /// Every finding produced by the detectors.
    pub findings: Vec<Finding>,
}

// ===========================================================================
// PatternMatcher
// ===========================================================================

/// Regex-free literal pattern matcher for known secret formats.
#[derive(Debug, Clone)]
pub struct PatternMatcher {
    /// The minimum digit-run length considered as a potential credit card.
    pub min_card_digits: usize,
}

/// Default minimum digit run for credit-card consideration.
pub const DEFAULT_MIN_CARD_DIGITS: usize = 13;

impl Default for PatternMatcher {
    fn default() -> Self {
        Self {
            min_card_digits: DEFAULT_MIN_CARD_DIGITS,
        }
    }
}

impl PatternMatcher {
    /// Construct a new matcher with the given minimum digit run for cards.
    #[must_use]
    pub fn new(min_card_digits: usize) -> Self {
        Self { min_card_digits }
    }

    /// Scan ``buf`` and return every pattern match.
    #[must_use]
    pub fn scan(&self, buf: &[u8]) -> Vec<Finding> {
        let text = String::from_utf8_lossy(buf);
        let mut out = Vec::new();
        out.extend(self.scan_aws_keys(&text));
        out.extend(self.scan_github_pats(&text));
        out.extend(self.scan_openai_keys(&text));
        out.extend(self.scan_ssns(&text));
        out.extend(self.scan_credit_cards(&text));
        out
    }

    fn scan_aws_keys(&self, text: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        let bytes = text.as_bytes();
        let mut i = 0;
        while i + 20 <= bytes.len() {
            if &bytes[i..i + 4] == b"AKIA"
                && bytes[i + 4..i + 20]
                    .iter()
                    .all(u8::is_ascii_uppercase_or_digit)
            {
                out.push(Finding {
                    kind: DetectorKind::PatternMatcher,
                    rule_id: "AWS_ACCESS_KEY".to_string(),
                    message: "AWS access key id literal".to_string(),
                    offset: i,
                    length: 20,
                });
                i += 20;
            } else {
                i += 1;
            }
        }
        out
    }

    fn scan_github_pats(&self, text: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        let bytes = text.as_bytes();
        let prefix = b"ghp_";
        let mut i = 0;
        while let Some(pos) = find_subslice(&bytes[i..], prefix) {
            let abs = i + pos;
            // gather >=36 alphanumeric chars after the prefix
            let mut end = abs + prefix.len();
            while end < bytes.len()
                && bytes[end].is_ascii_alphanumeric()
                && end - (abs + prefix.len()) < 40
            {
                end += 1;
            }
            let token_len = end - (abs + prefix.len());
            if token_len >= 36 {
                out.push(Finding {
                    kind: DetectorKind::PatternMatcher,
                    rule_id: "GITHUB_PAT".to_string(),
                    message: "GitHub personal access token literal".to_string(),
                    offset: abs,
                    length: end - abs,
                });
            }
            i = end;
        }
        out
    }

    fn scan_openai_keys(&self, text: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        let bytes = text.as_bytes();
        let prefix = b"sk-";
        let mut i = 0;
        while let Some(pos) = find_subslice(&bytes[i..], prefix) {
            let abs = i + pos;
            let mut end = abs + prefix.len();
            while end < bytes.len()
                && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_' || bytes[end] == b'-')
                && end - (abs + prefix.len()) < 80
            {
                end += 1;
            }
            let token_len = end - (abs + prefix.len());
            if token_len >= 20 {
                out.push(Finding {
                    kind: DetectorKind::PatternMatcher,
                    rule_id: "OPENAI_KEY".to_string(),
                    message: "OpenAI-style secret key literal".to_string(),
                    offset: abs,
                    length: end - abs,
                });
            }
            i = end;
        }
        out
    }

    fn scan_ssns(&self, text: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        let bytes = text.as_bytes();
        let mut i = 0;
        while i + 11 <= bytes.len() {
            if is_digit(bytes[i])
                && is_digit(bytes[i + 1])
                && is_digit(bytes[i + 2])
                && bytes[i + 3] == b'-'
                && is_digit(bytes[i + 4])
                && is_digit(bytes[i + 5])
                && bytes[i + 6] == b'-'
                && is_digit(bytes[i + 7])
                && is_digit(bytes[i + 8])
                && is_digit(bytes[i + 9])
                && is_digit(bytes[i + 10])
            {
                out.push(Finding {
                    kind: DetectorKind::PatternMatcher,
                    rule_id: "US_SSN".to_string(),
                    message: "US Social Security Number literal".to_string(),
                    offset: i,
                    length: 11,
                });
                i += 11;
            } else {
                i += 1;
            }
        }
        out
    }

    fn scan_credit_cards(&self, text: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if !is_digit(bytes[i]) {
                i += 1;
                continue;
            }
            // gather contiguous digits (ignoring spaces/dashes between groups)
            let mut digits: Vec<u8> = Vec::new();
            let mut j = i;
            let mut last_consumed = i;
            while j < bytes.len() && (is_digit(bytes[j]) || bytes[j] == b' ' || bytes[j] == b'-') {
                if is_digit(bytes[j]) {
                    digits.push(bytes[j] - b'0');
                    last_consumed = j;
                }
                j += 1;
                if digits.len() >= 19 {
                    break;
                }
            }
            if digits.len() >= self.min_card_digits && digits.len() <= 19 && luhn_passes(&digits) {
                out.push(Finding {
                    kind: DetectorKind::PatternMatcher,
                    rule_id: "CREDIT_CARD".to_string(),
                    message: "Credit-card number passing Luhn".to_string(),
                    offset: i,
                    length: last_consumed - i + 1,
                });
                i = last_consumed + 1;
            } else {
                i += 1;
            }
        }
        out
    }
}

// ===========================================================================
// EntropyDetector
// ===========================================================================

/// Shannon-entropy detector for high-entropy secret blobs.
#[derive(Debug, Clone)]
pub struct EntropyDetector {
    /// The minimum entropy (bits/byte) to flag.
    pub min_entropy: f64,
    /// The minimum window length to evaluate.
    pub min_length: usize,
}

impl Default for EntropyDetector {
    fn default() -> Self {
        Self {
            min_entropy: DEFAULT_MIN_ENTROPY,
            min_length: DEFAULT_MIN_LENGTH,
        }
    }
}

impl EntropyDetector {
    /// Construct a detector with custom thresholds.
    #[must_use]
    pub fn new(min_entropy: f64, min_length: usize) -> Self {
        Self {
            min_entropy,
            min_length,
        }
    }

    /// Scan ``buf`` for any window that exceeds the thresholds.
    ///
    /// Uses a sliding window of size ``min_length`` stepped every byte. Adjacent
    /// matching windows are coalesced into one maximal finding so a single
    /// secret is reported once without creating blind spots at window boundaries.
    #[must_use]
    pub fn scan(&self, buf: &[u8]) -> Vec<Finding> {
        if buf.len() < self.min_length {
            return Vec::new();
        }
        let mut out: Vec<Finding> = Vec::new();
        let mut i = 0;
        while i + self.min_length <= buf.len() {
            let window = &buf[i..i + self.min_length];
            // only evaluate printable windows (entropy of binary is noisy)
            if window.iter().all(is_printable) {
                let h = shannon_entropy(window);
                if h >= self.min_entropy {
                    let window_end = i + self.min_length;
                    if let Some(previous) = out.last_mut().filter(|finding| {
                        finding.kind == DetectorKind::EntropyDetector
                            && i <= finding.offset + finding.length
                    }) {
                        previous.length = window_end.saturating_sub(previous.offset);
                    } else {
                        out.push(Finding {
                            kind: DetectorKind::EntropyDetector,
                            rule_id: "HIGH_ENTROPY_BLOB".to_string(),
                            message: format!(
                                "high-entropy region (window h={h:.2} >= {:.2})",
                                self.min_entropy
                            ),
                            offset: i,
                            length: self.min_length,
                        });
                    }
                    i += 1;
                    continue;
                }
            }
            i += 1;
        }
        out
    }
}

/// Compute the Shannon entropy (bits/byte) of ``buf``.
#[must_use]
pub fn shannon_entropy(buf: &[u8]) -> f64 {
    if buf.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in buf {
        counts[b as usize] += 1;
    }
    let total = buf.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / total;
        h -= p * p.log2();
    }
    h
}

// ===========================================================================
// VolumeMonitor
// ===========================================================================

/// A single observed flow identified by a 5-tuple-ish key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// The destination (IP or domain) — used as the per-flow bucket.
    pub destination: String,
    /// The destination port.
    pub port: u16,
}

/// Per-flow rate limiter.
#[derive(Debug, Clone)]
pub struct VolumeMonitor {
    /// Maximum bytes per single transfer.
    pub max_per_transfer: usize,
    /// Maximum bytes per rolling hour.
    pub max_per_hour: usize,
    /// The window length in seconds (default 3600).
    pub window_seconds: u64,
    flows: HashMap<FlowKey, VecDeque<(u64, usize)>>,
    flow_totals: HashMap<FlowKey, usize>,
}

/// Errors returned by the monitor.
#[derive(Debug, Error)]
pub enum VolumeError {
    /// Tried to record a sample at a timestamp earlier than the previous one.
    #[error("non-monotonic timestamp: prev={prev} cur={cur}")]
    NonMonotonic {
        /// The previous timestamp.
        prev: u64,
        /// The current timestamp.
        cur: u64,
    },
}

/// The structured volume decision for one record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VolumeDecision {
    /// True iff the transfer is allowed under both caps.
    pub allowed: bool,
    /// The findings explaining the denial (empty if allowed).
    pub findings: Vec<Finding>,
    /// The flow's running total within the rolling window (bytes).
    pub window_total: usize,
}

impl Default for VolumeMonitor {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_PER_TRANSFER, DEFAULT_MAX_PER_HOUR)
    }
}

impl VolumeMonitor {
    /// Construct a monitor with custom caps.
    #[must_use]
    pub fn new(max_per_transfer: usize, max_per_hour: usize) -> Self {
        Self {
            max_per_transfer,
            max_per_hour,
            window_seconds: 3600,
            flows: HashMap::new(),
            flow_totals: HashMap::new(),
        }
    }

    /// Record ``len`` bytes against ``flow`` at epoch-seconds ``now``.
    ///
    /// Returns a decision that says whether the transfer is allowed under
    /// both caps. The monitor records the sample even when denying so the
    /// running total reflects attempted exfil volume.
    pub fn record(
        &mut self,
        flow: &FlowKey,
        len: usize,
        now: u64,
    ) -> Result<VolumeDecision, VolumeError> {
        let dq = self.flows.entry(flow.clone()).or_default();
        if let Some(&(t, _)) = dq.back() {
            if now < t {
                return Err(VolumeError::NonMonotonic { prev: t, cur: now });
            }
        }
        // purge samples outside the window
        let cutoff = now.saturating_sub(self.window_seconds);
        while let Some(&(t, _)) = dq.front() {
            if t < cutoff {
                dq.pop_front();
            } else {
                break;
            }
        }
        dq.push_back((now, len));
        // recompute window total
        let window_total: usize = dq.iter().map(|(_, l)| *l).sum();
        self.flow_totals.insert(flow.clone(), window_total);

        let mut findings = Vec::new();
        if len > self.max_per_transfer {
            findings.push(Finding {
                kind: DetectorKind::VolumeMonitor,
                rule_id: "PER_TRANSFER_EXCEEDED".to_string(),
                message: format!(
                    "transfer of {len} bytes exceeds per-transfer cap of {}",
                    self.max_per_transfer
                ),
                offset: 0,
                length: len,
            });
        }
        if window_total > self.max_per_hour {
            findings.push(Finding {
                kind: DetectorKind::VolumeMonitor,
                rule_id: "HOURLY_CAP_EXCEEDED".to_string(),
                message: format!(
                    "rolling-hour total of {window_total} bytes exceeds hourly cap of {}",
                    self.max_per_hour
                ),
                offset: 0,
                length: window_total,
            });
        }
        Ok(VolumeDecision {
            allowed: findings.is_empty(),
            findings,
            window_total,
        })
    }

    /// Return the current rolling-window byte total for ``flow``.
    #[must_use]
    pub fn window_total(&self, flow: &FlowKey) -> usize {
        self.flow_totals.get(flow).copied().unwrap_or(0)
    }
}

// ===========================================================================
// DomainBlocklist
// ===========================================================================

/// A simple domain blocklist with suffix matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainBlocklist {
    /// The blocked domains (matched as exact or suffix).
    pub blocked: Vec<String>,
}

impl Default for DomainBlocklist {
    fn default() -> Self {
        Self {
            blocked: DEFAULT_BLOCKED_DOMAINS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        }
    }
}

impl DomainBlocklist {
    /// Returns the findings produced by checking ``domain`` against the list.
    #[must_use]
    pub fn check(&self, domain: &str) -> Vec<Finding> {
        let needle = domain.to_ascii_lowercase();
        if self
            .blocked
            .iter()
            .any(|b| needle == *b || needle.ends_with(&format!(".{b}")))
        {
            vec![Finding {
                kind: DetectorKind::DomainBlocklist,
                rule_id: "BLOCKED_DOMAIN".to_string(),
                message: format!("destination {domain} is on the egress blocklist"),
                offset: 0,
                length: domain.len(),
            }]
        } else {
            Vec::new()
        }
    }
}

// ===========================================================================
// Top-level driver
// ===========================================================================

/// The top-level coordinator that runs every detector on a buffer.
#[derive(Debug, Clone, Default)]
pub struct ExfilGuard {
    /// The pattern matcher.
    pub patterns: PatternMatcher,
    /// The entropy detector.
    pub entropy: EntropyDetector,
    /// The volume monitor.
    pub volume: VolumeMonitor,
    /// The domain blocklist.
    pub blocklist: DomainBlocklist,
}

/// The payload handed to [`ExfilGuard::evaluate`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateRequest<'a> {
    /// The buffer to scan.
    pub buffer: &'a [u8],
    /// The destination flow (None if the destination is unknown).
    pub flow: Option<FlowKey>,
    /// The epoch-seconds timestamp of the transfer.
    pub now: u64,
}

impl ExfilGuard {
    /// Evaluate a single transfer.
    ///
    /// Runs the pattern matcher + entropy detector over ``buffer`` and the
    /// volume monitor + blocklist over the flow metadata (if supplied).
    /// Returns a single [`Verdict`] that the eBPF layer upholds.
    pub fn evaluate(&mut self, req: EvaluateRequest<'_>) -> Verdict {
        let mut findings = Vec::new();
        findings.extend(self.patterns.scan(req.buffer));
        findings.extend(self.entropy.scan(req.buffer));
        if let Some(flow) = req.flow.clone() {
            findings.extend(self.blocklist.check(&flow.destination));
            // volume monitor is best-effort: a non-monotonic timestamp shouldn't
            // accidentally allow an otherwise-flagged transfer through.
            if let Ok(d) = self.volume.record(&flow, req.buffer.len(), req.now) {
                findings.extend(d.findings);
            }
        }
        Verdict {
            allowed: findings.is_empty(),
            findings,
        }
    }
}

// ===========================================================================
// Internal helpers
// ===========================================================================

#[allow(clippy::trait_duplication_in_bounds)]
trait AsciiAlnumExt {
    fn is_ascii_uppercase_or_digit(&self) -> bool;
}

impl AsciiAlnumExt for u8 {
    fn is_ascii_uppercase_or_digit(&self) -> bool {
        self.is_ascii_uppercase() || self.is_ascii_digit()
    }
}

fn is_digit(b: u8) -> bool {
    b.is_ascii_digit()
}

fn is_printable(b: &u8) -> bool {
    // printable ASCII or common whitespace; rejects NUL/control bytes
    (0x20..=0x7E).contains(b) || *b == b'\n' || *b == b'\r' || *b == b'\t'
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn luhn_passes(digits: &[u8]) -> bool {
    // digits are values 0..=9 (already stripped of '0')
    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut v = d as u32;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    sum.is_multiple_of(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- PatternMatcher ----------
    #[test]
    fn pattern_finds_aws_key() {
        let m = PatternMatcher::default();
        let f = m.scan(b"x AKIAIOSFODNN7EXAMPLE y");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "AWS_ACCESS_KEY");
        assert_eq!(f[0].length, 20);
    }

    #[test]
    fn pattern_finds_github_pat() {
        let m = PatternMatcher::default();
        let pat = "ghp_".to_string() + &"a".repeat(36);
        let f = m.scan(pat.as_bytes());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "GITHUB_PAT");
    }

    #[test]
    fn pattern_finds_openai_key() {
        let m = PatternMatcher::default();
        let key = "sk-".to_string() + &"a".repeat(24);
        let f = m.scan(key.as_bytes());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "OPENAI_KEY");
    }

    #[test]
    fn pattern_finds_ssn() {
        let m = PatternMatcher::default();
        let f = m.scan(b"contact: 123-45-6789");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "US_SSN");
        assert_eq!(f[0].length, 11);
    }

    #[test]
    fn pattern_finds_credit_card_with_luhn() {
        // 4242 4242 4242 4242 is the canonical Stripe test card (passes Luhn).
        let m = PatternMatcher::default();
        let f = m.scan(b"4242 4242 4242 4242");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "CREDIT_CARD");
    }

    #[test]
    fn pattern_skips_non_luhn_digit_runs() {
        let m = PatternMatcher::default();
        let f = m.scan(b"1111 1111 1111 1111"); // 16 ones fails Luhn
        assert!(f.iter().all(|x| x.rule_id != "CREDIT_CARD"));
    }

    #[test]
    fn pattern_clean_buffer_produces_no_findings() {
        let m = PatternMatcher::default();
        assert!(m.scan(b"hello world").is_empty());
    }

    // ---------- EntropyDetector ----------
    #[test]
    fn entropy_flags_high_entropy_blob() {
        let det = EntropyDetector::default();
        // 64 random-looking printable bytes
        let blob = b"qxP9zR1vY8mK2bT7nL4sH6dF3jC5gW0aE9rU2iN7oM1pB8tX6yV4cQ3";
        let f = det.scan(blob);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "HIGH_ENTROPY_BLOB");
        assert_eq!(f[0].offset, 0);
        assert_eq!(f[0].length, blob.len());
    }

    #[test]
    fn entropy_keeps_disjoint_regions_separate() {
        let det = EntropyDetector::default();
        let blob = b"qxP9zR1vY8mK2bT7nL4sH6dF3jC5gW0aE9rU2iN7oM1pB8tX6yV4cQ3";
        let mut payload = blob.to_vec();
        payload.extend([0_u8; DEFAULT_MIN_LENGTH]);
        payload.extend(blob);

        let findings = det.scan(&payload);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].offset, 0);
        assert_eq!(findings[0].length, blob.len());
        assert_eq!(findings[1].offset, blob.len() + DEFAULT_MIN_LENGTH);
        assert_eq!(findings[1].length, blob.len());
    }

    #[test]
    fn entropy_clean_for_natural_language() {
        let det = EntropyDetector::default();
        let text = b"the quick brown fox jumps over the lazy dog the quick brown";
        let f = det.scan(text);
        assert!(f.is_empty(), "natural-language text should be low-entropy");
    }

    #[test]
    fn entropy_respects_min_length() {
        let det = EntropyDetector::new(4.5, 64);
        // 32 high-entropy bytes shouldn't trigger when min_length == 64
        let blob = b"qxP9zR1vY8mK2bT7nL4sH6dF3jC5gW0a";
        assert_eq!(blob.len(), 32);
        assert!(det.scan(blob).is_empty());
    }

    #[test]
    fn shannon_entropy_low_for_repeated_byte() {
        let buf = vec![b'a'; 64];
        assert!(shannon_entropy(&buf) < 0.1);
    }

    #[test]
    fn shannon_entropy_max_for_uniform_random() {
        let mut buf = Vec::with_capacity(256);
        for i in 0..=255u8 {
            buf.push(i);
        }
        // 256 distinct bytes -> entropy ~ 8.0 bits/byte
        assert!((shannon_entropy(&buf) - 8.0).abs() < 0.01);
    }

    // ---------- VolumeMonitor ----------
    #[test]
    fn volume_allows_under_both_caps() {
        let mut m = VolumeMonitor::new(1024, 4096);
        let flow = FlowKey {
            destination: "example.com".to_string(),
            port: 443,
        };
        let d = m.record(&flow, 100, 0).unwrap();
        assert!(d.allowed);
        assert_eq!(d.window_total, 100);
    }

    #[test]
    fn volume_flags_single_large_transfer() {
        let mut m = VolumeMonitor::new(100, 1000);
        let flow = FlowKey {
            destination: "x".to_string(),
            port: 1,
        };
        let d = m.record(&flow, 200, 0).unwrap();
        assert!(!d.allowed);
        assert_eq!(d.findings[0].rule_id, "PER_TRANSFER_EXCEEDED");
    }

    #[test]
    fn volume_flags_rolling_hour_cap() {
        let mut m = VolumeMonitor::new(100, 250);
        let flow = FlowKey {
            destination: "x".to_string(),
            port: 1,
        };
        assert!(m.record(&flow, 100, 0).unwrap().allowed);
        assert!(m.record(&flow, 100, 100).unwrap().allowed);
        let d = m.record(&flow, 100, 200).unwrap();
        assert!(!d.allowed);
        assert_eq!(d.findings[0].rule_id, "HOURLY_CAP_EXCEEDED");
    }

    #[test]
    fn volume_window_purges_old_samples() {
        let mut m = VolumeMonitor::new(10_000, 250);
        let flow = FlowKey {
            destination: "x".to_string(),
            port: 1,
        };
        // first sample outside the 3600s window
        m.record(&flow, 200, 0).unwrap();
        // 2h later -> first sample purged
        let d = m.record(&flow, 50, 7200).unwrap();
        assert!(d.allowed);
        assert_eq!(d.window_total, 50);
    }

    #[test]
    fn volume_rejects_non_monotonic_clock() {
        let mut m = VolumeMonitor::default();
        let flow = FlowKey {
            destination: "x".to_string(),
            port: 1,
        };
        m.record(&flow, 1, 100).unwrap();
        assert!(matches!(
            m.record(&flow, 1, 50),
            Err(VolumeError::NonMonotonic { .. })
        ));
    }

    // ---------- DomainBlocklist ----------
    #[test]
    fn blocklist_matches_default_entries_and_suffix() {
        let b = DomainBlocklist::default();
        assert_eq!(b.check("pastebin.com").len(), 1);
        assert_eq!(b.check("evil.ngrok.io").len(), 1);
        assert!(b.check("example.com").is_empty());
    }

    // ---------- ExfilGuard driver ----------
    #[test]
    fn guard_combines_all_detectors() {
        let mut g = ExfilGuard::default();
        let buf = b"token=AKIAIOSFODNN7EXAMPLE and a credit card 4242 4242 4242 4242";
        let flow = FlowKey {
            destination: "pastebin.com".to_string(),
            port: 443,
        };
        let v = g.evaluate(EvaluateRequest {
            buffer: buf,
            flow: Some(flow),
            now: 0,
        });
        assert!(!v.allowed);
        let rules: Vec<_> = v.findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains(&"AWS_ACCESS_KEY"));
        assert!(rules.contains(&"CREDIT_CARD"));
        assert!(rules.contains(&"BLOCKED_DOMAIN"));
    }

    #[test]
    fn guard_allows_clean_buffer_to_clean_destination() {
        let mut g = ExfilGuard::default();
        let buf = b"hello world";
        let flow = FlowKey {
            destination: "example.com".to_string(),
            port: 443,
        };
        let v = g.evaluate(EvaluateRequest {
            buffer: buf,
            flow: Some(flow),
            now: 0,
        });
        assert!(v.allowed);
        assert!(v.findings.is_empty());
    }
}
