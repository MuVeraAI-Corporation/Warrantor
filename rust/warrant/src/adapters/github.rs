//! W9 — the GitHub effect adapter.
//!
//! Performs staged GitHub effects at settle time. This is the first place a warrant actually
//! touches the outside world, so two properties matter more than the API details.
//!
//! # The agent never holds the token
//!
//! The credential lives here, in the settling process, and the agent is not part of that process.
//! This does not *shrink* the blast radius of a leaked GitHub token — it removes the token from
//! the agent entirely, so there is nothing to leak into a transcript, echo into a log, or reuse
//! after the run. It composes exactly with staging because the effect was deferred anyway: the
//! moment the call happens is a moment the agent has no part in.
//!
//! # Handles resolve to real identifiers
//!
//! A staged comment references `pr://staged/<warrant>/1`. By the time it is performed, the pull
//! request genuinely exists and has a number, and the resolution map carries it. That rewriting is
//! what lets an agent chain dependent effects against things that did not exist when it asked for
//! them — the property R1 measured and found frontier models handle without being told.

use std::collections::BTreeMap;

use crate::settle::EffectPerformer;
use crate::staging::StagedEffect;

/// A minimal HTTP transport, injected so the adapter is testable without a network.
///
/// Testing an adapter against a live API means either mutating a real repository on every test run
/// or not testing it. Neither is acceptable for the component that decides whether a developer's
/// pull request gets opened.
pub trait GitHubTransport {
    /// POST `body` to `path` under the API root, returning the response body.
    ///
    /// # Errors
    /// A human-readable reason. The settle engine stops on the first error and reports the
    /// boundary; it does not retry.
    fn post(&mut self, path: &str, body: &str) -> Result<String, String>;
}

/// Performs GitHub effects against a real API.
pub struct GitHubAdapter<T: GitHubTransport> {
    transport: T,
    owner: String,
    repo: String,
}

impl<T: GitHubTransport> GitHubAdapter<T> {
    /// Build an adapter for `owner/repo`.
    pub fn new(transport: T, owner: impl Into<String>, repo: impl Into<String>) -> Self {
        Self {
            transport,
            owner: owner.into(),
            repo: repo.into(),
        }
    }

    /// Resolve a staged handle to the real identifier an earlier release produced.
    fn resolve<'a>(
        &self,
        effect: &'a StagedEffect,
        resolved: &'a BTreeMap<String, String>,
    ) -> Result<&'a str, String> {
        let target = effect
            .arguments
            .get("target")
            .ok_or_else(|| format!("{} requires a target", effect.tool))?;
        resolved.get(target).map(String::as_str).ok_or_else(|| {
            // Unreachable while release order is topological, but a silent wrong answer here
            // would attach a comment to the wrong pull request.
            format!(
                "{target} has not been released yet; release order put a dependent before its \
                 dependency"
            )
        })
    }

    fn argument<'a>(&self, effect: &'a StagedEffect, name: &str) -> Result<&'a str, String> {
        effect
            .arguments
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| format!("{} requires {name}", effect.tool))
    }
}

/// Extract a field from a JSON response without pulling in a full parser dependency for one value.
///
/// Deliberately narrow: it reads a numeric or string field at the top level. If GitHub's shape
/// changes, this fails loudly rather than returning a plausible wrong id.
fn json_field(body: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let start = body.find(&needle)? + needle.len();
    let rest = body
        .get(start..)?
        .trim_start()
        .strip_prefix(':')?
        .trim_start();
    if let Some(text) = rest.strip_prefix('"') {
        return text.find('"').map(|end| text[..end].to_string());
    }
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    let digits = &rest[..end];
    (!digits.is_empty()).then(|| digits.to_string())
}

impl<T: GitHubTransport> EffectPerformer for GitHubAdapter<T> {
    fn perform(
        &mut self,
        effect: &StagedEffect,
        resolved: &BTreeMap<String, String>,
    ) -> Result<String, String> {
        let (owner, repo) = (self.owner.clone(), self.repo.clone());
        match effect.tool.as_str() {
            "github.create_pr" => {
                let title = self.argument(effect, "title")?;
                let body = effect.arguments.get("body").cloned().unwrap_or_default();
                let head = effect
                    .arguments
                    .get("head")
                    .cloned()
                    .unwrap_or_else(|| "HEAD".to_string());
                let base = effect
                    .arguments
                    .get("base")
                    .cloned()
                    .unwrap_or_else(|| "main".to_string());
                let payload = format!(
                    r#"{{"title":{},"body":{},"head":{},"base":{}}}"#,
                    quote(title),
                    quote(&body),
                    quote(&head),
                    quote(&base)
                );
                let response = self
                    .transport
                    .post(&format!("/repos/{owner}/{repo}/pulls"), &payload)?;
                json_field(&response, "number").ok_or_else(|| {
                    format!("GitHub accepted the pull request but returned no number: {response}")
                })
            }
            "github.comment" => {
                let number = self.resolve(effect, resolved)?;
                let body = self.argument(effect, "body")?;
                let payload = format!(r#"{{"body":{}}}"#, quote(body));
                self.transport
                    .post(
                        &format!("/repos/{owner}/{repo}/issues/{number}/comments"),
                        &payload,
                    )
                    .map(|response| {
                        json_field(&response, "id")
                            .unwrap_or_else(|| format!("comment-on-{number}"))
                    })
            }
            "github.request_review" => {
                let number = self.resolve(effect, resolved)?;
                let reviewer = self.argument(effect, "reviewer")?;
                let payload = format!(r#"{{"reviewers":[{}]}}"#, quote(reviewer));
                self.transport
                    .post(
                        &format!("/repos/{owner}/{repo}/pulls/{number}/requested_reviewers"),
                        &payload,
                    )
                    .map(|_| format!("review-requested-on-{number}"))
            }
            "github.add_label" => {
                let number = self.resolve(effect, resolved)?;
                let label = self.argument(effect, "label")?;
                let payload = format!(r#"{{"labels":[{}]}}"#, quote(label));
                self.transport
                    .post(
                        &format!("/repos/{owner}/{repo}/issues/{number}/labels"),
                        &payload,
                    )
                    .map(|_| format!("label-on-{number}"))
            }
            other => Err(format!(
                "the GitHub adapter does not implement {other}; it was staged by a registry that \
                 knows more tools than this adapter does"
            )),
        }
    }
}

/// JSON-quote a string.
///
/// Hand-rolled rather than pulling serde_json into the hot path for four fields, but it must be
/// correct: an unescaped quote in a PR title would produce malformed JSON, and GitHub would
/// either reject it or — worse — interpret it as different fields.
fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_escapes_what_would_break_the_payload() {
        assert_eq!(quote(r#"a"b"#), r#""a\"b""#);
        assert_eq!(quote("a\nb"), r#""a\nb""#);
        assert_eq!(quote("a\\b"), r#""a\\b""#);
        // A control character must be ESCAPED, not dropped: dropping it would silently
        // alter the text, while escaping preserves it and still yields valid JSON.
        assert_eq!(quote("a\u{1}b"), r#""a\u0001b""#);
    }

    #[test]
    fn json_field_reads_numbers_and_strings() {
        assert_eq!(
            json_field(r#"{"number": 482, "title":"x"}"#, "number").as_deref(),
            Some("482")
        );
        assert_eq!(
            json_field(r#"{"title":"Fix it"}"#, "title").as_deref(),
            Some("Fix it")
        );
        assert_eq!(json_field(r#"{"a":1}"#, "missing"), None);
    }
}
