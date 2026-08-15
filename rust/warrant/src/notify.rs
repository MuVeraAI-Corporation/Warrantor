//! Outbound notifications: telling a human who is not looking at the window that something
//! happened.
//!
//! The console, the desktop window and `warrantor status` all assume someone is watching. Approval
//! routing, off-site oversight and the plain case of "I left the run settling while I got coffee"
//! do not. This module is the smallest honest delivery mechanism: **webhooks, configured in a
//! local file, fired by the CLI actions they describe** — with the failure contract this
//! repository has already settled for automatic filing (PR #54): the action never blocks, the
//! failure prints in its own block stating both facts, and a durable queue retries at the next
//! notification.
//!
//! # What leaves the machine — decided, not accumulated
//!
//! A notification carries the **event, the warrant's id, goal, subject and state, a timestamp and
//! one small event-specific detail**. Nothing else, on purpose: staged-effect arguments can hold
//! source code and prompts, evidence bundles are files not facts, and a webhook is usually a
//! third-party service. Anything richer than "which warrant reached which state, when" becomes a
//! data-export decision, and those are made deliberately or not at all.
//!
//! # Authenticity
//!
//! A webhook configured with a `secret` receives every POST with
//! `X-Warrantor-Signature: sha256=<hex>`, an HMAC-SHA256 of the exact request body under that
//! secret, so the receiver can tell Warrantor's pings from anyone else's. A webhook without a
//! secret receives unsigned POSTs and should treat them as advisory — the signature header is the
//! difference between "something claiming to be Warrantor" and "Warrantor". The secret lives in
//! the config file beside the pairing record and the price table, never in source, never on a
//! command line.
//!
//! # The failure contract, copied from `autofile.rs` on purpose
//!
//! * **A failed notification never fails the action that caused it.** Settle, void and stop are
//!   local facts; an unreachable webhook cannot undo them, and a non-zero exit would tell a
//!   pipeline the settle failed when it did not.
//! * **Failures queue, loudly.** `notify/pending.jsonl` carries the exact payload that failed,
//!   and the **next notification drains the queue first** — the same retry-point discipline as
//!   the filing queue, for the same reason: it is the next moment this machine is already doing
//!   this kind of business, and a daemon would be a second process for no new capability.
//! * **An unconfigured machine sees byte-for-byte today's output.** No file, no notifications, no
//!   new words on the screen. A `notify.json` that exists and will not parse is the exception —
//!   an operator asked for notifications and stopped getting them, which is refused loudly
//!   rather than dropped.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use digest::{FixedOutput, KeyInit, Output, Update};
use hmac::SimpleHmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// The format line of the notification config.
pub const NOTIFY_CONFIG_FORMAT: &str = "warrantor.notify/1";
/// The format line of one notification payload.
pub const NOTIFICATION_FORMAT: &str = "warrantor.notification/1";
/// The format line of a pending-notification entry.
pub const PENDING_FORMAT: &str = "warrantor.pending-notification/1";

/// The event kinds v1 knows. Anything else in a config is refused rather than guessed at.
pub const EVENTS: [&str; 4] = ["settled", "voided", "stopped", "filing-queued"];

/// One webhook destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Webhook {
    /// Where to POST. `http://` or `https://`, no trailing slash; validated before anything is
    /// sent, so a typo is a config error rather than a delivery failure.
    pub url: String,
    /// HMAC-SHA256 secret for the signature header. Empty means unsigned, which the receiver
    /// should treat as advisory.
    #[serde(default)]
    pub secret: String,
    /// Which events this webhook wants. Empty means all of them.
    #[serde(default)]
    pub events: BTreeSet<String>,
}

/// The notification configuration, hand-written by the operator at `<root>/notify.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotifyConfig {
    /// Always [`NOTIFY_CONFIG_FORMAT`].
    pub format: String,
    /// Every destination. An empty list is the same as no config: nothing is sent.
    pub webhooks: Vec<Webhook>,
}

/// Where the notification config lives under a store root.
#[must_use]
pub fn config_path(root: &Path) -> PathBuf {
    root.join("notify.json")
}

/// Where failed notifications wait for the next one.
#[must_use]
pub fn pending_path(root: &Path) -> PathBuf {
    root.join("notify").join("pending.jsonl")
}

impl NotifyConfig {
    /// Read the config.
    ///
    /// An absent file is no configuration — the normal state of a machine that never asked for
    /// notifications, and every caller renders it as silence. A file that exists and will not
    /// parse, or names an event this build does not know, is an error: the operator asked for
    /// notifications and would silently stop getting them if this were read as "none".
    ///
    /// # Errors
    /// [`String`] naming the file and the reason.
    pub fn load(root: &Path) -> Result<Self, String> {
        let path = config_path(root);
        let Ok(bytes) = std::fs::read(&path) else {
            return Ok(Self {
                format: NOTIFY_CONFIG_FORMAT.to_string(),
                webhooks: Vec::new(),
            });
        };
        let config: NotifyConfig = serde_json::from_slice(&bytes)
            .map_err(|e| format!("{} cannot be read: {e}", path.display()))?;
        if config.format != NOTIFY_CONFIG_FORMAT {
            return Err(format!(
                "{} declares format {:?}, and this build reads only {NOTIFY_CONFIG_FORMAT}. \
                 Nothing is guessed at across formats.",
                path.display(),
                config.format
            ));
        }
        for (index, hook) in config.webhooks.iter().enumerate() {
            if let Err(e) = check_url(&hook.url) {
                return Err(format!(
                    "{} webhook {} has an unusable url: {e}",
                    path.display(),
                    index + 1
                ));
            }
            for event in &hook.events {
                if !EVENTS.contains(&event.as_str()) {
                    return Err(format!(
                        "{} webhook {} asks for event {:?}, and this build knows only {}.",
                        path.display(),
                        index + 1,
                        event,
                        EVENTS.join(", ")
                    ));
                }
            }
        }
        Ok(config)
    }

    /// Does this webhook want this event? An empty `events` set means all of them.
    #[must_use]
    pub fn wants(&self, hook: &Webhook, event: &str) -> bool {
        hook.events.is_empty() || hook.events.contains(event)
    }
}

/// Is this a URL a webhook can be posted to? http or https, with a host.
///
/// # Errors
/// [`String`] phrased about the URL given.
pub fn check_url(url: &str) -> Result<(), String> {
    let trimmed = url.trim();
    if trimmed != url || trimmed.ends_with('/') {
        return Err(format!(
            "{url:?} has leading/trailing whitespace or a trailing slash — the config wants the \
             bare url the receiver gave you."
        ));
    }
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return Err(format!(
            "{url:?} is not an http(s) URL. A webhook is POSTed over http or https and nothing \
             else."
        ));
    }
    Ok(())
}

/// One notification, as it is POSTed. Deliberately small; see the module doc for what is excluded
/// and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notification {
    /// Always [`NOTIFICATION_FORMAT`].
    pub format: String,
    /// `settled`, `voided`, `stopped` or `filing-queued`.
    pub event: String,
    /// The warrant this is about.
    pub warrant_id: String,
    /// The warrant's goal, so the receiver knows what this was without a lookup.
    pub goal: String,
    /// The warrant's subject.
    pub subject: String,
    /// The warrant's state after the action.
    pub state: String,
    /// When the event happened, epoch seconds.
    pub at: u64,
    /// One small event-specific fact (`{"complete": true}` for a settle). Never evidence bytes,
    /// never tool arguments.
    pub detail: serde_json::Value,
}

/// A failed delivery, queued verbatim: the payload that did not arrive, to the webhook that did
/// not receive it, in the words of whatever refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingNotification {
    /// Always [`PENDING_FORMAT`].
    pub format: String,
    /// The destination that did not receive it.
    pub url: String,
    /// The secret it was to be signed with, empty for unsigned. Carried in the queue so a retry
    /// signs exactly as the first attempt did; the queue file sits in the owner-only store root
    /// beside the config that held the same secret.
    pub secret: String,
    /// The payload, verbatim — a retry sends these bytes and no others.
    pub notification: Notification,
    /// When the delivery first failed, epoch seconds.
    pub queued_at: u64,
    /// How many delivery attempts have failed, this one included.
    pub attempts: u32,
    /// The most recent failure, in the sentence the caller reported.
    pub last_reason: String,
}

/// What delivering one notification did.
#[derive(Debug, PartialEq, Eq)]
pub enum Delivery {
    /// The webhook answered 2xx.
    Delivered,
    /// The delivery failed and was queued for the next notification. The sentence is the
    /// failure, carried unaltered.
    Queued {
        /// Why, in the words of whatever refused.
        reason: String,
    },
}

/// How a notification leaves this machine. A trait so the tests can deliver to a canned
/// transport, and so the CLI's ureq agent — timeouts, redirects refused — stays in the binary
/// with the other transports.
pub trait NotifyTransport {
    /// POST `body` to `url` with the given extra headers (`X-Warrantor-Signature`, if any).
    ///
    /// # Errors
    /// [`String`] on any non-2xx answer or transport failure, phrased for an operator.
    fn deliver(
        &mut self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(), String>;
}

/// The signature header a secret produces for a body, so every caller computes it the same way.
#[must_use]
pub fn signature_header(secret: &str, body: &[u8]) -> (String, String) {
    let mut mac = SimpleHmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(body);
    let mut tag = <Output<SimpleHmac<Sha256>> as Default>::default();
    mac.finalize_into(&mut tag);
    (
        "X-Warrantor-Signature".to_string(),
        format!("sha256={}", hex::encode(tag)),
    )
}

/// Queue a failed delivery verbatim.
///
/// # Errors
/// [`String`] when the queue cannot be written — the one state louder than the failure itself,
/// because nothing will retry it and nothing will say so.
pub fn queue_notification(
    root: &Path,
    hook: &Webhook,
    notification: &Notification,
    reason: &str,
    now: u64,
) -> Result<PendingNotification, String> {
    let entry = PendingNotification {
        format: PENDING_FORMAT.to_string(),
        url: hook.url.clone(),
        secret: hook.secret.clone(),
        notification: notification.clone(),
        queued_at: now,
        attempts: 1,
        last_reason: reason.to_string(),
    };
    let ledger = pending_path(root);
    if let Some(parent) = ledger.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let mut line = serde_json::to_vec(&entry).map_err(|e| format!("encode the entry: {e}"))?;
    line.push(b'\n');
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&ledger)
        .and_then(|mut file| {
            use std::io::Write;
            file.write_all(&line)
        })
        .map_err(|e| format!("append to {}: {e}", ledger.display()))?;
    Ok(entry)
}

/// Read the pending-notification ledger. Absent = empty (its normal state); present and
/// unparseable = an error naming the line, for the same reason as every other ledger here:
/// entries are promises to a human, and reading a broken file as "nothing pending" silently
/// abandons them.
///
/// # Errors
/// [`String`] naming the unreadable line.
pub fn load_pending(root: &Path) -> Result<Vec<PendingNotification>, String> {
    let ledger = pending_path(root);
    let Ok(bytes) = std::fs::read(&ledger) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (index, line) in String::from_utf8_lossy(&bytes).lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: PendingNotification = serde_json::from_str(line).map_err(|e| {
            format!(
                "{} line {} is not a pending notification this build can read: {e}. The queue is \
                 refused rather than read around — fix or remove the line, because entries in it \
                 are undelivered notifications someone asked for.",
                ledger.display(),
                index + 1
            )
        })?;
        if entry.format != PENDING_FORMAT {
            return Err(format!(
                "{} line {} declares format {:?}, and this build reads only {PENDING_FORMAT}.",
                ledger.display(),
                index + 1,
                entry.format
            ));
        }
        out.push(entry);
    }
    Ok(out)
}

/// What a drain did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DrainOutcome {
    /// Notifications that reached their webhook, as `(event, warrant_id, url)` triples.
    pub delivered: Vec<(String, String, String)>,
    /// Notifications still queued after this attempt, each with the newest reason and the
    /// attempt count.
    pub still_pending: Vec<String>,
}

/// Retry every pending notification, in the order they failed. The drain point is the next
/// notification — the caller invokes this before delivering anything new.
///
/// # Errors
/// [`String`] when the ledger cannot be read or the survivors cannot be written back. A caller
/// that delivers its new notification anyway is correct: a corrupt line from an old outage must
/// not stop fresh news, and the drain error prints at every notification until it is fixed.
pub fn drain_pending<T: NotifyTransport>(
    transport: &mut T,
    root: &Path,
) -> Result<DrainOutcome, String> {
    let entries = load_pending(root)?;
    let mut outcome = DrainOutcome::default();
    let mut survivors: Vec<PendingNotification> = Vec::new();
    for mut entry in entries {
        let body = serde_json::to_vec(&entry.notification)
            .map_err(|e| format!("re-encode a queued notification: {e}"))?;
        let mut headers = Vec::new();
        if !entry.secret.is_empty() {
            headers.push(signature_header(&entry.secret, &body));
        }
        match transport.deliver(&entry.url, &headers, &body) {
            Ok(()) => outcome.delivered.push((
                entry.notification.event.clone(),
                entry.notification.warrant_id.clone(),
                entry.url.clone(),
            )),
            Err(e) => {
                entry.attempts = entry.attempts.saturating_add(1);
                entry.last_reason = e.to_string();
                outcome.still_pending.push(format!(
                    "{} for {} → {} (attempt {})",
                    entry.notification.event,
                    entry.notification.warrant_id,
                    entry.url,
                    entry.attempts
                ));
                survivors.push(entry);
            }
        }
    }
    write_survivors(root, &survivors)?;
    Ok(outcome)
}

/// Rewrite the ledger with the survivors, or remove it when there are none.
fn write_survivors(root: &Path, survivors: &[PendingNotification]) -> Result<(), String> {
    let ledger = pending_path(root);
    if survivors.is_empty() {
        return match std::fs::remove_file(&ledger) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("remove {}: {e}", ledger.display())),
        };
    }
    let mut body = String::new();
    for entry in survivors {
        let line = serde_json::to_string(entry).map_err(|e| format!("encode an entry: {e}"))?;
        body.push_str(&line);
        body.push('\n');
    }
    let temporary = ledger.with_extension("jsonl.tmp");
    std::fs::write(&temporary, body.as_bytes())
        .map_err(|e| format!("write {}: {e}", temporary.display()))?;
    std::fs::rename(&temporary, &ledger).map_err(|e| format!("write {}: {e}", ledger.display()))
}

/// Deliver one notification to every webhook that wants it, queueing each failure. This is the
/// whole public flow: drain, then deliver.
///
/// # Errors
/// [`String`] only when the drain or a queue write fails. Delivery failures are [`Delivery`]
/// outcomes, not errors — the action that caused the notification is already done.
pub fn notify<T: NotifyTransport>(
    transport: &mut T,
    root: &Path,
    config: &NotifyConfig,
    notification: &Notification,
    now: u64,
) -> Result<Vec<(String, Delivery)>, String> {
    if let Err(e) = drain_pending(transport, root) {
        eprintln!(
            "warrantor: the pending-notification ledger could not be drained, so nothing queued \
             was retried: {e}. The new notifications below still go out."
        );
    }
    let body =
        serde_json::to_vec(notification).map_err(|e| format!("encode the notification: {e}"))?;
    let mut out = Vec::new();
    for hook in &config.webhooks {
        if !config.wants(hook, &notification.event) {
            continue;
        }
        let mut headers = Vec::new();
        if !hook.secret.is_empty() {
            headers.push(signature_header(&hook.secret, &body));
        }
        let outcome = match transport.deliver(&hook.url, &headers, &body) {
            Ok(()) => Delivery::Delivered,
            Err(e) => match queue_notification(root, hook, notification, &e, now) {
                Ok(_) => Delivery::Queued { reason: e },
                Err(queued) => {
                    // The one state louder than a failed delivery: a failure that will never be
                    // retried and never mentioned again unless we mention it now.
                    eprintln!(
                        "NOTIFICATION FAILED and could not even be queued — {queued}. Nobody \
                         will be told and nothing will retry: {e}"
                    );
                    Delivery::Queued {
                        reason: format!("{e} (and the queue write failed: {queued})"),
                    }
                }
            },
        };
        out.push((hook.url.clone(), outcome));
    }
    Ok(out)
}
