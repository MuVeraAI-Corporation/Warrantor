//! Outbound notifications: what a configured machine sends, what it refuses to send, and the
//! queue that refuses to lose a delivery.
//!
//! The library half lives here, against a scripted transport — the only place delivery,
//! queueing and draining can be produced on demand. The CLI contract (a settle whose
//! notification failed exits exactly as one with no configuration) is driven through the real
//! binary in `tests/autofile.rs`, beside the sibling contract it mirrors: a failed filing never
//! fails the settle either.

use std::path::PathBuf;

use hmac::SimpleHmac;
use serde_json::json;

use warrantor_warrant::notify::{
    self, Notification, NotifyConfig, NotifyTransport, Webhook, NOTIFICATION_FORMAT,
    NOTIFY_CONFIG_FORMAT,
};

const NOW: u64 = 1_786_000_000;

fn tempdir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "warrantor-notify-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).expect("tempdir");
    path
}

fn webhook(secret: &str) -> Webhook {
    Webhook {
        url: "http://127.0.0.1:9099/hook".to_string(),
        secret: secret.to_string(),
        events: Default::default(),
    }
}

fn config(secret: &str) -> NotifyConfig {
    NotifyConfig {
        format: NOTIFY_CONFIG_FORMAT.to_string(),
        webhooks: vec![webhook(secret)],
    }
}

fn event(event: &str) -> Notification {
    Notification {
        format: NOTIFICATION_FORMAT.to_string(),
        event: event.to_string(),
        warrant_id: "wrt_notify".to_string(),
        goal: "close the loop with whoever is not watching".to_string(),
        subject: "spiffe://muveraai.com/agent/alpha".to_string(),
        state: "settled".to_string(),
        at: NOW,
        detail: json!({ "complete": true }),
    }
}

/// What one delivery attempt was asked for: the url, the headers, the body.
type Asked = (String, Vec<(String, String)>, Vec<u8>);

/// Whatever the test says delivery did. Records what it was asked, header and body verbatim.
struct Scripted {
    results: Vec<Result<(), String>>,
    seen: Vec<Asked>,
}

impl Scripted {
    fn always_ok() -> Self {
        Self {
            results: vec![Ok(())],
            seen: Vec::new(),
        }
    }

    fn always_failing() -> Self {
        Self {
            // Deep enough for a notification and every retry this test makes of it; the
            // pop-empty panic below stays as the guard against unscripted deliveries.
            results: vec![Err("connection refused".to_string()); 16],
            seen: Vec::new(),
        }
    }
}

impl NotifyTransport for Scripted {
    fn deliver(
        &mut self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(), String> {
        self.seen
            .push((url.to_string(), headers.to_vec(), body.to_vec()));
        self.results
            .pop()
            .expect("one scripted answer per delivery")
    }
}

// ── the config ────────────────────────────────────────────────────────────────────────

/// An absent config is no configuration — the normal state, rendered as silence by every caller.
/// A config that exists and will not parse is an error, and so is a future format.
#[test]
fn an_absent_config_is_silent_and_a_broken_one_is_loud() {
    let fresh = tempdir("fresh");
    assert!(NotifyConfig::load(&fresh)
        .expect("absence is the normal state")
        .webhooks
        .is_empty());

    let root = tempdir("corrupt");
    std::fs::write(notify::config_path(&root), b"{ not a config").expect("write");
    assert!(NotifyConfig::load(&root).is_err());

    std::fs::write(
        notify::config_path(&root),
        "{\"format\":\"warrantor.notify/2\",\"webhooks\":[]}",
    )
    .expect("write");
    let error = NotifyConfig::load(&root).expect_err("a future format is not guessed at");
    assert!(error.contains("warrantor.notify/2"), "{error}");
}

/// A config naming an unusable url, or an event this build does not know, is refused with the
/// reason — never delivered-to-anyway or filtered-silently.
#[test]
fn a_config_with_a_bad_url_or_unknown_event_is_refused() {
    let root = tempdir("bad-config");
    let bad_url = NotifyConfig {
        format: NOTIFY_CONFIG_FORMAT.to_string(),
        webhooks: vec![Webhook {
            url: "127.0.0.1:9099".to_string(),
            secret: String::new(),
            events: Default::default(),
        }],
    };
    std::fs::write(
        notify::config_path(&root),
        serde_json::to_string(&bad_url).expect("encode"),
    )
    .expect("write");
    let error = NotifyConfig::load(&root).expect_err("refused");
    assert!(error.contains("not an http(s) URL"), "{error}");

    let unknown_event = NotifyConfig {
        format: NOTIFY_CONFIG_FORMAT.to_string(),
        webhooks: vec![Webhook {
            url: "http://127.0.0.1:9099/hook".to_string(),
            secret: String::new(),
            events: ["exploded".to_string()].into_iter().collect(),
        }],
    };
    std::fs::write(
        notify::config_path(&root),
        serde_json::to_string(&unknown_event).expect("encode"),
    )
    .expect("write");
    let error = NotifyConfig::load(&root).expect_err("refused");
    assert!(
        error.contains("\"exploded\"") && error.contains("settled, voided, stopped, filing-queued"),
        "the refusal names the word it refused and the four it knows: {error}"
    );
}

// ── delivery ──────────────────────────────────────────────────────────────────────────

/// A delivered notification carries exactly the eight agreed fields — the payload is a
/// deliberate, small contract, and a test that let a ninth field slip in would be exporting data
/// nobody decided to export.
#[test]
fn a_delivered_notification_carries_exactly_the_agreed_fields() {
    let mut transport = Scripted::always_ok();
    let root = tempdir("deliver");

    let outcomes = notify::notify(
        &mut transport,
        &root,
        &config("a-secret"),
        &event("settled"),
        NOW,
    )
    .expect("notify");

    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].1, notify::Delivery::Delivered);
    let (url, headers, body) = &transport.seen[0];
    assert_eq!(url, "http://127.0.0.1:9099/hook");
    assert_eq!(
        headers.len(),
        1,
        "a secret means exactly one header: {headers:?}"
    );
    assert_eq!(headers[0].0, "X-Warrantor-Signature");

    let body: serde_json::Value = serde_json::from_slice(body).expect("the body is JSON");
    let mut keys: Vec<&str> = body
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "at",
            "detail",
            "event",
            "format",
            "goal",
            "state",
            "subject",
            "warrant_id"
        ],
        "nothing rides along that was not decided: {body}"
    );
    assert_eq!(body["warrant_id"], "wrt_notify");
    assert_eq!(body["event"], "settled");
    assert!(
        !notify::pending_path(&root).exists(),
        "a success leaves no queue"
    );
}

/// The signature header is a real HMAC-SHA256 of the exact body under the configured secret —
/// recomputed here independently, so the header and the bytes it covers cannot drift apart.
#[test]
fn the_signature_is_an_hmac_of_the_exact_body_sent() {
    let mut transport = Scripted::always_ok();
    let root = tempdir("signed");

    notify::notify(
        &mut transport,
        &root,
        &config("a-secret"),
        &event("settled"),
        NOW,
    )
    .expect("notify");

    let (_, headers, body) = &transport.seen[0];
    let value = headers[0]
        .1
        .strip_prefix("sha256=")
        .expect("the scheme prefix");
    use digest::{FixedOutput, KeyInit, Update};
    let mut mac = SimpleHmac::<sha2::Sha256>::new_from_slice(b"a-secret")
        .expect("HMAC accepts any key length");
    mac.update(body);
    let mut tag = <digest::Output<SimpleHmac<sha2::Sha256>> as Default>::default();
    mac.finalize_into(&mut tag);
    assert_eq!(value, hex::encode(tag));

    // And a webhook without a secret is told the truth by omission: no header at all.
    let mut unsigned = Scripted::always_ok();
    notify::notify(&mut unsigned, &root, &config(""), &event("settled"), NOW).expect("notify");
    assert!(
        unsigned.seen[0].1.is_empty(),
        "no secret, no signature header — advisory, as documented"
    );
}

/// A webhook that only asked for some events only receives those events. The filter is the
/// receiver's, applied by us — the difference between "you chose" and "we decided for you".
#[test]
fn a_webhook_that_asked_for_some_events_gets_only_those() {
    let mut selective = webhook("");
    selective.events = ["settled".to_string()].into_iter().collect();
    let config = NotifyConfig {
        format: NOTIFY_CONFIG_FORMAT.to_string(),
        webhooks: vec![selective],
    };
    let mut transport = Scripted::always_ok();
    let root = tempdir("filtered");

    notify::notify(&mut transport, &root, &config, &event("voided"), NOW).expect("notify");

    assert!(
        transport.seen.is_empty(),
        "a voided event is not for a webhook that asked only for settled"
    );
}

// ── the queue and its drain ───────────────────────────────────────────────────────────

/// A failed delivery is queued with its payload verbatim and the refusal in its own words, and
/// the drain that later succeeds sends those bytes and no others.
#[test]
fn a_failed_delivery_queues_verbatim_and_the_next_drain_delivers_it() {
    let root = tempdir("queued");
    let mut failing = Scripted::always_failing();

    let outcomes =
        notify::notify(&mut failing, &root, &config("s"), &event("settled"), NOW).expect("notify");
    assert!(
        matches!(&outcomes[0].1, notify::Delivery::Queued { reason } if reason == "connection refused"),
        "{outcomes:?}"
    );
    let pending = notify::load_pending(&root).expect("readable");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].notification, event("settled"));
    assert_eq!(pending[0].attempts, 1);

    let mut ok = Scripted::always_ok();
    let outcome = notify::drain_pending(&mut ok, &root).expect("drain");
    assert_eq!(outcome.delivered.len(), 1);
    assert_eq!(outcome.delivered[0].0, "settled");
    let (_, headers, body) = &ok.seen[0];
    assert_eq!(
        serde_json::to_vec(&event("settled")).expect("encode"),
        *body,
        "the retry sent the queued payload verbatim, signature recomputed over those bytes"
    );
    assert_eq!(headers.len(), 1, "the queued secret signs the retry too");
    assert!(
        !notify::pending_path(&root).exists(),
        "an emptied queue is removed"
    );
}

/// A drain that fails again keeps the entry and counts the attempt.
#[test]
fn a_drain_that_fails_again_keeps_the_entry_and_counts() {
    let root = tempdir("drain-fail");
    let mut failing = Scripted::always_failing();
    notify::notify(&mut failing, &root, &config(""), &event("stopped"), NOW).expect("notify");

    let outcome = notify::drain_pending(&mut failing, &root).expect("drain");

    assert_eq!(outcome.still_pending.len(), 1);
    assert!(
        outcome.still_pending[0].contains("attempt 2"),
        "{outcome:?}"
    );
    let pending = notify::load_pending(&root).expect("readable");
    assert_eq!(pending[0].attempts, 2);
}

/// A corrupt queue is an error naming the line, not an empty queue — entries are promises to a
/// human, and reading a broken file as "nothing pending" silently abandons them.
#[test]
fn a_corrupt_queue_is_an_error_not_an_empty_queue() {
    let root = tempdir("corrupt-queue");
    std::fs::create_dir_all(root.join("notify")).expect("dir");
    std::fs::write(
        notify::pending_path(&root),
        b"{ not a pending notification\n",
    )
    .expect("write");

    let error = notify::load_pending(&root).expect_err("refused");
    assert!(
        error.contains("line 1") && error.contains("fix or remove"),
        "{error}"
    );
}
