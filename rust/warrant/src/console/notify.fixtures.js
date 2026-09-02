// frozen contract fixtures for the notification fabric (Task 4.2, L8-11).
//
// The console renders from these, against no backend. The Rust side
// (`rust/warrant/src/notify.rs` plus a future `/v1/notify` route on
// `serve.rs`) is the source of truth for the wire shape; this file
// pins what the operator will see and what the tests assert.
//
// Shape is additive, not breaking. `notify.json` and the existing
// `NotifyCommand` fronting are untouched: email, mobile push and chat
// are themselves fronted by `NotifyCommand` invocations, so this
// fabric does not introduce a runtime dependency, and the existing
// failure contract (the action never blocks, the failure prints,
// the next notification drains the queue) is preserved verbatim.
//
// Every fixture is marked `kind: 'fixture'` at the top so a test can
// refuse to confuse it for a server response.

/**
 * One transport the operator configured, and what the fabric knows
 * about it. The shape is what `/v1/notify` will return; if the Rust
 * side emits more fields the console will read them defensively, and
 * if it emits fewer the console renders "not stated".
 */
export const TRANSPORT_SHAPE = Object.freeze({
  /** One of 'email' | 'push' | 'chat' | 'webhook'. */
  name: '<string>',
  /** What the operator can read in plain language about the delivery
   *  guarantee this transport makes. The Rust side computes this
   *  from the transport kind and its config; the console never
   *  infers it. Examples below. */
  guarantees: '<string>',
  /** When the last delivery was attempted, epoch seconds. `null` when
   *  the transport has not been used yet, which the console renders
   *  as "not yet attempted" rather than as a zero. */
  last_attempt_at: '<number|null>',
  /** The result of the last attempt. One of
   *  'delivered' | 'degraded' | 'failed'. `degraded` means the
   *  transport failed AND the fabric handed the notification to the
   *  next transport in the order; the operator must see this, not
   *  'failed' which is the unrecoverable end. `failed` means the
   *  notification has been queued for the next drain and NO other
   *  transport reached the approver. */
  last_result: '<string|null>',
  /** The most recent failure reason in the words of whatever refused.
   *  `null` when the last attempt delivered. The console renders the
   *  reason verbatim when it is present, and renders nothing when
   *  it is null. */
  last_reason: '<string|null>',
  /** When `last_result === 'degraded'`, the transport that picked up
   *  the notification. The console paints the arrow so the
   *  degradation is visible: a transport that failed silently into
   *  the next one would be a transport the operator over-trusts. */
  degraded_to: '<string|null>',
});

/**
 * One row of the delivery ledger. Every notification that left the
 * machine is receipted, including the ones that did not reach a
 * person. A fabric that only records deliveries is a fabric that
 * hides its own failures.
 */
export const LEDGER_ROW_SHAPE = Object.freeze({
  /** `settled` | `voided` | `stopped` | `filing-queued` | `review-requested`. */
  event: '<string>',
  /** The warrant id this notification is about. */
  warrant_id: '<string>',
  /** Which transport took it. */
  transport: '<string>',
  /** Same vocabulary as `TRANSPORT_SHAPE.last_result`. */
  result: '<string>',
  /** The failure reason, if any. */
  reason: '<string|null>',
  /** End-to-end time from emit to transport-final-state, milliseconds.
   *  The console renders this as a number, never a traffic light. A
   *  notification that arrived in 18 seconds is the same color as
   *  one that arrived in 27, and both are colored differently from
   *  one that did not arrive. The exit gate asks the surface to
   *  measure, not grade. */
  latency_ms: '<number>',
  /** Epoch seconds. */
  at: '<number>',
});

/**
 * The top-level shape. One response, one pane; the console never
 * fans out into multiple requests for the same settings render.
 */
export const SETTINGS_SHAPE = Object.freeze({
  /** Always 'warrantor.notify/1', matching notify.rs NOTIFY_CONFIG_FORMAT. */
  format: '<string>',
  /** Whether the operator has any `notify.json` on disk at all. */
  configured: '<boolean>',
  /** Every transport the fabric knows about, in the order the fabric
   *  will try them. Email is first, push second, chat third, webhook
   *  always last; this order is the operator-facing decision and is
   *  rendered verbatim. */
  order: ['<string>'],
  /** The configured transports and their state. */
  transports: [TRANSPORT_SHAPE],
  /** The running delivery ledger, newest first. The fabric keeps the
   *  last N rows; N is an implementation choice, not a contract field. */
  ledger: [LEDGER_ROW_SHAPE],
  /** How many entries the fabric has queued for the next drain.
   *  `null` when the server cannot say, which the console renders
   *  as "not stated" rather than as zero. */
  pending: '<number|null>',
  /** What the fabric said in plain language about its own behavior.
   *  The console renders this verbatim, including any sentence the
   *  server has already added. */
  fabric_decision: '<string>',
});

/** Mark every fixture with this so a test can refuse to confuse it
 *  for a server response. */
const tag = (fixture) => Object.freeze({ ...fixture, kind: 'fixture' });

/**
 * The configured-everything case: email + push + chat all
 * configured, the order is email → push → chat, every recent
 * delivery landed, the pending count is zero. This is the surface
 * the operator sees when the machine is doing what they asked.
 */
export const configuredAll = tag({
  format: 'warrantor.notify/1',
  configured: true,
  order: ['email', 'push', 'chat', 'webhook'],
  transports: [
    {
      name: 'email',
      guarantees: 'email is best-effort end-to-end: an outbox script fronted by your SMTP relay; you may read it in the same inbox as the rest of your work.',
      last_attempt_at: 1_735_000_120,
      last_result: 'delivered',
      last_reason: null,
      degraded_to: null,
    },
    {
      name: 'push',
      guarantees: 'mobile push is best-effort end-to-end: a backend that fronts APNs and FCM; it will reach the device when the device is online and the app is installed.',
      last_attempt_at: 1_735_000_120,
      last_result: 'delivered',
      last_reason: null,
      degraded_to: null,
    },
    {
      name: 'chat',
      guarantees: 'chat is best-effort end-to-end: a backend that fronts Slack, Teams, or a webhook of your choosing; it appears in the channel the operator named in the config.',
      last_attempt_at: 1_735_000_120,
      last_result: 'delivered',
      last_reason: null,
      degraded_to: null,
    },
    {
      name: 'webhook',
      guarantees: 'webhook is the durable underlying transport: every event reaches a URL the operator owns, signed with HMAC-SHA256, and never escalates to a wider group on failure.',
      last_attempt_at: 1_735_000_120,
      last_result: 'delivered',
      last_reason: null,
      degraded_to: null,
    },
  ],
  ledger: [
    {
      event: 'review-requested',
      warrant_id: 'wrt_abc123',
      transport: 'email',
      result: 'delivered',
      reason: null,
      latency_ms: 4_120,
      at: 1_735_000_120,
    },
    {
      event: 'review-requested',
      warrant_id: 'wrt_def456',
      transport: 'email',
      result: 'delivered',
      reason: null,
      latency_ms: 3_950,
      at: 1_735_000_080,
    },
  ],
  pending: 0,
  fabric_decision:
    'first-class transports: email, mobile push, chat. the fabric tries them in this order: email, push, chat. a failed transport is logged and the next one is tried; the approver pool never widens; the webhook is the durable underlying transport and is always tried last.',
});

/**
 * A degraded delivery: email failed, push picked up, chat was not
 * needed. The ledger must show BOTH rows so the operator sees the
 * degradation. The console paints an arrow from email to push, with
 * the email failure reason on the email row, and the push success
 * on the push row. A fabric that hid the email failure would be a
 * fabric whose transport count the operator could not trust.
 */
export const degradedDelivery = tag({
  format: 'warrantor.notify/1',
  configured: true,
  order: ['email', 'push', 'chat', 'webhook'],
  transports: [
    {
      name: 'email',
      guarantees: 'email is best-effort end-to-end: an outbox script fronted by your SMTP relay; you may read it in the same inbox as the rest of your work.',
      last_attempt_at: 1_735_000_300,
      last_result: 'degraded',
      last_reason: 'smtp: relay refused: 550 5.7.1 message rejected as spam',
      degraded_to: 'push',
    },
    {
      name: 'push',
      guarantees: 'mobile push is best-effort end-to-end: a backend that fronts APNs and FCM; it will reach the device when the device is online and the app is installed.',
      last_attempt_at: 1_735_000_301,
      last_result: 'delivered',
      last_reason: null,
      degraded_to: null,
    },
    {
      name: 'chat',
      guarantees: 'chat is best-effort end-to-end: a backend that fronts Slack, Teams, or a webhook of your choosing; it appears in the channel the operator named in the config.',
      last_attempt_at: null,
      last_result: null,
      last_reason: null,
      degraded_to: null,
    },
    {
      name: 'webhook',
      guarantees: 'webhook is the durable underlying transport: every event reaches a URL the operator owns, signed with HMAC-SHA256, and never escalates to a wider group on failure.',
      last_attempt_at: 1_735_000_301,
      last_result: 'delivered',
      last_reason: null,
      degraded_to: null,
    },
  ],
  ledger: [
    {
      event: 'review-requested',
      warrant_id: 'wrt_xyz789',
      transport: 'push',
      result: 'delivered',
      reason: null,
      latency_ms: 5_240,
      at: 1_735_000_301,
    },
    {
      event: 'review-requested',
      warrant_id: 'wrt_xyz789',
      transport: 'email',
      result: 'degraded',
      reason: 'smtp: relay refused: 550 5.7.1 message rejected as spam',
      latency_ms: 1_180,
      at: 1_735_000_300,
    },
  ],
  pending: 0,
  fabric_decision:
    'first-class transports: email, mobile push, chat. the fabric tried email for wrt_xyz789 and the SMTP relay refused; it then tried push and the device accepted. the approver pool did not change.',
});

/**
 * The unconfigured case: no `notify.json` on disk. The fabric
 * delivers nothing. The console renders the same fixed prose that
 * `notify.rs::NotifyConfig::load` returns when the file is absent:
 * byte-for-byte today's output, no new words.
 */
export const unconfigured = tag({
  format: 'warrantor.notify/1',
  configured: false,
  order: [],
  transports: [],
  ledger: [],
  pending: null,
  fabric_decision:
    'no notify.json was found. the machine did not ask for notifications, so the fabric does not send any. write one to enable a transport.',
});

/**
 * A failed delivery where no transport reached the approver: all
 * three first-class transports failed, the fabric put the
 * notification in the pending queue, and the next drain will retry
 * it. The console renders the pending count and the three reasons;
 * it does NOT render "the approver was notified" — they were not.
 */
export const allFailed = tag({
  format: 'warrantor.notify/1',
  configured: true,
  order: ['email', 'push', 'chat', 'webhook'],
  transports: [
    {
      name: 'email',
      guarantees: 'email is best-effort end-to-end: an outbox script fronted by your SMTP relay; you may read it in the same inbox as the rest of your work.',
      last_attempt_at: 1_735_000_500,
      last_result: 'failed',
      last_reason: 'smtp: connection refused: 10.0.0.4:587',
      degraded_to: null,
    },
    {
      name: 'push',
      guarantees: 'mobile push is best-effort end-to-end: a backend that fronts APNs and FCM; it will reach the device when the device is online and the app is installed.',
      last_attempt_at: 1_735_000_502,
      last_result: 'failed',
      last_reason: 'apns: device token unregistered',
      degraded_to: null,
    },
    {
      name: 'chat',
      guarantees: 'chat is best-effort end-to-end: a backend that fronts Slack, Teams, or a webhook of your choosing; it appears in the channel the operator named in the config.',
      last_attempt_at: 1_735_000_504,
      last_result: 'failed',
      last_reason: 'slack: channel_not_found',
      degraded_to: null,
    },
    {
      name: 'webhook',
      guarantees: 'webhook is the durable underlying transport: every event reaches a URL the operator owns, signed with HMAC-SHA256, and never escalates to a wider group on failure.',
      last_attempt_at: 1_735_000_505,
      last_result: 'delivered',
      last_reason: null,
      degraded_to: null,
    },
  ],
  ledger: [
    {
      event: 'review-requested',
      warrant_id: 'wrt_qrs012',
      transport: 'webhook',
      result: 'delivered',
      reason: null,
      latency_ms: 6_800,
      at: 1_735_000_505,
    },
    {
      event: 'review-requested',
      warrant_id: 'wrt_qrs012',
      transport: 'chat',
      result: 'failed',
      reason: 'slack: channel_not_found',
      latency_ms: 240,
      at: 1_735_000_504,
    },
    {
      event: 'review-requested',
      warrant_id: 'wrt_qrs012',
      transport: 'push',
      result: 'failed',
      reason: 'apns: device token unregistered',
      latency_ms: 1_870,
      at: 1_735_000_502,
    },
    {
      event: 'review-requested',
      warrant_id: 'wrt_qrs012',
      transport: 'email',
      result: 'failed',
      reason: 'smtp: connection refused: 10.0.0.4:587',
      latency_ms: 1_300,
      at: 1_735_000_500,
    },
  ],
  pending: 1,
  fabric_decision:
    'first-class transports: email, mobile push, chat. all three failed for wrt_qrs012; the notification is queued for the next drain. the webhook delivered but the approver pool does not change.',
});

/**
 * A partial-config case: only email + chat are configured, push is
 * not. The order omits push, the transports list omits it, and the
 * ledger still shows what the configured transports did. The
 * console does NOT print a hint to "configure push" — that would
 * be a recommendation, and a recommendation is an opinion.
 */
export const partialConfig = tag({
  format: 'warrantor.notify/1',
  configured: true,
  order: ['email', 'chat', 'webhook'],
  transports: [
    {
      name: 'email',
      guarantees: 'email is best-effort end-to-end: an outbox script fronted by your SMTP relay; you may read it in the same inbox as the rest of your work.',
      last_attempt_at: 1_735_000_700,
      last_result: 'delivered',
      last_reason: null,
      degraded_to: null,
    },
    {
      name: 'chat',
      guarantees: 'chat is best-effort end-to-end: a backend that fronts Slack, Teams, or a webhook of your choosing; it appears in the channel the operator named in the config.',
      last_attempt_at: 1_735_000_700,
      last_result: 'delivered',
      last_reason: null,
      degraded_to: null,
    },
    {
      name: 'webhook',
      guarantees: 'webhook is the durable underlying transport: every event reaches a URL the operator owns, signed with HMAC-SHA256, and never escalates to a wider group on failure.',
      last_attempt_at: 1_735_000_700,
      last_result: 'delivered',
      last_reason: null,
      degraded_to: null,
    },
  ],
  ledger: [
    {
      event: 'settled',
      warrant_id: 'wrt_lmn345',
      transport: 'email',
      result: 'delivered',
      reason: null,
      latency_ms: 3_700,
      at: 1_735_000_700,
    },
  ],
  pending: 0,
  fabric_decision:
    'first-class transports: email, chat. mobile push is not configured. the fabric tries email, then chat, then the webhook.',
});
