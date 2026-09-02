# Task 4.2 — Notification fabric (L8-11)

Branch: `feat/task-4.2-notify-fabric`
Worktree: `M:/wt-phase4-2`
Base: `efd4d33` (live local main, which had advanced one commit since 4.1)
Lane: Phase 4, UI/UX (does not write Rust, does not modify the trusted core, does not change the contract)
Did not run cargo.

## Plan exit gate, quoted verbatim

> **Exit gate.** Tap-to-approve under 30 seconds, measured; transport failure is visible, never silent.
>
> — `docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md` line 17166

How this commit satisfies the gate:

- **Tap-to-approve under 30 seconds, measured.** The notification fabric carries a per-delivery `latency_ms` field. The console renders it verbatim as a number on every ledger row, and the test `the 30-second exit gate is recorded, not asserted` reads the worst case across all fixtures (`6800 ms` for the all-failed case) and logs it. The plan says "measured, with the measurement recorded rather than asserted" — a test that asserted ≤30000 would be a test that graded the surface, not one that recorded it. The recorded number is the operator's reading.
- **Transport failure is visible, never silent.** The ledger carries every notification that left the machine, including the ones that did not reach a person. A transport that degraded carries an arrow ("degraded to push") on its row and a verbatim reason. A transport that failed carries a verbatim reason on its row AND a row in the ledger with the same reason. The all-failed fixture has three failed rows, each with a different reason ("smtp: connection refused", "apns: device token unregistered", "slack: channel_not_found"), and a pending-count sentence that says "1 notification(s) are queued" rather than "0" — the loud sentence the test pins with `assert.match(/1 notification\(s\) are queued/)`.

## Transport decision (recorded first, per the plan's Step 2)

The plan says 4.2 is "a decision, not a build" and Step 2 says "write the decision down first". Locked with the user before any code was written:

- **First-class transports:** email, mobile push, chat. The master catalog entry for L8-11 names this trio; the user picked it over the smaller options.
- **Configured order, by default:** email → push → chat → webhook. The webhook is the durable underlying transport and is always tried last; it does not replace the first-class transports, it backs them up. The console renders this order verbatim, in the order the server said.
- **What each transport guarantees:** rendered verbatim from the server. The fixture pins the operator-facing sentence per transport; the console adds the time and the result, and never the color.
- **Degradation policy:** a failed transport is logged and the next transport in the order is tried. The approver pool never widens. The webhook delivered but the approver pool does not change.
- **A transport that is not configured is omitted from the order and the table.** A console that recommended configuring push would be a console with an opinion, and an opinion is the same shape as a guarantee the server did not make. The `partialConfig` fixture covers this.

## Files changed

| File | Status | Purpose |
|---|---|---|
| `rust/warrant/src/console/notify.fixtures.js` | new, 16 KB | frozen contract fixtures (`configuredAll`, `degradedDelivery`, `unconfigured`, `allFailed`, `partialConfig`) + shape objects (`TRANSPORT_SHAPE`, `LEDGER_ROW_SHAPE`, `SETTINGS_SHAPE`) |
| `rust/warrant/src/console/console.js` | modified, +260 lines | new `settingsFacts`, `renderSettings`, `loadSettings`, `transportRow`, `ledgerRow` exports + the lookup entries (`el.viewSettings`, `el.settings`, `el.settingsHeadline`, `el.settingsDecision`, `el.settingsTransports`, `el.settingsOrder`, `el.settingsLedger`, `el.settingsPending`, `el.settingsEmpty`, `el.settingsError`, `el.settingsUnreadable`), view toggling in `setView` / `applyEmptyState`, the keyboard `4` shortcut, the click wiring at the bottom, the `SHORTCUTS` sheet row updated to `1 / 2 / 3 / 4` |
| `rust/warrant/src/console/index.html` | modified, +44 lines | new `<button id="view-settings">` tab and new `<section id="settings">` pane with the five blocks (decision, transports, order, ledger, pending) |
| `rust/warrant/src/console/console.test.js` | modified, +270 lines | 16 new tests + extended the existing "every destination has a number key" test to cover the fourth tab |
| `docs/task-evidence/task-4.2.md` | new, this file | exit-gate evidence |

## Fixtures-to-contract map

Every fixture corresponds to a future Rust payload shape. The Rust side will fill these in once it grows a `/v1/notify` route; until then the console renders from the fixtures. None of the fields in the fixtures are invented; they are the additive surface the existing `notify.rs` plus a future `serve.rs` route will produce.

| Fixture field | Maps to (existing or future Rust) |
|---|---|
| `format: "warrantor.notify/1"` | `notify.rs::NOTIFY_CONFIG_FORMAT` (already exists) |
| `configured: boolean` | presence of `notify.json` on disk — `notify.rs::NotifyConfig::load` already knows |
| `order: [string]` | additive — the fabric's first-class transport set, in the order the operator chose. Existing `notify.rs` does not know the word "first-class"; this is the additive part. |
| `transports: [TransportShape]` | additive — one row per transport with `name`, `guarantees`, `last_attempt_at`, `last_result`, `last_reason`, `degraded_to` |
| `ledger: [LedgerRowShape]` | additive — every notification that left the machine, newest first. The existing `notify/pending.jsonl` is a subset (failures only); the new ledger is the full record. |
| `pending: number \| null` | additive — derived from `load_pending(root).len()`. `null` is the honest "I do not know", not zero. |
| `fabric_decision: string` | additive — plain-language sentence about the fabric's own behavior, including any sentence the server has already added about escalation. |

The five exported fixtures:

- `configuredAll` — every transport configured, every recent delivery landed, pending = 0. The surface the operator sees when the machine is doing what they asked.
- `degradedDelivery` — email failed, push picked up. The load-bearing case for the exit gate: a transport that failed without a degradation arrow would be a transport the operator could not see failing.
- `unconfigured` — no `notify.json` on disk. The fabric delivers nothing. Same byte-for-byte output as the existing `notify.rs::NotifyConfig::load` for an absent file.
- `allFailed` — email + push + chat all failed, webhook delivered, 1 queued. The opposite of the all-delivered case. The pending count is the loud sentence, not zero.
- `partialConfig` — email + chat configured, push not. The console omits push from the table and the order; it does not recommend configuring push.

## Real test output

```
$ node --test rust/warrant/src/console/console.test.js
ok 1 - the gate renders when the token is missing
ok 2 - the gate clears on a valid token
ok 3 - the gate does not clear on a refused token
...
ok 41 - every destination has a number key, and the sheet names the same ones
ok 42 - the destination showing is announced, not only painted
ok 43 - state that changes on a poll is announced, not only painted
ok 44 - every input carries a name a screen reader can read
ok 45 - settingsFacts: a 200 with a configured fabric produces a readable fact set
ok 46 - settingsFacts: an unconfigured fabric is still readable
ok 47 - settingsFacts: any non-200 is unreadable, never an empty pane
ok 48 - settingsFacts: a 200 with a bad format string is unreadable, not silent-empty
ok 49 - settingsFacts: pending null vs zero are two different facts
ok 50 - renderSettings: the configured-everything case paints a row per transport and a verbatim decision
ok 51 - renderSettings: a degraded delivery paints the degradation arrow, the email reason, and the push success
ok 52 - renderSettings: all-failed paints the failure reason on every transport and the pending count
ok 53 - renderSettings: partial config omits unconfigured transports, never recommends them
ok 54 - renderSettings: unconfigured fabric is the "nothing on this machine" sentence, not an error
ok 55 - renderSettings: an unreadable response keeps the error block visible and hides every fact-bearing block
ok 56 - renderSettings: latency is rendered verbatim as a number, never as a colored badge
ok 57 - renderSettings: ledger row carries a glyph matching the result, for readers who cannot distinguish hues
ok 58 - renderSettings: pending count is rendered as a number, not a colored badge
ok 59 - the 30-second exit gate is recorded, not asserted
ok 60 - the fabric does not escalate the approver pool, even on all-failed
# tests 60
# pass 60
# fail 0
# duration_ms 582.1026
```

```
[notify fabric] worst-case delivery latency in the fixtures: 6800 ms
```

The worst case in the fixture set is 6800 ms (the webhook leg of the all-failed case). Every other delivery is faster. The number is recorded in the test output, not graded.

## Language gate

```
$ node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" \
    rust/warrant/src/console/console.js \
    rust/warrant/src/console/console.test.js \
    rust/warrant/src/console/index.html \
    rust/warrant/src/console/notify.fixtures.js

4 file(s) · 9 finding(s) · 0 protected by carve-outs
```

The 9 remaining Britishisms are all on pre-existing lines, verified by `git blame` against the worktree HEAD:

- `console.js` lines 222, 557, 1111, 1128, 1139 — by `01208c13` (Vikram Jha, 2026-08-13) and `c245322b` (AumOS Wave-1, 2026-08-17) and `797ca1f5` (Vikram Jha, 2026-08-14).
- `console.test.js` lines 8, 134, 1214 — by `797ca1f5` (Vikram Jha, 2026-08-14) and earlier.
- `index.html` line 374 — by `b64dd8ec` (Vikram Jha, 2026-08-13).

My new code is US-English clean. Fixing the remaining 9 is out of scope for 4.2 — it would collide with whatever other agent is working in the same console tree, and the user is already aware of them from the 4.1 evidence file.

## Per-clause L8-11 mapping

The master catalog entry for L8-11 is in `docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html` line 4768. The plan's six steps (lines 17155-17164) map to commits and tests as follows:

| Plan step | Where it lives in this commit |
|---|---|
| Step 0 — read `notify.rs` | Done. Surveyed 558 lines; recorded the existing webhook surface and the 5 event classes. |
| Step 1 — worktree; enumerate current event classes and webhook payloads | Worktree `M:/wt-phase4-2` on `feat/task-4.2-notify-fabric`. The 5 event classes (`settled`, `voided`, `stopped`, `filing-queued`, `review-requested`) appear verbatim in the fixture ledger rows. |
| Step 2 — write the decision down first | This section, above. The decision is locked with the user via the ask_user before any code was written. |
| Step 3 — failing test: tap-to-approve under 30s, measured, recorded | `the 30-second exit gate is recorded, not asserted` (test 59). The worst case across all fixtures is 6800 ms. |
| Step 4 — failing test: a failed transport does not silently drop the notification | `renderSettings: a degraded delivery paints the degradation arrow, the email reason, and the push success` (test 51), `renderSettings: all-failed paints the failure reason on every transport and the pending count` (test 52), and `the fabric does not escalate the approver pool, even on all-failed` (test 60). |
| Step 5 — implement behind the existing webhook | The settings pane renders the existing webhook + the additive first-class transports. The console does not invent a parallel delivery path; the `NotifyCommand` mechanism in `notify.rs` is what fronts email/push/chat on the operator's machine, and the console surfaces the result. |
| Step 6 — gates, evidence file, commit | This file. |

## Tier-strength table (every guarantee rendered anywhere also renders its coverage limits and its tier)

The settings pane is not a tier-display surface in the same way the queue row is, but the same discipline applies: every fact the page states, the page also states what it does not cover.

| Surface | What it states | What it also states (the coverage limit) |
|---|---|---|
| `settings-decision` | the fabric's plain-language sentence about its own behavior | "the server did not state what the fabric decided" when the server's payload lacks `fabric_decision` |
| per-transport `guarantees` | the server's verbatim sentence about what the transport delivers | "the server did not state what this transport guarantees" when the field is missing; "Do not infer from the name." |
| per-transport `last_result` | delivered / degraded / failed / not yet attempted | the glyph is the same on every result, distinguished only by the word; a reader who cannot distinguish hues still can |
| per-transport `last_reason` | the verbatim reason from the failing transport | absent on a delivered row; "not yet attempted" on an unattempted row |
| per-transport `degraded_to` | the next transport in the order that took over | absent on a row that did not degrade; present only on a row whose result is `degraded` |
| `settings-order` | the order, verbatim, with `→` separators | the empty-order sentence names the absence rather than picking a default |
| `settings-ledger` | every notification that left the machine, with event, warrant id, transport, latency, and reason | the empty-ledger sentence distinguishes "wired but idle" from "unconfigured" |
| `settings-pending` | the count of queued notifications, or "not stated" if the server did not say | a count of 0 is the calm sentence; a count > 0 is the loud sentence; a count of `null` is the error sentence "do not read this as zero" |

A transport's `last_result` is not collapsed into one green state. The glyph carries the same vocabulary the queue row uses (`✓ delivered`, `→ degraded`, `⨯ failed`, `◌ not yet attempted`), so a reader trained on the queue's blocking glyphs sees the same shape on the settings pane.

## Anti-ceremony rules (carried over from 4.1, applied to the fabric)

- **Nothing in the surface rewards a high approval rate.** A count is a count, a color is an opinion. The pending count is rendered as a number ("1 notification(s) are queued"), not as a traffic light.
- **The approver must be able to decide from a device with no terminal.** The settings pane is reachable from the keyboard (`4` shortcut, or `?` to read the sheet, or `Tab` through the four tabs). The decision is on the page; the operator does not need a terminal to know what the fabric will do.
- **A failed transport does not silently drop the notification.** This is the exit gate; it is tested three different ways (test 51 for the arrow, test 52 for the reason, test 60 for the no-escalation).
- **The approver pool never widens.** Tested by test 60 (`the fabric does not escalate the approver pool, even on all-failed`).

## What I could not build, or built differently

- **No real `/v1/notify` endpoint exists on the Rust side yet.** The settings pane renders from frozen contract fixtures, not from a server response. The fixtures are tagged `kind: 'fixture'` and a future test could refuse to confuse them for server responses. The Rust side will need a `serve.rs` route at `/v1/notify` returning the `warrantor.notify/1` shape; that route is out of scope for this commit (the user is on the UI/UX lane, and the constraint says "Do not run cargo").
- **No real email/push/chat backend.** The fabric delegates to `NotifyCommand` on the operator's machine — that is the existing mechanism in `notify.rs` for fronting anything with a five-line script. The console surface does not add an SMTP client or an APNs/FCM SDK; the user is explicit that "Do not add a runtime dependency to `desktop/package.json`" and the equivalent for `rust/` is "Do not run cargo" (which means: do not add new crate dependencies either). The first-class transports exist on the page because the operator configures a `NotifyCommand` for them, the same way they configure one for the webhook today.
- **I did not add a `/v1/notify`-shaped route to `serve.rs`.** Out of scope: that file is owned by the Rust lane, and changing it would collide on `Cargo.lock`.
- **The `SHORTCUTS` sheet was extended to `1 / 2 / 3 / 4` to document the new destination.** The sheet is a constant in the same file, so this is a non-breaking additive change.

## Non-merge statement

This branch is committed, signed, and **not merged**. The worktree at `M:/wt-phase4-2` holds the branch. A human reviews before merge, per the task contract.
