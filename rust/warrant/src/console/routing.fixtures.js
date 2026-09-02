// frozen contract fixtures for the local-first inference routing surface
// (Task 4.5, L9-14).
//
// The console renders from these, against no backend. The Rust side
// (`rust/warrant/src/spend.rs::quotes` plus a future routing layer that
// picks the backend) is the source of truth for the wire shape; this
// file pins what the operator will see and what the tests assert.
//
// The load-bearing rule (the exit gate): routing decisions are
// receipted, the ceiling refuses rather than reconciles, and quoted
// figures carry their configuration. The four state values here are
// derived from the `spend.rs` `quotes()` function's output:
//
//   local          — the chosen backend is `safe` (no data leaves the
//                    machine). The receipt is recorded.
//   escalated      — the chosen backend is not `safe`; the receipt is
//                    recorded with the reason, the cost class, and the
//                    configuration that produced the figure.
//   ceiling_refused — no backend the routing layer can pick is
//                    affordable; the call is refused at the ceiling and
//                    is NOT recorded against the ledger. Reconciled-
//                    after-the-fact would mean the call had already
//                    happened; refused-at-the-ceiling means it did not.
//   unconfigured   — no backends are configured at all. The page says
//                    so honestly rather than guessing.
//
// Every fixture is marked `kind: 'fixture'` at the top so a test can
// refuse to confuse it for a server response.

/**
 * One backend the operator can route to. The shape mirrors `ModelBackend`
 * in `spend.rs` plus the routing layer's "is this safe to call without
 * escalating?" decision.
 */
export const BACKEND_SHAPE = Object.freeze({
  /** The id the agent uses in `UsageClaim.backend`. */
  id: '<string>',
  /** A human-readable label. */
  display: '<string>',
  /** `true` if no data leaves the machine through this backend. The
   *  routing policy prefers `safe` backends; the first non-safe
   *  backend the operator configures is the first escalation. */
  safe: '<boolean>',
  /** The cost class for the price table, e.g. `input_per_mtok_usd`. The
   *  console renders this verbatim. */
  cost_class: '<string>',
  /** Configuration that produced the quoted figure. Step 5 of the plan:
   *  "measurement configuration travels with any quoted guard figure —
   *  context length, seed, quantization. Each moves the number." A
   *  number without its configuration is a number the operator cannot
   *  re-derive, which is a number the operator cannot trust. */
  configuration: '<object>',
});

/**
 * One routing decision. A decision is what the routing layer said about
 * one call: which backend, what it cost, what the receipt carries.
 */
export const DECISION_SHAPE = Object.freeze({
  /** 'local' | 'escalated' | 'ceiling_refused' | 'unconfigured'. */
  state: '<string>',
  /** The warrant id this decision is about. */
  warrant_id: '<string>',
  /** The work the agent needed done, e.g. `summarise this conversation`
   *  or `classify this tool call`. The console renders verbatim. */
  task: '<string>',
  /** The backend the routing layer chose. `null` when `state ===
   *  'ceiling_refused'` (no backend was chosen) or `state ===
   *  'unconfigured'`. */
  chosen_backend: '<string|null>',
  /** The cost in micros, as priced from the operator's table and the
   *  ledger's remaining allowance. `null` when refused or unconfigured. */
  cost_micros: '<number|null>',
  /** The cost class the figure was priced against. `null` when refused. */
  cost_class: '<string|null>',
  /** The configuration the figure was produced under. Required even
   *  when the figure is zero, because a zero priced under one config
   *  is not the same as a zero priced under another. */
  configuration: '<object>|null',
  /** Why the routing layer escalated, when `state === 'escalated'`.
   *  The reason is one of the operator's own sentences; the console
   *  renders verbatim. */
  reason: '<string|null>',
  /** The receipt itself, when one was issued. `null` when the state is
   *  'ceiling_refused' — the rule is "refused at the ceiling, not
   *  reconciled", so there is no receipt. */
  receipt: '<object>|null',
  /** Epoch seconds. */
  at: '<number>',
});

/**
 * The top-level shape. One response, one pane; the console never
 * fans out into multiple requests for the same render.
 */
export const ROUTING_SHAPE = Object.freeze({
  /** Always 'warrantor.routing-decision/1'. */
  format: '<string>',
  /** When the decisions were last computed, epoch seconds. */
  as_of: '<number>',
  /** The policy the operator chose. The console renders this verbatim;
   *  it is the operator-facing statement of what "local-first" means
   *  on this machine. */
  policy: '<string>',
  /** Every backend the operator configured, in the order the routing
   *  layer will try them. `safe` first. */
  backends: [BACKEND_SHAPE],
  /** The spend ceiling. PLACEHOLDER until Task 1.4 lands — see the
   *  evidence file for the cross-reference. The shape is the
   *  additive part the console renders: declared / undeclared,
   *  cap_micros, spent_micros, remaining_micros. The semantics (what
   *  counts as a "ceiling refusal") are owned by 1.4. */
  ceiling: {
    /** `true` when the warrant declared a ceiling. `false` means
     *  the ledger treats the ceiling as zero (a free-backend-only
     *  warrant) — see `spend.rs` "Fail closed: an absent cap is a
     *  cap of zero, crate-wide". */
    declared: '<boolean>',
    /** The declared ceiling, in micros. `0` when `declared` is `false`. */
    cap_micros: '<number>',
    /** What the ledger has spent so far. */
    spent_micros: '<number>',
    /** `cap_micros - spent_micros`, computed at `as_of`. */
    remaining_micros: '<number>',
  },
  /** The decisions, newest first. */
  decisions: [DECISION_SHAPE],
});

/** Mark every fixture with this so a test can refuse to confuse it
 *  for a server response. */
const tag = (fixture) => Object.freeze({ ...fixture, kind: 'fixture' });

/**
 * The local-only case: every decision was served by a `safe` backend.
 * The receipt is recorded; the ceiling has plenty of headroom. The
 * surface the operator sees when the machine is doing what they asked.
 */
export const localOnly = tag({
  format: 'warrantor.routing-decision/1',
  as_of: 1_735_001_000,
  policy: 'local-first. safe backends are tried first. the first safe backend the operator configures is the first local choice. an escalation is a receipt, not a silent switch.',
  backends: [
    {
      id: 'qwen3-guard-4b-q4_k_m',
      display: 'Qwen3Guard 4B (Q4_K_M, local)',
      safe: true,
      cost_class: 'local-inference',
      configuration: {
        model: 'hf.co/mradermacher/Qwen3Guard-Gen-4B-GGUF:Q4_K_M',
        context_length: 8192,
        seed: 0,
        quantization: 'Q4_K_M',
        endpoint: 'http://127.0.0.1:11434',
      },
    },
  ],
  ceiling: {
    declared: true,
    cap_micros: 1_000_000,
    spent_micros: 24_500,
    remaining_micros: 975_500,
  },
  decisions: [
    {
      state: 'local',
      warrant_id: 'wrt_local01',
      task: 'classify the tool call before staging',
      chosen_backend: 'qwen3-guard-4b-q4_k_m',
      cost_micros: 1_240,
      cost_class: 'local-inference',
      configuration: {
        model: 'hf.co/mradermacher/Qwen3Guard-Gen-4B-GGUF:Q4_K_M',
        context_length: 8192,
        seed: 0,
        quantization: 'Q4_K_M',
      },
      reason: null,
      receipt: {
        format: 'warrantor.cost-receipt/1',
        at: 1_735_000_950,
        backend: 'qwen3-guard-4b-q4_k_m',
        cost_micros: 1_240,
        input_tokens: 412,
        output_tokens: 18,
      },
      at: 1_735_000_950,
    },
  ],
});

/**
 * The escalated case: a `safe` backend was tried first, could not
 * finish the work, and the routing layer escalated to a non-safe
 * backend. The receipt carries the reason, the cost class, the
 * configuration, and the spend class. A page that hid the reason
 * would be a page whose escalations the operator could not audit.
 */
export const escalatedWithReceipt = tag({
  format: 'warrantor.routing-decision/1',
  as_of: 1_735_002_000,
  policy: 'local-first. safe backends are tried first. an escalation is a receipt with a reason, a cost class, and the configuration that produced the figure.',
  backends: [
    {
      id: 'qwen3-guard-4b-q4_k_m',
      display: 'Qwen3Guard 4B (Q4_K_M, local)',
      safe: true,
      cost_class: 'local-inference',
      configuration: {
        model: 'hf.co/mradermacher/Qwen3Guard-Gen-4B-GGUF:Q4_K_M',
        context_length: 8192,
        seed: 0,
        quantization: 'Q4_K_M',
        endpoint: 'http://127.0.0.1:11434',
      },
    },
    {
      id: 'claude-opus-4-7',
      display: 'Claude Opus 4.7 (remote)',
      safe: false,
      cost_class: 'remote-premium',
      configuration: {
        model: 'claude-opus-4-7',
        context_length: 200_000,
        seed: null,
        quantization: null,
        endpoint: 'https://api.anthropic.com',
      },
    },
  ],
  ceiling: {
    declared: true,
    cap_micros: 1_000_000,
    spent_micros: 412_000,
    remaining_micros: 588_000,
  },
  decisions: [
    {
      state: 'escalated',
      warrant_id: 'wrt_esc01',
      task: 'summarize a 180k-token document',
      chosen_backend: 'claude-opus-4-7',
      cost_micros: 78_400,
      cost_class: 'remote-premium',
      configuration: {
        model: 'claude-opus-4-7',
        context_length: 200_000,
        seed: null,
        quantization: null,
        endpoint: 'https://api.anthropic.com',
      },
      reason: 'the local guard model has a 8,192-token context; the work is 180,000 tokens. escalation is the only way to fit the work, and the cost class is named so the operator can see the price.',
      receipt: {
        format: 'warrantor.cost-receipt/1',
        at: 1_735_001_900,
        backend: 'claude-opus-4-7',
        cost_micros: 78_400,
        input_tokens: 180_000,
        output_tokens: 4_200,
      },
      at: 1_735_001_900,
    },
  ],
});

/**
 * The ceiling-refused case: the work would cost more than the
 * remaining allowance. The routing layer REFUSES at the ceiling —
 * there is no receipt, because the call never happened, and the
 * decision ledger records the refusal with its reason. A page that
 * showed this as "the call was made and reconciled after" would
 * be a page whose budget the operator could not trust.
 */
export const ceilingRefused = tag({
  format: 'warrantor.routing-decision/1',
  as_of: 1_735_003_000,
  policy: 'local-first. the ceiling refuses rather than reconciles. a refused-at-the-ceiling decision is recorded with no receipt, because there is no receipt to record.',
  backends: [
    {
      id: 'qwen3-guard-4b-q4_k_m',
      display: 'Qwen3Guard 4B (Q4_K_M, local)',
      safe: true,
      cost_class: 'local-inference',
      configuration: {
        model: 'hf.co/mradermacher/Qwen3Guard-Gen-4B-GGUF:Q4_K_M',
        context_length: 8192,
        seed: 0,
        quantization: 'Q4_K_M',
        endpoint: 'http://127.0.0.1:11434',
      },
    },
    {
      id: 'claude-opus-4-7',
      display: 'Claude Opus 4.7 (remote)',
      safe: false,
      cost_class: 'remote-premium',
      configuration: {
        model: 'claude-opus-4-7',
        context_length: 200_000,
        seed: null,
        quantization: null,
        endpoint: 'https://api.anthropic.com',
      },
    },
  ],
  ceiling: {
    declared: true,
    cap_micros: 1_000_000,
    spent_micros: 980_000,
    remaining_micros: 20_000,
  },
  decisions: [
    {
      state: 'ceiling_refused',
      warrant_id: 'wrt_ceil01',
      task: 'classify a 6,000-token tool call',
      chosen_backend: null,
      cost_micros: null,
      cost_class: null,
      configuration: null,
      reason: 'the local backend would cost 8,400 micros; the remaining allowance is 20,000 micros. the work would have fit, but the next escalation — the only non-safe backend — would cost 64,000 micros, which the remaining allowance does not cover. the routing layer refused at the ceiling.',
      receipt: null,
      at: 1_735_002_800,
    },
  ],
});

/**
 * The unconfigured case: no backends are configured. The routing
 * layer cannot pick anything. The page renders "no backends
 * configured" rather than guessing at one.
 */
export const unconfigured = tag({
  format: 'warrantor.routing-decision/1',
  as_of: 1_735_004_000,
  policy: 'no backends are configured. the routing layer cannot pick anything until at least one is.',
  backends: [],
  ceiling: {
    declared: false,
    cap_micros: 0,
    spent_micros: 0,
    remaining_micros: 0,
  },
  decisions: [],
});
