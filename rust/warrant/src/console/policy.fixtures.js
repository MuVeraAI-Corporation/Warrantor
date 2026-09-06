/**
 * Frozen fixtures for the policy studio for non-developers (L8-04).
 *
 * # Why this file exists
 *
 * Task 11.3 builds the operator-facing policy studio on top of the policy-compiler
 * surface (Task 6.1, in `python/policy_compiler`). The compiler's contract is
 * already defined: it parses a small DSL into `Rule` objects and emits three
 * artifacts (Rego, Cedar, OpenShell). The studio does NOT replace the compiler
 * — it sits in front of it, runs the same parse on the operator's input, and
 * must refuse with the compiler's exact sentences when the operator's input is
 * malformed.
 *
 * The failure mode this file exists to prevent: the studio accepts a policy
 * that the compiler refuses, or refuses a policy the compiler accepts. Either
 * way the operator learned something false about their own controls. The
 * discipline is therefore to transcribe the compiler's refusal messages
 * verbatim and to keep one copy of the parse + emit logic that both surfaces
 * can run identically.
 *
 * # What this file freezes
 *
 *   `policyFixtures.refusals` — the exact refusal set the studio must reproduce.
 *     Each entry carries the offending line and the verbatim compiler message
 *     that must surface in the studio. These are NOT paraphrased; the
 *     `python/policy_compiler/src/policy_compiler/__init__.py` source is the
 *     ground truth and the texts here were transcribed from it on 2026-09-06.
 *
 *   `policyFixtures.acceptablePolicies` — a small set of inputs the studio
 *     accepts, so a test can confirm the studio's accept-set is non-empty and
 *     covers the four canonical intent phrases the Python phrasebook recognizes.
 *
 *   `policyFixtures.exceptionCases` — a set of exception inputs the studio
 *     must refuse (no `expires`, no `compensating_control`, or neither) and
 *     one complete exception the studio accepts. The exception refusal is
 *     added in this file, not in the Python compiler: Task 10.5 owns the
 *     server-side lifecycle that refuses exceptions without expiry or
 *     compensating control, and the studio must mirror that refusal in its
 *     own words, not in the policy-DSL parser's words.
 *
 * # The rule that overrides any design instinct
 *
 * "The compiler already refuses; the studio must refuse in the same words, or
 * the two disagree and the studio wins in the user's head." — Task 11.3 anchor.
 * The transcribed refusal strings here are the studio's contract. Editing one
 * without reading the Python source would split the two surfaces, which is
 * the failure this file exists to detect on the next test run.
 *
 * # What this file does NOT carry
 *
 * It carries no private key material, no real policy content, and no compiler
 * behavior of its own. The studio helpers in `console.js` are the only
 * surface that knows how to parse and emit; this file just freezes the test
 * inputs that pin the contract.
 */

const frozen = (value) => {
  Object.freeze(value);
  if (Array.isArray(value)) {
    for (const item of value) {
      if (item && typeof item === 'object') Object.freeze(item);
    }
  }
  return value;
};

// Refusals transcribed from `python/policy_compiler/src/policy_compiler/__init__.py`
// (line numbers as of 2026-09-06). Each entry is the offending line + the exact
// sentence the Python code raises. The studio's `compilePolicy` must surface the
// message verbatim; the test `studio and compiler refuse with identical text`
// pins it for every entry in the set.
const refusals = frozen([
  frozen({
    kind: 'fixture',
    label: 'malformed rule line',
    line: 'this is not a rule',
    compiler_message: "could not parse rule: 'this is not a rule'",
    source_line: 'python/policy_compiler/src/policy_compiler/__init__.py:RuleParseError(f"could not parse rule: {line!r}")',
  }),
  frozen({
    kind: 'fixture',
    label: 'trailing clause missing the `when` keyword',
    line: 'allow tool:read on /sandbox/* with clearance >= 3',
    compiler_message: "expected 'when <clause>' but got 'with clearance >= 3'",
    source_line: 'python/policy_compiler/src/policy_compiler/__init__.py:RuleParseError(f"expected \'when <clause>\' but got {rest!r}")',
  }),
  frozen({
    kind: 'fixture',
    label: 'unparseable condition after `when`',
    line: 'allow tool:read on r when clearance ~= 3',
    compiler_message: "could not parse condition: 'when clearance ~= 3'",
    source_line: 'python/policy_compiler/src/policy_compiler/__init__.py:RuleParseError(f"could not parse condition: {rest!r}")',
  }),
]);

// Inputs the studio accepts. Each carries an `intent`, an optional `rules`
// body, and the count of rules the studio must report after compilation
// (so a test can pin the number the phrasebook expands to plus any explicit
// enterprise rules). The counts were derived by running the Python compiler
// on the same inputs on 2026-09-06.
const acceptablePolicies = frozen([
  frozen({
    kind: 'fixture',
    label: 'intent "deny all egress" + one enterprise rule',
    intent: 'we want to deny all egress from this account',
    rules: 'allow tool:read on /sandbox/* when clearance >= 3',
    expected_rule_count: 2,
  }),
  frozen({
    kind: 'fixture',
    label: 'intent "require mfa" only, no enterprise rules',
    intent: 'please require mfa',
    rules: '',
    expected_rule_count: 1,
  }),
  frozen({
    kind: 'fixture',
    label: 'explicit unconditional deny',
    intent: '',
    rules: 'deny tool:write on /etc/* when always',
    expected_rule_count: 1,
  }),
  frozen({
    kind: 'fixture',
    label: 'no intent and no rules is a valid empty policy (default-deny at the broker)',
    intent: '',
    rules: '',
    expected_rule_count: 0,
  }),
]);

// Exception cases. The studio refuses an exception without `expires` or
// `compensating_control`; an exception with both fields is accepted. The
// refusal sentence is the studio's own, NOT the policy-DSL parser's, because
// Task 10.5 (server-side lifecycle) is the source of the rule and the studio
// mirrors it in its own words. The text is part of the contract and pinned
// by a test.
const exceptionCases = frozen([
  frozen({
    kind: 'fixture',
    label: 'exception without an expiry is refused',
    exception: {
      warrant_id: 'wrt_0000000000000042',
      compensating_control: 'paging on call to approve within 15 minutes',
    },
    accepted: false,
    refusal_substring: 'expires',
  }),
  frozen({
    kind: 'fixture',
    label: 'exception without a compensating control is refused',
    exception: {
      warrant_id: 'wrt_0000000000000042',
      expires: '2027-01-01T00:00:00Z',
    },
    accepted: false,
    refusal_substring: 'compensating control',
  }),
  frozen({
    kind: 'fixture',
    label: 'exception with both fields is accepted',
    exception: {
      warrant_id: 'wrt_0000000000000042',
      expires: '2027-01-01T00:00:00Z',
      compensating_control: 'paging on call to approve within 15 minutes',
    },
    accepted: true,
  }),
  frozen({
    kind: 'fixture',
    label: 'an empty exception is refused (neither field set)',
    exception: {},
    accepted: false,
    refusal_substring: 'expires',
  }),
]);

export const policyFixtures = Object.freeze({
  kind: 'fixture',
  refusals,
  acceptablePolicies,
  exceptionCases,
});
