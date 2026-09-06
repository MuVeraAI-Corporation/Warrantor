# Task 11.5 — Plain-language scope and dependency-aware partial approval

**Anchor.** L8-14, L8-15, both `core`, `status=none`, W2.

**Files.**

- `rust/warrant/src/console/console.js` — extended `partialReleaseBlock` to surface reversibility per fixture (`queue-partial-irreversible` paragraph when `irreversible_count > 0`, `queue-partial-reversible` paragraph otherwise). Added `scopePreview` and wired it as the FIRST block in every queue row. Modified the act-bar rendering so the Approve button is relabeled to "Release [independently-releasable summaries]" when a partial-release rule lists a refused dependent, and a `queue-acts-dependent` paragraph precedes the bar naming the dependent. Disabled the Approve button when the releasable set is empty. Two Britishisms in new comments corrected (`judgement` -> `judgment`).
- `rust/warrant/src/console/queue.fixtures.js` — extended `PROPOSED_EFFECT_SHAPE` with `reversible` (boolean). Extended `PARTIAL_RELEASE_SHAPE` with `irreversible_count`. Updated the `dependencyQueue` fixture with `reversible: true` on every effect and `irreversible_count: 0` on its partial-release. Added a new fixture `irreversibleQueue` (warrant `wrt_e`) covering the merge-pr case: a GitHub merge that is irreversible, a tracking issue that is reversible, a dependency rule that refuses the merge until the issue exists.
- `rust/warrant/src/console/console.test.js` — added 6 tests covering the exit gate, the irreversible preview, the dependent-stays-staged rule, the empty-releasable edge case, and the goal-and-effect scope summary. Extended the existing dynamic import to include `irreversibleQueue`. One Britishism in new code corrected (`judgement` -> `judgment`).
- `docs/task-evidence/task-11.5.md` — this file.

## Exit gate (verbatim from the plan)

> Approving one item of a batch with a dependent effect **surfaces the dependent before the approve control is reachable**, and a test asserts the dependent stays staged when only its prerequisite is released.

## Branch performance

| Step | Plan's check | Branch state |
|------|--------------|--------------|
| 2 | Failing test: a dependent effect is shown before approve is reachable. | `a dependent effect is rendered before the approve control is reachable` — passes; the partial-release block AND the `queue-acts-dependent` paragraph both appear BEFORE the act bar in DOM order, and the dependent's name appears in both places. |
| 3 | Failing test: releasing a prerequisite does not release its dependent. | `releasing a prerequisite does not release its dependent` — passes; the Approve button is relabeled "Release Add the new signing entry point; Add the matching key-parsing path", the dependent's name appears in the paragraph above the bar but NOT in the button label, and the paragraph says "Run the new signer tests… will stay staged until its prerequisite(s) are released." |
| 4 | Failing test: the preview distinguishes reversible from irreversible. | `the partial-release preview distinguishes reversible from irreversible` — passes; the irreversible fixture renders `1 of the releasable effect(s) are irreversible — once approved, they cannot be undone by a settle or a void.`, and the dependency sentence renders beside it. The scope preview above the act bar carries the same irreversible sentence. |
| 5 | Plain-language scope rendering, asserted for reading level. | `the scope preview recites the warrant goal and the proposed-effect summaries` — passes; the preview reads "You are being asked to release: Open a pull request titled \"Fix auth\" against main; Rewrite the refresh-token rotation to use the new signer. The warrant's goal is \"coordinate a one-week auth refactor across the runtime,\nthe desktop, and the console\"." |
| Plus | Empty-releasable edge case. | `a row whose releasable set is empty disables the Approve button` — passes; an act button labeled "Release nothing — no prerequisite is releasable" is rendered with `disabled = true`. |
| Plus | No-dep baseline. | `a warrant with no dependency renders an empty dependency sentence` — passes; the baseline queue's preview carries no `queue-scope-dependency` child, and the Approve button keeps the standard label. |

## Test count

`node --test rust/warrant/src/console/console.test.js` — 155/155 green.

- Before this task (head `1a59e13`): 149.
- After this task: 155.
- Net change: +6 (six new Task-11.5 tests).

The console test count is strictly greater, per the phase-wide constraint.

## US-English gate

`node M:/Project\ AumOS\ -\ Linkedin\ Blitzkrieg/scripts/verify-us-english.mjs` against the three touched files reports 8 Britishisms in the working tree. Of those, 0 fall in lines added by this task. The remaining 8 are pre-existing (git blame: Vikram Jha 2026-08-13/14 and AumOS Wave-1 2026-08-17). The queue-fixtures file ships clean (0 findings). The two Britishisms I added (`judgement` x 2 in comments) are fixed to `judgment`.

## Three-tier rule (no collapse)

The reversibility marker is not a tier — it is its own signal, rendered in its own paragraph beside the dependency sentence rather than inside the tier pill. A releasable set that is wholly reversible renders "Every releasable effect is reversible — a settle or a void would undo it." A set with one or more irreversible effects renders "N of the releasable effect(s) are irreversible — once approved, they cannot be undone by a settle or a void." The console composes no judgement about reversibility — `irreversible_count` comes from the server.

## Scope-preview discipline

The preview recites three server fields verbatim: `proposed_effects[].summary` (joined with `;`), `authority_chain[0].goal` (the root grant's goal, not the leaf's), and `partial_release.{reason, irreversible_count}` when present. The console composes no judgement — the join is a separator, not a paraphrase. The preview is the FIRST block in the row, before the proposed effects, the authority chain, the prior receipts, the timeout, and the partial-release block. A reader who reads only the preview and the act-bar label still knows what is being asked.

## What this pane is NOT

Not the queue itself — Task 4.1. Not the approval-quality instrumentation — Task 11.6. Not the policy studio — Task 11.3. The pane extends an existing queue row with a plain-language scope preview and a dependency-aware act-bar; it does not build a new queue, instrument approval quality, or compose policy content. Each of those is a separate task in this phase.