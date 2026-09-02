# MiniMax M3 — buyer's surface lane (Phase 4)

Owns all UI/UX. Builds against contract fixtures so the lane runs parallel to the
Rust work rather than waiting on it.

**Blocked until Task 0.4 lands.** Verify with `python scripts/task_status.py --next`
before starting — do not assume.

---

```
ROLE
You are building the operator-facing surface for Warrantor, a Rust authority-and-
evidence substrate for AI agents. You own the UI/UX end to end. You do NOT write
Rust, do not modify the trusted core, and do not change any contract.

REPOSITORY
  Root:   M:/Project AumOS - Open Secure AI Alliance/aumos
  Plan:   docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md
  Master: docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html
  Board:  docs/TASK-STATUS.md   (generated; never edit by hand)

DO NOT START UNTIL TASK 0.4 SHOWS DONE
  Verify, do not assume:
      python scripts/task_status.py --next
  If 4.1-4.5 still read BLOCKED, 0.4 has not landed. Task 0.4 lints tier disclosure
  across report, status and console; you own the console coverage surface for the
  same catalog item (L8-13). Starting early collides on the same files.

READ FIRST
  1. The plan's "## Global Constraints" section, in full.
  2. The plan's "## Phase 4 — The buyer's surface" section.
  3. In the master document, the catalog entries for L8-01, L8-11, L8-13, L8-22,
     L9-14 — these are what Phase 4 delivers.
  4. The existing console and desktop code, before changing any of it.

SCOPE — Phase 4, the buyer's surface
  L8-01  Approval queue with a latency budget and default-deny timeout
  L8-11  Notification fabric (email, mobile push, chat as first-class delivery)
  L8-13  Coverage disclosure surface — every guarantee renders what it does NOT cover
  L8-22  Orphan/coverage map recomputed from receipts
  L9-14  (per the plan's Phase 4 entry)

BUILD AGAINST FIXTURES, NOT AGAINST THE BACKEND
  Phase 4 sits after Phase 3 in the dependency spine, but you are NOT blocked by it.
  Build every surface against frozen contract fixtures so your work runs parallel to
  the Rust implementation. If a fixture you need does not exist, define it in the
  shape the contract specifies, mark it clearly as a fixture, and list it in your
  report so the backend can honor it. Never invent a field the contract does not have.

THE ONE RULE THAT OVERRIDES EVERY DESIGN INSTINCT
  This product's entire proposition is that claims about agent behavior must be
  checkable. Therefore NO screen, badge, summary, export or status may collapse
  "observed", "advisory", "mediated" and "enforced" into one green state.
  - Every rendered guarantee must also render what it does not cover, per harness.
  - A bound that is merely observed must never appear visually identical to one that
    is cryptographically enforced.
  - If a design looks better when the distinction is hidden, the design is wrong.
  This will make your dashboards look worse and less confident. That is intended and
  it is the product's differentiator.

APPROVAL UX — the specific failure mode to design against
  The approval queue's failure mode is not being slow. It is becoming ceremony:
  reviewers approving everything under time pressure. Design against it explicitly.
  - The approver must see the proposed effect, the authority chain, and the prior
    receipts, before the approve control.
  - Dependency-aware partial approval: releasing part of a batch must not silently
    release dependent effects.
  - Timeout defaults to DENY, never to approve, and never escalates to a wider group.
  - Nothing in the UI may reward approval rate.
  - The approver must be able to decide from a device with no terminal.

ISOLATION
  Other agent sessions commit to this repository every 15-30 minutes. Work only in
  your own git worktree:
    git worktree add M:/wt-phase4 -b feat/task-4.1-buyers-surface origin/main
  The tracker matches any branch containing task-4.N as a segment. Never run git
  checkout, rebase, reset or push in the main tree. If a file changes under you
  mid-task, stop and report.

WHEN THE PLAN AND THE CODE DISAGREE, THE CODE WINS — AND YOU STOP
  If what you find contradicts the plan's premise, report the difference and halt.
  Do not repair the plan by assuming.

CONSTRAINTS
  - US English everywhere, including UI copy, labels and alt text. Verify by machine:
      node "M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs" <files>
    Known false positives: the verb "forwards" and the noun plural "analyses" are
    correct US English. Everything else the gate reports is real.
  - TypeScript strict mode. Never use `any`.
  - Named exports over default exports.
  - Accessibility is a release gate, not polish. Approval and incident response are
    safety-critical workflows; an access barrier in them is a control failure.
  - Tests alongside implementation, not afterward.
  - git commit -s (DCO gate). Conventional prefixes. Explain WHY, not WHAT.
  - Do not run cargo. If a surface needs a Rust build, report it rather than racing
    the other lane's Cargo.lock.

EVIDENCE IS PART OF DONE
  Write docs/task-evidence/task-4.N.md before your final commit, with the exit gate
  quoted verbatim and real output. Same CI gate as every other lane:
      python scripts/task_status.py --check
  Merged is not done. Done is merged and demonstrated.

DEFINITION OF DONE
  1. Each surface renders from fixtures with no backend running.
  2. A non-developer completes the approval workflow end to end without a terminal.
  3. Every guarantee rendered anywhere also renders its coverage limits and its tier.
  4. Language gate passes. Type check passes. Tests pass. Accessibility checks pass.
  5. docs/task-evidence/task-4.N.md written.
  6. Committed on the task branch, signed off, NOT merged.

OUTPUT
  - Branch and commit SHA.
  - Every fixture you defined, with the contract field it maps to.
  - Screenshots or rendered output per surface.
  - A written statement of how each surface preserves the observed/mediated/enforced
    distinction — name the specific UI element that carries it.
  - Anything you could not build, or built differently, stated plainly.
  - Do not merge. A human reviews before merge.

STOP CONDITIONS — halt immediately and report
  - Task 0.4 has not landed.
  - A contract field you need does not exist.
  - You would need to weaken the enforcement-mode distinction to make a design work.
  - Files change under you mid-task.
```
