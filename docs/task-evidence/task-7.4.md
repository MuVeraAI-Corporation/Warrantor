# Task 7.4 — Adapters: cloud control plane, CI/CD and identity providers (L4-13, L4-14, L4-26)

Branch `feat/adapters-substrate-mutating`, worktree `M:/wt-7.4`, cut from `main` at `ebe1d62` on
2026-09-06, after Task 7.1's SDK merged that morning. The plan groups these three and routes them
away from volume work for one reason: each is a `MUTATE`-class surface that can rewrite the
substrate governing it. **An agent with any of these governs its own governor.** What this task
ships is the one predicate all three refuse through, the three adapters as the governance shape
Tasks 7.3 and 7.5 will transcribe onto real services, and the product sentence that names what
escapes.

| commit | what |
|---|---|
| (this branch, one commit) | `rust/warrant/src/adapters/substrate.rs` (new, the predicate and the three adapters), `rust/warrant/src/adapters/mod.rs` (one `pub mod` line), `rust/warrant/tests/adapters_substrate.rs` (new, 10 tests), `docs/W1-delivery-gaps.md` (section 3.1e), this file |

## The exit gate, quoted verbatim from the plan

> **Exit gate.** For each of the three, a test proves an effect that would modify Warrantor's own
> policy, workflow or entitlements is refused, **and** a control effect of the same class against
> an unrelated resource is allowed — a refusal that refuses everything proves nothing.

## Status of that gate: RUN

Three tests, one per adapter, each carrying its refusal and its control in the same function so
that neither can pass without the other:

| adapter | refused | control, allowed (staged) |
|---|---|---|
| cloud control plane | `apply_network_policy` on `warrantor-egress-floor`, the policy declared as the one that authorized the warrant | the same tool on `team-b-ingress` |
| CI/CD | `edit_workflow` on `.github/workflows/ci.yml`, declared as the gate workflow | the same tool on `docs-preview.yml`; and `trigger_run` on `ci.yml` itself, because running the gates is the opposite of escaping them |
| identity provider | `grant_entitlement` of `ent_warrantor_runner`, the entitlement the session used, to anyone; and of anything to `svc:warrantor-agent`, the session's own principal | the same tool granting `ent_billing_read` to `user:alice` |

The CI/CD control is the one that separates a predicate from a blanket refusal: a rule that refused
anything naming `ci.yml` would fail it.

## Step 0 — what existed, measured

| Fact | Value |
|---|---|
| Task 7.1's `EffectAdapter` contract | on `main` since `18276c3` this morning; transcribed, not restated |
| Task 3.7's self-protection predicate | does not exist. Task 3.7 has not started. The plan names it as this task's first real consumer; there is nothing to consume, so this task defines its own predicate narrowly (see *Deviations*) |
| `rust/self-governance/src/lib.rs` | 506 lines. A conformance **checker**: its header says enforcement happens when the platform's own agents call through the brokers. `grep -c "refuse\|Refuse"` on the file returns 0. It refuses nothing, at no tier |
| How adapters are dispatched today | `rust/warrant/src/adapters/github.rs` exists with a transport trait, wired to the settle path. `grep -rn "EffectAdapter\|effect_sdk::" rust/warrant/src/bin` returns nothing: no code in the shipping binary constructs or dispatches an SDK adapter |

## What the tests establish

- **Step 2, 3, 4** — the three refusal-plus-control tests above, all through the public
  `EffectAdapter::invoke` surface with a grant built from the adapter's own declared syscalls.
- **Undeclared is refused, not guessed.** An empty `OwnSubstrate` refuses every substrate-mutating
  effect with a sentence saying nothing was declared; with a substrate declared, the same target is
  not refused. An adapter that cannot tell what is its own may not find out by doing it.
- **A mutation with no named target is refused, never defaulted.** A missing or empty
  `policy_name` is a refusal that names the argument.
- **The refusal sentence is derived from the record.** `SelfGovernanceRefusal::render` is built
  from the `target` and `matched` fields the predicate returned, and the test asserts both appear
  in it.
- **A failed read is a refusal and not a receipt.** A transport that cannot answer produces
  `Refused`, never `Performed`; a working transport produces `Performed`.
- **Step 5** — all three adapters pass the Task 7.1 conformance kit: every tool declared in the
  registry, every decomposition equal to the registry's verb for verb, no planted sentinel in
  anything returned. The registry is the test's own literal, so the match is between two
  independent statements.
- **Step 6** — every mutating tool decomposes to `MUTATE`; `grant_entitlement` also to `CRED`,
  because an entitlement change is a credential change; every verb is one of Task 2.1's nine; the
  read tools carry neither `MUTATE` nor `CRED` (the control).
- **Step 7** — `SHELL_BYPASS_SENTENCE` names the shell-and-CLI bypass, the call-site scope, and
  the absence of a shipping dispatcher, and contains no "Enforced".

## Decompositions declared, against Task 2.1's vocabulary

| tool | syscalls |
|---|---|
| `cloud.apply_network_policy` | `net + mutate` |
| `cloud.describe_policy` | `net` |
| `cicd.edit_workflow` | `net + mutate` |
| `cicd.trigger_run` | `net + exec` |
| `cicd.read_workflow` | `net` |
| `idp.grant_entitlement` | `net + cred + mutate` |
| `idp.list_entitlements` | `net` |

## The honest tier of every bound this task introduces

| what | tier | why not a stronger word, and what escapes |
|---|---|---|
| the self-governance refusal, *when dispatched* | **Mediated (Tier B)** | a refusal at the adapter's own call site, before anything is staged. Escapes: any agent with a shell and the cloud, CI or IdP command line, which never passes through an adapter; and anything the declared `OwnSubstrate` omits, because the predicate matches declarations |
| the same refusal, as shipped | **no tier — no shipping caller** | nothing in the binary dispatches an `EffectAdapter` (verified by grep). This is the same state 3.1c and 3.1d record for the SDK and for computer use. It becomes Mediated when the settle path dispatches adapters, not before |
| staged mutations | **not performed here** | a `MUTATE` returns a settle handle. No adapter here talks to a cloud, a CI system or an identity provider; reads go through a caller-supplied transport, and no transport ships |
| `OwnSubstrate` | **a declaration** | it constrains nothing by itself; it is what the predicate matches against, and its omissions are the predicate's blind spots |

Nothing in this task is Enforced.

## What this task does NOT establish

1. **No real control plane, CI system or identity provider is bound.** L4-13, L4-14 and L4-26
   each require the refusal to bind a real call to a real service; all three stay `status=none`.
2. **Nothing dispatches these adapters.** The refusal is tested through the SDK surface and
   reached by no shipping path.
3. **The predicate's coverage is its declaration's coverage.** A policy, workflow or principal the
   caller did not declare is not protected. That is the design, and it is the escape the tier
   table names.
4. **The Kubernetes admission half of L4-25** stays unshipped, as Task 7.1 already recorded.

## Deviations from the plan

- **Task 3.7's predicate is consumed nowhere because it exists nowhere.** Step 0 requires
  recording which self-protection predicate 3.7 produces; 3.7 has not started. This task defines
  `governs_its_own_governor` itself over the three targets these adapters can reach. When 3.7
  lands it generalizes this predicate; the direction of dependency is recorded so the two are not
  built twice.
- **`rust/self-governance/src/lib.rs` is not modified.** The plan lists it under Files. It is a
  conformance checker that refuses nothing, and adding a refusal there would put the predicate in
  an orphan crate (it is one of the 28) where nothing could reach it. The predicate lives in the
  reachable crate beside the adapters that apply it, which is Task 7.1's Finding 4 applied again.
- **Mutations are staged, not performed.** The plan's tests are about refusal versus allowance;
  "allowed" here is `Staged`, the staging doctrine's handle, because performing a `MUTATE` in an
  adapter with no transport and no credential would be a claim with nothing behind it.

## Gate on the branch tip, exit codes captured before any pipe

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | 0 |
| `cargo test -p warrantor-warrant --test adapters_substrate` | 0; `10 passed; 0 failed` |
| `cargo clippy -p warrantor-warrant --all-targets -- -D warnings` | 0 |
| `cargo doc -p warrantor-warrant --no-deps` | 0. Nine unresolved-link warnings, all in files this task does not touch (`corpus.rs`, `guard.rs`, `serve.rs`, `egress.rs`, `mcp.rs`, `store.rs`), the same nine present on `main` |
| `check_docs.py` | PASS, 303 Markdown files |
| `check_us_english.py --files` on the gaps document and both Rust files | ok |

The full workspace run is the merge's, on the merged tree.

## Mutations run against the tests, with their outcomes

Each applied to `substrate.rs`, run, then restored and verified by sha256 (`ea4585f14e2e3d99`
before and after every one).

| mutation | expected | observed |
|---|---|---|
| the predicate never refuses (`return None` first) | every refusal test RED, every control green | `5 passed; 5 failed`: the three adapter tests, the undeclared-substrate test, and the derived-sentence test went red |
| the predicate always refuses | every control RED | `6 passed; 4 failed`: the three adapter tests went red on their controls, and the undeclared-substrate test went red on its own control, which asserts a declared substrate does not refuse an unrelated target |
| `trigger_run` routed through the predicate | the "running the gates is allowed" assertion RED | `9 passed; 1 failed`: only the CI/CD test, on that assertion |
| a missing target defaulted to `""` instead of refused | the no-named-target test RED | `9 passed; 1 failed`: only that test |

The second row is the one that proves the controls are not decoration: a predicate that refuses
everything satisfies every refusal assertion and fails four tests anyway.
