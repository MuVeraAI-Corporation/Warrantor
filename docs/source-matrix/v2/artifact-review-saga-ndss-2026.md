# SAGA NDSS 2026 artifact review

Status: pinned artifact partially reproduced; design prior art confirmed; strict request-count enforcement contradicted  
Reviewed: 2026-08-30  
Paper: <https://www.ndss-symposium.org/ndss-paper/saga-a-security-architecture-for-governing-ai-agentic-systems/>  
Repository: <https://github.com/gsiros/saga>  
Pinned commit: `7372111bea150e32cee390a616849316d2780bfc`  
Pinned commit date: 2026-05-18  
Package version: `1.0.1`  
Repository license file: Apache-2.0

## Decision

**Adopt SAGA as essential design and research prior art; reject its reviewed quota-consumption and
contact-policy implementations as Warrantor enforcement code.** The paper and repository establish
strong prior art for user-governed agent registration, inter-agent authorization, encrypted tokens,
recipient binding, expiry, request quotas, provider architecture and scoped symbolic analysis. They
invalidate any claim that agent-specific count-bounded authorization has not been designed or
implemented at all.

They do not establish a strict bounded-revocation service-level guarantee. A controlled concurrent
check reproduced a time-of-check/time-of-use race that admitted two requests from a token whose
remaining quota was one. A second controlled check showed that contact-policy results depend on
rule order rather than the documented most-specific-match rule. The formal models cover selected
secrecy and authentication queries, not concurrent quota consumption, policy-selection correctness,
durable revocation, partition behavior, complete mediation or residual downstream effects.

Warrantor should consume the architectural ideas and use SAGA as a differential baseline, while
owning a linearizable, durable, idempotent check-and-consume operation at every authoritative
enforcement point.

## Reproduction receipt

The public repository was cloned and pinned without modifying its source. The bounded review used
controlled local checks rather than a full CA, Provider, MongoDB, TLS and LLM deployment. This
avoided treating a demo topology as production evidence and avoided the repository's destructive
seed path, which drops the configured tools database.

| Surface | Result | Interpretation |
|---|---:|---|
| Python syntax compilation | Passed | The checked Python tree compiled in the controlled environment |
| Token encryption/decryption | Passed | A generated token round-tripped with nonce, future expiry, quota and recipient binding intact |
| Negative token checks | Passed | Unknown token, wrong recipient, zero quota and expired token were rejected in the controlled path |
| Contact-policy validity | Partially passed | Invalid negative budget was rejected; policy-selection order independence failed |
| Contact-policy specificity | **Failed** | The same specific and wildcard rules returned different budgets when order was reversed |
| Concurrent quota consume | **Failed** | Two threads were accepted from initial quota 1; final stored quota was 0 |
| Current Verifpal 1.3.6 | **Failed to parse** | `G` is now reserved; the repository model uses legacy syntax |
| Flake-era Verifpal 0.27.4 | Inconclusive | Parsed and exceeded 78,000 analysis steps; terminated after massive expansion without a proof result |
| ProVerif models | Not reproduced | ProVerif/Nix were unavailable in the controlled environment; embedded author output was inspected only |
| Full distributed deployment | Not executed | MongoDB, CA, Provider, TLS, agent and failure/partition behavior remain unverified |
| Native automated test suite | Not found | The only `experiments/test.py` is an interactive/demo script; CI builds documentation only |

The Verifpal termination is a bounded non-result. It neither confirms nor refutes the modeled
properties. The repository itself warns that its Verifpal models take an extremely long time under
an active attacker.

## Reproduced positive path

The controlled token path confirmed that the implementation can:

- generate an encrypted token containing a nonce, issuance time, expiry, configured quota and
  recipient public-access-control key;
- decrypt the token with the derived symmetric key;
- reject an unknown token, expired token, zero-quota token and recipient-key mismatch; and
- apply simple contact-policy rules when their file order happens to align with intended precedence.

These are valuable implementation signals. They do not convert separate validation and mutation
steps into an atomic security guarantee.

## Strict quota failure

The receiver validates and consumes quota in two separate critical sections:

1. `token_is_valid` acquires `active_tokens_lock`, reads the remaining quota, rejects only zero, and
   releases the lock after returning `True`.
2. `receive_conversation` later reacquires the same lock and decrements the quota with a floor of
   zero.

A deterministic two-thread schedule placed a barrier between those operations. Both threads
validated the same token while its quota was one; both then decremented and were accepted. The
recorded result was:

```text
QUOTA_RACE REPRODUCED accepted=2 initial_quota=1 final_quota=0
```

This is a controlled method-level reproduction of the implementation's actual validation and
decrement sequence, not a full socket/TLS/Mongo end-to-end exploit. It is sufficient to show that
the reviewed code does not make “at most Q accepted requests” a linearizable invariant under
concurrent sessions.

The same check/decrement structure is copied into the repository's adversary and benign experiment
variants, so this is not isolated to one unused helper.

## Contact-policy selection failure

The matcher documents that the budget belonging to the most specific matching pattern is returned.
It initializes `best_pattern` but never assigns the selected pattern to it. Every matching rule is
therefore compared against `None`, and the last matching rule wins. A controlled reversal produced:

```text
specific_first 50
specific_last 1
```

The rules and target were otherwise identical: a specific rule allowed one request and a wildcard
allowed fifty. Policy order is therefore security-significant in the reviewed implementation even
though the documented semantics say specificity should determine precedence.

## Formal-model boundary

The repository includes ProVerif and Verifpal models for registration and agent communication. The
ProVerif queries cover reachability, selected event correspondences, token secrecy and
authentication. They do not model:

- the mutable Python quota dictionary or atomic check-and-consume;
- concurrent conversations sharing one token;
- contact-policy matching or rule precedence;
- durable state, process restart, replication, failover or network partitions;
- release-consistency or maximum propagation time after revocation;
- tool, child-process or network-path complete mediation; or
- the number of downstream effects caused by one accepted protocol message.

The flake lock pins Nixpkgs commit `c2a03962b8e24e669fb37b7df10e7c79531ff1a4`,
which supplied Verifpal 0.27.4 during the reviewed period. Current Verifpal 1.3.6 rejects the model's
`G` constant syntax. The old version parsed but did not complete in the bounded run. The proof README
also gives `agent_communication.vp` to ProVerif even though the ProVerif model is the `.pv` file.

Author-reported ProVerif results remain useful paper evidence, but this review does not relabel them
as independently reproduced.

## Operational and reproducibility boundaries

| Boundary | Finding |
|---|---|
| Runtime state | Active and received token quotas are process-local dictionaries; restart and multi-instance consistency are unspecified |
| Dependency resolution | Runtime dependencies are lower bounds plus a live Git repository; `requirements.txt` and `setup.py` differ |
| Test automation | No unit/integration suite or security CI was located at the pinned commit |
| Data safety | The example seed script drops the configured tools database; the README now requires an isolated MongoDB deployment |
| License metadata | The repository license is Apache-2.0 while `setup.py` still declares the MIT classifier |
| Full failure semantics | Provider outage, registry inconsistency, stale tokens, replay across replicas and recovery were not reproduced |
| End-to-end effects | One accepted message may cause multiple model/tool/network actions; request count is not an effect count |

## Warrantor actions

### Adopt

- SAGA as the essential W6 and bounded-authorization comparator;
- explicit recipient binding, expiry and count-budget concepts;
- separation of user, provider, registry and agent roles;
- formal threat-model and protocol-query discipline; and
- SAGA's adversary scenarios as inputs to the invariant attack corpus.

### Modify

- implement one atomic `authorize_and_consume(token, operation_id, request_digest)` transaction;
- use durable, replicated state with an explicitly chosen consistency level and partition behavior;
- require an idempotency key so retries cannot consume twice or execute twice;
- bind one consumption decision to the immutable operation and its enforcement receipt;
- define precedence independently of policy serialization order and test every permutation;
- distinguish message count, tool-call count and externally observable effect count;
- expose propagation latency and residual accepted effects as measurable service-level indicators;
- add restart, failover, partition, replay, duplicate, cancellation and stale-session vectors; and
- connect formal state transitions to the production function that commits the enforcement decision.

### Reject

- reusing SAGA's separate check-then-decrement sequence;
- treating a process-local quota dictionary as a distributed revocation SLA;
- claiming that the symbolic model proves quota, policy-selection or release-consistency behavior;
- claiming request count bounds every downstream action or effect; and
- marketing “no open-source bounded authorization exists.”

## Claim decision

Repository claim `CLM-0007` is changed from **challenged** to **unresolved**.

- The broad absence of agent-specific execution-count authorization is contradicted at the design
  level by SAGA.
- The narrower absence of an open-source, measured, release-consistent bounded-revocation SLA is
  not disproved by the reviewed SAGA implementation.
- The reviewed evidence also cannot prove universal nonexistence.

The defensible Warrantor statement is: **SAGA is strong peer-reviewed design prior art for
count-and-expiry-bounded agent authorization, while Warrantor's proposed differentiation is an
independently measured, atomic, durable residual-action and propagation guarantee across all
authoritative enforcement points.**

## Remaining gates

1. Reproduce both ProVerif models with the exact pinned Nix environment and preserve machine-readable
   output, wall time and tool versions.
2. Patch only the Verifpal syntax needed for current compatibility, then determine whether the
   resulting model is semantically equivalent and tractable.
3. Run a clean isolated full deployment with concurrent sessions, multiple receiver/provider
   instances, crash/restart and partitions.
4. Test token replay, token sharing, key rotation, stale provider data, quota exhaustion, duplicate
   messages and downstream multi-effect amplification.
5. Compare SAGA with CAEP/SSF, transaction tokens, distributed leases, Zanzibar-style consistency
   tokens and Warrantor's exact W6 state machine.

## Quality adjustment

SAGA remains **essential (90/100)** because NDSS peer review, explicit threat modeling, open code,
formal models, systems evaluation and exceptional Warrantor relevance outweigh the artifact
defects. Reproducibility is reduced from 9/10 to 6/10 because the repository lacks a native automated
test suite, current Verifpal compatibility fails, bounded historical Verifpal analysis did not
terminate, and the two reviewed authorization semantics fail controlled negative tests.
