# Human Verification Pack — T-12 headline rows

**Generated 2026-08-30 from the stored coding files. For SaTML 2027, abstract 22 September.**

> **What this is for.** The paper discloses that coding was performed by LLM agents (§3.5.2).
> That disclosure is honest but it is not sufficient for the rows that carry findings. These
> **nine works** carry every headline claim in the paper. Verifying them against the quoted
> spans below is the difference between a method a reviewer tolerates and one they trust.

**How to use it.** For each work: read the quoted span, decide whether it supports the scored
tier, and mark the row. You are not re-reading the papers — you are checking that the span
says what the coder claims it says, and that the tier follows. **If a span does not support
its verdict, that is a finding, not a failure.**

Estimated **4–6 hours**. The nine rows below are ordered by how much damage an error would do.

**Marking:** `CONFIRMED` · `CORRECTED → <new verdict>` · `UNSUPPORTED — span does not carry it`
· `NEEDS SOURCE — must re-read the paper`

---

## 1. PAuth — `arXiv:2603.17170`

**Two-column verdict:** `A-T1 / B-T1`

**Why this row matters:** The ONLY work bounding an action cryptographically, and it does so topologically. If this is wrong the 'one work is both' claim falls.

### Conservative coder

- **Advertised:** The paper describes its enforcement strength as 'Precise means that the mechanism gives sufficient authorization for the agent to faithfully complete the task, and prevents it from performing any action that deviates from faithful execution. After task completion, there is no residual permission left.' and frames the goal as: 'Solving this problem essentially means that the servers can jointly ens
- **Scored (single column):** T3
- **Cheapest defeat:** WORKING THE TIER EXPLICITLY. (1) The guarantee: no operation inconsistent with the task-derived slice is executed. (2) The mechanism that must fail: the per-call admissibility check performed at the point where the concrete call is intercepted. (3) The cheapest adversary action causing that failure: reach the effect through any path that is not a declared tool call passing through that interception point. No signature forgery is required and no key is needed. In the evaluated build the interposition point is an in-process enforcer sitting between the agent and a fixed table of local Python fun
- **Full text retrieved:** True

**Quoted span — the thing to check:**

> The agent's tool calls are proxied through the enforcer (B1-B2), which matches each concrete call against the precompiled rules and, when needed, consults envelopes that are returned from previous computations.

- **Schneider:** split · surrogate: A per-call, default-deny admissibility predicate over a single concrete tool call: the operator must appear in allowed_calls, every operand at position i must equal the slice expression arg_exprs[key][i] once concretized · objective: Two non-monitorable objectives are advertised on top of that surrogate. (a) 'Faithful execution' of the task by an untrusted agent - the paper claims the mechanism 'prevents it from performing any action that deviates fr

### Charitable coder

- **Advertised:** The paper frames the guarantee as cryptographic and conditional only on signature unforgeability. Abstract: 'server-produced values are wrapped in signed envelopes that bind concrete values to symbolic provenance'; 'submitting a concrete NL task implicitly authorizes exactly the operations its faithful execution requires, even when the agent is compromised'. Design section: 'The authorization is p
- **Scored (single column):** T1
- **Cheapest defeat:** WORKED EXPLICITLY. (1) The guarantee: a participating server accepts a tool call only if operator and every operand match a deterministically compiled rule derived from the user's signed task, with each derived operand backed by a signature-verified envelope chain. (2) The mechanism that must fail: RSA-PSS envelope signature verification binding concrete value to symbolic provenance to originating server, plus the user's signature on the task text, plus deterministic rule matching in the server-embedded middleware. Verbatim: 'It then checks the RSA-PSS signature on each envelope against the pr
- **Full text retrieved:** True

**Quoted span — the thing to check:**

> no sequence of agent actions can cause a server to accept a call whose operands are inconsistent with the computation implied by the user’s task, provided envelope signatures are unforgeable

- **Schneider:** split · surrogate: A per-call, pre-execution, default-deny consistency predicate enforced by a reference monitor embedded at each server's tool-dispatch layer: for the incoming call, some compiled rule must exist whose guard conjunction ho · objective: Faithful execution of the user's natural-language intent, with minimality of granted authority — 'submitting a concrete NL task implicitly authorizes exactly the operations its faithful execution requires' and 'The autho

**Your verdict:** `________________`  
**Note:** 

---

## 2. Sandlock — `arXiv:2605.26298`

**Two-column verdict:** `A-NONE / B-T2`

**Why this row matters:** The only work above T3 on action, and the only A-NONE. Anchors both ends of the gap argument.

### Conservative coder

- **Advertised:** "static, input-independent policy is compiled into kernel-enforced rules, while a narrow supervisor handles runtime-dependent decisions and virtualized effects"; the pipeline gives capability separation "enforced by the kernel rather than trusted to the LLM’s judgment"; and against prompt injection Sandlock "provides an unprivileged, kernel-enforced substrate on which the separated stages run". La
- **Scored (single column):** T2
- **Cheapest defeat:** Work entirely inside the granted policy; the kernel boundary is never touched. Two concrete routes. (1) Exfiltrate through an allowlisted endpoint. The endpoint allowlist is per-destination, not per-payload, and the paper itself states the gap: an agent that legitimately reaches api.openai.com:443 can carry attacker-chosen bytes to that same allowed IP. The intended answer (HTTP method/host/path rules) requires the workload to trust an injected sandbox CA; adversarial code simply speaks raw TLS to the allowlisted destination, and then, in the paper's own words, "TLS flows are governed only by 
- **Full text retrieved:** True

**Quoted span — the thing to check:**

> If a decision is known before execve, Sandlock compiles it into Landlock or seccomp-bpf so the kernel enforces it without supervisor involvement.

- **Schneider:** split · surrogate: A per-stage, kernel-enforced capability bound that is a genuine safety property and exactly what a reference monitor enforces: no filesystem operation outside the granted read/write path scope, no connect to a destinatio · objective: Prompt-injection resistance / the “lethal trifecta” objective the pipeline operator is motivated by: that private data reached by one stage does not flow to an external party, i.e. non-interference between a private-data

### Charitable coder

- **Advertised:** "static, input-independent policy is compiled into kernel-enforced rules, while a narrow supervisor handles runtime-dependent decisions and virtualized effects"; "Landlock (Salaün, 2017) provides the kernel-enforced “static” layer of policy"; "the capability separation a prompt-injection-resistant decomposition relies on is enforced by the kernel rather than trusted to the LLM’s judgment"; "an unp
- **Scored (single column):** T2
- **Cheapest defeat:** TIER WORK, EXPLICIT. (1) Guarantee: a confined process tree cannot read or write outside granted path prefixes, cannot reach a network endpoint outside the pinned allowlist, cannot exceed process/memory caps, and cannot escape confinement by forking or exec-ing. (2) Mechanism that must fail: the Landlock LSM domain plus the seccomp-bpf filter, both installed after PR_SET_NO_NEW_PRIVS and both inherited across fork() and execve(), together with the seccomp user-notification supervisor running in the trusted parent. (3) Cheapest adversary action: there is no in-sandbox software bypass on offer —
- **Full text retrieved:** True

**Quoted span — the thing to check:**

> Sandlock uses it for constraints whose verdict is independent of syscall-time data: filesystem read/write scope, TCP port scope, and IPC boundaries. When a rule can be expressed this way, common operations are denied or allowed by the kernel without involving the supervisor.

- **Schneider:** split · surrogate: A per-process-tree syscall-and-resource safety property enforced by an actual execution monitor: no open/read/write outside the granted path prefixes, no connect/send to an endpoint outside the pinned allowlist, no fork  · objective: Prompt-injection resistance via capability separation — that private data never reaches an externally-communicating component (the 'lethal trifecta'). That is an information-flow hyperproperty over multiple executions an

**Your verdict:** `________________`  
**Note:** 

---

## 3. TDX trusted plane — `arXiv:2605.06393`

**Two-column verdict:** `A-T3`

**Why this row matters:** THE NEGATIVE RESULT. Best-placed candidate fails to populate A-T1. Stated first in the paper, so it must be right.

### Conservative coder

- **Advertised:** "Trusted Execution Environments (TEEs) provide hardware-backed protection for selected code and data, enabling stronger confidentiality and integrity guarantees for security-critical logic"; the system is presented as a "cloud-native TEE-backed trusted operation plane" giving "a trustworthy control point for security-critical classification and enforcement", such that "A compromised REE can still 
- **Scored (single column):** T3
- **Cheapest defeat:** Guarantee: no security-critical host effect occurs without a trusted-plane authorization bound to the exact operation. Mechanism that must fail: the REE-side 'OpenClaw execution gate' / operation-extraction layer must observe the operation, AND the 'constrained executor' must be the only path to the resource. Cheapest adversary action: have the agent (or injected content steering it) issue one ordinary command that spawns a process which performs the write, exec or socket connection directly with normal syscalls inside the container - the gate is an application-level interceptor on the agent's
- **Full text retrieved:** True

**Quoted span — the thing to check:**

> Security-relevant tool calls are intercepted by the OpenClaw execution gate before they reach privileged host-side services.

- **Schneider:** split · surrogate: A per-operation pre-execution reference-monitor check: each extracted operation instance is mapped to a risk level and an enforcement decision (allow in REE / isolated authorization / isolated execution / user confirmati · objective: The advertised objective is broader than the surrogate: prevention of 'host-level abuse' where risk is defined to include "confidentiality loss", "the externalization of protected resources", and multi-step chains "whose

### Charitable coder

- **Advertised:** Hardware-backed trusted isolation, explicitly claimed as 'a trust boundary stronger than the ordinary REE'. The paper says 'Trusted Execution Environments (TEEs) provide hardware-backed protection for selected code and data, enabling stronger confidentiality and integrity guarantees for security-critical logic', and that the design is 'protecting security-critical classification, authorization, bi
- **Scored (single column):** T3
- **Cheapest defeat:** TIER WORKED EXPLICITLY. (1) The guarantee: no unsafe or policy-disallowed host operation executes without a matching, fresh, scope-bound authorization issued by the TDX trusted operation plane. (2) The mechanism that must fail: the REE-side interposition pair - the 'operation-extraction layer' / 'OpenClaw execution gate' that decides which activity becomes a trusted operation request at all, and the REE-side constrained executor that checks the returned authorization. Neither is inside TDX. TDX only ever evaluates the requests the gate chooses to build; it has no independent view of the host. 
- **Full text retrieved:** True

**Quoted span — the thing to check:**

> Security-relevant tool calls are intercepted by the OpenClaw execution gate before they reach privileged host-side services. The execution gate extracts the requested operation and normalizes it into a trusted operation request, which is then forwarded to the TDX-backed trusted operation plane.

- **Schneider:** split · surrogate: A per-operation, pre-execution safety property a reference monitor can enforce: no protected host resource is touched by a constrained executor unless the pending action matches a fresh, non-replayed, scope-bound authori · objective: The advertised objective is broader than the surrogate and is not a safety property. The effect projection is defined over 'confidentiality loss, integrity violation, availability impact, privilege or control amplificati

**Your verdict:** `________________`  
**Note:** 

---

## 4. Separation-of-Powers (PEA) — `arXiv:2604.23646`

**Two-column verdict:** `A-T1 / B-T3`

**Why this row matters:** Modal pattern instance. Advertises 'cryptographically constrained capability tokens'.

### Conservative coder

- **Advertised:** PEA decouples intent generation, authorization, and execution into independent layers connected via cryptographically constrained capability tokens. | This represents the same conceptual shift that mandatory access control represented in operating systems: from “processes should behave safely” to “the system enforces safety regardless of process behavior.”
- **Scored (single column):** T3
- **Cheapest defeat:** GUARANTEE: no side-effecting action executes without a valid Capability Token (T1), and every executed action is capability-bounded by the authorizing intent (T5). MECHANISM THAT MUST FAIL: the in-process Execution-layer dispatch gate that checks the token before performing the effect. CHEAPEST ADVERSARY ACTION: reach the effect through any code path that never calls that dispatcher -- a tool implementation, plugin, library call, or child process that opens the file, socket, or exec directly. No signature forgery, no key theft, no HMAC break is needed; the crypto binds only what the dispatcher
- **Full text retrieved:** True

**Quoted span — the thing to check:**

> Create an alternative execution path bypassing the Authorization layer (Assumption A3: no bypass path exists).

- **Schneider:** split · surrogate: A per-step reference monitor over a typed intent stream: schema/type checking of the Policy IR (T4), a deterministic IVL table lookup against MinimalCapSet (T5), an equality check on the SHA-256 NLR anchor plus a thresho · objective: 'Goal Integrity' as advertised -- that executed behavior actually serves the user's originating goal and is free of coercion, blackmail, and unauthorized disclosure. That is not a safety property of a single execution: a

### Charitable coder

- **Advertised:** "PEA decouples intent generation, authorization, and execution into independent layers connected via cryptographically constrained capability tokens." / "structural enforcement converts the AI safety problem from a probabilistic behavioral question into a conditionally sound system property" / "the same conceptual shift that mandatory access control represented in operating systems: from 'agents s
- **Scored (single column):** T3
- **Cheapest defeat:** Worked explicitly. (1) The guarantee: no side-effecting action occurs without a valid signed capability token whose capability lies in MinimalCapSet, and no output is delivered without passing the OSG. (2) The mechanism that must fail: not the HMAC-SHA256 signature, but the Execution layer's in-process dispatch gate - "Execution Layer: validates tokens and dispatches approved actions. Policy-agnostic and decision-minimal: it executes what a valid token authorizes, nothing more." Non-bypassability of that gate is asserted, not built: it is Assumption A3, and the T1 proof rests entirely on it ("
- **Full text retrieved:** True

**Quoted span — the thing to check:**

> Create an alternative execution path bypassing the Authorization layer (Assumption A3: no bypass path exists).

- **Schneider:** split · surrogate: A per-action reference-monitor safety property a monitor can enforce: no state-changing transition occurs unless the actor presents an unexpired, unredeemed, correctly signed capability token whose (L1,L2,L3) triple is a · objective: 'Goal Integrity' as advertised - that executed actions are semantically faithful to the user's originating intent and that outputs carry no implicit coercion or unauthorized disclosure. Not enforceable in Schneider's sen

**Your verdict:** `________________`  
**Note:** 

---

## 5. AIP — `arXiv:2603.24775`

**Two-column verdict:** `A-T1 / B-T3`

**Why this row matters:** Modal pattern instance. Invocation-bound capability tokens.

### Conservative coder

- **Advertised:** "Scope attenuation is cryptographically enforced: a delegation block that attempts to widen any capability beyond its parent block fails verification." (Sec. 3.2) and "This is a cryptographic guarantee, not a runtime policy." (Sec. 6, malicious delegatee). Also "Adversarial evaluation across 600 attack attempts shows 100% rejection" (Abstract).
- **Scored (single column):** T3
- **Cheapest defeat:** Work the tier explicitly. GUARANTEE: no action outside the granted, attenuated scope is performed, and every action is recorded in the delegation chain. MECHANISM THAT MUST FAIL: the AIP verifier sitting in MCP-server / A2A-receiver / HTTP middleware, which extracts the X-AIP-Token (or Authorization: AIP) header, resolves the identity document, checks Ed25519 signatures and evaluates the Datalog checks. CHEAPEST ADVERSARY ACTION: do not send the request through that middleware at all -- have the agent (or any subprocess, sub-shell, library or descendant it spawns) call the tool's underlying HT
- **Full text retrieved:** True

**Quoted span — the thing to check:**

> AIP assumes the verifier is trusted and correctly implemented. Verifier compliance is an operational concern addressed through conformance testing and reference implementations, not a property the protocol can enforce cryptographically.

- **Schneider:** split · surrogate: A per-request access-control safety property enforceable by a reference monitor at the verifier: reject any request whose presented token chain fails Ed25519 signature verification on any block, whose delegation blocks a · objective: The advertised objective is provenance/accountability -- that a completed IBCT truthfully answers "Who authorized this action? Through which agents did the delegation flow? What constraints applied at each hop? What was 

### Charitable coder

- **Advertised:** "Scope attenuation is cryptographically enforced: a delegation block that attempts to widen any capability beyond its parent block fails verification." and, in the threat model, "This is a cryptographic guarantee, not a runtime policy." The evaluation is reported as "AIP rejected 600/600 attack attempts across all six categories."
- **Scored (single column):** T3
- **Cheapest defeat:** Tier reasoning worked explicitly. GUARANTEE: an agent cannot exercise authority beyond the scope/budget/depth/expiry its token chain carries. MECHANISM THAT MUST FAIL: the resource-side AIP verifier -- the MCP server middleware that extracts X-AIP-Token, resolves the identity document, checks Ed25519 signatures and runs the Datalog authorizer. CHEAPEST ADVERSARY ACTION: not forging a signature (Ed25519 forgery is infeasible, so the cryptographic layer holds on its own terms) but reaching the effector by a path that never presents a token to an AIP verifier -- calling one of the unauthenticated
- **Full text retrieved:** True

**Quoted span — the thing to check:**

> A verifier that skips signature checks, ignores policy evaluation, or accepts expired tokens can grant unauthorized access. AIP assumes the verifier is trusted and correctly implemented. Verifier compliance is an operational concern addressed through conformance testing and reference implementations, not a property the protocol can enforce cryptographically.

- **Schneider:** split · surrogate: A monotone, monitorable safety property checked per invocation by a reference monitor (the AIP verifier): every block signature validates against a resolved identity document; each delegation block's scope, budget and ex · objective: Accountable provenance -- the advertised claim that a completed IBCT answers "Who authorized this action? Through which agents did the delegation flow? What constraints applied at each hop? What was the outcome? Was the 

**Your verdict:** `________________`  
**Note:** 

---

## 6. Heartbeat-Bound (HBHC) — `arXiv:2605.20704`

**Two-column verdict:** `A-T1 / B-T3`

**Why this row matters:** Modal pattern instance. Its coder split dissolved completely under the two columns.

### Conservative coder

- **Advertised:** The paper's own words: HBHC "blocks all calls at the cryptographic layer once the zombie window closes"; Table 8 is titled "Agent defense stack. HBHC provides identity-layer safety that cannot be bypassed by application-layer attacks" and scores HBHC "Bypass-proof: Yes"; "guardrails constrain what an aligned agent outputs; HBHC constrains whether a rogue agent can act"; the conclusion says of the 
- **Scored (single column):** T3
- **Cheapest defeat:** Worked explicitly. (1) GUARANTEE: after parent revocation, a descendant agent cannot perform privileged actions, because no verifier will accept its proof. (2) MECHANISM THAT MUST FAIL: the freshness check of Algorithm 3 must actually be reached on the path from the agent's intent to the effect. Reaching it depends on the deployment the paper specifies: "sub-agent runtimes attach the latest heartbeat to tool calls, and service endpoints add a freshness check after standard JWT validation" — i.e. an in-process wrapper around the agent's declared tool-call surface, plus opt-in server-side checks
- **Full text retrieved:** True

**Quoted span — the thing to check:**

> The same integration pattern, which wraps tool calls with a cryptographic auth check, works identically across LangChain-style, CrewAI-style, and OpenAI-SDK-style agent frameworks with 14–18 lines of code.

- **Schneider:** split · surrogate: MONITORABLE AND ACTUALLY ENFORCED: 'no HBHC-modified verifier accepts an authentication proof whose parent heartbeat epoch is older than Wmax by the verifier's local clock, whose heartbeat signature fails under the cache · objective: ADVERTISED BUT NOT MONITORABLE AT THAT INTERPOSITION POINT: 'once the operator stops the orchestrator, no descendant agent performs any privileged action after Wz' — stated as "HBHC constrains whether a rogue agent can a

### Charitable coder

- **Advertised:** "a cryptographic protocol that binds credential validity to periodic parent liveness proofs"; "Under HBHC the LLM still attempts to continue (the injection succeeds at the cognitive layer), but every tool call is blocked at the cryptographic layer: 0 successes, 10 denials"; Table 8 caption: "HBHC provides identity-layer safety that cannot be bypassed by application-layer attacks."; "HBHC closes it
- **Scored (single column):** T1
- **Cheapest defeat:** TIER WORK-THROUGH. (1) Guarantee: after parent revocation no descendant can produce an authentication proof a verifier will accept, beyond W_max+Delta_h+epsilon. (2) Mechanism that must fail: the verifier-side VerifyAuth check -- epoch freshness against the local clock, ECDSA verification of sigma_h under the cached hpk_p, recomputation of the binding hash, and ECDSA verification of the child signature over challenge||epoch||sigma_h. (3) Cheapest adversary action causing that failure: NOT forgery. Forgery requires breaking ECDSA or extracting hsk_p from an HSM/TPM/TEE (the paper's Threat 3, wh
- **Full text retrieved:** True

**Quoted span — the thing to check:**

> forging a proof requires breaking ECDSA or obtaining both s k c sk_{c} and a fresh parent heartbeat, this conjunction is the core security amplification over bearer tokens.

- **Schneider:** split · surrogate: A per-request safety property enforced by a purely local reference monitor: VerifyAuth rejects any proof whose heartbeat epoch is older than W_max/Delta_h epochs by the verifier's own clock, or whose heartbeat signature, · objective: Deterministic TERMINATION of the agent swarm -- closing 'the gap between “operator decides to stop” and “all agents actually stop”' -- offered as a cryptographically verifiable implementation of EU AI Act Art. 9 / 12 / 1

**Your verdict:** `________________`  
**Note:** 

---

## 7. MiniScope — `arXiv:2512.11147`

**Two-column verdict:** `A-T1 / B-T3`

**Why this row matters:** Modal pattern instance, and a demotion candidate. Both at once.

### Conservative coder

- **Advertised:** "our enforcement is mechanical and provides rigorous guarantees"; "rigorous security enforcement for tool-calling agents"; "a novel way to automatically and rigorously enforce least privilege principles"; "MiniScope provides rigorous least-privilege guarantees"; and, of the Dual-LLM line of work, it "cannot provide the same rigorous security guarantees as MiniScope". The paper leans once on a cryp
- **Scored (single column):** T3
- **Cheapest defeat:** WORKED TIER DERIVATION. (1) Guarantee: every tool call the agent actually executes on a connected service lies inside the OAuth scope set granted for that session, and the agent never holds the user's bearer token. (2) Mechanism that must fail: the Permission Checker interposed on the agent-to-service path -- implemented as a Python decorator wrapping each MCP function, keyed on a session token carried in the MCP request header, backed by a credential-holding forwarding proxy. (3) Cheapest adversary action: reach the effector by any path that never invokes a wrapped MCP function. Nothing in th
- **Full text retrieved:** True

**Quoted span — the thing to check:**

> We wrap each MCP function with a decorator that validates whether the tool call is permitted under the currently granted permissions.

- **Schneider:** split · surrogate: Trace-level scope containment, enforced by an execution monitor: for every step j, every tool call in c_j is permitted under the granted permission state rho_j, where rho_j is the accumulated result of the user's Always- · objective: The advertised objective is broader and is NOT monitorable: confining potential damage from unreliable LLMs operating over sensitive user services, including the motivating harm that an unreliable agentic system with acc

### Charitable coder

- **Advertised:** our enforcement is mechanical and provides rigorous guarantees
- **Scored (single column):** T3
- **Cheapest defeat:** Tier work-through. GUARANTEE: every tool call the agent actually executes on a service is authorized by the permission state the user granted. MECHANISM THAT MUST FAIL: the Permission Checker, implemented as a decorator wrapping each MCP function, plus the credential-substitution step that swaps the agent's session token for the user's real bearer token ('Before a tool call reaches the service, it is intercepted by the Permission Checker, which verifies the request using the granted permissions associated with the session token stored in the Credential Storage.'). CHEAPEST ADVERSARY ACTION: no
- **Full text retrieved:** True

**Quoted span — the thing to check:**

> We wrap each MCP function with a decorator that validates whether the tool call is permitted under the currently granted permissions.

- **Schneider:** split · surrogate: A per-call safety property checkable by a reference monitor: at every step, each executed tool call must be a member of the currently granted scope set. Stated formally in the security game as 'we say the system is secur · objective: The advertised objective is damage confinement under an untrusted model and untrusted data: 'MiniScope aims to confine potential harm caused by the tool-calling agent to the user’s connected services' and, in the abstrac

**Your verdict:** `________________`  
**Note:** 

---

## 8. Grimlock — `arXiv:2605.27488`

**Two-column verdict:** `A-T1 / unscorable`

**Why this row matters:** The one split the columns did NOT resolve. Specificity floor case.

### Conservative coder

- **Advertised:** The paper advertises OS-level enforcement for the mediation half and cryptographic binding for the authorization half, in one system. Verbatim: "Grimlock realizes this split through eBPF no-bypass mediation and kTLS-bound post-handshake attestation for authenticated agent-to-agent communication."; "Grimlock uses eBPF because it enables OS-enforced, application-transparent mediation at the sandbox 
- **Scored (single column):** T3
- **Cheapest defeat:** Worked explicitly. (1) GUARANTEE: no data leaves an agent sandbox except inside a channel a guard has authorized, and delegation carried on that channel is least-privilege and auditable. (2) MECHANISM THAT MUST FAIL: the per-host guard proxy's release gate - the userspace decision that re-validates attestation result, token scope, audience, expiry and channel binding before releasing plaintext into the destination sandbox. The eBPF layer does not make this decision; it only steers packets to the entity that does. (3) CHEAPEST ADVERSARY ACTION: neither of the expensive ones. Forging the Scope T
- **Full text retrieved:** True

**Quoted span — the thing to check:**

> Traffic is then forwarded to the destination host, where the receiving guard re-validates the attestation result, token scope, audience, expiry, and channel binding; terminates TLS; and releases plaintext to the destination sandbox only after policy checks succeed.

- **Schneider:** split · surrogate: A per-connection reference-monitor safety property the guard can and does enforce: no plaintext is released into a destination sandbox unless, at that moment, the attestation appraisal succeeded under operator policy and · objective: What is advertised is broader and outside the enforceable class: "transparent, auditable, and scope-bound agent-to-agent communication", with "least privilege, delegation propagates auditable, scoped permissions" and pro

### Charitable coder

- **Advertised:** "eBPF-enforced traffic interception to ensure that sandbox communication passes through a guard"; "Grimlock uses eBPF because it enables OS-enforced, application-transparent mediation at the sandbox boundary"; "No-bypass enforcement: an eBPF-based design for mandatory mediation at the sandbox boundary, preventing agent traffic from evading the guard"; "Grimlock enforces mandatory mediation at the 
- **Scored (single column):** T2
- **Cheapest defeat:** Tier worked explicitly. GUARANTEE: no agent-originated flow reaches a peer without traversing the guard and presenting a valid channel-bound Scope Token. MECHANISM THAT MUST FAIL: the eBPF hook set attached at the sandbox boundary that redirects ingress/egress to the guard proxy CVM -- not the TLS exporter binding, not the attestation, not the token signature. CHEAPEST ADVERSARY ACTION: emit traffic on a path the attached programs do not cover, or that is attached over-broadly/incompletely -- an address family, network namespace, or hook point (cgroup/connect vs. tc vs. sockmap) outside the de
- **Full text retrieved:** True

**Quoted span — the thing to check:**

> Grimlock uses eBPF because it enables OS-enforced, application-transparent mediation at the sandbox boundary. eBPF can interpose on ingress/egress, associate flows with stable sandbox identity, and force all traffic through a controlled path such as redirecting sockets to a guard proxy) without modifying agent code.

- **Schneider:** split · surrogate: Three per-flow safety properties an in-line monitor can decide and the paper states as such: (i) no-bypass -- 'all sandbox traffic must traverse the guard' (a prefix-closed property: the bad thing is a single unmediated  · objective: The advertised aim is broader than the surrogate: 'identity, authorization, provenance, and delegation' enforced consistently, 'strict trust boundaries', and 'least privilege' over what an agent's authority and data can 

**Your verdict:** `________________`  
**Note:** 

---

## 9. AARM — `arXiv:2602.09433`

**Two-column verdict:** `A-T1 / B-T3`

**Why this row matters:** FLAGGED: record arrived truncated. B-T3 reconstructed. Do not publish until confirmed.

### Conservative coder

- **Advertised:** The paper advertises enforcement strength per-architecture rather than for the specification as a whole. Protocol Gateway: “Enforcement point: Network level. If network configuration ensures all tool traffic routes through the gateway, enforcement cannot be bypassed by agent-side code.” Kernel/eBPF: “Enforcement point: Kernel level. All system calls from the agent process pass through eBPF hooks. 
- **Scored (single column):** T3
- **Cheapest defeat:** Perform the effect through any path that does not traverse the mediation chokepoint. Worked explicitly: (1) GUARANTEE - no action reaches a tool without synchronous policy evaluation, and denied/deferred actions produce no effects. (2) MECHANISM THAT MUST FAIL - the interposition point, which in every architecture capable of satisfying conformance is an application-layer chokepoint: an MCP/protocol proxy the agent is configured to dial (Gateway), an in-process callback/middleware hook the agent framework is configured to call (SDK), or a vendor-side pre-execution hook inside the vendor's own r
- **Full text retrieved:** True

**Quoted span — the thing to check:**

> Not covered: Direct HTTP calls bypassing the protocol, raw database connections, local filesystem access, shell command execution, or tools using non-standard protocols. || Kernel-level (eBPF/LSM) implementations alone cannot satisfy AARM conformance for context-dependent allow, deny, or defer classifications. These classifications require semantic understanding of actions and accumulated session context—information that is fundamentally unavailable at the syscall level. || eBPF implementations SHOULD therefore be positioned as defense-in-depth backstop layers alongside semantic-aware enforcement architectures (Gateway, SDK, or Vendor Integration) that provide the context-dependent evaluation required for full AARM conformance. Vendors must not claim AARM compliance based solely on kernel-level monitoring. || [SDK] Bypass risk: Higher than gateway architecture. Malicious code, bugs, or misconfiguration could invoke tools directly without passing through AARM.

- **Schneider:** split · surrogate: A per-action execution monitor: synchronous pre-execution interception of each tool invocation (R1); evaluation of the action tuple (tool, operation, parameters, identity) against static policy plus a predicate over an a · objective: Prevention of compositional information flow - that no sequence of individually-permitted actions ever effects exfiltration, and that actions remain aligned with the user's true intent. Exfiltration-by-composition is an 

### Charitable coder

- **Advertised:** For the eBPF architecture: "Enforcement point: Kernel level. All system calls from the agent process pass through eBPF hooks. User-space code cannot bypass kernel enforcement without kernel compromise." and "Bypass risk: Lowest of any architecture. Evasion requires kernel-level exploit or running outside the monitored environment." For the specification as a whole: "The system MUST NOT have a fail
- **Scored (single column):** T3
- **Cheapest defeat:** Worked explicitly. (1) The guarantee: no action reaches a tool unless it has passed pre-execution policy plus context-dependent intent-alignment evaluation. (2) The mechanism that must fail: the chokepoint through which tool invocations are required to pass. Because the spec itself rules out the kernel as a standalone carrier of the context-dependent half of the guarantee, the conformant carrier is always an application/network chokepoint - the MCP gateway proxy, the SDK/middleware hook, or the vendor pre-tool hook. (3) The cheapest adversary action: emit one operation that never traverses tha
- **Full text retrieved:** True

**Quoted span — the thing to check:**

> An important constraint applies to kernel-level monitoring: kernel-level (eBPF/LSM) implementations alone cannot satisfy AARM conformance for context-dependent allow, deny, or defer classifications and should be positioned as defense-in-depth backstop layers alongside semantic-aware enforcement architectures.

- **Schneider:** split · surrogate: A per-action reference monitor over a syntactic predicate: pre-execution interception at a chokepoint, static policy match on (tool, operation, parameters, identity), parameter validation (type, range, pattern, allowlist · objective: Non-exfiltration and intent alignment - that no composition of individually-permitted actions moves sensitive data out, and that what the agent is doing still corresponds to why the user asked. This is an information-flo

**Your verdict:** `________________`  
**Note:** 

---

## After verification

1. Any row marked `CORRECTED` or `UNSUPPORTED` — tell me, and I re-score and re-state every
   claim that depends on it. Some headline sentences will change and that is the point.
2. **The AARM row is already flagged**: its record arrived truncated and its action-column
   score was reconstructed. It cannot appear in a published figure until confirmed from source.
3. The paper's LLM-usage section reports **how many rows you overturned**. A non-zero number
   strengthens the method section rather than weakening it — it demonstrates the verification
   layer is real rather than ceremonial.

**Verified rows: ____ / 9 · Overturned: ____ · Date: __________**