# W5 default-deny egress broker — source canon, implementation audit, prior-art pressure test, and decision program

Status: deep research wave complete; production conformance remains unproved  
Evidence snapshot: 2026-09-01  
Primary architecture: Warrantor v4 W5  
Main evidence window: 2024-08-28 through 2026-08-28  
Older material: explicitly separated as indispensable foundations  
Access/language rule: free full text, English  
Priority regions: North America, India, Saudi Arabia, United Arab Emirates, Qatar

## Executive answer

Warrantor should **retain W5 as a Tier-A product outcome but reject the current implementation as a
production egress broker**. The frozen specification asks the right question: can an untrusted agent
reach any destination or effect that was not independently authorized? The checked-in Rust code does
not implement that boundary. It makes local decisions over caller-supplied strings; it neither owns the
socket nor mediates DNS, TLS, redirects, methods, credentials, bytes, results, or effects.

The strongest current consume substrate is **NVIDIA OpenShell v0.0.116**, which combines a restricted
child process, capability removal, seccomp, Landlock, a network namespace, a mandatory proxy,
destination and process-identity policy, DNS/address validation, SSRF checks, TLS/L7 inspection,
credential injection, runtime policy revisions, and structured denial evidence. At the inspected tag,
the two most relevant Rust packages passed **1,504 tests with zero failures and seven ignored tests**.
That is unusually strong open implementation evidence. It is not a production guarantee: OpenShell is
young, some runtime integrations remain experimental, the ignored LocalStack cases were not exercised,
and Warrantor still needs independent end-to-end bypass, failure, and effect reconciliation tests.

Anthropic Sandbox Runtime v0.0.74 and Cloudflare Sandbox SDK supply additional shipping/open evidence
for default-deny host mediation, native OS isolation, controlled proxies, runtime host policies, TLS
termination, request filtering, and credential substitution outside the agent. Kubernetes
NetworkPolicy, Cilium, Istio, and Landlock supply lower layers. CaMeL and Fides supply planner-level
capability and information-flow prior art. Silent Egress supplies direct experimental evidence that
output-only safety is insufficient. Together they decisively defeat any broad claim that capability-
scoped, default-deny agent egress is unclaimed.

The remaining defensible Warrantor opportunity is narrower and more valuable:

> An open, transport-neutral **authority-to-effect egress assurance profile** that binds a trusted
> capability map, exact policy/catalog revision, workload identity, one-shot authorization, final
> network operation, credential use, observed response/effect, and independently verifiable W2
> evidence—while differentially testing multiple enforcement substrates.

That profile is not present in the reviewed sources as one complete, widely adopted implementation.
This is a dated feature-composition finding, not a legal novelty or freedom-to-operate opinion.

## Decisions to take now

| Question | Evidence judgment | Strong recommendation |
|---|---|---|
| Is the W5 architecture worth keeping? | Yes. Capability-to-destination indirection, enforced mediation, failure closure and explicit advisory/mediated modes are sound requirements | Keep W5 as a product and conformance boundary |
| Is `rust/egress` a broker? | No. It is a decision/receipt library with eight reproduced fail-open or trust failures | Rename/quarantine it as an experimental policy prototype until a real PEP owns the connect and effect paths |
| Are R7 and S6 eBPF/Falco/Tetragon enforcement implementations? | No. The Rust packages are in-process classification/decision libraries; the RFCs name substrates not wired into the repository | Remove implementation language; either build and attach a real program/adapter or consume an existing runtime |
| Should Warrantor build a sandbox/network stack from scratch? | No. OpenShell, Anthropic, Cloudflare, Kubernetes/Cilium/Istio and OS controls already cover large parts | Consume OpenShell first; keep an abstraction for Cloudflare/Anthropic/Kubernetes targets |
| Is broad W5 novelty defensible? | No. Mechanistic default-deny and capability/IFC agent defenses are established | Retire broad absence/first language; claim only the exact evidence-bound composition after it exists |
| Is a hostname allowlist enough? | No. Shared destinations, redirects, DNS, credentials, methods, bodies, tunnels and effects defeat destination-only reasoning | Require identity-, operation-, credential-, content- and effect-aware policy layers |
| Does a signed allow decision prove enforcement? | No. A producer can self-sign, omit events, authorize one request and forward another, or fail after permit | Pin verifier trust, bind the final operation, consume permits atomically, and reconcile result/effect sets independently |

## Repository proposition under test

The frozen specification establishes these intended requirements:

1. The agent names a capability, never a raw destination.
2. A trusted, signed, versioned, expiring catalog resolves the capability to an endpoint set.
3. Delegation-chain authority can only narrow that set.
4. DNS is broker-owned; returned addresses are validated and pinned.
5. Metadata, loopback, link-local, private and otherwise forbidden ranges fail closed.
6. TLS identity, protocol, method, redirects, purpose and content limits are enforced.
7. A new destination requires a separately authorized catalog amendment.
8. Only `mediated` mode may be described as containment.
9. Broker, catalog and notary failures deny access.
10. Evidence describes both the decision and the actual path/effect.

Those are evaluated separately from repository implementation. A good specification does not make
the current code production-ready; a weak implementation does not invalidate the target property.

## Assurance ladder

Warrantor should stop using “default deny” as a binary label. Record the achieved level per runtime.

| Level | Name | What is actually proved | Typical implementation | What remains unproved |
|---:|---|---|---|---|
| E0 | Prompt assertion | The model was told not to use the network | System prompt or tool description | Every technical control |
| E1 | Application decision | A policy function returned deny/allow | `rust/egress-filter` | Complete routing, immutable input, socket/effect |
| E2 | Cooperative proxy | Compliant clients use an allowlisting proxy | Proxy environment variables | Raw sockets, alternate transports, child/host bypass |
| E3 | Enforced chokepoint | The workload has no usable route except the PEP | Netns/WFP/Seatbelt/CNI/firewall plus proxy | Correct destination and higher-layer semantics |
| E4 | Identity-aware destination | The PEP binds workload/process identity to validated destination | Process hash/SPIFFE plus DNS/address pinning | Exact operation, credentials and content purpose |
| E5 | Operation/credential scoped | Method/path/protocol and credential injection are policy-bound | TLS/L7 proxy and external secret broker | Permit replay, result/effect completeness |
| E6 | One-shot permit-to-forward | A permit binds the exact final wire operation and is consumed atomically | Warrantor PEP wrapper around a substrate | What external system actually committed |
| E7 | Reconciled authority-to-effect | Expected decisions, forwards, results and independent effects reconcile | W2 receipts plus receiver/gateway/cloud evidence | Absolute completeness under compromised observers |

No W5 deployment should be sold as preventing egress below E3. `rust/egress` is currently E1.
OpenShell is credible E3–E5 prior art subject to deployment and independent conformance. The target
Warrantor differentiation is E6–E7 across more than one substrate.

## Mechanical repository audit

### Test receipts

| Target | Command scope | Result | Interpretation |
|---|---|---:|---|
| `warrantor-egress` | Native Rust unit suite | 13 passed | Internal decision and self-signed receipt behavior only |
| `warrantor-egress-filter` | Native Rust unit suite | 26 passed | String normalization and default-deny policy logic only |
| `warrantor-exfil-guard` | Native Rust unit suite | 21 passed | Content/entropy/volume classification only |
| Combined local W5-adjacent suite | Three packages | **60 passed, 0 failed** | Does not open, intercept or block a real network operation |
| OpenShell `openshell-policy` | Pinned v0.0.116 | **233 passed** | Strong schema, ambiguity, merge, identity and L7 policy evidence |
| OpenShell `openshell-supervisor-network` | Pinned v0.0.116 | **1,264 unit + 2 FD + 3 inference + 2 WebSocket passed** | Strong proxy/address/SSRF/TLS/L7/identity/failure-path evidence |
| OpenShell excluded cases | Pinned v0.0.116 | 2 unit + 5 LocalStack ignored | Not evidence for those environments |
| Total OpenShell targeted execution | Two packages and integrations | **1,504 passed, 7 ignored, 0 failed** | High-quality current implementation evidence, not independent production certification |

OpenShell reproduction pin:

- repository: `https://github.com/NVIDIA/OpenShell`
- tag: `v0.0.116`
- commit: `d1155aa70042d3e2ee49dbfa15346b108b7c1d92`
- commit time: `2026-08-28T08:27:17Z`

Anthropic inspection pin:

- repository: `https://github.com/anthropic-experimental/sandbox-runtime`
- tag: `v0.0.74`
- commit: `e5fb1b93ba61bab8e916bee7541860bbdaa612cf`
- commit time: `2026-08-25T17:32:42-04:00`
- test boundary: repository requires Bun and Node 20.11+; the pinned source and tests were inspected,
  but its Bun suite was not executed in this environment

### Reproduced W5 counterexamples

A disposable external Rust probe called only the public `warrantor-egress` API. It reproduced all
eight results below, then the exact temporary probe directory was moved to trash.

| Vector | Reproduced result | Security consequence |
|---|---|---|
| Unsigned catalog | `unsigned_catalog_allowed=true` | “Signed catalog” is documentation, not an enforced invariant |
| Invalid signature and digest | `invalid_signature_and_digest_allowed=true` | Catalog authenticity/integrity is never verified |
| Expired entry | `expired_entry_allowed=true` | Revoked/stale reachability remains usable |
| Invalid enforcement mode | `invalid_enforcement_mode_allowed=true` | Advisory or arbitrary mode can return an allow verdict |
| Raw hostname in capability | `raw_hostname_capability_allowed=true` | The agent can still express a destination-like value |
| Capability/endpoint swap | `capability_endpoint_swap_allowed=true` | Capability does not determine endpoint; caller chooses both independently |
| Metadata URL with userinfo | `metadata_userinfo_string_allowed=true` | Prefix-based address screening is not URL/IP canonicalization |
| Attacker self-signed receipt | `self_signed_attacker_receipt_verifies=true` | Embedded public-key verification authenticates no trusted issuer |

Additional code findings:

- `DestinationCatalog::compute_digest()` serializes the mutable `digest` and `signature` fields,
  producing a self-referential construction rather than a stable signed payload.
- `decide()` never validates catalog digest, signature, version, expiry, method, TLS identity or
  enforcement mode.
- The request independently contains `capability` and `logical_endpoint`; no trusted mapping derives
  the latter from the former.
- Address checks use string prefixes rather than parsed URL, host and IP semantics.
- No component owns DNS resolution, socket creation, CONNECT, TLS, redirect handling, credential
  injection, response processing, or effect observation.
- The receipt carries its own verification key and has no configured trust store, certificate/status
  policy, deployment identity, nonce, expiry, audience or transparency/receiver corroboration.
- `egress-filter` has materially improved default-deny normalization, but no reviewed eBPF object,
  loader, map, attachment, network namespace or CNI hook invokes it.
- `exfil-guard` has useful classifiers, but no Falco/Tetragon stream, proxy-body path, response path,
  policy deployment or independent observer invokes it.

## Current implementation prior art

### Comparative matrix

Legend: **Y** implemented/documented; **P** partial, configuration-dependent or unverified here;
**N** absent from reviewed material.

| System | Enforced chokepoint | Destination/DNS | L7 operation | Credential mediation | Runtime policy | Evidence | Principal boundary |
|---|:---:|:---:|:---:|:---:|:---:|:---:|---|
| Warrantor current Rust | N | P decision strings | N | N | N | P self-signed | Library caller |
| Warrantor frozen target | Y | Y | Y | P | Y | Y | Workload + authority chain |
| OpenShell v0.0.116 | Y | Y | Y | Y | Y | Y structured logs/denials | Restricted process identity |
| Anthropic Sandbox Runtime v0.0.74 | Y per documented OS path | Y host patterns | P via TLS termination/filter callback | Y mask/inject | P | P logs | Sandboxed process/account |
| Cloudflare Sandbox SDK | Y in managed container path | Y host/IP list | Y Worker handler | Y trusted Worker | Y | P platform logs | Container/sandbox ID |
| Kubernetes NetworkPolicy | Y if CNI implements | L3/L4 only | N | N | Y declarative | P CNI-dependent | Pod/selectors |
| Cilium 1.19.6 | Y | Y via trusted DNS proxy | Y HTTP/DNS and extensions | N by itself | Y | Y/Hubble where enabled | Endpoint/identity |
| Istio egress gateway | P; bypassable alone | Y service/TLS routing | Y Envoy | Y with integrations | Y | Y telemetry | Workload/mesh identity |
| Landlock ABI 10 | Y per process/kernel | Port only | N | N | Static additive | Kernel audit support | Process domain |
| CaMeL | N network layer | Capability/data-flow intent | Tool/program level | N | Planner policy | Experimental | Trusted query/control flow |
| Fides | N network layer | IFC labels/policy | Planner/tool level | N | Planner policy | Experimental | Confidentiality/integrity labels |

### NVIDIA OpenShell v0.0.116

Why it matters:

- It is the closest reviewed open implementation to W5's intended mediated mode.
- The restricted child loses ambient capabilities; seccomp blocks dangerous/raw-socket paths.
- A network namespace forces ordinary egress through the local policy proxy.
- Policy binds endpoints to process identity and can inspect REST method/path, WebSocket, GraphQL,
  MCP and JSON-RPC request shapes.
- DNS/address resolution, allowed IPs, SSRF ranges, TLS identities and validated connect targets are
  handled in the supervisor network boundary.
- Credential material can remain provider-controlled and be resolved/injected at the proxy.
- Policy revisions have explicit loaded/failed acknowledgement and retain captured revision identity.
- L4 denials can produce deterministic pending policy proposals rather than silently broadening.
- Its own architecture says runtimes, schedulers, identity, secrets and networking should remain
  ecosystem-owned—directly supporting Warrantor's consume strategy.

Limits and cautions:

- The project is young and fast-moving; exact guarantees are tag- and deployment-specific.
- Process/binary and L7 enforcement depend on the selected runtime topology and policy shape.
- L7 parsing intentionally has protocol limits; generic JSON-RPC checks methods, while response/SSE
  directions are not generally parsed for policy enforcement.
- Local-file/global policy modes do not use the same revision acknowledgement as sandbox-scoped
  gateway policy.
- Five LocalStack SigV4 tests and two unit tests were ignored in the targeted run.
- A green internal suite does not prove every Kubernetes, VM, rootless, DNS, proxy, failover or hostile
  workload path.
- It does not by itself implement Warrantor's W2 exact authority/permit/result/effect receipt profile.

Decision: **adopt and contribute**, with a Warrantor-owned adapter and independent conformance suite.

### Anthropic Sandbox Runtime v0.0.74

Strengths:

- Open Apache-2.0 research preview with allow-only network policy.
- Linux removes the workload network namespace and bridges approved proxy traffic over Unix sockets.
- macOS Seatbelt and Windows WFP supply platform-native outbound fences.
- HTTP/HTTPS and SOCKS5 TCP are mediated; domain patterns and deny precedence are explicit.
- Current source includes TLS termination, request filtering and credential sentinel substitution.
- Windows documentation states proxy variables are convenient routing inputs while WFP is the fence.
- The README openly documents broad-domain exfiltration, domain fronting, dangerous Unix sockets,
  weaker nested/macOS modes, TLS/revocation constraints and system-resolver behavior.

Historical failure evidence must remain version-aware:

- GHSA-9gqj-5w7c-vx47 / CVE-2025-66479 affected versions before 0.0.16: an empty
  `allowedDomains` list could fail to enforce the network sandbox. v0.0.16 patched it.
- Issue 225 demonstrated that `allowLocalBinding` could broaden outbound access on macOS. The
  inspected v0.0.74 source explicitly separates bind/inbound from outbound and permits outbound only
  to loopback, so this is a fixed historical regression vector, not a current v0.0.74 finding.

Decision: **adopt as a secondary local-developer/runtime target**, not the sole enterprise boundary.

### Cloudflare Sandbox SDK outbound controls

The current managed platform demonstrates that dynamic deny-by-default egress and credential-holding
handlers are already productized:

- `enableInternet=false` blocks unapproved outbound access.
- `allowedHosts` becomes a deny-by-default host/IP allowlist.
- only 80/443 and Cloudflare DNS remain available in the restricted configuration.
- outbound handlers can allow, deny, reroute, filter methods and inject credentials in a trusted
  Worker outside the sandbox.
- runtime APIs can add/remove hosts and handler bindings.
- a sidecar in the sandbox network namespace uses TPROXY in local development.

Important bounds:

- Internet access is enabled by default unless the operator disables it.
- `ContainerProxy` must be exported for interception.
- simple wildcard matching is not capability semantics.
- a host matching `allowedHosts` can reach the public Internet when no handler claims it.
- the managed boundary is Cloudflare-specific and does not supply portable W2 evidence.

Decision: **adopt as a managed deployment adapter and competitive baseline**.

### Kubernetes, Cilium and Istio

Kubernetes NetworkPolicy is a minimum L3/L4 containment substrate, not a W5 replacement:

- pods are egress-open by default;
- an explicit selecting policy with `policyTypes: [Egress]` is required for default deny;
- allows from multiple policies combine additively, so an unrelated broad allow can reopen access;
- DNS must be allowed deliberately;
- the CNI must implement the policy;
- standard NetworkPolicy does not understand FQDN, HTTP method, TLS identity, credentials or purpose.

Cilium adds useful DNS proxy and `toFQDNs` behavior, endpoint identity, L7 policies and observability.
Its FQDN security model assumes intercepted responses from trusted cluster DNS. Versioned limits,
endpoint IP caps, DNS proxy availability and interactions with other rule types must be tested.

Istio supplies mature egress routing and L7/TLS policy but its own documentation is explicit: a
sidecar can be bypassed, and Istio cannot securely force all traffic through an egress gateway by
itself. A firewall, Kubernetes NetworkPolicy, node routing or equivalent external control must close
the direct path.

Decision: **use Cilium/NetworkPolicy to close cluster routes and OpenShell/Envoy-class proxies for
identity/L7 enforcement; never infer complete mediation from service-mesh configuration alone**.

### Landlock ABI 10

Landlock is a valuable additive process sandbox:

- TCP bind/connect rules exist from ABI 4.
- pathname Unix-socket resolution exists from ABI 9.
- UDP bind/connect/send rules exist from ABI 10.
- restrictions are applied by an unprivileged process and inherited by children.

It is not destination policy. Network objects are ports, not remote identities, IPs, hostnames,
certificates or operations. Runtime kernel ABI support and errata behavior must be detected. Use it to
reduce bypass paths; do not present it as the W5 catalog.

## Research prior art and attack evidence

### CaMeL — Defeating Prompt Injections by Design (2025)

CaMeL separates trusted control flow from untrusted data and uses capabilities to prevent unauthorized
flows. Its current v2 AgentDojo evaluation reports 77% of tasks solved with provable security. This directly
challenges broad W5 novelty around capability-based prompt-injection-resistant exfiltration.

Boundary: CaMeL is a planner/program architecture, not a complete network namespace, DNS/TLS proxy or
effect-reconciliation system. Warrantor should compose its data/control-flow ideas with a hostile-
workload network boundary.

### Fides — Securing AI Agents with Information-Flow Control (2025)

Fides provides a formal model, confidentiality/integrity labels, deterministic enforcement and
selective hiding primitives, evaluated with AgentDojo. It is strong prior art for data-purpose and
label-aware authorization that W5's content controls need.

Boundary: the public artifact is primarily a tutorial and depends on external model service setup. It
does not prove a production network PEP, trusted loaded policy, one-shot permit or independent effect.

### Silent Egress (2026 preprint)

The study reports 480 runs with a qwen2.5:7b agent, estimated egress success probability 0.89, and
95% of successful attacks missed by output-based safety checks. It also considers sharding that avoids
simple content inspection. This is direct evidence against treating final-answer review or DLP alone as
containment.

Boundary: it is a preprint and one model/testbed. Treat the numerical result as experimental scope,
not a universal rate. Import its attacks into the W5 corpus and rerun across models, runtimes and PEPs.

## Standards and official-control crosswalk

| Authority | Relevant requirement or principle | W5 interpretation | What it does not establish |
|---|---|---|---|
| NIST SP 800-207 | No implicit location trust; authenticate/authorize each resource access | Bind workload/resource/context at the PEP, not just subnet | A concrete agent egress implementation |
| NIST SP 800-207A | Identity-tier policy using gateways, sidecars and SPIFFE-like identity | Compose workload identity, gateway and network tiers | Complete mediation or exact effect evidence |
| Saudi NCA ECC 2-2024 | Network segmentation, firewall, secure Internet/browsing, service/protocol/port restriction, DNS control | Regional procurement mapping for W5 modes, rules and evidence | W5 uniqueness or automatic compliance |
| India CERT-In government guidance | Internal DNS, block public DNS, proxy-only Internet, segmentation, selected ports/protocols and filtering | Require enterprise DNS ownership, proxy path and SIEM export | Universal private-sector applicability or agent-specific conformance |
| Qatar NIAS v2.1 | Gateway security, network security, information exchange and logging/control evidence | Map catalog, gateway, exchange and evidence operations to named control owners | A W5 technical design or legal conclusion |
| UAE Information Assurance Regulation v1.1 | Network service security, segregation, monitoring/review and controlled exchange | Support UAE deployment assurance and procurement evidence | Current agent-specific requirement or certification |

Regional controls are demand and procurement evidence, not novelty evidence. Every customer mapping
needs scope, accountable entity, control owner, deployment facts and qualified local review.

## Threat and negative-conformance corpus

Every production adapter must pass applicable vectors below at decision, wire and observed-effect
layers. A denial log without proof that the forbidden operation had no effect is incomplete.

### A. Catalog and policy integrity

1. Unsigned catalog.
2. Signature from an untrusted key.
3. Valid signature over a different catalog.
4. Self-referential or non-canonical digest.
5. Expired catalog or endpoint.
6. Rolled-back catalog version.
7. Equal-version equivocation.
8. Policy loaded but not acknowledged.
9. Failed reload followed by fail-open empty policy.
10. Last-known-good policy beyond its permitted lease.
11. Agent-writable catalog file, environment or socket.
12. Partial catalog distributed to one replica.
13. Control-plane outage during creation.
14. Policy generation changes between permit and connect.

### B. Capability and authority binding

15. Raw hostname presented as capability.
16. Capability string and endpoint supplied independently.
17. Wildcard `net.egress` defeats child attenuation.
18. Delegation chain reordered, truncated or replaced.
19. Expired/revoked delegation.
20. Wrong tenant, session, workload or process uses permit.
21. Process forks after authorization.
22. Executable changes at the same path after authorization.
23. Approval for discovery replayed for a different host.
24. Discovery approval silently becomes permanent catalog entry.

### C. Naming, DNS and address identity

25. DNS rebinding between evaluation and connect.
26. Multiple A/AAAA answers with one forbidden address.
27. CNAME chain to forbidden/private destination.
28. SVCB/HTTPS record changes endpoint/port.
29. Trailing dot, mixed case, IDNA and Unicode confusable.
30. IPv4-mapped IPv6, IPv4-compatible IPv6 and zone ID.
31. Decimal/octal/hex or shortened IPv4 spelling.
32. URL userinfo obscures metadata address.
33. Redirect to new scheme/host/port/private range.
34. Alternate resolver via DoH, DoT or DoQ.
35. DNS cache poisoning or stale TTL.
36. Split-horizon answer differs between PEP and connector.
37. Host header/SNI/certificate/connected-IP mismatch.
38. CDN or shared hostname permits attacker-controlled tenant.

### D. Transport and bypass

39. Client unsets proxy variables.
40. Raw TCP socket.
41. UDP/QUIC/HTTP3.
42. ICMP or non-TCP protocol.
43. SOCKS or HTTP CONNECT tunnel.
44. WebSocket upgrade and post-upgrade frames.
45. gRPC, SSE and streaming messages.
46. Unix/abstract socket to a privileged host service.
47. Docker/containerd/Kubernetes API socket.
48. Host networking or privileged/capability-added workload.
49. Sidecar/init/ephemeral container bypass.
50. Node process, daemonset or CNI path outside policy selector.
51. Existing keep-alive connection after revocation.
52. Connection pool reused by another tenant/authority.
53. Parent proxy `NO_PROXY` or upstream proxy bypass.
54. VPN/tunnel process or remote port forwarding.
55. Browser, helper daemon or Apple Events launches an unsandboxed process.

### E. L7, credentials and data purpose

56. Allowed host, forbidden method/path/tool.
57. Redirect changes method or drops policy-relevant body.
58. HTTP request smuggling/ambiguous framing.
59. Compressed, chunked, multipart or encoded body evades inspection.
60. JSON duplicate keys or parser differential.
61. GraphQL alias/fragments/batching hide mutation.
62. JSON-RPC/MCP notification bypass.
63. Credential sentinel sent to non-injection host.
64. Credential copied before masking or recovered from process environment.
65. Proxy authentication token stolen and reused.
66. Broad approved host such as GitHub/paste/object storage used for exfiltration.
67. Data sharded across many benign requests.
68. Encrypted application payload defeats body DLP.
69. Response supplies a second-stage destination or tool instruction.
70. Purpose label removed or downgraded.

### F. Permit, result and effect integrity

71. Request fields mutate after permit.
72. Permit consumed twice by retry/race.
73. Permit issued but no forward occurs.
74. Forward occurs without a permit.
75. Allowed request receives result from a different upstream.
76. Proxy crashes after external commit but before result receipt.
77. Client times out and retries an already committed operation.
78. Producer omits a forward/effect receipt.
79. Attacker self-signs receipt with embedded key.
80. Receiver/cloud audit contradicts producer success/failure.
81. Expected decision, forward, result and effect sets differ.
82. Logging/storage outage changes enforcement outcome.
83. Evidence contains secrets or regulated payloads.
84. Receipt redaction breaks verification or semantic meaning.

## Target architecture

```text
principal / delegation chain
            |
            v
W1/W6 authority decision ---- policy + catalog trust ---- operator approval
            |                         |
            +---- exact one-shot permit
                          |
restricted workload -- no-route boundary -- W5 PEP
                          |            |
                    trusted DNS        +-- L7 + credential broker
                          |            |
                          +-- validated connector -- external service
                                                     |
                                          result / independent effect
                                                     |
                  W2 expected-set reconciliation + signed evidence
```

### Warrantor-owned contracts

1. **Capability map:** one canonical mapping from authority capability to logical operation class;
   the agent cannot supply the destination map.
2. **Catalog statement:** version, validity interval, issuer/key ID, endpoint identities, allowed
   protocols/methods/paths, address policy, redirect policy, purpose and credential binding.
3. **Trust policy:** configured roots, issuer authorization, revocation/status, audience/tenant and
   monotonic version rules; never trust a key merely because a receipt embeds it.
4. **One-shot permit:** hashes exact final workload identity, authority chain, catalog/policy revision,
   method/protocol, logical endpoint, sanitized request/body commitment, credential handle and expiry.
5. **PEP adapter:** consumes one permit atomically, maps it to the substrate, records the validated
   connect target and rejects all post-authorization mutations.
6. **Result/effect evidence:** correlates upstream response and, where possible, receiver/cloud audit,
   transaction ID or resource state.
7. **Expected-set reconciliation:** detects missing, duplicate, conflicting or out-of-order decisions,
   forwards, results and effects.
8. **Assurance declaration:** names E0–E7 level, substrate/version/topology, bypass assumptions,
   exclusions, test corpus and last verification time.

### Consume/build/defer/reject matrix

| Capability | Decision | Preferred substrate | Warrantor work |
|---|---|---|---|
| Restricted agent process and netns | Consume | OpenShell first; Anthropic for local workflows | Adapter, pinned profile, hostile conformance |
| Kubernetes route closure | Consume | Cilium/NetworkPolicy; cloud firewall/NAT | Verified deployment profile and drift checks |
| L7 proxy/parser | Consume/contribute | OpenShell/Envoy-class implementation | Method maps, exact operation hash, parser differentials |
| DNS/address validation | Consume/contribute | OpenShell/Cilium patterns | Catalog identity, pinned connector evidence, test corpus |
| Workload identity | Consume | SPIFFE/SPIRE or runtime identity | Bind to W1/W6 decision and PEP |
| Credential broker | Consume/contribute | OpenShell/Cloudflare/Anthropic patterns | Authority-, host- and operation-scoped handle/evidence |
| Capability/catalog semantics | Build | Warrantor profile | Canonical schema, signing/trust, monotonic lifecycle |
| One-shot permit and W2 binding | Build | Warrantor | Atomic consume, immutable final wire operation |
| Effect reconciliation | Build/adapt | Receiver/cloud/SIEM connectors | Expected-set logic, independent evidence and uncertainty |
| Generic eBPF sandbox | Reject greenfield | Existing runtimes/CNI | Build only a narrow missing hook with tests if necessary |
| Entropy/DLP as primary containment | Reject | Use only defense in depth | Purpose/operation controls and attack-sharding tests |

## Product options and trade-offs

### Option A — OpenShell-first W5 reference profile (recommended)

Build the first vertical slice over pinned OpenShell. Add a Warrantor adapter that receives a one-shot
permit, installs/validates the exact policy revision, obtains loaded acknowledgement, invokes the
network supervisor, and emits decision/connect/result/effect evidence.

Benefits:

- shortest route to a credible E3–E6 boundary;
- strong current open test base;
- L7, process identity, DNS, SSRF and credential features already present;
- aligns with the repository's own consume decision.

Costs/risks:

- fast-moving alpha interface and topology dependence;
- Warrantor must maintain an upstream compatibility profile and independent tests;
- one substrate cannot prove transport neutrality.

### Option B — managed Cloudflare profile

Map W5 catalog entries to `allowedHosts` plus mandatory outbound handlers; keep secrets in the trusted
Worker and emit W2 evidence from both Worker and Warrantor.

Benefits: low operations burden, dynamic policy, managed scale.  
Costs: platform dependence, default-internet/configuration hazards, simple host globs, limited portable
effect evidence.

### Option C — enterprise Kubernetes profile

Use Cilium/NetworkPolicy to close direct routes, an OpenShell or Envoy-class per-workload/gateway proxy
for L7/credentials, and SPIFFE identity. Verify additive-policy drift continuously.

Benefits: enterprise fit and defense in depth.  
Costs: highest operational complexity; CNI, mesh, DNS, node, sidecar and cloud routing must compose.

### Option D — build a Warrantor-native sandbox and eBPF stack

Benefits: maximum control.  
Costs: duplicates mature work, creates kernel/platform maintenance and enlarges the trusted code base.

Decision: **reject unless a measured requirement cannot be met by contributing a narrow upstream
feature**.

## Phased execution program

### Phase 0 — claim and package hygiene (immediate)

- Remove “network enforcement,” “eBPF enforcement,” “Falco/Tetragon implementation,” and production
  broker language from packages that only return decisions.
- Mark `rust/egress` experimental and prohibit its receipt verifier in trust decisions.
- Replace broad novelty with the dated feature-composition statement in this report.
- Add CLM-0024 through CLM-0026 to release/marketing review gates.

Exit: repository documentation, package metadata and external claims match deployable evidence.

### Phase 1 — canonical contracts

- Define capability-map, signed catalog, trust policy, one-shot permit and result/effect predicates.
- Use deterministic canonical encoding or DSSE/in-toto payload authentication; never self-reference
  signature/digest fields.
- Generate Rust/Go/Python/TypeScript schemas and negative fixtures.
- Model monotonic catalog/version/permit invariants.

Exit: two independent producers and verifiers reject every catalog/receipt vector.

### Phase 2 — OpenShell vertical slice

- Pin an OpenShell profile and deployment topology.
- Bind W1/W6 decision to process/workload and exact policy revision.
- Require policy `LOADED` acknowledgement before permit use.
- Consume permit atomically at the PEP and record validated destination.
- Join forward, result and effect evidence into W2.

Exit: one real irreversible test operation passes E6 with no unmediated network route.

### Phase 3 — hostile conformance

- Implement all 84 vectors plus property-based URL/DNS/parser mutation.
- Exercise crash points before/after authorization, connect, write, response and external commit.
- Run privileged, hostNetwork, child, alternate runtime, IPv4/IPv6, TCP/UDP/QUIC and tunnel attempts.
- Measure denied-leak bytes, bypass rate, false-deny rate, latency, throughput and recovery.

Exit: zero unauthorized effects within declared threat model; all exclusions explicitly surfaced.

### Phase 4 — differential substrate proof

- Add Cloudflare and Kubernetes/Cilium profiles; optionally Anthropic local profile.
- Run the same semantic corpus and compare outcomes.
- Declare substrate-specific gaps rather than normalizing them away.

Exit: two independent enforcement stacks pass the common core with bounded exceptions.

### Phase 5 — production evidence

- Run HA, rolling upgrade, disaster recovery, policy rollback, key rotation and partition tests.
- Integrate SIEM/cloud/receiver effect corroboration and retention/privacy controls.
- Obtain independent security review and red-team reproduction.

Exit: E6/E7 assurance claim is versioned, independently reviewed and operationally monitored.

## Required metrics

| Metric | Definition | Release expectation |
|---|---|---|
| Unauthorized-effect rate | Forbidden externally observed effects / attempted forbidden effects | 0 in conformance threat model |
| Unmediated-route rate | Successful connects without PEP evidence / bypass attempts | 0 |
| Permit mismatch acceptance | Mutated final operations accepted / mutations | 0 |
| Permit replay acceptance | Duplicate forwards / one-shot permits | 0 |
| Evidence reconciliation gap | Missing or conflicting stages / expected stages | 0 or explicit unresolved incident |
| Revocation residual | Forbidden new bytes/effects after effective revocation | Measured bound, not “instant” |
| Policy activation latency | decision to independently confirmed loaded enforcement | p50/p95/p99 and maximum |
| Fail-closed availability | denied safe failures and unsafe allows during dependency failure | 100% safe; availability separately reported |
| Benign utility | legitimate tasks completed under policy | workload-specific and compared with baseline |
| Performance overhead | latency, throughput, CPU/memory, proxy amplification | budget by protocol and payload class |

## Business and procurement implications

### Product packaging

- Keep the capability/catalog/permit/receipt schemas and local verifier open.
- Monetize managed policy lifecycle, conformance, evidence retention, regional mappings, enterprise
  integrations, support and sovereign operation.
- Offer named assurance profiles—E3 containment, E5 operation/credential, E6 permit-to-forward, E7
  reconciled effect—rather than one “secure” tier.
- Do not charge for a signed decision as though it proves a prevented effect.

### Buyer questions Warrantor must answer

1. Which process/pod/VM/account is actually fenced?
2. Which paths can bypass the PEP?
3. Who owns DNS, TLS and credentials?
4. What happens on policy, catalog, notary, proxy, log or SIEM outage?
5. Can any other policy reopen egress?
6. How is a permit bound to the final operation and consumed once?
7. How is external commit known after timeout/crash?
8. What data enters receipts, where is it stored and who can verify it?
9. Which controls are independently tested at the exact deployed versions?
10. What is the residual-action/revocation bound?

### Regional entry use

- **Saudi Arabia:** map ECC 2-2024 network, protocol, secure Internet and DNS controls to the
  declared W5 profile; never market the map as certification.
- **India:** make internal DNS, public-DNS blocking, proxy-only Internet, segmentation and SIEM export
  explicit deployment checks for relevant government buyers.
- **Qatar:** map gateway/network/information-exchange/logging controls with named owners and evidence;
  validate sector and entity applicability.
- **UAE:** map network-service security, segregation and review evidence; obtain current English
  sector/procurement requirements and local assurance review.

## Academic research program

### Paper 1 — Authority-to-effect egress conformance for AI agents

Research question: can one semantic corpus distinguish policy decision, enforced mediation and
externally observed effect across heterogeneous sandboxes?

Hypotheses:

- H1: decision-only systems produce materially higher false assurance than enforced chokepoints.
- H2: destination-only policies fail more exfiltration vectors than operation/credential/purpose-aware
  policies at comparable utility.
- H3: one-shot exact-operation permits eliminate mutation/replay failures without prohibitive latency.
- H4: independent effect reconciliation detects commit ambiguity that proxy logs miss.

Baselines: current Warrantor libraries, OpenShell, Anthropic Sandbox Runtime, Cloudflare Sandbox,
Kubernetes/Cilium/Istio, CaMeL and Fides where artifacts permit.

### Paper 2 — Differential DNS and parser security for agent egress

Build property-based corpora for URL, DNS, IP, SNI/Host, HTTP framing, GraphQL, JSON-RPC/MCP and
redirect semantics. Measure disagreement and exploitability across runtimes.

### Paper 3 — Utility/security frontier under capability and IFC controls

Compose planner-level CaMeL/Fides controls with network E3–E7 profiles. Evaluate AgentDojo plus
Silent-Egress-derived workloads, benign utility, attack success, false denials and operator burden.

Candidate venues: USENIX Security, NDSS, IEEE S&P, ACM CCS, USENIX ATC, EuroSys, SOSP/OSDI when the
systems contribution and production evaluation justify them. Venue fit must be rechecked at submission.

## Evidence-led content program

1. “A deny decision is not a firewall: the seven levels of agent egress assurance.”
2. “Why allowing GitHub can still mean allowing exfiltration.”
3. “DNS rebinding, redirects and shared SaaS: the hard parts of AI-agent allowlists.”
4. “OpenShell, Cloudflare, Anthropic and Kubernetes: what Warrantor should consume.”
5. “From capability to effect: binding an AI-agent permit to the real network operation.”
6. “Why signed receipts need trusted issuers and expected-set reconciliation.”
7. “Regional egress evidence for Saudi, India, Qatar and UAE buyers—without compliance theater.”
8. “What 1,504 passing proxy tests prove—and what they do not.”

Every article must preserve version, threat-model and vendor-evidence qualifications.

## Reading paths

### Executives and product leaders

1. This report: executive answer, decisions and product options.
2. OpenShell architecture overview.
3. Cloudflare outbound controls.
4. Silent Egress.
5. Regional control applicable to the buyer.

### Security and platform architects

1. W5 frozen specification.
2. OpenShell sandbox architecture and pinned implementation.
3. Kubernetes NetworkPolicy, Cilium FQDN/L7 and Istio bypass guidance.
4. NIST SP 800-207/207A.
5. Threat corpus and target architecture in this report.

### Engineers and implementers

1. OpenShell `openshell-policy` and supervisor-network source/tests.
2. Anthropic Sandbox Runtime v0.0.74 source and disclosed limitations.
3. Cloudflare outbound handler guide.
4. Landlock network ABI documentation.
5. Warrantor Phase 1–4 gates and negative corpus.

### Academic researchers

1. CaMeL v2.
2. Fides.
3. Silent Egress.
4. OpenShell/Anthropic artifact pins.
5. Academic program and measurement definitions here.

### Risk, audit, policy and compliance teams

1. Assurance ladder and buyer questions.
2. NIST ZTA foundations.
3. Relevant Saudi/India/Qatar/UAE official control text.
4. Evidence/reconciliation and data-handling requirements.

### Marketing, partnerships and content teams

1. Executive decisions and prohibited overclaims.
2. Comparative matrix.
3. Product packaging and regional entry use.
4. Evidence-led content program.

## Essential current canon

| Priority | Source | Class | Why it is essential | Caution |
|---:|---|---|---|---|
| 1 | [OpenShell v0.0.116](https://github.com/NVIDIA/OpenShell) | Repository | Closest current open mechanistic agent-egress implementation; locally tested | Young, topology/version dependent; no W2 effect proof |
| 2 | [OpenShell sandbox architecture](https://github.com/NVIDIA/OpenShell/blob/main/architecture/sandbox.md) | Technical documentation | Exact trust, isolation, L7, credential and policy-revision boundary | First-party architecture; verify code/deployment |
| 3 | [Anthropic Sandbox Runtime v0.0.74](https://github.com/anthropic-experimental/sandbox-runtime) | Repository | Cross-platform native sandbox and proxy implementation with candid limits | Research preview; suite not run here |
| 4 | [Cloudflare Sandbox outbound traffic](https://developers.cloudflare.com/sandbox/guides/outbound-traffic/) | Technical documentation | Shipping managed dynamic egress and trusted credential handler | Vendor-specific; Internet enabled unless disabled |
| 5 | [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/) | Specification/documentation | Minimum cluster default-deny semantics and additive-policy boundary | L3/L4 and CNI dependent |
| 6 | [Cilium L3/FQDN policy](https://docs.cilium.io/en/stable/security/policy/layer3/) | Technical documentation | DNS-proxy FQDN and endpoint policy implementation | Trusted-DNS/configuration assumptions |
| 7 | [Istio egress gateway](https://istio.io/latest/docs/tasks/traffic-management/egress/egress-gateway/) | Technical documentation | Explicit sidecar-bypass warning and route-closure composition | Mesh alone is not containment |
| 8 | [Landlock network controls](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html) | Kernel documentation | Current process-level TCP/UDP/Unix-socket restriction layer | Port-level, ABI/kernel dependent |
| 9 | [CaMeL](https://arxiv.org/abs/2503.18813) | Research paper/preprint | Capability/data-control design and AgentDojo evidence | Planner layer, not network complete |
| 10 | [Fides](https://arxiv.org/abs/2505.23643) | Research paper/preprint | Formal IFC model and deterministic policy enforcement | Tutorial artifact, not production PEP |
| 11 | [Silent Egress](https://arxiv.org/abs/2602.22450) | Preprint | Direct exfiltration and output-DLP failure evidence | One model/testbed; numerical bounds limited |
| 12 | [Saudi ECC 2-2024](https://nca.gov.sa/en/regulatory-documents/controls-list/ecc/) | Government control | Priority Saudi network/DNS/protocol procurement anchor | Not agent-specific or automatic compliance |

## Indispensable older foundations

| Source | Why retained | Boundary |
|---|---|---|
| [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final) | Canonical zero-trust resource/connection authorization architecture | Abstract guidance |
| [NIST SP 800-207A](https://csrc.nist.gov/pubs/sp/800/207/a/final) | Identity-tier cloud-native enforcement using gateways, sidecars and SPIFFE | 2023; not agent-specific |
| [India CERT-In government security guidance](https://www.cert-in.org.in/PDF/guidelinesgovtentities.pdf) | Authoritative proxy-only Internet, internal DNS and segmentation controls | 2023 and scoped to named government entities |
| [Qatar NIAS v2.1](https://assurance.ncsa.gov.qa/sites/default/files/publications/policy/2023/NCSA_CSGA_%20National_Information_Assurance_Standard_En_V2.1_0.pdf) | Cross-sector assurance control anchor | Verify current applicability per entity |
| [UAE Information Assurance Regulation v1.1](https://tdra.gov.ae/-/media/About/regulations-and-ruling/EN/UAE-Information-Assurance-Regulation-v1-1-pdf.ashx) | UAE network-service and segregation control anchor | Older general control; current sector overlays needed |

## Search and verification limits

- This was an adversarial technical and public-source review, not a legal patent landscape, claim
  construction, infringement, validity, regulatory or freedom-to-operate opinion.
- Vendor documentation supports feature and stated-boundary findings, not independent efficacy.
- OpenShell's pinned core tests were executed, but full runtime/Kubernetes/VM deployments were not.
- Anthropic's source and test tree were inspected at v0.0.74; its Bun test suite was not executed in
  the available environment.
- Cloudflare's managed service was not provisioned or independently attacked.
- Silent Egress is a preprint with a bounded model/testbed.
- Regional controls require entity-, sector-, date- and deployment-specific legal/assurance review.
- No reviewed source proves event-set completeness against every compromised observer.
- Proprietary platforms and unpublished implementations may add overlapping prior art.

## Final recommendation

**Adopt W5's outcome; replace its implementation path.** Use OpenShell as the first reference
enforcement substrate, Cloudflare as the managed comparator, and Cilium/NetworkPolicy plus a trusted
L7 proxy for Kubernetes. Build only Warrantor's capability/catalog trust profile, one-shot exact-
operation permit, substrate adapters, W2 result/effect evidence and cross-substrate conformance.

Do not ship or market the current Rust packages as network enforcement. Do not claim that a signed
decision is non-bypassable. The release gate is an independently reproduced E6 vertical slice followed
by two-substrate E7 reconciliation—not another green unit-test count.
