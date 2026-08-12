# W5 — The Egress Broker

> Every one of the five self-disclosed frontier-lab intrusions of July 2026 failed the same way: the
> boundary lived in the prompt — *"you have no internet," "this is a simulation"* — while the
> substrate silently permitted a network path. This component makes the agent's belief about
> connectivity irrelevant to what the network actually does.
>
> **Status:** FROZEN CANDIDATE — Tier A. Absorbs R7 egress-filter, S6 exfil-guard, and N3's
> tool-call admission arm.

---

## 1. The design rule

> **The agent never supplies a destination.**

An agent does not name a hostname, IP, URL, or port. It names a **capability**, and the broker
resolves that capability to a destination set using a signed catalog the agent cannot influence.

This is what "model-belief-independent" has to mean concretely. If the agent can supply a
destination string, then a prompt injection, a hallucinated hostname, or a poisoned tool description
can supply one too — and the defense reduces to string filtering, which is the architecture that
already failed. **A destination the agent cannot express is a destination it cannot reach**,
regardless of what any injected instruction tells it to do.

```
  agent: "fetch the customer record"          agent: "connect to 203.0.113.9:443"
            │                                            │
            ▼                                            ▼
  capability: net.egress → db:prod.customers      ✖ REJECTED — not a capability
            │                                        the vocabulary has no
            ▼                                        way to express this
  broker resolves via signed catalog
            │
            ▼
  pinned endpoint, verified, connection established
```

---

## 2. Resolution

A `net.egress` capability's resource pattern (per the capability algebra) names a **logical
endpoint**, not an address. The broker resolves it through a **destination catalog**: a signed,
versioned mapping from logical endpoint to concrete addresses, TLS identity, and permitted methods.

| Property | Rule |
|---|---|
| Catalog integrity | Signed and content-digest identified; the digest **MUST** appear in the receipt |
| Who may amend | Operators, out-of-band. An agent **MUST NOT** be able to add, amend, or reorder entries — this is invariant I-11 applied to the destination namespace |
| Resolution point | The broker, never the agent's resolver |
| Effective destinations | The catalog entry ∧ the chain's `net.egress` capabilities — the meet, so delegation can only narrow reachability |

Because resolution is a meet against the delegation chain, a subagent can never reach an endpoint
its delegator could not.

---

## 3. Where egress control usually breaks

An allowlist that checks a hostname and then hands off to the operating system is not a control.
The broker owns the whole path, and each rule below exists because it is a documented escalation
route:

| Surface | Rule |
|---|---|
| **DNS** | The broker resolves and **pins** the address for the connection's lifetime. The agent's resolver is not consulted, and rebinding between check and connect is structurally impossible |
| **Address literals** | Connections to raw IPs are denied unless the catalog entry itself is an address |
| **Redirects** | A redirect to a destination outside the resolved set is **denied**, not followed. Redirect chains are bounded and every hop is re-checked |
| **TLS identity** | Certificate and SNI **MUST** match the catalog's expected identity. Name resolution alone is not identity |
| **Link-local and metadata** | `169.254.0.0/16` and equivalents are denied by default and **MUST NOT** be catalog-addable. This is the exact path that yielded node-role credentials in the 2026 incident |
| **Private ranges** | Denied unless explicitly catalogued, closing server-side request forgery into internal services |
| **Protocol** | Only catalogued protocols and methods; protocol downgrade is denied |
| **Proxies** | Agent-supplied proxy settings and environment overrides are ignored entirely |

---

## 4. Content policy on an authorized channel

Authorization decides *whether* a channel opens; it does not decide what may cross it. The broker
therefore also enforces the exfiltration controls absorbed from S6, with a deliberate asymmetry:

- Data classification and volume ceilings apply per destination class.
- Classified content bound to a purpose **MUST NOT** cross to a destination outside that purpose
  (invariant I-03).
- Content signals from classifiers are **advisory** and follow the receipt's asymmetry rule: they
  may cause a block, never an allow.

**Normative.** Content inspection is defense-in-depth and **MUST NOT** be relied on as the primary
control. Payloads can be encoded, encrypted, or split across sessions. The primary control is that
the channel was authorized in the first place — everything here is the second line.

---

## 5. Dynamic destinations, honestly

A broker that cannot reach genuinely new destinations is a broker teams will disable. The escape
hatch is explicit rather than implicit:

- A **discovery request** names a candidate destination and requires an `elevated` or `critical`
  authorization, with human approval at `critical`.
- Approval mints a **catalog amendment**, signed out-of-band and scoped/expiring.
- The receipt records that the destination was discovered rather than catalogued, so the audit trail
  distinguishes pre-authorized traffic from newly-granted traffic.

**Normative.** A discovery request **MUST NOT** be satisfiable by the agent alone. The point is not
to forbid new destinations; it is to ensure that reaching one is an event with a receipt and an
approver, not a side effect of a string appearing in a context window.

---

## 6. Enforcement mode

The broker is only a containment boundary in `mediated` mode:

| Mode | Requirement |
|---|---|
| `mediated` | The agent's network namespace has **no route** to any destination except through the broker — enforced by namespace isolation, kernel policy via OpenShell, or a capability-issued socket. Bypassing the broker means having no network at all |
| `advisory` | The broker observes and records but an unmediated path exists. Evidence only |

**Normative.** An egress broker in `advisory` mode **MUST NOT** be described as preventing
exfiltration. It records attempts; it does not stop a determined path.

---

## 7. Failure behavior

| Failure | Behavior |
|---|---|
| Catalog unavailable | **Deny.** No catalog, no resolution, no connection |
| Catalog signature invalid | **Deny**, and alarm — an unsigned or mis-signed catalog is a compromise indicator |
| Notary unreachable | **Deny** (I-09) |
| Transparency log unreachable | **Proceed** for routine/elevated with anchoring pending; deny for critical |
| Broker itself unavailable | Fail closed at the network layer: no route, hence no traffic. **MUST NOT** fail open to direct connectivity |

That last row is the one implementations get wrong. A broker whose crash restores direct network
access has inverted its own purpose.

---

## 8. The demo

The reference demonstration replays the documented misconfiguration in which an agent was told in
its prompt that it had no internet while the environment in fact permitted egress:

1. Run an agent under a prompt asserting an isolated sandbox, with real connectivity present.
2. Instruct it — as the incident's conditions effectively did — to reach an external system.
3. Show the outbound denied at the broker, with a signed `deny` receipt naming the capability that
   was absent.
4. Repeat with an injected instruction supplying an explicit hostname, and show it cannot even be
   expressed as a request.

The second half is the point. The first shows a policy working; the second shows that the attack's
usual payload — a destination string — has nowhere to go.

---

## 9. Conformance

| Test | Expected |
|---|---|
| Agent supplies hostname / IP / URL directly | Rejected as unexpressible |
| Injected instruction supplies a destination | Rejected; `deny` receipt records the injection attempt |
| DNS rebinding between check and connect | Impossible — address pinned at resolution |
| Redirect to an out-of-set destination | Denied, not followed |
| TLS identity mismatch | Denied |
| Metadata-service reachability (`169.254.x.x`) | Denied, and not catalog-addable |
| Subagent reaching an endpoint outside the delegator's set | Denied (capability meet) |
| Catalog amendment attempted by the agent | Denied (I-11) |
| Discovery request without approval at `critical` | Denied |
| Broker process killed | No route; traffic stops. **MUST NOT** fail open |
| Catalog unavailable | Deny |
| Purpose-bound data to an out-of-purpose destination | Denied (I-03) |
