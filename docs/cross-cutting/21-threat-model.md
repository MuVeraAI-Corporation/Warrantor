# 21 — Threat Model: Warrantor as an Attack Surface

> **Status:** normative. Every component RFC must reference this document rather than
> deferring to a "threat-model standard" that did not previously exist.
>
> **Scope:** this document models attacks **against the substrate itself**. Attacks by a
> misbehaving agent against a protected resource are the subject of the per-component
> STRIDE tables and of MITRE ATLAS mappings in P9. Those are the easy direction. This
> document covers the hard one: what happens when the thing enforcing the rules is the
> thing that has been compromised.

---

## 0. Why this document exists

An audit on 2026-08-09 found that of eight ways the substrate can be turned against its
users, **seven had never been analysed anywhere in the repository**. Only confused-deputy
was covered. At the same time, five of the twelve architectural invariants — including
**I-11, *"an agent cannot modify its own enforcement boundary, policy, or identity"*** —
had zero implementing code, and 46 of 54 component RFCs deferred their STRIDE analysis to
a `docs/cross-cutting/` standard that had no filename and did not exist.

A security substrate that has not modelled its own compromise is asking to be trusted on
the basis that nobody has thought about it carefully. This document is the correction.

---

## 1. Adversary model

We name five adversaries. Each is defined by capability, not by intent, because intent is
not observable and capability is.

| ID | Adversary | Capabilities | Explicitly NOT assumed |
|----|-----------|--------------|------------------------|
| **A1** | **Misbehaving agent** | Arbitrary code execution inside its own sandbox; can craft any message it is syntactically able to emit; can choose *not* to call any library; can read its own configuration and credentials. | Cannot break the sandbox; cannot read another tenant's memory. |
| **A2** | **Malicious tool server** | Controls the responses to every tool call routed to it; can lie in its tool descriptors and annotations; can be slow, or absent. | Cannot forge the gateway's identity to third parties. |
| **A3** | **Network adversary** | Full Dolev–Yao on any link not protected by mTLS: read, drop, reorder, replay, inject. | Cannot break Ed25519 or SHA-256. |
| **A4** | **Malicious insider / rogue issuer** | Holds a legitimate credential; may be an authority issuer, a policy author, an approver, or an operator with kill-switch rights. | Does not hold the trust-root private key (that is A5). |
| **A5** | **Root-key holder / supply-chain adversary** | Can sign artifacts the substrate accepts as authoritative; can substitute a dependency or a build artifact. | Assumed to be *detectable but not preventable* by Warrantor alone — see §3.1. |

**Position matters more than label.** A1 is the adversary the product is marketed against;
A4 and A5 are the adversaries that determine whether the product is worth deploying.

---

## 2. Trust boundaries

```
                              ┌──────────────────────────────────────┐
   UNTRUSTED (A1)             │  TRUSTED CORE                        │
 ┌─────────────────┐          │  ┌────────────────────────────────┐  │
 │  Agent runtime  │──────────┼─▶│ trust-core: canonicalise, sign │  │
 │  model + loop   │  B1      │  │ verify, Merkle                 │  │
 └─────────────────┘          │  └────────────────────────────────┘  │
         │                    │  ┌────────────────────────────────┐  │
         │ B2                 │  │ authority-spec: P1 semantics   │  │
         ▼                    │  └────────────────────────────────┘  │
 ┌─────────────────┐          │  ┌────────────────────────────────┐  │
 │  mcp-gateway    │──────────┼─▶│ protocol-contracts: P1–P12     │  │
 │  (enforcement)  │  B3      │  └────────────────────────────────┘  │
 └─────────────────┘          └──────────────────────────────────────┘
         │ B4                            ▲ B5
         ▼                               │
 ┌─────────────────┐          ┌──────────────────────┐
 │  Tool server    │          │  Trust bundle / KMS  │
 │  (A2)           │          │  (root of trust)     │
 └─────────────────┘          └──────────────────────┘
```

| Boundary | Crosses from → to | Enforced by | Current state |
|----------|-------------------|-------------|---------------|
| **B1** | Agent → trusted core | Signature verification on every envelope | Enforced in `protocol-contracts`; **AX-02 fixed** the gateway path |
| **B2** | Agent → gateway | Ed25519 envelope verification + keyId→issuer binding | **Enforced as of AX-02** |
| **B3** | Gateway → trusted core | Library call, same process | **Not a real boundary** — see §3.7 |
| **B4** | Gateway → tool server | mTLS + audience check | Audience checked; mTLS optional and off by default |
| **B5** | Trusted core → trust root | Trust bundle membership | **Enforced as of AX-02** for the gateway; five Rust crates still self-verify (AX-07) |

**The load-bearing admission:** B3 is not a boundary. The gateway and the trusted core are
the same process, so a compromise of either is a compromise of both. Treating them as
separate in a diagram would be theatre.

---

## 3. The eight self-compromise scenarios

### 3.1 Root-key compromise (A5)

**What happens:** every authority envelope, receipt, attestation and evaluation bundle ever
issued becomes forgeable, and — critically — **indistinguishable from a legitimate one**.
There is no signal in the artifact itself.

**Current defence:** none. There is no key rotation procedure, no m-of-n quorum on the
signing key, no transparency-log witness that would let a relying party detect
retrospective issuance.

**Residual risk: ACCEPTED AND HIGH.** Warrantor cannot prevent this. What it must do — and does
not yet — is make it *detectable*:

- Anchor every issuance in an append-only transparency log with an independent witness, so
  a forged artifact must either appear in the log (and be noticed) or fail inclusion proof.
- Publish a signed key-rotation and revocation procedure with a defined m-of-n.
- Bound key validity in time so a stolen key expires without action.

**Tracked as:** open. See §6.

### 3.2 Key rotation and recovery after compromise

**What happens:** with no rotation procedure, the response to a suspected compromise is to
stop the system. There is no defined path from "we think the key leaked" to "we are running
on a new key and old artifacts are correctly re-evaluated."

**Current defence:** none. `T1-trust-core.md` covers KMS on the *signing* side only.

**Requirement:** a rotation procedure must specify what happens to artifacts signed by the
old key — are they invalid, or valid-until-expiry with a cut-off timestamp? Both are
defensible; silence is not.

### 3.3 Malicious or misconfigured policy (A4)

**What happens:** a policy author who can write to the policy corpus can authorise anything.
`policy_digest` in a P2 receipt records *which* policy allowed the action, which is
excellent for forensics and useless for prevention.

**Current defence:** partial. `policy-bridge` correctly default-denies and rejects
fail-open policy documents. But `policies/` was an empty directory until AX-32, and there
is no signing requirement on a policy file.

**Requirement:** policies must be signed by an authority distinct from the agent's issuer,
and `policy_digest` must resolve to a signed artifact. A policy nobody signed is not a
control.

### 3.4 Hostile skill or plugin package (A1 supplying, A2 executing)

**What happens:** P5 defines a signed, permission-scoped skill package. Nothing enforces
the permission scope at runtime, and the MCP registry Warrantor interoperates with performs no
signing at all.

**Current defence:** `sandbox-runtime` is real — genuine Wasmtime fuel metering, WASI
deliberately unlinked, imports admitted against a signed policy, capabilities
index-addressed rather than string-addressed. That is the correct enforcement primitive. It
is not wired to P5's `runtime` enum.

**Requirement:** wire P5 to `sandbox-runtime`, and treat an unsigned skill as untrusted
input rather than as a skill.

### 3.5 Insider / rogue credential issuer (A4)

**What happens:** an issuer with a trusted key mints authority for an agent that should not
have it. Every downstream check passes, because every downstream check is *designed* to
trust the issuer.

**Current defence:** partial as of AX-02 — the gateway now binds `keyId → issuer`, so a key
can only speak for the issuer it is registered against. That contains a *stolen* key to one
issuer's blast radius. It does nothing against a legitimately-held key used maliciously.

**Requirement:** dual control on consequential-class issuance (the `approvalQuorum`
mechanism added in AX-02 is the hook), and issuance logging to a log the issuer cannot
rewrite.

### 3.6 Compromised receipt log / split-view attack

**What happens:** the evidence plane's entire value is that it is append-only and complete.
An adversary who controls the log can present one view to the auditor and another to the
operator — the classic split-view — and no single party can detect it.

**Current defence:** none. There is no witness, no gossip, no consistency proof, and the
Rekor client has never successfully contacted a real transparency log.

**Requirement:** consistency proofs between successive signed tree heads, and at least one
independent witness. Without a witness, an append-only log is append-only *by assertion*.

### 3.7 Control-plane denial of service

**What happens:** if the enforcement path is unavailable, the deployment either stops (fail
closed, availability loss) or proceeds unchecked (fail open, security loss). This is a
policy decision that must be made explicitly per side-effect class.

**Current defence:** inconsistent, and this is the honest finding. `inference-proxy`'s
`DenyAllAuth` default and `policy-bridge`'s `default allow := false` are correct. But four
paths failed open under dependency failure, of which the attestation path was the worst —
`warrantor_vllm` returned `verified=True` for any non-empty strings on real hardware until
AX-27.

**Requirement:** a single documented rule — **read may degrade, everything else denies** —
and a fault-injection test suite that breaks the clock, the mutex, the parser and the
transport, and asserts denial in each case.

### 3.8 Confused deputy via the substrate

**What happens:** the gateway is induced to use its own authority on behalf of a caller who
lacks it.

**Current defence: GOOD, and the one scenario that was already handled well.** The audience
check requires the gateway's SVID in `resources`; the tool-side check requires the tool's
SVID in `tools`; `AUDIENCE_MISMATCH` is a distinct error code; `go/agent-identity` tests the
empty-`aud` bypass explicitly. `X8-mcp-gateway.md`'s STRIDE table is the model the other 53
RFCs should follow.

---

## 4. Invariant I-11 — self-change is governed

> *"An agent cannot modify its own enforcement boundary, policy, or identity."*

This invariant had **zero implementing code**. It is now enforced at the gateway by treating
a defined set of resources as *protected*: no authority envelope, however well-signed, may
authorise a write to the substrate's own enforcement surfaces.

Protected surfaces:

- the trust bundle and any key material;
- the policy corpus and any `policy_digest` target;
- the tool registry and its scope declarations;
- the agent's own authority envelope, revocation handle, or identity document;
- the evidence log.

**Enforcement point:** `McpGateway.authorize()` — see `SELF_CHANGE_PROTECTED_PREFIXES` and
the `self_change_denied` reason code. A tool whose scope touches a protected surface is
denied regardless of the envelope's side-effect class, and the denial is not overridable by
approval, because an agent that can obtain approval to rewrite the policy engine can obtain
approval for anything thereafter.

**Known limitation, stated plainly:** this is enforcement at *one* chokepoint. An agent with
filesystem access to the policy corpus bypasses it entirely. I-11 is only as strong as the
weakest path to those files, which is an OS-level concern the gateway cannot reach. See §5.

---

## 5. What Warrantor does not defend against

Stated explicitly, because a security document without a residual-risk section is marketing.

1. **A compromised trust root.** See §3.1. Detectable at best, and not yet detectable.
2. **An adversary who does not call the gateway.** Enforcement lives in a library. An agent
   with arbitrary code execution and direct network access reaches tool servers without
   passing through any Warrantor code. Closing this requires a network chokepoint, an OS
   boundary, or a credential boundary — an architectural decision, not a patch.
3. **Filesystem-level tampering** with policies, trust bundles or evidence, by anything
   running with sufficient local privilege.
4. **A malicious model.** Warrantor constrains what an agent may *do*, not what it may *think*.
   Prompt injection that stays within granted authority is out of scope by design.
5. **Availability.** There is no DDoS defence, no rate limiting that survives more than one
   replica, and no backpressure.
6. **Side channels.** Timing, cache and speculative-execution attacks are unaddressed.
7. **Correctness of a TEE vendor's attestation.** Warrantor verifies a quote against a vendor
   root; if the vendor root is compromised or the silicon is broken, Warrantor reports success.
8. **Anything at all, currently, in the four components graded `mock_only`.**

---

## 6. Traceability

Each invariant must have a static check, a runtime check, an adversarial test and an
evidence field. Current state, measured rather than asserted:

| Invariant | Code refs | Adversarial test | Status |
|-----------|-----------|------------------|--------|
| I-01 no identity, no action | 0 | no | **OPEN** |
| I-02 delegation attenuates | 7 | yes | partial |
| I-03 purpose-bound context | 0 | no | **OPEN** |
| I-04 memory integrity | 1 | no | **OPEN** |
| I-05 revocation propagates | 9 | yes | partial — durability fixed under AX-40 |
| I-06 artifact provenance | 1 | no | **OPEN** |
| I-07 evidence before commit | 18 | yes | partial — durability fixed under AX-40 |
| I-08 approval for consequential | 35 | yes | **enforced**; quorum added under AX-02 |
| I-09 fail closed | 16 | partial | partial — four fail-open paths found; attestation fixed under AX-27 |
| I-10 replay detectable | 0 | no | **OPEN** — no nonce cache exists |
| I-11 self-change governed | 0 → enforced | yes | **enforced at the gateway** under AX-39; see §4 limitation |
| I-12 physical safe state | 0 | no | **OPEN** |

**Five invariants remain with no implementing code.** They are listed here rather than
omitted, because an invariant nobody implements is a claim, and claims belong in the
residual-risk section until they are code.

---

## 7. References

- Per-component STRIDE tables: `docs/rfcs/T1-trust-core.md`, `docs/rfcs/I1-agent-identity.md`,
  `docs/rfcs/X8-mcp-gateway.md` (the last is the quality bar).
- Error taxonomy: `docs/cross-cutting/20-error-code-registry.md`.
- Inter-component protocol and audience semantics: `docs/cross-cutting/19-inter-component-protocol.md`.
- Incident classification: `specs/protocols/P9-aix.md`, MITRE ATLAS v5.4.0, OWASP Agentic
  Top 10 (ASI01–ASI10, 2026).
