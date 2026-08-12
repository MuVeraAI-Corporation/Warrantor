# 02 — Architecture

> **Naming:** the platform is now **Warrantor**; "Warrantor" below is the historical name, retained in
> paths and package names. Read them as the same system.
>
> **Still authoritative:** the 12 planes and the 12 invariants I-01…I-12 survive v4 intact — the
> research sweep vindicated them, and the alliance's own SAFE issue tracker is requesting several of
> them by other names.
>
> **Amended by v4:** eight of the twelve invariants now cite external validation (HCP's
> execution-control invariants, arXiv 2606.29073); the trusted core is narrowed to the
> decision-plus-proof hot path with enforcement mediation delegated to the kernel and gateways; the
> protocol layer P1–P12 is demoted to *profiles* of one evidence envelope; and Plane 5 (context
> rights) is filled by adopted work rather than new invention. The normative specifications are in
> [`../specs/warrantor-v4/`](../specs/warrantor-v4/); scope and tiering in
> [`03-portfolio-recut-v4.md`](03-portfolio-recut-v4.md).

> The 12-plane pressure-tested architecture and the 12 formal invariants every component must
> satisfy. Derived from the V3 authority pressure test, the polyglot stack pressure test, and the
> Warrantor component DAG.

## 1. Architecture in one paragraph

Warrantor is a **contract-hub monorepo**. A normative, language-neutral contract plane (`specs/`,
`proto/`, `testvectors/`) is the spine. Per-language implementations hang off it: a **Rust trusted
core** owns every security invariant; **Python** owns agents/evals/research outside the trust
boundary; **TypeScript** owns developer surfaces; **Go** is phase-gated for Kubernetes control plane.
The runtime architecture is **12 planes**, each with a failure invariant; **12 formal invariants**
(I-01…​I-12) translate the principles into build-failing properties.

```
                        ┌────────────────────────────────────────┐
   12 · Verification & Response  (E1, X9, R3)
   11 · Evidence & Signals       (E1, P2, AIX)
   10 · Action Commit            (R3, R4, AAR)
    9 · Composite Attestation    (C1-1, C1-2, CAP)
    8 · Runtime Isolation        (R1, R2, R7, R8)
    7 · Tool & Skill Admission   (S4, X8, P5)
    6 · Model/Harness Assurance  (A1, A5, S1, VEB)
    5 · Context Rights           (P3, future context comp)
    4 · Policy & Approval        (R5, R6, AAE/ABS)
    3 · Authority & Budget       (I1, I2, P1, P7)
    2 · Workload Identity        (I1, I2)
    1 · Accountable Principal    (I1)
                        └────────────────────────────────────────┘
                                    ↑ attestation ↑
    0 · Hardware, firmware, GPU, confidential compute  (C1-1 … C1-5)
```

## 2. The 12 Planes (bottom-up)

| # | Plane | Failure invariant | Primary components |
|---|---|---|---|
| 0 | Hardware / GPU / confidential compute | Every attested claim chains to a hardware root of trust | C1-1 nvtrust-bridge, C1-2 cuda-gram, C1-3 attesta-flow, C1-4 tee-serve, C1-5 confidential-fabric |
| 1 | Accountable principal | Every action maps to a named human or governed autonomous principal | I1 agent-identity |
| 2 | Workload identity | No active identity, no action | I1, I2 identity-bindings |
| 3 | Authority & budget | No action exceeds the narrowest authority in the delegation chain; budgets are machine-enforced | I1 (AAE P1), R3 (ABS P7) |
| 4 | Policy & approval | No consequential action without current policy | R5 policy-compiler, R6 policy-bridge |
| 5 | Context rights | Untrusted context cannot silently become trusted instruction or durable memory | (future context components) + P3 CPE |
| 6 | Model / harness assurance | No material capability change ships without risk-relevant regression evidence | A1 safe-eval, A5 agentsec-lab, S1 safe-tensors-pp, P8 VEB |
| 7 | Tool & skill admission | Every tool/skill is signed, scoped, revocable before invocation | S4 model-sbom, X8 mcp-gateway, P5 SSP |
| 8 | Runtime isolation | The agent cannot modify its own ultimate enforcement boundary | R1 secure-workspace, R2 eval-guard, R7 egress-filter, R8 sandbox-runtime |
| 9 | Composite attestation | Attestations compose: hardware → runtime → agent identity | C1-1, C1-2, P12 CAP |
| 10 | Action commit | Evidence precedes commitment | R3 kill-switch, R4 credential-vault, P2 AAR |
| 11 | Evidence & signals | Every material side effect is attributable and independently reviewable | E1 flight-recorder, P2, P9 AIX |
| 12 | Verification & response | Containment remains possible even when the agent or model is compromised | X9 incident-exchange, R3 kill-switch, X6 metr-bridge |

## 3. The 12 Formal Invariants (I-01 … I-12)

Every invariant must have **at least one** static check, runtime check, adversarial test, and
evidence field. A component that breaks an invariant fails CI.

| ID | Invariant | Enforced primarily by |
|---|---|---|
| **I-01** | **No active identity, no action.** Every action carries a verifiable AAE (P1) with a valid, unrevoked SPIFFE SVID. | I1, all components check AAE |
| **I-02** | **No authority expansion.** The intersection of authorities in the delegation chain is the maximum authority; never the union. | I1, R3, MADE (P10) |
| **I-03** | **Purpose-bound data use.** Data tagged with a purpose in CPE (P3) is only used for that purpose; violation fails-closed. | (future context comps), all egress paths |
| **I-04** | **No consequential action without current policy.** Policy is re-evaluated at commit time, not just at start. | R5, R6, R3 |
| **I-05** | **Revocation latency is bounded.** Identity revocation (I1) propagates to all replicas in <5s; credential revocation (R4) in <1s. | I1, R4 |
| **I-06** | **Artifact identity is exact.** A model/skill/dataset is identified by its content digest, not its name or URI. | T1, S1, S4, AATM (P6) |
| **I-07** | **Evidence precedes commitment.** The AAR (P2) is signed *before* the action's effect is visible; the action only commits once evidence is durable. | E1, R3, R4 |
| **I-08** | **Critical actions require non-delegable human authority.** A defined class of actions (financial transfer, destructive op, physical actuation) require a human approval in the chain. | R3, R5, I1 |
| **I-09** | **Failure is safe.** If any plane fails open, the action fails closed. Network loss to I1 = deny. | All |
| **I-10** | **Replay is detectable.** Every action carries a nonce + timestamp; replays outside the window are rejected. | I1, all RPCs |
| **I-11** | **Self-change is governed.** An agent cannot modify its own enforcement boundary, policy, or identity. | R1, R2, R8, R5 |
| **I-12** | **Physical systems can reach a safe state.** For any cyber-physical action, there exists a kill path to a known-safe state. | R3, (future physical authority), R4 |

## 4. Deployment Topologies

| Topology | Use case | Components active | Trust posture |
|---|---|---|---|
| **A · Local dev** | Developer machine | All Wave-1 components; mock I1 | Self-signed; no production data |
| **B · Cloud-managed** | SMB | All components; Warrantor Cloud (X11) hosts control plane | mTLS; SPIFFE; per-tenant isolation |
| **C · Hybrid** | Enterprise | Customer VPC + Warrantor SaaS sync; Helm chart | Customer-owned KMS; audit streaming out |
| **D · Air-gapped sovereign** | Government / regulated | Appliance (X10); no external network | HSM/TPM-backed CA; annual sovereign license |

## 5. The Trusted Core Boundary (where Rust owns)

The Rust workspace (`rust/`) owns, exclusively, every operation that decides allow/deny, signs, or
verifies:

- Authority validation (P1 AAE verify)
- Evidence canonicalization & signing (P2 AAR sign/verify)
- Attestation verification (C1-1, C1-2 verify)
- Revocation enforcement (I1, R4)
- Capability mediation (P12 CAP)
- Sandbox boundary attestation (R2, R8)
- Kill-switch execution (R3)
- eBPF egress filter (R7, S6)
- Cryptographic auditing (X4)

**No other language implements these.** Python, TypeScript, and Go may *call* the Rust core via
generated bindings (PyO3 / napi-rs / FFI), but they never re-implement. The kill criterion from the
stack test: *"More than one language contains authoritative allow/deny logic" → stop and
consolidate.*

## 6. The Contract Plane (where the spec lives)

```
specs/        ← human-readable normative specs (Markdown + CDDL/JSON-Schema)
proto/        ← machine-checked wire contracts (protobuf, Buf-managed)
testvectors/  ← golden cross-language behavior vectors
policies/     ← Rego + Cedar + OpenShell profiles (the compiled form of authority)
```

**The contract plane is the real platform spine.** Every language consumes it identically; breaking
changes here break every implementation. `buf breaking` runs on every PR.

## 7. Reference Foundations (what we adopt, not reinvent)

Warrantor is built *on top of* mature OSS — we extend, we don't fork:

| Foundation | Adopt for | Extend with |
|---|---|---|
| NVIDIA OpenShell | Sandboxed agent runtime | Policy compiler (R5), signed policy bundles, fleet manager |
| NVIDIA NOOA | Agent harness | Security decorators, authority-aware methods (X2 nooa-ext) |
| HPE SPIFFE/SPIRE | Workload identity | Agent identity profiles, delegated authority (I1, I2) |
| Hugging Face Safetensors | Model serialization | Provenance + safety metadata (S1 safe-tensors-pp) |
| IBM/Red Hat Lightwell | Signed patches | AI-artifact patch extension (S9 lightwell-bridge) |
| Microsoft MDASH | Multi-model vuln discovery | Open model-neutral orchestration (A2 adversaria) |
| OpenSSF OSS-CRS / OMS | Cyber reasoning + model signing | Trust hub, runtime attestation |
| garak | LLM red-team | Agent trajectory probes, memory attacks |
| NeMo Guardrails | Runtime guardrails | Policy-driven rail selection (X2) |
| NVIDIA Morpheus | Telemetry anomaly detection | Agent attack-trajectory clustering |
| OpenTelemetry | Observability | Action-receipt overlay (P2) — operational telemetry ≠ signed evidence |
| OCSF | Security event schema | Agent incident extension (P9 AIX) |
| CycloneDX / SPDX | Software BOM | AI extensions (S4 model-sbom) |
| Sigstore / Rekor | Transparency logs | Provenance ledger checkpointing (S2 provena-chain) |

## 8. Cross-component data flow (a single agent action, end-to-end)

```
1. Human (or governed principal) → issues AAE (P1) via I1 agent-identity
2. I1 binds AAE to a SPIFFE SVID (I-01, I-02)
3. Agent starts in R1 secure-workspace; R2 eval-guard verifies sandbox (I-09, I-11)
4. Agent invokes a tool via X8 mcp-gateway; X8 checks S4 model-sbom + P5 SSP (I-06)
5. R4 credential-vault issues a 15-min scoped credential bound to the AAE (I-05)
6. R7 egress-filter enforces network policy; S6 exfil-guard enforces content policy
7. Tool executes; result flows back
8. E1 flight-recorder emits AAR (P2) *before* commit (I-07)
9. A1 safe-eval / R3 kill-switch watch the action stream (I-04, I-12)
10. On anomaly: R3 kills within 5s, R4 revokes creds within 1s (I-05)
11. AAR + any incident flows to X9 incident-exchange (P9 AIX) for response
12. All evidence reviewable by METR via X6 metr-bridge (plane 12)
```

## 9. Threat model summary (full STRIDE per RFC)

Cross-cutting threats (full per-component STRIDE in each RFC):

- **Spoofing** → mTLS + SPIFFE SVIDs (I1) + certificate transparency
- **Tampering** → content-digest identity (I-06) + signed AAR (I-07) + Merkle audit (S2)
- **Repudiation** → every action signed by SVID; Sigstore non-repudiable signatures
- **Information disclosure** → egress default-deny (R7) + sandbox (R8) + DP (F2) + data classification (cross-cutting 17)
- **Denial of service** → per-tenant quotas + rate limiting + reputation scoring
- **Elevation of privilege** → default-deny policy + strictly scoped capability tokens + delegation chain intersection (I-02)

Full 22-attack threat pressure test from the V3 doc is referenced in each component RFC's "Threat
Model" section.

## 10. Performance budgets (per-component targets documented in each RFC)

| Component | Target |
|---|---|
| I1 token validation | <1ms p99 |
| I1 token issuance | 5,000/sec/core |
| R2 sandbox attestation | <100ms cold start |
| R3 kill-switch end-to-end | <5s |
| R4 credential revocation | <1s |
| R7 egress filter overhead | <2% throughput |
| C1-2 GPU attestation verify | <500ms |
| N1 inference proxy overhead | <2ms per request |

## 11. Cross-references

- **Component catalog:** [`00-reconciliation-matrix.md`](00-reconciliation-matrix.md)
- **Vision / roadmap / metrics:** [`01-vision-and-portfolio.md`](01-vision-and-portfolio.md)
- **Inter-component protocol:** [`cross-cutting/19-inter-component-protocol.md`](cross-cutting/19-inter-component-protocol.md)
- **Per-component RFCs:** [`rfcs/`](rfcs/)
