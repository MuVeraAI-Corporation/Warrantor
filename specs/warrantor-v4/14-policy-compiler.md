# W4 — The Two-Layer Policy Compiler

> The component that converts Warrantor from *advisory* to *mediated*. Author policy once; compile
> it to the gateway layer **and** to the kernel, so that bypassing Warrantor means bypassing
> execution itself.
>
> **Status:** DRAFT SPEC — Tier B, and the Horizon 2 hinge. Absorbs R5, R6 (as its equivalence test
> harness), and A4.

---

## 1. Why this is the hinge

The adversarial review's sharpest finding was that a trusted core called *advisorily* is exactly as
bypassable as OPA — the host can ignore, cache, or fabricate the verdict. Non-bypassability is a
property of the deployment topology, and Warrantor does not own the kernel.

This component is how it gets into the kernel. Everything else in the portfolio produces better
evidence; **this produces enforcement.** Until it ships, `mediated` mode depends on a gateway being
correctly deployed by someone else, which is a real but weaker guarantee.

---

## 2. Two layers, different jobs

```
                  one authored policy
                          │
              ┌───────────┴────────────┐
              ▼                        ▼
      GATEWAY LAYER              KERNEL LAYER
      Cedar / OPA-Rego           seccomp · Landlock LSM · BPF-LSM
      (via OpenShell)
      semantic, per-action       structural, per-process
      knows: principal,          knows: syscall, path, socket
      capability, artifact       knows nothing about agents
      can deny with a reason     can only deny
```

Neither layer is sufficient alone, and understanding why is the whole design:

- The **gateway layer** understands *what* is happening — this principal, this capability, this
  artifact digest — and can produce a reasoned verdict and a receipt. But an agent that escapes the
  gateway's mediation escapes the policy entirely.
- The **kernel layer** cannot be escaped from inside the process, but it has no notion of a
  principal, a delegation chain, or an artifact digest. It sees a syscall and a path.

Compiling one policy to both gives semantic decisions where semantics exist and an inescapable
floor everywhere else.

---

## 3. The compilation contract

The source policy is authored against the capability vocabulary (`06-capability-algebra.md`), not
against syscalls. Compilation is a **projection**, and projection loses information:

| Property | Rule |
|---|---|
| **Soundness** | Anything the kernel layer permits, the gateway layer must also have permitted. The kernel floor **MUST NOT** be more permissive than the semantic policy |
| **Direction of loss** | The kernel projection **MUST** be *conservative* — where a capability cannot be expressed structurally, the kernel denies rather than permits |
| **No silent widening** | A capability that cannot be projected at all **MUST** produce a compile-time error, never a permissive default |
| **Provenance** | Every emitted artifact carries the source policy digest, compiler version, and target |

> **The uncompilable case is the important one.** A capability like "read customer records the user
> is entitled to" has no kernel expression — entitlement is not a filesystem property. The compiler
> **MUST** reject rather than approximate. Approximating semantic policy into structural policy is
> how a compiler silently grants more than the author wrote, and it would undermine the one
> guarantee this component exists to provide.

---

## 4. Equivalence testing (the absorbed R6)

Two enforcement points that disagree are worse than one, because the disagreement is invisible until
something goes wrong. R6 survives as the **decision-equivalence harness**:

For a corpus of decision inputs, evaluate at both layers and classify:

| Gateway | Kernel | Verdict |
|---|---|---|
| deny | deny | Consistent |
| deny | permit | **DEFECT** — kernel floor is more permissive than the policy |
| permit | deny | Acceptable, and reported. The kernel is conservative; this is expected where semantics don't project |
| permit | permit | Consistent |

**Normative.** Any `deny/permit` result is a **compiler defect** and blocks release. `permit/deny`
results are reported as a **coverage gap**, not a failure — but a gap rate above a declared
threshold means the policy is largely unenforceable at the kernel and the deployment should not
claim broad `mediated` coverage.

This is what makes the enforcement-mode contract's per-class `coverage[]` field truthful rather than
aspirational: it is generated from equivalence testing, not asserted by an operator.

---

## 5. Jurisdiction as modules, not engineering

Regulatory variation is packaging. Jurisdiction modules are **policy libraries** — a US model-risk
module, an India module pairing model-risk with data protection, a Gulf module — composed into the
authored policy and compiled through the same path.

**Normative.** A jurisdiction module **MUST NOT** require compiler changes. If one does, the
abstraction is wrong. The deliverable alongside the modules is the crosswalk report showing one
signed evidence bundle satisfying several supervisory expectations at once — which is the compliance
moat, and it is a documentation artifact, not an engineering programme.

---

## 6. Deployment

Compiled artifacts are content-addressed and signed. Loading one is itself a receipted action, and
the resulting digest is what the enforcement-mode contract's `mediation_digest` refers to.

| Rule | Reason |
|---|---|
| Policy is loaded by the platform, never by the agent | I-11 — self-change is governed |
| An agent **MUST NOT** be able to trigger a reload, rollback, or unload | Same |
| Kernel policy changes are **fail-closed**: if the new policy fails to load, the old one stays | A failed load must not leave the process unconfined |
| Rollout is staged — monitor, canary, enforce — as with any policy change | Policy changes are production changes |

---

## 7. Scope discipline

The **equivalence proof** — a machine-checked demonstration that the two projections agree for all
inputs, not merely for a corpus — is explicitly Tier C and out of scope here. The two-layer
compiler with empirical equivalence testing is the shippable version, and it is what earns
`mediated` mode. Attempting the proof first is precisely the trap the tiering exists to prevent:
the proof is the most interesting artifact and the least likely to ship.

---

## 8. Conformance

| Test | Expected |
|---|---|
| Kernel permits what the gateway denies | **DEFECT** — release blocked |
| Uncompilable capability | Compile-time error, never a permissive default |
| Compiled artifact without source-policy provenance | Rejected |
| Agent triggers a policy reload | Denied (I-11) |
| New kernel policy fails to load | Old policy remains; process never unconfined |
| Jurisdiction module requiring compiler changes | Non-conformant abstraction |
| `coverage[]` asserted without equivalence-test evidence | Non-conformant |
| Gap rate above threshold with broad `mediated` claim | Non-conformant |
