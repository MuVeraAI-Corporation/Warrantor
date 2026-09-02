# Artifact review: Microsoft Agent Governance Toolkit

Status: core artifact reproduced; multi-language and adversarial review pending  
Review date: 2026-08-29  
Repository: `https://github.com/microsoft/agent-governance-toolkit`  
Pinned commit: `46463ef8689433817fcc0c582a7881f515d4df15`  
Declared version: `5.0.0`  
License: MIT

## Decision summary

AGT is a credible high-quality implementation comparator across W1–W6. It is too broad, tested and documented to be dismissed as a vendor announcement. It is also explicitly an application-layer governance toolkit rather than a proof of non-bypassable, outcome-attested control. Warrantor should investigate selective consumption/interoperability with the Agent Control Specification and adapters while differentiating on properties AGT's own documentation leaves outside its boundary.

## Reproduced evidence

| Check | Result | Interpretation |
|---|---|---|
| Shallow clone at pinned commit | Pass | Source and history metadata were accessible |
| Repository inventory | 4,790 files; 1,070 test files | Large, multi-component implementation rather than a paper prototype |
| Language inventory | 1,888 Python; 142 Rust; 57 Go; 343 TypeScript/TSX; 151 C# files | Cross-language claim is materially supported at source level; semantic parity still needs differential testing |
| Project assurance material | 42 workflows; 10 specifications; 35 ADRs; 21 security-audit records | Strong engineering/governance surface; counts do not establish correctness |
| Rust policy-engine compilation | Pass | Core artifact builds in the review environment |
| Rust workspace without OPA | Fail closed at one Rego allow expectation | Revealed an undeclared-at-command-site runtime/test prerequisite, not an allow bypass |
| Rust workspace with OPA on both PATH and `ACS_OPA_PATH` | One negative-test provenance mismatch | Review setup did not match the Rust CI job; explicit environment override changes error source |
| CI-matched Rust workspace: checksum-verified OPA 0.70.0 on PATH, override unset | Pass | The complete invoked Rust policy-engine workspace passed at the pinned commit |

The OPA binary matched the SHA-256 checksum recorded in the repository's generated policy-engine CI workflow: `00d114b94fdb1606a48cccdfc73c9ccdc62c38721150131ae578d5ff3df5c084`.

## Material boundary findings

1. **Wrapper/host contract, not complete mediation.** A core test is explicitly named `retained_unwrapped_rig_like_tool_reference_is_host_contract_bypass`. Governed wrappers cannot stop a caller that retains and invokes an unwrapped reference.
2. **Application isolation.** The repository describes AGT as application-layer middleware and recommends containers/network/IAM for production isolation. Same-process governance is not a boundary against host compromise.
3. **Attempts rather than outcomes.** The limitations document states audit logs record attempts and decisions, not independently verified external-world outcomes.
4. **Audit durability is optional.** Error-handling guidance allows best-effort or fail-open audit while enforcement continues. That may be operationally reasonable but does not satisfy a strict evidence-before-commit invariant without an additional mode.
5. **Initialization matters.** No-policy and permissive configurations can allow actions. Effective enforcement state must be attested and checked, not inferred from package presence.
6. **Sequence and information-flow gaps.** Individually permitted actions can compose into exfiltration; cross-session state, knowledge provenance and credential persistence remain incomplete.
7. **Public-preview maturity.** APIs may change. Upstream compatibility and semantic-version gates are required before Warrantor consumes an interface as stable.
8. **First-party evidence.** Benchmarks and adopter claims need independent reproduction; repository self-reporting is not independent market or efficacy evidence.

## Warrantor build/consume implications

| Area | Decision | Rationale |
|---|---|---|
| Agent Control Specification schemas and fixtures | Evaluate/modify | Avoid inventing another intervention-point vocabulary; verify semantic fit and contribute missing guarantees where possible |
| Cedar/Rego dispatch and policy adapters | Consume or interoperate | Mature policy engines and current artifact tests reduce duplicate implementation burden |
| Multi-language SDK surface | Compare and reuse selectively | Existing breadth is valuable, but Warrantor needs independent canonical vectors and differential conformance |
| Identity/trust/delegation | Interoperate, do not inherit claims wholesale | AGT supplies relevant mechanisms but not W6's proven multi-principal intersection or end-to-end authority/effect binding |
| Audit/receipt layer | Modify substantially | Attempts and same-process logs are insufficient for independent W1/W2 evidence; add receiver/gateway/TEE/witness profiles and completeness semantics |
| Sandbox and kill switch | Treat as middleware controls | W3 must test host, process, network, stale-work and disconnected behavior below the wrapper layer |
| Egress | Differentiate | W5 should close direct network, child-process, DNS and alternate-client paths that application tool wrappers do not universally mediate |

## Remaining reproduction gates

- Run pinned Python, Go, TypeScript and .NET suites using the repository's documented toolchain and lock files.
- Reproduce published benchmarks on declared and independent environments; retain raw distributions and cold-start costs.
- Run cross-language canonical policy/verdict fixtures and mutation tests; record semantic drift.
- Execute bypass tests for unwrapped references, direct sockets, subprocesses, alternate MCP clients and compromised-host assumptions.
- Test audit backend outage, queue saturation, partial writes, chain truncation, external-store disagreement and recovery.
- Verify signatures, identity/delegation chains, kill propagation and credential lifecycle across process/network boundaries.
- Independently verify adopter and governance/hosting claims before using them in business or ecosystem positioning.
