# Wave-3 Verification Report

> Honest accounting of Wave-3 — what shipped, what is verified, what is deferred.

## Summary

Wave-3 shipped **6 components at v1.0.0**: S2 ProvenaChain (Rust), S5 DataProvenanceKit,
S7 TamperScan, S8 TrainGuard, A1 SafeEval, A2 Adversaria (all Python). Together they close
the supply-chain + eval portion of the EU AI Act Article 55 story (§1, §2, §3, §7).

**Test totals across the repo: 181 tests passing** (83 Rust + 90 Python + 8 Go), clippy clean,
buf lint clean, cross-language conformance verified.

## What is verified (evidence)

| Component | Version | Language | Tests | Verification |
|---|---|---|---|---|
| **S2 provena-chain** | 1.0.0 | Rust | 11 | Merkle root determinism + order-sensitivity; checkpoint sign/verify + tamper detection; JSON-LD export |
| **S5 data-provenance-kit** | 1.0.0 | Python | 11 | Lineage tracking across 7 transformation types; order-independent snapshot digests; JSON-LD export; CLI |
| **S7 tamper-scan** | 1.0.0 | Python | 13 | 4 analyzers (weight-distribution, backdoor, pruning, fine-tune); numpy acceleration + pure-Python fallback; CLI |
| **S8 train-guard** | 1.0.0 | Python | 15 | Gradient NaN/explosion/vanishing; loss divergence + counter reset; dependency hash; weight-init sanity; signed TrainingAttestation |
| **A1 safe-eval** | 1.0.0 | Python | 10 | 5 stage adapters (benchmarks/adversarial/safety/bias/red_team); pipeline orchestration with error isolation; VEB emission; YAML parsing; CLI |
| **A2 adversaria** | 1.0.0 | Python | 15 | 5 attack generators (prompt-injection/jailbreak/encoding/multi-turn/extraction); per-type detectors; suite run; baseline targets; CLI |

## Cumulative repo status (Waves 1 + 1.5 + 2 + 3)

- **181 tests passing total** (83 Rust + 90 Python + 8 Go).
- clippy clean (`-D warnings`); buf lint clean.
- Cross-language Ed25519 conformance verified (Rust + Python + Go).
- **20 components at v1.0.0** shipped across the 4 waves (Wave-1: 7, Wave-2: 7, Wave-3: 6).
- 8 Python packages installable via `pip install -e ".[dev]"`.
- 6 CI workflows (ci / coverage / sbom / provenance / fuzz / release) + SECURITY.md + dependabot.

## What is explicitly NOT yet verified (deferred to Wave-4+)

| Item | Deferred to | Why |
|---|---|---|
| Real garak / PyRIT invocation in A2 | Wave-4 task 03 | v1.0 ships the framework + 5 built-in generators with deterministic synthetic prompts; the `garak` / `pyrit` optional extras install the backends. Real tool invocation is task 03. |
| Real HELM / LM-Eval / MDASH in A1 | Wave-4 task 03 | v1.0 ships the adapter shape + synthetic metrics; real tool invocation is task 03. |
| Real Rekor HTTPS anchoring in S2 | Wave-4 task 03 | v1.0 produces signed checkpoints that *would* be anchored; the HTTPS POST to Rekor is task 03. |
| Coverage % gate (≥85% hard) | Wave-4 | Coverage workflow in place; baseline measurement on Linux CI is the gate to flipping it hard. |
| GPU-bound verification | out of scope | All Wave-3 components are CPU-only; none need a GPU to verify (S7 TamperScan takes flat weight lists; S8 TrainGuard takes plain floats). |

## How to run the verification yourself

```bash
cd aumos
buf lint

cd rust && cargo test && cargo clippy --all-targets -- -D warnings && cd ..
for p in cuda_gram model_sbom agentsec_lab data_provenance_kit tamper_scan train_guard safe_eval adversaria; do
  (cd python/$p && pip install -e ".[dev]" >/dev/null 2>&1 && pytest -q)
done
cd go/agent-identity && go test ./... && cd ../..

bash tools/conformance/run.sh
bash tools/ci/check-docs.sh

# Wave-3 CLIs
tamper-scan --subject <(echo '{"w":[100.0,0.0]}')   # HIGH finding → exit 1
adversaria run --target-compliant                    # 5 attacks succeed
safe-eval --pipeline pipe.yaml --veb                 # VEB bundle
```

## Conclusion

Wave-3 is **functionally complete and verified**. The supply-chain + eval story (S2/S5/S7/S8/A1/A2)
is now demonstrable end-to-end with synthetic inputs and produces signed, reproducible artifacts
the rest of the system can consume. Wave-4 (inference: N1 OpenServeKit, N2 BridgeRT, N3
InferenceProxy, N4 TenantGuard) is the next concrete step.
