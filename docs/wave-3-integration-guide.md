# Wave-3 Integration Guide — Supply Chain + Eval

> How the six Wave-3 components compose with each other and with Wave-1/Wave-2 to deliver the
> end-to-end AI-supply-chain-integrity story (EU AI Act Article 55 lineage + adversarial testing).

## The Wave-3 supply-chain + eval pipeline

```
                    ┌─────────────────────────────────────────────────┐
                    │  Training (PyTorch / JAX / TF)                  │
                    │       │                                          │
                    │       ▼                                         │
                    │  S8 train-guard ── emits TrainingAttestation ──┐│
                    └────────────────────────────────────────────────┘│
                                                                        ▼
            ┌──────────────────────┐    ┌──────────────────────────────────────┐
S5 input →  │ S5 data-provenance   │    │  S2 provena-chain                     │
            │ records every        │ →  │  appends an Entry per artifact event; │
            │ dataset transform    │    │  Merkle root anchored to Rekor        │
            └──────────────────────┘    └──────────────────────────────────────┘
                                                 │
                                                 ▼
                              ┌──────────────────────────────────────┐
                              │  S1 safe-tensors-pp (Wave-2)          │
                              │  signs __provenance__ on the weights  │
                              └──────────────────────────────────────┘
                                                 │
                ┌────────────────────────────────┴───────────────────────┐
                ▼                                                        ▼
┌──────────────────────────────┐                         ┌──────────────────────────────┐
│ S4 model-sbom                │                         │ S7 tamper-scan               │
│ emits CycloneDX/SPDX with AI │                         │ scans weights for backdoors, │
│ extensions + the S2 lineage  │                         │ pruning, fine-tune signature │
│ + S8 attestation             │                         └──────────────────────────────┘
└──────────────────────────────┘
                                                 │
                                                 ▼
                          ┌──────────────────────────────────────┐
                          │  A1 safe-eval                        │
                          │  runs benchmarks + safety + bias     │
                          │  + red_team stages; emits VEB (P8)   │
                          └──────────────────────────────────────┘
                                                 │
                                                 ▼
                          ┌──────────────────────────────────────┐
                          │  A2 adversaria                       │
                          │  runs 5 attack generators against    │
                          │  the target; A1's adversarial stage  │
                          │  delegates here                     │
                          └──────────────────────────────────────┘
```

## Component-to-component wires

| Producer → Consumer | Wire | Type-stable? |
|---|---|---|
| S5 → S2 | `LineageNode` JSON-LD becomes the `parents` of a `trained` Entry | ✅ shared JSON-LD vocab |
| S8 → S4 | `TrainingAttestation.to_dict()` embedded as a property on the SBOM model component | ✅ dict → JSON property |
| S8 → S2 | `TrainingAttestation` recorded as a `trained` Entry's `metadata` | ✅ BTreeMap<String,String> |
| S2 → S1 | S2's `merkle_root` recorded in S1's `__provenance__.lineage` | ✅ hex string |
| S1 → S4 | S1's `data_digest` populates S4's `model.digest` | ✅ hex string |
| S4 → A1 | S4's model id is A1's `target` | ✅ URI string |
| A1 → A2 | A1's `adversarial` stage delegates to `adversaria.AttackSuite.run` | ✅ same Target protocol |
| A2 → A1 | A2's `RunSummary` becomes the `adversarial` stage's metrics | ✅ Metric records |

## The EU AI Act Article 55 story (now complete for §1, §2, §7, §8)

| Article 55 obligation | Warrantor components |
|---|---|
| §1 Model documentation | S4 model-sbom (CycloneDX/SPDX with AI extensions) |
| §2 Training-data summary | S5 data-provenance-kit (signed JSON-LD lineage) |
| §3 Downstream provider information | S2 provena-chain (parent → child lineage edges) |
| §4 Copyright compliance | A3 bias-sentinel (Wave-6 — copyright module) |
| §5 Technical documentation | S4 + S2 + S1 (signed provenance chain) |
| §6 Systemic-risk assessment | A1 safe-eval + A2 adversaria |
| §7 Adversarial testing | **A2 adversaria (Wave-3)** |
| §8 Serious-incident reporting | X5 retro-spec-kit (Wave-6) + A4 comply-gate (Wave-6) |

A GPAI provider using the full Wave-3 stack can demonstrate **4 of 8** Article 55 obligations
with a single `defstack compliance-report` (§1, §2, §3, §7). The remainder land in Waves 4–6.

## Reproducible end-to-end demo (no real model needed)

```bash
# 1. Record a dataset lineage.
python -c "
from data_provenance_kit import Dataset, SourceType
ds = Dataset.from_source([{'x':1},{'x':2}], SourceType.LOCAL, 'file:///demo')
ds.dedup().filter(lambda r: r['x'] > 0)
import json; print(json.dumps(ds.to_jsonld(), indent=2))" > /tmp/dataset.jsonld

# 2. Run a training loop with train-guard hooks (synthetic).
python -c "
from train_guard import TrainGuard, DependencySnapshot, WeightInitSpec
g = TrainGuard(dependency_snapshot=DependencySnapshot.from_packages({'torch':'2.3.0'}), weight_init=WeightInitSpec('normal'))
for step in range(5):
    g.on_step_end(loss=1.0/(step+1), gradient_norm=0.5, step=step)
import json; print(json.dumps(g.finalize('run-1','model://demo').to_dict(), indent=2))" > /tmp/attestation.json

# 3. Scan weights for tampering.
python -c "
from tamper_scan import scan
import json
r = scan(None, {'layer1': [0.1, -0.2, 0.3, 50.0]})
print(json.dumps(r.to_dict(), indent=2))"

# 4. Run a safe-eval pipeline (uses the synthetic built-in adapters).
safe-eval --pipeline /tmp/pipe.yaml --veb

# 5. Run adversarial attacks against the compliant baseline.
adversaria run --target-compliant
```
