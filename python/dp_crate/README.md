# warrantor-dp-crate (F2)

Production-grade differential privacy toolkit. Three components:

- `DPSGDOptimizer` — clips per-example gradients to a fixed L2 bound, then adds calibrated
  Gaussian noise (the canonical Abadi et al. 2016 DPSGD recipe).
- `PrivacyAccountant` — tracks the (ε, δ) budget via Rényi Differential Privacy (Mironov 2017).
  Composition is additive in RDP space; conversion to (ε, δ) uses the Balle et al. 2020 bound.
- `DPDashboard` — serializable budget snapshot for ops dashboards.

The crate is intentionally pure-Python (no numpy/torch) so it can run inside a TEE and be
audited line-by-line.

## Quickstart

```python
from dp_crate import (
    AccountantConfig, PrivacyAccountant, DPSGDOptimizer, DPDashboard,
)

cfg = AccountantConfig(
    noise_multiplier=1.5, sampling_rate=0.005, delta=1e-5, target_epsilon=2.0,
)
accountant = PrivacyAccountant(cfg)
opt = DPSGDOptimizer(clipping_norm=1.0, noise_multiplier=1.5, accountant=accountant)

for batch in dataset:
    grads = [per_example_gradient(x) for x in batch]
    update = opt.private_step(grads, learning_rate=0.01)
    apply_update(model, update)

print(DPDashboard.from_accountant(accountant, clipping_norm=1.0).to_json())
```

## Key properties

- **RDP composition is additive**: `consume(2)` == `consume(1)` twice.
- **Per-step RDP** uses the subsampled-Gaussian upper bound (Mironov et al. 2019), exact at
  q=0 and q=1, conservative in between.
- **RDP → (ε, δ)** picks the tightest order from the alpha grid.
- **Budget gate**: `consume()` raises `BudgetExhausted` past `target_epsilon`; `try_consume()`
  returns `False` instead.

## References

- Abadi et al. 2016, "Deep Learning with Differential Privacy" (DPSGD).
- Mironov 2017, "Rényi Differential Privacy" (RDP).
- Mironov et al. 2019, "Rényi Differential Privacy of the Sampled Gaussian Mechanism".
- Balle et al. 2020, "Hypothesis Testing Interpretations of Rényi Differential Privacy".
- RFC `docs/rfcs/F2-dp-crate.md`.
