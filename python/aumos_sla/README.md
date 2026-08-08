# aumos-sla

Rolling-window **SLA monitor** for AumOS. Records metric samples and evaluates
them against `SLATarget` definitions.

## Model

An `SLATarget` specifies:

- `metric_name` — name of the metric this target applies to.
- `threshold` — numeric boundary value.
- `window_seconds` — how far back (in seconds) to look when evaluating.
- `comparison` — `lt` (value < threshold), `gt` (value > threshold), or
  `eq` (value == threshold).

A target is **meeting** the SLA if *every* sample inside the rolling window
satisfies the comparison, and **breaching** if *any* sample violates it. With
no target registered or no samples in the window the status is `UNKNOWN`.

## Typical AumOS metrics

| Metric                            | Threshold | Comparison | Window | Meaning                          |
| --------------------------------- | --------- | ---------- | ------ | -------------------------------- |
| `inference.p99_latency_ms`        | 500       | `lt`       | 60s    | Inference latency SLA            |
| `killswitch.trigger_to_kill_s`    | 5         | `lt`       | 60s    | Kill-switch latency (R3)         |
| `evidence.commit_lag_s`           | 60        | `lt`       | 60s    | AAR commit lag (invariant I-07)  |
| `attestation.verify_success_rate` | 0.99      | `gt`       | 300s   | Attestation verification health  |

## Usage

```python
from aumos_sla import SLAMonitor, SLAStatus, SLATarget

monitor = SLAMonitor()
monitor.add_target(SLATarget("p99_latency_ms", threshold=500,
                             window_seconds=60, comparison="lt"))
monitor.record_metric("p99_latency_ms", 410)
assert monitor.check_status("p99_latency_ms") is SLAStatus.MEETING

breaches = monitor.active_breaches()
```

## Properties

- **Thread-safe**: all reads and writes take an internal lock.
- **Bounded pruning**: stale samples are dropped lazily on every read.
- **Deterministic**: `now` can be supplied for reproducible tests.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```
