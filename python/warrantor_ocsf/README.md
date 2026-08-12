# warrantor-ocsf

AumOS **OCSF event forwarder**. Receives **AAR** (Agent Action Record) events
from the E1 flight-recorder, converts them to the
[OCSF](https://schema.ocsf.io/) v1.9.0 schema, and ships them to one or more
SIEM sinks (Splunk HEC, Elastic, Datadog, or a local JSONL file).

## Mapping rules

Every event is class `6003` (API Activity) in category `6` (Application
Activity). The class carries the payload; **significance is carried by
`severity_id`, not by the class**.

`activity_id` is derived from the AAR's `side_effect_class`, and must be one of
the six values OCSF defines for class 6003 — there is no "Access", no
"Authenticate" and no "Detect" activity on this class:

| `side_effect_class`      | `activity_id`  |
| ------------------------ | -------------- |
| `read`, `none`           | `2` (Read)     |
| `write`, `create`, `append` | `1` (Create)  |
| `update`, `modify`       | `3` (Update)   |
| `delete`, `destroy`      | `4` (Delete)   |
| present but unrecognised | `99` (Other)   |
| absent                   | `0` (Unknown)  |

Attestation verification maps to `99` (Other). OCSF 6003 has no Authenticate
activity; class `3002` (Authentication) is the correct long-term home.

`severity_id` uses the OCSF enum (`1` Informational, `2` Low, `3` Medium,
`4` High, `5` Critical):

| AAR shape               | `severity_id`    |
| ----------------------- | ---------------- |
| Kill-switch trigger     | `5` (Critical)   |
| Secret finding          | `4` (High)       |
| Tool error              | `3` (Medium)     |
| Everything else         | `1` (Informational) |

The full event includes `actor.user`, `actor.application`, `src_endpoint`,
`api.request` / `api.response`, `resources` (one entry per secret finding),
`metadata.product` (AumOS / MuVera AI) and a human-readable `message` line.
`metadata.version` is the **OCSF schema** version; this package's own version is
`metadata.product.version`.

`time` is milliseconds since the epoch, per OCSF `timestamp_t`.

### Validating

`tests/test_ocsf_schema.py` pins these rules offline, so CI enforces them without
a network call. To re-check them against the published schema — do this when
bumping `OCSF_VERSION` — run:

```bash
python tools/audit/ocsf_validate.py
```

## Sinks

- `FileSink(path)` — appends each event as one JSON line. Use in tests.
- `HTTPSink(url, token=...)` — POSTs each event to a Splunk HEC / Elastic /
  Datadog endpoint. Uses only the standard library.

Sinks implement the `Sink` protocol: `send(event: dict) -> bool`. Implement
your own sink (e.g. Kafka producer) by satisfying the protocol.

## Properties

- **Best-effort fan-out**: each sink is tried in registration order. A sink
  that returns `False` or raises does not abort delivery to the remaining
  sinks, so a flaky SIEM cannot block a healthy one.
- **Counters**: `stats.forwarded` / `stats.succeeded` / `stats.failed`.
- **Thread-safe**: all stats updates take a lock.

## Usage

```python
from warrantor_ocsf import OCSFForwarder, HTTPSink, FileSink

fwd = OCSFForwarder()
fwd.add_sink(HTTPSink("https://splunk:8088/services/collector", token="..."))
fwd.add_sink(FileSink("/var/log/warrantor-ocsf.jsonl"))

# Forward a single AAR:
fwd.forward(aar_event)

# Or a batch:
fwd.batch_forward([aar1, aar2, aar3])

print(fwd.stats.succeeded, fwd.stats.failed)
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```
