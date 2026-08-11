# warrantor-ocsf

AumOS **OCSF event forwarder**. Receives **AAR** (Agent Action Record) events
from the E1 flight-recorder, converts them to the
[OCSF](https://schema.ocsf.io/) v1.1.0 schema, and ships them to one or more
SIEM sinks (Splunk HEC, Elastic, Datadog, or a local JSONL file).

## Mapping rules

| AAR shape                          | OCSF class_uid | activity_id | severity    |
| ---------------------------------- | -------------- | ----------- | ----------- |
| Generic agent activity             | `6003` (API Activity)        | `1` (Access)         | Info        |
| Attestation verification           | `6003` (API Activity)        | `5` (Authenticate)   | Info        |
| AAR with secret finding            | `6003` (API Activity)        | `1` (Access)         | High (`3`)  |
| Kill-switch trigger                | `6007` (Security Response)   | `6` (Detect)         | Critical (`5`) |
| AAR with error                     | `6003` (API Activity)        | `1` (Access)         | Medium (`3`) |

The full event includes `actor.user`, `api.request` / `api.response`,
`resources` (one entry per secret finding), `metadata.product` (AumOS / MuVera AI)
and a human-readable `message` line.

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
