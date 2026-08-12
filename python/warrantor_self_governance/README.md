# warrantor-self-governance (Python)

**SG1 Self-governance keystone — Python verify path for self-governance conformance reports.**

The platform's own AI (NL console, policy compiler, risk scorer, audit fleet) is governed by
Warrantor itself. This package verifies the signed conformance reports the Rust checker issues.

## Test

```bash
PYTHONPATH=src pytest tests/ -v
```
