#!/usr/bin/env bash
# Compatibility entrypoint for POSIX environments. The authoritative runner is
# run.py so Windows, Linux, and CI execute identical conformance logic.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON_BIN="$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)"

if [ -z "$PYTHON_BIN" ]; then
  echo "conformance: Python 3.11+ is required" >&2
  exit 2
fi

exec "$PYTHON_BIN" "$REPO_ROOT/tools/conformance/run.py" "$@"
