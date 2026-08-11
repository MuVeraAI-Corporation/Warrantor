#!/usr/bin/env sh
# POSIX compatibility entry point; the Python implementation is cross-platform.
set -eu

REPOSITORY_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
PYTHON_EXECUTABLE=${PYTHON:-python3}
exec "$PYTHON_EXECUTABLE" "$REPOSITORY_ROOT/tools/ci/check_docs.py"
