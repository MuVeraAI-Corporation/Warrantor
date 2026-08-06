#!/usr/bin/env bash
# AumOS cross-language conformance runner.
#
# Wave-0 stub: validates the structural shape of the contract plane (specs/, proto/,
# testvectors/) and reports a clean "no components yet" result. Real conformance
# (per RFC T-CORE-1) lands in Wave-1 once trust-core, agent-identity, and the
# golden vectors exist.
#
# Exits 0 on success. Designed to be safe to call from `make conformance` even when
# no components are implemented yet.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

echo "==> AumOS conformance runner (Wave-0 structural checks)"
echo "    repo root: $REPO_ROOT"

fail=0
check_dir() {
  local dir="$1" label="$2"
  if [ -d "$dir" ] && [ -n "$(ls -A "$dir" 2>/dev/null)" ]; then
    echo "    [ok]   $label present ($dir)"
  else
    echo "    [warn] $label missing or empty ($dir)"
    fail=1
  fi
}

# Structural contract-plane directories must exist (per README + stack test §10)
check_dir "specs"        "language-neutral specs"
check_dir "proto"        "protobuf / JSON-schema contracts"
check_dir "testvectors"  "golden cross-language vectors"
check_dir "docs/rfcs"    "RFCs"
check_dir "docs/cross-cutting" "cross-cutting standards"

# Buf-managed proto must have a buf.yaml at repo root (enforces breaking-change gate)
if [ -f "buf.yaml" ]; then
  echo "    [ok]   buf.yaml present (contract breaking-change gate configured)"
else
  echo "    [fail] buf.yaml missing at repo root"
  fail=1
fi

# Makefile must exist and expose the standard targets (stack test kill-criterion #7)
if [ -f "Makefile" ]; then
  for tgt in help conformance lint test docs; do
    if grep -q "^${tgt}:" Makefile; then
      echo "    [ok]   make target: ${tgt}"
    else
      echo "    [fail] make target missing: ${tgt}"
      fail=1
    fi
  done
else
  echo "    [fail] Makefile missing"
  fail=1
fi

echo ""
if [ "$fail" -ne 0 ]; then
  echo "RESULT: structural issues found (see warnings above)"
  exit 1
fi
echo "RESULT: contract plane structurally sound. No components implemented yet —"
echo "        real cross-language conformance lands in Wave-1 (see RFC T-CORE-1)."
exit 0
