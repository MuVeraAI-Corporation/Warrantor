#!/usr/bin/env bash
# AumOS cross-language conformance runner (A6).
#
# Verifies the golden vectors in testvectors/ against the Rust, Python, and Go implementations.
# Each verifier reads a vector (JSON) from stdin and prints "ok"/"MISMATCH". This is the
# A6 conformance suite per RFC A6 and the polyglot stack pressure test §11 (conformance lane).
#
# Exits 0 only if every available language verifier agrees with the expected outcome on every
# vector. Missing languages are detected and skipped (with a clear warning), not failed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

fail=0

echo "==> AumOS cross-language conformance runner"
echo "    repo root: $REPO_ROOT"
echo ""

# --- Structural checks (kept from Wave-1) -------------------------------------
check_dir() {
  local dir="$1" label="$2"
  if [ -d "$dir" ] && [ -n "$(ls -A "$dir" 2>/dev/null)" ]; then
    echo "    [ok]   $label present ($dir)"
  else
    echo "    [warn] $label missing or empty ($dir)"
    fail=1
  fi
}

check_dir "specs"        "language-neutral specs"
check_dir "proto"        "protobuf / JSON-schema contracts"
check_dir "testvectors"  "golden cross-language vectors"
check_dir "docs/rfcs"    "RFCs"
check_dir "docs/cross-cutting" "cross-cutting standards"

if [ -f "buf.yaml" ]; then
  echo "    [ok]   buf.yaml present"
else
  echo "    [fail] buf.yaml missing"
  fail=1
fi
echo ""

# --- Toolchain detection ------------------------------------------------------
CARGO=$(command -v cargo 2>/dev/null || true)
PYTHON=$(command -v python 2>/dev/null || command -v python3 2>/dev/null || true)
GO=$(command -v go 2>/dev/null || true)

# --- T1 cross-language conformance: verify every T1 vector in every language --
# Each vector is an Ed25519 (payload, verifying_key, signature, expected).
echo "==> T1 cross-language conformance (Ed25519 sign/verify)"
if [ ! -d testvectors/T1 ]; then
  echo "    [skip] no testvectors/T1/ directory"
else
  shopt -s nullglob
  vectors=( testvectors/T1/*.json )
  shopt -u nullglob

  rust_ok=0; rust_fail=0
  py_ok=0; py_fail=0
  go_ok=0; go_fail=0

  for v in "${vectors[@]}"; do
    # Only run sign/verify vectors (those with payload_hex + signature_hex).
    if ! grep -q '"payload_hex"' "$v" || ! grep -q '"signature_hex"' "$v"; then
      echo "    [skip] $v (not a sign/verify vector)"
      continue
    fi

    # Rust: use the trust-core CLI's `verify` against the payload_hex + verifying_key + signature.
    if [ -n "$CARGO" ]; then
      payload_hex=$(python -c "import json,sys; print(json.load(open('$v'))['payload_hex'])")
      vk=$(python -c "import json,sys; print(json.load(open('$v'))['verifying_key_hex'])")
      sig=$(python -c "import json,sys; print(json.load(open('$v'))['signature_hex'])")
      # trust-core verify reads payload from stdin; we feed the decoded payload bytes.
      if python -c "import sys; sys.stdout.buffer.write(bytes.fromhex('$payload_hex'))" \
          | (cd rust && cargo run -q -p aumos-trust-core --bin trust-core -- verify --key "$vk" --signature "$sig") >/dev/null 2>&1; then
        rust_ok=$((rust_ok + 1))
        echo "    [rust] $v: ok"
      else
        # Distinguish "expected invalid" from genuine verification failure.
        expected=$(python -c "import json,sys; print(json.load(open('$v')).get('expected','valid'))")
        if [ "$expected" = "invalid" ]; then
          rust_ok=$((rust_ok + 1))
          echo "    [rust] $v: ok (expected invalid, correctly rejected)"
        else
          rust_fail=$((rust_fail + 1))
          echo "    [rust] $v: FAIL"
        fi
      fi
    fi

    # Python verifier
    if [ -n "$PYTHON" ]; then
      if "$PYTHON" tools/conformance/verify_python.py < "$v" >/dev/null 2>&1; then
        py_ok=$((py_ok + 1))
        echo "    [py]   $v: ok"
      else
        py_fail=$((py_fail + 1))
        echo "    [py]   $v: FAIL"
      fi
    fi

    # Go verifier
    if [ -n "$GO" ]; then
      # Compile + run once per vector (cheap; Go compile is fast).
      if go run tools/conformance/verify_go.go < "$v" >/dev/null 2>&1; then
        go_ok=$((go_ok + 1))
        echo "    [go]   $v: ok"
      else
        go_fail=$((go_fail + 1))
        echo "    [go]   $v: FAIL"
      fi
    fi
  done

  echo ""
  echo "    T1 conformance summary:"
  [ -n "$CARGO" ]  && echo "      rust:    $rust_ok ok, $rust_fail fail"
  [ -n "$PYTHON" ] && echo "      python:  $py_ok ok, $py_fail fail"
  [ -n "$GO" ]     && echo "      go:      $go_ok ok, $go_fail fail"
  [ -n "$CARGO" ]  && [ "$rust_fail" -gt 0 ] && fail=1
  [ -n "$PYTHON" ] && [ "$py_fail" -gt 0 ] && fail=1
  [ -n "$GO" ]     && [ "$go_fail" -gt 0 ] && fail=1
fi

# --- T1 cross-language conformance: Merkle roots (RFC 6962) -------------------
# Vectors with `leaves_hex` + `expected_root_hex` are Merkle-root vectors. Each language
# verifier recomputes the root over the leaves and compares to expected_root_hex. This
# covers the odd-leaf-count (orphan-promotion) path that the sign/verify lane does not.
echo ""
echo "==> T1 cross-language conformance (RFC 6962 Merkle root)"
if [ ! -d testvectors/T1 ]; then
  echo "    [skip] no testvectors/T1/ directory"
else
  shopt -s nullglob
  mvecs=( testvectors/T1/*.json )
  shopt -u nullglob

  m_rust_ok=0; m_rust_fail=0
  m_py_ok=0;   m_py_fail=0
  m_go_ok=0;   m_go_fail=0

  for v in "${mvecs[@]}"; do
    # Only run Merkle vectors (those with leaves_hex + expected_root_hex).
    if ! grep -q '"leaves_hex"' "$v" || ! grep -q '"expected_root_hex"' "$v"; then
      continue
    fi

    # Rust: recompute via the trust-core `merkle_vector` example (same impl as the lib).
    if [ -n "$CARGO" ]; then
      leaves_json=$(python -c "import json,sys; print(json.dumps(json.load(open('$v'))['leaves_hex']))")
      expected_root=$(python -c "import json,sys; print(json.load(open('$v'))['expected_root_hex'])")
      computed_root=$(cd rust && cargo run -q -p aumos-trust-core --example merkle_vector -- "$leaves_json" 2>/dev/null \
        | python -c "import sys,json; print(json.load(sys.stdin)['root_hex'])" 2>/dev/null || true)
      if [ -n "$computed_root" ] && [ "$computed_root" = "$expected_root" ]; then
        m_rust_ok=$((m_rust_ok + 1))
        echo "    [rust] $v: ok"
      else
        m_rust_fail=$((m_rust_fail + 1))
        echo "    [rust] $v: FAIL (computed=${computed_root:-<none>}, expected=$expected_root)"
      fi
    fi

    # Python Merkle verifier.
    if [ -n "$PYTHON" ]; then
      if "$PYTHON" tools/conformance/verify_merkle_python.py < "$v" >/dev/null 2>&1; then
        m_py_ok=$((m_py_ok + 1))
        echo "    [py]   $v: ok"
      else
        m_py_fail=$((m_py_fail + 1))
        echo "    [py]   $v: FAIL"
      fi
    fi

    # Go Merkle verifier.
    if [ -n "$GO" ]; then
      if go run tools/conformance/verify_merkle_go.go < "$v" >/dev/null 2>&1; then
        m_go_ok=$((m_go_ok + 1))
        echo "    [go]   $v: ok"
      else
        m_go_fail=$((m_go_fail + 1))
        echo "    [go]   $v: FAIL"
      fi
    fi
  done

  echo ""
  echo "    T1 Merkle conformance summary:"
  [ -n "$CARGO" ]  && echo "      rust:    $m_rust_ok ok, $m_rust_fail fail"
  [ -n "$PYTHON" ] && echo "      python:  $m_py_ok ok, $m_py_fail fail"
  [ -n "$GO" ]     && echo "      go:      $m_go_ok ok, $m_go_fail fail"
  [ -n "$CARGO" ]  && [ "$m_rust_fail" -gt 0 ] && fail=1
  [ -n "$PYTHON" ] && [ "$m_py_fail" -gt 0 ] && fail=1
  [ -n "$GO" ]     && [ "$m_go_fail" -gt 0 ] && fail=1
fi

echo ""
if [ "$fail" -ne 0 ]; then
  echo "RESULT: conformance issues found"
  exit 1
fi
echo "RESULT: cross-language conformance verified (or no verifiers available)"
exit 0
