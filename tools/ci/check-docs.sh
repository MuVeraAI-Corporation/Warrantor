#!/usr/bin/env bash
# AumOS documentation checker.
#
# Wave-0 stub: validates that the core docs exist and that every RFC follows the
# 10-section template (per DefStack RFC convention). Real markdown link checking
# and richer linting land with RFC C-CUT-18 (developer experience).
#
# Exits 0 on success.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

echo "==> AumOS doc checker (Wave-0 structural checks)"

fail=0

# Required top-level docs (per README + plan 0.2 / 0.3 / 0.4)
for doc in \
  "docs/00-reconciliation-matrix.md" \
  "docs/01-vision-and-portfolio.md" \
  "docs/02-architecture.md" \
  "docs/cross-cutting/17-data-classification-privacy.md" \
  "docs/cross-cutting/18-developer-experience.md" \
  "docs/cross-cutting/19-inter-component-protocol.md"
do
  if [ -f "$doc" ]; then
    echo "    [ok]   $doc"
  else
    echo "    [miss] $doc"
    fail=1
  fi
done

echo ""

# RFC template check: every RFC in docs/rfcs/ must contain the 10 section headers.
required_sections=(
  "^# .+RFC"
  "^## .*Background"
  "^## .*Goals"
  "^## .*Detailed Design"
  "^## .*Dependencies"
  "^## .*Threat Model"
  "^## .*API"
  "^## .*Testing"
  "^## .*Deployment"
  "^## .*Milestones"
)

shopt -s nullglob
rfcs=( docs/rfcs/*.md )
if [ "${#rfcs[@]}" -eq 0 ]; then
  echo "    [info] no RFCs yet in docs/rfcs/ (expected during Phase 0.5)"
else
  for rfc in "${rfcs[@]}"; do
    missing=0
    for pat in "${required_sections[@]}"; do
      if ! grep -qE "$pat" "$rfc"; then
        missing=$((missing + 1))
      fi
    done
    if [ "$missing" -gt 0 ]; then
      echo "    [warn] $rfc missing $missing of ${#required_sections[@]} required sections"
      fail=1
    else
      echo "    [ok]   $rfc (10/10 sections)"
    fi
  done
fi

echo ""
if [ "$fail" -ne 0 ]; then
  echo "RESULT: doc issues found (see above)"
  exit 1
fi
echo "RESULT: docs structurally sound."
exit 0
