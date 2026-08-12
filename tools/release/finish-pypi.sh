#!/usr/bin/env bash
# Upload the warrantor-* packages PyPI has not accepted yet.
#
# PyPI limits how many NEW projects an account may create in a rolling window
# ("429 Too many new projects created"). It is not a burst limit -- short pauses
# do not clear it, and the window is measured in hours. The 19 pre-existing
# projects on this account count toward it, which is why it tripped after four.
#
# So this is idempotent and resumable: it skips anything already live, uploads
# only what is missing, and stops cleanly on a 429 rather than hammering.
# Re-run it whenever; it will pick up exactly where it left off.
#
#   bash tools/release/finish-pypi.sh              # one pass
#   bash tools/release/finish-pypi.sh --watch      # retry every 30 min until done

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

DIST="$(cat "$LOCALAPPDATA/Temp/pypi-dist-dir.txt" 2>/dev/null || cat /tmp/pypi-dist-dir.txt 2>/dev/null)"
[ -d "$DIST" ] || { echo "no dist dir; rebuild with: python -m build --outdir <dir> python/<pkg>"; exit 1; }

PACKAGES=(warrantor_admission warrantor_agent warrantor_backup warrantor_harness
          warrantor_hf_plugin warrantor_jira warrantor_langchain warrantor_ocsf
          warrantor_rbac warrantor_retention warrantor_sla warrantor_vllm)

attempt() {
  local done_count=0 remaining=0 limited=0
  for name in "${PACKAGES[@]}"; do
    local proj="${name//_/-}"
    if curl -s -o /dev/null -w '%{http_code}' --max-time 10 "https://pypi.org/pypi/$proj/json" | grep -q 200; then
      done_count=$((done_count+1)); continue
    fi
    remaining=$((remaining+1))
    [ "$limited" -eq 1 ] && continue      # window is closed; do not keep asking

    local out
    out=$(python -m twine upload "$DIST"/${name}-*.whl "$DIST"/${name}-*.tar.gz 2>&1)
    if echo "$out" | grep -q "429"; then
      echo "  rate limited at $proj — new-project quota still closed"
      limited=1
    elif echo "$out" | grep -qi "error"; then
      echo "  FAILED $proj"; echo "$out" | grep -i error | head -2
    else
      echo "  published $proj"; done_count=$((done_count+1)); remaining=$((remaining-1))
      sleep 15
    fi
  done
  echo "  -> $done_count/12 live, $remaining remaining"
  [ "$remaining" -eq 0 ]
}

if [ "${1:-}" = "--watch" ]; then
  while ! attempt; do
    echo "  sleeping 30 min for the quota window..."
    sleep 1800
  done
  echo "All 12 published."
else
  attempt || echo "Re-run later, or use --watch to retry automatically."
fi
