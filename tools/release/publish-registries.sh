#!/usr/bin/env bash
# Publish the crates.io and npm packages that cannot go through Trusted Publishing
# on their first release, because both registries require the package to exist
# before a trusted publisher can be attached to it.
#
# PyPI is NOT here. PyPI supports pending publishers, so all twelve Python
# packages publish from CI via OIDC with no token at any point. Run this only for
# the two registries that genuinely need a first manual push.
#
# ── This script never sees a credential ──────────────────────────────────────
#
# You authenticate first, in your own shell:
#
#     cargo login          # paste your crates.io token at its prompt
#     npm login            # browser-based
#
# The script then uses the session those commands established. It does not read,
# write, print or accept a token, and it refuses to run if you are not already
# logged in — an unauthenticated run would fail halfway, which for a sequential
# publish is the worst possible moment.
#
# ── Why a script rather than a list of commands ──────────────────────────────
#
# The crates are a four-deep dependency chain, and crates.io indexes
# asynchronously. `cargo publish -p warrantor-trust-core` fails if warrantor-api
# is published but not yet visible in the index — and by then warrantor-api is
# irreversibly on the registry. A published version can be yanked but never
# replaced. The waiting is the part worth automating.
#
# Usage:
#     ./publish-registries.sh                 # dry run: shows everything, publishes nothing
#     ./publish-registries.sh --execute       # the real thing
#     ./publish-registries.sh --execute --crates-only
#     ./publish-registries.sh --execute --npm-only

set -euo pipefail

EXECUTE=false
DO_CRATES=true
DO_NPM=true

for arg in "$@"; do
  case "$arg" in
    --execute)     EXECUTE=true ;;
    --crates-only) DO_NPM=false ;;
    --npm-only)    DO_CRATES=false ;;
    -h|--help)     sed -n '2,36p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# Dependency order. Each crate can only be PACKAGED once everything it depends on
# is live on the registry, so this order is mandatory rather than stylistic.
CRATES=(warrantor-api warrantor-trust-core warrantor-authority-spec warrantor-warrant)
NPM_PACKAGES=(mcp-server mcp-gateway protocol-contracts)

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
warn() { printf '\033[33m%s\033[0m\n' "$1"; }
fail() { printf '\033[31m%s\033[0m\n' "$1" >&2; exit 1; }

if [ "$EXECUTE" = false ]; then
  warn "DRY RUN — nothing will be published. Re-run with --execute when the output looks right."
  echo
fi

# ── crates.io ────────────────────────────────────────────────────────────────

wait_for_crate() {
  # crates.io indexes asynchronously; publishing the next crate before its
  # dependency is visible fails, and the failure is unrecoverable in the sense
  # that the earlier publish cannot be taken back.
  local name="$1" tries=0
  printf '  waiting for %s to appear in the index' "$name"
  until curl -sf -A "warrantor-release/1.0" \
        "https://crates.io/api/v1/crates/$name" >/dev/null 2>&1; do
    tries=$((tries + 1))
    if [ "$tries" -gt 60 ]; then
      echo
      fail "  $name did not appear within 5 minutes. Check https://crates.io/crates/$name before continuing — do NOT re-run from the start, the earlier crates are already published."
    fi
    printf '.'
    sleep 5
  done
  echo " visible."
}

publish_crates() {
  bold "crates.io — ${#CRATES[@]} crates, in dependency order"

  if [ "$EXECUTE" = true ]; then
    # `cargo login` writes to the credentials file; its presence is the check.
    # We look for the file, never its contents.
    local cred="${CARGO_HOME:-$HOME/.cargo}/credentials.toml"
    [ -f "$cred" ] || [ -f "${cred%.toml}" ] || \
      fail "not logged in to crates.io. Run 'cargo login' first — this script will not ask you for a token."
  fi

  for crate in "${CRATES[@]}"; do
    if curl -sf -A "warrantor-release/1.0" \
       "https://crates.io/api/v1/crates/$crate" >/dev/null 2>&1; then
      warn "  $crate is already published — skipping."
      continue
    fi

    if [ "$EXECUTE" = false ]; then
      echo "  would publish: cargo publish -p $crate"
      continue
    fi

    bold "  publishing $crate"
    ( cd rust && cargo publish -p "$crate" ) \
      || fail "  $crate failed. Crates published before this point are live and cannot be withdrawn — fix the cause and re-run; already-published crates are skipped automatically."
    wait_for_crate "$crate"
  done
  echo
}

# ── npm ──────────────────────────────────────────────────────────────────────

publish_npm() {
  bold "npm — ${#NPM_PACKAGES[@]} packages under the @warrantor scope"

  if [ "$EXECUTE" = true ]; then
    npm whoami >/dev/null 2>&1 || \
      fail "not logged in to npm. Run 'npm login' first — this script will not ask you for a token."
  fi

  for pkg in "${NPM_PACKAGES[@]}"; do
    local dir="typescript/$pkg"
    [ -d "$dir" ] || fail "  $dir does not exist"

    if npm view "@warrantor/$pkg" version >/dev/null 2>&1; then
      warn "  @warrantor/$pkg is already published — skipping."
      continue
    fi

    if [ "$EXECUTE" = false ]; then
      echo "  would publish: @warrantor/$pkg  (build first, then npm publish --access public)"
      continue
    fi

    bold "  building @warrantor/$pkg"
    ( cd "$dir" && npm install --no-audit --no-fund && npm run build ) \
      || fail "  @warrantor/$pkg failed to build — nothing published for it."

    # --access public is required: scoped packages default to restricted, and
    # the publish fails on a free account without it.
    ( cd "$dir" && npm publish --access public ) \
      || fail "  @warrantor/$pkg failed to publish."
  done
  echo
}

# ── run ──────────────────────────────────────────────────────────────────────

[ "$DO_CRATES" = true ] && publish_crates
[ "$DO_NPM" = true ] && publish_npm

bold "Done."
cat <<'NEXT'

Next, and only after the above succeeded:

  1. Attach trusted publishing so no future release needs a token.
       crates.io  per crate → Settings → Trusted Publishing
       npm        `npm trust` (bulk) or per package
     For both:  repo MuVeraAI-Corporation/Warrantor · workflow publish.yml
                environment crates-io  /  npm

  2. PyPI needs none of this. Configure the twelve pending publishers at
     https://pypi.org/manage/account/publishing/ , then tag:

       git tag v1.0.0 && git push origin v1.0.0

     CI publishes all twelve over OIDC. No token is created at any point.
NEXT
