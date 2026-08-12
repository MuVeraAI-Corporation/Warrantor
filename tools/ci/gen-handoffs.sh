#!/usr/bin/env bash
# Generate agent handoff bundles (CLAUDE.md, AGENTS.md, PROMPT.md, tasks/01..08) for the
# Wave-1 components other than T1 (T1 was hand-written).
#
# Each bundle is component-aware: it pulls the component's name, language, dependencies, and
# purpose from the RFC's metadata table.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RFC_DIR="$REPO_ROOT/docs/rfcs"

# id|name|lang|deps|extra_context_for_agent
read -r -d '' WAVE1 <<'EOF' || true
X1|defstack-cli|Rust (clap)|none|The unified installer/orchestrator. Subcommands: install/verify/upgrade/compliance-report. Reads from a single ~/.aumos/config.yaml. Warrantor moved from Go/Cobra to Rust/clap per stack-test consolidation.
C1-1|nvtrust-bridge|Rust core + Python + Go bindings|none|NVTrust FFI bindings + nvtrust-verify CLI. NVTrust is NVIDIA's GPU attestation library. Offline/mock mode for CI is mandatory — do NOT attempt to download the real NVTrust SDK (NDA-gated). Define a Trait NVTrustBackend with Mock and Real impls.
C1-2|cuda-gram|Python (PyO3)|C1-1|High-level GPU attestation SDK. Exposes AttestationReport, CCSession, AttestationVerifier. Consumes C1-1's Rust core via PyO3 (do not use ctypes — that's the Warrantor original we are migrating away from).
R2|eval-guard|Rust + eBPF (aya)|C1-2|Sandbox boundary attestation. Four pre-flight checks: NetworkIsolation (canary IPs: huggingface.co, pypi.org, 1.1.1.1), FilesystemBoundary, ProcessIsolation, EgressAttestation (eBPF iptables rules, deny-all default). Emits signed SandboxAttestation via T1. Warrantor moved from Go to Rust per trusted-core doctrine. Requires Linux 5.13+ for eBPF; document this in the README.
R3|kill-switch|Rust core + Python policy|I1 (mock)|Three layers: Policy (OPA Rego, evaluated via regorus crate), Decision Engine, Execution (vLLM/Triton/K8s/eBPF). <5s end-to-end. Government Compliance API stub for the AI Kill Switch Act (H.R. 2026). Wave-1 uses the mock I1 from proto/warrantor/identity/v1/agent.proto.
R4|credential-vault|Rust|R3 (mock)|Agent-scoped credential brokering. 15-min TTL scoped tokens bound to SPIFFE identity + task + IP. Integrates HashiCorp Vault, AWS Secrets Manager, K8s Secrets via trait CredentialBackend. Revokes all tokens <1s on kill-switch trigger. Warrantor moved from Go to Rust.
EOF

while IFS='|' read -r id name lang deps extra; do
  [ -z "$id" ] && continue
  [[ "$id" == \#* ]] && continue
  dir="$RFC_DIR/${id}-${name}"
  mkdir -p "$dir/tasks"

  # CLAUDE.md
  cat > "$dir/CLAUDE.md" <<EOF
# CLAUDE.md — ${id} ${name} build instructions

> Paste-target for Claude Code / Cursor / any coding agent building ${id} ${name}.

## What you are building

**${id} ${name}** — ${lang}. You are implementing [\`docs/rfcs/${id}-${name}.md\`](../${id}-${name}.md).
Read it first.

## Repo context (read before coding)

- [\`../../00-reconciliation-matrix.md\`](../../00-reconciliation-matrix.md) — component's place in the portfolio
- [\`../../02-architecture.md\`](../../02-architecture.md) — planes and invariants
- [\`../../cross-cutting/18-developer-experience.md\`](../../cross-cutting/18-developer-experience.md) — workflow, ≥85% coverage, DCO
- [\`../../cross-cutting/19-inter-component-protocol.md\`](../../cross-cutting/19-inter-component-protocol.md) — wire format
- [\`../../cross-cutting/17-data-classification-privacy.md\`](../../cross-cutting/17-data-classification-privacy.md) — data handling

## Component-specific context

${extra}

## Dependencies

- **Warrantor internal:** ${deps}
- **External:** enumerated during MVP (task 02); record in the RFC.

## Build entrypoint

See \`tasks/01-setup.md\`. The component lives under the language folder matching its primary
language (e.g. \`rust/${name//-/_}/\`, \`python/${name//-/_}/\`).

## Conventions

- Consume the contract plane (\`proto/\`, \`specs/\`, \`testvectors/\`); generate bindings, don't hand-write.
- OTel instrumentation on every RPC and long-running operation.
- CycloneDX SBOM in CI; SLSA L3 provenance.
- Sign commits with \`git commit -s\` (DCO).
- No second authoritative implementation of any security invariant (T1 owns those).

## Anti-patterns

See [\`AGENTS.md\`](AGENTS.md).
EOF

  # AGENTS.md (component-aware)
  cat > "$dir/AGENTS.md" <<EOF
# AGENTS.md — ${id} ${name} anti-patterns

What **not** to do when building ${id} ${name}.

## Universal (apply to every component)
- ❌ Don't reinvent SPIFFE, OCSF, OTel, CycloneDX, CloudEvents, OpenSSF Model Signing — extend them.
- ❌ Don't hand-write protobuf messages; generate from \`proto/\`.
- ❌ Don't add a fourth protocol tier (only gRPC internal, REST external, CloudEvents async).
- ❌ Don't commit without \`-s\` (DCO).
- ❌ Don't merge without two reviewer approvals.
- ❌ Don't ship with <85% test coverage.
- ❌ Don't cut a release without an attached CycloneDX SBOM.
- ❌ Don't log PII — redact before logging (per cross-cutting 17).

## ${id}-specific
- ❌ Don't re-implement a security invariant that T1 trust-core owns — call T1.
EOF
  case "$id" in
    R2|R3|R4|C1-1)
      cat >> "$dir/AGENTS.md" <<EOF
- ❌ Don't implement crypto in Python or Go — route through T1.
- ❌ Don't log credentials or attestation reports at trace level — they may contain sensitive material.
EOF
      ;;
  esac
  case "$id" in
    C1-1|C1-2)
      cat >> "$dir/AGENTS.md" <<EOF
- ❌ Don't download the real NVIDIA NVTrust SDK in CI (NDA-gated). Use the documented Mock impl.
- ❌ Don't use ctypes for FFI — use the Rust binding via PyO3 (C1-2 calls C1-1's Rust core).
EOF
      ;;
  esac
  case "$id" in
    R2)
      cat >> "$dir/AGENTS.md" <<EOF
- ❌ Don't run eBPF tests on non-Linux CI; gate them and document Linux 5.13+ requirement.
- ❌ Don't make EvalGuard fail-open on attestation errors — invariant I-09 (failure is safe = fail closed).
EOF
      ;;
  esac
  case "$id" in
    R3)
      cat >> "$dir/AGENTS.md" <<EOF
- ❌ Don't exceed the 5-second end-to-end kill budget — benchmark it in CI.
- ❌ Don't skip the Government Compliance API stub even though the law isn't in force yet.
EOF
      ;;
  esac
  case "$id" in
    R4)
      cat >> "$dir/AGENTS.md" <<EOF
- ❌ Don't exceed the 1-second credential revocation budget — benchmark it.
- ❌ Don't cache credentials longer than their TTL; refresh on use.
EOF
      ;;
  esac

  # PROMPT.md
  cat > "$dir/PROMPT.md" <<EOF
# PROMPT.md — ${id} ${name} master prompt

> Paste this entire file into Claude Code / Cursor / Codex to build ${id} ${name} from scratch.

---

You are implementing **${id} ${name}** for Warrantor. Language: ${lang}. Dependencies: ${deps}.

## Component context

${extra}

## Read first

1. \`docs/rfcs/${id}-${name}.md\` — your spec.
2. \`docs/rfcs/${id}-${name}/CLAUDE.md\` — build conventions.
3. \`docs/rfcs/${id}-${name}/AGENTS.md\` — anti-patterns.
4. \`docs/rfcs/${id}-${name}/tasks/\` — 8 sequenced tickets. **Work them in order.**
5. \`docs/00-reconciliation-matrix.md\` — where this component fits.
6. \`docs/02-architecture.md\` — planes and invariants that apply.

## Hard rules

- Consume the contract plane; generate bindings.
- Call T1 trust-core for any sign/verify operation (do not re-implement).
- Respect invariant I-09: failure is safe = fail closed.
- ≥85% coverage; zero clippy warnings; DCO on every commit.
- No second authoritative implementation of any security invariant.

## Exit gate (Definition of Done)

- All 8 task tickets closed.
- v1.0 tag cut and signed.
- CycloneDX SBOM attached; SLSA L3 provenance.
- \`defstack install ${name}\` works.

Start with \`tasks/01-setup.md\`. Do not skip ahead.
EOF

  # tasks/01..08 — generic-but-component-aware
  task_names=(
    "01-setup:Crate/package skeleton, CI, smoke test"
    "02-mvp:Minimal usable version with the core feature working"
    "03-alpha:External integrations, mock backends, golden vectors"
    "04-beta:All features, conformance green, perf targets measured"
    "05-conformance:Cross-language golden vectors pass in every present language"
    "06-fuzz:Fuzz targets on parsers / untrusted-input paths"
    "07-docs:README, architecture notes, ADRs, RFC update with final status"
    "08-release:v1.0 tag signed, SBOM attached, SLSA L3, external review scheduled if security-critical"
  )
  for entry in "${task_names[@]}"; do
    tnum="${entry%%:*}"
    tname="${entry#*:}"
    cat > "$dir/tasks/${tnum}.md" <<EOF
# Task ${tnum} — ${id} ${name}

> **${tname}**. Acceptance criteria below.

## Objective

${tname} for ${id} ${name}.

## Steps

1. Implement per the RFC [\`docs/rfcs/${id}-${name}.md\`](../../${id}-${name}.md).
2. Follow conventions in [\`CLAUDE.md\`](../CLAUDE.md); avoid anti-patterns in [\`AGENTS.md\`](../AGENTS.md).
3. Add unit tests for every public surface.
4. Add at least one golden vector in \`testvectors/${id}/\`.
5. Wire CI to run lint + test + conformance.
6. Update CHANGELOG.md.

## Acceptance criteria

- [ ] Feature implemented per the RFC.
- [ ] \`cargo test\` / \`pytest\` / \`npm test\` green (per language).
- [ ] Lint clean (\`cargo clippy -D warnings\` / \`ruff\` / \`eslint\`).
- [ ] Coverage ≥85% on new code.
- [ ] Golden vector present.
- [ ] CHANGELOG updated.
- [ ] Commit signed (\`-s\`).

## Out of scope

Anything listed in a later task. Do not skip ahead.
EOF
  done

  echo "Generated handoff bundle for ${id} ${name} → $dir"
done <<< "$WAVE1"
echo "Done."
