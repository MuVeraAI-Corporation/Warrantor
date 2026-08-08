# Contributing to AumOS

Thank you for your interest in contributing to AumOS! This document describes how to set up your development environment and submit changes.

## Quick Start

```bash
git clone https://github.com/MuVeraAI/aumos.git
cd aumos
make setup   # detects toolchains
make test    # runs all tests
```

## Development Environment

### Required Toolchains

| Language | Version | Install |
|----------|---------|---------|
| Rust | stable | https://rustup.rs |
| Python | 3.11+ | https://python.org |
| Go | 1.22+ | https://go.dev |
| Node.js | 20 LTS | https://nodejs.org |
| Buf | latest | https://buf.build/docs/installation |

### Make Targets

```bash
make help           # list all targets
make setup          # detect and report toolchain status
make lint           # lint all present languages
make test           # test all present languages
make conformance    # run cross-language conformance suite
make fmt            # format all present languages
make docs           # check docs
make clean          # remove build artifacts
```

## Contribution Workflow

1. **Fork** the repository
2. **Branch**: `git checkout -b feat/<component-id>-<short-description>`
3. **Code**: make your changes
4. **Sign off**: every commit must be signed off (`git commit -s`) — this is the DCO
5. **Test**: `make lint test conformance` must all pass
6. **PR**: open a pull request with:
   - Which component/RFC this addresses
   - What changed and why
   - Test coverage delta
7. **Review**: two approvals required (one from the component owner)
8. **Merge**: squash-merge to main

## Commit Message Format

```
<type>(<scope>): <subject>

<body>

DCO: Your Name <your@email.com>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`, `build`
Scope: canonical component ID (e.g., `T1`, `I1`, `R3`)

## DCO (Developer Certificate of Origin)

All contributions must be signed off (`git commit -s`). This certifies that you have the right to submit the work under the Apache 2.0 license. No CLA is required for individual contributors.

## Code Standards

- **Rust**: `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`
- **Go**: `gofmt`, `go vet`
- **Python**: `ruff check`, `ruff format`
- **TypeScript**: `eslint`, `tsc --noEmit`
- All components must have ≥85% test coverage
- Every public function must have a doc comment

## Adding a New Component

1. Write an RFC following the 10-section template (see `docs/rfcs/T1-trust-core.md`)
2. Create the agent handoff files: `CLAUDE.md`, `AGENTS.md`, `PROMPT.md`, `tasks/01-08`
3. Scaffold the component in the appropriate language directory
4. Add it to the workspace config (`Cargo.toml`, `package.json`, etc.)
5. Wire it to `defstack-cli`'s component registry
6. Add cross-language conformance vectors if it involves signing/verification

## Security Vulnerabilities

Do NOT open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md) for private disclosure instructions.

## Code of Conduct

By participating in this project, you agree to abide by the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
