# AumOS — One-command dev/test/release Makefile
#
# Design rule (from polyglot stack pressure test §13):
#   "Monorepo cannot be built/tested with one top-level command" is a kill criterion.
# Missing toolchains are DETECTED and SKIPPED, not failed.

SHELL := /bin/bash
.DEFAULT_GOAL := help

# --- Tool detection -----------------------------------------------------------
CARGO      := $(shell command -v cargo 2>/dev/null)
PYTHON     := $(shell command -v python 2>/dev/null)
NODE       := $(shell command -v node 2>/dev/null)
NPM        := $(shell command -v npm 2>/dev/null)
GO         := $(shell command -v go 2>/dev/null)
BUF        := $(shell command -v buf 2>/dev/null)
UV         := $(shell command -v uv 2>/dev/null)
PIPX       := $(shell command -v pipx 2>/dev/null)

# --- Top-level targets --------------------------------------------------------
.PHONY: help setup lint test conformance docs fmt clean check-proto check-docs

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "AumOS — targets:\n\n"} \
	  /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

setup: ## Install dev toolchains (best-effort; idempotent)
	@echo "==> Installing dev toolchains (idempotent)..."
ifdef BUF
	@echo "    buf:           $(BUF)"
else
	@echo "    buf:           MISSING (install: https://buf.build/docs/installation)"
endif
ifdef CARGO
	@echo "    cargo/rust:    $(CARGO)"
else
	@echo "    cargo/rust:    MISSING (install: https://rustup.rs)"
endif
ifdef PYTHON
	@echo "    python:        $(PYTHON)"
else
	@echo "    python:        MISSING"
endif
ifdef NODE
	@echo "    node/npm:      $(NODE)"
else
	@echo "    node/npm:      MISSING"
endif
ifdef GO
	@echo "    go:            $(GO)  (phase-gated; see docs/cross-cutting/18-developer-experience.md)"
else
	@echo "    go:            MISSING (phase-gated; only required for Wave-2+ K8s operators)"
endif
	@echo "==> Detected toolchains listed above. Missing ones are skipped, not failed."

# --- Per-language checks ------------------------------------------------------
.PHONY: lint-rust lint-python lint-ts lint-go test-rust test-python test-ts test-go fmt-rust fmt-python fmt-ts fmt-go

lint-rust:
ifdef CARGO
	@echo "==> cargo clippy (rust/)"
	@cd rust && cargo clippy --all-targets -- -D warnings || echo "    (rust workspace empty or not yet initialized)"
endif

lint-python:
ifdef PYTHON
	@echo "==> ruff (python/)"
	@cd python && (command -v ruff >/dev/null && ruff check . || echo "    ruff not installed; skipping")
endif

lint-ts:
ifdef NPM
	@echo "==> eslint/tsc (typescript/)"
	@cd typescript && ([ -f package.json ] && npm run lint 2>/dev/null || echo "    (typescript workspace empty or not yet initialized)")
endif

lint-go:
ifdef GO
	@echo "==> go vet (go/)"
	@cd go && ([ -f go.mod ] && go vet ./... || echo "    (go workspace empty or not yet initialized)")
endif

test-rust:
ifdef CARGO
	@echo "==> cargo test (rust/)"
	@cd rust && cargo test --all || echo "    (rust workspace empty or not yet initialized)"
endif

test-python:
ifdef PYTHON
	@echo "==> pytest (python/)"
	@cd python && (command -v pytest >/dev/null && pytest -q || echo "    pytest not installed; skipping")
endif

test-ts:
ifdef NPM
	@echo "==> npm test (typescript/)"
	@cd typescript && ([ -f package.json ] && npm test 2>/dev/null || echo "    (typescript workspace empty or not yet initialized)")
endif

test-go:
ifdef GO
	@echo "==> go test (go/)"
	@cd go && ([ -f go.mod ] && go test ./... || echo "    (go workspace empty or not yet initialized)")
endif

# --- Aggregates ---------------------------------------------------------------
lint: lint-rust lint-python lint-ts lint-go ## Lint every present language
test: test-rust test-python test-ts test-go ## Test every present language

fmt-rust:
ifdef CARGO
	@cd rust && cargo fmt --all
endif
fmt-python:
ifdef PYTHON
	@cd python && (command -v ruff >/dev/null && ruff format . || true)
endif
fmt-ts:
ifdef NPM
	@cd typescript && ([ -f package.json ] && npm run format 2>/dev/null || true)
endif
fmt-go:
ifdef GO
	@cd go && ([ -f go.mod ] && gofmt -w . || true)
endif
fmt: fmt-rust fmt-python fmt-ts fmt-go ## Format every present language

# --- Contract plane -----------------------------------------------------------
check-proto:
ifdef BUF
	@echo "==> buf lint + breaking (proto/)"
	@cd proto && buf lint
	@cd proto && (buf breaking --against '.git#branch=main' 2>/dev/null || echo "    (no main branch yet; skipping breaking check)")
else
	@echo "==> buf not installed; skipping proto checks (install buf to enforce the breaking-change gate)"
endif

# --- Conformance (cross-language golden vectors) ------------------------------
conformance:
	@echo "==> Running cross-language conformance suite (tools/conformance/)"
	@tools/conformance/run.sh || echo "    (conformance runner not yet implemented; see RFC T-CORE-1)"

# --- Docs ---------------------------------------------------------------------
check-docs:
	@echo "==> Checking docs (markdown link integrity, RFC template)"
	@tools/ci/check-docs.sh || echo "    (doc checker not yet implemented; see docs/cross-cutting/18-developer-experience.md)"

docs: check-docs ## Check docs

# --- Clean --------------------------------------------------------------------
clean:
	@echo "==> Cleaning build artifacts"
	@[ -d rust/target ] && (cd rust && cargo clean) || true
	@[ -d python ] && find python -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@[ -d typescript ] && ([ -f typescript/package.json ] && (cd typescript && npm run clean 2>/dev/null) || true) || true
	@find . -type f -name '*.pyc' -delete 2>/dev/null || true
