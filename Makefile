# Warrantor strict, one-command development and verification entry point.
#
# Every target is fail-closed: a missing toolchain, empty project set, failed
# check, or broken conformance vector returns a non-zero status.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

PYTHON ?= python3

demo: ## Show the system working end to end: sign an action, log it, verify the proof
	@$(PYTHON) tools/demo/evidence_demo.py

sigstore-up: ## Start the local transparency log (MySQL + Trillian + Rekor)
	@docker compose -f deploy/local-sigstore/docker-compose.yml up -d
	@echo "then: ./deploy/local-sigstore/bootstrap.sh"

# Three steps, in this order, because the order is forced by the schema: `archive_runtime` does not
# exist until the migration has run, so its password cannot be set before that, and the server cannot
# authenticate until it is set, so the server starts last. A single `up -d` cannot work: compose
# refuses to interpolate ${ARCHIVE_RUNTIME_PASSWORD:?} if it is unset, and even when it is set the
# archive container cannot log in until the ALTER ROLE below has run.
archive-up: ## Start the evidence archive (Postgres, schema, runtime password, server)
	@: "$${POSTGRES_PASSWORD:?export POSTGRES_PASSWORD first — see deploy/evidence-archive/README.md}"
	@: "$${ARCHIVE_RUNTIME_PASSWORD:?export ARCHIVE_RUNTIME_PASSWORD first — see deploy/evidence-archive/README.md}"
	@docker compose -f deploy/evidence-archive/docker-compose.yml up -d db
	@docker compose -f deploy/evidence-archive/docker-compose.yml run --rm migrate
	@docker compose -f deploy/evidence-archive/docker-compose.yml exec -T \
	  -e PGPASSWORD="$$POSTGRES_PASSWORD" db \
	  psql -U archive_admin -d warrantor_archive -v ON_ERROR_STOP=1 \
	  -c "ALTER ROLE archive_runtime PASSWORD '$$ARCHIVE_RUNTIME_PASSWORD'"
	@docker compose -f deploy/evidence-archive/docker-compose.yml up -d archive
	@echo "then: deploy/evidence-archive/README.md — enrol a device"

# The database-backed tests are #[ignore]d so `cargo test --workspace` stays green in CI, which has
# no Postgres. This target is what actually runs them, and it is deliberately separate rather than
# folded into `test-rust`: a gate that silently needs a service is a gate that silently stops
# gating.
#
# BOTH URLs, and they are different roles on purpose. One connection cannot distinguish "the trigger
# refused" from "this role was never granted UPDATE", which is exactly how this crate once claimed to
# cover a trigger that had never fired.
archive-test: ## Run the archive's Postgres-backed tests (needs `make archive-up`)
	@: "$${POSTGRES_PASSWORD:?export POSTGRES_PASSWORD first — see deploy/evidence-archive/README.md}"
	@: "$${ARCHIVE_RUNTIME_PASSWORD:?export ARCHIVE_RUNTIME_PASSWORD first — see deploy/evidence-archive/README.md}"
	@cd rust && \
	  WARRANTOR_ARCHIVE_DATABASE_URL="postgres://archive_admin:$$POSTGRES_PASSWORD@127.0.0.1:5433/warrantor_archive" \
	  WARRANTOR_ARCHIVE_RUNTIME_DATABASE_URL="postgres://archive_runtime:$$ARCHIVE_RUNTIME_PASSWORD@127.0.0.1:5433/warrantor_archive" \
	  cargo test -p warrantor-archive -- --ignored

.PHONY: help setup require-tools verify build lint test fmt fmt-check tracker \
	build-rust build-ts lint-rust lint-python lint-ts lint-go \
	test-rust test-python test-ts test-go fmt-rust fmt-python fmt-go \
	fmt-check-rust fmt-check-python fmt-check-go check-proto check-protocols conformance \
	check-docs docs clean demo sigstore-up archive-up archive-test

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*##"; printf "Warrantor strict targets:\n\n"} \
	  /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

require-tools: ## Fail unless every required toolchain is available
	@command -v cargo >/dev/null
	@command -v "$(PYTHON)" >/dev/null
	@command -v go >/dev/null
	@command -v node >/dev/null
	@command -v npm >/dev/null
	@command -v buf >/dev/null
	@"$(PYTHON)" -c "import cryptography, pytest, ruff"
	@printf 'cargo:  '; cargo --version
	@printf 'python: '; "$(PYTHON)" --version
	@printf 'go:     '; go version
	@printf 'node:   '; node --version
	@printf 'npm:    '; npm --version
	@printf 'buf:    '; buf --version

setup: require-tools ## Validate toolchains and install locked TypeScript dependencies
	@cd typescript && npm ci

build-rust:
	@echo "==> Rust build"
	@cd rust && cargo build --workspace --all-targets

build-ts:
	@echo "==> TypeScript build"
	@cd typescript && npm run build

build: build-rust build-ts ## Build every compiled workspace

lint-rust:
	@echo "==> Rust clippy"
	@cd rust && cargo clippy --workspace --all-targets -- -D warnings

lint-python:
	@echo "==> Python lint (all projects)"
	@"$(PYTHON)" tools/ci/run_python_checks.py lint

lint-ts:
	@echo "==> TypeScript lint and conformance typecheck"
	@cd typescript && npm run lint
	@cd typescript && npm run typecheck:conformance

lint-go:
	@echo "==> Go vet (all modules)"
	@"$(PYTHON)" tools/ci/run_go_checks.py vet

lint: lint-rust lint-python lint-ts lint-go ## Lint every language and module

test-rust:
	@echo "==> Rust tests"
	@cd rust && cargo test --workspace --all-targets

test-python:
	@echo "==> Python tests (all projects)"
	@"$(PYTHON)" tools/ci/run_python_checks.py test

test-ts:
	@echo "==> TypeScript tests"
	@cd typescript && npm test

test-go:
	@echo "==> Go tests (all modules)"
	@"$(PYTHON)" tools/ci/run_go_checks.py test

test: test-rust test-python test-ts test-go ## Test every language and module

fmt-check-rust:
	@cd rust && cargo fmt --all -- --check

fmt-check-python:
	@"$(PYTHON)" tools/ci/run_python_checks.py format

fmt-check-go:
	@unformatted="$$(gofmt -l $$(find go -type f -name '*.go'))"; \
	  if [ -n "$$unformatted" ]; then printf '%s\n' "$$unformatted"; exit 1; fi

fmt-check: fmt-check-rust fmt-check-python fmt-check-go ## Verify formatting without modifying files

fmt-rust:
	@cd rust && cargo fmt --all

fmt-python:
	@for project in python/*; do \
	  if [ -d "$$project/src" ]; then \
	    "$(PYTHON)" -m ruff format "$$project/src" "$$project/tests"; \
	  fi; \
	done

fmt-go:
	@gofmt -w $$(find go -type f -name '*.go')

fmt: fmt-rust fmt-python fmt-go ## Format every supported language

check-proto: ## Lint protobuf contracts and reject breaking changes from main
	@echo "==> Protobuf contract plane"
	@buf lint
	@buf breaking --against '.git#branch=main'

check-protocols: ## Reject drift between registry.json and every generated protocol artifact
	@echo "==> Protocol codegen drift"
	@"$(PYTHON)" tools/protocols/generate.py --check

conformance: ## Run the required Rust/Python/Go/TypeScript vector matrix
	@echo "==> Cross-language conformance"
	@"$(PYTHON)" tools/conformance/run.py

check-docs:
	@echo "==> Documentation structure"
	@"$(PYTHON)" tools/ci/check_docs.py

docs: check-docs ## Check documentation contracts

tracker: ## Generate exhaustive machine-readable implementation inventory
	@"$(PYTHON)" tools/implementation/generate_tracker.py

verify: require-tools check-proto check-protocols fmt-check lint test build conformance docs tracker ## Run every required repository gate

clean: ## Remove generated build and cache artifacts
	@echo "==> Cleaning generated artifacts"
	@cd rust && cargo clean
	@find python -type d -name __pycache__ -prune -exec rm -rf {} +
	@find python -type f -name '*.pyc' -delete
	@find typescript -type f -name '*.tsbuildinfo' -delete
	@find typescript -type d -name dist -prune -exec rm -rf {} +
