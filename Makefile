SHELL := /bin/bash
PYTHON := $(shell command -v python3)
export PATH := /usr/bin:$(PATH)
export PYTHONDONTWRITEBYTECODE := 1
export CARGO_TARGET_DIR := $(CURDIR)/target
.PHONY: ci check test test-pg test-oidc dependencies licenses
ci: check test dependencies licenses test-pg test-oidc test-federated test-downstream
check:
	cargo fmt --all -- --check
	cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
	cargo check --locked --workspace --lib

test:
	$(PYTHON) -m unittest discover -s hack -p 'test_*.py'
	cargo test --locked --workspace

dependencies:
	$(PYTHON) hack/check_dependencies.py
	$(PYTHON) hack/check_consumer.py

licenses:
	cargo deny --locked check advisories licenses sources

test-pg:
	$(PYTHON) hack/providers.py pg

test-oidc:
	$(PYTHON) hack/providers.py oidc

.PHONY: test-federated
test-federated:
	$(PYTHON) hack/providers.py federated

.PHONY: test-downstream
test-downstream:
	$(PYTHON) hack/downstream.py
