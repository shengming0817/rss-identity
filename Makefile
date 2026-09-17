SHELL := /bin/bash
PYTHON := $(shell command -v python3)
REPOSITORY_ROOT := $(shell /usr/bin/dirname "$$(/usr/bin/git rev-parse --path-format=absolute --git-common-dir)")
export PATH := /usr/bin:$(PATH)
export PYTHONDONTWRITEBYTECODE := 1
CARGO_TARGET_DIR ?= $(REPOSITORY_ROOT)/target
export CARGO_TARGET_DIR
.PHONY: ci check test test-pg test-oidc dependencies licenses
ci: check test dependencies licenses test-pg test-oidc test-federated test-assembly
check:
	cargo fmt --all -- --check
	cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
	cargo check --locked --workspace --lib --bins

test:
	$(PYTHON) -m unittest discover -s hack -p 'test_*.py'
	cargo test --locked --workspace

dependencies:
	$(PYTHON) hack/check_dependencies.py

licenses:
	cargo deny --locked check advisories licenses sources

test-pg:
	$(PYTHON) hack/providers.py pg

test-oidc:
	$(PYTHON) hack/providers.py oidc

.PHONY: test-federated
test-federated:
	$(PYTHON) hack/providers.py federated

.PHONY: test-consumers
test-consumers:
	$(PYTHON) hack/check_consumer.py --revision "$(IDENTITY_CONSUMER_REVISION)" --output "$(IDENTITY_CONSUMER_OUTPUT)"

.PHONY: test-assembly
test-assembly:
	$(PYTHON) hack/providers.py assembly

.PHONY: test-ui candidate
test-ui:
	$(PYTHON) hack/ui.py
candidate:
	$(PYTHON) hack/release.py --output "$(CANDIDATE_OUTPUT)" --ui-source "$(IDENTITY_UI_SOURCE)" --ui-dist "$(IDENTITY_UI_DIST)"
