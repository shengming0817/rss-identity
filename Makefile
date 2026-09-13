SHELL := /bin/bash
PYTHON := $(shell command -v python3)
REPOSITORY_ROOT := $(shell /usr/bin/dirname "$$(/usr/bin/git rev-parse --path-format=absolute --git-common-dir)")
export PATH := /usr/bin:$(PATH)
export PYTHONDONTWRITEBYTECODE := 1
CARGO_TARGET_DIR ?= $(REPOSITORY_ROOT)/target
export CARGO_TARGET_DIR
.PHONY: ci check test test-pg test-oidc dependencies licenses
ci: check test dependencies licenses test-pg test-oidc test-federated test-downstream test-assembly test-gateway test-clients test-recovery test-platform
check:
	cargo fmt --all -- --check
	cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
	cargo check --locked --workspace --lib --bins

test:
	$(PYTHON) -m unittest discover -s hack -p 'test_*.py'
	$(PYTHON) -m unittest discover -s t3/identity-lifecycle -p 'test_*.py'
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

.PHONY: test-ui
test-ui:
	$(PYTHON) hack/ui.py

.PHONY: test-assembly
test-assembly:
	$(PYTHON) hack/assembly.py

.PHONY: candidate
candidate:
	$(PYTHON) hack/release.py --output "$(CANDIDATE_OUTPUT)" --ui-source "$(IDENTITY_UI_SOURCE)" --ui-dist "$(IDENTITY_UI_DIST)"

.PHONY: test-gateway
test-gateway:
	$(PYTHON) hack/gateway.py

.PHONY: test-clients
test-clients:
	$(PYTHON) hack/clients.py

.PHONY: test-recovery measure-capacity
test-recovery:
	$(PYTHON) hack/recovery.py

measure-capacity:
	$(PYTHON) hack/downstream.py --measure

.PHONY: prepare-t33 test-t33
prepare-t33:
	$(PYTHON) t3/identity-federated-sso/prepare.py --output "$(T33_ARTIFACTS)" --ui-source "$(IDENTITY_UI_SOURCE)" --ui-dist "$(IDENTITY_UI_DIST)"

test-t33:
	$(PYTHON) t3/identity-federated-sso/run.py --artifacts "$(T33_ARTIFACTS)" --artifacts-sha256 "$(T33_ARTIFACTS_SHA256)" --output "$(T33_OUTPUT)"
.PHONY: test-t3-local-auth check-t3-local-auth
check-t3-local-auth:
	$(PYTHON) -c "from pathlib import Path; [compile(p.read_bytes(), str(p), 'exec') for p in [*sorted(Path('t3/access-local-auth').glob('*.py')), Path('hack/bounded_process.py')]]"
	@for script in t3/access-local-auth/*.mjs; do node --check "$$script" || exit; done
	$(PYTHON) -m unittest discover -s t3/access-local-auth -p 'test_*.py'
	pnpm --dir t3/access-local-auth install --frozen-lockfile --ignore-scripts
	pnpm --dir t3/access-local-auth exec eslint .
	pnpm --dir t3/access-local-auth test
	pnpm --dir t3/access-local-auth audit

test-t3-local-auth:
	$(PYTHON) t3/access-local-auth/run.py --candidate "$(IDENTITY_T3_CANDIDATE)" --record "$(IDENTITY_T3_RECORD)"

.PHONY: test-lifecycle
test-lifecycle:
	$(PYTHON) t3/identity-lifecycle/run.py --candidate "$(LIFECYCLE_CANDIDATE)" --output "$(LIFECYCLE_OUTPUT)"

.PHONY: test-platform
test-platform:
	$(PYTHON) hack/platform_cli.py
