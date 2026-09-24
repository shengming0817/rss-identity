SHELL := /bin/bash
PYTHON := $(shell command -v python3)
REPOSITORY_ROOT := $(shell /usr/bin/dirname "$$(/usr/bin/git rev-parse --path-format=absolute --git-common-dir)")
export PATH := /usr/bin:$(PATH)
export PYTHONDONTWRITEBYTECODE := 1
CARGO_TARGET_DIR ?= $(REPOSITORY_ROOT)/target
export CARGO_TARGET_DIR
.PHONY: ci check test test-pg test-oidc dependencies licenses
ci: check test dependencies licenses test-pg test-oidc test-federated test-assembly test-gateway
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

.PHONY: test-assembly
test-assembly:
	$(PYTHON) hack/providers.py assembly

.PHONY: test-gateway
test-gateway:
	$(PYTHON) hack/gateway_t2.py

.PHONY: test-ui image test-reference
test-ui:
	$(PYTHON) hack/ui.py

IDENTITY_IMAGE ?= rss-identity:local
override RUST_IMAGE := $(shell $(PYTHON) -c 'import json; print(json.load(open("deployment/providers.lock.json"))["rust"])')
override RUNTIME_IMAGE := $(shell $(PYTHON) -c 'import json; print(json.load(open("deployment/providers.lock.json"))["runtime"])')
ifdef IDENTITY_GIT_AUTH_HEADER_FILE
IMAGE_SECRET := --secret "id=azure_header,src=$(IDENTITY_GIT_AUTH_HEADER_FILE)"
else ifdef SYSTEM_ACCESSTOKEN
IMAGE_SECRET := --secret id=azure_token,env=SYSTEM_ACCESSTOKEN
endif
image:
	docker buildx build --load --provenance=false -f deployment/Dockerfile --tag "$(IDENTITY_IMAGE)" --build-arg "RUST_IMAGE=$(RUST_IMAGE)" --build-arg "RUNTIME_IMAGE=$(RUNTIME_IMAGE)" $(IMAGE_SECRET) .

# Explicit functional product T3; stays outside normal component CI.
REFERENCE_TOOLS_IMAGE ?= rss-identity-test-reference:local
test-reference:
	@test -n "$(WEB_IMAGE)" || { echo "WEB_IMAGE required" >&2; exit 1; }
	@$(PYTHON) -c 'import pathlib,sys; p=pathlib.Path(sys.argv[1]); sys.exit(None if sys.argv[1] and p.is_absolute() and not p.exists() else "fresh absolute REFERENCE_RECORD required")' "$(REFERENCE_RECORD)"
	docker buildx build --load --provenance=false -f deployment/reference-tools.Dockerfile --tag "$(REFERENCE_TOOLS_IMAGE)" .

	$(PYTHON) hack/reference_t3.py --identity-image "$(IDENTITY_IMAGE)" --web-image "$(WEB_IMAGE)" --tools-image "$(REFERENCE_TOOLS_IMAGE)" --record "$(REFERENCE_RECORD)"
