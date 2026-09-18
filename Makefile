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

.PHONY: test-ui image test-reference
test-ui:
	$(PYTHON) hack/ui.py

IDENTITY_IMAGE ?= rss-identity:local
override IDENTITY_REVISION := $(shell /usr/bin/git rev-parse HEAD)
override RUST_IMAGE := $(shell $(PYTHON) -c 'import json; print(json.load(open("deployment/providers.lock.json"))["rust"])')
override RUNTIME_IMAGE := $(shell $(PYTHON) -c 'import json; print(json.load(open("deployment/providers.lock.json"))["runtime"])')
ifdef IDENTITY_GIT_AUTH_HEADER_FILE
IMAGE_SECRET := --secret "id=azure_header,src=$(IDENTITY_GIT_AUTH_HEADER_FILE)"
else ifdef SYSTEM_ACCESSTOKEN
IMAGE_SECRET := --secret id=azure_token,env=SYSTEM_ACCESSTOKEN
endif
image:
	@test -z "$$(/usr/bin/git status --porcelain)" || { echo "image requires clean HEAD" >&2; exit 1; }
	set -o pipefail; /usr/bin/git archive "$(IDENTITY_REVISION)" | docker buildx build --platform linux/amd64 --load --provenance=false -f deployment/Dockerfile --tag "$(IDENTITY_IMAGE)" --build-arg "IDENTITY_REVISION=$(IDENTITY_REVISION)" --build-arg "RUST_IMAGE=$(RUST_IMAGE)" --build-arg "RUNTIME_IMAGE=$(RUNTIME_IMAGE)" $(IMAGE_SECRET) -
	@test "$$(/usr/bin/git rev-parse HEAD)" = "$(IDENTITY_REVISION)" && test -z "$$(/usr/bin/git status --porcelain)"

# Explicit image/config seams on an isolated Linux Docker host; not part of CI.
test-reference:
	$(PYTHON) hack/reference_seams.py --identity-image "$(IDENTITY_IMAGE)" --web-image "$(WEB_IMAGE)" --previous-web-image "$(PREVIOUS_WEB_IMAGE)" --record "$(REFERENCE_RECORD)" --work "$(REFERENCE_WORK)"
