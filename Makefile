SHELL := /usr/bin/env bash

BINARY      := esops-doctor
PKG         := github.com/esops-dev/esops-doctor
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
ESOPS_MOD   ?= $(shell go list -m -f '{{.Version}}' github.com/esops-dev/esops-go 2>/dev/null || echo unknown)

LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE) \
	-X $(PKG)/internal/version.EsopsModule=$(ESOPS_MOD)

GO      ?= go
BIN_DIR := bin
GOBIN   := $(shell $(GO) env GOPATH)/bin

GOFLAGS := -trimpath -ldflags "$(LDFLAGS)"

export CGO_ENABLED=0

.PHONY: all
all: build

.PHONY: build
build:
	go build $(GOFLAGS) -o bin/$(BINARY) ./cmd/$(BINARY)

.PHONY: test
test: ## Run unit tests with the race detector
	$(GO) test -race -count=1 ./...

.PHONY: test-integration
test-integration: ## Run integration tests (build tag: integration; needs Docker)
	# The probe-layer integration tests spin up Elasticsearch and
	# OpenSearch via testcontainers — Docker must be reachable. Pin
	# images via ESOPS_DOCTOR_TEST_ES_IMAGE / ESOPS_DOCTOR_TEST_OS_IMAGE
	# to extend the matrix without touching the test source.
	#
	# Colima / Rancher Desktop note: testcontainers can't auto-detect the
	# socket the way it does for Docker Desktop. Before running this
	# target, export both:
	#
	#   export DOCKER_HOST="unix://$$HOME/.colima/default/docker.sock"
	#   export TESTCONTAINERS_RYUK_DISABLED=true
	#
	# (Ryuk must be disabled because the reaper container would otherwise
	# try to bind-mount the host's socket path into the VM, which fails
	# under Colima.)
	$(GO) test -race -count=1 -tags=integration ./...

.PHONY: lint
lint: ## Run golangci-lint
	@command -v golangci-lint >/dev/null || { echo "install: https://golangci-lint.run/welcome/install/"; exit 1; }
	golangci-lint run

.PHONY: security
security: ## Run gosec and govulncheck
	@command -v gosec >/dev/null || $(GO) install github.com/securego/gosec/v2/cmd/gosec@latest
	@command -v govulncheck >/dev/null || $(GO) install golang.org/x/vuln/cmd/govulncheck@latest
	PATH="$(GOBIN):$$PATH" gosec ./...
	PATH="$(GOBIN):$$PATH" govulncheck ./...

.PHONY: vuln
vuln: ## Run govulncheck (subset of `security` that does not need gosec)
	@command -v govulncheck >/dev/null || $(GO) install golang.org/x/vuln/cmd/govulncheck@latest
	PATH="$(GOBIN):$$PATH" govulncheck ./...

# Binary-budget audit. The guard here matches MaxStrippedBinarySize in
# internal/cli/binary_test.go so a developer running `make bin-size` and
# CI exercise the same number.
BIN_BUDGET_BYTES ?= 78643200    # 75 MiB

.PHONY: bin-size
bin-size: build ## Print stripped binary size; fail if it exceeds $(BIN_BUDGET_BYTES)
	@size=$$(stat -f%z bin/$(BINARY) 2>/dev/null || stat -c%s bin/$(BINARY)); \
	echo "$(BINARY): $$size bytes ($$((size / 1024 / 1024)) MiB)"; \
	if [ "$$size" -gt "$(BIN_BUDGET_BYTES)" ]; then \
		echo "FAIL: $(BINARY) exceeds budget of $(BIN_BUDGET_BYTES) bytes" >&2; \
		exit 1; \
	fi

.PHONY: docs
docs: build ## Regenerate docs/rules-reference.md from the embedded catalog
	@mkdir -p docs
	./bin/$(BINARY) docs rules --output-file docs/rules-reference.md
	@echo "wrote docs/rules-reference.md"

.PHONY: schemas
schemas: build ## Extract embedded JSON Schemas into ./schemas (idempotent)
	./bin/$(BINARY) docs schemas --output-dir schemas

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: release-snapshot
release-snapshot:
	goreleaser release --snapshot --clean

.PHONY: update
update: ## Update module dependencies and tidy
	$(GO) get -u ./...
	$(GO) mod tidy

.PHONY: clean
clean:
	rm -rf bin dist
