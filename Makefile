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
test-integration: ## Run integration tests (build tag: integration)
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
