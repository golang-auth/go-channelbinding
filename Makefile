current_dir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
GO          ?= go
GOBIN       ?= $(shell go env GOBIN)
TOOLBIN     := $(current_dir)/toolbin

.DEFAULT: check

.PHONY: check
check: fmtcheck lint coverage

.PHONY: fmtcheck
fmtcheck:
	@"$(CURDIR)/scripts/gofmtcheck.sh"

.PHONY: lint
lint:
	$(TOOLBIN)/golangci-lint run ./...

.PHONY: tools
tools: $(TOOLBIN) $(TOOLBIN)/golangci-lint
        @echo "==> installing required tooling..."

.PHONY: fmt
fmt:
	@echo "==> Fixing source code with gofmt..."
	@# This logic should match the search logic in scripts/gofmtcheck.sh
	find . -name '*.go' | grep -v vendor | xargs gofmt -s -w

.PHONY: coverage
coverage:
	@echo "==> Checking test coverage..."
	cd tests && \
		$(GO) test -coverprofile=../cover.out -covermode=atomic -coverpkg github.com/golang-auth/go-channelbinding -v 
	$(GO) tool cover -func=cover.out
	$(GO) tool cover -html=cover.out

$(TOOLBIN):
	mkdir -p $(TOOLBIN)

$(TOOLBIN)/golangci-lint:
	GOBIN=$(TOOLBIN) GO111MODULE=on $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.0
