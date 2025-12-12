ifeq ($(.CURDIR),)
	current_dir  = $(shell /bin/pwd)
else
	current_dir  = $(.CURDIR)
endif

GO          ?= go
GOOS 		?= $(shell $(GO) env GOOS)
GOARCH 		?= $(shell $(GO) env GOARCH)
TOOLBIN 	 = $(current_dir)/toolbin/$(GOOS)_$(GOARCH)

.PHONY: test
test:
	@echo "==> check code formatting"
	@./scripts/gofmt
	@echo "==> run tests"
	@cd tests && ${GO} test

.PHONY: lint
lint: | $(TOOLBIN)/golangci-lint
	$(TOOLBIN)/golangci-lint run 

.PHONY: tools
tools: $(TOOLBIN)/golangci-lint $(TOOLBIN)/gocovmerge $(TOOLBIN)/go-test-coverage
	@echo "==> installing required tooling..."

$(TOOLBIN)/golangci-lint:
	GOBIN=$(TOOLBIN) GO111MODULE=on $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2

