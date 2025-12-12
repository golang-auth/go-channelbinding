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
test: tools
	@echo "==> check code formatting"
	@./scripts/gofmt
	@echo "==> run tests"
	@cd tests && ${GO} test -coverprofile=../cover.out -covermode=atomic -coverpkg=github.com/golang-auth/go-channelbinding
	go tool cover -html=cover.out -o coverage.html
	@$(TOOLBIN)/go-test-coverage --config .testcoverage.yml

.PHONY: lint
lint: | $(TOOLBIN)/golangci-lint
	$(TOOLBIN)/golangci-lint run 

.PHONY: tools
tools: $(TOOLBIN)/golangci-lint $(TOOLBIN)/go-test-coverage
	@echo "==> installing required tooling..."

$(TOOLBIN)/golangci-lint:
	GOBIN=$(TOOLBIN) GO111MODULE=on $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2

$(TOOLBIN)/go-test-coverage:
	GOBIN=$(TOOLBIN) GO111MODULE=on $(GO) install github.com/vladopajic/go-test-coverage/v2@latest
