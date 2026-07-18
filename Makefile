BINARY   := open-defender
CMD      := ./cmd
BUILDDIR := build

export CGO_ENABLED := 1

GO        := go
PKGS      := ./...
COVERFILE := coverage.out

.DEFAULT_GOAL := build

.PHONY: build
build:
	$(GO) build -o $(BUILDDIR)/$(BINARY) $(CMD)

.PHONY: mocks
mocks:
	$(GO) generate $(PKGS)

.PHONY: test
test:
	$(GO) test $(PKGS)

.PHONY: test-verbose
test-verbose:
	$(GO) test -v $(PKGS)

.PHONY: test-race
test-race:
	$(GO) test -race $(PKGS)

.PHONY: test-integration
test-integration:
	$(GO) test -tags=integration $(PKGS)

.PHONY: cover
cover:
	$(GO) test -coverprofile=$(COVERFILE) -covermode=atomic $(PKGS)
	grep -v '/mocks/' $(COVERFILE) > $(COVERFILE).nomocks
	$(GO) tool cover -func=$(COVERFILE).nomocks

.PHONY: cover-html
cover-html: cover
	$(GO) tool cover -html=$(COVERFILE).nomocks

.PHONY: cover-integration
cover-integration:
	$(GO) test -tags=integration -coverprofile=$(COVERFILE) -covermode=atomic $(PKGS)
	grep -v '/mocks/' $(COVERFILE) > $(COVERFILE).nomocks
	$(GO) tool cover -func=$(COVERFILE).nomocks

.PHONY: vet
vet:
	$(GO) vet $(PKGS)

.PHONY: fmt
fmt:
	$(GO) fmt $(PKGS)

.PHONY: check
check: vet test

.PHONY: clean
clean:
	$(GO) clean -testcache
	rm -rf $(BUILDDIR) $(COVERFILE) $(COVERFILE).nomocks
