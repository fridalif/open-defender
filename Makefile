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

.PHONY: test
test:
	$(GO) test $(PKGS)

.PHONY: test-verbose
test-verbose:
	$(GO) test -v $(PKGS)

.PHONY: test-race
test-race:
	$(GO) test -race $(PKGS)

.PHONY: cover
cover:
	$(GO) test -coverprofile=$(COVERFILE) -covermode=atomic $(PKGS)
	$(GO) tool cover -func=$(COVERFILE)

.PHONY: cover-html
cover-html: cover
	$(GO) tool cover -html=$(COVERFILE)

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
	rm -rf $(BUILDDIR) $(COVERFILE)
