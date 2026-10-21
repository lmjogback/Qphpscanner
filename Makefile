# qphpscanner Makefile

BINARY      := qphpscanner
PKG         := github.com/rom/qphpscanner
CMD         := ./cmd/qphpscanner
BINDIR      := bin
MANDIR      ?= /usr/local/share/man/man1
PREFIX      ?= /usr/local

VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0")
COMMIT      := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE        := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
VERSION_PKG := $(PKG)/internal/version
LDFLAGS     := -s -w \
	-X '$(VERSION_PKG).Version=$(VERSION)' \
	-X '$(VERSION_PKG).Commit=$(COMMIT)' \
	-X '$(VERSION_PKG).Date=$(DATE)'

GO          ?= go

.DEFAULT_GOAL := build

## help: show this help
.PHONY: help
help:
	@echo "qphpscanner — make targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'

## build: compile the binary into bin/
.PHONY: build
build:
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/$(BINARY) $(CMD)

## install: install the binary and man page under PREFIX
.PHONY: install
install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BINDIR)/$(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	install -d $(DESTDIR)$(MANDIR)
	install -m 0644 docs/$(BINARY).1 $(DESTDIR)$(MANDIR)/$(BINARY).1

## uninstall: remove installed files
.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	rm -f $(DESTDIR)$(MANDIR)/$(BINARY).1

## run: build and run (use ARGS="..." to pass flags/targets)
.PHONY: run
run: build
	$(BINDIR)/$(BINARY) $(ARGS)

## web: build and launch the web GUI on 127.0.0.1:8088
.PHONY: web
web: build
	$(BINDIR)/$(BINARY) --web

## test: run the test suite
.PHONY: test
test:
	$(GO) test ./...

## test-race: run tests with the race detector
.PHONY: test-race
test-race:
	$(GO) test -race ./...

## cover: run tests and open a coverage summary
.PHONY: cover
cover:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

## vet: run go vet
.PHONY: vet
vet:
	$(GO) vet ./...

## fmt: format all Go sources
.PHONY: fmt
fmt:
	$(GO) fmt ./...

## fmtcheck: fail if any source is not gofmt-clean
.PHONY: fmtcheck
fmtcheck:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed on:"; echo "$$unformatted"; exit 1; \
	fi

## check: fmtcheck + vet + test (CI gate)
.PHONY: check
check: fmtcheck vet test

## dist: cross-compile release binaries into dist/
.PHONY: dist
dist:
	@mkdir -p dist
	@for target in \
		linux/amd64 linux/arm64 \
		darwin/amd64 darwin/arm64 \
		windows/amd64; do \
		os=$${target%/*}; arch=$${target#*/}; \
		ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		echo "building $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
			-o dist/$(BINARY)-$$os-$$arch$$ext $(CMD); \
	done

## clean: remove build artifacts
.PHONY: clean
clean:
	rm -rf $(BINDIR) dist coverage.out
