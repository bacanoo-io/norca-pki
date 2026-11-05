# norca-pki
GO ?= go

.PHONY: all test test-race lint vuln fmt help

all: fmt lint test

## test: Run the tests
test:
	$(GO) test -count=1 ./...

## test-race: Run the tests with the race detector (needs cgo; CI runs it on Linux)
test-race:
	$(GO) test -race -shuffle=on -count=1 ./...

## lint: Run golangci-lint v2 with .golangci.yml
lint:
	golangci-lint run ./...

## vuln: Check the module with govulncheck
vuln:
	govulncheck ./...

## fmt: Format with the gofmt of the toolchain in go.mod
fmt:
	"$$($(GO) env GOROOT)/bin/gofmt" -w .

## help: List the targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'
