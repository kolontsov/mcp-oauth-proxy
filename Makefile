BINARY  := mcp-oauth-proxy
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test clean upgrade

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) .

test:
	go test ./...

clean:
	rm -f $(BINARY)

upgrade:
	go get -u ./...
	go mod tidy
