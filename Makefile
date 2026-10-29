MODULE  := github.com/nyaaorick/clash-mihomac
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

DEBUG_LDFLAGS   := -X $(MODULE)/internal/buildinfo.Version=$(VERSION)
RELEASE_LDFLAGS := $(DEBUG_LDFLAGS) -X $(MODULE)/internal/buildinfo.Channel=stable -s -w

# The island4mac plugin is built, installed and published by island-plugin, the
# plugins repo's tool (this module lives there as mihomac/): `island-plugin dev`
# installs it into the app and rebuilds on every change, `island-plugin build`
# writes build/mihomac/ and build/mihomac.zip, CI publishes it. plugin.json
# comes from `mihomac --describe` (cmd/mihomac/island.go).
ISLAND_PLUGIN ?= ../.build/release/island-plugin

.PHONY: build release test vet darwin clean plugin plugin-install

# Debug build: GUI on 19991, data under Mihomac/debug.
build:
	go build -ldflags '$(DEBUG_LDFLAGS)' -o bin/mihomac ./cmd/mihomac

# Release build: GUI on 9991, data under Mihomac/stable.
release:
	go build -trimpath -ldflags '$(RELEASE_LDFLAGS)' -o dist/mihomac ./cmd/mihomac

test:
	go test ./...

vet:
	go vet ./...

# Cross-compile check for both Mac architectures.
darwin:
	GOOS=darwin GOARCH=arm64 go build ./...
	GOOS=darwin GOARCH=amd64 go build ./...

clean:
	rm -rf bin dist build .build

plugin:
	$(ISLAND_PLUGIN) build

plugin-install:
	$(ISLAND_PLUGIN) dev
