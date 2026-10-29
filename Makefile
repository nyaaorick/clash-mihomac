MODULE  := github.com/nyaaorick/clash-mihomac
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

DEBUG_LDFLAGS   := -X $(MODULE)/internal/buildinfo.Version=$(VERSION)
RELEASE_LDFLAGS := $(DEBUG_LDFLAGS) -X $(MODULE)/internal/buildinfo.Channel=stable -s -w

PLUGINS_DIR ?= $(HOME)/Library/Application Support/island4mac/Plugins

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
	rm -rf bin dist build

# The island4mac plugin: a folder holding plugin.json and a universal release
# binary. `mihomac island` runs the daemon in-process (plugin/, ROADMAP.md).
plugin:
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags '$(RELEASE_LDFLAGS)' -o build/plugin/mihomac-arm64 ./cmd/mihomac
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags '$(RELEASE_LDFLAGS)' -o build/plugin/mihomac-amd64 ./cmd/mihomac
	mkdir -p build/plugin/mihomac
	lipo -create -output build/plugin/mihomac/mihomac build/plugin/mihomac-arm64 build/plugin/mihomac-amd64
	rm build/plugin/mihomac-arm64 build/plugin/mihomac-amd64
	codesign -s - -f build/plugin/mihomac/mihomac
	cp plugin/plugin.json build/plugin/mihomac/plugin.json
	ditto -c -k --norsrc --noextattr --keepParent build/plugin/mihomac build/plugin/mihomac.zip
	@echo "Built build/plugin/mihomac (and mihomac.zip for Settings > Plugins > Install from File)"

# Installs the plugin into island4mac's plugins folder; the island restarts it
plugin-install: plugin
	mkdir -p "$(PLUGINS_DIR)/mihomac"
	cp build/plugin/mihomac/plugin.json "$(PLUGINS_DIR)/mihomac/plugin.json"
	cp build/plugin/mihomac/mihomac "$(PLUGINS_DIR)/mihomac/.mihomac.installing"
	mv "$(PLUGINS_DIR)/mihomac/.mihomac.installing" "$(PLUGINS_DIR)/mihomac/mihomac"
	@echo "Installed into $(PLUGINS_DIR)/mihomac; turn the Clash tab on under island4mac Settings > Tabs"
