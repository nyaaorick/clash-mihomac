MODULE  := github.com/nyaaorick/clash-mihomac
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

DEBUG_LDFLAGS   := -X $(MODULE)/internal/buildinfo.Version=$(VERSION)
RELEASE_LDFLAGS := $(DEBUG_LDFLAGS) -X $(MODULE)/internal/buildinfo.Channel=stable -s -w

HELPER_LABEL := com.clashmihomac.helper
HELPER_BIN   := /Library/PrivilegedHelperTools/$(HELPER_LABEL)
HELPER_PLIST := /Library/LaunchDaemons/$(HELPER_LABEL).plist

.PHONY: build release test vet verify install-helper uninstall-helper clean

# Debug build: default instance is "debug" (mixed-port only, TUN off).
build:
	go build -ldflags '$(DEBUG_LDFLAGS)' -o bin/mihomac ./cmd/mihomac
	go build -ldflags '$(DEBUG_LDFLAGS)' -o bin/mihomac-helper ./cmd/mihomac-helper

# Release build: default instance is "stable".
release:
	go build -trimpath -ldflags '$(RELEASE_LDFLAGS)' -o dist/mihomac ./cmd/mihomac
	go build -trimpath -ldflags '$(RELEASE_LDFLAGS)' -o dist/mihomac-helper ./cmd/mihomac-helper

test:
	go test ./...

vet:
	go vet ./...

# Phase 0 exit check against a real mihomo core.
verify: build
	scripts/verify-phase0.sh

# Installs (or reinstalls) the root helper as a launchd daemon for the
# current user. Stopping the old helper first ends its sessions, which
# restores the network.
SUDO ?= sudo
install-helper: build
	-$(SUDO) launchctl bootout system/$(HELPER_LABEL) 2>/dev/null
	$(SUDO) mkdir -p /Library/PrivilegedHelperTools
	$(SUDO) install -o root -g wheel -m 0755 bin/mihomac-helper $(HELPER_BIN)
	sed 's/__UID__/$(shell id -u)/' packaging/launchd/$(HELPER_LABEL).plist | $(SUDO) tee $(HELPER_PLIST) >/dev/null
	$(SUDO) chown root:wheel $(HELPER_PLIST)
	$(SUDO) chmod 0644 $(HELPER_PLIST)
	$(SUDO) launchctl bootstrap system $(HELPER_PLIST)

uninstall-helper:
	-$(SUDO) launchctl bootout system/$(HELPER_LABEL)
	$(SUDO) rm -f $(HELPER_PLIST) $(HELPER_BIN)

clean:
	rm -rf bin dist
