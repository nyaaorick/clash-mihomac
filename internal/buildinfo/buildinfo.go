// Package buildinfo holds values stamped in at build time with -ldflags.
package buildinfo

var (
	// Version is the Clash Mihomac version.
	Version = "dev"

	// Channel is "debug" for local builds and "stable" for release builds.
	// It picks the default instance, so a plain `go build` can never take
	// over the stable instance's ports or TUN device.
	Channel = "debug"
)
