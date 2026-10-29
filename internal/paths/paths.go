// Package paths locates Clash Mihomac's own data directory.
package paths

import (
	"os"
	"path/filepath"

	"github.com/nyaaorick/clash-mihomac/internal/buildinfo"
)

// Home returns the directory Clash Mihomac keeps its data in: rules,
// imported nodes, proposals, health and traffic history, tokens, and logs.
// MIHOMAC_HOME overrides it (tests, or running two copies side by side).
// Otherwise the stable and debug builds use separate directories so a
// development build never touches the state the stable one relies on.
func Home() (string, error) {
	if h := os.Getenv("MIHOMAC_HOME"); h != "" {
		return h, nil
	}
	d, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "Library", "Application Support", "Mihomac", buildinfo.Channel), nil
}

// GUIPort is the dashboard's default port for this build.
func GUIPort() int {
	if buildinfo.Channel == "stable" {
		return 9991
	}
	return 19991
}
