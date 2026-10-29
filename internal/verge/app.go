package verge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// App is an installed copy of Clash Verge Rev.
type App struct {
	Path     string `json:"path"` // the .app bundle
	Version  string `json:"version"`
	BundleID string `json:"bundle_id"`
	Service  bool   `json:"service"` // Verge's root service (for TUN) is installed
}

// BundleID is Clash Verge Rev's bundle identifier.
const BundleID = "io.github.clash-verge-rev.clash-verge-rev"

// ServicePlist is the launchd daemon Verge installs for TUN mode.
const ServicePlist = "/Library/LaunchDaemons/" + BundleID + ".service.plist"

// AppCandidates lists where the app may be installed, in search order.
func AppCandidates() []string {
	out := []string{filepath.Join("/Applications", AppName+".app")}
	if h, err := os.UserHomeDir(); err == nil {
		out = append(out, filepath.Join(h, "Applications", AppName+".app"))
	}
	return out
}

// ErrNotInstalled means no Clash Verge app was found.
var ErrNotInstalled = errors.New("Clash Verge is not installed (looked in /Applications and ~/Applications)")

// FindApp locates the installed app and reads its version.
func FindApp(ctx context.Context, r Runner) (App, error) {
	for _, p := range AppCandidates() {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return InspectApp(ctx, r, p)
		}
	}
	return App{}, ErrNotInstalled
}

// InspectApp reads the bundle's version and identifier and checks that it
// really is Clash Verge Rev.
func InspectApp(ctx context.Context, r Runner, path string) (App, error) {
	a := App{Path: path}
	out, err := r.Run(ctx, "/usr/bin/plutil", "-convert", "json", "-o", "-", filepath.Join(path, "Contents", "Info.plist"))
	if err != nil {
		return a, fmt.Errorf("read %s: %w", path, err)
	}
	var plist struct {
		Version  string `json:"CFBundleShortVersionString"`
		BundleID string `json:"CFBundleIdentifier"`
	}
	// Runners return stdout and stderr together; a warning on stderr must
	// not break the JSON.
	if i := strings.Index(out, "{"); i > 0 {
		out = out[i:]
	}
	if err := json.Unmarshal([]byte(out), &plist); err != nil {
		return a, fmt.Errorf("parse Info.plist of %s: %w", path, err)
	}
	a.Version, a.BundleID = plist.Version, plist.BundleID
	if a.BundleID != BundleID {
		return a, fmt.Errorf("%s is %q, not Clash Verge Rev", path, firstNonEmpty(a.BundleID, "an unknown app"))
	}
	_, err = os.Stat(ServicePlist)
	a.Service = err == nil
	return a, nil
}

// Open launches the app (or brings it to the front).
func (a App) Open(ctx context.Context, r Runner) error {
	_, err := r.Run(ctx, "/usr/bin/open", "-a", a.Path)
	return err
}

// Label is the app's name with its version.
func (a App) Label() string {
	if a.Version == "" {
		return AppName
	}
	return AppName + " " + strings.TrimPrefix(a.Version, "v")
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
