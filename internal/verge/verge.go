// Package verge reads Clash Verge Rev's files and drives the mihomo core
// it runs. Clash Mihomac no longer launches a core of its own: Verge owns
// mihomo, TUN, and the system proxy, and this package is how the daemon
// finds the controller, learns what is running, and gets its rules into
// Verge's config.
//
// Everything here is best effort against files Verge writes for itself:
// the runtime config (clash-verge.yaml) that it last handed to mihomo, the
// settings file (verge.yaml), and the profile index (profiles.yaml). Their
// layout is Verge's business and may change between releases, so every
// reader reports a clear error instead of guessing.
package verge

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Dir is Clash Verge Rev's data directory.
type Dir string

// DefaultDir is where Clash Verge Rev keeps its data on macOS.
func DefaultDir() (Dir, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return Dir(filepath.Join(h, "Library", "Application Support", "io.github.clash-verge-rev.clash-verge-rev")), nil
}

// Locate returns the Verge data directory: MIHOMAC_VERGE_DIR if set, else
// the default. It checks that the directory exists.
func Locate() (Dir, error) {
	var d Dir
	if env := os.Getenv("MIHOMAC_VERGE_DIR"); env != "" {
		d = Dir(env)
	} else {
		var err error
		if d, err = DefaultDir(); err != nil {
			return "", err
		}
	}
	if info, err := os.Stat(string(d)); err != nil || !info.IsDir() {
		return "", fmt.Errorf("Clash Verge Rev data directory not found at %s (is Clash Verge Rev installed and has it run once?)", d)
	}
	return d, nil
}

// Path joins elem onto the data directory.
func (d Dir) Path(elem ...string) string {
	return filepath.Join(append([]string{string(d)}, elem...)...)
}

// Runtime is the config Verge last handed to mihomo (clash-verge.yaml):
// the profile, merged with Verge's own settings and the user's merge and
// script overrides. It is the only place the controller address, secret,
// and the full proxy list are reliably written down.
type Runtime struct {
	Raw    []byte
	Config map[string]any

	Controller string // TCP host:port; empty when Verge has it off
	Socket     string // Unix socket path; empty when not configured
	Secret     string
	MixedPort  int
	Mode       string // rule, global, direct
	TUN        bool
	TUNDevice  string
	TUNStack   string
}

// RuntimeFile is the runtime config's file name.
const RuntimeFile = "clash-verge.yaml"

// ReadRuntime parses clash-verge.yaml.
func (d Dir) ReadRuntime() (Runtime, error) {
	data, err := os.ReadFile(d.Path(RuntimeFile))
	if err != nil {
		return Runtime{}, fmt.Errorf("read Clash Verge's runtime config: %w", err)
	}
	return ParseRuntime(data)
}

// ParseRuntime parses the runtime config from bytes.
func ParseRuntime(data []byte) (Runtime, error) {
	cfg := map[string]any{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Runtime{}, fmt.Errorf("parse %s: %w", RuntimeFile, err)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	r := Runtime{Raw: data, Config: cfg}
	r.Controller, _ = cfg["external-controller"].(string)
	r.Socket, _ = cfg["external-controller-unix"].(string)
	r.Secret, _ = cfg["secret"].(string)
	r.MixedPort = toInt(cfg["mixed-port"])
	r.Mode, _ = cfg["mode"].(string)
	if tun, ok := cfg["tun"].(map[string]any); ok {
		r.TUN, _ = tun["enable"].(bool)
		r.TUNDevice, _ = tun["device"].(string)
		r.TUNStack, _ = tun["stack"].(string)
	}
	return r, nil
}

// Names lists proxy names and group names in the runtime config.
func (r Runtime) Names() (proxies, groups []string) {
	for _, p := range listOfMaps(r.Config["proxies"]) {
		if n, _ := p["name"].(string); n != "" {
			proxies = append(proxies, n)
		}
	}
	for _, g := range listOfMaps(r.Config["proxy-groups"]) {
		if n, _ := g["name"].(string); n != "" {
			groups = append(groups, n)
		}
	}
	return proxies, groups
}

// Endpoint is how to reach mihomo's external controller.
type Endpoint struct {
	Network string // "unix" or "tcp"
	Address string // socket path or host:port
	Secret  string
}

// String describes the endpoint for people.
func (e Endpoint) String() string {
	if e.Network == "" {
		return "none"
	}
	return e.Network + " " + e.Address
}

// ServiceSocket is where Verge's root service puts the controller socket
// when it runs the core (service mode), whatever the runtime config says.
// It is a variable so tests on a Mac with a running Verge can point it
// elsewhere.
var ServiceSocket = func() string {
	return fmt.Sprintf("/var/run/clash-verge-service/users/%d/verge-mihomo.sock", os.Getuid())
}

// Endpoint picks the controller to use. Verge writes a Unix socket path
// into the runtime config, but when its root service runs the core the
// socket appears under /var/run/clash-verge-service instead, so a socket
// that exists wins (the configured one first, then the service's), then
// the TCP address if Verge has it on, then the configured socket for a
// Verge that isn't running yet.
func (r Runtime) Endpoint() (Endpoint, error) {
	var sockets []string
	if r.Socket != "" {
		sockets = append(sockets, r.Socket)
	}
	sockets = append(sockets, ServiceSocket())
	for _, p := range sockets {
		if isSocket(p) {
			return Endpoint{Network: "unix", Address: p, Secret: r.Secret}, nil
		}
	}
	if r.Controller != "" {
		addr := r.Controller
		if strings.HasPrefix(addr, ":") {
			addr = "127.0.0.1" + addr
		}
		return Endpoint{Network: "tcp", Address: addr, Secret: r.Secret}, nil
	}
	if r.Socket != "" {
		return Endpoint{Network: "unix", Address: r.Socket, Secret: r.Secret}, nil
	}
	return Endpoint{}, errors.New("Clash Verge has no external controller configured (neither a Unix socket nor a TCP address)")
}

func isSocket(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode()&os.ModeSocket != 0
}

// Settings are the parts of verge.yaml Clash Mihomac looks at.
type Settings struct {
	TUNMode            bool
	ExternalController bool
	WebUIList          []string
}

// SettingsFile is Verge's settings file name.
const SettingsFile = "verge.yaml"

// ReadSettings parses verge.yaml.
func (d Dir) ReadSettings() (Settings, error) {
	data, err := os.ReadFile(d.Path(SettingsFile))
	if err != nil {
		return Settings{}, fmt.Errorf("read Clash Verge's settings: %w", err)
	}
	var doc struct {
		TUN   bool     `yaml:"enable_tun_mode"`
		Ctrl  bool     `yaml:"enable_external_controller"`
		WebUI []string `yaml:"web_ui_list"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return Settings{}, fmt.Errorf("parse %s: %w", SettingsFile, err)
	}
	return Settings{TUNMode: doc.TUN, ExternalController: doc.Ctrl, WebUIList: doc.WebUI}, nil
}

// AddWebUI adds url to Verge's Web UI list (Settings → Web UI) so the
// dashboard is one click away inside Verge. Verge keeps verge.yaml in
// memory and rewrites it on changes, so this is only safe while Verge is
// not running; the caller checks that. It reports whether the file changed.
func (d Dir) AddWebUI(url string) (bool, error) {
	path := d.Path(SettingsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read Clash Verge's settings: %w", err)
	}
	doc := map[string]any{}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return false, fmt.Errorf("parse %s: %w", SettingsFile, err)
	}
	var list []any
	if cur, ok := doc["web_ui_list"].([]any); ok {
		list = cur
	}
	for _, v := range list {
		if s, _ := v.(string); s == url {
			return false, nil
		}
	}
	doc["web_ui_list"] = append(list, url)
	out, err := yaml.Marshal(doc)
	if err != nil {
		return false, err
	}
	return true, writeAtomic(path, out, 0o644)
}

// LogFile is Verge's current application log.
func (d Dir) LogFile() string { return d.Path("logs", "latest.log") }

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

func listOfMaps(v any) []map[string]any {
	items, _ := v.([]any)
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// writeAtomic replaces the file at path through a temp file in the same
// directory, keeping the existing file's mode and following a symlink to
// the real file, so a crash or a second writer never leaves it torn.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func(err error) error {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if _, err := f.Write(data); err != nil {
		return cleanup(err)
	}
	if err := f.Chmod(mode); err != nil {
		return cleanup(err)
	}
	if err := f.Sync(); err != nil {
		return cleanup(err)
	}
	if err := f.Close(); err != nil {
		return cleanup(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return cleanup(err)
	}
	return nil
}
