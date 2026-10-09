// Package instance defines the isolated profiles Clash Mihomac can run.
//
// Each instance owns its own directory, ports, and TUN device name so that a
// debug build never collides with the stable instance a developer relies on
// for their own connectivity.
package instance

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Instance is one isolated profile.
type Instance struct {
	Name           string
	Dir            string
	MixedPort      int
	ControllerPort int
	GUIPort        int
	TUNDevice      string
	// TUNAddress is the TUN interface's own address. It must differ from
	// other clients' (mihomo and Clash Verge default to 198.18.0.1/30):
	// two TUNs sharing an address make the kernel attach one's routes to
	// the other's interface.
	TUNAddress string
	// TUNDefault reports whether the instance starts in TUN mode by default.
	TUNDefault bool
}

var profiles = map[string]Instance{
	"stable": {MixedPort: 7990, ControllerPort: 9990, GUIPort: 9991, TUNDevice: "utun1990", TUNAddress: "198.18.254.1/30", TUNDefault: true},
	"debug":  {MixedPort: 17990, ControllerPort: 19990, GUIPort: 19991, TUNDevice: "utun1991", TUNAddress: "198.18.253.1/30", TUNDefault: false},
}

// TUNGateway is the TUN address without its prefix length: the gateway of
// every route the core adds.
func (i Instance) TUNGateway() string {
	addr, _, _ := strings.Cut(i.TUNAddress, "/")
	return addr
}

// Home returns the base directory for all Clash Mihomac data.
// MIHOMAC_HOME overrides the default, which is useful for tests.
func Home() (string, error) {
	if h := os.Getenv("MIHOMAC_HOME"); h != "" {
		return h, nil
	}
	d, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "Library", "Application Support", "Mihomac"), nil
}

// Get returns the named instance rooted under home.
func Get(home, name string) (Instance, error) {
	inst, ok := profiles[name]
	if !ok {
		return Instance{}, fmt.Errorf("unknown instance %q (known: %v)", name, Names())
	}
	inst.Name = name
	inst.Dir = filepath.Join(home, "instances", name)
	return inst, nil
}

// Names lists the known instance names in sorted order.
func Names() []string {
	names := make([]string, 0, len(profiles))
	for n := range profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Path joins elem onto the instance directory.
func (i Instance) Path(elem ...string) string {
	return filepath.Join(append([]string{i.Dir}, elem...)...)
}
