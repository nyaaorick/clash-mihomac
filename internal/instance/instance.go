// Package instance defines the isolated profiles Clash Mihomac can run.
//
// Each instance owns its own directory, ports, and TUN device name so that a
// debug build never collides with the stable instance a developer relies on
// for their own connectivity.
package instance

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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

// MaxProfiles is how many user-created profiles (p1..pN) can exist.
const MaxProfiles = 50

// Profile slot p<N> has all its ports, TUN device, and TUN address derived
// from N alone. The privileged helper derives the same values from the
// name, so it never has to trust a file a user can write to learn which
// TUN device or address a profile owns.
func slot(name string) (Instance, bool) {
	rest, ok := strings.CutPrefix(name, "p")
	if !ok || rest == "" || rest[0] == '0' {
		return Instance{}, false
	}
	n, err := strconv.Atoi(rest)
	if err != nil || n < 1 || n > MaxProfiles {
		return Instance{}, false
	}
	base := 20000 + 100*n
	return Instance{
		MixedPort: base, ControllerPort: base + 1, GUIPort: base + 2,
		TUNDevice:  fmt.Sprintf("utun%d", 2000+n),
		TUNAddress: fmt.Sprintf("198.18.%d.1/30", 100+n),
	}, true
}

// Get returns the named instance rooted under home.
func Get(home, name string) (Instance, error) {
	inst, ok := profiles[name]
	if !ok {
		inst, ok = slot(name)
	}
	if !ok {
		return Instance{}, fmt.Errorf("unknown instance %q (known: %v, or a profile such as p1)", name, Names())
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

// Slots lists every instance name that can exist: the built-in ones and
// all profile slots. The helper uses it to clean up after any of them.
func Slots() []string {
	names := Names()
	for n := 1; n <= MaxProfiles; n++ {
		names = append(names, fmt.Sprintf("p%d", n))
	}
	return names
}

// IsProfile reports whether name is a user-created profile rather than a
// built-in instance.
func IsProfile(name string) bool {
	_, ok := slot(name)
	return ok
}

// Label is the human-readable name of a profile, or the instance name for
// a built-in one.
func (i Instance) Label() string {
	if data, err := os.ReadFile(i.Path("label")); err == nil {
		if l := strings.TrimSpace(string(data)); l != "" {
			return l
		}
	}
	return i.Name
}

// Create makes a new profile in the lowest free slot.
func Create(home, label string) (Instance, error) {
	label = strings.TrimSpace(label)
	if label == "" || len(label) > 40 || strings.ContainsAny(label, "\n\r\x00") {
		return Instance{}, errors.New("profile label must be 1-40 characters on a single line")
	}
	for n := 1; n <= MaxProfiles; n++ {
		inst, err := Get(home, fmt.Sprintf("p%d", n))
		if err != nil {
			return Instance{}, err
		}
		if err := os.Mkdir(inst.Dir, 0o700); err != nil {
			if errors.Is(err, fs.ErrExist) {
				continue
			}
			if errors.Is(err, fs.ErrNotExist) {
				if err := os.MkdirAll(filepath.Dir(inst.Dir), 0o700); err != nil {
					return Instance{}, err
				}
				n--
				continue
			}
			return Instance{}, err
		}
		if err := os.WriteFile(inst.Path("label"), []byte(label+"\n"), 0o600); err != nil {
			os.RemoveAll(inst.Dir)
			return Instance{}, err
		}
		return inst, nil
	}
	return Instance{}, fmt.Errorf("all %d profile slots are in use; remove one first", MaxProfiles)
}

// Remove deletes a profile's directory. Built-in instances can't be removed.
// The caller must make sure the profile isn't running.
func Remove(home, name string) error {
	if !IsProfile(name) {
		return fmt.Errorf("%q is not a profile; only profiles created with `mihomac profile add` can be removed", name)
	}
	inst, err := Get(home, name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(inst.Dir); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("profile %q does not exist", name)
	}
	return os.RemoveAll(inst.Dir)
}

// List returns the built-in instances followed by the profiles that exist
// under home, in slot order.
func List(home string) ([]Instance, error) {
	var out []Instance
	for _, name := range Names() {
		inst, _ := Get(home, name)
		out = append(out, inst)
	}
	for n := 1; n <= MaxProfiles; n++ {
		inst, _ := Get(home, fmt.Sprintf("p%d", n))
		if info, err := os.Stat(inst.Dir); err == nil && info.IsDir() {
			out = append(out, inst)
		}
	}
	return out, nil
}
