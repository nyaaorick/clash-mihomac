package instance

import (
	"fmt"
	"strings"
	"testing"
)

func TestInstancesNeverOverlap(t *testing.T) {
	ports := map[int]string{}
	devices := map[string]string{}
	dirs := map[string]string{}
	for _, name := range Names() {
		inst, err := Get("/base", name)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range []int{inst.MixedPort, inst.ControllerPort, inst.GUIPort} {
			if other, dup := ports[p]; dup {
				t.Errorf("port %d used by both %s and %s", p, other, name)
			}
			ports[p] = name
		}
		if other, dup := devices[inst.TUNAddress]; dup || inst.TUNAddress == "" || inst.TUNAddress == "198.18.0.1/30" {
			t.Errorf("TUN address %q of %s is empty, the mihomo default, or shared with %s", inst.TUNAddress, name, other)
		}
		devices[inst.TUNAddress] = name
		if other, dup := devices[inst.TUNDevice]; dup {
			t.Errorf("TUN device %s used by both %s and %s", inst.TUNDevice, other, name)
		}
		devices[inst.TUNDevice] = name
		if other, dup := dirs[inst.Dir]; dup {
			t.Errorf("dir %s used by both %s and %s", inst.Dir, other, name)
		}
		dirs[inst.Dir] = name
	}
}

func TestDebugHasTUNOffByDefault(t *testing.T) {
	inst, err := Get("/base", "debug")
	if err != nil {
		t.Fatal(err)
	}
	if inst.TUNDefault {
		t.Error("debug instance must have TUN disabled by default")
	}
}

func TestUnknownInstance(t *testing.T) {
	if _, err := Get("/base", "nope"); err == nil {
		t.Error("expected error for unknown instance")
	}
}

func TestHomeOverride(t *testing.T) {
	t.Setenv("MIHOMAC_HOME", "/tmp/mh")
	h, err := Home()
	if err != nil || h != "/tmp/mh" {
		t.Errorf("Home() = %q, %v; want /tmp/mh", h, err)
	}
}

func TestProfileSlotsNeverOverlap(t *testing.T) {
	seen := map[string]string{}
	claim := func(kind, key, owner string) {
		k := kind + ":" + key
		if other, dup := seen[k]; dup {
			t.Errorf("%s %s used by both %s and %s", kind, key, other, owner)
		}
		seen[k] = owner
	}
	for _, name := range Slots() {
		inst, err := Get("/base", name)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range []int{inst.MixedPort, inst.ControllerPort, inst.GUIPort} {
			claim("port", fmt.Sprint(p), name)
		}
		claim("device", inst.TUNDevice, name)
		claim("address", inst.TUNAddress, name)
		claim("dir", inst.Dir, name)
		if inst.TUNAddress == "198.18.0.1/30" {
			t.Errorf("%s uses the mihomo default TUN address", name)
		}
	}
}

func TestProfileNamesAreStrict(t *testing.T) {
	for _, bad := range []string{"p0", "p01", "p51", "p-1", "p", "P1", "p1 ", "p1/../x", "../p1"} {
		if _, err := Get("/base", bad); err == nil {
			t.Errorf("Get(%q) should fail", bad)
		}
	}
	if !IsProfile("p3") || IsProfile("stable") {
		t.Error("IsProfile wrong")
	}
}

func TestCreateListRemove(t *testing.T) {
	home := t.TempDir()
	a, err := Create(home, "work")
	if err != nil || a.Name != "p1" || a.Label() != "work" {
		t.Fatalf("Create = %+v, %v", a, err)
	}
	b, err := Create(home, "home")
	if err != nil || b.Name != "p2" {
		t.Fatalf("second Create = %+v, %v", b, err)
	}
	if err := Remove(home, "p1"); err != nil {
		t.Fatal(err)
	}
	c, _ := Create(home, "again")
	if c.Name != "p1" {
		t.Errorf("freed slot not reused: %s", c.Name)
	}
	list, _ := List(home)
	var names []string
	for _, i := range list {
		names = append(names, i.Name)
	}
	if got := strings.Join(names, ","); got != "debug,stable,p1,p2" {
		t.Errorf("List = %s", got)
	}
	if err := Remove(home, "stable"); err == nil {
		t.Error("built-in instances must not be removable")
	}
	if err := Remove(home, "p9"); err == nil {
		t.Error("removing a missing profile should fail")
	}
	if _, err := Create(home, "bad\nlabel"); err == nil {
		t.Error("multi-line label accepted")
	}
}

func TestProfilesFillUp(t *testing.T) {
	home := t.TempDir()
	for i := 0; i < MaxProfiles; i++ {
		if _, err := Create(home, "x"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Create(home, "x"); err == nil {
		t.Error("expected slots to run out")
	}
}
