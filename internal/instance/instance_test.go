package instance

import "testing"

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
