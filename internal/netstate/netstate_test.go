package netstate_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nyaaorick/clash-mihomac/internal/netstate"
	"github.com/nyaaorick/clash-mihomac/internal/netstate/netstatetest"
)

func TestTakeSkipsDisabledServices(t *testing.T) {
	snap, err := netstate.Take(context.Background(), netstatetest.New())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Services) != 1 || snap.Services[0].Name != "Wi-Fi" {
		t.Fatalf("services = %+v", snap.Services)
	}
	if got := snap.Services[0].DNS; len(got) != 1 || got[0] != "192.168.1.1" {
		t.Errorf("DNS = %v", got)
	}
	if snap.DefaultGateway != "192.168.1.1" || snap.DefaultInterface != "en0" {
		t.Errorf("default route = %s via %s", snap.DefaultGateway, snap.DefaultInterface)
	}
}

func TestSystemProxyThenRestore(t *testing.T) {
	ctx := context.Background()
	f := netstatetest.New()
	before, err := netstate.Take(ctx, f)
	if err != nil {
		t.Fatal(err)
	}

	if err := netstate.SetSystemProxy(ctx, f, 7990); err != nil {
		t.Fatal(err)
	}
	f.DNS["Wi-Fi"] = []string{"198.18.0.2"} // something else changed DNS too
	f.Gateway = ""                          // and the default route vanished

	mid, _ := netstate.Take(ctx, f)
	if diffs := netstate.Diff(before, mid); len(diffs) != 6 {
		t.Errorf("diffs before restore = %d: %v", len(diffs), diffs)
	}

	rep, err := netstate.Restore(ctx, f, before)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("remaining = %v", rep.Remaining)
	}
	if len(rep.Actions) != 6 {
		t.Errorf("actions = %v", rep.Actions)
	}
	after, _ := netstate.Take(ctx, f)
	if d := netstate.Diff(before, after); len(d) != 0 {
		t.Errorf("not restored: %v", d)
	}
	if f.Proxies["Wi-Fi|web"].Enabled {
		t.Error("web proxy still enabled")
	}
}

func TestRestoreAutomaticDNS(t *testing.T) {
	ctx := context.Background()
	f := netstatetest.New()
	f.DNS["Wi-Fi"] = nil
	before, _ := netstate.Take(ctx, f)
	f.DNS["Wi-Fi"] = []string{"114.114.114.114"}

	rep, err := netstate.Restore(ctx, f, before)
	if err != nil || !rep.OK() {
		t.Fatalf("restore: %+v, %v", rep, err)
	}
	if f.DNS["Wi-Fi"] != nil {
		t.Errorf("DNS = %v, want automatic", f.DNS["Wi-Fi"])
	}
}

func TestRestoreNoopWhenUnchanged(t *testing.T) {
	ctx := context.Background()
	f := netstatetest.New()
	before, _ := netstate.Take(ctx, f)
	f.Calls = nil
	rep, err := netstate.Restore(ctx, f, before)
	if err != nil || !rep.OK() || len(rep.Actions) != 0 {
		t.Errorf("restore = %+v, %v", rep, err)
	}
	for _, c := range f.Calls {
		if strings.HasPrefix(c, "-set") {
			t.Errorf("unexpected change: %s", c)
		}
	}
}

func TestRoutesVia(t *testing.T) {
	f := netstatetest.New()
	f.Routes = `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
1                  198.18.0.1         UGSc             utun1024
1.1.1.1/32         198.18.253.1       UGSc             utun1991
223.5.5.5/32       198.18.253.1       UGSc             utun1024
`
	got, err := netstate.RoutesVia(context.Background(), f, "utun1991", "198.18.253.1")
	if err != nil || len(got) != 2 {
		t.Fatalf("routes = %v, %v", got, err)
	}
	if got[1].Dest != "223.5.5.5/32" || got[1].Netif != "utun1024" {
		t.Errorf("route attached to another interface not found: %+v", got[1])
	}

	f.Calls = nil
	netstate.RemoveRoutes(context.Background(), f, got)
	if len(f.Calls) != 2 || f.Calls[1] != "-n delete -inet 223.5.5.5/32 198.18.253.1" {
		t.Errorf("delete calls = %v", f.Calls)
	}
}
