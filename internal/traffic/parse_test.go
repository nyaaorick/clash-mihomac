package traffic

import (
	"net/netip"
	"os"
	"testing"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestParseLsof(t *testing.T) {
	socks, err := ParseLsof(fixture(t, "lsof.txt"))
	if err != nil {
		t.Fatal(err)
	}
	// 2 mDNS UDP + 5 Chrome (3 IP + listener + named unix; the anonymous unix pair and the regular file are dropped) + 1 node
	if len(socks) != 8 {
		t.Fatalf("got %d sockets: %+v", len(socks), socks)
	}
	by := func(local string) Socket {
		for _, s := range socks {
			if s.Local == local {
				return s
			}
		}
		t.Fatalf("no socket with local %q in %+v", local, socks)
		return Socket{}
	}
	tcp := by("192.168.1.20:54321")
	if tcp.PID != 501 || tcp.Command != "Google Chrome Helper" || tcp.User != "alice" || tcp.Proto != ProtoTCP || tcp.Family != "ipv4" ||
		tcp.Remote != "142.250.80.46:443" || tcp.State != "ESTABLISHED" || tcp.Listening {
		t.Errorf("tcp = %+v", tcp)
	}
	if q := by("192.168.1.20:60001"); q.Proto != ProtoUDP || q.Remote != "142.250.80.46:443" {
		t.Errorf("udp = %+v", q)
	}
	if v6 := by("[2001:db8::20]:54400"); v6.Family != "ipv6" || v6.Remote != "[2606:4700::6810:84e5]:443" {
		t.Errorf("ipv6 = %+v", v6)
	}
	if l := by("127.0.0.1:9222"); !l.Listening || l.Remote != "" {
		t.Errorf("listener = %+v", l)
	}
	if u := by("/var/run/mDNSResponder"); u.Proto != ProtoUnix || u.Family != "unix" || u.PID != 501 {
		t.Errorf("unix = %+v", u)
	}
	if n := by("198.18.253.1:50123"); n.State != "SYN_SENT" || n.Command != "node" {
		t.Errorf("node = %+v", n)
	}
	if _, err := ParseLsof("pxyz\n"); err == nil {
		t.Error("bad pid accepted")
	}
}

func TestParseIfaceCounters(t *testing.T) {
	c, err := ParseIfaceCounters(fixture(t, "netstat_ib.txt"))
	if err != nil {
		t.Fatal(err)
	}
	en0 := c["en0"]
	if en0.InBytes != 9876543210 || en0.OutBytes != 1234567890 || en0.InErrs != 12 || en0.OutErrs != 3 || en0.Drops != 17 || en0.InPkts != 9000000 {
		t.Errorf("en0 = %+v", en0)
	}
	// utun rows have no address column; the counters must still line up.
	if u := c["utun1990"]; u.InBytes != 30000000 || u.OutBytes != 28000000 || u.Drops != 2 {
		t.Errorf("utun1990 = %+v", u)
	}
	if len(c) != 4 { // lo0, en0, utun1990, and the down utun5* (name trimmed)
		t.Errorf("interfaces = %v", c)
	}
	if _, err := ParseIfaceCounters("nothing useful"); err == nil {
		t.Error("garbage accepted")
	}
}

func TestParseRoutesAndLookup(t *testing.T) {
	routes, err := ParseRoutes(fixture(t, "netstat_rn.txt"))
	if err != nil {
		t.Fatal(err)
	}
	rt := NewRouteTable(routes)
	cases := []struct {
		ip, iface, gw string
		avoid         string
	}{
		{"8.8.8.8", "utun1990", "198.18.253.2", ""},   // captured by our TUN's 0/1 split route
		{"8.8.8.8", "en0", "192.168.1.1", "utun1990"}, // where it goes after the TUN
		{"200.1.1.1", "utun1990", "198.18.253.2", ""}, // 128/1
		{"10.20.5.5", "en1", "10.20.0.1", ""},         // intranet via the second NIC (shorthand 10.20/16)
		{"100.64.1.1", "utun4", "100.64.0.2", ""},     // another VPN's route
		{"192.168.1.77", "en0", "", ""},               // on-link
		{"127.0.0.1", "lo0", "127.0.0.1", ""},         // 127 shorthand
		{"169.254.9.9", "en0", "", ""},                // 169.254 shorthand
		{"2001:db8::5", "en0", "", ""},                // IPv6 on-link
		{"::ffff:10.20.5.5", "en1", "10.20.0.1", ""},  // mapped addresses use the IPv4 table
		{"224.0.0.251", "en0", "", ""},                // 224.0.0/4
		{"2606:4700::1", "", "", ""},                  // IPv6 default is scoped (I) and ignored
	}
	for _, c := range cases {
		r, ok := rt.LookupAvoiding(netip.MustParseAddr(c.ip), c.avoid)
		if c.iface == "" {
			if ok {
				t.Errorf("%s: unexpected route %+v", c.ip, r)
			}
			continue
		}
		if !ok || r.Iface != c.iface || r.Gateway != c.gw {
			t.Errorf("%s (avoid %q): %+v, want %s via %q", c.ip, c.avoid, r, c.iface, c.gw)
		}
	}
	if _, err := ParseRoutes("garbage"); err == nil {
		t.Error("garbage accepted")
	}
}

func TestParsePSCodesignBundle(t *testing.T) {
	ps := ParsePS(fixture(t, "ps.txt"))
	if e := ps[501]; e.PPID != 1 || e.Path != "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" {
		t.Errorf("ps[501] = %+v", e)
	}
	if ps[777].PPID != 501 || len(ps) != 4 {
		t.Errorf("ps = %+v", ps)
	}
	if got := ParseCodesign(fixture(t, "codesign.txt")); got != "Developer ID Application: Google LLC (EQHXZ8M8AV) (team EQHXZ8M8AV)" {
		t.Errorf("codesign = %q", got)
	}
	if got := ParseCodesign("/usr/local/bin/node: code object is not signed at all"); got != "unsigned" {
		t.Errorf("unsigned = %q", got)
	}
	if got := ParseCodesign("Identifier=a.out\nTeamIdentifier=not set\n"); got != "a.out (ad hoc)" {
		t.Errorf("ad hoc = %q", got)
	}
	if got := BundleOf("/Applications/Google Chrome.app/Contents/Frameworks/X.app/Contents/MacOS/x"); got != "/Applications/Google Chrome.app" {
		t.Errorf("bundle = %q", got)
	}
	if BundleOf("/usr/bin/curl") != "" {
		t.Error("bundle for a plain binary")
	}
}
