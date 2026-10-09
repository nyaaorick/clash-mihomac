package traffic

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func inputs(t *testing.T) Inputs {
	t.Helper()
	routes, err := ParseRoutes(fixture(t, "netstat_rn.txt"))
	if err != nil {
		t.Fatal(err)
	}
	socks, err := ParseLsof(fixture(t, "lsof.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return Inputs{
		Time: now, Sockets: socks, Routes: NewRouteTable(routes), PS: ParsePS(fixture(t, "ps.txt")),
		TUNMode: true, OwnTUN: "utun1990", DefaultIface: "en0",
		AddrOwner: map[netip.Addr]string{netip.MustParseAddr("192.168.1.20"): "en0", netip.MustParseAddr("10.20.0.7"): "en1"},
		NodeAddrs: func(n string) []netip.Addr {
			if n == "MyNode" {
				return []netip.Addr{netip.MustParseAddr("203.0.113.9")}
			}
			return nil
		},
	}
}

func byID(flows []Flow, id string) Flow {
	for _, f := range flows {
		if f.ID == id {
			return f
		}
	}
	return Flow{}
}

func TestProxiedTUNFlowShowsBothHops(t *testing.T) {
	in := inputs(t)
	in.Conns = []Conn{{
		ID: "a", Start: now, Network: "tcp", Inbound: "Tun", Source: "198.18.253.1:50123", Host: "example.com",
		DestIP: "93.184.216.34", DestPort: "443", Process: "node", ProcessPath: "/usr/local/bin/node",
		Rule: "DomainSuffix", RulePayload: "example.com", Chains: []string{"MyNode", "Proxy"}, Upload: 1000, Download: 9000,
	}}
	f := byID(Join(in), "conn-a")
	if !f.Proxied || !f.EnteredTUN || f.Ingress != "utun1990" || f.Egress != "en0" || f.NextHop != "192.168.1.1" {
		t.Errorf("path = ingress %q egress %q via %q proxied=%v", f.Ingress, f.Egress, f.NextHop, f.Proxied)
	}
	if f.Node != "MyNode" || f.Group != "Proxy" || f.Bytes() != 10000 || f.Remote != "93.184.216.34:443" || f.Family != "ipv4" {
		t.Errorf("flow = %+v", f)
	}
	// The socket table supplies the PID and the process tree.
	if f.Process.PID != 777 || f.Process.ParentPID != 501 || f.Process.ParentName != "Google Chrome" || f.State != "SYN_SENT" {
		t.Errorf("process = %+v state=%q", f.Process, f.State)
	}
	if len(f.Anomalies) != 0 {
		t.Errorf("anomalies = %v", f.Anomalies)
	}
}

func TestDirectAndInterfaceTargets(t *testing.T) {
	in := inputs(t)
	in.Conns = []Conn{
		{ID: "d", Start: now, Network: "udp", Inbound: "Tun", Source: "198.18.253.1:1", DestIP: "10.20.5.5", DestPort: "53", Process: "dig", Chains: []string{"DIRECT"}},
		{ID: "i", Start: now, Network: "tcp", Inbound: "Tun", Source: "198.18.253.1:2", DestIP: "10.20.5.6", DestPort: "22", Process: "ssh", Chains: []string{"iface:en1"}},
		{ID: "r", Start: now, Network: "tcp", Inbound: "Tun", Source: "198.18.253.1:3", DestIP: "198.51.100.1", DestPort: "80", Process: "curl", Chains: []string{"REJECT"}},
		{ID: "6", Start: now, Network: "tcp", Inbound: "HTTP", Source: "127.0.0.1:5", DestIP: "2606:4700::1", DestPort: "443", Process: "curl", Chains: []string{"DIRECT"}},
	}
	flows := Join(in)
	if d := byID(flows, "conn-d"); d.Egress != "en1" || d.NextHop != "10.20.0.1" || d.Proxied || d.App != AppDNS {
		t.Errorf("direct = %+v", d)
	}
	if i := byID(flows, "conn-i"); i.Egress != "en1" || i.NextHop != "10.20.0.1" {
		t.Errorf("iface = %+v", i)
	}
	if r := byID(flows, "conn-r"); r.Egress != "" || r.Proxied {
		t.Errorf("rejected = %+v", r)
	}
	if v6 := byID(flows, "conn-6"); v6.Family != "ipv6" || v6.EnteredTUN || v6.Ingress != "" || v6.Egress != "en0" {
		t.Errorf("v6 / proxy-port flow = %+v", v6)
	}
}

func TestSocketOnlyFlows(t *testing.T) {
	in := inputs(t)
	flows := Join(in)

	// Chrome's TCP flow to a public IP is routed into our TUN by the 0/1 route.
	f := byID(flows, "sock-501-tcp-192.168.1.20:54321-142.250.80.46:443")
	if !f.EnteredTUN || f.Ingress != "utun1990" || f.Egress != "en0" || !f.BytesUnknown || f.Process.Name != "Google Chrome Helper" || f.Process.Bundle != "/Applications/Google Chrome.app" {
		t.Errorf("captured socket flow = %+v", f)
	}
	if q := byID(flows, "sock-501-udp-192.168.1.20:60001-142.250.80.46:443"); q.App != AppQUIC || q.Proto != ProtoUDP {
		t.Errorf("quic flow = %+v", q)
	}
	if l := byID(flows, "sock-501-tcp-127.0.0.1:9222-"); !l.Listen || l.Egress != "" || len(l.Anomalies) != 0 {
		t.Errorf("listener = %+v", l)
	}
	u := byID(flows, "sock-501-unix-/var/run/mDNSResponder-")
	if !u.Internal || u.Family != "unix" || u.Proto != ProtoUnix || u.Egress != "" {
		t.Errorf("unix = %+v", u)
	}
}

func TestBypassedTUNAndWrongNIC(t *testing.T) {
	in := inputs(t)
	in.Sockets = []Socket{
		// The corporate 10.20/16 route is more specific than TUN's 0/1: this skips TUN.
		{PID: 501, Command: "ssh", Proto: ProtoTCP, Family: "ipv4", Local: "10.20.0.7:40000", Remote: "10.20.5.5:22", State: "ESTABLISHED"},
		// Same destination, but the socket is bound to en0's address.
		{PID: 501, Command: "ssh", Proto: ProtoTCP, Family: "ipv4", Local: "192.168.1.20:40001", Remote: "10.20.5.5:22", State: "ESTABLISHED"},
		// Another VPN's tunnel.
		{PID: 501, Command: "tailscale", Proto: ProtoTCP, Family: "ipv4", Local: "100.64.0.9:40002", Remote: "100.64.1.1:22", State: "ESTABLISHED"},
		// Multicast is never captured by design.
		{PID: 312, Command: "mDNS", Proto: ProtoUDP, Family: "ipv4", Local: "192.168.1.20:5353", Remote: "224.0.0.251:5353"},
	}
	flows := Join(in)
	kinds := func(id string) string {
		var ks []string
		for _, a := range byID(flows, id).Anomalies {
			ks = append(ks, a.Kind)
		}
		return strings.Join(ks, ",")
	}
	if got := kinds("sock-501-tcp-10.20.0.7:40000-10.20.5.5:22"); got != AnomalyBypassedTUN {
		t.Errorf("intranet socket anomalies = %q", got)
	}
	if got := kinds("sock-501-tcp-192.168.1.20:40001-10.20.5.5:22"); got != AnomalyBypassedTUN+","+AnomalyWrongNIC {
		t.Errorf("wrong-NIC socket anomalies = %q", got)
	}
	if got := kinds("sock-501-tcp-100.64.0.9:40002-100.64.1.1:22"); got != AnomalyOtherVPN {
		t.Errorf("other-VPN socket anomalies = %q", got)
	}
	if got := kinds("sock-312-udp-192.168.1.20:5353-224.0.0.251:5353"); got != "" {
		t.Errorf("multicast flagged: %q", got)
	}
	a := byID(flows, "sock-501-tcp-10.20.0.7:40000-10.20.5.5:22").Anomalies[0]
	if !strings.Contains(a.Detail, "via en1") || !strings.Contains(a.Detail, "gateway 10.20.0.1") {
		t.Errorf("detail = %q", a.Detail)
	}

	in.TUNMode, in.OwnTUN = false, ""
	for _, f := range Join(in) {
		for _, a := range f.Anomalies {
			if a.Kind == AnomalyBypassedTUN {
				t.Errorf("TUN-bypass flagged with TUN off: %+v", f)
			}
		}
	}
}

func TestOtherVPNOnProxiedPath(t *testing.T) {
	in := inputs(t)
	in.NodeAddrs = func(string) []netip.Addr { return []netip.Addr{netip.MustParseAddr("100.64.3.3")} }
	in.Conns = []Conn{{ID: "v", Start: now, Network: "tcp", Inbound: "Tun", Source: "198.18.253.1:9", DestIP: "1.1.1.1", DestPort: "443", Chains: []string{"VPNNode"}}}
	f := byID(Join(in), "conn-v")
	if f.Egress != "utun4" || len(f.Anomalies) != 1 || f.Anomalies[0].Kind != AnomalyOtherVPN {
		t.Errorf("flow = %+v", f)
	}
}

func TestMatchedAndIgnoredSocketsAreNotDuplicated(t *testing.T) {
	in := inputs(t)
	in.Conns = []Conn{{ID: "a", Start: now, Network: "tcp", Inbound: "Tun", Source: "198.18.253.1:50123", DestIP: "104.16.1.1", DestPort: "443", Chains: []string{"DIRECT"}}}
	in.IgnorePIDs = []int{312}
	for _, f := range Join(in) {
		if strings.Contains(f.ID, "198.18.253.1:50123") {
			t.Errorf("matched socket repeated as %s", f.ID)
		}
		if f.Process.PID == 312 {
			t.Errorf("ignored process present: %s", f.ID)
		}
	}
}
