package traffic

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func sampleFlows() []Flow {
	end := now.Add(time.Minute)
	chrome := Process{PID: 1, Name: "Google Chrome Helper", Path: "/Applications/Google Chrome.app/Contents/MacOS/x", Bundle: "/Applications/Google Chrome.app"}
	curl := Process{PID: 2, Name: "curl", Path: "/usr/bin/curl"}
	return []Flow{
		{ID: "1", Start: now, Process: chrome, Proto: ProtoTCP, Family: "ipv4", Host: "example.com", Remote: "1.1.1.1:443", Proxied: true, EnteredTUN: true,
			Rule: "DomainSuffix", RulePayload: "example.com", Node: "HK", Group: "Proxy", Ingress: "utun1990", Egress: "en0", Upload: 100, Download: 900},
		{ID: "2", Start: now, Process: chrome, Proto: ProtoUDP, App: AppQUIC, Family: "ipv6", Remote: "[2606:4700::1]:443", Rule: "Match", Node: "DIRECT",
			Ingress: "utun1990", Egress: "en0", Upload: 50, Download: 450},
		{ID: "3", Start: now, End: &end, Process: curl, Proto: ProtoTCP, Family: "ipv4", Remote: "10.20.5.5:22", Rule: "IPCIDR", RulePayload: "10.20.0.0/16", Node: "iface:en1",
			Ingress: "utun1990", Egress: "en1", Upload: 10, Download: 20},
		{ID: "4", Start: now, Process: Process{Name: "mDNSResponder"}, Proto: ProtoUnix, Family: "unix", Internal: true, Local: "/var/run/mDNSResponder", BytesUnknown: true},
		{ID: "5", Start: now, Process: curl, Proto: ProtoTCP, Family: "ipv4", Remote: "127.0.0.1:9222", Listen: true},
		{ID: "6", Start: now, Process: curl, Proto: ProtoTCP, Family: "ipv4", Remote: "8.8.4.4:853", Egress: "en0", BytesUnknown: true,
			Anomalies: []Anomaly{{Kind: AnomalyBypassedTUN, Detail: "x"}}},
	}
}

func TestFilter(t *testing.T) {
	flows := sampleFlows()
	count := func(f Filter) string {
		var ids []string
		for _, x := range f.Apply(flows) {
			ids = append(ids, x.ID)
		}
		return strings.Join(ids, "")
	}
	cases := []struct {
		name string
		f    Filter
		want string
	}{
		{"default hides listeners", Filter{}, "12346"},
		{"listeners", Filter{Listening: true}, "123456"},
		{"process by app name", Filter{Process: "chrome"}, "12"},
		{"process by path", Filter{Process: "/usr/bin"}, "36"},
		{"proto", Filter{Proto: "udp"}, "2"},
		{"unix", Filter{Proto: "unix"}, "4"},
		{"iface egress", Filter{Iface: "en1"}, "3"},
		{"iface tunnel", Filter{Iface: "utun1990"}, "123"},
		{"rule", Filter{Rule: "ipcidr"}, "3"},
		{"node", Filter{Node: "HK"}, "1"},
		{"group", Filter{Node: "Proxy"}, "1"},
		{"proxied", Filter{Routing: "proxied"}, "1"},
		{"direct", Filter{Routing: "direct"}, "236"},
		{"ended before window", Filter{Since: now.Add(2 * time.Minute)}, "1246"},
		{"started after window", Filter{Until: now.Add(-time.Second)}, ""},
	}
	for _, c := range cases {
		if got := count(c.f); got != c.want {
			t.Errorf("%s: flows %q, want %q", c.name, got, c.want)
		}
	}
}

func node(s Sankey, id string) (SankeyNode, bool) {
	for _, n := range s.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return SankeyNode{}, false
}

func link(s Sankey, from, to string) (SankeyLink, bool) {
	for _, l := range s.Links {
		if l.Source == from && l.Target == to {
			return l, true
		}
	}
	return SankeyLink{}, false
}

func TestFullSankeyLayers(t *testing.T) {
	flows := Filter{}.Apply(sampleFlows())
	s := BuildSankey(flows, ViewFull, 0)
	if strings.Join(s.Layers, ",") != "process,protocol,tunnel,rule,node,nic,destination" {
		t.Errorf("layers = %v", s.Layers)
	}
	// Chrome's flows share one process box; its width is the sum of both flows.
	if n, ok := node(s, "process|Google Chrome"); !ok || n.Bytes != 1500 || n.Flows != 2 {
		t.Errorf("chrome node = %+v %v", n, ok)
	}
	if _, ok := node(s, "protocol|UDP/QUIC · IPv6"); !ok {
		t.Errorf("missing QUIC node; nodes: %v", s.Nodes)
	}
	// The full path of flow 1.
	for _, hop := range []struct {
		from, to string
		bytes    int64
	}{
		{"process|Google Chrome", "protocol|TCP · IPv4", 1000},
		{"protocol|TCP · IPv4", "tunnel|utun1990", 1030}, // curl's flow 3 shares this hop
		{"tunnel|utun1990", "rule|DomainSuffix example.com", 1000},
		{"rule|DomainSuffix example.com", "node|Proxy → HK", 1000},
		{"node|Proxy → HK", "nic|en0", 1000},
		{"nic|en0", "destination|example.com", 1000},
	} {
		if l, ok := link(s, hop.from, hop.to); !ok || l.Value != hop.bytes {
			t.Errorf("link %s → %s = %+v %v, want %d bytes", hop.from, hop.to, l, ok, hop.bytes)
		}
	}
	// Unix sockets are separate local IPC: process → Unix socket, nothing further.
	if _, ok := link(s, "process|mDNSResponder", "protocol|Unix socket"); !ok {
		t.Error("unix flow not linked to its socket type")
	}
	for _, l := range s.Links {
		if l.Source == "protocol|Unix socket" {
			t.Errorf("unix socket continues to %s", l.Target)
		}
	}
	// A flow that never entered TUN is labelled as such, and its anomaly lights the box.
	if n, ok := node(s, "tunnel|not captured"); !ok || !n.Alert {
		t.Errorf("not-captured node = %+v %v", n, ok)
	}
	// Unknown byte counts still draw a hairline.
	if l, ok := link(s, "nic|en0", "destination|8.8.4.4"); !ok || l.Value != 1 {
		t.Errorf("hairline link = %+v %v", l, ok)
	}
}

func TestHardwareAndSoftwareViews(t *testing.T) {
	flows := Filter{}.Apply(sampleFlows())
	hw := BuildSankey(flows, ViewHardware, 0)
	for _, n := range hw.Nodes {
		if n.Layer != LayerTunnel && n.Layer != LayerNIC {
			t.Errorf("hardware view has a %s node", n.Layer)
		}
	}
	if l, ok := link(hw, "tunnel|utun1990", "nic|en1"); !ok || l.Value != 30 {
		t.Errorf("utun→en1 = %+v %v", l, ok)
	}
	sw := BuildSankey(flows, ViewSoftware, 0)
	for _, n := range sw.Nodes {
		if n.Layer == LayerNIC || n.Layer == LayerTunnel || n.Layer == LayerNode {
			t.Errorf("software view has a %s node", n.Layer)
		}
	}
	if _, ok := link(sw, "process|curl", "protocol|TCP · IPv4"); !ok {
		t.Error("software view missing process→protocol")
	}
	if BuildSankey(flows, View("bogus"), 0).View != ViewFull {
		t.Error("unknown view should fall back to full")
	}
}

func TestSankeyGroupsSmallNodes(t *testing.T) {
	var flows []Flow
	for i := 0; i < 30; i++ {
		flows = append(flows, Flow{ID: fmt.Sprint(i), Process: Process{Name: fmt.Sprintf("app%02d", i)}, Proto: ProtoTCP, Family: "ipv4",
			Remote: "1.1.1.1:443", Node: "DIRECT", Egress: "en0", Upload: int64(1000 - i)})
	}
	s := BuildSankey(flows, ViewSoftware, 5)
	procs := 0
	for _, n := range s.Nodes {
		if n.Layer == LayerProcess {
			procs++
		}
	}
	if procs != 6 {
		t.Errorf("%d process boxes, want 5 + other", procs)
	}
	if n, ok := node(s, "process|other (25)"); !ok || n.Flows != 25 {
		t.Errorf("other node = %+v %v", n, ok)
	}
	// Totals are preserved through grouping.
	var sum int64
	for _, l := range s.Links {
		if strings.HasPrefix(l.Source, "process|") {
			sum += l.Value
		}
	}
	var want int64
	for _, f := range flows {
		want += f.Bytes()
	}
	if sum != want {
		t.Errorf("process links carry %d bytes, flows have %d", sum, want)
	}
}

func TestRollupByProcess(t *testing.T) {
	r := RollupByProcess(sampleFlows())
	if r[0].Name != "Google Chrome" || r[0].Flows != 2 || r[0].TCP != 1 || r[0].UDP != 1 || r[0].Upload != 150 || r[0].Download != 1350 {
		t.Errorf("chrome = %+v", r[0])
	}
	if r[0].ProxiedShare < 0.66 || r[0].ProxiedShare > 0.67 {
		t.Errorf("proxied share = %v", r[0].ProxiedShare)
	}
	var curl, mdns Rollup
	for _, x := range r {
		switch x.Name {
		case "curl":
			curl = x
		case "mDNSResponder":
			mdns = x
		}
	}
	if curl.Flows != 2 || curl.Anomalies != 1 || mdns.Unix != 1 {
		t.Errorf("curl = %+v, mdns = %+v", curl, mdns)
	}
}

func TestDeltaAndReconcile(t *testing.T) {
	before := map[string]IfaceCounters{
		"utun1990": {Name: "utun1990", InBytes: 1000, OutBytes: 2000},
		"en0":      {Name: "en0", InBytes: 5000, OutBytes: 6000},
	}
	after := map[string]IfaceCounters{
		"utun1990": {Name: "utun1990", InBytes: 11000, OutBytes: 12000},
		"en0":      {Name: "en0", InBytes: 16000, OutBytes: 18000},
		"en1":      {Name: "en1", InBytes: 100, OutBytes: 200},
		"lo0":      {Name: "lo0", InBytes: 1, OutBytes: 1},
	}
	d := Delta(before, after)
	if d["utun1990"].OutBytes != 10000 || d["en1"].OutBytes != 200 {
		t.Errorf("delta = %+v", d)
	}
	reset := Delta(map[string]IfaceCounters{"en0": {OutBytes: 900}}, map[string]IfaceCounters{"en0": {OutBytes: 100}})
	if reset["en0"].OutBytes != 100 {
		t.Errorf("counter reset = %+v", reset)
	}

	flows := []Flow{{Proxied: true, Upload: 8000}, {Upload: 1500}, {Node: "REJECT", Upload: 10},
		{Anomalies: []Anomaly{{Kind: AnomalyBypassedTUN}}}, {Anomalies: []Anomaly{{Kind: AnomalyOtherVPN}}}}
	r := Reconcile(d, "utun1990", flows, 10*time.Second)
	if r.TunUp != 10000 || r.TunDown != 10000 || r.NICUp != 12200 || r.NICDown != 11100 || r.GapUp != 2200 || r.GapDown != 1100 {
		t.Errorf("reconciliation = %+v", r)
	}
	if strings.Join(r.NICs, ",") != "en0,en1" {
		t.Errorf("NICs = %v (lo0 and the TUN aren't physical)", r.NICs)
	}
	text := strings.Join(r.Notes, "\n")
	for _, want := range []string{"more than the TUN received (22% extra)", "1 flows that bypass TUN", "1 flows routed through another VPN", "9.8 KB into utun1990", "7.8 KB of it was proxied"} {
		if !strings.Contains(text, want) {
			t.Errorf("notes missing %q:\n%s", want, text)
		}
	}
	if r2 := Reconcile(d, "", nil, time.Second); len(r2.Notes) != 1 || !strings.Contains(r2.Notes[0], "isn't in TUN mode") {
		t.Errorf("no-TUN notes = %v", r2.Notes)
	}

	rates := Rates(d, after, 10*time.Second)
	if len(rates) != 4 || rates[1].Name != "en1" || rates[0].OutBps != 1200 {
		t.Errorf("rates = %+v", rates)
	}
}
