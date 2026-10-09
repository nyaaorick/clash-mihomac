package traffic

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// View selects which layers the Sankey shows.
type View string

// Views.
const (
	ViewFull     View = "full"     // process → protocol → utun → rule → node → NIC → destination
	ViewHardware View = "hardware" // tunnels and NICs only
	ViewSoftware View = "software" // processes, protocols, and destinations only
)

// Layer names, in column order.
const (
	LayerProcess  = "process"
	LayerProtocol = "protocol"
	LayerTunnel   = "tunnel"
	LayerRule     = "rule"
	LayerNode     = "node"
	LayerNIC      = "nic"
	LayerDest     = "destination"
)

var viewLayers = map[View][]string{
	ViewFull:     {LayerProcess, LayerProtocol, LayerTunnel, LayerRule, LayerNode, LayerNIC, LayerDest},
	ViewHardware: {LayerTunnel, LayerNIC},
	ViewSoftware: {LayerProcess, LayerProtocol, LayerDest},
}

// Filter narrows the flows a view shows. Empty fields match everything.
type Filter struct {
	Since, Until time.Time
	Process      string // substring of the process name, path, or bundle
	Proto        string // tcp, udp, unix, icmp
	Iface        string // matches the ingress tunnel or the egress NIC
	Rule         string // substring of the rule type or payload
	Node         string // exact node name, group name, DIRECT, ...
	Routing      string // "proxied" or "direct"
	Listening    bool   // include listening sockets (they carry no traffic)
}

// Match reports whether f passes the filter.
func (fl Filter) Match(f Flow) bool {
	if f.Listen && !fl.Listening {
		return false
	}
	// A flow overlaps the window if it started before it ended and was
	// still open (or ended) after it began.
	if !fl.Until.IsZero() && f.Start.After(fl.Until) {
		return false
	}
	if !fl.Since.IsZero() && f.End != nil && f.End.Before(fl.Since) {
		return false
	}
	if fl.Process != "" && !containsFold(f.Process.Name+" "+f.Process.Path+" "+f.Process.Bundle, fl.Process) {
		return false
	}
	if fl.Proto != "" && !strings.EqualFold(f.Proto, fl.Proto) {
		return false
	}
	if fl.Iface != "" && f.Ingress != fl.Iface && f.Egress != fl.Iface {
		return false
	}
	if fl.Rule != "" && !containsFold(f.Rule+","+f.RulePayload, fl.Rule) {
		return false
	}
	if fl.Node != "" && f.Node != fl.Node && f.Group != fl.Node {
		return false
	}
	switch fl.Routing {
	case "proxied":
		if !f.Proxied {
			return false
		}
	case "direct":
		if f.Proxied || f.Internal {
			return false
		}
	}
	return true
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// Apply returns the flows that pass the filter.
func (fl Filter) Apply(flows []Flow) []Flow {
	var out []Flow
	for _, f := range flows {
		if fl.Match(f) {
			out = append(out, f)
		}
	}
	return out
}

// SankeyNode is one box in the diagram.
type SankeyNode struct {
	ID    string `json:"id"`
	Layer string `json:"layer"`
	Label string `json:"label"`
	Bytes int64  `json:"bytes"`
	Flows int    `json:"flows"`
	// Alert marks nodes carrying a flow with an anomaly.
	Alert bool `json:"alert,omitempty"`
}

// SankeyLink is a band between two boxes in adjacent present layers.
type SankeyLink struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Value  int64  `json:"value"` // bytes; flows with unknown byte counts count as 1
	Flows  int    `json:"flows"`
}

// Sankey is the diagram's data.
type Sankey struct {
	View   View         `json:"view"`
	Layers []string     `json:"layers"`
	Nodes  []SankeyNode `json:"nodes"`
	Links  []SankeyLink `json:"links"`
}

// DefaultNodesPerLayer limits boxes per column; the rest group into one
// "other" box so the diagram stays readable.
const DefaultNodesPerLayer = 12

// BuildSankey lays the (already filtered) flows out as a layered diagram.
func BuildSankey(flows []Flow, view View, perLayer int) Sankey {
	layers, ok := viewLayers[view]
	if !ok {
		view, layers = ViewFull, viewLayers[ViewFull]
	}
	if perLayer <= 0 {
		perLayer = DefaultNodesPerLayer
	}

	// First pass: each flow's label in each layer, and the totals that decide
	// which labels are big enough to keep their own box.
	labels := make([]map[string]string, len(flows))
	totals := map[string]map[string]int64{}
	for i, f := range flows {
		labels[i] = layerLabels(f)
		for _, l := range layers {
			if lab := labels[i][l]; lab != "" {
				if totals[l] == nil {
					totals[l] = map[string]int64{}
				}
				totals[l][lab] += weight(f)
			}
		}
	}
	keep := map[string]map[string]bool{}
	others := map[string]int{}
	for l, m := range totals {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if m[keys[i]] != m[keys[j]] {
				return m[keys[i]] > m[keys[j]]
			}
			return keys[i] < keys[j]
		})
		keep[l] = map[string]bool{}
		for i, k := range keys {
			if i < perLayer {
				keep[l][k] = true
			}
		}
		others[l] = max(0, len(keys)-perLayer)
	}

	nodes := map[string]*SankeyNode{}
	links := map[[2]string]*SankeyLink{}
	for i, f := range flows {
		w := weight(f)
		var prev string
		for _, l := range layers {
			lab := labels[i][l]
			if lab == "" {
				continue
			}
			if !keep[l][lab] {
				lab = fmt.Sprintf("other (%d)", others[l])
			}
			id := l + "|" + lab
			n := nodes[id]
			if n == nil {
				n = &SankeyNode{ID: id, Layer: l, Label: lab}
				nodes[id] = n
			}
			n.Bytes += f.Bytes()
			n.Flows++
			if len(f.Anomalies) > 0 {
				n.Alert = true
			}
			if prev != "" {
				k := [2]string{prev, id}
				lk := links[k]
				if lk == nil {
					lk = &SankeyLink{Source: prev, Target: id}
					links[k] = lk
				}
				lk.Value += w
				lk.Flows++
			}
			prev = id
		}
	}

	s := Sankey{View: view, Layers: layers, Nodes: []SankeyNode{}, Links: []SankeyLink{}}
	for _, n := range nodes {
		s.Nodes = append(s.Nodes, *n)
	}
	sort.Slice(s.Nodes, func(i, j int) bool {
		a, b := s.Nodes[i], s.Nodes[j]
		if a.Layer != b.Layer {
			return layerIndex(layers, a.Layer) < layerIndex(layers, b.Layer)
		}
		if a.Bytes != b.Bytes {
			return a.Bytes > b.Bytes
		}
		return a.Label < b.Label
	})
	for _, l := range links {
		s.Links = append(s.Links, *l)
	}
	sort.Slice(s.Links, func(i, j int) bool {
		a, b := s.Links[i], s.Links[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.Target < b.Target
	})
	return s
}

func layerIndex(layers []string, l string) int {
	for i, x := range layers {
		if x == l {
			return i
		}
	}
	return len(layers)
}

// weight is a flow's width in the diagram.
func weight(f Flow) int64 { return max(f.Bytes(), 1) }

// layerLabels names a flow's box in each layer; an empty label means the
// flow skips that layer.
func layerLabels(f Flow) map[string]string {
	m := map[string]string{
		LayerProcess:  AppName(f.Process),
		LayerProtocol: ProtocolLabel(f),
		LayerTunnel:   f.Ingress,
		LayerNIC:      f.Egress,
	}
	if f.Internal {
		return m // local IPC: process → "Unix socket", nothing more
	}
	if f.Rule != "" {
		m[LayerRule] = strings.TrimSuffix(f.Rule+" "+f.RulePayload, " ")
	}
	m[LayerNode] = f.Node
	if f.Group != "" && f.Group != f.Node {
		m[LayerNode] = f.Group + " → " + f.Node
	}
	m[LayerDest] = destLabel(f)
	if f.Ingress == "" && f.Egress != "" {
		m[LayerTunnel] = "not captured"
	}
	return m
}

// AppName is the name people know a process by.
func AppName(p Process) string {
	if p.Bundle != "" {
		return strings.TrimSuffix(filepath.Base(p.Bundle), ".app")
	}
	if p.Name != "" {
		return p.Name
	}
	return "unknown"
}

// ProtocolLabel is the transport and socket type, e.g. "UDP/QUIC · IPv6".
func ProtocolLabel(f Flow) string {
	if f.Internal || f.Proto == ProtoUnix {
		return "Unix socket"
	}
	p := strings.ToUpper(f.Proto)
	switch f.App {
	case AppQUIC:
		p += "/QUIC"
	case AppDNS:
		p += "/DNS"
	}
	fam := map[string]string{"ipv4": "IPv4", "ipv6": "IPv6"}[f.Family]
	if fam != "" {
		return p + " · " + fam
	}
	return p
}

func destLabel(f Flow) string {
	if f.Host != "" {
		return f.Host
	}
	host, _ := splitHostPort(f.Remote)
	return host
}

// Rollup is one process's traffic, summed over its flows.
type Rollup struct {
	Name         string  `json:"name"`
	Bundle       string  `json:"bundle,omitempty"`
	Flows        int     `json:"flows"`
	TCP          int     `json:"tcp"`
	UDP          int     `json:"udp"`
	Unix         int     `json:"unix"`
	Upload       int64   `json:"upload"`
	Download     int64   `json:"download"`
	ProxiedBytes int64   `json:"proxied_bytes"`
	ProxiedShare float64 `json:"proxied_share"` // of this process's bytes, 0..1
	Anomalies    int     `json:"anomalies"`
}

// RollupByProcess sums flows per application, biggest first.
func RollupByProcess(flows []Flow) []Rollup {
	m := map[string]*Rollup{}
	for _, f := range flows {
		if f.Listen {
			continue
		}
		name := AppName(f.Process)
		r := m[name]
		if r == nil {
			r = &Rollup{Name: name, Bundle: f.Process.Bundle}
			m[name] = r
		}
		r.Flows++
		switch f.Proto {
		case ProtoTCP:
			r.TCP++
		case ProtoUDP:
			r.UDP++
		case ProtoUnix:
			r.Unix++
		}
		r.Upload += f.Upload
		r.Download += f.Download
		if f.Proxied {
			r.ProxiedBytes += f.Bytes()
		}
		r.Anomalies += len(f.Anomalies)
	}
	out := make([]Rollup, 0, len(m))
	for _, r := range m {
		if total := r.Upload + r.Download; total > 0 {
			r.ProxiedShare = float64(r.ProxiedBytes) / float64(total)
		}
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ta, tb := a.Upload+a.Download, b.Upload+b.Download; ta != tb {
			return ta > tb
		}
		return a.Name < b.Name
	})
	return out
}
