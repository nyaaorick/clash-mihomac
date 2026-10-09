package traffic

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Inputs are one moment's worth of data from every source.
type Inputs struct {
	Time    time.Time
	Conns   []Conn
	Sockets []Socket
	Routes  *RouteTable
	PS      map[int]PSEntry

	// TUNMode is whether this instance is capturing traffic; OwnTUN is its
	// device, e.g. utun1990.
	TUNMode bool
	OwnTUN  string
	// DefaultIface is the physical interface DIRECT traffic uses when the
	// route table can't say.
	DefaultIface string
	// AddrOwner maps each local address to the interface that holds it.
	AddrOwner map[netip.Addr]string
	// NodeAddrs returns the addresses of a proxy node's server.
	NodeAddrs func(node string) []netip.Addr
	// IgnorePIDs are processes whose own sockets would double count flows
	// (the mihomo core: its sockets are the other half of proxied flows).
	IgnorePIDs []int
}

// Join builds flows from all sources. Every mihomo connection becomes a
// flow, enriched with the socket table's view of its process; sockets that
// mihomo never saw become flows of their own, which is how traffic that
// bypassed TUN, and local IPC, show up.
func Join(in Inputs) []Flow {
	socketsByLocal := map[netip.AddrPort]Socket{}
	for _, s := range in.Sockets {
		if s.Family == "unix" || s.Local == "" {
			continue
		}
		if ap, err := netip.ParseAddrPort(s.Local); err == nil {
			socketsByLocal[normalize(ap)] = s
		}
	}

	var flows []Flow
	matched := map[netip.AddrPort]bool{}
	for _, c := range in.Conns {
		f := connFlow(c, in)
		if ap, err := netip.ParseAddrPort(c.Source); err == nil {
			ap = normalize(ap)
			if s, ok := socketsByLocal[ap]; ok {
				matched[ap] = true
				f.Process = processFor(s.PID, s.Command, firstNonEmpty(c.ProcessPath, in.PS[s.PID].Path), in.PS)
				f.State = s.State
			}
		}
		flows = append(flows, f)
	}

	for _, s := range in.Sockets {
		if slices.Contains(in.IgnorePIDs, s.PID) {
			continue
		}
		if s.Family != "unix" {
			if ap, err := netip.ParseAddrPort(s.Local); err == nil && matched[normalize(ap)] {
				continue
			}
		}
		flows = append(flows, socketFlow(s, in))
	}
	return flows
}

func normalize(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())
}

func connFlow(c Conn, in Inputs) Flow {
	f := Flow{
		ID: "conn-" + c.ID, Start: c.Start, End: c.End,
		Process: processFor(0, c.Process, c.ProcessPath, in.PS),
		Proto:   strings.ToLower(c.Network), Local: c.Source,
		Host: c.Host, Rule: c.Rule, RulePayload: c.RulePayload,
		Upload: c.Upload, Download: c.Download,
		EnteredTUN: strings.EqualFold(c.Inbound, "tun"),
	}
	if f.Proto != ProtoTCP && f.Proto != ProtoUDP {
		f.Proto = ProtoOther
	}
	if f.Process.Name == "" {
		f.Process.Name = "unknown"
	}
	dest := c.DestIP
	f.Remote = joinHostPort(firstNonEmpty(dest, c.Host), c.DestPort)
	f.Family = "ipv4"
	var destAddr netip.Addr
	if a, err := netip.ParseAddr(dest); err == nil {
		destAddr = a.Unmap()
		if destAddr.Is6() {
			f.Family = "ipv6"
		}
	}
	f.App = appProto(f.Proto, c.DestPort)
	if f.EnteredTUN {
		f.Ingress = in.OwnTUN
	}

	if len(c.Chains) > 0 {
		f.Node = c.Chains[0]
		if len(c.Chains) > 1 {
			f.Group = c.Chains[1]
		}
	}
	switch {
	case f.Node == "":
	case strings.EqualFold(f.Node, "REJECT") || strings.EqualFold(f.Node, "REJECT-DROP"):
		// blocked: nothing leaves the machine
	case strings.HasPrefix(f.Node, "iface:"):
		f.Egress = strings.TrimPrefix(f.Node, "iface:")
		f.NextHop = routeVia(in, destAddr, f.Egress)
	case strings.EqualFold(f.Node, "DIRECT"):
		f.Egress, f.NextHop = egress(in, []netip.Addr{destAddr})
	default:
		f.Proxied = true
		f.Egress, f.NextHop = egress(in, in.nodeAddrs(f.Node))
	}
	f.Anomalies = pathAnomalies(f, in)
	return f
}

func (in Inputs) nodeAddrs(node string) []netip.Addr {
	if in.NodeAddrs == nil {
		return nil
	}
	return in.NodeAddrs(node)
}

// egress finds the physical interface and gateway traffic to any of addrs
// leaves through, looking past our own TUN's capture routes.
func egress(in Inputs, addrs []netip.Addr) (iface, gw string) {
	if in.Routes != nil {
		for _, a := range addrs {
			if !a.IsValid() {
				continue
			}
			if r, ok := in.Routes.LookupAvoiding(a, in.OwnTUN); ok {
				return r.Iface, r.Gateway
			}
		}
	}
	return in.DefaultIface, ""
}

func routeVia(in Inputs, dest netip.Addr, iface string) string {
	if in.Routes == nil || !dest.IsValid() {
		return ""
	}
	if r, ok := in.Routes.LookupAvoiding(dest, in.OwnTUN); ok && r.Iface == iface {
		return r.Gateway
	}
	return ""
}

// tunnelIface reports interfaces that carry tunneled traffic.
func tunnelIface(name string) bool {
	for _, p := range []string{"utun", "ipsec", "ppp", "gif", "stf"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func pathAnomalies(f Flow, in Inputs) []Anomaly {
	var out []Anomaly
	if f.Egress != "" && tunnelIface(f.Egress) && f.Egress != in.OwnTUN {
		out = append(out, Anomaly{AnomalyOtherVPN, fmt.Sprintf("this traffic leaves through %s, another tunnel's interface, not a physical NIC; another VPN's routes are taking it", f.Egress)})
	}
	return out
}

func socketFlow(s Socket, in Inputs) Flow {
	f := Flow{
		ID:      fmt.Sprintf("sock-%d-%s-%s-%s", s.PID, s.Proto, s.Local, s.Remote),
		Start:   in.Time,
		Process: processFor(s.PID, s.Command, in.PS[s.PID].Path, in.PS),
		Proto:   s.Proto, Family: s.Family, State: s.State,
		Local: s.Local, Remote: s.Remote, Listen: s.Listening,
		BytesUnknown: true,
	}
	if s.Family == "unix" {
		f.Internal = true
		return f
	}
	_, port := splitHostPort(s.Remote)
	f.App = appProto(s.Proto, port)
	if s.Listening || s.Remote == "" {
		return f
	}
	remote, err := netip.ParseAddrPort(s.Remote)
	if err != nil {
		return f
	}
	dest := remote.Addr().Unmap()
	if in.Routes == nil {
		return f
	}
	route, ok := in.Routes.Lookup(dest)
	if !ok {
		return f
	}

	switch {
	case in.OwnTUN != "" && route.Iface == in.OwnTUN:
		f.EnteredTUN, f.Ingress = true, in.OwnTUN
		f.Egress, f.NextHop = egress(in, []netip.Addr{dest})
	default:
		f.Egress, f.NextHop = route.Iface, route.Gateway
		if in.TUNMode && !localOnly(dest) && !tunnelIface(route.Iface) && route.Iface != "lo0" {
			f.Anomalies = append(f.Anomalies, Anomaly{AnomalyBypassedTUN, fmt.Sprintf(
				"this connection did not go through TUN: the route to %s is via %s%s, not %s",
				dest, route.Iface, viaGateway(route.Gateway), in.OwnTUN)})
		}
	}
	if tunnelIface(f.Egress) && f.Egress != in.OwnTUN {
		f.Anomalies = append(f.Anomalies, Anomaly{AnomalyOtherVPN, fmt.Sprintf("this traffic is routed into %s, another tunnel's interface", f.Egress)})
	}
	if local, err := netip.ParseAddrPort(s.Local); err == nil && in.AddrOwner != nil {
		owner := in.AddrOwner[local.Addr().Unmap()]
		if owner != "" && f.Egress != "" && owner != f.Egress && !tunnelIface(owner) && !tunnelIface(f.Egress) && f.Egress != "lo0" && owner != "lo0" {
			f.Anomalies = append(f.Anomalies, Anomaly{AnomalyWrongNIC, fmt.Sprintf(
				"the connection uses %s's address (%s) but the route to %s leaves through %s",
				owner, local.Addr().Unmap(), dest, f.Egress)})
		}
	}
	return f
}

func viaGateway(gw string) string {
	if gw == "" {
		return ""
	}
	return " (gateway " + gw + ")"
}

// localOnly reports destinations TUN legitimately doesn't capture: the
// machine itself, link-local, and multicast.
func localOnly(a netip.Addr) bool {
	return a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

func processFor(pid int, name, path string, ps map[int]PSEntry) Process {
	p := Process{PID: pid, Name: name, Path: path}
	if p.Name == "" && p.Path != "" {
		p.Name = filepath.Base(p.Path)
	}
	if e, ok := ps[pid]; ok {
		if p.Path == "" {
			p.Path = e.Path
		}
		p.ParentPID = e.PPID
		if parent, ok := ps[e.PPID]; ok {
			p.ParentName = filepath.Base(parent.Path)
		}
	}
	p.Bundle = BundleOf(p.Path)
	return p
}

func appProto(proto, port string) string {
	switch {
	case port == "53":
		return AppDNS
	case proto == ProtoUDP && (port == "443" || port == "8443"):
		return AppQUIC
	}
	return ""
}

func splitHostPort(s string) (host, port string) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().String(), fmt.Sprint(ap.Port())
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

func joinHostPort(host, port string) string {
	if host == "" {
		return ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port == "" {
		return host
	}
	return host + ":" + port
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
