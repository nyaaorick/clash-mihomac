package traffic

import (
	"net/netip"
	"sort"
	"strings"
)

// RouteTable answers "which interface and gateway would this destination
// use?".
type RouteTable struct {
	routes []parsedRoute
}

type parsedRoute struct {
	prefix netip.Prefix
	Route
}

// NewRouteTable indexes routes. Scoped default routes (flag I) serve one
// interface's own traffic and aren't part of ordinary lookups.
func NewRouteTable(routes []Route) *RouteTable {
	t := &RouteTable{}
	for _, r := range routes {
		p, err := netip.ParsePrefix(r.Dest)
		if err != nil || p.Bits() == 0 && strings.Contains(r.Flags, "I") {
			continue
		}
		t.routes = append(t.routes, parsedRoute{prefix: p, Route: r})
	}
	return t
}

// Lookup returns the best route for ip: the longest matching prefix, with
// ties going to the earlier table entry.
func (t *RouteTable) Lookup(ip netip.Addr) (Route, bool) { return t.lookup(ip, "") }

// LookupAvoiding is Lookup, ignoring routes through the named interface. It
// finds where traffic goes once our own TUN has captured and re-emitted it.
func (t *RouteTable) LookupAvoiding(ip netip.Addr, avoid string) (Route, bool) {
	return t.lookup(ip, avoid)
}

func (t *RouteTable) lookup(ip netip.Addr, avoid string) (Route, bool) {
	ip = ip.Unmap().WithZone("")
	best, bestBits := Route{}, -1
	for _, r := range t.routes {
		if avoid != "" && r.Iface == avoid || !r.prefix.Contains(ip) {
			continue
		}
		if r.prefix.Bits() > bestBits {
			best, bestBits = r.Route, r.prefix.Bits()
		}
	}
	return best, bestBits >= 0
}

// DestinationsVia lists up to max destinations (CIDRs) routed through the
// named interface, most specific first. It is safe on a nil table.
func (t *RouteTable) DestinationsVia(iface string, max int) []string {
	if t == nil {
		return nil
	}
	var rs []parsedRoute
	for _, r := range t.routes {
		if r.Iface == iface {
			rs = append(rs, r)
		}
	}
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].prefix.Bits() > rs[j].prefix.Bits() })
	var out []string
	for _, r := range rs {
		if len(out) == max {
			break
		}
		out = append(out, r.Dest)
	}
	return out
}
