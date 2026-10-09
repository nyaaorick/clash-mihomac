package daemon

import (
	"context"
	"net"
	"sort"
	"strings"

	"github.com/nyaaorick/clash-mihomac/internal/netstate"
)

// Iface is a network interface as the GUI shows it.
type Iface struct {
	Name    string   `json:"name"`
	Up      bool     `json:"up"`
	Addrs   []string `json:"addrs"`
	Routes  int      `json:"routes"` // routing-table entries through it
	Default bool     `json:"default"`
	Role    string   `json:"role"`
}

var shownPrefixes = []string{"en", "bridge", "utun", "ipsec", "ppp"}

// Interfaces lists the interfaces that matter for routing, with how many
// routes each one owns.
func Interfaces(ctx context.Context, r netstate.Runner, ownDevice string) ([]Iface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	routes := map[string]int{}
	if out, err := r.Run(ctx, "/usr/sbin/netstat", "-rn"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if f := strings.Fields(line); len(f) >= 4 {
				routes[f[3]]++
			}
		}
	}
	_, defIface := netstate.DefaultRoute(ctx, r)

	var out []Iface
	for _, ifi := range ifs {
		if !hasAnyPrefix(ifi.Name, shownPrefixes) {
			continue
		}
		it := Iface{Name: ifi.Name, Up: ifi.Flags&net.FlagUp != 0, Routes: routes[ifi.Name], Default: ifi.Name == defIface}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() {
				it.Addrs = append(it.Addrs, ipn.String())
			}
		}
		tunnel := hasAnyPrefix(ifi.Name, []string{"utun", "ipsec", "ppp"})
		if tunnel && it.Routes == 0 && len(it.Addrs) == 0 {
			continue // idle system tunnels (iCloud Private Relay, etc.)
		}
		switch {
		case ifi.Name == ownDevice:
			it.Role = "Clash Mihomac TUN (this instance)"
		case it.Default:
			it.Role = "default route"
		case tunnel:
			it.Role = "VPN or another TUN client"
		case strings.HasPrefix(ifi.Name, "bridge"):
			it.Role = "bridge (VMs, containers, sharing)"
		case len(it.Addrs) > 0:
			it.Role = "secondary network"
		default:
			it.Role = "not connected"
		}
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Default != out[j].Default {
			return out[i].Default
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
