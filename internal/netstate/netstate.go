// Package netstate snapshots and restores the parts of macOS network
// configuration Clash Mihomac can change: per-service DNS servers, system
// proxy settings, and the default route. It also finds routes left behind
// on a TUN device.
//
// Everything goes through a Runner so the parsing and restore logic can be
// tested without touching the real system.
package netstate

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Runner runs a system command and returns its combined output.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// ExecRunner runs real commands.
type ExecRunner struct{}

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

const (
	networksetup = "/usr/sbin/networksetup"
	route        = "/sbin/route"
	netstat      = "/usr/sbin/netstat"
)

// Proxy is one kind of system proxy on a service.
type Proxy struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server"`
	Port    int    `json:"port"`
}

// Service is the saved state of one network service (e.g. "Wi-Fi").
type Service struct {
	Name          string   `json:"name"`
	DNS           []string `json:"dns"` // empty means automatic (DHCP)
	Web           Proxy    `json:"web"`
	SecureWeb     Proxy    `json:"secure_web"`
	SOCKS         Proxy    `json:"socks"`
	BypassDomains []string `json:"bypass_domains"`
}

// Snapshot is the network state at a point in time.
type Snapshot struct {
	Taken            time.Time `json:"taken"`
	Services         []Service `json:"services"`
	DefaultGateway   string    `json:"default_gateway"`
	DefaultInterface string    `json:"default_interface"`
}

// Take captures the current state of every enabled network service.
func Take(ctx context.Context, r Runner) (Snapshot, error) {
	names, err := services(ctx, r)
	if err != nil {
		return Snapshot{}, err
	}
	snap := Snapshot{Taken: time.Now()}
	for _, name := range names {
		svc := Service{Name: name}
		out, err := r.Run(ctx, networksetup, "-getdnsservers", name)
		if err != nil {
			return Snapshot{}, err
		}
		svc.DNS = parseList(out)
		for _, p := range []struct {
			flag string
			dst  *Proxy
		}{{"-getwebproxy", &svc.Web}, {"-getsecurewebproxy", &svc.SecureWeb}, {"-getsocksfirewallproxy", &svc.SOCKS}} {
			out, err := r.Run(ctx, networksetup, p.flag, name)
			if err != nil {
				return Snapshot{}, err
			}
			*p.dst = parseProxy(out)
		}
		out, err = r.Run(ctx, networksetup, "-getproxybypassdomains", name)
		if err != nil {
			return Snapshot{}, err
		}
		svc.BypassDomains = parseList(out)
		snap.Services = append(snap.Services, svc)
	}
	snap.DefaultGateway, snap.DefaultInterface = DefaultRoute(ctx, r)
	return snap, nil
}

// services lists enabled network services.
func services(ctx context.Context, r Runner) ([]string, error) {
	out, err := r.Run(ctx, networksetup, "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	var names []string
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if i == 0 || line == "" || strings.HasPrefix(line, "*") {
			continue // header, blank, or disabled service
		}
		names = append(names, line)
	}
	return names, nil
}

// parseList parses networksetup output that is either a list of values,
// one per line, or a sentence saying there are none.
func parseList(out string) []string {
	var vals []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, " ") {
			continue // "There aren't any DNS Servers set on Wi-Fi."
		}
		vals = append(vals, line)
	}
	return vals
}

func parseProxy(out string) Proxy {
	var p Proxy
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "Enabled":
			p.Enabled = v == "Yes"
		case "Server":
			p.Server = v
		case "Port":
			p.Port, _ = strconv.Atoi(v)
		}
	}
	return p
}

// DefaultRoute returns the IPv4 default gateway and its interface, or
// empty strings if there is no default route.
func DefaultRoute(ctx context.Context, r Runner) (gateway, iface string) {
	out, err := r.Run(ctx, route, "-n", "get", "default")
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		switch k {
		case "gateway":
			gateway = strings.TrimSpace(v)
		case "interface":
			iface = strings.TrimSpace(v)
		}
	}
	return gateway, iface
}

// Diff lists how current differs from want, for the services in want.
func Diff(want, current Snapshot) []string {
	var diffs []string
	cur := map[string]Service{}
	for _, s := range current.Services {
		cur[s.Name] = s
	}
	for _, w := range want.Services {
		c, ok := cur[w.Name]
		if !ok {
			continue // service removed (e.g. a USB adapter unplugged); nothing to restore
		}
		if !slices.Equal(w.DNS, c.DNS) {
			diffs = append(diffs, fmt.Sprintf("%s DNS is %v, was %v", w.Name, orAuto(c.DNS), orAuto(w.DNS)))
		}
		for _, p := range []struct {
			kind string
			w, c Proxy
		}{{"web proxy", w.Web, c.Web}, {"secure web proxy", w.SecureWeb, c.SecureWeb}, {"SOCKS proxy", w.SOCKS, c.SOCKS}} {
			if !sameProxy(p.w, p.c) {
				diffs = append(diffs, fmt.Sprintf("%s %s is %s, was %s", w.Name, p.kind, p.c, p.w))
			}
		}
		if !slices.Equal(w.BypassDomains, c.BypassDomains) {
			diffs = append(diffs, fmt.Sprintf("%s proxy bypass list changed", w.Name))
		}
	}
	if want.DefaultGateway != "" && current.DefaultGateway == "" {
		diffs = append(diffs, fmt.Sprintf("default route via %s is missing", want.DefaultGateway))
	}
	return diffs
}

func sameProxy(a, b Proxy) bool {
	return a.Enabled == b.Enabled && (!a.Enabled || (a.Server == b.Server && a.Port == b.Port))
}

func (p Proxy) String() string {
	if !p.Enabled {
		return "off"
	}
	return fmt.Sprintf("%s:%d", p.Server, p.Port)
}

func orAuto(dns []string) any {
	if len(dns) == 0 {
		return "automatic"
	}
	return dns
}

// Report describes a restore.
type Report struct {
	Actions   []string `json:"actions"`   // what was changed back
	Remaining []string `json:"remaining"` // differences still present afterwards
}

// OK reports whether the network matches the snapshot after restoring.
func (r Report) OK() bool { return len(r.Remaining) == 0 }

// Restore puts every service back the way want recorded it, then checks.
func Restore(ctx context.Context, r Runner, want Snapshot) (Report, error) {
	current, err := Take(ctx, r)
	if err != nil {
		return Report{}, err
	}
	cur := map[string]Service{}
	for _, s := range current.Services {
		cur[s.Name] = s
	}

	var rep Report
	run := func(desc string, args ...string) {
		if _, err := r.Run(ctx, networksetup, args...); err != nil {
			rep.Remaining = append(rep.Remaining, fmt.Sprintf("%s failed: %v", desc, err))
			return
		}
		rep.Actions = append(rep.Actions, desc)
	}

	for _, w := range want.Services {
		c, ok := cur[w.Name]
		if !ok {
			continue
		}
		if !slices.Equal(w.DNS, c.DNS) {
			args := append([]string{"-setdnsservers", w.Name}, w.DNS...)
			if len(w.DNS) == 0 {
				args = append(args, "Empty")
			}
			run(fmt.Sprintf("restored %s DNS to %v", w.Name, orAuto(w.DNS)), args...)
		}
		restoreProxy(w.Name, "web proxy", "-setwebproxy", "-setwebproxystate", w.Web, c.Web, run)
		restoreProxy(w.Name, "secure web proxy", "-setsecurewebproxy", "-setsecurewebproxystate", w.SecureWeb, c.SecureWeb, run)
		restoreProxy(w.Name, "SOCKS proxy", "-setsocksfirewallproxy", "-setsocksfirewallproxystate", w.SOCKS, c.SOCKS, run)
		if !slices.Equal(w.BypassDomains, c.BypassDomains) {
			args := append([]string{"-setproxybypassdomains", w.Name}, w.BypassDomains...)
			if len(w.BypassDomains) == 0 {
				args = append(args, "Empty")
			}
			run(fmt.Sprintf("restored %s proxy bypass list", w.Name), args...)
		}
	}

	if want.DefaultGateway != "" && current.DefaultGateway == "" {
		if _, err := r.Run(ctx, route, "-n", "add", "default", want.DefaultGateway); err != nil {
			rep.Remaining = append(rep.Remaining, fmt.Sprintf("re-adding default route failed: %v", err))
		} else {
			rep.Actions = append(rep.Actions, "re-added default route via "+want.DefaultGateway)
		}
	}

	after, err := Take(ctx, r)
	if err != nil {
		return rep, err
	}
	rep.Remaining = append(rep.Remaining, Diff(want, after)...)
	return rep, nil
}

func restoreProxy(svc, kind, setFlag, stateFlag string, w, c Proxy, run func(string, ...string)) {
	if sameProxy(w, c) {
		return
	}
	if w.Enabled {
		run(fmt.Sprintf("restored %s %s to %s", svc, kind, w), setFlag, svc, w.Server, strconv.Itoa(w.Port))
		return
	}
	run(fmt.Sprintf("turned off %s %s", svc, kind), stateFlag, svc, "off")
}

// SetSystemProxy points every enabled service's HTTP, HTTPS, and SOCKS
// proxy at 127.0.0.1:port, bypassing local and private destinations.
func SetSystemProxy(ctx context.Context, r Runner, port int) error {
	names, err := services(ctx, r)
	if err != nil {
		return err
	}
	p := strconv.Itoa(port)
	bypass := []string{"localhost", "127.0.0.1", "::1", "*.local", "169.254/16", "10/8", "172.16/12", "192.168/16", "100.64/10"}
	for _, n := range names {
		cmds := [][]string{
			{"-setwebproxy", n, "127.0.0.1", p},
			{"-setsecurewebproxy", n, "127.0.0.1", p},
			{"-setsocksfirewallproxy", n, "127.0.0.1", p},
			append([]string{"-setproxybypassdomains", n}, bypass...),
		}
		for _, args := range cmds {
			if _, err := r.Run(ctx, networksetup, args...); err != nil {
				return err
			}
		}
	}
	return nil
}

// Route is one routing-table entry.
type Route struct {
	Dest    string
	Gateway string
	Netif   string
}

// RoutesVia lists routes that go through device, or whose gateway is
// gateway. Matching the gateway too catches routes a TUN core added that
// the kernel attached to another interface sharing its address.
func RoutesVia(ctx context.Context, r Runner, device, gateway string) ([]Route, error) {
	out, err := r.Run(ctx, netstat, "-rn")
	if err != nil {
		return nil, err
	}
	var routes []Route
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		if f[3] == device || (gateway != "" && f[1] == gateway) {
			routes = append(routes, Route{Dest: f[0], Gateway: f[1], Netif: f[3]})
		}
	}
	return routes, nil
}

// RemoveRoutes deletes routes, by gateway when it is an address and by
// interface otherwise.
func RemoveRoutes(ctx context.Context, r Runner, routes []Route) []error {
	var errs []error
	for _, rt := range routes {
		family := "-inet"
		if strings.Contains(rt.Dest, ":") {
			family = "-inet6"
		}
		args := []string{"-n", "delete", family, rt.Dest}
		if net.ParseIP(rt.Gateway) != nil {
			args = append(args, rt.Gateway)
		} else {
			args = append(args, "-interface", rt.Netif)
		}
		if _, err := r.Run(ctx, route, args...); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}
