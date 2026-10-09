// Package netstatetest provides an in-memory macOS network configuration
// for testing code that uses netstate.
package netstatetest

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/nyaaorick/clash-mihomac/internal/netstate"
)

// Fake models networksetup, route, and netstat with mutable state.
type Fake struct {
	mu       sync.Mutex
	Services []string // "*" prefix marks a disabled service
	DNS      map[string][]string
	Proxies  map[string]netstate.Proxy // key: service + "|" + "web" | "secure" | "socks"
	Bypass   map[string][]string
	Gateway  string
	Routes   string // netstat -rn output
	Calls    []string
}

// New returns a Fake with one enabled "Wi-Fi" service using 192.168.1.1
// for DNS and as its default gateway.
func New() *Fake {
	return &Fake{
		Services: []string{"Wi-Fi", "*Thunderbolt Bridge"},
		DNS:      map[string][]string{"Wi-Fi": {"192.168.1.1"}},
		Proxies:  map[string]netstate.Proxy{},
		Bypass:   map[string][]string{},
		Gateway:  "192.168.1.1",
	}
}

// Set changes state under the fake's lock.
func (f *Fake) Set(fn func(f *Fake)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// Run implements netstate.Runner.
func (f *Fake) Run(_ context.Context, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, strings.Join(args, " "))
	switch {
	case strings.HasSuffix(name, "/route") && args[1] == "get":
		if f.Gateway == "" {
			return "", fmt.Errorf("not in table")
		}
		return "   route to: default\n    gateway: " + f.Gateway + "\n  interface: en0\n", nil
	case strings.HasSuffix(name, "/route") && args[1] == "add":
		f.Gateway = args[3]
		return "", nil
	case strings.HasSuffix(name, "/route") && args[1] == "delete":
		return "", nil
	case strings.HasSuffix(name, "netstat"):
		return f.Routes, nil
	}

	svc := ""
	if len(args) > 1 {
		svc = args[1]
	}
	kind := map[string]string{
		"-getwebproxy": "web", "-setwebproxy": "web", "-setwebproxystate": "web",
		"-getsecurewebproxy": "secure", "-setsecurewebproxy": "secure", "-setsecurewebproxystate": "secure",
		"-getsocksfirewallproxy": "socks", "-setsocksfirewallproxy": "socks", "-setsocksfirewallproxystate": "socks",
	}[args[0]]

	switch args[0] {
	case "-listallnetworkservices":
		return "An asterisk (*) denotes that a network service is disabled.\n" + strings.Join(f.Services, "\n") + "\n", nil
	case "-getdnsservers":
		if len(f.DNS[svc]) == 0 {
			return "There aren't any DNS Servers set on " + svc + ".\n", nil
		}
		return strings.Join(f.DNS[svc], "\n") + "\n", nil
	case "-setdnsservers":
		if args[2] == "Empty" {
			f.DNS[svc] = nil
		} else {
			f.DNS[svc] = args[2:]
		}
	case "-getwebproxy", "-getsecurewebproxy", "-getsocksfirewallproxy":
		p := f.Proxies[svc+"|"+kind]
		yes := "No"
		if p.Enabled {
			yes = "Yes"
		}
		return fmt.Sprintf("Enabled: %s\nServer: %s\nPort: %d\nAuthenticated Proxy Enabled: 0\n", yes, p.Server, p.Port), nil
	case "-setwebproxy", "-setsecurewebproxy", "-setsocksfirewallproxy":
		var port int
		fmt.Sscan(args[3], &port)
		f.Proxies[svc+"|"+kind] = netstate.Proxy{Enabled: true, Server: args[2], Port: port}
	case "-setwebproxystate", "-setsecurewebproxystate", "-setsocksfirewallproxystate":
		p := f.Proxies[svc+"|"+kind]
		p.Enabled = args[2] == "on"
		f.Proxies[svc+"|"+kind] = p
	case "-getproxybypassdomains":
		if len(f.Bypass[svc]) == 0 {
			return "There aren't any bypass domains set on " + svc + ".\n", nil
		}
		return strings.Join(f.Bypass[svc], "\n") + "\n", nil
	case "-setproxybypassdomains":
		if args[2] == "Empty" {
			f.Bypass[svc] = nil
		} else {
			f.Bypass[svc] = args[2:]
		}
	default:
		return "", fmt.Errorf("unexpected command %s %v", name, args)
	}
	return "", nil
}
