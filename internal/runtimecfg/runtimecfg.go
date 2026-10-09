// Package runtimecfg turns a user's mihomo config into the config the
// daemon actually runs.
//
// The user supplies proxies, groups, and rules. Clash Mihomac owns every
// setting that opens a listener or touches the system, so an instance only
// ever listens where its profile says, and TUN is only on in TUN mode with
// the instance's own device name. The privileged helper runs the same
// enforcement again on any config it is asked to start as root.
package runtimecfg

import (
	"fmt"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/nyaaorick/clash-mihomac/internal/rules"
)

// Modes an instance can run in.
const (
	ModePortOnly    = "port-only"    // mixed-port only; nothing on the system changes
	ModeSystemProxy = "system-proxy" // mixed-port plus the macOS system proxy
	ModeTUN         = "tun"          // TUN device capturing all traffic
)

// Modes lists the valid modes.
var Modes = []string{ModeTUN, ModeSystemProxy, ModePortOnly}

// Options are the values Clash Mihomac enforces on every config.
type Options struct {
	MixedPort      int
	ControllerPort int
	Secret         string
	Mode           string // defaults to port-only
	TUNDevice      string // required in TUN mode
	TUNAddress     string // the TUN interface address, e.g. 198.18.253.1/30
	// RouteAddress limits which destinations TUN captures. Empty means
	// everything; tests use it to capture only a few addresses.
	RouteAddress []string
	// Rules are merged ahead of the config's own rules. Nil leaves the
	// config's rules untouched.
	Rules *rules.Compiled
}

// Result is a built runtime config.
type Result struct {
	Config   []byte
	Warnings []string
	// Sources gives the provenance of every rule in the final config, in
	// mihomo's rule order.
	Sources []rules.Source
}

// listenerKeys open listeners other than the managed mixed-port and are
// removed from user configs.
var listenerKeys = []string{
	"port", "socks-port", "redir-port", "tproxy-port",
	"external-controller-tls", "external-controller-unix", "external-controller-pipe",
	"listeners", "tunnels",
}

// Always excluded from TUN: link-local, multicast, and broadcast traffic
// must never be captured.
var tunExclude = []string{"169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "fe80::/10", "ff00::/8"}

var builtinTargets = []string{"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"}

// Build returns the runtime config, with a warning for every user setting
// that was overridden or removed.
func Build(user []byte, o Options) (Result, error) {
	if o.Mode == "" {
		o.Mode = ModePortOnly
	}
	if !slices.Contains(Modes, o.Mode) {
		return Result{}, fmt.Errorf("unknown mode %q", o.Mode)
	}
	if o.Mode == ModeTUN && o.TUNDevice == "" {
		return Result{}, fmt.Errorf("TUN mode needs a TUN device")
	}

	cfg := map[string]any{}
	if err := yaml.Unmarshal(user, &cfg); err != nil {
		return Result{}, fmt.Errorf("parse config: %w", err)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}

	var warnings []string
	warn := func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) }

	for _, k := range listenerKeys {
		if _, ok := cfg[k]; ok {
			delete(cfg, k)
			warn("ignored %q: Clash Mihomac only exposes the managed mixed-port", k)
		}
	}

	cfg["mixed-port"] = o.MixedPort
	cfg["allow-lan"] = false
	cfg["bind-address"] = "127.0.0.1"
	cfg["external-controller"] = fmt.Sprintf("127.0.0.1:%d", o.ControllerPort)
	cfg["secret"] = o.Secret
	if _, ok := cfg["find-process-mode"]; !ok {
		cfg["find-process-mode"] = "always" // needed for per-app rules and diagnostics
	}
	if _, ok := cfg["sniffer"]; !ok {
		// Recover domains for connections that arrive by IP, so domain rules
		// still match when DNS bypasses the core (e.g. a LAN resolver).
		cfg["sniffer"] = map[string]any{
			"enable": true,
			"sniff": map[string]any{
				"HTTP": map[string]any{"ports": []any{80, "8080-8880"}},
				"TLS":  map[string]any{"ports": []any{443, 8443}},
				"QUIC": map[string]any{"ports": []any{443, 8443}},
			},
		}
	}

	tun, _ := cfg["tun"].(map[string]any)
	if tun == nil {
		tun = map[string]any{}
	}
	dns, _ := cfg["dns"].(map[string]any)
	if dns != nil {
		if _, has := dns["listen"]; has {
			delete(dns, "listen")
			warn(`ignored "dns.listen": the DNS server is reached through TUN, never exposed`)
		}
	}

	if o.Mode == ModeTUN {
		if d, ok := tun["device"]; ok && d != o.TUNDevice {
			warn("TUN device %v replaced with this instance's %s", d, o.TUNDevice)
		}
		tun["enable"] = true
		tun["device"] = o.TUNDevice
		if o.TUNAddress != "" {
			tun["inet4-address"] = []any{o.TUNAddress}
		}
		if _, ok := tun["stack"]; !ok {
			tun["stack"] = "mixed"
		}
		tun["auto-route"] = true
		tun["auto-detect-interface"] = true
		tun["strict-route"] = false // coexist with VPN clients' routes
		tun["dns-hijack"] = []any{"any:53", "tcp://any:53"}
		tun["route-exclude-address"] = mergeStrings(tun["route-exclude-address"], tunExclude)
		if len(o.RouteAddress) > 0 {
			tun["route-address"] = toAny(o.RouteAddress)
		}
		if dns == nil {
			dns = map[string]any{}
		}
		dns["enable"] = true
		if _, ok := dns["enhanced-mode"]; !ok {
			dns["enhanced-mode"] = "redir-host" // real IPs: nothing breaks if DNS bypasses the core
		}
		if _, ok := dns["nameserver"]; !ok {
			dns["nameserver"] = []any{"system"}
		}
	} else {
		if tun["enable"] == true {
			warn("TUN disabled: this instance is running in %s mode", o.Mode)
		}
		tun["enable"] = false
	}
	cfg["tun"] = tun

	configRules, _ := cfg["rules"].([]any)
	var sources []rules.Source
	if o.Rules != nil {
		if err := checkTargets(cfg, o.Rules); err != nil {
			return Result{}, err
		}
		cfg["rules"] = append(toAny(o.Rules.Rules), configRules...)
		sources = append(sources, o.Rules.Sources...)

		proxies, _ := cfg["proxies"].([]any)
		for _, p := range o.Rules.Proxies {
			proxies = append(proxies, p)
		}
		cfg["proxies"] = proxies

		if len(o.Rules.NameserverPolicy) > 0 {
			if dns == nil {
				dns = map[string]any{"enable": true, "nameserver": []any{"system"}}
			}
			policy, _ := dns["nameserver-policy"].(map[string]any)
			if policy == nil {
				policy = map[string]any{}
			}
			for k, v := range o.Rules.NameserverPolicy {
				policy[k] = v
			}
			dns["nameserver-policy"] = policy
		}
	}
	if dns != nil {
		cfg["dns"] = dns
	}
	for i := range configRules {
		sources = append(sources, rules.Source{Kind: "config", Index: i + 1})
	}

	out, err := yaml.Marshal(cfg)
	if err != nil {
		return Result{}, err
	}
	return Result{Config: out, Warnings: warnings, Sources: sources}, nil
}

// checkTargets makes sure every compiled rule points at something that exists.
func checkTargets(cfg map[string]any, c *rules.Compiled) error {
	known := map[string]bool{}
	for _, t := range builtinTargets {
		known[t] = true
	}
	for _, key := range []string{"proxies", "proxy-groups"} {
		items, _ := cfg[key].([]any)
		for _, it := range items {
			if m, ok := it.(map[string]any); ok {
				if name, ok := m["name"].(string); ok {
					known[name] = true
				}
			}
		}
	}
	for _, p := range c.Proxies {
		known[p["name"].(string)] = true
	}
	for _, line := range c.Rules {
		parts := strings.Split(line, ",")
		if len(parts) < 3 || !known[parts[2]] {
			return fmt.Errorf("rule %q targets %q, which is not a proxy or group in your config", line, parts[min(2, len(parts)-1)])
		}
	}
	return nil
}

func mergeStrings(existing any, add []string) []any {
	var out []any
	seen := map[string]bool{}
	if list, ok := existing.([]any); ok {
		for _, v := range list {
			if s, ok := v.(string); ok && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	for _, s := range add {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
