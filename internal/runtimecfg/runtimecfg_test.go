package runtimecfg

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/nyaaorick/clash-mihomac/internal/rules"
)

var opts = Options{MixedPort: 17990, ControllerPort: 19990, Secret: "s3cret", TUNDevice: "utun1991", TUNAddress: "198.18.253.1/30"}

func build(t *testing.T, user string, o Options) (map[string]any, Result) {
	t.Helper()
	res, err := Build([]byte(user), o)
	if err != nil {
		t.Fatal(err)
	}
	cfg := map[string]any{}
	if err := yaml.Unmarshal(res.Config, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg, res
}

func TestEnforcedSettings(t *testing.T) {
	cfg, _ := build(t, `
mixed-port: 7890
allow-lan: true
bind-address: "*"
external-controller: 0.0.0.0:9090
secret: user
rules:
  - MATCH,DIRECT
`, opts)
	want := map[string]any{
		"mixed-port":          17990,
		"allow-lan":           false,
		"bind-address":        "127.0.0.1",
		"external-controller": "127.0.0.1:19990",
		"secret":              "s3cret",
		"find-process-mode":   "always",
	}
	for k, v := range want {
		if cfg[k] != v {
			t.Errorf("%s = %v, want %v", k, cfg[k], v)
		}
	}
	if rules, _ := cfg["rules"].([]any); len(rules) != 1 {
		t.Errorf("user rules not preserved: %v", cfg["rules"])
	}
}

func TestTUNForcedOffOutsideTUNMode(t *testing.T) {
	for _, mode := range []string{ModePortOnly, ModeSystemProxy} {
		o := opts
		o.Mode = mode
		cfg, res := build(t, "tun:\n  enable: true\n  stack: system\n", o)
		tun := cfg["tun"].(map[string]any)
		if tun["enable"] != false || tun["stack"] != "system" {
			t.Errorf("%s: tun = %v", mode, tun)
		}
		if len(res.Warnings) != 1 {
			t.Errorf("%s: warnings = %v, want one TUN warning", mode, res.Warnings)
		}
	}
}

func TestTUNMode(t *testing.T) {
	o := opts
	o.Mode = ModeTUN
	o.RouteAddress = []string{"1.1.1.1/32"}
	cfg, res := build(t, `
tun:
  device: utun9
  strict-route: true
  route-exclude-address: [10.99.0.0/16]
dns:
  enable: false
  listen: 0.0.0.0:53
`, o)
	tun := cfg["tun"].(map[string]any)
	checks := map[string]any{"enable": true, "device": "utun1991", "auto-route": true, "strict-route": false, "stack": "mixed", "auto-detect-interface": true}
	for k, v := range checks {
		if tun[k] != v {
			t.Errorf("tun.%s = %v, want %v", k, tun[k], v)
		}
	}
	if a, _ := tun["inet4-address"].([]any); len(a) != 1 || a[0] != "198.18.253.1/30" {
		t.Errorf("inet4-address = %v", tun["inet4-address"])
	}
	excl := tun["route-exclude-address"].([]any)
	if excl[0] != "10.99.0.0/16" || len(excl) != 1+len(tunExclude) {
		t.Errorf("route-exclude-address = %v", excl)
	}
	if ra := tun["route-address"].([]any); len(ra) != 1 || ra[0] != "1.1.1.1/32" {
		t.Errorf("route-address = %v", ra)
	}
	dns := cfg["dns"].(map[string]any)
	if dns["enable"] != true || dns["enhanced-mode"] != "redir-host" || dns["listen"] != nil {
		t.Errorf("dns = %v", dns)
	}
	if len(res.Warnings) != 2 {
		t.Errorf("warnings = %v, want device + dns.listen", res.Warnings)
	}

	o.TUNDevice = ""
	if _, err := Build(nil, o); err == nil {
		t.Error("TUN mode without a device should fail")
	}
}

func TestExtraListenersRemoved(t *testing.T) {
	cfg, res := build(t, `
port: 7890
socks-port: 7891
listeners:
  - name: extra
    type: socks
    port: 10000
dns:
  enable: true
  listen: 0.0.0.0:53
`, opts)
	for _, k := range []string{"port", "socks-port", "listeners"} {
		if _, ok := cfg[k]; ok {
			t.Errorf("%s not removed", k)
		}
	}
	dns := cfg["dns"].(map[string]any)
	if _, ok := dns["listen"]; ok || dns["enable"] != true {
		t.Errorf("dns = %v", dns)
	}
	if len(res.Warnings) != 4 {
		t.Errorf("warnings = %v, want 4", res.Warnings)
	}
}

func TestRulesMergedWithProvenance(t *testing.T) {
	compiled, err := rules.Compile(rules.Set{
		Rules:       []rules.Rule{{Type: rules.TypeDomainSuffix, Value: "corp.example.com", Target: "iface:en1"}, {Type: rules.TypeDomain, Value: "x.com", Target: "Proxy"}},
		InternalDNS: []rules.InternalDNS{{Domains: []string{"corp.example.com"}, Servers: []string{"10.0.0.53"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	o := opts
	o.Rules = &compiled
	cfg, res := build(t, `
proxies:
  - {name: Proxy, type: socks5, server: 127.0.0.1, port: 1080}
rules:
  - MATCH,Proxy
`, o)
	got := cfg["rules"].([]any)
	if got[0] != "DOMAIN-SUFFIX,corp.example.com,iface:en1" || got[len(got)-1] != "MATCH,Proxy" {
		t.Errorf("rules = %v", got)
	}
	if len(res.Sources) != len(got) || res.Sources[len(got)-1].Kind != "config" {
		t.Errorf("sources = %d for %d rules", len(res.Sources), len(got))
	}
	if n := len(cfg["proxies"].([]any)); n != 2 {
		t.Errorf("proxies = %d, want user proxy + iface:en1", n)
	}
	policy := cfg["dns"].(map[string]any)["nameserver-policy"].(map[string]any)
	if _, ok := policy["+.corp.example.com"]; !ok {
		t.Errorf("nameserver-policy = %v", policy)
	}

	if _, err := Build([]byte("rules: [MATCH,DIRECT]"), o); err == nil || !strings.Contains(err.Error(), `"Proxy"`) {
		t.Errorf("missing target: err = %v", err)
	}
}

func TestEmptyAndInvalidConfig(t *testing.T) {
	if _, err := Build(nil, opts); err != nil {
		t.Errorf("empty config: %v", err)
	}
	if _, err := Build([]byte("rules: [unclosed"), opts); err == nil {
		t.Error("expected parse error")
	}
	o := opts
	o.Mode = "bogus"
	if _, err := Build(nil, o); err == nil {
		t.Error("expected unknown mode error")
	}
}
