package rules

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileOrderAndProvenance(t *testing.T) {
	s := Set{
		Packs: []string{"bilibili"},
		Rules: []Rule{
			{Type: TypeIPCIDR, Value: "10.20.0.0/16", Target: "iface:en1", Note: "intranet"},
			{Type: TypeApp, Value: "/Applications/Safari.app", Target: "Proxy"},
		},
	}
	c, err := Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	if c.Rules[0] != "IP-CIDR,10.20.0.0/16,iface:en1,no-resolve" {
		t.Errorf("rule 0 = %q", c.Rules[0])
	}
	if c.Rules[1] != `PROCESS-PATH-REGEX,^/Applications/Safari\.app/,Proxy` {
		t.Errorf("rule 1 = %q", c.Rules[1])
	}
	if c.Sources[0].Kind != "user" || c.Sources[0].Note != "intranet" {
		t.Errorf("source 0 = %+v", c.Sources[0])
	}
	if c.Sources[2].Kind != "bypass" {
		t.Errorf("bypass must follow user rules, got %+v", c.Sources[2])
	}
	last := c.Sources[len(c.Sources)-1]
	if last.Kind != "pack" || last.Name != "bilibili" {
		t.Errorf("last source = %+v, want bilibili pack", last)
	}
	if len(c.Rules) != len(c.Sources) {
		t.Errorf("%d rules but %d sources", len(c.Rules), len(c.Sources))
	}
	if len(c.Proxies) != 1 || c.Proxies[0]["interface-name"] != "en1" || c.Proxies[0]["type"] != "direct" {
		t.Errorf("proxies = %v", c.Proxies)
	}
	if len(c.NameserverPolicy) != 0 {
		t.Errorf("CIDR and app rules must not add DNS policy: %v", c.NameserverPolicy)
	}
}

func TestInterfaceDomainsResolvedOnThatInterface(t *testing.T) {
	c, err := Compile(Set{
		Rules: []Rule{
			{Type: TypeDomainSuffix, Value: "corp.example.com", Target: "iface:en1"},
			{Type: TypeDomain, Value: "wiki.example.com", Target: "iface:en1"},
			{Type: TypeDomainSuffix, Value: "vpn.example.com", Target: "iface:en1"},
		},
		InternalDNS: []InternalDNS{{Domains: []string{"vpn.example.com"}, Servers: []string{"10.0.0.53"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"+.corp.example.com": "dhcp://en1", "wiki.example.com": "dhcp://en1", "+.vpn.example.com": "10.0.0.53"}
	for k, v := range want {
		got, _ := c.NameserverPolicy[k].([]string)
		if len(got) != 1 || got[0] != v {
			t.Errorf("policy[%s] = %v, want [%s]", k, c.NameserverPolicy[k], v)
		}
	}
}

func TestIPv6AndInternalDNS(t *testing.T) {
	c, err := Compile(Set{
		Rules:       []Rule{{Type: TypeIPCIDR, Value: "fd00::/8", Target: "DIRECT"}},
		InternalDNS: []InternalDNS{{Domains: []string{"corp.example.com"}, Servers: []string{"10.0.0.53"}, Interface: "en1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Rules[0] != "IP-CIDR6,fd00::/8,DIRECT,no-resolve" {
		t.Errorf("rule = %q", c.Rules[0])
	}
	got := c.NameserverPolicy["+.corp.example.com"].([]string)
	if len(got) != 1 || got[0] != "10.0.0.53#en1" {
		t.Errorf("nameserver-policy = %v", c.NameserverPolicy)
	}
}

func TestValidateRejectsUnsafeValues(t *testing.T) {
	bad := []Rule{
		{Type: TypeDomain, Value: "a.com,DIRECT\nMATCH", Target: "DIRECT"},
		{Type: TypeDomain, Value: "example.com", Target: "Proxy,no-resolve"},
		{Type: TypeIPCIDR, Value: "10.0.0.0/33", Target: "DIRECT"},
		{Type: TypeProcessPath, Value: "relative/bin", Target: "DIRECT"},
		{Type: TypeApp, Value: "/usr/bin/curl", Target: "DIRECT"},
		{Type: TypeDomain, Value: "example.com", Target: "iface:../../x"},
		{Type: "script", Value: "x", Target: "DIRECT"},
	}
	for _, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("accepted %+v", r)
		}
	}
	if err := (Set{Packs: []string{"nope"}}).Validate(); err == nil {
		t.Error("accepted unknown pack")
	}
	if err := (Set{InternalDNS: []InternalDNS{{Domains: []string{"corp"}, Servers: []string{"dns.corp"}}}}).Validate(); err == nil {
		t.Error("accepted non-IP DNS server")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if s, err := Load(path); err != nil || len(s.Rules) != 0 {
		t.Fatalf("missing file: %+v, %v", s, err)
	}
	want := Set{Packs: []string{"taobao"}, Rules: []Rule{{Type: TypeProcessName, Value: "WeChat", Target: "DIRECT", Note: "chat"}}}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || len(got.Rules) != 1 || got.Rules[0] != want.Rules[0] || got.Packs[0] != "taobao" {
		t.Errorf("round trip = %+v, %v", got, err)
	}
}

func TestApplyAndDiff(t *testing.T) {
	s := Set{Rules: []Rule{{Type: TypeDomainSuffix, Value: "old.com", Target: "DIRECT"}}}
	c := Change{
		Add:         []Rule{{Type: TypeDomainSuffix, Value: "new.com", Target: "Proxy"}},
		Remove:      []Rule{{Type: TypeDomainSuffix, Value: "old.com", Target: "DIRECT"}},
		EnablePacks: []string{"bilibili"},
	}
	next, err := s.Apply(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Rules) != 1 || next.Rules[0].Value != "new.com" || len(next.Packs) != 1 {
		t.Errorf("applied = %+v", next)
	}
	if len(s.Rules) != 1 || s.Rules[0].Value != "old.com" {
		t.Error("Apply modified the original set")
	}
	diff, err := s.Diff(c)
	if err != nil || !strings.Contains(diff, "+ domain-suffix new.com → Proxy") || !strings.Contains(diff, "- domain-suffix old.com") || !strings.Contains(diff, "+ pack bilibili") {
		t.Errorf("diff = %q, %v", diff, err)
	}

	if _, err := s.Apply(Change{Remove: []Rule{{Type: TypeDomain, Value: "missing.com", Target: "DIRECT"}}}); err == nil {
		t.Error("removing a missing rule should fail")
	}
}
