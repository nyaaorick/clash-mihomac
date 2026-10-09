package rules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const goodPack = `
name: dev-direct
version: 1.2.0
author: someone
description: Developer mirrors that should skip the proxy
rules:
  - type: domain-suffix
    value: mirrors.example.com
    target: DIRECT
    note: package mirror
  - type: domain-suffix
    value: ads.example.net
    target: REJECT
  - type: domain-suffix
    value: chat.example.org
    target: "@ai"
`

func TestParsePackAndResolve(t *testing.T) {
	p, err := ParsePack([]byte(goodPack))
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "dev-direct" || len(p.Rules) != 3 {
		t.Fatalf("pack = %+v", p)
	}
	if got := p.Placeholders(); len(got) != 1 || got[0] != "@ai" {
		t.Errorf("placeholders = %v", got)
	}
	if _, err := p.Resolve(nil); err == nil || !strings.Contains(err.Error(), "@ai") {
		t.Errorf("unresolved placeholder accepted: %v", err)
	}
	if _, err := p.Resolve(map[string]string{"ai": "bad,target"}); err == nil {
		t.Error("target with a comma accepted")
	}
	r, err := p.Resolve(map[string]string{"ai": "MyNode"})
	if err != nil || r.Rules[2].Target != "MyNode" || p.Rules[2].Target != "@ai" {
		t.Errorf("Resolve = %+v, %v (original %+v)", r, err, p.Rules[2])
	}
}

func TestParsePackRejectsHostileInput(t *testing.T) {
	long := strings.Repeat("a", 41)
	cases := map[string]string{
		"unknown field":      goodPack + "extra: 1\n",
		"two documents":      goodPack + "---\nname: other\n",
		"node target":        strings.Replace(goodPack, "target: DIRECT", "target: MyNode", 1),
		"iface target":       strings.Replace(goodPack, "target: DIRECT", "target: iface:en0", 1),
		"bad name":           strings.Replace(goodPack, "dev-direct", "Dev Direct", 1),
		"long name":          strings.Replace(goodPack, "dev-direct", long, 1),
		"builtin name":       strings.Replace(goodPack, "dev-direct", "bilibili", 1),
		"no version":         strings.Replace(goodPack, "version: 1.2.0\n", "", 1),
		"bad version":        strings.Replace(goodPack, "1.2.0", "v1", 1),
		"newline in author":  strings.Replace(goodPack, "author: someone", "author: \"a\\nb\"", 1),
		"comma in value":     strings.Replace(goodPack, "mirrors.example.com", "a.com,DIRECT", 1),
		"no rules":           "name: x\nversion: 1.0.0\nrules: []\n",
		"source in file":     goodPack + "source: https://evil.example\n",
		"unknown rule type":  strings.Replace(goodPack, "type: domain-suffix", "type: script", 1),
		"placeholder syntax": strings.Replace(goodPack, "@ai", "@AI", 1),
	}
	for name, body := range cases {
		if _, err := ParsePack([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	big := "name: big\nversion: 1.0.0\nrules:\n" + strings.Repeat("  - {type: domain, value: a.com, target: DIRECT}\n", MaxPackRules+1)
	if _, err := ParsePack([]byte(big)); err == nil {
		t.Error("oversized rule list accepted")
	}
	if _, err := ParsePack([]byte(strings.Repeat("#", MaxPackBytes+1))); err == nil {
		t.Error("oversized file accepted")
	}
}

func installed(t *testing.T) (Set, Pack) {
	t.Helper()
	p, err := ParsePack([]byte(goodPack))
	if err != nil {
		t.Fatal(err)
	}
	p, err = p.Resolve(map[string]string{"ai": "DIRECT"})
	if err != nil {
		t.Fatal(err)
	}
	return Set{}, p
}

func TestInstallEnableCompileRemove(t *testing.T) {
	s, p := installed(t)
	next, err := s.Apply(Change{InstallPacks: []Pack{p}, EnablePacks: []string{"dev-direct"}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := Compile(next)
	if err != nil {
		t.Fatal(err)
	}
	last := c.Sources[len(c.Sources)-1]
	if last.Kind != "pack" || last.Name != "dev-direct" || c.Rules[len(c.Rules)-3] != "DOMAIN-SUFFIX,mirrors.example.com,DIRECT" {
		t.Errorf("compiled = %v / %+v", c.Rules[len(c.Rules)-3:], last)
	}
	if len(s.Library) != 0 {
		t.Error("Apply modified the original set")
	}
	gone, err := next.Apply(Change{RemovePacks: []string{"dev-direct"}})
	if err != nil || len(gone.Library) != 0 || len(gone.Packs) != 0 {
		t.Errorf("after remove: %+v, %v", gone, err)
	}
	if _, err := next.Apply(Change{RemovePacks: []string{"bilibili"}}); err == nil {
		t.Error("removing a built-in pack should fail")
	}
	if _, err := s.Apply(Change{EnablePacks: []string{"dev-direct"}}); err == nil {
		t.Error("enabling an uninstalled pack should fail")
	}
}

func TestUpdateDiffAndConflicts(t *testing.T) {
	s, p := installed(t)
	s.Rules = []Rule{{Type: TypeDomainSuffix, Value: "mirrors.example.com", Target: "MyNode"}}
	diff, err := s.Diff(Change{InstallPacks: []Pack{p}, EnablePacks: []string{p.Name}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"+ install pack dev-direct 1.2.0 by someone (3 rules)", "domain-suffix ads.example.net → REJECT", "! dev-direct: domain-suffix mirrors.example.com → DIRECT is overridden by your rule (→ MyNode)"} {
		if !strings.Contains(diff, want) {
			t.Errorf("diff missing %q:\n%s", want, diff)
		}
	}

	s2, err := s.Apply(Change{InstallPacks: []Pack{p}})
	if err != nil {
		t.Fatal(err)
	}
	v2 := p
	v2.Version = "1.3.0"
	v2.Rules = append(v2.Rules[:1:1], Rule{Type: TypeDomain, Value: "new.example.com", Target: "DIRECT"})
	diff, _ = s2.Diff(Change{InstallPacks: []Pack{v2}})
	if !strings.Contains(diff, "~ update pack dev-direct 1.2.0 → 1.3.0 by someone (+1 −2 rules)") {
		t.Errorf("update diff:\n%s", diff)
	}
	big := p
	for i := 0; i < 100; i++ {
		big.Rules = append(big.Rules, Rule{Type: TypeDomain, Value: "h.example.com", Target: "DIRECT"})
	}
	diff, _ = s.Diff(Change{InstallPacks: []Pack{big}})
	if !strings.Contains(diff, "… and 78 more rules") {
		t.Errorf("long pack diff not capped:\n%s", diff)
	}
}

func TestLibraryValidation(t *testing.T) {
	_, p := installed(t)
	if err := (Set{Library: []Pack{p, p}}).Validate(); err == nil {
		t.Error("duplicate installed pack accepted")
	}
	bad := p
	bad.Rules = []Rule{{Type: TypeDomain, Value: "a.com", Target: "x\ny"}}
	if err := (Set{Library: []Pack{bad}}).Validate(); err == nil {
		t.Error("invalid installed rule accepted")
	}
}

func TestFetcher(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			w.Write([]byte(strings.Repeat("x", MaxPackBytes+10)))
		case "/missing":
			http.NotFound(w, r)
		default:
			w.Write([]byte(goodPack))
		}
	}))
	defer srv.Close()
	f := Fetcher{Client: srv.Client()}
	ctx := context.Background()
	if data, err := f.Fetch(ctx, srv.URL+"/pack.yaml"); err != nil || !strings.Contains(string(data), "dev-direct") {
		t.Errorf("Fetch = %q, %v", data, err)
	}
	if _, err := f.Fetch(ctx, srv.URL+"/big"); err == nil {
		t.Error("oversized download accepted")
	}
	if _, err := f.Fetch(ctx, srv.URL+"/missing"); err == nil {
		t.Error("404 accepted")
	}
	for _, u := range []string{"http://example.com/p.yaml", "file:///etc/passwd", "https://user:pw@example.com/p", "ftp://x"} {
		if _, err := f.Fetch(ctx, u); err == nil {
			t.Errorf("Fetch(%q) accepted", u)
		}
	}
	// The default fetcher must refuse loopback even over HTTPS.
	if _, err := NewFetcher().Fetch(ctx, srv.URL+"/pack.yaml"); err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Errorf("default fetcher reached loopback: %v", err)
	}
}
