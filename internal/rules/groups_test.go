package rules

import (
	"strings"
	"testing"
)

func goodGroup() Group {
	return Group{Name: "Auto", Type: GroupURLTest, Members: []string{"hk", "jp"}, Interval: 60, Tolerance: 50}
}

func TestGroupValidation(t *testing.T) {
	if err := goodGroup().Validate(); err != nil {
		t.Fatal(err)
	}
	mut := func(f func(*Group)) Group { g := goodGroup(); f(&g); return g }
	bad := map[string]Group{
		"empty name":       mut(func(g *Group) { g.Name = "" }),
		"reserved name":    mut(func(g *Group) { g.Name = "direct" }),
		"iface name":       mut(func(g *Group) { g.Name = "iface:en0" }),
		"comma in name":    mut(func(g *Group) { g.Name = "a,b" }),
		"unknown type":     mut(func(g *Group) { g.Type = "select" }),
		"one member":       mut(func(g *Group) { g.Members = []string{"hk"} }),
		"dup member":       mut(func(g *Group) { g.Members = []string{"hk", "hk"} }),
		"self member":      mut(func(g *Group) { g.Members = []string{"hk", "Auto"} }),
		"comma member":     mut(func(g *Group) { g.Members = []string{"hk", "a,b"} }),
		"file url":         mut(func(g *Group) { g.URL = "file:///etc/passwd" }),
		"url creds":        mut(func(g *Group) { g.URL = "https://u:p@x.example/" }),
		"fast interval":    mut(func(g *Group) { g.Interval = 1 }),
		"tiny timeout":     mut(func(g *Group) { g.Timeout = 10 }),
		"tolerance on fb":  mut(func(g *Group) { g.Type = GroupFallback }),
		"strategy on test": mut(func(g *Group) { g.Strategy = "round-robin" }),
		"bad strategy":     mut(func(g *Group) { g.Type, g.Tolerance, g.Strategy = GroupLoadBalance, 0, "random" }),
		"max failed":       mut(func(g *Group) { g.MaxFailed = 99 }),
	}
	for name, g := range bad {
		if err := g.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := (Set{Groups: []Group{goodGroup(), goodGroup()}}).Validate(); err == nil {
		t.Error("duplicate group names accepted")
	}
	outer := Group{Name: "Outer", Type: GroupFallback, Members: []string{"Auto", "us"}}
	if err := (Set{Groups: []Group{goodGroup(), outer}}).Validate(); err == nil {
		t.Error("nested groups accepted")
	}
}

func TestGroupCompile(t *testing.T) {
	lb := Group{Name: "LB", Type: GroupLoadBalance, Members: []string{"a", "b"}, MaxFailed: 3, Timeout: 2000}
	c, err := Compile(Set{Groups: []Group{goodGroup(), lb}, Rules: []Rule{{Type: TypeDomainSuffix, Value: "x.com", Target: "Auto"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Groups) != 2 {
		t.Fatalf("groups = %v", c.Groups)
	}
	g := c.Groups[0]
	if g["type"] != "url-test" || g["tolerance"] != 50 || g["interval"] != 60 || g["url"] != DefaultGroupURL || g["lazy"] != false {
		t.Errorf("url-test group = %v", g)
	}
	l := c.Groups[1]
	if l["strategy"] != "consistent-hashing" || l["max-failed-times"] != 3 || l["timeout"] != 2000 || l["interval"] != DefaultGroupInterval {
		t.Errorf("load-balance group = %v", l)
	}
	if _, has := l["tolerance"]; has {
		t.Error("tolerance leaked into a load-balance group")
	}
}

func TestGroupChangeAndDiff(t *testing.T) {
	s := Set{}
	c := Change{SetGroups: []Group{goodGroup()}}
	next, err := s.Apply(c)
	if err != nil || len(next.Groups) != 1 || len(s.Groups) != 0 {
		t.Fatalf("Apply = %+v, %v", next, err)
	}
	diff, _ := s.Diff(c)
	if !strings.Contains(diff, "+ add group Auto (url-test of hk, jp; check every 60 s, switch when 50 ms faster)") {
		t.Errorf("diff = %q", diff)
	}
	changed := goodGroup()
	changed.Tolerance = 100
	diff, _ = next.Diff(Change{SetGroups: []Group{changed}})
	if !strings.Contains(diff, "~ change group Auto") {
		t.Errorf("diff = %q", diff)
	}
	gone, err := next.Apply(Change{RemoveGroups: []string{"Auto"}})
	if err != nil || len(gone.Groups) != 0 {
		t.Errorf("remove = %+v, %v", gone, err)
	}
	if _, err := next.Apply(Change{RemoveGroups: []string{"nope"}}); err == nil {
		t.Error("removing a missing group should fail")
	}
}
