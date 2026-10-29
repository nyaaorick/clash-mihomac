package main

import (
	"strings"
	"testing"

	"github.com/nyaaorick/clash-mihomac/internal/daemon"
)

func rowTitles(c islandContent) []string {
	var t []string
	for _, r := range c.Rows {
		t = append(t, r.Title)
	}
	return t
}

func TestIslandShowsWhyTheDaemonIsntUp(t *testing.T) {
	c := renderIsland(islandView{DaemonErr: "Clash Verge isn't installed: no app"})
	if c.Compact == nil || c.Compact.State != "failed" {
		t.Fatalf("compact: %+v", c.Compact)
	}
	if len(c.Buttons) != 1 || c.Buttons[0].ID != "install" {
		t.Fatalf("an install button, got %+v", c.Buttons)
	}
	c = renderIsland(islandView{DaemonErr: "another Clash Mihomac holds port 9991"})
	if len(c.Buttons) != 0 || !strings.Contains(c.Rows[0].Subtitle, "port 9991") {
		t.Fatalf("rows %+v buttons %+v", c.Rows, c.Buttons)
	}
}

func TestIslandShowsTheCoreModeRulesAndNodes(t *testing.T) {
	st := &daemon.Status{
		Verge:    daemon.VergeStatus{MihomoVersion: "1.19.32", Controller: "unix:/tmp/x.sock", Mode: "rule", TUN: true, TUNDevice: "utun1024"},
		HasRules: true, RulesActive: true, Rules: map[string]int{"rule": 3, "pack": 1},
	}
	nodes := []daemon.Node{
		{Name: "Proxy", Type: "Selector", Now: "HK", Members: []string{"HK", "SG"}},
		{Name: "HK", Type: "vless", Alive: true, DelayMs: 42, Health: "healthy"},
		{Name: "SG", Type: "vless", Alive: false, Health: "blocked"},
		{Name: "DIRECT", Type: "Direct", Alive: true},
	}
	c := renderIsland(islandView{Status: st, Nodes: nodes})
	if c.Compact.Text != "Rule · TUN" || c.Compact.State != "" {
		t.Fatalf("compact %+v", c.Compact)
	}
	titles := rowTitles(c)
	for _, want := range []string{"Clash Verge", "Core", "Rule mode", "Global", "Direct", "Rules", "Nodes", "Proxy", "HK", "SG"} {
		found := false
		for _, have := range titles {
			if have == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing row %q in %v", want, titles)
		}
	}
	for _, have := range titles {
		if have == "DIRECT" {
			t.Fatal("built-in outbounds aren't nodes")
		}
	}
	var ruleToggle, sg wireRow
	for _, r := range c.Rows {
		switch r.Title {
		case "Rule mode":
			ruleToggle = r
		case "SG":
			sg = r
		}
	}
	if ruleToggle.Toggle == nil || !*ruleToggle.Toggle || ruleToggle.ID != "mode:rule" {
		t.Fatalf("the current mode's switch is on: %+v", ruleToggle)
	}
	if sg.State != "failed" {
		t.Fatalf("a blocked node is drawn failed: %+v", sg)
	}
	if len(c.Buttons) != 3 || c.Buttons[2].Confirm == "" {
		t.Fatalf("buttons %+v", c.Buttons)
	}
}

func TestIslandAsksToLoadRulesAndToReturnToRuleMode(t *testing.T) {
	st := &daemon.Status{Verge: daemon.VergeStatus{MihomoVersion: "1", Mode: "global"}, HasRules: true, RulesActive: false}
	c := renderIsland(islandView{Status: st})
	if c.Compact.State != "attention" {
		t.Fatalf("rules not loaded needs attention: %+v", c.Compact)
	}
	var rules wireRow
	for _, r := range c.Rows {
		if r.Title == "Rules" {
			rules = r
		}
	}
	if rules.ID != "apply" || rules.State != "attention" {
		t.Fatalf("rules row %+v", rules)
	}
	if !strings.Contains(strings.Join(rowTitles(c), "|"), "Rules route nothing in Global mode") {
		t.Fatalf("no mode warning in %v", rowTitles(c))
	}
	// Verge not running: the core row opens it
	st = &daemon.Status{Verge: daemon.VergeStatus{Mode: "rule"}}
	c = renderIsland(islandView{Status: st})
	if c.Compact.Text != "Off" || c.Rows[1].ID != "open-verge" {
		t.Fatalf("%+v %+v", c.Compact, c.Rows[1])
	}
}
