package daemon

import (
	"strings"
	"testing"

	"github.com/nyaaorick/clash-mihomac/internal/rules"
)

const testPack = `
name: ai-tools
version: 1.0.0
author: tester
description: AI tools
rules:
  - {type: domain-suffix, value: example.ai, target: "@ai"}
  - {type: domain-suffix, value: ads.example.ai, target: REJECT}
`

func TestPreviewPackNeedsMappingThenDiffs(t *testing.T) {
	d := &Daemon{}
	prev, err := d.previewPack([]byte(testPack), "", packPreviewRequest{Enable: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(prev.Placeholders) != 1 || prev.Placeholders[0] != "@ai" || prev.Diff != "" {
		t.Errorf("first preview = %+v", prev)
	}
	prev, err = d.previewPack([]byte(testPack), "https://packs.example/ai.yaml", packPreviewRequest{Map: map[string]string{"ai": "MyNode"}, Enable: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(prev.Placeholders) != 0 || !strings.Contains(prev.Diff, "install pack ai-tools 1.0.0 by tester") || !strings.Contains(prev.Diff, "example.ai → MyNode") {
		t.Errorf("second preview = %+v", prev)
	}
	c := prev.Change
	if len(c.InstallPacks) != 1 || c.InstallPacks[0].Source != "https://packs.example/ai.yaml" || len(c.EnablePacks) != 1 {
		t.Errorf("change = %+v", c)
	}
	if _, err := (rules.Set{}).Apply(c); err != nil {
		t.Errorf("preview's change doesn't apply: %v", err)
	}
	if _, err := d.previewPack([]byte("name: x"), "", packPreviewRequest{}); err == nil {
		t.Error("invalid pack accepted")
	}
}
