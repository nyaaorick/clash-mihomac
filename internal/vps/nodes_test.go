package vps

import (
	"path/filepath"
	"testing"
	"time"
)

func imp(machine, name, server string) Imported {
	return Imported{Node: Node{Name: name, Type: "trojan", Server: server, Port: 443, Proxy: map[string]any{"name": name, "type": "trojan", "server": server, "port": 443}}, Machine: machine, Added: time.Unix(1, 0)}
}

func TestNodeStoreRoundTripAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.yaml")
	if got, err := LoadNodes(path); err != nil || got != nil {
		t.Fatalf("missing file = %v, %v", got, err)
	}
	in := []Imported{imp("m1", "tokyo", "203.0.113.5")}
	if err := SaveNodes(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := LoadNodes(path)
	if err != nil || len(out) != 1 || out[0].Name != "tokyo" || out[0].Machine != "m1" || out[0].Proxy["server"] != "203.0.113.5" {
		t.Errorf("round trip = %+v, %v", out, err)
	}
}

func TestMergeNodes(t *testing.T) {
	list := []Imported{imp("m1", "tokyo", "old")}
	merged, err := MergeNodes(list, []Imported{imp("m1", "tokyo", "new")}, nil)
	if err != nil || len(merged) != 1 || merged[0].Server != "new" || merged[0].Proxy["server"] != "new" || !merged[0].Added.Equal(time.Unix(1, 0)) {
		t.Errorf("re-import from the same machine should replace: %+v %v", merged, err)
	}
	merged, _ = MergeNodes(list, []Imported{imp("", "tokyo", "other")}, map[string]bool{"tokyo-2": true})
	if len(merged) != 2 || merged[1].Name != "tokyo-3" || merged[1].Proxy["name"] != "tokyo-3" {
		t.Errorf("clashing names = %+v", merged)
	}
	if list[0].Server != "old" || len(list) != 1 {
		t.Error("MergeNodes modified its input")
	}
}
