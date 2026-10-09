package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/health"
)

func TestCheckNodesRecordsHealthyNodes(t *testing.T) {
	var asked []string
	var askedMu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/delay") || r.Header.Get("Authorization") != "Bearer s3cret" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		askedMu.Lock()
		asked = append(asked, r.URL.EscapedPath())
		askedMu.Unlock()
		json.NewEncoder(w).Encode(map[string]int{"delay": 42})
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	os.WriteFile(cfg, []byte("proxies:\n  - {name: hk, type: ss, server: 192.0.2.1, port: 8388}\n  - {name: \"jp/1\", type: ss, server: 192.0.2.2, port: 8388}\n  - {name: d, type: direct}\n"), 0o600)
	d := &Daemon{
		o:      Options{ConfigPath: cfg},
		ctrl:   controller{addr: strings.TrimPrefix(srv.URL, "http://"), secret: "s3cret"},
		health: health.LoadHistory(filepath.Join(dir, "health.json")),
	}
	// Stale nodes from an earlier config are forgotten.
	d.health.Record(health.Check{Time: time.Now(), Node: "gone", OK: true})

	names := d.checkNodes(context.Background(), "")
	if len(names) != 2 {
		t.Fatalf("checked %v", names)
	}
	v := d.healthView()
	if len(v.Nodes) != 2 || v.Nodes[0].Node != "hk" || v.Nodes[0].State != health.StateHealthy || v.Nodes[0].AvgDelayMs != 42 {
		t.Errorf("view = %+v", v)
	}
	if _, err := os.Stat(filepath.Join(dir, "health.json")); err != nil {
		t.Errorf("history not saved: %v", err)
	}
	if got := d.checkNodes(context.Background(), "hk"); len(got) != 1 || len(d.health.Checks("hk")) != 2 || len(d.health.Checks("jp/1")) != 1 {
		t.Errorf("single-node check: %v", got)
	}
	if got := d.checkNodes(context.Background(), "nope"); len(got) != 0 {
		t.Errorf("unknown node checked: %v", got)
	}
	if len(asked) < 3 || !strings.Contains(strings.Join(asked, " "), "jp%2F1") {
		t.Errorf("delay requests = %v (node names must be path-escaped)", asked)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/health/hk", nil)
	req.SetPathValue("node", "hk")
	d.handleNodeHealth(rec, req)
	var nh NodeHealth
	if err := json.Unmarshal(rec.Body.Bytes(), &nh); err != nil || len(nh.Checks) != 2 || nh.Summary.Node != "hk" {
		t.Errorf("node health = %s, %v", rec.Body.String(), err)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/health/zzz", nil)
	req.SetPathValue("node", "zzz")
	d.handleNodeHealth(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown node status = %d", rec.Code)
	}
}
