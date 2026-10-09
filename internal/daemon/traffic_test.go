package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/instance"
	"github.com/nyaaorick/clash-mihomac/internal/traffic"
)

func trafficDaemon(t *testing.T, flows []traffic.Flow) *Daemon {
	t.Helper()
	d := &Daemon{inst: instance.Instance{Name: "debug", TUNDevice: "utun1991"}}
	d.traffic = &trafficState{
		store:    traffic.OpenStore(filepath.Join(t.TempDir(), "h.jsonl"), time.Hour),
		seenOnce: map[string]int{}, addrs: map[string]nodeAddrEntry{},
		flows: flows, ownTUN: "utun1991", updated: time.Now(),
	}
	return d
}

func get(t *testing.T, h http.HandlerFunc, target string, out any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d: %s", target, rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
		t.Fatal(err)
	}
}

func TestTrafficAPIFiltersAndSummarizes(t *testing.T) {
	now := time.Now()
	flows := []traffic.Flow{
		{ID: "conn-1", Start: now, Process: traffic.Process{Name: "curl"}, Proto: "tcp", Family: "ipv4", Host: "example.com", Remote: "1.1.1.1:443",
			Proxied: true, Node: "HK", Ingress: "utun1991", Egress: "en0", Rule: "Match", Upload: 10, Download: 90},
		{ID: "sock-2", Start: now, Process: traffic.Process{Name: "ssh"}, Proto: "tcp", Family: "ipv4", Remote: "10.20.5.5:22", Egress: "en1", BytesUnknown: true,
			Anomalies: []traffic.Anomaly{{Kind: traffic.AnomalyBypassedTUN, Detail: "skipped TUN"}}},
	}
	d := trafficDaemon(t, flows)

	var v TrafficView
	get(t, d.handleTraffic, "/api/traffic?view=hardware", &v)
	if v.Flows != 2 || v.Mode != "live" || v.Sankey.View != traffic.ViewHardware || len(v.Anomalies) != 1 || v.Anomalies[0].Kind != traffic.AnomalyBypassedTUN || v.Anomalies[0].Process != "ssh" {
		t.Errorf("view = %+v", v)
	}
	get(t, d.handleTraffic, "/api/traffic?routing=proxied&process=curl", &v)
	if v.Flows != 1 || len(v.Anomalies) != 0 || len(v.Processes) != 1 || v.Processes[0].Name != "curl" {
		t.Errorf("filtered view = %+v", v)
	}

	var list []traffic.Flow
	get(t, d.handleTrafficFlows, "/api/traffic/flows?iface=en1", &list)
	if len(list) != 1 || list[0].ID != "sock-2" {
		t.Errorf("flows = %+v", list)
	}
	get(t, d.handleTrafficFlows, "/api/traffic/flows?proto=udp", &list)
	if list == nil || len(list) != 0 {
		t.Errorf("empty result should be [] not null: %v", list)
	}
}

func TestTrafficHistoryMode(t *testing.T) {
	d := trafficDaemon(t, nil)
	now := time.Now()
	d.traffic.store.Observe([]traffic.Flow{{ID: "conn-a", Start: now.Add(-time.Minute), Process: traffic.Process{Name: "curl"}, Upload: 5, Download: 5}})
	d.traffic.store.Observe(nil) // it closes

	var v TrafficView
	get(t, d.handleTraffic, "/api/traffic?mode=history&range=1h", &v)
	if v.Mode != "history" || v.Flows != 1 {
		t.Errorf("history view = %+v", v)
	}
	get(t, d.handleTraffic, "/api/traffic", &v)
	if v.Flows != 0 {
		t.Errorf("live view should not include finished flows: %+v", v)
	}
}

func TestAnomaliesNeedToPersist(t *testing.T) {
	tr := &trafficState{seenOnce: map[string]int{}}
	mk := func() []traffic.Flow {
		return []traffic.Flow{{ID: "sock-1", Anomalies: []traffic.Anomaly{{Kind: traffic.AnomalyBypassedTUN}}}, {ID: "conn-2"}}
	}
	if got := tr.stabilize(mk()); len(got[0].Anomalies) != 0 {
		t.Error("anomaly reported on first sight")
	}
	if got := tr.stabilize(mk()); len(got[0].Anomalies) != 1 {
		t.Error("anomaly not reported after persisting")
	}
	tr.stabilize([]traffic.Flow{{ID: "conn-2"}}) // sock-1 vanished
	if got := tr.stabilize(mk()); len(got[0].Anomalies) != 0 {
		t.Error("a flow that reappears should start counting again")
	}
}

func TestCounterWindow(t *testing.T) {
	t0 := time.Now()
	snap := func(sec int, out uint64) counterSnap {
		return counterSnap{t: t0.Add(time.Duration(sec) * time.Second), c: map[string]traffic.IfaceCounters{"en0": {Name: "en0", OutBytes: out}}}
	}
	tr := &trafficState{}
	if _, _, ok := tr.counterWindow(time.Minute); ok {
		t.Error("window with no data")
	}
	tr.ring = []counterSnap{snap(0, 0), snap(30, 300), snap(60, 600), snap(90, 900), snap(120, 1200)}
	delta, span, ok := tr.counterWindow(time.Minute)
	if !ok || span != time.Minute || delta["en0"].OutBytes != 600 {
		t.Errorf("window = %v %v %v", delta, span, ok)
	}
	delta, span, _ = tr.counterWindow(time.Hour)
	if span != 2*time.Minute || delta["en0"].OutBytes != 1200 {
		t.Errorf("long window = %v %v", delta, span)
	}
}
