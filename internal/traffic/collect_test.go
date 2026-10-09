package traffic

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type cmdRunner struct {
	calls map[string]int
	out   map[string]string
	fail  map[string]bool
}

func (r *cmdRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	key := name + " " + strings.Join(args, " ")
	r.calls[name]++
	for prefix, out := range r.out {
		if strings.HasPrefix(key, prefix) {
			if r.fail[prefix] {
				return "", errors.New("boom")
			}
			return out, nil
		}
	}
	return "", errors.New("unexpected command " + key)
}

func newRunner(t *testing.T) *cmdRunner {
	return &cmdRunner{calls: map[string]int{}, fail: map[string]bool{}, out: map[string]string{
		"/usr/sbin/lsof":        fixture(t, "lsof.txt"),
		"/usr/sbin/netstat -rn": fixture(t, "netstat_rn.txt"),
		"/usr/sbin/netstat -ib": fixture(t, "netstat_ib.txt"),
		"/bin/ps":               fixture(t, "ps.txt"),
		"/usr/bin/codesign":     fixture(t, "codesign.txt"),
		"/usr/bin/plutil":       "com.google.Chrome\n",
	}}
}

func TestCollectorReadsEverySource(t *testing.T) {
	r := newRunner(t)
	c := &Collector{Run: r}
	st := c.Read(context.Background())
	if len(st.Warnings) != 0 {
		t.Fatalf("warnings = %v", st.Warnings)
	}
	if len(st.Sockets) != 8 || st.Routes == nil || st.Counters["en0"].InBytes == 0 || st.PS[501].PPID != 1 {
		t.Errorf("state = %+v", st)
	}
	// The process table is cached between reads.
	c.Read(context.Background())
	if r.calls["/bin/ps"] != 1 {
		t.Errorf("ps ran %d times, want 1", r.calls["/bin/ps"])
	}
}

func TestCollectorSurvivesFailingSources(t *testing.T) {
	r := newRunner(t)
	r.fail["/usr/sbin/lsof"] = true
	r.fail["/usr/sbin/netstat -ib"] = true
	st := (&Collector{Run: r}).Read(context.Background())
	if len(st.Warnings) != 2 || st.Routes == nil {
		t.Errorf("warnings = %v, routes = %v", st.Warnings, st.Routes)
	}
	r.out["/usr/sbin/netstat -rn"] = "total garbage"
	st = (&Collector{Run: r}).Read(context.Background())
	if st.Routes != nil {
		t.Error("garbage route table accepted")
	}
}

type fixedSockets []Socket

func (f fixedSockets) Sockets(context.Context) ([]Socket, error) { return f, nil }

func TestCollectorUsesInjectedSocketSource(t *testing.T) {
	r := newRunner(t)
	st := (&Collector{Run: r, Sockets: fixedSockets{{PID: 1, Command: "x"}}}).Read(context.Background())
	if len(st.Sockets) != 1 || r.calls["/usr/sbin/lsof"] != 0 {
		t.Errorf("sockets = %v, lsof calls = %d", st.Sockets, r.calls["/usr/sbin/lsof"])
	}
}

func TestEnrichCachesAndBudgets(t *testing.T) {
	r := newRunner(t)
	c := &Collector{Run: r}
	chrome := Process{Name: "Chrome", Path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", Bundle: "/Applications/Google Chrome.app"}
	flows := []Flow{{Process: chrome}, {Process: chrome}}
	c.Enrich(context.Background(), flows)
	c.Enrich(context.Background(), flows)
	if flows[1].Process.BundleID != "com.google.Chrome" || !strings.Contains(flows[0].Process.Signature, "Google LLC") {
		t.Errorf("process = %+v", flows[0].Process)
	}
	if r.calls["/usr/bin/codesign"] != 1 || r.calls["/usr/bin/plutil"] != 1 {
		t.Errorf("codesign ran %d times and plutil %d; both should be cached", r.calls["/usr/bin/codesign"], r.calls["/usr/bin/plutil"])
	}

	var many []Flow
	for i := 0; i < 30; i++ {
		many = append(many, Flow{Process: Process{Path: "/usr/bin/tool" + string(rune('a'+i%26)) + string(rune('a'+i/26))}})
	}
	r2 := newRunner(t)
	(&Collector{Run: r2}).Enrich(context.Background(), many)
	if r2.calls["/usr/bin/codesign"] != maxEnrichPerRead {
		t.Errorf("codesign ran %d times in one pass, want the budget of %d", r2.calls["/usr/bin/codesign"], maxEnrichPerRead)
	}
}

func TestStoreLiveHistoryAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "traffic.jsonl")
	clock := now
	s := OpenStoreAt(path, time.Hour, func() time.Time { return clock })

	a := Flow{ID: "conn-a", Start: now, Process: Process{Name: "curl"}, Upload: 10, Download: 90}
	b := Flow{ID: "conn-b", Start: now, Process: Process{Name: "ssh"}, Upload: 5}
	idle := Flow{ID: "sock-x", Start: now, BytesUnknown: true}
	listener := Flow{ID: "sock-l", Listen: true}
	s.Observe([]Flow{a, b, idle, listener})
	if live := s.Live(); len(live) != 3 || live[0].ID != "conn-a" {
		t.Fatalf("live = %+v", live)
	}

	clock = now.Add(time.Minute)
	a.Download = 900
	s.Observe([]Flow{a}) // b and idle are gone
	if live := s.Live(); len(live) != 1 || live[0].Download != 900 {
		t.Errorf("live = %+v", live)
	}
	hist := s.Since(now)
	ids := map[string]Flow{}
	for _, f := range hist {
		ids[f.ID] = f
	}
	if len(ids) != 2 || ids["conn-b"].End == nil || !ids["conn-b"].End.Equal(clock) {
		t.Errorf("history = %+v (idle socket entries shouldn't be kept)", ids)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("history file: %v %v", info, err)
	}

	// A new process reads it back; old flows past retention are dropped.
	old := Flow{ID: "conn-old", Start: now.Add(-5 * time.Hour), Upload: 1}
	end := now.Add(-4 * time.Hour)
	old.End = &end
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("{not json}\n")
	json := `{"id":"conn-old","start":"` + old.Start.Format(time.RFC3339) + `","end":"` + end.Format(time.RFC3339) + `","upload":1}` + "\n"
	f.WriteString(json)
	f.Close()
	s2 := OpenStoreAt(path, time.Hour, func() time.Time { return clock })
	got := s2.Since(now.Add(-10 * time.Hour))
	if len(got) != 1 || got[0].ID != "conn-b" {
		t.Errorf("reloaded = %+v", got)
	}
	if err := s2.Compact(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if strings.Count(string(data), "\n") != 1 || strings.Contains(string(data), "conn-old") {
		t.Errorf("compacted file = %q", data)
	}
	if err := s2.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("Clear left the file behind")
	}
}
